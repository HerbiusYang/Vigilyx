//! YARA Rule Module - EML + AttachmentExecuteline YARA Rulematch.

//! ClamAV:ClamAV Use Sign detectalready,
//! YARA Use ofmodeRuledetectMaliciousDocumentation, Executeline, APT And.

//! CPU-bound module — the orchestrator runs `analyze()` inside `spawn_blocking`
//! when `cpu_bound = true`, so no inner `spawn_blocking` is needed here.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;
use vigilyx_core::models::{EmailSession, decode_base64_bytes_limited};

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::yara::engine::{YaraEngine, YaraMatch};
use crate::yara::structural::{CoverageGap, StructuralFinding, inspect_attachment};
use crate::yara::target::{ScanTarget, classify_scan_target};

const MAX_ATTACHMENT_SCAN_BYTES: usize = 25 * 1024 * 1024;

/// Per-email total YARA scan time budget. A single file keeps its own 10s
/// timeout in `YaraEngine::scan`, but many large attachments must not
/// collectively occupy the blocking pool for minutes.
const EMAIL_SCAN_BUDGET: Duration = Duration::from_secs(10);
const MAX_REPORTED_MATCHES: usize = 64;
const RTLO_FILENAME_RULE: &str = "Evasion_RTLO_Filename_Spoof";
const RTLO_FILENAME_DESCRIPTION: &str = "RTLO (U+202E) 文件名欺骗 — 利用右到左覆盖字符伪装扩展名";
const EXECUTABLE_FILENAME_SUFFIXES: &[&str] = &[".exe", ".scr", ".bat", ".cmd", ".pif", ".com"];

struct LocatedYaraMatch {
    matched: YaraMatch,
    location: String,
}

#[derive(Default)]
struct YaraScanCollector {
    matches: Vec<LocatedYaraMatch>,
    shadow_matches: Vec<LocatedYaraMatch>,
    coverage_gaps: Vec<CoverageGap>,
    failures: Vec<String>,
    shadow_failures: Vec<String>,
    shadow_budget_exhausted_locations: Vec<String>,
    shards_scanned: usize,
    rules_selected: usize,
}

fn add_located_matches(
    matches: &mut Vec<LocatedYaraMatch>,
    incoming: Vec<YaraMatch>,
    location: &str,
) {
    for matched in incoming {
        if matches.len() >= MAX_REPORTED_MATCHES {
            break;
        }
        if matches.iter().any(|existing| {
            existing.matched.rule_name == matched.rule_name && existing.location == location
        }) {
            continue;
        }
        matches.push(LocatedYaraMatch {
            matched,
            location: location.to_string(),
        });
    }
}

/// RTLO filename spoofing is a metadata predicate, not a payload byte rule.
/// Keeping it here prevents the same byte sequence inside a PDF, document, or
/// decoded archive member from being misreported as filename evidence.
fn is_rtlo_filename_spoof(filename: &str) -> bool {
    if !filename.contains('\u{202e}') {
        return false;
    }
    let lowercase = filename.to_ascii_lowercase();
    EXECUTABLE_FILENAME_SUFFIXES
        .iter()
        .any(|suffix| lowercase.ends_with(suffix))
}

fn rtlo_filename_match(filename: &str) -> Option<YaraMatch> {
    is_rtlo_filename_spoof(filename).then(|| YaraMatch {
        rule_name: RTLO_FILENAME_RULE.to_string(),
        category: "evasion_technique".to_string(),
        severity: "high".to_string(),
        description: RTLO_FILENAME_DESCRIPTION.to_string(),
        // Preserve the former built-in rule's default fidelity and breaker
        // behavior; this repair changes only the inspected object boundary.
        fidelity: "legacy".to_string(),
        breaker_eligible: false,
    })
}

fn scan_target_at_location(
    engine: &YaraEngine,
    data: &[u8],
    target: ScanTarget,
    location: &str,
    collector: &mut YaraScanCollector,
) {
    let outcome = engine.scan_target_detailed(data, target);
    collector.shards_scanned += outcome.shards_scanned;
    collector.rules_selected += outcome.rules_selected;
    add_located_matches(&mut collector.matches, outcome.matches, location);
    add_located_matches(
        &mut collector.shadow_matches,
        outcome.shadow_matches,
        location,
    );
    if outcome.budget_exhausted {
        collector.coverage_gaps.push(CoverageGap {
            location: location.to_string(),
            reason: "yara_shard_scan_budget",
        });
    }
    if !outcome.failed_shards.is_empty() {
        collector.coverage_gaps.push(CoverageGap {
            location: location.to_string(),
            reason: "yara_shard_scan_failed",
        });
        collector
            .failures
            .extend(outcome.failed_shards.into_iter().take(16));
    }
    if outcome.shadow_budget_exhausted
        && !collector
            .shadow_budget_exhausted_locations
            .iter()
            .any(|existing| existing == location)
    {
        collector
            .shadow_budget_exhausted_locations
            .push(location.to_string());
    }
    collector
        .shadow_failures
        .extend(outcome.shadow_failed_shards.into_iter().take(16));
}

pub struct YaraScanModule {
    meta: ModuleMetadata,
    engine: Arc<YaraEngine>,
    scan_budget: Duration,
}

impl YaraScanModule {
    pub fn new(engine: Arc<YaraEngine>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "yara_scan".to_string(),
                name: "YARA Rule扫描".to_string(),
                description: format!(
                    "Use {} Item内置 YARA RuledetectMaliciousDocumentation、可Executeline伪装、Malicious软件家族And脚本木马",
                    engine.rule_count()
                ),
                pillar: Pillar::Attachment,
                depends_on: vec![],
                timeout_ms: 15_000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
            engine,
            scan_budget: EMAIL_SCAN_BUDGET,
        }
    }

    /// Override the per-email scan budget (tests use a zero/tiny budget to
    /// force budget exhaustion deterministically).
    #[cfg(test)]
    fn with_scan_budget(mut self, budget: Duration) -> Self {
        self.scan_budget = budget;
        self
    }

    /// Scan one decoded attachment payload: YARA root scan, then structural
    /// inspection (decompression), then bounded decoded layers.
    ///
    /// The per-email budget is re-checked before *each* expensive stage (B5):
    /// previously it was only checked at the top of the attachment loop, so a
    /// single attachment's root scan plus up-to-64MB decompression always ran
    /// to completion even after the budget was blown — one crafted email
    /// could hog the blocking pool far beyond its 10s budget.
    #[allow(clippy::too_many_arguments)]
    fn scan_decoded_attachment(
        &self,
        filename: &str,
        content_type: &str,
        decoded: &[u8],
        start: &Instant,
        yara_scan: &mut YaraScanCollector,
        structural_findings: &mut Vec<StructuralFinding>,
        decoded_layers_scanned: &mut usize,
        skipped_attachments: &mut usize,
    ) {
        let root_location = format!("attachment:{filename}");

        if start.elapsed() >= self.scan_budget {
            *skipped_attachments += 1;
            yara_scan.coverage_gaps.push(CoverageGap {
                location: root_location,
                reason: "email_scan_time_budget",
            });
            return;
        }

        let root_target = classify_scan_target(filename, content_type, decoded);
        scan_target_at_location(
            &self.engine,
            decoded,
            root_target,
            &root_location,
            yara_scan,
        );

        // B5: re-check after the root scan — a large root payload may have
        // consumed the remaining budget; do not start decompression.
        if start.elapsed() >= self.scan_budget {
            *skipped_attachments += 1;
            yara_scan.coverage_gaps.push(CoverageGap {
                location: format!("{root_location}:inspection"),
                reason: "email_scan_time_budget",
            });
            return;
        }

        let inspection = inspect_attachment(filename, decoded);
        structural_findings.extend(inspection.findings);
        yara_scan.coverage_gaps.extend(inspection.coverage_gaps);
        for layer in inspection.layers {
            // B5: per-layer budget check — each decoded layer is a full YARA
            // scan, so the budget must gate every single one.
            if start.elapsed() >= self.scan_budget {
                yara_scan.coverage_gaps.push(CoverageGap {
                    location: layer.location,
                    reason: "email_scan_time_budget",
                });
                continue;
            }
            *decoded_layers_scanned += 1;
            let layer_target = classify_scan_target(&layer.location, "", &layer.data);
            scan_target_at_location(
                &self.engine,
                &layer.data,
                layer_target,
                &layer.location,
                yara_scan,
            );
        }
    }
}

/// Map YARA severity string to ThreatLevel.
fn severity_to_threat(severity: &str) -> ThreatLevel {
    match severity {
        "critical" => ThreatLevel::Critical,
        "high" => ThreatLevel::High,
        "medium" => ThreatLevel::Medium,
        "low" => ThreatLevel::Low,
        _ => ThreatLevel::High,
    }
}

fn reconstruct_yara_eml(session: &EmailSession) -> Vec<u8> {
    let estimated_size = session.content.raw_size.max(1024);
    let mut eml = Vec::with_capacity(estimated_size);

    for (name, value) in &session.content.headers {
        eml.extend_from_slice(name.as_bytes());
        eml.extend_from_slice(b": ");
        eml.extend_from_slice(value.as_bytes());
        eml.extend_from_slice(b"\r\n");
    }
    eml.extend_from_slice(b"\r\n");

    if let Some(text) = &session.content.body_text {
        eml.extend_from_slice(text.as_bytes());
        eml.extend_from_slice(b"\r\n");
    }
    if let Some(html) = &session.content.body_html {
        eml.extend_from_slice(html.as_bytes());
        eml.extend_from_slice(b"\r\n");
    }

    eml
}

#[async_trait]
impl SecurityModule for YaraScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        // Orchestrator already runs cpu_bound=true modules inside spawn_blocking,
        // so we execute the YARA scan directly here without a redundant inner spawn_blocking.
        let mut yara_scan = YaraScanCollector::default();
        let mut structural_findings: Vec<StructuralFinding> = Vec::new();
        let mut decoded_layers_scanned = 0usize;

        // Filename-only indicators are evaluated before byte/time limits: a
        // skipped or undecodable payload does not make its metadata disappear.
        for att in &ctx.session.content.attachments {
            if let Some(matched) = rtlo_filename_match(&att.filename) {
                add_located_matches(
                    &mut yara_scan.matches,
                    vec![matched],
                    &format!("attachment:{}", att.filename),
                );
            }
        }

        // 1. Scan message headers/body only. Attachments are scanned separately
        // below so their raw bytes keep their original container context.
        let eml = reconstruct_yara_eml(&ctx.session);
        if !eml.is_empty() {
            scan_target_at_location(
                &self.engine,
                &eml,
                ScanTarget::Message,
                "message:headers_body",
                &mut yara_scan,
            );
        }

        // 2. Scan attachment roots, then bounded decoded PDF/ZIP layers. The
        // structural inspector independently confirms executable payloads.
        let mut skipped_attachments = 0usize;
        for att in &ctx.session.content.attachments {
            if att.size > MAX_ATTACHMENT_SCAN_BYTES {
                skipped_attachments += 1;
                yara_scan.coverage_gaps.push(CoverageGap {
                    location: format!("attachment:{}", att.filename),
                    reason: "attachment_size_limit",
                });
                continue;
            }
            // Per-email scan budget: once exhausted, stop scanning the remaining
            // attachments so one crafted email cannot hog the blocking pool.
            if start.elapsed() >= self.scan_budget {
                skipped_attachments += 1;
                yara_scan.coverage_gaps.push(CoverageGap {
                    location: format!("attachment:{}", att.filename),
                    reason: "email_scan_time_budget",
                });
                continue;
            }
            if let Some(ref b64) = att.content_base64
                && let Some(decoded) = decode_base64_bytes_limited(b64, MAX_ATTACHMENT_SCAN_BYTES)
            {
                self.scan_decoded_attachment(
                    &att.filename,
                    &att.content_type,
                    &decoded,
                    &start,
                    &mut yara_scan,
                    &mut structural_findings,
                    &mut decoded_layers_scanned,
                    &mut skipped_attachments,
                );
            } else if att.size > 0 {
                skipped_attachments += 1;
                yara_scan.coverage_gaps.push(CoverageGap {
                    location: format!("attachment:{}", att.filename),
                    reason: "attachment_decode_failed_or_missing",
                });
            }
        }

        if skipped_attachments > 0 {
            warn!(
                skipped = skipped_attachments,
                budget_ms = self.scan_budget.as_millis() as u64,
                "YARA per-email scan budget exhausted, skipped remaining attachments"
            );
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        if yara_scan.matches.is_empty() && structural_findings.is_empty() {
            // A coverage gap with no matches is not a silent clean pass, but
            // it is also not threat evidence. Preserve the category, evidence,
            // details, and low confidence so the verdict/delivery layer can
            // apply source-specific coverage policy without painting the
            // module card Low.
            if !yara_scan.coverage_gaps.is_empty() {
                let gap_count = yara_scan.coverage_gaps.len();
                let inspection_budget_exhausted = yara_scan.coverage_gaps.iter().any(|gap| {
                    matches!(
                        gap.reason,
                        "email_scan_time_budget" | "yara_shard_scan_budget"
                    )
                });
                return Ok(ModuleResult {
                    module_id: self.meta.id.clone(),
                    module_name: self.meta.name.clone(),
                    pillar: self.meta.pillar,
                    threat_level: ThreatLevel::Safe,
                    confidence: 0.10,
                    categories: vec!["attachment_inspection_limited".to_string()],
                    summary: format!(
                        "YARA/结构扫描无威胁命中，但有 {} 个附件检查覆盖缺口",
                        gap_count
                    ),
                    evidence: yara_scan
                        .coverage_gaps
                        .iter()
                        .take(16)
                        .map(|gap| Evidence {
                            description: format!(
                                "Attachment inspection incomplete: {}",
                                gap.reason
                            ),
                            location: Some(gap.location.clone()),
                            snippet: None,
                        })
                        .collect(),
                    details: serde_json::json!({
                        "skipped_attachments": skipped_attachments,
                        "inspection_budget_exhausted": inspection_budget_exhausted,
                        "coverage_gaps": yara_scan.coverage_gaps.iter().map(|gap| serde_json::json!({
                            "location": gap.location,
                            "reason": gap.reason,
                        })).collect::<Vec<_>>(),
                        "decoded_layers_scanned": decoded_layers_scanned,
                        "yara_shards_scanned": yara_scan.shards_scanned,
                        "yara_rules_selected": yara_scan.rules_selected,
                        "yara_scan_failures": yara_scan.failures,
                        "shadow_scan_incomplete": !yara_scan.shadow_failures.is_empty()
                            || !yara_scan.shadow_budget_exhausted_locations.is_empty(),
                        "shadow_scan_failures": yara_scan.shadow_failures,
                        "shadow_budget_exhausted_locations": yara_scan.shadow_budget_exhausted_locations,
                        "shadow_match_count": yara_scan.shadow_matches.len(),
                        "shadow_matches": yara_scan.shadow_matches.iter().map(|located| serde_json::json!({
                            "rule": located.matched.rule_name,
                            "location": located.location,
                            "category": located.matched.category,
                            "severity": located.matched.severity,
                        })).collect::<Vec<_>>(),
                    }),
                    duration_ms,
                    analyzed_at: Utc::now(),
                    bpa: None,
                    engine_id: None,
                });
            }
            let mut result = ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "YARA 扫描complete，{} ItemRuleAll未命Medium",
                    self.engine.rule_count()
                ),
                duration_ms,
            );
            result.details = serde_json::json!({
                "skipped_attachments": skipped_attachments,
                "decoded_layers_scanned": decoded_layers_scanned,
                "yara_shards_scanned": yara_scan.shards_scanned,
                "yara_rules_selected": yara_scan.rules_selected,
                "yara_scan_failures": yara_scan.failures,
                "shadow_scan_incomplete": !yara_scan.shadow_failures.is_empty()
                    || !yara_scan.shadow_budget_exhausted_locations.is_empty(),
                "shadow_scan_failures": yara_scan.shadow_failures,
                "shadow_budget_exhausted_locations": yara_scan.shadow_budget_exhausted_locations,
                "engine_generation": self.engine.generation(),
                "engine_shard_count": self.engine.shard_count(),
                "pack_rule_count": self.engine.pack_rule_count(),
                "shadow_match_count": yara_scan.shadow_matches.len(),
                "shadow_matches": yara_scan.shadow_matches.iter().map(|located| serde_json::json!({
                    "rule": located.matched.rule_name,
                    "location": located.location,
                    "category": located.matched.category,
                    "severity": located.matched.severity,
                })).collect::<Vec<_>>(),
                "structural_validation": "no_valid_executable_payload",
            });
            return Ok(result);
        }

        // Build located evidence. Rule severity and confidence are independent:
        // legacy/custom Critical rules no longer inherit 98% confidence unless
        // they explicitly declare exact fidelity.
        let mut categories: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        let mut max_threat = ThreatLevel::Low;
        let mut rule_names: Vec<String> = Vec::new();
        let mut confidence: f64 = 0.0;
        let mut matched_rule_details = Vec::new();
        let mut structural_details = Vec::new();

        for located in &yara_scan.matches {
            let m = &located.matched;
            let threat = severity_to_threat(&m.severity);
            if threat > max_threat {
                max_threat = threat;
            }
            confidence = confidence.max(m.confidence());

            if !m.category.is_empty() && !categories.contains(&m.category) {
                categories.push(m.category.clone());
            }
            categories.push("yara_match".to_string());
            if m.breaker_eligible && m.fidelity == "exact" {
                categories.push("verified_yara_signature".to_string());
            }

            if !rule_names.contains(&m.rule_name) {
                rule_names.push(m.rule_name.clone());
            }

            evidence.push(Evidence {
                description: format!("YARA Rule {} 命Medium: {}", m.rule_name, m.description),
                location: Some(located.location.clone()),
                snippet: Some(format!(
                    "[{}] severity={} fidelity={} confidence={:.0}%",
                    m.category,
                    m.severity,
                    m.fidelity,
                    m.confidence() * 100.0
                )),
            });
            matched_rule_details.push(serde_json::json!({
                "rule": m.rule_name,
                "location": located.location,
                "category": m.category,
                "severity": m.severity,
                "fidelity": m.fidelity,
                "confidence": m.confidence(),
                "breaker_eligible": m.breaker_eligible && m.fidelity == "exact",
            }));
        }

        for finding in &structural_findings {
            let threat = severity_to_threat(finding.severity);
            if threat > max_threat {
                max_threat = threat;
            }
            confidence = confidence.max(finding.confidence);
            for category in &finding.categories {
                categories.push((*category).to_string());
            }
            categories.push("structural_payload_validation".to_string());
            if !rule_names.iter().any(|name| name == finding.rule_name) {
                rule_names.push(finding.rule_name.to_string());
            }
            evidence.push(Evidence {
                description: finding.description.clone(),
                location: Some(finding.location.clone()),
                snippet: Some(finding.validation.clone()),
            });
            structural_details.push(serde_json::json!({
                "rule": finding.rule_name,
                "location": finding.location,
                "offset": finding.offset,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "categories": finding.categories,
                "validation": finding.validation,
            }));
        }

        if !yara_scan.coverage_gaps.is_empty() {
            categories.push("attachment_inspection_limited".to_string());
            for gap in yara_scan.coverage_gaps.iter().take(16) {
                evidence.push(Evidence {
                    description: format!("Attachment inspection incomplete: {}", gap.reason),
                    location: Some(gap.location.clone()),
                    snippet: None,
                });
            }
        }

        categories.sort();
        categories.dedup();

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level: max_threat,
            confidence,
            categories,
            summary: format!(
                "YARA/结构扫描命中 {} 项: {}",
                yara_scan.matches.len() + structural_findings.len(),
                rule_names.join(", ")
            ),
            evidence,
            details: serde_json::json!({
                "matched_rules": rule_names,
                "match_count": yara_scan.matches.len(),
                "matched_rule_details": matched_rule_details,
                "structural_findings": structural_details,
                "structural_finding_count": structural_findings.len(),
                "total_rules": self.engine.rule_count(),
                "skipped_attachments": skipped_attachments,
                "decoded_layers_scanned": decoded_layers_scanned,
                "yara_shards_scanned": yara_scan.shards_scanned,
                "yara_rules_selected": yara_scan.rules_selected,
                "yara_scan_failures": yara_scan.failures,
                "shadow_scan_incomplete": !yara_scan.shadow_failures.is_empty()
                    || !yara_scan.shadow_budget_exhausted_locations.is_empty(),
                "shadow_scan_failures": yara_scan.shadow_failures,
                "shadow_budget_exhausted_locations": yara_scan.shadow_budget_exhausted_locations,
                "engine_generation": self.engine.generation(),
                "engine_shard_count": self.engine.shard_count(),
                "pack_rule_count": self.engine.pack_rule_count(),
                "shadow_match_count": yara_scan.shadow_matches.len(),
                "shadow_matches": yara_scan.shadow_matches.iter().map(|located| serde_json::json!({
                    "rule": located.matched.rule_name,
                    "location": located.location,
                    "category": located.matched.category,
                    "severity": located.matched.severity,
                })).collect::<Vec<_>>(),
                "coverage_gaps": yara_scan.coverage_gaps.iter().map(|gap| serde_json::json!({
                    "location": gap.location,
                    "reason": gap.reason,
                })).collect::<Vec<_>>(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::context::SecurityContext;
    use base64::Engine as _;
    use std::io::{Cursor, Write};
    use vigilyx_core::models::{EmailAttachment, EmailContent, Protocol};

    fn make_engine() -> Arc<YaraEngine> {
        Arc::new(YaraEngine::new().expect("YARA engine should compile"))
    }

    fn make_session(
        body: Option<&str>,
        attachments: Vec<EmailAttachment>,
    ) -> Arc<vigilyx_core::models::EmailSession> {
        let mut session = vigilyx_core::models::EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            headers: vec![("Subject".to_string(), "Test".to_string())],
            body_text: body.map(|s| s.to_string()),
            body_html: None,
            attachments,
            links: vec![],
            raw_size: 512,
            is_complete: true,
            is_encrypted: false,
            truncated: false,
            dropped_attachments: 0,
            links_truncated: false,
            link_index: std::collections::HashSet::new(),
            smtp_dialog: vec![],
        };
        Arc::new(session)
    }

    #[test]
    fn reconstruct_yara_eml_does_not_append_attachment_bytes() {
        let session = make_session(
            Some("body"),
            vec![EmailAttachment {
                filename: "invoice.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                size: 32,
                hash: String::new(),
                content_base64: Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(b"%PDF-1.7\nIcedID\nJFIF\n\x1F\x8B\x08\nMZ"),
                ),
            }],
        );
        let eml = reconstruct_yara_eml(&session);
        let eml_text = String::from_utf8_lossy(&eml);
        assert!(eml_text.contains("Subject: Test"));
        assert!(eml_text.contains("body"));
        assert!(!eml_text.contains("%PDF-1.7"));
        assert!(!eml_text.contains("IcedID"));
    }

    #[tokio::test]
    async fn test_clean_email_safe() {
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(Some("Normal business email"), vec![]));
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn shadow_budget_exhaustion_is_telemetry_not_a_low_finding() {
        let pack = crate::yara::pack::RulePackLoad {
            pack_id: Some("shadow-module-test".to_string()),
            generation: Some("shadow-module-g1".to_string()),
            sources: vec![crate::yara::pack::LoadedRuleSource {
                shard_id: "shadow".to_string(),
                target: ScanTarget::Generic,
                backend: crate::yara::pack::RuleBackend::YaraX,
                source: r#"rule shadow_module_hit { strings: $a = "SHADOW_MODULE_MARKER" condition: $a }"#
                    .to_string(),
                expected_rule_count: 1,
                license: "MIT".to_string(),
                provenance: "test".to_string(),
                version: "g1".to_string(),
                quality_tier: "legacy".to_string(),
                enforce: false,
            }],
            declared_rules: 1,
            ..crate::yara::pack::RulePackLoad::default()
        };
        let engine = YaraEngine::new_with_pack(&[], pack)
            .unwrap()
            .with_scan_budgets(Duration::from_secs(5), Duration::ZERO);
        let module = YaraScanModule::new(Arc::new(engine));
        let ctx = SecurityContext::new(make_session(Some("SHADOW_MODULE_MARKER"), vec![]));

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
        assert_eq!(result.details["shadow_scan_incomplete"], true);
        assert_eq!(
            result.details["shadow_budget_exhausted_locations"][0],
            "message:headers_body"
        );
    }

    #[tokio::test]
    async fn test_eicar_in_body_detected() {
        let module = YaraScanModule::new(make_engine());
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let ctx = SecurityContext::new(make_session(Some(eicar), vec![]));
        let result = module.analyze(&ctx).await.unwrap();
        assert!(
            result.threat_level >= ThreatLevel::High,
            "EICAR 应被detect: {:?}",
            result.threat_level
        );
        assert!(result.summary.contains("EICAR"));
        assert!(
            result
                .categories
                .contains(&"verified_yara_signature".to_string())
        );
    }

    #[tokio::test]
    async fn test_no_attachments_no_crash() {
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(None, vec![]));
        let result = module.analyze(&ctx).await.unwrap();
        // Empty email - should still complete without error
        assert!(result.threat_level <= ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_pdf_attachment_lure_content_does_not_trigger_icedid_via_eml_scan() {
        let module = YaraScanModule::new(make_engine());
        let attachment = EmailAttachment {
            filename: "invoice.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: 64,
            hash: String::new(),
            content_base64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(b"%PDF-1.7\nIcedID\nJFIF\n\x1F\x8B\x08\nMZ"),
            ),
        };
        let ctx = SecurityContext::new(make_session(
            Some("Normal business email"),
            vec![attachment],
        ));
        let result = module.analyze(&ctx).await.unwrap();
        assert!(
            !result.summary.contains("Mal_IcedID_BokBot"),
            "PDF lure content should not match IcedID via reconstructed EML: {}",
            result.summary
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn rtlo_filename_predicate_requires_rtlo_and_terminal_executable_suffix() {
        for filename in [
            "",
            "invoice.pdf",
            "报告\u{202e}.pdf",
            "invoice\u{202e}fdp.exe.txt",
            "normal-报告.exe",
        ] {
            assert!(
                !is_rtlo_filename_spoof(filename),
                "incomplete filename predicate must remain negative: {filename:?}"
            );
        }

        for filename in [
            "invoice\u{202e}fdp.exe",
            "photo\u{202e}gnp.SCR",
            "report\u{202e}cod.CmD",
        ] {
            assert!(
                is_rtlo_filename_spoof(filename),
                "complete filename predicate must be detected: {filename:?}"
            );
        }
    }

    #[tokio::test]
    async fn rtlo_tokens_inside_three_pdf_payloads_do_not_match_filename_rule() {
        let attachments = [".exe", ".scr", ".cmd"]
            .into_iter()
            .enumerate()
            .map(|(index, executable_token)| {
                let payload = format!(
                    "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\u{202e} {executable_token}\n%%EOF\n"
                );
                make_attachment(&format!("benign-{index}.pdf"), payload.as_bytes())
            })
            .collect();
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Security research PDF attachments"),
            attachments,
        ));

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.summary.contains(RTLO_FILENAME_RULE),
            "payload text must not activate a filename rule: {result:?}"
        );
        assert!(
            !result
                .evidence
                .iter()
                .any(|evidence| { evidence.description.contains(RTLO_FILENAME_RULE) })
        );
        assert!(
            result.details["matched_rule_details"]
                .as_array()
                .is_none_or(|details| details
                    .iter()
                    .all(|detail| { detail["rule"].as_str() != Some(RTLO_FILENAME_RULE) }))
        );
    }

    #[tokio::test]
    async fn rtlo_filename_with_executable_suffix_emits_located_match() {
        let spoofed_filename = "invoice\u{202e}fdp.exe";
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Please review the attachment"),
            vec![make_attachment(
                spoofed_filename,
                b"ordinary attachment payload",
            )],
        ));

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::High, "{result:?}");
        assert!(result.categories.contains(&"yara_match".to_string()));
        let expected_location = format!("attachment:{spoofed_filename}");
        assert!(result.evidence.iter().any(|evidence| {
            evidence.description.contains(RTLO_FILENAME_RULE)
                && evidence.location.as_deref() == Some(expected_location.as_str())
        }));
        let matched = result.details["matched_rule_details"]
            .as_array()
            .and_then(|details| {
                details
                    .iter()
                    .find(|detail| detail["rule"].as_str() == Some(RTLO_FILENAME_RULE))
            })
            .expect("structured RTLO filename match must be reported");
        assert_eq!(matched["fidelity"], "legacy");
        assert_eq!(matched["breaker_eligible"], false);
    }

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn make_attachment(filename: &str, payload: &[u8]) -> EmailAttachment {
        EmailAttachment {
            filename: filename.to_string(),
            content_type: "application/octet-stream".to_string(),
            size: payload.len(),
            hash: String::new(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(payload)),
        }
    }

    fn minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        data[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        data[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        data[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        let section = 0x80 + 24 + 0xF0;
        data[section..section + 5].copy_from_slice(b".text");
        data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data
    }

    fn flate_pdf(payload: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /XObject /Subtype /Image /Filter /FlateDecode >>\nstream\n".to_vec();
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n2 0 obj\n<< /Filter /DCTDecode >>\nstream\nJFIF MZ\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    #[tokio::test]
    async fn compressed_pdf_image_magic_coincidence_stays_safe() {
        let mut pixels = vec![0x41; 4096];
        pixels[100..102].copy_from_slice(b"MZ");
        pixels[3000..3004].copy_from_slice(b"PE\0\0");
        let pdf = flate_pdf(&pixels);
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Property valuation report"),
            vec![make_attachment("valuation.pdf", &pdf)],
        ));

        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert_eq!(
            result.details["structural_validation"],
            "no_valid_executable_payload"
        );
    }

    #[tokio::test]
    async fn disguised_structurally_valid_pe_is_a_verified_payload_anchor() {
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Please see attached report"),
            vec![make_attachment("report.pdf", &minimal_pe())],
        ));

        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Critical, "{result:?}");
        assert!(
            result
                .categories
                .contains(&"verified_payload_anchor".to_string())
        );
        assert!(result.evidence.iter().any(|evidence| {
            evidence
                .snippet
                .as_deref()
                .is_some_and(|snippet| snippet.contains("MZ@0 -> PE@128"))
        }));
    }

    #[tokio::test]
    async fn yara_scans_decoded_archive_member_with_location() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file("tests/eicar.com", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(EICAR).unwrap();
            writer.finish().unwrap();
        }
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Archive inspection test"),
            vec![make_attachment("sample.zip", cursor.get_ref())],
        ));

        let result = module.analyze(&ctx).await.unwrap();
        assert!(result.summary.contains("EICAR"));
        assert!(result.evidence.iter().any(|evidence| {
            evidence
                .location
                .as_deref()
                .is_some_and(|location| location.contains("archive:tests/eicar.com"))
        }));
    }

    #[tokio::test]
    async fn test_scan_budget_exhaustion_skips_attachments() {
        // Zero budget: every attachment must be skipped without scanning.
        let module = YaraScanModule::new(make_engine()).with_scan_budget(Duration::ZERO);
        let ctx = SecurityContext::new(make_session(
            Some("Normal business email"),
            vec![
                make_attachment("eicar.com", EICAR),
                make_attachment("notes.txt", b"quarterly report"),
            ],
        ));
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(
            result.details["skipped_attachments"], 2,
            "zero budget must skip every attachment: {:?}",
            result.details
        );
        // EICAR lives only inside the skipped attachment, so it must not fire.
        assert!(!result.summary.contains("EICAR"));
        // Budget exhaustion is visible coverage metadata, not threat evidence.
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
        assert_eq!(result.confidence, 0.10);
        assert!(!result.evidence.is_empty());
        assert_eq!(result.details["inspection_budget_exhausted"], true);
    }

    /// PoC (B5): the per-email budget used to be checked only at the top of
    /// the attachment loop, so a root scan + decompression always ran to
    /// completion on an exhausted budget. `scan_decoded_attachment` now gates
    /// every stage; with a spent budget, even an EICAR payload is skipped and
    /// surfaces as a coverage gap instead.
    #[test]
    fn exhausted_budget_skips_root_scan_and_structural_inspection() {
        let module = YaraScanModule::new(make_engine()).with_scan_budget(Duration::ZERO);
        let start = Instant::now();
        let mut collector = YaraScanCollector::default();
        let mut findings: Vec<StructuralFinding> = Vec::new();
        let mut layers = 0usize;
        let mut skipped = 0usize;

        module.scan_decoded_attachment(
            "eicar.com",
            "application/octet-stream",
            EICAR,
            &start,
            &mut collector,
            &mut findings,
            &mut layers,
            &mut skipped,
        );

        assert_eq!(skipped, 1);
        assert!(
            collector.matches.is_empty(),
            "EICAR must not be scanned once the budget is spent"
        );
        assert!(findings.is_empty(), "inspection must not run either");
        assert_eq!(layers, 0);
        assert!(
            collector
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "email_scan_time_budget"),
            "budget exhaustion must be a visible coverage gap: {:?}",
            collector.coverage_gaps
        );
    }

    /// B5 counterpart: within budget, the root scan and inspection do run.
    #[test]
    fn within_budget_scans_attachment_root() {
        let module = YaraScanModule::new(make_engine());
        let start = Instant::now();
        let mut collector = YaraScanCollector::default();
        let mut findings: Vec<StructuralFinding> = Vec::new();
        let mut layers = 0usize;
        let mut skipped = 0usize;

        module.scan_decoded_attachment(
            "eicar.com",
            "application/octet-stream",
            EICAR,
            &start,
            &mut collector,
            &mut findings,
            &mut layers,
            &mut skipped,
        );

        assert_eq!(skipped, 0);
        assert!(
            collector
                .matches
                .iter()
                .any(|located| located.matched.rule_name.contains("EICAR")),
            "EICAR at attachment root must be scanned within budget"
        );
    }

    #[tokio::test]
    async fn unterminated_pdf_stream_is_safe_with_visible_coverage_metadata() {
        let module = YaraScanModule::new(make_engine());
        let malformed_pdf =
            b"%PDF-1.7\n1 0 obj\n<< /Length 999 >>\nstream\nordinary business text\n%%EOF\n";
        let ctx = SecurityContext::new(make_session(
            Some("Normal business email"),
            vec![make_attachment("notice.pdf", malformed_pdf)],
        ));

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
        assert!(result.evidence.iter().any(|evidence| {
            evidence.description.contains("unterminated_pdf_stream")
                && evidence.location.as_deref() == Some("attachment:notice.pdf:pdf_stream")
        }));
        assert_eq!(result.details["coverage_gaps"][0]["reason"], "unterminated_pdf_stream");
    }

    #[tokio::test]
    async fn test_within_budget_scans_all_attachments() {
        // Default 10s budget: small attachments are all scanned, nothing skipped.
        let module = YaraScanModule::new(make_engine());
        let ctx = SecurityContext::new(make_session(
            Some("Normal business email"),
            vec![
                make_attachment("notes.txt", b"quarterly report"),
                make_attachment("eicar.com", EICAR),
            ],
        ));
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.details["skipped_attachments"], 0);
        assert!(result.summary.contains("EICAR"));
    }
}
