//! Email header analysis module - checks From/Reply-To domain mismatch, date anomalies,
//! missing Message-ID, header injection, SPF/DMARC failures, etc.
//! Also checks IPs found in Received chain:
//! 1. Local IOC lookup
//! 2. External intel query: OTX + VT Scrape + AbuseIPDB (per IP)
//! 3. Skips IPs already marked verdict=clean in IOC cache

mod checks;
mod intel;
mod parsed;

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::db_service::DbQueryService;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{
    Bpa, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};

pub struct HeaderScanModule {
    meta: ModuleMetadata,
    db: Arc<dyn DbQueryService>,
    intel: Option<IntelLayer>,
}

impl HeaderScanModule {
    pub fn new(db: Arc<dyn DbQueryService>, intel: Option<IntelLayer>) -> Self {
       // Increase timeout when intel is enabled: IP queries run in parallel with 10s per-IP timeout
        let has_intel = intel.is_some();
        let timeout_ms = if has_intel { 12000 } else { 3000 };

        Self {
            db,
            intel,
            meta: ModuleMetadata {
                id: "header_scan".to_string(),
                name: "Email header analysis".to_string(),
                description:
                    "Detect domain mismatch, date anomalies, header injection, SPF/DMARC failures in email headers"
                        .to_string(),
                pillar: Pillar::Package,
                depends_on: vec![],
                timeout_ms,
                is_remote: has_intel,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None, // I/O-bound: DB IOC queries + external intel
            },
        }
    }
}

#[async_trait]
impl SecurityModule for HeaderScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // --- Step 0: Extract all header data in a single pass ---
        let parsed = parsed::ParsedHeaders::extract(
            &ctx.session.content.headers,
            &ctx.session.client_ip,
            ctx.session.mail_from.as_deref(),
            ctx.session.content.is_complete,
            &|d| ctx.is_internal_domain(d),
        );

        // Fold in injection findings from the extraction pass
        total_score += parsed.injection_score;
        categories.extend(parsed.injection_categories.iter().cloned());
        evidence.extend(parsed.injection_evidence.iter().cloned());

        // --- Step 1: From / Reply-To domain mismatch ---
        checks::check_domain_mismatch(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 1b: Envelope spoofing ---
        checks::check_envelope_spoofing(
            &parsed,
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // --- Step 1c: SPF/DKIM/DMARC Authentication-Results ---
        checks::check_auth_results(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 2+3: Date anomaly + Missing Message-ID ---
        checks::check_date_anomaly(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 4: Suspicious X-Mailer ---
        checks::check_suspicious_mailer(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 5: Received chain analysis ---
        checks::check_received_chain(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 5b: Real-time domain impersonation (homoglyph + TLD swap) ---
        let impersonation_hit = checks::check_domain_impersonation(ctx, &mut total_score, &mut categories, &mut evidence);

        // --- Step 5c: Known impersonation IOC lookup ---
        // If the sender domain was previously recorded as a domain_impersonation IOC,
        // boost the score directly (self-learning: detect once → auto-record → future instant match).
        // Uses find_ioc() (includes source=auto) so auto-recorded impersonation IOCs are matched.
        let mut known_impersonation_target: Option<String> = None;
        if impersonation_hit.is_none()
            && let Some(sender_domain) = ctx.session.mail_from.as_deref().and_then(parsed::extract_domain)
            && let Ok(Some(ioc)) = self.db.find_ioc("domain", &sender_domain).await
            && ioc.attack_type == "domain_impersonation" && ioc.verdict != "clean"
        {
            let score_add = (ioc.confidence * 0.4).min(0.35);
            total_score += score_add;
            categories.push("known_impersonation_domain".to_string());
            evidence.push(crate::module::Evidence {
                description: format!(
                    "Sender domain '{}' is a known impersonation domain (IOC confidence={:.0}%, target={})",
                    sender_domain,
                    ioc.confidence * 100.0,
                    ioc.context.as_deref().unwrap_or("unknown"),
                ),
                location: Some("headers:MAIL_FROM".to_string()),
                snippet: Some(sender_domain.clone()),
            });
            // Extract target domain from IOC context for details
            known_impersonation_target = ioc.context.as_ref().and_then(|c| {
                c.split("target=").nth(1).map(|s| {
                    s.split([',', ' ', '|']).next().unwrap_or(s).to_string()
                })
            });
        }

        // --- Step 6: Received IP IOC lookup (local) ---
        let ioc_checked_ips = intel::query_ioc_ips(
            &parsed.received_ips,
            &self.db,
            &mut total_score,
            &mut categories,
            &mut evidence,
        )
        .await;

        // --- Step 7: Received IP external intel query ---
        // Skip IPs already checked in Step 6 to prevent double scoring
        if let Some(ref intel_layer) = self.intel
            && !parsed.received_ips.is_empty()
        {
            intel::query_external_intel(
                &parsed.received_ips,
                intel_layer,
                &ioc_checked_ips,
                &mut total_score,
                &mut categories,
                &mut evidence,
            )
            .await;
        }

        // --- Finalize ---
        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

       // Build summary describing what was analyzed and the outcome
        let summary = if threat_level == ThreatLevel::Safe {
            if parsed.received_ips.is_empty() {
                "Email header check passed, no anomalies found".to_string()
            } else {
                let intel_status = if self.intel.is_some() {
                    "queried external intel (OTX/VT/AbuseIPDB)"
                } else {
                    "local IOC check only"
                };
                format!(
                    "Email header check passed, analyzed {} sender IPs ({})",
                    parsed.received_ips.len(),
                    intel_status,
                )
            }
        } else {
            format!(
                "Email header analysis found {} anomalies, composite score {:.2}",
                evidence
                    .iter()
                    .filter(|e| {
                       // Only count anomaly evidence, exclude clean IP reputation entries
                        !e.description.contains("reputation clean")
                    })
                    .count(),
                total_score
            )
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: if threat_level == ThreatLevel::Safe {
                0.85
            } else {
                0.80
            },
            categories,
            summary,
            evidence,
            details: {
                let mut d = serde_json::json!({
                    "score": total_score,
                    "received_count": parsed.received_count,
                    "received_ips": parsed.received_ips,
                    "intel_enabled": self.intel.is_some(),
                });
                // Include impersonation hit info for post_verdict IOC auto-recording
                if let Some(ref hit) = impersonation_hit {
                    d["impersonation_hit"] = serde_json::json!({
                        "sender_domain": hit.sender_domain,
                        "target_domain": hit.target_domain,
                        "similarity_type": hit.similarity_type,
                        "score": hit.score,
                    });
                }
                // Include known impersonation IOC hit for audit trail
                if let Some(ref target) = known_impersonation_target {
                    d["known_impersonation_ioc_target"] = serde_json::json!(target);
                }
                d
            },
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(if threat_level == ThreatLevel::Safe {
                Bpa::safe_analyzed()
            } else {
                Bpa::from_score_confidence(total_score, 0.80)
            }),
            engine_id: None,
        })
    }
}
