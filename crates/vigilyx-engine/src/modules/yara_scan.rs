//! YARA Rule Module - EML + AttachmentExecuteline YARA Rulematch.

//! ClamAV:ClamAV Use Sign detectalready,
//! YARA Use ofmodeRuledetectMaliciousDocumentation, Executeline, APT And.

//! CPU-bound module — the orchestrator runs `analyze()` inside `spawn_blocking`
//! when `cpu_bound = true`, so no inner `spawn_blocking` is needed here.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use vigilyx_core::models::{decode_base64_bytes, EmailSession};

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::yara::engine::{YaraEngine, YaraMatch};

pub struct YaraScanModule {
    meta: ModuleMetadata,
    engine: Arc<YaraEngine>,
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
        let mut matches: Vec<YaraMatch> = Vec::new();

        // 1. Scan message headers/body only. Attachments are scanned separately
        // below so their raw bytes keep their original container context.
        let eml = reconstruct_yara_eml(&ctx.session);
        if !eml.is_empty() {
            matches.extend(self.engine.scan(&eml));
        }

        // 2. Scan attachments (may match different rules than the EML envelope)
        for att in &ctx.session.content.attachments {
            if let Some(ref b64) = att.content_base64
                && let Some(decoded) = decode_base64_bytes(b64)
            {
                let att_matches = self.engine.scan(&decoded);
                for m in att_matches {
                    // Deduplicate: same rule name
                    if !matches
                        .iter()
                        .any(|existing| existing.rule_name == m.rule_name)
                    {
                        matches.push(m);
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        if matches.is_empty() {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "YARA 扫描complete，{} ItemRuleAll未命Medium",
                    self.engine.rule_count()
                ),
                duration_ms,
            ));
        }

       // match - Build evidence And categories
        let mut categories: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();
        let mut max_threat = ThreatLevel::Low;
        let mut rule_names: Vec<String> = Vec::new();

        for m in &matches {
            let threat = severity_to_threat(&m.severity);
            if threat > max_threat {
                max_threat = threat;
            }

            if !m.category.is_empty() && !categories.contains(&m.category) {
                categories.push(m.category.clone());
            }
            categories.push("yara_match".to_string());

            rule_names.push(m.rule_name.clone());

            evidence.push(Evidence {
                description: format!("YARA Rule {} 命Medium: {}", m.rule_name, m.description),
                location: Some(format!("yara:{}", m.rule_name)),
                snippet: Some(format!("[{}] severity={}", m.category, m.severity)),
            });
        }

        categories.sort();
        categories.dedup();

       // According tomatchType:
       // - executable_disguise / malware_family / webshell: Malicious,High
       // - malicious_document: Documentation High (Normal Excel table Contains VBA),downgradeLow
        let has_high_confidence_match = categories
            .iter()
            .any(|c| c == "executable_disguise" || c == "malware_family" || c == "webshell");
        let confidence = if max_threat >= ThreatLevel::Critical && has_high_confidence_match {
            0.98
        } else if max_threat >= ThreatLevel::Critical {
            0.85 // Critical But malicious_document Class
        } else if max_threat >= ThreatLevel::High && has_high_confidence_match {
            0.90
        } else if max_threat >= ThreatLevel::High {
            0.70 // High But malicious_document - Documentation of FP High
        } else {
            0.65
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level: max_threat,
            confidence,
            categories,
            summary: format!(
                "YARA 命Medium {} ItemRule: {}",
                matches.len(),
                rule_names.join(", ")
            ),
            evidence,
            details: serde_json::json!({
                "matched_rules": rule_names,
                "match_count": matches.len(),
                "total_rules": self.engine.rule_count(),
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
    use base64::Engine as _;
    use crate::pipeline::context::SecurityContext;
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
        let ctx = SecurityContext::new(make_session(Some("Normal business email"), vec![attachment]));
        let result = module.analyze(&ctx).await.unwrap();
        assert!(
            !result.summary.contains("Mal_IcedID_BokBot"),
            "PDF lure content should not match IcedID via reconstructed EML: {}",
            result.summary
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }
}
