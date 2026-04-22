//! EML antivirus scan module - scans the complete reconstructed EML using ClamAV.
//!
//! Reconstructs an RFC 2822 EML byte stream (headers + body + attachments) from
//! `EmailSession` and sends it to ClamAV via the INSTREAM protocol.
//!
//! - If ClamAV is unavailable or times out, returns `scan_incomplete` with a low
//!   suspicion score (BPA b=0.08) — NOT `not_applicable` / safe (CWE-636 fix).
//! - Attachments >10MB without `content_base64` are omitted from the EML stream.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::clamav::{ClamAvClient, ClamAvError, ScanResult};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AvEmlScanModule {
    meta: ModuleMetadata,
    client: Arc<ClamAvClient>,
}

impl AvEmlScanModule {
    pub fn new(client: Arc<ClamAvClient>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "av_eml_scan".to_string(),
                name: "Email virus scan".to_string(),
                description: "Scan complete EML for virus signatures using ClamAV".to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec![],
                timeout_ms: 30_000,
                is_remote: true,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            client,
        }
    }
}

#[async_trait]
impl SecurityModule for AvEmlScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

       // Reconstruct EML
        let eml_bytes = ctx.session.reconstruct_eml();
        if eml_bytes.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "Email content empty, cannot reconstruct EML",
                duration_ms,
            ));
        }

        let eml_size = eml_bytes.len();

       // Scan via ClamAV
        match self.client.scan_bytes(&eml_bytes).await {
            Ok(ScanResult::Clean) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                Ok(ModuleResult::safe_analyzed(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    &format!("EML virus scan passed ({} bytes)", eml_size),
                    duration_ms,
                ))
            }
            Ok(ScanResult::Infected { virus_name }) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                Ok(ModuleResult {
                    module_id: self.meta.id.clone(),
                    module_name: self.meta.name.clone(),
                    pillar: self.meta.pillar,
                    threat_level: ThreatLevel::Critical,
                    confidence: 0.99,
                    categories: vec!["virus_detected".to_string()],
                    summary: format!("Virus detected: {}", virus_name),
                    evidence: vec![Evidence {
                        description: format!(
                            "ClamAV detected virus signature in complete EML ({} bytes): {}",
                            eml_size, virus_name
                        ),
                        location: Some("eml:full".to_string()),
                        snippet: None,
                    }],
                    details: serde_json::json!({
                        "virus_name": virus_name,
                        "eml_size": eml_size,
                        "scan_type": "eml_full",
                    }),
                    duration_ms,
                    analyzed_at: Utc::now(),
                    bpa: None,
                    engine_id: None,
                })
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let err_msg = format!("{}", e);
                // F02 fix: Return scan_incomplete with non-zero suspicion instead
                // of not_applicable (vacuous BPA). ClamAV failure must not be
                // silently treated as "safe".
                warn!(
                    module = "av_eml_scan",
                    error = %err_msg,
                    eml_size,
                    "ClamAV unavailable — EML virus scan could not be completed, marking as incomplete"
                );
                let reason = match e {
                    ClamAvError::Timeout => "clamav_timeout",
                    _ => "clamav_unavailable",
                };
                Ok(ModuleResult {
                    module_id: self.meta.id.clone(),
                    module_name: self.meta.name.clone(),
                    pillar: self.meta.pillar,
                    threat_level: ThreatLevel::Low,
                    confidence: 0.10,
                    categories: vec!["scan_incomplete".to_string()],
                    summary: format!(
                        "Antivirus scan could not be completed — ClamAV {} (EML {} bytes)",
                        if reason == "clamav_timeout" { "timed out" } else { "unavailable" },
                        eml_size
                    ),
                    evidence: vec![Evidence {
                        description: format!(
                            "ClamAV EML scan failed: {} (EML {} bytes)",
                            err_msg, eml_size
                        ),
                        location: Some("eml:full".to_string()),
                        snippet: None,
                    }],
                    details: serde_json::json!({
                        "scan_status": "incomplete",
                        "reason": reason,
                        "eml_size": eml_size,
                    }),
                    duration_ms,
                    analyzed_at: Utc::now(),
                    bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
                    engine_id: None,
                })
            }
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_session(body: Option<&str>, attachments: Vec<EmailAttachment>) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            headers: vec![
                ("From".to_string(), "test@example.com".to_string()),
                ("To".to_string(), "user@company.com".to_string()),
                ("Subject".to_string(), "Test email".to_string()),
            ],
            body_text: body.map(|s| s.to_string()),
            body_html: None,
            attachments,
            links: vec![],
            raw_size: 1024,
            is_complete: true,
            is_encrypted: false,
            smtp_dialog: vec![],
        };
        session
    }

    #[test]
    fn test_reconstruct_eml_headers_and_body() {
        let session = make_session(Some("Hello world"), vec![]);
        let eml = session.reconstruct_eml();
        let eml_str = String::from_utf8_lossy(&eml);

        assert!(eml_str.contains("From: test@example.com\r\n"));
        assert!(eml_str.contains("Subject: Test email\r\n"));
        assert!(eml_str.contains("\r\n\r\n")); // header-body separator
        assert!(eml_str.contains("Hello world"));
    }

    #[test]
    fn test_reconstruct_eml_with_attachment() {
        let att = EmailAttachment {
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 5,
            hash: "abc123".to_string(),
            content_base64: Some("SGVsbG8=".to_string()), // "Hello"
        };
        let session = make_session(Some("body"), vec![att]);
        let eml = session.reconstruct_eml();

       // Should contain the decoded attachment bytes
        let eml_str = String::from_utf8_lossy(&eml);
        assert!(eml_str.contains("Hello"));
    }

    #[test]
    fn test_reconstruct_eml_skips_missing_base64() {
        let att = EmailAttachment {
            filename: "big.zip".to_string(),
            content_type: "application/zip".to_string(),
            size: 20_000_000,
            hash: "def456".to_string(),
            content_base64: None, // >10MB, no base64
        };
        let session = make_session(Some("body"), vec![att]);
        let eml = session.reconstruct_eml();

       // Should still produce valid output, just without the attachment binary
        let eml_str = String::from_utf8_lossy(&eml);
        assert!(eml_str.contains("body"));
    }

    #[test]
    fn test_reconstruct_eml_empty_content() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.headers.clear();
        let eml = session.reconstruct_eml();

       // Just the blank line separator
        assert_eq!(eml, b"\r\n");
    }
}
