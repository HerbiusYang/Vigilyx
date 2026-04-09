//! Attachment antivirus scan module - scans email attachments using ClamAV.
//!
//! Decodes `content_base64` of each attachment independently and sends to ClamAV.
//! Attachments are scanned concurrently for high throughput.
//!
//! - Attachments >10MB without `content_base64` are skipped with evidence recorded.
//! - If any attachment is detected as infected, the verdict is immediately Critical.
//! - If ClamAV is unavailable, returns `not_applicable` (graceful degradation).

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::clamav::{ClamAvClient, ClamAvError, ScanResult};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AvAttachScanModule {
    meta: ModuleMetadata,
    client: Arc<ClamAvClient>,
}

impl AvAttachScanModule {
    pub fn new(client: Arc<ClamAvClient>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "av_attach_scan".to_string(),
                name: "Attachment Virus Scan".to_string(),
                description: "Scans each email attachment for virus signatures using ClamAV".to_string(),
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

/// Minimal base64 decoder (same approach as attach_content.rs / av_eml_scan.rs).
fn decode_base64_bytes(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &ch) in TABLE.iter().enumerate() {
        lookup[ch as usize] = i as u8;
    }

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        for (i, &b) in chunk.iter().enumerate() {
            let val = lookup[b as usize];
            if val == 255 {
                return None;
            }
            buf[i] = val;
        }

        if len >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Some(out)
}

/// Per-attachment scan result for evidence collection.
struct AttachmentScanOutcome {
    filename: String,
    size: usize,
    result: Result<ScanResult, ClamAvError>,
}

#[async_trait]
impl SecurityModule for AvAttachScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let attachments = &ctx.session.content.attachments;

        if attachments.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "Email has no attachments",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut infected_files: Vec<String> = Vec::new();
        let mut scanned_count: u32 = 0;
        let mut skipped_count: u32 = 0;
        let mut clamav_error = false;

       // Collect decodable attachments for concurrent scanning
        let mut scan_tasks = tokio::task::JoinSet::new();

        for att in attachments {
            if let Some(ref b64) = att.content_base64 {
                if let Some(decoded) = decode_base64_bytes(b64) {
                    let client = Arc::clone(&self.client);
                    let filename = att.filename.clone();
                    let size = decoded.len();

                    scan_tasks.spawn(async move {
                        let result = client.scan_bytes(&decoded).await;
                        AttachmentScanOutcome {
                            filename,
                            size,
                            result,
                        }
                    });
                } else {
                   // Base64 decode failed
                    skipped_count += 1;
                    evidence.push(Evidence {
                        description: format!(
                            "Attachment {} base64 decode failed, skipped virus scan",
                            att.filename
                        ),
                        location: Some(format!("attachment:{}", att.filename)),
                        snippet: None,
                    });
                }
            } else {
               // No content_base64 (>10MB)
                skipped_count += 1;
                evidence.push(Evidence {
                    description: format!(
                        "Attachment {} too large ({:.1} MB), no base64 data available, skipped virus scan",
                        att.filename,
                        att.size as f64 / (1024.0 * 1024.0)
                    ),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }
        }

       // Await all scan results
        while let Some(join_result) = scan_tasks.join_next().await {
            match join_result {
                Ok(outcome) => match outcome.result {
                    Ok(ScanResult::Clean) => {
                        scanned_count += 1;
                    }
                    Ok(ScanResult::Infected { virus_name }) => {
                        scanned_count += 1;
                        infected_files.push(outcome.filename.clone());
                        categories.push("virus_detected".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "Attachment {} ({} bytes) virus detected: {}",
                                outcome.filename, outcome.size, virus_name
                            ),
                            location: Some(format!("attachment:{}", outcome.filename)),
                            snippet: Some(virus_name),
                        });
                    }
                    Err(e) => {
                        clamav_error = true;
                        let err_msg = format!("{}", e);
                        warn!(
                            module = "av_attach_scan",
                            filename = %outcome.filename,
                            error = %err_msg,
                            "Attachment ClamAV scan failed"
                        );
                        evidence.push(Evidence {
                            description: format!(
                                "Attachment {} ClamAV scan failed: {}",
                                outcome.filename, err_msg
                            ),
                            location: Some(format!("attachment:{}", outcome.filename)),
                            snippet: None,
                        });
                    }
                },
                Err(join_err) => {
                    warn!(module = "av_attach_scan", error = %join_err, "Scan task panicked");
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

       // If ClamAV was completely unavailable (all scans failed, none succeeded)
        if clamav_error && scanned_count == 0 && infected_files.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "ClamAV unavailable, attachment virus scan skipped",
                duration_ms,
            ));
        }

       // All attachments were skipped (no content_base64, all>10MB)
        if scanned_count == 0 && infected_files.is_empty() && skipped_count > 0 {
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.0,
                categories: vec![],
                summary: format!(
                    "{} attachment(s) skipped virus scan due to large size, no scannable attachments",
                    skipped_count
                ),
                evidence,
                details: serde_json::json!({
                    "scanned_count": 0,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::vacuous()),
                engine_id: None,
            });
        }

       // If any attachment is infected -> Critical
        if !infected_files.is_empty() {
            categories.sort();
            categories.dedup();

            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Critical,
                confidence: 0.99,
                categories,
                summary: format!(
                    "Detected {} infected attachment(s): {}",
                    infected_files.len(),
                    infected_files.join(", ")
                ),
                evidence,
                details: serde_json::json!({
                    "infected_files": infected_files,
                    "scanned_count": scanned_count,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: None,
                engine_id: None,
            });
        }

       // All scanned attachments are clean
        Ok(ModuleResult::safe_analyzed(
            &self.meta.id,
            &self.meta.name,
            self.meta.pillar,
            &format!(
                "Scanned {} attachment(s), no viruses found{}",
                scanned_count,
                if skipped_count > 0 {
                    format!(" ({} skipped)", skipped_count)
                } else {
                    String::new()
                }
            ),
            duration_ms,
        ))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::models::{EmailAttachment, EmailContent, Protocol};

    fn make_session_with_attachments(
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
            headers: vec![
                ("From".to_string(), "test@example.com".to_string()),
                ("Subject".to_string(), "Test".to_string()),
            ],
            body_text: Some("body".to_string()),
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

    #[tokio::test]
    async fn test_no_attachments_returns_not_applicable() {
       // Use a client that will never be called (no attachments)
        let client = Arc::new(ClamAvClient::new("localhost".to_string(), 3310));
        let module = AvAttachScanModule::new(client);
        let ctx = crate::context::SecurityContext::new(make_session_with_attachments(vec![]));

        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.summary.contains("no attachments"));
    }

    #[tokio::test]
    async fn test_skip_large_attachment_without_base64() {
        let att = EmailAttachment {
            filename: "big.zip".to_string(),
            content_type: "application/zip".to_string(),
            size: 20_000_000,
            hash: "abc".to_string(),
            content_base64: None,
        };
       // Client won't connect (no scannable attachments) -> will be not_applicable
        let client = Arc::new(ClamAvClient::new("nonexistent-host".to_string(), 3310));
        let module = AvAttachScanModule::new(client);
        let ctx = crate::context::SecurityContext::new(make_session_with_attachments(vec![att]));

        let result = module.analyze(&ctx).await.unwrap();
       // All attachments were skipped, ClamAV never called -> not_applicable
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.description.contains("large"))
        );
    }

    #[test]
    fn test_decode_base64_roundtrip() {
        let result = decode_base64_bytes("SGVsbG8gV29ybGQ=");
        assert_eq!(result, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn test_decode_base64_no_padding() {
        let result = decode_base64_bytes("SGVsbG8");
        assert_eq!(result, Some(b"Hello".to_vec()));
    }
}
