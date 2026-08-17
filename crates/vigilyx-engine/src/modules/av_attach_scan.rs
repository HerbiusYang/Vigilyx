//! Attachment antivirus scan module - scans email attachments using ClamAV.
//!
//! Decodes `content_base64` of each attachment independently and sends to ClamAV.
//! Attachments are scanned concurrently for high throughput.
//!
//! - Attachments >10MB without `content_base64` are flagged as `scan_skipped_size_limit`
//!   with a low suspicion score (BPA b=0.08) — they are NOT marked as safe.
//! - If any attachment is detected as infected, the verdict is immediately Critical.
//! - If ClamAV is unavailable, returns `scan_incomplete` with a low suspicion score
//!   (BPA b=0.08) — NOT `not_applicable` / safe (CWE-636 fail-open prevention).
//! - A partial failure (some scans errored or panicked while others succeeded)
//!   also returns `scan_incomplete`: an errored attachment was never checked, so
//!   the email must not be presented as fully AV-clean (CWE-636).

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tracing::{info, warn};
use vigilyx_core::models::decode_base64_bytes_limited;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::clamav::{ClamAvClient, ClamAvError, ScanResult};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AvAttachScanModule {
    meta: ModuleMetadata,
    client: Arc<ClamAvClient>,
}

const MAX_ATTACHMENT_SCAN_BYTES: usize = 25 * 1024 * 1024;

impl AvAttachScanModule {
    pub fn new(client: Arc<ClamAvClient>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "av_attach_scan".to_string(),
                name: "Attachment Virus Scan".to_string(),
                description: "Scans each email attachment for virus signatures using ClamAV"
                    .to_string(),
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
        let mut error_count: u32 = 0;

        // Collect decodable attachments for concurrent scanning
        let mut scan_tasks = tokio::task::JoinSet::new();

        for att in attachments {
            if let Some(ref b64) = att.content_base64 {
                if att.size > MAX_ATTACHMENT_SCAN_BYTES {
                    skipped_count += 1;
                    evidence.push(Evidence {
                        description: format!(
                            "Attachment {} too large ({:.1} MB), skipped virus scan",
                            att.filename,
                            att.size as f64 / (1024.0 * 1024.0)
                        ),
                        location: Some(format!("attachment:{}", att.filename)),
                        snippet: None,
                    });
                } else if let Some(decoded) =
                    decode_base64_bytes_limited(b64, MAX_ATTACHMENT_SCAN_BYTES)
                {
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
                        error_count += 1;
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
                    // A panicked task means that attachment was never checked;
                    // count it as a scan error so the result cannot be Safe.
                    error_count += 1;
                    warn!(module = "av_attach_scan", error = %join_err, "Scan task panicked");
                    evidence.push(Evidence {
                        description: "Attachment scan task panicked — scan incomplete"
                            .to_string(),
                        location: None,
                        snippet: None,
                    });
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        // If ClamAV was completely unavailable (all scans failed, none succeeded)
        // F01 fix: Return scan_incomplete with non-zero suspicion instead of
        // not_applicable (vacuous BPA), so the verdict pipeline knows the scan
        // was NOT completed — not that the attachments are safe.
        if error_count > 0 && scanned_count == 0 && infected_files.is_empty() {
            warn!(
                module = "av_attach_scan",
                attachment_count = attachments.len(),
                "ClamAV unavailable — all attachment scans failed, marking as incomplete"
            );
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Low,
                confidence: 0.10,
                categories: vec!["scan_incomplete".to_string()],
                summary: format!(
                    "Antivirus scan could not be completed — ClamAV unavailable ({} attachment(s) not scanned)",
                    attachments.len()
                ),
                evidence,
                details: serde_json::json!({
                    "scan_status": "incomplete",
                    "reason": "clamav_unavailable",
                    "scanned_count": 0,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
                engine_id: None,
            });
        }

        // All attachments were skipped (no content_base64, all>10MB)
        // F03 fix: Return scan_skipped with non-zero suspicion instead of Safe.
        // Large attachments that bypass AV scanning represent unknown risk.
        if scanned_count == 0 && infected_files.is_empty() && skipped_count > 0 {
            info!(
                module = "av_attach_scan",
                skipped_count,
                total = attachments.len(),
                "All attachments exceed size limit for antivirus scanning, scan skipped"
            );
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Low,
                confidence: 0.10,
                categories: vec!["scan_skipped_size_limit".to_string()],
                summary: format!(
                    "{} attachment(s) exceed size limit for antivirus scanning (>10MB), scan skipped",
                    skipped_count
                ),
                evidence,
                details: serde_json::json!({
                    "scan_status": "skipped",
                    "reason": "attachments_exceed_size_limit",
                    "scanned_count": 0,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
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

        // F04 fix: some attachments scanned cleanly but at least one scan
        // errored (protocol/IO failure) or its task panicked. The errored
        // attachment was never actually checked, so the overall scan is
        // incomplete — never present a fully clean result over a coverage
        // gap (CWE-636; an attacker can deliberately induce per-stream
        // errors to smuggle an unscanned attachment past a clean one).
        if error_count > 0 {
            warn!(
                module = "av_attach_scan",
                error_count,
                scanned_count,
                "Some attachment scans failed alongside successful scans, marking scan as incomplete"
            );
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Low,
                confidence: 0.10,
                categories: vec!["scan_incomplete".to_string()],
                summary: format!(
                    "Scanned {} attachment(s) with no viruses found, but {} scan(s) failed — scan incomplete",
                    scanned_count, error_count
                ),
                evidence,
                details: serde_json::json!({
                    "scan_status": "incomplete",
                    "reason": "partial_scan_error",
                    "scanned_count": scanned_count,
                    "error_count": error_count,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
                engine_id: None,
            });
        }

        // Scanned attachments are clean, but some attachments bypassed AV
        // scanning (size limit or undecodable payload). A partially scanned
        // email must not be presented as a fully clean scan — keep a Low
        // scan_skipped_size_limit result so the verdict layer records the
        // coverage gap.
        if skipped_count > 0 {
            info!(
                module = "av_attach_scan",
                scanned_count,
                skipped_count,
                total = attachments.len(),
                "Some attachments exceed size limit for antivirus scanning, partial scan only"
            );
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Low,
                confidence: 0.10,
                categories: vec!["scan_skipped_size_limit".to_string()],
                summary: format!(
                    "Scanned {} attachment(s), no viruses found; {} attachment(s) skipped (size limit or undecodable), scan incomplete",
                    scanned_count, skipped_count
                ),
                evidence,
                details: serde_json::json!({
                    "scan_status": "partial",
                    "reason": "attachments_exceed_size_limit",
                    "scanned_count": scanned_count,
                    "skipped_count": skipped_count,
                    "total_attachments": attachments.len(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
                engine_id: None,
            });
        }

        // All scanned attachments are clean
        Ok(ModuleResult::safe_analyzed(
            &self.meta.id,
            &self.meta.name,
            self.meta.pillar,
            &format!(
                "Scanned {} attachment(s), no viruses found",
                scanned_count,
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
            truncated: false,
            dropped_attachments: 0,
            links_truncated: false,
            link_index: std::collections::HashSet::new(),
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
        // All attachments were skipped due to size -> scan_skipped (not Safe)
        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert!(
            result
                .categories
                .contains(&"scan_skipped_size_limit".to_string())
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.description.contains("large") || e.description.contains("too large"))
        );
    }

    /// Minimal clamd INSTREAM emulator: every scanned stream answers
    /// `stream: OK\0`. Lets tests reach the "scanned clean" code paths
    /// without a real ClamAV daemon.
    async fn spawn_mock_clamd() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock clamd");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Read the command (e.g. zINSTREAM) up to the NUL byte.
                    let mut byte = [0u8; 1];
                    while socket.read(&mut byte).await.unwrap_or(0) == 1 {
                        if byte[0] == 0 {
                            break;
                        }
                    }
                    // Read length-prefixed chunks until the zero terminator.
                    loop {
                        let mut len_buf = [0u8; 4];
                        if socket.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let mut remaining = u32::from_be_bytes(len_buf) as usize;
                        if remaining == 0 {
                            break;
                        }
                        let mut buf = [0u8; 4096];
                        while remaining > 0 {
                            let take = remaining.min(buf.len());
                            match socket.read(&mut buf[..take]).await {
                                Ok(0) => return,
                                Ok(n) => remaining -= n,
                                Err(_) => return,
                            }
                        }
                    }
                    let _ = socket.write_all(b"stream: OK\0").await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_partial_skip_oversized_attachment_is_not_safe() {
        // PoC bypass: one 26MB attachment exceeds the AV scan window while a
        // second small attachment scans clean. Previously the module
        // returned Safe, erasing the coverage gap from the verdict layer.
        let port = spawn_mock_clamd().await;
        let clean_att = EmailAttachment {
            filename: "notes.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 5,
            hash: "abc".to_string(),
            content_base64: Some("aGVsbG8=".to_string()),
        };
        let oversized_att = EmailAttachment {
            filename: "window.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 26 * 1024 * 1024,
            hash: "def".to_string(),
            content_base64: Some("aGVsbG8=".to_string()),
        };
        let client = Arc::new(ClamAvClient::new("127.0.0.1".to_string(), port));
        let module = AvAttachScanModule::new(client);
        let ctx = crate::context::SecurityContext::new(make_session_with_attachments(vec![
            clean_att,
            oversized_att,
        ]));

        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(
            result.threat_level,
            ThreatLevel::Low,
            "partial AV coverage must not be reported as Safe: {:?}",
            result.summary
        );
        assert!(
            result
                .categories
                .contains(&"scan_skipped_size_limit".to_string())
        );
        assert_eq!(result.details["scanned_count"], 1);
        assert_eq!(result.details["skipped_count"], 1);
    }

    /// Mock clamd where the first connection answers `stream: OK` and every
    /// later connection is dropped after reading the request (client sees an
    /// empty response -> `ClamAvError::ProtocolError`). Used to exercise the
    /// mixed clean+error coverage path.
    async fn spawn_flaky_clamd() -> u16 {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind flaky clamd");
        let port = listener.local_addr().expect("local addr").port();
        let conn_counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let seq = conn_counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // Read the command (e.g. zINSTREAM) up to the NUL byte.
                    let mut byte = [0u8; 1];
                    while socket.read(&mut byte).await.unwrap_or(0) == 1 {
                        if byte[0] == 0 {
                            break;
                        }
                    }
                    // Read length-prefixed chunks until the zero terminator.
                    loop {
                        let mut len_buf = [0u8; 4];
                        if socket.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let mut remaining = u32::from_be_bytes(len_buf) as usize;
                        if remaining == 0 {
                            break;
                        }
                        let mut buf = [0u8; 4096];
                        while remaining > 0 {
                            let take = remaining.min(buf.len());
                            match socket.read(&mut buf[..take]).await {
                                Ok(0) => return,
                                Ok(n) => remaining -= n,
                                Err(_) => return,
                            }
                        }
                    }
                    if seq == 0 {
                        let _ = socket.write_all(b"stream: OK\0").await;
                    }
                    // seq > 0: drop the connection without a response -> Err
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_mixed_scan_error_and_clean_is_not_safe() {
        // PoC bypass: one attachment scans clean while the second induces a
        // per-stream ClamAV error. Previously the module fell through to
        // Safe, presenting the errored (never-checked) attachment as clean.
        let port = spawn_flaky_clamd().await;
        let clean_att = EmailAttachment {
            filename: "notes.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 5,
            hash: "abc".to_string(),
            content_base64: Some("aGVsbG8=".to_string()),
        };
        let evil_att = EmailAttachment {
            filename: "invoice.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 5,
            hash: "def".to_string(),
            content_base64: Some("aGVsbG8=".to_string()),
        };
        let client = Arc::new(ClamAvClient::new("127.0.0.1".to_string(), port));
        let module = AvAttachScanModule::new(client);
        let ctx = crate::context::SecurityContext::new(make_session_with_attachments(vec![
            clean_att,
            evil_att,
        ]));

        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(
            result.threat_level,
            ThreatLevel::Low,
            "mixed clean+error AV coverage must not be reported as Safe: {:?}",
            result.summary
        );
        assert!(result.categories.contains(&"scan_incomplete".to_string()));
        assert_eq!(result.details["scan_status"], "incomplete");
        assert_eq!(result.details["scanned_count"], 1);
        assert_eq!(result.details["error_count"], 1);
    }

    #[test]
    fn test_decode_base64_roundtrip() {
        let result = decode_base64_bytes_limited("SGVsbG8gV29ybGQ=", MAX_ATTACHMENT_SCAN_BYTES);
        assert_eq!(result, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn test_decode_base64_no_padding() {
        let result = decode_base64_bytes_limited("SGVsbG8", MAX_ATTACHMENT_SCAN_BYTES);
        assert_eq!(result, Some(b"Hello".to_vec()));
    }
}
