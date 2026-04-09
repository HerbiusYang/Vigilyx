//! AttachmentTypedetectModule - CheckAttachmentextension, extension, MIME match, ByteAnd largeFile

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AttachScanModule {
    meta: ModuleMetadata,
}

impl Default for AttachScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachScanModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "attach_scan".to_string(),
                name: "AttachmentTypedetect".to_string(),
                description:
                    "CheckAttachmentextension、双extension、MIME 不matchAndAbnormallargesmall"
                        .to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "iso", "img", "hta", "msi", "dll", "com",
    "pif", "wsf", "wsh",
];

/// Expected MIME types for common extensions
fn expected_mime_for_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "pdf" => Some("application/pdf"),
        "doc" | "docx" => Some("application/"),
        "xls" | "xlsx" => Some("application/"),
        "ppt" | "pptx" => Some("application/"),
        "zip" => Some("application/zip"),
        "rar" => Some("application/"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "txt" => Some("text/plain"),
        "html" | "htm" => Some("text/html"),
        "csv" => Some("text/csv"),
        "exe" => Some("application/x-ms"),
        _ => None,
    }
}

const MAX_FILE_SIZE: usize = 25 * 1024 * 1024; // 25 MB

#[async_trait]
impl SecurityModule for AttachScanModule {
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
                "email无Attachment",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut dangerous_files: Vec<String> = Vec::new();

        for att in attachments {
            let filename_lower = att.filename.to_lowercase();

           // Extract last extension
            let last_ext = filename_lower.rsplit('.').next().unwrap_or("");

           // --- 1. Dangerous extension ---
            if DANGEROUS_EXTENSIONS.contains(&last_ext) {
                total_score += 0.35;
                categories.push("dangerous_extension".to_string());
                dangerous_files.push(att.filename.clone());
                evidence.push(Evidence {
                    description: format!("Dangerextension .{}: {}", last_ext, att.filename),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }

           // --- 2. Double extension ---
            let parts: Vec<&str> = filename_lower.split('.').collect();
            if parts.len() >= 3 {
               // The second-to-last extension exists and last extension is dangerous
                let second_ext = parts[parts.len() - 2];
                if DANGEROUS_EXTENSIONS.contains(&last_ext)
                    || DANGEROUS_EXTENSIONS.contains(&second_ext)
                {
                   // Only add if we haven't already flagged it as dangerous ext above
                    if !DANGEROUS_EXTENSIONS.contains(&last_ext) {
                        total_score += 0.30;
                        categories.push("double_extension".to_string());
                        dangerous_files.push(att.filename.clone());
                    }
                    evidence.push(Evidence {
                        description: format!(
                            "双extensiondetect: {} (.{}.{})",
                            att.filename, second_ext, last_ext
                        ),
                        location: Some(format!("attachment:{}", att.filename)),
                        snippet: None,
                    });
                }
            }

           // --- 3. MIME / extension mismatch ---
           // application/octet-stream General2Base/RadixType, emailclient DangerFileUse,
           // MIME match (Dangerextensionkeepdetect)
            if let Some(expected_prefix) = expected_mime_for_ext(last_ext) {
                let content_type_lower = att.content_type.to_lowercase();
                if !content_type_lower.starts_with(expected_prefix) {
                    let is_generic_octet =
                        content_type_lower.starts_with("application/octet-stream");
                    let is_dangerous_ext = DANGEROUS_EXTENSIONS.contains(&last_ext);

                    if is_generic_octet && !is_dangerous_ext {
                       // File octet-stream Normalline,hops
                    } else {
                        total_score += 0.20;
                        categories.push("mime_mismatch".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "MIME Type不match: extension .{} Period望 {} But实际  {}",
                                last_ext, expected_prefix, att.content_type
                            ),
                            location: Some(format!("attachment:{}", att.filename)),
                            snippet: None,
                        });
                    }
                }
            }

           // --- 4. Zero-byte file ---
            if att.size == 0 {
                total_score += 0.10;
                categories.push("zero_byte".to_string());
                evidence.push(Evidence {
                    description: format!("零ByteAttachment: {}", att.filename),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }

           // --- 5. Very large file (>25MB) ---
            if att.size > MAX_FILE_SIZE {
                total_score += 0.10;
                categories.push("oversized".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "超largeAttachment: {} ({:.1} MB)",
                        att.filename,
                        att.size as f64 / (1024.0 * 1024.0)
                    ),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "alreadyCheck {} Attachment，未FoundAbnormal",
                    attachments.len()
                ),
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.90,
            categories,
            summary: format!(
                "AttachmentTypedetectFound {} 处Abnormal，涉及File: {}",
                evidence.len(),
                dangerous_files.join(", ")
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "attachment_count": attachments.len(),
                "dangerous_files": dangerous_files,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}
