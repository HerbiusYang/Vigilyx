//! Attachment type detection module — checks attachment extension, double extension,
//! MIME mismatch, magic bytes cross-validation, and abnormal sizes.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tracing::{info, warn};
use vigilyx_core::magic_bytes::{
    self, DetectedFileType, detect_file_type, is_encrypted_archive, is_encrypted_pdf,
    is_high_risk_disguise,
};
use vigilyx_core::models::decode_base64_bytes;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

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
                name: "Attachment Type Detection".to_string(),
                description:
                    "Check attachment extension, double extension, MIME mismatch, magic bytes cross-validation, and abnormal size"
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

/// Score penalty for high-risk disguise (executable masquerading as document/image)
const SCORE_HIGH_RISK_DISGUISE: f64 = 0.30;
/// Score penalty for general type mismatch (non-dangerous, e.g., RTF claimed as TXT)
const SCORE_GENERAL_MISMATCH: f64 = 0.15;
/// Score penalty for encrypted archives that hide inner payloads from inspection
const SCORE_ENCRYPTED_ARCHIVE: f64 = 0.18;
/// Score penalty for password-protected PDFs that hide active content / lures
const SCORE_ENCRYPTED_PDF: f64 = 0.12;

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

fn mime_matches_expected_type(ext: &str, content_type: &str, expected_prefix: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with(expected_prefix) {
        return true;
    }

    if ext == "csv" {
        return ct.starts_with("text/comma-separated-values")
            || ct.starts_with("application/csv")
            || ct.starts_with("application/vnd.ms-excel")
            || ct.starts_with("text/plain");
    }

    false
}

/// Check if a Content-Type is generic/ambiguous (should not trigger mismatch)
fn is_generic_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("application/octet-stream")
        || ct.starts_with("application/x-download")
        || ct.starts_with("binary/octet-stream")
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
                "No attachments in email",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut dangerous_files: Vec<String> = Vec::new();

        for att in attachments {
            let filename_lower = att.filename.to_lowercase();

            // Extract last extension (only if filename contains a dot).
            // Handles edge cases:
            //   - "inline" (Content-Disposition: inline, no filename) → empty ext
            //     Without this guard, "inline" becomes the "extension" and magic-bytes
            //     cross-validation reports "claims to be .inline but is actually PNG"
            //     for every inline image — 7 images × 0.15 = 1.05 → Critical false positive.
            //   - MIME-encoded filenames with leftover terminators, e.g. "report.pdf?="
            //     → strip non-alphanumeric tail so ext becomes "pdf", not "pdf?=".
            let ext_owned: String = if filename_lower.contains('.') {
                let raw = filename_lower.rsplit('.').next().unwrap_or("");
                raw.chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect()
            } else {
                String::new()
            };
            let last_ext = ext_owned.as_str();

           // --- 1. Dangerous extension ---
            if module_data().contains("dangerous_extensions", last_ext) {
                total_score += 0.35;
                categories.push("dangerous_extension".to_string());
                dangerous_files.push(att.filename.clone());
                evidence.push(Evidence {
                    description: format!("Dangerous extension .{}: {}", last_ext, att.filename),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }

           // --- 2. Double extension ---
            let parts: Vec<&str> = filename_lower.split('.').collect();
            if parts.len() >= 3 {
               // The second-to-last extension exists and last extension is dangerous
                let second_ext = parts[parts.len() - 2];
                if module_data().contains("dangerous_extensions", last_ext)
                    || module_data().contains("dangerous_extensions", second_ext)
                {
                   // Only add if we haven't already flagged it as dangerous ext above
                    if !module_data().contains("dangerous_extensions", last_ext) {
                        total_score += 0.30;
                        categories.push("double_extension".to_string());
                        dangerous_files.push(att.filename.clone());
                    }
                    evidence.push(Evidence {
                        description: format!(
                            "Double extension detected: {} (.{}.{})",
                            att.filename, second_ext, last_ext
                        ),
                        location: Some(format!("attachment:{}", att.filename)),
                        snippet: None,
                    });
                }
            }

           // --- 3. MIME / extension mismatch ---
            if let Some(expected_prefix) = expected_mime_for_ext(last_ext) {
                let content_type_lower = att.content_type.to_lowercase();
                if !mime_matches_expected_type(last_ext, &content_type_lower, expected_prefix) {
                    let is_generic = is_generic_content_type(&att.content_type);
                    let is_dangerous_ext = module_data().contains("dangerous_extensions", last_ext);

                    if is_generic && !is_dangerous_ext {
                       // Generic octet-stream for non-dangerous files is normal
                    } else {
                        total_score += 0.20;
                        categories.push("mime_mismatch".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "MIME type mismatch: extension .{} expected {} but got {}",
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
                    description: format!("Zero-byte attachment: {}", att.filename),
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
                        "Oversized attachment: {} ({:.1} MB)",
                        att.filename,
                        att.size as f64 / (1024.0 * 1024.0)
                    ),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: None,
                });
            }

           // --- 6. Magic bytes cross-validation ---
            if let Some(ref b64) = att.content_base64
                && let Some(bytes) = decode_base64_bytes(b64)
            {
                let magic_result = analyze_magic_bytes(
                    &bytes,
                    &att.filename,
                    last_ext,
                    &att.content_type,
                );
                total_score += magic_result.score;
                if !magic_result.categories.is_empty() {
                    categories.extend(magic_result.categories);
                    dangerous_files.push(att.filename.clone());
                }
                evidence.extend(magic_result.evidence);

                let encrypted_result =
                    analyze_encrypted_container(&bytes, &att.filename, last_ext, &att.content_type);
                total_score += encrypted_result.score;
                if !encrypted_result.categories.is_empty() {
                    categories.extend(encrypted_result.categories);
                    dangerous_files.push(att.filename.clone());
                }
                evidence.extend(encrypted_result.evidence);
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
                    "Checked {} attachment(s), no abnormalities found",
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
                "Attachment scan found {} issue(s) in file(s): {}",
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

// ─────────────────────────────────────────────────────────────────────────────
// Magic bytes cross-validation
// ─────────────────────────────────────────────────────────────────────────────

/// Result of magic bytes analysis for a single attachment
struct MagicBytesResult {
    score: f64,
    categories: Vec<String>,
    evidence: Vec<Evidence>,
}

/// Analyze attachment binary content against its claimed extension and Content-Type.
///
/// Whitelist rules (no penalty):
/// - `application/octet-stream` — generic, can be anything
/// - ZIP-based Office formats: .docx/.xlsx/.pptx are ZIP files (normal)
/// - `text/plain` for CSV, TSV, XML, JSON, YAML (Content-Type doesn't distinguish)
/// - Attachments smaller than 4 bytes (insufficient data for signature detection)
fn analyze_magic_bytes(
    data: &[u8],
    filename: &str,
    ext: &str,
    content_type: &str,
) -> MagicBytesResult {
    let mut result = MagicBytesResult {
        score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
    };

    // Too small to determine file type reliably
    if data.len() < 4 {
        return result;
    }

    let detected = match detect_file_type(data) {
        Some(ft) => ft,
        None => return result,
    };

    // --- Whitelist: skip penalty for known benign combinations ---

    // application/octet-stream is generic — any actual type is acceptable
    if is_generic_content_type(content_type) && !detected.is_executable() {
        return result;
    }

    // ZIP-based Office formats: .docx/.xlsx/.pptx are ZIP archives (normal)
    if detected == DetectedFileType::ZipArchive
        && matches!(ext, "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "jar" | "apk" | "epub")
    {
        return result;
    }

    // text/plain variants: CSV, JSON, XML, etc. are all detected as PlainText
    if detected == DetectedFileType::PlainText && module_data().contains("text_plain_compatible_extensions", ext) {
        return result;
    }

    // PlainText and UnknownBinary: cannot meaningfully cross-validate
    if matches!(
        detected,
        DetectedFileType::PlainText | DetectedFileType::UnknownBinary
    ) {
        return result;
    }

    // --- Cross-validation: check if actual type matches claimed extension ---

    // No extension → no claim to validate (e.g. "inline" from Content-Disposition: inline).
    // Without a claimed extension there is nothing to cross-validate against magic bytes.
    if ext.is_empty() {
        return result;
    }

    let expected_exts = detected.expected_extensions();
    if expected_exts.is_empty() || expected_exts.contains(&ext) {
        // Extension matches detected type — no mismatch
        // But check for HTML smuggling: HTML with scripts disguised as .html is still suspicious
        // if it contains embedded JavaScript payloads. However, that check belongs in html_scan.
        return result;
    }

    // Mismatch detected! Determine severity.
    if is_high_risk_disguise(detected, ext) {
        // High-risk: executable/script/installer masquerading as document/image
        result.score = SCORE_HIGH_RISK_DISGUISE;
        result.categories.push("executable_disguise".to_string());
        warn!(
            filename = filename,
            actual_type = detected.display_name(),
            claimed_ext = ext,
            "High-risk file type disguise detected: {} is actually {}",
            filename,
            detected.display_name()
        );
        result.evidence.push(Evidence {
            description: format!(
                "Executable disguise: {} claims to be .{} but is actually {} (magic bytes)",
                filename, ext, detected.display_name()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });

        // Additional check: HTML smuggling (HTML with scripts disguised as non-HTML)
        if detected == DetectedFileType::HtmlDocument && magic_bytes::html_has_scripts(data) {
            result.score += 0.10; // extra penalty for active smuggling content
            result.categories.push("html_smuggling".to_string());
            result.evidence.push(Evidence {
                description: format!(
                    "HTML smuggling: {} disguised as .{} contains embedded <script> tags",
                    filename, ext
                ),
                location: Some(format!("attachment:{}", filename)),
                snippet: None,
            });
        }
    } else {
        // General mismatch: non-dangerous but still suspicious
        result.score = SCORE_GENERAL_MISMATCH;
        result.categories.push("type_mismatch".to_string());
        info!(
            filename = filename,
            actual_type = detected.display_name(),
            claimed_ext = ext,
            "File type mismatch: {} claimed as .{} but detected as {}",
            filename,
            ext,
            detected.display_name()
        );
        result.evidence.push(Evidence {
            description: format!(
                "Type mismatch: {} claims to be .{} but is actually {} (magic bytes)",
                filename, ext, detected.display_name()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    result
}

fn analyze_encrypted_container(
    data: &[u8],
    filename: &str,
    ext: &str,
    content_type: &str,
) -> MagicBytesResult {
    let mut result = MagicBytesResult {
        score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
    };

    let detected = detect_file_type(data);
    let content_type_lower = content_type.to_ascii_lowercase();
    let looks_like_archive = matches!(
        detected,
        Some(
            DetectedFileType::ZipArchive
                | DetectedFileType::RarArchive
                | DetectedFileType::SevenZipArchive
        )
    ) || matches!(ext, "zip" | "rar" | "7z")
        || content_type_lower.contains("zip")
        || content_type_lower.contains("rar")
        || content_type_lower.contains("7z");
    let looks_like_pdf = detected == Some(DetectedFileType::Pdf)
        || ext == "pdf"
        || content_type_lower.contains("pdf");

    if looks_like_archive && is_encrypted_archive(data) {
        result.score += SCORE_ENCRYPTED_ARCHIVE;
        result.categories.push("encrypted_attachment".to_string());
        result.categories.push("encrypted_archive".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Encrypted archive attachment blocks inner payload inspection: {}",
                filename
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    if looks_like_pdf && is_encrypted_pdf(data) {
        result.score += SCORE_ENCRYPTED_PDF;
        result.categories.push("encrypted_attachment".to_string());
        result.categories.push("encrypted_pdf".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Password-protected PDF attachment blocks deep content inspection: {}",
                filename
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::models::EmailAttachment;

    /// Helper: build a base64-encoded attachment for testing
    #[allow(dead_code)]
    fn make_attachment(filename: &str, content_type: &str, data: &[u8]) -> EmailAttachment {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        EmailAttachment {
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            size: data.len(),
            hash: "test_hash".to_string(),
            content_base64: Some(b64),
        }
    }

    /// Helper: run magic bytes analysis directly
    fn run_magic_check(filename: &str, content_type: &str, data: &[u8]) -> MagicBytesResult {
        let ext = filename.to_lowercase();
        let ext = ext.rsplit('.').next().unwrap_or("");
        analyze_magic_bytes(data, filename, ext, content_type)
    }

    fn run_encrypted_check(filename: &str, content_type: &str, data: &[u8]) -> MagicBytesResult {
        let ext = filename.to_lowercase();
        let ext = ext.rsplit('.').next().unwrap_or("");
        analyze_encrypted_container(data, filename, ext, content_type)
    }

    // ─── Detection tests ───

    #[test]
    fn test_detect_pe_magic() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        let result = run_magic_check("setup.exe", "application/x-msdownload", &data);
        // PE with correct extension: no mismatch
        assert_eq!(result.score, 0.0);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_detect_pdf_magic() {
        let data = b"%PDF-1.4 something here";
        let result = run_magic_check("document.pdf", "application/pdf", data);
        assert_eq!(result.score, 0.0);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_detect_zip_magic() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00, 0x00, 0x00];
        let result = run_magic_check("archive.zip", "application/zip", &data);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_encrypted_zip_attachment_is_flagged() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        let result = run_encrypted_check("payload.zip", "application/zip", &data);
        assert!(
            (result.score - SCORE_ENCRYPTED_ARCHIVE).abs() < f64::EPSILON,
            "encrypted zip should score {}, got {}",
            SCORE_ENCRYPTED_ARCHIVE,
            result.score
        );
        assert!(result.categories.contains(&"encrypted_archive".to_string()));
        assert!(result.categories.contains(&"encrypted_attachment".to_string()));
    }

    #[test]
    fn test_password_protected_pdf_is_flagged() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\n";
        let result = run_encrypted_check("secure.pdf", "application/pdf", data);
        assert!(
            (result.score - SCORE_ENCRYPTED_PDF).abs() < f64::EPSILON,
            "encrypted pdf should score {}, got {}",
            SCORE_ENCRYPTED_PDF,
            result.score
        );
        assert!(result.categories.contains(&"encrypted_pdf".to_string()));
        assert!(result.categories.contains(&"encrypted_attachment".to_string()));
    }

    // ─── High-risk disguise tests ───

    #[test]
    fn test_exe_disguised_as_pdf() {
        // PE executable with .pdf extension → high-risk +0.30
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        let result = run_magic_check("report.pdf", "application/pdf", &data);
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
            "EXE disguised as PDF should score {}, got {}",
            SCORE_HIGH_RISK_DISGUISE,
            result.score
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
    }

    #[test]
    fn test_exe_disguised_as_jpg() {
        // PE executable with .jpg extension → high-risk +0.30
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        let result = run_magic_check("photo.jpg", "image/jpeg", &data);
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
            "EXE disguised as JPG should score {}, got {}",
            SCORE_HIGH_RISK_DISGUISE,
            result.score
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
    }

    #[test]
    fn test_elf_disguised_as_png() {
        // ELF binary with .png extension → high-risk
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let result = run_magic_check("image.png", "image/png", &data);
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
    }

    // ─── Whitelist tests (should NOT flag) ───

    #[test]
    fn test_zip_based_docx_no_flag() {
        // .docx is a ZIP archive — this is normal, should NOT flag
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00, 0x00, 0x00];
        let result = run_magic_check(
            "report.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            &data,
        );
        assert_eq!(result.score, 0.0, "ZIP-based docx should not be flagged");
        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_text_plain_csv_no_flag() {
        // CSV files are detected as PlainText — text/plain is expected
        let data = b"name,email,phone\nJohn,john@test.com,12345\n";
        let result = run_magic_check("contacts.csv", "text/plain", data);
        assert_eq!(
            result.score, 0.0,
            "text/plain for CSV should not be flagged"
        );
    }

    #[test]
    fn csv_mime_aliases_are_accepted() {
        assert!(mime_matches_expected_type(
            "csv",
            "text/comma-separated-values",
            "text/csv"
        ));
        assert!(mime_matches_expected_type(
            "csv",
            "application/vnd.ms-excel",
            "text/csv"
        ));
        assert!(mime_matches_expected_type("csv", "text/plain", "text/csv"));
    }

    #[test]
    fn test_octet_stream_no_flag() {
        // application/octet-stream is generic — should not flag for non-executable
        let data = b"%PDF-1.4 document content here padded out";
        let result = run_magic_check("document.pdf", "application/octet-stream", data);
        assert_eq!(
            result.score, 0.0,
            "application/octet-stream for non-executable should not be flagged"
        );
    }

    // ─── Edge cases ───

    #[test]
    fn test_empty_attachment_graceful() {
        // Empty attachment — zero bytes, cannot determine type
        let result = run_magic_check("empty.pdf", "application/pdf", &[]);
        assert_eq!(result.score, 0.0, "Empty data should not cause errors");
    }

    #[test]
    fn test_very_small_attachment() {
        // Less than 4 bytes — insufficient for signature detection
        let result = run_magic_check("tiny.pdf", "application/pdf", &[0x25, 0x50]);
        assert_eq!(
            result.score, 0.0,
            "Data < 4 bytes should be skipped gracefully"
        );
    }

    // ─── Script and HTML smuggling tests ───

    #[test]
    fn test_script_disguised_as_document() {
        // Script (shebang) disguised as .docx → high-risk
        let data = b"#!/bin/bash\nrm -rf / --no-preserve-root\n# padding padding padding";
        let result = run_magic_check("report.docx", "application/octet-stream", data);
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
            "Script disguised as docx should score {}, got {}",
            SCORE_HIGH_RISK_DISGUISE,
            result.score
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
    }

    #[test]
    fn test_php_script_disguised_as_jpg() {
        // PHP script disguised as .jpg → high-risk
        let data = b"<?php echo shell_exec($_GET['cmd']); ?> padding for length test data";
        let result = run_magic_check("photo.jpg", "image/jpeg", data);
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
    }

    #[test]
    fn test_html_smuggling_disguised_as_pdf() {
        // HTML with <script> tags disguised as .pdf → high-risk + html_smuggling
        let data = b"<!DOCTYPE html><html><body><script>var a=atob('TVqQ');var b=new Blob([a]);</script></body></html>";
        let result = run_magic_check("invoice.pdf", "application/pdf", data);
        assert!(
            result.score >= SCORE_HIGH_RISK_DISGUISE,
            "HTML smuggling disguised as PDF should score >= {}, got {}",
            SCORE_HIGH_RISK_DISGUISE,
            result.score
        );
        assert!(result.categories.contains(&"executable_disguise".to_string()));
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "Should detect HTML smuggling"
        );
    }

    #[test]
    fn test_html_as_html_no_flag() {
        // Normal HTML file with .html extension — should NOT flag
        let data = b"<!DOCTYPE html><html><head><title>Hello</title></head><body>World</body></html>";
        let result = run_magic_check("page.html", "text/html", data);
        assert_eq!(result.score, 0.0, "HTML with .html extension should not be flagged");
    }

    // ─── General mismatch tests ───

    #[test]
    fn test_general_mismatch_rtf_as_txt() {
        // RTF file with .txt extension — general mismatch +0.15 (not high-risk)
        let mut data = Vec::from(b"{\\rtf1\\ansi This is an RTF document." as &[u8]);
        data.extend_from_slice(&[b' '; 100]); // pad to ensure text heuristic works
        let result = run_magic_check("notes.txt", "text/plain", &data);
        assert!(
            (result.score - SCORE_GENERAL_MISMATCH).abs() < f64::EPSILON,
            "RTF disguised as TXT should score {}, got {}",
            SCORE_GENERAL_MISMATCH,
            result.score
        );
        assert!(result.categories.contains(&"type_mismatch".to_string()));
    }

    #[test]
    fn test_pdf_disguised_as_jpg_general_mismatch() {
        // PDF with .jpg extension — general mismatch (PDF is not an executable)
        let data = b"%PDF-1.4 document content here padded out a bit more";
        let result = run_magic_check("photo.jpg", "image/jpeg", data);
        assert!(
            (result.score - SCORE_GENERAL_MISMATCH).abs() < f64::EPSILON,
            "PDF disguised as JPG is general mismatch (not executable), score should be {}, got {}",
            SCORE_GENERAL_MISMATCH,
            result.score
        );
        assert!(result.categories.contains(&"type_mismatch".to_string()));
    }

    // ─── P0-1/P0-2: Extension extraction regression tests ───

    /// Helper: reproduce the production extension extraction logic (lines 122-140)
    fn extract_extension(filename: &str) -> String {
        let filename_lower = filename.to_lowercase();
        if filename_lower.contains('.') {
            let raw = filename_lower.rsplit('.').next().unwrap_or("");
            raw.chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect()
        } else {
            String::new()
        }
    }

    #[test]
    fn test_ext_inline_without_dot_yields_empty() {
        // P0-1: "inline" from Content-Disposition: inline has no dot
        // → must yield empty extension, not "inline" as extension
        assert_eq!(
            extract_extension("inline"),
            "",
            "Filename 'inline' (no dot) should yield empty extension"
        );
    }

    #[test]
    fn test_ext_gbk_encoded_pdf_with_mime_residue() {
        // P0-2: GBK-encoded filename with MIME terminator leftover:
        // "=?gbk?B?...?=.pdf?=" → last segment is "pdf?="
        // take_while(alphanumeric) strips the "?=" → "pdf"
        assert_eq!(
            extract_extension("report.pdf?="),
            "pdf",
            "MIME residue '?=' should be stripped from extension"
        );
    }

    #[test]
    fn test_ext_normal_filename_unchanged() {
        assert_eq!(extract_extension("document.pdf"), "pdf");
        assert_eq!(extract_extension("photo.JPG"), "jpg"); // lowercased
        assert_eq!(extract_extension("archive.tar.gz"), "gz");
    }

    #[test]
    fn test_ext_no_extension_yields_empty() {
        // Files without any dot: README, Makefile, etc.
        assert_eq!(extract_extension("README"), "");
        assert_eq!(extract_extension("Makefile"), "");
    }

    #[test]
    fn test_ext_dot_only_yields_empty() {
        // Edge case: filename is just a dot
        assert_eq!(extract_extension("."), "");
        // Hidden file with no real extension
        assert_eq!(extract_extension(".gitignore"), "gitignore");
    }

    #[test]
    fn test_inline_png_no_type_mismatch() {
        // P0-1 integration: "inline" filename + PNG magic bytes should NOT trigger
        // type_mismatch. Previously yielded ext="inline" → mismatch with PNG magic.
        let png_magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let ext = extract_extension("inline");
        assert_eq!(ext, "", "ext must be empty for 'inline'");
        // Empty extension → analyze_magic_bytes should not flag mismatch
        let result = analyze_magic_bytes(&png_magic, "inline", &ext, "image/png");
        assert_eq!(
            result.score, 0.0,
            "inline PNG should not trigger type_mismatch, got score={} cats={:?}",
            result.score, result.categories
        );
    }
}
