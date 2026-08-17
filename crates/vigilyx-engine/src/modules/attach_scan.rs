//! Attachment type detection module — checks attachment extension, double extension,
//! MIME mismatch, magic bytes cross-validation, and abnormal sizes.

use std::io::Cursor;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tracing::{info, warn};
use unicode_normalization::UnicodeNormalization;
use vigilyx_core::magic_bytes::{
    self, DetectedFileType, detect_file_type, is_encrypted_archive, is_encrypted_pdf,
    is_high_risk_disguise,
};
use vigilyx_core::models::decode_base64_bytes_limited;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::content_scan::html_utils::decode_html_entities;

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
/// Encrypted containers are an inspection-coverage limitation, not malicious
/// evidence by themselves.  They are surfaced to the UI and to the MTA
/// delivery policy, but deliberately contribute zero threat score here.

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

    // Mail gateways commonly serialize ZIP parts with one of these
    // standards-compatible aliases.  Treating them as a mismatch creates a
    // payload cluster for an otherwise ordinary archive (and is especially
    // noisy for vendor questionnaires and code bundles).
    if ext == "zip"
        && matches!(
            ct.as_str(),
            "application/x-zip-compressed" | "application/x-zip" | "multipart/x-zip"
        )
    {
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
        let mut coverage_limited_files: Vec<String> = Vec::new();
        let mut ocr_unavailable_count = 0usize;

        for att in attachments {
            // NFKC-fold the filename before any extension logic: fullwidth
            // dots (U+FF0E invoice．exe), one-dot leaders (U+2024) and other
            // compatibility lookalikes otherwise hide the real extension from
            // both the dangerous-extension list and double-extension checks.
            let filename_lower: String = att.filename.nfkc().collect::<String>().to_lowercase();

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
            if att.size > MAX_FILE_SIZE {
                continue;
            }
            if let Some(ref b64) = att.content_base64
                && let Some(bytes) = decode_base64_bytes_limited(b64, MAX_FILE_SIZE)
            {
                let magic_result =
                    analyze_magic_bytes(&bytes, &att.filename, last_ext, &att.content_type);
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
                    let coverage_limited = encrypted_result.categories.iter().any(|category| {
                        matches!(
                            category.as_str(),
                            "attachment_inspection_limited"
                                | "encrypted_archive"
                                | "encrypted_pdf"
                        )
                    });
                    categories.extend(encrypted_result.categories);
                    if coverage_limited {
                        coverage_limited_files.push(att.filename.clone());
                    }
                }
                evidence.extend(encrypted_result.evidence);

                let opaque_result = analyze_opaque_container(&bytes, &att.filename);
                total_score += opaque_result.score;
                if !opaque_result.categories.is_empty() {
                    // analyze_opaque_container only ever returns coverage-gap
                    // categories (score 0), so any hit is coverage-limited.
                    coverage_limited_files.push(att.filename.clone());
                    categories.extend(opaque_result.categories);
                }
                evidence.extend(opaque_result.evidence);

                let active_result = analyze_active_content(
                    &bytes,
                    &att.filename,
                    last_ext,
                    &att.content_type,
                );
                total_score += active_result.score;
                if active_result
                    .categories
                    .iter()
                    .any(|category| category == "active_content")
                {
                    dangerous_files.push(att.filename.clone());
                }
                categories.extend(active_result.categories);
                evidence.extend(active_result.evidence);
                if active_result.ocr_unavailable {
                    ocr_unavailable_count += 1;
                }
            } else if att.content_type.to_ascii_lowercase().starts_with("image/") {
                // Metadata-only image attachments are still a coverage gap;
                // never present them as fully inspected.
                ocr_unavailable_count += 1;
                categories.push("ocr_unavailable".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Image attachment text was not OCR-scanned (content unavailable): {}",
                        att.filename
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

        if threat_level == ThreatLevel::Safe && evidence.is_empty() {
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

        let has_coverage_only = total_score == 0.0 && dangerous_files.is_empty();
        let summary = if has_coverage_only {
            if coverage_limited_files.is_empty() {
                format!(
                    "Checked {} attachment(s); no threat indicators found",
                    attachments.len()
                )
            } else {
                format!(
                    "Checked {} attachment(s); inner payload inspection unavailable for: {}",
                    attachments.len(),
                    coverage_limited_files.join(", ")
                )
            }
        } else if coverage_limited_files.is_empty() {
            format!(
                "Attachment scan found {} threat issue(s) in file(s): {}",
                evidence.len(),
                dangerous_files.join(", ")
            )
        } else {
            format!(
                "Attachment scan found {} threat issue(s); inspection limited for: {}",
                evidence.len(),
                coverage_limited_files.join(", ")
            )
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: if has_coverage_only { 0.35 } else { 0.90 },
            categories,
            summary,
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "attachment_count": attachments.len(),
                "dangerous_files": dangerous_files,
                "coverage_limited_files": coverage_limited_files,
                "ocr_unavailable_count": ocr_unavailable_count,
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
        && matches!(
            ext,
            "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "jar" | "apk" | "epub"
        )
    {
        return result;
    }

    // text/plain variants: CSV, JSON, XML, etc. are all detected as PlainText
    if detected == DetectedFileType::PlainText
        && module_data().contains("text_plain_compatible_extensions", ext)
    {
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

    // No extension → nothing to cross-validate against. But an executable or
    // script payload delivered without any extension claim is itself an
    // evasion (Windows runs a renamed PE regardless of the filename), so the
    // magic verdict still scores. Benign types (images, documents) keep the
    // old no-claim behavior — e.g. "inline" images from
    // Content-Disposition: inline must not become type-mismatch findings.
    if ext.is_empty() {
        if detected.is_executable() {
            result.score = SCORE_HIGH_RISK_DISGUISE;
            result.categories.push("executable_disguise".to_string());
            warn!(
                filename = filename,
                actual_type = detected.display_name(),
                "Executable attachment delivered with no file extension: {} is actually {}",
                filename,
                detected.display_name()
            );
            result.evidence.push(Evidence {
                description: format!(
                    "Executable without extension: {} has no file extension but is actually {} (magic bytes)",
                    filename,
                    detected.display_name()
                ),
                location: Some(format!("attachment:{}", filename)),
                snippet: None,
            });
        }
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
                filename,
                ext,
                detected.display_name()
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
                filename,
                ext,
                detected.display_name()
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
        result.categories
            .push("attachment_inspection_limited".to_string());
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
        result.categories
            .push("attachment_inspection_limited".to_string());
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

/// Opaque container formats we can recognise but not decode (TNEF winmail.dat,
/// AppleSingle/AppleDouble). Their payload is invisible to every content
/// scanner, so — exactly like an encrypted archive — this is a coverage gap
/// signal (score 0), not a threat verdict.
fn analyze_opaque_container(data: &[u8], filename: &str) -> MagicBytesResult {
    let mut result = MagicBytesResult {
        score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
    };

    let container_name = match detect_file_type(data) {
        Some(DetectedFileType::Tnef) => "TNEF (winmail.dat)",
        Some(DetectedFileType::AppleSingle) => "AppleSingle",
        Some(DetectedFileType::AppleDouble) => "AppleDouble",
        _ => return result,
    };

    result
        .categories
        .push("attachment_inspection_limited".to_string());
    result.categories.push("unsupported_container".to_string());
    result.evidence.push(Evidence {
        description: format!(
            "{} container attachment cannot be decoded; inner payload not inspected: {}",
            container_name, filename
        ),
        location: Some(format!("attachment:{}", filename)),
        snippet: None,
    });

    result
}

struct ActiveContentResult {
    score: f64,
    categories: Vec<String>,
    evidence: Vec<Evidence>,
    ocr_unavailable: bool,
}

fn contains_ascii_ci(data: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || data.len() < needle.len() {
        return false;
    }
    data.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
    })
}

fn pdf_name_token_positions(data: &[u8], name: &[u8]) -> Vec<usize> {
    if name.is_empty() || data.len() < name.len() {
        return Vec::new();
    }

    data.windows(name.len())
        .enumerate()
        .filter_map(|(idx, window)| {
            if window != name {
                return None;
            }
            let before_ok = idx == 0 || is_pdf_name_delimiter(data[idx - 1]);
            let after = idx + name.len();
            let after_ok = after == data.len() || is_pdf_name_delimiter(data[after]);
            if before_ok && after_ok {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn is_pdf_name_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(byte, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'{' | b'}' | b'%')
}

/// Detect PDF active-action names as actual PDF name tokens rather than loose
/// byte substrings.  In particular, `/aa` inside ordinary text must not turn a
/// scanned PDF into an active-content finding.
///
/// Matching runs on the `#hh`-decoded view (ISO 32000 §7.3.5) so
/// `/Op#65nAction` / `/J#61vaScript` spellings cannot hide active content.
fn detect_pdf_active_actions(data: &[u8]) -> (bool, bool) {
    let data = magic_bytes::normalize_pdf_name_escapes(data);
    let data = data.as_ref();
    let has_javascript = !pdf_name_token_positions(data, b"/JavaScript").is_empty()
        || !pdf_name_token_positions(data, b"/JS").is_empty();
    // /GoToE (embedded-document navigation), /RichMedia, /Collection and
    // /Rendition are the PDF-portfolio primitives used to auto-open a bundled
    // malicious document on view — no engine layer covered them before.
    let has_direct_action = [
        b"/OpenAction".as_slice(),
        b"/Launch",
        b"/SubmitForm",
        b"/GoToR",
        b"/GoToE",
        b"/RichMedia",
        b"/Collection",
        b"/Rendition",
    ]
    .iter()
    .any(|name| !pdf_name_token_positions(data, name).is_empty());

    let has_additional_action = pdf_name_token_positions(data, b"/AA")
        .into_iter()
        .any(|offset| {
            let window_end = (offset + 512).min(data.len());
            let window = &data[offset..window_end];
            [b"/JavaScript".as_slice(), b"/JS", b"/Launch", b"/SubmitForm"]
                .iter()
                .any(|name| !pdf_name_token_positions(window, name).is_empty())
        });

    (has_javascript, has_direct_action || has_additional_action)
}

/// Match `atob` payload-decoding invocations that plain `atob(` substring
/// matching misses: whitespace before the parenthesis (`atob (`) and the
/// string-literal dynamic form `"atob"` / `'atob'` (e.g. `window["atob"]`).
fn contains_atob_invocation(data: &[u8]) -> bool {
    if contains_ascii_ci(data, b"\"atob\"") || contains_ascii_ci(data, b"'atob'") {
        return true;
    }
    let needle: &[u8] = b"atob";
    if data.len() < needle.len() {
        return false;
    }
    data.windows(needle.len()).enumerate().any(|(idx, window)| {
        if !window
            .iter()
            .zip(needle)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        {
            return false;
        }
        let mut j = idx + needle.len();
        while j < data.len() && data[j].is_ascii_whitespace() {
            j += 1;
        }
        j < data.len() && data[j] == b'('
    })
}

/// Lightweight, read-only static inspection for active content that ordinary
/// document text extraction intentionally ignores. It does not execute code;
/// it only records evidence for macros, PDF actions/JavaScript and HTML
/// smuggling indicators. Full sandbox/ClamAV analysis remains asynchronous.
fn analyze_active_content(
    data: &[u8],
    filename: &str,
    ext: &str,
    content_type: &str,
) -> ActiveContentResult {
    let mut result = ActiveContentResult {
        score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
        ocr_unavailable: false,
    };
    let detected = detect_file_type(data);
    let location = || Some(format!("attachment:{filename}"));

    if matches!(detected, Some(DetectedFileType::Jpeg | DetectedFileType::Png | DetectedFileType::Gif | DetectedFileType::Bmp | DetectedFileType::Tiff))
        || content_type.to_ascii_lowercase().starts_with("image/")
    {
        result.ocr_unavailable = true;
        result.categories.push("ocr_unavailable".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Image attachment was not OCR-scanned; text embedded in the image is not covered: {filename}"
            ),
            location: location(),
            snippet: None,
        });
    }

    let mut macro_detected = false;
    if detected == Some(DetectedFileType::ZipArchive) {
        if let Ok(archive) = zip::ZipArchive::new(Cursor::new(data)) {
            macro_detected = archive.file_names().any(|name| {
                let lower = name.to_ascii_lowercase();
                lower.ends_with("vbaproject.bin")
                    || lower.ends_with("vba_project.bin")
                    || lower.contains("/macros/")
                    || lower.contains("/activex/")
            });
        }
    } else if detected == Some(DetectedFileType::OleCompound) {
        macro_detected = contains_ascii_ci(data, b"vba")
            || contains_ascii_ci(data, b"_vba_project")
            || contains_ascii_ci(data, b"macros")
            || contains_ascii_ci(data, b"dir\0");
    }
    if macro_detected {
        result.score += 0.35;
        result.categories.push("office_macro".to_string());
        result.categories.push("active_content".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Office active content signature detected (VBA/ActiveX metadata); code was not executed: {filename}"
            ),
            location: location(),
            snippet: None,
        });
    }

    if detected == Some(DetectedFileType::Pdf) || ext == "pdf" {
        let (has_js, has_action) = detect_pdf_active_actions(data);
        if has_js || has_action {
            result.score += if has_js { 0.25 } else { 0.15 };
            result.categories.push("pdf_active_content".to_string());
            result.categories.push("active_content".to_string());
            result.evidence.push(Evidence {
                description: format!(
                    "PDF contains JavaScript or an automatic action; content was not executed: {filename}"
                ),
                location: location(),
                snippet: None,
            });
        }
    }

    let is_html = matches!(detected, Some(DetectedFileType::HtmlDocument | DetectedFileType::ScriptText))
        || matches!(ext, "html" | "htm" | "xhtml" | "hta")
        || content_type.to_ascii_lowercase().contains("text/html");
    if is_html && vigilyx_core::magic_bytes::html_has_scripts(data) {
        // Token matching also runs on the entity-decoded view so spellings
        // like `d&#97;ta:` or `&#97;tob(` cannot hide smuggling indicators.
        let decoded = decode_html_entities(&String::from_utf8_lossy(data));
        let contains_ci = |needle: &[u8]| {
            contains_ascii_ci(data, needle) || contains_ascii_ci(decoded.as_bytes(), needle)
        };
        let smuggling = contains_ci(b"document.write")
            || contains_ci(b"createobjecturl")
            || contains_atob_invocation(data)
            || contains_atob_invocation(decoded.as_bytes())
            || contains_ci(b"msSaveOrOpenBlob")
            // Anchor-tag HTML smuggling without Blob/URL APIs: a `download`
            // attribute + `data:` URI + programmatic `.click()` reconstructs
            // the payload entirely through the anchor element.
            || (contains_ci(b"data:") && contains_ci(b"download") && contains_ci(b".click("));
        result.score += if smuggling { 0.30 } else { 0.12 };
        result.categories.push("html_active_content".to_string());
        if smuggling {
            result.categories.push("html_smuggling".to_string());
        }
        result.categories.push("active_content".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "HTML attachment contains embedded script{}; scripts were not executed: {filename}",
                if smuggling { " and payload-reconstruction indicators" } else { "" }
            ),
            location: location(),
            snippet: None,
        });
    }

    if detected == Some(DetectedFileType::Rtf)
        && (contains_ascii_ci(data, b"\\object") || contains_ascii_ci(data, b"\\objdata"))
    {
        result.score += 0.15;
        result.categories.push("rtf_embedded_object".to_string());
        result.categories.push("active_content".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "RTF contains an embedded object; object was not executed: {filename}"
            ),
            location: location(),
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
    use unicode_normalization::UnicodeNormalization;
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

    // ─── Opaque container coverage-gap tests ───

    #[test]
    fn test_tnef_winmail_dat_is_coverage_gap() {
        // TNEF magic: 78 9F 3E 22 — recognisable but undecodable container.
        let data = [0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00, 0x01, 0x00];
        let result = analyze_opaque_container(&data, "winmail.dat");
        assert_eq!(result.score, 0.0, "coverage gap must not add threat score");
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
        assert!(
            result
                .categories
                .contains(&"unsupported_container".to_string())
        );
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_appledouble_is_coverage_gap() {
        // AppleDouble magic: 00 05 16 07
        let data = [0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00];
        let result = analyze_opaque_container(&data, "._invoice.pdf");
        assert_eq!(result.score, 0.0);
        assert!(
            result
                .categories
                .contains(&"unsupported_container".to_string())
        );
    }

    #[test]
    fn test_applesingle_is_coverage_gap() {
        // AppleSingle magic: 00 05 16 00
        let data = [0x00, 0x05, 0x16, 0x00, 0x00, 0x02, 0x00, 0x00];
        let result = analyze_opaque_container(&data, "invoice.pdf");
        assert_eq!(result.score, 0.0);
        assert!(
            result
                .categories
                .contains(&"unsupported_container".to_string())
        );
    }

    #[test]
    fn test_regular_attachment_is_not_opaque_container() {
        let data = b"%PDF-1.4 normal document";
        let result = analyze_opaque_container(data, "document.pdf");
        assert!(result.categories.is_empty());
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_uuencode_disguised_as_txt_is_flagged() {
        // Valid uuencode frame: "begin 644 x.exe" + one data line ("!``" =
        // 1 payload byte 0x00) + zero-length line + end. Detected as Uuencode
        // while claiming .txt → type mismatch.
        let data = b"begin 644 x.exe\n!``\n`\nend\n";
        let result = run_magic_check("report.txt", "text/plain", data);
        assert!(
            result.categories.contains(&"type_mismatch".to_string()),
            "uuencode payload disguised as .txt must be flagged: {:?}",
            result.categories
        );
        assert!(result.score >= SCORE_GENERAL_MISMATCH);
    }

    #[test]
    fn test_uuencode_with_uue_extension_is_not_mismatch() {
        let data = b"begin 644 x.exe\n!``\n`\nend\n";
        let result = run_magic_check("payload.uue", "text/plain", data);
        assert_eq!(result.score, 0.0);
        assert!(result.categories.is_empty());
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
    fn test_pdf_plain_text_does_not_trigger_short_aa_token() {
        let data = b"%PDF-1.7\n1 0 obj\n(regular text /aa marker)\nendobj\n";
        let result = analyze_active_content(data, "scan.pdf", "pdf", "application/pdf");
        assert!(!result.categories.contains(&"pdf_active_content".to_string()));
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_pdf_javascript_name_is_active_content() {
        let data = b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n";
        let result = analyze_active_content(data, "payload.pdf", "pdf", "application/pdf");
        assert!(result.categories.contains(&"pdf_active_content".to_string()));
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(result.score >= 0.25);
    }

    #[test]
    fn test_encrypted_zip_attachment_is_flagged() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        let result = run_encrypted_check("payload.zip", "application/zip", &data);
        assert_eq!(result.score, 0.0, "coverage-only evidence must not score as threat");
        assert!(result.categories.contains(&"encrypted_archive".to_string()));
        assert!(
            result
                .categories
                .contains(&"encrypted_attachment".to_string())
        );
        assert!(result
            .categories
            .contains(&"attachment_inspection_limited".to_string()));
    }

    #[test]
    fn test_password_protected_pdf_is_flagged() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\n";
        let result = run_encrypted_check("secure.pdf", "application/pdf", data);
        assert_eq!(result.score, 0.0, "coverage-only evidence must not score as threat");
        assert!(result.categories.contains(&"encrypted_pdf".to_string()));
        assert!(
            result
                .categories
                .contains(&"encrypted_attachment".to_string())
        );
        assert!(result
            .categories
            .contains(&"attachment_inspection_limited".to_string()));
    }

    #[test]
    fn test_prefix_junk_pdf_disguised_as_jpg_is_flagged() {
        // PoC bypass: junk prefix moves %PDF- off offset 0; previously the
        // magic-bytes check could not see the real type at all.
        let mut data = vec![b'X'; 48];
        data.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\n");
        let result = run_magic_check("photo.jpg", "image/jpeg", &data);
        assert!(
            (result.score - SCORE_GENERAL_MISMATCH).abs() < f64::EPSILON,
            "prefix-junk PDF disguised as JPG should score {}, got {}",
            SCORE_GENERAL_MISMATCH,
            result.score
        );
        assert!(result.categories.contains(&"type_mismatch".to_string()));
    }

    #[test]
    fn test_prefix_junk_encrypted_pdf_with_trailer_encrypt_is_flagged() {
        // PoC bypass: %PDF- inside the 1024-byte window + /Encrypt only in
        // the trailing trailer (past the first 4 KiB).
        let mut data = vec![b'J'; 32];
        data.extend_from_slice(b"%PDF-1.7\n");
        data.extend_from_slice(&vec![b'x'; 8192]);
        data.extend_from_slice(b"trailer\n<< /Root 1 0 R /Encrypt 9 0 R >>\n%%EOF\n");
        let result = run_encrypted_check("secure.pdf", "application/pdf", &data);
        assert!(result.categories.contains(&"encrypted_pdf".to_string()));
        assert!(result
            .categories
            .contains(&"attachment_inspection_limited".to_string()));
    }

    #[test]
    fn test_whitespace_prefixed_rtf_as_txt_is_flagged() {
        // PoC bypass: leading whitespace before {\rtf previously defeated
        // offset-0 RTF detection, hiding the type mismatch.
        let mut data = Vec::from(b"\r\n  {\\rtf1\\ansi attacker payload" as &[u8]);
        data.extend_from_slice(&[b' '; 100]);
        let result = run_magic_check("notes.txt", "text/plain", &data);
        assert!(
            (result.score - SCORE_GENERAL_MISMATCH).abs() < f64::EPSILON,
            "whitespace-prefixed RTF disguised as TXT should score {}, got {}",
            SCORE_GENERAL_MISMATCH,
            result.score
        );
        assert!(result.categories.contains(&"type_mismatch".to_string()));
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
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
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
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
    }

    #[test]
    fn test_elf_disguised_as_png() {
        // ELF binary with .png extension → high-risk
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let result = run_magic_check("image.png", "image/png", &data);
        assert!((result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,);
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
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
    fn zip_mime_aliases_are_accepted() {
        for alias in [
            "application/x-zip-compressed",
            "application/x-zip",
            "multipart/x-zip",
        ] {
            assert!(
                mime_matches_expected_type("zip", alias, "application/zip"),
                "ZIP MIME alias should be accepted: {alias}"
            );
        }
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
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
    }

    #[test]
    fn test_php_script_disguised_as_jpg() {
        // PHP script disguised as .jpg → high-risk
        let data = b"<?php echo shell_exec($_GET['cmd']); ?> padding for length test data";
        let result = run_magic_check("photo.jpg", "image/jpeg", data);
        assert!((result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,);
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
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
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "Should detect HTML smuggling"
        );
    }

    #[test]
    fn test_html_as_html_no_flag() {
        // Normal HTML file with .html extension — should NOT flag
        let data =
            b"<!DOCTYPE html><html><head><title>Hello</title></head><body>World</body></html>";
        let result = run_magic_check("page.html", "text/html", data);
        assert_eq!(
            result.score, 0.0,
            "HTML with .html extension should not be flagged"
        );
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

    #[test]
    fn test_new_dangerous_extensions_are_seeded() {
        // PoC bypass: these script/MMC/macro-enabled extensions were missing
        // from the dangerous_extensions seed list, so attachments using them
        // sailed through with zero score.
        for ext in [
            "xlm",
            "msc",
            "sct",
            "wsc",
            "application",
            "appref-ms",
            "ppsm",
            "sldm",
            "xltm",
            "library-ms",
            "searchconnector-ms",
            "diagcab",
        ] {
            assert!(
                module_data().contains("dangerous_extensions", ext),
                ".{ext} must be present in the dangerous_extensions seed list"
            );
        }
    }

    /// Helper: reproduce the production extension extraction logic, including
    /// the NFKC folding that defuses fullwidth-dot lookalikes (U+FF0E etc.).
    fn extract_extension(filename: &str) -> String {
        let filename_lower = filename.nfkc().collect::<String>().to_lowercase();
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
    fn test_pdf_hash_escaped_active_content_detected() {
        // PoC bypass: ISO 32000 name escapes spell /OpenAction and
        // /JavaScript as /Op#65nAction / /J#61vaScript, which previously
        // slipped past the raw PDF token search.
        let data = b"%PDF-1.7\n<< /Op#65nAction << /S /J#61vaScript /J#53 (app.alert(1)) >> >>\n";
        let result = analyze_active_content(data, "payload.pdf", "pdf", "application/pdf");
        assert!(
            result.categories.contains(&"pdf_active_content".to_string()),
            "#hh-escaped PDF action names must be detected: {:?}",
            result.categories
        );
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(result.score >= 0.25);
    }

    #[test]
    fn test_pdf_hash_escape_does_not_invent_actions() {
        // Literal '#' content that is not a name escape must not fabricate
        // active-content findings.
        let data = b"%PDF-1.7\n(issue #45 resolved; see ticket #6162)\n";
        let result = analyze_active_content(data, "notes.pdf", "pdf", "application/pdf");
        assert!(!result.categories.contains(&"pdf_active_content".to_string()));
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_ext_fullwidth_dot_lookalike_extracted() {
        // PoC bypass: U+FF0E (fullwidth full stop) hides the extension —
        // "invoice．exe" previously yielded no extension at all.
        assert_eq!(extract_extension("invoice．exe"), "exe");
        // U+2024 ONE DOT LEADER is another compatibility dot.
        assert_eq!(extract_extension("invoice․scr"), "scr");
    }

    #[test]
    fn test_extensionless_executable_magic_scores() {
        // PoC bypass: PE bytes in an attachment with no extension claim
        // previously scored zero because there was "nothing to validate".
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        let result = analyze_magic_bytes(&data, "payload", "", "application/octet-stream");
        assert!(
            (result.score - SCORE_HIGH_RISK_DISGUISE).abs() < f64::EPSILON,
            "extensionless executable should score {}, got {}",
            SCORE_HIGH_RISK_DISGUISE,
            result.score
        );
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );

        // Extensionless ELF too.
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let result = analyze_magic_bytes(&elf, "runme", "", "application/octet-stream");
        assert!(
            result
                .categories
                .contains(&"executable_disguise".to_string())
        );
    }

    #[test]
    fn test_extensionless_benign_image_still_clean() {
        // Guard: an extension-less PNG (e.g. inline image) must not start
        // scoring just because the empty-extension branch changed.
        let png_magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = analyze_magic_bytes(&png_magic, "inline", "", "image/png");
        assert_eq!(result.score, 0.0);
        assert!(result.categories.is_empty());
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

    #[test]
    fn test_pdf_portfolio_navigation_tokens_detected() {
        // PoC bypass: PDF portfolios auto-navigate into an embedded document
        // via /Collection + /GoToE; none of the previously covered action
        // tokens fired, so the portfolio scored zero.
        let data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Collection 5 0 R >>\nendobj\n2 0 obj\n<< /S /GoToE /D (invoice.docx) >>\nendobj\n";
        let result = analyze_active_content(data, "portfolio.pdf", "pdf", "application/pdf");
        assert!(
            result.categories.contains(&"pdf_active_content".to_string()),
            "/Collection + /GoToE must be detected: {:?}",
            result.categories
        );
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(result.score >= 0.15);
    }

    #[test]
    fn test_html_smuggling_anchor_download_click_detected() {
        // PoC bypass: anchor-tag smuggling with a `download` attribute +
        // `data:` URI + programmatic `.click()` uses no Blob/URL APIs and
        // matched none of the literal indicators.
        let data = b"<!DOCTYPE html><html><body><a id=\"f\" download=\"invoice.exe\"></a><script>var a=document.getElementById(\"f\");a.href=\"data:application/octet-stream;base64,TVqQAAAA\";a.click();</script></body></html>";
        let result = analyze_active_content(data, "invoice.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "anchor download+click smuggling must be detected: {:?}",
            result.categories
        );
        assert!(result.score >= 0.30);
    }

    #[test]
    fn test_html_smuggling_atob_invocation_variants_detected() {
        // PoC bypass: `atob (` (whitespace before paren) and the dynamic
        // window["atob"] form did not match the literal `atob(` indicator.
        let spaced = b"<!DOCTYPE html><html><body><script>var p=atob (\"TVqQAAAA\");</script></body></html>";
        let result = analyze_active_content(spaced, "a.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "spaced atob call must be detected: {:?}",
            result.categories
        );

        let dynamic = b"<!DOCTYPE html><html><body><script>var p=window[\"atob\"](\"TVqQAAAA\");</script></body></html>";
        let result = analyze_active_content(dynamic, "b.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "dynamic atob call must be detected: {:?}",
            result.categories
        );

        // Entity-encoded atob must not hide either.
        let encoded = b"<!DOCTYPE html><html><body><script>var p=&#97;tob(\"TVqQAAAA\");</script></body></html>";
        let result = analyze_active_content(encoded, "c.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "entity-encoded atob must be detected: {:?}",
            result.categories
        );
    }
}
