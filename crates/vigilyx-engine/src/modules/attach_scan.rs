//! Attachment type detection module — checks attachment extension, double extension,
//! MIME mismatch, magic bytes cross-validation, and abnormal sizes.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use cfb::CompoundFile;
use chrono::Utc;
use regex::Regex;
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
use crate::modules::content_scan::html_utils::{decode_html_entities, strip_html_tags};
use crate::semantic::semantic_phrase_present;
use crate::yara::engine::YaraEngine;

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
    // `application/octet-stream` and its common aliases are deliberately
    // generic.  They do not contradict an executable extension; the magic
    // bytes and structural scanners below still establish the actual type.
    // Treating generic transport MIME as disguise evidence double-counts the
    // same declared executable attachment.
    if is_generic_content_type(&ct) {
        return true;
    }
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

fn is_known_extension_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 12
        && segment.chars().all(|c| c.is_ascii_alphanumeric())
        && (expected_mime_for_ext(segment).is_some()
            || module_data().contains("dangerous_extensions", segment))
}

/// `cs@example.com.xlsx`, `www.example.com.pdf`: an inner `.com` that ends an
/// e-mail address or a multi-label domain in the file name is a TLD, not a
/// second (DOS executable) extension. Only applies when the real final
/// extension is not itself dangerous; `invoice.com.pdf` keeps the flag.
fn inner_com_is_domain_suffix(parts: &[&str], last_ext: &str) -> bool {
    if parts.len() < 3
        || parts[parts.len() - 2] != "com"
        || module_data().contains("dangerous_extensions", last_ext)
    {
        return false;
    }
    let owner = parts[parts.len() - 3];
    let label = owner.rsplit('@').next().unwrap_or(owner);
    let domain_label =
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    domain_label && (owner.contains('@') || parts.len() >= 4)
}

fn has_dangerous_document_lure(filename_lower: &str, last_ext: &str) -> bool {
    if !module_data().contains("dangerous_extensions", last_ext) {
        return false;
    }

    let suffix = format!(".{last_ext}");
    let Some(stem) = filename_lower.strip_suffix(&suffix) else {
        return false;
    };

    module_data()
        .get_list("dangerous_attachment_document_lure_tokens")
        .iter()
        .any(|token| {
            let token = token.trim().to_lowercase();
            if token.is_empty() {
                return false;
            }
            if token.is_ascii() {
                stem.split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|segment| segment == token)
            } else {
                stem.contains(&token)
            }
        })
}

const MAX_FILE_SIZE: usize = 25 * 1024 * 1024; // 25 MB
/// Images above this pixel area can carry a full rendered phishing document;
/// when OCR is unavailable, returning a clean result is unsafe. Small logos
/// and icons remain coverage metadata without forcing every image mail into
/// quarantine.
const OCR_FAIL_CLOSED_MIN_PIXELS: u64 = 100_000;
const OCR_FAIL_CLOSED_MIN_METADATA_BYTES: usize = 32 * 1024;

/// Attachment instructions belong to recipient-readable text. HTML resource
/// attributes, embedded image bytes, and script/stylesheet source are scanned
/// by their own structural modules and cannot supply an execution speech act.
fn attachment_instruction_text(ctx: &SecurityContext) -> String {
    static NON_RENDERED_HTML_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)<(?:script|style)\b[^>]*>.*?(?:</(?:script|style)\s*>|$)")
            .expect("valid non-rendered HTML block regex")
    });
    let html_text = ctx
        .session
        .content
        .body_html
        .as_deref()
        .map(|html| strip_html_tags(&NON_RENDERED_HTML_RE.replace_all(html, " ")))
        .unwrap_or_default();
    format!(
        "{}\n{}\n{}",
        ctx.session.subject.as_deref().unwrap_or_default(),
        ctx.session.content.body_text.as_deref().unwrap_or_default(),
        html_text,
    )
    .to_lowercase()
}

fn image_requires_ocr_quarantine(data: &[u8], content_type: &str) -> bool {
    let is_image = matches!(
        detect_file_type(data),
        Some(
            DetectedFileType::Jpeg
                | DetectedFileType::Png
                | DetectedFileType::Gif
                | DetectedFileType::Bmp
                | DetectedFileType::Tiff
        )
    ) || content_type.to_ascii_lowercase().starts_with("image/");
    if !is_image {
        return false;
    }
    image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()
        .and_then(|reader| reader.into_dimensions().ok())
        .is_some_and(|(width, height)| {
            u64::from(width).saturating_mul(u64::from(height)) >= OCR_FAIL_CLOSED_MIN_PIXELS
        })
}

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
        let mut ocr_fail_closed_count = 0usize;
        let message_text = attachment_instruction_text(ctx);
        let execution_action_hits = module_data()
            .get_list("attachment_execution_action_terms")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let active_content_action_hits = module_data()
            .get_list("attachment_active_content_action_terms")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let active_content_negative_hits = module_data()
            .get_list("attachment_active_content_negative_markers")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let sensitive_archive_hits = module_data()
            .get_list("attachment_sensitive_archive_terms")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|address| address.rsplit('@').next())
            .map(str::to_ascii_lowercase);
        let sender_is_external = sender_domain.as_deref().is_none_or(|domain| {
            !ctx.is_internal_domain(domain)
                && !module_data().contains("protected_domains", domain)
                && !crate::modules::link_scan::is_well_known_safe_domain(domain)
        });

        // An archive can be syntactically incomplete or unavailable to the
        // extractor while the message still explicitly asks a recipient to
        // import security rules. Keep this narrow metadata/body compound so
        // the delivery is not silently treated as clean when no inner bytes
        // are readable.
        let security_rule_context_hits = module_data()
            .get_list("security_rule_archive_context_terms")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let security_rule_action_hits = module_data()
            .get_list("security_rule_archive_action_terms")
            .iter()
            .filter(|term| semantic_phrase_present(&message_text, term))
            .count();
        let has_security_rule_archive = attachments.iter().any(|att| {
            let filename = att.filename.to_lowercase();
            filename.ends_with(".zip") || filename.ends_with(".7z") || filename.ends_with(".rar")
        });
        if sender_is_external
            && has_security_rule_archive
            && security_rule_context_hits > 0
            && security_rule_action_hits > 0
        {
            total_score += 0.50;
            categories.push("security_rule_archive_lure".to_string());
            categories.push("malware".to_string());
            evidence.push(Evidence {
                description: format!(
                    "External sender pairs a security-rule archive with an import instruction (context={}, action={})",
                    security_rule_context_hits, security_rule_action_hits
                ),
                location: Some("subject + body + attachment metadata".to_string()),
                snippet: None,
            });
        }

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

            // Macro/active-content instructions are meaningful only beside a
            // document-capable attachment from an external sender. The
            // explicit negative list prevents security training and ordinary
            // office guidance from being promoted by the same words.
            if sender_is_external
                && active_content_action_hits > 0
                && active_content_negative_hits == 0
                && module_data().contains("attachment_active_document_extensions", last_ext)
            {
                total_score += 0.42;
                categories.push("office_active_content_lure".to_string());
                dangerous_files.push(att.filename.clone());
                evidence.push(Evidence {
                    description: format!(
                        "External sender pairs Office/document attachment `{}` with {} active-content enablement cue(s)",
                        att.filename, active_content_action_hits
                    ),
                    location: Some(format!("attachment:{} + body", att.filename)),
                    snippet: None,
                });
            }

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

                // A declared executable is a policy-risk observation, not
                // proof of malware. A document-themed name is a separate
                // social-delivery signal, however: decoded RFC 2231 names such
                // as `对账单.exe` are intended to look like ordinary business
                // documents. Keep this named compound separate from generic
                // transport MIME so vendor installers remain below quarantine.
                if has_dangerous_document_lure(&filename_lower, last_ext) {
                    total_score += 0.25;
                    categories.push("dangerous_document_lure".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Dangerous attachment uses a document-themed filename: {}",
                            att.filename
                        ),
                        location: Some(format!("attachment:{}", att.filename)),
                        snippet: None,
                    });
                }
                if sender_is_external
                    && module_data().contains("external_executable_attachment_extensions", last_ext)
                {
                    total_score += 0.18;
                    categories.push("external_executable_attachment".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "External sender delivered an executable-capable attachment type: {}",
                            att.filename
                        ),
                        location: Some(format!("attachment:{} + envelope", att.filename)),
                        snippet: None,
                    });
                }
            }

            // Some high-risk profiles/containers (RAR, VPN, calendar and
            // shortcut formats) are intentionally not dangerous by extension
            // alone.  Pairing them with an explicit open/import/execute
            // instruction is the named delivery compound.
            if execution_action_hits > 0
                && module_data().contains("dangerous_container_extensions", last_ext)
            {
                // The operation cue is the delivery step for a high-risk
                // container/profile, not a weak filename observation. Keep
                // the extension alone harmless, but let the named compound
                // survive evidence fusion even when no second attachment
                // anomaly (MIME mismatch, dangerous extension, etc.) exists.
                total_score += 0.36;
                categories.push("dangerous_container_lure".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "High-risk container/profile .{} is paired with {} execution instruction cue(s): {}",
                        last_ext, execution_action_hits, att.filename
                    ),
                    location: Some(format!("attachment:{} + body", att.filename)),
                    snippet: None,
                });
            }
            if execution_action_hits > 0
                && sensitive_archive_hits > 0
                && module_data().contains("attachment_sensitive_archive_extensions", last_ext)
                && !categories
                    .iter()
                    .any(|category| category == "dangerous_container_lure")
            {
                total_score += 0.35;
                categories.push("dangerous_container_lure".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Archive attachment .{} carries {} incident/secret cue(s) and {} extraction action cue(s): {}",
                        last_ext, sensitive_archive_hits, execution_action_hits, att.filename
                    ),
                    location: Some(format!("attachment:{} + body", att.filename)),
                    snippet: None,
                });
            }

            // --- 2. Double extension ---
            let parts: Vec<&str> = filename_lower.split('.').collect();
            if parts.len() >= 3 {
                // The second-to-last extension exists and last extension is dangerous
                let second_ext = parts[parts.len() - 2];
                if is_known_extension_segment(second_ext)
                    && (module_data().contains("dangerous_extensions", last_ext)
                        || module_data().contains("dangerous_extensions", second_ext))
                    && !inner_com_is_domain_suffix(&parts, last_ext)
                {
                    total_score += 0.30;
                    categories.push("double_extension".to_string());
                    if !dangerous_files.iter().any(|name| name == &att.filename) {
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

                let polyglot_result =
                    analyze_polyglot_container(&bytes, &att.filename, last_ext, &att.content_type);
                total_score += polyglot_result.score;
                if polyglot_result.score > 0.0 {
                    dangerous_files.push(att.filename.clone());
                }
                categories.extend(polyglot_result.categories);
                evidence.extend(polyglot_result.evidence);

                let executable_delivery_result = analyze_executable_delivery(
                    &bytes,
                    &att.filename,
                    last_ext,
                    execution_action_hits > 0,
                );
                total_score += executable_delivery_result.score;
                if executable_delivery_result.score > 0.0 {
                    dangerous_files.push(att.filename.clone());
                }
                categories.extend(executable_delivery_result.categories);
                evidence.extend(executable_delivery_result.evidence);

                let encrypted_result =
                    analyze_encrypted_container(&bytes, &att.filename, last_ext, &att.content_type);
                total_score += encrypted_result.score;
                if !encrypted_result.categories.is_empty() {
                    let coverage_limited = encrypted_result.categories.iter().any(|category| {
                        matches!(
                            category.as_str(),
                            "attachment_inspection_limited" | "encrypted_archive" | "encrypted_pdf"
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

                let active_result =
                    analyze_active_content(&bytes, &att.filename, last_ext, &att.content_type);
                total_score += active_result.threat_score;
                if active_result.threat_score > 0.0 {
                    dangerous_files.push(att.filename.clone());
                }
                if active_result.inspection_limited {
                    coverage_limited_files.push(att.filename.clone());
                }
                categories.extend(active_result.categories);
                evidence.extend(active_result.evidence);
                if active_result.ocr_unavailable {
                    ocr_unavailable_count += 1;
                }
                if active_result.ocr_fail_closed {
                    ocr_fail_closed_count += 1;
                }
            } else if att.content_type.to_ascii_lowercase().starts_with("image/") {
                // Metadata-only image attachments are still a coverage gap;
                // never present them as fully inspected.
                ocr_unavailable_count += 1;
                if att.size >= OCR_FAIL_CLOSED_MIN_METADATA_BYTES {
                    ocr_fail_closed_count += 1;
                }
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
                "ocr_fail_closed_count": ocr_fail_closed_count,
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

/// Detect an image/archive polyglot: a valid image header followed by a ZIP
/// local-file header.  The first magic check intentionally returns the image
/// type, so a second container marker must be checked independently.  This is
/// a structural payload observation, not a text prompt or keyword rule.
fn analyze_polyglot_container(
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

    let image_claim = matches!(ext, "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "svg")
        || content_type.to_ascii_lowercase().starts_with("image/");
    let image_magic = matches!(
        detect_file_type(data),
        Some(
            DetectedFileType::Jpeg
                | DetectedFileType::Png
                | DetectedFileType::Gif
                | DetectedFileType::Bmp
                | DetectedFileType::Tiff
        )
    );
    let zip_offset = data
        .windows(4)
        .position(|window| window == [0x50, 0x4B, 0x03, 0x04])
        .filter(|offset| *offset >= 64);

    if image_claim && image_magic && zip_offset.is_some() {
        let offset = zip_offset.unwrap_or_default();
        result.score = 0.45;
        result.categories.push("polyglot_container".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Image attachment contains a trailing ZIP local-file header at byte {}: {}",
                offset, filename
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    result
}

/// Detect an executable/script payload delivered under a non-executable
/// attachment name when the message also tells the recipient to run, install,
/// import, mount, or otherwise apply it.  A normal binary attachment remains
/// an observation until the delivery instruction completes the compound.
fn analyze_executable_delivery(
    data: &[u8],
    filename: &str,
    ext: &str,
    has_execution_instruction: bool,
) -> MagicBytesResult {
    let mut result = MagicBytesResult {
        score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
    };
    if !has_execution_instruction {
        return result;
    }

    let detected = detect_file_type(data);
    let direct_executable = detected.is_some_and(|file_type| file_type.is_executable())
        && !matches!(
            ext,
            "exe" | "dll" | "sys" | "scr" | "com" | "elf" | "so" | "out"
        );
    let gzip_with_script_tail = matches!(detected, Some(DetectedFileType::Gzip))
        && data
            .windows(2)
            .enumerate()
            .any(|(offset, window)| offset >= 16 && window == b"#!");

    if direct_executable || gzip_with_script_tail {
        result.score = 0.45;
        result
            .categories
            .push("executable_delivery_lure".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Executable or script payload is paired with an execution/import instruction: {}",
                filename
            ),
            location: Some(format!("attachment:{} + body", filename)),
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
        result
            .categories
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
        result
            .categories
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
    /// Locally observed feature score. Kept for focused detector diagnostics.
    score: f64,
    /// Portion supported by actionable behavior; only this enters verdicts.
    threat_score: f64,
    categories: Vec<String>,
    evidence: Vec<Evidence>,
    ocr_unavailable: bool,
    ocr_fail_closed: bool,
    inspection_limited: bool,
}

const MAX_OFFICE_STRUCTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OFFICE_ZIP_ENTRIES: usize = 4096;
const MAX_VBA_PROJECTS_PER_DOCUMENT: usize = 8;
const MAX_VBA_PROJECT_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CFB_ENTRIES: usize = 4096;
const MAX_VBA_MODULES: usize = 256;
const MAX_VBA_MODULE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_VBA_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
const MAX_VBA_CONTAINER_ATTEMPTS: usize = 128;

#[derive(Debug, Default)]
struct OfficeActiveContentInspection {
    vba_metadata_observed: bool,
    activex_metadata_observed: bool,
    vba_structure_confirmed: bool,
    activex_structure_confirmed: bool,
    autoexec_confirmed: bool,
    suspicious_api_confirmed: bool,
    module_count: usize,
    inspection_limited: bool,
}

impl OfficeActiveContentInspection {
    fn office_observed(&self) -> bool {
        self.vba_metadata_observed
            || self.activex_metadata_observed
            || self.vba_structure_confirmed
            || self.activex_structure_confirmed
    }

    fn actionable_vba_behavior(&self) -> bool {
        should_promote_office_vba(
            self.vba_structure_confirmed,
            self.autoexec_confirmed,
            self.suspicious_api_confirmed,
        )
    }
}

fn should_promote_office_vba(
    structure_confirmed: bool,
    autoexec_confirmed: bool,
    suspicious_api_confirmed: bool,
) -> bool {
    structure_confirmed && (autoexec_confirmed || suspicious_api_confirmed)
}

fn office_structure_size_allowed(data_len: usize) -> bool {
    data_len <= MAX_OFFICE_STRUCTURE_BYTES
}

fn office_path_has_component(path: &str, component: &str) -> bool {
    path.split(['/', '\\'])
        .any(|part| part.eq_ignore_ascii_case(component))
}

fn office_zip_metadata(data: &[u8]) -> Option<(bool, bool, bool)> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    if archive.len() > MAX_OFFICE_ZIP_ENTRIES {
        return Some((false, false, false));
    }

    let mut vba_observed = false;
    let mut activex_observed = false;
    let mut vba_project_count = 0usize;
    let mut vba_project_bytes = 0u64;
    let mut parse_budget_ok = true;

    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index(index) else {
            parse_budget_ok = false;
            continue;
        };
        let Ok(name) = entry.name() else {
            parse_budget_ok = false;
            continue;
        };
        let lower = name.to_ascii_lowercase();
        let is_vba_project =
            lower.ends_with("vbaproject.bin") || lower.ends_with("vba_project.bin");
        let is_macro_path = office_path_has_component(&lower, "macros");
        let is_activex_path = office_path_has_component(&lower, "activex");

        vba_observed |= is_vba_project || is_macro_path;
        activex_observed |= is_activex_path;

        if is_vba_project {
            vba_project_count = vba_project_count.saturating_add(1);
            vba_project_bytes = vba_project_bytes.saturating_add(entry.size());
            if entry.size() > MAX_VBA_PROJECT_UNCOMPRESSED_BYTES
                || vba_project_count > MAX_VBA_PROJECTS_PER_DOCUMENT
                || vba_project_bytes > MAX_OFFICE_STRUCTURE_BYTES as u64
            {
                parse_budget_ok = false;
            }
        }
    }

    Some((vba_observed, activex_observed, parse_budget_ok))
}

#[derive(Debug, Default)]
struct OfficeVbaProjectInspection {
    structure_confirmed: bool,
    module_count: usize,
    autoexec_confirmed: bool,
    suspicious_api_confirmed: bool,
    inspection_limited: bool,
}

fn merge_vba_project_inspection(
    target: &mut OfficeActiveContentInspection,
    project: OfficeVbaProjectInspection,
) {
    target.vba_structure_confirmed |= project.structure_confirmed;
    target.module_count = target.module_count.saturating_add(project.module_count);
    target.autoexec_confirmed |= project.autoexec_confirmed;
    target.suspicious_api_confirmed |= project.suspicious_api_confirmed;
    target.inspection_limited |= project.inspection_limited;
}

fn inspect_zip_vba_projects(data: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return (Vec::new(), false);
    };
    if archive.len() > MAX_OFFICE_ZIP_ENTRIES {
        return (Vec::new(), false);
    }

    let mut projects = Vec::new();
    let mut project_count = 0usize;
    let mut project_bytes = 0u64;
    let mut budget_ok = true;
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            budget_ok = false;
            continue;
        };
        let Ok(name) = entry.name() else {
            budget_ok = false;
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with("vbaproject.bin") || lower.ends_with("vba_project.bin")) {
            continue;
        }
        project_count = project_count.saturating_add(1);
        project_bytes = project_bytes.saturating_add(entry.size());
        if entry.size() > MAX_VBA_PROJECT_UNCOMPRESSED_BYTES
            || project_count > MAX_VBA_PROJECTS_PER_DOCUMENT
            || project_bytes > MAX_OFFICE_STRUCTURE_BYTES as u64
        {
            budget_ok = false;
            continue;
        }
        let mut bytes = Vec::new();
        let read_limit = MAX_VBA_PROJECT_UNCOMPRESSED_BYTES.saturating_add(1);
        if entry
            .by_ref()
            .take(read_limit)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_VBA_PROJECT_UNCOMPRESSED_BYTES
        {
            budget_ok = false;
            continue;
        }
        projects.push(bytes);
    }
    (projects, budget_ok)
}

#[derive(Debug)]
struct CfbStreamMetadata {
    path: PathBuf,
    name: String,
    len: u64,
    is_stream: bool,
}

fn inspect_cfb_office(data: &[u8]) -> (OfficeVbaProjectInspection, bool) {
    let mut project = OfficeVbaProjectInspection::default();
    let mut activex_confirmed = false;
    let Ok(mut compound) = CompoundFile::open(Cursor::new(data.to_vec())) else {
        project.inspection_limited = true;
        return (project, activex_confirmed);
    };

    let mut entries = Vec::new();
    for entry in compound.walk() {
        if entries.len() >= MAX_CFB_ENTRIES {
            project.inspection_limited = true;
            break;
        }
        let path = entry.path().to_path_buf();
        let path_text = path.to_string_lossy();
        activex_confirmed |= office_path_has_component(&path_text, "activex");
        entries.push(CfbStreamMetadata {
            path,
            name: entry.name().to_string(),
            len: entry.len(),
            is_stream: entry.is_stream(),
        });
    }

    let vba_storages: Vec<PathBuf> = entries
        .iter()
        .filter(|entry| {
            entry.is_stream
                && entry.name.eq_ignore_ascii_case("dir")
                && office_path_has_component(&entry.path.to_string_lossy(), "vba")
        })
        .filter_map(|entry| entry.path.parent().map(Path::to_path_buf))
        .collect();

    for vba_storage in vba_storages.into_iter().take(MAX_VBA_MODULES) {
        let same_storage = |entry: &&CfbStreamMetadata| {
            entry.is_stream && entry.path.parent() == Some(vba_storage.as_path())
        };
        let has_dir = entries
            .iter()
            .any(|entry| same_storage(&entry) && entry.name.eq_ignore_ascii_case("dir"));
        let has_project = entries
            .iter()
            .any(|entry| same_storage(&entry) && entry.name.eq_ignore_ascii_case("_vba_project"));
        let modules: Vec<&CfbStreamMetadata> = entries
            .iter()
            .filter(same_storage)
            .filter(|entry| {
                !matches!(
                    entry.name.to_ascii_lowercase().as_str(),
                    "dir" | "_vba_project" | "project" | "projectwm"
                ) && !entry.name.to_ascii_lowercase().starts_with("__srp_")
            })
            .take(MAX_VBA_MODULES)
            .collect();

        if !has_dir || !has_project || modules.is_empty() {
            continue;
        }
        project.structure_confirmed = true;
        if modules.len() == MAX_VBA_MODULES {
            project.inspection_limited = true;
        }

        for module in modules {
            if module.len > MAX_VBA_MODULE_BYTES {
                project.inspection_limited = true;
                continue;
            }
            let mut stream = match compound.open_stream(&module.path) {
                Ok(stream) => stream,
                Err(_) => {
                    project.inspection_limited = true;
                    continue;
                }
            };
            let mut bytes = Vec::new();
            if stream
                .by_ref()
                .take(MAX_VBA_MODULE_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_VBA_MODULE_BYTES
            {
                project.inspection_limited = true;
                continue;
            }
            let Some(source) = extract_vba_source(&bytes) else {
                continue;
            };
            project.module_count = project.module_count.saturating_add(1);
            project.autoexec_confirmed |= vba_has_autoexec_procedure(&source);
            project.suspicious_api_confirmed |= vba_has_suspicious_yara_behavior(&source);
        }
    }

    (project, activex_confirmed)
}

fn extract_vba_source(data: &[u8]) -> Option<Vec<u8>> {
    let mut attempts = 0usize;
    for (offset, byte) in data.iter().enumerate() {
        if *byte != 0x01 {
            continue;
        }
        attempts = attempts.saturating_add(1);
        if attempts > MAX_VBA_CONTAINER_ATTEMPTS {
            break;
        }
        let Some(source) = decompress_vba_container(&data[offset..], MAX_VBA_DECOMPRESSED_BYTES)
        else {
            continue;
        };
        if vba_source_looks_structured(&source) {
            return Some(source);
        }
    }
    None
}

fn decompress_vba_container(data: &[u8], max_output: usize) -> Option<Vec<u8>> {
    if data.first().copied() != Some(0x01) {
        return None;
    }
    let mut position = 1usize;
    let mut output = Vec::new();
    while position < data.len() {
        if position.checked_add(2)? > data.len() {
            return None;
        }
        let header = u16::from_le_bytes([data[position], data[position + 1]]);
        let chunk_total = (header & 0x0fff) as usize + 3;
        let chunk_end = position.checked_add(chunk_total)?;
        if chunk_total < 3 || chunk_end > data.len() {
            return None;
        }
        let payload_start = position + 2;
        let chunk_start_output = output.len();
        let compressed = header & 0x8000 != 0;
        if !compressed {
            let payload = &data[payload_start..chunk_end];
            if output.len().checked_add(payload.len())? > max_output || payload.len() > 4096 {
                return None;
            }
            output.extend_from_slice(payload);
        } else {
            let mut cursor = payload_start;
            while cursor < chunk_end && output.len() - chunk_start_output < 4096 {
                let flags = *data.get(cursor)?;
                cursor += 1;
                for bit in 0..8 {
                    if cursor >= chunk_end || output.len() - chunk_start_output >= 4096 {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        if output.len() >= max_output {
                            return None;
                        }
                        output.push(*data.get(cursor)?);
                        cursor += 1;
                        continue;
                    }
                    let token_end = cursor.checked_add(2)?;
                    if token_end > chunk_end {
                        return None;
                    }
                    let token = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
                    cursor = token_end;
                    let current = output.len() - chunk_start_output;
                    let bit_count = if current <= 1 {
                        4
                    } else {
                        ((current - 1).ilog2() + 1).clamp(4, 12) as u16
                    };
                    let length_mask = 0xffffu16 >> bit_count;
                    let offset = ((token & !length_mask) >> (16 - bit_count)) as usize + 1;
                    let length = (token & length_mask) as usize + 3;
                    if offset > current {
                        return None;
                    }
                    let remaining = 4096usize.saturating_sub(current);
                    let copy_length = length.min(remaining);
                    if output.len().checked_add(copy_length)? > max_output {
                        return None;
                    }
                    for _ in 0..copy_length {
                        let source = output.len().checked_sub(offset)?;
                        let byte = *output.get(source)?;
                        output.push(byte);
                    }
                }
            }
        }
        position = chunk_end;
    }
    Some(output)
}

fn vba_source_looks_structured(source: &[u8]) -> bool {
    contains_ascii_ci(source, b"attribute vb_")
        || (contains_ascii_ci(source, b"sub ") && contains_ascii_ci(source, b"end sub"))
        || (contains_ascii_ci(source, b"function ") && contains_ascii_ci(source, b"end function"))
}

fn sanitize_vba_source(source: &[u8]) -> String {
    let mut sanitized = String::with_capacity(source.len());
    for line in String::from_utf8_lossy(source).lines() {
        let trimmed = line.trim_start();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.starts_with('\'') || lower == "rem" || lower.starts_with("rem ") {
            sanitized.push('\n');
            continue;
        }
        let mut in_string = false;
        for ch in line.chars() {
            if ch == '"' {
                in_string = !in_string;
                sanitized.push(' ');
            } else if ch == '\'' && !in_string {
                break;
            } else if in_string {
                sanitized.push(' ');
            } else {
                sanitized.push(ch);
            }
        }
        sanitized.push('\n');
    }
    sanitized
}

fn vba_has_autoexec_procedure(source: &[u8]) -> bool {
    const AUTOEXEC_NAMES: &[&str] = &[
        "autoopen",
        "auto_open",
        "autoexec",
        "document_open",
        "document_close",
        "workbook_open",
        "workbook_activate",
        "workbook_beforeclose",
        "worksheet_activate",
    ];
    sanitize_vba_source(source).lines().any(|line| {
        let tokens: Vec<String> = line
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|token| !token.is_empty())
            .map(|token| token.to_ascii_lowercase())
            .collect();
        tokens.windows(2).any(|window| {
            matches!(window[0].as_str(), "sub" | "function")
                && AUTOEXEC_NAMES.contains(&window[1].as_str())
        })
    })
}

fn vba_has_suspicious_yara_behavior(source: &[u8]) -> bool {
    let sanitized = sanitize_vba_source(source);
    let lowered = sanitized.to_ascii_lowercase();
    const SUSPICIOUS_API_MARKERS: &[&str] = &[
        "createobject",
        "wscript.shell",
        "url_download_to_file",
        "urldownloadtofile",
        "xmlhttp",
        "winhttp",
        "internetopen",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "powershell",
    ];
    if SUSPICIOUS_API_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return true;
    }
    let Ok(engine) = YaraEngine::new() else {
        return false;
    };
    engine.scan(sanitized.as_bytes()).iter().any(|matched| {
        matches!(
            matched.rule_name.as_str(),
            "VBA_Macro_AutoExec" | "VBA_Macro_Download"
        )
    })
}

fn inspect_office_active_content(
    data: &[u8],
    detected: Option<DetectedFileType>,
) -> OfficeActiveContentInspection {
    let mut inspection = OfficeActiveContentInspection::default();
    let mut parse_budget_ok = office_structure_size_allowed(data.len());

    match detected {
        Some(DetectedFileType::ZipArchive) => {
            if let Some((vba_observed, activex_observed, zip_budget_ok)) = office_zip_metadata(data)
            {
                inspection.vba_metadata_observed = vba_observed;
                inspection.activex_metadata_observed = activex_observed;
                // A valid central-directory member under the ActiveX hierarchy
                // is structural metadata. It remains an observation because no
                // ActiveX code is executed or behaviorally emulated here.
                inspection.activex_structure_confirmed = activex_observed;
                parse_budget_ok &= zip_budget_ok;
            }
        }
        Some(DetectedFileType::OleCompound) => {
            // These whole-file tokens are deliberately observation-only. They
            // select the document for bounded structural parsing, but can never
            // establish VBA/ActiveX validity or malicious behavior themselves.
            inspection.vba_metadata_observed = contains_ascii_ci(data, b"vba")
                || contains_ascii_ci(data, b"_vba_project")
                || contains_ascii_ci(data, b"macros")
                || contains_ascii_ci(data, b"dir\0");
            inspection.activex_metadata_observed = contains_ascii_ci(data, b"activex");

            if parse_budget_ok {
                let (project, activex_confirmed) = inspect_cfb_office(data);
                inspection.activex_structure_confirmed = activex_confirmed;
                merge_vba_project_inspection(&mut inspection, project);
            }
        }
        _ => return inspection,
    }

    if !inspection.vba_metadata_observed {
        return inspection;
    }
    if !parse_budget_ok {
        inspection.inspection_limited = true;
        return inspection;
    }

    let (projects, zip_budget_ok) = inspect_zip_vba_projects(data);
    if !zip_budget_ok {
        inspection.inspection_limited = true;
    }
    for project_bytes in projects {
        merge_vba_project_inspection(&mut inspection, inspect_cfb_office(&project_bytes).0);
    }

    inspection
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
            let after = idx + name.len();
            let after_ok = after == data.len() || is_pdf_name_delimiter(data[after]);
            // The leading slash is itself the PDF name delimiter, so compact
            // dictionaries such as `/S/JavaScript` are valid even though the
            // previous byte is the final `S` of another name. The trailing
            // delimiter check still rejects prefixes such as `/JSON`.
            if after_ok { Some(idx) } else { None }
        })
        .collect()
}

fn is_pdf_name_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'{' | b'}' | b'%'
        )
}

fn pdf_js_literal_is_benign_icon_import(data: &[u8], js_name_offset: usize) -> bool {
    let Some(tail) = data.get(js_name_offset + b"/JS".len()..) else {
        return false;
    };
    let tail = tail
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .and_then(|offset| tail.get(offset..))
        .unwrap_or_default();
    const ALLOWED: [&[u8]; 2] = [
        b"(event.target.buttonImportIcon\\(\\);)",
        b"(event.target.buttonImportIcon\\(\\))",
    ];

    ALLOWED.iter().any(|allowed| {
        tail.starts_with(allowed)
            && tail
                .get(allowed.len())
                .is_none_or(|byte| is_pdf_name_delimiter(*byte))
    })
}

/// Detect PDF active-action names as actual PDF name tokens rather than loose
/// byte substrings.  In particular, `/aa` inside ordinary text must not turn a
/// scanned PDF into an active-content finding.
///
/// Matching runs on the `#hh`-decoded view (ISO 32000 §7.3.5) so
/// `/Op#65nAction` / `/J#61vaScript` spellings cannot hide active content.
fn detect_pdf_active_actions(data: &[u8]) -> (bool, bool, bool) {
    let data = magic_bytes::normalize_pdf_name_escapes(data);
    let data = data.as_ref();
    let javascript_positions = pdf_name_token_positions(data, b"/JavaScript");
    let js_positions = pdf_name_token_positions(data, b"/JS");
    // Acrobat-generated photo fields use a tiny, user-initiated helper to
    // open the local icon picker. Treat only the complete literal below as a
    // non-scoring observation. Any extra statement, stream payload, missing
    // action-name pair, or additional JavaScript object remains actionable.
    let has_benign_icon_import = !js_positions.is_empty()
        && javascript_positions.len() == js_positions.len()
        && js_positions
            .iter()
            .all(|offset| pdf_js_literal_is_benign_icon_import(data, *offset));
    let has_javascript =
        (!javascript_positions.is_empty() || !js_positions.is_empty()) && !has_benign_icon_import;
    // /OpenAction is intentionally not actionable by itself. PDF catalogs
    // commonly use `/OpenAction [page /Fit]` as a benign initial-view
    // destination. Executable action dictionaries still carry one of the
    // concrete action names below (or /JavaScript / /JS) and remain detected.
    // /GoToE (embedded-document navigation), /RichMedia, /Collection and
    // /Rendition are the PDF-portfolio primitives used to auto-open a bundled
    // malicious document on view — no engine layer covered them before.
    let has_direct_action = [
        b"/Launch".as_slice(),
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
            [
                b"/JavaScript".as_slice(),
                b"/JS",
                b"/Launch",
                b"/SubmitForm",
            ]
            .iter()
            .any(|name| !pdf_name_token_positions(window, name).is_empty())
        });

    (
        has_javascript,
        has_direct_action || has_additional_action,
        has_benign_icon_import,
    )
}

/// Generic PDF JavaScript is common in interactive forms and is not enough
/// to establish malicious behavior. Keep the behavior markers versioned in
/// engine module data so the detector does not grow an embedded policy list.
fn pdf_has_suspicious_javascript_behavior(data: &[u8]) -> bool {
    let normalized = magic_bytes::normalize_pdf_name_escapes(data);
    module_data()
        .get_list("pdf_active_js_behavior_terms")
        .iter()
        .map(|term| term.trim())
        .filter(|term| !term.is_empty())
        .any(|term| contains_ascii_ci(normalized.as_ref(), term.as_bytes()))
}

fn pdf_has_name(data: &[u8], name: &[u8]) -> bool {
    let normalized = magic_bytes::normalize_pdf_name_escapes(data);
    !pdf_name_token_positions(normalized.as_ref(), name).is_empty()
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

fn find_ascii_ci(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    data.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
    })
}

/// Require a complete payload reconstruction/execution chain inside one
/// script block. File-wide token co-occurrence is insufficient: legitimate
/// business tools often contain SVG icons plus `atob()` for an embedded XLSX
/// template, without creating or executing an HTML/binary payload.
fn html_has_smuggling_chain(data: &[u8]) -> bool {
    let mut cursor = 0usize;
    let has_download_attribute = contains_ascii_ci(data, b" download=");

    while cursor < data.len() {
        let Some(open_rel) = find_ascii_ci(&data[cursor..], b"<script") else {
            break;
        };
        let open = cursor + open_rel;
        let Some(tag_end_rel) = data[open..].iter().position(|byte| *byte == b'>') else {
            break;
        };
        let body_start = open + tag_end_rel + 1;
        let close_rel = find_ascii_ci(&data[body_start..], b"</script");
        let body_end = close_rel.map_or(data.len(), |offset| body_start + offset);
        let script = &data[body_start..body_end];

        let has_atob = contains_atob_invocation(script);
        let has_decoder = has_atob || contains_ascii_ci(script, b"fromcharcode");
        let has_blob_sink = contains_ascii_ci(script, b"createobjecturl")
            || contains_ascii_ci(script, b"mssaveoropenblob");
        let has_delivery = contains_ascii_ci(script, b"download")
            || contains_ascii_ci(script, b".click(")
            || contains_ascii_ci(script, b"data:application")
            || contains_ascii_ci(script, b"data:text/html");
        let has_execution_sink = contains_ascii_ci(script, b"document.write")
            || contains_ascii_ci(script, b"eval(")
            || contains_ascii_ci(script, b"new function")
            || contains_ascii_ci(script, b"webassembly.instantiate")
            || contains_ascii_ci(script, b".srcdoc");

        let blob_delivery_chain = has_decoder && has_blob_sink && has_delivery;
        let decoded_execution_chain = has_atob && has_execution_sink;
        let anchor_data_delivery_chain = contains_ascii_ci(script, b"data:")
            && (contains_ascii_ci(script, b"download") || has_download_attribute)
            && contains_ascii_ci(script, b".click(");
        if blob_delivery_chain || decoded_execution_chain || anchor_data_delivery_chain {
            return true;
        }

        cursor = close_rel.map_or(data.len(), |offset| body_start + offset + b"</script".len());
    }

    false
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
        threat_score: 0.0,
        categories: Vec::new(),
        evidence: Vec::new(),
        ocr_unavailable: false,
        ocr_fail_closed: false,
        inspection_limited: false,
    };
    let detected = detect_file_type(data);
    let location = || Some(format!("attachment:{filename}"));

    if matches!(
        detected,
        Some(
            DetectedFileType::Jpeg
                | DetectedFileType::Png
                | DetectedFileType::Gif
                | DetectedFileType::Bmp
                | DetectedFileType::Tiff
        )
    ) || content_type.to_ascii_lowercase().starts_with("image/")
    {
        result.ocr_unavailable = true;
        result.ocr_fail_closed = image_requires_ocr_quarantine(data, content_type);
        result.categories.push("ocr_unavailable".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "Image attachment was not OCR-scanned; text embedded in the image is not covered: {filename}"
            ),
            location: location(),
            snippet: None,
        });
    }

    let office = inspect_office_active_content(data, detected);
    if office.office_observed() {
        if office.vba_metadata_observed || office.vba_structure_confirmed {
            result.categories.push("office_macro".to_string());
        }
        result.categories.push("active_content".to_string());
        if office.vba_structure_confirmed {
            result
                .categories
                .push("office_vba_structure_confirmed".to_string());
        }
        if office.activex_structure_confirmed {
            result
                .categories
                .push("office_activex_structure_confirmed".to_string());
        }

        if office.actionable_vba_behavior() {
            // Preserve the historical 0.35 score only for the newly qualified
            // positive neighbor. Metadata or structure alone always stays 0.
            result.score += 0.35;
            result.threat_score += 0.35;
            result
                .categories
                .push("office_macro_suspicious_behavior".to_string());
            if office.autoexec_confirmed {
                result.categories.push("office_macro_autoexec".to_string());
            }
            if office.suspicious_api_confirmed {
                result
                    .categories
                    .push("office_macro_suspicious_api".to_string());
            }
            result.evidence.push(Evidence {
                description: format!(
                    "Structured VBA project confirmed with {} parsed module(s) and qualified automatic-execution/API behavior; code was not executed: {filename}",
                    office.module_count
                ),
                location: location(),
                snippet: None,
            });
        } else {
            result.evidence.push(Evidence {
                description: if office.vba_structure_confirmed {
                    format!(
                        "Structured Office active content confirmed with {} parsed VBA module(s), but no qualified automatic-execution or suspicious API behavior was found; observation only: {filename}",
                        office.module_count
                    )
                } else {
                    format!(
                        "Office active-content metadata observed, but VBA/ActiveX malicious behavior was not structurally confirmed; observation only: {filename}"
                    )
                },
                location: location(),
                snippet: None,
            });
        }

        if office.inspection_limited {
            result.inspection_limited = true;
            result
                .categories
                .push("office_active_content_unparsed".to_string());
            result
                .categories
                .push("attachment_inspection_limited".to_string());
        }
    }

    if detected == Some(DetectedFileType::Pdf) || ext == "pdf" {
        let (has_js, has_action, has_benign_icon_import) = detect_pdf_active_actions(data);
        if has_benign_icon_import {
            result
                .categories
                .push("pdf_form_icon_import_observed".to_string());
            result.evidence.push(Evidence {
                description: format!(
                    "PDF contains only the user-initiated Acrobat buttonImportIcon form helper; no code was executed: {filename}"
                ),
                location: location(),
                snippet: None,
            });
        }
        if has_js || has_action {
            let has_launch_action = pdf_has_name(data, b"/Launch");
            let has_activated_script_behavior =
                has_js && pdf_has_suspicious_javascript_behavior(data);
            let has_qualified_payload = has_launch_action || has_activated_script_behavior;
            // JavaScript and navigation/form actions also occur in legitimate
            // PDFs. Generic script remains a low module observation, while
            // only a configured behavior or a Launch action is fusion-grade.
            // Portfolio navigation retains a small signal for the established
            // positive neighbor without reaching Medium.
            let has_portfolio_navigation =
                pdf_has_name(data, b"/Collection") && pdf_has_name(data, b"/GoToE");
            let observed_score = if has_qualified_payload {
                if has_js { 0.55 } else { 0.35 }
            } else if has_js {
                0.25
            } else if has_portfolio_navigation {
                0.15
            } else {
                0.0
            };
            result.score += observed_score;
            if has_qualified_payload {
                result.threat_score += observed_score;
            }
            result.categories.push("pdf_active_content".to_string());
            result.categories.push("active_content".to_string());
            if has_qualified_payload {
                result.categories.push("pdf_active_payload".to_string());
            }
            result.evidence.push(Evidence {
                description: if has_qualified_payload {
                    format!(
                        "PDF contains JavaScript behavior or a Launch action requiring review; content was not executed: {filename}"
                    )
                } else {
                    format!(
                        "PDF contains JavaScript or a form/navigation action; this static feature alone does not establish malicious behavior, and content was not executed: {filename}"
                    )
                },
                location: location(),
                snippet: None,
            });
        }
    }

    // SVG is XML with scriptable event attributes, but magic-byte detection
    // commonly classifies tiny SVGs as generic text/image data. Inspect the
    // event-handler value and configured executable operations directly; this
    // is static analysis only and does not render or execute the file.
    let is_svg = ext == "svg" || content_type.to_ascii_lowercase().contains("svg");
    if is_svg {
        let lower = String::from_utf8_lossy(data).to_ascii_lowercase();
        let has_event_handler =
            lower.contains("onload=") || lower.contains("onerror=") || lower.contains("onclick=");
        let active_ops = module_data()
            .get_list("dangerous_inline_event_handler_ops")
            .iter()
            .filter(|op| lower.contains(op.as_str()))
            .count();
        if has_event_handler && active_ops > 0 {
            result.score += 0.55;
            result.threat_score += 0.55;
            result.categories.push("svg_active_content".to_string());
            result.categories.push("active_content".to_string());
            result.evidence.push(Evidence {
                description: format!(
                    "SVG attachment contains an event handler with {} configured executable/network operation(s); content was not executed: {filename}",
                    active_ops
                ),
                location: location(),
                snippet: None,
            });
        }
    }

    let is_html = matches!(
        detected,
        Some(DetectedFileType::HtmlDocument | DetectedFileType::ScriptText)
    ) || matches!(ext, "html" | "htm" | "xhtml" | "hta")
        || content_type.to_ascii_lowercase().contains("text/html");
    if is_html && vigilyx_core::magic_bytes::html_has_scripts(data) {
        // Token matching also runs on the entity-decoded view so spellings
        // like `d&#97;ta:` or `&#97;tob(` cannot hide smuggling indicators.
        let decoded = decode_html_entities(&String::from_utf8_lossy(data));
        let smuggling =
            html_has_smuggling_chain(data) || html_has_smuggling_chain(decoded.as_bytes());
        let html_score = if smuggling { 0.30 } else { 0.12 };
        result.score += html_score;
        result.threat_score += html_score;
        result.categories.push("html_active_content".to_string());
        if smuggling {
            result.categories.push("html_smuggling".to_string());
        }
        result.categories.push("active_content".to_string());
        result.evidence.push(Evidence {
            description: format!(
                "HTML attachment contains embedded script{}; scripts were not executed: {filename}",
                if smuggling {
                    " and payload-reconstruction indicators"
                } else {
                    ""
                }
            ),
            location: location(),
            snippet: None,
        });
    }

    if detected == Some(DetectedFileType::Rtf)
        && (contains_ascii_ci(data, b"\\object") || contains_ascii_ci(data, b"\\objdata"))
    {
        result.score += 0.15;
        result.threat_score += 0.15;
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
    use base64::Engine as _;
    use std::io::Write;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailAttachment, EmailSession, Protocol};

    fn analyze_instruction_attachment(
        filename: &str,
        body_text: Option<&str>,
        body_html: Option<&str>,
    ) -> ModuleResult {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            2525,
            "192.0.2.20".to_string(),
            25,
        );
        session.mail_from = Some("sender@example.test".to_string());
        session.subject = Some("Generated report notification".to_string());
        session.content.body_text = body_text.map(str::to_string);
        session.content.body_html = body_html.map(str::to_string);
        let bytes = make_zip(&[("report.txt", b"An ordinary generated business report.")]);
        session.content.attachments.push(EmailAttachment {
            filename: filename.to_string(),
            content_type: "application/octet-stream".to_string(),
            size: bytes.len(),
            hash: "synthetic-instruction-fixture".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        });
        let ctx = SecurityContext::new(Arc::new(session));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(AttachScanModule::new().analyze(&ctx))
            .expect("attachment scan")
    }

    #[test]
    fn generated_report_image_bytes_cannot_supply_archive_lure_cues() {
        let html = r#"<img src="data:image/png;base64,AAARUNIOCAAA">
            <p style="font-size:14px">您的企业信用报告已经生成，请下载浏览。</p>
            <a href="https://reports.example.test/download?run=IOC">下载</a>"#;
        let result = analyze_instruction_attachment("business-report.zip", None, Some(html));

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"dangerous_container_lure".to_string())
        );
        assert!(
            !result
                .categories
                .contains(&"security_rule_archive_lure".to_string())
        );
    }

    #[test]
    fn non_rendered_source_cannot_supply_attachment_instructions() {
        let html = r#"<style>.run-IOC { content:'malware sample; extract and open'; }</style>
            <script>const sample = 'IOC; run the installer';</script>
            <p>您的业务报告已生成。</p>"#;
        let result = analyze_instruction_attachment("business-report.zip", None, Some(html));

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"dangerous_container_lure".to_string())
        );
    }

    #[test]
    fn ordinary_words_cannot_supply_ascii_execution_and_incident_terms() {
        let result = analyze_instruction_attachment(
            "training-report.zip",
            Some("This biochemistry report describes the runtime of the calculation."),
            None,
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"dangerous_container_lure".to_string())
        );
    }

    #[test]
    fn visible_archive_extraction_instruction_retains_container_lure() {
        let result = analyze_instruction_attachment(
            "incident-samples.zip",
            None,
            Some(
                "<p>These are IOC indicators. Please extract and open the attached malware sample.</p>",
            ),
        );

        assert!(
            result
                .categories
                .contains(&"dangerous_container_lure".to_string())
        );
        assert!(result.details["score"].as_f64().unwrap() >= 0.35);
    }

    #[test]
    fn visible_profile_import_instruction_retains_container_lure() {
        let result =
            analyze_instruction_attachment("connection.ovpn", Some("请导入配置并重启生效。"), None);

        assert!(
            result
                .categories
                .contains(&"dangerous_container_lure".to_string())
        );
        assert!(result.details["score"].as_f64().unwrap() >= 0.36);
    }

    #[test]
    fn visible_office_enablement_instruction_retains_macro_lure() {
        let result = analyze_instruction_attachment(
            "report.docx",
            None,
            Some("<p>Please enable content in the attached report.</p>"),
        );

        assert!(
            result
                .categories
                .contains(&"office_active_content_lure".to_string())
        );
        assert!(result.details["score"].as_f64().unwrap() >= 0.42);
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

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, data) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("synthetic ZIP entry should start");
            writer
                .write_all(data)
                .expect("synthetic ZIP entry should be written");
        }
        writer
            .finish()
            .expect("synthetic ZIP should finish")
            .into_inner()
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
    fn test_ole_keyword_only_office_macro_is_observation() {
        let mut data = vec![0u8; 1024];
        data[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        let marker = b"VBA macros dir\0 AutoOpen";
        data[128..128 + marker.len()].copy_from_slice(marker);

        let result =
            analyze_active_content(&data, "business-document.doc", "doc", "application/msword");

        assert_eq!(result.score, 0.0, "OLE byte tokens are observation-only");
        assert!(result.categories.contains(&"office_macro".to_string()));
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(
            !result
                .categories
                .contains(&"office_macro_suspicious_behavior".to_string())
        );
    }

    #[test]
    fn test_ooxml_vba_name_with_plaintext_behavior_is_observation() {
        let data = make_zip(&[(
            "word/vbaProject.bin",
            b"Sub AutoOpen()\nCreateObject(\"WScript.Shell\")\nEnd Sub",
        )]);

        let result = analyze_active_content(
            &data,
            "unstructured.docm",
            "docm",
            "application/vnd.ms-word.document.macroenabled.12",
        );

        assert_eq!(
            result.score, 0.0,
            "strings outside a parseable VBA project must not be promoted"
        );
        assert!(result.categories.contains(&"office_macro".to_string()));
        assert!(
            result
                .categories
                .contains(&"office_active_content_unparsed".to_string())
        );
        assert!(
            !result
                .categories
                .contains(&"office_macro_suspicious_behavior".to_string())
        );
    }

    #[test]
    fn test_structured_activex_member_is_observation() {
        let data = make_zip(&[("word/activeX/activeX1.bin", b"ActiveX control metadata")]);
        let result = analyze_active_content(
            &data,
            "control.docm",
            "docm",
            "application/vnd.ms-word.document.macroenabled.12",
        );

        assert_eq!(result.score, 0.0);
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(
            result
                .categories
                .contains(&"office_activex_structure_confirmed".to_string())
        );
    }

    #[test]
    fn test_vba_behavior_requires_structure_and_qualified_source_behavior() {
        let benign = b"Sub BuildReport()\nDim total As Long\nEnd Sub";
        assert!(!should_promote_office_vba(
            true,
            vba_has_autoexec_procedure(benign),
            vba_has_suspicious_yara_behavior(benign)
        ));

        let autoexec = b"Sub AutoOpen()\nMsgBox \"Ready\"\nEnd Sub";
        assert!(should_promote_office_vba(
            true,
            vba_has_autoexec_procedure(autoexec),
            vba_has_suspicious_yara_behavior(autoexec)
        ));
        assert!(!should_promote_office_vba(
            false,
            vba_has_autoexec_procedure(autoexec),
            vba_has_suspicious_yara_behavior(autoexec)
        ));

        let suspicious_api =
            b"Sub RunTask()\nSet runner = CreateObject(\"WScript.Shell\")\nEnd Sub";
        assert!(should_promote_office_vba(
            true,
            vba_has_autoexec_procedure(suspicious_api),
            vba_has_suspicious_yara_behavior(suspicious_api)
        ));
    }

    #[test]
    fn test_vba_behavior_words_in_comments_and_strings_do_not_qualify() {
        let source =
            b"' Sub AutoOpen()\nSub BuildReport()\nlabel = \"CreateObject WScript.Shell\"\nEnd Sub";
        let autoexec = vba_has_autoexec_procedure(source);
        let suspicious_api = vba_has_suspicious_yara_behavior(source);
        assert!(!autoexec);
        assert!(!suspicious_api);
        assert!(!should_promote_office_vba(true, autoexec, suspicious_api));
    }

    #[test]
    fn test_vba_uncompressed_container_is_bounded_and_decodable() {
        let source = b"Sub AutoOpen()\r\nEnd Sub";
        let chunk_size = source.len() + 2 - 3;
        let header = chunk_size as u16;
        let mut container = vec![0x01, header as u8, (header >> 8) as u8];
        container.extend_from_slice(source);
        let decoded = decompress_vba_container(&container, 4096).expect("valid chunk");
        assert_eq!(decoded, source);
        assert!(decompress_vba_container(&container, source.len() - 1).is_none());
    }

    #[test]
    fn test_office_structure_parser_budget_is_bounded() {
        assert!(office_structure_size_allowed(MAX_OFFICE_STRUCTURE_BYTES));
        assert!(!office_structure_size_allowed(
            MAX_OFFICE_STRUCTURE_BYTES + 1
        ));
    }

    #[test]
    fn test_malformed_ole_keyword_fuzz_never_promotes() {
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        for len in (8usize..=4096).step_by(31) {
            let mut data = vec![0u8; len];
            data[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
            for byte in &mut data[8..] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let marker = b"VBA dir\0 AutoOpen";
            let api = b"WScript.Shell!!!";
            if len >= 16 + marker.len() + api.len() {
                let marker_end = 16 + marker.len();
                data[16..marker_end].copy_from_slice(marker);
                data[marker_end..marker_end + api.len()].copy_from_slice(api);
            }

            let result = analyze_active_content(&data, "fuzz.doc", "doc", "application/msword");
            assert_eq!(result.score, 0.0, "malformed sample length {len}");
            assert!(
                !result
                    .categories
                    .contains(&"office_macro_suspicious_behavior".to_string())
            );
        }
    }

    #[test]
    fn test_pdf_plain_text_does_not_trigger_short_aa_token() {
        let data = b"%PDF-1.7\n1 0 obj\n(regular text /aa marker)\nendobj\n";
        let result = analyze_active_content(data, "scan.pdf", "pdf", "application/pdf");
        assert!(
            !result
                .categories
                .contains(&"pdf_active_content".to_string())
        );
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_pdf_javascript_name_is_active_content() {
        let data = b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n";
        let result = analyze_active_content(data, "payload.pdf", "pdf", "application/pdf");
        assert!(
            result
                .categories
                .contains(&"pdf_active_content".to_string())
        );
        assert!(result.categories.contains(&"active_content".to_string()));
        assert!(result.score >= 0.25);
        assert_eq!(
            result.threat_score, 0.0,
            "generic PDF JavaScript is analyst-visible but not fusion-grade"
        );
        assert!(
            !result
                .categories
                .contains(&"pdf_active_payload".to_string()),
            "generic PDF JavaScript must not receive the actionable payload category"
        );
    }

    #[test]
    fn test_pdf_open_action_view_destination_is_not_active_content() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction [5 0 R /Fit] /Pages 6 0 R >>\nendobj\n";
        let result = analyze_active_content(data, "scan.pdf", "pdf", "application/pdf");

        assert!(
            !result
                .categories
                .contains(&"pdf_active_content".to_string()),
            "a page-fit destination is a view preference, not executable content: {:?}",
            result.categories
        );
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_pdf_form_icon_import_javascript_is_observation_only() {
        let data = br#"%PDF-1.7
1 0 obj <</Type/Catalog/AcroForm<</Fields[]>>>> endobj
79 0 obj <</JS(event.target.buttonImportIcon\(\);)/S/JavaScript>> endobj
80 0 obj <</JS(event.target.buttonImportIcon\(\);)/S/JavaScript>> endobj
"#;
        let result = analyze_active_content(data, "form.pdf", "pdf", "application/pdf");

        assert!(
            result
                .categories
                .contains(&"pdf_form_icon_import_observed".to_string()),
            "the bounded form helper should remain analyst-visible: {:?}",
            result.categories
        );
        assert!(
            !result
                .categories
                .contains(&"pdf_active_content".to_string()),
            "the exact icon-picker helper is not malicious active content: {:?}",
            result.categories
        );
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_pdf_form_icon_import_with_extra_javascript_remains_active() {
        let data = br#"%PDF-1.7
79 0 obj <</JS(event.target.buttonImportIcon\(\);app.launchURL\('https://malicious.example'\);)/S/JavaScript>> endobj
"#;
        let result = analyze_active_content(data, "payload.pdf", "pdf", "application/pdf");

        assert!(
            result
                .categories
                .contains(&"pdf_active_content".to_string()),
            "any statement added to the form helper must remain detected: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"pdf_active_payload".to_string())
        );
        assert!(result.threat_score >= 0.55);
        assert!(result.score >= 0.25);
    }

    #[test]
    fn test_encrypted_zip_attachment_is_flagged() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        let result = run_encrypted_check("payload.zip", "application/zip", &data);
        assert_eq!(
            result.score, 0.0,
            "coverage-only evidence must not score as threat"
        );
        assert!(result.categories.contains(&"encrypted_archive".to_string()));
        assert!(
            result
                .categories
                .contains(&"encrypted_attachment".to_string())
        );
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
    }

    #[test]
    fn test_password_protected_pdf_is_flagged() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\n";
        let result = run_encrypted_check("secure.pdf", "application/pdf", data);
        assert_eq!(
            result.score, 0.0,
            "coverage-only evidence must not score as threat"
        );
        assert!(result.categories.contains(&"encrypted_pdf".to_string()));
        assert!(
            result
                .categories
                .contains(&"encrypted_attachment".to_string())
        );
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
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
        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
    }

    #[test]
    fn test_image_zip_polyglot_is_flagged() {
        let mut data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        data.resize(96, 0);
        data.extend_from_slice(b"PK\x03\x04");
        let result = analyze_polyglot_container(&data, "photo.png", "png", "image/png");

        assert_eq!(result.score, 0.45);
        assert!(
            result
                .categories
                .contains(&"polyglot_container".to_string())
        );
    }

    #[test]
    fn test_executable_delivery_requires_instruction() {
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let observed = analyze_executable_delivery(&elf, "firmware.bin", "bin", false);
        assert_eq!(observed.score, 0.0);

        let flagged = analyze_executable_delivery(&elf, "firmware.bin", "bin", true);
        assert_eq!(flagged.score, 0.45);
        assert!(
            flagged
                .categories
                .contains(&"executable_delivery_lure".to_string())
        );
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
    fn generic_binary_mime_is_not_a_mismatch_for_declared_executable() {
        assert!(mime_matches_expected_type(
            "exe",
            "application/octet-stream",
            "application/x-ms"
        ));
        assert!(mime_matches_expected_type(
            "exe",
            "application/x-download",
            "application/x-ms"
        ));
    }

    #[test]
    fn version_segments_are_not_treated_as_double_extensions() {
        assert!(is_known_extension_segment("pdf"));
        assert!(is_known_extension_segment("exe"));
        assert!(!is_known_extension_segment("6"));
        assert!(!is_known_extension_segment(
            "4638-ljm329_v4_driveronlywebpack"
        ));
    }

    /// Production false positive (2026-11-13): a spreadsheet named after a
    /// mailbox (`cs@example.com.xlsx`) was flagged as a `.com.xlsx` double extension.
    #[test]
    fn inner_com_of_an_address_or_domain_is_not_a_double_extension() {
        for name in [
            "cs@example.com.xlsx",
            "www.example.com.pdf",
            "报表.example.com.docx",
        ] {
            let parts: Vec<&str> = name.split('.').collect();
            let last = parts[parts.len() - 1];
            assert!(inner_com_is_domain_suffix(&parts, last), "{name}");
        }
        for name in ["invoice.com.pdf", "cs@example.com.exe", "invoice.pdf.exe"] {
            let parts: Vec<&str> = name.split('.').collect();
            let last = parts[parts.len() - 1];
            assert!(!inner_com_is_domain_suffix(&parts, last), "{name}");
        }
    }

    #[test]
    fn document_lure_executable_is_distinct_from_vendor_installer() {
        assert!(has_dangerous_document_lure("对账单.exe", "exe"));
        assert!(has_dangerous_document_lure("invoice_2026.exe", "exe"));
        assert!(!has_dangerous_document_lure(
            "v4_driveronlywebpack-48.6.4638-ljm329_v4_driveronlywebpack.exe",
            "exe"
        ));
        assert!(!has_dangerous_document_lure("对账单.pdf", "pdf"));
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
            result
                .categories
                .contains(&"pdf_active_content".to_string()),
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
        assert!(
            !result
                .categories
                .contains(&"pdf_active_content".to_string())
        );
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
            result
                .categories
                .contains(&"pdf_active_content".to_string()),
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
    fn test_html_smuggling_reconstruction_delivery_chain_detected() {
        let data = br#"<!DOCTYPE html><html><body><script>
const bytes = Uint8Array.from(atob(payload), c => c.charCodeAt(0));
const blob = new Blob([bytes], {type: "application/octet-stream"});
const link = document.createElement("a");
link.href = URL.createObjectURL(blob); link.download = "invoice.zip"; link.click();
</script></body></html>"#;
        let result = analyze_active_content(data, "invoice.html", "html", "text/html");

        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "a decoder + Blob URL + download chain must remain detected: {:?}",
            result.categories
        );
        assert!(result.score >= 0.30);
    }

    #[test]
    fn test_html_smuggling_atob_invocation_variants_require_execution_sink() {
        // PoC bypass: `atob (` (whitespace before paren) and the dynamic
        // window["atob"] form did not match the literal `atob(` indicator.
        // Keep the decoder paired with an execution sink so ordinary template
        // decoding is not promoted into threat evidence.
        let spaced =
            b"<!DOCTYPE html><html><body><script>var p=atob (\"TVqQAAAA\");eval(p);</script></body></html>";
        let result = analyze_active_content(spaced, "a.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "spaced atob call must be detected: {:?}",
            result.categories
        );

        let dynamic = b"<!DOCTYPE html><html><body><script>var p=window[\"atob\"](\"TVqQAAAA\");eval(p);</script></body></html>";
        let result = analyze_active_content(dynamic, "b.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "dynamic atob call must be detected: {:?}",
            result.categories
        );

        // Entity-encoded atob must not hide either.
        let encoded = b"<!DOCTYPE html><html><body><script>var p=&#97;tob(\"TVqQAAAA\");eval(p);</script></body></html>";
        let result = analyze_active_content(encoded, "c.html", "html", "text/html");
        assert!(
            result.categories.contains(&"html_smuggling".to_string()),
            "entity-encoded atob must be detected: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_html_xlsx_template_decoder_is_observation_only() {
        let data = br#"<!DOCTYPE html><html><body>
<svg viewBox="0 0 16 16"><path d="M1 1h4v4z"/></svg>
<script>
var TEMPLATE_BASE64 = "UEsDBAoAAAAAAAEAIQAAAAAAAAAAAAAAAAAJAAAAZG9jUHJvcHMv";
var templateWb = XLSX.read(window.atob(TEMPLATE_BASE64), {type:"binary"});
</script></body></html>"#;
        let result = analyze_active_content(data, "report.html", "html", "text/html");

        assert!(
            result
                .categories
                .contains(&"html_active_content".to_string())
        );
        assert!(
            !result.categories.contains(&"html_smuggling".to_string()),
            "decoding an XLSX template without an execution/delivery sink is not HTML smuggling: {:?}",
            result.categories
        );
        assert!((result.score - 0.12).abs() < f64::EPSILON);
    }
}
