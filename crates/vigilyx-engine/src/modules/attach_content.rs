//! Attachment content scan module.
//!
//! Reuses the runtime keyword lists from `content_scan` and extends attachment
//! text extraction beyond plain text so PDF / OOXML / legacy Office documents
//! are covered by the same `/security/keywords` configuration.

use std::io::{Cursor, Read};
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::decode_base64_bytes_limited;
use vigilyx_parser::mime::MimeParser;

use crate::context::SecurityContext;
use crate::data_security::document_extract;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::html_utils::strip_html_tags;
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

pub struct AttachContentModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
    weak_phishing_keywords: Vec<String>,
    bec_phrases: Vec<String>,
}

impl Default for AttachContentModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachContentModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "attach_content".to_string(),
                name: "Attachment Content Analysis".to_string(),
                description: "Scan attachment text for runtime keywords and DLP signals"
                    .to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec!["attach_scan".to_string()],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords: effective.phishing_keywords,
            weak_phishing_keywords: effective.weak_phishing_keywords,
            bec_phrases: effective.bec_phrases,
        }
    }
}

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());
static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{17}[\dXx]\b").unwrap());

// URL extraction inside extracted attachment text. PDF / DOCX phishing
// commonly hides the malicious link inside an annotation or hyperlink target;
// once we extract document text we still need to surface those URLs so that
// downstream pipeline scoring can correlate them with intel / link_content.
//
// We deliberately use a permissive but bounded pattern so that we tolerate
// the noisy whitespace / line wraps produced by document text extractors.
static RE_ATTACH_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>\)\]\}"']{4,512}"#).unwrap());

// Suspicious URL features evaluated independently of the link_scan / link_content
// modules so that PDF / DOCX-only campaigns (no links in the email body) still
// surface a useful signal.
static RE_URL_AT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bhttps?://[^/\s]*@").unwrap());
static RE_URL_IP_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bhttps?://(?:\d{1,3}\.){3}\d{1,3}").unwrap());

// TLDs that are abused at far higher rates than legitimate corporate use,
// based on Spamhaus / SURBL "most abused TLDs" reports. Hits inside an
// attachment URL are weighted lightly — the goal is correlation, not
// outright blocking.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".zip", ".mov", ".tk", ".top", ".xyz", ".click", ".country", ".gq", ".ml", ".cf", ".ga",
    ".work", ".loan", ".cam", ".rest", ".bar", ".monster", ".buzz", ".live", ".surf", ".icu",
    ".cyou", ".lol",
];

const MAX_ATTACHMENT_TEXT_DECODE_BYTES: usize = 25 * 1024 * 1024;
const MAX_NESTED_ATTACHMENT_DEPTH: usize = 3;
const MAX_ARCHIVE_ENTRIES: usize = 64;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 10 * 1024 * 1024;
const MAX_NESTED_TEXT_CHARS: usize = 4 * 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_NESTED_EXPANDED_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_NESTED_ENTRIES: usize = 128;
const MAX_TOTAL_SCANNED_TEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct AttachmentExtractionBudget {
    remaining_input_bytes: usize,
    remaining_nested_bytes: usize,
    remaining_nested_entries: usize,
    remaining_text_bytes: usize,
    exhausted: bool,
}

impl Default for AttachmentExtractionBudget {
    fn default() -> Self {
        Self {
            remaining_input_bytes: MAX_TOTAL_ATTACHMENT_INPUT_BYTES,
            remaining_nested_bytes: MAX_TOTAL_NESTED_EXPANDED_BYTES,
            remaining_nested_entries: MAX_TOTAL_NESTED_ENTRIES,
            remaining_text_bytes: MAX_TOTAL_SCANNED_TEXT_BYTES,
            exhausted: false,
        }
    }
}

impl AttachmentExtractionBudget {
    fn decode_top_level(&mut self, encoded: &str, declared_size: usize) -> Option<Vec<u8>> {
        let per_attachment_limit = MAX_ATTACHMENT_TEXT_DECODE_BYTES;
        let limit = per_attachment_limit.min(self.remaining_input_bytes);
        if declared_size > limit {
            self.exhausted = true;
            return None;
        }

        let decoded = decode_base64_bytes_limited(encoded, limit);
        let Some(decoded) = decoded else {
            if encoded.len().saturating_mul(3) / 4 > limit {
                self.exhausted = true;
            }
            return None;
        };
        self.remaining_input_bytes = self.remaining_input_bytes.saturating_sub(decoded.len());
        Some(decoded)
    }

    fn reserve_nested_entry(&mut self, size: usize) -> bool {
        if self.remaining_nested_entries == 0 || size > self.remaining_nested_bytes {
            self.exhausted = true;
            return false;
        }
        self.remaining_nested_entries -= 1;
        self.remaining_nested_bytes -= size;
        true
    }

    fn retain_scannable_text(&mut self, mut text: String) -> Option<String> {
        if text.is_empty() || self.remaining_text_bytes == 0 {
            if !text.is_empty() {
                self.exhausted = true;
            }
            return None;
        }

        if text.len() > self.remaining_text_bytes {
            self.exhausted = true;
            truncate_utf8(&mut text, self.remaining_text_bytes);
        }
        self.remaining_text_bytes = self.remaining_text_bytes.saturating_sub(text.len());
        if text.is_empty() { None } else { Some(text) }
    }
}

/// Heuristics for individual URLs found inside attachment text. Returns a
/// list of `(reason, weight)` tuples so the caller can both score and
/// surface evidence.
fn classify_attachment_url(url: &str) -> Vec<(&'static str, f64)> {
    let mut hits: Vec<(&'static str, f64)> = Vec::new();
    let url_lower = url.to_ascii_lowercase();

    if RE_URL_AT.is_match(url) {
        hits.push((
            "contains @ in authority (credential or display spoofing)",
            0.30,
        ));
    }
    if RE_URL_IP_HOST.is_match(url) {
        hits.push(("uses raw IP address as host", 0.25));
    }
    if url.len() > 200 {
        hits.push(("excessively long URL (>200 chars)", 0.10));
    }
    // Extract host for TLD / scheme checks
    if let Some(rest) = url_lower.strip_prefix("http://") {
        hits.push(("plaintext http:// inside document", 0.10));
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        if SUSPICIOUS_TLDS.iter().any(|tld| host.ends_with(tld)) {
            hits.push(("suspicious TLD", 0.15));
        }
    } else if let Some(rest) = url_lower.strip_prefix("https://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        if SUSPICIOUS_TLDS.iter().any(|tld| host.ends_with(tld)) {
            hits.push(("suspicious TLD", 0.15));
        }
    }
    // Embedded credential phishing markers
    if url_lower.contains("login") || url_lower.contains("verify") || url_lower.contains("account")
    {
        hits.push(("auth-themed path segment", 0.10));
    }
    // OAuth / device-code phishing artifacts
    if url_lower.contains("device/code") || url_lower.contains("device-login") {
        hits.push(("OAuth device-code endpoint", 0.30));
    }
    hits
}

fn is_text_mime_candidate(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("text/")
        || ct.contains("application/json")
        || ct.contains("application/xml")
        || ct.contains("application/csv")
        || ct.contains("text/calendar")
        || ct.contains("message/rfc822")
}

fn decode_plain_text_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn extract_attachment_text(
    filename: &str,
    content_type: &str,
    content_base64: &str,
    declared_size: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    let bytes = budget.decode_top_level(content_base64, declared_size)?;
    extract_attachment_text_from_bytes(filename, content_type, &bytes, 0, budget)
}

fn extract_attachment_text_from_bytes(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
    depth: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }

    let file_type = detect_file_type(bytes);
    let ext = file_extension(filename);

    if is_eml_candidate(ext.as_deref(), content_type, file_type) {
        return extract_nested_eml_text(bytes, depth, budget);
    }

    if file_type == Some(DetectedFileType::ZipArchive) {
        let direct_text = if is_ooxml_or_odf_extension(ext.as_deref()) {
            cap_optional_text(document_extract::extract_text(bytes, file_type))
        } else {
            None
        };
        let nested_text = extract_nested_zip_text(bytes, depth, budget);

        return join_optional_text(direct_text, nested_text);
    }

    if file_type.is_some_and(|ft| ft.is_extractable_document()) {
        return cap_optional_text(document_extract::extract_text(bytes, file_type));
    }

    if file_type == Some(DetectedFileType::HtmlDocument)
        || ext
            .as_deref()
            .is_some_and(|ext| matches!(ext, "html" | "htm" | "xhtml" | "hta"))
    {
        let html = decode_plain_text_bytes(bytes)?;
        let text = strip_html_tags(&html).trim().to_string();
        return if text.is_empty() {
            None
        } else {
            Some(cap_text(text))
        };
    }

    if file_type.is_some_and(|ft| ft.is_text_scannable())
        || is_text_mime_candidate(content_type)
        || is_plain_text_extension(ext.as_deref())
    {
        return cap_optional_text(decode_plain_text_bytes(bytes));
    }

    None
}

fn file_extension(filename: &str) -> Option<String> {
    filename
        .rsplit_once('.')
        .map(|(_, ext)| {
            ext.trim_matches(|ch| ch == '"' || ch == '\'')
                .to_ascii_lowercase()
        })
        .filter(|ext| !ext.is_empty())
}

fn is_ooxml_or_odf_extension(ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some("docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "odt" | "ods" | "odp")
    )
}

fn is_plain_text_extension(ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some(
            "txt"
                | "csv"
                | "json"
                | "xml"
                | "log"
                | "md"
                | "ics"
                | "vcf"
                | "yaml"
                | "yml"
                | "ini"
                | "cfg"
        )
    )
}

fn is_eml_candidate(
    ext: Option<&str>,
    content_type: &str,
    file_type: Option<DetectedFileType>,
) -> bool {
    let ct = content_type.to_ascii_lowercase();
    matches!(ext, Some("eml"))
        || ct.contains("message/rfc822")
        || (file_type == Some(DetectedFileType::PlainText)
            && ct.contains("application/vnd.ms-outlook"))
}

fn is_archive_scan_candidate(filename: &str, file_type: Option<DetectedFileType>) -> bool {
    let ext = file_extension(filename);
    matches!(
        ext.as_deref(),
        Some(
            "pdf"
                | "doc"
                | "xls"
                | "ppt"
                | "docx"
                | "xlsx"
                | "pptx"
                | "rtf"
                | "txt"
                | "csv"
                | "json"
                | "xml"
                | "html"
                | "htm"
                | "ics"
                | "eml"
                | "zip"
        )
    ) || file_type.is_some_and(|ft| ft.is_extractable_document() || ft.is_text_scannable())
}

fn is_attachment_text_candidate_by_metadata(filename: &str, content_type: &str) -> bool {
    let ext = file_extension(filename);
    let ct = content_type.to_ascii_lowercase();
    is_plain_text_extension(ext.as_deref())
        || is_ooxml_or_odf_extension(ext.as_deref())
        || matches!(
            ext.as_deref(),
            Some("pdf" | "doc" | "xls" | "ppt" | "rtf" | "html" | "htm" | "eml" | "zip")
        )
        || is_text_mime_candidate(&ct)
        || ct.contains("pdf")
        || ct.contains("rtf")
        || ct.contains("officedocument")
        || ct.contains("opendocument")
        || ct.contains("application/zip")
        || ct.contains("application/octet-stream")
}

fn truncate_utf8(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

fn cap_text(mut text: String) -> String {
    truncate_utf8(&mut text, MAX_NESTED_TEXT_CHARS);
    text
}

fn cap_optional_text(text: Option<String>) -> Option<String> {
    text.map(cap_text).filter(|text| !text.trim().is_empty())
}

fn append_nested_text(target: &mut String, text: &str) {
    let separator_len = usize::from(!target.is_empty());
    let remaining = MAX_NESTED_TEXT_CHARS.saturating_sub(target.len() + separator_len);
    if remaining == 0 {
        return;
    }
    if !target.is_empty() {
        target.push('\n');
    }
    let mut end = remaining.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&text[..end]);
}

fn join_optional_text(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(mut left), Some(right)) => {
            append_nested_text(&mut left, &right);
            Some(left)
        }
        (Some(text), None) | (None, Some(text)) => Some(text),
        (None, None) => None,
    }
}

fn extract_nested_zip_text(
    bytes: &[u8],
    depth: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    if depth >= MAX_NESTED_ATTACHMENT_DEPTH {
        budget.exhausted = true;
        return None;
    }

    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let mut out = String::new();

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        budget.exhausted = true;
    }
    let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
    for i in 0..entry_count {
        if out.len() >= MAX_NESTED_TEXT_CHARS {
            budget.exhausted = true;
            break;
        }

        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }

        let name = entry.name().to_string();
        let Ok(entry_size) = usize::try_from(entry.size()) else {
            budget.exhausted = true;
            continue;
        };
        if entry_size > MAX_ARCHIVE_ENTRY_BYTES {
            budget.exhausted = true;
            continue;
        }
        if !budget.reserve_nested_entry(entry_size) {
            continue;
        }

        let mut data = Vec::with_capacity((entry.size() as usize).min(64 * 1024));
        let limit = (MAX_ARCHIVE_ENTRY_BYTES + 1) as u64;
        if (&mut entry).take(limit).read_to_end(&mut data).is_err()
            || data.len() > MAX_ARCHIVE_ENTRY_BYTES
        {
            continue;
        }

        let nested_type = detect_file_type(&data);
        if !is_archive_scan_candidate(&name, nested_type) {
            continue;
        }

        if let Some(text) = extract_attachment_text_from_bytes(&name, "", &data, depth + 1, budget)
        {
            append_nested_text(&mut out, &format!("[{name}]\n{text}"));
        }
    }

    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_nested_eml_text(
    bytes: &[u8],
    depth: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    if depth >= MAX_NESTED_ATTACHMENT_DEPTH {
        budget.exhausted = true;
        return None;
    }

    let parser = MimeParser::new();
    let content = parser.parse(bytes).ok()?;
    let mut out = String::new();

    for header in ["Subject", "From", "To"] {
        if let Some(value) = content.get_header(header) {
            append_nested_text(&mut out, &format!("{header}: {value}"));
        }
    }

    if let Some(text) = content.body_text.as_deref() {
        append_nested_text(&mut out, text);
    }
    if let Some(html) = content.body_html.as_deref() {
        append_nested_text(&mut out, &strip_html_tags(html));
    }

    if content.attachments.len() > 16 {
        budget.exhausted = true;
    }
    for attachment in content.attachments.iter().take(16) {
        let Some(content_base64) = attachment.content_base64.as_deref() else {
            continue;
        };
        if attachment.size > MAX_ATTACHMENT_TEXT_DECODE_BYTES
            || !budget.reserve_nested_entry(attachment.size)
        {
            budget.exhausted = true;
            continue;
        }
        let Some(bytes) = decode_base64_bytes_limited(content_base64, attachment.size) else {
            continue;
        };
        if let Some(text) = extract_attachment_text_from_bytes(
            &attachment.filename,
            &attachment.content_type,
            &bytes,
            depth + 1,
            budget,
        ) {
            append_nested_text(&mut out, &format!("[{}]\n{text}", attachment.filename));
        }
    }

    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn scan_attachment_text(
    text: &str,
    filename: &str,
    phishing_keywords: &[String],
    weak_phishing_keywords: &[String],
    bec_phrases: &[String],
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score: f64 = 0.0;
    let text_lower = normalize_text(&text.to_lowercase())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut phishing_hits = Vec::new();
    for kw in phishing_keywords {
        if text_lower.contains(kw.as_str()) {
            phishing_hits.push(kw.clone());
        }
    }
    if !phishing_hits.is_empty() {
        score += (phishing_hits.len() as f64 * 0.08).min(0.5);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} phishing keyword(s)",
                filename,
                phishing_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(phishing_hits.join(", ")),
        });
    }

    let mut weak_hits = Vec::new();
    for kw in weak_phishing_keywords {
        if text_lower.contains(kw.as_str()) {
            weak_hits.push(kw.clone());
        }
    }
    if weak_hits.len() >= 3 {
        score += (weak_hits.len() as f64 * 0.03).min(0.18);
        categories.push("weak_phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} weak phishing keyword(s)",
                filename,
                weak_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(weak_hits.join(", ")),
        });
    }

    let mut bec_hits = Vec::new();
    for phrase in bec_phrases {
        if text_lower.contains(phrase.as_str()) {
            bec_hits.push(phrase.clone());
        }
    }
    if !bec_hits.is_empty() {
        score += (bec_hits.len() as f64 * 0.10).min(0.4);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} BEC phrase(s)",
                filename,
                bec_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(bec_hits.join(", ")),
        });
    }

    let cc_count = RE_CREDIT_CARD.find_iter(text).count();
    if cc_count > 0 {
        score += 0.25;
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} possible credit card number(s)",
                filename, cc_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    let id_count = RE_CHINESE_ID.find_iter(text).count();
    if id_count > 0 {
        score += 0.20;
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} possible Chinese ID number(s)",
                filename, id_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    score
}

#[async_trait]
impl SecurityModule for AttachContentModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut scanned_count = 0usize;
        let mut retained_count = 0usize;
        let mut budget = AttachmentExtractionBudget::default();

        for attachment in &ctx.session.content.attachments {
            if attachment.size > MAX_ATTACHMENT_TEXT_DECODE_BYTES {
                if is_attachment_text_candidate_by_metadata(
                    &attachment.filename,
                    &attachment.content_type,
                ) {
                    budget.exhausted = true;
                }
                continue;
            }
            let Some(content_base64) = attachment.content_base64.as_deref() else {
                continue;
            };
            retained_count += 1;

            let Some(text) = extract_attachment_text(
                &attachment.filename,
                &attachment.content_type,
                content_base64,
                attachment.size,
                &mut budget,
            ) else {
                continue;
            };
            let Some(text) = budget.retain_scannable_text(text) else {
                continue;
            };

            scanned_count += 1;
            total_score += scan_attachment_text(
                &text,
                &attachment.filename,
                &self.phishing_keywords,
                &self.weak_phishing_keywords,
                &self.bec_phrases,
                &mut evidence,
                &mut categories,
            );

            // Extract embedded URLs from the document text and run our
            // structural heuristics on each one. PDF / DOCX phishing routinely
            // hides the malicious link as a text annotation that the body of
            // the email never references — without this pass those campaigns
            // produce zero link-layer signal.
            let mut url_score_for_attachment = 0.0f64;
            let mut url_count = 0usize;
            for m in RE_ATTACH_URL.find_iter(&text).take(20) {
                let url = m.as_str();
                url_count += 1;
                let hits = classify_attachment_url(url);
                if hits.is_empty() {
                    continue;
                }
                let local: f64 = hits.iter().map(|(_, w)| *w).sum::<f64>().min(0.45);
                url_score_for_attachment += local;
                let reasons: Vec<&'static str> = hits.iter().map(|(r, _)| *r).collect();
                evidence.push(Evidence {
                    description: format!(
                        "Suspicious URL inside `{}`: {}",
                        attachment.filename,
                        reasons.join("; ")
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: Some(url.chars().take(160).collect::<String>()),
                });
                categories.push("attachment_phishing_url".to_string());
            }
            // Cap the per-attachment URL contribution so a single document
            // packed with junk links cannot single-handedly trip a verdict.
            total_score += url_score_for_attachment.min(0.55);
            if url_count >= 5 {
                // High link density inside a document is itself a weak
                // structural signal (template campaigns).
                total_score += 0.05;
                categories.push("attachment_link_density".to_string());
            }
        }

        if budget.exhausted {
            total_score += 0.15;
            categories.push("attachment_inspection_limited".to_string());
            evidence.push(Evidence {
                description: "Attachment content inspection reached its per-message resource budget; remaining content requires deferred sandbox scanning"
                    .to_string(),
                location: Some("attachments".to_string()),
                snippet: None,
            });
        }

        if scanned_count == 0 && !budget.exhausted {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No attachments with extractable text content",
                duration_ms,
            ));
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
                    "Scanned {} attachment(s) with extractable text, no threats found",
                    scanned_count
                ),
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.80,
            categories,
            summary: format!(
                "Attachment content analysis found {} finding(s) across {} scanned attachment(s)",
                evidence.len(),
                scanned_count
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "scanned_count": scanned_count,
                "retained_attachments": retained_count,
                "inspection_budget_exhausted": budget.exhausted,
                "input_bytes_scanned": MAX_TOTAL_ATTACHMENT_INPUT_BYTES - budget.remaining_input_bytes,
                "nested_expanded_bytes_scanned": MAX_TOTAL_NESTED_EXPANDED_BYTES - budget.remaining_nested_bytes,
                "nested_entries_examined": MAX_TOTAL_NESTED_ENTRIES - budget.remaining_nested_entries,
                "text_bytes_scanned": MAX_TOTAL_SCANNED_TEXT_BYTES - budget.remaining_text_bytes,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::sync::Arc;

    use base64::Engine as _;
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_ctx(attachments: Vec<EmailAttachment>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_module_with_keywords(
        phishing_keywords: &[&str],
        weak_phishing_keywords: &[&str],
    ) -> AttachContentModule {
        AttachContentModule::new_with_keyword_lists(EffectiveKeywordLists {
            phishing_keywords: phishing_keywords
                .iter()
                .map(|keyword| normalize_text(&keyword.to_lowercase()))
                .collect(),
            weak_phishing_keywords: weak_phishing_keywords
                .iter()
                .map(|keyword| normalize_text(&keyword.to_lowercase()))
                .collect(),
            ..Default::default()
        })
    }

    fn build_docx_like_attachment_xml(text: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>
</w:document>"#
        )
    }

    fn build_ooxml_zip(files: &[(&str, &str)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip_w = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for (name, content) in files {
            zip_w.start_file(name, options).expect("start zip entry");
            zip_w
                .write_all(content.as_bytes())
                .expect("write zip entry");
        }

        zip_w.finish().expect("finish zip").into_inner()
    }

    fn make_attachment(filename: &str, content_type: &str, bytes: &[u8]) -> EmailAttachment {
        EmailAttachment {
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            size: bytes.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        }
    }

    #[tokio::test]
    async fn test_docx_attachment_uses_runtime_keywords() {
        let docx = build_ooxml_zip(&[(
            "word/document.xml",
            &build_docx_like_attachment_xml(
                "Please review the secure voicemail and verify your account immediately",
            ),
        )]);
        let attachment = make_attachment(
            "voicemail.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            &docx,
        );

        let result = make_module_with_keywords(&["secure voicemail", "verify your account"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "OOXML attachment text should reuse runtime keywords: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_rtf_attachment_uses_runtime_keywords() {
        let rtf = br"{\rtf1\ansi Please \b verify your account\b0 before closing.}";
        let attachment = make_attachment("notice.rtf", "application/rtf", rtf);

        let result = make_module_with_keywords(&["verify your account", "before closing"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "RTF attachment text should be scanned: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_zip_nested_document_attachment_is_scanned() {
        let zip = build_ooxml_zip(&[(
            "invoice.rtf",
            r"{\rtf1\ansi Please verify your account to view the invoice.}",
        )]);
        let attachment = make_attachment("invoice_bundle.zip", "application/zip", &zip);

        let result = make_module_with_keywords(&["verify your account", "view the invoice"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "documents nested in ZIP attachments should be scanned: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_nested_eml_attachment_is_scanned() {
        let nested_body = "Please verify your account using the attached notice.";
        let nested_body_b64 =
            base64::engine::general_purpose::STANDARD.encode(nested_body.as_bytes());
        let eml = format!(
            "From: vendor@example.com\r\n\
             Subject: forwarded notice\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"B\"\r\n\
             \r\n\
             --B\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             \r\n\
             See attached.\r\n\
             --B\r\n\
             Content-Type: text/plain; name=\"notice.txt\"\r\n\
             Content-Disposition: attachment; filename=\"notice.txt\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {nested_body_b64}\r\n\
             --B--\r\n"
        );
        let attachment = make_attachment("thread.eml", "message/rfc822", eml.as_bytes());

        let result = make_module_with_keywords(&["verify your account", "attached notice"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "nested EML content should be scanned: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_plain_text_attachment_uses_weak_keyword_list() {
        let content =
            "Please review today the employee handbook acknowledgement policy document update";
        let attachment = make_attachment("notice.txt", "text/plain", content.as_bytes());

        let result = make_module_with_keywords(
            &[],
            &[
                "employee handbook",
                "acknowledgement",
                "policy document",
                "document update",
                "review today",
            ],
        )
        .analyze(&make_ctx(vec![attachment]))
        .await
        .unwrap();

        assert!(
            result.categories.contains(&"weak_phishing".to_string()),
            "weak phishing keywords from runtime config should be honored: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_binary_image_attachment_is_not_scanned_as_text() {
        let png_stub = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];
        let attachment = make_attachment("logo.png", "image/png", &png_stub);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(
            result.summary,
            "No attachments with extractable text content"
        );
    }

    #[tokio::test]
    async fn test_uninspectable_oversized_attachment_surfaces_incomplete_coverage() {
        let attachment = EmailAttachment {
            filename: "oversized.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: MAX_ATTACHMENT_TEXT_DECODE_BYTES + 1,
            hash: "hash".to_string(),
            content_base64: Some("QQ==".to_string()),
        };

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string())
        );
        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert_eq!(result.details["inspection_budget_exhausted"], true);
    }

    #[tokio::test]
    async fn test_oversized_known_non_text_attachment_does_not_create_coverage_alert() {
        let attachment = EmailAttachment {
            filename: "training.mp4".to_string(),
            content_type: "video/mp4".to_string(),
            size: MAX_ATTACHMENT_TEXT_DECODE_BYTES + 1,
            hash: "hash".to_string(),
            content_base64: Some("AAAA".to_string()),
        };

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(
            result.summary,
            "No attachments with extractable text content"
        );
    }

    #[test]
    fn test_attachment_budget_rejects_cumulative_top_level_overflow() {
        let mut budget = AttachmentExtractionBudget {
            remaining_input_bytes: 2,
            ..Default::default()
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"abc");

        assert!(budget.decode_top_level(&encoded, 3).is_none());
        assert!(budget.exhausted);
        assert_eq!(budget.remaining_input_bytes, 2);
    }

    #[test]
    fn test_attachment_budget_enforces_nested_entry_count_and_bytes() {
        let mut budget = AttachmentExtractionBudget {
            remaining_nested_bytes: 4,
            remaining_nested_entries: 1,
            ..Default::default()
        };

        assert!(budget.reserve_nested_entry(4));
        assert!(!budget.reserve_nested_entry(1));
        assert!(budget.exhausted);
        assert_eq!(budget.remaining_nested_bytes, 0);
        assert_eq!(budget.remaining_nested_entries, 0);
    }

    #[test]
    fn test_attachment_budget_truncates_utf8_at_cumulative_text_limit() {
        let mut budget = AttachmentExtractionBudget {
            remaining_text_bytes: 4,
            ..Default::default()
        };

        let retained = budget
            .retain_scannable_text("测ab".to_string())
            .expect("a UTF-8 prefix should remain");

        assert_eq!(retained, "测a");
        assert!(budget.exhausted);
        assert_eq!(budget.remaining_text_bytes, 0);
    }

    #[test]
    fn test_nested_archive_at_depth_limit_marks_incomplete_inspection() {
        let zip = build_ooxml_zip(&[]);
        let mut budget = AttachmentExtractionBudget::default();

        let text = extract_nested_zip_text(&zip, MAX_NESTED_ATTACHMENT_DEPTH, &mut budget);

        assert!(text.is_none());
        assert!(budget.exhausted);
    }

    #[test]
    fn test_archive_entry_limit_marks_incomplete_inspection() {
        let cursor = Cursor::new(Vec::new());
        let mut zip_w = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for index in 0..=MAX_ARCHIVE_ENTRIES {
            zip_w
                .start_file(format!("entry-{index}.txt"), options)
                .expect("start zip entry");
            zip_w.write_all(b"normal text").expect("write zip entry");
        }
        let zip = zip_w.finish().expect("finish zip").into_inner();
        let mut budget = AttachmentExtractionBudget::default();

        let text = extract_nested_zip_text(&zip, 0, &mut budget);

        assert!(text.is_some());
        assert!(budget.exhausted);
    }
}
