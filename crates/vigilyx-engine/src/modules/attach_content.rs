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
use tracing::debug;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::{EmailAttachment, decode_base64_bytes_limited};
use vigilyx_parser::mime::{MimeParser, decode_rfc2047};

use crate::context::SecurityContext;
use crate::data_security::document_extract;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::common::is_probable_schema_reference_url;
use crate::modules::content_scan::html_utils::{decode_html_entities, strip_html_tags};
use crate::modules::content_scan::{EffectiveKeywordLists, is_strong_bec_phrase, normalize_text};

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

// URL extraction inside extracted attachment text. PDF / DOCX phishing
// commonly hides the malicious link inside an annotation or hyperlink target;
// once we extract document text we still need to surface those URLs so that
// downstream pipeline scoring can correlate them with intel / link_content.
//
// We deliberately use a permissive but bounded pattern so that we tolerate
// the noisy whitespace / line wraps produced by document text extractors.
static RE_ATTACH_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>\)\]\}"']{4,512}"#).unwrap());

// Attribute URLs inside HTML attachments. Tag stripping (strip_html_tags)
// discards every attribute, so a pure `<a href="https://evil.example">` lure
// or a `<form action=...>` credential endpoint would otherwise leave no URL
// signal at all. Quoted and unquoted attribute forms are both accepted.
static RE_HTML_ATTR_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:href|src|action)\s*=\s*(?:"([^"<>\s]{4,1024})"|'([^'<>\s]{4,1024})'|([^\s>"']{4,1024}))"#).unwrap()
});

// `<meta>` tags and their `content` attribute, used to locate
// `http-equiv=refresh` redirect targets attribute-order independently.
static RE_META_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
static RE_META_CONTENT_ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)content\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap()
});
static RE_HTML_FORM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<form\b[^>]*>(.*?)</form\s*>").unwrap());
static RE_HTML_CREDENTIAL_INPUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<input\b[^>]*(?:type\s*=\s*["']?password|name\s*=\s*["']?(?:password|passwd|pwd|email|username|user)|autocomplete\s*=\s*["']?(?:current-password|username))[^>]*>"#,
    )
    .unwrap()
});

const MAX_HTML_ATTRIBUTE_URLS: usize = 32;
const MAX_META_REFRESH_URLS: usize = 8;

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

/// Extracted attachment text plus the structural signals discovered while
/// producing it. `<meta http-equiv="refresh">` redirect targets live inside
/// tag attributes that stripping discards, so they are carried alongside the
/// text instead of being re-derivable from it.
#[derive(Debug, Default)]
struct ExtractedText {
    text: String,
    meta_refresh_urls: Vec<String>,
    credential_form: bool,
    nested_message: bool,
}

impl ExtractedText {
    fn from_text(text: String) -> Self {
        Self {
            text,
            meta_refresh_urls: Vec::new(),
            credential_form: false,
            nested_message: false,
        }
    }
}

fn merge_meta_refresh_urls(target: &mut Vec<String>, extra: Vec<String>) {
    for url in extra {
        if target.len() >= MAX_META_REFRESH_URLS {
            break;
        }
        target.push(url);
    }
}

fn html_contains_credential_form(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    RE_HTML_FORM.captures_iter(&lower).any(|caps| {
        let form = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        let form_has_action = form.contains("action=") && form.contains("http");
        let form_has_credential_word = [
            "password",
            "passwd",
            "credential",
            "verify your account",
            "验证",
            "密碼",
            "密码",
        ]
        .iter()
        .any(|term| form.contains(term));
        form_has_action
            && (RE_HTML_CREDENTIAL_INPUT.is_match(form) || form_has_credential_word)
    })
}

/// Extract scannable text from an HTML attachment: visible text plus the
/// URLs hidden in `href`/`src`/`action` attributes and `<meta refresh>`
/// targets. Entity decoding is applied to captured attribute values, while
/// the original markup is passed to the tag stripper so escaped markup such as
/// `&lt;form&gt;` never becomes a real credential form during analysis.
fn extract_html_attachment_text(html: &str) -> Option<ExtractedText> {
    let mut attribute_urls: Vec<String> = Vec::new();
    for caps in RE_HTML_ATTR_URL
        .captures_iter(html)
        .take(MAX_HTML_ATTRIBUTE_URLS)
    {
        let raw_url = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|m| m.as_str())
            .unwrap_or("");
        let url = decode_html_entities(raw_url);
        // Only absolute http(s) URLs carry weight downstream; relative paths
        // and `data:`/`javascript:` payloads stay out of the URL heuristics.
        if url.to_ascii_lowercase().starts_with("http") {
            attribute_urls.push(url);
        }
    }

    let meta_refresh_urls = extract_meta_refresh_targets(html);
    let credential_form = html_contains_credential_form(html);

    let mut text = strip_html_tags(html).trim().to_string();
    // Surface the recovered URLs as plain text so RE_ATTACH_URL and the
    // keyword scans can see them after tag stripping.
    for url in attribute_urls.iter().chain(meta_refresh_urls.iter()) {
        text.push(' ');
        text.push_str(url);
    }

    if text.is_empty() && meta_refresh_urls.is_empty() {
        return None;
    }
    Some(ExtractedText {
        text,
        meta_refresh_urls,
        credential_form,
        nested_message: false,
    })
}

fn extract_meta_refresh_targets(html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for tag_match in RE_META_TAG.find_iter(html) {
        if urls.len() >= MAX_META_REFRESH_URLS {
            break;
        }
        let tag = tag_match.as_str();
        let tag_lower = tag.to_lowercase();
        if !(tag_lower.contains("http-equiv") && tag_lower.contains("refresh")) {
            continue;
        }
        let Some(content_caps) = RE_META_CONTENT_ATTR.captures(tag) else {
            continue;
        };
        let content = content_caps
            .get(1)
            .or_else(|| content_caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        let decoded_content = decode_html_entities(content);
        if let Some(target) = meta_refresh_content_url(&decoded_content) {
            urls.push(target);
        }
    }
    urls
}

/// Parse the `<seconds>; url=<target>` payload of a meta-refresh `content`
/// attribute, tolerating arbitrary whitespace and casing around the tokens.
fn meta_refresh_content_url(content: &str) -> Option<String> {
    let lower = content.to_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"url" {
            // Make sure this is the start of a token (not e.g. "curl=").
            let prev_is_boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b',');
            if !prev_is_boundary {
                i += 1;
                continue;
            }
            let mut j = i + 3;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                j += 1;
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                let url = lower
                    .get(j..)
                    .unwrap_or("")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_string();
                if !url.is_empty() {
                    return Some(url);
                }
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Unfold RFC 5545 §3.1 continuation lines: a CRLF followed by a single
/// space or tab continues the previous line. Folded URLs / ATTACH payloads
/// would otherwise be split across the scan text and hide from both the URL
/// regex and the structured ICS checks.
fn unfold_ics_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let continuation = line
            .strip_prefix(' ')
            .or_else(|| line.strip_prefix('\t'));
        match continuation {
            Some(rest) if !out.is_empty() => out.push_str(rest),
            _ => {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(line);
            }
        }
    }
    out
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

/// Return true when extracted attachment text contains a credential-oriented
/// lure rather than merely generic business language.  This is intentionally
/// a small structural gate: it is only consumed together with a suspicious
/// URL and either an HTML credential form or a nested message, so a normal
/// document mentioning an account or a password does not become a standalone
/// attachment verdict.
fn attachment_has_credential_lure(text: &str) -> bool {
    let normalized = normalize_text(&text.to_lowercase());
    let has_identity = [
        "account",
        "账户",
        "帐户",
        "用户",
        "identity",
        "身份",
        "login",
        "登录",
        "sign in",
        "signin",
    ]
    .iter()
    .any(|term| normalized.contains(term));
    let has_secret = [
        "password",
        "passwd",
        "credential",
        "密码",
        "口令",
        "凭据",
        "enter",
        "输入",
    ]
    .iter()
    .any(|term| normalized.contains(term));
    let has_verification = [
        "verify",
        "verification",
        "confirm",
        "authenticate",
        "验证",
        "确认",
        "认证",
        "click",
        "点击",
        "immediately",
        "立即",
    ]
    .iter()
    .any(|term| normalized.contains(term));

    (has_identity && (has_secret || has_verification)) || (has_secret && has_verification)
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
) -> Option<ExtractedText> {
    let bytes = budget.decode_top_level(content_base64, declared_size)?;
    extract_attachment_text_from_bytes(filename, content_type, &bytes, 0, budget)
}

/// Bounded attachment text made available to policy engines such as outbound
/// DLP. `complete=false` means at least one attachment that should have been
/// inspectable was unavailable, failed extraction, or exhausted a resource
/// budget; callers must apply an explicit fail-safe policy.
#[derive(Debug, Default)]
pub struct PolicyAttachmentText {
    pub text: String,
    pub complete: bool,
    pub scanned_count: usize,
}

pub fn extract_attachment_text_for_policy(attachments: &[EmailAttachment]) -> PolicyAttachmentText {
    let mut budget = AttachmentExtractionBudget::default();
    let mut output = String::new();
    let mut complete = true;
    let mut scanned_count = 0usize;

    for attachment in attachments {
        let metadata_candidate = is_attachment_text_candidate_by_metadata(
            &attachment.filename,
            &attachment.content_type,
        );
        if attachment.size > MAX_ATTACHMENT_TEXT_DECODE_BYTES {
            complete &= !metadata_candidate;
            if metadata_candidate {
                budget.exhausted = true;
            }
            continue;
        }
        let Some(content_base64) = attachment.content_base64.as_deref() else {
            complete &= !metadata_candidate;
            continue;
        };
        let Some(text) = extract_attachment_text(
            &attachment.filename,
            &attachment.content_type,
            content_base64,
            attachment.size,
            &mut budget,
        ) else {
            complete &= !metadata_candidate;
            continue;
        };
        let Some(text) = budget.retain_scannable_text(text.text) else {
            complete = false;
            continue;
        };

        output.push_str("\n[attachment:");
        output.push_str(&attachment.filename);
        output.push_str("]\n");
        output.push_str(&text);
        scanned_count += 1;
    }

    PolicyAttachmentText {
        text: output,
        complete: complete && !budget.exhausted,
        scanned_count,
    }
}

fn extract_attachment_text_from_bytes(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
    depth: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<ExtractedText> {
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
                .map(ExtractedText::from_text)
        } else {
            None
        };
        let nested_text = extract_nested_zip_text(bytes, depth, budget);

        return join_optional_text(direct_text, nested_text);
    }

    if file_type.is_some_and(|ft| ft.is_extractable_document()) {
        return cap_optional_text(document_extract::extract_text(bytes, file_type))
            .map(ExtractedText::from_text);
    }

    if file_type == Some(DetectedFileType::HtmlDocument)
        || ext
            .as_deref()
            .is_some_and(|ext| matches!(ext, "html" | "htm" | "xhtml" | "hta"))
    {
        let html = decode_plain_text_bytes(bytes)?;
        let extracted = extract_html_attachment_text(&html)?;
        return Some(ExtractedText {
            text: cap_text(extracted.text),
            meta_refresh_urls: extracted.meta_refresh_urls,
            credential_form: extracted.credential_form,
            nested_message: extracted.nested_message,
        });
    }

    // iCalendar invites (.ics / text/calendar) are line-folded; unfold before
    // scanning so wrapped URLs and ATTACH payloads stay contiguous.
    if ext.as_deref().is_some_and(|ext| ext == "ics")
        || content_type.to_lowercase().contains("text/calendar")
    {
        let text = decode_plain_text_bytes(bytes)?;
        return cap_optional_text(Some(unfold_ics_lines(&text))).map(ExtractedText::from_text);
    }

    if file_type.is_some_and(|ft| ft.is_text_scannable())
        || is_text_mime_candidate(content_type)
        || is_plain_text_extension(ext.as_deref())
    {
        return cap_optional_text(decode_plain_text_bytes(bytes)).map(ExtractedText::from_text);
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
    // MHTML (.mht/.mhtml) is a MIME multipart/related archive of a web page:
    // the same parser path that handles nested .eml messages extracts its
    // base64-encoded HTML body and inline parts.
    matches!(ext, Some("eml" | "mht" | "mhtml"))
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
                | "mht"
                | "mhtml"
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
            Some("pdf" | "doc" | "xls" | "ppt" | "rtf" | "html" | "htm" | "eml" | "mht" | "mhtml" | "zip")
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

fn join_optional_text(first: Option<ExtractedText>, second: Option<ExtractedText>) -> Option<ExtractedText> {
    match (first, second) {
        (Some(mut left), Some(right)) => {
            append_nested_text(&mut left.text, &right.text);
            merge_meta_refresh_urls(&mut left.meta_refresh_urls, right.meta_refresh_urls);
            left.credential_form |= right.credential_form;
            left.nested_message |= right.nested_message;
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
) -> Option<ExtractedText> {
    if depth >= MAX_NESTED_ATTACHMENT_DEPTH {
        budget.exhausted = true;
        return None;
    }

    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let mut out = ExtractedText::default();

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        budget.exhausted = true;
    }
    let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
    for i in 0..entry_count {
        if out.text.len() >= MAX_NESTED_TEXT_CHARS {
            budget.exhausted = true;
            break;
        }

        let Ok(mut entry) = archive.by_index(i) else {
            // Entry open failure (e.g. a password-protected entry the reader
            // refuses to open) hides inner payloads from every scanner:
            // record the coverage gap instead of silently skipping it.
            budget.exhausted = true;
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
            // An entry that cannot be read (encrypted, truncated, or CRC
            // mismatch) is an inspection coverage gap, not a clean pass.
            budget.exhausted = true;
            continue;
        }

        let nested_type = detect_file_type(&data);
        if !is_archive_scan_candidate(&name, nested_type) {
            continue;
        }

        if let Some(nested) = extract_attachment_text_from_bytes(&name, "", &data, depth + 1, budget)
        {
            append_nested_text(&mut out.text, &format!("[{name}]\n{}", nested.text));
            merge_meta_refresh_urls(&mut out.meta_refresh_urls, nested.meta_refresh_urls);
            out.credential_form |= nested.credential_form;
            out.nested_message |= nested.nested_message;
        }
    }

    if out.text.trim().is_empty() && out.meta_refresh_urls.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_nested_eml_text(
    bytes: &[u8],
    depth: usize,
    budget: &mut AttachmentExtractionBudget,
) -> Option<ExtractedText> {
    if depth >= MAX_NESTED_ATTACHMENT_DEPTH {
        budget.exhausted = true;
        return None;
    }

    let parser = MimeParser::new();
    // A nested message that fails to parse is an inspection coverage gap —
    // the same rule as the unreadable-zip-entry path. Silently skipping it
    // let a malformed .eml hide its payload from every content scanner.
    let content = match parser.parse(bytes) {
        Ok(content) => content,
        Err(err) => {
            debug!(error = ?err, "nested eml parse failed — marking inspection budget exhausted");
            budget.exhausted = true;
            return None;
        }
    };
    if content.truncated || content.dropped_attachments > 0 {
        // The nested parse itself degraded (part/depth budget, dropped or
        // oversized attachments): its payload was only partially scanned.
        budget.exhausted = true;
    }
    let mut out = ExtractedText {
        nested_message: true,
        ..Default::default()
    };

    for header in ["Subject", "From", "To"] {
        if let Some(value) = content.get_header(header) {
            // RFC 2047 decode: nested messages routinely carry encoded-word
            // subjects (=?UTF-8?B?...?=) that are opaque base64 to keyword
            // scans, hiding the phishing lure entirely.
            let decoded = decode_rfc2047(value);
            append_nested_text(&mut out.text, &format!("{header}: {decoded}"));
        }
    }

    if let Some(text) = content.body_text.as_deref() {
        append_nested_text(&mut out.text, text);
    }
    if let Some(html) = content.body_html.as_deref() {
        // MHTML archives and HTML-bodied forwards: keep the attribute URLs /
        // meta-refresh targets that plain tag stripping would discard.
        if let Some(extracted) = extract_html_attachment_text(html) {
            append_nested_text(&mut out.text, &extracted.text);
            merge_meta_refresh_urls(&mut out.meta_refresh_urls, extracted.meta_refresh_urls);
            out.credential_form |= extracted.credential_form;
        }
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
        if let Some(nested) = extract_attachment_text_from_bytes(
            &attachment.filename,
            &attachment.content_type,
            &bytes,
            depth + 1,
            budget,
        ) {
            append_nested_text(&mut out.text, &format!("[{}]\n{}", attachment.filename, nested.text));
            merge_meta_refresh_urls(&mut out.meta_refresh_urls, nested.meta_refresh_urls);
            out.credential_form |= nested.credential_form;
            out.nested_message |= nested.nested_message;
        }
    }

    if out.text.trim().is_empty() && out.meta_refresh_urls.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Urgency vocabulary for calendar-invite lures. Chinese terms carry their
/// traditional variants （紧急/緊急、尽快/儘快/盡快） so a traditional-script
/// invite cannot dodge the check; the runtime keyword lists are tuned for
/// prose bodies and rarely cover ICS-only campaigns.
const ICS_URGENCY_TERMS: &[&str] = &[
    "紧急",
    "緊急",
    "立即",
    "尽快",
    "儘快",
    "盡快",
    "urgent",
    "immediately",
    "asap",
];

const MAX_ICS_ATTACH_DECODE_BYTES: usize = 8 * 1024 * 1024;

fn is_ics_attachment(filename: &str, content_type: &str) -> bool {
    file_extension(filename).as_deref() == Some("ics")
        || content_type.to_lowercase().contains("text/calendar")
}

/// Structured checks on (unfolded) iCalendar content that plain text
/// scanning cannot perform: urgency-lure language, and `ATTACH;ENCODING=
/// BASE64` properties whose embedded binary payload is never decoded by the
/// text path.
fn scan_ics_structure(
    text: &str,
    filename: &str,
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score = 0.0f64;
    let text_lower = text.to_lowercase();

    let urgency_hits: Vec<&str> = ICS_URGENCY_TERMS
        .iter()
        .copied()
        .filter(|term| text_lower.contains(term))
        .collect();
    if !urgency_hits.is_empty() {
        score += 0.15;
        categories.push("ics_urgency".to_string());
        evidence.push(Evidence {
            description: format!(
                "Calendar invite {} uses urgency language ({})",
                filename,
                urgency_hits.join(", ")
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(urgency_hits.join(", ")),
        });
    }

    for line in text.lines() {
        let line_lower = line.to_ascii_lowercase();
        if !(line_lower.starts_with("attach") && line_lower.contains("encoding=base64")) {
            continue;
        }
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        let Some(bytes) = decode_base64_bytes_limited(value.trim(), MAX_ICS_ATTACH_DECODE_BYTES)
        else {
            continue;
        };
        if detect_file_type(&bytes).is_some_and(|ft| ft.is_executable()) {
            score += 0.40;
            categories.push("ics_embedded_executable".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Calendar invite {} embeds an executable payload via ATTACH;ENCODING=BASE64",
                    filename
                ),
                location: Some(format!("attachment:{}", filename)),
                snippet: None,
            });
            break;
        }
    }

    score
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
    // Generic business vocabulary inside spreadsheets is not a phishing lure
    // by itself. Weak terms only corroborate a primary phishing phrase.
    if weak_hits.len() >= 3 && !phishing_hits.is_empty() {
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
    let (strong_bec_hits, weak_bec_hits): (Vec<String>, Vec<String>) = bec_hits
        .into_iter()
        .partition(|phrase| is_strong_bec_phrase(phrase));
    if !strong_bec_hits.is_empty() {
        score += (strong_bec_hits.len() as f64 * 0.10).min(0.4);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} strong BEC phrase(s)",
                filename,
                strong_bec_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(strong_bec_hits.join(", ")),
        });
    } else if weak_bec_hits.len() >= 3 {
        score += (weak_bec_hits.len() as f64 * 0.04).min(0.12);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} weak BEC hints that co-occur",
                filename,
                weak_bec_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(weak_bec_hits.join(", ")),
        });
    }

    // Reuse the shared validators instead of treating every 16/18-digit XML
    // metadata value as payment/identity data. In particular, OOXML embeds
    // UUIDs and numeric font-script identifiers that match a raw regex but do
    // not pass card BIN/Luhn or Chinese identity-number validation.
    let dlp_result = crate::data_security::dlp::scan_text(text);
    let cc_count = dlp_result
        .details
        .iter()
        .find(|(kind, _)| kind == "credit_card")
        .map_or(0, |(_, values)| values.len());
    if cc_count > 0 {
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} validated credit card number(s) (informational DLP; not threat evidence)",
                filename, cc_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    let id_count = dlp_result
        .details
        .iter()
        .find(|(kind, _)| kind == "id_number")
        .map_or(0, |(_, values)| values.len());
    if id_count > 0 {
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} validated Chinese ID number(s) (informational DLP; not threat evidence)",
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

        // Parser-level coverage gaps (multipart budget degradation, dropped
        // or oversized attachments) must surface here even when the retained
        // attachments themselves extract cleanly — otherwise a 101-attachment
        // or >32MB-payload message reports "fully scanned".
        if ctx.session.content.truncated || ctx.session.content.dropped_attachments > 0 {
            budget.exhausted = true;
        }

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
                if is_attachment_text_candidate_by_metadata(
                    &attachment.filename,
                    &attachment.content_type,
                ) {
                    // Imported/legacy sessions may carry attachment metadata
                    // without retained bytes. Treat that as unavailable
                    // coverage rather than as "no extractable text".
                    budget.exhausted = true;
                }
                continue;
            };
            retained_count += 1;

            let Some(extracted) = extract_attachment_text(
                &attachment.filename,
                &attachment.content_type,
                content_base64,
                attachment.size,
                &mut budget,
            ) else {
                continue;
            };
            let Some(text) = budget.retain_scannable_text(extracted.text) else {
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
            let mut has_suspicious_url = false;
            for m in RE_ATTACH_URL.find_iter(&text).take(20) {
                let url = m.as_str();
                if is_probable_schema_reference_url(url) {
                    continue;
                }
                url_count += 1;
                let hits = classify_attachment_url(url);
                if hits.is_empty() {
                    continue;
                }
                has_suspicious_url = true;
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

            // HTML credential forms and forwarded/rfc822 messages are common
            // phishing containers.  Their inner text is already extracted,
            // but historically the only score came from a weak embedded URL
            // signal.  Require both a credential lure and a suspicious URL so
            // ordinary forms/documents remain low-risk, then promote the
            // structural combination to an independent Medium-strength
            // attachment signal.
            if has_suspicious_url && attachment_has_credential_lure(&text) {
                if extracted.credential_form {
                    total_score += 0.36;
                    categories.push("attachment_credential_form".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "HTML attachment `{}` combines an external suspicious action URL with a credential-verification lure",
                            attachment.filename
                        ),
                        location: Some(format!("attachment:{}", attachment.filename)),
                        snippet: None,
                    });
                }
                if extracted.nested_message {
                    total_score += 0.30;
                    categories.push("nested_message_phishing".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Nested message attachment `{}` contains phishing language and a suspicious URL",
                            attachment.filename
                        ),
                        location: Some(format!("attachment:{}", attachment.filename)),
                        snippet: None,
                    });
                }
            }
            if url_count >= 5 {
                // High link density inside a document is itself a weak
                // structural signal (template campaigns).
                total_score += 0.05;
                categories.push("attachment_link_density".to_string());
            }

            // A `<meta http-equiv="refresh">` target lives inside tag
            // attributes, so tag stripping hides the redirect from every
            // other layer — a pure meta-refresh report.html produced zero
            // signal. Score it like the body html_scan meta-refresh path.
            if !extracted.meta_refresh_urls.is_empty() {
                total_score += 0.25;
                categories.push("attachment_meta_refresh".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "HTML attachment {} contains a meta refresh redirect ({} target(s))",
                        attachment.filename,
                        extracted.meta_refresh_urls.len()
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: extracted
                        .meta_refresh_urls
                        .first()
                        .map(|url| url.chars().take(160).collect::<String>()),
                });
            }

            // Structured iCalendar checks (urgency lures, base64 ATTACH
            // payloads) that plain text scanning cannot perform.
            if is_ics_attachment(&attachment.filename, &attachment.content_type) {
                total_score += scan_ics_structure(
                    &text,
                    &attachment.filename,
                    &mut evidence,
                    &mut categories,
                );
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

        let dlp_only = !categories.is_empty()
            && categories
                .iter()
                .all(|category| category.starts_with("dlp_"));
        if threat_level == ThreatLevel::Safe && !dlp_only {
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
            summary: if threat_level == ThreatLevel::Safe {
                format!(
                    "Attachment content analysis found {} informational sensitive-data finding(s) across {} scanned attachment(s); no threat evidence",
                    evidence.len(),
                    scanned_count
                )
            } else {
                format!(
                    "Attachment content analysis found {} finding(s) across {} scanned attachment(s)",
                    evidence.len(),
                    scanned_count
                )
            },
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
        make_ctx_with_flags(attachments, false, 0)
    }

    fn make_ctx_with_flags(
        attachments: Vec<EmailAttachment>,
        truncated: bool,
        dropped_attachments: usize,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            attachments,
            truncated,
            dropped_attachments,
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
    async fn test_xlsx_schema_metadata_does_not_trigger_url_or_card_findings() {
        let workbook_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
 xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">
 <metadata>{00000000-0001-0000-0000-000000000000} 0302050205020502</metadata>
</workbook>"#;
        let xlsx = build_ooxml_zip(&[("xl/workbook.xml", workbook_xml)]);
        let attachment = make_attachment(
            "community-expenses.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            &xlsx,
        );

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(!result.categories.iter().any(|category| matches!(
            category.as_str(),
            "attachment_phishing_url" | "attachment_link_density" | "dlp_credit_card"
        )));
    }

    #[tokio::test]
    async fn test_real_attachment_url_and_valid_card_remain_detected() {
        let content = b"Review http://evil.top/login and card 4111111111111111";
        let attachment = make_attachment("notice.txt", "text/plain", content);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string())
        );
        assert!(result.categories.contains(&"dlp_credit_card".to_string()));
    }

    #[test]
    fn plaintext_http_scheme_alone_is_not_a_phishing_finding() {
        assert!(classify_attachment_url("http://images.example.com/banner").is_empty());
        assert!(
            classify_attachment_url("http://evil.example/login")
                .iter()
                .any(|(reason, _)| *reason == "auth-themed path segment")
        );
    }

    #[test]
    fn single_character_bec_hint_does_not_flag_attachment() {
        let mut evidence = vec![];
        let mut categories = vec![];
        let score = scan_attachment_text(
            "这是正常业务的紧急情况说明",
            "notice.docx",
            &[],
            &[],
            &["急".to_string()],
            &mut evidence,
            &mut categories,
        );

        assert_eq!(score, 0.0);
        assert!(!categories.iter().any(|category| category == "bec"));
    }

    #[test]
    fn strong_bec_phrase_still_flags_attachment() {
        let mut evidence = vec![];
        let mut categories = vec![];
        let score = scan_attachment_text(
            "Please change bank account before payment.",
            "invoice.docx",
            &[],
            &[],
            &["change bank account".to_string()],
            &mut evidence,
            &mut categories,
        );

        assert!(score > 0.0);
        assert!(categories.iter().any(|category| category == "bec"));
    }

    #[tokio::test]
    async fn business_workbook_terms_and_id_numbers_do_not_create_threat() {
        let text = "身份核验 发票 账单 转账 通知 合同问题 11010519491231002X";
        let attachment = make_attachment("reply-ticket.xlsx", "text/plain", text.as_bytes());
        let seed: crate::modules::content_scan::KeywordOverrides = serde_json::from_str(
            include_str!("../../../../shared/schemas/keyword_overrides_seed.json"),
        )
        .expect("keyword seed must parse");
        let effective = crate::modules::content_scan::build_effective_keyword_lists(
            &seed,
            &crate::modules::content_scan::KeywordOverrides::default(),
        );
        let module = AttachContentModule::new_with_keyword_lists(effective);

        let result = module.analyze(&make_ctx(vec![attachment])).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.categories, vec!["dlp_id_number".to_string()]);
        assert!(result.summary.contains("no threat evidence"));
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
    async fn html_credential_form_with_suspicious_action_is_medium() {
        let html = r#"<!doctype html>
            <html><body>
              <h1>账户异常，请立即验证</h1>
              <p>请输入密码完成登录确认。</p>
              <form action="http://203.0.113.50/harvest" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
              </form>
            </body></html>"#;
        let attachment = make_attachment("工资调整通知.html", "text/html", html.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_credential_form".to_string()),
            "credential form combination should be surfaced: {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::Medium,
            "credential form plus suspicious action must not remain Low: {:?} ({})",
            result.threat_level,
            result.details["score"]
        );
    }

    #[test]
    fn escaped_markup_is_not_reinterpreted_as_a_credential_form() {
        let html = "Visible text &lt;form action=\"http://203.0.113.50/harvest\"&gt;"
            .to_string()
            + "&lt;input type=\"password\" name=\"password\"&gt;&lt;/form&gt;";
        let extracted = extract_html_attachment_text(&html).expect("visible text is retained");
        assert!(!extracted.credential_form);
        assert!(extracted.text.contains("form"));
    }

    #[tokio::test]
    async fn nested_rfc822_phishing_with_suspicious_url_is_medium() {
        let nested = b"From: vendor@example.com\r\n\
            Subject: account notice\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Your account is blocked. Verify your identity and enter your password at http://203.0.113.50/login\r\n";
        let attachment = make_attachment("notice.eml", "message/rfc822", nested);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"nested_message_phishing".to_string()),
            "nested phishing combination should be surfaced: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Medium);
    }

    #[tokio::test]
    async fn test_plain_text_attachment_uses_weak_keywords_as_corroboration() {
        let content = "Please verify your account and review today the employee handbook acknowledgement policy document update";
        let attachment = make_attachment("notice.txt", "text/plain", content.as_bytes());

        let result = make_module_with_keywords(
            &["verify your account"],
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
    async fn test_missing_text_attachment_payload_surfaces_incomplete_coverage() {
        let attachment = EmailAttachment {
            filename: "missing.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 128,
            hash: "hash".to_string(),
            content_base64: None,
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
        assert_eq!(result.details["inspection_budget_exhausted"], true);
    }

    #[tokio::test]
    async fn test_nested_eml_parse_failure_marks_budget_exhausted() {
        // Declared boundary never appears → MimeParser::parse fails with
        // BoundaryNotFound. A silently-skipped .eml would hide its payload
        // from every content scanner, so this must surface as a coverage gap.
        let broken_eml =
            b"Content-Type: multipart/mixed; boundary=\"NOPE\"\r\n\r\nbody without any boundary";
        let attachment = make_attachment("forward.eml", "message/rfc822", broken_eml);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string()),
            "unparseable nested eml must surface as coverage gap: {:?}",
            result.categories
        );
        assert_eq!(result.details["inspection_budget_exhausted"], true);
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_parser_truncation_flag_surfaces_inspection_limited() {
        // Session-level degradation (>100 attachments dropped, oversized
        // attachment kept metadata-only, part/depth budget hit) is recorded
        // on EmailContent by the parser; the module must not claim full
        // coverage in that case.
        let benign = make_attachment("notes.txt", "text/plain", b"quarterly report");

        let result = AttachContentModule::new()
            .analyze(&make_ctx_with_flags(vec![benign], true, 1))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_inspection_limited".to_string()),
            "parser truncation flags must surface as coverage gap: {:?}",
            result.categories
        );
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

    #[test]
    fn test_unreadable_zip_entry_marks_incomplete_inspection() {
        // PoC bypass: an entry that fails to read (encrypted, or corrupted so
        // its CRC check fails) previously hit a silent `continue` and the
        // archive produced zero signal. The budget must be marked exhausted
        // so the verdict layer records the coverage gap.
        let cursor = Cursor::new(Vec::new());
        let mut zip_w = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w
            .start_file("secret.txt", options)
            .expect("start zip entry");
        zip_w
            .write_all(b"payload text here")
            .expect("write zip entry");
        let mut zip = zip_w.finish().expect("finish zip").into_inner();

        // Flip one byte inside the stored entry data: the central directory
        // stays valid, but reading the entry now fails its CRC check —
        // the same failure shape as an entry that cannot be decrypted.
        let needle = b"payload text here";
        let pos = zip
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("entry data should be present in the archive");
        zip[pos] ^= 0xFF;

        let mut budget = AttachmentExtractionBudget::default();
        let text = extract_nested_zip_text(&zip, 0, &mut budget);

        assert!(text.is_none());
        assert!(
            budget.exhausted,
            "unreadable (e.g. encrypted) zip entries must mark the inspection budget exhausted"
        );
    }

    #[tokio::test]
    async fn test_mht_attachment_body_and_links_are_scanned() {
        // PoC bypass: invoice.mht (MHTML, multipart/related) was not an eml
        // candidate, so the base64-encoded HTML phishing page inside was
        // never decoded and its links never scored.
        let html = r#"<html><body><p>Please verify your account to download the invoice.</p><a href="http://evil.top/login">View invoice</a></body></html>"#;
        let html_b64 = base64::engine::general_purpose::STANDARD.encode(html.as_bytes());
        let mht = format!(
            "From: \"Saved Page\" <saved@example.com>\r\n\
             Subject: invoice\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/related; boundary=\"MHT\"; type=\"text/html\"\r\n\
             \r\n\
             --MHT\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {html_b64}\r\n\
             --MHT--\r\n"
        );
        let attachment = make_attachment("invoice.mht", "application/octet-stream", mht.as_bytes());

        let result = make_module_with_keywords(&["verify your account"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "MHTML body text should be decoded and keyword-scanned: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "links inside the MHTML page should be extracted and scored: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_html_attachment_meta_refresh_target_is_scored() {
        // PoC bypass: a report.html whose only payload is a meta refresh
        // redirect stripped to empty text and produced zero signal.
        let html = br#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=https://evil.example/login"></head><body>Loading</body></html>"#;
        let attachment = make_attachment("report.html", "text/html", html);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_meta_refresh".to_string()),
            "meta refresh redirect target must be scored: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_html_attachment_attribute_url_is_scored() {
        // PoC bypass: href/src/action attribute URLs were discarded by tag
        // stripping; an HTML attachment whose lure link never appears as
        // visible text scored zero.
        let html = br#"<!DOCTYPE html><html><body><a href="http://evil.top/login">Open the shared document</a></body></html>"#;
        let attachment = make_attachment("report.html", "text/html", html);

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "attribute URLs must be recovered and scored: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_nested_eml_rfc2047_subject_is_decoded_and_scanned() {
        // PoC bypass: nested eml headers were concatenated raw, so an
        // encoded-word phishing subject (=?UTF-8?B?...?=) stayed opaque
        // base64 and keyword scans never saw it.
        // =?UTF-8?B?6LSm5oi35byC5bi4?= decodes to 账户异常.
        let eml = "From: vendor@example.com\r\n\
                   Subject: =?UTF-8?B?6LSm5oi35byC5bi4?=\r\n\
                   Content-Type: text/plain; charset=utf-8\r\n\
                   \r\n\
                   请立即登录处理。\r\n";
        let attachment = make_attachment("alert.eml", "message/rfc822", eml.as_bytes());

        let result = make_module_with_keywords(&["账户异常", "立即登录"], &[])
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "decoded nested subject should feed keyword scanning: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_ics_base64_attach_executable_is_scored() {
        // PoC bypass: ATTACH;ENCODING=BASE64 embeds a binary payload inside a
        // calendar invite; plain-text scanning never decoded it.
        let pe_stub = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(pe_stub);
        let ics = format!(
            "BEGIN:VCALENDAR\r\n\
             VERSION:2.0\r\n\
             BEGIN:VEVENT\r\n\
             SUMMARY:Quarterly sync\r\n\
             ATTACH;ENCODING=BASE64;VALUE=BINARY:{payload_b64}\r\n\
             END:VEVENT\r\n\
             END:VCALENDAR\r\n"
        );
        let attachment = make_attachment("invite.ics", "text/calendar", ics.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"ics_embedded_executable".to_string()),
            "base64 ATTACH payload must be decoded and magic-checked: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_ics_chinese_urgency_language_is_scored() {
        // PoC bypass: fake Chinese meeting invites with urgency lures
        // produced zero signal — the runtime keyword lists do not cover
        // ICS-only campaigns and there was no ICS-specific urgency check.
        let ics = "BEGIN:VCALENDAR\r\n\
                   VERSION:2.0\r\n\
                   BEGIN:VEVENT\r\n\
                   SUMMARY:紧急：请立即确认参会\r\n\
                   DESCRIPTION:请尽快查看附件中的会议材料。\r\n\
                   END:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        let attachment = make_attachment("meeting.ics", "text/calendar", ics.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"ics_urgency".to_string()),
            "Chinese urgency lure in ICS must be scored: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_ics_folded_url_is_unfolded_and_scored() {
        // PoC bypass: RFC 5545 line folding splits a malicious URL across
        // lines, hiding it from the attachment URL regex. (Written as a
        // single-line literal: Rust string continuation would strip the
        // leading space that marks the folded line.)
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:Review meeting notes\r\nURL:http://evil.t\r\n op/login\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let attachment = make_attachment("notes.ics", "text/calendar", ics.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "folded ICS URL must be unfolded and scored: {:?}",
            result.categories
        );
    }
}
