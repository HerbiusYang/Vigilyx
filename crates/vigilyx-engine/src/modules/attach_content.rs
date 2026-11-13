//! Attachment content scan module.
//!
//! Reuses the runtime keyword lists from `content_scan` and extends attachment
//! text extraction beyond plain text so PDF / OOXML / legacy Office documents
//! are covered by the same `/security/keywords` configuration.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::sync::LazyLock;
use std::time::Instant;

use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use tracing::debug;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::{EmailAttachment, EmailLink, EmailSession, decode_base64_bytes_limited};
use vigilyx_core::security::{
    SemanticClaim, SemanticCoverageStatus, SemanticLinkExtractionSource, SemanticMessageContext,
    SemanticPolarity, SemanticQuoteStatus, SemanticSourcePart, SemanticSpan, SemanticSpeechAct,
};
use vigilyx_parser::mime::{MimeParser, decode_rfc2047};

use crate::context::SecurityContext;
use crate::data_security::document_extract;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::common::is_probable_schema_reference_url;
use crate::modules::content_scan::html_utils::decode_html_entities;
use crate::modules::content_scan::{
    EffectiveKeywordLists, is_actionable_bec_phrase, normalize_text,
};
use crate::semantic::{
    extract_semantic_context, is_current_recipient_action, semantic_counter_context_qualifies,
    semantic_phrase_present, semantic_text_projection_with_coverage,
};

pub struct AttachContentModule {
    meta: ModuleMetadata,
    phishing_matcher: KeywordMatcher,
    weak_phishing_matcher: KeywordMatcher,
    bec_matcher: KeywordMatcher,
    nested_message_identity_freeze_enabled: bool,
}

/// Reusable multi-pattern matcher for the attachment keyword hot path.
///
/// The old path called `str::contains` once per keyword for every document
/// segment.  This keeps the exact same per-pattern results (including empty
/// and duplicate patterns) while compiling the patterns once per module
/// instance and scanning each segment with Aho-Corasick.
struct KeywordMatcher {
    patterns: Vec<String>,
    automaton: Option<AhoCorasick>,
    owners: Vec<Vec<usize>>,
}

impl KeywordMatcher {
    fn new(patterns: &[String]) -> Self {
        let mut unique_patterns = Vec::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut pattern_to_id: HashMap<String, usize> = HashMap::new();

        for (index, pattern) in patterns.iter().enumerate() {
            if pattern.is_empty() {
                continue;
            }
            if let Some(&id) = pattern_to_id.get(pattern) {
                owners[id].push(index);
            } else {
                let id = unique_patterns.len();
                pattern_to_id.insert(pattern.clone(), id);
                unique_patterns.push(pattern.clone());
                owners.push(vec![index]);
            }
        }

        let automaton = (!unique_patterns.is_empty()).then(|| {
            AhoCorasick::new(&unique_patterns)
                .expect("attachment keyword matcher patterns must be valid")
        });

        Self {
            patterns: patterns.to_vec(),
            automaton,
            owners,
        }
    }

    fn find<'a>(&'a self, haystack: &str) -> Vec<&'a String> {
        let mut matched = vec![false; self.patterns.len()];
        for (index, pattern) in self.patterns.iter().enumerate() {
            if pattern.is_empty() {
                // Preserve str::contains("") semantics from the old path.
                matched[index] = true;
            }
        }

        if let Some(automaton) = &self.automaton {
            for mat in automaton.find_overlapping_iter(haystack.as_bytes()) {
                for &owner in &self.owners[mat.pattern().as_usize()] {
                    matched[owner] = true;
                }
            }
        }

        self.patterns
            .iter()
            .zip(matched)
            .filter_map(|(pattern, matched)| matched.then_some(pattern))
            .collect()
    }
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
        let nested_message_identity_freeze_enabled =
            std::env::var("VIGILYX_NESTED_MESSAGE_IDENTITY_FREEZE_ENABLED")
                .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        Self::new_with_nested_message_identity_freeze(
            effective,
            nested_message_identity_freeze_enabled,
        )
    }

    fn new_with_nested_message_identity_freeze(
        effective: EffectiveKeywordLists,
        nested_message_identity_freeze_enabled: bool,
    ) -> Self {
        let phishing_matcher = KeywordMatcher::new(&effective.phishing_keywords);
        let weak_phishing_matcher = KeywordMatcher::new(&effective.weak_phishing_keywords);
        let bec_matcher = KeywordMatcher::new(&effective.bec_phrases);
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
            phishing_matcher,
            weak_phishing_matcher,
            bec_matcher,
            nested_message_identity_freeze_enabled,
        }
    }
}

/// Structural or local-action context that permits attachment vocabulary to
/// become threat evidence. Generic business terms remain observations until
/// one of these gates is present.
#[derive(Debug, Clone, Copy, Default)]
struct AttachmentThreatGate {
    suspicious_url: bool,
    credential_form: bool,
}

impl AttachmentThreatGate {
    fn is_open(self) -> bool {
        self.suspicious_url || self.credential_form
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
static RE_META_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
static RE_META_CONTENT_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)content\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());
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
    credential_form_urls: Vec<String>,
    nested_message: bool,
    projection_limited: bool,
    semantic_source_ranges: Vec<AttachmentSemanticSourceRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentSemanticSourceKind {
    RenderedHtml,
    Rtf,
}

#[derive(Debug, Clone, Copy)]
struct AttachmentSemanticSourceRange {
    span: SemanticSpan,
    kind: AttachmentSemanticSourceKind,
}

impl ExtractedText {
    fn from_text(text: String) -> Self {
        Self {
            text,
            meta_refresh_urls: Vec::new(),
            credential_form: false,
            credential_form_urls: Vec::new(),
            nested_message: false,
            projection_limited: false,
            semantic_source_ranges: Vec::new(),
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
        form_has_action && (RE_HTML_CREDENTIAL_INPUT.is_match(form) || form_has_credential_word)
    })
}

/// Keep the observed action of each real credential form separate from other
/// links appended to the extracted text. A form cannot qualify a different
/// image, service endpoint, or unrelated anchor in the same attachment.
fn html_credential_form_urls(html: &str) -> Vec<String> {
    RE_HTML_FORM
        .captures_iter(html)
        .take(MAX_HTML_ATTRIBUTE_URLS)
        .filter_map(|caps| {
            let form = caps.get(0)?.as_str();
            if !html_contains_credential_form(form) {
                return None;
            }
            let opening_tag = &form[..form.find('>')?];
            RE_HTML_ATTR_URL
                .captures_iter(opening_tag)
                .find_map(|attribute| {
                    let raw = attribute.get(0)?.as_str();
                    if !raw.split_once('=')?.0.trim().eq_ignore_ascii_case("action") {
                        return None;
                    }
                    let value = attribute
                        .get(1)
                        .or_else(|| attribute.get(2))
                        .or_else(|| attribute.get(3))?
                        .as_str();
                    let decoded = decode_html_entities(value);
                    let parsed = url::Url::parse(&decoded).ok()?;
                    matches!(parsed.scheme(), "http" | "https").then_some(parsed.to_string())
                })
        })
        .collect()
}

/// Reconstruct only adjacent JavaScript string literals. This is deliberately
/// not a JavaScript interpreter: it handles string fragments used to assemble
/// a credential form, while keeping execution, DOM access, and arbitrary
/// expressions out of the scanner.
fn reconstruct_script_literal_markup(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut reconstructed = String::new();

    while let Some(start_rel) = lower[cursor..].find("<script") {
        let start = cursor + start_rel;
        let tag_end = lower[start..].find('>')? + start;
        let close_rel = lower[tag_end + 1..].find("</script")?;
        let body_end = tag_end + 1 + close_rel;
        let script = &html[tag_end + 1..body_end];
        let bytes = script.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let quote = match bytes[i] {
                b'\'' | b'"' => bytes[i],
                _ => {
                    i += 1;
                    continue;
                }
            };
            i += 1;
            let mut literal = String::new();
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                    literal.push(bytes[i] as char);
                } else {
                    literal.push(bytes[i] as char);
                }
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            if reconstructed.len() + literal.len() <= 128 * 1024 {
                reconstructed.push_str(&literal);
            } else {
                return None;
            }
        }
        cursor = body_end + "</script".len();
    }

    let lower_reconstructed = reconstructed.to_ascii_lowercase();
    (lower_reconstructed.contains("<form") && lower_reconstructed.contains("</form"))
        .then_some(reconstructed)
}

/// Extract scannable text from an HTML attachment: visible text plus the
/// URLs hidden in `href`/`src`/`action` attributes and `<meta refresh>`
/// targets. Entity decoding is applied to captured attribute values, while
/// the original markup is passed to the tag stripper so escaped markup such as
/// `&lt;form&gt;` never becomes a real credential form during analysis.
fn extract_html_attachment_text(html: &str) -> Option<ExtractedText> {
    let reconstructed_script = reconstruct_script_literal_markup(html);
    let scan_markup = reconstructed_script
        .as_deref()
        .map_or_else(|| html.to_string(), |markup| format!("{html}\n{markup}"));
    let mut attribute_urls: Vec<String> = Vec::new();
    for caps in RE_HTML_ATTR_URL
        .captures_iter(&scan_markup)
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
    let credential_form = html_contains_credential_form(&scan_markup);
    let credential_form_urls = html_credential_form_urls(&scan_markup);

    // Preserve rendered paragraph, quote and anchor positions. Appending all
    // hrefs at the end would manufacture adjacency to an unrelated request.
    let (projection, projection_limited) =
        semantic_text_projection_with_coverage(html, SemanticSourcePart::Html);
    let mut text = projection.trim().to_string();
    let rendered_end = text.len();
    let projected_urls: HashSet<String> = RE_ATTACH_URL
        .find_iter(&text)
        .filter_map(|matched| {
            url::Url::parse(
                matched
                    .as_str()
                    .trim_end_matches(['.', ',', ';', '。', '，', '；']),
            )
            .ok()
            .map(|url| url.to_string())
        })
        .collect();
    // Unprojected attributes remain structural observations. Mark their
    // origin so a hidden href cannot become a visible URL-only continuation.
    for url in attribute_urls.iter().chain(meta_refresh_urls.iter()) {
        if url::Url::parse(url).is_ok_and(|parsed| projected_urls.contains(parsed.as_str())) {
            continue;
        }
        text.push_str("\nattachment_html_attribute_url: ");
        text.push_str(url);
    }
    if let Some(markup) = reconstructed_script {
        text.push_str("\nattachment_reconstructed_script:\n");
        text.push_str(&markup);
    }

    if text.is_empty() && meta_refresh_urls.is_empty() {
        return None;
    }
    Some(ExtractedText {
        text,
        meta_refresh_urls,
        credential_form,
        credential_form_urls,
        nested_message: false,
        projection_limited,
        semantic_source_ranges: vec![AttachmentSemanticSourceRange {
            span: SemanticSpan {
                start_byte: 0,
                end_byte: rendered_end,
            },
            kind: AttachmentSemanticSourceKind::RenderedHtml,
        }],
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
        let continuation = line.strip_prefix(' ').or_else(|| line.strip_prefix('\t'));
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
    let is_long = url.len() > 200;

    if RE_URL_AT.is_match(url) {
        hits.push((
            "contains @ in authority (credential or display spoofing)",
            0.30,
        ));
    }
    if RE_URL_IP_HOST.is_match(url) {
        hits.push(("uses raw IP address as host", 0.25));
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
    // Length is useful corroboration for an already suspicious URL, but
    // signed document/report links routinely exceed 200 characters. It must
    // never manufacture attachment_phishing_url on its own.
    if is_long && !hits.is_empty() {
        hits.push(("excessively long URL (>200 chars)", 0.10));
    }
    hits
}

fn attachment_url_has_reason(hits: &[(&'static str, f64)], reason: &str) -> bool {
    hits.iter().any(|(candidate, _)| *candidate == reason)
}

/// Return true only when an attachment URL has an independently meaningful
/// attack shape or is bound to an explicit attachment lure/container.
///
/// A literal IP host, a generic auth-looking path, and URL length are useful
/// analyst observations, but they are common in internal test reports and
/// must not enter threat fusion without a stronger local or structural cue.
fn attachment_url_is_actionable(
    hits: &[(&'static str, f64)],
    is_redirect_container: bool,
    has_credential_lure: bool,
) -> bool {
    let has_userinfo = attachment_url_has_reason(
        hits,
        "contains @ in authority (credential or display spoofing)",
    );
    let has_device_code = attachment_url_has_reason(hits, "OAuth device-code endpoint");
    let has_suspicious_tld = attachment_url_has_reason(hits, "suspicious TLD");
    let has_auth_path = attachment_url_has_reason(hits, "auth-themed path segment");

    has_userinfo
        || has_device_code
        || (has_suspicious_tld && has_auth_path)
        || (is_redirect_container && has_auth_path)
        || has_credential_lure
}

/// Parse the physical occurrence offsets retained in a semantic link ID.
fn attachment_link_span(link_id: &str) -> Option<SemanticSpan> {
    let mut offsets = link_id.rsplit(':');
    let end_byte = offsets.next()?.parse().ok()?;
    let start_byte = offsets.next()?.parse().ok()?;
    (start_byte < end_byte).then_some(SemanticSpan {
        start_byte,
        end_byte,
    })
}

/// Target continuation must not turn a report, quoted line or local warning
/// into the preceding CTA's physical destination. Inspect only the candidate
/// source range; an earlier, independent training paragraph cannot suppress a
/// later current request. Topic words inside normal prose require a heading
/// delimiter before they count as a structural boundary.
fn attachment_target_context_boundary(
    value: &str,
    data: &crate::module_data::ModuleDataRegistry,
) -> bool {
    let normalized = normalize_text(&value.to_lowercase());
    let report_topics = data
        .get_structured("semantic_context_guard_policy_v1")
        .and_then(|policy| policy.get("report_topics"))
        .and_then(serde_json::Value::as_array);
    normalized
        .split(['\n', '\r', ',', '，', ';', '；', '.', '。', '!', '！'])
        .any(|segment| {
            let prefix = segment.trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, ':' | '：' | '[' | '【')
            });
            if prefix.starts_with('>') {
                return true;
            }
            let starts_marker =
                |term: &str| prefix.starts_with(term) && semantic_phrase_present(prefix, term);
            data.get_list("semantic_anti_action_markers_v1")
                .iter()
                .map(|term| normalize_text(&term.to_lowercase()))
                .any(|term| starts_marker(&term))
                || data
                    .get_list("semantic_report_markers_v1")
                    .iter()
                    .map(|term| normalize_text(&term.to_lowercase()))
                    .any(|term| {
                        if !starts_marker(&term) {
                            return false;
                        }
                        let topic = report_topics.is_some_and(|topics| {
                            topics
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .any(|topic| normalize_text(&topic.to_lowercase()) == term)
                        });
                        !topic || prefix[term.len()..].trim_start().starts_with([':', '：'])
                    })
        })
}

/// Anchor annotations can add a line break inside a rendered paragraph. A
/// following URL-only line with another target still makes the local pointer
/// ambiguous; narrative, quoted and attribute-observation lines end this scan.
fn attachment_adjacent_url_target_is_ambiguous(
    text: &str,
    target_line_end: usize,
    source_end: usize,
    canonical_target: &str,
) -> bool {
    const MAX_NEXT_LINE_GAP_BYTES: usize = 192;
    let mut line_start = target_line_end;
    let Some(tail) = text.get(target_line_end..source_end.min(text.len())) else {
        return false;
    };
    for line in tail.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.trim().is_empty() {
            line_start += line.len();
            continue;
        }
        if line_start.saturating_sub(target_line_end) > MAX_NEXT_LINE_GAP_BYTES {
            return false;
        }
        let mut cursor = 0;
        let mut observed = false;
        let mut different = false;
        for matched in RE_ATTACH_URL.find_iter(content).take(20) {
            if !content[cursor..matched.start()].trim().is_empty() {
                return false;
            }
            let token = matched
                .as_str()
                .trim_end_matches(['.', ',', ';', '。', '，', '；']);
            let Ok(url) = url::Url::parse(token) else {
                return false;
            };
            observed = true;
            different |= url.as_str() != canonical_target;
            cursor = matched.start() + token.len();
        }
        if !observed
            || !content[cursor..]
                .trim_matches(|character: char| {
                    character.is_whitespace() || matches!(character, '.' | '。' | '!' | '！')
                })
                .is_empty()
        {
            return false;
        }
        if different {
            return true;
        }
        line_start += line.len();
    }
    false
}

/// A deictic CTA keeps its original claim span. Its separately observed target
/// may be only the first following URL-only rendered line, never an arbitrary
/// URL elsewhere in the attachment or one recovered from hidden attributes.
fn bind_attachment_deictic_targets(
    text: &str,
    source_ranges: &[AttachmentSemanticSourceRange],
    context: &mut SemanticMessageContext,
) {
    const MAX_TARGET_GAP_BYTES: usize = 384;
    let data = module_data();
    let credential_objects = data.get_list("attachment_credential_object_terms_v1");
    let target_markers = data.get_list("attachment_credential_deictic_target_markers_v1");
    let snapshot = context.claims.clone();
    let mut bindings = Vec::new();
    for (claim_index, original_claim) in snapshot.iter().enumerate() {
        let mut claim = original_claim.clone();
        let mut candidate = claim.clone();
        // Counter-context is rechecked after the previously unknown target has
        // been physically bound. A counter naming another URL cannot refute it.
        candidate.counter_context_ids.clear();
        if !is_current_recipient_action(&candidate)
            || !claim.objects.iter().any(|object| {
                credential_objects
                    .iter()
                    .any(|term| object.eq_ignore_ascii_case(term))
            })
        {
            continue;
        }
        if !claim.link_ids.is_empty() {
            // The shared plain-text extractor can already have appended a
            // following URL-only line. Recover this CTA's original line only
            // for that explicit provenance and physically observed links;
            // the attachment gate below must still validate the deictic
            // relation, including a counter tied to the actual target.
            if !claim
                .provenance
                .iter()
                .any(|value| value == "adjacent_url_only_continuation")
            {
                continue;
            }
            let Some(claim_text) = text.get(claim.span.start_byte..claim.span.end_byte) else {
                continue;
            };
            let Some(line_end) = claim_text
                .find('\n')
                .map(|offset| claim.span.start_byte + offset)
            else {
                continue;
            };
            let original_end =
                claim.span.start_byte + text[claim.span.start_byte..line_end].trim_end().len();
            if original_end <= claim.span.start_byte
                || RE_ATTACH_URL.is_match(&text[claim.span.start_byte..original_end])
                || !claim.link_ids.iter().all(|link_id| {
                    context.links.iter().any(|link| {
                        &link.link_id == link_id
                            && attachment_link_span(link_id).is_some_and(|span| {
                                span.start_byte > line_end && span.end_byte <= claim.span.end_byte
                            })
                    })
                })
            {
                continue;
            }
            claim.span.end_byte = original_end;
            claim.source_span_id = format!(
                "plain_text:{}:{}",
                claim.span.start_byte, claim.span.end_byte
            );
            claim.causal_key = format!("semantic_span:{}", claim.source_span_id);
            claim.link_ids.clear();
            // A shared-parser continuation is an observation until this
            // attachment adapter validates its own pointer, intervening scope
            // and physical URL. Rejected candidates must not retain the old
            // expanded-span link authority through the direct-link fallback.
            context.claims[claim_index] = claim.clone();
        }
        let Some(claim_text) = text.get(claim.span.start_byte..claim.span.end_byte) else {
            continue;
        };
        let normalized = normalize_text(&claim_text.to_lowercase());
        if attachment_target_context_boundary(claim_text, &data) {
            continue;
        }
        let explicitly_deictic = target_markers
            .iter()
            .any(|term| normalized.contains(&normalize_text(&term.to_lowercase())));
        let Some(line_end) = text[claim.span.end_byte..]
            .find('\n')
            .map(|offset| claim.span.end_byte + offset)
        else {
            continue;
        };
        let mut target_line_start = line_end + 1;
        let target_line = text[target_line_start..]
            .split_inclusive('\n')
            .find(|line| {
                if line.trim().is_empty() {
                    target_line_start += line.len();
                    false
                } else {
                    true
                }
            });
        let Some(target_line) = target_line else {
            continue;
        };
        let target_line_end = target_line_start + target_line.trim_end_matches(['\r', '\n']).len();
        if target_line_end.saturating_sub(claim.span.end_byte) > MAX_TARGET_GAP_BYTES {
            continue;
        }
        let rendered_authentication_target = source_ranges.iter().any(|range| {
            range.kind == AttachmentSemanticSourceKind::RenderedHtml
                && range.span.start_byte <= claim.span.start_byte
                && target_line_end <= range.span.end_byte
        }) && !claim.actions.is_empty()
            // An inherited request on the disable consequence must not
            // compete with the explicit CTA for the same following target.
            && (["semantic_request_markers_v1", "semantic_instruction_markers_v1"]
                .iter().any(|key| data.get_list(key).iter().any(|term| {
                    semantic_phrase_present(&normalized, &normalize_text(&term.to_lowercase()))
                }))
                || data.get_list("semantic_imperative_prefixes_v2").iter().any(|term| {
                    let term = normalize_text(&term.to_lowercase());
                    let prefix = normalized.trim_start_matches(|character: char| {
                        character.is_whitespace() || matches!(character, ',' | '，' | ';' | '；' | ':' | '：' | '(' | '（')
                    });
                    prefix.starts_with(&term) && semantic_phrase_present(prefix, &term)
                }))
            && claim.actions.iter().all(|action| {
                data.get_list("attachment_credential_continuation_actions_v1")
                    .iter()
                    .any(|term| action.eq_ignore_ascii_case(term))
            });
        // The adapter may have separately verified a same-sentence compound
        // such as “enter the OTP and log in”. Its following URL-only line is
        // still independently checked below after shared-parser authority was
        // revoked. This typed proof is never minted by URL words themselves.
        let same_sentence_credential_target = claim
            .provenance
            .iter()
            .any(|value| value == "attachment_credential_same_sentence_continuation_v1");
        if !explicitly_deictic
            && !rendered_authentication_target
            && !same_sentence_credential_target
        {
            continue;
        }
        let consequence = text[claim.span.end_byte..line_end].trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '，' | '.' | '。' | '!' | '！')
        });
        if !consequence.is_empty()
            && (!explicitly_deictic
                || !data
                    .get_list("account_security_no_link_imminent_disable_terms")
                    .iter()
                    .any(|term| {
                        normalize_text(&consequence.to_lowercase())
                            == normalize_text(&term.to_lowercase())
                    }))
        {
            continue;
        }
        let gap = &text[claim.span.end_byte..target_line_start];
        if RE_ATTACH_URL.is_match(gap)
            || snapshot.iter().enumerate().any(|(other_index, other)| {
                if other_index == claim_index
                    || other.span.end_byte <= claim.span.end_byte
                    || other.span.start_byte >= target_line_end
                {
                    return false;
                }
                if other.quote_or_forward_status != SemanticQuoteStatus::Original
                    || matches!(
                        other.speech_act,
                        SemanticSpeechAct::Report
                            | SemanticSpeechAct::Quotation
                            | SemanticSpeechAct::Warning
                    )
                    || other.polarity == SemanticPolarity::AntiAction
                {
                    return true;
                }
                if !matches!(
                    other.speech_act,
                    SemanticSpeechAct::Request | SemanticSpeechAct::Instruction
                ) && other.polarity != SemanticPolarity::Action
                {
                    return false;
                }
                // The shared extractor may inherit the CTA into its comma
                // separated consequence ("24h without verification..."). Only
                // that configured, original same-line consequence can pass;
                // a separate explicit instruction is an intervening request.
                let other_text = text[other.span.start_byte..other.span.end_byte].trim_matches(
                    |character: char| {
                        character.is_whitespace()
                            || matches!(character, ',' | '，' | '.' | '。' | '!' | '！')
                    },
                );
                let exact_disable_consequence = data
                    .get_list("account_security_no_link_imminent_disable_terms")
                    .iter()
                    .any(|term| {
                        normalize_text(&other_text.to_lowercase())
                            == normalize_text(&term.to_lowercase())
                    });
                other.span.end_byte > line_end || !exact_disable_consequence
            })
        {
            continue;
        }
        let mut cursor = target_line_start;
        let mut canonical_target = None;
        let mut observed = Vec::new();
        let mut valid = true;
        for matched in RE_ATTACH_URL
            .find_iter(&text[target_line_start..target_line_end])
            .take(20)
        {
            let start_byte = target_line_start + matched.start();
            let token = matched
                .as_str()
                .trim_end_matches(['.', ',', ';', '。', '，', '；']);
            let span = SemanticSpan {
                start_byte,
                end_byte: start_byte + token.len(),
            };
            if !text[cursor..start_byte].trim().is_empty() {
                valid = false;
                break;
            }
            let Ok(url) = url::Url::parse(token) else {
                valid = false;
                break;
            };
            if canonical_target
                .as_ref()
                .is_some_and(|target: &String| target != url.as_str())
            {
                valid = false;
                break;
            }
            canonical_target = Some(url.to_string());
            let Some(link_index) = context.links.iter().position(|link| {
                attachment_link_span(&link.link_id) == Some(span)
                    && url::Url::parse(&link.original_url).is_ok_and(|original| original == url)
            }) else {
                valid = false;
                break;
            };
            observed.push((link_index, span));
            cursor = span.end_byte;
        }
        if !valid
            || observed.is_empty()
            || !text[cursor..target_line_end]
                .trim_matches(|character: char| {
                    character.is_whitespace() || matches!(character, '.' | '。' | '!' | '！')
                })
                .is_empty()
        {
            continue;
        }
        let source_end = source_ranges
            .iter()
            .find(|range| {
                range.kind == AttachmentSemanticSourceKind::RenderedHtml
                    && range.span.start_byte <= claim.span.start_byte
                    && target_line_end <= range.span.end_byte
            })
            .map_or(text.len(), |range| range.span.end_byte);
        if canonical_target.as_deref().is_some_and(|target| {
            attachment_adjacent_url_target_is_ambiguous(text, target_line_end, source_end, target)
        }) {
            continue;
        }
        bindings.push((claim_index, target_line_start, claim, observed));
    }
    for (claim_index, target_line_start, bound_claim, observed) in &bindings {
        // Two requests competing for the same following line are ambiguous.
        if bindings
            .iter()
            .filter(|(_, line_start, _, _)| line_start == target_line_start)
            .count()
            != 1
        {
            continue;
        }
        let mut claim = bound_claim.clone();
        claim
            .provenance
            .push("attachment_credential_deictic_target_v1".to_string());
        if !bound_claim
            .provenance
            .iter()
            .any(|value| value == "attachment_credential_rendered_target_v1")
            && source_ranges.iter().any(|range| {
                range.kind == AttachmentSemanticSourceKind::RenderedHtml
                    && range.span.start_byte <= claim.span.start_byte
                    && observed
                        .iter()
                        .all(|(_, span)| span.end_byte <= range.span.end_byte)
            })
        {
            claim
                .provenance
                .push("attachment_credential_rendered_target_v1".to_string());
        }
        claim.provenance.push(format!(
            "attachment_credential_deictic_source:{}",
            claim.source_span_id
        ));
        for (link_index, span) in observed {
            let link = &mut context.links[*link_index];
            claim.link_ids.push(link.link_id.clone());
            claim.provenance.push(format!(
                "attachment_credential_target_span:{}:{}",
                span.start_byte, span.end_byte
            ));
            // The observed URL has its own source span; the CTA is connected by
            // link ID rather than by extending the CTA across another sentence.
            link.source_span_id = Some(format!("plain_text:{}:{}", span.start_byte, span.end_byte));
        }
        let retained_counters = claim
            .counter_context_ids
            .iter()
            .filter(|counter_id| {
                snapshot
                    .iter()
                    .find(|counter| &counter.source_span_id == *counter_id)
                    .is_none_or(|counter| semantic_counter_context_qualifies(&claim, counter))
            })
            .cloned()
            .collect();
        claim.counter_context_ids = retained_counters;
        context.claims[*claim_index] = claim;
    }
}

/// An RTF credential request can supply its target through an explicit
/// following Click pointer, but only its configured recipient-disable tail
/// may intervene. The decoded source range, original request and physical
/// pointer remain separate facts; unrelated text and targets cannot join them.
fn bind_attachment_rtf_credential_targets(
    text: &str,
    source_ranges: &[AttachmentSemanticSourceRange],
    context: &mut SemanticMessageContext,
) {
    const MAX_POINTER_GAP_BYTES: usize = 192;
    const MAX_COMPOUND_BYTES: usize = 512;
    let data = module_data();
    let pointer_markers = data.get_list("attachment_credential_target_pointer_markers_v1");
    let disable_tails = data.get_list("attachment_credential_disable_continuation_terms_v1");
    let credential_objects = data.get_list("attachment_credential_object_terms_v1");
    let authentication_actions = data.get_list("attachment_credential_continuation_actions_v1");
    if pointer_markers.is_empty() || disable_tails.is_empty() {
        return;
    }
    fn trim_tail(value: &str) -> &str {
        value.trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '，' | '.' | '。' | '!' | '！')
        })
    }
    let exact_disable_tail = |value: &str| {
        let normalized = normalize_text(&trim_tail(value).to_lowercase());
        disable_tails
            .iter()
            .any(|term| normalized == normalize_text(&term.to_lowercase()))
    };
    let snapshot = context.claims.clone();
    let mut bindings = Vec::new();
    for matched in RE_ATTACH_URL.find_iter(text).take(20) {
        let token = matched
            .as_str()
            .trim_end_matches(['.', ',', ';', '。', '，', '；']);
        let target_span = SemanticSpan {
            start_byte: matched.start(),
            end_byte: matched.start() + token.len(),
        };
        let before_url = text[..target_span.start_byte].trim_end_matches([' ', '\t']);
        let Some(marker) = pointer_markers.iter().find(|marker| {
            before_url
                .to_ascii_lowercase()
                .ends_with(&marker.to_ascii_lowercase())
        }) else {
            continue;
        };
        let pointer_start = before_url.len().saturating_sub(marker.len());
        if text[..pointer_start]
            .chars()
            .next_back()
            .is_some_and(|character| character.is_alphanumeric() || character == '_')
        {
            continue;
        }
        let Some(pointer_claim) = snapshot.iter().find(|claim| {
            claim.span.start_byte == pointer_start
                && target_span.end_byte <= claim.span.end_byte
                && RE_ATTACH_URL
                    .find_iter(&text[claim.span.start_byte..claim.span.end_byte])
                    .count()
                    == 1
                && trim_tail(&text[target_span.end_byte..claim.span.end_byte]).is_empty()
                && claim.quote_or_forward_status == SemanticQuoteStatus::Original
                && claim.polarity != SemanticPolarity::AntiAction
                && !matches!(
                    claim.speech_act,
                    SemanticSpeechAct::Report
                        | SemanticSpeechAct::Quotation
                        | SemanticSpeechAct::Warning
                )
        }) else {
            continue;
        };
        let Ok(url) = url::Url::parse(token) else {
            continue;
        };
        let Some(link_index) = context.links.iter().position(|link| {
            attachment_link_span(&link.link_id) == Some(target_span)
                && url::Url::parse(&link.original_url).is_ok_and(|original| original == url)
        }) else {
            continue;
        };
        let candidates = snapshot
            .iter()
            .enumerate()
            .filter(|(_, claim)| {
                let mut action = (*claim).clone();
                action.counter_context_ids.clear();
                if !is_current_recipient_action(&action)
                    || !claim.link_ids.is_empty()
                    || claim.span.end_byte > pointer_start
                    || pointer_start.saturating_sub(claim.span.end_byte) > MAX_POINTER_GAP_BYTES
                    || target_span.end_byte.saturating_sub(claim.span.start_byte)
                        > MAX_COMPOUND_BYTES
                    || !source_ranges.iter().any(|range| {
                        range.kind == AttachmentSemanticSourceKind::Rtf
                            && range.span.start_byte <= claim.span.start_byte
                            && target_span.end_byte <= range.span.end_byte
                    })
                    || claim.actions.is_empty()
                    || !claim.actions.iter().all(|action| {
                        authentication_actions
                            .iter()
                            .any(|term| action.eq_ignore_ascii_case(term))
                    })
                    || !claim.objects.iter().any(|object| {
                        credential_objects
                            .iter()
                            .any(|term| object.eq_ignore_ascii_case(term))
                    })
                {
                    return false;
                }
                let prefix = &text[claim.span.start_byte..pointer_start];
                let normalized = normalize_text(&trim_tail(prefix).to_lowercase());
                let gap = &text[claim.span.end_byte..pointer_start];
                !prefix.contains(['\n', '\r'])
                    && !attachment_target_context_boundary(prefix, &data)
                    && !RE_ATTACH_URL.is_match(prefix)
                    && disable_tails
                        .iter()
                        .any(|term| normalized.ends_with(&normalize_text(&term.to_lowercase())))
                    && (trim_tail(gap).is_empty() || exact_disable_tail(gap))
                    && !snapshot.iter().any(|other| {
                        other.source_span_id != claim.source_span_id
                            && other.source_span_id != pointer_claim.source_span_id
                            && other.span.end_byte > claim.span.end_byte
                            && other.span.start_byte < pointer_start
                            && (other.quote_or_forward_status != SemanticQuoteStatus::Original
                                || other.polarity == SemanticPolarity::AntiAction
                                || matches!(
                                    other.speech_act,
                                    SemanticSpeechAct::Report
                                        | SemanticSpeechAct::Quotation
                                        | SemanticSpeechAct::Warning
                                )
                                || !exact_disable_tail(
                                    &text[other.span.start_byte..other.span.end_byte],
                                ))
                    })
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if let [claim_index] = candidates.as_slice() {
            bindings.push((
                *claim_index,
                link_index,
                target_span,
                pointer_claim.source_span_id.clone(),
            ));
        }
    }
    for (claim_index, link_index, target_span, pointer_source) in bindings {
        if context.claims[claim_index]
            .link_ids
            .iter()
            .any(|link_id| link_id != &context.links[link_index].link_id)
        {
            continue;
        }
        let claim = &mut context.claims[claim_index];
        claim
            .link_ids
            .push(context.links[link_index].link_id.clone());
        claim
            .provenance
            .push("attachment_credential_deictic_target_v1".to_string());
        claim
            .provenance
            .push("attachment_credential_typed_freeze_pointer_v1".to_string());
        claim.provenance.push(format!(
            "attachment_credential_deictic_source:{}",
            claim.source_span_id
        ));
        claim.provenance.push(format!(
            "attachment_credential_continuation_source:{pointer_source}"
        ));
        claim.provenance.push(format!(
            "attachment_credential_target_span:{}:{}",
            target_span.start_byte, target_span.end_byte
        ));
        claim.counter_context_ids = claim
            .counter_context_ids
            .iter()
            .filter(|counter_id| {
                snapshot
                    .iter()
                    .find(|counter| &counter.source_span_id == *counter_id)
                    .is_none_or(|counter| semantic_counter_context_qualifies(claim, counter))
            })
            .cloned()
            .collect();
        context.links[link_index].source_span_id = Some(format!(
            "plain_text:{}:{}",
            target_span.start_byte, target_span.end_byte
        ));
    }
}

/// Apply the common bounded semantic extractor to the attachment's own visible
/// text and observed URLs. The plain-text adapter supplies physical URL
/// provenance; identifiers are then attributed to this attachment projection.
/// Mail-body links and language never supply an attachment's action authority.
fn attachment_credential_context(
    session: &EmailSession,
    text: &str,
    attachment_hash: &str,
    source_ranges: &[AttachmentSemanticSourceRange],
) -> SemanticMessageContext {
    let mut context = attachment_plain_semantic_context(session, text, source_ranges);
    attribute_attachment_context(&mut context, attachment_hash);
    context
}

/// The attachment context with plain-text semantics and plain-text
/// identifiers, before attribution. The semantic engine analyzes it with the
/// plain-text relation rules and attributes the results afterwards.
fn attachment_plain_semantic_context(
    session: &EmailSession,
    text: &str,
    source_ranges: &[AttachmentSemanticSourceRange],
) -> SemanticMessageContext {
    let mut projection = EmailSession::new(
        session.protocol,
        session.client_ip.clone(),
        session.client_port,
        session.server_ip.clone(),
        session.server_port,
    );
    projection.mail_from = session.mail_from.clone();
    projection.rcpt_to = session.rcpt_to.clone();
    // This projection represents bytes successfully decoded for this
    // attachment. Message-level capture gaps are handled independently by
    // the existing attachment budget and final-verdict coverage policy.
    projection.content.is_complete = true;
    projection.content.links = RE_ATTACH_URL
        .find_iter(text)
        .take(20)
        .filter(|matched| !is_probable_schema_reference_url(matched.as_str()))
        .map(|matched| EmailLink {
            url: matched
                .as_str()
                .trim_end_matches(['.', ',', ';', '。', '，', '；'])
                .to_string(),
            text: None,
            suspicious: false,
        })
        .collect();
    let mut context = extract_semantic_context(&projection, text, SemanticSourcePart::PlainText);
    let data = module_data();
    let credential_objects = data.get_list("attachment_credential_object_terms_v1");
    let continuation_actions = data.get_list("attachment_credential_continuation_actions_v1");
    let deictic_target_markers = data.get_list("attachment_credential_deictic_target_markers_v1");
    for (name, terms) in [
        ("attachment credential object", credential_objects),
        ("attachment credential continuation", continuation_actions),
        (
            "attachment credential deictic target",
            deictic_target_markers,
        ),
        (
            "attachment credential target pointer",
            data.get_list("attachment_credential_target_pointer_markers_v1"),
        ),
        (
            "attachment credential disable continuation",
            data.get_list("attachment_credential_disable_continuation_terms_v1"),
        ),
    ] {
        if terms.is_empty() {
            context.coverage = SemanticCoverageStatus::Incomplete;
            let reason = format!("{name} policy is missing or empty");
            context.coverage_reason = Some(context.coverage_reason.map_or_else(
                || reason.clone(),
                |existing| format!("{existing}; {reason}"),
            ));
        }
    }
    // The shared extractor splits "enter the code and immediately log in"
    // into two action clauses. Keep that one-sentence credential relationship
    // without borrowing an account/password mention from another paragraph or
    // a request already bound to a different link.
    let original_claims = context.claims.clone();
    for (index, claim) in context.claims.iter_mut().enumerate().skip(1) {
        let previous = &original_claims[index - 1];
        if !is_current_recipient_action(claim)
            || claim.link_ids.is_empty()
            || claim.actions.is_empty()
            || !claim.actions.iter().all(|action| {
                continuation_actions
                    .iter()
                    .any(|term| action.eq_ignore_ascii_case(term))
            })
            || !is_current_recipient_action(previous)
            || !previous.link_ids.is_empty()
            || !previous.objects.iter().any(|object| {
                credential_objects
                    .iter()
                    .any(|term| object.eq_ignore_ascii_case(term))
            })
            || previous.span.end_byte > claim.span.start_byte
            || !text[previous.span.end_byte..claim.span.start_byte]
                .chars()
                .all(|character| matches!(character, ' ' | '\t'))
            || text[previous.span.start_byte..claim.span.start_byte].contains(['\n', '\r'])
            || text[previous.span.start_byte..previous.span.end_byte]
                .trim_end()
                .ends_with(['.', '．', '。', '！', '？', '!', '?', ';', '；'])
            || text[claim.span.start_byte..claim.span.end_byte]
                .trim_start()
                .starts_with([';', '；'])
            || attachment_target_context_boundary(
                &text[previous.span.start_byte..claim.span.end_byte],
                &data,
            )
        {
            continue;
        }
        let continuation_id = claim.source_span_id.clone();
        claim
            .provenance
            .push("attachment_credential_same_sentence_continuation_v1".to_string());
        claim.provenance.push(format!(
            "attachment_credential_continuation_source:{}",
            previous.source_span_id
        ));
        claim.provenance.push(format!(
            "attachment_credential_continuation_source:{continuation_id}"
        ));
        claim.span.start_byte = previous.span.start_byte;
        claim.source_span_id = format!(
            "plain_text:{}:{}",
            claim.span.start_byte, claim.span.end_byte
        );
        if claim.object.is_none() {
            claim.object = previous.object.clone();
        }
        for object in &previous.objects {
            if !claim.objects.contains(object) {
                claim.objects.push(object.clone());
            }
        }
        for action in &previous.actions {
            if !claim.actions.contains(action) {
                claim.actions.push(action.clone());
            }
        }
        for link in &mut context.links {
            if link.source_span_id.as_deref() == Some(continuation_id.as_str()) {
                link.source_span_id = Some(claim.source_span_id.clone());
            }
        }
    }
    bind_attachment_deictic_targets(text, source_ranges, &mut context);
    bind_attachment_rtf_credential_targets(text, source_ranges, &mut context);
    context
}

fn attachment_span_id(id: &str, attachment_hash: &str) -> String {
    id.strip_prefix("plain_text:").map_or_else(
        || id.to_string(),
        |offsets| format!("attachment:{attachment_hash}:{offsets}"),
    )
}

/// Attribute a plain-text claim to one attachment projection. Identifiers
/// already attributed are left unchanged.
pub(crate) fn attribute_attachment_claim(claim: &mut SemanticClaim, attachment_hash: &str) {
    let attachment_id = |id: &str| attachment_span_id(id, attachment_hash);
    claim.source_part = SemanticSourcePart::Attachment;
    claim.source_span_id = attachment_id(&claim.source_span_id);
    claim.causal_key = format!("semantic_span:{}", claim.source_span_id);
    for counter in &mut claim.counter_context_ids {
        *counter = attachment_id(counter);
    }
    for provenance in &mut claim.provenance {
        if let Some(source) = provenance.strip_prefix("attachment_credential_continuation_source:")
        {
            *provenance = format!(
                "attachment_credential_continuation_source:{}",
                attachment_id(source)
            );
        } else if let Some(source) =
            provenance.strip_prefix("attachment_credential_deictic_source:")
        {
            *provenance = format!(
                "attachment_credential_deictic_source:{}",
                attachment_id(source)
            );
        }
    }
}

/// Attribute every claim and link of a plain-text attachment context.
pub(crate) fn attribute_attachment_context(
    context: &mut SemanticMessageContext,
    attachment_hash: &str,
) {
    for claim in &mut context.claims {
        attribute_attachment_claim(claim, attachment_hash);
    }
    for link in &mut context.links {
        link.extraction_source = SemanticLinkExtractionSource::Attachment;
        link.source_span_id = link
            .source_span_id
            .as_deref()
            .map(|id| attachment_span_id(id, attachment_hash));
    }
}

/// A credential request qualifies only its physically observed URL occurrence.
/// An account column, a verification-environment heading, URL path words, a
/// quote, a report, or an anti-action claim cannot manufacture this relation.
fn attachment_has_credential_lure<'a>(
    context: &'a SemanticMessageContext,
    url: &str,
    url_span: SemanticSpan,
) -> Option<&'a SemanticClaim> {
    let data = module_data();
    let terms = data.get_list("attachment_credential_object_terms_v1");
    let canonical = url::Url::parse(url.trim_end_matches(['.', ',', ';', '。', '，', '；']))
        .ok()?
        .to_string();
    context.claims.iter().find(|claim| {
        is_current_recipient_action(claim)
            && claim
                .objects
                .iter()
                .any(|object| terms.iter().any(|term| object.eq_ignore_ascii_case(term)))
            && context.links.iter().any(|link| {
                claim.link_ids.contains(&link.link_id)
                    && attachment_link_span(&link.link_id) == Some(url_span)
                    && url::Url::parse(&link.original_url)
                        .is_ok_and(|parsed| parsed.as_str() == canonical)
                    && ((link.source_span_id.as_deref() == Some(claim.source_span_id.as_str())
                        && claim.span.start_byte <= url_span.start_byte
                        && url_span.end_byte <= claim.span.end_byte)
                        || (claim
                            .provenance
                            .iter()
                            .any(|value| value == "attachment_credential_deictic_target_v1")
                            && claim.provenance.iter().any(|value| {
                                value
                                    == &format!(
                                        "attachment_credential_target_span:{}:{}",
                                        url_span.start_byte, url_span.end_byte
                                    )
                            })))
            })
    })
}

/// A forwarded message may place its recipient-directed identity check and
/// short account-freeze threat in one paragraph while placing the only link
/// in the next paragraph. Admit that relation only for a nested message, an
/// original recipient action claim that explicitly verifies identity, a
/// configured freeze deadline, and an exact deictic physical target binding.
/// This compatibility compound never provides unbound URL authority.
fn nested_message_has_identity_freeze_lure(context: &SemanticMessageContext, text: &str) -> bool {
    let data = module_data();
    let verification_terms =
        data.get_list("account_security_no_link_credential_verification_terms");
    context.claims.iter().any(|claim| {
        if !is_current_recipient_action(claim) {
            return false;
        }
        if !claim
            .provenance
            .iter()
            .any(|value| value == "attachment_credential_deictic_target_v1")
            || !claim.link_ids.iter().any(|link_id| {
                let Some(span) = attachment_link_span(link_id) else {
                    return false;
                };
                context
                    .links
                    .iter()
                    .find(|link| &link.link_id == link_id)
                    .is_some_and(|link| {
                        attachment_has_credential_lure(context, &link.original_url, span)
                            .is_some_and(|bound| bound.source_span_id == claim.source_span_id)
                    })
            })
        {
            return false;
        }
        let Some(claim_text) = text.get(claim.span.start_byte..claim.span.end_byte) else {
            return false;
        };
        if !verification_terms.iter().any(|term| {
            normalize_text(&claim_text.to_lowercase())
                .contains(&normalize_text(&term.to_lowercase()))
        }) {
            return false;
        }
        let Some(window) = text_around_span(text, claim.span, 256) else {
            return false;
        };
        attachment_config_term_hits(window, "account_security_no_link_imminent_disable_terms") > 0
    })
}

/// Return a bounded character window around a valid UTF-8 byte span.
fn text_around_span(text: &str, span: SemanticSpan, radius_chars: usize) -> Option<&str> {
    let before = text.get(..span.start_byte)?;
    let after = text.get(span.end_byte..)?;
    let start = before
        .char_indices()
        .rev()
        .nth(radius_chars.saturating_sub(1))
        .map_or(0, |(offset, _)| offset);
    let end = after
        .char_indices()
        .nth(radius_chars)
        .map_or(text.len(), |(offset, character)| {
            span.end_byte + offset + character.len_utf8()
        });
    text.get(start..end)
}

/// Count distinct configured phrases in attachment text. Attachment policy
/// lists live in the JSON registry so deployments can tune vocabulary without
/// embedding prompts or campaign-specific prose in the binary.
fn attachment_config_term_hits(text: &str, key: &str) -> usize {
    let normalized = normalize_text(&text.to_lowercase());
    module_data()
        .get_list(key)
        .iter()
        .filter(|term| {
            let term = normalize_text(&term.to_lowercase());
            !term.is_empty() && normalized.contains(&term)
        })
        .count()
}

fn attachment_has_payment_lure(text: &str) -> bool {
    attachment_config_term_hits(text, "attachment_payment_lure_terms") > 0
        && attachment_config_term_hits(text, "attachment_payment_lure_action_terms") > 0
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

fn is_internet_shortcut_candidate(filename: &str, content_type: &str) -> bool {
    file_extension(filename).as_deref() == Some("url")
        || content_type
            .to_ascii_lowercase()
            .contains("internet-shortcut")
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
        budget.exhausted |= text.projection_limited;
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

/// Bounds for attachment text handed to the semantic engine. Attachments past
/// these bounds stay covered by this module's own extraction; the semantic
/// pass records them as skipped instead of reporting a coverage gap.
const MAX_SEMANTIC_ATTACHMENT_SOURCES: usize = 4;
const MAX_SEMANTIC_ATTACHMENT_DECODE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SEMANTIC_ATTACHMENT_TEXT_BYTES: usize = 256 * 1024;
/// Extraction cannot be interrupted, so a new attachment is started only with
/// at least this much time left before the semantic deadline.
const MIN_SEMANTIC_ATTACHMENT_TIME: std::time::Duration = std::time::Duration::from_millis(300);

/// One attachment's visible text with plain-text semantic facts whose
/// identifiers are not yet attributed to the attachment.
pub(crate) struct SemanticAttachmentSource {
    pub(crate) hash: String,
    pub(crate) filename: String,
    pub(crate) text: String,
    pub(crate) context: SemanticMessageContext,
    pub(crate) projection_limited: bool,
}

#[derive(Default)]
pub(crate) struct SemanticAttachmentSources {
    pub(crate) sources: Vec<SemanticAttachmentSource>,
    /// Attachment filename and the reason it was not analyzed.
    pub(crate) skipped: Vec<(String, &'static str)>,
}

/// Extract bounded attachment text for the semantic engine.
pub(crate) fn semantic_attachment_sources(
    session: &EmailSession,
    deadline: Instant,
) -> SemanticAttachmentSources {
    let mut budget = AttachmentExtractionBudget::default();
    let mut result = SemanticAttachmentSources::default();
    for attachment in &session.content.attachments {
        let skipped = |reason| (attachment.filename.clone(), reason);
        if result.sources.len() >= MAX_SEMANTIC_ATTACHMENT_SOURCES {
            result.skipped.push(skipped("source_limit"));
            continue;
        }
        let Some(content_base64) = attachment.content_base64.as_deref() else {
            result.skipped.push(skipped("bytes_not_retained"));
            continue;
        };
        if attachment.size > MAX_SEMANTIC_ATTACHMENT_DECODE_BYTES {
            result.skipped.push(skipped("size_limit"));
            continue;
        }
        if deadline.saturating_duration_since(Instant::now()) < MIN_SEMANTIC_ATTACHMENT_TIME {
            result.skipped.push(skipped("time_budget"));
            continue;
        }
        let Some(extracted) = extract_attachment_text(
            &attachment.filename,
            &attachment.content_type,
            content_base64,
            attachment.size,
            &mut budget,
        ) else {
            result.skipped.push(skipped("no_text"));
            continue;
        };
        let Some(mut text) = budget.retain_scannable_text(extracted.text) else {
            result.skipped.push(skipped("no_text"));
            continue;
        };
        let mut projection_limited = extracted.projection_limited;
        if text.len() > MAX_SEMANTIC_ATTACHMENT_TEXT_BYTES {
            truncate_utf8(&mut text, MAX_SEMANTIC_ATTACHMENT_TEXT_BYTES);
            projection_limited = true;
        }
        let source_ranges = extracted
            .semantic_source_ranges
            .into_iter()
            .filter(|range| range.span.end_byte <= text.len())
            .collect::<Vec<_>>();
        let context = attachment_plain_semantic_context(session, &text, &source_ranges);
        result.sources.push(SemanticAttachmentSource {
            hash: attachment.hash.clone(),
            filename: attachment.filename.clone(),
            text,
            context,
            projection_limited,
        });
    }
    result
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
            cap_optional_text(extract_document_text(bytes, file_type, budget), budget)
                .map(ExtractedText::from_text)
        } else {
            None
        };
        let nested_text = extract_nested_zip_text(bytes, depth, budget);

        return join_optional_text(direct_text, nested_text, budget);
    }

    // Decode the recipient-visible RTF controls before retaining source
    // ranges. Raw control bytes cannot define a request or a URL boundary.
    if file_type == Some(DetectedFileType::Rtf) || ext.as_deref() == Some("rtf") {
        let text = extract_document_text(bytes, Some(DetectedFileType::Rtf), budget)?;
        let text = cap_text(text, budget);
        if text.trim().is_empty() {
            return None;
        }
        let mut extracted = ExtractedText::from_text(text);
        extracted
            .semantic_source_ranges
            .push(AttachmentSemanticSourceRange {
                span: SemanticSpan {
                    start_byte: 0,
                    end_byte: extracted.text.len(),
                },
                kind: AttachmentSemanticSourceKind::Rtf,
            });
        return Some(extracted);
    }

    if file_type.is_some_and(|ft| ft.is_extractable_document()) {
        return cap_optional_text(extract_document_text(bytes, file_type, budget), budget)
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
            text: cap_text(extracted.text, budget),
            meta_refresh_urls: extracted.meta_refresh_urls,
            credential_form: extracted.credential_form,
            credential_form_urls: extracted.credential_form_urls,
            nested_message: extracted.nested_message,
            projection_limited: extracted.projection_limited,
            semantic_source_ranges: extracted.semantic_source_ranges,
        });
    }

    if is_internet_shortcut_candidate(filename, content_type) {
        let text = decode_plain_text_bytes(bytes)?;
        return cap_optional_text(Some(text), budget).map(ExtractedText::from_text);
    }

    // iCalendar invites (.ics / text/calendar) are line-folded; unfold before
    // scanning so wrapped URLs and ATTACH payloads stay contiguous.
    if ext.as_deref().is_some_and(|ext| ext == "ics")
        || content_type.to_lowercase().contains("text/calendar")
    {
        let text = decode_plain_text_bytes(bytes)?;
        return cap_optional_text(Some(unfold_ics_lines(&text)), budget)
            .map(ExtractedText::from_text);
    }

    if file_type.is_some_and(|ft| ft.is_text_scannable())
        || is_text_mime_candidate(content_type)
        || is_plain_text_extension(ext.as_deref())
    {
        return cap_optional_text(decode_plain_text_bytes(bytes), budget)
            .map(ExtractedText::from_text);
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
    is_internet_shortcut_candidate(filename, content_type)
        || is_plain_text_extension(ext.as_deref())
        || is_ooxml_or_odf_extension(ext.as_deref())
        || matches!(
            ext.as_deref(),
            Some(
                "pdf"
                    | "doc"
                    | "xls"
                    | "ppt"
                    | "rtf"
                    | "html"
                    | "htm"
                    | "eml"
                    | "mht"
                    | "mhtml"
                    | "hwp"
                    | "zip"
            )
        )
        || is_text_mime_candidate(&ct)
        || ct.contains("pdf")
        || ct.contains("rtf")
        || ct.contains("officedocument")
        || ct.contains("opendocument")
        || ct.contains("application/zip")
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

fn extract_document_text(
    bytes: &[u8],
    file_type: Option<DetectedFileType>,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    let extracted = document_extract::extract_text_with_coverage(bytes, file_type);
    budget.exhausted |= !extracted.complete;
    extracted.text
}

fn cap_text(text: String, budget: &mut AttachmentExtractionBudget) -> String {
    cap_text_to_limit(text, MAX_NESTED_TEXT_CHARS, budget)
}

fn cap_text_to_limit(
    mut text: String,
    limit: usize,
    budget: &mut AttachmentExtractionBudget,
) -> String {
    if text.len() > limit {
        budget.exhausted = true;
        truncate_utf8(&mut text, limit);
    }
    text
}

fn cap_optional_text(
    text: Option<String>,
    budget: &mut AttachmentExtractionBudget,
) -> Option<String> {
    text.map(|text| cap_text(text, budget))
        .filter(|text| !text.trim().is_empty())
}

fn append_nested_text(target: &mut String, text: &str, budget: &mut AttachmentExtractionBudget) {
    let separator_len = usize::from(!target.is_empty());
    let remaining = MAX_NESTED_TEXT_CHARS.saturating_sub(target.len() + separator_len);
    if text.len() > remaining {
        budget.exhausted = true;
    }
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

fn append_nested_extraction(
    target: &mut ExtractedText,
    nested: ExtractedText,
    prefix: &str,
    budget: &mut AttachmentExtractionBudget,
) {
    let offset = target.text.len() + usize::from(!target.text.is_empty()) + prefix.len();
    append_nested_text(
        &mut target.text,
        &format!("{prefix}{}", nested.text),
        budget,
    );
    for range in nested.semantic_source_ranges {
        let start_byte = offset.saturating_add(range.span.start_byte);
        let end_byte = offset
            .saturating_add(range.span.end_byte)
            .min(target.text.len());
        if start_byte < end_byte {
            target
                .semantic_source_ranges
                .push(AttachmentSemanticSourceRange {
                    span: SemanticSpan {
                        start_byte,
                        end_byte,
                    },
                    kind: range.kind,
                });
        }
    }
    merge_meta_refresh_urls(&mut target.meta_refresh_urls, nested.meta_refresh_urls);
    target.credential_form |= nested.credential_form;
    target
        .credential_form_urls
        .extend(nested.credential_form_urls);
    target.nested_message |= nested.nested_message;
    target.projection_limited |= nested.projection_limited;
}

fn join_optional_text(
    first: Option<ExtractedText>,
    second: Option<ExtractedText>,
    budget: &mut AttachmentExtractionBudget,
) -> Option<ExtractedText> {
    match (first, second) {
        (Some(mut left), Some(right)) => {
            append_nested_extraction(&mut left, right, "", budget);
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

        let Ok(name) = entry.name().map(|name| name.into_owned()) else {
            budget.exhausted = true;
            continue;
        };
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

        if let Some(nested) =
            extract_attachment_text_from_bytes(&name, "", &data, depth + 1, budget)
        {
            append_nested_extraction(&mut out, nested, &format!("[{name}]\n"), budget);
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
            append_nested_text(&mut out.text, &format!("{header}: {decoded}"), budget);
        }
    }

    if let Some(text) = content.body_text.as_deref() {
        append_nested_text(&mut out.text, text, budget);
    }
    if let Some(html) = content.body_html.as_deref() {
        // MHTML archives and HTML-bodied forwards: keep the attribute URLs /
        // meta-refresh targets that plain tag stripping would discard.
        if let Some(extracted) = extract_html_attachment_text(html) {
            append_nested_extraction(&mut out, extracted, "", budget);
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
            append_nested_extraction(
                &mut out,
                nested,
                &format!("[{}]\n", attachment.filename),
                budget,
            );
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

    // Calendar invitations can hide the only actionable URL in the `URL`
    // property while the surrounding MIME body remains harmless. Require an
    // untrusted authentication path plus at least two configured credential
    // cues in the calendar text; a normal meeting URL or attendee metadata is
    // not enough.
    let normalized = normalize_text(&text_lower);
    let compact: String = normalized
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect();
    let credential_hits = module_data()
        .get_list("ics_credential_lure_terms")
        .iter()
        .filter(|term| {
            let term_normalized = normalize_text(&term.to_lowercase());
            normalized.contains(&term_normalized)
                || compact.contains(
                    &term_normalized
                        .chars()
                        .filter(|ch| ch.is_alphanumeric())
                        .collect::<String>(),
                )
        })
        .count();
    let module_data = module_data();
    let auth_path_terms = module_data.get_list("ics_auth_path_terms");
    let auth_url = RE_ATTACH_URL.find_iter(text).find_map(|matched| {
        let candidate = matched.as_str().trim_end_matches(['.', ',', ';', ')', ']']);
        let parsed = url::Url::parse(candidate).ok()?;
        let domain = parsed.host_str()?;
        let untrusted = !crate::modules::link_scan::is_trusted_url_domain(domain)
            && !crate::modules::link_scan::is_well_known_safe_domain(domain);
        let auth_path = parsed.path_segments().is_some_and(|mut segments| {
            segments.any(|segment| {
                auth_path_terms
                    .iter()
                    .any(|term| segment.eq_ignore_ascii_case(term))
            })
        });
        (untrusted && auth_path && credential_hits >= 2).then_some(candidate.to_string())
    });
    if let Some(target) = auth_url {
        score += 0.50;
        categories.push("ics_url_credential_lure".to_string());
        evidence.push(Evidence {
            description: format!(
                "Calendar invite {} embeds an untrusted authentication URL with {} credential cues",
                filename, credential_hits
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(target),
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

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn scan_attachment_text(
    text: &str,
    filename: &str,
    phishing_keywords: &[String],
    weak_phishing_keywords: &[String],
    bec_phrases: &[String],
    gate: AttachmentThreatGate,
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let phishing_matcher = KeywordMatcher::new(phishing_keywords);
    let weak_phishing_matcher = KeywordMatcher::new(weak_phishing_keywords);
    let bec_matcher = KeywordMatcher::new(bec_phrases);
    scan_attachment_text_with_matchers(
        text,
        filename,
        &phishing_matcher,
        &weak_phishing_matcher,
        &bec_matcher,
        gate,
        evidence,
        categories,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_attachment_text_with_matchers(
    text: &str,
    filename: &str,
    phishing_matcher: &KeywordMatcher,
    weak_phishing_matcher: &KeywordMatcher,
    bec_matcher: &KeywordMatcher,
    gate: AttachmentThreatGate,
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score: f64 = 0.0;
    let normalized = normalize_text(&text.to_lowercase());
    // Keep local document boundaries. Flattening a policy/manual into one
    // string lets unrelated paragraphs (for example an account-status section
    // and an SMS-code section) fabricate a phishing scenario.
    let segments: Vec<&str> = normalized
        .split(['\n', '\r', '。', '！', '？', '!', '?', '；', ';'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect();
    let data = module_data();
    let context_required_phishing = data.get_list("attachment_context_required_phishing_keywords");
    let phishing_action_markers = data.get_list("attachment_phishing_action_markers");
    let payment_behavior_markers = data.get_list("attachment_payment_behavior_markers");
    let mut phishing_hits: HashSet<String> = HashSet::new();
    let mut phishing_observations: HashSet<String> = HashSet::new();
    let mut weak_hits: HashSet<String> = HashSet::new();
    let mut strong_bec_hits: HashSet<String> = HashSet::new();
    let mut weak_bec_cluster_hits: HashSet<String> = HashSet::new();
    let mut bec_observations: HashSet<String> = HashSet::new();

    for (segment_index, segment) in segments.iter().enumerate() {
        // A nested message is rendered as `Subject`, `From`, then body. Keep
        // context qualification local, but allow a header signal to pair with
        // an action marker in the next two rendered segments. This catches a
        // synthetic split lure without flattening an entire
        // policy/manual into one cross-paragraph phishing sentence.
        let context_start = segment_index.saturating_sub(2);
        let context_end = (segment_index + 2).min(segments.len().saturating_sub(1));
        let has_phishing_action = segments[context_start..=context_end]
            .iter()
            .any(|candidate| {
                phishing_action_markers
                    .iter()
                    .any(|marker| candidate.contains(marker.as_str()))
            });
        let has_payment_behavior = segments[context_start..=context_end]
            .iter()
            .any(|candidate| {
                payment_behavior_markers
                    .iter()
                    .any(|marker| candidate.contains(marker.as_str()))
            });
        let local_gate_open = gate.is_open() || has_phishing_action || has_payment_behavior;
        let local_phishing: Vec<&String> = phishing_matcher
            .find(segment)
            .into_iter()
            .filter(|keyword| !context_required_phishing.contains(keyword) || has_phishing_action)
            .collect();
        for keyword in &local_phishing {
            if local_gate_open {
                phishing_hits.insert((*keyword).clone());
            } else {
                phishing_observations.insert((*keyword).clone());
            }
        }

        // Weak vocabulary may corroborate a qualified primary phrase only in
        // the same local segment; terms scattered through a long document do
        // not accumulate into one lure.
        if !local_phishing.is_empty() && local_gate_open {
            let local_weak = weak_phishing_matcher.find(segment);
            if local_weak.len() >= 3 {
                for keyword in local_weak {
                    weak_hits.insert(keyword.clone());
                }
            }
        }

        let local_bec = bec_matcher.find(segment);
        let mut local_weak_bec = Vec::new();
        for phrase in local_bec {
            if is_actionable_bec_phrase(segment, phrase) && local_gate_open {
                strong_bec_hits.insert(phrase.clone());
            } else {
                local_weak_bec.push(phrase);
            }
        }
        if local_weak_bec.len() >= 3 {
            for phrase in &local_weak_bec {
                if local_gate_open {
                    weak_bec_cluster_hits.insert((*phrase).clone());
                } else {
                    bec_observations.insert((*phrase).clone());
                }
            }
        } else if !local_weak_bec.is_empty() && !local_gate_open {
            bec_observations.extend(local_weak_bec.into_iter().cloned());
        }
    }

    let mut phishing_hits: Vec<String> = phishing_hits.into_iter().collect();
    phishing_hits.sort_unstable();
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

    let mut phishing_observations: Vec<String> = phishing_observations.into_iter().collect();
    phishing_observations.sort_unstable();
    if !phishing_observations.is_empty() {
        categories.push("attachment_business_keyword_observation".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} retained {} generic phishing-shaped keyword observation(s); no local action, suspicious link, credential form, or payment behavior gate",
                filename,
                phishing_observations.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(phishing_observations.join(", ")),
        });
    }

    let mut weak_hits: Vec<String> = weak_hits.into_iter().collect();
    weak_hits.sort_unstable();
    if !weak_hits.is_empty() {
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

    let mut strong_bec_hits: Vec<String> = strong_bec_hits.into_iter().collect();
    strong_bec_hits.sort_unstable();
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
    } else if !weak_bec_cluster_hits.is_empty() {
        let mut weak_bec_hits: Vec<String> = weak_bec_cluster_hits.into_iter().collect();
        weak_bec_hits.sort_unstable();
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

    let mut bec_observations: Vec<String> = bec_observations.into_iter().collect();
    bec_observations.sort_unstable();
    if !bec_observations.is_empty() {
        categories.push("attachment_business_keyword_observation".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} retained {} generic business/BEC keyword observation(s); no local action, suspicious link, credential form, or payment behavior gate",
                filename,
                bec_observations.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(bec_observations.join(", ")),
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
        let mut attachment_credential_contexts = Vec::new();
        let mut qualified_attachment_credential_claims = Vec::new();
        let mut budget = AttachmentExtractionBudget::default();
        let sender_is_external = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|address| address.rsplit('@').next())
            .is_none_or(|domain| {
                !ctx.is_internal_domain(domain)
                    && !module_data().contains("protected_domains", domain)
                    && !crate::modules::link_scan::is_well_known_safe_domain(domain)
            });

        // Parser-level coverage gaps (multipart budget degradation, dropped
        // or oversized attachments) must surface here even when the retained
        // attachments themselves extract cleanly — otherwise a 101-attachment
        // or >32MB-payload message reports "fully scanned".
        if ctx.session.content.truncated || ctx.session.content.dropped_attachments > 0 {
            budget.exhausted = true;
        }

        for attachment in &ctx.session.content.attachments {
            let nested_message_declared = file_extension(&attachment.filename).as_deref()
                == Some("eml")
                || attachment
                    .content_type
                    .to_ascii_lowercase()
                    .contains("message/rfc822");
            if nested_message_declared {
                categories.push("nested_message_observed".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Nested RFC822 message `{}` was retained for content inspection",
                        attachment.filename
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: None,
                });
            }
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
                if is_attachment_text_candidate_by_metadata(
                    &attachment.filename,
                    &attachment.content_type,
                ) {
                    // Bytes were retained but the typed extractor could not
                    // decode them (malformed/unsupported document). This is
                    // an inspection gap, not a clean attachment result.
                    budget.exhausted = true;
                }
                continue;
            };
            budget.exhausted |= extracted.projection_limited;
            let Some(text) = budget.retain_scannable_text(extracted.text) else {
                continue;
            };

            scanned_count += 1;

            // Extract embedded URLs from the document text and run our
            // structural heuristics on each one. PDF / DOCX phishing routinely
            // hides the malicious link as a text annotation that the body of
            // the email never references — without this pass those campaigns
            // produce zero link-layer signal.
            let mut url_score_for_attachment = 0.0f64;
            let mut url_count = 0usize;
            let mut has_suspicious_url = false;
            let mut weak_url_observation_count = 0usize;
            let mut raw_ip_url_observation_count = 0usize;
            let mut seen_urls: HashSet<String> = HashSet::new();
            let mut nested_ip_auth_urls: HashMap<String, Vec<(&'static str, f64)>> = HashMap::new();
            let mut seen_reason_hosts: HashSet<(String, &'static str)> = HashSet::new();
            let mut credential_context = attachment_credential_context(
                &ctx.session,
                &text,
                &attachment.hash,
                &extracted.semantic_source_ranges,
            );
            if extracted.projection_limited {
                credential_context.coverage = SemanticCoverageStatus::Incomplete;
                let reason = "attachment HTML semantic projection was limited by its source, link, or wall-clock budget";
                credential_context.coverage_reason =
                    Some(credential_context.coverage_reason.map_or_else(
                        || reason.to_string(),
                        |existing| format!("{existing}; {reason}"),
                    ));
            }
            if credential_context.coverage == SemanticCoverageStatus::Incomplete {
                budget.exhausted = true;
            }
            let mut has_credential_lure = false;
            let has_payment_lure = attachment_has_payment_lure(&text);
            let is_redirect_container = !extracted.meta_refresh_urls.is_empty()
                || is_internet_shortcut_candidate(&attachment.filename, &attachment.content_type);
            for m in RE_ATTACH_URL.find_iter(&text).take(20) {
                let url = m.as_str();
                if is_probable_schema_reference_url(url) {
                    continue;
                }
                let first_url_occurrence = seen_urls.insert(url.to_string());
                if first_url_occurrence {
                    url_count += 1;
                }
                let hits = classify_attachment_url(url);
                if hits.is_empty() {
                    continue;
                }
                if extracted.nested_message
                    && attachment_url_has_reason(&hits, "uses raw IP address as host")
                    && attachment_url_has_reason(&hits, "auth-themed path segment")
                    && let Ok(parsed) =
                        url::Url::parse(url.trim_end_matches(['.', ',', ';', '。', '，', '；']))
                {
                    nested_ip_auth_urls
                        .entry(parsed.to_string())
                        .or_insert_with(|| hits.clone());
                }
                let trimmed_url = url.trim_end_matches(['.', ',', ';', '。', '，', '；']);
                let credential_claim = attachment_has_credential_lure(
                    &credential_context,
                    trimmed_url,
                    SemanticSpan {
                        start_byte: m.start(),
                        end_byte: m.start() + trimmed_url.len(),
                    },
                );
                let credential_form_target = url::Url::parse(trimmed_url).ok().is_some_and(|url| {
                    extracted
                        .credential_form_urls
                        .iter()
                        .any(|target| target == url.as_str())
                });
                let has_local_credential_lure =
                    credential_claim.is_some() || credential_form_target;
                if !attachment_url_is_actionable(
                    &hits,
                    is_redirect_container,
                    has_local_credential_lure || (sender_is_external && has_payment_lure),
                ) {
                    if first_url_occurrence {
                        weak_url_observation_count += 1;
                        if attachment_url_has_reason(&hits, "uses raw IP address as host") {
                            raw_ip_url_observation_count += 1;
                        }
                    }
                    continue;
                }
                has_suspicious_url = true;
                has_credential_lure |= has_local_credential_lure;
                if let Some(claim) = credential_claim {
                    qualified_attachment_credential_claims.push(serde_json::json!({
                        "attachment_hash": attachment.hash,
                        "category": "attachment_phishing_url",
                        "claim": claim,
                        "supporting_claim_ids": claim.provenance.iter().filter_map(|value| {
                            value.strip_prefix("attachment_credential_continuation_source:")
                                .or_else(|| value.strip_prefix("attachment_credential_deictic_source:"))
                        }).collect::<Vec<_>>(),
                        "observed_target_span": SemanticSpan {
                            start_byte: m.start(),
                            end_byte: m.start() + trimmed_url.len(),
                        },
                        "target_link_observations": credential_context.links.iter().filter(|link| {
                            claim.link_ids.contains(&link.link_id)
                                && attachment_link_span(&link.link_id) == Some(SemanticSpan {
                                    start_byte: m.start(),
                                    end_byte: m.start() + trimmed_url.len(),
                                })
                        }).collect::<Vec<_>>(),
                        "original_url": trimmed_url,
                        "effective_url": trimmed_url,
                        "link_extraction_source": "attachment",
                        "link_transport_status": "not_attempted",
                        "link_content_status": "not_observed",
                        "link_ownership_status": "unknown",
                        "coverage_reason": "attachment target was extracted but transport, content, and ownership were not verified",
                    }));
                }
                let reason_host = url::Url::parse(url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
                    .unwrap_or_else(|| "<unparseable>".to_string());
                let independent_hits: Vec<(&'static str, f64)> = hits
                    .into_iter()
                    .filter(|(reason, _)| seen_reason_hosts.insert((reason_host.clone(), *reason)))
                    .collect();
                if independent_hits.is_empty() {
                    continue;
                }
                let local: f64 = independent_hits
                    .iter()
                    .map(|(_, weight)| *weight)
                    .sum::<f64>()
                    .min(0.45);
                url_score_for_attachment += local;
                let reasons: Vec<&'static str> =
                    independent_hits.iter().map(|(reason, _)| *reason).collect();
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
            let nested_identity_freeze_compound = self.nested_message_identity_freeze_enabled
                && extracted.nested_message
                && sender_is_external
                && url_count == 1
                && nested_ip_auth_urls.len() == 1
                && credential_context.coverage == SemanticCoverageStatus::Complete
                && nested_message_has_identity_freeze_lure(&credential_context, &text);
            if nested_identity_freeze_compound {
                // Raw-IP and auth-path shape are weak on their own. Promote
                // them only as one bounded nested-message compound with an
                // original recipient identity-verification claim, an
                // account anomaly, and an imminent freeze deadline.
                evidence.push(Evidence {
                    description: format!(
                        "Stage-B nested message `{}` combines an identity-verification request with an imminent account-freeze threat and its explicitly referenced authentication URL",
                        attachment.filename
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: None,
                });
                if !has_suspicious_url {
                    let (_, hits) = nested_ip_auth_urls
                        .iter()
                        .next()
                        .expect("the compound requires exactly one URL");
                    let local_score = hits
                        .iter()
                        .map(|(_, weight)| *weight)
                        .sum::<f64>()
                        .min(0.45);
                    url_score_for_attachment += local_score;
                    has_suspicious_url = true;
                    categories.push("attachment_phishing_url".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Nested message `{}` combines a raw-IP authentication URL with a recipient-directed identity check and an imminent account-freeze threat",
                            attachment.filename
                        ),
                        location: Some(format!("attachment:{}", attachment.filename)),
                        snippet: None,
                    });
                }
                has_credential_lure = true;
                weak_url_observation_count = 0;
                raw_ip_url_observation_count = 0;
            }
            attachment_credential_contexts.push(serde_json::json!({
                "attachment_hash": attachment.hash,
                "coverage": credential_context.coverage,
                "coverage_reason": credential_context.coverage_reason,
                "claims": credential_context.claims,
                "links": credential_context.links,
                "credential_form_targets": extracted.credential_form_urls,
                "projection_limited": extracted.projection_limited,
            }));
            if sender_is_external && has_suspicious_url && has_payment_lure {
                total_score += 0.45;
                categories.push("attachment_payment_lure".to_string());
                categories.push("phishing".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "External attachment combines a suspicious embedded URL with payment and verification wording: {}",
                        attachment.filename
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: None,
                });
            }
            if weak_url_observation_count > 0 {
                let detail = if raw_ip_url_observation_count == weak_url_observation_count {
                    format!("{raw_ip_url_observation_count} literal-IP URL(s)")
                } else {
                    format!(
                        "{weak_url_observation_count} weak URL-shape finding(s), including {raw_ip_url_observation_count} literal-IP URL(s)"
                    )
                };
                categories.push("attachment_url_shape_observation".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Attachment `{}` contains {}; retained as observation only (no credential lure, malicious target, or active container evidence)",
                        attachment.filename, detail
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: None,
                });
            }

            // vCard/contact-card attachments are normally harmless, but a
            // contact card carrying an external onboarding/action URL is a
            // named redirect compound.  Keep both semantic dimensions in
            // JSON so ordinary address-book exports do not score.
            let filename_lower = attachment.filename.to_ascii_lowercase();
            let content_type_lower = attachment.content_type.to_ascii_lowercase();
            let is_contact_card = content_type_lower.contains("vcard")
                || filename_lower.ends_with(".vcf")
                || filename_lower.ends_with(".vcard");
            if is_contact_card {
                let surrounding = format!(
                    "{}\n{}\n{}",
                    ctx.session.subject.as_deref().unwrap_or_default(),
                    ctx.session.content.body_text.as_deref().unwrap_or_default(),
                    text
                );
                let surrounding_normalized = normalize_text(&surrounding.to_lowercase())
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let surrounding_compact: String = surrounding_normalized
                    .chars()
                    .filter(|ch| ch.is_alphanumeric())
                    .collect();
                let contact_hits = module_data()
                    .get_list("contact_card_redirect_terms")
                    .iter()
                    .filter(|term| {
                        let normalized = normalize_text(&term.to_lowercase());
                        surrounding_normalized.contains(&normalized)
                            || surrounding_compact.contains(
                                &normalized
                                    .chars()
                                    .filter(|ch| ch.is_alphanumeric())
                                    .collect::<String>(),
                            )
                    })
                    .count();
                let action_hits = module_data()
                    .get_list("contact_card_action_terms")
                    .iter()
                    .filter(|term| {
                        let normalized = normalize_text(&term.to_lowercase());
                        surrounding_normalized.contains(&normalized)
                            || surrounding_compact.contains(
                                &normalized
                                    .chars()
                                    .filter(|ch| ch.is_alphanumeric())
                                    .collect::<String>(),
                            )
                    })
                    .count();
                let has_untrusted_url = RE_ATTACH_URL.find_iter(&text).any(|matched| {
                    let target = matched.as_str().trim_end_matches(['.', ',', ';', ')', ']']);
                    let Ok(parsed) = url::Url::parse(target) else {
                        return false;
                    };
                    parsed.host_str().is_some_and(|domain| {
                        !crate::modules::link_scan::is_trusted_url_domain(domain)
                            && !crate::modules::link_scan::is_well_known_safe_domain(domain)
                    })
                });
                if contact_hits > 0 && action_hits > 0 && has_untrusted_url {
                    url_score_for_attachment += 0.25;
                    categories.push("attachment_contact_redirect".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Contact-card attachment combines {} contact cues, {} action cues, and an untrusted destination",
                            contact_hits, action_hits
                        ),
                        location: Some(format!("attachment:{} + body", attachment.filename)),
                        snippet: Some(text.chars().take(180).collect()),
                    });
                }
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
            if has_suspicious_url && has_credential_lure {
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
            // Generic business vocabulary from an attachment is observation
            // only unless the same attachment contains a local recipient
            // directive, a suspicious URL, a real credential form, or an
            // explicit payment action. Run keyword scanning after the
            // structural pass so it can use those gates.
            total_score += scan_attachment_text_with_matchers(
                &text,
                &attachment.filename,
                &self.phishing_matcher,
                &self.weak_phishing_matcher,
                &self.bec_matcher,
                AttachmentThreatGate {
                    suspicious_url: has_suspicious_url,
                    credential_form: extracted.credential_form,
                },
                &mut evidence,
                &mut categories,
            );

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

                // A meta refresh to an untrusted authentication path is an
                // actionable embedded phishing URL. Trusted refreshes stay
                // as the existing low-risk structural observation.
                let meta_refresh_actionable = extracted.meta_refresh_urls.iter().any(|url| {
                    let Some(parsed) = url::Url::parse(url).ok() else {
                        return false;
                    };
                    let Some(domain) = parsed.host_str() else {
                        return false;
                    };
                    let untrusted = !ctx.is_internal_domain(domain)
                        && !module_data().contains("protected_domains", domain)
                        && !crate::modules::link_scan::is_trusted_url_domain(domain)
                        && !crate::modules::link_scan::is_well_known_safe_domain(domain);
                    let module_data = module_data();
                    let auth_path_terms = module_data.get_list("credential_auth_path_segments");
                    let shared_auth_path_terms =
                        module_data.get_list("shared_hosted_auth_path_segments");
                    let auth_path = parsed.path_segments().is_some_and(|mut segments| {
                        segments.any(|segment| {
                            auth_path_terms
                                .iter()
                                .any(|term| segment.eq_ignore_ascii_case(term))
                                || (crate::modules::link_scan::is_shared_hosting_platform(domain)
                                    && shared_auth_path_terms
                                        .iter()
                                        .any(|term| segment.eq_ignore_ascii_case(term)))
                        })
                    });
                    sender_is_external
                        && auth_path
                        && (untrusted
                            || crate::modules::link_scan::is_shared_hosting_platform(domain))
                });
                if meta_refresh_actionable {
                    total_score += 0.25;
                    categories.push("attachment_phishing_url".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "HTML attachment {} redirects to an untrusted authentication target",
                            attachment.filename
                        ),
                        location: Some(format!("attachment:{}", attachment.filename)),
                        snippet: extracted.meta_refresh_urls.first().cloned(),
                    });
                }

                // Invitation attachments often redirect to an RSVP/payment
                // page whose path is not auth-themed. Require independent
                // invitation-context and RSVP/action cues before promoting
                // this otherwise low-risk refresh observation.
                let meta_context = format!(
                    "{}\n{}\n{}\n{}",
                    ctx.session.subject.as_deref().unwrap_or_default(),
                    ctx.session.content.body_text.as_deref().unwrap_or_default(),
                    text,
                    extracted.meta_refresh_urls.join(" ")
                );
                let meta_context_hits = attachment_config_term_hits(
                    &meta_context,
                    "attachment_meta_refresh_context_terms",
                );
                let meta_action_hits = attachment_config_term_hits(
                    &meta_context,
                    "attachment_meta_refresh_action_terms",
                );
                let meta_redirect_lure = sender_is_external
                    && !meta_refresh_actionable
                    && meta_context_hits >= 2
                    && meta_action_hits > 0
                    && extracted.meta_refresh_urls.iter().any(|url| {
                        url::Url::parse(url)
                            .ok()
                            .and_then(|parsed| parsed.host_str().map(str::to_string))
                            .is_some_and(|host| {
                                !ctx.is_internal_domain(&host)
                                    && !module_data().contains("protected_domains", &host)
                                    && !crate::modules::link_scan::is_trusted_url_domain(&host)
                                    && !crate::modules::link_scan::is_well_known_safe_domain(&host)
                            })
                    });
                if meta_redirect_lure {
                    total_score += 0.45;
                    categories.push("attachment_redirect_lure".to_string());
                    categories.push("attachment_phishing_url".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "External HTML attachment combines an untrusted meta-refresh target with invitation context ({meta_context_hits}) and RSVP/action wording ({meta_action_hits})"
                        ),
                        location: Some(format!("attachment:{}", attachment.filename)),
                        snippet: extracted.meta_refresh_urls.first().cloned(),
                    });
                }
            }

            // Structured iCalendar checks (urgency lures, base64 ATTACH
            // payloads) that plain text scanning cannot perform.
            if is_ics_attachment(&attachment.filename, &attachment.content_type) {
                total_score +=
                    scan_ics_structure(&text, &attachment.filename, &mut evidence, &mut categories);
            }
        }

        if budget.exhausted {
            // Resource exhaustion is a coverage state, not evidence that the
            // omitted attachment content is malicious.  Keep the category and
            // evidence visible; the verdict layer separately applies the
            // operational MTA quarantine policy when required.
            categories.push("attachment_inspection_limited".to_string());
            evidence.push(Evidence {
                description: "Attachment content inspection reached its per-message resource budget; remaining content requires deferred sandbox scanning"
                    .to_string(),
                location: Some("attachments".to_string()),
                snippet: None,
            });
        }

        if scanned_count == 0 && !budget.exhausted && evidence.is_empty() {
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
        let has_keyword_observations = categories
            .iter()
            .any(|category| category == "attachment_business_keyword_observation");
        let has_url_observations = categories
            .iter()
            .any(|category| category == "attachment_url_shape_observation");
        if threat_level == ThreatLevel::Safe
            && categories.is_empty()
            && !dlp_only
            && !has_keyword_observations
            && !has_url_observations
        {
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
                    "Attachment content analysis found {} informational finding(s) across {} scanned attachment(s); no threat evidence",
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
                "attachment_credential_contexts": attachment_credential_contexts,
                "qualified_attachment_credential_claims": qualified_attachment_credential_claims,
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

    fn ev08_nested_message_ctx() -> SecurityContext {
        let raw = include_bytes!("../../tests/redteam_cases/ev08_nested_rfc822.eml");
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.50".to_string(),
            40000,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("it-support@partner.example".to_string());
        session.rcpt_to.push("employee@corp.internal".to_string());
        session.content = MimeParser::new().parse(raw).expect("frozen fixture parses");
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

    fn credential_context_for_text(text: &str) -> SemanticMessageContext {
        attachment_credential_context(&make_ctx(vec![]).session, text, "synthetic-document", &[])
    }

    fn credential_context_for_extraction(extracted: &ExtractedText) -> SemanticMessageContext {
        attachment_credential_context(
            &make_ctx(vec![]).session,
            &extracted.text,
            "synthetic-document",
            &extracted.semantic_source_ranges,
        )
    }

    fn extracted_rtf(text: &str) -> ExtractedText {
        let rtf = format!("{{\\rtf1\\ansi {text}\\par}}");
        extract_attachment_text_from_bytes(
            "notice.rtf",
            "application/rtf",
            rtf.as_bytes(),
            0,
            &mut AttachmentExtractionBudget::default(),
        )
        .expect("typed RTF projection")
    }

    fn credential_claim_for_url<'a>(
        context: &'a SemanticMessageContext,
        text: &str,
        target: &str,
    ) -> Option<&'a SemanticClaim> {
        let matched = RE_ATTACH_URL
            .find_iter(text)
            .find(|matched| matched.as_str() == target)?;
        attachment_has_credential_lure(
            context,
            target,
            SemanticSpan {
                start_byte: matched.start(),
                end_byte: matched.end(),
            },
        )
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

    #[tokio::test]
    async fn benign_business_docx_with_multiple_ip_service_urls_is_observation_only() {
        let report = "理财业务平台项目发版测试报告：环境入口与接口联调结果\n\
            http://192.0.2.11:9080\n\
            http://192.0.2.12:8081\n\
            http://192.0.2.13:8081/index\n\
            http://192.0.2.14:9528/login";
        let docx =
            build_ooxml_zip(&[("word/document.xml", &build_docx_like_attachment_xml(report))]);
        let attachment = make_attachment(
            "理财业务平台发版测试报告.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            &docx,
        );

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "raw IP service URLs in a business report must not enter threat fusion: {result:?}"
        );
        assert!(
            result
                .categories
                .contains(&"attachment_url_shape_observation".to_string())
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|item| item.description.contains("4 literal-IP URL(s)"))
        );
    }

    #[tokio::test]
    async fn verification_environment_and_user_column_do_not_qualify_ip_urls() {
        let report = format!(
            "单元/集成/性能/安全/压力/验证环境\n{}\n用户 环境地址 联调结果\n\
             http://192.0.2.11:9080\n\
             http://192.0.2.12:8081\n\
             http://192.0.2.13:8081/index\n\
             http://192.0.2.14:9528/login",
            "测试结果记录：接口联调完成，功能测试通过。\n".repeat(80)
        );
        let docx = build_ooxml_zip(&[(
            "word/document.xml",
            &build_docx_like_attachment_xml(&report),
        )]);
        let attachment = make_attachment("发布测试报告.docx", "application/octet-stream", &docx);
        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert_eq!(result.details["score"], 0.0);
        assert!(
            !result
                .categories
                .contains(&"attachment_phishing_url".to_string())
        );
        assert!(
            result
                .categories
                .contains(&"attachment_url_shape_observation".to_string())
        );
        assert!(
            result.details["qualified_attachment_credential_claims"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn attachment_credential_requests_bind_only_their_observed_target() {
        for (text, target) in [
            (
                "请在 http://192.0.2.60/login 输入账户密码。",
                "http://192.0.2.60/login",
            ),
            (
                "Please enter your account password at http://192.0.2.61/login",
                "http://192.0.2.61/login",
            ),
            (
                "请输入短信验证码并立即登录。\nhttp://192.0.2.62/login",
                "http://192.0.2.62/login",
            ),
            (
                "Please enter your password and immediately log in at http://192.0.2.60/login",
                "http://192.0.2.60/login",
            ),
            (
                "Please enter your password for analyst@example.test and log in at http://192.0.2.60/login",
                "http://192.0.2.60/login",
            ),
        ] {
            let context = credential_context_for_text(text);
            let claim = credential_claim_for_url(&context, text, target)
                .unwrap_or_else(|| panic!("recipient request should bind its target: {context:?}"));
            assert_eq!(claim.source_part, SemanticSourcePart::Attachment);
            assert!(
                claim
                    .source_span_id
                    .starts_with("attachment:synthetic-document:")
            );
            assert!(is_current_recipient_action(claim));
        }
    }

    #[test]
    fn attachment_credential_continuation_cannot_cross_sentence_or_line() {
        for text in [
            "Please enter your password. Immediately log in at http://192.0.2.60/login",
            "Please enter your password\nImmediately log in at http://192.0.2.60/login",
            "Please enter your password; immediately log in at http://192.0.2.60/login",
        ] {
            let context = credential_context_for_text(text);
            assert!(
                credential_claim_for_url(&context, text, "http://192.0.2.60/login").is_none(),
                "an unrelated credential instruction must not bind this target: {context:?}"
            );
        }
    }

    #[test]
    fn attachment_same_sentence_credential_compound_revalidates_its_adjacent_target() {
        let target = "http://192.0.2.60/login";
        let text = format!("请输入短信验证码并立即登录。\n{target}");
        let context = credential_context_for_text(&text);
        let claim = credential_claim_for_url(&context, &text, target).unwrap_or_else(|| {
            panic!("the verified compound must retain its own target: {context:?}")
        });
        assert!(is_current_recipient_action(claim));
        assert!(
            claim
                .provenance
                .iter()
                .any(|value| { value == "attachment_credential_same_sentence_continuation_v1" })
        );
        let start = text.find(target).unwrap();
        assert!(
            claim.span.end_byte < start,
            "the target is bound without widening the CTA"
        );
        assert!(!text[claim.span.start_byte..claim.span.end_byte].contains(target));
        let link = context
            .links
            .iter()
            .find(|link| {
                attachment_link_span(&link.link_id)
                    == Some(SemanticSpan {
                        start_byte: start,
                        end_byte: start + target.len(),
                    })
            })
            .unwrap();
        assert!(claim.link_ids.contains(&link.link_id));
        assert_ne!(
            link.source_span_id.as_deref(),
            Some(claim.source_span_id.as_str())
        );
    }

    #[tokio::test]
    async fn quoted_reported_and_anti_action_attachment_urls_remain_observations() {
        for text in [
            "> 请在 http://192.0.2.60/login 输入账户密码。",
            "安全培训案例：攻击者要求在 http://192.0.2.60/login 输入账户密码。",
            "请勿在 http://192.0.2.60/login 输入账户密码。",
            "Incident report: the attacker requests your password at http://192.0.2.60/login",
            "Do not enter your account password at http://192.0.2.60/login",
        ] {
            let attachment = make_attachment("security-review.txt", "text/plain", text.as_bytes());
            let result = AttachContentModule::new()
                .analyze(&make_ctx(vec![attachment]))
                .await
                .unwrap();
            assert_eq!(result.threat_level, ThreatLevel::Safe, "{text}: {result:?}");
            assert!(
                !result
                    .categories
                    .contains(&"attachment_phishing_url".to_string()),
                "{text}"
            );
            assert!(
                result
                    .categories
                    .contains(&"attachment_url_shape_observation".to_string()),
                "{text}"
            );
        }
    }

    #[test]
    fn attachment_mixed_warning_does_not_refute_a_different_target_request() {
        let text = "请勿在 http://192.0.2.60/login 输入账户密码。\n\
                    请在 http://192.0.2.61/login 输入账户密码。";
        let context = credential_context_for_text(text);
        assert!(credential_claim_for_url(&context, text, "http://192.0.2.60/login").is_none());
        assert!(
            credential_claim_for_url(&context, text, "http://192.0.2.61/login").is_some(),
            "{context:?}"
        );
    }

    #[test]
    fn attachment_same_target_counter_context_refutes_only_its_request() {
        let text = "请在 http://192.0.2.60/login 输入账户密码。\n\
                    请勿在 http://192.0.2.60/login 输入账户密码。";
        let context = credential_context_for_text(text);
        assert!(
            credential_claim_for_url(&context, text, "http://192.0.2.60/login").is_none(),
            "{context:?}"
        );
        assert!(
            context
                .claims
                .iter()
                .any(|claim| !claim.counter_context_ids.is_empty())
        );
    }

    #[tokio::test]
    async fn quoted_duplicate_url_does_not_hide_a_later_original_request() {
        let text = "> 请在 http://192.0.2.60/login 输入账户密码。\n\n\
                    请在 http://192.0.2.60/login 输入账户密码。";
        let attachment = make_attachment("account-action.txt", "text/plain", text.as_bytes());
        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();
        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "{result:?}"
        );
        assert_eq!(
            result.details["qualified_attachment_credential_claims"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }

    #[tokio::test]
    async fn credential_request_cannot_borrow_unrelated_document_ip_urls() {
        let text = "请在 https://portal.example.invalid/verify 输入账户密码。\n\n\
                    测试环境地址：\nhttp://192.0.2.60:8081/index\nhttp://192.0.2.61:9080/login";
        let context = credential_context_for_text(text);
        assert!(credential_claim_for_url(&context, text, "http://192.0.2.60:8081/index").is_none());
        assert!(credential_claim_for_url(&context, text, "http://192.0.2.61:9080/login").is_none());
        let attachment = make_attachment("环境说明.txt", "text/plain", text.as_bytes());
        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();
        assert!(
            result
                .evidence
                .iter()
                .filter_map(|item| item.snippet.as_deref())
                .all(|url| { !url.starts_with("http://192.0.2.") }),
            "{result:?}"
        );
        assert!(
            result
                .categories
                .contains(&"attachment_url_shape_observation".to_string())
        );
    }

    #[test]
    fn limited_html_projection_propagates_attachment_policy_coverage() {
        let html = format!(
            "<p>Ordinary attachment report.</p><!--{}-->",
            "x".repeat(512 * 1024)
        );
        let extracted = extract_html_attachment_text(&html).expect("visible prefix is retained");
        assert!(extracted.projection_limited);
        let nested = format!(
            "From: vendor@example.invalid\r\nSubject: report\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n"
        );
        let zip = build_ooxml_zip(&[("report.html", &html)]);
        for attachment in [
            make_attachment("report.html", "text/html", html.as_bytes()),
            make_attachment("report.eml", "message/rfc822", nested.as_bytes()),
            make_attachment("report.zip", "application/zip", &zip),
        ] {
            let policy = extract_attachment_text_for_policy(&[attachment]);
            assert!(
                !policy.complete,
                "HTML projection limits must survive top-level, nested-message and archive extraction: {policy:?}"
            );
            assert!(
                policy.scanned_count > 0,
                "the available visible prefix is retained"
            );
        }
    }

    #[test]
    fn attachment_deictic_identity_request_keeps_claim_and_target_spans_separate() {
        let target = "http://192.0.2.60/verify/login";
        for html in [
            format!(
                "<p>尊敬的用户：系统检测到您的账户存在异常登录，为保障您的资金安全，请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p><a href='{target}'>{target}</a></p><p>客服电话 400-123-4567</p>"
            ),
            format!(
                "<p>Please click the link below to verify your account.</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<p>Please click the link below to verify your identity.</p><p><a href='{target}'>{target}</a></p>"
            ),
        ] {
            let extracted = extract_html_attachment_text(&html).expect("visible HTML projection");
            let context = credential_context_for_text(&extracted.text);
            let claim =
                credential_claim_for_url(&context, &extracted.text, target).unwrap_or_else(|| {
                    panic!(
                        "the explicit following target must bind: {context:?}, text={:?}",
                        extracted.text
                    )
                });
            assert!(is_current_recipient_action(claim));
            assert!(
                claim
                    .provenance
                    .iter()
                    .any(|value| value == "attachment_credential_deictic_target_v1")
            );
            let target_start = extracted.text.find(target).expect("observed target");
            assert!(
                claim.span.end_byte < target_start,
                "the CTA must retain its original span: {claim:?}"
            );
            assert!(!extracted.text[claim.span.start_byte..claim.span.end_byte].contains(target));
            let target_span = SemanticSpan {
                start_byte: target_start,
                end_byte: target_start + target.len(),
            };
            let observation = context
                .links
                .iter()
                .find(|link| attachment_link_span(&link.link_id) == Some(target_span))
                .expect("physical target observation");
            assert!(claim.link_ids.contains(&observation.link_id));
            assert_ne!(
                observation.source_span_id.as_deref(),
                Some(claim.source_span_id.as_str())
            );
        }
    }

    #[test]
    fn attachment_deictic_quotes_reports_and_anti_actions_do_not_bind() {
        let target = "http://192.0.2.60/verify/login";
        for html in [
            format!(
                "<blockquote><p>请立即点击下方链接验证身份。</p><p><a href='{target}'>{target}</a></p></blockquote>"
            ),
            format!(
                "<p>安全培训案例：请立即点击下方链接验证身份。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<p>攻击者要求立即点击下方链接验证身份。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!("<p>请勿点击下方链接验证身份。</p><p><a href='{target}'>{target}</a></p>"),
            format!(
                "<p>请立即点击下方链接验证身份。</p><blockquote><p><a href='{target}'>{target}</a></p></blockquote>"
            ),
            format!(
                "<p>请立即点击下方链接验证身份。</p><a style='display:none' href='{target}'>{target}</a>"
            ),
        ] {
            let extracted =
                extract_html_attachment_text(&html).expect("HTML projection is retained");
            let context = credential_context_for_text(&extracted.text);
            assert!(
                credential_claim_for_url(&context, &extracted.text, target).is_none(),
                "a quote/report/warning/hidden href cannot supply the target: html={html:?}, {context:?}, text={:?}",
                extracted.text,
            );
        }
    }

    #[test]
    fn attachment_deictic_request_does_not_borrow_an_unrelated_target() {
        let target = "http://192.0.2.60/verify/login";
        for text in [
            format!("请立即点击下方链接验证身份。\n普通测试报告记录服务地址：\n{target}"),
            format!("请立即点击下方链接验证身份。普通测试报告记录服务地址。\n{target}"),
            format!("请立即点击下方链接验证身份。\n请阅读附件文档。\n{target}"),
            format!("请立即点击下方链接验证身份。\n{target} http://192.0.2.61/verify/login"),
            format!("请立即点击下方链接验证身份。\nattachment_html_attribute_url: {target}"),
            format!(
                "请立即点击下方链接验证身份。{}\n{target}",
                "普通环境记录。".repeat(80)
            ),
            format!(
                "请立即在 https://portal.example.invalid/login 点击下方链接验证身份。\n{target}"
            ),
            format!(
                "请立即点击下方链接验证身份，安全培训案例：24小时内未验证将冻结账户。\n{target}"
            ),
        ] {
            let context = credential_context_for_text(&text);
            assert!(
                credential_claim_for_url(&context, &text, target).is_none(),
                "an unrelated or ambiguous target must remain an observation: {context:?}, text={text:?}"
            );
        }
    }

    #[test]
    fn attachment_adjacent_target_cannot_cross_a_local_scope_boundary() {
        let target = "http://192.0.2.60/verify/login";
        for text in [
            format!(
                "请立即点击下方链接验证身份，安全培训案例：24小时内未验证将冻结账户。\n{target}"
            ),
            format!(
                "请立即点击下方链接验证身份，邮件原文写道：24小时内未验证将冻结账户。\n{target}"
            ),
            format!(
                "Please click the link below to verify your account, incident report: your mailbox will be disabled in 24 hours.\n{target}"
            ),
            format!("请立即点击下方链接验证身份，切勿点击下方链接。\n{target}"),
            format!("请立即点击下方链接验证身份。\n> {target}"),
        ] {
            let context = credential_context_for_text(&text);
            assert!(
                context.links.iter().any(|link| link.original_url == target),
                "the actual URL observation is retained: {context:?}"
            );
            assert!(
                credential_claim_for_url(&context, &text, target).is_none(),
                "neither a continuation nor direct-span fallback may borrow the target: {context:?}"
            );
        }
    }

    #[test]
    fn attachment_adjacent_target_preserves_a_fresh_request_and_real_consequence() {
        let target = "http://192.0.2.60/verify/login";
        for text in [
            format!("安全培训案例：请勿泄露验证码。\n\n请立即点击下方链接验证身份。\n{target}"),
            format!("请立即点击下方链接验证身份，24小时内未验证将冻结账户。\n{target}"),
            format!("请登录安全培训平台并点击下方链接验证身份。\n{target}"),
            format!(
                "This is a training schedule.\n\nPlease click the link below to verify your account.\n{target}"
            ),
        ] {
            let context = credential_context_for_text(&text);
            let claim = credential_claim_for_url(&context, &text, target).unwrap_or_else(|| {
                panic!("the fresh adjacent target must bind: {context:?}, text={text:?}")
            });
            assert!(is_current_recipient_action(claim));
            assert!(claim.span.end_byte < text.rfind(target).unwrap());
            assert!(
                claim
                    .provenance
                    .iter()
                    .any(|value| { value == "attachment_credential_deictic_target_v1" })
            );
        }
    }

    #[test]
    fn attachment_deictic_counter_context_uses_the_actual_same_target() {
        for (counter_target, expected) in [
            ("http://192.0.2.59/verify/login", true),
            ("http://192.0.2.60/verify/login", false),
        ] {
            let target = "http://192.0.2.60/verify/login";
            let text = format!(
                "请勿在 {counter_target} 点击链接验证身份。\n请立即点击下方链接验证身份。\n{target}"
            );
            let context = credential_context_for_text(&text);
            let observed_start = text.rfind(target).expect("deictic URL occurrence");
            let bound = attachment_has_credential_lure(
                &context,
                target,
                SemanticSpan {
                    start_byte: observed_start,
                    end_byte: observed_start + target.len(),
                },
            );
            assert_eq!(
                bound.is_some(),
                expected,
                "counter-context must refer to this actual target: {context:?}"
            );
            let deictic = context
                .claims
                .iter()
                .find(|claim| {
                    claim
                        .provenance
                        .iter()
                        .any(|value| value == "attachment_credential_deictic_target_v1")
                })
                .expect("the physical relation is retained even when countered");
            assert!(
                deictic.span.end_byte < observed_start,
                "counter qualification must retain the original CTA span: {deictic:?}"
            );
            let observation = context
                .links
                .iter()
                .find(|link| {
                    attachment_link_span(&link.link_id)
                        == Some(SemanticSpan {
                            start_byte: observed_start,
                            end_byte: observed_start + target.len(),
                        })
                })
                .expect("the following target keeps its physical observation");
            assert!(deictic.link_ids.contains(&observation.link_id));
            assert_ne!(
                observation.source_span_id.as_deref(),
                Some(deictic.source_span_id.as_str())
            );
            let mut action = deictic.clone();
            action.counter_context_ids.clear();
            assert!(
                is_current_recipient_action(&action),
                "counter qualification must retain the original recipient action: {deictic:?}"
            );
            assert_eq!(
                deictic.counter_context_ids.is_empty(),
                expected,
                "same-target refutation must survive binding: {deictic:?}"
            );
        }
    }

    #[test]
    fn rendered_authentication_request_binds_only_its_adjacent_physical_target() {
        let target = "http://203.0.113.60/verify/login";
        let html = format!(
            "<html><head><style>.x{{display:none}}</style></head><body><p>尊敬的用户：您的账<span class=x>kq</span>户存在异<span class=x>tb</span>常，请立<span class=x>uj</span>即登<span class=x>vm</span>录验<span class=x>yn</span>证身份。</p><p><a href='{target}'>{target}</a></p></body></html>"
        );
        let extracted = extract_html_attachment_text(&html).expect("rendered HTML projection");
        let context = credential_context_for_extraction(&extracted);
        let claim =
            credential_claim_for_url(&context, &extracted.text, target).unwrap_or_else(|| {
                panic!("rendered authentication target must bind: {context:?}, {extracted:?}")
            });
        assert!(is_current_recipient_action(claim));
        assert!(
            claim
                .provenance
                .iter()
                .any(|value| value == "attachment_credential_rendered_target_v1")
        );
        assert!(!extracted.text[claim.span.start_byte..claim.span.end_byte].contains(target));
        let observed = context
            .links
            .iter()
            .find(|link| claim.link_ids.contains(&link.link_id))
            .expect("physical target");
        assert_ne!(
            observed.source_span_id.as_deref(),
            Some(claim.source_span_id.as_str())
        );

        for html in [
            format!(
                "<p>普通测试报告：用户账户验证环境。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<blockquote><p>请立即登录验证身份。</p><p><a href='{target}'>{target}</a></p></blockquote>"
            ),
            format!("<p>攻击者要求立即登录验证身份。</p><p><a href='{target}'>{target}</a></p>"),
            format!("<p>请勿登录验证身份。</p><p><a href='{target}'>{target}</a></p>"),
            format!(
                "<p>请立即登录验证身份。</p><p>测试环境地址：</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<p>请立即登录验证身份。</p><p>请阅读附件文档。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<p>请立即登录验证身份。</p><p><a href='{target}'>{target}</a> http://203.0.113.61/verify/login</p>"
            ),
            format!(
                "<p>请立即在 https://portal.example.invalid/login 登录验证身份。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!("<p>请立即登录验证身份。</p><a hidden href='{target}'>{target}</a>"),
        ] {
            let extracted = extract_html_attachment_text(&html).expect("HTML projection");
            let context = credential_context_for_extraction(&extracted);
            assert!(
                credential_claim_for_url(&context, &extracted.text, target).is_none(),
                "unrelated, hidden, quoted and countered targets remain observations: {context:?}, {extracted:?}"
            );
        }
        let text = format!("请立即登录验证身份。\n{target} {target}");
        assert!(
            credential_claim_for_url(&credential_context_for_text(&text), &text, target).is_none(),
            "untyped document text cannot borrow rendered source authority"
        );
    }

    #[test]
    fn rendered_target_continuation_requires_an_explicit_request_and_unique_local_target() {
        let target = "http://203.0.113.60/verify/login";
        let html = format!(
            "<p>请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p><a href='{target}'>{target}</a></p>"
        );
        let extracted = extract_html_attachment_text(&html).expect("rendered projection");
        let context = credential_context_for_extraction(&extracted);
        let claim =
            credential_claim_for_url(&context, &extracted.text, target).unwrap_or_else(|| {
                panic!("the explicit CTA must survive its inherited consequence: {context:?}")
            });
        assert!(extracted.text[claim.span.start_byte..claim.span.end_byte].contains("下方链接"));
        assert!(!extracted.text[claim.span.start_byte..claim.span.end_byte].contains("冻结账户"));
        assert_eq!(
            context
                .claims
                .iter()
                .filter(|claim| claim
                    .provenance
                    .iter()
                    .any(|value| value == "attachment_credential_deictic_target_v1"))
                .count(),
            1
        );

        for html in [
            format!(
                "<p>请立即登录验证身份。</p><p><a href='{target}'>{target}</a> http://203.0.113.61/verify/login</p>"
            ),
            format!(
                "<p>请立即点击下方链接验证身份。</p><p><a href='{target}'>{target}</a> http://203.0.113.61/verify/login</p>"
            ),
        ] {
            let extracted = extract_html_attachment_text(&html).expect("mixed target projection");
            let context = credential_context_for_extraction(&extracted);
            assert!(
                credential_claim_for_url(&context, &extracted.text, target).is_none(),
                "an anchor-generated line break cannot hide the competing rendered target: {context:?}, {extracted:?}"
            );
        }
        let html = format!(
            "<p>请立即登录验证身份。</p><p><a href='{target}'>{target}</a></p><p>请勿在 http://203.0.113.61/verify/login 登录验证身份。</p>"
        );
        let extracted = extract_html_attachment_text(&html).expect("mixed warning projection");
        let context = credential_context_for_extraction(&extracted);
        assert!(
            credential_claim_for_url(&context, &extracted.text, target).is_some(),
            "a separate different-target warning cannot refute the current target: {context:?}"
        );
    }

    #[test]
    fn typed_credential_continuations_preserve_same_target_counter_context() {
        let target = "http://203.0.113.60/verify/login";
        for (counter_target, expected) in
            [("http://203.0.113.59/verify/login", true), (target, false)]
        {
            let html = format!(
                "<p>请勿在 {counter_target} 登录验证身份。</p><p>请立即登录验证身份。</p><p><a href='{target}'>{target}</a></p>"
            );
            let rtf = format!(
                "Do not verify your account at {counter_target}. Verify your account immediately, your mailbox will be disabled in 24 hours. Click: {target}"
            );
            for extracted in [
                extract_html_attachment_text(&html).expect("HTML projection"),
                extracted_rtf(&rtf),
            ] {
                let context = credential_context_for_extraction(&extracted);
                let observed_start = extracted.text.rfind(target).expect("following target");
                let span = SemanticSpan {
                    start_byte: observed_start,
                    end_byte: observed_start + target.len(),
                };
                assert_eq!(
                    attachment_has_credential_lure(&context, target, span).is_some(),
                    expected,
                    "only a same-action/object/actual-target counter may refute the CTA: {context:?}, {extracted:?}"
                );
                let claim = context
                    .claims
                    .iter()
                    .find(|claim| {
                        claim.provenance.iter().any(|value| {
                            value
                                == &format!(
                                    "attachment_credential_target_span:{}:{}",
                                    span.start_byte, span.end_byte
                                )
                        })
                    })
                    .expect("physical relation remains auditable even when countered");
                assert_eq!(claim.counter_context_ids.is_empty(), expected);
                assert!(claim.span.end_byte < span.start_byte);
            }
        }
    }

    #[test]
    fn rtf_disable_pointer_requires_the_original_recipient_request_and_target() {
        let target = "http://203.0.113.60/verify";
        let text = format!(
            "English notice: verify your account immediately, your mailbox will be disabled in 24 hours. Click: {target}"
        );
        let extracted = extracted_rtf(&text);
        let context = credential_context_for_extraction(&extracted);
        let claim = credential_claim_for_url(&context, &extracted.text, target)
            .unwrap_or_else(|| panic!("typed RTF request must bind: {context:?}, {extracted:?}"));
        assert!(is_current_recipient_action(claim));
        assert!(
            claim
                .provenance
                .iter()
                .any(|value| value == "attachment_credential_typed_freeze_pointer_v1")
        );
        assert!(!extracted.text[claim.span.start_byte..claim.span.end_byte].contains(target));
        assert!(!extracted.text.contains("\\par"));
        for text in [
            format!(
                "Security training example: verify your account immediately, your mailbox will be disabled in 24 hours. Click: {target}"
            ),
            format!(
                "Do not verify your account immediately, your mailbox will be disabled in 24 hours. Click: {target}"
            ),
            format!(
                "Users need to verify their account immediately, your mailbox will be disabled in 24 hours. Click: {target}"
            ),
            format!(
                "Verify your account immediately, my mailbox will be disabled in 24 hours. Click: {target}"
            ),
            format!(
                "Verify your account immediately, your mailbox will be disabled in 24 hours. Ordinary test report records. Click: {target}"
            ),
            format!(
                "Verify your account immediately, your mailbox will be disabled in 24 hours. Please read the document. Click: {target}"
            ),
            format!(
                "Verify your account immediately at https://portal.example.invalid/login, your mailbox will be disabled in 24 hours. Click: {target}"
            ),
            format!(
                "Verify your account immediately, your mailbox will be disabled in 24 hours. Test service: {target}"
            ),
            format!("Verify your account immediately. Click: {target}"),
            format!(
                "Verify your account immediately, your mailbox will be disabled in 24 hours. Click: {target} http://203.0.113.61/verify"
            ),
        ] {
            let extracted = extracted_rtf(&text);
            let context = credential_context_for_extraction(&extracted);
            assert!(
                credential_claim_for_url(&context, &extracted.text, target).is_none(),
                "a missing/mixed request, consequence or target cannot join: {context:?}, {extracted:?}"
            );
        }
        let context = credential_context_for_text(&text);
        assert!(
            credential_claim_for_url(&context, &text, target).is_none(),
            "the continuation cannot be synthesized from untyped document text"
        );
    }

    #[tokio::test]
    async fn frozen_html_and_rtf_credential_paths_keep_native_detection() {
        for fixture in [
            include_bytes!("../../tests/redteam_cases/ev36_attach_hidden_pair.eml").as_slice(),
            include_bytes!("../../tests/redteam_cases/ev79_rtf_attach_lure.eml").as_slice(),
        ] {
            let mut session = make_ctx(vec![]).session.as_ref().clone();
            session.content = MimeParser::new()
                .parse(fixture)
                .expect("frozen fixture parses");
            let result = AttachContentModule::new()
                .analyze(&SecurityContext::new(Arc::new(session)))
                .await
                .unwrap();
            assert!(
                result
                    .categories
                    .contains(&"attachment_phishing_url".to_string()),
                "{result:?}"
            );
            assert!(
                !result.details["qualified_attachment_credential_claims"]
                    .as_array()
                    .expect("qualified claims")
                    .is_empty(),
                "coverage isolation alone does not preserve the original credential path: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn nested_deictic_report_and_quoted_targets_remain_observations() {
        let target = "http://192.0.2.60/verify/login";
        for body in [
            format!(
                "<blockquote><p>您的账户存在异常登录，请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p><a href='{target}'>{target}</a></p></blockquote>"
            ),
            format!(
                "<p>您的账户存在异常登录，请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p>普通报告记录环境服务地址。</p><p><a href='{target}'>{target}</a></p>"
            ),
            format!(
                "<p>您的账户存在异常登录，请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><blockquote><p><a href='{target}'>{target}</a></p></blockquote>"
            ),
        ] {
            let nested = format!(
                "From: vendor@example.invalid\r\nSubject: notice\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}\r\n"
            );
            let attachment = make_attachment("notice.eml", "message/rfc822", nested.as_bytes());
            let result = make_module_with_keywords(&[], &[])
                .analyze(&make_ctx(vec![attachment]))
                .await
                .unwrap();
            assert_eq!(
                result.threat_level,
                ThreatLevel::Safe,
                "an unrelated target must not reopen the nested compound: {result:?}"
            );
            assert!(
                !result
                    .categories
                    .contains(&"nested_message_phishing".to_string()),
                "{result:?}"
            );
            assert!(
                !result
                    .categories
                    .contains(&"attachment_phishing_url".to_string()),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn raw_ip_attachment_with_local_credential_lure_remains_actionable() {
        let content = "系统检测到账户异常，请输入短信验证码并立即登录。\n\
            http://192.0.2.60/login";
        let attachment = make_attachment("安全验证通知.txt", "text/plain", content.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_phishing_url".to_string()),
            "a raw IP URL bound to a local credential lure must remain actionable: {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Low);
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
    fn attachment_url_words_do_not_self_qualify_as_a_credential_lure() {
        let bare_url = "http://192.0.2.60/verify/login";
        let context = credential_context_for_text(bare_url);
        assert!(credential_claim_for_url(&context, bare_url, bare_url).is_none());
        let request = "请输入短信验证码并立即登录。\nhttp://192.0.2.60/verify/login";
        let context = credential_context_for_text(request);
        assert!(credential_claim_for_url(&context, request, bare_url).is_some());
    }

    #[test]
    fn signed_report_url_length_is_only_corroborating_evidence() {
        let benign = format!(
            "https://reports.vendor.invalid/risk-monitor/report?signature={}",
            "a".repeat(240)
        );
        assert!(
            classify_attachment_url(&benign).is_empty(),
            "URL length alone must not become attachment phishing evidence"
        );

        let malicious = format!("http://192.0.2.44/login?token={}", "a".repeat(240));
        let findings = classify_attachment_url(&malicious);
        assert!(
            findings
                .iter()
                .any(|(reason, _)| *reason == "uses raw IP address as host")
        );
        assert!(
            findings
                .iter()
                .any(|(reason, _)| *reason == "excessively long URL (>200 chars)")
        );
    }

    #[tokio::test]
    async fn repeated_same_host_ip_links_do_not_simulate_independent_phishing_iocs() {
        let content = (0..10)
            .map(|index| format!("https://192.0.2.44/Synthetic.App/Company?id={index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let attachment = make_attachment("券商交流资料.txt", "text/plain", content.as_bytes());

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.description.contains("10 literal-IP URL(s)"))
                .count(),
            1,
            "repeated raw-IP observations should be summarized once without threat score"
        );
        assert!(
            result
                .categories
                .contains(&"attachment_url_shape_observation".to_string())
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
            AttachmentThreatGate::default(),
            &mut evidence,
            &mut categories,
        );

        assert_eq!(score, 0.0);
        assert!(!categories.iter().any(|category| category == "bec"));
    }

    #[test]
    fn keyword_matcher_preserves_contains_semantics() {
        let patterns = vec![
            "account".to_string(),
            "count".to_string(),
            "account".to_string(),
            String::new(),
            "不存在".to_string(),
        ];
        let haystack = "account verification";
        let expected: Vec<String> = patterns
            .iter()
            .filter(|pattern| haystack.contains(pattern.as_str()))
            .cloned()
            .collect();
        let actual: Vec<String> = KeywordMatcher::new(&patterns)
            .find(haystack)
            .into_iter()
            .cloned()
            .collect();

        assert_eq!(actual, expected);
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
            AttachmentThreatGate::default(),
            &mut evidence,
            &mut categories,
        );

        assert!(score > 0.0);
        assert!(categories.iter().any(|category| category == "bec"));
    }

    #[test]
    fn privacy_policy_vocabulary_does_not_form_cross_paragraph_phishing_or_bec() {
        let mut evidence = vec![];
        let mut categories = vec![];
        let score = scan_attachment_text(
            "账号异常处理规则用于说明风控流程。\n短信验证码是基本功能处理的数据类型。\n\
             请注意阅读隐私政策。\n下载文件功能可能需要网络权限。\n\
             紧急情况章节说明用户如何联系客服。",
            "示例隐私政策.docx",
            &["账号异常".to_string(), "短信验证码".to_string()],
            &[
                "请注意".to_string(),
                "下载文件".to_string(),
                "通知".to_string(),
                "您的账户".to_string(),
            ],
            &["紧急情况".to_string()],
            AttachmentThreatGate::default(),
            &mut evidence,
            &mut categories,
        );

        assert_eq!(score, 0.0, "{evidence:?}");
        assert_eq!(
            categories,
            vec!["attachment_business_keyword_observation".to_string()]
        );
    }

    #[test]
    fn distant_payment_policy_clause_does_not_promote_whole_attachment() {
        let mut evidence = vec![];
        let mut categories = vec![];
        let score = scan_attachment_text(
            "组合贷款按合同采用受托支付至监管账户。\n\
             第一章说明贷款受理范围。第二章说明贷前调查职责。\n\
             第三章说明合同变更程序。第四章说明档案保管要求。\n\
             借款人已按规定建立住房公积金账户。客户本人可到营业机构重置密码。\n\
             个人鉴别信息包括动态口令。贷后管理包括受理特殊交易申请。\n\
             动态口令与账号结合可直接完成用户鉴别。",
            "月度业务考试资料.doc",
            &[
                "公积金账户".to_string(),
                "动态口令".to_string(),
                "重置密码".to_string(),
            ],
            &[],
            &["特殊交易".to_string(), "直接完成".to_string()],
            AttachmentThreatGate::default(),
            &mut evidence,
            &mut categories,
        );

        assert_eq!(score, 0.0, "{evidence:?}");
        assert!(
            !categories.iter().any(|category| category == "phishing"),
            "a distant regulatory payment clause must not qualify credential vocabulary: {evidence:?}"
        );
        assert!(
            !categories.iter().any(|category| category == "bec"),
            "a distant regulatory payment clause must not qualify business vocabulary: {evidence:?}"
        );
        assert!(
            categories
                .iter()
                .any(|category| category == "attachment_business_keyword_observation")
        );
    }

    #[test]
    fn attachment_credential_directive_stays_actionable() {
        let mut evidence = vec![];
        let mut categories = vec![];
        let score = scan_attachment_text(
            "系统检测到账号异常。请输入短信验证码并立即登录。",
            "示例安全通知.docx",
            &["账号异常".to_string(), "短信验证码".to_string()],
            &[],
            &[],
            AttachmentThreatGate::default(),
            &mut evidence,
            &mut categories,
        );

        assert!(score > 0.0, "{evidence:?}");
        assert!(categories.iter().any(|category| category == "phishing"));
    }

    #[tokio::test]
    async fn business_workbook_terms_and_id_numbers_do_not_create_threat() {
        let text = "身份核验 发票 账单 转账 通知 合同问题 000000194912310027";
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
        let html = "Visible text &lt;form action=\"http://203.0.113.50/harvest\"&gt;".to_string()
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
            "nested phishing combination should be surfaced: {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium);
    }

    #[tokio::test]
    async fn nested_rfc822_identity_freeze_lure_with_separate_ip_auth_url_is_medium() {
        let result = AttachContentModule::new_with_nested_message_identity_freeze(
            EffectiveKeywordLists::default(),
            true,
        )
        .analyze(&ev08_nested_message_ctx())
        .await
        .unwrap();

        assert!(
            result.evidence.iter().any(|item| {
                item.description
                    .contains("Stage-B nested message `notice.eml`")
            }),
            "the nested high-consequence compound should be surfaced: {result:?}"
        );
        assert!(
            result.threat_level >= ThreatLevel::Medium,
            "the frozen red-team fixture must not remain Low: {result:?}"
        );
    }

    #[tokio::test]
    async fn nested_rfc822_identity_freeze_compound_is_feature_gated() {
        let result = AttachContentModule::new_with_nested_message_identity_freeze(
            EffectiveKeywordLists::default(),
            false,
        )
        .analyze(&ev08_nested_message_ctx())
        .await
        .unwrap();

        assert!(
            !result.evidence.iter().any(|item| {
                item.description
                    .contains("Stage-B nested message `notice.eml`")
            }),
            "the Stage-B compound evidence must stay disabled unless its explicit feature flag is on: {result:?}"
        );
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
        assert_eq!(result.threat_level, ThreatLevel::Safe);
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
        assert_eq!(result.threat_level, ThreatLevel::Safe);
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

    #[tokio::test]
    async fn test_generic_octet_stream_media_does_not_create_text_coverage_alert() {
        let attachment = make_attachment(
            "50E1BA6B-2232-40EE-A0EF-7342E15DC8C6.MOV",
            "application/octet-stream",
            &[0, 1, 2, 3, 4, 5, 6, 7],
        );

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert_eq!(
            result.summary,
            "No attachments with extractable text content"
        );
        assert!(
            !result
                .categories
                .contains(&"attachment_inspection_limited".to_string()),
            "opaque media must be handled by binary scanners, not text-coverage alerts: {result:?}"
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

#[cfg(test)]
#[path = "attach_content_budget_regressions.rs"]
mod security_budget_regressions;

#[cfg(test)]
#[path = "attach_content_deadline_regressions.rs"]
mod security_deadline_regressions;
