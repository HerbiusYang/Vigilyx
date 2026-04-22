//! HTML scan module - Detect malicious tags and dangerous attributes in HTML body

use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

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

/// Extract the URL target from a `<meta http-equiv="refresh" content="N;URL=...">`
/// tag. Returns None if the tag is malformed.
static META_REFRESH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"'>]+)["']"#,
    )
    .expect("valid meta refresh regex")
});

/// Match `<a ... href="javascript:...">` / `<form action="javascript:...">` —
/// we want a dedicated signal beyond the generic "javascript:" substring.
static JS_HREF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|action|src|formaction)\s*=\s*["']?\s*javascript:"#)
        .expect("valid js href regex")
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
                description: "Scan HTML body for malicious tags, script injection, and dangerous attributes"
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
        pattern: "<iframe",
        severity: 0.25,
        label: "Embedded frame <iframe>",
        category: "xss",
    },
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
        pattern: "onerror=",
        severity: 0.25,
        label: "Event handler onerror",
        category: "xss",
    },
    HtmlPattern {
        pattern: "onload=",
        severity: 0.20,
        label: "Event handler onload",
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
    HtmlPattern {
        pattern: "<meta http-equiv=\"refresh\"",
        severity: 0.20,
        label: "Meta auto-refresh/redirect",
        category: "redirect",
    },
];

/// Analyze <script> tags in HTML: extract content and check for dangerous operations
fn analyze_scripts(html_lower: &str, html_original: &str) -> (f64, Vec<Evidence>) {
    let mut score = 0.0f64;
    let mut evidence = Vec::new();
    let mut search_from = 0;
    let dangerous_script_ops = module_data().get_list("dangerous_script_ops").to_vec();

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

        if !dangerous_hits.is_empty() {
           // Contains dangerous operations -> high severity
            score += 0.30;
            let ops: Vec<String> = dangerous_hits.iter().map(|s| s.to_string()).collect();
            let snip_start = abs_open.saturating_sub(10);
            let snip_end = (tag_end + 50).min(html_original.len());
            evidence.push(Evidence {
                description: format!("Inline script contains dangerous operations: {}", ops.join(", ")),
                location: Some("body_html".to_string()),
                snippet: Some(html_original[snip_start..snip_end].to_string()),
            });
        }
       // Scripts without dangerous operations are benign (e.g., var tracking = ...)

        search_from = close_idx + 9; // skip past </script>
    }

    (score, evidence)
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

/// Extract the URL target from any `<meta http-equiv="refresh">` tags.
/// The `content` attribute has format `<seconds>;URL=<target>` (case-insensitive,
/// flexible whitespace). Returns all extracted target URLs.
fn extract_meta_refresh_urls(html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for cap in META_REFRESH_RE.captures_iter(html) {
        let content = cap.get(1).map(|m| m.as_str()).unwrap_or("");
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
                let prev_is_boundary = i == 0
                    || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b',');
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
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

       // Check each dangerous pattern (excluding <script> which is handled separately)
        for pat in HTML_PATTERNS {
            let pat_lower = pat.pattern.to_lowercase();
            let count = html_lower.matches(&pat_lower).count();
            if count > 0 {
                total_score += pat.severity * count as f64;
                categories.push(pat.category.to_string());

                let snippet = if let Some(idx) = html_lower.find(&pat_lower) {
                    let snip_start = idx.saturating_sub(20);
                    let snip_end = (idx + pat_lower.len() + 40).min(body_html.len());
                    Some(body_html[snip_start..snip_end].to_string())
                } else {
                    None
                };

                evidence.push(Evidence {
                    description: format!("{} (found {} occurrence(s))", pat.label, count),
                    location: Some("body_html".to_string()),
                    snippet,
                });
            }
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

       // Check base64 data URIs
        let b64_findings = check_base64_data_uris(&html_lower);
        if !b64_findings.is_empty() {
            total_score += 0.2 * b64_findings.len() as f64;
            categories.push("data_uri".to_string());
            for (desc, pos) in &b64_findings {
                let snip_start = pos.saturating_sub(10);
                let snip_end = (*pos + 60).min(body_html.len());
                evidence.push(Evidence {
                    description: format!("Base64 data URI: {}", desc),
                    location: Some("body_html".to_string()),
                    snippet: Some(body_html[snip_start..snip_end].to_string()),
                });
            }
        }

       // CSS hidden text detection: display:none / visibility:hidden / font-size:0
       // Used to hide malicious content from users while evading NLP analysis and email client rendering
        {
            let css_hidden_patterns = module_data().get_list("css_hidden_content_patterns").to_vec();

            let hidden_count = css_hidden_patterns
                .iter()
                .filter(|p| html_lower.contains(p.as_str()))
                .count();

            if hidden_count > 0 {
               // Check whether hidden elements contain sensitive content (heuristic: count hidden elements)
                let display_none_count = html_lower.matches("display:none").count()
                    + html_lower.matches("display: none").count();
                let visibility_hidden_count = html_lower.matches("visibility:hidden").count()
                    + html_lower.matches("visibility: hidden").count();
                let total_hidden = display_none_count + visibility_hidden_count;

                if total_hidden >= 3 {
                   // Many hidden elements - highly suspicious
                    total_score += 0.30;
                    categories.push("css_hidden_content".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Found {} CSS hidden content instances (display:none/visibility:hidden) — possibly used to evade analysis or hide malicious payloads",
                            total_hidden
                        ),
                        location: Some("body_html:style".to_string()),
                        snippet: None,
                    });
                } else if total_hidden >= 1 {
                   // Few hidden elements - possibly normal responsive design, low severity
                    total_score += 0.10;
                    categories.push("css_hidden_content".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Found {} CSS hidden content instance(s) (possibly responsive design or hidden malicious content)",
                            total_hidden
                        ),
                        location: Some("body_html:style".to_string()),
                        snippet: None,
                    });
                }
            }
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
        let (bidi_total, bidi_distinct) = count_bidi_control_chars(body_html);
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
        let zw_count = count_zero_width_chars(body_html);
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

        // --- Meta refresh redirect URL analysis ---
        // <meta http-equiv="refresh" content="0;URL=..."> is used by phishing
        // landing pages to redirect instantly after page load. Beyond the flat
        // +0.20 charged by the static pattern match above, we also delegate the
        // *target* URL to the full link analyser so that a redirect to a known
        // phishing-style URL is properly scored.
        let meta_refresh_urls = extract_meta_refresh_urls(body_html);
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
        let js_href_hits: Vec<_> = JS_HREF_RE.find_iter(body_html).collect();
        if !js_href_hits.is_empty() {
            total_score += 0.15 * js_href_hits.len().min(3) as f64;
            categories.push("javascript_protocol_href".to_string());
            for m in js_href_hits.iter().take(3) {
                let snip_start = m.start().saturating_sub(10);
                let snip_end = (m.end() + 50).min(body_html.len());
                evidence.push(Evidence {
                    description: "Navigation attribute uses javascript: pseudo-protocol — code execution via link click".to_string(),
                    location: Some("body_html:href".to_string()),
                    snippet: Some(body_html[snip_start..snip_end].to_string()),
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
                "No malicious content found in HTML body",
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
    fn extracts_meta_refresh_with_spaces_and_lowercase() {
        let html = r#"<meta http-equiv='refresh' content=' 5 ; url = https://slow.example/step2 '>"#;
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
}
