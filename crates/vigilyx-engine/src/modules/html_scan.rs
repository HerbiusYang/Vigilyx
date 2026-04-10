//! HTML scan module - Detect malicious tags and dangerous attributes in HTML body

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

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

/// Dangerous operations within scripts - indicate malicious <script> content
const DANGEROUS_SCRIPT_OPS: &[&str] = &[
    "eval(",
    "function(",
    "settimeout(",
    "setinterval(",
    "document.location",
    "window.location",
    "location.href",
    "location.replace(",
    "document.cookie",
    "document.write(",
    "xmlhttprequest",
    "fetch(",
    "atob(",
    "string.fromcharcode(",
    ".submit()",
    ".innerhtml",
    "new blob(",
    "createelement(",
];

const DANGEROUS_ONCLICK_OPS: &[&str] = &[
    "window.location",
    "document.location",
    "location.href",
    "location=",
    "javascript:",
    "eval(",
    "fetch(",
    "xmlhttprequest",
    "atob(",
];

/// Analyze <script> tags in HTML: extract content and check for dangerous operations
fn analyze_scripts(html_lower: &str, html_original: &str) -> (f64, Vec<Evidence>) {
    let mut score = 0.0f64;
    let mut evidence = Vec::new();
    let mut search_from = 0;

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
        let dangerous_hits: Vec<&&str> = DANGEROUS_SCRIPT_OPS
            .iter()
            .filter(|op| script_body.contains(**op))
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

        if DANGEROUS_ONCLICK_OPS
            .iter()
            .any(|op| handler.contains(op))
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
            let hidden_patterns = [
                "display:none",
                "display: none",
                "visibility:hidden",
                "visibility: hidden",
                "font-size:0",
                "font-size: 0",
                "opacity:0",
                "opacity: 0",
                "height:0",
                "height: 0",
                "max-height:0",
                "max-height: 0",
                "text-indent:-9999",
                "text-indent: -9999",
                "position:absolute;left:-9999",
                "position: absolute; left: -9999",
            ];

            let hidden_count = hidden_patterns
                .iter()
                .filter(|&&p| html_lower.contains(p))
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
}
