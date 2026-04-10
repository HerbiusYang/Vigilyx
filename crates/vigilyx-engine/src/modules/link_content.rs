//! URL content detection module - URL structural heuristic analysis
//!
//! Detects: suspicious URL path keywords, suspicious query parameters, encoding anomalies,
//! abnormal URL length, sensitive operation paths, fragment routing analysis, path typosquatting, etc.

use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use rayon::prelude::*;
use regex::Regex;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::common::{
    extract_domain_from_url, is_probable_cloud_asset_host, is_probable_static_asset_path,
};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

/// Long random hex string detection (DGA indicators) - static to avoid recompilation
static RE_HEX_DGA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-f]{8,}").unwrap());

/// Minimum number of URL words to trigger parallel Levenshtein computation.
const TYPO_PAR_THRESHOLD: usize = 20;

pub struct LinkContentModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
}

impl Default for LinkContentModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkContentModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        let mut phishing_keywords = effective.phishing_keywords;
        for keyword in effective.weak_phishing_keywords {
            if !phishing_keywords.contains(&keyword) {
                phishing_keywords.push(keyword);
            }
        }
        Self {
            meta: ModuleMetadata {
                id: "link_content".to_string(),
                name: "URL Content Analysis".to_string(),
                description: "URL path, parameter, and fragment heuristic analysis + typosquatting detection".to_string(),
                pillar: Pillar::Link,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords,
        }
    }
}

/// Suspicious URL path keywords (phishing and credential harvesting indicators)
const SUSPICIOUS_PATH_KEYWORDS: &[&str] = &[
    "login",
    "signin",
    "sign-in",
    "logon",
    "log-on",
    "verify",
    "verification",
    "confirm",
    "validate",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "passwd",
    "credential",
    "banking",
    "payment",
    "billing",
    "checkout",
    "recover",
    "restore",
    "unlock",
    "reactivate",
    "webmail",
    "outlook",
    "office365",
    "onedrive",
    "申报",
    "核对",
    "办理",
    "领取",
    "查看",
];

/// Suspicious query parameter names (phishing credential parameters)
const SUSPICIOUS_PARAMS: &[&str] = &[
    "token",
    "session",
    "auth",
    "redirect",
    "return_url",
    "returnurl",
    "callback",
    "next",
    "email",
    "user",
    "username",
    "ssn",
    "password",
    "otp",
];

/// Common URL words dictionary (used for typosquatting detection)
/// Phishing URLs often contain misspelled versions of common words
const COMMON_URL_WORDS: &[&str] = &[
    "invoice",
    "download",
    "upload",
    "account",
    "verify",
    "confirm",
    "payment",
    "receipt",
    "document",
    "certificate",
    "transfer",
    "balance",
    "statement",
    "profile",
    "settings",
    "service",
    "banking",
    "finance",
    "security",
    "password",
    "login",
    "register",
    "activate",
    "update",
    "manage",
    "notification",
    "message",
    "support",
    "customer",
    "portal",
    "index",
    "detail",
    "query",
    "result",
    "report",
];

const AUTH_BARRIER_TERMS: &[&str] = &[
    "captcha",
    "turnstile",
    "cloudflare",
    "verify-human",
    "verify you are human",
    "prove you are human",
    "security-check",
    "security check",
    "human verification",
    "checking your browser",
];
const OAUTH_FLOW_TERMS: &[&str] = &[
    "oauth2",
    "/authorize",
    "client_id=",
    "redirect_uri=",
    "response_type=",
    "prompt=consent",
    "scope=",
    "offline_access",
];
const OFFICIAL_LOGIN_SUFFIXES: &[&str] = &[
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office365.com",
    "live.com",
    "okta.com",
    "google.com",
];

/// Compute edit distance (Levenshtein distance) between two strings
fn edit_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Extract word segments from URL path/fragment (split by / - _ . and camelCase)
fn extract_url_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
   // Split by / - _ .
    for segment in text.split(['/', '-', '_', '.']) {
        if segment.is_empty() {
            continue;
        }
       // Split by camelCase/PascalCase: "InvoiveDown" -> ["Invoive", "Down"]
        let mut current = String::new();
        for ch in segment.chars() {
            if ch.is_uppercase() && !current.is_empty() {
                if current.len() >= 3 {
                    words.push(current.to_lowercase());
                }
                current = String::new();
            }
            current.push(ch);
        }
        if current.len() >= 3 {
            words.push(current.to_lowercase());
        }
    }
    words
}

fn consonant_metrics(alpha_bytes: &[u8]) -> (u32, f64) {
    let vowels = b"aeiou";
    let mut max_consonant_run = 0u32;
    let mut current_run = 0u32;
    for &b in alpha_bytes {
        if !vowels.contains(&b.to_ascii_lowercase()) {
            current_run += 1;
            max_consonant_run = max_consonant_run.max(current_run);
        } else {
            current_run = 0;
        }
    }

    let consonant_count = alpha_bytes
        .iter()
        .filter(|b| !vowels.contains(&b.to_ascii_lowercase()))
        .count();
    let consonant_ratio = consonant_count as f64 / alpha_bytes.len() as f64;

    (max_consonant_run, consonant_ratio)
}

fn is_human_readable_label_segment(segment: &str) -> bool {
    let normalized = segment.to_ascii_lowercase();
    if crate::modules::identity_anomaly::is_human_readable_domain_label(&normalized) {
        return true;
    }
    if normalized.len() < 4 || !normalized.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let alpha_bytes = normalized.as_bytes();
    let has_vowel = alpha_bytes
        .iter()
        .any(|b| b"aeiou".contains(&b.to_ascii_lowercase()));
    let (max_consonant_run, consonant_ratio) = consonant_metrics(alpha_bytes);
    has_vowel && max_consonant_run <= 2 && consonant_ratio < 0.75
}

/// Check one word against the dictionary for near-misses.
fn find_typo_match(word: &str) -> Option<(String, String)> {
    for &dict_word in COMMON_URL_WORDS {
        let len_diff = (word.len() as i32 - dict_word.len() as i32).unsigned_abs() as usize;
        if len_diff > 2 {
            continue;
        }
        let dist = edit_distance(word, dict_word);
        let same_boundary_chars = word.chars().next() == dict_word.chars().next()
            && word.chars().last() == dict_word.chars().last();
        if dist == 1 || (dist == 2 && word.len() >= 6 && same_boundary_chars) {
            return Some((
                format!(
                    "URL path typosquatting: \"{}\" likely misspelling of \"{}\" (edit distance={})",
                    word, dict_word, dist
                ),
                "url_typo".to_string(),
            ));
        }
    }
    None
}

/// Detect typosquatting anomalies in URL path/fragment
/// Returns (score, findings) - each typosquatting match found
fn detect_typos(text: &str) -> (f64, Vec<(String, String)>) {
    let url_words = extract_url_words(text);

   // Filter candidates (too short or exact match -> skip)
    let candidates: Vec<&String> = url_words
        .iter()
        .filter(|w| w.len() >= 4 && !COMMON_URL_WORDS.contains(&w.as_str()))
        .collect();

    let findings: Vec<(String, String)> = if candidates.len() >= TYPO_PAR_THRESHOLD {
        candidates
            .par_iter()
            .filter_map(|word| find_typo_match(word))
            .collect()
    } else {
        candidates
            .iter()
            .filter_map(|word| find_typo_match(word))
            .collect()
    };

   // Each typosquatting finding is a moderate signal; cap at 3+ findings
    let score = (findings.len() as f64 * 0.10).min(0.30);
    (score, findings)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn domain_matches_suffix(domain: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{}", suffix)))
}

fn build_email_context(ctx: &SecurityContext) -> String {
    let mut context = String::new();
    if let Some(subject) = ctx.session.subject.as_deref() {
        context.push_str(subject);
        context.push(' ');
    }
    if let Some(body) = ctx.session.content.body_text.as_deref() {
        context.push_str(body);
        context.push(' ');
    }
    if let Some(body_html) = ctx.session.content.body_html.as_deref() {
        context.push_str(body_html);
        context.push(' ');
    }
    for link in &ctx.session.content.links {
        if let Some(text) = link.text.as_deref() {
            context.push_str(text);
            context.push(' ');
        }
    }
    for attachment in &ctx.session.content.attachments {
        context.push_str(&attachment.filename);
        context.push(' ');
    }
    context.to_lowercase()
}

fn has_keyword_context(text: &str, keywords: &[String]) -> bool {
    let normalized = normalize_text(text);
    keywords.iter().any(|keyword| normalized.contains(keyword))
}

fn url_looks_like_device_code_flow(url_lower: &str) -> bool {
    url_lower.contains("microsoft.com/devicelogin")
        || url_lower.contains("/deviceauth")
        || (url_lower.contains("device") && url_lower.contains("code"))
}

fn url_looks_like_oauth_flow(url_lower: &str) -> bool {
    contains_any(url_lower, OAUTH_FLOW_TERMS)
}

fn url_looks_like_auth_barrier(url_lower: &str) -> bool {
    contains_any(url_lower, AUTH_BARRIER_TERMS)
}

/// URL heuristic analysis (includes fragment and typosquatting detection)
fn analyze_url(url: &str) -> (f64, Vec<(String, String)>) {
    let mut score: f64 = 0.0;
    let mut findings: Vec<(String, String)> = Vec::new();
   // Decode HTML entities (URLs in email body may contain &amp; etc.)
    let url_decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"");
    let effective_url = crate::modules::link_scan::unwrap_mail_security_gateway_target(&url_decoded)
        .unwrap_or_else(|| url_decoded.clone());
    let url_lower = effective_url.to_lowercase();
    let used_gateway_target = effective_url != url_decoded;

   // Parse URL: scheme://host/path?query#fragment
    let after_scheme = url_lower
        .strip_prefix("https://")
        .or_else(|| url_lower.strip_prefix("http://"))
        .unwrap_or(&url_lower);

   // fragment
    let (url_without_fragment, fragment) = match after_scheme.split_once('#') {
        Some((main, frag)) => (main, Some(frag)),
        None => (after_scheme, None),
    };

    let (host_path, query) = match url_without_fragment.split_once('?') {
        Some((hp, q)) => (hp, Some(q)),
        None => (url_without_fragment, None),
    };

    let path = host_path.find('/').map(|i| &host_path[i..]).unwrap_or("/");
    let host_for_check = host_path
        .split('/')
        .next()
        .and_then(|h| h.split(':').next())
        .unwrap_or("");
    let host_under_safe_domain =
        crate::modules::link_scan::is_well_known_safe_domain(host_for_check);

   // Static image/font/script assets hosted on object storage frequently use
   // bucket labels and long query strings, but they are not landing pages and
   // should not trigger login-path/DGA heuristics on their own. The same
   // treatment applies to static assets hosted under curated well-known safe
   // domains such as provider CDN roots (for example *.127.net).
    if (is_probable_cloud_asset_host(host_for_check) || host_under_safe_domain)
        && is_probable_static_asset_path(path)
    {
        return (score, findings);
    }

   // Skip structural checks for trusted domains and mail security gateways.
   // Trusted domains (e.g., QQ mail download URLs) naturally have long params.
   // Security gateways (e.g., Trend Micro DDEI, Proofpoint) rewrite URLs with
   // redirect/auth params that would otherwise trigger false positives.
    if crate::modules::link_scan::is_trusted_url_domain(host_for_check)
        || (!used_gateway_target
            && crate::modules::link_scan::is_mail_security_gateway_pub(&url_lower))
    {
        return (score, findings);
    }

   // 1. Suspicious path keywords (check both path and fragment)
    let combined_path = if let Some(frag) = fragment {
        format!("{} {}", path, frag)
    } else {
        path.to_string()
    };

   // Trusted domains (IOC verdict=clean) get reduced structural check weight
    let url_domain = host_path.split('/').next().unwrap_or("");
    let domain_trusted = crate::modules::link_scan::is_trusted_url_domain(url_domain);

    let mut path_hits = Vec::new();
    for &kw in SUSPICIOUS_PATH_KEYWORDS {
        if combined_path.contains(kw) {
            path_hits.push(kw);
        }
    }
    if !path_hits.is_empty() {
        let weight = if domain_trusted { 0.02 } else { 0.10 };
        score += (path_hits.len() as f64 * weight).min(0.30);
        findings.push((
            format!(
                "URL path contains suspicious keywords: {}{}",
                path_hits.join(", "),
                if domain_trusted {
                    " (trusted domain, reduced weight)"
                } else {
                    ""
                }
            ),
            "suspicious_path".to_string(),
        ));
    }

   // 2. Suspicious query parameters (parameter name matching)
    if let Some(q) = query {
        let mut param_hits = Vec::new();
        let param_names: Vec<&str> = q
            .split('&')
            .filter_map(|pair| {
                let name = pair.split('=').next()?;
                if name.is_empty() { None } else { Some(name) }
            })
            .collect();
        for &suspicious in SUSPICIOUS_PARAMS {
            if param_names.contains(&suspicious) {
                param_hits.push(suspicious);
            }
        }
        if !param_hits.is_empty() {
            let pw = if domain_trusted { 0.02 } else { 0.08 };
            score += (param_hits.len() as f64 * pw).min(0.25);
            findings.push((
                format!(
                    "URL query parameters suspicious: {}{}",
                    param_hits.join(", "),
                    if domain_trusted {
                        " (trusted domain, reduced weight)"
                    } else {
                        ""
                    }
                ),
                "suspicious_params".to_string(),
            ));
        }
    }

   // 3. Abnormally long URL (over 400 characters is suspicious)
    if effective_url.len() > 400 {
        score += 0.10;
        findings.push((
            format!("Abnormally long URL: {} characters", effective_url.len()),
            "long_url".to_string(),
        ));
    }

   // 4. Encoding anomalies (check path and query for abnormal URL encoding)
    let path_lower = path.to_lowercase();
    if path_lower.contains("%25") {
        score += 0.25;
        findings.push((
            "URL path contains double percent-encoding (%25)".to_string(),
            "double_encoding".to_string(),
        ));
    }
    if path_lower.contains("%2f") || path_lower.contains("%5c") {
        score += 0.15;
        findings.push((
            "URL path contains encoded path separators".to_string(),
            "encoded_separator".to_string(),
        ));
    }

   // 5. @ sign in URL (domain obfuscation)
    if after_scheme.contains('@') {
        score += 0.35;
        findings.push((
            "URL contains @ sign (potentially hiding real domain)".to_string(),
            "at_sign_obfuscation".to_string(),
        ));
    }

   // 5b. DGA/random domain detection (consonant clustering analysis)
   // e.g., rqvzkqb.shbllgs.cn is likely DGA-generated
    if !host_under_safe_domain {
        let domain_part = host_for_check;
       // Split into domain labels (excluding TLD)
        let labels: Vec<&str> = domain_part.split('.').collect();
        for label in &labels {
            if label.len() < 5 {
                continue;
            }
           // Only check ASCII labels
            if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                continue;
            }
            let normalized_label = label.to_ascii_lowercase();
            let label_segments: Vec<&str> =
                normalized_label.split('-').filter(|segment| !segment.is_empty()).collect();
            if label_segments.len() > 1
                && label_segments
                    .iter()
                    .all(|segment| is_human_readable_label_segment(segment))
            {
                continue;
            }

            let dga_candidates: Vec<&str> = if label_segments.len() > 1 {
                label_segments
            } else {
                vec![normalized_label.as_str()]
            };
            for candidate in dga_candidates {
                let alpha_bytes: Vec<u8> = candidate
                    .bytes()
                    .filter(|b| b.is_ascii_alphabetic())
                    .collect();
                if alpha_bytes.len() < 5 {
                    continue;
                }
                if crate::modules::identity_anomaly::is_human_readable_domain_label(candidate) {
                    continue;
                }

                let (max_consonant_run, consonant_ratio) = consonant_metrics(&alpha_bytes);
                if max_consonant_run >= 4 || (max_consonant_run >= 3 && consonant_ratio > 0.70) {
                    let dga_weight = if domain_trusted { 0.05 } else { 0.30 };
                    score += dga_weight;
                    findings.push((
                        format!(
                            "Domain label \"{}\" likely DGA-generated (consecutive consonants={}, consonant ratio={:.0}%)",
                            candidate, max_consonant_run, consonant_ratio * 100.0
                        ),
                        "dga_random_domain".to_string(),
                    ));
                    break; // One DGA finding per URL is sufficient
                }
            }

            if findings
                .iter()
                .any(|(_, category)| category == "dga_random_domain")
            {
                break;
            }
        }
    }

   // 5c. IDN homograph attack detection (Cyrillic/Greek characters in domain)
   // e.g., аpple.com (Cyrillic U+0430) vs apple.com (Latin a U+0061)
    {
        let host = host_path.split('/').next().unwrap_or("");
        let domain_part = host.split(':').next().unwrap_or(host);
        let has_latin = domain_part.chars().any(|c| c.is_ascii_alphabetic());
        let has_non_latin_script = domain_part.chars().any(|c| {
            !c.is_ascii() && c.is_alphabetic()
                && !('\u{4e00}'..='\u{9fff}').contains(&c) // Exclude CJK (normal in Chinese domains)
                && !('\u{3040}'..='\u{30ff}').contains(&c) // Exclude Japanese kana
                && !('\u{ac00}'..='\u{d7af}').contains(&c) // Exclude Korean
        });
        if has_latin && has_non_latin_script {
            score += 0.40;
            findings.push((
                format!(
                    "Mixed-script domain (IDN homograph attack): {} — potentially impersonating legitimate domain",
                    domain_part
                ),
                "idn_homograph".to_string(),
            ));
        }
    }

   // 6. Multiple redirect parameters
    let redirect_count = url_lower.matches("redirect").count()
        + url_lower.matches("return").count()
        + url_lower.matches("next=").count()
        + url_lower.matches("url=").count();
    if redirect_count >= 2 {
        score += 0.20;
        findings.push((
            format!(
                "URL contains multiple redirect parameters ({} occurrences)",
                redirect_count
            ),
            "multiple_redirects".to_string(),
        ));
    }

   // 7. Non-standard port
    let host = url_without_fragment.split('/').next().unwrap_or("");
    if let Some(port_str) = host.split(':').nth(1)
        && let Ok(port) = port_str.parse::<u16>()
        && port != 80
        && port != 443
        && port != 8080
        && port != 8443
    {
        score += 0.15;
        findings.push((
            format!("URL uses non-standard port: {}", port),
            "unusual_port".to_string(),
        ));
    }

   // 8. Fragment (SPA RoadBy) Analyze
    if let Some(frag) = fragment
        && !frag.is_empty()
    {
       // Fragment contains multi-level path (common in SPA-based phishing)
        let frag_depth = frag.matches('/').count();
        if frag_depth >= 2 {
            score += 0.10;
            findings.push((
                format!(
                    "URL fragment contains multi-level SPA routing: #{} (depth={})",
                    frag, frag_depth
                ),
                "deep_fragment_route".to_string(),
            ));
        }

       // Suspicious keywords in fragment
        let mut frag_hits = Vec::new();
        for &kw in SUSPICIOUS_PATH_KEYWORDS {
            if frag.contains(kw) {
                frag_hits.push(kw);
            }
        }
        if !frag_hits.is_empty() {
            score += (frag_hits.len() as f64 * 0.10).min(0.25);
            findings.push((
                format!(
                    "URL fragment contains suspicious keywords: #{} [{}]",
                    frag,
                    frag_hits.join(", ")
                ),
                "suspicious_fragment".to_string(),
            ));
        }

       // Fragment typosquatting detection
        let (typo_score, typo_findings) = detect_typos(frag);
        if typo_score > 0.0 {
            score += typo_score;
            findings.extend(typo_findings);
        }
    }

   // 9. Path typosquatting detection (check URL path)
    let (path_typo_score, path_typo_findings) = detect_typos(path);
    if path_typo_score > 0.0 {
        score += path_typo_score;
        findings.extend(path_typo_findings);
    }

    (score, findings)
}

#[async_trait]
impl SecurityModule for LinkContentModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, _ctx: &SecurityContext) -> bool {
        true
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let links = &ctx.session.content.links;

        if links.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No links found in email",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut suspicious_urls: Vec<String> = Vec::new();

        for link in links {
            let (url_score, findings) = analyze_url(&link.url);
            if url_score > 0.0 {
                total_score += url_score;
                suspicious_urls.push(link.url.clone());
                for (desc, category) in findings {
                    categories.push(category);
                    evidence.push(Evidence {
                        description: desc,
                        location: Some("links".to_string()),
                        snippet: Some(if link.url.len() > 120 {
                            format!("{}...", &link.url[..120])
                        } else {
                            link.url.clone()
                        }),
                    });
                }
            }
        }

       // Additional phishing URL pattern detection

        // 10. Recipient email embedded in URL (targeted phishing)
       // e.g., phishing link contains the recipient's email address as a parameter
        for link in links {
            let effective_url =
                crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                    .unwrap_or_else(|| link.url.clone());
            let effective_url_lower = effective_url.to_lowercase();
            let link_domain = extract_domain_from_url(&effective_url_lower);
            let is_trusted = link_domain
                .as_ref()
                .is_some_and(|d| crate::modules::link_scan::is_trusted_url_domain(d));
            if is_trusted {
                continue;
            }
            let has_recipient = ctx.session.rcpt_to.iter().any(|rcpt| {
                let rcpt_lower = rcpt.to_lowercase();
                effective_url_lower.contains(&rcpt_lower)
                    || effective_url_lower.contains(&rcpt_lower.replace('@', "%40"))
            });
            if has_recipient {
                total_score += 0.35;
                categories.push("recipient_in_url".to_string());
                evidence.push(Evidence {
                    description: "URL contains recipient email address (targeted credential phishing)"
                        .to_string(),
                    location: Some("links".to_string()),
                    snippet: Some(if effective_url.len() > 120 {
                        format!("{}...", &effective_url[..120])
                    } else {
                        effective_url
                    }),
                });
                break; // Only record once
            }
        }

       // 10b. @ obfuscation + recipient email compound signal
       // If the same email has both URL @ sign obfuscation and embedded recipient address,
       // this is a strong credential phishing indicator (e.g., spoofed Apple ID attack pattern)
        {
            let has_at_obfuscation = categories.iter().any(|c| c == "at_sign_obfuscation");
            let has_recipient_in_url = categories.iter().any(|c| c == "recipient_in_url");
            if has_at_obfuscation && has_recipient_in_url {
                total_score += 0.30;
                categories.push("targeted_credential_phishing".to_string());
                evidence.push(Evidence {
                    description:
                        "URL combines @ sign obfuscation + embedded recipient email — high-confidence targeted credential theft"
                            .to_string(),
                    location: Some("links".to_string()),
                    snippet: None,
                });
            }
        }

       // 11. Organization domain mimicry in URL subdomain
        {
            let org_domains: &[&str] = &["corp-internal.com"];
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if let Ok(parsed) = url::Url::parse(&effective_url)
                    && let Some(host) = parsed.host_str()
                {
                    let host_lower = host.to_lowercase();
                    for org in org_domains {
                        let org_name = org.split('.').next().unwrap_or(org);
                        if host_lower.contains(org_name) && !host_lower.ends_with(org) {
                            total_score += 0.30;
                            categories.push("org_domain_mimicry".to_string());
                            evidence.push(Evidence {
                                description: format!("URL subdomain mimics organization domain '{}': {}", org, host),
                                location: Some("links".to_string()),
                                snippet: Some(effective_url.clone()),
                            });
                        }
                    }
                }
            }
        }

       // 12. Long random hex in subdomain (DGA indicator)
        {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if let Ok(parsed) = url::Url::parse(&effective_url)
                    && let Some(host) = parsed.host_str()
                {
                   // Get first subdomain label
                    let first_label = host.split('.').next().unwrap_or("");
                    if RE_HEX_DGA.is_match(first_label) {
                        total_score += 0.15;
                        categories.push("hex_subdomain".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "URL subdomain contains long random hex string (DGA indicator): {}",
                                host
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(effective_url),
                        });
                        break;
                    }
                }
            }
        }

       // Analyze email body for URL-related phishing patterns (may not be extracted as links)
        if let Some(ref body) = ctx.session.content.body_text {
            let body_lower = body.to_lowercase();
           // Check for mobile browser redirect instructions (common phishing tactic)
            if body_lower.contains("复制地址到")
                || body_lower.contains("复制链接到")
                || body_lower.contains("手机浏览器")
                || body_lower.contains("手机查看")
            {
                total_score += 0.20;
                categories.push("mobile_redirect".to_string());
                evidence.push(Evidence {
                    description: "Body asks user to manually copy link to mobile browser (common phishing tactic)".to_string(),
                    location: Some("body".to_string()),
                    snippet: None,
                });
            }
        }

        let email_context = build_email_context(ctx);
        let keyword_context = has_keyword_context(&email_context, &self.phishing_keywords);

        if keyword_context {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                let effective_lower = effective_url.to_lowercase();
                let link_domain = extract_domain_from_url(&effective_lower);

                if url_looks_like_device_code_flow(&effective_lower) {
                    total_score += 0.40;
                    categories.push("device_code_phishing".to_string());
                    evidence.push(Evidence {
                        description:
                            "Email uses a device-code lure and links to a device-login workflow"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }

                if link_domain
                    .as_deref()
                    .is_some_and(|domain| domain_matches_suffix(domain, OFFICIAL_LOGIN_SUFFIXES))
                    && url_looks_like_oauth_flow(&effective_lower)
                {
                    total_score += 0.25;
                    categories.push("oauth_device_flow".to_string());
                    evidence.push(Evidence {
                        description:
                            "Email pairs a device-code lure with an OAuth authorization URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }
            }
        }

        if keyword_context {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                let effective_lower = effective_url.to_lowercase();
                if contains_any(&effective_lower, SUSPICIOUS_PATH_KEYWORDS)
                    || url_looks_like_oauth_flow(&effective_lower)
                    || url_looks_like_device_code_flow(&effective_lower)
                {
                    total_score += 0.20;
                    categories.push("qr_to_login_chain".to_string());
                    evidence.push(Evidence {
                        description:
                            "Email contains a QR lure and a follow-on login / authorization URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }
            }
        }

        if keyword_context {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                let effective_lower = effective_url.to_lowercase();
                if url_looks_like_auth_barrier(&effective_lower)
                    && (contains_any(&effective_lower, SUSPICIOUS_PATH_KEYWORDS)
                        || url_looks_like_oauth_flow(&effective_lower)
                        || url_looks_like_device_code_flow(&effective_lower))
                {
                    total_score += 0.18;
                    categories.push("auth_barrier_url".to_string());
                    evidence.push(Evidence {
                        description:
                            "Login-themed email routes through a CAPTCHA / auth-barrier URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();
        suspicious_urls.sort();
        suspicious_urls.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "Analyzed {} links, no suspicious content found",
                    links.len()
                ),
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.75,
            categories,
            summary: format!(
                "URL content analysis found {} anomalies across {} suspicious URLs",
                evidence.len(),
                suspicious_urls.len()
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "suspicious_urls": suspicious_urls,
                "total_links": links.len(),
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
    use std::collections::HashSet;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn analyze_with_runtime(module: &LinkContentModule, ctx: &SecurityContext) -> ModuleResult {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(module.analyze(ctx))
            .unwrap()
    }

    fn reset_url_domain_sets() {
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::new()));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));
    }

    fn make_ctx_with_body(link: &str, body_text: Option<&str>, subject: Option<&str>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = subject.map(str::to_string);
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            links: vec![EmailLink {
                url: link.to_string(),
                text: None,
                suspicious: false,
            }],
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_ctx(link: &str) -> SecurityContext {
        make_ctx_with_body(link, None, None)
    }

    fn make_module_with_keywords(keywords: &[&str]) -> LinkContentModule {
        LinkContentModule::new_with_keyword_lists(EffectiveKeywordLists {
            phishing_keywords: keywords.iter().map(|keyword| normalize_text(keyword)).collect(),
            ..Default::default()
        })
    }

    #[test]
    fn test_gateway_target_url_is_used_for_recipient_matching() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin%3Fuser%3Dvictim%40example.com",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(result.categories.contains(&"recipient_in_url".to_string()));
    }

    #[test]
    fn test_legitimate_brand_label_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://rep.hundsun.cn/report/clearance");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "Known brand labels should not be marked as DGA: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_object_storage_static_asset_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login-banner.png?x-oss-process=image/resize,w_600",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(result.categories.is_empty(), "static cloud asset should be ignored: {:?}", result.categories);
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_well_known_safe_cdn_asset_is_not_flagged_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::from([
            "127.net".to_string(),
        ])));
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://mail-online.nosdn.127.net/wzpmmc/b7713ee39fc6d0272a61196c395ab44e.jpg",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "curated safe CDN assets should not trip DGA heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_login_landing_page_still_has_structural_path_signal() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) = analyze_url("https://pro.qcc.com/login?path=investigation/automation-check");

        assert!(findings
            .iter()
            .any(|(_, category)| category == "suspicious_path"));
    }

    #[test]
    fn test_hyphenated_human_readable_domain_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://product-support.chaitin.cn/package/detail?id=12345");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "human-readable hyphenated labels should not be marked as DGA: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_receive_path_is_not_treated_as_receipt_typo() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) = analyze_url("https://product-support.chaitin.cn/message/receive?id=12345");

        assert!(
            !findings.iter().any(|(_, category)| category == "url_typo"),
            "common verbs like receive should not be treated as receipt typos: {:?}",
            findings
        );
    }

    #[test]
    fn test_device_code_flow_requires_keyword_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["secure voicemail", "device code"]);
        let ctx = make_ctx_with_body(
            "https://microsoft.com/devicelogin",
            Some("Secure voicemail: enter the device code"),
            Some("Secure message"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"device_code_phishing".to_string()),
            "device-code structure should only fire with keyword context: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_device_code_flow_without_keyword_context_stays_clean() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://microsoft.com/devicelogin");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"device_code_phishing".to_string()),
            "device-code URL alone should not trip the dynamic-keyword gate: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_auth_barrier_url_uses_dynamic_keyword_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["mailbox alert", "review now"]);
        let ctx = make_ctx_with_body(
            "https://example.com/security-check/captcha?redirect_uri=https://login.microsoftonline.com",
            Some("Mailbox alert review now"),
            Some("Mailbox alert"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"auth_barrier_url".to_string()),
            "auth-barrier URL should use runtime keywords instead of hardcoded lure text: {:?}",
            result.categories
        );
    }
}
