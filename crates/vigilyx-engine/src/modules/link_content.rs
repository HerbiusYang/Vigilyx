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
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::common::{
    extract_domain_from_url, is_probable_cloud_asset_host,
    is_probable_non_clickable_render_asset_url, is_probable_opaque_mail_callback_url,
    is_probable_safe_static_asset_url, is_probable_schema_reference_url,
    is_probable_static_asset_path,
};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};
use unicode_normalization::UnicodeNormalization;

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
                description:
                    "URL path, parameter, and fragment heuristic analysis + typosquatting detection"
                        .to_string(),
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

// SUSPICIOUS_PATH_KEYWORDS: moved to module_data JSON (key: "suspicious_path_keywords")
// SUSPICIOUS_PARAMS: moved to module_data JSON (key: "suspicious_query_params")
// COMMON_URL_WORDS: moved to module_data JSON (key: "common_url_words")
// AUTH_BARRIER_TERMS: moved to module_data JSON (key: "auth_barrier_terms")
// OAUTH_FLOW_TERMS: moved to module_data JSON (key: "oauth_flow_terms")
// OFFICIAL_LOGIN_SUFFIXES: moved to module_data JSON (key: "official_login_suffixes")

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
    let md = crate::module_data::module_data();
    for dict_word in md.get_list("common_url_words") {
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

    let md = crate::module_data::module_data();
    // Filter candidates (too short or exact match -> skip)
    let candidates: Vec<&String> = url_words
        .iter()
        .filter(|w| w.len() >= 4 && !md.contains("common_url_words", w))
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

fn contains_any_suspicious_path_keywords(haystack: &str) -> bool {
    crate::matcher::suspicious_path_keywords().is_match(haystack)
}

fn domain_matches_official_login_suffix(domain: &str) -> bool {
    let md = crate::module_data::module_data();
    for suffix in md.get_list("official_login_suffixes") {
        if domain == suffix || domain.ends_with(&format!(".{}", suffix)) {
            return true;
        }
    }
    false
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

fn has_qr_lure_context(text: &str) -> bool {
    const QR_TERMS: &[&str] = &[
        "qr code",
        "scan the code",
        "scan qr",
        "scan to login",
        "二维码",
        "扫码",
        "扫描二维码",
        "扫码登录",
    ];

    QR_TERMS.iter().any(|term| text.contains(term))
}

fn url_looks_like_device_code_flow(url_lower: &str) -> bool {
    url_lower.contains("microsoft.com/devicelogin")
        || url_lower.contains("/deviceauth")
        || (url_lower.contains("device") && url_lower.contains("code"))
}

fn url_looks_like_oauth_flow(url_lower: &str) -> bool {
    let md = crate::module_data::module_data();
    // `profile`, `email`, and `openid` are common path/query words on
    // ordinary business-card and mail pages. They only become OAuth evidence
    // when paired with a flow marker such as /authorize, client_id, or scope.
    const CONTEXT_ONLY_TERMS: &[&str] = &["profile", "email", "openid", "saml"];
    md.get_list("oauth_flow_terms")
        .iter()
        .any(|term| !CONTEXT_ONLY_TERMS.contains(&term.as_str()) && url_lower.contains(term))
}

fn url_looks_like_auth_barrier(url_lower: &str) -> bool {
    let md = crate::module_data::module_data();
    for term in md.get_list("auth_barrier_terms") {
        if url_lower.contains(term) {
            return true;
        }
    }
    false
}

/// Fullwidth Latin letters (U+FF21-FF3A / U+FF41-FF5A) are visually identical
/// to ASCII Latin and collapse to it under NFKC.
fn is_fullwidth_latin(c: char) -> bool {
    ('\u{ff21}'..='\u{ff3a}').contains(&c) || ('\u{ff41}'..='\u{ff5a}').contains(&c)
}

/// Match the homoglyph skeleton of a non-ASCII domain against known brand
/// domains (`official_login_suffixes`). NFKC first folds fullwidth/compatibility
/// characters to ASCII, then header_scan's look-alike map folds Cyrillic/digit
/// substitutions to Latin. Returns the matched brand domain, if any.
fn match_idn_skeleton_brand(domain_part: &str) -> Option<String> {
    let folded: String = domain_part.nfkc().collect();
    let skeleton =
        crate::modules::header_scan::checks::normalize_homoglyph_simple(&folded).to_lowercase();
    // No folding happened -> nothing visually confusable with Latin brands.
    if skeleton == domain_part.to_lowercase() {
        return None;
    }
    let md = crate::module_data::module_data();
    md.get_list("official_login_suffixes")
        .iter()
        .find(|brand| skeleton == **brand || skeleton.ends_with(&format!(".{}", brand)))
        .cloned()
}

fn hex_digest<D>(value: &str) -> String
where
    D: Digest + Default,
{
    let mut hasher = D::default();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Recipient identifiers are normal metadata on unsubscribe, preference,
/// open-tracking, and delivery callback endpoints. Without an authentication
/// context they must not be promoted to credential-phishing evidence.
fn is_recipient_metadata_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let path = normalize_text(&parsed.path().to_ascii_lowercase());
    const METADATA_PATH_MARKERS: &[&str] = &[
        "unsubscribe",
        "opt-out",
        "optout",
        "preference",
        "subscription",
        "email-settings",
        "email_settings",
        "/trace/",
        "/tracking/",
        "/track/",
        "/open/",
        "/pixel/",
        "/webhook",
        "/callback",
    ];
    METADATA_PATH_MARKERS
        .iter()
        .any(|marker| path.contains(marker))
        || path.ends_with("/track")
        || path.ends_with("/open")
        || path.ends_with("/report")
}

fn detect_external_brand_host(host: &str) -> Option<(String, String, f64)> {
    let decoded = idna::domain_to_unicode(host).0.to_ascii_lowercase();
    let labels: Vec<&str> = decoded.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let base = labels[labels.len() - 2];
    let md = crate::module_data::module_data();
    let anchors = md.get_structured("brand_anchor_domains")?.as_array()?;
    for entry in anchors {
        let brand = entry.get("keyword")?.as_str()?;
        let anchor = entry.get("domain")?.as_str()?;
        let anchor_base = anchor.split('.').next()?;
        if base == anchor_base || decoded == anchor || decoded.ends_with(&format!(".{anchor}")) {
            continue;
        }
        let normalized_base = crate::modules::header_scan::checks::normalize_homoglyph_simple(base);
        let normalized_anchor =
            crate::modules::header_scan::checks::normalize_homoglyph_simple(anchor_base);
        if normalized_base != base && normalized_base == normalized_anchor {
            return Some((brand.to_string(), anchor.to_string(), 0.45));
        }
        let distance = edit_distance(base, anchor_base);
        let max_len = base.len().max(anchor_base.len());
        if distance > 0 && distance <= 2 && max_len >= 6 {
            return Some((brand.to_string(), anchor.to_string(), 0.35));
        }
    }
    None
}

/// Object-storage / CDN "content override" query parameters
/// (`?response-content-type=text/html`, `?response-content-disposition=...`)
/// rewrite the served response headers of a stored object. Attackers abuse
/// them to make an exempt `.../malware.jpg` URL return an HTML phishing page,
/// so any URL carrying them must lose the static-asset exemption.
pub(crate) fn has_content_override_params(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    let query = query.split('#').next().unwrap_or(query);
    query.split('&').any(|pair| {
        let name = crate::modules::common::percent_decode(pair.split('=').next().unwrap_or(""))
            .to_ascii_lowercase();
        matches!(
            name.as_str(),
            "response-content-type"
                | "response-content-disposition"
                | "response-content-language"
                | "response-content-encoding"
                | "response-cache-control"
                | "response-expires"
        )
    })
}

/// URL heuristic analysis (includes fragment and typosquatting detection)
pub(crate) fn analyze_url(url: &str) -> (f64, Vec<(String, String)>) {
    analyze_url_with_anchor_context(url, false)
}

/// `has_anchor_text` marks a user-clickable `<a>` link carrying visible
/// anchor text. The static-asset exemption only applies to chrome-less
/// render resources (`<img>`/`<link>`/`<script>` src without anchor text);
/// a clickable link pointing at "static" content is a landing-page
/// candidate and must go through structural analysis.
fn analyze_url_with_anchor_context(
    url: &str,
    has_anchor_text: bool,
) -> (f64, Vec<(String, String)>) {
    let mut score: f64 = 0.0;
    let mut findings: Vec<(String, String)> = Vec::new();
    if is_probable_schema_reference_url(url)
        || is_probable_opaque_mail_callback_url(url)
        || crate::modules::link_scan::is_known_safe_tokenized_resource_url(url)
    {
        return (score, findings);
    }
    // Decode HTML entities (URLs in email body may contain &amp; etc.)
    let url_decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"");
    let effective_url =
        crate::modules::link_scan::unwrap_mail_security_gateway_target(&url_decoded)
            .unwrap_or_else(|| url_decoded.clone());
    let url_lower = effective_url.to_lowercase();

    // Parse URL with the WHATWG parser. The old hand-rolled splitter was
    // blind in two ways:
    // - userinfo (`http://mail.qq.com:443@evil.tk/login`): the userinfo
    //   segment was mistaken for the host, so the fake "trusted" prefix hit
    //   safe-domain exemptions while the real host after `@` was never
    //   checked;
    // - backslash separators (`http:/\evil.com/login`): `strip_prefix` failed
    //   and the "host" collapsed to the literal string "http".
    // The WHATWG parser normalizes both (`\` becomes `/` in special schemes)
    // and always exposes the real host via `host_str()`.
    let Ok(parsed_url) = url::Url::parse(&effective_url) else {
        // Unparsable hrefs are preserved at extraction time and scored by
        // link_scan's unparseable_url category; no reliable host/path signal
        // can be derived here.
        return (score, findings);
    };
    let host_for_check = parsed_url.host_str().unwrap_or("");
    let path = parsed_url.path();
    let query = parsed_url.query();
    let fragment = parsed_url.fragment();
    // Operator/system-whitelisted roots are first-party infrastructure.  A
    // subdomain such as `ebank.ccabchina.com` must not be compared against an
    // unrelated external brand merely because its second-level label is close
    // to that brand's anchor (ccabchina vs. abchina/ABC).
    let domain_trusted = crate::modules::link_scan::is_trusted_url_domain(host_for_check);
    let hosted_platform = crate::modules::link_scan::is_shared_hosting_platform(host_for_check);
    let host_under_safe_domain =
        crate::modules::link_scan::is_well_known_safe_domain(host_for_check);

    // Static image/font/script assets hosted on object storage frequently use
    // bucket labels and long query strings, but they are not landing pages and
    // should not trigger login-path/DGA heuristics on their own. The same
    // treatment applies to static assets hosted under curated well-known safe
    // domains such as provider CDN roots (for example *.127.net).
    //
    // The exemption is deliberately narrow:
    // - it never applies to clickable links carrying anchor text (an
    //   attacker-lured <a> "static" URL is a landing-page candidate);
    // - it never applies when the query rewrites the served response headers
    //   (`response-content-type=text/html` turns a stored ".jpg" into an
    //   HTML phishing page).
    let looks_like_static_asset = is_probable_safe_static_asset_url(&effective_url)
        || ((is_probable_cloud_asset_host(host_for_check) || host_under_safe_domain)
            && is_probable_static_asset_path(path));
    if looks_like_static_asset && !has_anchor_text && !has_content_override_params(&effective_url) {
        return (score, findings);
    }
    if looks_like_static_asset && has_content_override_params(&effective_url) {
        score += 0.30;
        findings.push((
            "Static-asset URL carries object-storage content-override parameters (response-content-type/disposition) — served Content-Type can be rewritten to HTML".to_string(),
            "oss_content_override".to_string(),
        ));
    }

    if !domain_trusted
        && !host_under_safe_domain
        && let Some((brand, anchor, brand_score)) = detect_external_brand_host(host_for_check)
    {
        score += brand_score;
        findings.push((
            format!(
                "External brand typosquatting: host '{}' resembles {} ({})",
                host_for_check, brand, anchor
            ),
            "brand_typosquatting".to_string(),
        ));
    }

    // The wrapper has already been removed. Score the real destination's TLD
    // from the JSON-managed policy list; the trusted DDEI hostname never
    // contributes to this finding.
    let md = crate::module_data::module_data();
    if md.get_list("suspicious_tlds").iter().any(|suffix| {
        host_for_check == suffix.as_str() || host_for_check.ends_with(&format!(".{suffix}"))
    }) {
        score += 0.12;
        findings.push((
            format!("Destination uses high-risk TLD: {host_for_check}"),
            "suspicious_tld".to_string(),
        ));
    }

    // 1. Suspicious path keywords (check both path and fragment)
    let combined_path = if let Some(frag) = fragment {
        format!("{} {}", path, frag)
    } else {
        path.to_string()
    };

    // Trusted domains (IOC verdict=clean) get reduced structural check weight
    // A trusted first-party asset may bypass noisy token/URL checks, but a
    // shared tenant platform (Forms/Notion/Workers/Functions) is attacker
    // controlled and must retain normal phishing weights.
    let structural_trusted = domain_trusted && !hosted_platform;

    // Percent-encoding must not hide keywords (e.g. %6c%6f%67%69%6e = login):
    // decode one layer before the Aho-Corasick scan. The %25 double-encoding
    // check below still inspects the raw path.
    let combined_path_decoded =
        crate::modules::common::percent_decode(&combined_path).to_lowercase();
    let path_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
        .scan(&combined_path_decoded)
        .distinct_patterns();
    if !path_hits.is_empty() {
        let weight = if structural_trusted { 0.02 } else { 0.10 };
        score += (path_hits.len() as f64 * weight).min(0.30);
        findings.push((
            format!(
                "URL path contains suspicious keywords: {}{}",
                path_hits.join(", "),
                if structural_trusted {
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
        let mut param_hits: Vec<String> = Vec::new();
        // Decode each parameter name before matching so that encoded names
        // (e.g. tok%65n = token) cannot bypass the suspicious-params list.
        let param_names: Vec<String> = q
            .split('&')
            .filter_map(|pair| {
                let name = pair.split('=').next()?;
                if name.is_empty() {
                    None
                } else {
                    Some(crate::modules::common::percent_decode(name).to_lowercase())
                }
            })
            .collect();
        for suspicious in md.get_list("suspicious_query_params") {
            if param_names.contains(suspicious) {
                param_hits.push(suspicious.to_string());
            }
        }
        if !param_hits.is_empty() {
            let pw = if structural_trusted { 0.02 } else { 0.08 };
            score += (param_hits.len() as f64 * pw).min(0.25);
            findings.push((
                format!(
                    "URL query parameters suspicious: {}{}",
                    param_hits.join(", "),
                    if structural_trusted {
                        " (trusted domain, reduced weight)"
                    } else {
                        ""
                    }
                ),
                "suspicious_params".to_string(),
            ));
        }

        // Parameter *values* are scanned as well: phishing kits hide protocol
        // handlers and keywords behind percent-encoding in redirect
        // parameters (e.g. ?next=%6A%61%76%61%73%63%72%69%70%74%3A... =
        // javascript:). Decoded values that are themselves plain http(s) URLs
        // or bare paths are skipped for the keyword scan — legitimate
        // SSO/redirect targets routinely contain words like "login".
        let mut value_protocol_hit = false;
        let mut value_keyword_hits: Vec<String> = Vec::new();
        for pair in q.split('&') {
            let Some((_, value)) = pair.split_once('=') else {
                continue;
            };
            if value.len() < 4 {
                continue;
            }
            let decoded_value = crate::modules::common::percent_decode(value).to_lowercase();
            if decoded_value.contains("javascript:")
                || decoded_value.contains("vbscript:")
                || decoded_value.contains("data:text/html")
            {
                value_protocol_hit = true;
            }
            let was_encoded = value.contains('%');
            if was_encoded
                && !decoded_value.starts_with("http://")
                && !decoded_value.starts_with("https://")
                && !decoded_value.starts_with('/')
            {
                value_keyword_hits.extend(
                    crate::matcher::suspicious_path_keywords()
                        .scan(&decoded_value)
                        .distinct_patterns(),
                );
            }
        }
        if value_protocol_hit {
            score += 0.30;
            findings.push((
                "Percent-encoded query parameter value resolves to a dangerous protocol (javascript:/vbscript:/data:)".to_string(),
                "encoded_protocol_param".to_string(),
            ));
        }
        if !value_keyword_hits.is_empty() {
            value_keyword_hits.sort();
            value_keyword_hits.dedup();
            let vw = if structural_trusted { 0.02 } else { 0.08 };
            score += (value_keyword_hits.len() as f64 * vw).min(0.25);
            findings.push((
                format!(
                    "URL query parameter values contain suspicious keywords: {}",
                    value_keyword_hits.join(", ")
                ),
                "suspicious_param_value".to_string(),
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

    // 4. Encoding anomalies (check path, query and fragment for abnormal URL
    // encoding). Browsers never decode the fragment — phishing pages decode
    // #%25xx themselves in JS — so %25 double-encoding must be checked on
    // every component, not just the path.
    let path_lower = path.to_lowercase();
    let mut double_encoded_parts: Vec<&str> = Vec::new();
    if path_lower.contains("%25") {
        double_encoded_parts.push("path");
    }
    if query.is_some_and(|q| q.to_lowercase().contains("%25")) {
        double_encoded_parts.push("query");
    }
    if fragment.is_some_and(|f| f.to_lowercase().contains("%25")) {
        double_encoded_parts.push("fragment");
    }
    if !double_encoded_parts.is_empty() {
        score += 0.25;
        findings.push((
            format!(
                "URL {} contains double percent-encoding (%25)",
                double_encoded_parts.join("/")
            ),
            "double_encoding".to_string(),
        ));

        // Decode a second layer (bounded at exactly two layers, no exponential
        // fan-out) so payloads like %253A%252F%252F (%3A%2F%2F -> ://) or
        // double-encoded javascript:/login keywords do not stop at the
        // double_encoding label without their content ever being inspected.
        let raw_components = format!(
            "{} {} {}",
            path,
            query.unwrap_or(""),
            fragment.unwrap_or("")
        );
        let second_decoded = crate::modules::common::percent_decode(
            &crate::modules::common::percent_decode(&raw_components),
        )
        .to_lowercase();
        let mut second_layer_reasons: Vec<String> = Vec::new();
        if second_decoded.contains("javascript:")
            || second_decoded.contains("vbscript:")
            || second_decoded.contains("data:text/html")
        {
            second_layer_reasons.push("dangerous protocol".to_string());
        }
        let second_keyword_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
            .scan(&second_decoded)
            .distinct_patterns();
        if !second_keyword_hits.is_empty() {
            second_layer_reasons.push(format!("keywords: {}", second_keyword_hits.join(", ")));
        }
        if !second_layer_reasons.is_empty() {
            score += 0.20;
            findings.push((
                format!(
                    "Second-layer percent-decoding reveals {}",
                    second_layer_reasons.join("; ")
                ),
                "double_encoded_payload".to_string(),
            ));
        }
    }
    if path_lower.contains("%2f") || path_lower.contains("%5c") {
        score += 0.15;
        findings.push((
            "URL path contains encoded path separators".to_string(),
            "encoded_separator".to_string(),
        ));
    }

    // 5. @ sign in URL (domain obfuscation)
    // Only userinfo in the authority is flagged, not @ in query strings
    // e.g. http://user@evil.com is suspicious, but ?wght@700 (Google Fonts) is benign
    if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
        score += 0.35;
        findings.push((
            "URL contains @ sign in authority (potentially hiding real domain)".to_string(),
            "at_sign_obfuscation".to_string(),
        ));
    }

    // 5b. DGA/random domain detection (consonant clustering analysis)
    // e.g., rqvzkqb.shbllgs.cn is likely DGA-generated
    if !host_under_safe_domain {
        let domain_part = host_for_check;
        // Split into domain labels (excluding TLD)
        let labels: Vec<&str> = domain_part.split('.').collect();
        let md = crate::module_data::module_data();
        let common_subdomains = md.get_list("common_service_subdomains");
        for label in &labels {
            if label.len() < 5 {
                continue;
            }
            // Skip well-known service subdomain prefixes (fonts, static, cdn, track, etc.)
            if common_subdomains
                .iter()
                .any(|s| s.eq_ignore_ascii_case(label))
            {
                continue;
            }
            // Only check ASCII labels
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                continue;
            }
            let normalized_label = label.to_ascii_lowercase();
            let label_segments: Vec<&str> = normalized_label
                .split('-')
                .filter(|segment| !segment.is_empty())
                .collect();
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
                if max_consonant_run >= 4
                    || (max_consonant_run >= 3 && consonant_ratio > 0.80 && alpha_bytes.len() >= 8)
                {
                    let dga_weight = if structural_trusted { 0.05 } else { 0.30 };
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
        // Stored links are normalized to punycode by the WHATWG parser; decode
        // back to Unicode before script analysis.
        let domain_part = idna::domain_to_unicode(host_for_check).0.to_lowercase();
        // Fullwidth Latin (U+FF21+) counts as Latin script: it is visually
        // identical to ASCII Latin and folds to it under NFKC.
        let has_latin = domain_part
            .chars()
            .any(|c| c.is_ascii_alphabetic() || is_fullwidth_latin(c));
        let has_non_latin_script = domain_part.chars().any(|c| {
            !c.is_ascii() && c.is_alphabetic()
                && !is_fullwidth_latin(c)
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
        } else if !domain_part.is_ascii()
            && let Some(brand) = match_idn_skeleton_brand(&domain_part)
        {
            // Pure non-Latin letter-script (e.g. all-Cyrillic "аррӏе.com") and
            // fullwidth-Latin ("ａｐｐｌｅ.com") domains produce no mixed-script
            // signal; flag them only when their homoglyph skeleton matches a
            // known brand domain. CJK-only domains never match - CJK ideographs
            // have no Latin skeleton mapping.
            score += 0.40;
            findings.push((
                format!(
                    "Non-Latin lookalike domain (IDN homograph attack): {} — homoglyph skeleton matches brand \"{}\"",
                    domain_part, brand
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

    // 7. Non-standard port (`Url::port()` is None for scheme-default ports
    // 80/443, so any value returned here is already non-default)
    if let Some(port) = parsed_url.port()
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
        if frag_depth >= 2 && !structural_trusted {
            score += 0.10;
            findings.push((
                format!(
                    "URL fragment contains multi-level SPA routing: #{} (depth={})",
                    frag, frag_depth
                ),
                "deep_fragment_route".to_string(),
            ));
        }

        // Suspicious keywords in fragment (decoded so %-encoding cannot hide them)
        let frag_decoded = crate::modules::common::percent_decode(frag).to_lowercase();
        let frag_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
            .scan(&frag_decoded)
            .distinct_patterns();
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

        // Fragment typosquatting is useful on untrusted hosts, but normal
        // first-party SPAs frequently use internal route/component names that
        // are not dictionary words (and may contain harmless spelling drift).
        if !structural_trusted {
            let (typo_score, typo_findings) = detect_typos(frag);
            if typo_score > 0.0 {
                score += typo_score;
                findings.extend(typo_findings);
            }
        }
    }

    // 9. Path typosquatting detection (check URL path)
    if !structural_trusted {
        let (path_typo_score, path_typo_findings) = detect_typos(path);
        if path_typo_score > 0.0 {
            score += path_typo_score;
            findings.extend(path_typo_findings);
        }
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
            let effective_url =
                crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                    .unwrap_or_else(|| link.url.clone());
            let link_text_empty = link
                .text
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty);
            if link_text_empty
                && (is_probable_non_clickable_render_asset_url(&effective_url)
                    || is_probable_opaque_mail_callback_url(&effective_url))
                && !has_content_override_params(&effective_url)
            {
                continue;
            }

            let (url_score, findings) =
                analyze_url_with_anchor_context(&link.url, !link_text_empty);
            if url_score > 0.0 {
                total_score += url_score;
                suspicious_urls.push(link.url.clone());
                for (desc, category) in findings {
                    categories.push(category);
                    evidence.push(Evidence {
                        description: desc,
                        location: Some("links".to_string()),
                        snippet: Some(if link.url.len() > 120 {
                            // UTF-8 safe truncation: never split a multi-byte character
                            format!("{}...", link.url.get(..120).unwrap_or(&link.url))
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
            if is_recipient_metadata_url(&effective_url_lower) {
                continue;
            }
            let link_domain = extract_domain_from_url(&effective_url_lower);
            let is_trusted = link_domain
                .as_ref()
                .is_some_and(|d| crate::modules::link_scan::is_trusted_url_domain(d));
            if is_trusted
                && !link_domain
                    .as_deref()
                    .is_some_and(crate::modules::link_scan::is_shared_hosting_platform)
            {
                continue;
            }
            let has_recipient = ctx.session.rcpt_to.iter().any(|rcpt| {
                let rcpt_lower = rcpt.to_lowercase();
                let decoded_url = crate::modules::common::percent_decode(&effective_url_lower);
                if decoded_url.contains(&rcpt_lower)
                    || decoded_url.contains(&rcpt_lower.replace('@', "%40"))
                {
                    return true;
                }

                // Targeted campaigns increasingly embed a digest rather than
                // the clear-text mailbox.  Check both common cryptographic
                // encodings against the URL after percent decoding.
                let sha1_hex = hex_digest::<Sha1>(&rcpt_lower);
                let sha256_hex = hex_digest::<Sha256>(&rcpt_lower);
                decoded_url.contains(&sha1_hex) || decoded_url.contains(&sha256_hex)
            });
            if has_recipient {
                total_score += 0.35;
                categories.push("recipient_in_url".to_string());
                evidence.push(Evidence {
                    description: "URL contains recipient email or a SHA-1/SHA-256 mailbox digest (targeted credential phishing)".to_string(),
                    location: Some("links".to_string()),
                    snippet: Some(if effective_url.len() > 120 {
                        // UTF-8 safe truncation: never split a multi-byte character
                        format!("{}...", effective_url.get(..120).unwrap_or(&effective_url))
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
                if is_probable_opaque_mail_callback_url(&effective_url) {
                    continue;
                }
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
                                description: format!(
                                    "URL subdomain mimics organization domain '{}': {}",
                                    org, host
                                ),
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
                if is_probable_opaque_mail_callback_url(&effective_url) {
                    continue;
                }
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
        let qr_lure_context = has_qr_lure_context(&email_context);

        if keyword_context {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
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
                    .is_some_and(domain_matches_official_login_suffix)
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

        if qr_lure_context {
            for link in links {
                let effective_url =
                    crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if is_probable_schema_reference_url(&effective_url) {
                    continue;
                }
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
                let effective_lower = effective_url.to_lowercase();
                // Decode one percent-encoding layer so obfuscated login/oauth
                // URLs cannot slip past the structure checks.
                let effective_decoded =
                    crate::modules::common::percent_decode(&effective_lower).to_lowercase();
                if contains_any_suspicious_path_keywords(&effective_decoded)
                    || url_looks_like_oauth_flow(&effective_decoded)
                    || url_looks_like_device_code_flow(&effective_decoded)
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
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
                let effective_lower = effective_url.to_lowercase();
                // Decode one percent-encoding layer so obfuscated barrier/login
                // URLs cannot slip past the structure checks.
                let effective_decoded =
                    crate::modules::common::percent_decode(&effective_lower).to_lowercase();
                if url_looks_like_auth_barrier(&effective_decoded)
                    && (contains_any_suspicious_path_keywords(&effective_decoded)
                        || url_looks_like_oauth_flow(&effective_decoded)
                        || url_looks_like_device_code_flow(&effective_decoded))
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

    fn make_ctx_with_body(
        link: &str,
        body_text: Option<&str>,
        subject: Option<&str>,
    ) -> SecurityContext {
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
            phishing_keywords: keywords
                .iter()
                .map(|keyword| normalize_text(keyword))
                .collect(),
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
    fn test_preference_url_recipient_digest_is_marketing_metadata() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let digest = hex_digest::<Sha256>("victim@example.com");
        let url =
            format!("https://connect.acams.org/set-user-preferences-SC?hea={digest}&elq=campaign");

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));

        assert!(
            !result.categories.contains(&"recipient_in_url".to_string()),
            "preference metadata must not become credential evidence: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_login_url_recipient_digest_remains_targeting_evidence() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let digest = hex_digest::<Sha256>("victim@example.com");
        let url = format!("https://evil.example/login?hea={digest}");

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));

        assert!(
            result.categories.contains(&"recipient_in_url".to_string()),
            "recipient digest on a login endpoint must remain targeting evidence: {:?}",
            result.categories
        );
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
    fn test_bootcdn_service_label_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://cdn.bootcdn.net/ajax/libs/normalize/8.0.1/normalize.min.css");

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "BootCDN is a consonant-heavy service label, not a DGA: {:?}",
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

        assert!(
            result.categories.is_empty(),
            "static cloud asset should be ignored: {:?}",
            result.categories
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_gateway_wrapped_showimg_asset_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://ddei3-0-ctp.asiainfo-sec.com:443/wis/clicktime/v1/query?url=http%3a%2f%2fhome.sumscope.com%3a8050%2fportal%2fsendcloud%2fshowImg%3fid%3d74916bf1ba5d4f7f9731941883c1ffc0&umid=test&auth=test",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "gateway-wrapped non-clickable render assets should be ignored: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_cloudses_callback_webhook_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://1254335589-hk.callback.cloudses.com/api/webhook?upn=eb4ffc552935405db76234bb95083795f5831773d61927b5570fc6a831840ab1e14a24f90146ee0acaa8686e500ef2d19b18f996d9bd793495d67541b7d8a00231607ea8ae2fad80dcd113e71697a8ac2304bb479066ea23679c0ec3543cb6f2d824b17c1975aa08cc55e23ac9a94d16a4563e9298a6311f9d03143bc0b68f97b35b1ed43efa99779fd84e2b5c04f28e98a37bafbdc2f29dbfada478edc0fd48009894dc0c55df9eb4c5616bd93d42e49d9d57d20952d8b2535c7114ccd935a29b7eb38020056d02e9cb6d8f2219ca7aec3deddc123165c20c194e9d1cea8538160e652b7ec0018d2beb47d6740482cba4cf66bd443f07f2e42353dd4eb477a7261775245e32b1253bb8b1c8e98e8fd323f54bd8629fc625815dbe07040d8a5a0a8a9cf27f9fba890a63b682546f23cb40999b8abb70119612d759d5431793df9d18bdbb7a436cf4d41510aed45a9463e49c52b94d293c387d162367732cc814a05710f72728d612af8ced3ea0fb7dcd",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "opaque cloudses callback URLs should skip structural link heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_schema_reference_url_is_ignored() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("http://schemas.microsoft.com/office/2004/12/omml");

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "namespace/schema references should not be treated as user-facing links: {:?}",
            result.categories
        );
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
    fn test_sendcloud_tracking_domain_is_not_marked_as_dga_when_seeded_safe() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::from([
            "sendcloud.net".to_string(),
        ])));
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://sctrack.sendcloud.net/track/open2/eNptjsEKwjAQRP8leExCts0mm5v_IVLSbYqtmoJpDyr-uy09eJG5DPOGYU4VgPcohZBiNc6agJYw2AYAA7hm5w1ZD7qwAqOCAkIFjtSQ22nJnTm042t8xiNzbPky5Kh5ugtpVok-3kraxsFrNNpZDVCLX74h7gkt1FQRIdvkGIld7QJWgVKHe6vw_Ih81SXljm_T0umcZiHfH7k_lTVJ8ffI-Qtx8j7M.gif",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "seeded safe tracking domains should not trip DGA heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_qr_to_login_chain_requires_real_qr_lure_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx_with_body(
            "https://www.swift.com/myswift/billing/direct-debit",
            Some(
                "Please review your invoice and settle the overdue amount through the billing portal.",
            ),
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"qr_to_login_chain".to_string()),
            "billing/login links without any QR lure context should not trip QR-chain detection: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_login_landing_page_still_has_structural_path_signal() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) =
            analyze_url("https://pro.qcc.com/login?path=investigation/automation-check");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path")
        );
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
        let (_, findings) =
            analyze_url("https://product-support.chaitin.cn/message/receive?id=12345");

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
            result
                .categories
                .contains(&"device_code_phishing".to_string()),
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
            !result
                .categories
                .contains(&"device_code_phishing".to_string()),
            "device-code URL alone should not trip the dynamic-keyword gate: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_business_card_profile_path_is_not_oauth_flow() {
        assert!(!url_looks_like_oauth_flow(
            "https://work.weixin.qq.com/wework_admin/user/h5/qqmail_user_card/vc123?from=myprofile"
        ));
        assert!(url_looks_like_oauth_flow(
            "https://login.example.com/oauth2/authorize?client_id=abc&scope=openid"
        ));
    }

    #[test]
    fn qq_ftn_download_url_is_clean_in_link_content_analysis() {
        let (score, findings) = analyze_url(
            "https://wx.mail.qq.com/ftn/download?func=3&k=opaque-download-token&key=opaque-download-token&code=opaque-code&from=",
        );

        assert_eq!(score, 0.0);
        assert!(findings.is_empty(), "findings={findings:?}");
    }

    #[test]
    fn aliyun_directmail_trace_url_is_clean_in_link_content_analysis() {
        let (score, findings) = analyze_url(
            "https://dm-cn.aliyuncs.com/trace/v1/report?bid=1&mf=sender%40mail.example&msgid=id&to=recipient%40example.com&tag=opentag&tid=&sign=opaque-sign",
        );

        assert_eq!(score, 0.0);
        assert!(findings.is_empty(), "findings={findings:?}");
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

    #[test]
    fn test_gateway_without_extractable_target_still_runs_structural_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Mail security gateway domain whose query carries no valid embedded
        // target URL: unwrapping fails, so structural checks must still run.
        let (_, findings) =
            analyze_url("https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?token=abc123");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "gateway URL without a valid embedded target must not be exempted: {:?}",
            findings
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "a gateway URL without an embedded target must not invent a destination TLD: {:?}",
            findings
        );
    }

    #[test]
    fn test_unwrapped_gateway_target_is_exempt_from_wrapper_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Successful unwrap: the wrapper's own params must not be flagged.
        let (_, findings) = analyze_url(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.example.com%2Fhome",
        );

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "unwrapped gateway target should not inherit wrapper params: {:?}",
            findings
        );
    }

    #[test]
    fn test_userinfo_url_analyzes_real_host_after_at() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC (B1-1): the hand-rolled splitter treated the userinfo segment
        // "mail.qq.com:443" as the host, so the fake trusted prefix hit
        // safe-domain logic and the real destination (evil.tk) was never
        // checked. WHATWG parsing exposes the host after `@`.
        let (_, findings) = analyze_url("http://mail.qq.com:443@evil.tk/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "at_sign_obfuscation"),
            "userinfo authority must be flagged: {:?}",
            findings
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "the real host evil.tk must drive host-based checks: {:?}",
            findings
        );
    }

    #[test]
    fn test_backslash_url_host_is_visible_to_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC (B1-2): for `http:/\evil.tk/login` the old splitter failed
        // `strip_prefix("http://")` and collapsed the host to the literal
        // string "http", blinding every host-based check. WHATWG parsing
        // normalizes `\` to `/` in special schemes, exposing evil.tk.
        let (_, findings) = analyze_url("http:/\\xkqzvwp.tk/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "backslash URL host must participate in TLD checks: {:?}",
            findings
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "backslash URL path must still be scanned: {:?}",
            findings
        );
    }

    #[test]
    fn test_unwrapped_gateway_target_itself_is_still_analyzed() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) = analyze_url(
            "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=https%3A%2F%2Fwww.cy1109.top%2F%3Ftoken%3DIPx02BJ5syULgAJjwyJngqP5wDKnhEb&auth=gateway-signature",
        );

        assert!(
            score >= 0.20,
            "target findings should be visible at low risk"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "the embedded destination token must be analyzed: {:?}",
            findings
        );
    }

    #[test]
    fn test_idn_pure_cyrillic_brand_spoof_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // All-Cyrillic "аррӏе.сом" (incl. Cyrillic TLD) has no ASCII Latin at
        // all, so the mixed-script check cannot fire; the homoglyph skeleton
        // still matches the brand "apple.com".
        let (_, findings) = analyze_url("https://аррӏе.сом/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "pure Cyrillic brand spoof should be detected: {:?}",
            findings
        );
    }

    #[test]
    fn test_external_brand_host_typosquatting_detected_realtime() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (score, findings) = analyze_url("https://microsft.com/login");
        assert!(score > 0.0);
        assert!(
            findings
                .iter()
                .any(|(_, category)| { category == "brand_typosquatting" })
        );
    }

    #[test]
    fn test_trusted_org_subdomain_is_not_external_brand_typosquatting() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "*.ccabchina.com".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        let (score, findings) = analyze_url(
            "https://ebank.ccabchina.com/mbank/wap/index.html?filuqeid=2087405200113799168#InvoiveDown/Index/Index",
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "brand_typosquatting"),
            "trusted organization subdomains must not be compared to external brands: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "deep_fragment_route"),
            "trusted first-party SPA routes must not be flagged as deep fragments: {findings:?}"
        );
        assert_eq!(
            score, 0.0,
            "trusted invoice route should have no structural score: {findings:?}"
        );

        reset_url_domain_sets();
    }

    #[test]
    fn test_trusted_cmb_newsletter_routes_are_not_typosquatting() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "*.cmbchina.com".to_string(),
            "*.cmbimg.com".to_string(),
            "*.cmbt.cn".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        for url in [
            "https://weclub.ccc.cmbchina.com/weclub/url-link?lc=AweKqgWwO9&f=mrxjgj",
            "https://cmbt.cn/c/fg2?z=3",
            "https://site.cc.cmbimg.com/Router/invoke.html?url=cmblife%3A%2F%2Fcfp%2FExchange8",
            "https://xyk.cmbchina.com/kf/MRXYGJQXDY",
        ] {
            let (score, findings) = analyze_url(url);
            assert!(
                !findings.iter().any(|(_, category)| {
                    matches!(
                        category.as_str(),
                        "brand_typosquatting" | "url_typo" | "redirect_url" | "deep_fragment_route"
                    )
                }),
                "trusted CMB URL must not produce structural false positives: {url}: {findings:?}"
            );
            assert_eq!(
                score, 0.0,
                "trusted CMB URL should have no structural score: {url}"
            );
        }

        reset_url_domain_sets();
    }

    #[test]
    fn test_fullwidth_latin_folds_to_canonical_domain_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Fullwidth Latin (U+FF41+) is mapped to ASCII by UTS-46 host
        // processing — the browser also navigates to plain "apple.com", so
        // this is the canonical domain, NOT an IDN spoof. Guard against
        // false positives: idn_homograph must not fire.
        let (_, findings) = analyze_url("https://ａｐｐｌｅ.ｃｏｍ/login");

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "fullwidth Latin folds to the canonical domain and must not be flagged: {:?}",
            findings
        );
    }

    #[test]
    fn test_idn_mixed_script_still_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Cyrillic 'а' (U+0430) mixed into an ASCII domain - pre-existing behavior.
        let (_, findings) = analyze_url("https://аpple.com/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "mixed-script domain should still be detected: {:?}",
            findings
        );
    }

    #[test]
    fn test_idn_pure_cjk_domain_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // CJK ideographs are not letter-script lookalikes and are exempt.
        let (_, findings) = analyze_url("https://清华大学.cn/");

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "pure CJK domain must not be flagged as IDN homograph: {:?}",
            findings
        );
    }

    #[test]
    fn test_qq_qlogo_render_endpoint_is_not_flagged_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) =
            analyze_url("http://thirdqq.qlogo.cn/g?b=oidb&k=avatar-token&s=100&t=1700000000");

        assert_eq!(
            score, 0.0,
            "qlogo render asset should be exempt: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "dga_random_domain"),
            "QQ avatar host is provider infrastructure, not DGA: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_path_keyword_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // %6c%6f%67%69%6e decodes to "login": before the fix the raw path
        // carried no literal keyword and the Aho-Corasick scan never fired.
        let (score, findings) = analyze_url("https://evil.example/%6c%6f%67%69%6e");

        assert!(score > 0.0);
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "percent-encoded login path must not bypass the keyword scan: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_query_param_name_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // tok%65n decodes to "token": encoded parameter names previously
        // bypassed the suspicious_query_params list entirely.
        let (_, findings) = analyze_url("https://evil.example/page?tok%65n=abc123");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "percent-encoded query parameter name must not bypass the param scan: {findings:?}"
        );
    }

    #[test]
    fn test_observed_huawei_telemetry_callbacks_have_no_content_score() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        for url in [
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/clicknum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&urlPageIndex=f7cf6546-809b-4359-b402-b04ae180817a&urlIndex=d5431c23-7909-41fa-8c8b-0541cfd1ff17&key=92e3d69690d94e58685eec9ecaf3e3e93d5d63f6716ad3543aa4caa6869b9de6",
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82",
        ] {
            let (score, findings) = analyze_url(url);
            assert_eq!(
                score, 0.0,
                "validated callback must not score: {findings:?}"
            );
            assert!(
                findings.is_empty(),
                "validated callback must not emit findings: {findings:?}"
            );
        }
    }

    #[test]
    fn test_huawei_lookalike_with_redirect_target_remains_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = "https://svc-drcn.developer.huawei.com.evil.example/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82&url=https%3A%2F%2Fevil.example%2Flogin";

        let (score, findings) = analyze_url(url);
        assert!(score > 0.0, "lookalike redirect must remain scored");
        assert!(
            findings.iter().any(|(_, category)| {
                matches!(category.as_str(), "suspicious_params" | "redirect_url")
            }),
            "lookalike redirect must remain analyzable: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_fragment_keyword_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Encoded SPA route: #%6c%6f%67%69%6e decodes to #login.
        let (_, findings) = analyze_url("https://evil.example/app#%6c%6f%67%69%6e");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "percent-encoded login fragment must not bypass the keyword scan: {findings:?}"
        );
    }

    #[test]
    fn test_qr_to_login_chain_detects_percent_encoded_login_url() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx_with_body(
            "https://evil.example/%6c%6f%67%69%6e",
            Some("您的账户存在异常，请扫码登录完成验证"),
            Some("账户安全通知"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"qr_to_login_chain".to_string()),
            "QR lure + percent-encoded login URL must be detected: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_auth_barrier_detects_percent_encoded_barrier_term() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["mailbox alert"]);
        // %63%61%70%74%63%68%61 decodes to "captcha" (an auth-barrier term);
        // only the decoded form satisfies url_looks_like_auth_barrier, so this
        // URL slipped through before the fix.
        let ctx = make_ctx_with_body(
            "https://evil.example/%63%61%70%74%63%68%61/login",
            Some("Mailbox alert"),
            Some("Mailbox alert"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"auth_barrier_url".to_string()),
            "auth-barrier URL with percent-encoded barrier term must be detected: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_double_encoded_fragment_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ①: browsers never decode the fragment — the phishing page's own
        // JS decodes #%256c%256f... (%6c%6f%67%69%6e -> "login"). Before the
        // fix the %25 check only inspected the path, so the fragment payload
        // was completely invisible.
        let (score, findings) = analyze_url("https://evil.example/app#%256c%256f%2567%2569%256e");

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoding"),
            "fragment %25 double-encoding must be flagged: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoded_payload"),
            "second-layer decode must reveal the login keyword: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_query_value_protocol_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ②: query parameter *values* were never scanned, so
        // ?next=%6A%61%76%61%73%63%72%69%70%74%3A... (= javascript:alert(1))
        // escaped every protocol check.
        let (score, findings) = analyze_url(
            "https://evil.example/landing?next=%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29",
        );

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "encoded_protocol_param"),
            "encoded javascript: in a query value must be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_double_encoded_path_payload_is_unwrapped() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ③: %256a%2561... double-encodes "javascript:". Before the fix
        // the first-layer decode produced still-encoded %6a%61... which no
        // keyword/protocol scan ever inspected.
        let (score, findings) = analyze_url(
            "https://evil.example/r/%256a%2561%2576%2561%2573%2563%2572%2569%2570%2574%253a",
        );

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoding"),
            "path %25 double-encoding must be flagged: {findings:?}"
        );
        assert!(
            findings.iter().any(|(desc, category)| {
                category == "double_encoded_payload" && desc.contains("dangerous protocol")
            }),
            "second-layer decode must reveal the javascript: protocol: {findings:?}"
        );
    }

    #[test]
    fn test_oss_content_override_cancels_static_asset_exemption() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // PoC ④: ?response-content-type=text/html rewrites the served
        // Content-Type of the stored object — the "static" .jpg URL actually
        // returns an HTML phishing page, so the static-asset exemption must
        // not apply even without anchor text. "login" in the path is the
        // second signal.
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login.jpg?response-content-type=text/html",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.threat_level >= ThreatLevel::Low,
            "override-param asset must score: {:?}",
            result
        );
        assert!(
            result
                .categories
                .contains(&"oss_content_override".to_string()),
            "content-override parameters must cancel the exemption: {:?}",
            result.categories
        );
        assert!(
            result.categories.contains(&"suspicious_path".to_string()),
            "structural checks must run once the exemption is gone: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_anchor_texted_oss_static_asset_loses_exemption() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // PoC ④b: the exemption exists for chrome-less render resources
        // (<img>/<link>/<script> src). A clickable <a> with anchor text
        // pointing at OSS "static" content is a landing-page candidate and
        // must go through structural analysis.
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            links: vec![EmailLink {
                url: "https://evil-bucket.oss-cn-hangzhou.aliyuncs.com/login/verify.jpg"
                    .to_string(),
                text: Some("点击验证您的账户".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };
        let ctx = SecurityContext::new(Arc::new(session));

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.threat_level >= ThreatLevel::Low,
            "anchor-texted asset must score: {:?}",
            result
        );
        assert!(
            result.categories.contains(&"suspicious_path".to_string()),
            "login/verify path keywords must be scored on a clickable link: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_render_asset_without_anchor_or_override_stays_exempt() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // Guard: the legitimate exemption case (no anchor text, no override
        // params) must keep working — x-oss-process is an image-processing
        // parameter, not a response-header override.
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/banner.jpg?x-oss-process=image/resize,w_600",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "plain render asset must stay exempt: {:?}",
            result.categories
        );
    }
}
