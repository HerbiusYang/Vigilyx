//! AitM (Adversary-in-the-Middle) phishing fingerprint detection module.
//!
//! Detects reverse-proxy phishing attacks (Tycoon2FA, EvilProxy, Evilginx3, etc.)
//! which proxy legitimate login pages to steal session tokens and bypass MFA.
//!
//! Detection dimensions:
//! - AitM platform domain patterns (Cloudflare Workers/Pages, known DGA styles)
//! - OAuth/SSO redirect anomalies (redirect_uri pointing to non-official domains)
//! - MFA bait text detection (urgency + MFA/2FA interception language)
//! - Reverse proxy fingerprints (Turnstile CAPTCHA, toolkit URI patterns)
//! - Suspicious login page indicators (brand impersonation on unrelated domains)

use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::RegexSet;
use tracing::debug;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::common::extract_domain_from_url;

// ---------------------------------------------------------------------------
// Constants: AitM subdomain regex patterns (not data-driven)
// ---------------------------------------------------------------------------

/// Subdomain patterns typical of AitM kits (DGA-like or toolkit-generated).
/// Checked against the full hostname, not just TLD.
static RE_AITM_SUBDOMAIN_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Long hex or alphanumeric subdomains (DGA style): >=12 hex chars
        r"^[0-9a-f]{12,}\.",
        // UUID-like subdomain labels
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.",
        // Base64-ish random subdomains (mix of upper/lower/digit, >=16 chars)
        r"^[A-Za-z0-9]{16,}\.",
        // Known phishing kit subdomain naming: login-<brand>, auth-<brand>, verify-<brand>
        r"^(login|auth|verify|secure|account|signin|sso)-[a-z]+\.",
    ])
    .expect("AITM subdomain regex compilation failed")
});

// ---------------------------------------------------------------------------
// Module struct
// ---------------------------------------------------------------------------

pub struct AitmDetectModule {
    meta: ModuleMetadata,
}

impl Default for AitmDetectModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AitmDetectModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "aitm_detect".to_string(),
                name: "AitM Phishing Detection".to_string(),
                description: "Detects Adversary-in-the-Middle reverse-proxy phishing attacks (Tycoon2FA, EvilProxy, Evilginx3, etc.)".to_string(),
                pillar: Pillar::Link,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Check if a domain matches any known AitM platform hosting suffix.
fn is_aitm_platform_domain(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    let md = module_data();
    md.get_list("aitm_platform_domain_suffixes")
        .iter()
        .any(|suffix| lower.ends_with(suffix.as_str()))
}

/// Check if a hostname has AitM-typical subdomain patterns (DGA, UUID, toolkit naming).
fn has_aitm_subdomain_pattern(hostname: &str) -> bool {
    let lower = hostname.to_ascii_lowercase();
    RE_AITM_SUBDOMAIN_PATTERNS.is_match(&lower)
}

/// Check if a domain is an official SSO provider.
fn is_official_sso_domain(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    let md = module_data();
    md.get_list("official_sso_domains")
        .iter()
        .any(|official| lower == *official || lower.ends_with(&format!(".{}", official)))
}

/// Check if a domain legitimately belongs to a brand.
fn domain_belongs_to_brand(domain: &str, legitimate_suffixes: &[&str]) -> bool {
    let lower = domain.to_ascii_lowercase();
    legitimate_suffixes
        .iter()
        .any(|suffix| lower == *suffix || lower.ends_with(&format!(".{}", suffix)))
}

/// Extract the domain from a URL, or return None.
fn url_domain(url: &str) -> Option<String> {
    let decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let unwrapped = crate::modules::link_scan::unwrap_mail_security_gateway_target(&decoded)
        .unwrap_or(decoded);
    extract_domain_from_url(&unwrapped.to_lowercase())
}

/// Extract the path+query from a URL (lowercase).
fn url_path_query(url: &str) -> Option<String> {
    let decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let unwrapped = crate::modules::link_scan::unwrap_mail_security_gateway_target(&decoded)
        .unwrap_or(decoded);
    let lower = unwrapped.to_lowercase();
    let after_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    let path_start = after_scheme.find('/')?;
    Some(after_scheme[path_start..].to_string())
}

/// Extract query parameter value by name from a URL.
fn extract_query_param<'a>(url: &'a str, param_name: &str) -> Option<&'a str> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=')
            && name.eq_ignore_ascii_case(param_name)
        {
            return Some(value);
        }
    }
    None
}

/// Percent-decode a URL component.
fn percent_decode(input: &str) -> String {
    crate::modules::common::percent_decode(input)
}

// ---------------------------------------------------------------------------
// Detection dimension: AitM domain patterns
// ---------------------------------------------------------------------------

fn detect_aitm_domain_patterns(
    links: &[vigilyx_core::models::EmailLink],
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();
    let mut flagged_domains = std::collections::HashSet::new();

    for link in links {
        let Some(domain) = url_domain(&link.url) else {
            continue;
        };

        if flagged_domains.contains(&domain) {
            continue;
        }

        // Check known AitM platform hosting
        if is_aitm_platform_domain(&domain) {
            // Also check if the URL path looks like a login/auth page
            let path = url_path_query(&link.url).unwrap_or_default();
            let md = module_data();
            let has_auth_path = md
                .get_list("aitm_toolkit_path_patterns")
                .iter()
                .any(|p| path.contains(p.as_str()));
            let has_suspicious_keywords = path.contains("login")
                || path.contains("signin")
                || path.contains("verify")
                || path.contains("auth")
                || path.contains("password")
                || path.contains("account");

            if has_auth_path || has_suspicious_keywords {
                score += 0.45;
                findings.push((
                    format!(
                        "URL hosted on AitM proxy platform ({}) with login/auth path",
                        domain
                    ),
                    "aitm_platform_login".to_string(),
                ));
            } else {
                score += 0.25;
                findings.push((
                    format!(
                        "URL hosted on known AitM proxy platform: {}",
                        domain
                    ),
                    "aitm_platform_domain".to_string(),
                ));
            }
            flagged_domains.insert(domain.clone());
        }

        // Check AitM-typical subdomain patterns
        if !flagged_domains.contains(&domain) && has_aitm_subdomain_pattern(&domain) {
            let path = url_path_query(&link.url).unwrap_or_default();
            let md = module_data();
            let has_auth_indicator = md
                .get_list("aitm_toolkit_path_patterns")
                .iter()
                .any(|p| path.contains(p.as_str()));
            if has_auth_indicator {
                score += 0.35;
                findings.push((
                    format!(
                        "URL has AitM-typical subdomain pattern with auth path: {}",
                        domain
                    ),
                    "aitm_subdomain_auth".to_string(),
                ));
                flagged_domains.insert(domain);
            }
        }
    }

    (score, findings)
}

// ---------------------------------------------------------------------------
// Detection dimension: OAuth/SSO redirect anomalies
// ---------------------------------------------------------------------------

fn detect_oauth_redirect_anomalies(
    links: &[vigilyx_core::models::EmailLink],
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    for link in links {
        let url_lower = link.url.to_lowercase();
        let decoded = url_lower
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">");
        let effective = crate::modules::link_scan::unwrap_mail_security_gateway_target(&decoded)
            .unwrap_or(decoded);

        // Check for OAuth redirect_uri parameters pointing to non-official domains
        let oauth_params = module_data();
        let oauth_redirect_params = oauth_params.get_list("oauth_redirect_params");
        for param_name in oauth_redirect_params {
            if let Some(raw_value) = extract_query_param(&effective, param_name.as_str()) {
                let decoded_value = percent_decode(raw_value);
                let redirect_domain = extract_domain_from_url(&decoded_value);

                if let Some(ref redir_domain) = redirect_domain {
                    // If the redirect target is not an official SSO domain
                    // and the main URL IS an official login page → suspicious
                    let main_domain = extract_domain_from_url(&effective);
                    let main_is_official = main_domain
                        .as_deref()
                        .is_some_and(is_official_sso_domain);

                    if main_is_official && !is_official_sso_domain(redir_domain) {
                        score += 0.40;
                        findings.push((
                            format!(
                                "OAuth redirect_uri on official SSO page points to non-official domain: {} → {}",
                                param_name, redir_domain
                            ),
                            "oauth_redirect_hijack".to_string(),
                        ));
                        break; // One finding per link
                    }

                    // Even if the main URL is not official, a redirect to AitM infra is suspicious
                    if is_aitm_platform_domain(redir_domain) {
                        score += 0.35;
                        findings.push((
                            format!(
                                "OAuth {} redirects to AitM proxy platform: {}",
                                param_name, redir_domain
                            ),
                            "oauth_redirect_to_aitm".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        // Check for multiple redirect chain indicators (common in AitM flows)
        let redirect_count = effective.matches("redirect").count()
            + effective.matches("return").count()
            + effective.matches("callback").count()
            + effective.matches("next=").count();
        if redirect_count >= 3 {
            score += 0.20;
            findings.push((
                format!(
                    "URL contains excessive redirect chain parameters ({} redirect-like terms)",
                    redirect_count
                ),
                "aitm_redirect_chain".to_string(),
            ));
        }
    }

    (score, findings)
}

// ---------------------------------------------------------------------------
// Detection dimension: MFA bait text
// ---------------------------------------------------------------------------

fn detect_mfa_bait_text(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    // Combine subject + body for text analysis
    let mut combined = String::new();
    if let Some(s) = subject {
        combined.push_str(s);
        combined.push(' ');
    }
    if let Some(bt) = body_text {
        combined.push_str(bt);
        combined.push(' ');
    }
    if let Some(bh) = body_html {
        // Strip HTML tags for keyword matching
        let stripped: String = strip_html_tags(bh);
        combined.push_str(&stripped);
    }

    let combined_lower = combined.to_lowercase();
    if combined_lower.is_empty() {
        return (score, findings);
    }

    // Check for MFA bait phrases
    let mut mfa_hits: Vec<String> = Vec::new();
    let md = module_data();
    for phrase in md.get_list("mfa_bait_phrases_en") {
        if combined_lower.contains(phrase.as_str()) {
            mfa_hits.push(phrase.clone());
        }
    }
    for phrase in md.get_list("mfa_bait_phrases_zh") {
        if combined_lower.contains(phrase.as_str()) {
            mfa_hits.push(phrase.clone());
        }
    }

    if mfa_hits.is_empty() {
        return (score, findings);
    }

    // Base score for MFA bait presence
    let mfa_base_score = (mfa_hits.len() as f64 * 0.10).min(0.30);
    score += mfa_base_score;
    findings.push((
        format!(
            "Email contains MFA/2FA bait phrases: [{}]",
            mfa_hits.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ),
        "aitm_mfa_bait".to_string(),
    ));

    // Amplify if urgency language co-occurs
    let mut urgency_hits: Vec<String> = Vec::new();
    let urgency_md = module_data();
    for phrase in urgency_md.get_list("aitm_urgency_phrases") {
        if combined_lower.contains(&phrase.to_lowercase()) {
            urgency_hits.push(phrase.clone());
        }
    }

    if !urgency_hits.is_empty() {
        score += 0.15;
        findings.push((
            format!(
                "MFA bait combined with urgency language: [{}]",
                urgency_hits.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
            "aitm_mfa_urgency".to_string(),
        ));
    }

    (score, findings)
}

/// Minimal HTML tag stripper for keyword extraction.
fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Detection dimension: Reverse proxy fingerprints
// ---------------------------------------------------------------------------

fn detect_reverse_proxy_fingerprints(
    links: &[vigilyx_core::models::EmailLink],
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    // Check URLs for AitM toolkit path patterns combined with CAPTCHA indicators
    for link in links {
        let path = url_path_query(&link.url).unwrap_or_default();
        let url_lower = link.url.to_lowercase();
        let domain = url_domain(&link.url);

        // Skip official SSO domains (they legitimately have /auth/ /login/ paths)
        if domain.as_deref().is_some_and(is_official_sso_domain) {
            continue;
        }

        let md = module_data();
        let has_toolkit_path = md
            .get_list("aitm_toolkit_path_patterns")
            .iter()
            .any(|p| path.contains(p.as_str()));

        let has_captcha_indicator = md
            .get_list("captcha_indicators")
            .iter()
            .any(|c| url_lower.contains(c.as_str()));

        // Cloudflare Turnstile + auth path on non-official domain = strong AitM signal
        if has_toolkit_path && has_captcha_indicator {
            score += 0.40;
            findings.push((
                format!(
                    "URL combines auth/login path with CAPTCHA challenge on non-official domain: {}",
                    domain.as_deref().unwrap_or("unknown")
                ),
                "aitm_captcha_auth".to_string(),
            ));
        }
    }

    // Check email body for Cloudflare Turnstile / CAPTCHA references
    // (phishing pages often use Turnstile to evade automated scanning)
    let body_combined = {
        let mut s = String::new();
        if let Some(bt) = body_text {
            s.push_str(bt);
            s.push(' ');
        }
        if let Some(bh) = body_html {
            s.push_str(bh);
        }
        s.to_lowercase()
    };

    if !body_combined.is_empty() {
        let turnstile_in_body = body_combined.contains("cf-turnstile")
            || body_combined.contains("challenges.cloudflare.com/turnstile")
            || body_combined.contains("cdn-cgi/challenge-platform");

        if turnstile_in_body {
            score += 0.25;
            findings.push((
                "Email body contains Cloudflare Turnstile CAPTCHA references (common AitM pre-gate)"
                    .to_string(),
                "aitm_turnstile_body".to_string(),
            ));
        }
    }

    (score, findings)
}

// ---------------------------------------------------------------------------
// Detection dimension: Brand impersonation on unrelated domains
// ---------------------------------------------------------------------------

fn detect_brand_impersonation_login(
    links: &[vigilyx_core::models::EmailLink],
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();
    let mut flagged_brands: std::collections::HashSet<String> = std::collections::HashSet::new();

    for link in links {
        let Some(domain) = url_domain(&link.url) else {
            continue;
        };
        let url_lower = link.url.to_lowercase();
        let path = url_path_query(&link.url).unwrap_or_default();

        let empty_vec = vec![];
        let md = module_data();
        let brands = md.get_structured("aitm_brand_impersonation_targets");
        let brand_arr = brands.and_then(|v| v.as_array()).unwrap_or(&empty_vec);
        for brand_obj in brand_arr {
            let brand_keyword = brand_obj.get("brand").and_then(|v| v.as_str()).unwrap_or("");
            let domain_values = brand_obj.get("legitimate_domains")
                .or_else(|| brand_obj.get("domains"))
                .and_then(|v| v.as_array()).unwrap_or(&empty_vec);
            let legitimate_suffixes: Vec<&str> = domain_values
                .iter()
                .filter_map(|v| v.as_str())
                .collect();

            if brand_keyword.is_empty() {
                continue;
            }
            if flagged_brands.contains(brand_keyword) {
                continue;
            }

            // Check if the URL path or subdomain contains the brand name
            let brand_in_path = path.contains(brand_keyword);
            let brand_in_subdomain = domain.contains(brand_keyword);
            let brand_in_url = url_lower.contains(brand_keyword);

            if !brand_in_url {
                continue;
            }

            // Check if the domain actually belongs to the brand
            if domain_belongs_to_brand(&domain, &legitimate_suffixes) {
                continue; // Legitimate brand domain, skip
            }

            // Brand name appears in URL but domain is not the real brand
            let has_login_indicator = path.contains("login")
                || path.contains("signin")
                || path.contains("auth")
                || path.contains("verify")
                || path.contains("password")
                || path.contains("account")
                || path.contains("sso");

            if brand_in_subdomain && has_login_indicator {
                // Strong signal: brand in subdomain + login path on unrelated domain
                score += 0.45;
                findings.push((
                    format!(
                        "Brand impersonation: '{}' in subdomain of unrelated domain {} with login path",
                        brand_keyword, domain
                    ),
                    "aitm_brand_subdomain_login".to_string(),
                ));
                flagged_brands.insert(brand_keyword.to_string());
            } else if brand_in_path && has_login_indicator {
                // Moderate signal: brand in path + login indicators
                score += 0.35;
                findings.push((
                    format!(
                        "Brand impersonation: '{}' in URL path on unrelated domain {} with login indicators",
                        brand_keyword, domain
                    ),
                    "aitm_brand_path_login".to_string(),
                ));
                flagged_brands.insert(brand_keyword.to_string());
            } else if brand_in_subdomain {
                // Weaker signal: brand in subdomain without explicit login path
                score += 0.20;
                findings.push((
                    format!(
                        "Potential brand impersonation: '{}' in subdomain of unrelated domain {}",
                        brand_keyword, domain
                    ),
                    "aitm_brand_subdomain".to_string(),
                ));
                flagged_brands.insert(brand_keyword.to_string());
            }
        }

        // Homograph detection for login URLs (Cyrillic/Greek lookalikes)
        // e.g., microsоft.com with Cyrillic 'о' (U+043E) instead of Latin 'o'
        detect_homograph_brand_in_domain(&domain, &mut score, &mut findings);
    }

    (score, findings)
}

/// Detect homograph attacks specifically targeting brand login domains.
/// Checks if the domain uses mixed scripts (Latin + Cyrillic/Greek) to impersonate brands.
fn detect_homograph_brand_in_domain(
    domain: &str,
    score: &mut f64,
    findings: &mut Vec<(String, String)>,
) {
    let normalized_domain = if domain.is_ascii() && domain.contains("xn--") {
        idna::domain_to_unicode(domain).0
    } else {
        domain.to_string()
    };

    // Only check domains that have non-ASCII characters (potential IDN homographs)
    if normalized_domain.is_ascii() {
        return;
    }

    let has_latin = normalized_domain.chars().any(|c| c.is_ascii_alphabetic());
    let has_cyrillic = normalized_domain
        .chars()
        .any(|c| ('\u{0400}'..='\u{04FF}').contains(&c));
    let has_greek = normalized_domain
        .chars()
        .any(|c| ('\u{0370}'..='\u{03FF}').contains(&c));

    if has_latin && (has_cyrillic || has_greek) {
        *score += 0.50;
        findings.push((
            format!(
                "IDN homograph attack on login domain: {} (mixed Latin + {} characters)",
                normalized_domain,
                if has_cyrillic { "Cyrillic" } else { "Greek" }
            ),
            "aitm_homograph_login".to_string(),
        ));
    }
}

// ---------------------------------------------------------------------------
// Compound signal detection
// ---------------------------------------------------------------------------

/// Check for compound AitM signals that, individually, may be weak but together
/// indicate a high-confidence AitM phishing attack.
fn detect_compound_aitm_signals(
    categories: &[String],
    _score: f64,
) -> (f64, Vec<(String, String)>) {
    let mut bonus_score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    let has_platform = categories.iter().any(|c| {
        c.starts_with("aitm_platform") || c == "aitm_subdomain_auth"
    });
    let has_mfa_bait = categories.iter().any(|c| c.starts_with("aitm_mfa"));
    let has_brand = categories.iter().any(|c| c.starts_with("aitm_brand"));
    let has_captcha = categories.iter().any(|c| c.starts_with("aitm_captcha"));
    let has_redirect = categories.iter().any(|c| {
        c == "oauth_redirect_hijack" || c == "oauth_redirect_to_aitm"
    });

    // Platform domain + MFA bait = high-confidence AitM
    if has_platform && has_mfa_bait {
        bonus_score += 0.20;
        findings.push((
            "Compound AitM signal: phishing proxy platform + MFA bait language".to_string(),
            "aitm_compound_platform_mfa".to_string(),
        ));
    }

    // Brand impersonation + CAPTCHA gate = likely Tycoon2FA
    if has_brand && has_captcha {
        bonus_score += 0.15;
        findings.push((
            "Compound AitM signal: brand impersonation + CAPTCHA gate (Tycoon2FA pattern)"
                .to_string(),
            "aitm_compound_brand_captcha".to_string(),
        ));
    }

    // OAuth redirect hijack + MFA bait = credential + session token theft
    if has_redirect && has_mfa_bait {
        bonus_score += 0.20;
        findings.push((
            "Compound AitM signal: OAuth redirect hijack + MFA bait (session token theft pattern)"
                .to_string(),
            "aitm_compound_redirect_mfa".to_string(),
        ));
    }

    // Three or more independent AitM dimensions = very high confidence
    let dimension_count = [has_platform, has_mfa_bait, has_brand, has_captcha, has_redirect]
        .iter()
        .filter(|&&v| v)
        .count();
    if dimension_count >= 3 {
        bonus_score += 0.15;
        findings.push((
            format!(
                "Multi-dimensional AitM signal convergence: {} independent indicators detected",
                dimension_count
            ),
            "aitm_multi_convergence".to_string(),
        ));
    }

    (bonus_score, findings)
}

// ---------------------------------------------------------------------------
// SecurityModule implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl SecurityModule for AitmDetectModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, _ctx: &SecurityContext) -> bool {
        true
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let links = &ctx.session.content.links;
        let subject = ctx.session.subject.as_deref();
        let body_text = ctx.session.content.body_text.as_deref();
        let body_html = ctx.session.content.body_html.as_deref();

        // Need at least links or text content to analyze
        if links.is_empty() && body_text.is_none() && body_html.is_none() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No links or text content to analyze for AitM indicators",
                duration_ms,
            ));
        }

        let mut all_evidence: Vec<Evidence> = Vec::new();
        let mut all_categories: Vec<String> = Vec::new();
        let mut total_score: f64 = 0.0;

        // Dimension 1: AitM domain patterns
        if !links.is_empty() {
            let (s, findings) = detect_aitm_domain_patterns(links);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("links".to_string()),
                    snippet: None,
                });
            }
        }

        // Dimension 2: OAuth/SSO redirect anomalies
        if !links.is_empty() {
            let (s, findings) = detect_oauth_redirect_anomalies(links);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("links".to_string()),
                    snippet: None,
                });
            }
        }

        // Dimension 3: MFA bait text
        {
            let (s, findings) = detect_mfa_bait_text(subject, body_text, body_html);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("body".to_string()),
                    snippet: None,
                });
            }
        }

        // Dimension 4: Reverse proxy fingerprints
        if !links.is_empty() || body_text.is_some() || body_html.is_some() {
            let (s, findings) = detect_reverse_proxy_fingerprints(links, body_text, body_html);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("links/body".to_string()),
                    snippet: None,
                });
            }
        }

        // Dimension 5: Brand impersonation on unrelated domains
        if !links.is_empty() {
            let (s, findings) = detect_brand_impersonation_login(links);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("links".to_string()),
                    snippet: None,
                });
            }
        }

        // Compound signal amplification
        {
            let (bonus, findings) = detect_compound_aitm_signals(&all_categories, total_score);
            total_score += bonus;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("composite".to_string()),
                    snippet: None,
                });
            }
        }

        total_score = total_score.min(1.0);
        all_categories.sort();
        all_categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            debug!(
                session_id = %ctx.session.id,
                duration_ms,
                "AitM detection: no indicators found"
            );
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "Analyzed {} links and email content, no AitM phishing indicators found",
                    links.len()
                ),
                duration_ms,
            ));
        }

        debug!(
            session_id = %ctx.session.id,
            score = total_score,
            categories = ?all_categories,
            duration_ms,
            "AitM detection: indicators found"
        );

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.80,
            categories: all_categories,
            summary: format!(
                "AitM reverse-proxy phishing indicators: {} findings across {} links",
                all_evidence.len(),
                links.len()
            ),
            evidence: all_evidence,
            details: serde_json::json!({
                "score": total_score,
                "total_links": links.len(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn reset_url_domain_sets() {
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::new()));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));
    }

    fn analyze_with_runtime(module: &AitmDetectModule, ctx: &SecurityContext) -> ModuleResult {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(module.analyze(ctx))
            .unwrap()
    }

    fn make_ctx_with_links_and_body(
        links: Vec<&str>,
        body_text: Option<&str>,
        body_html: Option<&str>,
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
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            body_html: body_html.map(str::to_string),
            links: links
                .into_iter()
                .map(|url| EmailLink {
                    url: url.to_string(),
                    text: None,
                    suspicious: false,
                })
                .collect(),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_ctx_links(links: Vec<&str>) -> SecurityContext {
        make_ctx_with_links_and_body(links, None, None, None)
    }

    // --- Dimension A: AitM domain pattern detection ---

    #[test]
    fn test_aitm_detect_workers_dev_with_login_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://abc123.workers.dev/auth/login?redirect=https://outlook.com",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_platform_login".to_string()),
            "workers.dev with auth path should trigger aitm_platform_login: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Medium);
    }

    #[test]
    fn test_aitm_detect_pages_dev_without_login_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://my-phish.pages.dev/welcome"]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_platform_domain".to_string()),
            "pages.dev should trigger aitm_platform_domain: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[test]
    fn test_aitm_detect_dga_subdomain_with_auth_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://a1b2c3d4e5f6a1b2.example.com/auth/microsoft/callback",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_subdomain_auth".to_string()),
            "DGA subdomain + auth path should trigger aitm_subdomain_auth: {:?}",
            result.categories
        );
    }

    // --- Dimension B: OAuth/SSO redirect anomaly ---

    #[test]
    fn test_aitm_detect_oauth_redirect_to_non_official_domain() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fevil-proxy.workers.dev%2Fcallback",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        let has_redirect_finding = result.categories.iter().any(|c| {
            c == "oauth_redirect_hijack" || c == "oauth_redirect_to_aitm"
        });
        assert!(
            has_redirect_finding,
            "OAuth redirect to non-official domain should trigger redirect detection: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_multiple_redirect_chain() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://evil.com/redirect?next=https://example.com&callback=x&return=y&redirect=z",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_redirect_chain".to_string()),
            "Multiple redirect parameters should trigger aitm_redirect_chain: {:?}",
            result.categories
        );
    }

    // --- Dimension C: MFA bait text ---

    #[test]
    fn test_aitm_detect_mfa_bait_english() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://example.com/verify"],
            Some("Please verify your identity. Authentication required. Enter verification code immediately."),
            None,
            Some("Security Verification Required"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_mfa_bait".to_string()),
            "English MFA bait text should trigger aitm_mfa_bait: {:?}",
            result.categories
        );
        assert!(
            result.categories.contains(&"aitm_mfa_urgency".to_string()),
            "Urgency + MFA should trigger aitm_mfa_urgency: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_mfa_bait_chinese() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://example.com/verify"],
            Some("请立即完成身份验证，您的账户需要安全认证，否则将在24小时内被冻结。"),
            None,
            Some("紧急：二次验证通知"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_mfa_bait".to_string()),
            "Chinese MFA bait text should trigger aitm_mfa_bait: {:?}",
            result.categories
        );
    }

    // --- Dimension D: Reverse proxy fingerprints ---

    #[test]
    fn test_aitm_detect_captcha_with_auth_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://evil-phish.com/auth/login?cf-turnstile=true",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_captcha_auth".to_string()),
            "CAPTCHA + auth path on non-official domain should trigger: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_turnstile_in_html_body() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://example.com/page"],
            None,
            Some("<div class=\"cf-turnstile\" data-sitekey=\"0x4AAA\"></div>"),
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_turnstile_body".to_string()),
            "Turnstile in HTML body should trigger aitm_turnstile_body: {:?}",
            result.categories
        );
    }

    // --- Dimension E: Brand impersonation on unrelated domains ---

    #[test]
    fn test_aitm_detect_microsoft_brand_in_subdomain_with_login() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://microsoft-login.evil-domain.com/auth/signin",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_brand_subdomain_login".to_string()),
            "Microsoft brand in subdomain + login path should trigger: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Medium);
    }

    #[test]
    fn test_aitm_detect_legitimate_microsoft_domain_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        // Should NOT flag legitimate Microsoft login URL
        let has_brand_finding = result
            .categories
            .iter()
            .any(|c| c.starts_with("aitm_brand"));
        assert!(
            !has_brand_finding,
            "Legitimate Microsoft domain should not trigger brand impersonation: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_homograph_domain() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        // Using Cyrillic 'о' (U+043E) in "micros\u{043E}ft"
        let ctx = make_ctx_links(vec![
            "https://micros\u{043E}ft-login.com/auth/signin",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_homograph_login".to_string()),
            "Homograph domain should trigger aitm_homograph_login: {:?}",
            result.categories
        );
    }

    // --- Compound signal detection ---

    #[test]
    fn test_aitm_detect_compound_platform_plus_mfa_bait() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://phish-page.workers.dev/auth/login"],
            Some("Please verify your identity immediately or your account will be suspended."),
            None,
            Some("Security Verification Required"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_compound_platform_mfa".to_string()),
            "Platform + MFA bait compound should trigger: {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::High,
            "Compound AitM signals should reach High: {:?}",
            result.threat_level
        );
    }

    // --- Edge cases ---

    #[test]
    fn test_aitm_detect_no_links_no_body_returns_not_applicable() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(vec![], None, None, None);

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.summary.contains("No links or text content"));
    }

    #[test]
    fn test_aitm_detect_clean_email_safe() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://www.google.com/search?q=rust"],
            Some("Hello, this is a normal business email about our quarterly report."),
            None,
            Some("Q4 Financial Report"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "Clean email should be Safe: score={:?}, categories={:?}",
            result.details.get("score"),
            result.categories
        );
    }

    // --- Official SSO domain with auth path should not trigger proxy fingerprint ---

    #[test]
    fn test_aitm_detect_official_sso_auth_path_not_flagged_as_proxy() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec![
            "https://login.microsoftonline.com/auth/login?client_id=abc",
        ]);

        let result = analyze_with_runtime(&module, &ctx);

        let has_captcha_auth = result
            .categories
            .contains(&"aitm_captcha_auth".to_string());
        assert!(
            !has_captcha_auth,
            "Official SSO domain should not trigger captcha_auth fingerprint: {:?}",
            result.categories
        );
    }
}
