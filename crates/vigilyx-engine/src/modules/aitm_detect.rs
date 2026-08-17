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
use regex::{Regex, RegexSet};
use tracing::debug;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::matcher::{
    aitm_toolkit_paths, aitm_urgency, captcha_indicators, device_code_enter_phrases,
    mfa_bait_all_locales,
};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::common::extract_domain_from_url;
use crate::modules::content_scan::html_utils::strip_html_tags;
use crate::modules::content_scan::normalize_text;

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

fn is_shared_hosting_platform(domain: &str) -> bool {
    crate::modules::link_scan::is_shared_hosting_platform(domain)
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

/// Check whether `keyword` appears in `haystack` with non-alphanumeric (or
/// string) boundaries on both sides.
///
/// Used for brand-keyword matching to avoid false positives such as the brand
/// `"line"` matching the substring inside `microsoftonline.com`. A keyword
/// embedded inside a longer alphanumeric run is rejected; only matches where
/// both surrounding characters are word boundaries (e.g. `.`, `-`, `/`, `_`,
/// end-of-string) are accepted.
///
/// Boundary judgement is Unicode-aware: a CJK / Cyrillic / Greek letter
/// adjacent to an ASCII brand name is treated as part of the same word run, so
/// e.g. brand `"line"` will not match `账号line绑定` either. ASCII byte
/// scanning is sufficient because UTF-8 guarantees that a byte-level substring
/// match aligns on `char` boundaries when the keyword itself is valid UTF-8.
fn keyword_has_word_boundary(haystack: &str, keyword: &str) -> bool {
    if keyword.is_empty() || haystack.len() < keyword.len() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let key_bytes = keyword.as_bytes();
    let max_start = bytes.len() - key_bytes.len();
    for start in 0..=max_start {
        if &bytes[start..start + key_bytes.len()] != key_bytes {
            continue;
        }
        let end = start + key_bytes.len();
        // Defensive: only consider matches that align to char boundaries.
        // For valid UTF-8 keywords this is always true, but be explicit.
        if !haystack.is_char_boundary(start) || !haystack.is_char_boundary(end) {
            continue;
        }
        let left_ok = haystack[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let right_ok = haystack[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

/// Extract the domain from a URL, or return None.
fn url_domain(url: &str) -> Option<String> {
    let decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let unwrapped =
        crate::modules::link_scan::unwrap_mail_security_gateway_target(&decoded).unwrap_or(decoded);
    extract_domain_from_url(&unwrapped.to_lowercase())
}

/// Extract the path+query from a URL (lowercase).
fn url_path_query(url: &str) -> Option<String> {
    let decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let unwrapped =
        crate::modules::link_scan::unwrap_mail_security_gateway_target(&decoded).unwrap_or(decoded);
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

        // First-party provider domains can still host attacker-controlled
        // Forms/Notion/Functions pages.  Keep a signal for auth-like paths
        // instead of inheriting the clean-domain bypass used for static URLs.
        if is_shared_hosting_platform(&domain) && !is_aitm_platform_domain(&domain) {
            let path = url_path_query(&link.url).unwrap_or_default();
            let has_auth_path = aitm_toolkit_paths().is_match(&path)
                || [
                    "login",
                    "signin",
                    "verify",
                    "password",
                    "account",
                    "credential",
                    "security",
                    "payment",
                    "invoice",
                    "oauth",
                    "session",
                ]
                .iter()
                .any(|term| path.contains(term));
            if has_auth_path {
                score += 0.35;
                findings.push((
                    format!(
                        "Attacker-controlled hosted platform URL contains authentication/lure path: {}",
                        domain
                    ),
                    "aitm_hosted_platform_auth".to_string(),
                ));
            } else {
                score += 0.12;
                findings.push((
                    format!(
                        "Link uses a shared content-hosting platform where tenant content is untrusted: {}",
                        domain
                    ),
                    "aitm_hosted_platform".to_string(),
                ));
            }
            flagged_domains.insert(domain.clone());
        }

        // Check known AitM platform hosting
        if !flagged_domains.contains(&domain) && is_aitm_platform_domain(&domain) {
            // Also check if the URL path looks like a login/auth page
            let path = url_path_query(&link.url).unwrap_or_default();
            let has_auth_path = aitm_toolkit_paths().is_match(&path);
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
                    format!("URL hosted on known AitM proxy platform: {}", domain),
                    "aitm_platform_domain".to_string(),
                ));
            }
            flagged_domains.insert(domain.clone());
        }

        // Check AitM-typical subdomain patterns
        if !flagged_domains.contains(&domain) && has_aitm_subdomain_pattern(&domain) {
            let path = url_path_query(&link.url).unwrap_or_default();
            let has_auth_indicator = aitm_toolkit_paths().is_match(&path);
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

/// Escalate a shared-hosting link only when the surrounding message supplies
/// credential-verification context.  A Forms/Docs URL by itself is common in
/// legitimate mail and remains the existing Low hosted-platform signal; the
/// combination of a tenant-controlled platform, a credential lure, and an
/// action/auth path is materially different and must cross the quarantine
/// boundary in the inline pipeline.
fn detect_hosted_platform_credential_lure(
    links: &[vigilyx_core::models::EmailLink],
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> (f64, Vec<(String, String)>) {
    let mut corpus = String::new();
    for value in [subject, body_text].into_iter().flatten() {
        corpus.push_str(value);
        corpus.push('\n');
    }
    if let Some(html) = body_html {
        corpus.push_str(&strip_html_tags(html));
    }
    let corpus = normalize_text(&corpus.to_lowercase());
    if corpus.is_empty() {
        return (0.0, Vec::new());
    }

    let has_identity = [
        "account",
        "identity",
        "credential",
        "password",
        "login",
        "sign in",
        "账户",
        "帐户",
        "身份",
        "凭据",
        "密码",
        "登录",
        "验证",
        "认证",
    ]
    .iter()
    .any(|term| corpus.contains(term));
    let has_action = [
        "click",
        "confirm",
        "verify",
        "enter",
        "complete",
        "immediately",
        "点击",
        "确认",
        "验证",
        "输入",
        "立即",
        "完成",
    ]
    .iter()
    .any(|term| corpus.contains(term));
    if !has_identity || !has_action {
        return (0.0, Vec::new());
    }

    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    let mut score = 0.0;
    for link in links {
        let Some(domain) = url_domain(&link.url) else {
            continue;
        };
        if !is_shared_hosting_platform(&domain) || !seen.insert(domain.clone()) {
            continue;
        }
        let path = url_path_query(&link.url).unwrap_or_default();
        let link_text = link.text.as_deref().unwrap_or_default().to_lowercase();
        let auth_path = [
            "login",
            "signin",
            "verify",
            "password",
            "account",
            "credential",
            "security",
            "confirm",
            "viewform",
            "oauth",
        ]
        .iter()
        .any(|term| path.contains(term) || link_text.contains(term));
        if !auth_path {
            continue;
        }

        score += 0.38;
        findings.push((
            format!(
                "Shared-hosting URL {} is paired with credential-verification language and an action/auth path",
                domain
            ),
            "aitm_hosted_credential_lure".to_string(),
        ));
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
                    let main_is_official =
                        main_domain.as_deref().is_some_and(is_official_sso_domain);

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
    links: &[vigilyx_core::models::EmailLink],
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    let mut blocks = Vec::new();
    for source in [
        subject.map(str::to_string),
        body_text.map(str::to_string),
        // Shared stripper: decodes HTML entities and handles bare '<', so
        // "&#36134;户" / unclosed-tag tricks cannot hide bait phrases.
        body_html.map(strip_html_tags),
    ]
    .into_iter()
    .flatten()
    {
        blocks.extend(
            source
                .split(['\n', '\r', '。', '！', '？', '!', '?', ';', '；'])
                .map(|block| normalize_text(&block.to_lowercase()))
                .filter(|block| !block.trim().is_empty()),
        );
    }
    // Tag stripping inserts a space at every tag boundary, so bait phrases
    // spliced by inline markup ("身份验</b>证" -> "身份验 证") still evade
    // substring matching. Push an additional whitespace-free view of each
    // block; locality semantics are preserved because compaction happens
    // per block, not across the whole body.
    let original_len = blocks.len();
    for i in 0..original_len {
        let compact: String = blocks[i].chars().filter(|c| !c.is_whitespace()).collect();
        if compact != blocks[i] {
            blocks.push(compact);
        }
    }
    for link in links {
        if let Some(text) = link.text.as_deref() {
            let normalized = normalize_text(&text.to_lowercase());
            if !normalized.trim().is_empty() {
                blocks.push(normalized);
            }
        }
    }
    if blocks.is_empty() {
        return (score, findings);
    }

    let has_auth_link = links.iter().any(|link| {
        let effective = crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
            .unwrap_or_else(|| link.url.clone());
        let Ok(parsed) = url::Url::parse(&effective) else {
            return false;
        };
        parsed.path_segments().is_some_and(|segments| {
            segments.map(str::to_ascii_lowercase).any(|segment| {
                matches!(
                    segment.as_str(),
                    "login"
                        | "log-in"
                        | "signin"
                        | "sign-in"
                        | "auth"
                        | "authenticate"
                        | "verify"
                        | "verification"
                        | "mfa"
                        | "2fa"
                        | "sso"
                        | "oauth"
                )
            })
        })
    });

    const ACTION_INSTRUCTION_TERMS: &[&str] = &[
        "please verify",
        "verify your",
        "please confirm",
        "click to",
        "click here",
        "sign in",
        "log in",
        "enter verification",
        "enter the code",
        "enter your password",
        "请验证",
        "请立即",
        "请完成",
        "点击",
        "输入验证码",
        "输入密码",
        "登录",
        "してください",
        "入力",
        "クリック",
        "로그인",
        "입력",
        "클릭",
        "введите",
        "нажмите",
        "войдите",
        "подтвердите",
        "inicie sesión",
        "ingrese",
        "clique",
        "saisissez",
        "connectez-vous",
        "geben sie",
        "anmelden",
        "أدخل",
        "انقر",
    ];
    const CREDENTIAL_ENTRY_TERMS: &[&str] = &[
        "enter verification",
        "enter the code",
        "enter your password",
        "输入验证码",
        "输入密码",
        "user_code",
        "one-time code",
        "otp",
    ];

    let mut mfa_hits = Vec::new();
    let mut urgency_hits = Vec::new();
    for block in &blocks {
        let block_mfa_hits = mfa_bait_all_locales().scan(block).distinct_patterns();
        if block_mfa_hits.is_empty() {
            continue;
        }
        let has_action_instruction = ACTION_INSTRUCTION_TERMS
            .iter()
            .any(|term| block.contains(term));
        let has_credential_entry = CREDENTIAL_ENTRY_TERMS
            .iter()
            .any(|term| block.contains(term));
        if !has_action_instruction || (!has_auth_link && !has_credential_entry) {
            continue;
        }

        mfa_hits.extend(block_mfa_hits);
        urgency_hits.extend(aitm_urgency().scan(block).distinct_patterns());
    }
    mfa_hits.sort();
    mfa_hits.dedup();
    urgency_hits.sort();
    urgency_hits.dedup();

    if mfa_hits.is_empty() {
        return (score, findings);
    }

    // Base score for MFA bait presence
    let mfa_base_score = (mfa_hits.len() as f64 * 0.10).min(0.30);
    score += mfa_base_score;
    findings.push((
        format!(
            "Email contains MFA/2FA bait phrases: [{}]",
            mfa_hits
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "aitm_mfa_bait".to_string(),
    ));

    // Amplify only when urgency occurs in the same local block as the MFA
    // instruction. Navigation text and an unrelated CTA cannot be joined.
    if !urgency_hits.is_empty() {
        score += 0.15;
        findings.push((
            format!(
                "MFA bait combined with urgency language: [{}]",
                urgency_hits
                    .iter()
                    .take(3)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "aitm_mfa_urgency".to_string(),
        ));
    }

    (score, findings)
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

        let has_toolkit_path = aitm_toolkit_paths().is_match(&path);

        let has_captcha_indicator = captcha_indicators().is_match(&url_lower);

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
        let path = url_path_query(&link.url).unwrap_or_default();

        let empty_vec = vec![];
        let md = module_data();
        let brands = md.get_structured("aitm_brand_impersonation_targets");
        let brand_arr = brands.and_then(|v| v.as_array()).unwrap_or(&empty_vec);
        for brand_obj in brand_arr {
            let brand_keyword = brand_obj
                .get("brand")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let domain_values = brand_obj
                .get("legitimate_domains")
                .or_else(|| brand_obj.get("domains"))
                .and_then(|v| v.as_array())
                .unwrap_or(&empty_vec);
            let legitimate_suffixes: Vec<&str> =
                domain_values.iter().filter_map(|v| v.as_str()).collect();

            if brand_keyword.is_empty() {
                continue;
            }
            if flagged_brands.contains(brand_keyword) {
                continue;
            }

            // Check if the URL path or subdomain contains the brand name
            // with word boundaries (avoid e.g. "line" matching microsoftonline.com).
            let brand_in_path = keyword_has_word_boundary(&path, brand_keyword);
            let brand_in_subdomain = keyword_has_word_boundary(&domain, brand_keyword);
            let brand_in_visible_text = link.text.as_deref().is_some_and(|text| {
                keyword_has_word_boundary(&text.to_ascii_lowercase(), brand_keyword)
            });
            let brand_in_url = brand_in_path || brand_in_subdomain || brand_in_visible_text;

            if !brand_in_url {
                continue;
            }

            // Check if the domain actually belongs to the brand
            if domain_belongs_to_brand(&domain, &legitimate_suffixes)
                && !(is_shared_hosting_platform(&domain)
                    && (brand_in_path || brand_in_visible_text))
            {
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
            } else if brand_in_visible_text && is_shared_hosting_platform(&domain) {
                score += 0.30;
                findings.push((
                    format!(
                        "Hosted-platform link uses brand lure text '{}' on tenant-controlled domain {}",
                        brand_keyword, domain
                    ),
                    "aitm_hosted_brand_lure".to_string(),
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
// Storm-2372 Device Code Phishing detection
// ---------------------------------------------------------------------------
//
// Microsoft OAuth Device Code Flow lets a user-side device delegate
// authentication via a short user_code shown on a second device. Storm-2372
// (named by Microsoft Threat Intelligence, observed since late 2024) abuses
// this flow:
//
//   1. Attacker initiates Device Code Flow at the legit
//      https://microsoft.com/devicelogin endpoint and receives a fresh
//      user_code (8-character alphanumeric, e.g. `BXFK7QHZ`).
//   2. Attacker emails the victim asking them to "enter this code at
//      microsoft.com/devicelogin to complete verification".
//   3. The victim — believing this is a legitimate Microsoft authentication
//      step — visits the URL (which is genuinely Microsoft) and enters the
//      code, authorizing the *attacker's* session against the victim's
//      tenant. MFA is satisfied by the victim's own browser/device.
//   4. Attacker now holds OAuth tokens that bypass MFA, used to read mail,
//      Teams, SharePoint, etc.
//
// The detection is hard because the URL is genuinely Microsoft; URL
// reputation lookups, SafeBrowsing, and homograph checks all return clean.
// The signal lives in the *combination*:
//
//   - Reference to a Device Code Flow URL (microsoft.com/devicelogin or
//     login.microsoftonline.com/...deviceauth)
//   - An 8-character user_code string in the body
//   - Imperative "enter this code" / "输入此代码" phrasing
//
// False-positive guards:
//   - If the sender domain is on a Microsoft-controlled list
//     (microsoft.com, microsoftonline.com, office.com etc.), suppress.
//     Real Microsoft notifications about devicelogin do exist (rare).
//   - Require the user_code regex to match in close vicinity (same body)
//     to the device-login URL or the enter-code phrase, not anywhere.
fn detect_device_code_phishing(
    links: &[vigilyx_core::models::EmailLink],
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
    sender_domain: Option<&str>,
) -> (f64, Vec<(String, String)>) {
    let mut score = 0.0_f64;
    let mut findings: Vec<(String, String)> = Vec::new();

    // ── Whitelist: real Microsoft sender domains ─────────────────────────
    if let Some(d) = sender_domain {
        let d = d.to_ascii_lowercase();
        const MS_DOMAINS: &[&str] = &[
            "microsoft.com",
            "microsoftonline.com",
            "office.com",
            "office365.com",
            "outlook.com",
            "azure.com",
        ];
        if MS_DOMAINS
            .iter()
            .any(|sfx| d == *sfx || d.ends_with(&format!(".{}", sfx)))
        {
            return (score, findings);
        }
    }

    // ── Build corpus ─────────────────────────────────────────────────────
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
        let stripped: String = strip_html_tags(bh);
        combined.push_str(&stripped);
    }
    // Unicode normalization (NFKC + zero-width stripping): full-width
    // letters/digits and zero-width splices must not hide the device-login
    // URL, the enter-code phrase, or the user_code itself.
    let combined_normalized = normalize_text(&combined);
    let combined_lower = combined_normalized.to_lowercase();

    // ── Signal 1: Device-login URL reference ────────────────────────────
    let device_url_in_links = links.iter().any(|link| {
        let ll = link.url.to_ascii_lowercase();
        ll.contains("microsoft.com/devicelogin")
            || ll.contains("microsoftonline.com/common/oauth2/deviceauth")
            || ll.contains("/devicelogin")
                && (ll.contains("microsoft") || ll.contains("microsoftonline"))
    });
    let device_url_in_text = combined_lower.contains("microsoft.com/devicelogin")
        || combined_lower.contains("microsoftonline.com/common/oauth2/deviceauth")
        || combined_lower.contains("aka.ms/devicelogin");
    let has_device_url = device_url_in_links || device_url_in_text;

    if has_device_url {
        score += 0.30;
        findings.push((
            "Email references Microsoft Device Code Flow login URL".to_string(),
            "device_code_login_url".to_string(),
        ));
    }

    // ── Signal 2: 8-character alphanumeric user_code ────────────────────
    // Microsoft device codes are letters + digits, 8 chars, sometimes with
    // separators (BXFK-7QHZ, "BXFK 7QHZ"). The match is case-insensitive
    // and tolerates repeated whitespace/dash separators so attackers cannot
    // evade by lowercasing the code or inserting extra spaces. All-digit
    // candidates are still rejected below (order/invoice numbers).
    static RE_USER_CODE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b([A-Z0-9]{4}[\s\-]*[A-Z0-9]{4})\b").expect("device code regex")
    });
    let mut user_codes: Vec<String> = Vec::new();
    for caps in RE_USER_CODE.captures_iter(&combined_normalized) {
        if let Some(m) = caps.get(1) {
            // Reject if all-digits (likely an order/invoice number).
            if m.as_str().chars().any(|c| c.is_ascii_alphabetic()) {
                user_codes.push(m.as_str().to_string());
            }
        }
    }
    let has_user_code = !user_codes.is_empty();

    // ── Signal 3: "enter this code" imperative phrasing ──────────────────
    // Phrase list is data-driven (seed: `device_code_enter_phrases`) so
    // ops can hot-tune wording without redeploying the engine.
    //
    // We deliberately defer the matcher invocation until at least one
    // upstream signal has fired. Building the underlying automaton on first
    // use takes ~1 ms; gating it behind upstream signals keeps the
    // not-applicable / safe path completely free of work.
    let enter_phrase_hit: Option<String> = if has_device_url || has_user_code {
        device_code_enter_phrases()
            .scan(&combined_lower)
            .first_pattern()
    } else {
        None
    };
    // A standalone eight-character identifier is common in business mail and
    // must not be labelled as a device-code attack.  Require a device-login
    // URL, or a code plus an explicit enter-code instruction, before emitting
    // the user-code signal.
    let actionable_device_context = has_device_url || (has_user_code && enter_phrase_hit.is_some());
    if actionable_device_context && has_user_code {
        score += 0.20;
        findings.push((
            format!(
                "Possible Device Code user_code present in body: {}",
                user_codes
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "device_code_user_code".to_string(),
        ));
    }
    if actionable_device_context && let Some(ref phrase) = enter_phrase_hit {
        score += 0.20;
        findings.push((
            format!(
                "Device-code enter-instruction phrase detected: '{}'",
                phrase
            ),
            "device_code_enter_phrase".to_string(),
        ));
    }

    // ── Combo escalation: all three core signals together ────────────────
    if has_device_url && has_user_code && enter_phrase_hit.is_some() {
        score += 0.20;
        findings.push((
            "Compound device-code phishing signal (Storm-2372): URL + user_code + enter-phrase"
                .to_string(),
            "device_code_phishing_combo".to_string(),
        ));
    }

    (score, findings)
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

    let has_platform = categories
        .iter()
        .any(|c| c.starts_with("aitm_platform") || c == "aitm_subdomain_auth");
    let has_mfa_bait = categories.iter().any(|c| c.starts_with("aitm_mfa"));
    let has_brand = categories.iter().any(|c| c.starts_with("aitm_brand"));
    let has_captcha = categories.iter().any(|c| c.starts_with("aitm_captcha"));
    let has_redirect = categories
        .iter()
        .any(|c| c == "oauth_redirect_hijack" || c == "oauth_redirect_to_aitm");

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
    let dimension_count = [
        has_platform,
        has_mfa_bait,
        has_brand,
        has_captcha,
        has_redirect,
    ]
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

        // Dimension 1b: tenant-controlled hosted forms/pages paired with a
        // credential lure.  This stays local and inline-safe; reputation and
        // landing-page fetches remain deferred to the asynchronous pipeline.
        {
            let (s, findings) = detect_hosted_platform_credential_lure(
                links,
                subject,
                body_text,
                body_html,
            );
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("body+links".to_string()),
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
            let (s, findings) = detect_mfa_bait_text(subject, body_text, body_html, links);
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

        // Dimension 6: Storm-2372 Device Code Phishing
        {
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|addr| addr.split('@').nth(1));
            let (s, findings) =
                detect_device_code_phishing(links, subject, body_text, body_html, sender_domain);
            total_score += s;
            for (desc, category) in findings {
                all_categories.push(category);
                all_evidence.push(Evidence {
                    description: desc,
                    location: Some("body+links".to_string()),
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

    #[test]
    fn keyword_has_word_boundary_ascii_runs_are_rejected() {
        // Embedded inside an alphanumeric run -> no boundary.
        assert!(!keyword_has_word_boundary("microsoftonline.com", "line"));
        assert!(!keyword_has_word_boundary("paypalexpress.net", "paypal"));
        assert!(!keyword_has_word_boundary("box123.example", "box"));
    }

    #[test]
    fn keyword_has_word_boundary_ascii_with_separators_match() {
        assert!(keyword_has_word_boundary("login.line.me", "line"));
        assert!(keyword_has_word_boundary("paypal-login.com", "paypal"));
        assert!(keyword_has_word_boundary("/auth/box/signin", "box"));
        assert!(keyword_has_word_boundary("paypal", "paypal"));
    }

    #[test]
    fn keyword_has_word_boundary_unicode_neighbours_block_match() {
        // CJK adjacent to an ASCII brand should not produce a boundary match,
        // because CJK letters are alphanumeric in Unicode.
        assert!(!keyword_has_word_boundary("账号line绑定", "line"));
        assert!(!keyword_has_word_boundary("paypalパスワード", "paypal"));
        // Cyrillic letter neighbour should also block.
        assert!(!keyword_has_word_boundary("приlineсвет", "line"));
    }

    #[test]
    fn keyword_has_word_boundary_punctuation_neighbours_match() {
        // Punctuation / separators on either side should produce boundaries.
        assert!(keyword_has_word_boundary("登录-line-入口", "line"));
        assert!(keyword_has_word_boundary(
            "https://支付宝.com/login",
            "支付宝"
        ));
        assert!(keyword_has_word_boundary("paypal/checkout", "paypal"));
    }

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
            result
                .categories
                .contains(&"aitm_platform_login".to_string()),
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
            result
                .categories
                .contains(&"aitm_platform_domain".to_string()),
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
            result
                .categories
                .contains(&"aitm_subdomain_auth".to_string()),
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

        let has_redirect_finding = result
            .categories
            .iter()
            .any(|c| c == "oauth_redirect_hijack" || c == "oauth_redirect_to_aitm");
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
            result
                .categories
                .contains(&"aitm_redirect_chain".to_string()),
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
            Some(
                "Please verify your identity. Authentication required. Enter verification code immediately.",
            ),
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

    #[test]
    fn test_separated_recertification_and_registration_cta_do_not_form_aitm_bait() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://connect.acams.org/signin"],
            Some("重新认证\n本月培训活动席位有限，立即报名。"),
            None,
            Some("ACAMS 八月活动通讯"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"aitm_mfa_bait".to_string()),
            "distant navigation and CTA text must not be combined: {:?}",
            result.categories
        );
        assert!(
            !result.categories.contains(&"aitm_mfa_urgency".to_string()),
            "distant urgency must not amplify an MFA term: {:?}",
            result.categories
        );
    }

    // --- Dimension D: Reverse proxy fingerprints ---

    #[test]
    fn test_aitm_detect_captcha_with_auth_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://evil-phish.com/auth/login?cf-turnstile=true"]);

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
            result
                .categories
                .contains(&"aitm_turnstile_body".to_string()),
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
        let ctx = make_ctx_links(vec!["https://microsoft-login.evil-domain.com/auth/signin"]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"aitm_brand_subdomain_login".to_string()),
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
        let ctx = make_ctx_links(vec!["https://micros\u{043E}ft-login.com/auth/signin"]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"aitm_homograph_login".to_string()),
            "Homograph domain should trigger aitm_homograph_login: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_short_brand_abc_does_not_match_random_domain() {
        // Brand "abc" (Agricultural Bank of China) is 3 chars and would
        // false-positive on any URL containing the substring "abc" before
        // the word-boundary fix. The legitimate domain `taobaoabc.com`
        // (synthetic) is unrelated to ABC bank, has the substring `abc` in
        // its second-level label but not as a separate word.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://login.taobaoabc.com/auth/signin"]);

        let result = analyze_with_runtime(&module, &ctx);
        let has_brand_finding = result
            .categories
            .iter()
            .any(|c| c.starts_with("aitm_brand"));
        assert!(
            !has_brand_finding,
            "Brand 'abc' must not match the substring inside taobaoabc.com: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_short_brand_line_does_not_match_microsoft_online() {
        // Regression test for the original word-boundary bug: brand "line"
        // (the LINE messenger) was matching microsoftonline.com because the
        // detection used a raw substring contains. This test guards that
        // fix at the *module* level (the helper-only test only proves the
        // boundary helper, not its integration into detect_brand_impersonation).
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://account.microsoftonline.com/users/login"]);

        let result = analyze_with_runtime(&module, &ctx);
        let line_brand_finding = result
            .categories
            .iter()
            .any(|c| c.starts_with("aitm_brand"));
        assert!(
            !line_brand_finding,
            "Brand 'line' must not match microsoftonline.com substring: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_paypal_brand_in_phishing_subdomain() {
        // Word-boundary case: paypal in a subdomain of an unrelated host
        // should still trigger brand impersonation. The boundary helper
        // accepts this because `paypal` is bordered by `.` on both sides.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://paypal.evil-host.example/account/verify"]);

        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result
                .categories
                .iter()
                .any(|c| c.starts_with("aitm_brand")),
            "paypal in subdomain of unrelated host should trigger brand impersonation: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_brand_path_login_signal() {
        // Brand in path (not subdomain) on an unrelated host with login
        // indicators should trigger `aitm_brand_path_login`.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://random-host.example/paypal/login"]);

        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result
                .categories
                .contains(&"aitm_brand_path_login".to_string()),
            "Brand in path with login indicator should trigger aitm_brand_path_login: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_aitm_detect_multiple_brands_in_one_url_only_flagged_once_per_brand() {
        // The detect loop deduplicates flagged brands via `flagged_brands`
        // HashSet. Two distinct brands in the same URL should still produce
        // two separate findings, but the same brand in subdomain + path
        // should not double-count.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        // Both `paypal` (subdomain) and `microsoft` (path) on an unrelated
        // host. We expect at least one brand finding and no duplicate
        // findings for the same brand.
        let ctx = make_ctx_links(vec!["https://paypal.evil-host.example/microsoft/login"]);

        let result = analyze_with_runtime(&module, &ctx);
        let brand_findings: Vec<&String> = result
            .categories
            .iter()
            .filter(|c| c.starts_with("aitm_brand"))
            .collect();
        assert!(
            !brand_findings.is_empty(),
            "expected at least one brand finding for paypal+microsoft URL: {:?}",
            result.categories
        );
        // Distinct categories shouldn't have any duplicates for the same brand.
        // (The flagged_brands HashSet ensures only one finding per brand.)
        let mut seen = std::collections::HashSet::new();
        for cat in &brand_findings {
            assert!(
                seen.insert((*cat).clone()),
                "duplicate brand category {cat:?} in {brand_findings:?}"
            );
        }
    }

    #[test]
    fn test_aitm_detect_legitimate_paypal_subdomain_not_flagged() {
        // Mirror of the microsoft legitimate-domain test, but for a
        // different brand. Confirms `domain_belongs_to_brand` correctly
        // accepts paypal.com and any subdomain thereof.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_links(vec!["https://www.paypal.com/signin?country.x=US"]);

        let result = analyze_with_runtime(&module, &ctx);
        let has_brand_finding = result
            .categories
            .iter()
            .any(|c| c.starts_with("aitm_brand"));
        assert!(
            !has_brand_finding,
            "Legitimate paypal.com domain should not trigger brand impersonation: {:?}",
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
            result
                .categories
                .contains(&"aitm_compound_platform_mfa".to_string()),
            "Platform + MFA bait compound should trigger: {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::High,
            "Compound AitM signals should reach High: {:?}",
            result.threat_level
        );
    }

    #[test]
    fn hosted_form_with_credential_lure_crosses_medium_boundary() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://docs.google.com/forms/d/e/attacker/viewform"],
            Some("请立即确认您的账户信息，输入密码完成身份验证。"),
            None,
            Some("账户安全验证通知"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"aitm_hosted_credential_lure".to_string()),
            "hosted form credential lure should be explicit: {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::Medium,
            "hosted credential lure must not remain Low: {:?} ({})",
            result.threat_level,
            result.details["score"]
        );
    }

    #[test]
    fn ordinary_hosted_document_without_lure_remains_safe_or_low() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_with_links_and_body(
            vec!["https://docs.google.com/document/d/quarterly-report"],
            Some("Please review the quarterly report and add comments."),
            None,
            Some("Q3 report"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(!result.categories.contains(&"aitm_hosted_credential_lure".to_string()));
        assert!(result.threat_level <= ThreatLevel::Low);
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

        let has_captcha_auth = result.categories.contains(&"aitm_captcha_auth".to_string());
        assert!(
            !has_captcha_auth,
            "Official SSO domain should not trigger captcha_auth fingerprint: {:?}",
            result.categories
        );
    }

    // ── Storm-2372 Device Code Phishing tests ────────────────────────────

    /// Build a context with a sender (mail_from) so the device-code
    /// whitelist can be exercised. The other test-helpers above don't
    /// expose mail_from, so this one inlines the EmailSession construction.
    fn make_ctx_device_code(
        sender: &str,
        subject: Option<&str>,
        body_text: Option<&str>,
        links: Vec<&str>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.5".to_string(),
            54321,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(sender.to_string());
        session.subject = subject.map(str::to_string);
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
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

    #[test]
    fn test_device_code_phishing_classic_storm2372_fires() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "Hello,\nTo finish setting up your new device, please \
                    visit https://microsoft.com/devicelogin and enter this \
                    code: BXFK7QHZ to complete verification. The code \
                    expires in 15 minutes.";
        let ctx = make_ctx_device_code(
            "it-helpdesk@random-cdn-host.tld",
            Some("Action required: complete device sign-in"),
            Some(body),
            vec!["https://microsoft.com/devicelogin"],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"device_code_login_url".to_string()),
            "must detect device-login URL, got {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"device_code_user_code".to_string()),
            "must detect user_code, got {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"device_code_enter_phrase".to_string()),
            "must detect enter-phrase, got {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"device_code_phishing_combo".to_string()),
            "must escalate to combo, got {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::High,
            "Storm-2372 combo must reach High, got {:?}",
            result.threat_level
        );
    }

    #[test]
    fn test_device_code_phishing_chinese_lure_fires() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "您好，IT 部门提示请访问 microsoft.com/devicelogin, \
                    请输入此代码 ABCD-1234 完成设备验证, 代码 15 分钟内有效。";
        let ctx = make_ctx_device_code(
            "noreply@some-random-host.cn",
            Some("设备登录完成提醒"),
            Some(body),
            vec![],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"device_code_login_url".to_string())
                && result
                    .categories
                    .contains(&"device_code_user_code".to_string())
                && result
                    .categories
                    .contains(&"device_code_enter_phrase".to_string()),
            "Chinese lure must hit all three core signals, got {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::High);
    }

    #[test]
    fn test_device_code_phishing_real_microsoft_sender_suppressed() {
        // A genuine Microsoft notification mentioning devicelogin must
        // NOT trigger device_code_* categories — sender whitelist short
        // circuits the entire detector.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "We noticed a sign-in to your account on a new device. \
                    To complete sign-in please visit \
                    https://microsoft.com/devicelogin and enter this code: \
                    ABCD1234.";
        let ctx = make_ctx_device_code(
            "account-security-noreply@accountprotection.microsoft.com",
            Some("Device sign-in"),
            Some(body),
            vec!["https://microsoft.com/devicelogin"],
        );

        let result = analyze_with_runtime(&module, &ctx);

        let any_device_cat = result
            .categories
            .iter()
            .any(|c| c.starts_with("device_code_"));
        assert!(
            !any_device_cat,
            "Real Microsoft sender must suppress device_code categories, got {:?}",
            result.categories
        );
    }

    #[test]
    fn test_device_code_phishing_url_only_no_combo() {
        // Just a microsoft.com/devicelogin reference without code or
        // enter-phrase: scores Low only (single signal, no combo).
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "FYI: Microsoft has a device-login flow at \
                    microsoft.com/devicelogin.";
        let ctx = make_ctx_device_code(
            "blog@tech-news.tld",
            Some("Tech newsletter"),
            Some(body),
            vec![],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"device_code_login_url".to_string()),
            "URL alone should still fire URL category, got {:?}",
            result.categories
        );
        assert!(
            !result
                .categories
                .contains(&"device_code_phishing_combo".to_string()),
            "single URL must not escalate to combo, got {:?}",
            result.categories
        );
    }

    #[test]
    fn test_device_code_phishing_user_code_rejects_all_digit_strings() {
        // Order numbers / invoice IDs are 8-digit strings without any
        // letters — must not be flagged as user_code.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "Your order #12345678 has shipped.";
        let ctx = make_ctx_device_code(
            "shipping@store.example",
            Some("Order shipped"),
            Some(body),
            vec![],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"device_code_user_code".to_string()),
            "all-digit order number must not be classified as user_code, got {:?}",
            result.categories
        );
    }

    #[test]
    fn test_device_code_standalone_alphanumeric_reference_is_not_phishing() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let ctx = make_ctx_device_code(
            "billing@vendor.example",
            Some("Order reference"),
            Some("Your order reference is 75D857C4. No action is required."),
            vec![],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"device_code_user_code".to_string()),
            "standalone order/reference code must not be classified as device-login evidence: {:?}",
            result.categories
        );
    }

    // ── Normalization evasion regression tests ───────────────────────────

    #[test]
    fn test_mfa_bait_fullwidth_and_zero_width_evasion_fires() {
        // Evasion PoC: full-width Latin letters and a zero-width splice
        // inside "authentication" previously bypassed the lowercase-only
        // Aho-Corasick corpus. normalize_text folds/strips them.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "Ｖｅｒｉｆｙ ｙｏｕｒ ｉｄｅｎｔｉｔｙ now. \
                    Additional authenticati\u{200B}on required to keep your mailbox active.";
        let ctx = make_ctx_with_links_and_body(
            vec!["https://example.com/verify"],
            Some(body),
            None,
            Some("Security notice"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_mfa_bait".to_string()),
            "full-width / zero-width MFA bait must trigger aitm_mfa_bait: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_device_code_lowercase_and_wide_separator_fires() {
        // Evasion PoC: lowercase user_code with a double-space separator and
        // a zero-width splice inside the device-login URL previously slipped
        // past the uppercase-only, single-separator regex and the raw
        // substring URL check.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        let body = "Hello, to finish setup please visit \
                    microsoft.com/devicelo\u{200B}gin and enter this code: \
                    bxfk  7qhz to complete verification. The code expires soon.";
        let ctx = make_ctx_device_code(
            "it-helpdesk@random-cdn-host.tld",
            Some("Action required: complete device sign-in"),
            Some(body),
            vec![],
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"device_code_login_url".to_string()),
            "zero-width-spliced device-login URL must be detected, got {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"device_code_user_code".to_string()),
            "lowercase multi-space user_code must be detected, got {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"device_code_enter_phrase".to_string()),
            "enter-phrase must be detected, got {:?}",
            result.categories
        );
    }

    #[test]
    fn test_mfa_bait_spliced_by_html_tags_and_entities_fires() {
        // PoC: the old private HTML stripper left entities undecoded and
        // (like any tag stripper) split keywords across inline tags, so
        // "身份验</b>证" and "验证&#30721;" both slipped past the MFA bait
        // scan. The shared stripper decodes entities; a per-block
        // whitespace-free view restores tag-spliced phrases.
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = AitmDetectModule::new();
        // "身份验</b>证" splices 身份验证 (mfa bait); "验证&#30721;" is an
        // entity-encoded 验证码 (mfa bait + credential entry "输入验证码").
        let html = "<p>安全提醒：您的登录会话需要复核，请立即完成<b>身份验</b>证并输入<b>验证&#30721;</b>以保障账户安全。</p>";
        let ctx = make_ctx_with_links_and_body(vec![], None, Some(html), None);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"aitm_mfa_bait".to_string()),
            "tag-spliced / entity-encoded MFA bait must be detected: {:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::Low,
            "two MFA bait hits must reach Low, got {:?}",
            result.threat_level
        );
    }
}
