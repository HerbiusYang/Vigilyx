//! Landing-page fetch and analysis module.
//!
//! Follows a small number of candidate URLs to detect:
//! - device-code phishing landing pages
//! - CAPTCHA / auth-barrier gated credential harvesters
//! - QR-to-login chains that only become obvious after redirection

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

use super::common::{extract_domain_from_url, is_probable_cloud_asset_url};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::fetcher::{FetchConfig, FetchResult, UrlFetcher};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

const MAX_CANDIDATE_URLS: usize = 2;
const AUTH_BARRIER_TERMS: &[&str] = &[
    "captcha",
    "turnstile",
    "cloudflare",
    "verify you are human",
    "prove you are human",
    "human verification",
    "security check",
    "checking your browser",
    "one more step",
];
const DEVICE_CODE_PAGE_TERMS: &[&str] = &[
    "microsoft.com/devicelogin",
    "device code",
    "device login",
    "enter code",
    "enter the code",
    "code provided to you",
];
const OAUTH_URL_TERMS: &[&str] = &[
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

pub struct LandingPageScanModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
}

impl Default for LandingPageScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LandingPageScanModule {
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
                id: "landing_page_scan".to_string(),
                name: "Landing Page Scan".to_string(),
                description: "Fetch and analyze suspicious landing pages for device-code and CAPTCHA-gated phishing"
                    .to_string(),
                pillar: Pillar::Link,
                depends_on: vec!["link_scan".to_string(), "link_content".to_string()],
                timeout_ms: 12_000,
                is_remote: true,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            phishing_keywords,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct LureSignals {
    keyword_context: bool,
}

#[derive(Default)]
struct PageAssessment {
    score: f64,
    categories: Vec<String>,
    evidence: Vec<Evidence>,
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

fn derive_lure_signals_from_text(text: &str, keywords: &[String]) -> LureSignals {
    let normalized = normalize_text(text);
    LureSignals {
        keyword_context: keywords.iter().any(|keyword| normalized.contains(keyword)),
    }
}

fn derive_lure_signals(ctx: &SecurityContext, keywords: &[String]) -> LureSignals {
    derive_lure_signals_from_text(&build_email_context(ctx), keywords)
}

fn unwrap_candidate_url(url: &str) -> Option<String> {
    let effective = crate::modules::link_scan::unwrap_mail_security_gateway_target(url)
        .unwrap_or_else(|| url.to_string());
    if effective.starts_with("http://") || effective.starts_with("https://") {
        Some(effective)
    } else {
        None
    }
}

fn candidate_priority(url: &str, signals: &LureSignals) -> u8 {
    let lower = url.to_lowercase();
    let mut score = 0u8;
    if contains_any(&lower, DEVICE_CODE_PAGE_TERMS) {
        score += 5;
    }
    if contains_any(&lower, OAUTH_URL_TERMS) {
        score += 3;
    }
    if contains_any(&lower, AUTH_BARRIER_TERMS) {
        score += 4;
    }
    if signals.keyword_context {
        score += 1;
    }
    score
}

fn collect_candidate_urls(ctx: &SecurityContext, signals: &LureSignals) -> Vec<String> {
    let mut ranked = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for link in &ctx.session.content.links {
        let Some(url) = unwrap_candidate_url(&link.url) else {
            continue;
        };
        if is_probable_cloud_asset_url(&url) || !seen.insert(url.clone()) {
            continue;
        }
        let priority = candidate_priority(&url, signals);
        if priority == 0 && !signals.keyword_context {
            continue;
        }
        ranked.push((priority, url));
    }

    ranked.sort_by(|(left_score, _), (right_score, _)| right_score.cmp(left_score));
    ranked
        .into_iter()
        .take(MAX_CANDIDATE_URLS)
        .map(|(_, url)| url)
        .collect()
}

fn assess_fetched_page(
    original_url: &str,
    fetch: &FetchResult,
    signals: &LureSignals,
) -> PageAssessment {
    let mut assessment = PageAssessment::default();
    if fetch.error.is_some() {
        return assessment;
    }

    let final_url_lower = fetch.final_url.to_lowercase();
    let title_lower = fetch
        .page_title
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    let page_text_lower = fetch.page_text.to_lowercase();
    let combined = format!("{} {} {}", final_url_lower, title_lower, page_text_lower);
    let has_login_form =
        fetch.form_analysis.has_login_form || fetch.form_analysis.password_fields > 0;
    let has_auth_barrier = contains_any(&combined, AUTH_BARRIER_TERMS);
    let has_device_code = contains_any(&combined, DEVICE_CODE_PAGE_TERMS);
    let has_oauth_flow = contains_any(&combined, OAUTH_URL_TERMS);
    let original_domain = extract_domain_from_url(original_url);
    let final_domain = extract_domain_from_url(&fetch.final_url);
    let redirected_to_different_domain = original_domain != final_domain;
    let lands_on_official_login = final_domain
        .as_deref()
        .is_some_and(|domain| domain_matches_suffix(domain, OFFICIAL_LOGIN_SUFFIXES));

    if signals.keyword_context && has_device_code {
        assessment.score += 0.45;
        assessment
            .categories
            .push("device_code_landing".to_string());
        assessment.evidence.push(Evidence {
            description: format!(
                "Landing page {} matches device-code phishing flow",
                fetch.final_url
            ),
            location: Some("landing_page".to_string()),
            snippet: fetch
                .page_title
                .clone()
                .or_else(|| Some(fetch.final_url.clone())),
        });
    } else if has_device_code && (lands_on_official_login || has_oauth_flow) {
        assessment.score += 0.25;
        assessment.categories.push("device_code_flow".to_string());
        assessment.evidence.push(Evidence {
            description: format!(
                "Landing page {} exposes device-code sign-in workflow",
                fetch.final_url
            ),
            location: Some("landing_page".to_string()),
            snippet: Some(fetch.final_url.clone()),
        });
    }

    if has_auth_barrier {
        assessment.score += 0.20;
        assessment
            .categories
            .push("auth_barrier_landing".to_string());
        assessment.evidence.push(Evidence {
            description: format!(
                "Landing page {} shows CAPTCHA / human-verification barrier",
                fetch.final_url
            ),
            location: Some("landing_page".to_string()),
            snippet: fetch
                .page_title
                .clone()
                .or_else(|| Some(fetch.final_url.clone())),
        });
    }

    if has_auth_barrier && has_login_form {
        assessment.score += 0.20;
        assessment
            .categories
            .push("captcha_gated_login".to_string());
    }

    if signals.keyword_context && has_login_form {
        assessment.score += 0.20;
        assessment
            .categories
            .push("phishing_landing_chain".to_string());
    }

    if redirected_to_different_domain && has_login_form {
        assessment.score += 0.15;
        assessment
            .categories
            .push("redirected_login_landing".to_string());
    }

    if lands_on_official_login && has_login_form && signals.keyword_context {
        assessment.score += 0.10;
        assessment
            .categories
            .push("official_login_landing".to_string());
    }

    assessment
}

#[async_trait]
impl SecurityModule for LandingPageScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, ctx: &SecurityContext) -> bool {
        if ctx.session.content.links.is_empty() {
            return false;
        }
        let signals = derive_lure_signals(ctx, &self.phishing_keywords);
        if signals.keyword_context {
            return true;
        }
        ctx.session
            .content
            .links
            .iter()
            .filter_map(|link| unwrap_candidate_url(&link.url))
            .any(|url| candidate_priority(&url, &signals) >= 2)
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let signals = derive_lure_signals(ctx, &self.phishing_keywords);
        let candidates = collect_candidate_urls(ctx, &signals);
        if candidates.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No landing-page candidates worth fetching",
                start.elapsed().as_millis() as u64,
            ));
        }

        let fetcher = UrlFetcher::new(FetchConfig {
            timeout_secs: 8,
            max_redirects: 4,
            max_response_bytes: 600 * 1024,
            skip_private_ips: true,
        });

        let mut total_score = 0.0_f64;
        let mut categories = Vec::new();
        let mut evidence = Vec::new();
        let mut fetched_pages = 0usize;
        let mut fetch_errors = Vec::new();

        for url in &candidates {
            let fetch = fetcher.fetch(url).await;
            fetched_pages += 1;
            if let Some(error) = fetch.error.as_ref() {
                fetch_errors.push(format!("{}: {}", url, error));
                continue;
            }

            let assessment = assess_fetched_page(url, &fetch, &signals);
            if assessment.score <= 0.0 {
                continue;
            }
            total_score += assessment.score;
            categories.extend(assessment.categories);
            evidence.extend(assessment.evidence);
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
                    "Fetched {} landing page(s), no gated phishing indicators found",
                    fetched_pages
                ),
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.82,
            categories,
            summary: format!(
                "Landing-page scan found {} findings across {} fetched page(s)",
                evidence.len(),
                fetched_pages
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "fetched_pages": fetched_pages,
                "candidate_urls": candidates,
                "fetch_errors": fetch_errors,
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

    fn mock_fetch(
        original_url: &str,
        final_url: &str,
        title: Option<&str>,
        page_text: &str,
        has_login_form: bool,
    ) -> FetchResult {
        FetchResult {
            url: original_url.to_string(),
            final_url: final_url.to_string(),
            status_code: 200,
            content_type: "text/html".to_string(),
            page_text: page_text.to_string(),
            page_title: title.map(str::to_string),
            form_analysis: crate::external::fetcher::FormAnalysis {
                total_forms: usize::from(has_login_form),
                login_forms: usize::from(has_login_form),
                password_fields: usize::from(has_login_form),
                input_fields: usize::from(has_login_form) * 2,
                has_login_form,
            },
            error: None,
        }
    }

    #[test]
    fn test_device_code_landing_is_scored() {
        let signals = derive_lure_signals_from_text(
            "secure voicemail microsoft 365 device code enter the code immediately",
            &[
                normalize_text("secure voicemail"),
                normalize_text("device code"),
            ],
        );
        let fetch = mock_fetch(
            "https://example.com/message",
            "https://microsoft.com/devicelogin",
            Some("Microsoft device login"),
            "Enter the code provided to you to continue",
            false,
        );

        let assessment = assess_fetched_page("https://example.com/message", &fetch, &signals);

        assert!(
            assessment.score >= 0.40,
            "device-code landing should score strongly"
        );
        assert!(
            assessment
                .categories
                .contains(&"device_code_landing".to_string())
        );
    }

    #[test]
    fn test_captcha_gated_login_is_scored() {
        let signals = derive_lure_signals_from_text(
            "review your mailbox login alert",
            &[
                normalize_text("mailbox alert"),
                normalize_text("review now"),
            ],
        );
        let fetch = mock_fetch(
            "https://mail-check.example/login",
            "https://mail-check.example/challenge",
            Some("One more step"),
            "Cloudflare Turnstile security check. Verify you are human before sign in.",
            true,
        );

        let assessment = assess_fetched_page("https://mail-check.example/login", &fetch, &signals);

        assert!(
            assessment.score >= 0.30,
            "captcha-gated login should be suspicious"
        );
        assert!(
            assessment
                .categories
                .contains(&"auth_barrier_landing".to_string())
        );
        assert!(
            assessment
                .categories
                .contains(&"captcha_gated_login".to_string())
        );
    }

    #[test]
    fn test_safe_landing_page_has_no_score() {
        let signals = derive_lure_signals_from_text("normal business email", &[]);
        let fetch = mock_fetch(
            "https://example.com/news",
            "https://example.com/news",
            Some("Quarterly update"),
            "Welcome to our quarterly business report.",
            false,
        );

        let assessment = assess_fetched_page("https://example.com/news", &fetch, &signals);
        assert_eq!(assessment.score, 0.0);
    }
}
