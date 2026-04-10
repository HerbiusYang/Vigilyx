//! URL modedetectModule - CheckemailMediumlinkConnectofmode:IP AddresslinkConnect, data URI, shortlinkConnect, href/text matchwait

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::{LazyLock, OnceLock, RwLock};

use super::common::{extract_domain_from_url, extract_redirect_target_urls, percent_decode};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct LinkScanModule {
    meta: ModuleMetadata,
}

impl Default for LinkScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkScanModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "link_scan".to_string(),
                name: "URLmodedetect".to_string(),
                description: "ChecklinkConnectof IP Address、data URI、shortlinkConnect、href/text 不matchwait".to_string(),
                pillar: Pillar::Link,
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

static RE_IP_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap());
static RE_DOMAINISH_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b").unwrap()
});
static RE_EMAIL_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
    )
    .unwrap()
});

#[cfg(test)]
static URL_DOMAIN_SET_TEST_GUARD: LazyLock<std::sync::Mutex<()>> =
    LazyLock::new(|| std::sync::Mutex::new(()));

const URL_SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "goo.gl",
    "tinyurl.com",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "rb.gy",
    "short.io",
];

/// already emailSecurity Domain - URL write
/// `https://gateway/redirect?url=ORIGINAL` Used for SecurityCheck.

/// URL redirect_url / suspicious_params detect,
/// Extract Mediumpacket of Target URL lineAnalyze.
const MAIL_SECURITY_GATEWAYS: &[&str] = &[
    "asiainfo-sec.com",                 // Security DDEI
    "urldefense.proofpoint.com",        // Proofpoint URL Defense
    "safelinks.protection.outlook.com", // Microsoft Defender ATP
    "url.emailprotection.link",         // Mimecast
    "urlsand.com",                      // Libraesva URLsand
    "secureweb.cisco.com",              // Cisco Email Security
    "click.pstmrk.it",                  // Postmark
];

/// Check if a URL belongs to a mail security gateway URL rewrite.
fn is_mail_security_gateway(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    MAIL_SECURITY_GATEWAYS
        .iter()
        .any(|gw| url_lower.contains(gw))
}

/// Public version for use by other link analysis modules (e.g., link_content).
pub fn is_mail_security_gateway_pub(url_lower: &str) -> bool {
    MAIL_SECURITY_GATEWAYS
        .iter()
        .any(|gw| url_lower.contains(gw))
}

/// Extract the wrapped target URL from a mail-security gateway rewrite.
pub fn unwrap_mail_security_gateway_target(url: &str) -> Option<String> {
    if !is_mail_security_gateway(url) {
        return None;
    }
    extract_redirect_target_urls(url).into_iter().next()
}

fn domain_in_set(set: &HashSet<String>, domain: &str) -> bool {
    let lower = domain.to_lowercase();
    if set.contains(&lower) {
        return true;
    }
    let mut parts = lower.as_str();
    while let Some(pos) = parts.find('.') {
        parts = &parts[pos + 1..];
        if set.contains(parts) {
            return true;
        }
    }
    false
}

/// URL DomainSet (From DB Load, For link_content waitModuleShared)

/// `set_trusted_url_domains()` EngineStart Set.
/// Domainof URL Day packetContainslong token Parameter, suspicious_params/long_url.
static GLOBAL_TRUSTED_URL_DOMAINS: OnceLock<Arc<RwLock<HashSet<String>>>> = OnceLock::new();
/// Well-known safe sender domains (used by content heuristics, not URL structure bypasses).
static GLOBAL_WELL_KNOWN_SAFE_DOMAINS: OnceLock<Arc<RwLock<HashSet<String>>>> = OnceLock::new();

/// Set URL DomainSet (EngineStart 1Time/Count)
pub fn set_trusted_url_domains(domains: Arc<HashSet<String>>) {
    let shared = GLOBAL_TRUSTED_URL_DOMAINS
        .get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
        .clone();
   *shared
        .write()
        .expect("trusted url domain lock poisoned") = domains.as_ref().clone();
}

/// Set well-known safe sender domains (EngineStart 1Time/Count).
pub fn set_well_known_safe_domains(domains: Arc<HashSet<String>>) {
    let shared = GLOBAL_WELL_KNOWN_SAFE_DOMAINS
        .get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
        .clone();
   *shared
        .write()
        .expect("well-known safe domain lock poisoned") = domains.as_ref().clone();
}

/// Check URL Domainwhether Service (pub: For link_content ModuleShared)
pub fn is_trusted_url_domain(domain: &str) -> bool {
    let Some(set) = GLOBAL_TRUSTED_URL_DOMAINS.get() else {
        return false;
    };
    let set = set.read().expect("trusted url domain lock poisoned");
    domain_in_set(&set, domain)
}

/// Check whether a domain is in the well-known safe-domain set.
pub fn is_well_known_safe_domain(domain: &str) -> bool {
    let Some(set) = GLOBAL_WELL_KNOWN_SAFE_DOMAINS.get() else {
        return false;
    };
    let set = set.read().expect("well-known safe domain lock poisoned");
    domain_in_set(&set, domain)
}

fn looks_like_urlish_link_text(text: &str) -> bool {
    let normalized = text.trim().to_ascii_lowercase();
    normalized.contains("http://")
        || normalized.contains("https://")
        || normalized.contains("www.")
        || RE_DOMAINISH_TEXT.is_match(&normalized)
}

fn link_text_matches_embedded_contact_context(text: &str, analysis_url: &str) -> bool {
    let emails: Vec<String> = RE_EMAIL_TEXT
        .find_iter(text)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect();
    if emails.is_empty() {
        return false;
    }

    let decoded_url = percent_decode(analysis_url).to_ascii_lowercase();
    emails.iter().all(|email| decoded_url.contains(email))
}

#[cfg(test)]
pub(crate) fn lock_url_domain_set_test_guard() -> std::sync::MutexGuard<'static, ()> {
    URL_DOMAIN_SET_TEST_GUARD
        .lock()
        .expect("url domain set test guard poisoned")
}

#[async_trait]
impl SecurityModule for LinkScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
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
                "email无linkConnect",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut suspicious_urls: Vec<String> = Vec::new();
        let mut unique_domains: HashSet<String> = HashSet::with_capacity(links.len());

        for link in links {
            let url = &link.url;
            let url_lower = url.to_lowercase();
            let gateway_target = unwrap_mail_security_gateway_target(url);
            let analysis_url = gateway_target.as_deref().unwrap_or(url);
            let analysis_url_lower = analysis_url.to_lowercase();
            let using_gateway_target = gateway_target.is_some();

            let link_domain = extract_domain_from_url(&analysis_url_lower);
            if let Some(ref domain) = link_domain {
                unique_domains.insert(domain.clone());
            }

           // Mail security gateway URL unwrapping: extract the real target URL
           // wrapped by the gateway. The gateway URL itself must skip structural
           // checks (redirect_url / suspicious_params) - those patterns are
           // inherent to the gateway's URL rewriting, not phishing indicators.
            let is_gateway = is_mail_security_gateway(&url_lower);
            let effective_domain = link_domain.clone();

           // Trusted domains skip structural checks (suspicious_params, long_url,
           // redirect_url) - their URLs naturally contain long token parameters.
           // NOTE: Security gateways are NOT blanket-trusted. Only the gateway's own
           // URL parameters (redirect_url, suspicious_params) are skipped. The unwrapped
           // target domain must still be analyzed for random_domain, IP URL, etc.
            let is_trusted = effective_domain
                .as_ref()
                .is_some_and(|d| is_trusted_url_domain(d));
           // If we successfully unwrapped the target URL, inspect that target normally.
           // Only the outer gateway wrapper should skip redirect-parameter heuristics.
            let skip_redirect_checks = (!using_gateway_target && is_gateway) || is_trusted;

           // --- 1. IP-based URL ---
            if RE_IP_URL.is_match(&analysis_url_lower) {
                total_score += 0.25;
                categories.push("ip_url".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: format!("IP AddresslinkConnect: {}", analysis_url),
                    location: Some("links".to_string()),
                    snippet: Some(analysis_url.to_string()),
                });
            }

           // --- 2. data: URI ---
            if analysis_url_lower.starts_with("data:") {
                total_score += 0.30;
                categories.push("data_uri".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: "data: URI linkConnect".to_string(),
                    location: Some("links".to_string()),
                    snippet: Some(analysis_url.chars().take(100).collect()),
                });
            }

           // --- 3. javascript: URI ---
            if analysis_url_lower.starts_with("javascript:") {
                total_score += 0.35;
                categories.push("javascript_uri".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: "javascript: URI linkConnect".to_string(),
                    location: Some("links".to_string()),
                    snippet: Some(analysis_url.chars().take(100).collect()),
                });
            }

           // --- 4. href/text mismatch ---
            if let Some(ref text) = link.text
                && !text.is_empty()
                && let Some(url_domain) = extract_domain_from_url(&analysis_url_lower)
            {
                let text_lower = text.to_lowercase();
               // If the link text looks like a URL or contains a domain, check for mismatch
                if looks_like_urlish_link_text(&text_lower)
                    && !link_text_matches_embedded_contact_context(&text_lower, analysis_url)
                    && !text_lower.contains(&url_domain)
                {
                    total_score += 0.30;
                    categories.push("href_text_mismatch".to_string());
                    suspicious_urls.push(analysis_url.to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "linkConnectText与 URL Domain不match: Text=\"{}\" URLDomain=\"{}\"",
                            text, url_domain
                        ),
                        location: Some("links".to_string()),
                        snippet: Some(format!("<a href=\"{}\">{}</a>", analysis_url, text)),
                    });
                }
            }

           // --- 5. URL shortener ---
            if let Some(domain) = extract_domain_from_url(&analysis_url_lower)
                && URL_SHORTENERS
                    .iter()
                    .any(|&s| domain == s || domain.ends_with(&format!(".{}", s)))
            {
                total_score += 0.15;
                categories.push("url_shortener".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: format!(
                        "shortlinkConnectService: {} (Domain: {})",
                        analysis_url, domain
                    ),
                    location: Some("links".to_string()),
                    snippet: Some(analysis_url.to_string()),
                });
            }

           // --- 6. Redirect/tracking + suspicious params detection ---
           // Skip for trusted domains and security gateways (their URL params are legitimate)
            if !skip_redirect_checks {
               // 6a. Parameterdetect
                let redirect_params = [
                    "clickenc=http",
                    "redirect=http",
                    "url=http",
                    "goto=http",
                    "target=http",
                    "dest=http",
                    "clickenc=https",
                    "redirect=https",
                    "url=https",
                    "goto=https",
                    "target=https",
                    "dest=https",
                    "clickenc=http%3a",
                    "redirect=http%3a",
                    "clickenc=https%3a",
                    "redirect=https%3a",
                ];
                for param in redirect_params {
                    if analysis_url_lower.contains(param) {
                        total_score += 0.20;
                        categories.push("redirect_url".to_string());
                        suspicious_urls.push(analysis_url.to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "URL packetContains重定向Parameter (possibly隐藏真实目of地): {}...{}",
                                &analysis_url[..analysis_url.len().min(80)],
                                if analysis_url.len() > 80 { "..." } else { "" }
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(analysis_url.chars().take(200).collect()),
                        });
                        break;
                    }
                }

               // 6b. Suspicious token/auth Parameter
                static RE_TOKEN_PARAM: LazyLock<regex::Regex> = LazyLock::new(|| {
                    regex::Regex::new(
                        r"[?&](token|auth|session|verify|code|key)=[a-zA-Z0-9_\-]{16,}",
                    )
                    .expect("token param regex")
                });
                if RE_TOKEN_PARAM.is_match(&analysis_url_lower) {
                    total_score += 0.15;
                    if !categories.contains(&"suspicious_params".to_string()) {
                        categories.push("suspicious_params".to_string());
                    }
                    suspicious_urls.push(analysis_url.to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "URL packetContainsSuspiciousofAuthentication/令牌Parameter (常见于凭证窃GetPhishing): {}",
                            &analysis_url[..analysis_url.len().min(100)],
                        ),
                        location: Some("links".to_string()),
                        snippet: Some(analysis_url.chars().take(200).collect()),
                    });
                }
            } // end if!is_trusted
        } // end for link in links

       // --- 7. Excessive URL count ---
        if links.len() > 15 {
           // Signal: /New emailDay large linkConnect
            total_score += 0.08;
            categories.push("excessive_links".to_string());
            evidence.push(Evidence {
                description: format!("linkConnectCount多: {} （Threshold 15）", links.len()),
                location: Some("links".to_string()),
                snippet: None,
            });
        }

       // Deduplicate suspicious URLs
        suspicious_urls.sort();
        suspicious_urls.dedup();

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
                &format!("alreadyCheck {} linkConnect，未FoundAbnormal", links.len()),
                duration_ms,
            ));
        }

        let unique_domain_list: Vec<String> = unique_domains.into_iter().collect();

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.85,
            categories,
            summary: format!(
                "URL modedetectFound {} 处Abnormal，涉及 {} Suspicious URL",
                evidence.len(),
                suspicious_urls.len()
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "total_links": links.len(),
                "suspicious_urls": suspicious_urls,
                "unique_domains": unique_domain_list,
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
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn analyze_with_runtime(module: &LinkScanModule, ctx: &SecurityContext) -> ModuleResult {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(module.analyze(ctx))
            .unwrap()
    }

    fn make_ctx(url: &str, text: Option<&str>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            links: vec![EmailLink {
                url: url.to_string(),
                text: text.map(str::to_string),
                suspicious: false,
            }],
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[test]
    fn test_gateway_target_ip_url_is_analyzed() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://safelinks.protection.outlook.com/?url=http%3A%2F%2F192.0.2.10%2Flogin",
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(result.categories.contains(&"ip_url".to_string()));
    }

    #[test]
    fn test_gateway_target_used_for_href_text_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin",
            Some("https://portal.example.com"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(result.categories.contains(&"href_text_mismatch".to_string()));
    }

    #[test]
    fn test_descriptive_filename_text_is_not_treated_as_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://product-support.chaitin.cn/package/detail?id=18557ddf86cb4f28a89c4cfbf5cc726c7476",
            Some("攻击检测引擎升级包5.11.24-arm64"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"href_text_mismatch".to_string()),
            "descriptive link labels with version numbers should not be treated as URL/domain text: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_business_card_email_text_matching_url_context_is_not_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=2428735896%40qq.com&code=abc",
            Some("丁小帅 2428735896@qq.com"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"href_text_mismatch".to_string()),
            "contact-card text whose email is embedded in the destination URL should not be treated as a deceptive URL label: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_safe_and_trusted_domain_sets_are_separate() {
        let _guard = lock_url_domain_set_test_guard();
        let mut trusted = HashSet::new();
        trusted.insert("mail.qq.com".to_string());
        set_trusted_url_domains(Arc::new(trusted));

        let mut safe = HashSet::new();
        safe.insert("microsoft.com".to_string());
        set_well_known_safe_domains(Arc::new(safe));

        assert!(is_trusted_url_domain("wx.mail.qq.com"));
        assert!(!is_trusted_url_domain("microsoft.com"));
        assert!(is_well_known_safe_domain("login.microsoft.com"));
    }
}
