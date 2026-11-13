//! URL modedetectModule - CheckemailMediumlinkConnectofmode:IP AddresslinkConnect, data URI, shortlinkConnect, href/text matchwait

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::{LazyLock, OnceLock, RwLock};

use super::common::{
    domain_matches_policy_set, domains_share_organizational_domain, extract_domain_from_url,
    extract_redirect_target_urls, host_matches_domain_or_subdomain, is_operational_delivery_alert,
    is_private_network_url, is_probable_non_clickable_render_asset_url,
    is_probable_opaque_mail_callback_url, is_probable_safe_static_asset_url, organizational_domain,
    percent_decode, url_has_userinfo,
};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

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
static RE_EMAIL_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());

/// IP-literal URL detection. The dotted-decimal regex is only a fast path;
/// the WHATWG parser is authoritative: it normalizes hex (0xC0A80001),
/// octal (0300.0250.0001.0001) and single-integer (3232235521) IPv4 forms
/// to a canonical IPv4 host, and recognizes IPv6 literals. Numeric-host
/// obfuscation must not be able to hide an IP-literal phishing URL.
pub(crate) fn url_host_is_ip(url: &str) -> bool {
    if RE_IP_URL.is_match(url) {
        return true;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    matches!(
        parsed.host(),
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_))
    )
}

/// Some mail generators emit a complete href with every delimiter percent
/// encoded (`https%3A%2F%2F...`). Decode exactly one layer only when the raw
/// value has no literal HTTP(S) scheme and the decoded value is a valid
/// absolute web URL. Already-schemed malformed hrefs stay parser-differential
/// evidence instead of being "repaired" into a potentially different URL.
fn decode_fully_encoded_absolute_http_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let raw_lower = trimmed.to_ascii_lowercase();
    if raw_lower.starts_with("http://") || raw_lower.starts_with("https://") {
        return None;
    }

    let decoded = percent_decode(trimmed);
    if decoded == trimmed {
        return None;
    }
    let parsed = url::Url::parse(&decoded).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.to_string())
}

#[cfg(test)]
static URL_DOMAIN_SET_TEST_GUARD: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

// URL_SHORTENERS: moved to module_data JSON (key: "url_shorteners")
// MAIL_SECURITY_GATEWAYS: moved to module_data JSON (key: "mail_security_gateways")

/// Check if a URL belongs to a mail security gateway URL rewrite.
fn is_mail_security_gateway(url: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url) else {
        return false;
    };
    let md = crate::module_data::module_data();
    for gw in md.get_list("mail_security_gateways") {
        if host_matches_domain_or_subdomain(&domain, gw) {
            return true;
        }
    }
    false
}

/// Public version for use by other link analysis modules (e.g., link_content).
pub fn is_mail_security_gateway_pub(url_lower: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url_lower) else {
        return false;
    };
    let md = crate::module_data::module_data();
    for gw in md.get_list("mail_security_gateways") {
        if host_matches_domain_or_subdomain(&domain, gw) {
            return true;
        }
    }
    false
}

/// Extract the wrapped target URL from a mail-security gateway rewrite.
pub fn unwrap_mail_security_gateway_target(url: &str) -> Option<String> {
    if !is_mail_security_gateway(url) {
        return None;
    }
    // The recursive extractor returns outer-to-inner order; analyze the
    // deepest destination as the effective URL while link_reputation retains
    // every hop for evidence and per-domain analysis.
    extract_redirect_target_urls(url).into_iter().last()
}

/// Recover a destination that is safe to use as the *effective* structural
/// analysis target.
///
/// Redirect parameters are attacker-controlled, so an arbitrary outer URL
/// must never be replaced by its `next=` value: doing so would let
/// `evil.example/?next=https://legit.example` hide the malicious outer host.
/// Replacement is limited to transport wrappers, configured trusted hosts,
/// and shared platforms whose redirect endpoint is otherwise able to inherit
/// a structural bypass. The returned target is still analyzed with the normal
/// IP/userinfo/path rules and does not inherit trust from the wrapper.
pub fn unwrap_redirect_target_for_analysis(url: &str) -> Option<String> {
    if let Some(target) = unwrap_mail_security_gateway_target(url) {
        return Some(target);
    }

    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    // r.jina.ai accepts the fetched URL as a path rather than a query
    // parameter (`/http://host/path`). Decode at most two layers, matching the
    // bounded query-parameter extractor.
    if host == "r.jina.ai" {
        let mut candidate = parsed.path().trim_start_matches('/').to_string();
        for _ in 0..2 {
            let decoded = percent_decode(&candidate);
            if decoded == candidate {
                break;
            }
            candidate = decoded;
        }
        if let Ok(target) = url::Url::parse(&candidate)
            && matches!(target.scheme(), "http" | "https")
            && target.host_str().is_some()
        {
            let target = target.to_string();
            return extract_redirect_target_urls(&target)
                .into_iter()
                .last()
                .or(Some(target));
        }
    }

    // Shared-content platforms commonly carry arbitrary query parameters on
    // normal documents/forms. Only their known redirect endpoint is eligible
    // for replacement, otherwise a benign `src=` field could be reinterpreted
    // as a navigation target. Configured first-party redirectors remain
    // eligible because that trust decision is tenant-controlled.
    let known_shared_redirect_endpoint =
        matches!(host.as_str(), "docs.google.com" | "www.google.com")
            && parsed.path().trim_end_matches('/') == "/url";
    if !known_shared_redirect_endpoint && !is_trusted_url_domain(&host) {
        return None;
    }

    extract_redirect_target_urls(url).into_iter().last()
}

fn domain_in_set(set: &HashSet<String>, domain: &str) -> bool {
    domain_matches_policy_set(domain, set)
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
    *shared.write().expect("trusted url domain lock poisoned") = domains.as_ref().clone();
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

pub(crate) fn is_official_claimed_domain(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    module_data().contains("protected_domains", &domain)
        || is_well_known_safe_domain(&domain)
        || [
            ".gov", ".gov.uk", ".gov.cn", ".gov.au", ".govt.nz", ".gc.ca", ".gouv.fr", ".gob.mx",
            ".go.jp", ".go.kr", ".gov.sg", ".gov.in",
        ]
        .iter()
        .any(|suffix| domain.ends_with(suffix))
}

fn untrusted_host_embeds_sender_domain(host: &str, sender_domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let sender_domain = sender_domain.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || sender_domain.is_empty()
        || domains_share_organizational_domain(&host, &sender_domain)
    {
        return false;
    }
    host.starts_with(&format!("{sender_domain}."))
        || host.contains(&format!(".{sender_domain}."))
        || host.ends_with(&format!(".{sender_domain}"))
}

/// Shared-content hosting platforms are legitimate services, but the tenant's
/// page content is attacker-controlled.  They must not inherit the same
/// structural/reputation bypass as a first-party static asset or mail gateway.
pub fn is_shared_hosting_platform(domain: &str) -> bool {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    const EXPLICIT_PLATFORMS: &[&str] = &[
        "forms.google.com",
        "docs.google.com",
        "forms.office.com",
        "notion.so",
        "notion.site",
        "tally.so",
        "typeform.com",
        "cloudfunctions.net",
        "run.app",
        "firebaseapp.com",
        "web.app",
        "fcapp.run",
        "fc.aliyuncs.com",
    ];
    if EXPLICIT_PLATFORMS
        .iter()
        .any(|suffix| lower == *suffix || lower.ends_with(&format!(".{suffix}")))
    {
        return true;
    }

    let md = module_data();
    md.get_list("aitm_platform_domain_suffixes")
        .iter()
        .any(|suffix| {
            let suffix = suffix.trim_start_matches('.');
            lower == suffix || lower.ends_with(&format!(".{suffix}"))
        })
}

fn looks_like_urlish_link_text(text: &str) -> bool {
    let normalized = text.trim().to_ascii_lowercase();
    normalized.contains("http://")
        || normalized.contains("https://")
        || normalized.contains("www.")
        || RE_DOMAINISH_TEXT.is_match(&normalized)
}

fn is_machine_tracking_url_text(text: &str) -> bool {
    let trimmed = text.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    is_mail_security_gateway(&lower)
        || !extract_redirect_target_urls(trimmed).is_empty()
        || lower.contains("/track/")
        || lower.contains("/click2/")
        || lower.contains("/clicktime/")
        || lower.contains("track/unsubscribe")
        || lower.contains("umid=")
        || lower.contains("auth=")
}

/// ESP click tracking: the href is the provider's counting redirect and the
/// visible text is the destination it forwards to (the lingxi360 newsletter
/// pattern `etrack01.com/track/click2/<token>` shown as `https://chinasif.org/`).
/// A tracker host or tracker path is not a deceptive label by itself.
fn is_click_tracking_href(url_lower: &str) -> bool {
    static RE_LINGXI_TRACKER_HOST: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^etrack\d{2}\.com$").unwrap());
    const TRACKER_HOSTS: &[&str] = &[
        "sendgrid.net",
        "list-manage.com",
        "mandrillapp.com",
        "sparkpostmail.com",
        "hubspotlinks.com",
    ];
    const TRACKER_PATHS: &[&str] = &["/track/click", "/ls/click", "/wf/click"];
    let Ok(parsed) = url::Url::parse(url_lower) else {
        return false;
    };
    let Some(host) = parsed.host_str().map(|host| host.trim_end_matches('.')) else {
        return false;
    };
    RE_LINGXI_TRACKER_HOST.is_match(host)
        || TRACKER_HOSTS
            .iter()
            .any(|tracker| host == *tracker || host.ends_with(&format!(".{tracker}")))
        || TRACKER_PATHS
            .iter()
            .any(|prefix| parsed.path().starts_with(prefix))
}

fn is_protocol_only_link_text(text: &str) -> bool {
    matches!(
        text.trim().to_ascii_lowercase().as_str(),
        "http://" | "https://"
    )
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

/// Known first-party tokenized resources.  These are file/image or notification
/// endpoints rather than user-facing login pages; their opaque parameters are
/// expected and must not become standalone phishing evidence.
pub fn is_known_safe_tokenized_resource_url(url: &str) -> bool {
    let normalized = percent_decode(url).to_ascii_lowercase();

    normalized.starts_with("https://wx.mail.qq.com/info/get_mailhead_icon?")
        || normalized.starts_with("http://wx.mail.qq.com/info/get_mailhead_icon?")
        || normalized.starts_with("https://wx.mail.qq.com/ftn/download?")
        || normalized.starts_with("http://wx.mail.qq.com/ftn/download?")
        || normalized.starts_with("https://dm-cn.aliyuncs.com/trace/v1/report?")
        || normalized.starts_with("http://dm-cn.aliyuncs.com/trace/v1/report?")
        || normalized.starts_with("https://mail.qq.com/info/get_mailhead_icon?")
        || normalized.starts_with("http://mail.qq.com/info/get_mailhead_icon?")
        || ((normalized.starts_with("https://wx.mail.qq.com/home/index")
            || normalized.starts_with("http://wx.mail.qq.com/home/index")
            || normalized.starts_with("https://mail.qq.com/home/index")
            || normalized.starts_with("http://mail.qq.com/home/index"))
            && normalized.contains("readmail_businesscard_midpage"))
        || (normalized.starts_with("https://dashi.163.com/html/cloud-attachment-download/")
            && normalized.contains("key="))
        || (normalized.starts_with("http://dashi.163.com/html/cloud-attachment-download/")
            && normalized.contains("key="))
        || normalized
            .starts_with("https://dashi.163.com/projects/signature-manager/detail/index.html?")
        || normalized
            .starts_with("http://dashi.163.com/projects/signature-manager/detail/index.html?")
        // 163 webmail embeds a tokenized open-tracking/icon resource in
        // forwarded messages. Its key/id parameters are provider metadata,
        // not a credential-phishing redirect.
        || normalized.starts_with("https://hermes.mail.163.com/mt/icon.gif?")
        || normalized.starts_with("http://hermes.mail.163.com/mt/icon.gif?")
        || ((normalized.starts_with("https://kcart.alipay.com/web/bi.do")
            || normalized.starts_with("http://kcart.alipay.com/web/bi.do"))
            && normalized.contains("pg="))
}

fn extract_visible_domain_texts(text: &str) -> Vec<String> {
    RE_DOMAINISH_TEXT
        .find_iter(text)
        .map(|matched| {
            matched
                .as_str()
                .trim_end_matches(['.', ',', ';', ':', '/'])
                .to_ascii_lowercase()
        })
        .filter(|domain| !domain.is_empty())
        .collect()
}

fn text_and_url_domains_equivalent(text: &str, url_domain: &str) -> bool {
    let text_domains = extract_visible_domain_texts(text);
    if text_domains.is_empty() {
        return false;
    }

    // Descriptive labels may include prose around the host (for example,
    // "Manage tokens on npmjs.com"). Accept them only when every visible
    // domain belongs to the href's organizational domain; a second unrelated
    // domain keeps the mismatch signal intact.
    text_domains.iter().all(|text_domain| {
        text_domain == url_domain || domains_share_organizational_domain(text_domain, url_domain)
    })
}

#[cfg(test)]
pub(crate) fn lock_url_domain_set_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    URL_DOMAIN_SET_TEST_GUARD.blocking_lock()
}

#[cfg(test)]
pub(crate) async fn lock_url_domain_set_test_guard_async() -> tokio::sync::MutexGuard<'static, ()> {
    URL_DOMAIN_SET_TEST_GUARD.lock().await
}

#[async_trait]
impl SecurityModule for LinkScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let links = ctx.analysis_links();

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
        let mut redirect_causes: HashSet<String> = HashSet::new();
        let mut unparseable_hits: usize = 0;
        let mut generic_mismatch_hits: usize = 0;
        let mut tracked_label_observations: usize = 0;
        let mut opaque_token_observations: usize = 0;
        let operational_alert = is_operational_delivery_alert(&ctx.session);
        let mut operational_management_link_observations: usize = 0;
        let sender_is_external = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|address| address.rsplit('@').next())
            .is_none_or(|domain| {
                !ctx.is_internal_domain(domain)
                    && !module_data().contains("protected_domains", domain)
                    && !is_well_known_safe_domain(domain)
            });
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|address| address.rsplit('@').next());
        let mut shared_hosted_redirect_observed = false;

        for link in &links {
            let decoded_absolute_url = decode_fully_encoded_absolute_http_url(&link.url);
            let url = decoded_absolute_url.as_deref().unwrap_or(link.url.as_str());
            let url_lower = url.to_lowercase();
            let gateway_target = unwrap_mail_security_gateway_target(url);
            let redirect_target = unwrap_redirect_target_for_analysis(url);
            let analysis_url = redirect_target.as_deref().unwrap_or(url);
            let analysis_url_lower = analysis_url.to_lowercase();
            let using_gateway_target = gateway_target.is_some();

            if is_probable_opaque_mail_callback_url(analysis_url) {
                continue;
            }

            let link_domain = extract_domain_from_url(&analysis_url_lower);
            if let Some(ref domain) = link_domain {
                unique_domains.insert(domain.clone());
            }

            // Mail security gateway URL unwrapping: extract the real target URL
            // wrapped by the gateway. Only a successfully unwrapped gateway URL
            // skips structural checks (redirect_url / suspicious_params) - those
            // patterns are inherent to the gateway's URL rewriting. A gateway URL
            // whose target cannot be extracted is NOT exempt and is checked below.
            let is_gateway = is_mail_security_gateway(&url_lower);
            let effective_domain = link_domain.clone();

            // A sender's exact domain embedded as a subdomain of a different
            // registered host is a common file-share impersonation pattern
            // (for example, sender.example.attacker-share.test). Preserve it
            // as a named link signal even when the link has no visible anchor.
            if sender_is_external
                && let (Some(host), Some(sender_domain)) =
                    (effective_domain.as_deref(), sender_domain)
                && untrusted_host_embeds_sender_domain(host, sender_domain)
            {
                total_score += 0.65;
                categories.push("sender_domain_nested_in_untrusted_host".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Sender domain {sender_domain} is embedded as a subdomain of unrelated link host {host}"
                    ),
                    location: Some("sender domain + links".to_string()),
                    snippet: Some(analysis_url.chars().take(200).collect()),
                });
            }

            // Trusted domains skip structural checks (suspicious_params, long_url,
            // redirect_url) - their URLs naturally contain long token parameters.
            // NOTE: Security gateways are NOT blanket-trusted. Only the gateway's own
            // URL parameters (redirect_url, suspicious_params) are skipped. The unwrapped
            // target domain must still be analyzed for random_domain, IP URL, etc.
            let is_trusted = effective_domain
                .as_ref()
                .is_some_and(|d| is_trusted_url_domain(d));
            let is_known_safe_resource = is_known_safe_tokenized_resource_url(analysis_url);
            // Skip redirect-parameter heuristics only when the gateway wrapper was
            // successfully unwrapped: the extracted target's params may be gateway
            // rewrite artifacts. A gateway URL WITHOUT an extractable target must
            // still be checked - nothing stops an attacker from crafting gateway
            // URLs that carry no valid embedded target.
            let skip_redirect_checks =
                (is_gateway && using_gateway_target) || is_trusted || is_known_safe_resource;

            // A known shared platform can wrap an attacker-controlled
            // destination in its own redirect endpoint. The wrapper itself is
            // trusted infrastructure, but an external auth target must not
            // inherit that trust. Keep this as a named compound so ordinary
            // Google/Office document links remain unaffected.
            if sender_is_external
                && !shared_hosted_redirect_observed
                && redirect_target.is_some()
                && url::Url::parse(url).ok().is_some_and(|wrapper| {
                    wrapper.host_str().is_some_and(is_shared_hosting_platform)
                        && wrapper.path().trim_end_matches('/') == "/url"
                })
                && redirect_target.as_deref().is_some_and(|target| {
                    let Ok(parsed) = url::Url::parse(target) else {
                        return false;
                    };
                    let Some(domain) = parsed.host_str() else {
                        return false;
                    };
                    let untrusted = !ctx.is_internal_domain(domain)
                        && !module_data().contains("protected_domains", domain)
                        && !is_trusted_url_domain(domain)
                        && !is_well_known_safe_domain(domain);
                    let auth_path = parsed.path_segments().is_some_and(|segments| {
                        module_data()
                            .get_list("credential_auth_path_segments")
                            .iter()
                            .any(|term| {
                                segments
                                    .clone()
                                    .any(|segment| segment.eq_ignore_ascii_case(term))
                            })
                    });
                    untrusted && auth_path
                })
            {
                shared_hosted_redirect_observed = true;
                total_score += 0.45;
                categories.push("shared_hosted_redirect_lure".to_string());
                suspicious_urls.push(redirect_target.clone().unwrap_or_default());
                evidence.push(Evidence {
                    description: format!(
                        "Shared-content redirect endpoint wraps an untrusted authentication target: {}",
                        redirect_target.as_deref().unwrap_or(url)
                    ),
                    location: Some("links:shared_hosted_redirect".to_string()),
                    snippet: Some(url.chars().take(200).collect()),
                });
            }

            // --- 1. IP-based URL ---
            let operational_management_link =
                operational_alert && is_private_network_url(analysis_url);
            if operational_management_link {
                operational_management_link_observations += 1;
                evidence.push(Evidence {
                    description: format!(
                        "Operational alert management URL observed; private IP is not treated as an external phishing destination: {}",
                        analysis_url
                    ),
                    location: Some("links:operational_alert".to_string()),
                    snippet: Some(analysis_url.to_string()),
                });
            } else if url_host_is_ip(&analysis_url_lower) {
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

            // --- 3b. Unparseable href (parser-differential signal) ---
            // Extraction (EmailContent::push_or_update_link) no longer silently
            // drops hrefs the URL parser rejects — the browser may still
            // resolve them (`http://legit.com%40evil.com/` style). An
            // unreadable href in an email link is itself a weak phishing
            // signal. Capped so href spam cannot inflate the score.
            if url::Url::parse(url).is_err() {
                unparseable_hits += 1;
                if unparseable_hits <= 2 {
                    total_score += 0.10;
                }
                categories.push("unparseable_url".to_string());
                suspicious_urls.push(url.chars().take(200).collect());
                evidence.push(Evidence {
                    description: format!(
                        "linkConnect href 无法ParseAs URL (browser/parser differential, 浏览器仍可Resolve): {}",
                        url.chars().take(80).collect::<String>()
                    ),
                    location: Some("links".to_string()),
                    snippet: Some(url.chars().take(200).collect()),
                });
                // Nothing structural can be derived from an unparsable href.
                continue;
            }

            // --- 3c. Userinfo authority obfuscation ---
            // `http://mail.qq.com:443@evil.tk/login` renders the trusted name
            // in the link while the browser connects to the host after `@`.
            // Userinfo in an email link has no legitimate use — score it.
            if url_has_userinfo(&analysis_url_lower) {
                total_score += 0.30;
                categories.push("userinfo_in_url".to_string());
                suspicious_urls.push(analysis_url.to_string());
                evidence.push(Evidence {
                    description: format!(
                        "URL authority 包含 userinfo (trueHost在 @ 之后, 经典凭证Phishing混淆): {}",
                        analysis_url.chars().take(80).collect::<String>()
                    ),
                    location: Some("links".to_string()),
                    snippet: Some(analysis_url.chars().take(200).collect()),
                });
            }

            // --- 4. href/text mismatch ---
            if let Some(ref text) = link.text
                && !text.is_empty()
                && let Some(url_domain) = extract_domain_from_url(&analysis_url_lower)
            {
                let text_lower = text.to_lowercase();
                // Skip mismatch check if the URL domain is a well-known safe domain
                let skip_mismatch = is_well_known_safe_domain(&url_domain)
                    || is_trusted_url_domain(&url_domain)
                    || is_known_safe_tokenized_resource_url(analysis_url);
                // If the link text looks like a URL or contains a domain, check for mismatch
                if !skip_mismatch
                    && looks_like_urlish_link_text(&text_lower)
                    && !is_machine_tracking_url_text(text)
                    && !is_protocol_only_link_text(text)
                    && !link_text_matches_embedded_contact_context(&text_lower, analysis_url)
                    && !text_and_url_domains_equivalent(text, &url_domain)
                    && !text_lower.contains(&url_domain)
                {
                    let official_domain_text_mismatch = extract_domain_from_url(&text_lower)
                        .is_some_and(|claimed_domain| {
                            is_official_claimed_domain(&claimed_domain)
                                && !domains_share_organizational_domain(
                                    &claimed_domain,
                                    &url_domain,
                                )
                        });
                    // A generic label behind a click-tracking href names the
                    // destination the tracker forwards to. An official-domain
                    // claim is still checked: any host can imitate the path.
                    if !official_domain_text_mismatch && is_click_tracking_href(&analysis_url_lower)
                    {
                        tracked_label_observations += 1;
                    } else {
                        // A newsletter has many links; generic mismatches count
                        // at most twice so link volume cannot reach Critical alone.
                        total_score += if official_domain_text_mismatch {
                            0.70
                        } else {
                            generic_mismatch_hits += 1;
                            match generic_mismatch_hits {
                                1 => 0.30,
                                2 => 0.15,
                                _ => 0.0,
                            }
                        };
                        categories.push("href_text_mismatch".to_string());
                        if official_domain_text_mismatch {
                            categories.push("official_domain_text_mismatch".to_string());
                        }
                        suspicious_urls.push(analysis_url.to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "linkConnectText与 URL Domain不match: Text=\"{}\" URLDomain=\"{}\"{}",
                                text,
                                url_domain,
                                if official_domain_text_mismatch {
                                    " (the visible URL claims an official trusted domain)"
                                } else {
                                    ""
                                }
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(format!("<a href=\"{}\">{}</a>", analysis_url, text)),
                        });
                    }
                }
            }

            // --- 5. URL shortener ---
            if let Some(domain) = extract_domain_from_url(&analysis_url_lower) {
                let md = crate::module_data::module_data();
                let is_shortener = md
                    .get_list("url_shorteners")
                    .iter()
                    .any(|s| domain == *s || domain.ends_with(&format!(".{}", s)));
                if is_shortener {
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
            }

            // --- 6. Redirect/tracking + suspicious params detection ---
            // Skip for trusted domains and security gateways (their URL params are legitimate)
            if !skip_redirect_checks {
                // 6a. Parsed cross-organization redirect target. Query names
                // must match exactly and their decoded values must be HTTP(S)
                // URLs; this prevents `elq=` from satisfying the old `q=`
                // substring check. Repeated campaign links sharing the same
                // source/target organizations contribute only one cause.
                let source_domain = extract_domain_from_url(analysis_url);
                for target in extract_redirect_target_urls(analysis_url) {
                    let Some(target_domain) = extract_domain_from_url(&target) else {
                        continue;
                    };
                    if source_domain.as_deref().is_some_and(|source| {
                        domains_share_organizational_domain(source, &target_domain)
                    }) {
                        continue;
                    }

                    let source_cause = source_domain
                        .as_deref()
                        .and_then(organizational_domain)
                        .unwrap_or_else(|| "unknown".to_string());
                    let target_cause = organizational_domain(&target_domain)
                        .unwrap_or_else(|| target_domain.clone());
                    if !redirect_causes.insert(format!("{source_cause}->{target_cause}")) {
                        continue;
                    }

                    total_score += 0.20;
                    categories.push("redirect_url".to_string());
                    suspicious_urls.push(analysis_url.to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "URL contains a cross-organization redirect target ({} → {}): {}{}",
                            source_cause,
                            target_cause,
                            analysis_url.chars().take(80).collect::<String>(),
                            if analysis_url.chars().count() > 80 {
                                "..."
                            } else {
                                ""
                            }
                        ),
                        location: Some("links".to_string()),
                        snippet: Some(analysis_url.chars().take(200).collect()),
                    });
                }

                // 6b. Suspicious token/auth Parameter
                static RE_TOKEN_PARAM: LazyLock<regex::Regex> = LazyLock::new(|| {
                    regex::Regex::new(
                        r"[?&](token|auth|session|verify|code|key)=[a-zA-Z0-9_\-]{16,}",
                    )
                    .expect("token param regex")
                });
                if RE_TOKEN_PARAM.is_match(&analysis_url_lower) {
                    opaque_token_observations += 1;
                    let credential_path = url::Url::parse(analysis_url)
                        .ok()
                        .map(|parsed| parsed.path().to_ascii_lowercase())
                        .is_some_and(|path| {
                            [
                                "login",
                                "signin",
                                "verify",
                                "password",
                                "credential",
                                "oauth",
                                "mfa",
                            ]
                            .iter()
                            .any(|term| path.contains(term))
                        });
                    if credential_path {
                        total_score += 0.15;
                        if !categories.contains(&"suspicious_params".to_string()) {
                            categories.push("suspicious_params".to_string());
                        }
                        suspicious_urls.push(analysis_url.to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "Opaque authentication token appears on a credential-related path: {}",
                                analysis_url.chars().take(100).collect::<String>(),
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(analysis_url.chars().take(200).collect()),
                        });
                    }
                }
            } // end if!is_trusted
        } // end for link in links

        // --- 7. Excessive URL count ---
        // HTML newsletters often contain many image/CSS/template resources.
        // Count only links that are not first-party/trusted resources; otherwise
        // an asset-heavy bank statement can be downgraded solely for having many
        // embedded URLs. Untrusted links are still checked individually above.
        let non_trusted_link_count = links
            .iter()
            .filter(|link| {
                let effective_url = unwrap_redirect_target_for_analysis(&link.url)
                    .unwrap_or_else(|| link.url.clone());
                if is_probable_opaque_mail_callback_url(&effective_url) {
                    return false;
                }
                // Render/static assets are excluded from the count only while
                // they behave like assets: object-storage content-override
                // parameters (?response-content-type=text/html) can turn a
                // ".jpg" into a served HTML page, so those stay countable.
                if (is_probable_non_clickable_render_asset_url(&effective_url)
                    || is_probable_safe_static_asset_url(&effective_url))
                    && !crate::modules::link_content::has_content_override_params(&effective_url)
                {
                    return false;
                }
                extract_domain_from_url(&effective_url).is_none_or(|domain| {
                    !is_trusted_url_domain(&domain) && !is_well_known_safe_domain(&domain)
                })
            })
            .count();
        if non_trusted_link_count > 15 {
            total_score += 0.08;
            categories.push("excessive_links".to_string());
            evidence.push(Evidence {
                description: format!(
                    "linkConnectCount多: {} 个非可信链接（Threshold 15）",
                    non_trusted_link_count
                ),
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
            let mut result = ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!("alreadyCheck {} linkConnect，未FoundAbnormal", links.len()),
                duration_ms,
            );
            result.details = serde_json::json!({
                "total_links": links.len(),
                "qr_decoded_links": ctx.decoded_qr_urls().len(),
                "opaque_token_observations": opaque_token_observations,
                "tracked_label_observations": tracked_label_observations,
                "operational_alert": operational_alert,
                "operational_management_link_observations": operational_management_link_observations,
            });
            return Ok(result);
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
                "qr_decoded_links": ctx.decoded_qr_urls().len(),
                "suspicious_urls": suspicious_urls,
                "unique_domains": unique_domain_list,
                "opaque_token_observations": opaque_token_observations,
                "tracked_label_observations": tracked_label_observations,
                "operational_alert": operational_alert,
                "operational_management_link_observations": operational_management_link_observations,
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

    fn make_ctx_with_urls(urls: &[&str]) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            links: urls
                .iter()
                .map(|url| EmailLink {
                    url: (*url).to_string(),
                    text: None,
                    suspicious: false,
                })
                .collect(),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[test]
    fn test_huawei_telemetry_callback_is_not_a_link_scan_candidate() {
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/clicknum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&urlPageIndex=f7cf6546-809b-4359-b402-b04ae180817a&urlIndex=d5431c23-7909-41fa-8c8b-0541cfd1ff17&key=92e3d69690d94e58685eec9ecaf3e3e93d5d63f6716ad3543aa4caa6869b9de6",
            Some("问卷链接"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.details["opaque_token_observations"], 0);
        assert!(result.categories.is_empty());
        assert!(result.evidence.is_empty());
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
    fn trusted_open_redirect_uses_inner_target_for_analysis() {
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://docs.google.com/url?q=http%3A%2F%2F203.0.113.60%2Flogin",
            Some("查看详情"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"ip_url".to_string()),
            "{result:?}"
        );
        assert!(
            result.evidence.iter().any(|item| item
                .snippet
                .as_deref()
                .is_some_and(|value| value.contains("203.0.113.60/login"))),
            "evidence must point at the inner destination: {result:?}"
        );
    }

    #[test]
    fn benign_trusted_redirect_target_does_not_inherit_wrapper_risk() {
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://docs.google.com/url?q=https%3A%2F%2Fwww.google.com%2Fhelp",
            Some("查看帮助"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"ip_url".to_string()),
            "{result:?}"
        );
        assert!(
            !result.categories.contains(&"userinfo_in_url".to_string()),
            "{result:?}"
        );
    }

    #[test]
    fn ordinary_shared_document_query_is_not_treated_as_redirect() {
        assert_eq!(
            unwrap_redirect_target_for_analysis(
                "https://docs.google.com/document/d/benign?src=http%3A%2F%2F203.0.113.60%2Flogin"
            ),
            None
        );
    }

    #[test]
    fn untrusted_outer_url_is_not_replaced_by_benign_next_target() {
        assert_eq!(
            unwrap_redirect_target_for_analysis(
                "https://evil.example/login?next=https%3A%2F%2Fwww.google.com%2Fhelp"
            ),
            None
        );
    }

    #[test]
    fn jina_path_wrapper_recovers_ip_login_target() {
        assert_eq!(
            unwrap_redirect_target_for_analysis("https://r.jina.ai/http://203.0.113.60/login"),
            Some("http://203.0.113.60/login".to_string())
        );
    }

    #[test]
    fn test_operational_ddei_management_url_is_observation_only() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("notifications@ddei.example".to_string());
        session.subject = Some("DDEI 严重 - 系统警报 - 中继MTA服务器不可达".to_string());
        session.content = EmailContent {
            body_text: Some(
                "Deep Discovery Email Inspector无法发送以下邮件到中继MTA服务器\n\
                 以下中继MTA服务器不可达：[198.51.100.68]:25"
                    .to_string(),
            ),
            links: vec![EmailLink {
                url: "https://10.0.0.41/loginPage.ddei".to_string(),
                text: Some("https://10.0.0.41/loginPage.ddei".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkScanModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.is_empty());
        assert_eq!(result.details["operational_alert"], true);
        assert_eq!(
            result.details["operational_management_link_observations"],
            1
        );
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

        assert!(
            result
                .categories
                .contains(&"href_text_mismatch".to_string())
        );
    }

    #[test]
    fn test_machine_tracking_text_is_not_treated_as_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://etrack01.com/track/click2/tokenized-path.html",
            Some(
                "https://tracking-gateway.invalid/click?url=https%3A%2F%2Fassets.vendor.example&trace=fixture",
            ),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "machine-generated tracking URL text should not be treated as deceptive label: {:?}",
            result.categories
        );
    }

    fn make_ctx_with_labeled_links(links: &[(&str, &str)]) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            links: links
                .iter()
                .map(|(url, text)| EmailLink {
                    url: (*url).to_string(),
                    text: Some((*text).to_string()),
                    suspicious: false,
                })
                .collect(),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    /// Production false positive (2026-11-13): an event invitation sent through
    /// the lingxi360 ESP reached Critical because every click-tracked link
    /// showed its real destination as text.
    #[test]
    fn esp_click_tracking_links_showing_their_destination_are_not_mismatches() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));
        let ctx = make_ctx_with_labeled_links(&[
            (
                "https://etrack01.com/track/click2/eNptjr1uwkAQhN",
                "https://wen.1xi.co/IW8aNeF",
            ),
            (
                "https://etrack01.com/track/click2/eNptjz1zwjAQRP",
                "https://v.wjx.cn/vm/h4La06R.aspx#",
            ),
            (
                "https://etrack01.com/track/click2/eNptj8tOwzAQRf",
                "https://wj.qq.com/s2/27383562/e95e/",
            ),
            (
                "https://etrack01.com/track/click2/eNptjs0OgjAQhN",
                "https://chinasif.org/",
            ),
        ]);

        let result = analyze_with_runtime(&LinkScanModule::new(), &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "{:?}",
            result.categories
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.details["tracked_label_observations"], 4);
    }

    #[test]
    fn official_domain_claim_behind_a_tracker_path_is_still_a_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));
        let ctx = make_ctx(
            "https://portal-check.invalid/track/click/abc",
            Some("https://www.gov.cn"),
        );

        let result = analyze_with_runtime(&LinkScanModule::new(), &ctx);

        assert!(
            result
                .categories
                .contains(&"official_domain_text_mismatch".to_string()),
            "{:?}",
            result.categories
        );
    }

    #[test]
    fn generic_href_mismatches_cannot_accumulate_to_critical() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));
        let ctx = make_ctx_with_labeled_links(&[
            ("https://mailer.invalid/a", "https://news-one.example/"),
            ("https://mailer.invalid/b", "https://news-two.example/"),
            ("https://mailer.invalid/c", "https://news-three.example/"),
            ("https://mailer.invalid/d", "https://news-four.example/"),
        ]);

        let result = analyze_with_runtime(&LinkScanModule::new(), &ctx);

        assert!(
            result
                .categories
                .contains(&"href_text_mismatch".to_string())
        );
        assert!(
            result.threat_level <= ThreatLevel::Medium,
            "{:?}",
            result.threat_level
        );
    }

    #[test]
    fn ddei_clicktime_rewrite_is_analyzed_at_its_inner_target() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));
        let ctx = make_ctx(
            "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=http%3a%2f%2f203.0.113.10%2fpage&umid=fixture",
            None,
        );

        let result = analyze_with_runtime(&LinkScanModule::new(), &ctx);

        assert!(
            result.categories.contains(&"ip_url".to_string()),
            "{:?}",
            result.categories
        );
    }

    #[test]
    fn test_protocol_only_text_from_mail_gateway_is_not_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://safelinks.example.test/?url=https%3A%2F%2Fwww.ratian.com%2F",
            Some("http://"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "a protocol-only visible label is not a deceptive domain label: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_descriptive_filename_text_is_not_treated_as_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://product-support.vendor.invalid/package/detail?id=fixture-package-id",
            Some("攻击检测引擎升级包5.11.24-arm64"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
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
            "https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=fixture-card%40example.com&code=fixture-code",
            Some("测试联系人 fixture-card@example.com"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "contact-card text whose email is embedded in the destination URL should not be treated as a deceptive URL label: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_same_registered_domain_text_and_www_host_are_not_href_mismatch() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        let ctx = make_ctx("https://www.rail.example", Some("rail.example"));

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "same registrable domain should not be treated as deceptive label: {:?}",
            result.categories
        );
    }

    #[test]
    fn descriptive_official_domain_text_matches_www_href() {
        assert!(text_and_url_domains_equivalent(
            "Manage Tokens on npmjs.com",
            "www.npmjs.com"
        ));
    }

    #[test]
    fn descriptive_lookalike_domain_text_does_not_match_href() {
        assert!(!text_and_url_domains_equivalent(
            "Manage Tokens on bad-npmjs.com",
            "www.npmjs.com"
        ));
    }

    #[test]
    fn descriptive_text_with_unrelated_second_domain_keeps_mismatch() {
        assert!(!text_and_url_domains_equivalent(
            "Manage tokens at npmjs.com using attacker.example",
            "www.npmjs.com"
        ));
    }

    #[test]
    fn test_safe_and_trusted_domain_sets_are_separate() {
        let _guard = lock_url_domain_set_test_guard();
        let mut trusted = HashSet::new();
        trusted.insert("*.mail.qq.com".to_string());
        set_trusted_url_domains(Arc::new(trusted));

        let mut safe = HashSet::new();
        safe.insert("*.microsoft.com".to_string());
        set_well_known_safe_domains(Arc::new(safe));

        assert!(is_trusted_url_domain("wx.mail.qq.com"));
        assert!(!is_trusted_url_domain("microsoft.com"));
        assert!(is_well_known_safe_domain("login.microsoft.com"));
    }

    #[test]
    fn test_safe_mail_resource_url_skips_suspicious_params_without_trusted_cache() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://wx.mail.qq.com/info/get_mailhead_icon?key=MBLLmnJ6KVsQGy6nRRZQne96NS4zwRWy3hACPff49oZr&r=2085971486",
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"suspicious_params".to_string()),
            "known QQ webmail resource URLs should not be treated as phishing token links: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_qq_ftn_download_resource_is_safe_with_opaque_params() {
        assert!(is_known_safe_tokenized_resource_url(
            "https://wx.mail.qq.com/ftn/download?func=3&key=opaque-download-token&code=opaque-code"
        ));
    }

    #[test]
    fn test_163_webmail_icon_resource_is_safe_with_opaque_params() {
        assert!(is_known_safe_tokenized_resource_url(
            "https://hermes.mail.163.com/mt/icon.gif?key=opaque-token&id=message"
        ));
    }

    #[test]
    fn test_aliyun_directmail_trace_resource_is_safe_with_recipient_metadata() {
        assert!(is_known_safe_tokenized_resource_url(
            "https://dm-cn.aliyuncs.com/trace/v1/report?bid=1&mf=sender%40mail.example&msgid=id&to=recipient%40example.com&tag=opentag&sign=opaque-sign"
        ));
    }

    #[test]
    fn test_first_party_tokenized_mail_resources_are_not_phishing_evidence() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        for url in [
            "https://dashi.163.com/html/cloud-attachment-download/abc?key=opaque-token",
            "https://kcart.alipay.com/web/bi.do?pg=opaque-page-token",
        ] {
            let result = analyze_with_runtime(&module, &make_ctx(url, Some("查看附件")));
            assert!(
                !result.categories.contains(&"suspicious_params".to_string())
                    && !result
                        .categories
                        .contains(&"href_text_mismatch".to_string()),
                "first-party tokenized resource must not create phishing evidence: {url}: {:?}",
                result.categories
            );
        }
    }

    #[test]
    fn test_trusted_vendor_export_link_skips_suspicious_params() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::from([
            "exports.vendor.example".to_string()
        ])));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://exports.vendor.example/offline-export?id=fixture-report&token=fixture-token",
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"suspicious_params".to_string()),
            "trusted vendor export links should not be treated as phishing token URLs: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_exact_trusted_domain_does_not_bleed_into_subdomains() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::from(["rail.vendor.example".to_string()])));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        assert!(is_trusted_url_domain("rail.vendor.example"));
        assert!(!is_trusted_url_domain("pay.rail.vendor.example"));
    }

    #[test]
    fn test_trusted_synthetic_newsletter_assets_do_not_trigger_excessive_links() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::from([
            "*.newsletter.example".to_string(),
            "*.assets.example".to_string(),
            "*.short.example".to_string(),
        ])));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let urls = [
            "https://portal.newsletter.example/newsletter/url-link?campaign=fixture&format=html",
            "https://go.short.example/c/fixture?variant=3",
            "https://site.assets.example/Router/invoke.html?url=fixtureapp%3A%2F%2Fopen%2Fitem",
            "https://res.assets.example/files/public/fixture-a.html",
            "https://res.assets.example/files/public/fixture-b.html",
            "https://billing.assets.example/bill/ten-day-bills",
            "https://go.short.example/fixture-route",
            "https://portal.newsletter.example/help/fixture-topic",
            "https://billing.assets.example/bill/daily_bill_01",
            "https://billing.assets.example/bill/daily_bill_02",
            "https://billing.assets.example/bill/daily_bill_03",
            "https://billing.assets.example/bill/daily_bill_04",
            "https://billing.assets.example/bill/daily_bill_05",
            "https://billing.assets.example/bill/daily_bill_06",
            "https://billing.assets.example/bill/daily_bill_07",
            "https://billing.assets.example/bill/daily_bill_08",
            "https://billing.assets.example/bill/daily_bill_09",
            "https://billing.assets.example/bill/daily_bill_stats",
        ];
        let result = analyze_with_runtime(&LinkScanModule::new(), &make_ctx_with_urls(&urls));
        assert!(!result.categories.contains(&"excessive_links".to_string()));

        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));
    }

    #[test]
    fn test_fake_gateway_host_does_not_unwrap() {
        assert_eq!(
            unwrap_mail_security_gateway_target(
                "https://safelinks.protection.outlook.com.evil.net/?url=https%3A%2F%2Fevil.example%2Flogin"
            ),
            None
        );
        assert!(!is_mail_security_gateway_pub(
            "https://safelinks.protection.outlook.com.evil.net/?url=https%3A%2F%2Fevil.example%2Flogin"
        ));
    }

    #[test]
    fn test_redirect_url_evidence_truncation_is_utf8_safe() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // Byte 80 falls in the middle of the 3-byte character '中':
        // 20 ("https://example.com/") + 59 ('a' * 59) = 79 bytes, then '中'.
        // A naive `&url[..80]` slice would panic on this input.
        let url = format!(
            "https://example.com/{}中?q=https%3A%2F%2Fevil.example%2Flogin",
            "a".repeat(59)
        );
        assert_eq!(&url.as_bytes()[79..82], "中".as_bytes());

        let module = LinkScanModule::new();
        let ctx = make_ctx(&url, None);
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"redirect_url".to_string()),
            "redirect param should be detected without panicking: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_suspicious_params_evidence_truncation_is_utf8_safe() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // Keep a multibyte character beyond the evidence preview boundary.
        // The credential path is the independent fact that promotes the
        // otherwise routine opaque token into a finding.
        let url = format!(
            "https://example.com/login/{}中?token=0123456789abcdef0",
            "a".repeat(79)
        );
        assert!(url.contains('中'));

        let module = LinkScanModule::new();
        let ctx = make_ctx(&url, None);
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"suspicious_params".to_string()),
            "token on a credential path should be detected without panicking: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_gateway_without_extractable_target_still_runs_redirect_checks() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // A redirect-looking query name without an HTTP(S) target is not
        // redirect evidence. Other structural checks must still run.
        let module = LinkScanModule::new();

        let ctx = make_ctx("https://urldefense.proofpoint.com/v2/url?q=notaurl", None);
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            !result.categories.contains(&"redirect_url".to_string()),
            "a non-URL q value must not be classified as a redirect: {:?}",
            result.categories
        );

        let ctx = make_ctx(
            "https://urldefense.proofpoint.com/v2/url?trace=fixture&token=fixture-opaque-token",
            None,
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            !result.categories.contains(&"suspicious_params".to_string()),
            "opaque gateway tracking tokens are context, not credential evidence: {:?}",
            result.categories
        );
        assert_eq!(result.details["opaque_token_observations"], 1);
    }

    #[test]
    fn test_generic_tracking_token_is_observed_but_safe() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let result = analyze_with_runtime(
            &LinkScanModule::new(),
            &make_ctx(
                "https://mailer.example.com/campaign/open?token=0123456789abcdef0",
                None,
            ),
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.details["opaque_token_observations"], 1);
        assert!(!result.categories.contains(&"suspicious_params".to_string()));
    }

    #[test]
    fn test_eloqua_and_utm_params_are_not_redirects() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let result = analyze_with_runtime(
            &LinkScanModule::new(),
            &make_ctx(
                "https://events.vendor.example/event?elq=fixture&elqTrackId=fixture-track&utm_source=newsletter&q_campaign=august",
                None,
            ),
        );

        assert!(
            !result.categories.contains(&"redirect_url".to_string()),
            "marketing parameters must not satisfy exact redirect names: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_repeated_redirect_cause_is_scored_once() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let urls: Vec<String> = (0..20)
            .map(|index| {
                format!(
                    "https://track.example/click/{index}?q=https%3A%2F%2Fevil.example%2Flogin%3Fcampaign%3D{index}"
                )
            })
            .collect();
        let url_refs: Vec<&str> = urls.iter().map(String::as_str).collect();
        let result = analyze_with_runtime(&LinkScanModule::new(), &make_ctx_with_urls(&url_refs));

        let redirect_evidence = result
            .evidence
            .iter()
            .filter(|item| item.description.contains("cross-organization redirect"))
            .count();
        assert_eq!(redirect_evidence, 1);
        assert_eq!(result.details["score"].as_f64(), Some(0.28));
    }

    #[test]
    fn test_gateway_with_extractable_target_skips_wrapper_param_checks() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // Successful unwrap: the analysis URL becomes the extracted target, and
        // the gateway wrapper's own redirect/auth params must not be flagged.
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.example.com%2Fhome",
            None,
        );
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"redirect_url".to_string()),
            "unwrapped gateway target must not inherit wrapper redirect params: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_obfuscated_ip_literal_urls_are_detected() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // RE_IP_URL only recognizes dotted-decimal hosts; hex, octal and
        // single-integer IPv4 forms (and IPv6 literals) previously slipped
        // through. WHATWG parsing normalizes them all to an IP host.
        let module = LinkScanModule::new();
        for url in [
            "http://0xC0A80001/login",
            "http://3232235521/login",
            "http://0300.0250.0001.0001/login",
            "http://[2001:db8::1]/login",
        ] {
            let result = analyze_with_runtime(&module, &make_ctx(url, None));
            assert!(
                result.categories.contains(&"ip_url".to_string()),
                "obfuscated IP-literal URL must be detected: {url}: {:?}",
                result.categories
            );
        }
    }

    #[test]
    fn test_dotted_decimal_ip_url_still_detected_via_fast_path() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        let result = analyze_with_runtime(&module, &make_ctx("http://192.0.2.10/login", None));
        assert!(result.categories.contains(&"ip_url".to_string()));
    }

    #[test]
    fn test_hostname_with_ip_like_prefix_is_not_ip_url_via_parse() {
        // "192.168.0.1.evil.example" matches the fast-path regex prefix, but a
        // plain hostname must never be parsed into an IP host.
        assert!(!matches!(
            url::Url::parse("http://192.168.0.1.evil.example/login").map(|u| u
                .host()
                .map(|h| matches!(h, url::Host::Ipv4(_) | url::Host::Ipv6(_)))),
            Ok(Some(true))
        ));
        assert!(url_host_is_ip("http://0xC0A80001/"));
        assert!(!url_host_is_ip("https://example.com/login"));
    }

    #[test]
    fn test_userinfo_authority_obfuscation_detected() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // PoC (B1-1): before the fix, `http://mail.qq.com:443@evil.tk/login`
        // could not be parsed at all (userinfo rejection), so href/text
        // mismatch and every host-based check were skipped. Now the real host
        // (evil.tk) is analyzed and userinfo itself is scored.
        let module = LinkScanModule::new();
        let ctx = make_ctx(
            "http://mail.qq.com:443@evil.tk/login",
            Some("https://mail.qq.com"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"userinfo_in_url".to_string()),
            "userinfo in the authority must be scored: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"href_text_mismatch".to_string()),
            "visible mail.qq.com label hiding evil.tk must be a mismatch: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_unparseable_href_is_recorded_as_weak_signal() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        // PoC (B1-3): `%40` inside the host is rejected by the WHATWG parser
        // but browsers/mail clients may still resolve it; such hrefs were
        // silently dropped at extraction. Two unreadable hrefs reach 0.20
        // (Low) so the category survives the Safe cutoff.
        let module = LinkScanModule::new();
        let ctx = make_ctx_with_urls(&["http://legit.com%40evil.com/", "http://[::1/login"]);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"unparseable_url".to_string()),
            "unparseable hrefs must produce the weak signal: {:?}",
            result.categories
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|item| { item.description.contains("legit.com%40evil.com") }),
            "the dropped href must appear in evidence: {:?}",
            result.evidence
        );
    }

    #[test]
    fn test_fully_encoded_absolute_href_is_canonicalized_before_analysis() {
        let _guard = lock_url_domain_set_test_guard();
        set_trusted_url_domains(Arc::new(HashSet::new()));
        set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkScanModule::new();
        let ctx = make_ctx_with_urls(&[
            "https%3A%2F%2Freports.vendor.example%2Fmonitor%2Fdaily%3Freport%3Dfixture",
        ]);
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"unparseable_url".to_string()),
            "a fully encoded absolute href is an encoding variant, not a parser differential: {:?}",
            result.categories
        );
        assert_eq!(
            decode_fully_encoded_absolute_http_url(
                "https%3A%2F%2Freports.vendor.example%2Fmonitor%2Fdaily"
            )
            .as_deref(),
            Some("https://reports.vendor.example/monitor/daily")
        );
    }
}
