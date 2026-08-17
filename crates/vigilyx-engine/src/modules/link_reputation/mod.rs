//! URL ReputationQueryModule - HeuristicDomainAnalyze + Name Check + Query

//! detect: Suspicious TLD, (DNS NS),, longDomain, randomcharactersDomain,
//! www first (if wwwkp.privcat.com), IP Reputationwait
//! : IntelLayer Query VirusTotal/AbuseIPDB,Result Autocache IOC

mod data;
mod heuristics;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use tokio::sync::RwLock;

use super::common::{
    extract_domain_from_url, host_matches_domain_or_subdomain, is_probable_cloud_asset_host,
    is_probable_non_clickable_render_asset_url, is_probable_opaque_mail_callback_url,
    is_probable_schema_reference_url,
};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};
use crate::module_data::module_data;

use heuristics::{
    analyze_domain_heuristics, extract_redirect_target_urls_full, get_registered_domain, get_tld,
};

/// NS cacheentry
struct NsCacheEntry {
    ns_base_domains: HashSet<String>,
    created_at: Instant,
}

#[derive(Default, Clone, Copy)]
struct DomainUrlProfile {
    observed_urls: u32,
    non_asset_urls: u32,
}

impl DomainUrlProfile {
    fn observe_url(&mut self, url: &str) {
        self.observed_urls += 1;
        if !crate::modules::common::is_probable_safe_static_asset_url(url) {
            self.non_asset_urls += 1;
        }
    }

    fn is_static_cloud_asset_only(&self) -> bool {
        self.observed_urls > 0 && self.non_asset_urls == 0
    }
}

fn is_public_mail_service_domain(domain: &str) -> bool {
    let registered = get_registered_domain(domain);
    crate::pipeline::internal_domains::is_public_mail_domain(&registered)
}

fn should_skip_domain_reputation(domain: &str) -> bool {
    is_public_mail_service_domain(domain)
        || crate::modules::link_scan::is_well_known_safe_domain(domain)
        || crate::modules::link_scan::is_trusted_url_domain(domain)
}

fn is_shared_hosting_platform(domain: &str) -> bool {
    crate::modules::link_scan::is_shared_hosting_platform(domain)
}

fn should_skip_registered_domain_intel_for_host(domain: &str, registered_domain: &str) -> bool {
    domain != registered_domain
        && !is_shared_hosting_platform(domain)
        && should_skip_domain_reputation(registered_domain)
        && is_probable_cloud_asset_host(domain)
}

const REPUTATION_NOISE_TOLERANT_DOMAINS: &[&str] = &[
    // Social / collaboration platforms that often accumulate noisy public intel pulses.
    "facebook.com",
    "fb.com",
    "youtube.com",
    "youtu.be",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    // Microsoft / Office / Teams / Microsoft-owned short links.
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office365.com",
    "sharepoint.com",
    "live.com",
    "outlook.com",
    "aka.ms",
    "teams.microsoft.com",
    // SWIFT and Salesforce-hosted SWIFT service portals seen in customer mail.
    "swift.com",
    "swift.my.site.com",
    // WTW / Willis Towers Watson benefit and survey services.
    "wtwco.com",
    "willistowerswatson.com",
    "wtwrewardsdataintel.com",
    "wtwdataservices.com",
    // Tongcheng marketing/invoice infrastructure. Only OTX-only pulse noise is
    // suppressed; blacklist and non-OTX malicious intelligence remain active.
    "bootcdn.net",
    "17u.cn",
    "40017.cn",
    // Official banking / payment / fund domains. These should not become
    // high-confidence malicious solely from weak domain reputation noise.
    "cmbchina.com",
    "ccb.com",
    "abchina.com",
    "boc.cn",
    "bankofchina.com",
    "icbc.com.cn",
    "psbc.com",
    "bankcomm.com",
    "unionpay.com",
    "chinaunionpay.com",
    "southernfund.com",
    "efunds.com.cn",
    "bosera.com",
    "chinaamc.com",
    "htsc.com",
];

fn is_reputation_noise_tolerant_domain(domain: &str) -> bool {
    REPUTATION_NOISE_TOLERANT_DOMAINS
        .iter()
        .any(|trusted| host_matches_domain_or_subdomain(domain, trusted))
}

fn is_reputation_noise_tolerant_url(url: &str) -> bool {
    extract_domain_from_url(url).is_some_and(|domain| is_reputation_noise_tolerant_domain(&domain))
}

fn sender_registered_domain(ctx: &SecurityContext) -> Option<String> {
    ctx.session
        .mail_from
        .as_deref()
        .and_then(|mail_from| mail_from.rsplit('@').next())
        .map(get_registered_domain)
}

fn is_otx_only_source(source: &str) -> bool {
    let mut saw_any = false;
    for part in source.split('+') {
        if part != "otx" {
            return false;
        }
        saw_any = true;
    }
    saw_any
}

fn suspicious_domain_intel_score(
    source: &str,
    registered_domain: &str,
    sender_reg_domain: Option<&str>,
) -> Option<f64> {
    let same_org_family = sender_reg_domain.is_some_and(|sender| {
        let sender_registered = get_registered_domain(sender);
        let sender_stem = sender_registered.split('.').next().unwrap_or("");
        let domain_registered = get_registered_domain(registered_domain);
        let domain_stem = domain_registered.split('.').next().unwrap_or("");
        !sender_stem.is_empty() && sender_stem == domain_stem
    });

    let reputation_tolerant = is_reputation_noise_tolerant_domain(registered_domain);

    if is_otx_only_source(source) {
        if reputation_tolerant || sender_reg_domain == Some(registered_domain) || same_org_family {
            None
        } else {
            Some(0.10)
        }
    } else if reputation_tolerant {
        Some(0.05)
    } else {
        Some(0.25)
    }
}

fn malicious_domain_intel_score(source: &str, registered_domain: &str) -> Option<f64> {
    if is_otx_only_source(source) && is_reputation_noise_tolerant_domain(registered_domain) {
        None
    } else if is_reputation_noise_tolerant_domain(registered_domain) {
        Some(0.20)
    } else {
        Some(0.60)
    }
}

fn url_intel_score(verdict: &str, source: &str, url: &str) -> Option<f64> {
    let reputation_tolerant = is_reputation_noise_tolerant_url(url);
    match verdict {
        "malicious" if is_otx_only_source(source) && reputation_tolerant => None,
        "malicious" if reputation_tolerant => Some(0.10),
        "malicious" => Some(0.65),
        "suspicious" if is_otx_only_source(source) && reputation_tolerant => None,
        "suspicious" if reputation_tolerant => Some(0.05),
        "suspicious" => Some(0.30),
        _ => Some(0.0),
    }
}

/// NS cache TTL: 1 small
const NS_CACHE_TTL: Duration = Duration::from_secs(3600);
/// DNS QueryTimeout: 2
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_EXTERNAL_INTEL_DOMAINS: usize = 3;
const MAX_EXTERNAL_INTEL_URLS: usize = 3;

pub struct LinkReputationModule {
    meta: ModuleMetadata,
    domain_blacklist: HashSet<String>,
    resolver: TokioResolver,
    ns_cache: RwLock<HashMap<String, NsCacheEntry>>,
    intel: Option<IntelLayer>,
}

impl LinkReputationModule {
    pub fn new(intel: Option<IntelLayer>) -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = DNS_TIMEOUT;
        opts.attempts = 1;
        let mut resolver_builder = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        );
        *resolver_builder.options_mut() = opts;
        let resolver = resolver_builder
            .build()
            .expect("default DNS resolver configuration must be valid");

        let timeout_ms = intel
            .as_ref()
            .map(IntelLayer::link_reputation_timeout_ms)
            .unwrap_or(5000);

        Self {
            meta: ModuleMetadata {
                id: "link_reputation".to_string(),
                name: "URLReputationQuery".to_string(),
                description:
                    "Heuristic domain analysis + DNS NS brand verification + blocklist check + external intel query"
                        .to_string(),
                pillar: Pillar::Link,
                depends_on: vec![],
                timeout_ms,
                is_remote: intel.is_some(),
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            domain_blacklist: HashSet::new(),
            resolver,
            ns_cache: RwLock::new(HashMap::new()),
            intel,
        }
    }

    /// QueryDomainof NS Recording,Return nameserver ofRegisterDomainSet(withcache)
    async fn resolve_ns_base_domains(&self, domain: &str) -> Option<HashSet<String>> {
        // cache
        {
            let cache = self.ns_cache.read().await;
            if let Some(entry) = cache.get(domain)
                && entry.created_at.elapsed() < NS_CACHE_TTL
            {
                return Some(entry.ns_base_domains.clone());
            }
        }

        // DNS NS Query
        let ns_response = self.resolver.ns_lookup(domain).await.ok()?;
        let ns_domains: HashSet<String> = ns_response
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.to_string()),
                _ => None,
            })
            .map(|ns_str| {
                let ns_clean = ns_str.trim_end_matches('.').to_lowercase();
                get_registered_domain(&ns_clean)
            })
            .collect();

        if ns_domains.is_empty() {
            return None;
        }

        // writecache
        {
            let mut cache = self.ns_cache.write().await;
            cache.insert(
                domain.to_string(),
                NsCacheEntry {
                    ns_base_domains: ns_domains.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        Some(ns_domains)
    }

    /// DNS NS JudgeDomainwhether Official
    /// Return: Some(true) = Same1, Some(false) = Same, None = Judge
    async fn is_same_org_by_ns(&self, domain_reg: &str, brand_anchor: &str) -> Option<bool> {
        let domain_ns = self.resolve_ns_base_domains(domain_reg).await?;
        let brand_ns = self.resolve_ns_base_domains(brand_anchor).await?;

        // NS
        let overlap: HashSet<_> = domain_ns.intersection(&brand_ns).cloned().collect();
        if overlap.is_empty() {
            return Some(false); // NS Same -> Same
        }

        // DNS providers (Shared DNS providers do not prove ownership)
        let meaningful: Vec<_> = overlap
            .iter()
            .filter(|d| !module_data().contains("shared_dns_providers", d))
            .collect();

        if !meaningful.is_empty() {
            // Shared NS -> Same1 (if NS all qq.com ofServicehandler)
            return Some(true);
        }

        // allUse DNS For -> NS Judge
        None
    }
}

#[async_trait]
impl SecurityModule for LinkReputationModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let links = &ctx.session.content.links;
        let sender_reg_domain = sender_registered_domain(ctx);

        if links.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.0,
                categories: vec![],
                summary: "Email body contains no links, skipping URL reputation analysis"
                    .to_string(),
                evidence: vec![],
                details: serde_json::json!({
                    "unique_domains": Vec::<String>::new(),
                    "intel_enabled": self.intel.is_some(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(Bpa::vacuous()),
                engine_id: None,
            });
        }

        // Collect unique domains (Contains TargetParse)
        let mut unique_domains: HashSet<String> = HashSet::new();
        let mut redirect_target_urls: HashSet<String> = HashSet::new(); // From URL ParameterMediumDecodeof full TargetURL
        let mut untrusted_redirect_target_urls: HashSet<String> = HashSet::new();
        let mut redirect_exempt_outer: HashSet<String> = HashSet::new(); // already ServiceofOuter layerDomain (Analyze)
        let mut domain_profiles: HashMap<String, DomainUrlProfile> = HashMap::new();
        for link in links {
            if is_probable_schema_reference_url(&link.url)
                || is_probable_opaque_mail_callback_url(&link.url)
            {
                continue;
            }
            let target_urls = extract_redirect_target_urls_full(&link.url);
            let link_text_empty = link
                .text
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty);
            if link_text_empty
                && (is_probable_non_clickable_render_asset_url(&link.url)
                    || target_urls
                        .iter()
                        .any(|target| is_probable_non_clickable_render_asset_url(target)))
            {
                continue;
            }
            if let Some(domain) = extract_domain_from_url(&link.url) {
                unique_domains.insert(domain.clone());
                domain_profiles
                    .entry(domain.clone())
                    .or_default()
                    .observe_url(&link.url);

                // Check if this is a tracking/redirect service or mail security gateway.
                // Gateway domains (Trend Micro DDEI, Proofpoint, etc.) rewrite URLs
                // with redirect params - the outer domain is legitimate and should be
                // exempt from heuristic analysis and intel queries.
                let md = module_data();
                let redirect_domains = md.get_list("redirect_service_domains");
                let is_redirect_service = redirect_domains
                    .iter()
                    .any(|rd| host_matches_domain_or_subdomain(&domain, rd))
                    || crate::modules::link_scan::is_mail_security_gateway_pub(
                        &link.url.to_lowercase(),
                    );
                for target_url in &target_urls {
                    if is_probable_schema_reference_url(target_url) {
                        continue;
                    }
                    redirect_target_urls.insert(target_url.clone());
                    if !is_redirect_service {
                        untrusted_redirect_target_urls.insert(target_url.clone());
                    }
                    if let Some(target_domain) = extract_domain_from_url(target_url) {
                        unique_domains.insert(target_domain.clone());
                        domain_profiles
                            .entry(target_domain)
                            .or_default()
                            .observe_url(target_url);
                    }
                }
                if !target_urls.is_empty() && is_redirect_service {
                    // already Service (if adnxs.com, doubleclick.net),
                    // Outer layerDomain Legitimate,hopsHeuristicAnalyzeAnd Query.
                    // Decode ofTargetDomain NormalAnalyze.
                    redirect_exempt_outer.insert(domain);
                }
            }
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut suspicious_domains: Vec<String> = Vec::new();
        // A decoded target from a trusted security/marketing rewrite is
        // provenance, not an independent threat. The target domain is still
        // analyzed below. Generic, untrusted redirect parameters retain the
        // redirect_target category.
        for target_url in &redirect_target_urls {
            let untrusted = untrusted_redirect_target_urls.contains(target_url);
            evidence.push(Evidence {
                description: if untrusted {
                    format!(
                        "URL redirect target: {} (decoded from untrusted redirect parameter)",
                        target_url
                    )
                } else {
                    format!(
                        "URL rewrite target: {} (decoded from trusted redirect service; target analyzed separately)",
                        target_url
                    )
                },
                location: Some(if untrusted {
                    "links:redirect".to_string()
                } else {
                    "links:redirect_exempt_target".to_string()
                }),
                snippet: Some(target_url.clone()),
            });
            if untrusted {
                categories.push("redirect_target".to_string());
            }
        }

        for domain in &unique_domains {
            // --- already ServiceOuter layerDomain ---
            // if adnxs.com, doubleclick.net wait: Outer layerDomain Legitimate,
            // hopsHeuristicAnalyze/ detect/ Query, RecordingFor.
            if redirect_exempt_outer.contains(domain) {
                evidence.push(Evidence {
                    description: format!(
                        "Skipping known redirect service domain: {} (legitimate tracking/ad platform, target domain analyzed separately)",
                        domain
                    ),
                    location: Some("links:redirect_exempt".to_string()),
                    snippet: Some(domain.clone()),
                });
                continue;
            }

            // --- Name Check ---
            if self.domain_blacklist.contains(domain) {
                total_score += 0.80;
                categories.push("blacklisted_domain".to_string());
                suspicious_domains.push(domain.clone());
                evidence.push(Evidence {
                    description: format!("Domain {} matched malicious domain blocklist", domain),
                    location: Some("links".to_string()),
                    snippet: Some(domain.clone()),
                });
                continue;
            }
            let reg_domain = get_registered_domain(domain);
            if domain != &reg_domain && self.domain_blacklist.contains(&reg_domain) {
                total_score += 0.70;
                categories.push("blacklisted_parent_domain".to_string());
                suspicious_domains.push(domain.clone());
                evidence.push(Evidence {
                    description: format!(
                        "Parent domain {} matched malicious domain blocklist",
                        reg_domain
                    ),
                    location: Some("links".to_string()),
                    snippet: Some(format!("{} -> {}", domain, reg_domain)),
                });
                continue;
            }

            if domain_profiles
                .get(domain)
                .is_some_and(DomainUrlProfile::is_static_cloud_asset_only)
            {
                evidence.push(Evidence {
                    description: format!(
                        "Skipping cloud object-storage asset domain: {} (only static asset URLs observed)",
                        domain
                    ),
                    location: Some("links:asset".to_string()),
                    snippet: Some(domain.clone()),
                });
                continue;
            }

            // Skip public mail providers and other known-clean domains. These
            // domains are legitimate service infrastructure and frequently show
            // up in external intel feeds despite being benign in normal mail.
            if should_skip_domain_reputation(domain) && !is_shared_hosting_platform(domain) {
                // Keep structural observations (long/deep labels, etc.) for
                // analyst telemetry while excluding trusted service domains
                // from the score and from external reputation lookups.
                let (_, findings) = analyze_domain_heuristics(domain);
                for (description, category) in findings {
                    categories.push(category);
                    evidence.push(Evidence {
                        description: format!(
                            "Observed structural domain shape but skipped reputation scoring: {} ({})",
                            description, domain
                        ),
                        location: Some("links:safe".to_string()),
                        snippet: Some(domain.clone()),
                    });
                }
                evidence.push(Evidence {
                    description: format!(
                        "Skipping known-clean service domain from reputation heuristics: {}",
                        domain
                    ),
                    location: Some("links:safe".to_string()),
                    snippet: Some(domain.clone()),
                });
                continue;
            }

            // --- HeuristicAnalyze (Contains detect) ---
            let (domain_score, findings) = analyze_domain_heuristics(domain);
            if domain_score > 0.0 {
                total_score += domain_score;
                suspicious_domains.push(domain.clone());
                for (desc, category) in findings {
                    categories.push(category);
                    evidence.push(Evidence {
                        description: format!("{} ({})", desc, domain),
                        location: Some("links".to_string()),
                        snippet: Some(domain.clone()),
                    });
                }
            }

            // --- Brand impersonation detection (DNS NS comparison) ---
            let tld = get_tld(domain);
            let domain_no_tld = domain.strip_suffix(&format!(".{}", tld)).unwrap_or(domain);

            // Get brand anchor domains from module data registry
            // Collect into owned Vec before any .await to avoid holding RwLockReadGuard across await
            let brand_entries: Vec<(String, String)> = {
                let md = module_data();
                md.get_structured("brand_anchor_domains")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|entry| {
                                let brand = entry.get("keyword").and_then(|v| v.as_str())?;
                                let anchor = entry.get("domain").and_then(|v| v.as_str())?;
                                if brand.is_empty() || anchor.is_empty() {
                                    return None;
                                }
                                Some((brand.to_string(), anchor.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            for (brand, anchor) in &brand_entries {
                if !domain_no_tld.contains(brand.as_str()) {
                    continue;
                }
                // If registered domain matches anchor domain -> official
                if reg_domain == anchor.as_str() {
                    break;
                }
                // DNS NS comparison: query NS records to determine if same org
                match self.is_same_org_by_ns(&reg_domain, anchor).await {
                    Some(true) => {
                        // NS matches -> same org, not suspicious
                        break;
                    }
                    Some(false) => {
                        // NS differs -> likely impersonation
                        total_score += 0.35;
                        categories.push("brand_impersonation".to_string());
                        suspicious_domains.push(domain.clone());
                        evidence.push(Evidence {
                            description: format!(
                                "Suspected brand impersonation: domain contains \"{}\" but DNS infrastructure differs from {} ({})",
                                brand, anchor, domain
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(domain.clone()),
                        });
                        break;
                    }
                    None => {
                        // DNS query failed or all using shared DNS -> cannot determine
                        break;
                    }
                }
            }
        }

        // --- Query (IntelLayer Query VT/AbuseIPDB) ---
        if let Some(ref intel) = self.intel {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
            let mut queried_reg_domains: HashSet<String> = HashSet::new();
            let mut join_set = tokio::task::JoinSet::new();
            let query_timeout = intel.link_reputation_query_timeout();
            let mut intel_domain_candidates: Vec<&String> = unique_domains.iter().collect();
            intel_domain_candidates.sort_by(|left, right| {
                let left_score = analyze_domain_heuristics(left).0;
                let right_score = analyze_domain_heuristics(right).0;
                right_score
                    .total_cmp(&left_score)
                    .then_with(|| left.cmp(right))
            });

            for domain in intel_domain_candidates {
                // already Medium Name ofDomain
                if self.domain_blacklist.contains(domain) {
                    continue;
                }
                // already ServiceOuter layerDomain (if adnxs.com)
                if redirect_exempt_outer.contains(domain) {
                    continue;
                }
                if domain_profiles
                    .get(domain)
                    .is_some_and(DomainUrlProfile::is_static_cloud_asset_only)
                {
                    continue;
                }
                // Skip public mail providers and other known-clean domains to
                // prevent OTX/VT pollution from escalating legitimate service
                // links such as qq.com / 163.com / gmail.com.
                if should_skip_domain_reputation(domain) && !is_shared_hosting_platform(domain) {
                    continue;
                }
                // Trusted enterprise/social/financial domains can carry stale
                // OTX pulses or noisy registered-domain reputation (for example
                // SWIFT Salesforce portals under my.site.com). Keep structural
                // heuristics above, but avoid using weak domain reputation to
                // escalate them.
                if is_reputation_noise_tolerant_domain(domain) {
                    continue;
                }

                // According toRegisterDomainDeduplicate (Same1RegisterDomainonly 1Time/Count)
                let reg_domain = get_registered_domain(domain);
                if should_skip_registered_domain_intel_for_host(domain, &reg_domain) {
                    continue;
                }
                if queried_reg_domains.contains(&reg_domain) {
                    continue;
                }
                if queried_reg_domains.len() >= MAX_EXTERNAL_INTEL_DOMAINS {
                    break;
                }
                queried_reg_domains.insert(reg_domain.clone());

                let sem = semaphore.clone();
                let intel_c = intel.clone();
                let dom = reg_domain;
                let is_ip = domain.parse::<std::net::Ipv4Addr>().is_ok();

                join_set.spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return None,
                    };
                    let query_result = if is_ip {
                        tokio::time::timeout(query_timeout, intel_c.query_ip(&dom)).await
                    } else {
                        tokio::time::timeout(query_timeout, intel_c.query_domain(&dom)).await
                    };
                    match query_result {
                        Ok(result) => Some((dom, result)),
                        Err(_) => {
                            tracing::warn!(
                                domain = dom.as_str(),
                                timeout_ms = query_timeout.as_millis() as u64,
                                "External intel query timed out"
                            );
                            None
                        }
                    }
                });
            }

            // QueryResult
            while let Some(join_result) = join_set.join_next().await {
                if let Ok(Some((domain, intel_result))) = join_result {
                    if !intel_result.found {
                        continue;
                    }
                    match intel_result.verdict.as_str() {
                        "malicious" => {
                            let Some(score) =
                                malicious_domain_intel_score(&intel_result.source, &domain)
                            else {
                                evidence.push(Evidence {
                                    description: format!(
                                        "Ignoring weak intel hit on reputation-tolerant domain: {} ({})",
                                        domain,
                                        intel_result
                                            .details
                                            .as_deref()
                                            .unwrap_or("no additional details")
                                    ),
                                    location: Some("intel".to_string()),
                                    snippet: Some(domain),
                                });
                                continue;
                            };
                            total_score += score;
                            if score >= 0.60 {
                                categories.push("intel_malicious".to_string());
                            } else {
                                categories.push("intel_malicious_reduced".to_string());
                            }
                            suspicious_domains.push(domain.clone());
                            evidence.push(Evidence {
                                description: if score >= 0.60 {
                                    format!(
                                        "External intel flagged as malicious: {} (source: {}, {})",
                                        domain,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                } else {
                                    format!(
                                        "External intel flagged reputation-tolerant domain as malicious with reduced weight: {} (source: {}, {})",
                                        domain,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                },
                                location: Some("intel".to_string()),
                                snippet: Some(domain),
                            });
                        }
                        "suspicious" => {
                            let otx_only = is_otx_only_source(&intel_result.source);
                            let suspicious_score = suspicious_domain_intel_score(
                                &intel_result.source,
                                &domain,
                                sender_reg_domain.as_deref(),
                            );
                            if suspicious_score.is_none() {
                                evidence.push(Evidence {
                                    description: format!(
                                        "Ignoring OTX-only weak intel hit on sender-owned or reputation-tolerant domain: {} ({})",
                                        domain,
                                        intel_result.details.as_deref().unwrap_or("no additional details")
                                    ),
                                    location: Some("intel".to_string()),
                                    snippet: Some(domain),
                                });
                                continue;
                            }

                            let score = suspicious_score.unwrap_or(0.0);
                            total_score += score;
                            if !otx_only && score >= 0.25 {
                                categories.push("intel_suspicious".to_string());
                            } else if !otx_only {
                                categories.push("intel_suspicious_reduced".to_string());
                            }
                            suspicious_domains.push(domain.clone());
                            evidence.push(Evidence {
                                description: if otx_only {
                                    format!(
                                        "OTX-only weak intel flagged domain as suspicious: {} ({})",
                                        domain,
                                        intel_result
                                            .details
                                            .as_deref()
                                            .unwrap_or("no additional details")
                                    )
                                } else if score < 0.25 {
                                    format!(
                                        "External intel flagged reputation-tolerant domain as suspicious with reduced weight: {} (source: {}, {})",
                                        domain,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                } else {
                                    format!(
                                        "External intel flagged as suspicious: {} (source: {}, {})",
                                        domain,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                },
                                location: Some("intel".to_string()),
                                snippet: Some(domain),
                            });
                        }
                        // "clean" -> already Security, Add (Autocache IOC Name)
                        // Recording evidence Forfirst Query
                        _ => {
                            evidence.push(Evidence {
                                description: format!(
                                    "Domain {} reputation normal (source: {}, {})",
                                    domain,
                                    intel_result.source,
                                    intel_result
                                        .details
                                        .as_deref()
                                        .unwrap_or("no threat records")
                                ),
                                location: Some("intel".to_string()),
                                snippet: Some(domain.clone()),
                            });
                            // A clean/unknown intel response is not evidence that
                            // a newly registered DGA domain is benign: zero-day
                            // domains commonly have no VT record.  Preserve all
                            // structural DGA signals and only record the clean
                            // result as context.
                            if suspicious_domains
                                .iter()
                                .any(|d| get_registered_domain(d) == domain)
                            {
                                evidence.push(Evidence {
                                    description: format!(
                                        "Intel returned clean/unknown for {}, but structural DGA heuristics were retained",
                                        domain
                                    ),
                                    location: Some("intel:dga_preserved".to_string()),
                                    snippet: Some(domain.clone()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // ---: URL levelQuery (VT Scrape complete URL detect) ---
        // DomainQueryonlydetectDomainReputation;URL Query detect Maliciouspath(if /phishing/login.php)
        if let Some(ref intel) = self.intel {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
            let mut url_join_set = tokio::task::JoinSet::new();
            let mut queried_urls: HashSet<String> = HashSet::new();
            let mut intel_urls = Vec::new();
            let query_timeout = intel.link_reputation_query_timeout();

            for link in links {
                let link_domain = extract_domain_from_url(&link.url);
                let is_redirect_service = link_domain
                    .as_ref()
                    .is_some_and(|dom| redirect_exempt_outer.contains(dom));
                let mut candidates = if is_redirect_service {
                    extract_redirect_target_urls_full(&link.url)
                } else {
                    Vec::new()
                };
                if candidates.is_empty() {
                    candidates.push(link.url.clone());
                }

                for candidate in candidates {
                    if intel_urls.len() >= MAX_EXTERNAL_INTEL_URLS {
                        break;
                    }
                    if is_probable_schema_reference_url(&candidate)
                        || is_probable_opaque_mail_callback_url(&candidate)
                    {
                        continue;
                    }
                    if !candidate.starts_with("http://") && !candidate.starts_with("https://") {
                        continue;
                    }
                    if crate::modules::common::is_probable_cloud_asset_url(&candidate) {
                        continue;
                    }
                    if queried_urls.insert(candidate.clone()) {
                        intel_urls.push(candidate);
                    }
                }
                if intel_urls.len() >= MAX_EXTERNAL_INTEL_URLS {
                    break;
                }
            }

            for url_owned in intel_urls {
                let sem = semaphore.clone();
                let intel_c = intel.clone();

                url_join_set.spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return None,
                    };
                    match tokio::time::timeout(query_timeout, intel_c.query_url(&url_owned)).await {
                        Ok(result) => Some((url_owned, result)),
                        Err(_) => {
                            tracing::warn!(
                                url = url_owned.as_str(),
                                timeout_ms = query_timeout.as_millis() as u64,
                                "URL intel query timed out"
                            );
                            None
                        }
                    }
                });
            }

            while let Some(join_result) = url_join_set.join_next().await {
                if let Ok(Some((url, intel_result))) = join_result {
                    if !intel_result.found {
                        continue;
                    }
                    match intel_result.verdict.as_str() {
                        "malicious" => {
                            let Some(score) =
                                url_intel_score("malicious", &intel_result.source, &url)
                            else {
                                evidence.push(Evidence {
                                    description: format!(
                                        "Ignoring weak URL intel hit on reputation-tolerant URL: {} ({})",
                                        url,
                                        intel_result
                                            .details
                                            .as_deref()
                                            .unwrap_or("no additional details")
                                    ),
                                    location: Some("intel:url".to_string()),
                                    snippet: Some(url),
                                });
                                continue;
                            };
                            total_score += score;
                            if score >= 0.65 {
                                categories.push("url_intel_malicious".to_string());
                            } else {
                                categories.push("url_intel_malicious_reduced".to_string());
                            }
                            suspicious_domains.push(url.clone());
                            evidence.push(Evidence {
                                description: if score >= 0.65 {
                                    format!(
                                        "URL intel flagged as malicious: {} (source: {}, {})",
                                        url,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                } else {
                                    format!(
                                        "URL intel flagged reputation-tolerant URL as malicious with reduced weight: {} (source: {}, {})",
                                        url,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                },
                                location: Some("intel:url".to_string()),
                                snippet: Some(url),
                            });
                        }
                        "suspicious" => {
                            let Some(score) =
                                url_intel_score("suspicious", &intel_result.source, &url)
                            else {
                                evidence.push(Evidence {
                                    description: format!(
                                        "Ignoring weak URL intel hit on reputation-tolerant URL: {} ({})",
                                        url,
                                        intel_result
                                            .details
                                            .as_deref()
                                            .unwrap_or("no additional details")
                                    ),
                                    location: Some("intel:url".to_string()),
                                    snippet: Some(url),
                                });
                                continue;
                            };
                            total_score += score;
                            if score >= 0.30 {
                                categories.push("url_intel_suspicious".to_string());
                            } else {
                                categories.push("url_intel_suspicious_reduced".to_string());
                            }
                            suspicious_domains.push(url.clone());
                            evidence.push(Evidence {
                                description: if score >= 0.30 {
                                    format!(
                                        "URL intel flagged as suspicious: {} (source: {}, {})",
                                        url,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                } else {
                                    format!(
                                        "URL intel flagged reputation-tolerant URL as suspicious with reduced weight: {} (source: {}, {})",
                                        url,
                                        intel_result.source,
                                        intel_result.details.as_deref().unwrap_or("")
                                    )
                                },
                                location: Some("intel:url".to_string()),
                                snippet: Some(url),
                            });
                        }
                        _ => {
                            evidence.push(Evidence {
                                description: format!(
                                    "URL {} reputation normal (source: {}, {})",
                                    url,
                                    intel_result.source,
                                    intel_result
                                        .details
                                        .as_deref()
                                        .unwrap_or("no threat records")
                                ),
                                location: Some("intel:url".to_string()),
                                snippet: Some(url),
                            });
                        }
                    }
                }
            }
        }

        // --- Sending domain reputation check ---
        for (name, value) in &ctx.session.content.headers {
            if name.to_lowercase() == "received" {
                let val_lower = value.to_lowercase();
                for sus_domain in module_data().get_list("suspicious_sending_domains") {
                    if val_lower.contains(sus_domain) {
                        total_score += 0.15;
                        categories.push("suspicious_sender_domain".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "Suspicious sending service domain: {}",
                                sus_domain
                            ),
                            location: Some("headers:Received".to_string()),
                            snippet: Some(value.chars().take(200).collect()),
                        });
                    }
                }
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let domain_list: Vec<String> = unique_domains.into_iter().collect();
        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            let heuristic_observations = categories.clone();
            let intel_status = if self.intel.is_some() {
                "queried external intel (OTX/VT/AbuseIPDB)"
            } else {
                "heuristic analysis only"
            };
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.85,
                // Preserve non-actionable shape observations for analysts and
                // telemetry. Fusion excludes Safe module results, so these do
                // not become threat evidence until another fact corroborates
                // them and the aggregate reaches the Low threshold.
                categories: heuristic_observations.clone(),
                summary: format!(
                    "Analyzed {} domains, no reputation anomalies found ({})",
                    domain_list.len(),
                    intel_status,
                ),
                evidence, // packetContains Query (Contains clean Result)
                details: serde_json::json!({
                    "score": total_score,
                    "unique_domains": domain_list,
                    "suspicious_domains": suspicious_domains,
                    "blacklist_size": self.domain_blacklist.len(),
                    "intel_enabled": self.intel.is_some(),
                    "heuristic_observations": heuristic_observations,
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(Bpa::safe_analyzed()),
                engine_id: None,
            });
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.80,
            categories,
            summary: format!(
                "URL reputation analysis found {} suspicious domains: {}",
                suspicious_domains.len(),
                suspicious_domains.join(", ")
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "unique_domains": domain_list,
                "suspicious_domains": suspicious_domains,
                "blacklist_size": self.domain_blacklist.len(),
                "intel_enabled": self.intel.is_some(),
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
    use crate::context::SecurityContext;
    use crate::module::SecurityModule;
    use std::collections::HashSet;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    // Re-import heuristic helpers for unit tests
    use super::heuristics::{analyze_domain_heuristics, get_registered_domain, get_tld};

    /// BuildTest SecurityContext,packetContains of URL linkConnectList
    fn make_ctx(urls: &[&str]) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            headers: vec![("Subject".to_string(), "Test".to_string())],
            links: urls
                .iter()
                .map(|u| EmailLink {
                    url: u.to_string(),
                    text: None,
                    suspicious: false,
                })
                .collect(),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    // Legitimate URL Test

    #[tokio::test]
    async fn test_legitimate_no_links() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.summary.contains("no links"));
    }

    #[tokio::test]
    async fn test_legitimate_google_com() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://www.google.com/search?q=rust"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_legitimate_microsoft_com() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://www.microsoft.com",
            "https://outlook.office365.com/owa",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_huawei_telemetry_callbacks_are_not_reputation_candidates() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/clicknum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&urlPageIndex=f7cf6546-809b-4359-b402-b04ae180817a&urlIndex=d5431c23-7909-41fa-8c8b-0541cfd1ff17&key=92e3d69690d94e58685eec9ecaf3e3e93d5d63f6716ad3543aa4caa6869b9de6",
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82",
        ]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(
            result.details["unique_domains"].as_array().map(Vec::len),
            Some(0)
        );
    }

    #[tokio::test]
    async fn test_userinfo_url_real_host_enters_reputation_analysis() {
        // PoC (B1-1): before the fix, extract_domain_from_url rejected URLs
        // carrying userinfo, so `http://mail.qq.com:443@evil.tk/login` never
        // entered reputation analysis at all — the displayed "trusted" prefix
        // was a free blind spot. The real host after `@` must be analyzed.
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://mail.qq.com:443@evil.tk/login"]);
        let result = module.analyze(&ctx).await.unwrap();

        let domains: Vec<String> = result.details["unique_domains"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            domains.iter().any(|domain| domain == "evil.tk"),
            "the real destination host must be analyzed: {domains:?}"
        );
        assert!(
            !domains.iter().any(|domain| domain == "mail.qq.com"),
            "the deceptive userinfo prefix is not a destination: {domains:?}"
        );
    }

    #[tokio::test]
    async fn test_legitimate_github_com() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://github.com/anthropics/claude"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_legitimate_baidu_com() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://www.baidu.com"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_legitimate_163_com() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://mail.163.com"]);
        let result = module.analyze(&ctx).await.unwrap();
        // 163.com known_numeric Name Medium, Mark
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_object_storage_static_asset_domain_is_skipped() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login-banner.png?x-oss-process=image/resize,w_600",
        ]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"random_domain".to_string()),
            "object-storage asset domain should not be treated as suspicious: {:?}",
            result.categories
        );
    }

    // Malicious/Suspicious URL Test

    #[tokio::test]
    async fn test_suspicious_tld_tk() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://free-prize.tk/claim"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"suspicious_tld".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_tld_xyz() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://login-verify.xyz/account"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"suspicious_tld".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_tld_lol() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://iosmaziprices.lol"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"suspicious_tld".to_string()));
    }

    #[tokio::test]
    async fn test_free_hosting_ngrok() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://abc123.ngrok-free.app/phish"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"free_hosting".to_string()));
    }

    #[tokio::test]
    async fn test_free_hosting_herokuapp() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://fake-bank-login.herokuapp.com"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"free_hosting".to_string()));
    }

    #[tokio::test]
    async fn test_www_impersonation() {
        let module = LinkReputationModule::new(None);
        // wwwkp.privcat.com - www first +
        let ctx = make_ctx(&["http://wwwkp.privcat.com/login"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"www_impersonation".to_string()));
    }

    #[tokio::test]
    async fn test_numbered_www_subdomain_is_not_impersonation() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://www2.swift.com/knowledgecentre/kb_articles/87276"]);
        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"www_impersonation".to_string()),
            "numbered www subdomains are commonly legitimate infrastructure: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_random_domain_dga() {
        let module = LinkReputationModule::new(None);
        // DGA ofrandomDomain
        let ctx = make_ctx(&["http://xvkrnbstq.com/payload"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"random_domain".to_string()));
    }

    #[tokio::test]
    async fn test_legitimate_hundsun_domain_is_not_random() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://rep.hundsun.cn/report/clearance"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert!(
            !result.categories.contains(&"random_domain".to_string()),
            "Brand-like business domains should not be marked as random: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_seeded_safe_sendcloud_domain_skips_reputation_heuristics() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard_async().await;
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::from([
            "sendcloud.net".to_string(),
        ])));
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://sctrack.sendcloud.net/track/open2/test.gif"]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"random_domain".to_string()),
            "seeded safe domains should skip sendcloud tracking heuristics: {:?}",
            result.categories
        );
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));
    }

    #[tokio::test]
    async fn test_trusted_url_domain_skips_reputation_heuristics_even_without_safe_domain_seed() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard_async().await;
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "aliyuncs.com".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/offline-export?id=116eb8a2&token=aa6d62d9ef98b077a3fd3cc6ddbff7e3",
        ]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"random_domain".to_string()),
            "trusted URL domains should bypass reputation heuristics even if they are not in the safe-domain seed: {:?}",
            result.categories
        );

        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::new()));
    }

    #[test]
    fn test_cloud_asset_subdomain_skips_registered_domain_intel_when_root_is_trusted() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "aliyuncs.com".to_string(),
        ])));

        assert!(should_skip_registered_domain_intel_for_host(
            "qfk-files.oss-cn-hangzhou.aliyuncs.com",
            "aliyuncs.com"
        ));
        assert!(!should_skip_registered_domain_intel_for_host(
            "login.evil-example.com",
            "evil-example.com"
        ));

        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::new()));
    }

    #[tokio::test]
    async fn test_long_domain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "http://this-is-a-very-long-domain-name-used-for-phishing-attacks.com/login",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"long_domain".to_string()));
    }

    #[tokio::test]
    async fn test_deep_subdomain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://a.b.c.d.e.evil.com/phish"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_embedded_ip_in_domain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://192-168-1-1.evil.com/admin"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"embedded_ip".to_string()));
    }

    #[tokio::test]
    async fn test_numeric_domain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://88889999.com/transfer"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_known_numeric_brand_domain_is_not_flagged() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://www.12306.cn"]);
        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"numeric_domain".to_string()),
            "seeded numeric brand domains should bypass numeric-domain heuristic: {:?}",
            result.categories
        );
    }

    // Scenario: Signal Add

    #[tokio::test]
    async fn test_combo_suspicious_tld_plus_random() {
        let module = LinkReputationModule::new(None);
        // Suspicious TLD + randomDomain = Signal
        let ctx = make_ctx(&["http://xvkrnbstq.tk/payload"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        let score = result.details["score"].as_f64().unwrap();
        // Two independent shape facts converge at the actionable threshold.
        // A single TLD or DGA observation remains below it.
        assert!(score >= 0.15, "combo score = {}, expected >= 0.15", score);
    }

    #[tokio::test]
    async fn test_combo_free_hosting_plus_www_fake() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://wwwsecure.netlify.app/bank-login"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        // www_impersonation (0.25) + free_hosting (0.20)
        let score = result.details["score"].as_f64().unwrap();
        assert!(score >= 0.40, "combo score = {}, expected >= 0.40", score);
    }

    // : Legitimate + Malicious URL Same1emailMedium

    #[tokio::test]
    async fn test_mixed_legit_and_malicious() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://www.google.com",        // Legitimate
            "http://login-paypal.tk/verify", // Suspicious TLD
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        // The reputation module contributes only a weak TLD observation here;
        // brand/path deception belongs to link/content detectors.
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"suspicious_tld".to_string()));
    }

    // IntelLayer = None Heuristicmode

    #[tokio::test]
    async fn test_no_intel_pure_heuristic() {
        let module = LinkReputationModule::new(None);
        assert_eq!(module.meta.timeout_ms, 5000); // intel = 5s Timeout
        assert!(!module.meta.is_remote);
    }

    // function YuanTest

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            extract_domain_from_url("https://www.google.com/search"),
            Some("www.google.com".to_string())
        );
        assert_eq!(
            extract_domain_from_url("http://evil.tk:8080/payload"),
            Some("evil.tk".to_string())
        );
        assert_eq!(extract_domain_from_url("ftp://invalid"), None);
    }

    #[test]
    fn test_get_registered_domain() {
        assert_eq!(get_registered_domain("www.google.com"), "google.com");
        assert_eq!(get_registered_domain("a.b.c.evil.com"), "evil.com");
        assert_eq!(get_registered_domain("example.com"), "example.com");
    }

    #[test]
    fn test_get_tld() {
        assert_eq!(get_tld("example.com"), "com");
        assert_eq!(get_tld("evil.tk"), "tk");
        assert_eq!(get_tld("deep.sub.domain.xyz"), "xyz");
    }

    #[test]
    fn test_heuristic_clean_domain() {
        let (score, findings) = analyze_domain_heuristics("google.com");
        assert_eq!(score, 0.0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_heuristic_suspicious_tld() {
        let (score, _) = analyze_domain_heuristics("malware.tk");
        assert_eq!(score, 0.05);
    }

    #[test]
    fn test_heuristic_free_hosting() {
        let (score, _) = analyze_domain_heuristics("phish.herokuapp.com");
        assert!(score >= 0.20);
    }

    #[test]
    fn test_heuristic_www_impersonation() {
        let (score, findings) = analyze_domain_heuristics("wwwsafe.evil.com");
        assert!(score >= 0.25);
        assert!(findings.iter().any(|(_, cat)| cat == "www_impersonation"));
    }

    #[test]
    fn test_otx_only_sender_owned_domain_is_ignored() {
        assert_eq!(
            suspicious_domain_intel_score("otx", "swift.com", Some("swift.com")),
            None
        );
    }

    #[test]
    fn test_otx_only_non_sender_domain_is_only_weak_signal() {
        assert_eq!(
            suspicious_domain_intel_score("otx", "12306.cn", Some("rails.com.cn")),
            Some(0.10)
        );
    }

    #[test]
    fn test_otx_only_same_brand_cross_tld_is_ignored() {
        assert_eq!(
            suspicious_domain_intel_score("otx", "hundsun.com", Some("hundsun.cn")),
            None
        );
    }

    #[test]
    fn test_reputation_noise_tolerant_domains_match_subdomains_and_vendor_portals() {
        assert!(is_reputation_noise_tolerant_domain(
            "login.microsoftonline.com"
        ));
        assert!(is_reputation_noise_tolerant_domain("swift.my.site.com"));
        assert!(is_reputation_noise_tolerant_domain("survey.wtwco.com"));
        assert!(is_reputation_noise_tolerant_domain("static.linkedin.com"));
        assert!(is_reputation_noise_tolerant_domain("service.cmbchina.com"));
        assert!(is_reputation_noise_tolerant_domain("cdn.bootcdn.net"));
        assert!(is_reputation_noise_tolerant_domain("finance.17u.cn"));
        assert!(is_reputation_noise_tolerant_domain("file.40017.cn"));
        assert!(!is_reputation_noise_tolerant_domain(
            "microsoft-login.evil.example"
        ));
    }

    #[test]
    fn test_otx_only_reputation_tolerant_domain_is_ignored() {
        assert_eq!(
            suspicious_domain_intel_score("otx", "microsoftonline.com", Some("example.com")),
            None
        );
        assert_eq!(
            suspicious_domain_intel_score("otx", "linkedin.com", Some("example.com")),
            None
        );
    }

    #[test]
    fn test_non_otx_reputation_tolerant_domain_is_reduced() {
        assert_eq!(
            suspicious_domain_intel_score("virustotal", "microsoftonline.com", Some("example.com")),
            Some(0.05)
        );
        assert_eq!(
            malicious_domain_intel_score("virustotal", "microsoftonline.com"),
            Some(0.20)
        );
        assert_eq!(
            malicious_domain_intel_score("virustotal", "bootcdn.net"),
            Some(0.20)
        );
        assert_eq!(malicious_domain_intel_score("otx", "bootcdn.net"), None);
    }

    #[test]
    fn test_url_intel_on_reputation_tolerant_shortlinks_is_capped() {
        assert_eq!(
            url_intel_score("malicious", "virustotal", "https://aka.ms/joinmeeting"),
            Some(0.10)
        );
        assert_eq!(
            url_intel_score(
                "suspicious",
                "virustotal",
                "https://forms.office.com/pages/responsepage.aspx?id=abc"
            ),
            Some(0.05)
        );
        assert_eq!(
            url_intel_score("malicious", "virustotal", "https://evil.example/login"),
            Some(0.65)
        );
    }

    /// Domain Test - completeAnalyze
    #[tokio::test]
    async fn test_single_domain_debug() {
        let module = LinkReputationModule::new(None);
        let urls = &["http://xred.mooo.com/VNRecycler/VNRecycler.exe"];
        let ctx = make_ctx(urls);
        let result = module.analyze(&ctx).await.unwrap();

        println!("\n{}", "=".repeat(80));
        println!("  单DomainTest: xred.mooo.com (纯Heuristic, 无外部情报)");
        println!("{}", "=".repeat(80));
        println!("    threat: {:?}", result.threat_level);
        if let Some(score) = result.details.get("score") {
            println!("     score: {}", score);
        }
        println!("   summary: {}", result.summary);
        if !result.categories.is_empty() {
            println!("categories: {:?}", result.categories);
        }
        for ev in &result.evidence {
            println!("  evidence: {}", ev.description);
        }
        println!(
            "   details: {}",
            serde_json::to_string_pretty(&result.details).unwrap()
        );
        println!("{}", "=".repeat(80));
    }

    /// complete Test: IntelLayer (VT MaliciousResult) + LinkReputationModule

    /// Scenario: xred.mooo.com already C2 MaliciousDomain (OTX 10 Malicious)
    /// VT detectResult: EngineMark malicious
    /// Period: Heuristic (free_hosting 0.20) + (intel_malicious 0.60) = HIGH
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_xred_mooo_com_with_intel() {
        use crate::intel::{IntelLayer, IntelSourceConfig};
        use crate::ioc::IocManager;
        use vigilyx_db::VigilDb;

        // 1. CreateMemorydata + initializetable
        let db = VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();

        // 2. IOC: VT QueryResult alreadycache
        // data: OTX xred.mooo.com 10 Malicious
        let now = chrono::Utc::now();
        let ioc = vigilyx_core::security::IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: "mooo.com".to_string(),
            ioc_type: "domain".to_string(),
            source: "virustotal".to_string(),
            verdict: "malicious".to_string(),
            confidence: 0.75,
            attack_type: "c2".to_string(),
            first_seen: now,
            last_seen: now,
            hit_count: 1,
            context: Some(
                "malicious=12/94, OTX关联10Malicious样本, C2ServiceDevice/Handler".to_string(),
            ),
            expires_at: Some(now + chrono::Duration::hours(72)),
            created_at: now,
            updated_at: now,
        };
        db.upsert_ioc(&ioc).await.unwrap();

        // 3. construct IntelLayer (VT alreadycache, API)
        let ioc_manager = IocManager::new(db.clone());
        let config = IntelSourceConfig {
            otx_enabled: false, // IOC cache,
            vt_scrape_enabled: false,
            ..Default::default()
        };
        let intel = IntelLayer::new(
            ioc_manager,
            config,
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        );

        // 4. CreateModule + Analyze
        let module = LinkReputationModule::new(Some(intel));
        let ctx = make_ctx(&["http://xred.mooo.com/VNRecycler/VNRecycler.exe"]);
        let result = module.analyze(&ctx).await.unwrap();

        // 5. OutputcompleteResult
        println!("\n{}", "=".repeat(80));
        println!("  端到端Test: xred.mooo.com (Heuristic + VT 情报)");
        println!("{}", "=".repeat(80));
        println!("    threat: {:?}", result.threat_level);
        if let Some(score) = result.details.get("score") {
            println!("     score: {}", score);
        }
        println!("   summary: {}", result.summary);
        if !result.categories.is_empty() {
            println!("categories: {:?}", result.categories);
        }
        for ev in &result.evidence {
            println!("  evidence: {}", ev.description);
        }
        println!(
            "   details: {}",
            serde_json::to_string_pretty(&result.details).unwrap()
        );
        println!("{}", "=".repeat(80));

        // 6. Break/Judge: verdict HighRisk
        assert!(
            result.threat_level == ThreatLevel::High
                || result.threat_level == ThreatLevel::Critical,
            "xred.mooo.com (already知 C2 MaliciousDomain) 应被verdict  High/Critical, 实际: {:?}, score: {}",
            result.threat_level,
            result
                .details
                .get("score")
                .and_then(|s| s.as_f64())
                .unwrap_or(0.0)
        );
        // Same packetContainsHeuristicAnd According to
        assert!(
            result.categories.contains(&"free_hosting".to_string()),
            "应触发 free_hosting Heuristic"
        );
        assert!(
            result.categories.contains(&"intel_malicious".to_string()),
            "应触发 intel_malicious 情报"
        );
    }

    /// URL Test - completeModuleAnalyzeResult
    /// line: cargo test -p vigilyx-engine -- test_real_url_analysis --nocapture
    #[tokio::test]
    async fn test_real_url_analysis() {
        let module = LinkReputationModule::new(None);

        // TestUse case: (ScenarioName, URL List)
        let cases: Vec<(&str, Vec<&str>)> = vec![
            // Legitimate URL
            (
                "Legitimate: Google 搜索",
                vec!["https://www.google.com/search?q=rust+programming"],
            ),
            (
                "Legitimate: 微软 Office365",
                vec![
                    "https://login.microsoftonline.com/common/oauth2/authorize",
                    "https://outlook.office365.com/owa/",
                ],
            ),
            (
                "Legitimate: GitHub",
                vec!["https://github.com/anthropics/claude-code"],
            ),
            (
                "Legitimate: 网易email",
                vec!["https://mail.163.com", "https://mail.126.com"],
            ),
            ("Legitimate: 百度", vec!["https://www.baidu.com"]),
            (
                "Legitimate: 淘宝",
                vec!["https://www.taobao.com/markets/tbhome/list"],
            ),
            // Phishing URL ()
            (
                "Phishing: 仿冒 PayPal (.tk)",
                vec!["http://paypal-login-verify.tk/secure/update"],
            ),
            (
                "Phishing: 仿冒 Apple (.xyz)",
                vec!["https://apple-id-verify.xyz/account/login"],
            ),
            (
                "Phishing: 仿冒微软 (ngrok 隧道)",
                vec!["https://microsoft-login-abc123.ngrok-free.app/auth"],
            ),
            (
                "Phishing: 仿冒 Google (Heroku)",
                vec!["https://google-drive-share.herokuapp.com/view"],
            ),
            // Malicious
            (
                "Malicious: DGA RandomDomain",
                vec!["http://xvkrnbstqp.com/beacon"],
            ),
            (
                "Malicious: 免费Domain + Random",
                vec!["http://qxjrnbvft.tk/c2callback"],
            ),
            (
                "Malicious: IP 嵌入Domain",
                vec!["http://192-168-1-100.attacker.com/shell"],
            ),
            (
                "Malicious: 超深子Domain + longDomain",
                vec![
                    "http://secure.login.account.verify.update.this-is-definitely-not-a-legitimate-banking-portal.com/auth",
                ],
            ),
            // Attackmode ()
            (
                "Attack: www first缀伪装 + 免费托管",
                vec!["http://wwwsecure.netlify.app/banking/login"],
            ),
            (
                "Attack: Phishingemail常见混合 (Legitimate+Malicious)",
                vec![
                    "https://www.microsoft.com/en-us/microsoft-365", // LegitimatelinkConnect (AddAddTrusted)
                    "http://microsoft-account-verify.tk/Reset",      // MaliciouslinkConnect
                ],
            ),
            (
                "Attack: 纯 IP 数字Domain",
                vec!["http://88889999.com/transfer"],
            ),
            (
                "Attack: Wix 免费建站仿冒",
                vec!["https://mybank-secure-login.wixsite.com/portal"],
            ),
        ];

        println!("\n{}", "=".repeat(90));
        println!("  URL ReputationModule — 真实 URL AnalyzeResult ");
        println!("{}\n", "=".repeat(90));

        for (scenario, urls) in &cases {
            let ctx = make_ctx(urls);
            let result = module.analyze(&ctx).await.unwrap();

            let threat_icon = match result.threat_level {
                ThreatLevel::Safe => "[ SAFE ]",
                ThreatLevel::Low => "[ LOW  ]",
                ThreatLevel::Medium => "[MEDIUM]",
                ThreatLevel::High => "[ HIGH ]",
                ThreatLevel::Critical => "[ CRIT ]",
            };

            println!("{} {}", threat_icon, scenario);
            for u in urls {
                println!("       URL: {}", u);
            }
            println!("    threat: {:?}", result.threat_level);
            if let Some(score) = result.details.get("score") {
                println!("     score: {}", score);
            }
            println!("   summary: {}", result.summary);
            if !result.categories.is_empty() {
                println!("categories: {:?}", result.categories);
            }
            for ev in &result.evidence {
                println!("  evidence: {}", ev.description);
            }
            println!("  duration: {} ms", result.duration_ms);
            println!("{}", "-".repeat(90));
        }
    }

    // ServiceOuter layerDomain Test

    #[tokio::test]
    async fn test_redirect_service_adnxs_exempt() {
        // adnxs.com (Microsoft AppNexus) packet of URL
        // Outer layerDomain adnxs.com,onlyAnalyzeTargetDomain example.com
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://nym1-ib.adnxs.com/click2?clickenc=https%3A%2F%2Fwww.example.com%2Fpage",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "adnxs.com wrapping example.com should be safe, got {:?} with score {:?}",
            result.threat_level,
            result.details.get("score")
        );
        // Verify Recording evidence Medium
        assert!(
            result.evidence.iter().any(|e| e
                .description
                .contains("Skipping known redirect service domain")),
            "Should record redirect exemption in evidence"
        );
        assert!(
            !result.categories.contains(&"redirect_target".to_string()),
            "A trusted rewrite target is provenance, not a separate threat category"
        );
    }

    #[tokio::test]
    async fn test_untrusted_redirect_parameter_retains_redirect_target_category() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://example.com/track?url=https%3A%2F%2Fexample.org%2Flanding"]);
        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"redirect_target".to_string()),
            "An untrusted redirect parameter must remain reportable: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_tongcheng_invoice_asset_domains_do_not_create_structural_findings() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://finance.17u.cn/einvoice/download?id=example",
            "https://file.40017.cn/tcservice/post/picture/post-title.png",
            "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=https%3A%2F%2Fcdn.bootcdn.net%2Fajax%2Flibs%2Fnormalize%2F8.0.1%2Fnormalize.min.css",
        ]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        for category in ["numeric_domain", "random_domain", "redirect_target"] {
            assert!(
                !result.categories.contains(&category.to_string()),
                "Tongcheng invoice infrastructure should not emit {category}: {:?}",
                result.categories
            );
        }
    }

    #[tokio::test]
    async fn test_redirect_service_malicious_target_still_detected() {
        // immediately Outer layer Legitimate Service,MaliciousTargetDomain detect
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://nym1-ib.adnxs.com/click?clickenc=https%3A%2F%2Fxvkrnbstq.tk%2Fpayload",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        // xvkrnbstq.tk:.tk Suspicious TLD + randomDomain -> Mark
        assert!(
            result.threat_level > ThreatLevel::Safe,
            "Malicious target behind redirect service must still be detected, got {:?}",
            result.threat_level
        );
        assert!(
            result.categories.contains(&"suspicious_tld".to_string())
                || result.categories.contains(&"random_domain".to_string()),
            "Target domain should trigger heuristic categories: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_redirect_service_doubleclick_exempt() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://ad.doubleclick.net/ddm/trackclk/redirect=https%3A%2F%2Fwww.example.com%2Fpromo",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "doubleclick.net wrapping example.com should be safe"
        );
    }

    #[tokio::test]
    async fn test_redirect_exempt_does_not_skip_blacklisted() {
        // if Outer layerDomain Name Medium,immediately Service
        // (Whenfirst domain_blacklist, TestVerify)
        let module = LinkReputationModule::new(None);
        // sendgrid.net Service
        let ctx =
            make_ctx(&["https://track.sendgrid.net/redirect?url=https%3A%2F%2Fwww.example.com"]);
        let result = module.analyze(&ctx).await.unwrap();
        // sendgrid.net Name -> -> Safe
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_redirect_target_analyzed_not_outer() {
        // Verify: Outer layerDomain,ButTargetDomain found suspicious_domains Medium
        let module = LinkReputationModule::new(None);
        let ctx =
            make_ctx(&["https://nym1-ib.adnxs.com/click?clickenc=https%3A%2F%2Fmalware.tk%2Fdrop"]);
        let result = module.analyze(&ctx).await.unwrap();
        let empty = vec![];
        let suspicious = result
            .details
            .get("suspicious_domains")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty)
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        // TargetDomain malware.tk SuspiciousListMedium
        assert!(
            suspicious.iter().any(|d| d.contains("malware.tk")),
            "Redirect target domain should be in suspicious_domains: {:?}",
            suspicious
        );
        // Outer layerDomain adnxs.com SuspiciousListMedium
        assert!(
            !suspicious.iter().any(|d| d.contains("adnxs.com")),
            "Outer redirect service domain should NOT be in suspicious_domains: {:?}",
            suspicious
        );
    }

    #[tokio::test]
    async fn test_gateway_wrapped_showimg_asset_is_ignored() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "https://ddei3-0-ctp.asiainfo-sec.com:443/wis/clicktime/v1/query?url=http%3a%2f%2fhome.sumscope.com%3a8050%2fportal%2fsendcloud%2fshowImg%3fid%3d74916bf1ba5d4f7f9731941883c1ffc0&umid=test&auth=test",
        ]);
        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"redirect_target".to_string()),
            "non-clickable render assets should not emit redirect_target: {:?}",
            result.categories
        );
    }
}
