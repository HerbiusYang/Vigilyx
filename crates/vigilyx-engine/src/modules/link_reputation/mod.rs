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
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use tokio::sync::RwLock;

use super::common::extract_domain_from_url;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};

use data::{
    BRAND_ANCHOR_DOMAINS, REDIRECT_SERVICE_DOMAINS, SHARED_DNS_PROVIDERS,
    SUSPICIOUS_SENDING_DOMAINS,
};
use heuristics::{
    analyze_domain_heuristics, extract_redirect_target_urls_full, extract_redirect_targets,
    get_registered_domain, get_tld,
};

/// NS cacheentry
struct NsCacheEntry {
    ns_base_domains: HashSet<String>,
    created_at: Instant,
}

/// NS cache TTL: 1 small
const NS_CACHE_TTL: Duration = Duration::from_secs(3600);
/// DNS QueryTimeout: 2
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

pub struct LinkReputationModule {
    meta: ModuleMetadata,
    domain_blacklist: HashSet<String>,
    resolver: TokioAsyncResolver,
    ns_cache: RwLock<HashMap<String, NsCacheEntry>>,
    intel: Option<IntelLayer>,
}

impl LinkReputationModule {
    pub fn new(intel: Option<IntelLayer>) -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = DNS_TIMEOUT;
        opts.attempts = 1;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

       // AddAddTimeout (Query 15, 3 Concurrent)
        let timeout_ms = if intel.is_some() { 8000 } else { 5000 };

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
            .iter()
            .map(|ns| {
                let ns_str = ns.to_string();
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

       // DNS (Shared DNS For DescriptionOwnership)
        let meaningful: Vec<_> = overlap
            .iter()
            .filter(|d| !SHARED_DNS_PROVIDERS.contains(&d.as_str()))
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

        if links.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.0,
                categories: vec![],
                summary: "Email body contains no links, skipping URL reputation analysis".to_string(),
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
        let mut redirect_targets: HashSet<String> = HashSet::new(); // From URL ParameterMediumDecodeof TargetDomain
        let mut redirect_target_urls: HashSet<String> = HashSet::new(); // From URL ParameterMediumDecodeof full TargetURL
        let mut redirect_exempt_outer: HashSet<String> = HashSet::new(); // already ServiceofOuter layerDomain (Analyze)
        for link in links {
            if let Some(domain) = extract_domain_from_url(&link.url) {
                unique_domains.insert(domain.clone());

               // Check if this is a tracking/redirect service or mail security gateway.
               // Gateway domains (Trend Micro DDEI, Proofpoint, etc.) rewrite URLs
               // with redirect params - the outer domain is legitimate and should be
               // exempt from heuristic analysis and intel queries.
                let is_redirect_service = REDIRECT_SERVICE_DOMAINS
                    .iter()
                    .any(|&rd| domain.contains(rd) || domain.ends_with(rd))
                    || crate::modules::link_scan::is_mail_security_gateway_pub(
                        &link.url.to_lowercase(),
                    );
                let target_urls = extract_redirect_target_urls_full(&link.url);
                let targets = extract_redirect_targets(&link.url);
                for target_url in &target_urls {
                    redirect_target_urls.insert(target_url.clone());
                }
                if !targets.is_empty() {
                    for target in &targets {
                        redirect_targets.insert(target.clone());
                        unique_domains.insert(target.clone());
                    }
                    if is_redirect_service {
                       // already Service (if adnxs.com, doubleclick.net),
                       // Outer layerDomain Legitimate,hopsHeuristicAnalyzeAnd Query.
                       // Decode ofTargetDomain NormalAnalyze.
                        redirect_exempt_outer.insert(domain);
                    }
                }
            }
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut suspicious_domains: Vec<String> = Vec::new();

       // Recording TargetDomain (Info According to, Add).
       // TargetDomain ofHeuristicAnalyzeAnd QueryMediumindependent.
        for target_url in &redirect_target_urls {
            evidence.push(Evidence {
                description: format!(
                    "URL redirect target: {} (decoded from tracking/ad link)",
                    target_url
                ),
                location: Some("links:redirect".to_string()),
                snippet: Some(target_url.clone()),
            });
            categories.push("redirect_target".to_string());
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
                    description: format!("Parent domain {} matched malicious domain blocklist", reg_domain),
                    location: Some("links".to_string()),
                    snippet: Some(format!("{} -> {}", domain, reg_domain)),
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

           // --- detect (DNS NS) ---
            let tld = get_tld(domain);
            let domain_no_tld = domain.strip_suffix(&format!(".{}", tld)).unwrap_or(domain);
            for &(brand, anchor) in BRAND_ANCHOR_DOMAINS {
                if !domain_no_tld.contains(brand) {
                    continue;
                }
               // if RegisterDomain Domain -> Official
                if reg_domain == anchor {
                    break;
                }
               // DNS NS: Query NS,JudgewhetherSame1
                match self.is_same_org_by_ns(&reg_domain, anchor).await {
                    Some(true) => {
                       // NS Same -> Same1,
                        break;
                    }
                    Some(false) => {
                       // NS Same -> large
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
                       // DNS QueryFailed allUse DNS -> Judge, Add
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

            for domain in &unique_domains {
               // already Medium Name ofDomain
                if self.domain_blacklist.contains(domain) {
                    continue;
                }
               // already ServiceOuter layerDomain (if adnxs.com)
                if redirect_exempt_outer.contains(domain) {
                    continue;
                }

               // According toRegisterDomainDeduplicate (Same1RegisterDomainonly 1Time/Count)
                let reg_domain = get_registered_domain(domain);
                if queried_reg_domains.contains(&reg_domain) {
                    continue;
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
                        tokio::time::timeout(Duration::from_secs(15), intel_c.query_ip(&dom)).await
                    } else {
                        tokio::time::timeout(Duration::from_secs(15), intel_c.query_domain(&dom))
                            .await
                    };
                    match query_result {
                        Ok(result) => Some((dom, result)),
                        Err(_) => {
                            tracing::warn!(domain = dom.as_str(), "External intel query timed out (15s)");
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
                            total_score += 0.60;
                            categories.push("intel_malicious".to_string());
                            suspicious_domains.push(domain.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "External intel flagged as malicious: {} (source: {}, {})",
                                    domain,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
                                location: Some("intel".to_string()),
                                snippet: Some(domain),
                            });
                        }
                        "suspicious" => {
                            total_score += 0.25;
                            categories.push("intel_suspicious".to_string());
                            suspicious_domains.push(domain.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "External intel flagged as suspicious: {} (source: {}, {})",
                                    domain,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
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
                                    intel_result.details.as_deref().unwrap_or("no threat records")
                                ),
                                location: Some("intel".to_string()),
                                snippet: Some(domain),
                            });
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
                    if intel_urls.len() >= 5 {
                        break;
                    }
                    if !candidate.starts_with("http://") && !candidate.starts_with("https://") {
                        continue;
                    }
                    if queried_urls.insert(candidate.clone()) {
                        intel_urls.push(candidate);
                    }
                }
                if intel_urls.len() >= 5 {
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
                    match tokio::time::timeout(
                        Duration::from_secs(15),
                        intel_c.query_url(&url_owned),
                    )
                    .await
                    {
                        Ok(result) => Some((url_owned, result)),
                        Err(_) => {
                            tracing::warn!(url = url_owned.as_str(), "URL intel query timed out (15s)");
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
                            total_score += 0.65;
                            categories.push("url_intel_malicious".to_string());
                            suspicious_domains.push(url.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "URL intel flagged as malicious: {} (source: {}, {})",
                                    url,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
                                location: Some("intel:url".to_string()),
                                snippet: Some(url),
                            });
                        }
                        "suspicious" => {
                            total_score += 0.30;
                            categories.push("url_intel_suspicious".to_string());
                            suspicious_domains.push(url.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "URL intel flagged as suspicious: {} (source: {}, {})",
                                    url,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
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
                                    intel_result.details.as_deref().unwrap_or("no threat records")
                                ),
                                location: Some("intel:url".to_string()),
                                snippet: Some(url),
                            });
                        }
                    }
                }
            }
        }

       // --- SendingDomainReputationCheck ---
        for (name, value) in &ctx.session.content.headers {
            if name.to_lowercase() == "received" {
                let val_lower = value.to_lowercase();
                for &sus_domain in SUSPICIOUS_SENDING_DOMAINS {
                    if val_lower.contains(sus_domain) {
                        total_score += 0.15;
                        categories.push("suspicious_sender_domain".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "SendServiceDevice/HandlerDomainSuspicious: {}",
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
                categories: vec![],
                summary: format!(
                    "Analyzed {} domains, no reputation anomalies found ({})",
                    domain_list.len(),
                    intel_status,
                ),
                evidence, // packetContains Query (Contains clean Result)
                details: serde_json::json!({
                    "unique_domains": domain_list,
                    "blacklist_size": self.domain_blacklist.len(),
                    "intel_enabled": self.intel.is_some(),
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

    
   // Malicious/Suspicious URL Test
    

    #[tokio::test]
    async fn test_suspicious_tld_tk() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://free-prize.tk/claim"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"suspicious_tld".to_string()));
    }

    #[tokio::test]
    async fn test_suspicious_tld_xyz() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["https://login-verify.xyz/account"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
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
    async fn test_random_domain_dga() {
        let module = LinkReputationModule::new(None);
       // DGA ofrandomDomain
        let ctx = make_ctx(&["http://xvkrnbstq.com/payload"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"random_domain".to_string()));
    }

    #[tokio::test]
    async fn test_long_domain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&[
            "http://this-is-a-very-long-domain-name-used-for-phishing-attacks.com/login",
        ]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"long_domain".to_string()));
    }

    #[tokio::test]
    async fn test_deep_subdomain() {
        let module = LinkReputationModule::new(None);
        let ctx = make_ctx(&["http://a.b.c.d.e.evil.com/phish"]);
        let result = module.analyze(&ctx).await.unwrap();
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"deep_subdomain".to_string()));
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
        assert_ne!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.contains(&"numeric_domain".to_string()));
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
       // 0.15 (suspicious_tld) + 0.20 (random_domain) = 0.35
        assert!(score >= 0.30, "combo score = {}, expected >= 0.30", score);
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
        assert_ne!(result.threat_level, ThreatLevel::Safe);
       // At least suspicious_tld
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
        assert!(score >= 0.15);
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
    #[ignore] // Requires external PostgreSQL: TEST_DATABASE_URL=postgres://...
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
}
