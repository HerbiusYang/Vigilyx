//! Threat intelligence query layer.
//!
//! Features:
//! - Unified query interface: IP / Domain / URL / Hash / SMTP
//! - Local IOC cache lookup
//! - Parallel queries: OTX AlienVault (free) + VT Scrape (Playwright) + AbuseIPDB
//! - Result fusion: take highest verdict, weighted-average confidence, merge details
//! - Auto-cache query results as IOC (TTL: clean 72h, malicious 30d, suspicious 1d)
//! - Per-source rate limiting to avoid API abuse

mod sources;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::ioc::IocManager;
use crate::modules::common::domain_matches_policy_set;
use vigilyx_core::{
    DEFAULT_INTERNAL_SERVICE_HOSTS, security::IocEntry, validate_internal_service_url,
};

/// Result of a threat intelligence query against one or more sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelResult {
    pub indicator: String,
    pub ioc_type: String,
    pub found: bool,
    pub verdict: String,
    pub confidence: f64,
    pub source: String,
    pub details: Option<String>,
}

impl IntelResult {
    fn not_found(indicator: &str, ioc_type: &str) -> Self {
        Self {
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            found: false,
            verdict: "unknown".to_string(),
            confidence: 0.0,
            source: "none".to_string(),
            details: None,
        }
    }

    fn from_ioc(ioc: &IocEntry) -> Self {
        Self {
            indicator: ioc.indicator.clone(),
            ioc_type: ioc.ioc_type.clone(),
            found: true,
            verdict: ioc.verdict.clone(),
            confidence: ioc.confidence,
            source: ioc.source.clone(),
            details: ioc.context.clone(),
        }
    }

    /// Return a numeric severity rank for a verdict string (higher = more severe).
    fn verdict_severity(verdict: &str) -> u8 {
        match verdict.to_ascii_lowercase().as_str() {
            "malicious" => 4,
            "suspicious" => 3,
            "clean" | "safe" => 2,
            "unknown" => 1,
            _ => 0,
        }
    }
}

/// True when `source` consists solely of external intel feeds (possibly merged
/// with `+`, e.g. "otx+vt_scrape"). Entries from any other source (auto /
/// manual / import / admin_clean / system) must never be overwritten by an
/// external feed result.
fn is_external_intel_source(source: &str) -> bool {
    !source.is_empty()
        && source
            .split('+')
            .all(|s| matches!(s, "otx" | "vt_scrape" | "virustotal" | "abuseipdb"))
}

/// Check whether `domain` appears in the safe-domain set.
///
/// The safe set is loaded from DB entries where source='system'|'admin_clean' and
/// verdict='clean'. Plain entries are exact-match only; `*.example.com` enables
/// explicit subdomain trust. It can also be managed via the admin UI.
fn is_domain_in_set(domain: &str, safe_set: &HashSet<String>) -> bool {
    domain_matches_policy_set(domain, safe_set)
}

/// Third-party reputation services must never receive private or internal
/// indicators. Local IOC lookups happen before this policy gate.
fn is_non_public_ip(value: &str) -> bool {
    let Ok(address) = value.parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (first & 0xfe00) == 0xfc00 // RFC 4193 unique-local
                || (first & 0xffc0) == 0xfe80 // RFC 4291 link-local
        }
    }
}

fn is_internal_domain(domain: &str) -> bool {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    let configured: Vec<String> = std::env::var("VIGILYX_INTERNAL_DOMAINS")
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    normalized == "localhost"
        || configured
            .iter()
            .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
        || [
            "local",
            "internal",
            "intranet",
            "lan",
            "corp",
            "home",
            "test",
            "example",
            "invalid",
        ]
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
}

fn external_intel_blocked(indicator: &str, ioc_type: &str) -> bool {
    match ioc_type {
        "ip" => is_non_public_ip(indicator),
        "domain" => is_internal_domain(indicator),
        "url" => url::Url::parse(indicator)
            .ok()
            .and_then(|parsed| parsed.host_str().map(is_internal_domain))
            .unwrap_or(false)
            || url::Url::parse(indicator)
                .ok()
                .and_then(|parsed| parsed.host_str().map(is_non_public_ip))
                .unwrap_or(false),
        _ => false,
    }
}

/// Reload the safe-domain cache into the given shared set (loaded from DB verdict='clean').
pub async fn reload_safe_domains_into(
    db: &vigilyx_db::VigilDb,
    target: &Arc<StdRwLock<HashSet<String>>>,
) {
    match db.load_clean_domains().await {
        Ok(domains) => {
            let set: HashSet<String> = domains.into_iter().collect();
            info!(count = set.len(), "Safe domain cache reloaded from DB");
            *target.write().expect("safe domain lock poisoned") = set;
        }
        Err(e) => warn!("Failed to reload safe domain cache: {}", e),
    }
}

/// Classify OTX pulse count into a verdict and confidence.
///
/// OTX is treated as a weak intel source. High-profile legitimate domains can
/// accumulate many public pulses, so OTX alone must never promote a domain to
/// "malicious". Strong verdicts should come from higher-signal sources such as
/// VT results, local IOC hits, or structural corroboration.
fn classify_otx_pulses(pulse_count: u64) -> (&'static str, f64) {
    if pulse_count >= 25 {
        ("suspicious", 0.45)
    } else if pulse_count >= 3 {
        ("suspicious", 0.28 + (pulse_count as f64 * 0.01).min(0.10))
    } else {
        ("clean", 0.8)
    }
}

/// IOC cache TTL (hours) for a cached external verdict.
///
/// Clean gets a short TTL: a long-lived clean cache can be pre-poisoned by an
/// attacker who seeds benign traffic before launching the real campaign.
fn cache_ttl_hours(verdict: &str) -> i64 {
    match verdict.to_ascii_lowercase().as_str() {
        "malicious" => 720,     // 30 days
        "clean" | "safe" => 72, // 3 days (was 15 days — pre-poisoning window)
        _ => 24,                // 1 day (suspicious / unknown)
    }
}

/// Configuration for external threat intelligence sources.
///
/// Uses `#[serde(default)]` so that legacy config JSON (containing old fields like
/// `virustotal_enabled`) can still deserialize -- missing new fields get their
/// `Default` values, and unknown fields are silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntelSourceConfig {
    /// OTX AlienVault (free, no API key required)
    pub otx_enabled: bool,
    /// VT Scrape - headless Playwright fetcher for VirusTotal results
    pub vt_scrape_enabled: bool,
    /// VT Scrape service URL (defaults to http://127.0.0.1:8900)
    pub vt_scrape_url: Option<String>,
    /// VirusTotal Official API v3 Key (preferred over VT scrape when set)
    pub virustotal_api_key: Option<String>,
    /// AbuseIPDB (requires API key)
    pub abuseipdb_enabled: bool,
    pub abuseipdb_api_key: Option<String>,
}

impl Default for IntelSourceConfig {
    fn default() -> Self {
        Self {
            otx_enabled: true,        // Free, enabled by default
            vt_scrape_enabled: false, // Optional AI bridge; explicit opt-in only
            vt_scrape_url: None,      // Defaults to http://127.0.0.1:8900 when enabled
            virustotal_api_key: None,
            abuseipdb_enabled: false,
            abuseipdb_api_key: None,
        }
    }
}

impl IntelSourceConfig {
    pub(super) fn vt_scrape_base_url(&self) -> String {
        let base = self.vt_scrape_url.clone().unwrap_or_else(|| {
            std::env::var("AI_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:8900".to_string())
        });
        base.trim().trim_end_matches('/').to_string()
    }

    fn link_reputation_query_timeout(&self) -> Duration {
        if self.vt_scrape_enabled {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(6)
        }
    }

    fn link_reputation_module_timeout_ms(&self) -> u64 {
        if self.vt_scrape_enabled {
            // At most one three-query domain batch and one three-query URL
            // batch, each with a 15-second operation deadline.
            40_000
        } else if self.virustotal_api_key.is_some() {
            // Official VT can be queried once at each stage through the
            // general five-second HTTP client.
            16_000
        } else {
            // OTX-only/default path performs one bounded external stage; URL
            // lookups are local IOC cache checks when no VT source is enabled.
            8_000
        }
    }
}

/// Per-source API rate limiter state.
pub(super) struct ApiRateLimit {
    max_per_minute: u32,
    minute_count: u32,
    minute_reset: Instant,
    /// Daily quota limit (None = unlimited)
    daily_quota: Option<u32>,
    day_count: u32,
    day_reset: Instant,
    /// True when daily quota exhausted until next day reset
    quota_exhausted: bool,
}

impl ApiRateLimit {
    pub(super) fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            minute_count: 0,
            minute_reset: Instant::now(),
            daily_quota: None,
            day_count: 0,
            day_reset: Instant::now(),
            quota_exhausted: false,
        }
    }

    pub(super) fn with_daily_quota(mut self, quota: u32) -> Self {
        self.daily_quota = Some(quota);
        self
    }

    /// Try to acquire one request slot. Returns false when rate-limited or quota exhausted.
    pub(super) fn try_acquire(&mut self) -> bool {
        let now = Instant::now();

        // Reset daily quota counter after 24 hours
        if now.duration_since(self.day_reset).as_secs() >= 86400 {
            self.day_count = 0;
            self.day_reset = now;
            self.quota_exhausted = false;
        }

        // Check daily quota
        if let Some(quota) = self.daily_quota
            && (self.quota_exhausted || self.day_count >= quota)
        {
            self.quota_exhausted = true;
            return false;
        }

        // Reset per-minute counter
        if now.duration_since(self.minute_reset).as_secs() >= 60 {
            self.minute_count = 0;
            self.minute_reset = now;
        }
        if self.minute_count >= self.max_per_minute {
            return false;
        }

        self.minute_count += 1;
        if self.daily_quota.is_some() {
            self.day_count += 1;
        }
        true
    }

    /// Mark quota as exhausted (e.g. on HTTP 429 response)
    pub(super) fn mark_exhausted(&mut self) {
        self.quota_exhausted = true;
    }

    pub(super) fn is_quota_exhausted(&self) -> bool {
        self.quota_exhausted
    }

    /// Non-mutating check: would a request slot be available right now?
    pub(super) fn would_allow(&self) -> bool {
        let now = Instant::now();

        if let Some(quota) = self.daily_quota {
            let day_count = if now.duration_since(self.day_reset).as_secs() >= 86400 {
                0
            } else {
                self.day_count
            };
            if self.quota_exhausted || day_count >= quota {
                return false;
            }
        } else if self.quota_exhausted {
            return false;
        }

        let minute_count = if now.duration_since(self.minute_reset).as_secs() >= 60 {
            0
        } else {
            self.minute_count
        };
        minute_count < self.max_per_minute
    }
}

/// Aggregated rate limiter state for all external API sources.
pub(super) struct RateLimiterState {
    pub(super) otx: ApiRateLimit,
    pub(super) vt_scrape: ApiRateLimit,
    /// VT official API: 4/min, 500/day (free tier)
    pub(super) vt_api: ApiRateLimit,
    pub(super) abuseipdb: ApiRateLimit,
}

/// Threat intelligence query layer.
#[derive(Clone)]
pub struct IntelLayer {
    pub(super) ioc: IocManager,
    pub(super) config: IntelSourceConfig,
    /// General HTTP client (5s timeout, used for OTX / official VT / AbuseIPDB)
    pub(super) http: reqwest::Client,
    /// VT Scrape HTTP client (25s timeout, Playwright needs longer)
    pub(super) http_vt: reqwest::Client,
    pub(super) rate_limiter: Arc<Mutex<RateLimiterState>>,
    /// Safe-domain cache loaded from DB (verdict='clean'); supports exact and suffix match.
    safe_domains: Arc<StdRwLock<HashSet<String>>>,
}

impl IntelLayer {
    pub fn new(
        ioc: IocManager,
        config: IntelSourceConfig,
        safe_domains: Arc<StdRwLock<HashSet<String>>>,
    ) -> Self {
        let vt_scrape_base_url = config.vt_scrape_base_url();
        let allow_internal_vt_auth = config.vt_scrape_enabled
            && validate_internal_service_url(&vt_scrape_base_url, DEFAULT_INTERNAL_SERVICE_HOSTS)
                .is_ok();
        if config.vt_scrape_enabled && !allow_internal_vt_auth {
            warn!(
                url = %vt_scrape_base_url,
                "SEC: VT scrape URL failed internal allowlist check; suppressing internal auth header"
            );
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        // SEC-H07: VT scrape request uses the AI-scoped internal token only
        let http_vt = {
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(25));
            if allow_internal_vt_auth {
                builder = builder.redirect(reqwest::redirect::Policy::none());
                if let Ok(token) = std::env::var("AI_INTERNAL_TOKEN") {
                    let mut headers = reqwest::header::HeaderMap::new();
                    if let Ok(v) = token.parse() {
                        headers.insert("X-Internal-Token", v);
                    }
                    builder = builder.default_headers(headers);
                }
            }
            builder.build().expect("VT scrape client should build")
        };

        let rate_limiter = Arc::new(Mutex::new(RateLimiterState {
            otx: ApiRateLimit::new(10),      // OTX: 10/min (free, no key)
            vt_scrape: ApiRateLimit::new(6), // VT Scrape: 6/min (Playwright)
            vt_api: ApiRateLimit::new(4).with_daily_quota(500), // VT API free: 4/min, 500/day
            abuseipdb: ApiRateLimit::new(15).with_daily_quota(1000), // AbuseIPDB free: 1000/day
        }));

        let safe_domain_count = safe_domains
            .read()
            .expect("safe domain lock poisoned")
            .len();
        info!(count = safe_domain_count, "Safe domain cache loaded");

        Self {
            ioc,
            config,
            http,
            http_vt,
            rate_limiter,
            safe_domains,
        }
    }

    /// Expose the safe-domains Arc so callers can pass it to `reload_safe_domains_into`.
    pub fn safe_domains_handle(&self) -> &Arc<StdRwLock<HashSet<String>>> {
        &self.safe_domains
    }

    pub fn link_reputation_query_timeout(&self) -> Duration {
        self.config.link_reputation_query_timeout()
    }

    pub fn link_reputation_timeout_ms(&self) -> u64 {
        self.config.link_reputation_module_timeout_ms()
    }

    /// Reload safe domain cache from DB.
    pub async fn reload_safe_domains(&self, db: &vigilyx_db::VigilDb) {
        reload_safe_domains_into(db, &self.safe_domains).await;
    }

    /// True when every enabled external source is currently rate-limited or
    /// quota-exhausted (for IP queries). Callers should degrade to local IOC
    /// lookup only and surface an `inspection_limited` signal instead of
    /// silently treating "no external answer" as "clean".
    pub async fn external_sources_saturated(&self) -> bool {
        let rl = self.rate_limiter.lock().await;
        let mut any_enabled = false;
        let mut any_available = false;
        if self.config.otx_enabled {
            any_enabled = true;
            any_available |= rl.otx.would_allow();
        }
        if self.config.virustotal_api_key.is_some() {
            any_enabled = true;
            any_available |= rl.vt_api.would_allow();
        }
        if self.config.vt_scrape_enabled {
            any_enabled = true;
            any_available |= rl.vt_scrape.would_allow();
        }
        if self.config.abuseipdb_enabled && self.config.abuseipdb_api_key.is_some() {
            any_enabled = true;
            any_available |= rl.abuseipdb.would_allow();
        }
        any_enabled && !any_available
    }

    /// Test helper: spend the whole OTX per-minute budget.
    #[cfg(all(test, feature = "infra-tests"))]
    pub(crate) async fn exhaust_otx_budget(&self) {
        let mut rl = self.rate_limiter.lock().await;
        while rl.otx.try_acquire() {}
    }

    // ============================================
    // Public query interface - parallel source queries + fusion
    // ============================================

    /// Query IP reputation (parallel: OTX + VT Scrape + AbuseIPDB).
    pub async fn query_ip(&self, ip: &str) -> IntelResult {
        self.query_ip_inner(ip, false).await
    }

    /// Query IP reputation, distrusting cached *clean* external results.
    ///
    /// External clean cache entries can be pre-poisoned (attacker seeds a
    /// clean verdict, then launches the real campaign within the TTL). When
    /// the current email already produced local detection signals, callers
    /// should use this variant so a cached clean verdict forces re-validation
    /// against live external sources. Non-clean cached verdicts are honored.
    pub async fn query_ip_revalidating(&self, ip: &str) -> IntelResult {
        self.query_ip_inner(ip, true).await
    }

    async fn query_ip_inner(&self, ip: &str, revalidate_clean: bool) -> IntelResult {
        // 1. Check local IOC cache first - exclude auto source to prevent amplification loops
        if let Some(ioc) = self.ioc.check_indicator_external_only("ip", ip).await {
            // Only *external* clean cache entries are distrusted under
            // revalidation; admin/system clean entries stay authoritative.
            let cached_external_clean =
                matches!(ioc.verdict.to_ascii_lowercase().as_str(), "clean" | "safe")
                    && is_external_intel_source(&ioc.source);
            if !(revalidate_clean && cached_external_clean) {
                return IntelResult::from_ioc(&ioc);
            }
        }

        if external_intel_blocked(ip, "ip") {
            warn!(indicator = %ip, "SEC: blocked third-party intel lookup for non-public IP");
            return IntelResult::not_found(ip, "ip");
        }

        // 2. Query all enabled external sources in parallel
        let (otx, vt_scrape, abuseipdb) = tokio::join!(
            self.query_otx_ip_if_enabled(ip),
            self.query_vt_scrape_if_enabled(ip, "ip"),
            self.query_abuseipdb_if_enabled(ip),
        );

        // 3. Fuse all results and cache
        self.fuse_and_cache(ip, "ip", &[otx, vt_scrape, abuseipdb])
            .await
    }

    /// Query domain reputation (parallel: OTX + VT Scrape).
    pub async fn query_domain(&self, domain: &str) -> IntelResult {
        self.query_domain_inner(domain, false).await
    }

    /// Query domain reputation, distrusting cached *clean* external results.
    /// See [`Self::query_ip_revalidating`] for the rationale.
    pub async fn query_domain_revalidating(&self, domain: &str) -> IntelResult {
        self.query_domain_inner(domain, true).await
    }

    async fn query_domain_inner(&self, domain: &str, revalidate_clean: bool) -> IntelResult {
        // Safe-domain shortcut: skip external queries for known-clean domains (loaded from DB)
        {
            let safe = self
                .safe_domains
                .read()
                .expect("global safe domain lock poisoned");
            if is_domain_in_set(domain, &safe) {
                return IntelResult::not_found(domain, "domain");
            }
        }

        // Exclude auto source to prevent amplification loops
        if let Some(ioc) = self
            .ioc
            .check_indicator_external_only("domain", domain)
            .await
        {
            // Only *external* clean cache entries are distrusted under
            // revalidation; admin/system clean entries stay authoritative.
            let cached_external_clean =
                matches!(ioc.verdict.to_ascii_lowercase().as_str(), "clean" | "safe")
                    && is_external_intel_source(&ioc.source);
            if !(revalidate_clean && cached_external_clean) {
                return IntelResult::from_ioc(&ioc);
            }
        }

        if external_intel_blocked(domain, "domain") {
            warn!(indicator = %domain, "SEC: blocked third-party intel lookup for internal domain");
            return IntelResult::not_found(domain, "domain");
        }

        let (otx, vt_scrape) = tokio::join!(
            self.query_otx_domain_if_enabled(domain),
            self.query_vt_scrape_if_enabled(domain, "domain"),
        );

        // AbuseIPDB does not support domain queries
        self.fuse_and_cache(domain, "domain", &[otx, vt_scrape])
            .await
    }

    /// Query URL reputation (VT Scrape).
    pub async fn query_url(&self, url: &str) -> IntelResult {
        // Exclude auto source to prevent amplification loops
        if let Some(ioc) = self.ioc.check_indicator_external_only("url", url).await {
            return IntelResult::from_ioc(&ioc);
        }

        if external_intel_blocked(url, "url") {
            warn!(indicator = %url, "SEC: blocked third-party intel lookup for internal URL");
            return IntelResult::not_found(url, "url");
        }

        let vt_scrape = self.query_vt_scrape_if_enabled(url, "url").await;
        self.fuse_and_cache(url, "url", &[vt_scrape]).await
    }

    /// Query file hash reputation (VT Scrape).
    pub async fn query_hash(&self, hash: &str) -> IntelResult {
        // Exclude auto source to prevent amplification loops (auto IOC may record attachment hashes)
        if let Some(ioc) = self.ioc.check_indicator_external_only("hash", hash).await {
            return IntelResult::from_ioc(&ioc);
        }

        let vt_scrape = self.query_vt_scrape_if_enabled(hash, "hash").await;
        self.fuse_and_cache(hash, "hash", &[vt_scrape]).await
    }

    /// Query email address reputation (local IOC only).
    pub async fn query_email(&self, email: &str) -> IntelResult {
        if let Some(ioc) = self.ioc.check_indicator("email", email).await {
            return IntelResult::from_ioc(&ioc);
        }
        IntelResult::not_found(email, "email")
    }

    /// Query HELO domain reputation (local IOC only).
    pub async fn query_helo(&self, helo: &str) -> IntelResult {
        if let Some(ioc) = self.ioc.check_indicator("helo", helo).await {
            return IntelResult::from_ioc(&ioc);
        }
        IntelResult::not_found(helo, "helo")
    }

    /// Query X-Mailer reputation (local IOC only).
    pub async fn query_xmailer(&self, xmailer: &str) -> IntelResult {
        if let Some(ioc) = self.ioc.check_indicator("x_mailer", xmailer).await {
            return IntelResult::from_ioc(&ioc);
        }
        IntelResult::not_found(xmailer, "x_mailer")
    }

    // ============================================
    // Per-source query helpers (enabled check + rate limiting)
    // ============================================

    async fn query_otx_domain_if_enabled(&self, domain: &str) -> Option<IntelResult> {
        if !self.config.otx_enabled {
            return None;
        }
        self.query_otx_domain(domain).await
    }

    async fn query_otx_ip_if_enabled(&self, ip: &str) -> Option<IntelResult> {
        if !self.config.otx_enabled {
            return None;
        }
        self.query_otx_ip(ip).await
    }

    async fn query_vt_scrape_if_enabled(
        &self,
        indicator: &str,
        ioc_type: &str,
    ) -> Option<IntelResult> {
        // Prefer official VT API when key is configured
        if self.config.virustotal_api_key.is_some() {
            let result = self.query_virustotal_api(indicator, ioc_type).await;
            if result.is_some() {
                return result;
            }
            // If quota exhausted, degrade gracefully — skip scrape too
            let quota_exhausted = self.rate_limiter.lock().await.vt_api.is_quota_exhausted();
            if quota_exhausted {
                warn!(
                    "VT API daily quota exhausted, skipping VT for {}",
                    indicator
                );
                return None;
            }
            // API failed for non-quota reason, fall through to scrape
        }
        if !self.config.vt_scrape_enabled {
            return None;
        }
        self.query_vt_scrape(indicator, ioc_type).await
    }

    async fn query_abuseipdb_if_enabled(&self, ip: &str) -> Option<IntelResult> {
        if !self.config.abuseipdb_enabled {
            return None;
        }
        self.query_abuseipdb(ip).await
    }

    // ============================================
    // Multi-source result fusion
    // ============================================

    /// Fuse results from multiple sources and cache the combined result.
    ///
    /// Fusion rules:
    /// - Take the highest-severity verdict (malicious > suspicious > clean > unknown)
    /// - Weighted-average confidence (malicious sources get 2x weight)
    /// - Merge details: "OTX: 5 pulses | VT: malicious=12/94 | AbuseIPDB: score=85"
    /// - Merge source names: "otx+vt_scrape+abuseipdb"
    async fn fuse_and_cache(
        &self,
        indicator: &str,
        ioc_type: &str,
        results: &[Option<IntelResult>],
    ) -> IntelResult {
        let found: Vec<&IntelResult> = results.iter().filter_map(|r| r.as_ref()).collect();

        if found.is_empty() {
            return IntelResult::not_found(indicator, ioc_type);
        }

        // Pick the highest-severity verdict
        let best_verdict = found
            .iter()
            .map(|r| r.verdict.as_str())
            .max_by_key(|v| IntelResult::verdict_severity(v))
            .unwrap_or("unknown");

        // Weighted-average confidence
        let (weighted_sum, weight_total) = found.iter().fold((0.0_f64, 0.0_f64), |(ws, wt), r| {
            let w = if r.verdict == "malicious" { 2.0 } else { 1.0 };
            (ws + r.confidence * w, wt + w)
        });
        let avg_confidence = if weight_total > 0.0 {
            weighted_sum / weight_total
        } else {
            0.0
        };

        // Merge detail strings
        let details_parts: Vec<String> = found
            .iter()
            .filter_map(|r| r.details.as_ref().cloned())
            .collect();
        let merged_details = if details_parts.is_empty() {
            None
        } else {
            Some(details_parts.join(" | "))
        };

        // Merge source names
        let sources: Vec<&str> = found.iter().map(|r| r.source.as_str()).collect();
        let merged_source = sources.join("+");

        let fused = IntelResult {
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            found: true,
            verdict: best_verdict.to_string(),
            confidence: avg_confidence,
            source: merged_source,
            details: merged_details,
        };

        // Cache the fused result exactly once. Per-source caching was removed:
        // independent upserts raced each other, letting a weak source's "clean"
        // overwrite a strong source's "malicious" depending on completion order.
        self.cache_external_result(&fused).await;

        fused
    }

    // ============================================
    // IOC cache
    // ============================================

    /// Cache an external query result as an IOC entry.
    ///
    /// TTL strategy:
    /// - clean -> 72 hours (short window: clean cache can be pre-poisoned)
    /// - malicious -> 30 days
    /// - suspicious / unknown -> 1 day
    ///
    /// Protection: an external feed result never overwrites an entry recorded
    /// by a non-external source (auto/manual/import/admin_clean/system), and
    /// never downgrades a cached verdict of higher severity (a weak "clean"
    /// must not erase a cached "malicious"). In both cases only
    /// last_seen/hit_count are refreshed.
    pub(super) async fn cache_external_result(&self, result: &IntelResult) {
        if !result.found {
            return;
        }

        match self
            .ioc
            .db
            .find_ioc(&result.ioc_type, &result.indicator)
            .await
        {
            Ok(Some(existing))
                if !is_external_intel_source(&existing.source)
                    || IntelResult::verdict_severity(&existing.verdict)
                        > IntelResult::verdict_severity(&result.verdict) =>
            {
                if let Err(e) = self
                    .ioc
                    .db
                    .touch_ioc_last_seen(&result.ioc_type, &result.indicator)
                    .await
                {
                    warn!("Failed to touch IOC last_seen: {}", e);
                }
                return;
            }
            Err(e) => {
                // Cache lookup failed; fall through to the UPSERT path, whose
                // source-protection CASEs still guard privileged entries.
                warn!("IOC cache precheck failed: {}", e);
            }
            _ => {}
        }

        let now = chrono::Utc::now();
        let ttl_hours = cache_ttl_hours(&result.verdict);
        let expires = now + chrono::Duration::hours(ttl_hours);

        let ioc = IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: result.indicator.clone(),
            ioc_type: result.ioc_type.clone(),
            source: result.source.clone(),
            verdict: result.verdict.clone(),
            confidence: result.confidence,
            attack_type: String::new(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: result.details.clone(),
            expires_at: Some(expires),
            created_at: now,
            updated_at: now,
        };

        if let Err(e) = self.ioc.db.upsert_ioc(&ioc).await {
            warn!("Failed to cache external intel result: {}", e);
        }
    }
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_intel_blocks_non_public_indicators() {
        assert!(external_intel_blocked("10.0.0.5", "ip"));
        assert!(external_intel_blocked("mail.corp", "domain"));
        assert!(external_intel_blocked("http://127.0.0.1/admin", "url"));
        assert!(external_intel_blocked(
            "https://portal.bank.internal/login",
            "url"
        ));
        assert!(!external_intel_blocked("198.51.100.10", "ip"));
        assert!(!external_intel_blocked("public.example.net", "domain"));
    }

    #[test]
    fn test_verdict_severity_ordering() {
        assert!(
            IntelResult::verdict_severity("malicious")
                > IntelResult::verdict_severity("suspicious")
        );
        assert!(
            IntelResult::verdict_severity("suspicious") > IntelResult::verdict_severity("clean")
        );
        assert!(IntelResult::verdict_severity("clean") > IntelResult::verdict_severity("unknown"));
    }

    #[test]
    fn test_default_config_otx_enabled() {
        let config = IntelSourceConfig::default();
        assert!(config.otx_enabled);
        assert!(!config.vt_scrape_enabled);
        assert!(!config.abuseipdb_enabled);
        assert!(config.abuseipdb_api_key.is_none());
    }

    #[test]
    fn test_vt_scrape_base_url_custom() {
        let config = IntelSourceConfig {
            vt_scrape_url: Some("http://10.0.0.5:9000".to_string()),
            ..Default::default()
        };
        assert_eq!(config.vt_scrape_base_url(), "http://10.0.0.5:9000");
    }

    #[test]
    fn test_vt_scrape_base_url_none_uses_fallback() {
        let config = IntelSourceConfig::default();
        // No URL configured, falls back to AI_SERVICE_URL env or 127.0.0.1:8900
        let url = config.vt_scrape_base_url();
        assert!(url.starts_with("http"));
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut rl = ApiRateLimit::new(3);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire()); // 4th attempt exceeds limit of 3
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_fuse_results_takes_highest_verdict() {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        let ioc_manager = IocManager::new(db);
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );

        let otx_result = Some(IntelResult {
            indicator: "evil.com".into(),
            ioc_type: "domain".into(),
            found: true,
            verdict: "suspicious".into(),
            confidence: 0.4,
            source: "otx".into(),
            details: Some("OTX: 2 threat pulses linked".into()),
        });

        let vt_result = Some(IntelResult {
            indicator: "evil.com".into(),
            ioc_type: "domain".into(),
            found: true,
            verdict: "malicious".into(),
            confidence: 0.85,
            source: "vt_scrape".into(),
            details: Some("VT: malicious=12/94".into()),
        });

        let fused = layer
            .fuse_and_cache("evil.com", "domain", &[otx_result, vt_result, None])
            .await;

        assert_eq!(fused.verdict, "malicious");
        assert!(fused.confidence > 0.5); // Weighted average
        assert!(fused.source.contains("otx"));
        assert!(fused.source.contains("vt_scrape"));
        assert!(fused.details.as_ref().unwrap().contains("OTX"));
        assert!(fused.details.as_ref().unwrap().contains("VT"));
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_fuse_results_empty_returns_not_found() {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        let ioc_manager = IocManager::new(db);
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );

        let fused = layer
            .fuse_and_cache("test.com", "domain", &[None, None])
            .await;

        assert!(!fused.found);
        assert_eq!(fused.verdict, "unknown");
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_fuse_results_single_source() {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        let ioc_manager = IocManager::new(db);
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );

        let single = Some(IntelResult {
            indicator: "1.2.3.4".into(),
            ioc_type: "ip".into(),
            found: true,
            verdict: "clean".into(),
            confidence: 0.9,
            source: "otx".into(),
            details: Some("OTX: 0 threat pulses linked".into()),
        });

        let fused = layer.fuse_and_cache("1.2.3.4", "ip", &[single, None]).await;

        assert_eq!(fused.verdict, "clean");
        assert_eq!(fused.source, "otx");
        assert!((fused.confidence - 0.9).abs() < 0.01);
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_query_domain_local_ioc_hit() {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();

        // Insert a test IOC entry
        let now = chrono::Utc::now();
        let ioc = IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: "cached-evil.com".to_string(),
            ioc_type: "domain".to_string(),
            source: "otx".to_string(),
            verdict: "malicious".to_string(),
            confidence: 0.75,
            attack_type: "c2".to_string(),
            first_seen: now,
            last_seen: now,
            hit_count: 1,
            context: Some("cached result".to_string()),
            expires_at: Some(now + chrono::Duration::hours(72)),
            created_at: now,
            updated_at: now,
        };
        db.upsert_ioc(&ioc).await.unwrap();

        let ioc_manager = IocManager::new(db);
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );

        let result = layer.query_domain("cached-evil.com").await;
        assert!(result.found);
        assert_eq!(result.verdict, "malicious");
        assert_eq!(result.source, "otx");
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_query_ip_all_disabled_returns_not_found() {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        let ioc_manager = IocManager::new(db);
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );

        let result = layer.query_ip("8.8.8.8").await;
        assert!(!result.found);
        assert_eq!(result.verdict, "unknown");
    }

    #[test]
    fn test_old_config_format_deserializes_with_defaults() {
        // Old config JSON may contain legacy fields like virustotal_enabled/urlscan_enabled.
        // serde(default) gives missing new fields their Default values; unknown fields are ignored.
        let old_json = r#"{
            "virustotal_enabled": true,
            "virustotal_api_key": "old-key",
            "abuseipdb_enabled": true,
            "abuseipdb_api_key": "abuse-key",
            "urlscan_enabled": false,
            "urlscan_api_key": null
        }"#;

        let config: IntelSourceConfig = serde_json::from_str(old_json).unwrap();
        // New fields get their default values
        assert!(config.otx_enabled); // default = true
        assert!(!config.vt_scrape_enabled); // optional AI bridge defaults off
        assert!(config.vt_scrape_url.is_none());
        // Existing fields deserialize normally
        assert!(config.abuseipdb_enabled);
        assert_eq!(config.abuseipdb_api_key.as_deref(), Some("abuse-key"));
    }

    #[test]
    fn test_intel_source_config_serde_roundtrip() {
        let config = IntelSourceConfig {
            otx_enabled: true,
            vt_scrape_enabled: true,
            vt_scrape_url: Some("http://10.0.0.5:9000".to_string()),
            virustotal_api_key: None,
            abuseipdb_enabled: true,
            abuseipdb_api_key: Some("test-key".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: IntelSourceConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.otx_enabled);
        assert_eq!(
            parsed.vt_scrape_url.as_deref(),
            Some("http://10.0.0.5:9000")
        );
        assert_eq!(parsed.abuseipdb_api_key.as_deref(), Some("test-key"));
    }

    #[test]
    fn test_link_reputation_deadlines_cover_bounded_provider_stages() {
        let default_config = IntelSourceConfig::default();
        assert_eq!(
            default_config.link_reputation_query_timeout(),
            Duration::from_secs(6)
        );
        assert!(
            default_config.link_reputation_module_timeout_ms()
                > default_config.link_reputation_query_timeout().as_millis() as u64
        );

        let official_vt = IntelSourceConfig {
            virustotal_api_key: Some("test-key".to_string()),
            ..Default::default()
        };
        assert!(
            official_vt.link_reputation_module_timeout_ms()
                > (official_vt.link_reputation_query_timeout().as_millis() as u64 * 2)
        );

        let vt_scrape = IntelSourceConfig {
            vt_scrape_enabled: true,
            ..Default::default()
        };
        assert!(
            vt_scrape.link_reputation_module_timeout_ms()
                > (vt_scrape.link_reputation_query_timeout().as_millis() as u64 * 2)
        );
    }

    // ================================================================
    // OTX pulse_count threshold classification tests
    // ================================================================

    #[test]
    fn test_otx_pulses_zero_is_clean() {
        let (verdict, confidence) = classify_otx_pulses(0);
        assert_eq!(verdict, "clean");
        assert!((confidence - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_otx_pulses_1_is_clean_noise() {
        let (verdict, confidence) = classify_otx_pulses(1);
        assert_eq!(verdict, "clean");
        assert!(
            confidence >= 0.8,
            "single-pulse OTX noise should be treated as clean: {}",
            confidence
        );
    }

    #[test]
    fn test_otx_pulses_3_is_suspicious_not_malicious() {
        // 3 pulses should be downgraded from malicious to suspicious
        let (verdict, _) = classify_otx_pulses(3);
        assert_eq!(
            verdict, "suspicious",
            "3 pulses should be suspicious, not malicious (prevents adnxs.com-type FPs)"
        );
    }

    #[test]
    fn test_otx_pulses_9_still_suspicious() {
        let (verdict, _) = classify_otx_pulses(9);
        assert_eq!(verdict, "suspicious");
    }

    #[test]
    fn test_otx_pulses_10_is_still_suspicious() {
        let (verdict, _) = classify_otx_pulses(10);
        assert_eq!(verdict, "suspicious");
    }

    #[test]
    fn test_otx_pulses_50_stays_suspicious() {
        let (verdict, confidence) = classify_otx_pulses(50);
        assert_eq!(verdict, "suspicious");
        assert!(
            confidence <= 0.45,
            "OTX confidence should remain capped as a weak signal: {}",
            confidence
        );
        assert!(
            confidence >= 0.4,
            "High-pulse OTX hits should still remain only moderately confident: {}",
            confidence
        );
    }

    // ================================================================
    // Safe-domain set tests (exact + explicit wildcard only)
    // ================================================================

    fn build_test_safe_set() -> HashSet<String> {
        [
            "qq.com",
            "163.com",
            "partner.example.com",
            "*.partner.example.cn",
            "gmail.com",
            "127.net",
            "*.127.net",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn test_safe_domain_exact_match() {
        let set = build_test_safe_set();
        assert!(is_domain_in_set("qq.com", &set));
        assert!(is_domain_in_set("163.com", &set));
        assert!(is_domain_in_set("partner.example.com", &set));
        assert!(is_domain_in_set("gmail.com", &set));
        // Domains not in the set
        assert!(!is_domain_in_set("aliyuncs.com", &set));
        assert!(!is_domain_in_set("myqcloud.com", &set));
    }

    #[test]
    fn test_safe_domain_subdomain_match() {
        let set = build_test_safe_set();
        assert!(is_domain_in_set("rep.partner.example.cn", &set));
        assert!(is_domain_in_set("127.net", &set));
        assert!(is_domain_in_set("mail-online.nosdn.127.net", &set));
        assert!(!is_domain_in_set("mail.qq.com", &set));
        assert!(!is_domain_in_set("smtp.163.com", &set));
        // Parent domain not in set, so subdomain also not matched
        assert!(!is_domain_in_set("oss-cn-hangzhou.aliyuncs.com", &set));
    }

    #[test]
    fn test_safe_domain_case_insensitive() {
        let set = build_test_safe_set();
        assert!(is_domain_in_set("QQ.COM", &set));
        assert!(is_domain_in_set("Partner.Example.Com", &set));
    }

    #[test]
    fn test_unknown_domain_not_safe() {
        let set = build_test_safe_set();
        assert!(!is_domain_in_set("evil-phishing.com", &set));
        assert!(!is_domain_in_set("hechangre.com", &set));
        assert!(!is_domain_in_set("notqq.com", &set)); // Not a subdomain of qq.com
    }

    // ================================================================
    // Clean-cache TTL & external-source classification (R4 hardening)
    // ================================================================

    #[test]
    fn test_clean_cache_ttl_is_short_against_pre_poisoning() {
        assert_eq!(cache_ttl_hours("clean"), 72);
        assert_eq!(cache_ttl_hours("safe"), 72);
        assert_eq!(cache_ttl_hours("malicious"), 720);
        assert_eq!(cache_ttl_hours("suspicious"), 24);
        assert_eq!(cache_ttl_hours("unknown"), 24);
    }

    #[test]
    fn test_external_intel_source_classification() {
        assert!(is_external_intel_source("otx"));
        assert!(is_external_intel_source("vt_scrape"));
        assert!(is_external_intel_source("virustotal"));
        assert!(is_external_intel_source("abuseipdb"));
        assert!(is_external_intel_source("otx+vt_scrape"));
        assert!(is_external_intel_source("otx+vt_scrape+abuseipdb"));
        assert!(!is_external_intel_source("auto"));
        assert!(!is_external_intel_source("manual"));
        assert!(!is_external_intel_source("import"));
        assert!(!is_external_intel_source("admin_clean"));
        assert!(!is_external_intel_source("system"));
        assert!(!is_external_intel_source(""));
        assert!(!is_external_intel_source("otx+auto"));
    }

    #[test]
    fn test_rate_limiter_would_allow_is_non_mutating() {
        let mut rl = ApiRateLimit::new(2);
        assert!(rl.would_allow());
        assert!(rl.would_allow(), "would_allow must not consume a slot");
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.would_allow());
        assert!(!rl.try_acquire());
    }

    #[test]
    fn test_rate_limiter_would_allow_respects_quota_exhaustion() {
        let mut rl = ApiRateLimit::new(10).with_daily_quota(100);
        assert!(rl.would_allow());
        rl.mark_exhausted();
        assert!(!rl.would_allow());
    }

    // ================================================================
    // Fused-result caching & clean-cache revalidation (infra-tests)
    // ================================================================

    #[cfg(feature = "infra-tests")]
    async fn make_test_layer() -> (vigilyx_db::VigilDb, IntelLayer) {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        let ioc_manager = IocManager::new(db.clone());
        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: false,
            abuseipdb_enabled: false,
            ..Default::default()
        };
        let layer = IntelLayer::new(
            ioc_manager,
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );
        (db, layer)
    }

    /// PoC (multi-source race): the fused verdict is cached exactly once, so a
    /// weak source's clean can never overwrite a strong source's malicious.
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_fused_malicious_cached_despite_weak_clean_source() {
        let (db, layer) = make_test_layer().await;
        let indicator = format!("{}.fuse-race.example", uuid::Uuid::new_v4().simple());

        let weak_clean = Some(IntelResult {
            indicator: indicator.clone(),
            ioc_type: "domain".into(),
            found: true,
            verdict: "clean".into(),
            confidence: 0.8,
            source: "otx".into(),
            details: Some("OTX: 0 threat pulses linked".into()),
        });
        let strong_malicious = Some(IntelResult {
            indicator: indicator.clone(),
            ioc_type: "domain".into(),
            found: true,
            verdict: "malicious".into(),
            confidence: 0.9,
            source: "vt_scrape".into(),
            details: Some("VT: malicious=12/94".into()),
        });

        let fused = layer
            .fuse_and_cache(&indicator, "domain", &[weak_clean, strong_malicious])
            .await;
        assert_eq!(fused.verdict, "malicious");

        let cached = db
            .find_ioc("domain", &indicator)
            .await
            .unwrap()
            .expect("fused result must be cached");
        assert_eq!(cached.verdict, "malicious");
        assert_eq!(cached.source, "otx+vt_scrape");
    }

    /// PoC (self-neutralization): an external clean result must not overwrite
    /// an auto-recorded malicious IOC — only last_seen is refreshed.
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_cache_external_result_never_overwrites_auto_entry() {
        let (db, layer) = make_test_layer().await;
        let indicator = format!("{}.cache-guard.example", uuid::Uuid::new_v4().simple());

        // Simulate: first email Critical -> auto malicious IOC recorded.
        let now = chrono::Utc::now();
        db.upsert_ioc(&IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: indicator.clone(),
            ioc_type: "domain".into(),
            source: "auto".into(),
            verdict: "malicious".into(),
            confidence: 0.9,
            attack_type: "phishing".into(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

        // Attacker drives an external feed to return clean for the indicator.
        layer
            .cache_external_result(&IntelResult {
                indicator: indicator.clone(),
                ioc_type: "domain".into(),
                found: true,
                verdict: "clean".into(),
                confidence: 0.8,
                source: "otx".into(),
                details: None,
            })
            .await;

        let ioc = db
            .find_ioc("domain", &indicator)
            .await
            .unwrap()
            .expect("auto IOC must survive external clean");
        assert_eq!(ioc.verdict, "malicious");
        assert_eq!(ioc.source, "auto");
        assert_eq!(ioc.hit_count, 1, "last_seen/hit_count still refreshed");
    }

    /// PoC (severity guard): a fresh weak clean must not downgrade a cached
    /// external malicious verdict either.
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_cache_external_result_never_downgrades_severity() {
        let (db, layer) = make_test_layer().await;
        let indicator = format!("{}.severity.example", uuid::Uuid::new_v4().simple());

        layer
            .cache_external_result(&IntelResult {
                indicator: indicator.clone(),
                ioc_type: "domain".into(),
                found: true,
                verdict: "malicious".into(),
                confidence: 0.9,
                source: "virustotal".into(),
                details: None,
            })
            .await;
        layer
            .cache_external_result(&IntelResult {
                indicator: indicator.clone(),
                ioc_type: "domain".into(),
                found: true,
                verdict: "clean".into(),
                confidence: 0.8,
                source: "otx".into(),
                details: None,
            })
            .await;

        let ioc = db
            .find_ioc("domain", &indicator)
            .await
            .unwrap()
            .expect("cached entry must exist");
        assert_eq!(ioc.verdict, "malicious");
        assert_eq!(ioc.source, "virustotal");
    }

    /// PoC (clean-cache pre-poisoning): with revalidation enabled, a cached
    /// external clean verdict is distrusted and external sources are
    /// re-queried (here: none enabled -> not_found instead of cached clean).
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_revalidating_query_distrusts_cached_clean() {
        let (db, layer) = make_test_layer().await;
        let ip = "203.0.113.77";
        let now = chrono::Utc::now();
        db.upsert_ioc(&IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: ip.to_string(),
            ioc_type: "ip".into(),
            source: "otx".into(),
            verdict: "clean".into(),
            confidence: 0.8,
            attack_type: String::new(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: None,
            expires_at: Some(now + chrono::Duration::hours(72)),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

        // Normal path: cached clean is honored.
        let cached = layer.query_ip(ip).await;
        assert!(cached.found);
        assert_eq!(cached.verdict, "clean");

        // Revalidating path: cached clean is distrusted; with all sources
        // disabled the re-query finds nothing instead of blindly trusting
        // the poisoned clean entry.
        let revalidated = layer.query_ip_revalidating(ip).await;
        assert!(
            !revalidated.found,
            "revalidating query must bypass cached clean, got {:?}",
            revalidated
        );

        // Non-clean cached verdicts are still honored by the revalidating path.
        db.upsert_ioc(&IocEntry {
            id: uuid::Uuid::new_v4(),
            indicator: ip.to_string(),
            ioc_type: "ip".into(),
            source: "virustotal".into(),
            verdict: "malicious".into(),
            confidence: 0.9,
            attack_type: String::new(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: None,
            expires_at: Some(now + chrono::Duration::hours(720)),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
        let revalidated = layer.query_ip_revalidating(ip).await;
        assert!(revalidated.found);
        assert_eq!(revalidated.verdict, "malicious");
    }

    /// Rate-budget exhaustion must be detectable so callers can degrade to
    /// local-IOC-only plus `inspection_limited` instead of failing open.
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_external_sources_saturated_detection() {
        // No sources enabled -> never "saturated" (nothing to degrade from).
        let (_db, layer) = make_test_layer().await;
        assert!(!layer.external_sources_saturated().await);

        // OTX enabled: initially available, saturated after budget is spent.
        let db2 = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        let layer2 = IntelLayer::new(
            IocManager::new(db2),
            IntelSourceConfig {
                otx_enabled: true,
                vt_scrape_enabled: false,
                abuseipdb_enabled: false,
                ..Default::default()
            },
            Arc::new(StdRwLock::new(HashSet::new())),
        );
        assert!(!layer2.external_sources_saturated().await);
        {
            let mut rl = layer2.rate_limiter.lock().await;
            while rl.otx.try_acquire() {} // spend the whole per-minute budget
        }
        assert!(layer2.external_sources_saturated().await);
    }
}
