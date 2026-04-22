//! External intelligence source query implementations.
//!
//! HTTP clients for external sources (OTX AlienVault, VT Scrape, AbuseIPDB).
//! All methods are private implementations of `IntelLayer`, called from `mod.rs`.

use tracing::{debug, warn};
use vigilyx_core::{DEFAULT_INTERNAL_SERVICE_HOSTS, validate_internal_service_url};

use super::{IntelLayer, IntelResult, classify_otx_pulses};

// OTX AlienVault Query (, API Key)

impl IntelLayer {
    /// OTX DomainQuery
    /// GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general
    pub(super) async fn query_otx_domain(&self, domain: &str) -> Option<IntelResult> {
        {
            let mut rl = self.rate_limiter.lock().await;
            if !rl.otx.try_acquire() {
                warn!("OTX rate limiting: hopsQueryDomain {}", domain);
                return None;
            }
        }

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/general",
            domain
        );

        let response = self.http.get(&url).send().await.ok()?;
        if !response.status().is_success() {
            warn!("OTX DomainQueryReturn {}: {}", response.status(), domain);
            return None;
        }

        let body: serde_json::Value = response.json().await.ok()?;
        self.parse_otx_response(domain, "domain", &body).await
    }

    /// OTX IP Query
    /// GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
    pub(super) async fn query_otx_ip(&self, ip: &str) -> Option<IntelResult> {
        {
            let mut rl = self.rate_limiter.lock().await;
            if !rl.otx.try_acquire() {
                warn!("OTX rate limiting: hopsQuery IP {}", ip);
                return None;
            }
        }

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general",
            ip
        );

        let response = self.http.get(&url).send().await.ok()?;
        if !response.status().is_success() {
            warn!("OTX IP QueryReturn {}: {}", response.status(), ip);
            return None;
        }

        let body: serde_json::Value = response.json().await.ok()?;
        self.parse_otx_response(ip, "ip", &body).await
    }

    /// Parse OTX API Response
    async fn parse_otx_response(
        &self,
        indicator: &str,
        ioc_type: &str,
        body: &serde_json::Value,
    ) -> Option<IntelResult> {
        let pulse_count = body
            .pointer("/pulse_info/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // pulse_count: of
        // Note: HighStream LegitimateDomain (if adnxs.com, doubleclick.net) possiblydue to found
        // Analyze Medium High, tableDomain Malicious.ThresholdSet.
        let (verdict, confidence) = classify_otx_pulses(pulse_count);

        let details = format!("OTX: {} threat pulse associations", pulse_count);

        let result = IntelResult {
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            found: true,
            verdict: verdict.to_string(),
            confidence,
            source: "otx".to_string(),
            details: Some(details),
        };

        // independentcache OTX Result
        self.cache_external_result(&result).await;

        Some(result)
    }

    // VT Scrape Query (Python Playwright Service)

    /// Python Playwright Service Get VirusTotal data
    pub(super) async fn query_vt_scrape(
        &self,
        indicator: &str,
        ioc_type: &str,
    ) -> Option<IntelResult> {
        {
            let mut rl = self.rate_limiter.lock().await;
            if !rl.vt_scrape.try_acquire() {
                warn!(
                    "VT Scrape rate limiting: hopsQuery {} ({})",
                    indicator, ioc_type
                );
                return None;
            }
        }

        let base_url = self.config.vt_scrape_base_url();
        if let Err(err) = validate_internal_service_url(&base_url, DEFAULT_INTERNAL_SERVICE_HOSTS) {
            warn!(
                url = %base_url,
                error = %err,
                "SEC: refusing VT scrape request to non-internal URL"
            );
            return None;
        }
        let url = format!("{}/api/vt-scrape", base_url);

        // BuildRequest
        let request_body = serde_json::json!({
            "indicator": indicator,
            "indicator_type": ioc_type,
        });

        let response = match self.http_vt.post(&url).json(&request_body).send().await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("VT Scrape Service不可用: {} (url={})", e, url);
                return None;
            }
        };

        if !response.status().is_success() {
            warn!("VT Scrape Return {}: {}", response.status(), indicator);
            return None;
        }

        let body: serde_json::Value = response.json().await.ok()?;

        // Parse Python ServiceReturnofStandardResponse
        let success = body.get("success")?.as_bool().unwrap_or(false);
        if !success {
            let error = body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown");
            debug!("VT Scrape QueryFailed: {} — {}", indicator, error);
            return None;
        }

        let verdict = body.get("verdict")?.as_str()?.to_string();
        let confidence = body
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5);
        let malicious_count = body
            .get("malicious_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_engines = body
            .get("total_engines")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let details_str = body.get("details").and_then(|v| v.as_str()).unwrap_or("");

        let result = IntelResult {
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            found: true,
            verdict,
            confidence,
            source: "vt_scrape".to_string(),
            details: Some(format!(
                "VT: malicious={}/{} {}",
                malicious_count, total_engines, details_str
            )),
        };

        // independentcache VT Scrape Result
        self.cache_external_result(&result).await;

        Some(result)
    }

    // VirusTotal Official API v3

    /// VirusTotal Official API v3 Query
    /// Supports: domain, ip, hash, url
    /// Free tier: 4 requests/min, 500/day
    /// Degrades gracefully on 429 (marks quota exhausted)
    pub(super) async fn query_virustotal_api(
        &self,
        indicator: &str,
        ioc_type: &str,
    ) -> Option<IntelResult> {
        {
            let mut rl = self.rate_limiter.lock().await;
            if !rl.vt_api.try_acquire() {
                warn!(
                    "VT API rate limit / quota exhausted: {} ({})",
                    indicator, ioc_type
                );
                return None;
            }
        }

        let api_key = self.config.virustotal_api_key.as_ref()?;

        let url = match ioc_type {
            "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", indicator),
            "ip" => format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{}",
                indicator
            ),
            "hash" => format!("https://www.virustotal.com/api/v3/files/{}", indicator),
            "url" => {
                use base64::Engine;
                let encoded =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(indicator.as_bytes());
                format!("https://www.virustotal.com/api/v3/urls/{}", encoded)
            }
            _ => return None,
        };

        let response = match self
            .http
            .get(&url)
            .header("x-apikey", api_key.as_str())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("VT API request failed: {} ({})", e, indicator);
                return None;
            }
        };

        // 429 = quota exhausted — mark so we stop trying until reset
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("VT API 429: daily quota exhausted");
            self.rate_limiter.lock().await.vt_api.mark_exhausted();
            return None;
        }

        if !response.status().is_success() {
            warn!("VT API returned {}: {}", response.status(), indicator);
            return None;
        }

        let body: serde_json::Value = response.json().await.ok()?;
        let stats = body.pointer("/data/attributes/last_analysis_stats")?;

        let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let suspicious = stats
            .get("suspicious")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total: u64 = [
            "malicious",
            "suspicious",
            "undetected",
            "harmless",
            "timeout",
        ]
        .iter()
        .filter_map(|k| stats.get(*k).and_then(|v| v.as_u64()))
        .sum();

        if total == 0 {
            return None;
        }

        let (verdict, confidence) = if malicious >= 3 {
            let conf = ((malicious as f64 / total as f64) * 2.0).min(0.95);
            ("malicious", conf)
        } else if malicious >= 1 || suspicious >= 3 {
            let conf = 0.4 + malicious as f64 * 0.1 + suspicious as f64 * 0.03;
            ("suspicious", conf.min(0.65))
        } else {
            ("clean", 0.80)
        };

        let result = IntelResult {
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            found: true,
            verdict: verdict.to_string(),
            confidence,
            source: "virustotal".to_string(),
            details: Some(format!("VT API: malicious={}/{} engines", malicious, total)),
        };

        self.cache_external_result(&result).await;
        Some(result)
    }

    // AbuseIPDB Query (Need/Require API Key)

    pub(super) async fn query_abuseipdb(&self, ip: &str) -> Option<IntelResult> {
        {
            let mut rl = self.rate_limiter.lock().await;
            if !rl.abuseipdb.try_acquire() {
                warn!("AbuseIPDB rate limiting: hopsQuery {}", ip);
                return None;
            }
        }

        let api_key = self.config.abuseipdb_api_key.as_ref()?;
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );

        let response = self
            .http
            .get(&url)
            .header("Key", api_key.as_str())
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            warn!("AbuseIPDB returned {}", response.status());
            return None;
        }

        let body: serde_json::Value = response.json().await.ok()?;
        let data = body.get("data")?;
        let abuse_score = data.get("abuseConfidenceScore")?.as_f64()?;

        let (verdict, confidence) = if abuse_score >= 80.0 {
            ("malicious", abuse_score / 100.0)
        } else if abuse_score >= 30.0 {
            ("suspicious", abuse_score / 100.0)
        } else {
            ("clean", 1.0 - abuse_score / 100.0)
        };

        let result = IntelResult {
            indicator: ip.to_string(),
            ioc_type: "ip".to_string(),
            found: true,
            verdict: verdict.to_string(),
            confidence,
            source: "abuseipdb".to_string(),
            details: Some(format!("AbuseIPDB: abuse_score={}", abuse_score)),
        };

        // independentcache
        self.cache_external_result(&result).await;

        Some(result)
    }
}
