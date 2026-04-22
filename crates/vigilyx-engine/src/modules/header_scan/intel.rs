//! Async IOC/intel lookup functions for IPs found in email headers.
//! Step 6: local IOC database lookup
//! Step 7: external threat intel query (OTX + VT Scrape + AbuseIPDB)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::db_service::DbQueryService;
use crate::intel::{IntelLayer, IntelResult};
use crate::module::Evidence;

fn is_otx_only_source(source: &str) -> bool {
    source.eq_ignore_ascii_case("otx")
}

fn malicious_ip_intel_weight(intel_result: &IntelResult) -> f64 {
    if is_otx_only_source(&intel_result.source) {
        0.12
    } else if intel_result.confidence < 0.70 {
        0.25
    } else {
        0.40
    }
}

fn suspicious_ip_intel_weight(intel_result: &IntelResult) -> f64 {
    if is_otx_only_source(&intel_result.source) {
        0.05
    } else {
        0.20
    }
}

fn local_ioc_ip_weight(source: &str, verdict: &str, confidence: f64) -> f64 {
    match verdict.to_ascii_lowercase().as_str() {
        "clean" => 0.0,
        "malicious" => {
            if is_otx_only_source(source) {
                0.12
            } else {
                (confidence * 0.5).min(0.40)
            }
        }
        "suspicious" => {
            if is_otx_only_source(source) {
                0.05
            } else {
                (confidence * 0.35).min(0.20)
            }
        }
        _ => {
            if is_otx_only_source(source) {
                0.05
            } else {
                (confidence * 0.35).min(0.25)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Received IP IOC lookup (local)
// ---------------------------------------------------------------------------

/// Query local IOC database for each received IP.
///
/// Returns the set of IPs already checked (for deduplication in Step 7).
/// IPs with `verdict=clean` are recorded in the set but do not add score.
pub(super) async fn query_ioc_ips(
    received_ips: &[String],
    db: &Arc<dyn DbQueryService>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) -> HashSet<String> {
    // Record IPs already found in IOC to avoid duplicate scoring in Step 7
    // (query_ip also checks IOC cache, so the same IOC would be counted twice)
    let mut ioc_checked_ips = HashSet::new();
    let mut ioc_score_total = 0.0;
    for ip in received_ips {
        if let Ok(Some(ioc)) = db.find_ioc("ip", ip).await {
            // Skip IPs with verdict=clean (already vetted as safe)
            if ioc.verdict == "clean" {
                ioc_checked_ips.insert(ip.clone());
                continue;
            }
            ioc_checked_ips.insert(ip.clone());
            let score_add = local_ioc_ip_weight(&ioc.source, &ioc.verdict, ioc.confidence);
            ioc_score_total += score_add;
            *total_score += score_add;
            evidence.push(Evidence {
                description: format!(
                    "Received chain IP {} matched {}IOC threat intel (verdict={}, source={}, confidence={:.0}%, type={})",
                    ip,
                    if is_otx_only_source(&ioc.source) {
                        "weak OTX-only "
                    } else {
                        ""
                    },
                    ioc.verdict,
                    ioc.source,
                    ioc.confidence * 100.0,
                    if ioc.attack_type.is_empty() {
                        "unknown"
                    } else {
                        &ioc.attack_type
                    }
                ),
                location: Some("headers:Received".to_string()),
                snippet: Some(ip.clone()),
            });
        }
    }
    if ioc_score_total >= 0.15 {
        categories.push("ioc_ip_hit".to_string());
    }
    ioc_checked_ips
}

// ---------------------------------------------------------------------------
// 7. Received IP external intel query (OTX + VT Scrape + AbuseIPDB)
// ---------------------------------------------------------------------------

/// Query external threat intel for received IPs.
///
/// Skips IPs already checked in Step 6 IOC lookup to prevent double scoring.
pub(super) async fn query_external_intel(
    received_ips: &[String],
    intel: &IntelLayer,
    ioc_checked_ips: &HashSet<String>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // Deduplicate: each IP queried only once, skip those already found in IOC
    let mut unique_ips: Vec<String> = received_ips.to_vec();
    unique_ips.sort();
    unique_ips.dedup();
    unique_ips.retain(|ip| !ioc_checked_ips.contains(ip));

    if unique_ips.is_empty() {
        return;
    }

    // Parallel query IPs (3 concurrent, 10s timeout per IP)
    let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
    let mut join_set = tokio::task::JoinSet::new();

    for ip in unique_ips {
        let sem = semaphore.clone();
        let intel_c = intel.clone();

        join_set.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            let query_result =
                tokio::time::timeout(Duration::from_secs(10), intel_c.query_ip(&ip)).await;
            match query_result {
                Ok(result) => Some((ip, result)),
                Err(_) => {
                    tracing::warn!(
                        ip = ip.as_str(),
                        "Sender IP external intel query timed out (10s)"
                    );
                    None
                }
            }
        });
    }

    // Collect query results
    while let Some(join_result) = join_set.join_next().await {
        if let Ok(Some((ip, intel_result))) = join_result {
            if !intel_result.found {
                continue;
            }
            match intel_result.verdict.as_str() {
                "malicious" => {
                    let ip_weight = malicious_ip_intel_weight(&intel_result);
                    *total_score += ip_weight;
                    if ip_weight >= 0.15 {
                        categories.push("sender_ip_malicious".to_string());
                    }
                    evidence.push(Evidence {
                        description: format!(
                            "Sender IP {} flagged as {} by external intel (source: {}, {})",
                            ip,
                            if is_otx_only_source(&intel_result.source) {
                                "weak OTX-only malicious signal"
                            } else {
                                "malicious"
                            },
                            intel_result.source,
                            intel_result.details.as_deref().unwrap_or("")
                        ),
                        location: Some("headers:Received".to_string()),
                        snippet: Some(ip),
                    });
                }
                "suspicious" => {
                    let ip_weight = suspicious_ip_intel_weight(&intel_result);
                    *total_score += ip_weight;
                    if ip_weight >= 0.15 {
                        categories.push("sender_ip_suspicious".to_string());
                    }
                    evidence.push(Evidence {
                        description: format!(
                            "Sender IP {} flagged as {} by external intel (source: {}, {})",
                            ip,
                            if is_otx_only_source(&intel_result.source) {
                                "weak OTX-only suspicious signal"
                            } else {
                                "suspicious"
                            },
                            intel_result.source,
                            intel_result.details.as_deref().unwrap_or("")
                        ),
                        location: Some("headers:Received".to_string()),
                        snippet: Some(ip),
                    });
                }
                // "clean" -> no score added (result is auto-cached in IOC)
                // Still record evidence for audit trail
                _ => {
                    evidence.push(Evidence {
                        description: format!(
                            "Sender IP {} reputation clean (source: {}, {})",
                            ip,
                            intel_result.source,
                            intel_result
                                .details
                                .as_deref()
                                .unwrap_or("no threat records")
                        ),
                        location: Some("headers:Received".to_string()),
                        snippet: Some(ip),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intel_result(source: &str, confidence: f64) -> IntelResult {
        IntelResult {
            indicator: "1.2.3.4".to_string(),
            ioc_type: "ip".to_string(),
            found: true,
            verdict: "suspicious".to_string(),
            confidence,
            source: source.to_string(),
            details: None,
        }
    }

    #[test]
    fn otx_only_ip_hits_are_weak_signals() {
        let result = intel_result("otx", 0.45);

        assert_eq!(suspicious_ip_intel_weight(&result), 0.05);
        assert_eq!(malicious_ip_intel_weight(&result), 0.12);
    }

    #[test]
    fn multi_source_ip_hits_keep_existing_weight() {
        let result = intel_result("otx+vt_scrape", 0.82);

        assert_eq!(suspicious_ip_intel_weight(&result), 0.20);
        assert_eq!(malicious_ip_intel_weight(&result), 0.40);
    }

    #[test]
    fn otx_only_local_ioc_hits_are_weak_signals() {
        assert_eq!(local_ioc_ip_weight("otx", "malicious", 0.90), 0.12);
        assert_eq!(local_ioc_ip_weight("otx", "suspicious", 0.90), 0.05);
    }

    #[test]
    fn multi_source_local_ioc_hits_keep_existing_weight() {
        assert_eq!(
            local_ioc_ip_weight("otx+vt_scrape", "malicious", 0.90),
            0.40
        );
        assert_eq!(local_ioc_ip_weight("auto", "suspicious", 0.80), 0.20);
    }
}
