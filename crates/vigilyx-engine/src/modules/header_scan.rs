//! Email header analysis module - checks From/Reply-To domain mismatch, date anomalies,
//! missing Message-ID, header injection, SPF/DMARC failures, etc.
//! Also checks IPs found in Received chain:
//! 1. Local IOC lookup
//! 2. External intel query: OTX + VT Scrape + AbuseIPDB (per IP)
//! 3. Skips IPs already marked verdict=clean in IOC cache

use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::Arc;
use std::sync::LazyLock;

use super::common::extract_domain_from_email;
use crate::context::SecurityContext;
use crate::db_service::DbQueryService;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};

pub struct HeaderScanModule {
    meta: ModuleMetadata,
    db: Arc<dyn DbQueryService>,
    intel: Option<IntelLayer>,
}

impl HeaderScanModule {
    pub fn new(db: Arc<dyn DbQueryService>, intel: Option<IntelLayer>) -> Self {
       // Increase timeout when intel is enabled: IP queries run in parallel with 10s per-IP timeout
        let has_intel = intel.is_some();
        let timeout_ms = if has_intel { 12000 } else { 3000 };

        Self {
            db,
            intel,
            meta: ModuleMetadata {
                id: "header_scan".to_string(),
                name: "Email header analysis".to_string(),
                description:
                    "Detect domain mismatch, date anomalies, header injection, SPF/DMARC failures in email headers"
                        .to_string(),
                pillar: Pillar::Package,
                depends_on: vec![],
                timeout_ms,
                is_remote: has_intel,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None, // I/O-bound: DB IOC queries + external intel
            },
        }
    }
}

/// Alias kept for readability - delegates to the shared helper.
fn extract_domain(addr: &str) -> Option<String> {
    extract_domain_from_email(addr)
}

static RE_IP_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap());

/// Check whether IP is private/reserved (RFC 1918 + loopback + link-local)
fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("0.")
        || ip.starts_with("169.254.")
   // link-local
    {
        return true;
    }
   // 172.16.0.0/12 = 172.16.x.x ~ 172.31.x.x
    if ip.starts_with("172.")
        && let Some(second) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok())
        && (16..=31).contains(&second)
    {
        return true;
    }
    false
}

/// Protected internal domains - spoofing these in From header is a strong signal
const PROTECTED_DOMAINS: &[&str] = &["corp-internal.com"];

/// Suspicious X-Mailer patterns
const SUSPICIOUS_MAILERS: &[&str] = &[
    "phpmailer",
    "swiftmailer",
    "mass mailer",
    "bulk mailer",
    "sendinblue",
    "mailchimp", // Not inherently malicious but notable in targeted mail
    "python",
    "ruby",
    "perl",
    "wget",
    "curl",
];

#[async_trait]
impl SecurityModule for HeaderScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let headers = &ctx.session.content.headers;

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

       // Gather key headers
        let mut from_value: Option<String> = None;
        let mut reply_to_value: Option<String> = None;
        let mut date_value: Option<String> = None;
        let mut message_id_found = false;
        let mut x_mailer_value: Option<String> = None;
        let mut received_count = 0usize;
        let mut received_ips: Vec<String> = Vec::new();

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            match name_lower.as_str() {
                "from" => from_value = Some(value.clone()),
                "reply-to" => reply_to_value = Some(value.clone()),
                "date" => date_value = Some(value.clone()),
                "message-id" => message_id_found = true,
                "x-mailer" => x_mailer_value = Some(value.clone()),
                "received" => {
                    received_count += 1;
                   // Extract IPs from Received headers
                    for cap in RE_IP_ADDR.captures_iter(value) {
                        if let Some(m) = cap.get(1) {
                            let ip = m.as_str().to_string();
                           // Skip private/loopback/link-local
                            if !is_private_ip(&ip) {
                                received_ips.push(ip);
                            }
                        }
                    }
                }
                _ => {}
            }

           // --- Header injection detection ---
            if value.contains("\r\n") || value.contains('\r') || value.contains('\n') {
                total_score += 0.40;
                categories.push("header_injection".to_string());
                evidence.push(Evidence {
                    description: format!("Header injection: {} contains line break characters", name),
                    location: Some(format!("headers:{}", name)),
                    snippet: Some(value.chars().take(100).collect()),
                });
            }
        }

       // --- 1. From / Reply-To domain mismatch ---
        if let (Some(from), Some(reply_to)) = (&from_value, &reply_to_value) {
            let from_domain = extract_domain(from);
            let reply_domain = extract_domain(reply_to);
            if let (Some(fd), Some(rd)) = (from_domain, reply_domain)
                && fd != rd
            {
               // Domain mismatch detected
                total_score += 0.25;
                categories.push("domain_mismatch".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "From domain ({}) does not match Reply-To domain ({})",
                        fd, rd
                    ),
                    location: Some("headers:From,Reply-To".to_string()),
                    snippet: Some(format!("From: {} | Reply-To: {}", from, reply_to)),
                });

               // Check if From uses a brand domain but Reply-To points to a free email provider
               // (e.g. From=id.apple.com, Reply-To=xxx@139.com) — classic brand spoofing pattern
                let known_brand_domains: &[&str] = &[
                    "apple.com",
                    "id.apple.com",
                    "microsoft.com",
                    "google.com",
                    "amazon.com",
                    "paypal.com",
                    "netflix.com",
                    "facebook.com",
                    "instagram.com",
                    "linkedin.com",
                    "twitter.com",
                    "icloud.com",
                    "outlook.com",
                    "live.com",
                ];
                let free_email_domains: &[&str] = &[
                    "139.com",
                    "qq.com",
                    "163.com",
                    "126.com",
                    "yeah.net",
                    "sina.com",
                    "sina.cn",
                    "foxmail.com",
                    "189.cn",
                    "gmail.com",
                    "hotmail.com",
                    "yahoo.com",
                    "outlook.com",
                ];
                let from_is_brand = known_brand_domains
                    .iter()
                    .any(|&b| fd == b || fd.ends_with(&format!(".{}", b)));
                let reply_is_free = free_email_domains
                    .iter()
                    .any(|&f| rd == f || rd.ends_with(&format!(".{}", f)));

                if from_is_brand && reply_is_free {
                    total_score += 0.35;
                    categories.push("brand_spoof_reply_to".to_string());
                    evidence.push(Evidence {
                            description: format!(
                                "Brand domain ({}) Reply-To points to free email ({}) — classic brand spoofing phishing",
                                fd, rd
                            ),
                            location: Some("headers:From,Reply-To".to_string()),
                            snippet: Some(format!("From: {} → Reply-To: {}", from, reply_to)),
                        });
                }
            }
        }

       // --- 1b. From header domain vs MAIL_FROM (envelope) domain mismatch ---
       // This catches spoofing where the display From differs from the SMTP envelope sender
        if let Some(ref from) = from_value {
            let from_domain = extract_domain(from);
            let envelope_domain = ctx.session.mail_from.as_deref().and_then(extract_domain);
            if let (Some(fd), Some(ed)) = (&from_domain, &envelope_domain)
                && fd != ed
            {
               // Base score for any envelope mismatch
                total_score += 0.30;
                categories.push("envelope_spoofing".to_string());
                evidence.push(Evidence {
                        description: format!(
                            "From header domain ({}) does not match envelope sender domain ({}) — possible sender spoofing",
                            fd, ed
                        ),
                        location: Some("headers:From vs MAIL_FROM".to_string()),
                        snippet: Some(format!("From: {} | MAIL FROM domain: {}", from, ed)),
                    });

               // Extra penalty if From claims an internal/protected domain
                if ctx.is_internal_domain(fd) || PROTECTED_DOMAINS.iter().any(|&pd| fd == pd) {
                    total_score += 0.20;
                    categories.push("protected_domain_spoof".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "From header spoofs protected domain {} (actually sent from {})",
                            fd, ed
                        ),
                        location: Some("headers:From".to_string()),
                        snippet: None,
                    });
                }
            }
        }

       // Pre-compute internal sender flags (reused by no_auth_results + no_received)
        let is_internal = ctx.session.client_ip.starts_with("10.")
            || ctx.session.client_ip.starts_with("192.168.");
        let sender_is_internal_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(extract_domain)
            .is_some_and(|d| ctx.is_internal_domain(&d));

       // --- 1c. SPF/DKIM/DMARC Authentication-Results Parse ---
       // Parse Authentication-Results / ARC-Authentication-Results headers (Exchange, Postfix, etc.)
       // spf=fail/none or dmarc=fail/none are strong spoofing signals.
       // Detects "legitimate-looking phishing" even when IPs appear clean, if SPF/DMARC fail.
        {
            let mut spf_fail = false;
            let mut dmarc_fail = false;
            let mut auth_results_found = false;

            for (name, value) in headers {
                let name_lower = name.to_lowercase();
                if name_lower == "authentication-results"
                    || name_lower == "arc-authentication-results"
                    || name_lower == "x-ms-exchange-authentication-results"
                {
                    auth_results_found = true;
                    let val_lower = value.to_lowercase();

                   // SPF: fail / softfail / none are all failures
                    if val_lower.contains("spf=fail")
                        || val_lower.contains("spf=softfail")
                        || val_lower.contains("spf=none")
                    {
                        spf_fail = true;
                    }

                   // DMARC: fail / none are failures
                    if val_lower.contains("dmarc=fail") || val_lower.contains("dmarc=none") {
                        dmarc_fail = true;
                    }
                }
            }

            if spf_fail && dmarc_fail {
               // Both authentication mechanisms failed: strong spoofing signal
                total_score += 0.35;
                categories.push("auth_spf_dmarc_fail".to_string());
                evidence.push(Evidence {
                    description: "SPF and DMARC both failed — sender identity cannot be verified, highly suspicious of spoofing"
                        .to_string(),
                    location: Some("headers:Authentication-Results".to_string()),
                    snippet: None,
                });
            } else if spf_fail {
                total_score += 0.20;
                categories.push("auth_spf_fail".to_string());
                evidence.push(Evidence {
                    description:
                        "SPF failed (fail/softfail/none) — sending IP not authorized by domain"
                            .to_string(),
                    location: Some("headers:Authentication-Results".to_string()),
                    snippet: None,
                });
            } else if dmarc_fail {
                total_score += 0.20;
                categories.push("auth_dmarc_fail".to_string());
                evidence.push(Evidence {
                    description: "DMARC failed — domain policy verification failed".to_string(),
                    location: Some("headers:Authentication-Results".to_string()),
                    snippet: None,
                });
            }

           // Missing Authentication-Results on external email -> suspicious
            if !auth_results_found && !headers.is_empty() {
                if !is_internal && !sender_is_internal_domain && ctx.session.content.is_complete {
                    total_score += 0.10;
                    categories.push("no_auth_results".to_string());
                    evidence.push(Evidence {
                        description: "Missing Authentication-Results header — cannot verify sender authentication status".to_string(),
                        location: Some("headers".to_string()),
                        snippet: None,
                    });
                }
            }
        }

       // --- 2. Date anomaly ---
        if let Some(ref date_str) = date_value {
           // Try to parse RFC 2822 date
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
                let now = Utc::now();
                let diff = now.signed_duration_since(parsed.with_timezone(&Utc));

                if diff.num_seconds() < -300 {
                   // Date is>5 min in the future
                    total_score += 0.20;
                    categories.push("future_date".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Date header has future timestamp: {} (offset {} seconds)",
                            date_str,
                            -diff.num_seconds()
                        ),
                        location: Some("headers:Date".to_string()),
                        snippet: Some(date_str.clone()),
                    });
                } else if diff.num_days() > 7 {
                   // Date is more than 7 days old
                    total_score += 0.15;
                    categories.push("stale_date".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Date header is stale: {} ({} days old)",
                            date_str,
                            diff.num_days()
                        ),
                        location: Some("headers:Date".to_string()),
                        snippet: Some(date_str.clone()),
                    });
                }
            }
        } else if ctx.session.content.is_complete && !headers.is_empty() {
           // Only flag missing Date when we have a complete email with headers
            total_score += 0.10;
            categories.push("missing_date".to_string());
            evidence.push(Evidence {
                description: "Missing Date header".to_string(),
                location: Some("headers".to_string()),
                snippet: None,
            });
        }

       // --- 3. Missing Message-ID (only flag for complete emails with headers) ---
        if !message_id_found && ctx.session.content.is_complete && !headers.is_empty() {
            total_score += 0.10;
            categories.push("missing_message_id".to_string());
            evidence.push(Evidence {
                description: "Missing Message-ID header".to_string(),
                location: Some("headers".to_string()),
                snippet: None,
            });
        }

       // --- 4. Suspicious X-Mailer ---
        if let Some(ref mailer) = x_mailer_value {
            let mailer_lower = mailer.to_lowercase();
            for &pattern in SUSPICIOUS_MAILERS {
                if mailer_lower.contains(pattern) {
                    total_score += 0.15;
                    categories.push("suspicious_mailer".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Suspicious email client: {} (matches {})",
                            mailer, pattern
                        ),
                        location: Some("headers:X-Mailer".to_string()),
                        snippet: Some(mailer.clone()),
                    });
                    break;
                }
            }
        }

       // --- 5. Received chain analysis ---
        if received_count == 0 && !headers.is_empty()
            && !is_internal && !sender_is_internal_domain
        {
            total_score += 0.10;
            categories.push("no_received".to_string());
            evidence.push(Evidence {
                description: "Email missing Received header (possible direct injection)".to_string(),
                location: Some("headers".to_string()),
                snippet: None,
            });
        } else if received_count > 15 {
            total_score += 0.10;
            categories.push("excessive_hops".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Received chain too long: {} hops (normally < 10)",
                    received_count
                ),
                location: Some("headers:Received".to_string()),
                snippet: None,
            });
        }

       // --- 6. Received IP IOC lookup (local) ---
       // Record IPs already found in IOC to avoid duplicate scoring in Step 7
       // (query_ip also checks IOC cache, so the same IOC would be counted twice)
        let mut ioc_checked_ips = std::collections::HashSet::new();
        for ip in &received_ips {
            if let Ok(Some(ioc)) = self.db.find_ioc("ip", ip).await {
               // Skip IPs with verdict=clean (already vetted as safe)
                if ioc.verdict == "clean" {
                    ioc_checked_ips.insert(ip.clone());
                    continue;
                }
                ioc_checked_ips.insert(ip.clone());
                let score_add = (ioc.confidence * 0.5).min(0.40);
                total_score += score_add;
                categories.push("ioc_ip_hit".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Received chain IP {} matched IOC threat intel (verdict={}, confidence={:.0}%, type={})",
                        ip, ioc.verdict, ioc.confidence * 100.0, if ioc.attack_type.is_empty() { "unknown" } else { &ioc.attack_type }
                    ),
                    location: Some("headers:Received".to_string()),
                    snippet: Some(ip.clone()),
                });
            }
        }

       // --- 7. Received IP external intel query (OTX + VT Scrape + AbuseIPDB) ---
       // Skip IPs already checked in Step 6 IOC lookup to prevent double scoring
        if let Some(ref intel) = self.intel
            && !received_ips.is_empty()
        {
           // Deduplicate: each IP queried only once, skip those already found in IOC
            let mut unique_ips: Vec<String> = received_ips.clone();
            unique_ips.sort();
            unique_ips.dedup();
            unique_ips.retain(|ip| !ioc_checked_ips.contains(ip));

           // Parallel query IPs (3 concurrent, 10s timeout per IP)
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(3));
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
                           // Low-confidence malicious (e.g. OTX pulse only, VT clean) gets lower weight
                           // High-confidence sources get full malicious weight
                            let ip_weight = if intel_result.confidence < 0.70 {
                                0.25
                            } else {
                                0.40
                            };
                            total_score += ip_weight;
                            categories.push("sender_ip_malicious".to_string());
                            evidence.push(Evidence {
                                description: format!(
                                    "Sender IP {} flagged as malicious by external intel (source: {}, {})",
                                    ip,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
                                location: Some("headers:Received".to_string()),
                                snippet: Some(ip),
                            });
                        }
                        "suspicious" => {
                            total_score += 0.20;
                            categories.push("sender_ip_suspicious".to_string());
                            evidence.push(Evidence {
                                description: format!(
                                    "Sender IP {} flagged as suspicious by external intel (source: {}, {})",
                                    ip,
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
                                    intel_result.details.as_deref().unwrap_or("no threat records")
                                ),
                                location: Some("headers:Received".to_string()),
                                snippet: Some(ip),
                            });
                        }
                    }
                }
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

       // Build summary describing what was analyzed and the outcome
        let summary = if threat_level == ThreatLevel::Safe {
            if received_ips.is_empty() {
                "Email header check passed, no anomalies found".to_string()
            } else {
                let intel_status = if self.intel.is_some() {
                    "queried external intel (OTX/VT/AbuseIPDB)"
                } else {
                    "local IOC check only"
                };
                format!(
                    "Email header check passed, analyzed {} sender IPs ({})",
                    received_ips.len(),
                    intel_status,
                )
            }
        } else {
            format!(
                "Email header analysis found {} anomalies, composite score {:.2}",
                evidence
                    .iter()
                    .filter(|e| {
                       // Only count anomaly evidence, exclude clean IP reputation entries
                        !e.description.contains("reputation clean")
                    })
                    .count(),
                total_score
            )
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: if threat_level == ThreatLevel::Safe {
                0.85
            } else {
                0.80
            },
            categories,
            summary,
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "received_count": received_count,
                "received_ips": received_ips,
                "intel_enabled": self.intel.is_some(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(if threat_level == ThreatLevel::Safe {
                Bpa::safe_analyzed()
            } else {
                Bpa::from_score_confidence(total_score, 0.80)
            }),
            engine_id: None,
        })
    }
}
