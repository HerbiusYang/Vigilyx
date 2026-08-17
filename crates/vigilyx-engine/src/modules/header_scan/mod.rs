//! Email header analysis module - checks From/Reply-To domain mismatch, date anomalies,
//! missing Message-ID, header injection, SPF/DMARC failures, etc.
//! Also checks IPs found in Received chain:
//! 1. Local IOC lookup
//! 2. External intel query: OTX + VT Scrape + AbuseIPDB (per IP)
//! 3. Skips IPs already marked verdict=clean in IOC cache

pub(crate) mod checks;
mod intel;
mod parsed;

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::db_service::DbQueryService;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{Bpa, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use vigilyx_core::models::SessionSource;

/// Hard budget for the external-intel step (Step 7). Must stay comfortably
/// below the module timeout (12s) so local findings are always returned even
/// when external sources hang.
const INTEL_STEP_BUDGET: Duration = Duration::from_secs(8);

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

#[async_trait]
impl SecurityModule for HeaderScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // --- Step 0: Extract all header data in a single pass ---
        let parsed = parsed::ParsedHeaders::extract_for_session(
            &ctx.session.content.headers,
            &ctx.session.client_ip,
            ctx.session.mail_from.as_deref(),
            ctx.session.content.is_complete,
            &|d| ctx.is_internal_domain(d),
            ctx.session.source == SessionSource::MtaProxy,
        );

        // Fold in injection findings from the extraction pass
        total_score += parsed.injection_score;
        categories.extend(parsed.injection_categories.iter().cloned());
        evidence.extend(parsed.injection_evidence.iter().cloned());

        // --- Step 1: From / Reply-To domain mismatch ---
        checks::check_domain_mismatch(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 1b: Envelope spoofing ---
        checks::check_envelope_spoofing(
            &parsed,
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // --- Step 1c: SPF/DKIM/DMARC Authentication-Results ---
        checks::check_auth_results(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 1d: M365 Direct Send abuse (look-internal spoof at EOP) ---
        checks::check_direct_send_abuse(
            &parsed,
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // --- Step 2+3: Date anomaly + Missing Message-ID ---
        checks::check_date_anomaly(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 4: Suspicious X-Mailer ---
        checks::check_suspicious_mailer(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 5: Received chain analysis ---
        checks::check_received_chain(&parsed, &mut total_score, &mut categories, &mut evidence);

        // --- Step 5b: Real-time domain impersonation (homoglyph + TLD swap) ---
        let impersonation_hit = checks::check_domain_impersonation(
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // --- Step 5c: Known impersonation IOC lookup ---
        // If the sender domain was previously recorded as a domain_impersonation IOC,
        // boost the score directly (self-learning: detect once → auto-record → future instant match).
        // Uses find_ioc() (includes source=auto) so auto-recorded impersonation IOCs are matched.
        let mut known_impersonation_target: Option<String> = None;
        if impersonation_hit.is_none()
            && let Some(sender_domain) = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(parsed::extract_domain)
            && let Ok(Some(ioc)) = self.db.find_ioc("domain", &sender_domain).await
            && ioc.attack_type == "domain_impersonation"
            && ioc.verdict != "clean"
        {
            let score_add = (ioc.confidence * 0.4).min(0.35);
            total_score += score_add;
            categories.push("known_impersonation_domain".to_string());
            evidence.push(crate::module::Evidence {
                description: format!(
                    "Sender domain '{}' is a known impersonation domain (IOC confidence={:.0}%, target={})",
                    sender_domain,
                    ioc.confidence * 100.0,
                    ioc.context.as_deref().unwrap_or("unknown"),
                ),
                location: Some("headers:MAIL_FROM".to_string()),
                snippet: Some(sender_domain.clone()),
            });
            // Extract target domain from IOC context for details
            known_impersonation_target = ioc.context.as_ref().and_then(|c| {
                c.split("target=")
                    .nth(1)
                    .map(|s| s.split([',', ' ', '|']).next().unwrap_or(s).to_string())
            });
        }

        // --- Step 6: Received IP IOC lookup (local) ---
        let ioc_checked_ips = intel::query_ioc_ips(
            &parsed.received_ips,
            &self.db,
            &mut total_score,
            &mut categories,
            &mut evidence,
        )
        .await;

        // --- Step 7: Received IP external intel query ---
        // Skip IPs already checked in Step 6 to prevent double scoring.
        // The intel step runs on separate accumulators under a hard time
        // budget: a slow/hanging external source can only forfeit the intel
        // contribution, never the local findings computed in Steps 0-6.
        if let Some(ref intel_layer) = self.intel
            && !parsed.received_ips.is_empty()
        {
            // When earlier steps already produced signals, distrust cached
            // external *clean* verdicts (clean cache can be pre-poisoned).
            let revalidate_clean = total_score >= 0.15;
            let mut intel_score = 0.0;
            let mut intel_categories: Vec<String> = Vec::new();
            let mut intel_evidence: Vec<crate::module::Evidence> = Vec::new();
            let intel_future = intel::query_external_intel(
                &parsed.received_ips,
                intel_layer,
                &ioc_checked_ips,
                revalidate_clean,
                &mut intel_score,
                &mut intel_categories,
                &mut intel_evidence,
            );
            let intel_outcome = tokio::time::timeout(INTEL_STEP_BUDGET, intel_future).await;
            match intel_outcome {
                Ok(()) => {
                    total_score += intel_score;
                    categories.extend(intel_categories);
                    evidence.extend(intel_evidence);
                }
                Err(_) => {
                    tracing::warn!(
                        budget_ms = INTEL_STEP_BUDGET.as_millis() as u64,
                        "header_scan intel step exceeded its time budget; returning local findings only"
                    );
                    categories.push("inspection_limited".to_string());
                    evidence.push(crate::module::Evidence {
                        description:
                            "External intel queries exceeded the time budget; verdict is based on local header checks only"
                                .to_string(),
                        location: Some("headers:Received".to_string()),
                        snippet: None,
                    });
                }
            }
        }

        // --- Finalize ---
        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        // Build summary describing what was analyzed and the outcome
        let summary = if threat_level == ThreatLevel::Safe {
            if parsed.received_ips.is_empty() {
                "Email header check passed, no anomalies found".to_string()
            } else {
                let intel_status = if self.intel.is_some() {
                    "queried external intel (OTX/VT/AbuseIPDB)"
                } else {
                    "local IOC check only"
                };
                format!(
                    "Email header check passed, analyzed {} sender IPs ({})",
                    parsed.received_ips.len(),
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
            details: {
                let mut d = serde_json::json!({
                    "score": total_score,
                    "received_count": parsed.received_count,
                    "received_ips": parsed.received_ips,
                    "intel_enabled": self.intel.is_some(),
                });
                // Include impersonation hit info for post_verdict IOC auto-recording
                if let Some(ref hit) = impersonation_hit {
                    d["impersonation_hit"] = serde_json::json!({
                        "sender_domain": hit.sender_domain,
                        "target_domain": hit.target_domain,
                        "similarity_type": hit.similarity_type,
                        "score": hit.score,
                    });
                }
                // Include known impersonation IOC hit for audit trail
                if let Some(ref target) = known_impersonation_target {
                    d["known_impersonation_ioc_target"] = serde_json::json!(target);
                }
                d
            },
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

#[cfg(all(test, feature = "infra-tests"))]
mod tests {
    use super::*;
    use crate::intel::IntelSourceConfig;
    use std::collections::HashSet;
    use std::sync::RwLock as StdRwLock;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    struct MockDb;

    #[async_trait]
    impl DbQueryService for MockDb {
        async fn find_ioc(
            &self,
            _ioc_type: &str,
            _indicator: &str,
        ) -> anyhow::Result<Option<vigilyx_core::IocEntry>> {
            Ok(None)
        }
        async fn count_sender_domain_history(
            &self,
            _sender_domain: &str,
            _exclude_session_id: &str,
        ) -> anyhow::Result<i64> {
            Ok(0)
        }
        async fn count_sender_address_history(
            &self,
            _sender_address: &str,
            _exclude_session_id: &str,
        ) -> anyhow::Result<i64> {
            Ok(0)
        }
        async fn count_distinct_senders_for_domain(
            &self,
            _sender_domain: &str,
        ) -> anyhow::Result<i64> {
            Ok(0)
        }
    }

    /// PoC (timeout bomb): a hanging external intel source must not kill the
    /// whole analyze() — local findings (Steps 0-6) are returned and the lost
    /// intel coverage is surfaced as `inspection_limited`.
    #[tokio::test]
    async fn intel_timeout_preserves_local_findings() {
        // TCP server that accepts connections but never responds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // hold open, never answer
            }
        });

        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();

        let config = IntelSourceConfig {
            otx_enabled: false,
            vt_scrape_enabled: true,
            vt_scrape_url: Some(format!("http://127.0.0.1:{port}")),
            virustotal_api_key: None,
            abuseipdb_enabled: false,
            abuseipdb_api_key: None,
        };
        let intel = IntelLayer::new(
            crate::ioc::IocManager::new(db),
            config,
            Arc::new(StdRwLock::new(HashSet::new())),
        );
        let module = HeaderScanModule::new(Arc::new(MockDb), Some(intel));

        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("attacker@evil.tld".to_string());
        session.content = EmailContent {
            headers: vec![
                ("From".to_string(), "Attacker <attacker@evil.tld>".to_string()),
                ("Reply-To".to_string(), "drop@other.tld".to_string()),
                (
                    "Received".to_string(),
                    "from mail.evil.tld ([203.0.113.10]) by mx.example.org".to_string(),
                ),
            ],
            is_complete: true,
            ..Default::default()
        };
        let ctx = SecurityContext::new(Arc::new(session));

        let started = Instant::now();
        let result = module.analyze(&ctx).await.expect("analyze must not fail");
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(12),
            "intel hang must not consume the whole module budget: {:?}",
            elapsed
        );
        assert!(
            result.categories.iter().any(|c| c == "domain_mismatch"),
            "local findings must be preserved, categories={:?}",
            result.categories
        );
        assert!(
            result.categories.iter().any(|c| c == "inspection_limited"),
            "lost intel coverage must be reported, categories={:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::Low,
            "local score must survive: {:?}",
            result.threat_level
        );
    }
}
