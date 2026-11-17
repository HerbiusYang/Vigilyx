use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use vigilyx_core::models::{EmailLink, EmailLinkExtractionSource, EmailSession};

use crate::module::{ModuleResult, ThreatLevel};

/// Shared context during a pipeline run.

/// Uses `DashMap` instead of `RwLock<HashMap>` for lock-free concurrent
/// access from 15+ detection modules running in parallel.
#[derive(Clone)]
pub struct SecurityContext {
    pub session: Arc<EmailSession>,
    results: Arc<DashMap<String, ModuleResult>>,
    qr_inspection: Arc<std::sync::OnceLock<crate::modules::html_pixel_art::HtmlQrInspection>>,
    pub started_at: DateTime<Utc>,
    /// AutodetectofInternalDomainSet(if corp-internal.com)
    /// InternalDomainofSender Add,downgradeLow
    pub internal_domains: Arc<HashSet<String>>,
}

/// A link plus its derived extraction carrier.  The canonical `EmailLink`
/// remains wire-compatible; this sidecar prevents modules from losing whether
/// a URL came from an HTML href, visible text, or a QR payload.
#[derive(Debug, Clone)]
pub struct LinkObservation {
    pub link: EmailLink,
    pub extraction_source: EmailLinkExtractionSource,
}

impl SecurityContext {
    pub fn new(session: Arc<EmailSession>) -> Self {
        Self {
            session,
            results: Arc::new(DashMap::with_capacity_and_shard_amount(16, 4)),
            qr_inspection: Arc::new(std::sync::OnceLock::new()),
            started_at: Utc::now(),
            internal_domains: Arc::new(HashSet::new()),
        }
    }

    /// CreatewithInternalDomainSetofContext
    pub fn with_internal_domains(
        session: Arc<EmailSession>,
        domains: Arc<HashSet<String>>,
    ) -> Self {
        Self {
            session,
            results: Arc::new(DashMap::with_capacity_and_shard_amount(16, 4)),
            qr_inspection: Arc::new(std::sync::OnceLock::new()),
            started_at: Utc::now(),
            internal_domains: domains,
        }
    }

    /// CheckDomainwhether InternalDomain
    pub fn is_internal_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.internal_domains.iter().any(|configured| {
            let configured = configured.trim_end_matches('.').to_ascii_lowercase();
            domain == configured || domain.ends_with(&format!(".{configured}"))
        })
    }

    /// Return valid QR-decoded HTTP(S) targets once per pipeline run.
    ///
    /// QR is an alternate URL carrier. Keeping this cache on the shared
    /// context lets HTML and URL modules inspect the same decoded targets
    /// without mutating the canonical parsed session or decoding the same
    /// table repeatedly.
    pub fn decoded_qr_urls(&self) -> &[String] {
        self.html_qr_inspection().urls.as_slice()
    }

    pub(crate) fn html_qr_inspection(&self) -> &crate::modules::html_pixel_art::HtmlQrInspection {
        self.qr_inspection.get_or_init(|| {
            self.session
                .content
                .body_html
                .as_deref()
                .map(|html| {
                    crate::modules::html_pixel_art::inspect_html_qr(
                        html,
                        crate::modules::email_attack_hardening::stage_b_enabled(),
                    )
                })
                .unwrap_or_default()
        })
    }

    /// Return parser links plus deduplicated QR-decoded URL targets for
    /// modules that analyze URLs. QR payloads are added only to this derived
    /// view; the canonical session and persisted link list remain unchanged.
    pub fn analysis_links(&self) -> Vec<EmailLink> {
        self.analysis_link_observations()
            .into_iter()
            .map(|observation| observation.link)
            .collect()
    }

    /// Return parser links plus QR-derived links with bounded extraction
    /// provenance.  QR links are a derived analysis view and are not written
    /// back into the canonical session.
    pub fn analysis_link_observations(&self) -> Vec<LinkObservation> {
        let mut observations = self
            .session
            .content
            .links
            .iter()
            .cloned()
            .map(|link| LinkObservation {
                extraction_source: self.session.content.link_extraction_source(&link),
                link,
            })
            .collect::<Vec<_>>();
        let mut seen = observations
            .iter()
            .map(|observation| observation.link.url.clone())
            .collect::<HashSet<_>>();
        for url in self.decoded_qr_urls() {
            if seen.insert(url.clone()) {
                observations.push(LinkObservation {
                    link: EmailLink {
                        url: url.clone(),
                        text: None,
                        suspicious: false,
                    },
                    extraction_source: EmailLinkExtractionSource::Qr,
                });
            }
        }
        observations
    }

    /// Get a snapshot of all completed module results.

    /// Returns a clone so the context remains intact for subsequent callers
    /// (e.g. verdict module reads first, then orchestrator reads the same data).
    pub async fn module_results(&self) -> HashMap<String, ModuleResult> {
        self.results
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get a specific module's result
    pub async fn get_result(&self, module_id: &str) -> Option<ModuleResult> {
        self.results
            .get(module_id)
            .map(|entry| entry.value().clone())
    }

    /// Insert a module result (called by orchestrator after module completes)
    pub async fn insert_result(&self, result: ModuleResult) {
        self.results.insert(result.module_id.clone(), result);
    }

    /// Check if any prior module has flagged threat>= given level
    pub async fn max_threat_level(&self) -> ThreatLevel {
        self.results
            .iter()
            .map(|entry| entry.value().threat_level)
            .max()
            .unwrap_or(ThreatLevel::Safe)
    }

    /// Check if a specific module has completed
    pub async fn has_result(&self, module_id: &str) -> bool {
        self.results.contains_key(module_id)
    }

    /// Get the number of completed modules
    pub async fn completed_count(&self) -> usize {
        self.results.len()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::module::{ModuleResult, Pillar};
    use vigilyx_core::models::Protocol;

    fn test_session() -> Arc<EmailSession> {
        Arc::new(EmailSession::new(
            Protocol::Smtp,
            "127.0.0.1".to_string(),
            12345,
            "127.0.0.1".to_string(),
            25,
        ))
    }

    #[tokio::test]
    async fn test_module_results_returns_snapshot_without_draining() {
        let ctx = SecurityContext::new(test_session());

        // Insert a result
        ctx.insert_result(ModuleResult::safe(
            "test_module",
            "Test",
            Pillar::Content,
            "ok",
            10,
        ))
        .await;

        assert_eq!(ctx.completed_count().await, 1);

        // First read - should return all results
        let results1 = ctx.module_results().await;
        assert_eq!(results1.len(), 1);
        assert!(results1.contains_key("test_module"));

        // Second read - context still intact (non-destructive)
        let results2 = ctx.module_results().await;
        assert_eq!(results2.len(), 1);
        assert!(results2.contains_key("test_module"));

        // Context retains data
        assert_eq!(ctx.completed_count().await, 1);
    }

    #[tokio::test]
    async fn test_insert_and_get_result() {
        let ctx = SecurityContext::new(test_session());

        ctx.insert_result(ModuleResult::safe(
            "header_scan",
            "Header Scan",
            Pillar::Package,
            "no issues",
            50,
        ))
        .await;

        let result = ctx.get_result("header_scan").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().module_id, "header_scan");

        assert!(ctx.get_result("nonexistent").await.is_none());
    }

    #[test]
    fn test_analysis_links_keeps_canonical_links_unchanged() {
        let mut session = (*test_session()).clone();
        session.content.links.push(EmailLink {
            url: "https://example.invalid/news".to_string(),
            text: Some("News".to_string()),
            suspicious: false,
        });
        let ctx = SecurityContext::new(Arc::new(session));

        let links = ctx.analysis_links();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].url, "https://example.invalid/news");
        assert_eq!(ctx.session.content.links.len(), 1);
        assert!(ctx.decoded_qr_urls().is_empty());
    }

    #[test]
    fn test_analysis_link_observations_keep_carrier_provenance() {
        let mut session = (*test_session()).clone();
        session.content.body_text = Some("查看 https://example.invalid/login".to_string());
        session.content.links.push(EmailLink {
            url: "https://example.invalid/login".to_string(),
            text: Some("登录".to_string()),
            suspicious: false,
        });
        let ctx = SecurityContext::new(Arc::new(session));

        let observations = ctx.analysis_link_observations();

        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].extraction_source,
            vigilyx_core::models::EmailLinkExtractionSource::PlainText
        );
    }

    #[test]
    fn test_internal_domain_matches_subdomains_without_matching_suffix_lookalikes() {
        let ctx = SecurityContext::with_internal_domains(
            test_session(),
            Arc::new(HashSet::from(["corp.internal".to_string()])),
        );

        assert!(ctx.is_internal_domain("corp.internal"));
        assert!(ctx.is_internal_domain("portal.corp.internal"));
        assert!(!ctx.is_internal_domain("corp.internal.attacker.example"));
        assert!(!ctx.is_internal_domain("notcorp.internal"));
    }

    #[tokio::test]
    async fn test_max_threat_level_across_modules() {
        let ctx = SecurityContext::new(test_session());

        ctx.insert_result(ModuleResult::safe(
            "mod_a",
            "A",
            Pillar::Content,
            "safe",
            10,
        ))
        .await;

        assert_eq!(ctx.max_threat_level().await, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_has_result() {
        let ctx = SecurityContext::new(test_session());
        assert!(!ctx.has_result("mod_x").await);

        ctx.insert_result(ModuleResult::safe("mod_x", "X", Pillar::Link, "ok", 5))
            .await;

        assert!(ctx.has_result("mod_x").await);
    }
}
