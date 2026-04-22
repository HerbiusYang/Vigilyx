use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use vigilyx_core::models::EmailSession;

use crate::module::{ModuleResult, ThreatLevel};

/// Shared context during a pipeline run.

/// Uses `DashMap` instead of `RwLock<HashMap>` for lock-free concurrent
/// access from 15+ detection modules running in parallel.
#[derive(Clone)]
pub struct SecurityContext {
    pub session: Arc<EmailSession>,
    results: Arc<DashMap<String, ModuleResult>>,
    pub started_at: DateTime<Utc>,
    /// AutodetectofInternalDomainSet(if corp-internal.com)
    /// InternalDomainofSender Add,downgradeLow
    pub internal_domains: Arc<HashSet<String>>,
}

impl SecurityContext {
    pub fn new(session: Arc<EmailSession>) -> Self {
        Self {
            session,
            results: Arc::new(DashMap::with_capacity_and_shard_amount(16, 4)),
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
            started_at: Utc::now(),
            internal_domains: domains,
        }
    }

    /// CheckDomainwhether InternalDomain
    pub fn is_internal_domain(&self, domain: &str) -> bool {
        self.internal_domains.contains(&domain.to_lowercase())
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
