//! Database query abstraction for detection modules.

//! Defines the [`DbQueryService`] trait so that detection modules depend on
//! an abstract interface rather than directly on `VigilDb`. This allows
//! modules to be tested with mock implementations and reduces coupling
//! between the engine and the persistence layer.

use async_trait::async_trait;
use vigilyx_core::IocEntry;

/// Async database query interface consumed by detection modules.

/// Modules that need database access (e.g., `header_scan`, `identity_anomaly`)
/// accept an `Arc<dyn DbQueryService>` instead of a concrete `VigilDb`.
#[async_trait]
pub trait DbQueryService: Send + Sync {
   /// Look up a single IOC entry by type (e.g. "ip", "domain") and indicator value.
    
   /// Returns `Ok(None)` if no matching, non-expired entry exists.
    async fn find_ioc(&self, ioc_type: &str, indicator: &str) -> anyhow::Result<Option<IocEntry>>;

   /// Check whether a sender domain has appeared in historical completed sessions.
    
   /// Returns `Ok(0)` if this is a first-contact domain, `Ok(1)` if previously seen.
   /// `exclude_session_id` prevents the current session from counting itself.
    async fn count_sender_domain_history(
        &self,
        sender_domain: &str,
        exclude_session_id: &str,
    ) -> anyhow::Result<i64>;
}

/// Blanket implementation that delegates to `VigilDb`.
#[async_trait]
impl DbQueryService for vigilyx_db::VigilDb {
    async fn find_ioc(&self, ioc_type: &str, indicator: &str) -> anyhow::Result<Option<IocEntry>> {
        self.find_ioc(ioc_type, indicator).await
    }

    async fn count_sender_domain_history(
        &self,
        sender_domain: &str,
        exclude_session_id: &str,
    ) -> anyhow::Result<i64> {
        self.count_sender_domain_history(sender_domain, exclude_session_id)
            .await
    }
}
