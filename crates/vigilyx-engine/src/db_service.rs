//! Database query abstraction for detection modules.

//! Defines the [`DbQueryService`] trait so that detection modules depend on
//! an abstract interface rather than directly on `VigilDb`. This allows
//! modules to be tested with mock implementations and reduces coupling
//! between the engine and the persistence layer.

use async_trait::async_trait;
use vigilyx_core::IocEntry;

/// Prior Safe/Low history available to the experimental fusion model.
///
/// Counts are restricted by the DB implementation to prior live sessions and
/// never imply trust on their own.  The v2 fusion path applies the occurrence,
/// distinct-day, authentication and coverage gates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderRelationshipHistory {
    pub sender_completed_count: i64,
    pub sender_distinct_days: i64,
    pub relationship_completed_count: i64,
    pub relationship_distinct_days: i64,
}

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

    /// Check whether this exact envelope mailbox has appeared in history.
    async fn count_sender_address_history(
        &self,
        sender_address: &str,
        exclude_session_id: &str,
    ) -> anyhow::Result<i64>;

    /// Count prior live Safe/Low sessions for the exact sender mailbox and for
    /// the exact sender-to-current-recipient relationship.  The default is
    /// vacuous so test doubles and deployments without history support cannot
    /// accidentally create normal evidence.
    async fn sender_relationship_history(
        &self,
        _sender_address: &str,
        _recipient_addresses: &[String],
        _exclude_session_id: &str,
        _before_started_at: &str,
    ) -> anyhow::Result<SenderRelationshipHistory> {
        Ok(SenderRelationshipHistory::default())
    }

    /// Count distinct senders (mail_from) from a given domain in completed sessions.
    /// Used as a heuristic: if a domain has many different senders, it's likely a shared/public
    /// email domain, and domain-level "first contact" is meaningless.
    async fn count_distinct_senders_for_domain(&self, sender_domain: &str) -> anyhow::Result<i64>;
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

    async fn count_distinct_senders_for_domain(&self, sender_domain: &str) -> anyhow::Result<i64> {
        self.count_distinct_senders_for_domain(sender_domain).await
    }

    async fn count_sender_address_history(
        &self,
        sender_address: &str,
        exclude_session_id: &str,
    ) -> anyhow::Result<i64> {
        self.count_sender_address_history(sender_address, exclude_session_id)
            .await
    }

    async fn sender_relationship_history(
        &self,
        sender_address: &str,
        recipient_addresses: &[String],
        exclude_session_id: &str,
        before_started_at: &str,
    ) -> anyhow::Result<SenderRelationshipHistory> {
        let (
            sender_completed_count,
            sender_distinct_days,
            relationship_completed_count,
            relationship_distinct_days,
        ) = vigilyx_db::VigilDb::sender_relationship_history(
            self,
            sender_address,
            recipient_addresses,
            exclude_session_id,
            before_started_at,
        )
        .await?;
        Ok(SenderRelationshipHistory {
            sender_completed_count,
            sender_distinct_days,
            relationship_completed_count,
            relationship_distinct_days,
        })
    }
}
