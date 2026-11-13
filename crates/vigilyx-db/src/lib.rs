//! Vigilyx Unified Data Layer
//!
//! Provides all data access capabilities with feature flag isolation:
//! - `postgres`: PostgreSQL persistence (sessions/packets/security verdicts/IOC/temporal state)
//! - `redis`: Redis Streams with consumer groups for at-least-once data-plane delivery,
//!   plus Pub/Sub for fire-and-forget control-plane commands and notifications
//!
//!   Usage:
//! - vigilyx-sniffer: only the `redis` feature (capture -> publish sessions to Streams;
//!   use Pub/Sub for control-plane notifications)
//! - vigilyx-engine: PostgreSQL + Redis (consume Streams, analyze, and persist verdicts)
//! - vigilyx-api: PostgreSQL + Redis (serve APIs, persist state, and publish control commands)

#[cfg(feature = "postgres")]
use std::sync::Arc;

#[cfg(feature = "postgres")]
use tokio::sync::Mutex;

pub mod error;

// ===== Redis Message Queue (redis feature) =====
#[cfg(feature = "redis")]
pub mod mq;

// ===== Shared operational read cache (redis feature) =====
// Kept separate from `mq`: this client may only talk to the optional
// eviction-enabled read-cache Valkey instance, never to the message bus.
#[cfg(feature = "redis")]
pub mod cache;

// ===== PostgreSQL Persistence (postgres feature) =====
#[cfg(feature = "postgres")]
mod infra;

// ===== Security Engine Data Layer (postgres feature) =====
#[cfg(feature = "postgres")]
pub mod security;

// Re-export DB-specific types
#[cfg(feature = "postgres")]
pub use infra::migrate::SchemaMigration;
#[cfg(feature = "postgres")]
pub use infra::platform_auth::{
    ADMIN_ROLE_ID, AUDIT_ROLE_ID, AUDIT_ROLE_PERMISSIONS, PLATFORM_PERMISSIONS, PlatformAuthUser,
    PlatformPermission, PlatformRole, PlatformUser,
};
#[cfg(feature = "postgres")]
pub use infra::session::{SessionCountSnapshot, SessionListCursor, SessionListEntry};
#[cfg(feature = "postgres")]
pub use infra::typed_config::VersionedConfig;
#[cfg(feature = "postgres")]
pub use security::data_security::{EmailReviewFilters, HttpSessionFilters};
#[cfg(feature = "postgres")]
pub use security::delivery::DeliveryRiskDetailKind;
#[cfg(feature = "postgres")]
pub use security::disposition::DispositionRuleRow;
#[cfg(feature = "postgres")]
pub use security::privacy::{PrivacyAccessRequest, PrivacyOperatorSecret};
#[cfg(feature = "postgres")]
pub use security::verdict::VerdictWithMeta;
#[cfg(feature = "postgres")]
pub use security::yara::YaraRuleRow;
#[cfg(feature = "postgres")]
use vigilyx_core::security::SecurityStats;

/// Unified data access layer
///
/// Wraps PostgreSQL connection pool and provides all database operations.
/// Domain-specific methods are distributed across different modules in `impl VigilDb` blocks.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct VigilDb {
    pool: sqlx::Pool<sqlx::Postgres>,
    /// Short-lived process-local cache for the dashboard's expensive stats
    /// snapshot. Holding this mutex during refresh coalesces request bursts.
    pub(crate) security_stats_cache: Arc<Mutex<Option<(std::time::Instant, SecurityStats)>>>,
    pub(crate) session_count_cache: Arc<infra::session::SessionCountCache>,
}

#[cfg(feature = "postgres")]
impl VigilDb {
    /// Get underlying connection pool
    pub fn pool(&self) -> &sqlx::Pool<sqlx::Postgres> {
        &self.pool
    }

    /// Get underlying connection pool (backward compatibility alias)
    pub fn get_pool(&self) -> &sqlx::Pool<sqlx::Postgres> {
        &self.pool
    }

    /// Execute SQL with parameters (for management operations like precise cleanup)
    pub async fn execute_sql(&self, sql: &str, params: &[&String]) -> anyhow::Result<()> {
        // Caller-supplied SQL string; params are bound, the statement text is not.
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
        for p in params {
            query = query.bind(*p);
        }
        query.execute(&self.pool).await?;
        Ok(())
    }
}

/// Backward compatibility alias: original Database type from vigilyx-api
#[cfg(feature = "postgres")]
pub type Database = VigilDb;

/// Backward compatibility alias: original EngineDb type from vigilyx-engine
#[cfg(feature = "postgres")]
pub type EngineDb = VigilDb;
