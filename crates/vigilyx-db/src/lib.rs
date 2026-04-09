//! Vigilyx Unified Data Layer
//!
//! Provides all data access capabilities with feature flag isolation:
//! - `postgres`: PostgreSQL persistence (sessions/packets/security verdicts/IOC/temporal state)
//! - `redis`: Redis Pub/Sub message communication (real-time notifications between components)
//!
//!   Usage:
//! - vigilyx-sniffer: only redis feature (capture -> publish)
//! - vigilyx-engine: only postgres feature (analyze -> store verdict)
//! - vigilyx-api: both postgres + redis (receive message -> persist -> trigger analysis)

pub mod error;

// ===== Redis Message Queue (redis feature) =====
#[cfg(feature = "redis")]
pub mod mq;

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
pub use security::data_security::HttpSessionFilters;
#[cfg(feature = "postgres")]
pub use security::disposition::DispositionRuleRow;
#[cfg(feature = "postgres")]
pub use security::verdict::VerdictWithMeta;
#[cfg(feature = "postgres")]
pub use security::yara::YaraRuleRow;
#[cfg(feature = "postgres")]
pub use infra::typed_config::VersionedConfig;

/// Unified data access layer
///
/// Wraps PostgreSQL connection pool and provides all database operations.
/// Domain-specific methods are distributed across different modules in `impl VigilDb` blocks.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct VigilDb {
    pool: sqlx::Pool<sqlx::Postgres>,
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
        let mut query = sqlx::query(sql);
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
