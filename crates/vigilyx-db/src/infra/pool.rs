//! PostgreSQL Connection Pool Creation and Management

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;

use crate::VigilDb;

/// Default max connections **per pool**
///
/// PostgreSQL `max_connections=100`. The system creates at most 4 pools.
/// (API x2 + standalone Engine + MTA), so each pool limit must satisfy:
///   4 × DEFAULT_MAX_CONNECTIONS < 100
/// 20 x 4 = 80, leaving 20 for superuser / ops / migrations.
/// Can be overridden with the `PG_MAX_CONNECTIONS` environment variable.
const DEFAULT_MAX_CONNECTIONS: u32 = 20;

/// Default min connections **per pool**
///
/// 4 pools x 2 = 8 warm connections, which is enough for steady-state load.
/// Can be overridden with the `PG_MIN_CONNECTIONS` environment variable.
const DEFAULT_MIN_CONNECTIONS: u32 = 2;

impl VigilDb {
    /// Create database connection pool
    ///
    /// `url` format: `postgres://user:password@host:port/dbname`
    ///
    /// Connection pool parameters can be overridden via environment variables:
    /// - `PG_MAX_CONNECTIONS`: max connections(Default 50)
    /// - `PG_MIN_CONNECTIONS`: min connections(Default 8)
    pub async fn new(url: &str) -> Result<Self> {
        let max_conn = std::env::var("PG_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        let min_conn = std::env::var("PG_MIN_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MIN_CONNECTIONS);

        let pool = PgPoolOptions::new()
            .max_connections(max_conn)
            .min_connections(min_conn)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .idle_timeout(std::time::Duration::from_secs(600))
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    /// Check database health status
    ///
    /// Returns `Ok(true)` if the database responds within 5 seconds,
    /// `Err` on timeout or query failure.
    pub async fn health_check(&self) -> Result<bool> {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sqlx::query_as::<_, (i32,)>("SELECT 1").fetch_one(&self.pool),
        )
        .await
        {
            Ok(Ok((val,))) => Ok(val == 1),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Health check timed out after 5 seconds")),
        }
    }
}
