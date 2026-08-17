//! Config KV storage

use anyhow::Result;

use crate::VigilDb;

impl VigilDb {
    /// Read config value from config table
    pub async fn get_config(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM config WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(v,)| v))
    }

    /// Set config value in config table
    pub async fn set_config(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // SEC (M-1, 2026-08-15): the global `bump_auth_token_version` was removed.
    // Session revocation is per user (`bump_platform_user_token_version`),
    // per role (`bump_platform_role_token_versions`) or all users
    // (`bump_all_platform_user_token_versions`) — a single global counter let
    // any user's logout invalidate every operator's session.
}
