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

   /// Atomically bump the auth token version stored in the config table.
   ///
   /// This is used when logout must revoke previously issued JWTs before their
   /// normal expiry time.
    pub async fn bump_auth_token_version(&self) -> Result<u64> {
        let (value,): (String,) = sqlx::query_as(
            r#"
            INSERT INTO config (key, value)
            VALUES ('auth_token_version', '1')
            ON CONFLICT(key) DO UPDATE
            SET value = (COALESCE(NULLIF(config.value, ''), '0')::BIGINT + 1)::TEXT
            RETURNING value
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        value
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid auth_token_version after bump: {e}"))
    }
}
