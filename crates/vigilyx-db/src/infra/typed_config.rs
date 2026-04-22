//! Typed config accessor layer for JSONB config tables.
//!
//! Each config domain has its own table with:
//! - `id = 1` singleton row
//! - `version` monotonic counter (bumped on every write)
//! - `config` JSONB column
//! - `updated_at` timestamp
//!
//! The `version` column enables:
//! - Change detection (consumers poll version to detect changes)
//! - Reload ACK protocol (API sends config_version, consumer confirms)

use anyhow::Result;

use crate::VigilDb;

/// Whitelist of allowed config table names for SQL interpolation (defense-in-depth).
const ALLOWED_TABLES: &[&str] = &[
    "config_security_pipeline",
    "config_ai_service",
    "config_email_alert",
    "config_sniffer",
    "config_syslog",
    "config_time_policy",
    "config_deployment",
    "config_internal_domains",
];

/// Result of reading a typed config: the config value and its version.
#[derive(Debug, Clone)]
pub struct VersionedConfig<T> {
    pub config: T,
    pub version: i64,
}

impl VigilDb {
    /// Generic: read typed config from a JSONB config table.
    ///
    /// Returns `None` if the singleton row does not exist.
    async fn get_typed_config_raw(&self, table: &str) -> Result<Option<(serde_json::Value, i64)>> {
        assert!(
            ALLOWED_TABLES.contains(&table),
            "Invalid config table name: {table}"
        );
        let sql = format!("SELECT config, version FROM {table} WHERE id = 1");
        let row: Option<(serde_json::Value, i64)> =
            sqlx::query_as(&sql).fetch_optional(&self.pool).await?;
        Ok(row)
    }

    /// Generic: write typed config to a JSONB config table.
    ///
    /// Atomically increments `version` and returns the new version.
    /// Creates the singleton row if it doesn't exist.
    async fn set_typed_config_raw(&self, table: &str, config: &serde_json::Value) -> Result<i64> {
        assert!(
            ALLOWED_TABLES.contains(&table),
            "Invalid config table name: {table}"
        );
        let sql = format!(
            r#"
            INSERT INTO {table} (id, version, config, updated_at)
            VALUES (1, 1, $1, NOW())
            ON CONFLICT (id) DO UPDATE
            SET config = EXCLUDED.config,
                version = {table}.version + 1,
                updated_at = NOW()
            RETURNING version
            "#,
        );
        let (version,): (i64,) = sqlx::query_as(&sql)
            .bind(config)
            .fetch_one(&self.pool)
            .await?;
        Ok(version)
    }

    // ── Domain-specific typed config accessors ──

    /// Get pipeline config (typed).
    pub async fn get_pipeline_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_security_pipeline")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set pipeline config (typed). Returns new version.
    pub async fn set_pipeline_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_security_pipeline", config)
            .await
    }

    /// Get AI service config (typed).
    pub async fn get_ai_service_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_ai_service")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set AI service config (typed). Returns new version.
    pub async fn set_ai_service_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_ai_service", config).await
    }

    /// Get email alert config (typed).
    pub async fn get_email_alert_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_email_alert")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set email alert config (typed). Returns new version.
    pub async fn set_email_alert_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_email_alert", config)
            .await
    }

    /// Get sniffer config (typed).
    pub async fn get_sniffer_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_sniffer")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set sniffer config (typed). Returns new version.
    pub async fn set_sniffer_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_sniffer", config).await
    }

    /// Get syslog config (typed).
    pub async fn get_syslog_config_v2(&self) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_syslog")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set syslog config (typed). Returns new version.
    pub async fn set_syslog_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_syslog", config).await
    }

    /// Get time policy config (typed).
    pub async fn get_time_policy_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_time_policy")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set time policy config (typed). Returns new version.
    pub async fn set_time_policy_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_time_policy", config)
            .await
    }

    /// Get deployment config (typed).
    pub async fn get_deployment_config_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_deployment")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set deployment config (typed). Returns new version.
    pub async fn set_deployment_config_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_deployment", config).await
    }

    /// Get internal domains (typed).
    pub async fn get_internal_domains_v2(
        &self,
    ) -> Result<Option<VersionedConfig<serde_json::Value>>> {
        Ok(self
            .get_typed_config_raw("config_internal_domains")
            .await?
            .map(|(config, version)| VersionedConfig { config, version }))
    }

    /// Set internal domains (typed). Returns new version.
    pub async fn set_internal_domains_v2(&self, config: &serde_json::Value) -> Result<i64> {
        self.set_typed_config_raw("config_internal_domains", config)
            .await
    }

    // ── Auth credentials (separate table) ──

    /// Get auth credentials (password hash + token version).
    pub async fn get_auth_credentials(&self) -> Result<Option<(String, i64)>> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT password_hash, token_version FROM auth_credentials WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Set auth password hash. Returns new token version.
    pub async fn set_auth_password_hash(&self, hash: &str) -> Result<i64> {
        let (tv,): (i64,) = sqlx::query_as(
            r#"
            INSERT INTO auth_credentials (id, password_hash, token_version, updated_at)
            VALUES (1, $1, 1, NOW())
            ON CONFLICT (id) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                token_version = auth_credentials.token_version + 1,
                updated_at = NOW()
            RETURNING token_version
            "#,
        )
        .bind(hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(tv)
    }

    /// Get the current token version (for JWT invalidation).
    pub async fn get_auth_token_version(&self) -> Result<i64> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT token_version FROM auth_credentials WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v).unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioned_config_debug() {
        let vc = VersionedConfig {
            config: serde_json::json!({"key": "value"}),
            version: 42,
        };
        let debug = format!("{:?}", vc);
        assert!(debug.contains("42"));
    }
}
