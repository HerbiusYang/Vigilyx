//! SecurityEngineConfigurationData (pipeline, AI service, email alert)

use anyhow::Result;
use std::collections::HashSet;

use crate::VigilDb;

impl VigilDb {
   /// GetStream Configuration JSON
    pub async fn get_pipeline_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'security_pipeline'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// Stream Configuration JSON
    pub async fn set_pipeline_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('security_pipeline', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get AI Service configuration JSON
    pub async fn get_ai_service_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'ai_service_config'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// AI Service configuration JSON
    pub async fn set_ai_service_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('ai_service_config', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// GetEmail alert configuration JSON
    pub async fn get_email_alert_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'email_alert_config'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// Email alert configuration JSON
    pub async fn set_email_alert_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('email_alert_config', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get WeChat alert configuration JSON
    pub async fn get_wechat_alert_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'wechat_alert_config'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// WeChat alert configuration JSON
    pub async fn set_wechat_alert_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('wechat_alert_config', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get DomainConfiguration
    pub async fn get_internal_domains(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'auto_internal_domains'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// DomainConfiguration
    pub async fn set_internal_domains(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('auto_internal_domains', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// GetData security Configuration JSON
    pub async fn get_time_policy_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'ds_time_policy'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// Data security Configuration JSON
    pub async fn set_time_policy_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('ds_time_policy', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get Syslog Configuration JSON(Configuration, Data security)
    pub async fn get_syslog_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'syslog_config'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// Syslog Configuration JSON
    pub async fn set_syslog_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('syslog_config', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get Sniffer Data securityConfiguration JSON (webmail_servers, http_ports)
    pub async fn get_sniffer_config(&self) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'sniffer_config'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

   /// Sniffer Data securityConfiguration JSON
    pub async fn set_sniffer_config(&self, json: &str) -> Result<()> {
        sqlx::query("INSERT INTO config (key, value) VALUES ('sniffer_config', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
            .bind(json)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

   /// Get inbound target IP rules from ui_preferences.capture.inbound_dst.
    pub async fn get_capture_inbound_target_ips(&self) -> Result<HashSet<String>> {
        let raw = self.get_config("ui_preferences").await?;
        Ok(raw
            .as_deref()
            .map(parse_capture_inbound_target_ips)
            .unwrap_or_default())
    }

   /// Domain
   ///
   /// :Statistics N Day, DomainReceived SenderDomain.
   /// Such as 1 DomainReceived>= min_senders SendingDomain,
   /// Domain Domain(Source).
   ///
   /// rcpt_to JSON (Such as `["user@domain.com"]`),
   /// jsonb_array_elements_text Extract Domain.
    pub async fn detect_internal_domains(
        &self,
        days: i32,
        min_senders: i32,
    ) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            WITH rcpt AS (
                SELECT
                    LOWER(split_part(elem, '@', 2)) as rcpt_domain,
                    sender_domain
                FROM sessions,
                     jsonb_array_elements_text(rcpt_to::jsonb) as elem
                WHERE status = 'Completed'
                  AND rcpt_to IS NOT NULL AND rcpt_to != '[]' AND rcpt_to != ''
                  AND sender_domain IS NOT NULL
                  AND started_at::timestamptz > NOW() - ($1 || ' days')::INTERVAL
            )
            SELECT rcpt_domain, COUNT(DISTINCT sender_domain)::BIGINT as unique_senders
            FROM rcpt
            WHERE rcpt_domain IS NOT NULL AND rcpt_domain != ''
            GROUP BY rcpt_domain
            HAVING COUNT(DISTINCT sender_domain) >= $2
            ORDER BY unique_senders DESC
            LIMIT 20
            "#,
        )
        .bind(days.to_string())
        .bind(min_senders as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

fn parse_capture_inbound_target_ips(raw: &str) -> HashSet<String> {
    let parsed = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(value) => value,
        Err(_) => return HashSet::new(),
    };

    parsed
        .get("capture")
        .and_then(|capture| capture.get("inbound_dst"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .map(str::to_string)
        .collect()
}
