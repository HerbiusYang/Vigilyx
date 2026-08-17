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
    ///
    /// Poisoning guard: only sessions that reached a verdict (i.e. entered
    /// DATA and were actually analyzed) count. RCPTs that were rejected with
    /// 550 before DATA must not inflate a domain's sender diversity, or an
    /// attacker could spray recipients at their own domain to get it
    /// auto-classified as "internal".
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
                  AND EXISTS (
                      SELECT 1 FROM security_verdicts sv
                      WHERE sv.session_id = sessions.id
                  )
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

// DB-backed regression tests for internal-domain auto-detection.
// Gated behind `infra-tests` (TEST_DATABASE_URL).
#[cfg(all(test, feature = "infra-tests"))]
mod infra_tests {
    use crate::VigilDb;

    async fn make_db() -> VigilDb {
        let db = VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init().await.unwrap();
        db.init_security_tables().await.unwrap();
        db
    }

    async fn insert_session(db: &VigilDb, id: &str, rcpt_domain: &str, sender_domain: &str) {
        sqlx::query(
            "INSERT INTO sessions \
                (id, protocol, client_ip, client_port, server_ip, server_port, \
                 started_at, status, rcpt_to, sender_domain) \
             VALUES ($1, 'SMTP', '203.0.113.5', 2525, '10.0.0.2', 25, \
                     $2, 'Completed', $3, $4)",
        )
        .bind(id)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(format!(r#"["user@{}"]"#, rcpt_domain))
        .bind(sender_domain)
        .execute(db.pool())
        .await
        .unwrap();
    }

    async fn insert_verdict(db: &VigilDb, session_id: &str) {
        sqlx::query(
            "INSERT INTO security_verdicts \
                (id, session_id, threat_level, confidence, categories, summary, \
                 pillar_scores, modules_run, modules_flagged, total_duration_ms, created_at) \
             VALUES ($1, $2, 'Safe', 0.9, '[]', 'test', '{}', 1, 0, 5, $3)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(session_id)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(db.pool())
        .await
        .unwrap();
    }

    /// PoC (internal-domain poisoning): RCPTs from sessions that never
    /// produced a verdict (e.g. 550-rejected before DATA) must not count
    /// toward auto-detection.
    #[tokio::test]
    async fn detect_internal_domains_requires_verdict() {
        let db = make_db().await;
        let target = format!("poison-{}.example", uuid::Uuid::new_v4().simple());

        // 5 "distinct senders" deliver to the target domain but every session
        // was rejected before analysis (no verdict rows).
        let mut session_ids = Vec::new();
        for i in 0..5 {
            let id = uuid::Uuid::new_v4().to_string();
            insert_session(&db, &id, &target, &format!("s{}.senders.example", i)).await;
            session_ids.push(id);
        }

        let detected = db.detect_internal_domains(30, 5).await.unwrap();
        assert!(
            !detected.iter().any(|(domain, _)| domain == &target),
            "sessions without verdicts must not count: {:?}",
            detected
        );

        // Once the sessions are actually analyzed (verdict exists), the same
        // traffic does count.
        for id in &session_ids {
            insert_verdict(&db, id).await;
        }
        let detected = db.detect_internal_domains(30, 5).await.unwrap();
        assert!(
            detected.iter().any(|(domain, _)| domain == &target),
            "analyzed sessions must count: {:?}",
            detected
        );
    }
}
