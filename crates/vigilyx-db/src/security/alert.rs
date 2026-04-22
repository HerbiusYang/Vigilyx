//! Alert Database Operations

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::security::{AlertLevel, AlertRecord};

use crate::VigilDb;

impl VigilDb {
    /// InsertAlert
    pub async fn insert_alert(&self, alert: &AlertRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_alerts
                (id, verdict_id, session_id, alert_level, expected_loss,
                 return_period, cvar, risk_final, k_conflict, cusum_alarm,
                 rationale, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(alert.id.to_string())
        .bind(alert.verdict_id.to_string())
        .bind(alert.session_id.to_string())
        .bind(alert.alert_level.as_str())
        .bind(alert.expected_loss)
        .bind(alert.return_period)
        .bind(alert.cvar)
        .bind(alert.risk_final)
        .bind(alert.k_conflict)
        .bind(alert.cusum_alarm)
        .bind(&alert.rationale)
        .bind(alert.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query alerts (Pagination)
    pub async fn list_alerts(
        &self,
        level_filter: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AlertRecord>> {
        let mut sql = String::from(
            "SELECT id, verdict_id, session_id, alert_level, expected_loss, \
             return_period, cvar, risk_final, k_conflict, cusum_alarm, rationale, \
             acknowledged, acknowledged_by, acknowledged_at, created_at \
             FROM security_alerts",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(level) = level_filter {
            binds.push(level.to_string());
            sql.push_str(" WHERE alert_level = $1");
        }
        sql.push_str(" ORDER BY created_at DESC");
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));
        let mut query = sqlx::query_as::<_, AlertRow>(&sql);
        for b in &binds {
            query = query.bind(b);
        }
        let rows = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| r.into_record()).collect())
    }

    /// Acknowledge alert
    pub async fn acknowledge_alert(&self, alert_id: Uuid, acknowledged_by: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE security_alerts
            SET acknowledged = TRUE, acknowledged_by = $2, acknowledged_at = $3
            WHERE id = $1
            "#,
        )
        .bind(alert_id.to_string())
        .bind(acknowledged_by)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

// Database row type

#[derive(Debug, sqlx::FromRow)]
struct AlertRow {
    id: String,
    verdict_id: String,
    session_id: String,
    alert_level: String,
    expected_loss: f64,
    return_period: f64,
    #[sqlx(default)]
    cvar: f64,
    risk_final: f64,
    k_conflict: f64,
    cusum_alarm: bool,
    rationale: String,
    #[sqlx(default)]
    acknowledged: Option<bool>,
    #[sqlx(default)]
    acknowledged_by: Option<String>,
    #[sqlx(default)]
    acknowledged_at: Option<String>,
    created_at: String,
}

impl AlertRow {
    fn into_record(self) -> AlertRecord {
        AlertRecord {
            id: Uuid::parse_str(&self.id).unwrap_or_else(|e| {
                tracing::warn!(
                    raw = self.id,
                    "Invalid alert UUID, generating fallback: {}",
                    e
                );
                Uuid::new_v4()
            }),
            verdict_id: Uuid::parse_str(&self.verdict_id).unwrap_or_else(|e| {
                tracing::warn!(
                    raw = self.verdict_id,
                    "Invalid verdict UUID, generating fallback: {}",
                    e
                );
                Uuid::new_v4()
            }),
            session_id: Uuid::parse_str(&self.session_id).unwrap_or_else(|e| {
                tracing::warn!(
                    raw = self.session_id,
                    "Invalid session UUID, generating fallback: {}",
                    e
                );
                Uuid::new_v4()
            }),
            alert_level: AlertLevel::parse(&self.alert_level),
            expected_loss: self.expected_loss,
            return_period: self.return_period,
            cvar: self.cvar,
            risk_final: self.risk_final,
            k_conflict: self.k_conflict,
            cusum_alarm: self.cusum_alarm,
            rationale: self.rationale,
            acknowledged: self.acknowledged.unwrap_or(false),
            acknowledged_by: self.acknowledged_by,
            acknowledged_at: self.acknowledged_at.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|t| t.with_timezone(&Utc))
            }),
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}
