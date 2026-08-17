//! Alert Database Operations

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use uuid::Uuid;

use vigilyx_core::security::{AlertLevel, AlertRecord};

use crate::VigilDb;

/// Time window in which a duplicate `(session_id, alert_level)` alert is
/// suppressed. Rescan paths (release rescan, periodic catch-up) re-run
/// post-verdict for the same session minutes apart; 10 minutes covers that
/// without hiding genuinely new alerts for long-lived sessions.
pub const ALERT_DEDUP_WINDOW_MINUTES: i64 = 10;

/// Canonical timestamp format for the `security_alerts` table.
///
/// The `created_at` column is TEXT and the dedup window compares it
/// lexicographically (`created_at >= $cutoff`). That is only sound when every
/// writer uses one fixed-width format with a `Z` suffix — mixing
/// `to_rfc3339()` output (`+00:00` offset, variable fractional digits) with
/// anything else silently corrupts the comparison. ALL writes and ALL
/// comparisons on this table's timestamps must go through this helper.
pub(crate) fn format_alert_timestamp(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

impl VigilDb {
    /// InsertAlert
    ///
    /// Idempotent within [`ALERT_DEDUP_WINDOW_MINUTES`]: a second alert for the
    /// same `(session_id, alert_level)` inside the window (e.g. a release
    /// rescan racing the periodic catch-up rescan, or a verdict + disposition
    /// double evaluation) is dropped instead of duplicated. Returns `true`
    /// when the row was actually inserted.
    pub async fn insert_alert(&self, alert: &AlertRecord) -> Result<bool> {
        let cutoff = format_alert_timestamp(
            &(alert.created_at - chrono::Duration::minutes(ALERT_DEDUP_WINDOW_MINUTES)),
        );
        let result = sqlx::query(
            r#"
            INSERT INTO security_alerts
                (id, verdict_id, session_id, alert_level, expected_loss,
                 return_period, cvar, risk_final, k_conflict, cusum_alarm,
                 rationale, created_at)
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
            WHERE NOT EXISTS (
                SELECT 1 FROM security_alerts
                WHERE session_id = $3 AND alert_level = $4 AND created_at >= $13
            )
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
        .bind(format_alert_timestamp(&alert.created_at))
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Query alerts (Pagination)
    pub async fn list_alerts(
        &self,
        level_filter: Option<&str>,
        acknowledged: Option<bool>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AlertRecord>> {
        let (where_clause, binds) = build_alert_filter(level_filter, acknowledged);
        let mut sql = String::from(
            "SELECT id, verdict_id, session_id, alert_level, expected_loss, \
             return_period, cvar, risk_final, k_conflict, cusum_alarm, rationale, \
             acknowledged, acknowledged_by, acknowledged_at, created_at \
             FROM security_alerts",
        );
        sql.push_str(&where_clause);
        sql.push_str(" ORDER BY created_at DESC");
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));
        let mut query = sqlx::query_as::<_, AlertRow>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            query = query.bind(b);
        }
        let rows = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| r.into_record()).collect())
    }

    /// Count alerts matching the same filters as [`list_alerts`].
    pub async fn count_alerts(
        &self,
        level_filter: Option<&str>,
        acknowledged: Option<bool>,
    ) -> Result<i64> {
        let (where_clause, binds) = build_alert_filter(level_filter, acknowledged);
        let sql = format!("SELECT COUNT(*) FROM security_alerts{}", where_clause);
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in &binds {
            query = query.bind(b);
        }
        let total = query.fetch_one(&self.pool).await?;
        Ok(total)
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
        .bind(format_alert_timestamp(&Utc::now()))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

// Database row type

/// Build the WHERE clause (and bind values) shared by `list_alerts` / `count_alerts`.
/// `acknowledged` is a typed bool, so it is inlined as a SQL literal instead of a bind
/// (the `acknowledged` column is BOOLEAN; only the TEXT level filter is parameterized).
fn build_alert_filter(
    level_filter: Option<&str>,
    acknowledged: Option<bool>,
) -> (String, Vec<String>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(level) = level_filter {
        binds.push(level.to_string());
        conditions.push(format!("alert_level = ${}", binds.len()));
    }
    if let Some(ack) = acknowledged {
        conditions.push(if ack {
            "acknowledged IS TRUE".to_string()
        } else {
            "acknowledged IS FALSE".to_string()
        });
    }
    if conditions.is_empty() {
        (String::new(), binds)
    } else {
        (format!(" WHERE {}", conditions.join(" AND ")), binds)
    }
}

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

#[cfg(test)]
mod tests {
    use super::{build_alert_filter, format_alert_timestamp};
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn filter_without_params_has_no_where_clause() {
        let (where_clause, binds) = build_alert_filter(None, None);
        assert_eq!(where_clause, "");
        assert!(binds.is_empty());
    }

    #[test]
    fn filter_with_level_only_binds_first_position() {
        let (where_clause, binds) = build_alert_filter(Some("P0"), None);
        assert_eq!(where_clause, " WHERE alert_level = $1");
        assert_eq!(binds, vec!["P0".to_string()]);
    }

    #[test]
    fn filter_with_acknowledged_only_uses_boolean_literal() {
        let (where_clause, binds) = build_alert_filter(None, Some(false));
        assert_eq!(where_clause, " WHERE acknowledged IS FALSE");
        assert!(binds.is_empty());

        let (where_clause, binds) = build_alert_filter(None, Some(true));
        assert_eq!(where_clause, " WHERE acknowledged IS TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn filter_with_level_and_acknowledged_combines_conditions() {
        let (where_clause, binds) = build_alert_filter(Some("P2"), Some(true));
        assert_eq!(
            where_clause,
            " WHERE alert_level = $1 AND acknowledged IS TRUE"
        );
        assert_eq!(binds, vec!["P2".to_string()]);
    }

    #[test]
    fn alert_timestamp_format_is_fixed_width_z_suffixed() {
        // Format invariant (C8): security_alerts.created_at is TEXT and the
        // dedup window compares it lexicographically. Every value must be
        // fixed-width with a 'Z' suffix — a single `to_rfc3339()` write
        // ("+00:00", variable fractional digits) silently corrupts the
        // comparison for all rows around it.
        let t = Utc.with_ymd_and_hms(2026, 8, 15, 4, 57, 5).unwrap();
        let s = format_alert_timestamp(&t);
        assert!(s.ends_with('Z'), "must use Z suffix, got {s}");
        assert!(!s.contains('+'), "must not use +00:00 offset, got {s}");
        // YYYY-MM-DDTHH:MM:SS.ffffffZ — exactly 27 chars.
        assert_eq!(s.len(), 27, "must be fixed-width, got {s}");
        assert_eq!(&s[19..20], ".", "must always carry microseconds, got {s}");
    }

    #[test]
    fn alert_timestamp_lexicographic_order_matches_chronology() {
        // The dedup window (`created_at >= cutoff`) is a string comparison;
        // it is only correct when lexicographic order == chronological order,
        // including across sub-second boundaries and around whole seconds.
        let base = Utc.with_ymd_and_hms(2026, 8, 15, 4, 57, 5).unwrap();
        let times = [
            base,
            base + Duration::microseconds(1),
            base + Duration::milliseconds(500),
            base + Duration::microseconds(999_999),
            base + Duration::seconds(1),
            base + Duration::minutes(10),
        ];
        let formatted: Vec<String> = times.iter().map(format_alert_timestamp).collect();
        let mut sorted = formatted.clone();
        sorted.sort();
        assert_eq!(
            formatted, sorted,
            "lexicographic order must match chronological order"
        );

        // The window cutoff string must compare correctly against row values:
        // a row exactly at the cutoff is kept (>=), one microsecond before is not.
        let cutoff = format_alert_timestamp(&(base + Duration::seconds(1)));
        let at = format_alert_timestamp(&(base + Duration::seconds(1)));
        let before = format_alert_timestamp(
            &(base + Duration::seconds(1) - Duration::microseconds(1)),
        );
        assert!(at >= cutoff);
        assert!(before < cutoff);
    }
}
