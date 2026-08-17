//! MTA CRUD

//! MTA,.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::VigilDb;

/// C6: TTL enforcement for quarantined raw messages. Compares in absolute
/// time (timestamptz) and never touches a release that is in flight.
const QUARANTINE_CLEANUP_EXPIRED_SQL: &str = r#"DELETE FROM quarantine
               WHERE created_at::timestamptz < NOW() - (ttl_days || ' days')::INTERVAL
                 AND status != 'releasing'"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub session_id: String,
    pub verdict_id: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    pub subject: Option<String>,
    pub threat_level: String,
    pub reason: Option<String>,
    pub status: String,
    pub created_at: String,
    pub released_at: Option<String>,
    pub released_by: Option<String>,
    pub ttl_days: i32,
    /// raw_eml (),
    #[serde(default)]
    pub raw_eml_size: i64,
    /// Submitting client IP at quarantine time; used to stamp the Received
    /// hop when the message is later released downstream (release audit).
    #[serde(default)]
    pub client_ip: Option<String>,
}

/// (raw_eml)
#[derive(sqlx::FromRow)]
struct QuarantineListRow {
    id: String,
    session_id: String,
    verdict_id: Option<String>,
    mail_from: Option<String>,
    rcpt_to: String,
    subject: Option<String>,
    threat_level: String,
    reason: Option<String>,
    status: String,
    created_at: String,
    released_at: Option<String>,
    released_by: Option<String>,
    ttl_days: i32,
    raw_eml_size: i64,
    client_ip: Option<String>,
}

#[derive(sqlx::FromRow)]
struct QuarantineRawRow {
    id: String,
    session_id: String,
    verdict_id: Option<String>,
    mail_from: Option<String>,
    rcpt_to: String,
    subject: Option<String>,
    threat_level: String,
    reason: Option<String>,
    status: String,
    created_at: String,
    released_at: Option<String>,
    released_by: Option<String>,
    ttl_days: i32,
    raw_eml: Vec<u8>,
    client_ip: Option<String>,
}

fn raw_row_to_entry(row: QuarantineRawRow) -> (Vec<u8>, QuarantineEntry) {
    let eml_size = row.raw_eml.len() as i64;
    let entry = QuarantineEntry {
        id: row.id,
        session_id: row.session_id,
        verdict_id: row.verdict_id,
        mail_from: row.mail_from,
        rcpt_to: serde_json::from_str(&row.rcpt_to).unwrap_or_default(),
        subject: row.subject,
        threat_level: row.threat_level,
        reason: row.reason,
        status: row.status,
        created_at: row.created_at,
        released_at: row.released_at,
        released_by: row.released_by,
        ttl_days: row.ttl_days,
        raw_eml_size: eml_size,
        client_ip: row.client_ip,
    };

    (row.raw_eml, entry)
}

pub struct QuarantineStoreRequest<'a> {
    pub session_id: &'a Uuid,
    pub verdict_id: Option<&'a Uuid>,
    pub mail_from: Option<&'a str>,
    pub rcpt_to: &'a [String],
    pub subject: Option<&'a str>,
    pub raw_eml: &'a [u8],
    pub threat_level: &'a str,
    pub reason: Option<&'a str>,
    /// Submitting client IP (MTA proxy connection peer); preserved so a later
    /// release can stamp an accurate Received hop instead of "from unknown".
    pub client_ip: Option<&'a str>,
}

impl VigilDb {
    /// Comment retained in English.
    pub async fn quarantine_store(&self, req: &QuarantineStoreRequest<'_>) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let rcpt_json = serde_json::to_string(req.rcpt_to)?;

        sqlx::query(
            r#"INSERT INTO quarantine
               (id, session_id, verdict_id, mail_from, rcpt_to, subject,
                raw_eml, threat_level, reason, status, created_at, ttl_days, client_ip)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'quarantined', $10, 30, $11)"#,
        )
        .bind(&id)
        .bind(req.session_id.to_string())
        .bind(req.verdict_id.map(|v| v.to_string()))
        .bind(req.mail_from)
        .bind(&rcpt_json)
        .bind(req.subject)
        .bind(req.raw_eml)
        .bind(req.threat_level)
        .bind(req.reason)
        .bind(&now)
        .bind(req.client_ip)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// (raw_eml)
    pub async fn quarantine_list(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<QuarantineEntry>> {
        let rows: Vec<QuarantineListRow> = sqlx::query_as(
            r#"SELECT id, session_id, verdict_id, mail_from, rcpt_to, subject,
                      threat_level, reason, status, created_at, released_at,
                      released_by, ttl_days, length(raw_eml)::BIGINT as raw_eml_size,
                      client_ip
               FROM quarantine
               WHERE ($1::TEXT IS NULL OR status = $1)
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| QuarantineEntry {
                id: r.id,
                session_id: r.session_id,
                verdict_id: r.verdict_id,
                mail_from: r.mail_from,
                rcpt_to: serde_json::from_str(&r.rcpt_to).unwrap_or_default(),
                subject: r.subject,
                threat_level: r.threat_level,
                reason: r.reason,
                status: r.status,
                created_at: r.created_at,
                released_at: r.released_at,
                released_by: r.released_by,
                ttl_days: r.ttl_days,
                raw_eml_size: r.raw_eml_size,
                client_ip: r.client_ip,
            })
            .collect())
    }

    /// EML ()
    pub async fn quarantine_get_raw_eml(
        &self,
        id: &str,
    ) -> Result<Option<(Vec<u8>, QuarantineEntry)>> {
        let row: Option<QuarantineRawRow> = sqlx::query_as(
            "SELECT id, session_id, verdict_id, mail_from, rcpt_to, subject,
                    threat_level, reason, status, created_at, released_at,
                    released_by, ttl_days, raw_eml, client_ip
             FROM quarantine WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(raw_row_to_entry))
    }

    /// Atomically claim a quarantined message for release before any downstream delivery.
    pub async fn quarantine_claim_release(
        &self,
        id: &str,
    ) -> Result<Option<(Vec<u8>, QuarantineEntry)>> {
        let row: Option<QuarantineRawRow> = sqlx::query_as(
            "UPDATE quarantine
             SET status = 'releasing'
             WHERE id = $1 AND status = 'quarantined'
             RETURNING id, session_id, verdict_id, mail_from, rcpt_to, subject,
                       threat_level, reason, status, created_at, released_at,
                       released_by, ttl_days, raw_eml, client_ip",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(raw_row_to_entry))
    }

    /// Current status lookup used to explain release conflicts cleanly.
    pub async fn quarantine_status(&self, id: &str) -> Result<Option<String>> {
        let row = sqlx::query_scalar::<_, String>("SELECT status FROM quarantine WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Finalize a previously claimed release after the downstream relay accepted the message.
    pub async fn quarantine_finalize_release(&self, id: &str, released_by: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE quarantine SET status = 'released', released_at = $1, released_by = $2
             WHERE id = $3 AND status = 'releasing'",
        )
        .bind(&now)
        .bind(released_by)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Return a claimed release back to the queue when downstream delivery failed.
    pub async fn quarantine_release_reset(&self, id: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE quarantine
             SET status = 'quarantined', released_at = NULL, released_by = NULL
             WHERE id = $1 AND status = 'releasing'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark a claimed release as blocked by the mandatory pre-release rescan.
    pub async fn quarantine_mark_release_blocked(&self, id: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE quarantine
             SET status = 'release_blocked'
             WHERE id = $1 AND status = 'releasing'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Record the pre-release rescan verdict on the quarantine entry.
    ///
    /// The rescan replaces the session's verdict row (one current verdict per
    /// session), so the original `verdict_id` would dangle; pointing it at the
    /// rescan verdict keeps the reference valid and auditable.
    pub async fn quarantine_record_release_rescan(
        &self,
        id: &str,
        verdict_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE quarantine
             SET verdict_id = $2
             WHERE id = $1",
        )
        .bind(id)
        .bind(verdict_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// SEC: refuse to delete an entry whose release is in flight — removing it
    /// mid-relay would orphan the 'releasing' lock and break the release audit
    /// trail (F2). Returns an explicit error in that case; `Ok(false)` still
    /// means "entry not found".
    pub async fn quarantine_delete(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM quarantine WHERE id = $1 AND status != 'releasing'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() > 0 {
            return Ok(true);
        }
        if let Some(status) = self.quarantine_status(id).await?
            && status == "releasing"
        {
            anyhow::bail!(
                "quarantine entry {id} is currently being released and cannot be deleted"
            );
        }
        Ok(false)
    }

    /// Delete entries past their TTL (invoked by the engine's daily cleanup).
    ///
    /// `created_at` is stored as an RFC 3339 UTC string written by Rust
    /// (`Utc::now().to_rfc3339()`), so the cutoff comparison must cast to
    /// `timestamptz` — the previous TO_CHAR approach rendered the cutoff in
    /// the PG session timezone but tagged it "Z" and compared as text,
    /// deleting entries up to 8 hours early (container TZ=Asia/Shanghai).
    /// Entries in `releasing` state are never deleted: a release in flight
    /// owns the raw_eml bytes and its audit trail.
    pub async fn quarantine_cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query(QUARANTINE_CLEANUP_EXPIRED_SQL)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn quarantine_count(&self, status: Option<&str>) -> Result<i64> {
        #[derive(sqlx::FromRow)]
        struct CountRow {
            count: i64,
        }
        let row: CountRow = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT as count FROM quarantine WHERE ($1::TEXT IS NULL OR status = $1)",
        )
        .bind(status)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.count)
    }
}

#[cfg(test)]
mod tests {
    use super::QUARANTINE_CLEANUP_EXPIRED_SQL;

    #[test]
    fn cleanup_expired_sql_compares_absolute_time_and_protects_releasing() {
        // C6 regression: TO_CHAR rendered the cutoff in the PG session
        // timezone but tagged it "Z", then compared as text — with the
        // container TZ=Asia/Shanghai that deleted entries up to 8 hours
        // early, and rows being released could vanish mid-relay.
        assert!(
            QUARANTINE_CLEANUP_EXPIRED_SQL.contains("created_at::timestamptz"),
            "cutoff must be compared in absolute time"
        );
        assert!(
            !QUARANTINE_CLEANUP_EXPIRED_SQL.contains("TO_CHAR"),
            "TO_CHAR text comparison reintroduces the timezone bug"
        );
        assert!(
            QUARANTINE_CLEANUP_EXPIRED_SQL.contains("status != 'releasing'"),
            "an in-flight release must never be garbage-collected"
        );
    }
}
