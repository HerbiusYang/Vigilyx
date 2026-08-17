//! False Positive Feedback Database Operations

use anyhow::Result;
use chrono::{DateTime, Utc};

use vigilyx_core::security::{FeedbackEntry, FeedbackStat};

use crate::VigilDb;

impl VigilDb {
    /// Submit feedback unless the same actor already submitted feedback for
    /// this session during the deduplication window.
    ///
    /// The `NOT EXISTS` guard is part of the INSERT so concurrent requests
    /// cannot both pass a separate check and lower IOC confidence twice.
    pub async fn insert_feedback(
        &self,
        fb: &FeedbackEntry,
        dedupe_since: DateTime<Utc>,
        max_recent_feedback: u64,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            WITH actor_lock AS (
                -- Serialize the per-actor count + insert across API replicas.
                -- Without this transaction-level lock, concurrent requests can
                -- all observe the same count and exceed the abuse budget.
                SELECT pg_advisory_xact_lock(hashtextextended($4, 0))
            )
            INSERT INTO security_feedback
                (id, session_id, verdict_id, submitted_by, feedback_type,
                 module_id, original_threat_level, user_comment, status, created_at)
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
            FROM actor_lock
            WHERE (
                SELECT COUNT(*)
                FROM security_feedback
                WHERE submitted_by = $4
                  AND created_at::timestamptz >= $11::timestamptz
            ) < $12
            AND NOT EXISTS (
                SELECT 1 FROM security_feedback
                  WHERE session_id = $2
                  AND submitted_by = $4
                  AND created_at::timestamptz >= $11::timestamptz
            )
            "#,
        )
        .bind(fb.id.to_string())
        .bind(fb.session_id.to_string())
        .bind(fb.verdict_id.as_ref().map(|v| v.to_string()))
        .bind(&fb.submitted_by)
        .bind(&fb.feedback_type)
        .bind(&fb.module_id)
        .bind(&fb.original_threat_level)
        .bind(&fb.user_comment)
        .bind(&fb.status)
        .bind(fb.created_at.to_rfc3339())
        .bind(dedupe_since.to_rfc3339())
        .bind(max_recent_feedback as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Count feedback submitted by one platform identity inside a sliding
    /// window. This is deliberately persisted in PostgreSQL so a process
    /// restart or a second API replica cannot reset the abuse budget.
    pub async fn count_recent_feedback(
        &self,
        submitted_by: &str,
        since: DateTime<Utc>,
    ) -> Result<u64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM security_feedback \
             WHERE submitted_by = $1 AND created_at::timestamptz >= $2::timestamptz",
        )
        .bind(submitted_by)
        .bind(since.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;
        Ok(count.max(0) as u64)
    }

    /// Get feedback statistics (false positives per module)
    pub async fn get_feedback_stats(&self) -> Result<Vec<FeedbackStat>> {
        let rows: Vec<(Option<String>, i64, i64)> = sqlx::query_as(
            r#"
            SELECT module_id, COUNT(*) as total,
                   COALESCE(SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END), 0)::BIGINT as fp_count
            FROM security_feedback
            GROUP BY module_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(module_id, total, fp)| FeedbackStat {
                module_id: module_id.unwrap_or_else(|| "overall".to_string()),
                total_feedback: total as u64,
                false_positives: fp as u64,
            })
            .collect())
    }

    /// Get false positive count for same sender/domain
    pub async fn count_false_positives_for_session_sender(
        &self,
        mail_from_domain: &str,
    ) -> Result<u64> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM security_feedback f
            JOIN sessions s ON f.session_id = s.id
            WHERE f.feedback_type = 'false_positive'
            AND s.mail_from LIKE '%' || $1
            "#,
        )
        .bind(mail_from_domain)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.0 as u64)
    }
}
