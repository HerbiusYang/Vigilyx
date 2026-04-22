//! False Positive Feedback Database Operations

use anyhow::Result;

use vigilyx_core::security::{FeedbackEntry, FeedbackStat};

use crate::VigilDb;

impl VigilDb {
    /// Submit false positive feedback
    pub async fn insert_feedback(&self, fb: &FeedbackEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_feedback
                (id, session_id, verdict_id, feedback_type, module_id,
                 original_threat_level, user_comment, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(fb.id.to_string())
        .bind(fb.session_id.to_string())
        .bind(fb.verdict_id.as_ref().map(|v| v.to_string()))
        .bind(&fb.feedback_type)
        .bind(&fb.module_id)
        .bind(&fb.original_threat_level)
        .bind(&fb.user_comment)
        .bind(&fb.status)
        .bind(fb.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
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
