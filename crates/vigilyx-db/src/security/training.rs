//! Training Sample Database Operations (NLP fine-tuning)

use std::collections::HashMap;

use anyhow::Result;
use uuid::Uuid;

use vigilyx_core::security::TrainingSample;

use crate::VigilDb;

/// Database row type (clippy::type_complexity)
type TrainingSampleRow = (
    String,         // id
    String,         // session_id
    i32,            // label
    String,         // label_name
    Option<String>, // subject
    Option<String>, // body_text
    Option<String>, // body_html
    Option<String>, // mail_from
    Option<String>, // rcpt_to (JSON)
    Option<String>, // analyst_comment
    Option<String>, // original_threat_level
    Option<String>, // verdict_id
    String,         // created_at
);

impl VigilDb {
    /// Insert a training sample
    pub async fn insert_training_sample(&self, sample: &TrainingSample) -> Result<()> {
        let rcpt_to_json = serde_json::to_string(&sample.rcpt_to)?;
        sqlx::query(
            r#"
            INSERT INTO training_samples
                (id, session_id, label, label_name, subject, body_text, body_html,
                 mail_from, rcpt_to, analyst_comment, original_threat_level,
                 verdict_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(sample.id.to_string())
        .bind(sample.session_id.to_string())
        .bind(sample.label)
        .bind(&sample.label_name)
        .bind(&sample.subject)
        .bind(&sample.body_text)
        .bind(&sample.body_html)
        .bind(&sample.mail_from)
        .bind(&rcpt_to_json)
        .bind(&sample.analyst_comment)
        .bind(&sample.original_threat_level)
        .bind(sample.verdict_id.as_ref().map(|v| v.to_string()))
        .bind(sample.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query training samples (pagination, by creation time descending)
    pub async fn list_training_samples(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<TrainingSample>> {
        let rows: Vec<TrainingSampleRow> = sqlx::query_as(
            r#"
            SELECT id, session_id, label, label_name, subject, body_text, body_html,
                   mail_from, rcpt_to, analyst_comment, original_threat_level,
                   verdict_id, created_at
            FROM training_samples
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_training_sample).collect()
    }

    /// Get all training samples (batch read during training)
    pub async fn get_all_training_samples(&self) -> Result<Vec<TrainingSample>> {
        let rows: Vec<TrainingSampleRow> = sqlx::query_as(
            r#"
            SELECT id, session_id, label, label_name, subject, body_text, body_html,
                   mail_from, rcpt_to, analyst_comment, original_threat_level,
                   verdict_id, created_at
            FROM training_samples
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_training_sample).collect()
    }

    /// Delete training sample
    pub async fn delete_training_sample(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM training_samples WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Statistics: count samples by classification
    pub async fn get_training_sample_counts(&self) -> Result<HashMap<String, u64>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT label_name, COUNT(*) as cnt
            FROM training_samples
            GROUP BY label_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut counts = HashMap::new();
        for (label_name, cnt) in rows {
            counts.insert(label_name, cnt as u64);
        }
        Ok(counts)
    }

    /// Total sample count
    pub async fn count_training_samples(&self) -> Result<u64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM training_samples")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as u64)
    }

    /// Modify training sample label (only label + label_name can be modified)
    pub async fn update_training_sample_label(
        &self,
        id: &str,
        label: i32,
        label_name: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE training_samples SET label = $1, label_name = $2 WHERE id = $3")
                .bind(label)
                .bind(label_name)
                .bind(id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Check if training sample exists by session_id (deduplication)
    pub async fn training_sample_exists(&self, session_id: &str) -> Result<bool> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM training_samples WHERE session_id = $1")
                .bind(session_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }
}

/// Convert database row to TrainingSample
fn row_to_training_sample(row: TrainingSampleRow) -> Result<TrainingSample> {
    let (
        id,
        session_id,
        label,
        label_name,
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to_json,
        analyst_comment,
        original_threat_level,
        verdict_id,
        created_at,
    ) = row;

    let rcpt_to: Vec<String> = rcpt_to_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let verdict_id = verdict_id.and_then(|v| Uuid::parse_str(&v).ok());

    Ok(TrainingSample {
        id: Uuid::parse_str(&id)?,
        session_id: Uuid::parse_str(&session_id)?,
        label,
        label_name,
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to,
        analyst_comment,
        original_threat_level: original_threat_level.unwrap_or_default(),
        verdict_id,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&chrono::Utc),
    })
}
