//! False Positive Feedback Database Operations

use anyhow::Result;
use chrono::{DateTime, Utc};

use vigilyx_core::security::{FeedbackEntry, FeedbackStat};

use crate::VigilDb;

#[derive(Debug, PartialEq, Eq)]
pub enum LearningFeedbackInsert {
    Inserted,
    StaleVerdict,
    Duplicate,
    RateLimited,
}

#[derive(Debug, sqlx::FromRow)]
struct LearningFeedbackRow {
    id: String,
    session_id: String,
    feedback_type: String,
    corrected_threat_level: Option<String>,
    original_threat_level: String,
    status: String,
    created_at: String,
    learning_status: String,
    learning_reason: Option<String>,
    evidence_snapshot: serde_json::Value,
    snapshot_sha256: Option<String>,
}

impl VigilDb {
    /// Lock the current verdict and the submitting actor before checking the
    /// budget and inserting the immutable label plus snapshot in one transaction.
    /// Separate statements after the actor lock get a fresh READ COMMITTED
    /// snapshot; a CTE lock alone cannot refresh a pre-lock statement snapshot.
    pub async fn insert_learning_feedback(
        &self,
        fb: &FeedbackEntry,
        dedupe_since: DateTime<Utc>,
        max_recent_feedback: u64,
    ) -> Result<LearningFeedbackInsert> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&fb.submitted_by)
            .execute(&mut *tx)
            .await?;
        let current: Option<String> =
            sqlx::query_scalar("SELECT id FROM security_verdicts WHERE session_id = $1 FOR SHARE")
                .bind(fb.session_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if current != fb.verdict_id.map(|id| id.to_string()) || current.is_none() {
            tx.rollback().await?;
            return Ok(LearningFeedbackInsert::StaleVerdict);
        }
        let (count, duplicate): (i64, bool) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(BOOL_OR(session_id = $3), false) \
             FROM security_feedback WHERE submitted_by = $1 AND created_at::timestamptz >= $2::timestamptz",
        ).bind(&fb.submitted_by).bind(dedupe_since.to_rfc3339())
            .bind(fb.session_id.to_string()).fetch_one(&mut *tx).await?;
        if count.max(0) as u64 >= max_recent_feedback {
            tx.rollback().await?;
            return Ok(LearningFeedbackInsert::RateLimited);
        }
        if duplicate {
            tx.rollback().await?;
            return Ok(LearningFeedbackInsert::Duplicate);
        }
        sqlx::query(
            "INSERT INTO security_feedback \
             (id,session_id,verdict_id,submitted_by,feedback_type,module_id,original_threat_level, \
              user_comment,status,created_at,corrected_threat_level,evidence_snapshot,snapshot_sha256,learning_status,learning_reason) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        ).bind(fb.id.to_string()).bind(fb.session_id.to_string())
            .bind(fb.verdict_id.map(|id| id.to_string())).bind(&fb.submitted_by)
            .bind(&fb.feedback_type).bind(&fb.module_id).bind(&fb.original_threat_level)
            .bind(&fb.user_comment).bind(&fb.status).bind(fb.created_at.to_rfc3339())
            .bind(&fb.corrected_threat_level).bind(&fb.evidence_snapshot).bind(&fb.snapshot_sha256)
            .bind(&fb.learning_status).bind(&fb.learning_reason).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(LearningFeedbackInsert::Inserted)
    }

    /// Metadata only: no comments, identities, source text or evidence objects
    /// are returned to the ordinary session-history endpoint.
    pub async fn session_feedback_history(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<serde_json::Value> {
        let rows: Vec<LearningFeedbackRow> = sqlx::query_as(
            "SELECT id,session_id,feedback_type,corrected_threat_level,original_threat_level,status,created_at, \
             learning_status,learning_reason,'{}'::jsonb AS evidence_snapshot,NULL::text AS snapshot_sha256 \
             FROM security_feedback WHERE session_id = $1 ORDER BY created_at DESC,id DESC LIMIT 100",
        ).bind(session_id.to_string()).fetch_all(&self.pool).await?;
        let learning_status = rows.first().map(|row| row.learning_status.as_str());
        let learning_reason = rows.first().and_then(|row| row.learning_reason.as_deref());
        Ok(serde_json::json!({
            "feedbacks": rows.iter().map(|row| serde_json::json!({
                "id":row.id,"feedback_type":row.feedback_type,
                "corrected_threat_level":row.corrected_threat_level,
                "original_threat_level":row.original_threat_level,"status":row.status,"created_at":row.created_at,
            })).collect::<Vec<_>>(), "learning_status":learning_status,"learning_reason":learning_reason,
        }))
    }

    /// Each page contains complete sessions, never a truncated set of reviewers.
    /// Only the latest vote per actor is current; disagreement across actors
    /// excludes that session rather than selecting a convenient label.
    pub async fn ds_learning_samples_page(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<serde_json::Value> {
        let limit = limit.clamp(1, 10_000);
        let rows: Vec<LearningFeedbackRow> = sqlx::query_as(
            "WITH selected_sessions AS ( \
                SELECT session_id,MAX(created_at) AS updated_at FROM security_feedback \
                GROUP BY session_id ORDER BY updated_at DESC,session_id LIMIT $1 OFFSET $2 \
             ), current_votes AS ( \
                SELECT DISTINCT ON (f.session_id,f.submitted_by) f.* \
                FROM security_feedback f JOIN selected_sessions s USING(session_id) \
                ORDER BY f.session_id,f.submitted_by,f.created_at DESC,f.id DESC \
             ) SELECT id,session_id,feedback_type,corrected_threat_level,original_threat_level,status,created_at, \
                learning_status,learning_reason,evidence_snapshot,snapshot_sha256 \
             FROM current_votes ORDER BY session_id,created_at DESC,id DESC",
        ).bind(i64::from(limit)).bind(i64::from(offset))
            .fetch_all(&self.pool).await?;
        let mut dataset = learning_dataset(rows);
        let next_offset = (dataset["session_count"].as_u64() == Some(u64::from(limit)))
            .then(|| u64::from(offset) + u64::from(limit));
        dataset["pagination"] = serde_json::json!({"limit":limit,"offset":offset,
            "next_offset":next_offset,"scope":"recent_feedback_sessions","live_snapshot":true});
        Ok(dataset)
    }

    pub async fn ds_learning_samples(&self, limit: u32) -> Result<serde_json::Value> {
        self.ds_learning_samples_page(limit, 0).await
    }

    /// CAS prevents a slower learner from replacing state published by a newer
    /// feedback batch. None means insert only; it never overwrites an existing key.
    pub async fn compare_and_set_config(
        &self,
        key: &str,
        expected: Option<&str>,
        value: &str,
    ) -> Result<bool> {
        let changed = if let Some(expected) = expected {
            sqlx::query("UPDATE config SET value = $3 WHERE key = $1 AND value = $2")
                .bind(key)
                .bind(expected)
                .bind(value)
                .execute(&self.pool)
                .await?
        } else {
            sqlx::query("INSERT INTO config(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING")
                .bind(key)
                .bind(value)
                .execute(&self.pool)
                .await?
        };
        Ok(changed.rows_affected() == 1)
    }

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
                   COALESCE(SUM(CASE WHEN feedback_type IN ('legitimate', 'false_positive') THEN 1 ELSE 0 END), 0)::BIGINT as fp_count
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
            WHERE f.feedback_type IN ('legitimate', 'false_positive')
            AND s.mail_from LIKE '%' || $1
            "#,
        )
        .bind(mail_from_domain)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.0 as u64)
    }
}

fn learning_dataset(rows: Vec<LearningFeedbackRow>) -> serde_json::Value {
    use std::collections::BTreeMap;
    let mut sessions: BTreeMap<String, Vec<LearningFeedbackRow>> = BTreeMap::new();
    for row in rows {
        sessions
            .entry(row.session_id.clone())
            .or_default()
            .push(row);
    }
    let mut cases = Vec::new();
    let mut excluded: BTreeMap<&str, usize> = BTreeMap::new();
    let session_count = sessions.len();
    for (session_id, votes) in sessions {
        let row = &votes[0];
        if votes.iter().any(|other| {
            other.feedback_type != row.feedback_type
                || other.corrected_threat_level != row.corrected_threat_level
        }) {
            *excluded.entry("conflicting_labels").or_default() += 1;
            continue;
        }
        let snapshot = &row.evidence_snapshot;
        if row.corrected_threat_level.is_none()
            || row.learning_status != "recorded"
            || snapshot["schema_version"] != 1
            || snapshot["items"].as_array().is_none_or(Vec::is_empty)
            || snapshot["content_sha256"]
                .as_str()
                .is_none_or(|hash| hash.len() != 64)
            || snapshot["provenance"]["input_content_sha256"] != snapshot["content_sha256"]
            || snapshot["provenance"]["training_authorized_at_submission"] != true
            || row.snapshot_sha256.is_none()
        {
            *excluded.entry("missing_evidence_or_severity").or_default() += 1;
            continue;
        }
        cases.push(serde_json::json!({
            "case_id":row.id,"session_id":session_id,"label_source":"analyst_feedback",
            "label":if row.feedback_type == "legitimate" {0} else {1},
            "label_name":row.feedback_type,"corrected_threat_level":row.corrected_threat_level,
            "items":snapshot["items"],"content_sha256":snapshot["content_sha256"],
            "group_id":serde_json::Value::Null,"split":"train","data_origin":"analyst_feedback",
            "observed_at":snapshot["observed_at"],"labeled_at":row.created_at,"adjudicated":false,
            "snapshot_sha256":row.snapshot_sha256,"provenance":snapshot["provenance"],
        }));
    }
    serde_json::json!({"schema_version":1,"comparison_scope":"runtime_items","cases":cases,
        "session_count":session_count,"exclusions":excluded,
        "evaluation_protocol":{"holdout_frozen_before_fit":false,
            "permitted_use":"candidate_training_only; no independent performance claim"}})
}

#[cfg(test)]
mod learning_tests {
    use super::*;
    use serde_json::json;

    fn row(session: &str, kind: &str, severity: Option<&str>) -> LearningFeedbackRow {
        LearningFeedbackRow {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session.to_string(),
            feedback_type: kind.to_string(),
            corrected_threat_level: severity.map(str::to_string),
            original_threat_level: "high".to_string(),
            status: "pending".to_string(),
            created_at: "2026-11-13T00:00:00Z".to_string(),
            learning_status: "recorded".to_string(),
            learning_reason: None,
            snapshot_sha256: Some("b".repeat(64)),
            evidence_snapshot: json!({"schema_version":1,"content_sha256":"a".repeat(64),
                "observed_at":"2026-11-12T00:00:00Z","items":[{"source_id":"test:signal"}],
                "provenance":{"model":"clustered_ds_v2","training_authorized_at_submission":true,
                    "input_content_sha256":"a".repeat(64)}}),
        }
    }

    #[test]
    fn legacy_missing_severity_and_conflicting_analysts_never_become_training_labels() {
        let data = learning_dataset(vec![
            row("legacy", "legitimate", None),
            row("conflict", "phishing", Some("high")),
            row("conflict", "phishing", Some("low")),
            row("consistent", "legitimate", Some("safe")),
            row("consistent", "legitimate", Some("safe")),
        ]);
        assert_eq!(data["cases"].as_array().unwrap().len(), 1);
        assert_eq!(data["cases"][0]["label"], 0);
        assert_eq!(data["cases"][0]["corrected_threat_level"], "safe");
        assert!(data["cases"][0]["group_id"].is_null());
        assert_eq!(data["cases"][0]["adjudicated"], false);
        assert_eq!(data["exclusions"]["conflicting_labels"], 1);
        assert_eq!(data["exclusions"]["missing_evidence_or_severity"], 1);
    }

    #[test]
    fn snapshot_absence_is_not_backfilled_from_the_current_verdict() {
        let mut unavailable = row("missing", "phishing", Some("high"));
        unavailable.evidence_snapshot = json!({});
        let data = learning_dataset(vec![unavailable]);
        assert!(data["cases"].as_array().unwrap().is_empty());
        assert_eq!(data["exclusions"]["missing_evidence_or_severity"], 1);
    }

    #[test]
    fn submission_training_authorization_is_not_borrowed_from_a_later_trainer() {
        let mut unapproved = row("not-authorized", "legitimate", Some("safe"));
        unapproved.evidence_snapshot["provenance"]["training_authorized_at_submission"] =
            json!(false);
        assert!(
            learning_dataset(vec![unapproved])["cases"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn input_content_hash_must_match_the_original_verdict_evidence() {
        let mut changed = row("changed", "phishing", Some("high"));
        changed.evidence_snapshot["provenance"]["input_content_sha256"] = json!("c".repeat(64));
        assert!(
            learning_dataset(vec![changed])["cases"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let mut missing = row("missing", "phishing", Some("high"));
        missing.evidence_snapshot["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("input_content_sha256");
        assert!(
            learning_dataset(vec![missing])["cases"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
