//! Analyze FeedbackProcess (5Classification)

//! Features:
//! - 5ClassificationFeedback: legitimate / phishing / spoofing / social_engineering / other_threat
//! - write security_feedback table
//! - write training_samples table (store emailContent, By Python 1 Process)
//! - legitimate Feedback: downgradeLow IOC, Check Name
//! - FeedbackStatistics

use chrono::{Duration, Utc};
use tracing::{info, warn};
use uuid::Uuid;

use vigilyx_core::security::{FeedbackEntry, TrainingSample, feedback_type_to_label};
use vigilyx_db::VigilDb;

use crate::ioc::IocManager;

const MAX_TRAINING_SUBJECT_CHARS: usize = 500;
const MAX_TRAINING_BODY_CHARS: usize = 20_000;
const MAX_TRAINING_COMMENT_CHARS: usize = 2_000;
const MAX_TRAINING_ADDRESS_CHARS: usize = 320;
const MAX_TRAINING_RECIPIENTS: usize = 100;
const MAX_FEEDBACK_COMMENT_CHARS: usize = 2_000;
const MAX_FEEDBACK_MODULE_ID_CHARS: usize = 128;
const MAX_FEEDBACK_PER_WINDOW: u64 = 30;
const FEEDBACK_WINDOW_MINUTES: i64 = 10;

pub const FEEDBACK_RATE_LIMIT_ERROR: &str = "Feedback submission rate limit exceeded";
pub const FEEDBACK_DUPLICATE_ERROR: &str = "Feedback already submitted for this session";

/// FeedbackManagementhandler
#[derive(Clone)]
pub struct FeedbackManager {
    db: VigilDb,
    #[allow(dead_code)]
    ioc: IocManager,
}

/// FeedbackRequest
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubmitFeedbackRequest {
    /// 5Classification: "legitimate" | "phishing" | "spoofing" | "social_engineering" | "other_threat"
    pub feedback_type: String,
    /// ModuleofFeedback ()
    pub module_id: Option<String>,
    /// Analyze
    pub comment: Option<String>,
}

/// FeedbackProcessResult
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedbackResult {
    pub feedback_id: Uuid,
    pub ioc_adjusted: u32,
    pub whitelist_suggested: bool,
    pub training_sample_saved: bool,
    pub total_samples: u64,
}

impl FeedbackManager {
    pub fn new(db: VigilDb, ioc: IocManager) -> Self {
        Self { db, ioc }
    }

    /// 5ClassificationFeedback
    pub async fn submit(
        &self,
        session_id: Uuid,
        req: &SubmitFeedbackRequest,
        submitted_by: &str,
        save_training_sample: bool,
        can_adjust_ioc: bool,
    ) -> anyhow::Result<FeedbackResult> {
        // Verify feedback_type Valid
        let (label, label_name) = feedback_type_to_label(&req.feedback_type).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid feedback_type: '{}'. Expected: legitimate/phishing/spoofing/social_engineering/other_threat",
                req.feedback_type
            )
        })?;
        validate_feedback_request(req)?;
        if submitted_by.trim().is_empty() {
            anyhow::bail!("Feedback submitter identity is missing");
        }

        let now = Utc::now();
        let window_start = now - Duration::minutes(FEEDBACK_WINDOW_MINUTES);
        let recent_feedback = self
            .db
            .count_recent_feedback(submitted_by, window_start)
            .await?;
        if recent_feedback >= MAX_FEEDBACK_PER_WINDOW {
            anyhow::bail!(FEEDBACK_RATE_LIMIT_ERROR);
        }

        // Feedback must refer to an analyzed session. This also prevents an
        // authenticated caller from filling the table with arbitrary UUIDs.
        let verdict = self
            .db
            .get_verdict_by_session(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session verdict not found"))?;

        let fb = FeedbackEntry {
            id: Uuid::new_v4(),
            session_id,
            verdict_id: Some(verdict.id),
            submitted_by: submitted_by.to_string(),
            feedback_type: req.feedback_type.clone(),
            module_id: req.module_id.clone(),
            original_threat_level: verdict.threat_level.to_string(),
            user_comment: req.comment.clone(),
            status: "pending".to_string(),
            created_at: now,
        };

        // 1. write table. The database performs the same-actor/session dedupe in
        // the INSERT predicate, closing the concurrent-request race.
        if !self
            .db
            .insert_feedback(&fb, window_start, MAX_FEEDBACK_PER_WINDOW)
            .await?
        {
            // The database applies the same limit while holding the actor
            // lock. Re-check only to return a useful status when a concurrent
            // request consumed the final slot; the safety gate is the SQL
            // predicate above, not this diagnostic query.
            let current_count = self
                .db
                .count_recent_feedback(submitted_by, window_start)
                .await?;
            if current_count >= MAX_FEEDBACK_PER_WINDOW {
                anyhow::bail!(FEEDBACK_RATE_LIMIT_ERROR);
            }
            anyhow::bail!(FEEDBACK_DUPLICATE_ERROR);
        }
        info!(
            feedback_id = %fb.id,
            session_id = %session_id,
            submitted_by = %submitted_by,
            feedback_type = %req.feedback_type,
            label = label,
            "Feedback submitted"
        );

        let mut ioc_adjusted = 0u32;
        let mut whitelist_suggested = false;

        // 2. Only the IOC-management permission may turn analyst feedback
        // into a global IOC confidence change. Other permitted analysts leave
        // the record pending for review and cannot poison detection state.
        if req.feedback_type == "legitimate" && can_adjust_ioc {
            ioc_adjusted = self.process_false_positive(session_id).await;
            whitelist_suggested = self.check_whitelist_suggestion(session_id).await;
        }

        // 3. write table (Deduplicate: Same1 session)
        let training_sample_saved = if save_training_sample {
            self.save_training_sample(session_id, label, label_name, &fb, req.comment.as_deref())
                .await
        } else {
            false
        };

        let total_samples = self.db.count_training_samples().await.unwrap_or(0);

        Ok(FeedbackResult {
            feedback_id: fb.id,
            ioc_adjusted,
            whitelist_suggested,
            training_sample_saved,
            total_samples,
        })
    }

    /// store data (emailContent, By Python 1 Process)
    async fn save_training_sample(
        &self,
        session_id: Uuid,
        label: i32,
        label_name: &str,
        feedback: &FeedbackEntry,
        comment: Option<&str>,
    ) -> bool {
        // DeduplicateCheck
        match self
            .db
            .training_sample_exists(&session_id.to_string())
            .await
        {
            Ok(true) => {
                info!(session_id = %session_id, "Training sample already exists, skipping");
                return false;
            }
            Err(e) => {
                warn!(error = %e, "Failed to check training sample existence");
                return false;
            }
            Ok(false) => {}
        }

        // Load session emailContent
        let session = match self.db.get_session(session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                warn!(session_id = %session_id, "Session not found, cannot save training sample");
                return false;
            }
            Err(e) => {
                warn!(error = %e, "Failed to load session for training sample");
                return false;
            }
        };

        let sample = TrainingSample {
            id: Uuid::new_v4(),
            session_id,
            label,
            label_name: label_name.to_string(),
            subject: limit_optional_text(session.subject.as_deref(), MAX_TRAINING_SUBJECT_CHARS),
            body_text: limit_optional_text(
                session.content.body_text.as_deref(),
                MAX_TRAINING_BODY_CHARS,
            ),
            body_html: limit_optional_text(
                session.content.body_html.as_deref(),
                MAX_TRAINING_BODY_CHARS,
            ),
            mail_from: limit_optional_text(
                session.mail_from.as_deref(),
                MAX_TRAINING_ADDRESS_CHARS,
            ),
            rcpt_to: limit_recipients(&session.rcpt_to),
            analyst_comment: limit_optional_text(comment, MAX_TRAINING_COMMENT_CHARS),
            original_threat_level: feedback.original_threat_level.clone(),
            verdict_id: feedback.verdict_id,
            created_at: Utc::now(),
        };

        match self.db.insert_training_sample(&sample).await {
            Ok(()) => {
                info!(
                    session_id = %session_id,
                    label = label,
                    label_name = label_name,
                    "Training sample saved to database"
                );
                true
            }
            Err(e) => {
                warn!(error = %e, "Failed to save training sample");
                false
            }
        }
    }

    /// Process: downgradeLow IOC
    async fn process_false_positive(&self, session_id: Uuid) -> u32 {
        let results = match self.db.get_module_results_by_session(session_id).await {
            Ok(r) => r,
            Err(_) => return 0,
        };

        let mut adjusted = 0u32;
        let reduction = 0.2;

        for result in &results {
            if result.threat_level > crate::module::ThreatLevel::Safe {
                for ev in &result.evidence {
                    if let Some(ref snippet) = ev.snippet {
                        for ioc_type in &["ip", "domain", "url", "email", "hash"] {
                            if let Err(e) = self
                                .db
                                .reduce_ioc_confidence(ioc_type, snippet, reduction)
                                .await
                            {
                                warn!("Failed to reduce IOC confidence: {}", e);
                            } else {
                                adjusted += 1;
                            }
                        }
                    }
                }
            }
        }

        if adjusted > 0 {
            info!(session_id = %session_id, adjusted, "Reduced IOC confidence for false positive");
        }

        adjusted
    }

    /// Checkwhether add Name (SameDomain>= 3 Time/Count)
    async fn check_whitelist_suggestion(&self, _session_id: Uuid) -> bool {
        false
    }

    /// GetFeedbackStatistics
    pub async fn get_stats(&self) -> anyhow::Result<Vec<vigilyx_core::security::FeedbackStat>> {
        self.db.get_feedback_stats().await
    }
}

fn validate_feedback_request(req: &SubmitFeedbackRequest) -> anyhow::Result<()> {
    if req
        .module_id
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_FEEDBACK_MODULE_ID_CHARS)
    {
        anyhow::bail!(
            "Feedback module_id exceeds {MAX_FEEDBACK_MODULE_ID_CHARS} characters"
        );
    }
    if req
        .comment
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_FEEDBACK_COMMENT_CHARS)
    {
        anyhow::bail!(
            "Feedback comment exceeds {MAX_FEEDBACK_COMMENT_CHARS} characters"
        );
    }
    Ok(())
}

fn limit_optional_text(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|text| limit_text(text, max_chars))
}

fn limit_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

fn limit_recipients(recipients: &[String]) -> Vec<String> {
    recipients
        .iter()
        .take(MAX_TRAINING_RECIPIENTS)
        .map(|recipient| limit_text(recipient, MAX_TRAINING_ADDRESS_CHARS))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_text_preserves_utf8_boundaries() {
        let limited = limit_text("测测测abc", 4);

        assert_eq!(limited, "测测测a");
    }

    #[test]
    fn limit_recipients_caps_count_and_address_length() {
        let recipients: Vec<String> = (0..150)
            .map(|idx| format!("{}@example.com", "x".repeat(400 + idx)))
            .collect();

        let limited = limit_recipients(&recipients);

        assert_eq!(limited.len(), MAX_TRAINING_RECIPIENTS);
        assert!(
            limited
                .iter()
                .all(|item| item.chars().count() <= MAX_TRAINING_ADDRESS_CHARS)
        );
    }

    #[test]
    fn feedback_request_rejects_oversized_user_controlled_fields() {
        let oversized_comment = SubmitFeedbackRequest {
            feedback_type: "legitimate".to_string(),
            module_id: None,
            comment: Some("x".repeat(MAX_FEEDBACK_COMMENT_CHARS + 1)),
        };
        assert!(validate_feedback_request(&oversized_comment).is_err());

        let oversized_module = SubmitFeedbackRequest {
            feedback_type: "legitimate".to_string(),
            module_id: Some("x".repeat(MAX_FEEDBACK_MODULE_ID_CHARS + 1)),
            comment: None,
        };
        assert!(validate_feedback_request(&oversized_module).is_err());
    }
}
