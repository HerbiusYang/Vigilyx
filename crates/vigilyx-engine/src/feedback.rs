//! Analyze FeedbackProcess (5Classification)

//! Features:
//! - 5ClassificationFeedback: legitimate / phishing / spoofing / social_engineering / other_threat
//! - write security_feedback table
//! - write training_samples table (store emailContent, By Python 1 Process)
//! - legitimate Feedback: downgradeLow IOC, Check Name
//! - FeedbackStatistics

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use vigilyx_core::security::{FeedbackEntry, TrainingSample, feedback_type_to_label};
use vigilyx_db::VigilDb;

use crate::ioc::IocManager;

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
    ) -> anyhow::Result<FeedbackResult> {
        // Verify feedback_type Valid
        let (label, label_name) = feedback_type_to_label(&req.feedback_type).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid feedback_type: '{}'. Expected: legitimate/phishing/spoofing/social_engineering/other_threat",
                req.feedback_type
            )
        })?;

        // GetWhenfirst verdict
        let verdict = self.db.get_verdict_by_session(session_id).await?;

        let fb = FeedbackEntry {
            id: Uuid::new_v4(),
            session_id,
            verdict_id: verdict.as_ref().map(|v| v.id),
            feedback_type: req.feedback_type.clone(),
            module_id: req.module_id.clone(),
            original_threat_level: verdict
                .as_ref()
                .map(|v| v.threat_level.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            user_comment: req.comment.clone(),
            status: "pending".to_string(),
            created_at: Utc::now(),
        };

        // 1. write table
        self.db.insert_feedback(&fb).await?;
        info!(
            feedback_id = %fb.id,
            session_id = %session_id,
            feedback_type = %req.feedback_type,
            label = label,
            "Feedback submitted"
        );

        let mut ioc_adjusted = 0u32;
        let mut whitelist_suggested = false;

        // 2. legitimate Feedback: downgradeLow IOC + Name
        if req.feedback_type == "legitimate" {
            ioc_adjusted = self.process_false_positive(session_id).await;
            whitelist_suggested = self.check_whitelist_suggestion(session_id).await;
        }

        // 3. write table (Deduplicate: Same1 session)
        let training_sample_saved = self
            .save_training_sample(session_id, label, label_name, &fb, req.comment.as_deref())
            .await;

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
            subject: session.subject.clone(),
            body_text: session.content.body_text.clone(),
            body_html: session.content.body_html.clone(),
            mail_from: session.mail_from.clone(),
            rcpt_to: session.rcpt_to.clone(),
            analyst_comment: comment.map(|c| c.to_string()),
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
