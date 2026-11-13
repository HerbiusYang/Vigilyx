//! Immutable analyst feedback for candidate DS learning.
//!
//! Classification and corrected severity are separate labels. Feedback never
//! changes the original verdict, IOC confidence, whitelist or active model.

use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{FeedbackEntry, SecurityVerdict, feedback_type_to_label};
use vigilyx_db::VigilDb;
use vigilyx_db::security::LearningFeedbackInsert;

use crate::ioc::IocManager;

const MAX_FEEDBACK_COMMENT_CHARS: usize = 2_000;
const MAX_FEEDBACK_MODULE_ID_CHARS: usize = 128;
const MAX_FEEDBACK_PER_WINDOW: u64 = 30;
const FEEDBACK_WINDOW_MINUTES: i64 = 10;
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024;

pub const FEEDBACK_RATE_LIMIT_ERROR: &str = "Feedback submission rate limit exceeded";
pub const FEEDBACK_DUPLICATE_ERROR: &str = "Feedback already submitted for this session";
pub const FEEDBACK_STALE_VERDICT_ERROR: &str =
    "Verdict changed; refresh and review before submitting feedback";

#[derive(Clone)]
pub struct FeedbackManager {
    db: VigilDb,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubmitFeedbackRequest {
    pub feedback_type: String,
    pub module_id: Option<String>,
    pub comment: Option<String>,
    #[serde(default)]
    pub corrected_threat_level: Option<String>,
    #[serde(default)]
    pub expected_verdict_id: Option<Uuid>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedbackResult {
    pub feedback_id: Uuid,
    // Legacy clients still receive explicit zero/false side-effect fields.
    pub ioc_adjusted: u32,
    pub whitelist_suggested: bool,
    pub training_sample_saved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_samples: Option<u64>,
    pub learning_status: String,
    pub learning_reason: Option<String>,
}

impl FeedbackManager {
    pub fn new(db: VigilDb, _ioc: IocManager) -> Self {
        Self { db }
    }

    pub async fn submit(
        &self,
        session_id: Uuid,
        req: &SubmitFeedbackRequest,
        submitted_by: &str,
        save_training_sample: bool,
        _can_adjust_ioc: bool,
    ) -> anyhow::Result<FeedbackResult> {
        validate_feedback_request(req)?;
        if submitted_by.trim().is_empty() {
            anyhow::bail!("Feedback submitter identity is missing");
        }
        let verdict = self
            .db
            .get_verdict_by_session(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session verdict not found"))?;
        if req.expected_verdict_id.is_some_and(|id| id != verdict.id) {
            anyhow::bail!(FEEDBACK_STALE_VERDICT_ERROR);
        }
        let session = self.db.get_session(session_id).await?;
        let now = Utc::now();
        let (snapshot, reason) =
            feedback_snapshot(&verdict, session.as_ref(), req, save_training_sample)?;
        let learning_status = if reason.is_none() {
            "recorded"
        } else {
            "insufficient_evidence"
        }
        .to_string();
        let snapshot_sha256 = digest(&serde_json::to_vec(&snapshot)?);
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
            corrected_threat_level: req.corrected_threat_level.clone(),
            evidence_snapshot: snapshot,
            snapshot_sha256: Some(snapshot_sha256),
            learning_status: learning_status.clone(),
            learning_reason: reason.clone(),
        };
        match self
            .db
            .insert_learning_feedback(
                &fb,
                now - Duration::minutes(FEEDBACK_WINDOW_MINUTES),
                MAX_FEEDBACK_PER_WINDOW,
            )
            .await?
        {
            LearningFeedbackInsert::Inserted => {}
            LearningFeedbackInsert::StaleVerdict => anyhow::bail!(FEEDBACK_STALE_VERDICT_ERROR),
            LearningFeedbackInsert::Duplicate => anyhow::bail!(FEEDBACK_DUPLICATE_ERROR),
            LearningFeedbackInsert::RateLimited => anyhow::bail!(FEEDBACK_RATE_LIMIT_ERROR),
        }
        // The immutable ledger is the learning hand-off. No raw-content
        // training copy or IOC/whitelist action is coupled to feedback.
        Ok(FeedbackResult {
            feedback_id: fb.id,
            ioc_adjusted: 0,
            whitelist_suggested: false,
            training_sample_saved: false,
            total_samples: None,
            learning_status,
            learning_reason: reason,
        })
    }

    pub async fn get_stats(&self) -> anyhow::Result<Vec<vigilyx_core::security::FeedbackStat>> {
        self.db.get_feedback_stats().await
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Allowlist the typed trace. Causal identities are hashed before persistence,
/// and no evidence snippets, summaries, message content or addresses enter it.
fn private_learning_items(primary: &Value) -> Vec<Value> {
    primary["learning_evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| {
            let causal_key = item["causal_key"]
                .as_str()
                .map(|key| digest(key.as_bytes()));
            json!({
                "source_id":item["source_id"],"causal_key":causal_key,"cluster":item["cluster"],
                "raw_score":item["raw_score"],"confidence":item["confidence"],
                "item_scored":item["item_scored"],"legacy_mass":item["legacy_mass"],
                "confirmed_anchor_mass":item["confirmed_anchor_mass"],
            })
        })
        .collect()
}

fn valid_learning_items(items: &[Value]) -> bool {
    !items.is_empty()
        && items.len() <= 512
        && items.iter().all(|item| {
            item["source_id"].as_str().is_some_and(|s| {
                s.len() <= 256
                    && s.split_once(':').is_some_and(|(module, category)| {
                        !module.is_empty() && !category.is_empty()
                    })
            }) && item["cluster"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
                && (item["causal_key"].is_null()
                    || item["causal_key"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 8192))
                && item["item_scored"].is_boolean()
                && [
                    "raw_score",
                    "confidence",
                    "legacy_mass",
                    "confirmed_anchor_mass",
                ]
                .iter()
                .all(|key| {
                    item[*key]
                        .as_f64()
                        .is_some_and(|v| v.is_finite() && (0.0..=1.0).contains(&v))
                })
                && item["confirmed_anchor_mass"].as_f64() <= item["legacy_mass"].as_f64()
        })
}

fn learning_evidence_reason(
    primary: &Value,
    content_sha256: Option<&str>,
    req: &SubmitFeedbackRequest,
    training_authorized: bool,
) -> Option<&'static str> {
    if !training_authorized {
        Some("training_permission_missing")
    } else if req.module_id.is_some() {
        // A module-level correction does not label the whole email harmless.
        Some("module_scoped_feedback")
    } else if req.corrected_threat_level.is_none() {
        Some("corrected_severity_missing")
    } else if req.expected_verdict_id.is_none() {
        Some("reviewed_verdict_missing")
    } else if primary["model"] != "clustered_ds_v2"
        || !primary["learning_evidence"]
            .as_array()
            .is_some_and(|items| valid_learning_items(items))
        || primary["input_content_sha256"].as_str().is_none()
    {
        Some("immutable_learning_evidence_missing")
    } else if !primary["learning_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["item_scored"] == true
                && item["raw_score"].as_f64().is_some_and(|v| v > 0.0)
                && item["confidence"].as_f64().is_some_and(|v| v > 0.0)
        })
    {
        Some("item_level_learning_evidence_missing")
    } else if content_sha256.is_none() {
        Some("retained_raw_mime_missing")
    } else if primary["input_content_sha256"].as_str() != content_sha256 {
        Some("verdict_content_changed")
    } else {
        None
    }
}

fn feedback_snapshot(
    verdict: &SecurityVerdict,
    session: Option<&EmailSession>,
    req: &SubmitFeedbackRequest,
    training_authorized: bool,
) -> anyhow::Result<(Value, Option<String>)> {
    let primary = verdict
        .fusion_details
        .as_ref()
        .and_then(|f| f.primary_result.as_ref())
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
    let items = private_learning_items(&primary);
    let content_sha256 = session
        .and_then(|s| s.content.raw_mime.as_deref())
        .filter(|raw| !raw.is_empty())
        .map(digest);
    let policy = primary
        .get("active_constraints")
        .cloned()
        .unwrap_or(json!([]));
    let reason = learning_evidence_reason(
        &primary,
        content_sha256.as_deref(),
        req,
        training_authorized,
    );
    let constraints: Vec<Value> = policy
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| json!({"id":c["id"],"lower":c["lower"],"upper":c["upper"]}))
        .collect();
    let provenance = json!({
        "model":primary["model"],"model_version":primary["model_version"],
        "learning_model":primary["learning_model"],
        "policy_sha256":digest(&serde_json::to_vec(&policy)?),
        "policy_constraints":constraints,
        "raw_mime_hash_source":"server_retained_raw_mime_at_feedback",
        "input_content_sha256":primary["input_content_sha256"],
        "causal_key_encoding":"sha256",
        "training_authorized_at_submission":training_authorized,
    });
    let mut snapshot = json!({
        "schema_version":1,"verdict_id":verdict.id,
        "observed_at":verdict.created_at,"captured_at":Utc::now(),
        "original_threat_level":verdict.threat_level,
        "original_classification":verdict.classification,
        "original_risk":primary["risk_constrained"],"original_bel":primary["risk_base"],
        "inspection_coverage":verdict.inspection_coverage,
        "items":items,"content_sha256":content_sha256,"provenance":provenance,
        "adjudicated":false,
    });
    if serde_json::to_vec(&snapshot)?.len() > MAX_SNAPSHOT_BYTES {
        // Preserve explicit absence instead of truncating a trace into a
        // different training example.
        snapshot["items"] = json!([]);
        return Ok((
            snapshot,
            Some("learning_evidence_exceeds_snapshot_limit".to_string()),
        ));
    }
    Ok((snapshot, reason.map(str::to_string)))
}

fn validate_feedback_request(req: &SubmitFeedbackRequest) -> anyhow::Result<()> {
    if feedback_type_to_label(&req.feedback_type).is_none() {
        anyhow::bail!("Invalid feedback_type: '{}'", req.feedback_type);
    }
    if let Some(level) = req.corrected_threat_level.as_deref() {
        let valid = if req.feedback_type == "legitimate" {
            level == "safe"
        } else {
            matches!(level, "low" | "medium" | "high" | "critical")
        };
        if !valid {
            anyhow::bail!("Invalid corrected_threat_level for feedback classification");
        }
        if req.expected_verdict_id.is_none() {
            anyhow::bail!(
                "Invalid feedback: expected_verdict_id is required with corrected_threat_level"
            );
        }
    }
    if req
        .module_id
        .as_deref()
        .is_some_and(|s| s.chars().count() > MAX_FEEDBACK_MODULE_ID_CHARS)
    {
        anyhow::bail!("Feedback module_id exceeds {MAX_FEEDBACK_MODULE_ID_CHARS} characters");
    }
    if req
        .comment
        .as_deref()
        .is_some_and(|s| s.chars().count() > MAX_FEEDBACK_COMMENT_CHARS)
    {
        anyhow::bail!("Feedback comment exceeds {MAX_FEEDBACK_COMMENT_CHARS} characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: &str, severity: Option<&str>) -> SubmitFeedbackRequest {
        SubmitFeedbackRequest {
            feedback_type: kind.to_string(),
            module_id: None,
            comment: None,
            corrected_threat_level: severity.map(str::to_string),
            expected_verdict_id: Some(Uuid::new_v4()),
        }
    }

    #[test]
    fn classification_does_not_imply_severity_and_legacy_stays_unlabelled() {
        let mut legacy = request("phishing", None);
        legacy.expected_verdict_id = None;
        assert!(validate_feedback_request(&legacy).is_ok());
        assert!(legacy.corrected_threat_level.is_none());
        for level in ["low", "medium", "high", "critical"] {
            assert!(validate_feedback_request(&request("phishing", Some(level))).is_ok());
            assert!(validate_feedback_request(&request("legitimate", Some(level))).is_err());
        }
        assert!(validate_feedback_request(&request("legitimate", Some("safe"))).is_ok());
        assert!(validate_feedback_request(&request("phishing", Some("safe"))).is_err());
        let mut unbound = request("phishing", Some("medium"));
        unbound.expected_verdict_id = None;
        assert!(validate_feedback_request(&unbound).is_err());
    }

    #[test]
    fn snapshot_trace_hashes_identities_and_omits_untrusted_extra_fields() {
        let primary = json!({"learning_evidence":[{
            "source_id":"content_scan:bec_payment_change","causal_key":"host:private.example",
            "cluster":"business_sensitivity","raw_score":0.8,"confidence":0.7,
            "item_scored":true,"legacy_mass":0.4,"confirmed_anchor_mass":0.0,
            "snippet":"must not persist","body":"must not persist",
        }]});
        let items = private_learning_items(&primary);
        assert!(valid_learning_items(&items));
        let encoded = serde_json::to_string(&items).unwrap();
        assert!(!encoded.contains("private.example"));
        assert!(!encoded.contains("must not persist"));
        assert_eq!(items[0]["causal_key"], digest(b"host:private.example"));
        assert!(!valid_learning_items(&[]));
    }

    fn learning_primary() -> Value {
        json!({"model":"clustered_ds_v2","input_content_sha256":digest(b"original fixture"),
        "learning_evidence":[{
            "source_id":"content_scan:bec_payment_change","causal_key":"fixture:key",
            "cluster":"business_sensitivity","raw_score":0.8,"confidence":0.7,
            "item_scored":true,"legacy_mass":0.4,"confirmed_anchor_mass":0.0,
        }]})
    }

    #[test]
    fn learning_snapshot_requires_original_verdict_content_binding() {
        let mut primary = learning_primary();
        let req = request("phishing", Some("high"));
        let original = digest(b"original fixture");
        assert_eq!(
            learning_evidence_reason(&primary, Some(&original), &req, true),
            None
        );
        assert_eq!(
            learning_evidence_reason(&primary, Some(&digest(b"changed fixture")), &req, true),
            Some("verdict_content_changed")
        );
        assert_eq!(
            learning_evidence_reason(&primary, None, &req, true),
            Some("retained_raw_mime_missing")
        );
        primary
            .as_object_mut()
            .unwrap()
            .remove("input_content_sha256");
        assert_eq!(
            learning_evidence_reason(&primary, Some(&original), &req, true),
            Some("immutable_learning_evidence_missing")
        );
    }

    #[test]
    fn learning_snapshot_requires_an_admitted_item_level_signal() {
        let req = request("phishing", Some("high"));
        let original = digest(b"original fixture");
        for (key, value) in [
            ("item_scored", json!(false)),
            ("raw_score", json!(0)),
            ("confidence", json!(0)),
        ] {
            let mut primary = learning_primary();
            primary["learning_evidence"][0][key] = value;
            assert_eq!(
                learning_evidence_reason(&primary, Some(&original), &req, true),
                Some("item_level_learning_evidence_missing")
            );
        }
    }

    #[test]
    fn module_feedback_cannot_become_a_whole_email_training_label() {
        let mut req = request("legitimate", Some("safe"));
        req.module_id = Some("header_scan".into());
        assert_eq!(
            learning_evidence_reason(
                &learning_primary(),
                Some(&digest(b"original fixture")),
                &req,
                true
            ),
            Some("module_scoped_feedback")
        );
    }

    #[test]
    fn learning_item_bounds_match_runtime_contract_before_hashing() {
        let item = learning_primary()["learning_evidence"][0].clone();
        assert!(valid_learning_items(&vec![item.clone(); 512]));
        assert!(!valid_learning_items(&vec![item.clone(); 513]));
        for (key, value) in [
            ("source_id", json!("missing_category")),
            ("source_id", json!(":empty_module")),
            ("source_id", json!("empty_category:")),
            ("cluster", json!("c".repeat(257))),
            ("causal_key", json!("")),
            ("causal_key", json!("x".repeat(8193))),
            ("confirmed_anchor_mass", json!(0.5)),
        ] {
            let mut invalid = item.clone();
            invalid[key] = value;
            assert!(
                !valid_learning_items(&[invalid]),
                "unexpected valid field: {key}"
            );
        }
        let mut boundary = item;
        boundary["cluster"] = json!("c".repeat(256));
        boundary["causal_key"] = Value::Null;
        assert!(valid_learning_items(&[boundary]));
    }
}
