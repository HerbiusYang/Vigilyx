#![cfg(feature = "infra-tests")]

//! Run only against an exclusive disposable PostgreSQL database. This exercises
//! the public feedback and learner paths; it neither sends SMTP nor starts an engine.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
use vigilyx_core::security::{
    Bpa, DsLearningEvidence, DsModelParameters, EpistemicState, FusionDetails, FusionModelResult,
    InspectionCoverage, SecurityVerdict, ThreatLevel,
};
use vigilyx_db::VigilDb;
use vigilyx_engine::ds_learning::{LearningState, STATE_KEY, predict, refresh_candidate};
use vigilyx_engine::feedback::{
    FEEDBACK_STALE_VERDICT_ERROR, FeedbackManager, SubmitFeedbackRequest,
};
use vigilyx_engine::ioc::IocManager;

const SOURCE: &str = "header_scan:domain_mismatch";
const LEGACY_MASS: f64 = 0.16;

fn test_database_url() -> Result<String> {
    let raw = std::env::var("VIGILYX_TEST_DATABASE_URL")
        .context("VIGILYX_TEST_DATABASE_URL must name an exclusive disposable database")?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1"),
        "disposable PostgreSQL acknowledgement required"
    );
    let url = url::Url::parse(&raw).context("invalid disposable database URL")?;
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && url
                .path()
                .trim_start_matches('/')
                .starts_with("vigilyx_test"),
        "refusing a database whose name does not start with vigilyx_test"
    );
    Ok(raw)
}

fn fixture(raw: &[u8]) -> (EmailSession, SecurityVerdict) {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.10".into(),
        2525,
        "192.0.2.20".into(),
        25,
    );
    session.mail_from = Some("sender@sender.example".into());
    session.rcpt_to = vec!["recipient@recipient.example".into()];
    session.subject = Some("Synthetic DS feedback test".into());
    session.content = EmailContent {
        body_text: Some("Synthetic evidence fixture; no live links or delivery.".into()),
        raw_mime: Some(raw.to_vec()),
        is_complete: true,
        ..Default::default()
    };
    let bpa = Bpa::new(LEGACY_MASS, 0.0, 1.0 - LEGACY_MASS);
    let primary = FusionModelResult {
        model: "clustered_ds_v2".into(),
        model_version: 2,
        fused_bpa: bpa,
        k_conflict: 0.0,
        risk_base: LEGACY_MASS,
        risk_constrained: 0.8,
        epistemic_state: EpistemicState::ThreatSupported,
        source_details: vec![],
        active_constraints: vec![],
        constraint_conflict: None,
        artifact_count: 1,
        fallback_artifact_count: 0,
        learning_evidence: vec![DsLearningEvidence {
            source_id: SOURCE.into(),
            causal_key: Some("header_from_reply_to:synthetic-domain-pair".into()),
            cluster: "sender_identity_authenticity".into(),
            raw_score: 0.25,
            confidence: 0.8,
            item_scored: true,
            legacy_mass: LEGACY_MASS,
            confirmed_anchor_mass: 0.0,
        }],
        learning_model: None,
        input_content_sha256: Some(hex::encode(Sha256::digest(raw))),
    };
    let verdict = SecurityVerdict {
        inspection_coverage: InspectionCoverage::Complete,
        coverage_reasons: vec![],
        id: Uuid::new_v4(),
        session_id: session.id,
        threat_level: ThreatLevel::High,
        threat_type: None,
        classification: None,
        confidence: 0.8,
        categories: vec!["domain_mismatch".into()],
        summary: "Synthetic original verdict, never a training label".into(),
        pillar_scores: HashMap::new(),
        modules_run: 1,
        modules_flagged: 1,
        total_duration_ms: 0,
        created_at: Utc::now(),
        fusion_details: Some(FusionDetails {
            fused_bpa: bpa,
            k_conflict: 0.0,
            risk_single: 0.8,
            eta: 0.0,
            engine_details: vec![],
            credibility_weights: HashMap::new(),
            novelty: None,
            k_cross: None,
            betp: None,
            fusion_method: Some("clustered_ds_v2".into()),
            circuit_breaker: None,
            convergence_breaker: None,
            shadow_results: vec![],
            primary_result: Some(primary),
            relational_shadow: None,
        }),
    };
    (session, verdict)
}

fn request(verdict: &SecurityVerdict, legitimate: bool) -> SubmitFeedbackRequest {
    SubmitFeedbackRequest {
        feedback_type: if legitimate { "legitimate" } else { "phishing" }.into(),
        corrected_threat_level: Some(if legitimate { "safe" } else { "high" }.into()),
        expected_verdict_id: Some(verdict.id),
        module_id: None,
        comment: Some("Independent synthetic analyst review".into()),
    }
}

async fn read_state(db: &VigilDb) -> Result<LearningState> {
    let raw = db
        .get_config(STATE_KEY)
        .await?
        .context("learner must persist a state")?;
    let state: LearningState = serde_json::from_str(&raw)?;
    state.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        state.active.is_none(),
        "feedback must never activate candidate parameters"
    );
    ensure!(
        state.active_acceptance.is_none(),
        "training must not manufacture acceptance"
    );
    Ok(state)
}

fn candidate(state: &LearningState) -> Result<DsModelParameters> {
    let model = state
        .candidate
        .clone()
        .context("expected fitted candidate")?;
    ensure!(
        model.training_status == "candidate",
        "candidate must remain unvalidated"
    );
    ensure!(
        model.calibration.is_none(),
        "training feedback is not independent calibration"
    );
    Ok(model)
}

fn cases(data: &Value) -> Result<&Vec<Value>> {
    data["cases"].as_array().context("dataset cases missing")
}

#[tokio::test]
async fn analyst_feedback_really_trains_a_candidate_without_overwriting_the_verdict() -> Result<()>
{
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    // Never erase another test's ledger or a pre-existing model to make assertions pass.
    ensure!(
        db.get_config(STATE_KEY).await?.is_none(),
        "use a fresh exclusive disposable database"
    );
    ensure!(
        db.ds_learning_samples(256).await?["session_count"] == 0,
        "integration fixture requires an empty feedback ledger"
    );
    let run = Uuid::new_v4().to_string();
    let actor = format!("ds-learning-{run}");
    let second_actor = format!("ds-learning-conflict-{run}");
    let stale_actor = format!("ds-learning-stale-{run}");
    let raw_benign = format!(
        "From: sender@sender.example\r\nTo: recipient@recipient.example\r\nSubject: benign-{run}\r\n\r\nSynthetic benign feedback."
    );
    let raw_threat = format!(
        "From: sender@sender.example\r\nTo: recipient@recipient.example\r\nSubject: threat-{run}\r\n\r\nSynthetic threat feedback."
    );
    let first = fixture(raw_benign.as_bytes());
    let second = fixture(raw_threat.as_bytes());
    let duplicate = fixture(raw_threat.as_bytes());
    let conflicting_content = fixture(raw_threat.as_bytes());
    let fixtures = [&first, &second, &duplicate, &conflicting_content];
    let manager = FeedbackManager::new(db.clone(), IocManager::new(db.clone()));

    let outcome: Result<()> = async {
        for (session, verdict) in fixtures {
            db.insert_session(session).await?;
            db.insert_verdict(verdict).await?;
        }
        let feedback = manager
            .submit(first.0.id, &request(&first.1, true), &actor, true, false)
            .await?;
        ensure!(
            feedback.learning_status == "recorded" && feedback.learning_reason.is_none(),
            "explicit correction with retained original evidence must be trainable"
        );
        ensure!(
            feedback.ioc_adjusted == 0 && !feedback.whitelist_suggested,
            "learning feedback must not adjust IOC or whitelist"
        );
        let data = db.ds_learning_samples(256).await?;
        let rows = cases(&data)?;
        ensure!(
            rows.len() == 1 && rows[0]["label"] == 0,
            "analyst safe correction, not original High verdict, must supply the label"
        );
        ensure!(
            rows[0]["label_source"] == "analyst_feedback"
                && rows[0]["corrected_threat_level"] == "safe",
            "explicit human label provenance must survive the database round trip"
        );
        ensure!(
            rows[0]["content_sha256"] == hex::encode(Sha256::digest(raw_benign.as_bytes())),
            "snapshot must bind the original retained MIME bytes"
        );
        ensure!(
            rows[0]["provenance"]["input_content_sha256"] == rows[0]["content_sha256"],
            "training snapshot must retain the analysis-time content binding"
        );
        ensure!(
            rows[0]["snapshot_sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64),
            "immutable snapshot hash must be persisted"
        );
        let probe: Vec<DsLearningEvidence> = serde_json::from_value(rows[0]["items"].clone())?;
        ensure!(
            probe.len() == 1 && probe[0].item_scored && probe[0].source_id == SOURCE,
            "item-level producer trace must survive the feedback snapshot"
        );
        ensure!(
            probe[0]
                .causal_key
                .as_ref()
                .is_some_and(|key| key.len() == 64),
            "persisted causal identity should be hashed"
        );

        refresh_candidate(&db).await?;
        let first_state = read_state(&db).await?;
        let first_model = candidate(&first_state)?;
        let first_prediction = predict(&probe, &first_model).map_err(anyhow::Error::msg)?;
        ensure!(
            first_prediction.learned_items == 1 && first_prediction.bpa.b < LEGACY_MASS,
            "safe feedback must actually lower learned support relative to the bootstrap item"
        );
        ensure!(
            first_state.eligible_count == 1 && first_model.training_sample_count == 1,
            "first correction must be represented once"
        );
        let unchanged = db
            .get_verdict_by_session(first.0.id)
            .await?
            .context("original verdict missing")?;
        ensure!(
            unchanged.id == first.1.id && unchanged.threat_level == ThreatLevel::High,
            "feedback must preserve the original verdict"
        );

        refresh_candidate(&db).await?;
        let same_batch = read_state(&db).await?;
        ensure!(
            same_batch.revision == first_state.revision && candidate(&same_batch)? == first_model,
            "refreshing an unchanged ledger must not train the same batch twice"
        );

        manager
            .submit(second.0.id, &request(&second.1, false), &actor, true, false)
            .await?;
        refresh_candidate(&db).await?;
        let balanced_state = read_state(&db).await?;
        let balanced_model = candidate(&balanced_state)?;
        let balanced_prediction = predict(&probe, &balanced_model).map_err(anyhow::Error::msg)?;
        ensure!(
            balanced_model.sources != first_model.sources
                && balanced_prediction.probability > first_prediction.probability,
            "a new independent threat label must change fitted parameters and prediction"
        );
        ensure!(
            balanced_state.eligible_count == 2 && balanced_model.training_sample_count == 2,
            "two distinct contents must supply two training cases"
        );
        ensure!(
            !balanced_state
                .pending_gates
                .iter()
                .any(|gate| gate == "both_classes"),
            "both human label classes are present, but independent validation must remain pending"
        );
        ensure!(
            balanced_state
                .pending_gates
                .iter()
                .any(|gate| gate == "sealed_holdout"),
            "feedback fitting cannot satisfy the sealed holdout gate"
        );

        manager
            .submit(
                duplicate.0.id,
                &request(&duplicate.1, false),
                &actor,
                true,
                false,
            )
            .await?;
        refresh_candidate(&db).await?;
        let deduplicated = read_state(&db).await?;
        ensure!(
            deduplicated.feedback_count == 3 && deduplicated.eligible_count == 2,
            "repeated content is a recorded review, not an independent training example"
        );
        ensure!(
            candidate(&deduplicated)? == balanced_model,
            "duplicate content with the same human label must not train the candidate again"
        );

        manager
            .submit(
                conflicting_content.0.id,
                &request(&conflicting_content.1, true),
                &actor,
                true,
                false,
            )
            .await?;
        refresh_candidate(&db).await?;
        let content_conflict = read_state(&db).await?;
        ensure!(
            content_conflict.eligible_count == 1 && content_conflict.excluded_count == 3,
            "contradictory reviews of identical bytes must exclude the entire content group"
        );
        ensure!(
            candidate(&content_conflict)?.training_sample_count == 1,
            "conflicting duplicate content must not contribute either label"
        );

        manager
            .submit(
                first.0.id,
                &request(&first.1, false),
                &second_actor,
                true,
                false,
            )
            .await?;
        let conflict_data = db.ds_learning_samples(256).await?;
        ensure!(
            cases(&conflict_data)?
                .iter()
                .all(|row| row["session_id"] != first.0.id.to_string()),
            "disagreement across reviewers must exclude that session before fitting"
        );
        refresh_candidate(&db).await?;
        let all_conflicted = read_state(&db).await?;
        ensure!(
            all_conflicted.eligible_count == 0 && all_conflicted.candidate.is_none(),
            "no candidate can be trained when every content group has conflicting labels"
        );

        let mut rescanned = first.1.clone();
        rescanned.id = Uuid::new_v4();
        rescanned.created_at = Utc::now();
        rescanned.threat_level = ThreatLevel::Medium;
        db.insert_verdict(&rescanned).await?;
        let history_before = db.session_feedback_history(first.0.id).await?;
        let rejected = manager
            .submit(
                first.0.id,
                &request(&first.1, true),
                &stale_actor,
                true,
                false,
            )
            .await
            .err()
            .context("an old verdict ID must be rejected")?;
        ensure!(
            rejected.to_string() == FEEDBACK_STALE_VERDICT_ERROR,
            "expected optimistic-lock rejection"
        );
        ensure!(
            db.session_feedback_history(first.0.id).await? == history_before,
            "stale feedback must not create a record"
        );
        let current = db
            .get_verdict_by_session(first.0.id)
            .await?
            .context("current verdict missing")?;
        ensure!(
            current.id == rescanned.id && current.threat_level == ThreatLevel::Medium,
            "rejected stale feedback must not overwrite the newer verdict"
        );
        Ok(())
    }
    .await;

    // Target only this test's generated rows. Cleanup also runs on assertion errors.
    let cleanup: Result<()> = async {
        for actor in [&actor, &second_actor, &stale_actor] {
            db.execute_sql(
                "DELETE FROM security_feedback WHERE submitted_by = $1",
                &[actor],
            )
            .await?;
        }
        for (session, _) in fixtures {
            let session_id = session.id.to_string();
            db.execute_sql(
                "DELETE FROM security_verdicts WHERE session_id = $1",
                &[&session_id],
            )
            .await?;
            db.execute_sql("DELETE FROM sessions WHERE id = $1", &[&session_id])
                .await?;
        }
        db.execute_sql(
            "DELETE FROM config WHERE key = $1",
            &[&STATE_KEY.to_string()],
        )
        .await?;
        Ok(())
    }
    .await;
    outcome?;
    cleanup?;
    Ok(())
}
