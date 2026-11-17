#![cfg(feature = "infra-tests")]

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
use vigilyx_core::security::{FeedbackEntry, SecurityVerdict, ThreatLevel};
use vigilyx_db::{VigilDb, security::LearningFeedbackInsert};

fn test_database_url() -> Result<String> {
    let url = std::env::var("VIGILYX_TEST_DATABASE_URL")
        .context("VIGILYX_TEST_DATABASE_URL must name a disposable database")?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1"),
        "disposable PostgreSQL acknowledgement required"
    );
    ensure!(
        url.to_ascii_lowercase().contains("vigilyx_test"),
        "refusing a database without vigilyx_test in its name"
    );
    Ok(url)
}

fn verdict(session_id: Uuid) -> SecurityVerdict {
    SecurityVerdict {
        inspection_coverage: Default::default(),
        coverage_reasons: vec![],
        id: Uuid::new_v4(),
        session_id,
        threat_level: ThreatLevel::High,
        threat_type: None,
        classification: None,
        confidence: 0.8,
        categories: vec![],
        summary: "synthetic feedback fixture".to_string(),
        pillar_scores: HashMap::new(),
        modules_run: 0,
        modules_flagged: 0,
        total_duration_ms: 0,
        created_at: Utc::now(),
        fusion_details: None,
    }
}

fn feedback(v: &SecurityVerdict, actor: &str) -> FeedbackEntry {
    FeedbackEntry {
        id: Uuid::new_v4(),
        session_id: v.session_id,
        verdict_id: Some(v.id),
        submitted_by: actor.to_string(),
        feedback_type: "legitimate".to_string(),
        module_id: None,
        original_threat_level: "high".to_string(),
        user_comment: Some("private analyst text".to_string()),
        status: "pending".to_string(),
        created_at: Utc::now(),
        corrected_threat_level: Some("safe".to_string()),
        evidence_snapshot: json!({"schema_version":1,"items":[{"source_id":"fixture:signal"}],
            "content_sha256":"a".repeat(64)}),
        snapshot_sha256: Some("b".repeat(64)),
        learning_status: "recorded".to_string(),
        learning_reason: None,
    }
}

#[tokio::test]
async fn feedback_is_atomic_stale_guarded_immutable_and_cas_protected() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    let first = verdict(Uuid::new_v4());
    let second = verdict(Uuid::new_v4());
    db.insert_verdict(&first).await?;
    db.insert_verdict(&second).await?;
    let actor = format!("feedback-test-{}", Uuid::new_v4());
    let since = Utc::now() - Duration::minutes(10);

    let mut stale = feedback(&first, &actor);
    stale.verdict_id = Some(Uuid::new_v4());
    assert_eq!(
        db.insert_learning_feedback(&stale, since, 30).await?,
        LearningFeedbackInsert::StaleVerdict
    );
    assert!(
        db.session_feedback_history(first.session_id).await?["feedbacks"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Constraint failure must not leave a feedback record or consume a budget slot.
    let mut invalid = feedback(&first, &actor);
    invalid.corrected_threat_level = Some("high".to_string());
    assert!(
        db.insert_learning_feedback(&invalid, since, 30)
            .await
            .is_err()
    );
    assert!(
        db.session_feedback_history(first.session_id).await?["feedbacks"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let a = feedback(&first, &actor);
    let b = feedback(&second, &actor);
    let (ra, rb) = tokio::join!(
        db.insert_learning_feedback(&a, since, 1),
        db.insert_learning_feedback(&b, since, 1),
    );
    let outcomes = [ra?, rb?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == LearningFeedbackInsert::Inserted)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == LearningFeedbackInsert::RateLimited)
            .count(),
        1
    );
    let stored = if outcomes[0] == LearningFeedbackInsert::Inserted {
        &a
    } else {
        &b
    };
    let history = db.session_feedback_history(stored.session_id).await?;
    assert_eq!(history["feedbacks"][0]["corrected_threat_level"], "safe");
    let encoded = serde_json::to_string(&history)?;
    assert!(!encoded.contains("private analyst text"));
    assert!(!encoded.contains(&actor));
    assert!(
        sqlx::query("UPDATE security_feedback SET evidence_snapshot = '{}'::jsonb WHERE id=$1")
            .bind(stored.id.to_string())
            .execute(db.pool())
            .await
            .is_err()
    );
    assert_eq!(
        db.get_verdict_by_session(stored.session_id)
            .await?
            .unwrap()
            .threat_level,
        ThreatLevel::High
    );

    let key = format!("ds_learning_test_{}", Uuid::new_v4());
    assert!(db.compare_and_set_config(&key, None, "one").await?);
    assert!(!db.compare_and_set_config(&key, None, "two").await?);
    assert!(
        !db.compare_and_set_config(&key, Some("wrong"), "two")
            .await?
    );
    assert!(db.compare_and_set_config(&key, Some("one"), "two").await?);
    assert_eq!(db.get_config(&key).await?.as_deref(), Some("two"));
    sqlx::query("DELETE FROM config WHERE key=$1")
        .bind(key)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM security_feedback WHERE submitted_by=$1")
        .bind(actor)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM security_verdicts WHERE session_id=ANY($1)")
        .bind(vec![
            first.session_id.to_string(),
            second.session_id.to_string(),
        ])
        .execute(db.pool())
        .await?;
    Ok(())
}
