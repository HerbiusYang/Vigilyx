#![cfg(feature = "infra-tests")]

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use sqlx::Row;
use tokio::sync::Barrier;
use uuid::Uuid;
use vigilyx_core::security::{AlertLevel, AlertRecord};
use vigilyx_db::{VigilDb, security::quarantine::QuarantineStoreRequest};

fn test_database_url() -> Result<String> {
    let url = std::env::var("VIGILYX_TEST_DATABASE_URL")
        .context("VIGILYX_TEST_DATABASE_URL must point to a disposable PostgreSQL database")?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1"),
        "set VIGILYX_ALLOW_REAL_INFRA_TESTS=1 to acknowledge use of a disposable database"
    );
    ensure!(
        url.to_ascii_lowercase().contains("vigilyx_test"),
        "refusing to run destructive integration tests unless the database name contains vigilyx_test"
    );
    Ok(url)
}

async fn store_message(db: &VigilDb, suffix: &str) -> Result<String> {
    let session_id = Uuid::new_v4();
    let recipients = vec!["recipient@example.test".to_string()];
    let raw_eml = format!(
        "From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: {suffix}\r\n\r\nbody"
    );
    let request = QuarantineStoreRequest {
        session_id: &session_id,
        verdict_id: None,
        mail_from: Some("sender@example.test"),
        rcpt_to: &recipients,
        subject: Some(suffix),
        raw_eml: raw_eml.as_bytes(),
        threat_level: "high",
        reason: Some("integration-test"),
        client_ip: Some("203.0.113.7"),
    };
    db.quarantine_store(&request).await
}

#[tokio::test]
async fn real_migrations_are_repeatable_and_upgrade_a_missing_column() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    // Recreate a known older sessions shape by removing the column added by the
    // current migration, then prove init() upgrades it again.
    sqlx::query("ALTER TABLE sessions DROP COLUMN IF EXISTS sender_domain")
        .execute(db.pool())
        .await?;
    db.init().await?;

    let sender_domain_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'sessions' AND column_name = 'sender_domain')",
    )
    .fetch_one(db.pool())
    .await?;
    assert!(sender_domain_exists);

    db.init().await?;
    db.init_security_tables().await?;
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS total, COUNT(DISTINCT version)::BIGINT AS distinct_total \
         FROM schema_migrations",
    )
    .fetch_one(db.pool())
    .await?;
    assert_eq!(
        row.get::<i64, _>("total"),
        row.get::<i64, _>("distinct_total")
    );
    Ok(())
}

#[tokio::test]
async fn real_quarantine_claim_is_single_owner_and_finalize_failure_stays_locked() -> Result<()> {
    let url = test_database_url()?;
    let db = VigilDb::new(&url).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let concurrent_id = store_message(&db, "concurrent-release").await?;
    let workers = 12;
    let barrier = std::sync::Arc::new(Barrier::new(workers));
    let mut tasks = Vec::with_capacity(workers);
    for _ in 0..workers {
        let worker_db = db.clone();
        let worker_id = concurrent_id.clone();
        let worker_barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            worker_barrier.wait().await;
            worker_db.quarantine_claim_release(&worker_id).await
        }));
    }

    let mut winners = 0;
    for task in tasks {
        if task.await??.is_some() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "only one release request may own downstream delivery"
    );
    assert_eq!(
        db.quarantine_status(&concurrent_id).await?.as_deref(),
        Some("releasing")
    );
    assert!(
        db.quarantine_finalize_release(&concurrent_id, "integration-admin")
            .await?
    );
    assert!(
        !db.quarantine_finalize_release(&concurrent_id, "duplicate-admin")
            .await?
    );
    assert_eq!(
        db.quarantine_status(&concurrent_id).await?.as_deref(),
        Some("released")
    );

    // Model the post-relay partial failure: the message has been claimed and the
    // downstream accepted it, but the application pool dies before finalization.
    let finalize_failure_id = store_message(&db, "finalize-failure").await?;
    assert!(
        db.quarantine_claim_release(&finalize_failure_id)
            .await?
            .is_some()
    );
    db.pool().close().await;
    assert!(
        db.quarantine_finalize_release(&finalize_failure_id, "integration-admin")
            .await
            .is_err()
    );

    let observer = VigilDb::new(&url).await?;
    assert_eq!(
        observer
            .quarantine_status(&finalize_failure_id)
            .await?
            .as_deref(),
        Some("releasing"),
        "a failed finalize must remain locked to prevent duplicate downstream delivery"
    );
    Ok(())
}

fn make_alert(session_id: Uuid, level: AlertLevel, created_at: chrono::DateTime<Utc>) -> AlertRecord {
    AlertRecord {
        id: Uuid::new_v4(),
        verdict_id: Uuid::new_v4(),
        session_id,
        alert_level: level,
        expected_loss: 0.0,
        return_period: 0.0,
        cvar: 0.0,
        risk_final: 0.5,
        k_conflict: 0.0,
        cusum_alarm: false,
        rationale: "integration-test".to_string(),
        acknowledged: false,
        acknowledged_by: None,
        acknowledged_at: None,
        created_at,
    }
}

#[tokio::test]
async fn real_alert_insert_dedupes_same_session_level_within_window() -> Result<()> {
    // Round-4 regression: a release rescan and the periodic catch-up rescan
    // both run post-verdict for the same session. Two alert inserts for the
    // same (session, level) inside the dedup window must yield ONE row.
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();

    assert!(
        db.insert_alert(&make_alert(session_id, AlertLevel::P2, Utc::now()))
            .await?,
        "first alert must be stored"
    );
    assert!(
        !db.insert_alert(&make_alert(session_id, AlertLevel::P2, Utc::now()))
            .await?,
        "duplicate (session, level) alert within the window must be suppressed"
    );
    assert!(
        db.insert_alert(&make_alert(session_id, AlertLevel::P3, Utc::now()))
            .await?,
        "a different alert level for the same session is a distinct alert"
    );

    // Outside the window a same-level alert is stored again.
    let stale =
        Utc::now() - Duration::minutes(vigilyx_db::security::ALERT_DEDUP_WINDOW_MINUTES + 1);
    assert!(
        db.insert_alert(&make_alert(session_id, AlertLevel::P2, stale))
            .await?,
        "an alert older than the dedup window must not block new inserts"
    );
    assert!(
        db.insert_alert(&make_alert(session_id, AlertLevel::P2, Utc::now()))
            .await?,
        "after the window, the same (session, level) alert is stored again"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM security_alerts WHERE session_id = $1",
    )
    .bind(session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(count, 4, "expected 4 stored alerts, got {count}");
    Ok(())
}

#[tokio::test]
async fn real_quarantine_client_ip_roundtrip_and_delete_guard() -> Result<()> {
    // Round-4 F2/client_ip regression: the submitting client IP must be
    // persisted (so a later release stamps an accurate Received hop), and a
    // message whose release is in flight must refuse deletion.
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let id = store_message(&db, "client-ip-roundtrip").await?;

    // client_ip survives list / raw reads.
    let listed = db.quarantine_list(Some("quarantined"), 100, 0).await?;
    let entry = listed
        .iter()
        .find(|e| e.id == id)
        .context("stored entry must appear in quarantine list")?;
    assert_eq!(entry.client_ip.as_deref(), Some("203.0.113.7"));

    let (_eml, entry) = db
        .quarantine_get_raw_eml(&id)
        .await?
        .context("raw eml lookup must find the entry")?;
    assert_eq!(entry.client_ip.as_deref(), Some("203.0.113.7"));

    // Claim (status -> releasing): delete must now fail with an explicit error.
    let (_eml, claimed) = db
        .quarantine_claim_release(&id)
        .await?
        .context("claim must succeed for a quarantined entry")?;
    assert_eq!(
        claimed.client_ip.as_deref(),
        Some("203.0.113.7"),
        "claim_release must return the stored client_ip for the release relay path"
    );

    let delete_result = db.quarantine_delete(&id).await;
    assert!(
        delete_result.is_err(),
        "deleting an entry whose release is in flight must return an explicit error"
    );
    assert_eq!(
        db.quarantine_status(&id).await?.as_deref(),
        Some("releasing"),
        "a refused delete must leave the releasing entry untouched"
    );

    // Reset to quarantined: delete succeeds again.
    assert!(db.quarantine_release_reset(&id).await?);
    assert!(
        db.quarantine_delete(&id).await?,
        "delete must succeed once the entry is quarantined again"
    );
    assert!(
        !db.quarantine_delete(&id).await?,
        "deleting a missing entry stays Ok(false)"
    );
    Ok(())
}
