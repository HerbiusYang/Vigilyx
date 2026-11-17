#![cfg(feature = "infra-tests")]

//! Engine -> PostgreSQL -> websocket regression against an exclusive disposable database.
use anyhow::{Context, Result, ensure};
use std::time::Duration;
use tokio::sync::broadcast;
use vigilyx_core::{HttpMethod, HttpSession, WsMessage};
use vigilyx_db::VigilDb;
use vigilyx_engine::data_security::engine::DataSecurityEngine;

fn fixture(body: &str, user: &str, uri: &str) -> HttpSession {
    let mut session = HttpSession::new(
        "192.0.2.77".into(),
        43210,
        "198.51.100.77".into(),
        80,
        HttpMethod::Post,
        uri.into(),
    );
    session.request_body = Some(body.into());
    session.request_body_size = body.len();
    session.detected_user = Some(user.into());
    session.host = Some("synthetic-policy-test.invalid".into());
    session
}

async fn wait_for_count(db: &VigilDb, kind: &str, expected: u64) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let count = db
                .list_data_security_incidents(Some(kind), None, None, None, None, 1, 0)
                .await?
                .1;
            if count == expected {
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(
                count < expected,
                "unexpected extra {kind} incidents: {count}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("engine did not persist expected events")??;
    Ok(())
}

#[tokio::test]
async fn single_transfers_retries_drafts_public_data_and_bulk_escalation() -> Result<()> {
    let raw = std::env::var("VIGILYX_TEST_DATABASE_URL")
        .context("exclusive disposable database required")?;
    let url = url::Url::parse(&raw)?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1")
            && url
                .path()
                .trim_start_matches('/')
                .starts_with("vigilyx_test"),
        "refusing non-test database"
    );
    let db = VigilDb::new(&raw).await?;
    db.init().await?;
    db.init_security_tables().await?;
    db.init_data_security_tables().await?;
    db.set_config("time_policy", r#"{"enabled":false,"work_hour_start":8,"work_hour_end":18,"utc_offset_hours":8,"weekend_is_off_hours":true}"#).await?;
    let (ws, mut events) = broadcast::channel(256);
    let engine = DataSecurityEngine::start(db.clone(), ws);
    engine
        .reload_time_policy(&db)
        .await
        .map_err(anyhow::Error::msg)?;
    let first = fixture(
        "客户手机号：13800138000",
        "single-item-fixture",
        "/mail/send",
    );
    engine
        .submit(first.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    engine
        .submit(first.clone())
        .await
        .map_err(anyhow::Error::msg)?;
    let mut second = first.clone();
    second.id = uuid::Uuid::new_v4();
    engine.submit(second).await.map_err(anyhow::Error::msg)?;
    engine
        .submit(fixture("SWIFT: TESTUS33", "public-fixture", "/mail/send"))
        .await
        .map_err(anyhow::Error::msg)?;
    engine
        .submit(fixture(
            "password=synthetic-only",
            "login-fixture",
            "/login",
        ))
        .await
        .map_err(anyhow::Error::msg)?;
    for _ in 0..6 {
        engine
            .submit(fixture(
                r#"{"action":"save","attrs":{"content":"客户手机号 13800138000"}}"#,
                "draft-fixture",
                "/coremail/common/mbox/compose.jsp",
            ))
            .await
            .map_err(anyhow::Error::msg)?;
    }
    wait_for_count(&db, "sensitive_data_transfer", 2).await?;
    wait_for_count(&db, "draft_box_abuse", 6).await?;
    let volume = db
        .list_data_security_incidents(Some("volume_anomaly"), None, None, None, None, 1, 0)
        .await?
        .1;
    assert_eq!(volume, 0, "draft saves cannot escalate transfer bursts");
    let mut ws_ids = std::collections::HashSet::new();
    while let Ok(WsMessage::DataSecurityAlert(incident)) = events.try_recv() {
        assert!(
            ws_ids.insert(incident.id),
            "duplicate websocket notification"
        );
    }
    assert_eq!(ws_ids.len(), 8);
    // A process restart or competing consumer must still hit durable ON CONFLICT idempotency.
    let persisted = db
        .list_data_security_incidents(
            Some("sensitive_data_transfer"),
            None,
            None,
            None,
            None,
            10,
            0,
        )
        .await?
        .0;
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let db = db.clone();
        let incident = persisted[0].clone();
        attempts.spawn(async move { db.insert_data_security_incident(&incident).await });
    }
    while let Some(result) = attempts.join_next().await {
        assert!(!result??);
    }
    for _ in 0..49 {
        engine
            .submit(fixture("CVV: 731", "bulk-fixture", "/mail/send"))
            .await
            .map_err(anyhow::Error::msg)?;
    }
    wait_for_count(&db, "sensitive_data_transfer", 51).await?;
    let before = db
        .list_data_security_incidents(
            Some("bulk_sensitive_transfer"),
            None,
            None,
            None,
            None,
            1,
            0,
        )
        .await?
        .1;
    assert_eq!(
        before, 0,
        "49 transfers already alert individually but do not reach the extra bulk threshold"
    );
    engine
        .submit(fixture("CVV: 731", "bulk-fixture", "/mail/send"))
        .await
        .map_err(anyhow::Error::msg)?;
    wait_for_count(&db, "sensitive_data_transfer", 52).await?;
    wait_for_count(&db, "bulk_sensitive_transfer", 1).await?;
    let stats = db.get_data_security_stats().await?;
    assert_eq!(stats.sensitive_transfer_count, 52);
    assert_eq!(stats.bulk_transfer_count, 1);
    assert_eq!(stats.draft_abuse_count, 6);
    drop(engine);
    Ok(())
}
