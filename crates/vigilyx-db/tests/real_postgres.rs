#![cfg(feature = "infra-tests")]

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Timelike, Utc};
use sqlx::Row;
use std::collections::HashMap;
use tokio::sync::Barrier;
use uuid::Uuid;
use vigilyx_core::security::{AlertLevel, AlertRecord, SecurityVerdict, ThreatLevel};
use vigilyx_core::{
    Direction, EmailAttachment, EmailSession, Protocol, SessionStatus, SmtpAuthInfo,
    SmtpDialogEntry,
};
use vigilyx_db::{
    DeliveryRiskDetailKind, VigilDb,
    security::quarantine::QuarantineStoreRequest,
    security::{IocIndicatorObservation, IocMessageObservation},
};

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

async fn read_stats_cache(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> std::result::Result<(i64, i64, i64, i64, i64, i64, i64, i64), sqlx::Error> {
    sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(
        r#"SELECT total_sessions, active_sessions, total_bytes, total_packets,
                  smtp_sessions, pop3_sessions, imap_sessions, http_sessions
           FROM public.stats_cache WHERE id = 1"#,
    )
    .fetch_one(&mut **tx)
    .await
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
        direction: "outbound",
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
async fn ioc_telemetry_is_session_deduplicated_and_feedback_is_separate() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();
    let verdict_id = Uuid::new_v4();
    let observed_at = Utc::now();
    let message = IocMessageObservation {
        session_id,
        verdict_id,
        direction: "inbound".to_string(),
        threat_level: "safe".to_string(),
        engine_confidence: 0.85,
        observed_at,
        capture_coverage: "complete".to_string(),
    };
    let indicator = IocIndicatorObservation {
        session_id,
        verdict_id,
        indicator: "share.example.test".to_string(),
        ioc_type: "domain".to_string(),
        source_detector: "traffic_observation".to_string(),
        detector_family: "traffic_observation".to_string(),
        external_provider: "local".to_string(),
        evidence_cluster: "traffic:domain".to_string(),
        activity_key: "sha256:test-activity".to_string(),
        direction: "inbound".to_string(),
        threat_level: "safe".to_string(),
        engine_confidence: 0.85,
        observed_at,
        capture_coverage: "complete".to_string(),
    };

    // Duplicate input and a replayed session each count once.
    assert_eq!(
        db.record_ioc_telemetry(&message, &[indicator.clone(), indicator.clone()])
            .await?,
        1
    );
    assert_eq!(db.record_ioc_telemetry(&message, &[indicator]).await?, 0);

    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT observed_count, distinct_session_count, distinct_activity_count \
         FROM security_ioc_traffic_stats WHERE ioc_type = 'domain' AND indicator = $1",
    )
    .bind("share.example.test")
    .fetch_one(db.pool())
    .await?;
    assert_eq!(counts, (1, 1, 1));

    assert_eq!(
        db.record_ioc_outcome_for_session(
            session_id,
            Some(verdict_id),
            "normal",
            "quarantine_release",
            "test-operator",
            Some("released after review"),
        )
        .await?,
        1
    );

    let shadow = db
        .get_ioc_shadow_telemetry("domain", "share.example.test", Utc::now())
        .await?
        .context("shadow telemetry missing")?;
    assert_eq!(shadow.actionability, "shadow_only");
    assert_eq!(shadow.calibration_status, "hypothesis_only");
    assert_eq!(shadow.traffic.distinct_session_count, 1);
    assert_eq!(shadow.traffic.distinct_activity_count, 1);
    assert!(
        db.get_ioc_shadow_telemetry("domain", "missing.example.test", Utc::now())
            .await?
            .is_none()
    );
    let calibration = db.get_ioc_calibration_summary(20, Utc::now()).await?;
    assert_eq!(calibration.status, "hypothesis_only");
    assert_eq!(calibration.labeled_observations, 1);
    assert!(calibration.brier_score.is_some());

    sqlx::query("DELETE FROM security_ioc_outcomes WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM security_ioc_observations WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM security_ioc_message_population WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query(
        "DELETE FROM security_ioc_traffic_stats \
         WHERE ioc_type = 'domain' AND indicator = 'share.example.test'",
    )
    .execute(db.pool())
    .await?;
    Ok(())
}

#[tokio::test]
async fn session_count_matches_filtered_rows_and_legacy_content() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    let source = format!("count-fixture-{}", Uuid::new_v4());
    let mut ids = Vec::new();
    for i in 0..4 {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            source.clone(),
            40_000,
            "198.51.100.20".into(),
            if i == 3 { 465 } else { 25 },
        );
        session.status = SessionStatus::Completed;
        session.subject = Some(format!("bound ' query {i}"));
        session.started_at = Utc::now() - Duration::seconds(i);
        if i == 0 {
            session.content.body_text = Some("synthetic body".into());
        }
        if i == 1 {
            session
                .content
                .headers
                .push(("Subject".into(), "legacy".into()));
        }
        if i == 3 {
            session.content.is_encrypted = true;
        }
        session.auth_info = Some(SmtpAuthInfo {
            auth_method: "PLAIN".into(),
            username: None,
            password: None,
            auth_success: Some(i == 0),
        });
        ids.push(session.id);
        db.insert_session(&session).await?;
    }
    // Old rows have no list metadata. Both count and rows must still use the
    // exact JSON predicate (including headers-only content).
    sqlx::query("UPDATE sessions SET list_has_content = false WHERE id = $1")
        .bind(ids[1].to_string())
        .execute(db.pool())
        .await?;
    for (content, auth, search, expected) in [
        ("WITH_CONTENT", None, None, 2),
        ("WITH_CONTENT", Some("AUTH_SUCCESS"), None, 1),
        ("WITH_CONTENT", Some("AUTH_FAILED"), None, 1),
        ("NON_ENCRYPTED", None, None, 3),
        ("ENCRYPTED", None, None, 1),
        ("WITH_CONTENT", None, Some("bound ' query 1"), 1),
        ("WITH_CONTENT", None, Some("missing"), 0),
    ] {
        let snapshot = db
            .count_sessions(
                Some("SMTP,IMAP"),
                Some("completed"),
                None,
                Some(content),
                auth,
                Some(&source),
                Some("198.51.100.20"),
                search,
                &[],
            )
            .await?;
        let (rows, skipped_total) = db
            .list_sessions(
                10,
                0,
                Some("SMTP,IMAP"),
                Some("completed"),
                None,
                Some(content),
                auth,
                Some(&source),
                Some("198.51.100.20"),
                search,
                &[],
                true,
            )
            .await?;
        assert_eq!(snapshot.total, expected);
        assert_eq!(rows.len() as u64, snapshot.total);
        assert_eq!(skipped_total, 0);
    }
    let (page, _) = db
        .list_sessions(
            2,
            1,
            Some("SMTP"),
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some(&source),
            None,
            None,
            &[],
            true,
        )
        .await?;
    assert_eq!(page.iter().map(|s| s.id).collect::<Vec<_>>(), ids[1..3]);
    // Sharing a cloned DB also shares the count snapshot across operators.
    let first = db
        .count_sessions(None, None, None, None, None, Some(&source), None, None, &[])
        .await?;
    let second = db
        .clone()
        .count_sessions(None, None, None, None, None, Some(&source), None, None, &[])
        .await?;
    assert_eq!(first.counted_at, second.counted_at);
    assert_eq!(first.total, 4);
    sqlx::query("DELETE FROM sessions WHERE client_ip = $1")
        .bind(&source)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn session_seek_pages_preserve_ties_and_do_not_shift_after_insertions() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    let source = format!("seek-fixture-{}", Uuid::new_v4());
    let started_at = Utc::now();
    for _ in 0..4 {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            source.clone(),
            40_000,
            "198.51.100.30".into(),
            25,
        );
        session.started_at = started_at;
        session.content.body_text = Some("synthetic cursor fixture".into());
        db.insert_session(&session).await?;
    }
    let (all, _) = db
        .list_session_entries(
            10,
            0,
            None,
            None,
            None,
            Some("WITH_CONTENT"),
            None,
            Some(&source),
            None,
            None,
            &[],
            true,
            None,
        )
        .await?;
    assert_eq!(all.len(), 4);
    let (first, _) = db
        .list_session_entries(
            3,
            0,
            None,
            None,
            None,
            Some("WITH_CONTENT"),
            None,
            Some(&source),
            None,
            None,
            &[],
            true,
            None,
        )
        .await?;
    let cursor = first[1].cursor.clone();
    assert_eq!(cursor.started_at, all[1].cursor.started_at);
    let mut inserted = EmailSession::new(
        Protocol::Smtp,
        source.clone(),
        40_000,
        "198.51.100.30".into(),
        25,
    );
    inserted.started_at = started_at + Duration::seconds(1);
    inserted.content.body_text = Some("new row before the cursor".into());
    db.insert_session(&inserted).await?;
    let (next, _) = db
        .list_session_entries(
            3,
            u32::MAX,
            None,
            None,
            None,
            Some("WITH_CONTENT"),
            None,
            Some(&source),
            None,
            None,
            &[],
            true,
            Some(&cursor),
        )
        .await?;
    assert_eq!(
        next.iter()
            .map(|entry| entry.session.id)
            .collect::<Vec<_>>(),
        all[2..]
            .iter()
            .map(|entry| entry.session.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        next.len(),
        2,
        "a full final page must not fabricate a successor"
    );
    let (empty, _) = db
        .list_session_entries(
            3,
            0,
            None,
            None,
            None,
            Some("WITH_CONTENT"),
            None,
            Some(&source),
            None,
            None,
            &[],
            true,
            Some(&next[1].cursor),
        )
        .await?;
    assert!(empty.is_empty());
    sqlx::query("DELETE FROM sessions WHERE client_ip = $1")
        .bind(&source)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn session_count_timeout_is_an_error_and_does_not_poison_page_queries() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    let mut lock = db.pool().begin().await?;
    sqlx::query("LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let started = std::time::Instant::now();
    let result = db
        .count_sessions(
            None,
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some("timeout-fixture"),
            None,
            None,
            &[],
        )
        .await;
    assert!(
        result.is_err(),
        "a cancelled COUNT must never be returned as zero"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(11));
    lock.rollback().await?;
    let retry_started = std::time::Instant::now();
    assert!(
        db.count_sessions(
            None,
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some("timeout-fixture"),
            None,
            None,
            &[]
        )
        .await
        .is_err()
    );
    assert!(retry_started.elapsed() < std::time::Duration::from_secs(1));
    let (rows, _) = db
        .list_sessions(
            2,
            0,
            None,
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some("timeout-fixture"),
            None,
            None,
            &[],
            true,
        )
        .await?;
    assert!(rows.is_empty());
    let mut page_lock = db.pool().begin().await?;
    sqlx::query("LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *page_lock)
        .await?;
    let page_started = std::time::Instant::now();
    assert!(
        db.list_session_entries(
            2,
            0,
            None,
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some("timeout-fixture"),
            None,
            None,
            &[],
            true,
            None
        )
        .await
        .is_err()
    );
    assert!(page_started.elapsed() < std::time::Duration::from_secs(11));
    page_lock.rollback().await?;
    let (rows_after_timeout, _) = db
        .list_sessions(
            2,
            0,
            None,
            None,
            None,
            Some("NON_ENCRYPTED"),
            None,
            Some("timeout-fixture"),
            None,
            None,
            &[],
            true,
        )
        .await?;
    assert!(rows_after_timeout.is_empty());
    // SET LOCAL must not leak to another request on a pooled connection.
    let read_only: String = sqlx::query_scalar("SHOW transaction_read_only")
        .fetch_one(db.pool())
        .await?;
    assert_eq!(read_only, "off");
    Ok(())
}

#[tokio::test]
async fn session_writes_dual_write_typed_timestamps() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();
    let started_at = Utc::now()
        .with_nanosecond(123_456_000)
        .context("failed to set test timestamp precision")?
        - Duration::hours(2);
    let ended_at = started_at + Duration::seconds(7);
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".to_string(),
        40_000,
        "198.51.100.10".to_string(),
        25,
    );
    session.id = session_id;
    session.started_at = started_at;
    session.ended_at = Some(ended_at);
    session.status = SessionStatus::Completed;
    session.content.body_text = Some("synthetic list metadata body".to_string());
    session.content.is_complete = true;
    session.content.attachments.push(EmailAttachment {
        filename: "fixture.txt".to_string(),
        content_type: "text/plain".to_string(),
        size: 7,
        hash: "fixture-hash".to_string(),
        content_base64: None,
    });
    session.auth_info = Some(SmtpAuthInfo {
        auth_method: "PLAIN".to_string(),
        username: Some("integration-user".to_string()),
        password: None,
        auth_success: Some(true),
    });

    let postgres_started_at =
        started_at - Duration::nanoseconds((started_at.timestamp_subsec_nanos() % 1_000) as i64);
    let postgres_ended_at =
        ended_at - Duration::nanoseconds((ended_at.timestamp_subsec_nanos() % 1_000) as i64);

    db.insert_session(&session).await?;
    // Exercise the transitional typed/legacy timestamp predicate used by the
    // expensive login aggregate while the row is still newly written.
    let login_stats = db.get_external_login_stats().await?;
    assert!(login_stats.total_24h >= 1);
    assert!(login_stats.success_24h >= 1);
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT to_char(started_at_ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                to_char(ended_at_ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM sessions WHERE id = $1",
    )
    .bind(session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(&row.0)?.with_timezone(&Utc),
        postgres_started_at
    );
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(row.1.as_deref().context("ended_at_ts missing")?)?
            .with_timezone(&Utc),
        postgres_ended_at
    );

    let (listed, total) = db
        .list_sessions(
            50,
            0,
            Some("SMTP"),
            Some("Completed"),
            None,
            Some("WITH_CONTENT"),
            None,
            Some("192.0.2.10"),
            Some("198.51.100.10"),
            None,
            &[],
            false,
        )
        .await?;
    let listed_session = listed
        .iter()
        .find(|candidate| candidate.id == session_id)
        .context("content-bearing session missing from direction-filtered list")?;
    assert!(total >= 1);
    assert!(listed_session.content.is_complete);
    assert_eq!(listed_session.content.attachments.len(), 1);

    let batch_session_id = Uuid::new_v4();
    let batch_started_at = Utc::now()
        .with_nanosecond(654_321_000)
        .context("failed to set batch test timestamp precision")?
        - Duration::minutes(4);
    let batch_ended_at = batch_started_at + Duration::seconds(11);
    let mut batch_session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.11".to_string(),
        40_001,
        "198.51.100.11".to_string(),
        25,
    );
    batch_session.id = batch_session_id;
    batch_session.started_at = batch_started_at;
    batch_session.ended_at = Some(batch_ended_at);
    batch_session.status = SessionStatus::Completed;

    let batch_postgres_started_at = batch_started_at
        - Duration::nanoseconds((batch_started_at.timestamp_subsec_nanos() % 1_000) as i64);
    let batch_postgres_ended_at = batch_ended_at
        - Duration::nanoseconds((batch_ended_at.timestamp_subsec_nanos() % 1_000) as i64);

    let (inserted, is_new, _) = db.insert_sessions_batch(&[batch_session]).await?;
    assert_eq!(inserted, 1);
    assert_eq!(is_new, vec![true]);
    let batch_row: (String, Option<String>) = sqlx::query_as(
        "SELECT to_char(started_at_ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
                to_char(ended_at_ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
         FROM sessions WHERE id = $1",
    )
    .bind(batch_session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(&batch_row.0)?.with_timezone(&Utc),
        batch_postgres_started_at
    );
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(
            batch_row
                .1
                .as_deref()
                .context("batch ended_at_ts missing")?
        )?
        .with_timezone(&Utc),
        batch_postgres_ended_at
    );

    sqlx::query("DELETE FROM sessions WHERE id = ANY($1::text[])")
        .bind(vec![session_id.to_string(), batch_session_id.to_string()])
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn verdict_list_filter_keeps_sql_injection_payload_as_data() -> Result<()> {
    // The list endpoint accepts a comma-separated query value. A quote and
    // comment payload must remain one bound array element, not become SQL.
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();
    let verdict_id = Uuid::new_v4();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.90".to_string(),
        40_090,
        "198.51.100.90".to_string(),
        25,
    );
    session.id = session_id;
    session.status = SessionStatus::Completed;
    session.mail_from = Some("sql-injection-test@example.test".to_string());
    session.rcpt_to = vec!["recipient@example.test".to_string()];
    db.insert_session(&session).await?;
    db.insert_verdict(&make_verdict(session_id, verdict_id, Utc::now()))
        .await?;

    let (items, _) = db
        .list_recent_verdicts(Some("high') OR TRUE --"), 100, 0)
        .await?;
    assert!(
        items
            .iter()
            .all(|item| item.verdict_id != verdict_id.to_string()),
        "SQL metacharacters must not broaden the verdict result set"
    );

    let (items, _) = db.list_recent_verdicts(Some("high"), 100, 0).await?;
    assert!(
        items
            .iter()
            .any(|item| item.verdict_id == verdict_id.to_string()),
        "the same row must remain visible for the legitimate bound filter"
    );

    sqlx::query("DELETE FROM security_verdicts WHERE id = $1")
        .bind(verdict_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn stats_cache_tracks_session_insert_update_and_delete_deltas() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;

    let mut tx = db.pool().begin().await?;
    let before = read_stats_cache(&mut tx).await?;
    let session_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    sqlx::query(
        r#"INSERT INTO sessions
           (id, protocol, client_ip, client_port, server_ip, server_port, started_at,
            started_at_ts, status, packet_count, total_bytes, content)
           VALUES ($1, 'SMTP', '192.0.2.30', 40300, '198.51.100.30', 25, $2, $2::timestamptz,
                   'Completed', 7, 1000, '{}'::jsonb)"#,
    )
    .bind(&session_id)
    .bind(&timestamp)
    .execute(&mut *tx)
    .await?;
    let after_insert = read_stats_cache(&mut tx).await?;
    assert_eq!(after_insert.0 - before.0, 1);
    assert_eq!(after_insert.1 - before.1, 0);
    assert_eq!(after_insert.2 - before.2, 1000);
    assert_eq!(after_insert.3 - before.3, 7);
    assert_eq!(after_insert.4 - before.4, 1);

    sqlx::query(
        r#"UPDATE sessions
           SET protocol = 'HTTP', status = 'Active', packet_count = 11, total_bytes = 2500
           WHERE id = $1"#,
    )
    .bind(&session_id)
    .execute(&mut *tx)
    .await?;
    let after_update = read_stats_cache(&mut tx).await?;
    assert_eq!(after_update.0 - before.0, 1);
    assert_eq!(after_update.1 - before.1, 1);
    assert_eq!(after_update.2 - before.2, 2500);
    assert_eq!(after_update.3 - before.3, 11);
    assert_eq!(after_update.4 - before.4, 0);
    assert_eq!(after_update.7 - before.7, 1);

    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&session_id)
        .execute(&mut *tx)
        .await?;
    let after_delete = read_stats_cache(&mut tx).await?;
    assert_eq!(after_delete, before);
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn delivery_hop_tracks_only_post_message_security_policy_rejection() -> Result<()> {
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.20".to_string(),
        40_020,
        "198.51.100.20".to_string(),
        25,
    );
    session.id = session_id;
    session.status = SessionStatus::Completed;
    session.content.smtp_dialog.push(SmtpDialogEntry {
        direction: Direction::Inbound,
        command: "554 5.7.1 SECURITY_POLICY_REJECTED".to_string(),
        size: 27,
        timestamp: Utc::now(),
    });
    db.insert_session(&session).await?;

    let chain = db
        .register_email_delivery_hop(
            "integration-smtp-rejection-preextract",
            session_id,
            &session.client_ip,
            &session.server_ip,
            session.started_at,
        )
        .await?;
    let rejected: (bool, bool) = sqlx::query_as(
        "SELECT smtp_security_rejected, smtp_security_rejection_metadata_ready \
         FROM email_delivery_hops WHERE session_id = $1",
    )
    .bind(session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(rejected, (true, true));

    // A later session upsert is expected in passive capture when the final
    // DATA response arrives after the completed message was first emitted.
    // Generic mailbox/user failures must clear rather than create a security
    // action, and the exact parser marker must restore it.
    session.content.smtp_dialog.clear();
    session.content.smtp_dialog.push(SmtpDialogEntry {
        direction: Direction::Inbound,
        command: "552 5.2.2 mailbox full".to_string(),
        size: 24,
        timestamp: Utc::now(),
    });
    db.insert_session(&session).await?;
    let benign_failure: (bool, bool) = sqlx::query_as(
        "SELECT smtp_security_rejected, smtp_security_rejection_metadata_ready \
         FROM email_delivery_hops WHERE session_id = $1",
    )
    .bind(session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(benign_failure, (false, true));

    session.content.smtp_dialog.clear();
    session.content.smtp_dialog.push(SmtpDialogEntry {
        direction: Direction::Inbound,
        command: "550 5.7.1 SECURITY_POLICY_REJECTED".to_string(),
        size: 34,
        timestamp: Utc::now(),
    });
    db.insert_session(&session).await?;
    let late_security_action: (bool, bool) = sqlx::query_as(
        "SELECT smtp_security_rejected, smtp_security_rejection_metadata_ready \
         FROM email_delivery_hops WHERE session_id = $1",
    )
    .bind(session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(late_security_action, (true, true));

    sqlx::query("DELETE FROM email_delivery_hops WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = $1")
        .bind(chain.chain_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn security_migrations_serialize_concurrent_initializers() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);

    // Mirror mode starts API and Engine together with independent pools. Both
    // initializers must finish cleanly even when they enter at the same time.
    let api_db = VigilDb::new(&database_url).await?;
    let engine_db = VigilDb::new(&database_url).await?;
    let (api_result, engine_result) = tokio::join!(
        api_db.init_security_tables(),
        engine_db.init_security_tables()
    );
    api_result?;
    engine_result?;

    Ok(())
}

#[tokio::test]
async fn delivery_lineage_reuses_first_verdict_and_marks_dangerous_forwarding() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);
    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let suffix = Uuid::new_v4().simple().to_string();
    let fingerprint = format!("integration-delivery-{suffix}");
    let first_session_id = Uuid::new_v4();
    let downstream_session_id = Uuid::new_v4();
    let third_session_id = Uuid::new_v4();
    let late_session_id = Uuid::new_v4();
    let first_verdict_id = Uuid::new_v4();
    let observed_at = Utc::now() - Duration::minutes(1);

    let first = db
        .register_email_delivery_hop(
            &fingerprint,
            first_session_id,
            "198.51.100.10",
            "10.0.0.10",
            observed_at,
        )
        .await?;
    let downstream = db
        .register_email_delivery_hop(
            &fingerprint,
            downstream_session_id,
            "10.0.0.10",
            "10.0.0.20",
            observed_at + Duration::seconds(1),
        )
        .await?;
    let replay = db
        .register_email_delivery_hop(
            &fingerprint,
            downstream_session_id,
            "10.0.0.10",
            "10.0.0.20",
            observed_at + Duration::seconds(2),
        )
        .await?;

    assert!(first.is_first_hop);
    assert_eq!(first.hop_index, 0);
    assert!(!downstream.is_first_hop);
    assert_eq!(downstream.first_session_id, first_session_id);
    assert_eq!(downstream.hop_index, 1);
    assert_eq!(replay, downstream, "hop registration must be idempotent");
    let third = db
        .register_email_delivery_hop(
            &fingerprint,
            third_session_id,
            "10.0.0.20",
            "10.0.0.30",
            observed_at + Duration::seconds(3),
        )
        .await?;
    assert_eq!(third.hop_index, 2);

    sqlx::query(
        "INSERT INTO security_verdicts \
         (id, session_id, threat_level, confidence, categories, summary, pillar_scores, \
          modules_run, modules_flagged, total_duration_ms, created_at, verdict_origin) \
         VALUES ($1, $2, 'high', 0.9, '[]', 'integration', '{}', 1, 1, 1, NOW()::TEXT, 'native')",
    )
    .bind(first_verdict_id.to_string())
    .bind(first_session_id.to_string())
    .execute(db.pool())
    .await?;

    db.record_email_delivery_first_verdict(first_session_id, first_verdict_id, "high")
        .await?;
    assert!(
        db.insert_reused_first_hop_verdict(downstream_session_id, first_session_id)
            .await?
    );
    db.mark_email_delivery_hop_reused(downstream_session_id, first_session_id)
        .await?;

    // Regression guard: a downstream hop can be registered after the first
    // verdict is finalized. It must inherit the first-hop risk state too.
    let late = db
        .register_email_delivery_hop(
            &fingerprint,
            late_session_id,
            "10.0.0.30",
            "10.0.0.40",
            observed_at + Duration::seconds(4),
        )
        .await?;
    assert_eq!(late.hop_index, 3);

    let row = sqlx::query(
        "SELECT first_hop_threat_level, verdict_origin, dangerous_forwarded \
         FROM email_delivery_hops WHERE session_id = $1",
    )
    .bind(downstream_session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(row.get::<String, _>("first_hop_threat_level"), "high");
    assert_eq!(row.get::<String, _>("verdict_origin"), "reused_first_hop");
    assert!(row.get::<bool, _>("dangerous_forwarded"));

    let late_row = sqlx::query(
        "SELECT first_hop_threat_level, dangerous_forwarded \
         FROM email_delivery_hops WHERE session_id = $1",
    )
    .bind(late_session_id.to_string())
    .fetch_one(db.pool())
    .await?;
    assert_eq!(late_row.get::<String, _>("first_hop_threat_level"), "high");
    assert!(late_row.get::<bool, _>("dangerous_forwarded"));

    let reused = db.get_verdict_by_session(downstream_session_id).await?;
    assert_eq!(
        reused.as_ref().map(|verdict| verdict.threat_level),
        Some(vigilyx_core::security::ThreatLevel::High)
    );

    // Move the chain past the settlement window. Nodes 0-2 continued to a
    // downstream hop; node 3 has no next-hop evidence, so it is unconfirmed,
    // not a vendor block.
    sqlx::query(
        "UPDATE email_delivery_chains SET last_seen_at = (NOW() - INTERVAL '1 minute')::TEXT WHERE chain_id = $1",
    )
    .bind(first.chain_id.to_string())
    .execute(db.pool())
    .await?;
    let stats = db.get_security_stats().await?;
    assert_eq!(stats.first_hop_dangerous_total, 1);
    assert_eq!(stats.dangerous_forwarded_total, 1);
    let terminal_observation = stats
        .delivery_node_comparisons
        .iter()
        .find(|node| node.server_ips.iter().any(|ip| ip == "10.0.0.40"))
        .context("automatic delivery node comparison should include the terminal observation")?;
    assert_eq!(terminal_observation.vendor_blocked_total, 0);
    assert_eq!(terminal_observation.vendor_unconfirmed_total, 1);
    assert_eq!(terminal_observation.both_threat_total, 0);

    sqlx::query("DELETE FROM security_verdicts WHERE session_id IN ($1, $2, $3, $4)")
        .bind(first_session_id.to_string())
        .bind(downstream_session_id.to_string())
        .bind(third_session_id.to_string())
        .bind(late_session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = $1")
        .bind(first.chain_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = $1")
        .bind(first.chain_id.to_string())
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn delivery_lineage_does_not_reuse_verdict_for_disconnected_same_identity() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);
    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let fingerprint = format!("integration-disconnected-{}", Uuid::new_v4().simple());
    let first_id = Uuid::new_v4();
    let unrelated_id = Uuid::new_v4();
    let observed_at = Utc::now() - Duration::minutes(1);

    let first = db
        .register_email_delivery_hop(
            &fingerprint,
            first_id,
            "198.51.100.10",
            "10.0.0.10",
            observed_at,
        )
        .await?;
    let unrelated = db
        .register_email_delivery_hop(
            &fingerprint,
            unrelated_id,
            "203.0.113.77",
            "10.0.0.10",
            observed_at + Duration::seconds(1),
        )
        .await?;
    assert!(first.is_first_hop);
    assert!(unrelated.is_first_hop);
    assert_ne!(first.chain_id, unrelated.chain_id);

    sqlx::query("DELETE FROM email_delivery_hops WHERE session_id IN ($1, $2)")
        .bind(first_id.to_string())
        .bind(unrelated_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE fingerprint = $1")
        .bind(&fingerprint)
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn delivery_lineage_reorders_out_of_order_arrivals_by_smtp_topology() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);
    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let fingerprint = format!("integration-topology-{}", Uuid::new_v4().simple());
    let gateway_1 = Uuid::new_v4();
    let gateway_2 = Uuid::new_v4();
    let terminal = Uuid::new_v4();
    let observed_at = Utc::now() - Duration::minutes(2);

    let terminal_registration = db
        .register_email_delivery_hop(
            &fingerprint,
            terminal,
            "192.0.2.41",
            "198.51.100.68",
            observed_at,
        )
        .await?;
    assert!(terminal_registration.is_first_hop);

    db.register_email_delivery_hop(
        &fingerprint,
        gateway_2,
        "192.0.2.40",
        "192.0.2.41",
        observed_at + Duration::seconds(5),
    )
    .await?;
    let first_registration = db
        .register_email_delivery_hop(
            &fingerprint,
            gateway_1,
            "198.51.100.8",
            "192.0.2.40",
            observed_at + Duration::seconds(40),
        )
        .await?;

    assert!(first_registration.is_first_hop);
    assert_eq!(first_registration.hop_index, 0);
    assert_eq!(first_registration.first_session_id, gateway_1);

    let rows = sqlx::query(
        "SELECT session_id, server_ip, hop_index FROM email_delivery_hops \
         WHERE chain_id = $1 ORDER BY hop_index",
    )
    .bind(first_registration.chain_id.to_string())
    .fetch_all(db.pool())
    .await?;
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows[0].get::<String, _>("session_id"),
        gateway_1.to_string()
    );
    assert_eq!(
        rows[1].get::<String, _>("session_id"),
        gateway_2.to_string()
    );
    assert_eq!(rows[2].get::<String, _>("session_id"), terminal.to_string());
    assert_eq!(rows[0].get::<String, _>("server_ip"), "192.0.2.40");
    assert_eq!(rows[1].get::<String, _>("server_ip"), "192.0.2.41");
    assert_eq!(rows[2].get::<String, _>("server_ip"), "198.51.100.68");

    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = $1")
        .bind(first_registration.chain_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = $1")
        .bind(first_registration.chain_id.to_string())
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn delivery_node_pass_uses_outbound_edge_without_matching_upstream_hop() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);

    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let suffix = Uuid::new_v4().simple().to_string();
    let node_ip = format!("2001:db8:{}::40", &suffix[..4]);
    let next_ip = format!("2001:db8:{}::41", &suffix[..4]);
    let terminal_ip = format!("2001:db8:{}::68", &suffix[..4]);
    let observed_at = Utc::now() - Duration::minutes(2);
    let observed_at_text = observed_at.to_rfc3339();

    let seed_chain = Uuid::new_v4().to_string();
    let seed_session = Uuid::new_v4().to_string();
    let output_chain = Uuid::new_v4().to_string();
    let output_session = Uuid::new_v4().to_string();

    for (session_id, client_ip, server_ip, subject) in [
        (
            &seed_session,
            "198.51.100.20",
            node_ip.as_str(),
            "gateway-input-observation",
        ),
        (
            &output_session,
            node_ip.as_str(),
            next_ip.as_str(),
            "gateway-output-proof",
        ),
    ] {
        sqlx::query(
            "INSERT INTO sessions \
             (id, protocol, client_ip, client_port, server_ip, server_port, started_at, status, \
              mail_from, rcpt_to, subject, content, message_id) \
             VALUES ($1, 'SMTP', $2, 2525, $3, 25, $4, 'Completed', \
                     'sender@example.test', '[\"recipient@example.test\"]', $5, \
                     '{\"smtp_dialog\":[]}'::jsonb, $6)",
        )
        .bind(session_id)
        .bind(client_ip)
        .bind(server_ip)
        .bind(&observed_at_text)
        .bind(subject)
        .bind(format!("<{session_id}@example.test>"))
        .execute(db.pool())
        .await?;
    }

    for (chain_id, session_id, server_ip, threat_level) in [
        (&seed_chain, &seed_session, &node_ip, "safe"),
        (&output_chain, &output_session, &next_ip, "high"),
    ] {
        sqlx::query(
            "INSERT INTO email_delivery_chains \
             (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
              first_verdict_id, first_threat_level, last_seen_at, hop_count, \
              dangerous_forwarded_count, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $4, 1, 0, $4, $4)",
        )
        .bind(chain_id)
        .bind(format!("outbound-proof-{chain_id}"))
        .bind(session_id)
        .bind(&observed_at_text)
        .bind(server_ip)
        .bind(Uuid::new_v4().to_string())
        .bind(threat_level)
        .execute(db.pool())
        .await?;
    }

    for (session_id, chain_id, client_ip, server_ip, threat_level) in [
        (
            &seed_session,
            &seed_chain,
            "198.51.100.20",
            node_ip.as_str(),
            "safe",
        ),
        (
            &output_session,
            &output_chain,
            node_ip.as_str(),
            next_ip.as_str(),
            "high",
        ),
    ] {
        sqlx::query(
            "INSERT INTO email_delivery_hops \
             (session_id, chain_id, fingerprint, first_session_id, hop_index, client_ip, server_ip, \
              observed_at, first_hop_threat_level, verdict_origin, dangerous_forwarded) \
             VALUES ($1, $2, $3, $1, 0, $4, $5, $6, $7, 'native', FALSE)",
        )
        .bind(session_id)
        .bind(chain_id)
        .bind(format!("outbound-proof-{chain_id}"))
        .bind(client_ip)
        .bind(server_ip)
        .bind(&observed_at_text)
        .bind(threat_level)
        .execute(db.pool())
        .await?;
    }

    let stats = db
        .get_security_stats_with_terminal_mail_servers_for_test(vec![terminal_ip.clone()])
        .await?;
    let node = stats
        .delivery_node_comparisons
        .iter()
        .find(|candidate| candidate.server_ips.iter().any(|ip| ip == &node_ip))
        .context("outbound client gateway must appear as a comparison node")?;
    assert_eq!(node.comparable_total, 2);
    assert_eq!(node.vendor_passed_total, 1);
    assert_eq!(node.vendor_blocked_total, 1);
    assert_eq!(node.vendor_unconfirmed_total, 0);
    assert_eq!(node.vigilyx_only_threat_total, 1);
    assert_eq!(node.vendor_only_threat_total, 1);
    assert_eq!(stats.dangerous_forwarded_total, 1);

    let (items, total) = db
        .list_delivery_risk_details_with_terminal_mail_servers_for_test(
            DeliveryRiskDetailKind::NodeRejected,
            Some(&node_ip),
            &stats.delivery_stats_as_of,
            10,
            0,
            vec![terminal_ip.clone()],
        )
        .await?;
    assert_eq!(total, 1);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].session_id, seed_session);
    assert_eq!(items[0].action_evidence, "path_termination");

    let (items, total) = db
        .list_delivery_risk_details_with_terminal_mail_servers_for_test(
            DeliveryRiskDetailKind::NodeForwarded,
            Some(&node_ip),
            &stats.delivery_stats_as_of,
            10,
            0,
            vec![],
        )
        .await?;
    assert_eq!(total, 1);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].session_id, output_session);
    assert_eq!(items[0].action_evidence, "forwarded");

    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = ANY($1)")
        .bind(vec![&seed_chain, &output_chain])
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = ANY($1)")
        .bind(vec![&seed_chain, &output_chain])
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
        .bind(vec![&seed_session, &output_session])
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn delivery_node_observed_pass_wins_over_an_earlier_security_rejection() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);

    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let suffix = Uuid::new_v4().simple().to_string();
    let node_ip = format!("2001:db8:{}::40", &suffix[..4]);
    let next_ip = format!("2001:db8:{}::41", &suffix[..4]);
    let chain_id = Uuid::new_v4().to_string();
    let input_session = Uuid::new_v4().to_string();
    let output_session = Uuid::new_v4().to_string();
    let observed_at = Utc::now() - Duration::minutes(2);
    let observed_at_text = observed_at.to_rfc3339();
    let output_at_text = (observed_at + Duration::seconds(1)).to_rfc3339();

    for (session_id, client_ip, server_ip, started_at, content) in [
        (
            &input_session,
            "198.51.100.40",
            node_ip.as_str(),
            &observed_at_text,
            r#"{"smtp_dialog":[{"direction":"inbound","command":"550 5.7.1 SECURITY_POLICY_REJECTED"}]}"#,
        ),
        (
            &output_session,
            node_ip.as_str(),
            next_ip.as_str(),
            &output_at_text,
            r#"{"smtp_dialog":[]}"#,
        ),
    ] {
        sqlx::query(
            "INSERT INTO sessions \
             (id, protocol, client_ip, client_port, server_ip, server_port, started_at, status, \
              mail_from, rcpt_to, subject, content, message_id) \
             VALUES ($1, 'SMTP', $2, 2525, $3, 25, $4, 'Completed', \
                     'sender@example.test', '[\"recipient@example.test\"]', \
                     'pass-wins-over-rejection', $5::jsonb, $6)",
        )
        .bind(session_id)
        .bind(client_ip)
        .bind(server_ip)
        .bind(started_at)
        .bind(content)
        .bind(format!("<{session_id}@example.test>"))
        .execute(db.pool())
        .await?;
    }

    sqlx::query(
        "INSERT INTO email_delivery_chains \
         (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
          first_verdict_id, first_threat_level, last_seen_at, hop_count, \
          dangerous_forwarded_count, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'safe', $7, 2, 0, $4, $7)",
    )
    .bind(&chain_id)
    .bind(format!("pass-wins-{suffix}"))
    .bind(&input_session)
    .bind(&observed_at_text)
    .bind(&node_ip)
    .bind(Uuid::new_v4().to_string())
    .bind(&output_at_text)
    .execute(db.pool())
    .await?;

    for (session_id, hop_index, client_ip, server_ip, hop_at, smtp_security_rejected) in [
        (
            &input_session,
            0,
            "198.51.100.40",
            node_ip.as_str(),
            &observed_at_text,
            true,
        ),
        (
            &output_session,
            1,
            node_ip.as_str(),
            next_ip.as_str(),
            &output_at_text,
            false,
        ),
    ] {
        sqlx::query(
            "INSERT INTO email_delivery_hops \
             (session_id, chain_id, fingerprint, first_session_id, hop_index, client_ip, server_ip, \
              observed_at, first_hop_threat_level, verdict_origin, dangerous_forwarded, \
              smtp_security_rejected, smtp_security_rejection_metadata_ready) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'safe', $9, FALSE, $10, TRUE)",
        )
        .bind(session_id)
        .bind(&chain_id)
        .bind(format!("pass-wins-{suffix}"))
        .bind(&input_session)
        .bind(hop_index)
        .bind(client_ip)
        .bind(server_ip)
        .bind(hop_at)
        .bind(if hop_index == 0 {
            "native"
        } else {
            "reused_first_hop"
        })
        .bind(smtp_security_rejected)
        .execute(db.pool())
        .await?;
    }

    let stats = db
        .get_security_stats_with_terminal_mail_servers_for_test(vec![])
        .await?;
    let node = stats
        .delivery_node_comparisons
        .iter()
        .find(|candidate| candidate.server_ips.iter().any(|ip| ip == &node_ip))
        .context("conflicting-action node must appear in comparison")?;
    assert_eq!(node.comparable_total, 1);
    assert_eq!(node.vendor_passed_total, 1);
    assert_eq!(node.vendor_blocked_total, 0);
    assert_eq!(node.vendor_only_threat_total, 0);
    assert_eq!(
        node.comparable_total - node.vigilyx_only_threat_total - node.vendor_only_threat_total,
        1
    );

    let (_, rejected_total) = db
        .list_delivery_risk_details_with_terminal_mail_servers_for_test(
            DeliveryRiskDetailKind::NodeRejected,
            Some(&node_ip),
            &stats.delivery_stats_as_of,
            10,
            0,
            vec![],
        )
        .await?;
    assert_eq!(rejected_total, 0);
    let (forwarded_items, forwarded_total) = db
        .list_delivery_risk_details_with_terminal_mail_servers_for_test(
            DeliveryRiskDetailKind::NodeForwarded,
            Some(&node_ip),
            &stats.delivery_stats_as_of,
            10,
            0,
            vec![],
        )
        .await?;
    assert_eq!(forwarded_total, 1);
    assert_eq!(forwarded_items[0].session_id, output_session);

    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = $1")
        .bind(&chain_id)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = $1")
        .bind(&chain_id)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
        .bind(vec![&input_session, &output_session])
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn security_stats_use_one_snapshot_across_totals_and_node_comparisons() -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    // The base migrator currently uses a session-level advisory lock. Close
    // its disposable test pool so that lock cannot survive on an idle pooled
    // connection and block the security migrator below.
    base_db.pool().close().await;
    drop(base_db);

    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let suffix = Uuid::new_v4().simple().to_string();
    let chain_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();
    let fingerprint = format!("snapshot-delivery-{suffix}");
    let server_ip = "203.0.113.199";
    let writer_db = db.clone();
    let writer_chain_id = chain_id.clone();
    let writer_session_id = session_id.clone();
    let writer_fingerprint = fingerprint.clone();

    let snapshot_before_insert = db
        .get_security_stats_with_interquery_hook_for_test(move || async move {
            let observed_at = (Utc::now() - Duration::minutes(1)).to_rfc3339();
            sqlx::query(
                "INSERT INTO email_delivery_chains \
                 (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
                  first_verdict_id, first_threat_level, last_seen_at, hop_count, \
                  dangerous_forwarded_count, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'high', $4, 1, 0, $4, $4)",
            )
            .bind(&writer_chain_id)
            .bind(&writer_fingerprint)
            .bind(&writer_session_id)
            .bind(&observed_at)
            .bind(server_ip)
            .bind(Uuid::new_v4().to_string())
            .execute(writer_db.pool())
            .await?;
            sqlx::query(
                "INSERT INTO email_delivery_hops \
                 (session_id, chain_id, fingerprint, first_session_id, hop_index, server_ip, \
                  observed_at, first_hop_threat_level, verdict_origin, dangerous_forwarded) \
                 VALUES ($1, $2, $3, $1, 0, $4, $5, 'high', 'native', FALSE)",
            )
            .bind(&writer_session_id)
            .bind(&writer_chain_id)
            .bind(&writer_fingerprint)
            .bind(server_ip)
            .bind(&observed_at)
            .execute(writer_db.pool())
            .await?;
            Ok(())
        })
        .await?;

    assert!(
        snapshot_before_insert
            .delivery_node_comparisons
            .iter()
            .all(|node| !node.server_ips.iter().any(|ip| ip == server_ip)),
        "a row committed between the two statements must not leak into the older snapshot"
    );

    let next_snapshot = db
        .get_security_stats_with_interquery_hook_for_test(|| async { Ok(()) })
        .await?;
    assert!(
        next_snapshot
            .delivery_node_comparisons
            .iter()
            .any(|node| node.server_ips.iter().any(|ip| ip == server_ip)),
        "the following snapshot must observe the committed delivery row"
    );

    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = $1")
        .bind(&chain_id)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = $1")
        .bind(&chain_id)
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn delivery_risk_detail_categories_reconcile_with_the_stats_snapshot() -> Result<()> {
    assert_delivery_risk_categories_at_age(Duration::minutes(2)).await?;
    assert_delivery_risk_categories_at_age(Duration::days(400)).await
}

async fn assert_delivery_risk_categories_at_age(age: Duration) -> Result<()> {
    let database_url = test_database_url()?;
    let base_db = VigilDb::new(&database_url).await?;
    base_db.init().await?;
    base_db.pool().close().await;
    drop(base_db);

    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;

    let suffix = Uuid::new_v4().simple().to_string();
    let node_ip = format!("2001:db8:{}::41", &suffix[..4]);
    let downstream_ip = format!("2001:db8:{}::68", &suffix[..4]);
    let observed_at = Utc::now() - age;
    let observed_at_text = observed_at.to_rfc3339();
    let downstream_at_text = (observed_at + Duration::seconds(1)).to_rfc3339();
    let normal_content = r#"{"smtp_dialog":[]}"#;
    let rejected_content = r#"{"smtp_dialog":[{"direction":"inbound","command":"550 5.7.1 SECURITY_POLICY_REJECTED"}]}"#;

    let forwarded_chain = Uuid::new_v4().to_string();
    let forwarded_first = Uuid::new_v4().to_string();
    let forwarded_next = Uuid::new_v4().to_string();
    let safe_forwarded_chain = Uuid::new_v4().to_string();
    let safe_forwarded_first = Uuid::new_v4().to_string();
    let safe_forwarded_next = Uuid::new_v4().to_string();
    let aligned_chain = Uuid::new_v4().to_string();
    let aligned_session = Uuid::new_v4().to_string();
    let different_chain = Uuid::new_v4().to_string();
    let different_session = Uuid::new_v4().to_string();
    let unconfirmed_chain = Uuid::new_v4().to_string();
    let unconfirmed_session = Uuid::new_v4().to_string();
    let repeated_node_chain = Uuid::new_v4().to_string();
    let repeated_node_first = Uuid::new_v4().to_string();
    let repeated_node_next = Uuid::new_v4().to_string();

    for (session_id, server_ip, subject, content, started_at) in [
        (
            &forwarded_first,
            &node_ip,
            "forwarded-risk",
            normal_content,
            &observed_at_text,
        ),
        (
            &forwarded_next,
            &downstream_ip,
            "forwarded-risk",
            normal_content,
            &downstream_at_text,
        ),
        (
            &safe_forwarded_first,
            &node_ip,
            "forwarded-safe",
            normal_content,
            &observed_at_text,
        ),
        (
            &safe_forwarded_next,
            &downstream_ip,
            "forwarded-safe",
            normal_content,
            &downstream_at_text,
        ),
        (
            &aligned_session,
            &node_ip,
            "aligned-risk",
            rejected_content,
            &observed_at_text,
        ),
        (
            &different_session,
            &node_ip,
            "different-safe",
            rejected_content,
            &observed_at_text,
        ),
        (
            &unconfirmed_session,
            &node_ip,
            "unconfirmed-safe",
            normal_content,
            &observed_at_text,
        ),
        (
            &repeated_node_first,
            &node_ip,
            "same-node-retry",
            normal_content,
            &observed_at_text,
        ),
        (
            &repeated_node_next,
            &node_ip,
            "same-node-retry",
            normal_content,
            &downstream_at_text,
        ),
    ] {
        sqlx::query(
            "INSERT INTO sessions \
             (id, protocol, client_ip, client_port, server_ip, server_port, started_at, status, \
              mail_from, rcpt_to, subject, content, message_id) \
             VALUES ($1, 'SMTP', '198.51.100.10', 2525, $2, 25, $3, 'Completed', \
                     'sender@example.test', '[\"recipient@example.test\"]', $4, $5::jsonb, $6)",
        )
        .bind(session_id)
        .bind(server_ip)
        .bind(started_at)
        .bind(subject)
        .bind(content)
        .bind(format!("<{session_id}@example.test>"))
        .execute(db.pool())
        .await?;
    }

    for (chain_id, first_session_id, threat_level, last_seen_at, hop_count) in [
        (
            &forwarded_chain,
            &forwarded_first,
            "high",
            &downstream_at_text,
            2,
        ),
        (
            &safe_forwarded_chain,
            &safe_forwarded_first,
            "safe",
            &downstream_at_text,
            2,
        ),
        (
            &aligned_chain,
            &aligned_session,
            "high",
            &observed_at_text,
            1,
        ),
        (
            &different_chain,
            &different_session,
            "safe",
            &observed_at_text,
            1,
        ),
        (
            &unconfirmed_chain,
            &unconfirmed_session,
            "safe",
            &observed_at_text,
            1,
        ),
        (
            &repeated_node_chain,
            &repeated_node_first,
            "high",
            &downstream_at_text,
            2,
        ),
    ] {
        sqlx::query(
            "INSERT INTO email_delivery_chains \
             (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
              first_verdict_id, first_threat_level, last_seen_at, hop_count, \
              dangerous_forwarded_count, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $4, $8)",
        )
        .bind(chain_id)
        .bind(format!("detail-{chain_id}"))
        .bind(first_session_id)
        .bind(&observed_at_text)
        .bind(&node_ip)
        .bind(Uuid::new_v4().to_string())
        .bind(threat_level)
        .bind(last_seen_at)
        .bind(hop_count)
        .execute(db.pool())
        .await?;
    }

    for (
        session_id,
        chain_id,
        first_session_id,
        hop_index,
        server_ip,
        hop_at,
        threat_level,
        origin,
    ) in [
        (
            &forwarded_first,
            &forwarded_chain,
            &forwarded_first,
            0,
            &node_ip,
            &observed_at_text,
            "high",
            "native",
        ),
        (
            &forwarded_next,
            &forwarded_chain,
            &forwarded_first,
            1,
            &downstream_ip,
            &downstream_at_text,
            "high",
            "reused_first_hop",
        ),
        (
            &safe_forwarded_first,
            &safe_forwarded_chain,
            &safe_forwarded_first,
            0,
            &node_ip,
            &observed_at_text,
            "safe",
            "native",
        ),
        (
            &safe_forwarded_next,
            &safe_forwarded_chain,
            &safe_forwarded_first,
            1,
            &downstream_ip,
            &downstream_at_text,
            "safe",
            "reused_first_hop",
        ),
        (
            &aligned_session,
            &aligned_chain,
            &aligned_session,
            0,
            &node_ip,
            &observed_at_text,
            "high",
            "native",
        ),
        (
            &different_session,
            &different_chain,
            &different_session,
            0,
            &node_ip,
            &observed_at_text,
            "safe",
            "native",
        ),
        (
            &unconfirmed_session,
            &unconfirmed_chain,
            &unconfirmed_session,
            0,
            &node_ip,
            &observed_at_text,
            "safe",
            "native",
        ),
        (
            &repeated_node_first,
            &repeated_node_chain,
            &repeated_node_first,
            0,
            &node_ip,
            &observed_at_text,
            "high",
            "native",
        ),
        (
            &repeated_node_next,
            &repeated_node_chain,
            &repeated_node_first,
            1,
            &node_ip,
            &downstream_at_text,
            "high",
            "reused_first_hop",
        ),
    ] {
        let client_ip = if server_ip == &downstream_ip {
            node_ip.as_str()
        } else {
            "198.51.100.10"
        };
        let smtp_security_rejected =
            session_id == &aligned_session || session_id == &different_session;
        sqlx::query(
            "INSERT INTO email_delivery_hops \
             (session_id, chain_id, fingerprint, first_session_id, hop_index, client_ip, server_ip, \
              observed_at, first_hop_threat_level, verdict_origin, dangerous_forwarded, \
              smtp_security_rejected, smtp_security_rejection_metadata_ready) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, TRUE)",
        )
        .bind(session_id)
        .bind(chain_id)
        .bind(format!("detail-{chain_id}"))
        .bind(first_session_id)
        .bind(hop_index)
        .bind(client_ip)
        .bind(server_ip)
        .bind(hop_at)
        .bind(threat_level)
        .bind(origin)
        .bind(hop_index > 0 && threat_level == "high")
        .bind(smtp_security_rejected)
        .execute(db.pool())
        .await?;
    }

    let stats = db
        .get_security_stats_with_terminal_mail_servers_for_test(vec![downstream_ip.clone()])
        .await?;
    assert_eq!(stats.delivery_stats_scope, "all_history");
    let node = stats
        .delivery_node_comparisons
        .iter()
        .find(|candidate| candidate.server_ips.iter().any(|ip| ip == &node_ip))
        .context("fixture node must appear in delivery comparison")?;
    assert_eq!(node.comparable_total, 6);
    assert_eq!(node.vendor_blocked_total, 4);
    assert_eq!(node.vendor_passed_total, 2);
    assert_eq!(node.terminal_delivered_total, 2);
    assert_eq!(node.vendor_unconfirmed_total, 0);
    assert_eq!(node.vigilyx_risky_total, 3);
    assert_eq!(node.both_threat_total, 2);
    assert_eq!(node.vigilyx_only_threat_total, 1);
    assert_eq!(node.vendor_only_threat_total, 2);
    assert_eq!(stats.first_hop_dangerous_total, 3);
    assert_eq!(stats.dangerous_forwarded_total, 1);

    for (kind, expected) in [
        (DeliveryRiskDetailKind::NodeSettled, node.comparable_total),
        (DeliveryRiskDetailKind::NodeRisky, node.vigilyx_risky_total),
        (
            DeliveryRiskDetailKind::NodeRejected,
            node.vendor_blocked_total,
        ),
        (
            DeliveryRiskDetailKind::NodeForwarded,
            node.vendor_passed_total,
        ),
        (
            DeliveryRiskDetailKind::TerminalDelivered,
            node.terminal_delivered_total,
        ),
        (
            DeliveryRiskDetailKind::Agreement,
            node.comparable_total - node.vigilyx_only_threat_total - node.vendor_only_threat_total,
        ),
        (
            DeliveryRiskDetailKind::Disagreement,
            node.vigilyx_only_threat_total + node.vendor_only_threat_total,
        ),
        (DeliveryRiskDetailKind::BothThreat, node.both_threat_total),
        (
            DeliveryRiskDetailKind::VigilyxOnly,
            node.vigilyx_only_threat_total,
        ),
        (
            DeliveryRiskDetailKind::VendorOnly,
            node.vendor_only_threat_total,
        ),
        (
            DeliveryRiskDetailKind::SafePassed,
            node.vendor_passed_total - node.vigilyx_only_threat_total,
        ),
        (
            DeliveryRiskDetailKind::Unconfirmed,
            node.vendor_unconfirmed_total,
        ),
    ] {
        let (items, total) = db
            .list_delivery_risk_details_with_terminal_mail_servers_for_test(
                kind,
                Some(&node_ip),
                &stats.delivery_stats_as_of,
                100,
                0,
                vec![downstream_ip.clone()],
            )
            .await?;
        let (_, before_fixture) = db
            .list_delivery_risk_details_with_terminal_mail_servers_for_test(
                kind,
                Some(&node_ip),
                &(observed_at - Duration::seconds(1)).to_rfc3339(),
                100,
                0,
                vec![downstream_ip.clone()],
            )
            .await?;
        assert_eq!(
            before_fixture,
            0,
            "future rows must stay outside {} snapshot",
            kind.as_str()
        );
        assert_eq!(total, expected, "{} must reconcile", kind.as_str());
        assert_eq!(items.len() as u64, expected, "{} item count", kind.as_str());
    }

    sqlx::query("DELETE FROM email_delivery_hops WHERE chain_id = ANY($1)")
        .bind(vec![
            &forwarded_chain,
            &safe_forwarded_chain,
            &aligned_chain,
            &different_chain,
            &unconfirmed_chain,
            &repeated_node_chain,
        ])
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains WHERE chain_id = ANY($1)")
        .bind(vec![
            &forwarded_chain,
            &safe_forwarded_chain,
            &aligned_chain,
            &different_chain,
            &unconfirmed_chain,
            &repeated_node_chain,
        ])
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
        .bind(vec![
            &forwarded_first,
            &forwarded_next,
            &safe_forwarded_first,
            &safe_forwarded_next,
            &aligned_session,
            &different_session,
            &unconfirmed_session,
            &repeated_node_first,
            &repeated_node_next,
        ])
        .execute(db.pool())
        .await?;

    Ok(())
}

#[tokio::test]
async fn bounce_reports_keep_source_identity_and_link_only_their_report_sessions() -> Result<()> {
    use vigilyx_core::security::{ThreatScene, ThreatSceneStatus, ThreatSceneType};
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.pool().close().await;
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init_security_tables().await?;
    let sessions = [
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
    ];
    let now = Utc::now();
    for id in &sessions {
        sqlx::query("INSERT INTO sessions (id, protocol, client_ip, client_port, server_ip, server_port, started_at, status, mail_from, rcpt_to, subject, content) VALUES ($1, 'SMTP', '192.0.2.41', 2525, '198.51.100.25', 25, $2, 'Completed', 'notifier@appliance.example', '[]', 'report', '{}'::jsonb)")
            .bind(id).bind(now.to_rfc3339()).execute(db.pool()).await?;
    }
    let actor = format!("source-{}.example", Uuid::new_v4().simple());
    let mut scene = ThreatScene {
        id: Uuid::new_v4(),
        scene_type: ThreatSceneType::BounceHarvest,
        actor: actor.clone(),
        actor_type: "domain".into(),
        target_domain: Some("corp.example".into()),
        time_window_start: now - Duration::minutes(1),
        time_window_end: now,
        email_count: 0,
        unique_recipients: 2,
        bounce_count: 2,
        sample_subjects: vec![],
        sample_recipients: vec![],
        threat_level: ThreatLevel::Low,
        status: ThreatSceneStatus::Active,
        auto_blocked: false,
        ioc_id: None,
        details: serde_json::json!({"source":"reported_alert", "source_session_ids": &sessions[..2]}),
        created_at: now,
        updated_at: now,
    };
    db.upsert_threat_scene(&scene).await?;
    let reported_id = scene.id;
    scene.id = Uuid::new_v4();
    scene.details = serde_json::json!({"source":"network_bounce"});
    scene.auto_blocked = true;
    db.upsert_threat_scene(&scene).await?;
    let reported = db
        .find_active_bounce_scene(&actor, "corp.example", "reported_alert")
        .await?
        .context("reported scene must exist")?;
    assert_eq!(reported.id, reported_id);
    assert!(!reported.auto_blocked);
    assert_eq!(
        db.find_active_bounce_scene(&actor, "corp.example", "network_bounce")
            .await?
            .context("network scene must exist")?
            .id,
        scene.id
    );
    let emails = db.get_scene_emails(&reported, 100).await?;
    assert_eq!(emails.len(), 2);
    assert!(
        emails
            .iter()
            .all(|email| sessions[..2].iter().any(|id| email["session_id"] == *id))
    );
    sqlx::query("DELETE FROM security_threat_scenes WHERE actor = $1")
        .bind(&actor)
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
        .bind(sessions.to_vec())
        .execute(db.pool())
        .await?;
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
            let request_id = Uuid::new_v4().to_string();
            let claimed = worker_db
                .quarantine_claim_release(&worker_id, &request_id)
                .await?;
            Ok::<_, anyhow::Error>((request_id, claimed))
        }));
    }

    let mut winners = 0;
    let mut winning_request_id = None;
    let mut winning_session_id = None;
    for task in tasks {
        let (request_id, claimed) = task.await??;
        if let Some((_raw_eml, entry)) = claimed {
            winners += 1;
            winning_request_id = Some(request_id);
            winning_session_id = Some(entry.session_id);
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
    let winning_request_id = winning_request_id.context("one claim must win")?;
    let winning_session_id = winning_session_id.context("winning claim has session id")?;
    let verdict_id = Uuid::new_v4().to_string();
    let unrelated_request_id = Uuid::new_v4().to_string();
    assert!(
        !db.quarantine_complete_release_rescan(
            &concurrent_id,
            &unrelated_request_id,
            &winning_session_id,
            &Uuid::new_v4().to_string(),
            "safe",
            &"f".repeat(64),
        )
        .await?,
        "an unrelated rescan request must not satisfy the release claim"
    );
    assert!(
        db.quarantine_complete_release_rescan(
            &concurrent_id,
            &winning_request_id,
            &winning_session_id,
            &verdict_id,
            "safe",
            &"a".repeat(64),
        )
        .await?
    );
    let correlated = db
        .quarantine_release_rescan_result(&concurrent_id, &winning_request_id)
        .await?
        .context("correlated release result")?;
    assert_eq!(correlated.verdict_id, verdict_id);
    assert_eq!(correlated.content_sha256, "a".repeat(64));
    assert!(
        db.quarantine_release_rescan_result(&concurrent_id, &unrelated_request_id)
            .await?
            .is_none()
    );
    assert!(
        !db.quarantine_finalize_release(&concurrent_id, &unrelated_request_id, "racing-admin",)
            .await?
    );
    assert!(
        db.quarantine_finalize_release(&concurrent_id, &winning_request_id, "integration-admin",)
            .await?
    );
    assert!(
        !db.quarantine_finalize_release(&concurrent_id, &winning_request_id, "duplicate-admin",)
            .await?
    );
    assert_eq!(
        db.quarantine_status(&concurrent_id).await?.as_deref(),
        Some("released")
    );

    // Model the post-relay partial failure: the message has been claimed and the
    // downstream accepted it, but the application pool dies before finalization.
    let finalize_failure_id = store_message(&db, "finalize-failure").await?;
    let finalize_request_id = Uuid::new_v4().to_string();
    let (_raw_eml, finalize_entry) = db
        .quarantine_claim_release(&finalize_failure_id, &finalize_request_id)
        .await?
        .context("finalize-failure claim")?;
    assert!(
        db.quarantine_complete_release_rescan(
            &finalize_failure_id,
            &finalize_request_id,
            &finalize_entry.session_id,
            &Uuid::new_v4().to_string(),
            "safe",
            &"b".repeat(64),
        )
        .await?
    );
    db.pool().close().await;
    assert!(
        db.quarantine_finalize_release(
            &finalize_failure_id,
            &finalize_request_id,
            "integration-admin",
        )
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

fn make_alert(
    session_id: Uuid,
    level: AlertLevel,
    created_at: chrono::DateTime<Utc>,
) -> AlertRecord {
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

fn make_verdict(
    session_id: Uuid,
    verdict_id: Uuid,
    created_at: chrono::DateTime<Utc>,
) -> SecurityVerdict {
    SecurityVerdict {
        inspection_coverage: Default::default(),
        coverage_reasons: vec![],
        id: verdict_id,
        session_id,
        threat_level: ThreatLevel::High,
        threat_type: None,
        classification: None,
        confidence: 0.9,
        categories: vec!["integration_test".to_string()],
        summary: "integration-test verdict".to_string(),
        pillar_scores: HashMap::new(),
        modules_run: 0,
        modules_flagged: 0,
        total_duration_ms: 1,
        created_at,
        fusion_details: None,
    }
}

#[tokio::test]
async fn real_verdict_coverage_roundtrip_and_reuse_remain_independent_of_threat() -> Result<()> {
    use vigilyx_core::security::InspectionCoverage;
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let mut verdict = make_verdict(first_id, Uuid::new_v4(), Utc::now());
    verdict.threat_level = ThreatLevel::Safe;
    verdict.inspection_coverage = InspectionCoverage::Limited;
    verdict.coverage_reasons = vec!["semantic_inspection_limited".to_string()];
    db.insert_verdict(&verdict).await?;
    let stored = db
        .get_verdict_by_session(first_id)
        .await?
        .expect("stored verdict");
    assert_eq!(stored.threat_level, ThreatLevel::Safe);
    assert_eq!(stored.inspection_coverage, InspectionCoverage::Limited);
    assert_eq!(stored.coverage_reasons, verdict.coverage_reasons);
    assert!(
        db.insert_reused_first_hop_verdict(second_id, first_id)
            .await?
    );
    let reused = db
        .get_verdict_by_session(second_id)
        .await?
        .expect("reused verdict");
    assert_eq!(reused.threat_level, ThreatLevel::Safe);
    assert_eq!(reused.inspection_coverage, InspectionCoverage::Limited);
    assert_eq!(reused.coverage_reasons, verdict.coverage_reasons);
    verdict.inspection_coverage = InspectionCoverage::Complete;
    verdict.coverage_reasons.clear();
    db.insert_verdict(&verdict).await?;
    let rescanned = db
        .get_verdict_by_session(first_id)
        .await?
        .expect("rescanned verdict");
    assert_eq!(rescanned.inspection_coverage, InspectionCoverage::Complete);
    assert!(rescanned.coverage_reasons.is_empty());
    sqlx::query("DELETE FROM security_verdicts WHERE session_id = ANY($1)")
        .bind(vec![first_id.to_string(), second_id.to_string()])
        .execute(db.pool())
        .await?;
    Ok(())
}

#[tokio::test]
async fn real_verdict_rescan_rebinds_existing_and_delayed_alerts() -> Result<()> {
    // Regression: a rescan replaces the one current verdict id for a session.
    // Existing alerts and delayed post-verdict alerts must both point to the
    // replacement, otherwise the UI shows orphaned verdict references.
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let session_id = Uuid::new_v4();
    let first_verdict_id = Uuid::new_v4();
    db.insert_verdict(&make_verdict(session_id, first_verdict_id, Utc::now()))
        .await?;

    let mut existing_alert = make_alert(session_id, AlertLevel::P2, Utc::now());
    existing_alert.verdict_id = first_verdict_id;
    assert!(db.insert_alert(&existing_alert).await?);

    let current_verdict_id = Uuid::new_v4();
    db.insert_verdict(&make_verdict(session_id, current_verdict_id, Utc::now()))
        .await?;

    let stored_current_id: String =
        sqlx::query_scalar("SELECT id FROM security_verdicts WHERE session_id = $1")
            .bind(session_id.to_string())
            .fetch_one(db.pool())
            .await?;
    assert_eq!(stored_current_id, current_verdict_id.to_string());

    let linked_ids: Vec<String> = sqlx::query_scalar(
        "SELECT verdict_id FROM security_alerts WHERE session_id = $1 ORDER BY created_at",
    )
    .bind(session_id.to_string())
    .fetch_all(db.pool())
    .await?;
    assert_eq!(linked_ids, vec![current_verdict_id.to_string()]);

    let mut delayed_alert = make_alert(session_id, AlertLevel::P1, Utc::now());
    delayed_alert.verdict_id = Uuid::new_v4();
    assert!(db.insert_alert(&delayed_alert).await?);

    let linked_ids: Vec<String> = sqlx::query_scalar(
        "SELECT verdict_id FROM security_alerts WHERE session_id = $1 ORDER BY created_at",
    )
    .bind(session_id.to_string())
    .fetch_all(db.pool())
    .await?;
    assert_eq!(
        linked_ids,
        vec![
            current_verdict_id.to_string(),
            current_verdict_id.to_string()
        ]
    );

    sqlx::query("DELETE FROM security_alerts WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    sqlx::query("DELETE FROM security_verdicts WHERE session_id = $1")
        .bind(session_id.to_string())
        .execute(db.pool())
        .await?;
    Ok(())
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

    // Use a separate long-lived session to exercise the time window. Inserting
    // an old alert after a current one would correctly be suppressed by that
    // already-current row and would not test window expiry.
    let window_session_id = Uuid::new_v4();
    let stale =
        Utc::now() - Duration::minutes(vigilyx_db::security::ALERT_DEDUP_WINDOW_MINUTES + 1);
    assert!(
        db.insert_alert(&make_alert(window_session_id, AlertLevel::P2, stale))
            .await?,
        "the first old alert for the window test must be stored"
    );
    assert!(
        db.insert_alert(&make_alert(window_session_id, AlertLevel::P2, Utc::now()))
            .await?,
        "after the window, the same (session, level) alert is stored again"
    );

    let session_ids = vec![session_id.to_string(), window_session_id.to_string()];
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM security_alerts WHERE session_id = ANY($1)",
    )
    .bind(&session_ids)
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
    assert_eq!(entry.direction, "outbound");

    let (_eml, entry) = db
        .quarantine_get_raw_eml(&id)
        .await?
        .context("raw eml lookup must find the entry")?;
    assert_eq!(entry.client_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(entry.direction, "outbound");

    // Claim (status -> releasing): delete must now fail with an explicit error.
    let release_request_id = Uuid::new_v4().to_string();
    let (_eml, claimed) = db
        .quarantine_claim_release(&id, &release_request_id)
        .await?
        .context("claim must succeed for a quarantined entry")?;
    assert_eq!(
        claimed.client_ip.as_deref(),
        Some("203.0.113.7"),
        "claim_release must return the stored client_ip for the release relay path"
    );
    assert_eq!(claimed.direction, "outbound");

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
    assert!(
        db.quarantine_release_reset(&id, &release_request_id)
            .await?
    );
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

#[tokio::test]
async fn real_delivery_reuse_handles_missing_chain_verdict_without_losing_source_risk() -> Result<()>
{
    let db = VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    // A verdict can be available before the chain metadata update finishes.
    // Preserve that source risk while keeping a completely unknown result
    // nullable in the level column and non-null in the boolean column.
    for (
        chain_level,
        source_level,
        previous_hop_level,
        hop_index,
        expected_level,
        expected_danger,
    ) in [
        (None, Some(ThreatLevel::High), None, 1, Some("high"), true),
        (None, None, None, 1, None, false),
        (None, Some(ThreatLevel::High), None, 0, Some("high"), false),
        (
            Some("safe"),
            Some(ThreatLevel::High),
            None,
            1,
            Some("safe"),
            false,
        ),
        (Some("high"), None, None, 1, Some("high"), true),
        (
            None,
            Some(ThreatLevel::High),
            Some("safe"),
            1,
            Some("high"),
            true,
        ),
        (Some("safe"), None, Some("high"), 1, Some("safe"), false),
    ] {
        let source_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let chain_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        if let Some(level) = source_level {
            let mut verdict = make_verdict(source_id, Uuid::new_v4(), Utc::now());
            verdict.threat_level = level;
            db.insert_verdict(&verdict).await?;
        }
        sqlx::query(
            "INSERT INTO email_delivery_chains \
             (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
              first_threat_level, last_seen_at, created_at, updated_at) \
             VALUES ($1, $1, $2, $3, '192.0.2.10', $4, $3, $3, $3)",
        )
        .bind(&chain_id)
        .bind(source_id.to_string())
        .bind(&now)
        .bind(chain_level)
        .execute(db.pool())
        .await?;
        sqlx::query(
            "INSERT INTO email_delivery_hops \
             (session_id, chain_id, fingerprint, first_session_id, hop_index, server_ip, observed_at, first_hop_threat_level) \
             VALUES ($1, $2, $2, $3, $4, '192.0.2.11', $5, $6)",
        )
        .bind(session_id.to_string())
        .bind(&chain_id)
        .bind(source_id.to_string())
        .bind(hop_index)
        .bind(&now)
        .bind(previous_hop_level)
        .execute(db.pool())
        .await?;

        db.mark_email_delivery_hop_reused(session_id, source_id)
            .await?;
        let (level, dangerous, origin, reused_source): (Option<String>, bool, String, Option<String>) =
            sqlx::query_as(
                "SELECT first_hop_threat_level, dangerous_forwarded, verdict_origin, reused_from_session_id \
                 FROM email_delivery_hops WHERE session_id = $1",
            )
            .bind(session_id.to_string())
            .fetch_one(db.pool())
            .await?;
        assert_eq!(level.as_deref(), expected_level);
        assert_eq!(dangerous, expected_danger);
        assert_eq!(origin, "reused_first_hop");
        assert_eq!(reused_source, Some(source_id.to_string()));
    }
    Ok(())
}
