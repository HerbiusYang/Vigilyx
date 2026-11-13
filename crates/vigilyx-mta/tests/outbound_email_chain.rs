//! Cross-boundary outbound email tests.
//!
//! The default test proves the MTA and mirror adapters feed the same shared
//! parser/DLP/review contract. The opt-in test adds the real PostgreSQL
//! persistence boundary and checks idempotency plus database redaction.

use std::sync::Arc;

#[cfg(feature = "infra-tests")]
use anyhow::{Context, Result, ensure};
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::time::{Duration, timeout};
use vigilyx_core::{
    EmailAuditClass, EmailReviewAction, EmailReviewDirection, EmailSession, Protocol,
    SessionSource, SessionStatus,
};
use vigilyx_engine::data_security::{
    email_dlp::scan_email, email_review::build_email_review_with_class,
};
use vigilyx_mta::config::{DownstreamConfig, MtaConfig};
use vigilyx_mta::server::connection::{HandleResult, SmtpConnection};
use vigilyx_parser::{MimeParser, SmtpStateMachine};

const LOCAL_DOMAINS: &[&str] = &["corp.example"];
const MAIL_FROM: &str = "alice@corp.example";
const RECIPIENT: &str = "recipient@example.net";

fn raw_email() -> Vec<u8> {
    concat!(
        "From: alice@corp.example\r\n",
        "To: recipient@example.net\r\n",
        "Subject: Synthetic outbound review\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"security-boundary\"\r\n",
        "\r\n",
        "--security-boundary\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Contact: 13800138000, 13900139000, 14700147000\r\n",
        "--security-boundary\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Disposition: attachment; filename=\"report.txt\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "c3ludGhldGljIGF0dGFjaG1lbnQ=\r\n",
        "--security-boundary--\r\n",
    )
    .as_bytes()
    .to_vec()
}

fn fuzz_next(state: &mut u64) -> u64 {
    // Deterministic xorshift stream; this is deliberately dependency-free so
    // the MTA boundary test remains part of the normal workspace test graph.
    let mut value = *state;
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    *state = value;
    value.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn fuzz_command_script(iteration: usize) -> Vec<u8> {
    let mut state = 0xD1CE_2026_0819_5EED_u64 ^ iteration as u64;
    let line_count = 1 + (fuzz_next(&mut state) % 8) as usize;
    let mut script = Vec::new();

    for _ in 0..line_count {
        match fuzz_next(&mut state) % 5 {
            0 => script.extend_from_slice(b"NOOP\r\n"),
            1 => script.extend_from_slice(b"RSET\r\n"),
            2 => script.extend_from_slice(b"HELO fuzz.example\r\n"),
            3 => script.extend_from_slice(b"EHLO fuzz.example\r\n"),
            _ => {
                let token = fuzz_next(&mut state);
                script.extend_from_slice(format!("X-Fuzz-{token:016x}\r\n").as_bytes());
            }
        }
    }
    script.extend_from_slice(b"QUIT\r\n");
    script
}

fn mta_config() -> Arc<MtaConfig> {
    Arc::new(MtaConfig {
        listen_smtp: "127.0.0.1:2525".parse().unwrap(),
        listen_submission: None,
        listen_smtps: None,
        max_connections: 4,
        tls: None,
        downstream: DownstreamConfig {
            host: "127.0.0.1".to_string(),
            port: 25,
            starttls: false,
            timeout_secs: 5,
        },
        outbound: Some(DownstreamConfig {
            host: "127.0.0.1".to_string(),
            port: 2526,
            starttls: false,
            timeout_secs: 5,
        }),
        local_domains: LOCAL_DOMAINS.iter().map(|v| (*v).to_string()).collect(),
        trusted_upstream_cidrs: vec!["192.0.2.0/24".to_string()],
        inline_timeout_secs: 8,
        fail_open: false,
        require_starttls: false,
        quarantine_threshold: vigilyx_core::security::ThreatLevel::Medium,
        reject_threshold: vigilyx_core::security::ThreatLevel::Critical,
        max_message_size: 1024 * 1024,
        message_memory_budget: Arc::new(tokio::sync::Semaphore::new(16 * 1024 * 1024)),
        max_recipients: 10,
        database_url: String::new(),
        redis_url: None,
        hostname: "test-mta".to_string(),
        dlp: vigilyx_mta::dlp::DlpConfig::default(),
    })
}

async fn mta_session(raw: &[u8]) -> EmailSession {
    let mut input = Vec::new();
    input.extend_from_slice(b"EHLO client.example\r\n");
    input.extend_from_slice(format!("MAIL FROM:<{MAIL_FROM}>\r\n").as_bytes());
    input.extend_from_slice(format!("RCPT TO:<{RECIPIENT}>\r\n").as_bytes());
    input.extend_from_slice(b"DATA\r\n");
    input.extend_from_slice(raw);
    if !raw.ends_with(b"\r\n") {
        input.extend_from_slice(b"\r\n");
    }
    input.extend_from_slice(b".\r\n");

    let (mut client, server) = tokio::io::duplex(8192);
    client.write_all(&input).await.expect("write SMTP fixture");
    client.shutdown().await.expect("close SMTP input");

    let mut server = BufStream::new(server);
    let mut connection = SmtpConnection::new(
        "192.0.2.7".to_string(),
        40_000,
        "192.0.2.25".to_string(),
        25,
        mta_config(),
        false,
    );
    let results = connection.handle(&mut server, false).await;

    results
        .into_iter()
        .find_map(|result| match result {
            HandleResult::Email(session, _) => Some(*session),
            _ => None,
        })
        .expect("MTA DATA path must produce one email session")
}

fn mirror_session(raw: &[u8]) -> EmailSession {
    let mut smtp = SmtpStateMachine::new();
    smtp.process_client_data(b"EHLO client.example\r\n");
    smtp.process_server_response(b"250 OK\r\n");
    smtp.process_client_data(format!("MAIL FROM:<{MAIL_FROM}>\r\n").as_bytes());
    smtp.process_client_data(format!("RCPT TO:<{RECIPIENT}>\r\n").as_bytes());
    smtp.process_client_data(b"DATA\r\n");
    smtp.process_server_response(b"354 Start mail input\r\n");
    smtp.process_client_data(raw);
    if !raw.ends_with(b"\r\n") {
        smtp.process_client_data(b"\r\n");
    }
    smtp.process_client_data(b".\r\n");

    let message = smtp
        .take_completed_messages()
        .into_iter()
        .next()
        .expect("mirror DATA path must reconstruct one email");
    assert!(
        message.is_complete,
        "synthetic mirror capture must be complete"
    );

    let content = MimeParser::new()
        .parse(&message.data)
        .expect("mirror MIME parser must accept the same fixture");
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.7".to_string(),
        40_000,
        "192.0.2.25".to_string(),
        25,
    );
    session.status = SessionStatus::Completed;
    session.ended_at = Some(session.started_at);
    session.source = SessionSource::Sniffer;
    session.mail_from = smtp.mail_from().map(str::to_string);
    session.rcpt_to = smtp.rcpt_to().to_vec();
    session.subject = content.get_header("Subject").map(str::to_string);
    session.content = content;
    session.email_count = 1;
    session
}

fn review_for(
    session: &EmailSession,
    direction: EmailReviewDirection,
    class: EmailAuditClass,
    status: &str,
) -> vigilyx_core::EmailDataSecurityReview {
    let inspection = scan_email(session);
    let local_domains = LOCAL_DOMAINS
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    build_email_review_with_class(
        session,
        direction,
        class,
        &local_domains,
        Some(&inspection),
        EmailReviewAction::Audit,
        Some(status.to_string()),
        None,
    )
}

#[tokio::test]
async fn mta_and_mirror_share_dlp_and_outbound_review_contract() {
    let raw = raw_email();
    let mta = mta_session(&raw).await;
    let mirror = mirror_session(&raw);

    assert_eq!(mta.source, SessionSource::MtaProxy);
    assert_eq!(mirror.source, SessionSource::Sniffer);
    assert_eq!(mta.mail_from.as_deref(), Some(MAIL_FROM));
    assert_eq!(mirror.mail_from.as_deref(), Some(MAIL_FROM));
    assert_eq!(mta.rcpt_to, mirror.rcpt_to);
    assert_eq!(mta.content.body_text, mirror.content.body_text);
    assert_eq!(mta.content.attachments.len(), 1);
    assert_eq!(mirror.content.attachments.len(), 1);

    let mta_review = review_for(
        &mta,
        EmailReviewDirection::Outbound,
        EmailAuditClass::ConfirmedOutbound,
        "mta_accepted",
    );
    let mirror_review = review_for(
        &mirror,
        EmailReviewDirection::Unknown,
        EmailAuditClass::OutboundCandidate,
        "mirror_audit",
    );

    assert_eq!(mta_review.dlp_result, vigilyx_core::EmailDlpResult::Hit);
    assert_eq!(mirror_review.dlp_result, mta_review.dlp_result);
    assert_eq!(mirror_review.dlp_matches, mta_review.dlp_matches);
    assert_eq!(mirror_review.content_hash, mta_review.content_hash);
    assert_eq!(
        mirror_review.external_recipient_domains,
        vec!["example.net"]
    );
    assert_eq!(mta_review.audit_class, EmailAuditClass::ConfirmedOutbound);
    assert_eq!(
        mirror_review.audit_class,
        EmailAuditClass::OutboundCandidate
    );
    assert_eq!(mta_review.attachment_count, 1);
    assert_eq!(mta_review.attachments_scanned, 1);
    assert!(mta_review.attachment_inspection_complete);
}

#[tokio::test]
async fn mta_hostile_command_fuzz_is_bounded_and_never_fabricates_email() {
    // This exercises the real MTA connection loop (not only the shared SMTP
    // parser) with 256 deterministic command sequences. DATA/BDAT/AUTH/
    // STARTTLS are intentionally excluded so this remains a bounded command
    // state fuzz campaign with no downstream network dependency.
    for iteration in 0..256 {
        let script = fuzz_command_script(iteration);
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        client
            .write_all(&script)
            .await
            .expect("write bounded MTA fuzz script");
        client.shutdown().await.expect("close MTA fuzz input");

        let mut stream = BufStream::new(server);
        let mut connection = SmtpConnection::new(
            "192.0.2.7".to_string(),
            40_000,
            "192.0.2.25".to_string(),
            25,
            mta_config(),
            false,
        );
        let results = timeout(
            Duration::from_secs(1),
            connection.handle(&mut stream, false),
        )
        .await
        .unwrap_or_else(|_| panic!("MTA command fuzz iteration {iteration} exceeded deadline"));

        assert!(
            results
                .iter()
                .all(|result| !matches!(result, HandleResult::Email(_, _))),
            "command-only fuzz input fabricated an email at iteration {iteration}"
        );
    }
}

#[cfg(feature = "infra-tests")]
fn test_database_url() -> Result<String> {
    let url = std::env::var("VIGILYX_TEST_DATABASE_URL")
        .context("VIGILYX_TEST_DATABASE_URL must point to a disposable PostgreSQL database")?;
    ensure!(
        std::env::var("VIGILYX_ALLOW_REAL_INFRA_TESTS").as_deref() == Ok("1"),
        "set VIGILYX_ALLOW_REAL_INFRA_TESTS=1 to acknowledge disposable DB use"
    );
    ensure!(
        url.to_ascii_lowercase().contains("vigilyx_test"),
        "refusing persistence test outside a vigilyx_test database"
    );
    Ok(url)
}

#[tokio::test]
#[cfg(feature = "infra-tests")]
async fn real_postgres_persists_mta_and_mirror_reviews_idempotently() -> Result<()> {
    let db = vigilyx_db::VigilDb::new(&test_database_url()?).await?;
    db.init().await?;
    db.init_security_tables().await?;

    let raw = raw_email();
    let mta_session = mta_session(&raw).await;
    let mirror_session = mirror_session(&raw);
    let mta_review = review_for(
        &mta_session,
        EmailReviewDirection::Outbound,
        EmailAuditClass::ConfirmedOutbound,
        "mta_accepted",
    );
    let mirror_review = review_for(
        &mirror_session,
        EmailReviewDirection::Unknown,
        EmailAuditClass::OutboundCandidate,
        "mirror_audit",
    );

    for review in [&mta_review, &mirror_review, &mta_review, &mirror_review] {
        db.upsert_email_data_security_review(review).await?;
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_security_email_reviews WHERE dedupe_key IN ($1, $2)",
    )
    .bind(&mta_review.dedupe_key)
    .bind(&mirror_review.dedupe_key)
    .fetch_one(db.pool())
    .await?;
    assert_eq!(count, 2, "replay must not create duplicate review rows");

    let stored: (String, Option<String>, Option<String>, String) = sqlx::query_as(
        "SELECT mail_from, subject, dlp_details, inspection_status
         FROM data_security_email_reviews WHERE dedupe_key = $1",
    )
    .bind(&mta_review.dedupe_key)
    .fetch_one(db.pool())
    .await?;
    assert_eq!(stored.0, "a****@corp.example");
    assert_eq!(stored.1.as_deref(), Some("[REDACTED]"));
    assert!(!stored.2.unwrap_or_default().contains("13800138000"));
    assert_eq!(stored.3, "inspected");

    Ok(())
}
