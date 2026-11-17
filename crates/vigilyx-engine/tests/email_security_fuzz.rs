//! Fuzz/property tests for the shared email DLP and review contract.

use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use uuid::Uuid;
use vigilyx_core::{
    EmailAttachment, EmailAuditClass, EmailContent, EmailDlpResult, EmailInspectionStatus,
    EmailReviewAction, EmailReviewDirection, EmailSession, HttpMethod, HttpSession, Protocol,
    SessionSource, SessionStatus,
};
use vigilyx_engine::data_security::{
    email_dlp::scan_email,
    email_review::{build_email_review_with_class, build_webmail_email_review},
};

/// Visa's documented non-production test PAN; it cannot authorize a payment.
const TEST_VISA_PAN: &str = "4111111111111111";

fn attachment_strategy() -> impl Strategy<Value = EmailAttachment> {
    (
        prop::string::string_regex(r"[A-Za-z0-9._/]{0,96}").unwrap(),
        prop::string::string_regex(r"[A-Za-z0-9./_-]{0,96}").unwrap(),
        prop::collection::vec(any::<u8>(), 0..4 * 1024),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..4 * 1024)),
    )
        .prop_map(
            |(filename, content_type, payload, encoded)| EmailAttachment {
                filename,
                content_type,
                size: payload.len(),
                hash: "synthetic-attachment-hash".to_string(),
                content_base64: encoded.map(|value| String::from_utf8_lossy(&value).into_owned()),
            },
        )
}

fn fuzz_session(
    body: &[u8],
    subject: &[u8],
    truncated: bool,
    encrypted: bool,
    links_truncated: bool,
    dropped_attachments: usize,
    attachments: Vec<EmailAttachment>,
) -> EmailSession {
    let mut content = EmailContent::new();
    content.body_text = Some(String::from_utf8_lossy(body).into_owned());
    content.is_complete = !truncated;
    content.truncated = truncated;
    content.is_encrypted = encrypted;
    content.links_truncated = links_truncated;
    content.dropped_attachments = dropped_attachments;
    content.attachments = attachments;

    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.7".to_string(),
        40_000,
        "192.0.2.25".to_string(),
        25,
    );
    session.id = Uuid::new_v4();
    session.status = SessionStatus::Completed;
    session.ended_at = Some(session.started_at);
    session.source = SessionSource::Sniffer;
    session.mail_from = Some("alice@corp.example".to_string());
    session.rcpt_to = vec![
        "local@corp.example".to_string(),
        "recipient@example.net".to_string(),
    ];
    session.subject = Some(String::from_utf8_lossy(subject).into_owned());
    session.content = content;
    session
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_email_content_never_panics_or_reports_incomplete_as_clean(
        body in prop::collection::vec(any::<u8>(), 0..16 * 1024),
        subject in prop::collection::vec(any::<u8>(), 0..2 * 1024),
        truncated in any::<bool>(),
        encrypted in any::<bool>(),
        links_truncated in any::<bool>(),
        dropped_attachments in 0usize..4,
        attachments in prop::collection::vec(attachment_strategy(), 0..5),
    ) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let session = fuzz_session(
                &body,
                &subject,
                truncated,
                encrypted,
                links_truncated,
                dropped_attachments,
                attachments.clone(),
            );
            let inspection = scan_email(&session);
            let review = build_email_review_with_class(
                &session,
                EmailReviewDirection::Unknown,
                EmailAuditClass::OutboundCandidate,
                &["corp.example".to_string()],
                Some(&inspection),
                EmailReviewAction::Audit,
                Some("mirror_audit".to_string()),
                None,
            );

            prop_assert_eq!(review.recipient_count, 2);
            prop_assert_eq!(
                review.external_recipient_domains,
                vec!["example.net".to_string()]
            );
            prop_assert_eq!(review.content_hash.as_deref().map(str::len), Some(64));
            prop_assert_eq!(review.attachment_count, attachments.len() as u32);
            prop_assert!(review.attachments_scanned <= review.attachment_count);

            if review.inspection_status != EmailInspectionStatus::Inspected {
                prop_assert_ne!(review.dlp_result, EmailDlpResult::Clean);
            }
            if encrypted {
                prop_assert_eq!(review.inspection_status, EmailInspectionStatus::Encrypted);
                prop_assert_ne!(review.dlp_result, EmailDlpResult::Clean);
            }

            Ok::<(), TestCaseError>(())
        }));

        prop_assert!(outcome.is_ok(), "arbitrary email content caused a panic");
        prop_assert!(outcome.unwrap().is_ok());
    }
}

#[test]
fn inspection_gap_preserves_dlp_hit_but_forbids_clean_verdict() {
    let body = format!("Documented payment-network test PAN: {TEST_VISA_PAN}");
    let mut session = fuzz_session(
        body.as_bytes(),
        b"synthetic review",
        true,
        false,
        false,
        0,
        Vec::new(),
    );
    session.error_reason = Some("inspection:stream_gap:1".to_string());

    let inspection = scan_email(&session);
    let review = build_email_review_with_class(
        &session,
        EmailReviewDirection::Unknown,
        EmailAuditClass::OutboundCandidate,
        &["corp.example".to_string()],
        Some(&inspection),
        EmailReviewAction::Audit,
        Some("mirror_audit".to_string()),
        None,
    );

    assert_eq!(review.inspection_status, EmailInspectionStatus::Incomplete);
    assert_eq!(review.dlp_result, EmailDlpResult::Hit);
}

#[test]
fn retained_text_attachment_is_scanned_and_counted() {
    use base64::Engine as _;

    let attachment_body = TEST_VISA_PAN.as_bytes();
    let mut session = fuzz_session(
        b"body without a sensitive vector",
        b"attachment scan",
        false,
        false,
        false,
        0,
        vec![EmailAttachment {
            filename: "report.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: attachment_body.len(),
            hash: "synthetic-attachment-hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(attachment_body)),
        }],
    );
    session.content.is_complete = true;

    let inspection = scan_email(&session);
    let review = build_email_review_with_class(
        &session,
        EmailReviewDirection::Outbound,
        EmailAuditClass::ConfirmedOutbound,
        &["corp.example".to_string()],
        Some(&inspection),
        EmailReviewAction::Audit,
        Some("mta_accepted".to_string()),
        None,
    );

    assert_eq!(review.attachment_count, 1);
    assert_eq!(review.attachments_scanned, 1);
    assert!(review.attachment_inspection_complete);
    assert_eq!(review.dlp_result, EmailDlpResult::Hit);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_webmail_delivery_keeps_attribution_and_coverage_separate(
        body_fragment in prop::collection::vec(any::<u8>(), 0..8 * 1024),
        body_size_overstated in any::<bool>(),
        binary_body in any::<bool>(),
        capture_gaps in any::<bool>(),
        attachment_present in any::<bool>(),
    ) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let fragment = String::from_utf8_lossy(&body_fragment).into_owned();
            let body = serde_json::json!({
                "action": "deliver",
                "attrs": {
                    "subject": "synthetic subject",
                    "content": fragment,
                },
            }).to_string();

            let mut session = HttpSession::new(
                "192.0.2.7".to_string(),
                40_000,
                "192.0.2.25".to_string(),
                80,
                HttpMethod::Post,
                "/coremail/common/mbox/compose.jsp".to_string(),
            );
            session.request_body_size = body
                .len()
                .saturating_add(usize::from(body_size_overstated));
            session.request_body = Some(body);
            session.detected_sender = Some("alice@corp.example".to_string());
            session.detected_recipients = vec!["recipient@example.net".to_string()];
            session.content_type = Some("application/json".to_string());
            session.body_is_binary = binary_body;
            session.has_gaps = capture_gaps;
            session.uploaded_filename = attachment_present.then(|| "report.txt".to_string());

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build bounded webmail fuzz runtime");
            let result = runtime.block_on(
                vigilyx_engine::data_security::email_review::classify_and_scan_webmail_email(
                    &session,
                    &["corp.example".to_string()],
                ),
            );
            let (audit_class, inspection) = result
                .expect("delivery-shaped webmail request must be auditable");
            prop_assert_eq!(audit_class, EmailAuditClass::OutboundCandidate);

            let review = build_webmail_email_review(
                &session,
                audit_class,
                &["corp.example".to_string()],
                Some(&inspection),
            );
            prop_assert_eq!(
                review.external_recipient_domains,
                vec!["example.net".to_string()]
            );

            if body_size_overstated || binary_body || capture_gaps || attachment_present {
                prop_assert_ne!(review.inspection_status, EmailInspectionStatus::Inspected);
                prop_assert_ne!(review.dlp_result, EmailDlpResult::Clean);
            }

            Ok::<(), TestCaseError>(())
        }));

        prop_assert!(outcome.is_ok(), "arbitrary webmail delivery caused a panic");
        prop_assert!(outcome.unwrap().is_ok());
    }
}
