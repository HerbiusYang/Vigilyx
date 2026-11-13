//! Domain helpers for the unified outbound email data-security review.
//!
//! This module does not decide transport behavior. It translates a parsed
//! email and shared DLP inspection into the durable review contract consumed by
//! both the mirror and MTA adapters.

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vigilyx_core::{
    EmailAuditClass, EmailDataSecurityReview, EmailDlpResult, EmailInspectionStatus,
    EmailReviewAction, EmailReviewDirection, EmailSession, HttpMethod, HttpSession, SessionSource,
    email_domain, external_recipient_domains as core_external_recipient_domains,
    is_internal_sender, is_internal_to_external,
};

use super::email_dlp::EmailDlpInspection;

/// Build the canonical review row for a parsed email.
pub fn build_email_review(
    session: &EmailSession,
    direction: EmailReviewDirection,
    local_domains: &[String],
    inspection: Option<&EmailDlpInspection>,
    action: EmailReviewAction,
    delivery_status: Option<String>,
    quarantine_id: Option<String>,
) -> EmailDataSecurityReview {
    let audit_class = match direction {
        EmailReviewDirection::Outbound => EmailAuditClass::ConfirmedOutbound,
        EmailReviewDirection::Unknown => EmailAuditClass::AttributionPending,
        EmailReviewDirection::Inbound | EmailReviewDirection::Internal => EmailAuditClass::Legacy,
    };
    build_email_review_with_class(
        session,
        direction,
        audit_class,
        local_domains,
        inspection,
        action,
        delivery_status,
        quarantine_id,
    )
}

/// Build the canonical review row with an explicit message-level audit class.
#[allow(clippy::too_many_arguments)]
pub fn build_email_review_with_class(
    session: &EmailSession,
    direction: EmailReviewDirection,
    audit_class: EmailAuditClass,
    local_domains: &[String],
    inspection: Option<&EmailDlpInspection>,
    action: EmailReviewAction,
    delivery_status: Option<String>,
    quarantine_id: Option<String>,
) -> EmailDataSecurityReview {
    let inspection_status = inspection_status(session, inspection);
    let dlp_result = match inspection {
        Some(inspection) if !inspection.result.is_empty() => EmailDlpResult::Hit,
        Some(_) if inspection_status == EmailInspectionStatus::Inspected => EmailDlpResult::Clean,
        Some(_) => EmailDlpResult::Unknown,
        None => EmailDlpResult::Unknown,
    };
    let dlp_matches = inspection
        .map(|inspection| inspection.result.matches.clone())
        .unwrap_or_default();
    let max_jrt_level = inspection.and_then(|inspection| {
        inspection
            .result
            .matches
            .iter()
            .map(|name| super::jrt::jrt_level(name))
            .max()
            .filter(|level| *level > 0)
    });
    let dlp_details = inspection.map(|inspection| {
        serde_json::Value::Object(
            inspection
                .result
                .details
                .iter()
                .map(|(name, values)| {
                    (
                        name.clone(),
                        serde_json::Value::Array(
                            values
                                .iter()
                                .take(3)
                                .map(|value| serde_json::Value::String(value.clone()))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    });
    let external_recipient_domains =
        core_external_recipient_domains(&session.rcpt_to, local_domains);
    let attachment_count = session.content.attachments.len() as u32;

    EmailDataSecurityReview {
        id: session.id,
        session_id: session.id,
        dedupe_key: format!("session:{}", session.id),
        source: session.source,
        direction,
        audit_class,
        direction_reason: Some(direction_reason(
            direction,
            audit_class,
            session,
            local_domains,
        )),
        inspection_reason: inspection_reason(session, inspection),
        inspection_status,
        dlp_result,
        max_jrt_level,
        dlp_matches,
        dlp_details,
        action,
        delivery_status,
        quarantine_id,
        verdict_id: None,
        client_ip: session.client_ip.clone(),
        mail_from: session.mail_from.clone(),
        external_recipient_domains,
        recipient_count: session.rcpt_to.len() as u32,
        subject: session.subject.clone(),
        content_hash: Some(content_hash(session)),
        attachment_count,
        attachments_scanned: inspection
            .map(|inspection| inspection.attachments_scanned as u32)
            .unwrap_or(0),
        attachment_inspection_complete: inspection
            .map(|inspection| inspection.complete)
            .unwrap_or(false),
        encrypted: session.content.is_encrypted,
        created_at: session.started_at,
        updated_at: Utc::now(),
    }
}

/// Return whether the parsed message has enough coverage for a clean result.
pub fn inspection_status(
    session: &EmailSession,
    inspection: Option<&EmailDlpInspection>,
) -> EmailInspectionStatus {
    if session.content.is_encrypted {
        return EmailInspectionStatus::Encrypted;
    }
    // Capture/parser anomalies are part of the content-coverage axis.  A
    // scanner may still return useful hits, but it cannot prove a clean,
    // complete inspection when the upstream session reports an inspection
    // error.
    if session
        .error_reason
        .as_deref()
        .is_some_and(|error| error.starts_with("inspection:"))
    {
        return EmailInspectionStatus::Incomplete;
    }
    let Some(inspection) = inspection else {
        return EmailInspectionStatus::Incomplete;
    };
    if !session.content.is_complete
        || session.content.truncated
        || session.content.dropped_attachments > 0
        || session.content.links_truncated
        || !inspection.complete
    {
        return EmailInspectionStatus::Incomplete;
    }
    EmailInspectionStatus::Inspected
}

/// Return stable, non-sensitive coverage reason codes for the UI and audit log.
fn inspection_reason(
    session: &EmailSession,
    inspection: Option<&EmailDlpInspection>,
) -> Option<String> {
    if session.content.is_encrypted {
        return Some("transport_encrypted".to_string());
    }

    let mut reasons = Vec::new();
    if let Some(error) = session.error_reason.as_deref()
        && let Some(reason) = error.strip_prefix("inspection:")
    {
        reasons.extend(normalize_inspection_error_reasons(reason));
    }
    if !session.content.is_complete {
        reasons.push("capture_incomplete".to_string());
    }
    if session.content.truncated {
        reasons.push("parser_truncated".to_string());
    }
    if session.content.dropped_attachments > 0 {
        reasons.push("attachments_dropped".to_string());
    }
    if session.content.links_truncated {
        reasons.push("links_truncated".to_string());
    }
    if inspection.is_none() {
        reasons.push("content_scan_not_run".to_string());
    } else if inspection.is_some_and(|value| !value.complete) {
        reasons.push("attachment_extraction_incomplete".to_string());
    }

    reasons.sort();
    reasons.dedup();
    (!reasons.is_empty()).then(|| reasons.join(","))
}

/// Convert parser/capture diagnostics into stable, non-sensitive audit codes.
/// Counts and historical `prior:` payloads are intentionally discarded: they
/// are operational diagnostics, not durable UI or policy identifiers.
fn normalize_inspection_error_reasons(value: &str) -> Vec<String> {
    let mut reasons = value
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() || part.starts_with("prior:") {
                return None;
            }
            let code = part.split(':').next().unwrap_or_default().trim();
            let normalized = code
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect::<String>();
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        reasons.push("capture_error".to_string());
    }
    reasons
}

pub fn external_recipient_domains(recipients: &[String], local_domains: &[String]) -> Vec<String> {
    core_external_recipient_domains(recipients, local_domains)
}

fn direction_reason(
    direction: EmailReviewDirection,
    audit_class: EmailAuditClass,
    session: &EmailSession,
    local_domains: &[String],
) -> String {
    let sender_domain = session
        .mail_from
        .as_deref()
        .and_then(email_domain)
        .unwrap_or_else(|| "unknown".to_string());
    let sender_is_local = is_internal_sender(session.mail_from.as_deref(), local_domains);
    let external_count = core_external_recipient_domains(&session.rcpt_to, local_domains).len();
    match audit_class {
        EmailAuditClass::ConfirmedOutbound => format!(
            "confirmed outbound; local sender domain={sender_is_local}; external recipient domains={external_count}"
        ),
        EmailAuditClass::OutboundCandidate => format!(
            "outbound candidate; local sender domain={sender_is_local}; external recipient domains={external_count}; source attribution pending"
        ),
        EmailAuditClass::AttributionPending => format!(
            "outbound attribution pending; sender domain={sender_domain}; external recipient domains={external_count}"
        ),
        EmailAuditClass::Legacy => match direction {
            EmailReviewDirection::Outbound => format!(
                "legacy outbound; local sender domain={sender_is_local}; external recipient domains={external_count}"
            ),
            EmailReviewDirection::Internal => "local sender and local recipients".to_string(),
            EmailReviewDirection::Inbound => {
                "external sender or untrusted local-sender claim".to_string()
            }
            EmailReviewDirection::Unknown => {
                "outbound source or envelope could not be trusted".to_string()
            }
        },
    }
}

/// Whether an HTTP request represents a Webmail send operation with enough
/// envelope evidence to be audited. Draft/autosave requests are excluded.
pub fn webmail_audit_class(
    session: &HttpSession,
    local_domains: &[String],
) -> Option<EmailAuditClass> {
    webmail_audit_class_with_body(
        session,
        local_domains,
        session.request_body.as_deref().unwrap_or_default(),
    )
}

fn webmail_audit_class_with_body(
    session: &HttpSession,
    local_domains: &[String],
    body: &str,
) -> Option<EmailAuditClass> {
    if !matches!(session.method, HttpMethod::Post | HttpMethod::Put)
        || !super::coremail::is_delivery_request(&session.uri, Some(body))
    {
        return None;
    }

    if is_internal_to_external(
        session.detected_sender.as_deref(),
        &session.detected_recipients,
        local_domains,
    ) {
        Some(EmailAuditClass::OutboundCandidate)
    } else if session
        .detected_sender
        .as_deref()
        .is_some_and(|sender| is_internal_sender(Some(sender), local_domains))
        && session.detected_recipients.is_empty()
    {
        Some(EmailAuditClass::AttributionPending)
    } else {
        None
    }
}

/// Read the complete retained Webmail body once for both delivery attribution
/// and DLP. The sniffer stores bodies over 16 KiB in a validated temp file;
/// reading it here prevents large Coremail deliveries from disappearing from
/// the audit stream merely because `request_body` is intentionally empty.
async fn read_webmail_body(session: &HttpSession) -> (String, bool) {
    if let Some(path) = session.body_temp_file.as_deref() {
        return match super::read_temp_path_limited_async(
            path,
            super::MAX_TEMP_BODY_READ_BYTES.saturating_add(1),
        )
        .await
        {
            Some(bytes) => {
                let complete = bytes.len() <= super::MAX_TEMP_BODY_READ_BYTES
                    && (session.request_body_size == 0 || session.request_body_size <= bytes.len());
                (String::from_utf8_lossy(&bytes).into_owned(), complete)
            }
            None => (String::new(), false),
        };
    }

    let body = session.request_body.clone().unwrap_or_default();
    let complete = (session.request_body_size == 0 || session.request_body_size <= body.len())
        && !session.body_is_binary;
    (body, complete)
}

fn scan_webmail_email_with_body(
    session: &HttpSession,
    body: &str,
    body_complete: bool,
) -> EmailDlpInspection {
    let dlp_text =
        super::dlp::extract_dlp_text(body, &session.uri, session.content_type.as_deref());
    let result = super::dlp::scan_text(&dlp_text);
    let complete = body_complete
        && !session.has_gaps
        && session.uploaded_filename.is_none()
        && !session.body_is_binary
        && !result.truncated;
    EmailDlpInspection {
        result,
        complete,
        attachments_scanned: 0,
    }
}

/// Classify and scan one Webmail delivery using the same captured body. This
/// avoids reading large temp-file bodies twice and guarantees that send
/// attribution and DLP inspect the same bytes.
pub async fn classify_and_scan_webmail_email(
    session: &HttpSession,
    local_domains: &[String],
) -> Option<(EmailAuditClass, EmailDlpInspection)> {
    let (body, body_complete) = read_webmail_body(session).await;
    let audit_class = webmail_audit_class_with_body(session, local_domains, &body)?;
    let inspection = scan_webmail_email_with_body(session, &body, body_complete);
    Some((audit_class, inspection))
}

/// Scan the captured Webmail compose body with the same DLP rule engine used
/// by SMTP. Large HTTP bodies are read from the validated temp-file path. A
/// multipart upload remains incomplete until its attachment bytes are
/// available to the email attachment extractor; it is never reported clean.
pub async fn scan_webmail_email(session: &HttpSession) -> EmailDlpInspection {
    let (body, body_complete) = read_webmail_body(session).await;
    scan_webmail_email_with_body(session, &body, body_complete)
}

/// Build one unified audit row for a Webmail send request.
pub fn build_webmail_email_review(
    session: &HttpSession,
    audit_class: EmailAuditClass,
    local_domains: &[String],
    inspection: Option<&EmailDlpInspection>,
) -> EmailDataSecurityReview {
    let inspection_status = webmail_inspection_status(session, inspection);
    let dlp_result = match inspection {
        Some(value) if !value.result.is_empty() => EmailDlpResult::Hit,
        Some(_) if inspection_status == EmailInspectionStatus::Inspected => EmailDlpResult::Clean,
        _ => EmailDlpResult::Unknown,
    };
    let dlp_matches = inspection
        .map(|value| value.result.matches.clone())
        .unwrap_or_default();
    let dlp_details = inspection.map(|value| {
        serde_json::Value::Object(
            value
                .result
                .details
                .iter()
                .map(|(name, values)| (name.clone(), serde_json::json!({ "count": values.len() })))
                .collect(),
        )
    });
    let external_recipient_domains =
        core_external_recipient_domains(&session.detected_recipients, local_domains);
    let attachment_count = u32::from(session.uploaded_filename.is_some());
    EmailDataSecurityReview {
        id: session.id,
        session_id: session.id,
        dedupe_key: format!("webmail-session:{}", session.id),
        source: SessionSource::Sniffer,
        direction: EmailReviewDirection::Unknown,
        audit_class,
        direction_reason: Some(format!(
            "Webmail send request; local sender={}, external recipient domains={}; source attribution pending",
            is_internal_sender(session.detected_sender.as_deref(), local_domains),
            external_recipient_domains.len()
        )),
        inspection_reason: webmail_inspection_reason(session, inspection),
        inspection_status,
        dlp_result,
        max_jrt_level: inspection.and_then(|value| {
            value
                .result
                .matches
                .iter()
                .map(|name| super::jrt::jrt_level(name))
                .max()
                .filter(|level| *level > 0)
        }),
        dlp_matches,
        dlp_details,
        action: EmailReviewAction::Audit,
        delivery_status: Some("webmail_audit".to_string()),
        quarantine_id: None,
        verdict_id: None,
        client_ip: session.client_ip.clone(),
        mail_from: session.detected_sender.clone(),
        external_recipient_domains,
        recipient_count: session.detected_recipients.len() as u32,
        subject: None,
        content_hash: Some(webmail_content_hash(session)),
        attachment_count,
        attachments_scanned: inspection
            .map(|value| value.attachments_scanned as u32)
            .unwrap_or(0),
        attachment_inspection_complete: inspection
            .map(|value| value.complete && attachment_count == 0)
            .unwrap_or(false),
        encrypted: false,
        created_at: session.timestamp,
        updated_at: Utc::now(),
    }
}

fn webmail_inspection_status(
    session: &HttpSession,
    inspection: Option<&EmailDlpInspection>,
) -> EmailInspectionStatus {
    if session.body_is_binary {
        return EmailInspectionStatus::Incomplete;
    }
    let Some(inspection) = inspection else {
        return EmailInspectionStatus::Incomplete;
    };
    if inspection.complete {
        EmailInspectionStatus::Inspected
    } else {
        EmailInspectionStatus::Incomplete
    }
}

fn webmail_inspection_reason(
    session: &HttpSession,
    inspection: Option<&EmailDlpInspection>,
) -> Option<String> {
    let mut reasons = Vec::new();
    if session.has_gaps {
        reasons.push("capture_gaps");
    }
    if session.body_temp_file.is_none()
        && session.request_body_size > session.request_body.as_deref().unwrap_or_default().len()
    {
        reasons.push("request_body_truncated");
    }
    if session.body_temp_file.is_some() && inspection.is_some_and(|value| !value.complete) {
        reasons.push("body_temp_file_incomplete");
    }
    if session.uploaded_filename.is_some() {
        reasons.push("attachment_not_scanned");
    }
    if inspection.is_none() {
        reasons.push("content_scan_not_run");
    } else if inspection.is_some_and(|value| !value.complete) {
        reasons.push("webmail_capture_incomplete");
    }
    (!reasons.is_empty()).then(|| reasons.join(","))
}

fn webmail_content_hash(session: &HttpSession) -> String {
    let mut hasher = Sha256::new();
    for value in [
        session.detected_sender.as_deref().unwrap_or_default(),
        session.request_body.as_deref().unwrap_or_default(),
        &session.detected_recipients.join(","),
    ] {
        hasher.update(value.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

fn content_hash(session: &EmailSession) -> String {
    let mut hasher = Sha256::new();
    for value in [
        session.mail_from.as_deref().unwrap_or_default(),
        session.subject.as_deref().unwrap_or_default(),
        session.content.body_text.as_deref().unwrap_or_default(),
        session.content.body_html.as_deref().unwrap_or_default(),
    ] {
        hasher.update(value.as_bytes());
        hasher.update([0u8]);
    }
    for attachment in &session.content.attachments {
        hasher.update(attachment.filename.as_bytes());
        hasher.update(attachment.hash.as_bytes());
        hasher.update((attachment.size as u64).to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Build a stable review id for callers that need to correlate API links.
pub fn review_id(session: &EmailSession) -> Uuid {
    session.id
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::{
        EmailContent, HttpMethod, HttpSession, Protocol, SessionSource, SessionStatus,
    };

    fn session() -> EmailSession {
        EmailSession {
            id: Uuid::new_v4(),
            protocol: Protocol::Smtp,
            client_ip: "10.0.0.2".into(),
            client_port: 1234,
            server_ip: "10.0.0.1".into(),
            server_port: 25,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            status: SessionStatus::Completed,
            packet_count: 1,
            total_bytes: 10,
            mail_from: Some("a@corp.example".into()),
            rcpt_to: vec!["b@external.example".into()],
            subject: Some("secret subject".into()),
            content: EmailContent {
                is_complete: true,
                ..EmailContent::default()
            },
            email_count: 1,
            error_reason: None,
            message_id: None,
            auth_info: None,
            threat_level: None,
            threat_type: None,
            source: SessionSource::Sniffer,
            smtp_helo: None,
            release_rescan: None,
        }
    }

    #[test]
    fn clean_requires_complete_inspection() {
        let session = session();
        let inspection = EmailDlpInspection {
            complete: true,
            ..EmailDlpInspection::default()
        };
        let review = build_email_review(
            &session,
            EmailReviewDirection::Outbound,
            &["corp.example".into()],
            Some(&inspection),
            EmailReviewAction::Audit,
            None,
            None,
        );
        assert_eq!(review.dlp_result, EmailDlpResult::Clean);
        assert_eq!(review.inspection_status, EmailInspectionStatus::Inspected);
    }

    #[test]
    fn incomplete_inspection_is_not_clean() {
        let mut session = session();
        session.content.truncated = true;
        let inspection = EmailDlpInspection::default();
        let review = build_email_review(
            &session,
            EmailReviewDirection::Outbound,
            &["corp.example".into()],
            Some(&inspection),
            EmailReviewAction::Audit,
            None,
            None,
        );
        assert_eq!(review.inspection_status, EmailInspectionStatus::Incomplete);
        assert_eq!(review.dlp_result, EmailDlpResult::Unknown);
    }

    #[test]
    fn missing_scan_is_incomplete_with_reason() {
        let review = build_email_review(
            &session(),
            EmailReviewDirection::Unknown,
            &["corp.example".into()],
            None,
            EmailReviewAction::Audit,
            Some("mirror_audit".into()),
            None,
        );
        assert_eq!(review.inspection_status, EmailInspectionStatus::Incomplete);
        assert_eq!(review.dlp_result, EmailDlpResult::Unknown);
        assert_eq!(
            review.inspection_reason.as_deref(),
            Some("content_scan_not_run")
        );
    }

    #[test]
    fn encrypted_review_preserves_unknown_dlp_and_transport_reason() {
        let mut session = session();
        session.mail_from = None;
        session.rcpt_to.clear();
        session.content.is_encrypted = true;
        session.content.is_complete = false;

        let review = build_email_review_with_class(
            &session,
            EmailReviewDirection::Unknown,
            EmailAuditClass::AttributionPending,
            &["corp.example".into()],
            None,
            EmailReviewAction::Audit,
            Some("mirror_audit".into()),
            None,
        );

        assert_eq!(review.audit_class, EmailAuditClass::AttributionPending);
        assert_eq!(review.inspection_status, EmailInspectionStatus::Encrypted);
        assert_eq!(review.dlp_result, EmailDlpResult::Unknown);
        assert_eq!(
            review.inspection_reason.as_deref(),
            Some("transport_encrypted")
        );
        assert!(review.encrypted);
    }

    #[test]
    fn protocol_anomaly_forces_incomplete_but_preserves_dlp_hit() {
        let mut session = session();
        session.error_reason = Some("inspection:protocol_anomaly:1".into());
        let inspection = EmailDlpInspection {
            complete: true,
            result: super::super::dlp::DlpScanResult {
                matches: vec!["bank_card".into()],
                ..super::super::dlp::DlpScanResult::default()
            },
            ..EmailDlpInspection::default()
        };

        let review = build_email_review(
            &session,
            EmailReviewDirection::Unknown,
            &["corp.example".into()],
            Some(&inspection),
            EmailReviewAction::Audit,
            Some("mirror_audit".into()),
            None,
        );

        assert_eq!(review.inspection_status, EmailInspectionStatus::Incomplete);
        assert_eq!(review.dlp_result, EmailDlpResult::Hit);
        assert_eq!(
            review.inspection_reason.as_deref(),
            Some("protocol_anomaly")
        );
    }

    #[test]
    fn inspection_error_reasons_are_stable_deduplicated_codes() {
        assert_eq!(
            normalize_inspection_error_reasons(
                "protocol_anomaly:2; prior:content_scan_not_run; smtp_stream_gap:1;protocol_anomaly:3"
            ),
            vec!["protocol_anomaly", "smtp_stream_gap"]
        );
        assert_eq!(
            normalize_inspection_error_reasons("prior:legacy only"),
            vec!["capture_error"]
        );
    }

    #[tokio::test]
    async fn large_coremail_delivery_from_temp_file_is_audited_and_scanned() {
        let body = r#"{"attrs":{"subject":"report","content":"联系电话 13800138000、13900139000、14700147000"},"action":"deliver"}"#;
        let id = Uuid::new_v4();
        let relative_path = format!("data/tmp/http/{id}.bin");
        std::fs::create_dir_all("data/tmp/http").expect("create HTTP temp directory");
        std::fs::write(&relative_path, body.as_bytes()).expect("write HTTP temp body");

        let mut session = HttpSession::new(
            "10.0.0.2".into(),
            12345,
            "10.0.0.1".into(),
            80,
            HttpMethod::Post,
            "/coremail/common/mbox/compose.jsp".into(),
        );
        session.request_body_size = body.len();
        session.body_temp_file = Some(relative_path.clone());
        session.detected_sender = Some("alice@corp.example".into());
        session.detected_recipients = vec!["outside@example.net".into()];
        session.content_type = Some("application/json".into());

        let result = classify_and_scan_webmail_email(&session, &["corp.example".into()])
            .await
            .expect("delivery must be recognized from the temp body");
        assert_eq!(result.0, EmailAuditClass::OutboundCandidate);
        assert!(result.1.complete);
        assert!(result.1.result.matches.iter().any(|m| m == "phone_number"));

        std::fs::remove_file(relative_path).expect("remove HTTP temp body");
    }
}
