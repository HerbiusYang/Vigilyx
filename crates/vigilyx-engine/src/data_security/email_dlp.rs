//! Shared email DLP scanning for passive mirror and MTA proxy paths.
//!
//! Transport-specific code decides whether a message is outbound and what to
//! do with a hit. This module owns only content collection and scan coverage so
//! both paths cannot silently drift apart.

use std::ops::Deref;

use vigilyx_core::EmailSession;

use super::dlp::{DlpScanResult, scan_text};
use crate::modules::attach_content::extract_attachment_text_for_policy;

/// Hard upper bound on the text assembled for one email review.
const DLP_MAX_SCAN_SIZE: usize = 100 * 1024 * 1024;

/// Result of inspecting the text and retained attachment content of an email.
#[derive(Debug, Default)]
pub struct EmailDlpInspection {
    pub result: DlpScanResult,
    pub complete: bool,
    pub attachments_scanned: usize,
}

impl Deref for EmailDlpInspection {
    type Target = DlpScanResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

/// Scan subject, plain text, HTML, and extractable attachment text.
pub fn scan_email(session: &EmailSession) -> EmailDlpInspection {
    let mut text = String::new();

    if let Some(subject) = &session.subject {
        text.push_str(subject);
        text.push('\n');
    }
    if let Some(body) = &session.content.body_text {
        text.push_str(body);
        text.push('\n');
    }
    if let Some(html) = &session.content.body_html {
        text.push_str(html);
        text.push('\n');
    }

    let attachment_text = extract_attachment_text_for_policy(&session.content.attachments);
    text.push_str(&attachment_text.text);

    if text.is_empty() {
        return EmailDlpInspection {
            result: DlpScanResult::default(),
            complete: attachment_text.complete && !session.content.truncated,
            attachments_scanned: attachment_text.scanned_count,
        };
    }

    let mut scan_truncated = false;
    if text.len() > DLP_MAX_SCAN_SIZE {
        tracing::warn!(
            session_id = %session.id,
            text_size = text.len(),
            max_size = DLP_MAX_SCAN_SIZE,
            "Email DLP scan truncated: content exceeds 100MB limit"
        );
        truncate_to_char_boundary(&mut text, DLP_MAX_SCAN_SIZE);
        scan_truncated = true;
    }

    let result = scan_text(&text);
    EmailDlpInspection {
        complete: attachment_text.complete
            && !session.content.truncated
            && !scan_truncated
            && !result.truncated,
        result,
        attachments_scanned: attachment_text.scanned_count,
    }
}

pub fn truncate_to_char_boundary(text: &mut String, max_size: usize) {
    if text.len() <= max_size {
        return;
    }

    let mut end = max_size;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::{EmailContent, Protocol, SessionStatus};

    fn session_with_body(body: &str) -> EmailSession {
        let mut content = EmailContent::new();
        content.body_text = Some(body.to_string());
        content.is_complete = true;
        EmailSession {
            id: uuid::Uuid::new_v4(),
            protocol: Protocol::Smtp,
            client_ip: "10.0.0.2".to_string(),
            client_port: 12345,
            server_ip: "10.0.0.1".to_string(),
            server_port: 25,
            started_at: chrono::Utc::now(),
            ended_at: Some(chrono::Utc::now()),
            status: SessionStatus::Completed,
            packet_count: 1,
            total_bytes: body.len(),
            mail_from: Some("alice@example.com".to_string()),
            rcpt_to: vec!["outside@example.net".to_string()],
            subject: Some("review".to_string()),
            content,
            email_count: 1,
            error_reason: None,
            message_id: None,
            auth_info: None,
            threat_level: None,
            threat_type: None,
            source: vigilyx_core::SessionSource::Sniffer,
            smtp_helo: None,
            release_rescan: None,
        }
    }

    #[test]
    fn incomplete_parser_content_never_reports_complete() {
        // Visa's documented non-production test PAN; it cannot authorize a payment.
        let mut session = session_with_body("test PAN 4111111111111111");
        session.content.truncated = true;
        let inspection = scan_email(&session);
        assert!(!inspection.complete);
    }
}
