//! MTA DLP ()

//! vigilyx-engine DLP (24+).

use serde::{Deserialize, Serialize};
#[cfg(test)]
use vigilyx_core::models::EmailSession;
use vigilyx_core::models::{MailDirection, classify_mail_direction};
use vigilyx_engine::data_security::dlp::DlpScanResult;
pub use vigilyx_engine::data_security::email_dlp::{
    EmailDlpInspection as DlpInspection, scan_email as run_dlp_scan, truncate_to_char_boundary,
};

/// DLP
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    Block,

    #[default]
    Quarantine,

    AllowAndAlert,
}

/// DLP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// DLP
    pub enabled: bool,

    pub action: DlpAction,
    /// Candidate security level (1-5); personal-financial C1-C3 categories are separate.
    pub min_level: u8,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DlpAction::Quarantine,
            min_level: 3,
        }
    }
}

impl DlpConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("MTA_DLP_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            action: match std::env::var("MTA_DLP_ACTION")
                .unwrap_or_default()
                .to_lowercase()
                .as_str()
            {
                "block" => DlpAction::Block,
                "allow" | "allow_and_alert" => DlpAction::AllowAndAlert,
                _ => DlpAction::Quarantine,
            },
            min_level: std::env::var("MTA_DLP_MIN_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        }
    }
}

/// Mail direction classification.
///
/// SEC: `trusted_submitter` means the connection comes from a trusted submission path (authenticated submission / trusted upstream IP).
/// Unauthenticated port 25 connections **must** pass `false`, even if MAIL FROM claims to use a local domain -
/// otherwise an external attacker could spoof `MAIL FROM:<ceo@corp.com>` and bypass all inline scanning.
pub fn detect_direction(
    mail_from: Option<&str>,
    rcpt_to: &[String],
    local_domains: &[String],
    trusted_submitter: bool,
) -> MailDirection {
    let direction = classify_mail_direction(mail_from, rcpt_to, local_domains, trusted_submitter);
    if !trusted_submitter
        && mail_from
            .and_then(|from| from.rsplit('@').next())
            .is_some_and(|domain| {
                local_domains
                    .iter()
                    .any(|local| local.eq_ignore_ascii_case(domain))
            })
    {
        tracing::warn!(
            mail_from = mail_from.unwrap_or("<>"),
            "Untrusted connection claims local sender domain, forcing Inbound scan"
        );
    }
    direction
}

/// DLP
pub fn format_dlp_reason(result: &DlpScanResult) -> String {
    let details: Vec<String> = result
        .details
        .iter()
        .map(|(typ, vals)| format!("{}({})", typ, vals.len()))
        .collect();
    format!("DLP: 检测到敏感数据外发 — {}", details.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_direction_inbound() {
        let d = detect_direction(
            Some("attacker@evil.com"),
            &["user@corp.com".into()],
            &["corp.com".into()],
            false,
        );
        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_detect_direction_outbound_trusted() {
        // Trusted submitter + local sender + external recipient -> outbound
        let d = detect_direction(
            Some("user@corp.com"),
            &["external@gmail.com".into()],
            &["corp.com".into()],
            true,
        );
        assert_eq!(d, MailDirection::Outbound);
    }

    #[test]
    fn test_detect_direction_internal_trusted() {
        // Trusted submitter + local sender + local recipient -> internal
        let d = detect_direction(
            Some("alice@corp.com"),
            &["bob@corp.com".into()],
            &["corp.com".into()],
            true,
        );
        assert_eq!(d, MailDirection::Internal);
    }

    #[test]
    fn test_detect_direction_spoofed_local_sender_untrusted() {
        // SEC: untrusted connection spoofing a local sender -> force inbound (prevent scan bypass)
        let d = detect_direction(
            Some("ceo@corp.com"),
            &["finance@corp.com".into()],
            &["corp.com".into()],
            false,
        );
        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_detect_direction_spoofed_outbound_untrusted() {
        // SEC: untrusted connection spoofing a local sender to an external recipient -> still inbound
        let d = detect_direction(
            Some("user@corp.com"),
            &["external@gmail.com".into()],
            &["corp.com".into()],
            false,
        );
        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_detect_direction_mixed_recipients_trusted() {
        // Trusted + local sender + mixed recipients (including external) = outbound
        let d = detect_direction(
            Some("user@corp.com"),
            &["bob@corp.com".into(), "ext@gmail.com".into()],
            &["corp.com".into()],
            true,
        );
        assert_eq!(d, MailDirection::Outbound);
    }

    #[test]
    fn test_detect_direction_no_sender() {
        // bounce (<>) -> Inbound
        let d = detect_direction(None, &["user@corp.com".into()], &["corp.com".into()], false);
        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_detect_direction_case_insensitive_trusted() {
        let d = detect_direction(
            Some("user@Corp.Com"),
            &["ext@gmail.com".into()],
            &["corp.com".into()],
            true,
        );
        assert_eq!(d, MailDirection::Outbound);
    }

    #[test]
    fn test_detect_direction_multiple_local_domains_case_insensitive() {
        let d = detect_direction(
            Some("alice@Sub.Corp.Com"),
            &["bob@internal.example".into()],
            &[
                "corp.com".into(),
                "sub.corp.com".into(),
                "INTERNAL.EXAMPLE".into(),
            ],
            true,
        );
        assert_eq!(d, MailDirection::Internal);
    }

    #[test]
    fn test_detect_direction_trusted_external_sender_remains_inbound() {
        let d = detect_direction(
            Some("vendor@example.net"),
            &["user@corp.com".into()],
            &["corp.com".into()],
            true,
        );

        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_detect_direction_empty_local_domain_list_is_inbound() {
        let d = detect_direction(
            Some("user@corp.com"),
            &["external@example.net".into()],
            &[],
            true,
        );

        assert_eq!(d, MailDirection::Inbound);
    }

    #[test]
    fn test_dlp_scan_detects_credit_card() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session.content.body_text = Some("请将款项转到以下卡号：4532015112830366，谢谢。".into());
        let result = run_dlp_scan(&session);
        assert!(!result.is_empty(), "Should detect credit card number");
    }

    #[test]
    fn test_dlp_scan_clean_email() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session.content.body_text = Some("会议安排在明天下午三点。".into());
        let result = run_dlp_scan(&session);
        assert!(result.is_empty(), "Normal email should have no DLP hits");
    }

    #[test]
    fn test_dlp_scan_includes_html_body() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session.content.body_html =
            Some("<html><body>备用卡号 4532015112830366</body></html>".into());
        let result = run_dlp_scan(&session);
        assert!(
            result.matches.iter().any(|name| name == "credit_card"),
            "HTML-only sensitive content should be scanned"
        );
    }

    #[test]
    fn test_dlp_scan_includes_subject() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session.subject = Some("收款账号 4532015112830366".into());
        let result = run_dlp_scan(&session);
        assert!(
            result.matches.iter().any(|name| name == "credit_card"),
            "Subject-only sensitive content should be scanned"
        );
    }

    #[test]
    fn test_dlp_scan_includes_text_attachment_content() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session
            .content
            .attachments
            .push(vigilyx_core::EmailAttachment {
                filename: "accounts.txt".into(),
                content_type: "text/plain".into(),
                size: 37,
                hash: "test".into(),
                content_base64: Some("Q3VzdG9tZXIgY2FyZDogNDUzMjAxNTExMjgzMDM2Ng==".into()),
            });

        let inspection = run_dlp_scan(&session);

        assert!(inspection.complete);
        assert_eq!(inspection.attachments_scanned, 1);
        assert!(inspection.matches.iter().any(|name| name == "credit_card"));
    }

    #[test]
    fn test_dlp_marks_missing_text_attachment_payload_incomplete() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        session
            .content
            .attachments
            .push(vigilyx_core::EmailAttachment {
                filename: "accounts.csv".into(),
                content_type: "text/csv".into(),
                size: 1024,
                hash: "test".into(),
                content_base64: None,
            });

        let inspection = run_dlp_scan(&session);

        assert!(!inspection.complete);
        assert_eq!(inspection.attachments_scanned, 0);
    }

    #[test]
    fn test_dlp_scan_empty_email() {
        let session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(),
            25000,
            "10.0.0.2".into(),
            25,
        );
        let result = run_dlp_scan(&session);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dlp_truncation_preserves_utf8_boundary() {
        let mut text = "测测abc".to_string();

        truncate_to_char_boundary(&mut text, 5);

        assert_eq!(text, "测");
        assert!(text.is_char_boundary(text.len()));
    }

    #[test]
    fn test_dlp_truncation_zero_limit_clears_string() {
        let mut text = "abc".to_string();

        truncate_to_char_boundary(&mut text, 0);

        assert!(text.is_empty());
    }

    #[test]
    fn test_dlp_action_serde_uses_snake_case() {
        assert_eq!(
            serde_json::from_str::<DlpAction>("\"allow_and_alert\"").unwrap(),
            DlpAction::AllowAndAlert
        );
        assert_eq!(
            serde_json::to_string(&DlpAction::Quarantine).unwrap(),
            "\"quarantine\""
        );
    }

    #[test]
    fn test_format_dlp_reason() {
        let result = DlpScanResult {
            matches: vec!["credit_card".into(), "phone_number".into()],
            details: vec![
                ("credit_card".into(), vec!["4532***".into()]),
                (
                    "phone_number".into(),
                    vec!["138***".into(), "139***".into()],
                ),
            ],
            ..Default::default()
        };
        let reason = format_dlp_reason(&result);
        assert!(reason.contains("credit_card(1)"));
        assert!(reason.contains("phone_number(2)"));
    }

    #[test]
    fn test_format_dlp_reason_handles_empty_details() {
        let result = DlpScanResult::default();
        let reason = format_dlp_reason(&result);

        assert!(reason.starts_with("DLP: 检测到敏感数据外发"));
    }

    #[test]
    fn test_dlp_config_defaults() {
        let cfg = DlpConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.action, DlpAction::Quarantine);
        assert_eq!(cfg.min_level, 3);
    }
}
