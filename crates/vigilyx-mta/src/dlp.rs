//! MTA DLP ()


//! vigilyx-engine DLP (24+).

use serde::{Deserialize, Serialize};
use vigilyx_core::models::{EmailSession, MailDirection};
use vigilyx_engine::data_security::dlp::{scan_text, DlpScanResult};

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
   /// JR/T (1-5, 3 = C3)
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
    let sender_local = mail_from
        .and_then(|f| f.rsplit('@').next())
        .map(|d| local_domains.iter().any(|ld| ld.eq_ignore_ascii_case(d)))
        .unwrap_or(false);

    let any_external_rcpt = rcpt_to.iter().any(|r| {
        r.rsplit('@')
            .next()
            .map(|d| !local_domains.iter().any(|ld| ld.eq_ignore_ascii_case(d)))
            .unwrap_or(true)
    });

    match (trusted_submitter, sender_local, any_external_rcpt) {
        // Trusted submitter + local sender + all local recipients -> internal
        (true, true, false) => MailDirection::Internal,
        // Trusted submitter + local sender + any external recipient -> outbound
        (true, true, true) => MailDirection::Outbound,
        // Untrusted connection claiming a local sender -> force inbound scanning (anti-spoofing)
        (false, true, _) => {
            tracing::warn!(
                mail_from = mail_from.unwrap_or("<>"),
                "Untrusted connection claims local sender domain, forcing Inbound scan"
            );
            MailDirection::Inbound
        }
        // External sender -> inbound
        (_, false, _) => MailDirection::Inbound,
    }
}

/// DLP (100MB),
const DLP_MAX_SCAN_SIZE: usize = 100 * 1024 * 1024;

/// DLP
pub fn run_dlp_scan(session: &EmailSession) -> DlpScanResult {
    let mut text = String::new();

    if let Some(ref subject) = session.subject {
        text.push_str(subject);
        text.push('\n');
    }
    if let Some(ref body) = session.content.body_text {
        text.push_str(body);
        text.push('\n');
    }
    if let Some(ref html) = session.content.body_html {
        text.push_str(html);
        text.push('\n');
    }

    if text.is_empty() {
        return DlpScanResult::default();
    }

    if text.len() > DLP_MAX_SCAN_SIZE {
        tracing::warn!(
            session_id = %session.id,
            text_size = text.len(),
            max_size = DLP_MAX_SCAN_SIZE,
            "DLP scan truncated: email content exceeds 100MB limit"
        );
        text.truncate(DLP_MAX_SCAN_SIZE);
    }

    scan_text(&text)
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
    fn test_dlp_scan_detects_credit_card() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(), 25000, "10.0.0.2".into(), 25,
        );
        session.content.body_text = Some(
            "请将款项转到以下卡号：4532015112830366，谢谢。".into(),
        );
        let result = run_dlp_scan(&session);
        assert!(
            !result.is_empty(),
            "Should detect credit card number"
        );
    }

    #[test]
    fn test_dlp_scan_clean_email() {
        let mut session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(), 25000, "10.0.0.2".into(), 25,
        );
        session.content.body_text = Some("会议安排在明天下午三点。".into());
        let result = run_dlp_scan(&session);
        assert!(result.is_empty(), "Normal email should have no DLP hits");
    }

    #[test]
    fn test_dlp_scan_empty_email() {
        let session = EmailSession::new(
            vigilyx_core::Protocol::Smtp,
            "10.0.0.1".into(), 25000, "10.0.0.2".into(), 25,
        );
        let result = run_dlp_scan(&session);
        assert!(result.is_empty());
    }

    #[test]
    fn test_format_dlp_reason() {
        let result = DlpScanResult {
            matches: vec!["credit_card".into(), "phone_number".into()],
            details: vec![
                ("credit_card".into(), vec!["4532***".into()]),
                ("phone_number".into(), vec!["138***".into(), "139***".into()]),
            ],
        };
        let reason = format_dlp_reason(&result);
        assert!(reason.contains("credit_card(1)"));
        assert!(reason.contains("phone_number(2)"));
    }

    #[test]
    fn test_dlp_config_defaults() {
        let cfg = DlpConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.action, DlpAction::Quarantine);
        assert_eq!(cfg.min_level, 3);
    }
}
