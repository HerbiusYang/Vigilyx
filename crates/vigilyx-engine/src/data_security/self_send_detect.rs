//! Self-sending detector.
//!
//! Detects users sending emails to themselves via webmail HTTP interface.
//! Scenario: user sends an email (HTTP POST to send endpoint),
//! where recipient address matches sender address.
//!
//! Coremail handling: compose.jsp URL is shared for send and save;
//! the JSON body `"action":"deliver"` field identifies send operations.

use chrono::Utc;
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, HttpMethod, HttpSession};

use super::coremail;
use super::dlp;
use super::{DataSecurityDetector, DetectorResult, extract_snippet};

/// Send email URI patterns (case-insensitive matching).
const SEND_URI_PATTERNS: &[&str] = &[
    "/compose/send",
    "/sendmail",
    "/send_mail",
   // Coremail send email (API)
    "func=mbox:compose&action=deliver",
    "func=mbox:deliver",
    "action=deliver",
    "/coremail/xt5/proxy/compose",
   // Exchange OWA
    "/owa/service.svc",
   // General API
    "/api/mail/send",
    "/api/compose/send",
    "/mail/send",
    "/webmail/send",
];

/// Coremail send email action values.
const COREMAIL_SEND_ACTIONS: &[&str] = &["deliver"];

#[derive(Default)]
pub struct SelfSendDetector;

impl SelfSendDetector {
    pub fn new() -> Self {
        Self
    }

    fn is_send_uri(uri: &str) -> bool {
        let uri_lower = uri.to_lowercase();
        SEND_URI_PATTERNS
            .iter()
            .any(|pattern| uri_lower.contains(pattern))
    }

   /// Normalize email address (handle display name, angle brackets, lowercase, trim).
   ///
   /// - `"\"Zhang San\" <zhangsan@corp.com>"` -> `zhangsan@corp.com`
   /// - `<user@domain.com>` -> `user@domain.com`
   /// - `user@domain.com` -> `user@domain.com`
    fn normalize_email(addr: &str) -> String {
        let trimmed = addr.trim();
       // Process "\"Display Name\" <email@domain.com>"
        if let Some(start) = trimmed.rfind('<')
            && let Some(end) = trimmed.rfind('>')
            && start < end
        {
            return trimmed[start + 1..end].trim().to_lowercase();
        }
        trimmed
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim()
            .to_lowercase()
    }

   /// Check whether this is a self-sending scenario.
    fn is_self_sending(sender: &str, recipients: &[String]) -> bool {
        let sender_norm = Self::normalize_email(sender);
        if sender_norm.is_empty() {
            return false;
        }
        recipients
            .iter()
            .any(|r| Self::normalize_email(r) == sender_norm)
    }
}

impl DataSecurityDetector for SelfSendDetector {
    fn id(&self) -> &str {
        "self_send_detect"
    }

    fn name(&self) -> &str {
        "Self-sending detection"
    }

    fn analyze(&self, session: &HttpSession) -> DetectorResult {
       // Only check POST requests
        if session.method != HttpMethod::Post {
            return None;
        }

       // URI match: direct send URL or Coremail compose.jsp + action=deliver
        let is_send = if Self::is_send_uri(&session.uri) {
            true
        } else if coremail::is_coremail_compose_uri(&session.uri) {
            session
                .request_body
                .as_deref()
                .and_then(coremail::extract_body_action)
                .map(|a| COREMAIL_SEND_ACTIONS.contains(&a.as_str()))
                .unwrap_or(false)
        } else {
            false
        };
        if !is_send {
            return None;
        }

       // Extract sender and recipient info
        let sender = session.detected_sender.as_deref()?;
        if sender.is_empty() || session.detected_recipients.is_empty() {
            return None;
        }

       // Check if this is a self-send
        if !Self::is_self_sending(sender, &session.detected_recipients) {
            return None;
        }

        let mut evidence = Vec::new();
        let sender_display = Self::normalize_email(sender);

        evidence.push(Evidence {
            description: format!(
                "User {} sent email to themselves via webmail (URI: {})",
                sender_display, session.uri
            ),
            location: Some("HTTP request".to_string()),
            snippet: Some(format!(
                "from={}, to={}",
                sender_display,
                session.detected_recipients.join(", ")
            )),
        });

       // DLP scan email content - self-sending with sensitive data triggers alert
        let mut dlp_matches = Vec::new();
        let mut dlp_for_jrt = None;

        if let Some(ref body) = session.request_body
            && !body.is_empty()
        {
           // Coremail: extract attrs.content to avoid raw JSON metadata
            let dlp_text = dlp::extract_dlp_text(body, &session.uri);
            let dlp_result = dlp::scan_text(&dlp_text);
            if !dlp_result.is_empty() {
                dlp_for_jrt = Some(dlp_result.clone());
                dlp_matches.extend(dlp_result.matches);
                for (dtype, values) in &dlp_result.details {
                    let snippet = extract_snippet(&dlp_text, values);
                    evidence.push(Evidence {
                        description: format!(
                            "Email content contains {} ({} occurrences): {}",
                            super::dlp_type_cn(dtype),
                            values.len(),
                            values.join(", ")
                        ),
                        location: Some("email body".to_string()),
                        snippet,
                    });
                }
            }
        }

       // Self-sending without sensitive data is normal behavior (e.g. notes, reminders) — no alert
        if dlp_matches.is_empty() {
            return None;
        }

       // Determine severity by highest JR/T classification level (JR/T 0197-2020)
        let severity = super::jrt::severity_from_max_jrt_level(&dlp_matches);

        let summary = format!(
            "Self-sending: {} from {} sent email to self containing {}",
            sender_display,
            session.client_ip,
            dlp_matches.join(", ")
        );

        Some((
            DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id: session.id,
                incident_type: DataSecurityIncidentType::SelfSending,
                severity,
                confidence: 0.85,
                summary,
                evidence,
                details: None,
                dlp_matches,
                client_ip: session.client_ip.clone(),
                detected_user: dlp::extract_user(session),
                request_url: session.uri.clone(),
                host: session.host.clone(),
                method: session.method.to_string(),
                created_at: Utc::now(),
            },
            dlp_for_jrt,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(
        uri: &str,
        sender: Option<&str>,
        recipients: Vec<&str>,
        body: Option<&str>,
    ) -> HttpSession {
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            uri.to_string(),
        );
        s.detected_sender = sender.map(|s| s.to_string());
        s.detected_recipients = recipients.into_iter().map(|r| r.to_string()).collect();
        s.request_body = body.map(|b| b.to_string());
        s
    }

    #[test]
    fn test_self_send_no_sensitive_data_no_alert() {
       // self-sendButnot Sensitivedata -> Normalline, Alert
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["alice@example.com"],
            Some("test content"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "self-send without sensitive data should NOT alert"
        );
    }

    #[test]
    fn test_self_send_with_sensitive_data_alerts() {
       // self-send + Sensitivedata -> Alert
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["bob@example.com", "alice@example.com"],
           // 4532015112830366 is Luhn-valid
            Some("客户信用Card number: 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "self-send WITH sensitive data should alert"
        );
        let (incident, _dlp) = result.unwrap();
        assert_eq!(
            incident.incident_type,
            DataSecurityIncidentType::SelfSending
        );
        assert!(!incident.dlp_matches.is_empty());
    }

    #[test]
    fn test_self_send_case_insensitive() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/api/mail/send",
            Some("Alice@Example.COM"),
            vec!["alice@example.com"],
            Some("ID card: 110101199001011237"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Case-insensitive match with sensitive data should alert"
        );
    }

    #[test]
    fn test_self_send_with_angle_brackets() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("<alice@example.com>"),
            vec!["alice@example.com"],
            Some("Password: abc123456"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Angle bracket format with sensitive data should alert"
        );
    }

    #[test]
    fn test_self_send_different_addresses_no_alert() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["bob@example.com"],
            Some("Hello Bob"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_self_send_non_send_uri_no_alert() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/inbox/list",
            Some("alice@example.com"),
            vec!["alice@example.com"],
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_self_send_with_sensitive_content_high_severity() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["alice@example.com"],
           // 4532015112830366 is Luhn-valid
            Some("信用Card number: 4532015112830366, ID card: 110101199001011237"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (incident, _dlp) = result.unwrap();
        assert!(incident.severity >= vigilyx_core::DataSecuritySeverity::Medium);
        assert!(!incident.dlp_matches.is_empty());
    }

    #[test]
    fn test_self_send_no_sender_no_alert() {
        let detector = SelfSendDetector::new();
        let session = make_session("/compose/send", None, vec!["alice@example.com"], None);
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_self_send_coremail_compose_jsp_deliver_with_sensitive() {
        let detector = SelfSendDetector::new();
       // Coremail compose.jsp + action=deliver + self-send + Sensitivedata (ID cardNumber)
        let body = r#"{"attrs":{"account":"user@corp.com","to":["user@corp.com"],"content":"客户ID card 110101199001011237"},"action":"deliver"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc123",
            Some("user@corp.com"),
            vec!["user@corp.com"],
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail self-send with sensitive data should be detected"
        );
        let (incident, _dlp) = result.unwrap();
        assert_eq!(
            incident.incident_type,
            DataSecurityIncidentType::SelfSending
        );
        assert!(!incident.dlp_matches.is_empty());
    }

    #[test]
    fn test_self_send_coremail_compose_jsp_deliver_no_sensitive() {
        let detector = SelfSendDetector::new();
       // Coremail compose.jsp + action=deliver + self-send But Sensitivedata -> Alert
        let body =
            r#"{"attrs":{"account":"user@corp.com","to":["user@corp.com"]},"action":"deliver"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc123",
            Some("user@corp.com"),
            vec!["user@corp.com"],
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Coremail self-send without sensitive data should NOT alert"
        );
    }

    #[test]
    fn test_self_send_coremail_compose_jsp_save_not_send() {
        let detector = SelfSendDetector::new();
       // action=save Send, self-senddetect
        let body =
            r#"{"attrs":{"account":"user@corp.com","to":["user@corp.com"]},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            Some("user@corp.com"),
            vec!["user@corp.com"],
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Coremail action=save should NOT trigger self-send detection"
        );
    }

    #[test]
    fn test_self_send_coremail_display_name_addresses() {
        let detector = SelfSendDetector::new();
       // with NameofAddress + Sensitivedata
        let session = make_session(
            "/compose/send",
            Some("\"Zhang San\" <zhangsan@corp.com>"),
            vec!["\"Zhang San\" <zhangsan@corp.com>"],
            Some("合SameAmount Password: secret123"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Display name format addresses with sensitive data should alert"
        );
    }

    #[test]
    fn test_normalize_email_display_name_format() {
       // ofNormalize
        assert_eq!(
            SelfSendDetector::normalize_email("\"Zhang San\" <zhangsan@corp.com>"),
            "zhangsan@corp.com"
        );
        assert_eq!(
            SelfSendDetector::normalize_email("<user@domain.com>"),
            "user@domain.com"
        );
        assert_eq!(
            SelfSendDetector::normalize_email("User@Domain.COM"),
            "user@domain.com"
        );
        assert_eq!(
            SelfSendDetector::normalize_email("  alice@example.com  "),
            "alice@example.com"
        );
    }

    
   // Test: Item
    

    #[test]
    fn test_self_send_case_insensitive_with_sensitive_data() {
       // sizewrite SameButSame1email + Sensitivedata
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("Alice@CORP.COM"),
            vec!["alice@corp.com"],
            Some("Password: admin123"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Case-insensitive sender/recipient match should detect self-send"
        );
    }

    #[test]
    fn test_self_send_multiple_recipients_one_is_self() {
       // recipientMedium 1
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@corp.com"),
            vec!["bob@corp.com", "charlie@corp.com", "alice@corp.com"],
            Some("ID card 110101199001011237"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Self in CC list should still trigger self-send detection"
        );
    }

    #[test]
    fn test_self_send_empty_recipients() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@corp.com"),
            vec![],
            Some("test"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_none(), "Empty recipients should not trigger");
    }

    #[test]
    fn test_self_send_empty_sender() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some(""),
            vec!["alice@corp.com"],
            Some("Password: abc"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_none(), "Empty sender should not trigger");
    }

    #[test]
    fn test_self_send_get_request_no_alert() {
        let detector = SelfSendDetector::new();
        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Get,
            "/compose/send".to_string(),
        );
        session.detected_sender = Some("alice@corp.com".to_string());
        session.detected_recipients = vec!["alice@corp.com".to_string()];
        session.request_body = Some("Password: admin".to_string());
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "GET request should never trigger self-send"
        );
    }

    #[test]
    fn test_normalize_email_edge_cases() {
       // Number
        assert_eq!(
            SelfSendDetector::normalize_email("<user@test.com>"),
            "user@test.com"
        );
        
        assert_eq!(
            SelfSendDetector::normalize_email("  <  user@test.com  >  "),
            "user@test.com"
        );
       // String
        assert_eq!(SelfSendDetector::normalize_email(""), "");
       // @ Number
        assert_eq!(SelfSendDetector::normalize_email("@"), "@");
    }

    #[test]
    fn test_self_send_returns_dlp_for_jrt() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["alice@example.com"],
            Some("信用Card number: 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (_inc, dlp_opt) = result.unwrap();
        assert!(
            dlp_opt.is_some(),
            "Should return DLP result for JRT compliance tracking"
        );
    }

    #[test]
    fn test_self_send_coremail_xt5_proxy_uri() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/coremail/xt5/proxy/compose",
            Some("alice@corp.com"),
            vec!["alice@corp.com"],
            Some("Password: secret123"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail xt5 proxy compose URI should be recognized"
        );
    }

    #[test]
    fn test_self_send_exchange_owa_uri() {
        let detector = SelfSendDetector::new();
        let session = make_session(
            "/owa/service.svc?action=SendMessage",
            Some("alice@corp.com"),
            vec!["alice@corp.com"],
            Some("Password: secret123"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Exchange OWA service.svc URI should be recognized"
        );
    }

    #[test]
    fn test_coremail_json_id_no_false_positive_phone() {
       // found: Coremail compose JSON of id SegmentContainsClassMobile phoneNumber "1774418005615"
       // CSS class NameContains "1774418008257", misclassified 3 Mobile phoneNumber
        let detector = SelfSendDetector::new();
        let coremail_body = r#"{"id":"1774418005615","attrs":{"account":"\"Testuser\" <support@example.com>","to":["\"Testuser\" <support@example.com>"],"subject":"","isHtml":true,"content":"<style>p {margin:0}.default-font-1774418008257 {font-size: 14px}</style><div class=\"default-font-1774418008257\"><span>38D3670BE3FE3409EAB10543FED9430DA27B7F02BB31FD0AFAEC29C218DD905E</span></div>"},"action":"deliver"}"#;
        let mut session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=BAWhTkKKxyz",
            Some("support@example.com"),
            vec!["support@example.com"],
            Some(coremail_body),
        );
        session.detected_sender = Some("support@example.com".to_string());
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Coremail JSON id/CSS phone-number-like digits should not trigger DLP false positive, but got: {:?}",
            result.map(|(inc, _)| inc.dlp_matches)
        );
    }
}
