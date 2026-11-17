//! Sensitive Webmail delivery submissions, including self-sending.
//! Authorization and completed delivery are not inferred from captured content.

use chrono::Utc;
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, HttpMethod, HttpSession};

use super::coremail;
use super::dlp;
use super::{DataSecurityDetector, DetectorResult, extract_snippet};

#[derive(Default)]
pub struct MailTransferDetector;

impl MailTransferDetector {
    pub fn new() -> Self {
        Self
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

    /// 比较用归一化: 在 normalize_email 基础上剥离本地部分 `+tag` (plus addressing)。
    /// 攻击者用 `user+tag@own.com` 变形绕过自发自送比对;
    /// 仅用于 is_self_sending 比较路径, 展示仍用 normalize_email 保留原始值
    fn normalize_email_for_compare(addr: &str) -> String {
        let normalized = Self::normalize_email(addr);
        match normalized.split_once('@') {
            Some((local, domain)) => {
                let local_base = local.split('+').next().unwrap_or(local);
                format!("{}@{}", local_base, domain)
            }
            None => normalized,
        }
    }

    /// Check whether this is a self-sending scenario.
    fn is_self_sending(sender: &str, recipients: &[String]) -> bool {
        let sender_norm = Self::normalize_email_for_compare(sender);
        if sender_norm.is_empty() {
            return false;
        }
        recipients
            .iter()
            .any(|r| Self::normalize_email_for_compare(r) == sender_norm)
    }
}

impl DataSecurityDetector for MailTransferDetector {
    fn id(&self) -> &str {
        "mail_transfer_detect"
    }

    fn name(&self) -> &str {
        "Sensitive mail transfer detection"
    }

    fn analyze(&self, session: &HttpSession) -> DetectorResult {
        // Only check POST requests
        if !matches!(session.method, HttpMethod::Post | HttpMethod::Put) {
            return None;
        }

        // Temp bodies contain the complete bounded payload; the in-memory body may be a preview.
        let temp_body = session
            .body_temp_file
            .as_deref()
            .and_then(|path| super::read_temp_path_limited(path, super::MAX_TEMP_BODY_READ_BYTES))
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        let body = temp_body.as_deref().or(session.request_body.as_deref());
        let is_send = coremail::is_delivery_request(&session.uri, body);
        if !is_send {
            return None;
        }

        let sender = session.detected_sender.as_deref().unwrap_or("unknown");
        let self_sending = Self::is_self_sending(sender, &session.detected_recipients);
        let sender_display = Self::normalize_email(sender);
        let mut evidence = vec![Evidence {
            description: "Sensitive content in a Webmail delivery submission; authorization and completed delivery require verification".to_string(),
            location: Some("HTTP delivery request".to_string()),
            snippet: None,
        }];

        // DLP scan email content - self-sending with sensitive data triggers alert
        let mut dlp_matches = Vec::new();
        let mut dlp_for_bulk = None;

        if let Some(body) = body
            && !body.is_empty()
        {
            // Coremail: extract attrs.content to avoid raw JSON metadata
            let dlp_text =
                dlp::extract_dlp_text(body, &session.uri, session.content_type.as_deref());
            let dlp_result = dlp::scan_text(&dlp_text);
            if !dlp_result.is_empty() {
                dlp_for_bulk = Some(dlp_result.clone());
                dlp_matches.extend(dlp_result.matches);
                for (dtype, values) in &dlp_result.details {
                    let snippet = (super::financial_policy::match_level(dtype, &dlp_matches) < 4)
                        .then(|| extract_snippet(&dlp_text, values))
                        .flatten();
                    evidence.push(Evidence {
                        description: format!(
                            "Email content contains {} ({} field matches)",
                            super::dlp_type_cn(dtype),
                            values.len()
                        ),
                        location: Some("email body".to_string()),
                        snippet,
                    });
                }
            }
        }

        // Self-sending without sensitive data is normal behavior (e.g. notes, reminders) — no alert
        if super::financial_policy::max_security_level(&dlp_matches) <= 1 {
            return None;
        }

        // Single sensitive field is sufficient; bulk escalation is independent.
        let severity = super::financial_policy::transfer_severity(&dlp_matches);

        let summary = format!(
            "Sensitive mail transfer risk: {} from {} submitted {}; authorization unverified",
            sender_display,
            session.client_ip,
            dlp_matches.join(", ")
        );
        let details = super::financial_policy::transfer_details(&dlp_matches, "webmail");

        let mut incident = DataSecurityIncident {
            id: vigilyx_core::fast_uuid(),
            http_session_id: session.id,
            incident_type: if self_sending {
                DataSecurityIncidentType::SelfSending
            } else {
                DataSecurityIncidentType::SensitiveDataTransfer
            },
            severity,
            confidence: 0.85,
            summary,
            evidence,
            details: Some(details),
            dlp_matches,
            client_ip: session.client_ip.clone(),
            detected_user: dlp::extract_user(session),
            request_url: session.uri.clone(),
            host: session.host.clone(),
            method: session.method.to_string(),
            created_at: Utc::now(),
        };
        super::financial_policy::assign_incident_id(&mut incident);
        Some((incident, dlp_for_bulk))
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
    fn envelope_addresses_do_not_alert_but_customer_addresses_in_content_do() {
        for (body, expected) in [
            (
                r#"{"from":"alice@example.com","to":["bob@example.net"],"body":"Meeting at noon"}"#,
                false,
            ),
            (
                r#"{"from":"alice@example.com","to":["bob@example.net"],"body":"客户联系邮箱：customer@example.org"}"#,
                true,
            ),
            (
                r#"{"from":"alice@example.com","to":["bob@example.net"],"body":"客户手机号：13800138000"}"#,
                true,
            ),
        ] {
            let session = make_session("/mail/send", None, vec![], Some(body));
            assert_eq!(
                MailTransferDetector.analyze(&session).is_some(),
                expected,
                "{body}"
            );
        }
        let mut form = make_session(
            "/mail/send",
            None,
            vec![],
            Some("to=bob%40example.net&from=alice%40example.com&body=Meeting+at+noon"),
        );
        form.content_type = Some("application/x-www-form-urlencoded".into());
        assert!(MailTransferDetector.analyze(&form).is_none());
    }

    #[test]
    fn single_sensitive_item_alerts_for_an_ordinary_recipient() {
        for (text, kind, severity) in [
            (
                "客户身份证：000000200001010005",
                "id_number",
                vigilyx_core::DataSecuritySeverity::High,
            ),
            (
                "客户手机号：13800138000",
                "phone_number",
                vigilyx_core::DataSecuritySeverity::High,
            ),
            (
                "客户邮箱：alice@example.com",
                "email_address",
                vigilyx_core::DataSecuritySeverity::High,
            ),
            (
                "客户信用卡号：4532015112830366",
                "credit_card",
                vigilyx_core::DataSecuritySeverity::High,
            ),
            (
                "CVV: 731",
                "cvv_code",
                vigilyx_core::DataSecuritySeverity::Critical,
            ),
        ] {
            let session = make_session(
                "/api/mail/send",
                Some("sender@corp.example"),
                vec!["recipient@example.net"],
                Some(text),
            );
            let (incident, result) = MailTransferDetector.analyze(&session).expect(text);
            assert_eq!(
                incident.incident_type,
                DataSecurityIncidentType::SensitiveDataTransfer
            );
            assert_eq!(incident.severity, severity, "{text}");
            assert!(result.unwrap().matches.contains(&kind.to_string()));
            assert_eq!(
                incident.details.as_ref().unwrap()["authorization_status"],
                "unverified"
            );
        }
    }

    #[test]
    fn repeated_processing_is_idempotent_but_new_sends_are_retained() {
        let first = make_session(
            "/mail/send",
            None,
            vec![],
            Some("身份证 000000200001010005"),
        );
        let first_incident = MailTransferDetector.analyze(&first).unwrap().0;
        assert_eq!(
            first_incident.id,
            MailTransferDetector.analyze(&first).unwrap().0.id
        );
        let mut second = first.clone();
        second.id = uuid::Uuid::new_v4();
        assert_ne!(
            first_incident.id,
            MailTransferDetector.analyze(&second).unwrap().0.id
        );
    }

    #[test]
    fn public_reference_login_and_saved_drafts_are_not_sensitive_sends() {
        for (uri, body) in [
            ("/mail/send", "SWIFT: CITIUS33"),
            ("/login", "password=abc123456"),
            (
                "/coremail/common/mbox/compose.jsp",
                r#"{"action":"save","attrs":{"content":"身份证 000000200001010005"}}"#,
            ),
            (
                "/owa/service.svc?action=CreateItem",
                r#"{"Body":{"MessageDisposition":"SaveOnly","Content":"身份证 000000200001010005"}}"#,
            ),
            (
                "/coremail/xt5/proxy/compose",
                r#"{"action":"save","attrs":{"content":"身份证 000000200001010005"}}"#,
            ),
        ] {
            assert!(
                MailTransferDetector
                    .analyze(&make_session(uri, None, vec![], Some(body)))
                    .is_none(),
                "{uri}"
            );
        }
    }

    #[test]
    fn secret_evidence_never_copies_raw_credentials() {
        let session = make_session(
            "/mail/send",
            None,
            vec![],
            Some("Password: UniqueSecret729!"),
        );
        let incident = MailTransferDetector.analyze(&session).unwrap().0;
        assert!(
            !serde_json::to_string(&incident)
                .unwrap()
                .contains("UniqueSecret729")
        );
    }

    #[test]
    fn send_action_and_sensitive_tail_are_loaded_from_a_validated_temp_body() {
        let path = format!("data/tmp/http/{}.bin", uuid::Uuid::new_v4());
        std::fs::create_dir_all("data/tmp/http").unwrap();
        let body = serde_json::json!({"action":"deliver", "attrs":{"content": format!("{} 客户手机 13800138000", "普通内容 ".repeat(3000))}}).to_string();
        std::fs::write(&path, &body).unwrap();
        let mut session = make_session(
            "/coremail/common/mbox/compose.jsp",
            None,
            vec![],
            Some("preview only"),
        );
        session.body_temp_file = Some(path.clone());
        session.request_body_size = body.len();
        let result = MailTransferDetector.analyze(&session);
        std::fs::remove_file(path).unwrap();
        assert!(
            result
                .unwrap()
                .0
                .dlp_matches
                .contains(&"phone_number".to_string())
        );
    }

    #[test]
    fn test_self_send_no_sensitive_data_no_alert() {
        // self-sendButnot Sensitivedata -> Normalline, Alert
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/api/mail/send",
            Some("Alice@Example.COM"),
            vec!["alice@example.com"],
            Some("ID card: 000000200001010005"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Case-insensitive match with sensitive data should alert"
        );
    }

    #[test]
    fn test_self_send_with_angle_brackets() {
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@example.com"),
            vec!["alice@example.com"],
            // 4532015112830366 is Luhn-valid
            Some("信用Card number: 4532015112830366, ID card: 000000200001010005"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (incident, _dlp) = result.unwrap();
        assert!(incident.severity >= vigilyx_core::DataSecuritySeverity::Medium);
        assert!(!incident.dlp_matches.is_empty());
    }

    #[test]
    fn test_self_send_no_sender_no_alert() {
        let detector = MailTransferDetector::new();
        let session = make_session("/compose/send", None, vec!["alice@example.com"], None);
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_self_send_coremail_compose_jsp_deliver_with_sensitive() {
        let detector = MailTransferDetector::new();
        // Coremail compose.jsp + action=deliver + self-send + Sensitivedata (ID cardNumber)
        let body = r#"{"attrs":{"account":"user@corp.example","to":["user@corp.example"],"content":"客户ID card 000000200001010005"},"action":"deliver"}"#;
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
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
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
            MailTransferDetector::normalize_email("\"Zhang San\" <zhangsan@corp.com>"),
            "zhangsan@corp.com"
        );
        assert_eq!(
            MailTransferDetector::normalize_email("<user@domain.com>"),
            "user@domain.com"
        );
        assert_eq!(
            MailTransferDetector::normalize_email("User@Domain.COM"),
            "user@domain.com"
        );
        assert_eq!(
            MailTransferDetector::normalize_email("  alice@example.com  "),
            "alice@example.com"
        );
    }

    // Test: Item

    #[test]
    fn test_self_send_case_insensitive_with_sensitive_data() {
        // sizewrite SameButSame1email + Sensitivedata
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@corp.com"),
            vec!["bob@corp.com", "charlie@corp.com", "alice@corp.com"],
            Some("ID card 000000200001010005"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Self in CC list should still trigger self-send detection"
        );
    }

    #[test]
    fn test_self_send_empty_recipients() {
        let detector = MailTransferDetector::new();
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
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/compose/send",
            Some(""),
            vec!["alice@corp.com"],
            Some("Password: abc"),
        );
        let result = detector.analyze(&session);
        assert_eq!(
            result.unwrap().0.incident_type,
            DataSecurityIncidentType::SensitiveDataTransfer
        );
    }

    #[test]
    fn test_self_send_get_request_no_alert() {
        let detector = MailTransferDetector::new();
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
            MailTransferDetector::normalize_email("<user@test.com>"),
            "user@test.com"
        );

        assert_eq!(
            MailTransferDetector::normalize_email("  <  user@test.com  >  "),
            "user@test.com"
        );
        // String
        assert_eq!(MailTransferDetector::normalize_email(""), "");
        // @ Number
        assert_eq!(MailTransferDetector::normalize_email("@"), "@");
    }

    #[test]
    fn test_normalize_email_for_compare_strips_plus_tag() {
        // PoC: +tag (plus addressing) 变形比对必须一致
        assert_eq!(
            MailTransferDetector::normalize_email_for_compare("alice+archive@corp.com"),
            "alice@corp.com"
        );
        assert_eq!(
            MailTransferDetector::normalize_email_for_compare("\"Zhang\" <zhangsan+evil@corp.com>"),
            "zhangsan@corp.com"
        );
        // 展示路径保留原始 +tag
        assert_eq!(
            MailTransferDetector::normalize_email("alice+archive@corp.com"),
            "alice+archive@corp.com"
        );
    }

    #[test]
    fn test_self_send_plus_tag_bypass_detected() {
        // PoC: 攻击者发往 alice+archive@corp.com (plus addressing 仍投递本人邮箱),
        // 修复前地址比对不一致 -> 绕过自发自送检测; 修复后 +tag 剥离 -> 检出
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice@corp.com"),
            vec!["alice+archive@corp.com"],
            Some("客户ID card 000000200001010005"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Recipient with +tag variant of sender address should still be detected as self-send"
        );
    }

    #[test]
    fn test_self_send_plus_tag_on_sender_side_detected() {
        // PoC 变体: 发件人一侧带 +tag, 收件人是裸地址
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/compose/send",
            Some("alice+evil@corp.com"),
            vec!["alice@corp.com"],
            Some("客户ID card 000000200001010005"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Sender with +tag should match bare recipient address"
        );
    }

    #[test]
    fn test_self_send_returns_dlp_for_bulk() {
        let detector = MailTransferDetector::new();
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
            "Should return DLP result for additional bulk escalation"
        );
    }

    #[test]
    fn test_self_send_coremail_xt5_proxy_uri() {
        let detector = MailTransferDetector::new();
        let session = make_session(
            "/coremail/xt5/proxy/compose",
            Some("alice@corp.com"),
            vec!["alice@corp.com"],
            Some(r#"{"action":"deliver","attrs":{"content":"Password: secret123"}}"#),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail xt5 proxy compose URI should be recognized"
        );
    }

    #[test]
    fn test_self_send_exchange_owa_uri() {
        let detector = MailTransferDetector::new();
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
        // Synthetic 13-digit JSON/CSS identifiers must not be treated as phone numbers.
        let detector = MailTransferDetector::new();
        let coremail_body = r#"{"id":"1000000000001","attrs":{"account":"\"Testuser\" <support@example.com>","to":["\"Testuser\" <support@example.com>"],"subject":"","isHtml":true,"content":"<style>p {margin:0}.default-font-1000000000002 {font-size: 14px}</style><div class=\"default-font-1000000000002\"><span>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</span></div>"},"action":"deliver"}"#;
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
