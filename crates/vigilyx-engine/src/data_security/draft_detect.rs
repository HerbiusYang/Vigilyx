//! Draft box abuse detector.
//!
//! Detects users saving sensitive content via webmail draft functionality.
//! Scenario: user saves a web draft (HTTP POST/PUT to save endpoint),
//! and the content contains card numbers, ID card numbers, or other sensitive data.
//!
//! Coremail handling: compose.jsp URL is shared for both send and save operations;
//! the JSON body `"action":"save"/"autosave"` field distinguishes them.

use chrono::Utc;
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, HttpMethod, HttpSession};

use super::coremail;
use super::dlp;
use super::{DataSecurityDetector, DetectorResult, extract_snippet};

/// Draft save URI patterns (case-insensitive matching).
const DRAFT_URI_PATTERNS: &[&str] = &[
    "/draft",
    "/savedraft",
    "/save_draft",
    "/compose/save",
    "/compose/draft",
   // Coremail draft save (API)
    "func=mbox:compose&action=savedraft",
    "func=mbox:savedraft",
    "action=savedraft",
    "/coremail/xt5/proxy/compose",
   // Exchange OWA
    "/owa/service.svc",
   // General API
    "/api/draft",
    "/api/compose/save",
    "/mail/draft/save",
    "/webmail/draft",
];

/// Coremail draft save action values.
const COREMAIL_DRAFT_ACTIONS: &[&str] = &["save", "autosave"];

#[derive(Default)]
pub struct DraftBoxDetector;

impl DraftBoxDetector {
    pub fn new() -> Self {
        Self
    }

   /// Check whether URI matches a draft save pattern.
    fn is_draft_uri(uri: &str) -> bool {
        let uri_lower = uri.to_lowercase();
        DRAFT_URI_PATTERNS
            .iter()
            .any(|pattern| uri_lower.contains(pattern))
    }
}

impl DataSecurityDetector for DraftBoxDetector {
    fn id(&self) -> &str {
        "draft_box_detect"
    }

    fn name(&self) -> &str {
        "Draft box abuse detection"
    }

    fn analyze(&self, session: &HttpSession) -> DetectorResult {
       // Only check POST/PUT requests
        if !matches!(session.method, HttpMethod::Post | HttpMethod::Put) {
            return None;
        }

       // URI match: direct draft URL or Coremail compose.jsp + action=save
        let is_draft = if Self::is_draft_uri(&session.uri) {
            true
        } else if coremail::is_coremail_compose_uri(&session.uri) {
           // Coremail URL reuse: check body action field to distinguish save vs send
            session
                .request_body
                .as_deref()
                .and_then(coremail::extract_body_action)
                .map(|a| COREMAIL_DRAFT_ACTIONS.contains(&a.as_str()))
                .unwrap_or(false)
        } else {
            false
        };
        if !is_draft {
            return None;
        }

       // Get request body
        let body = session.request_body.as_deref()?;
        if body.is_empty() {
            return None;
        }

       // DLP scan on request body (Coremail: extract attrs.content to avoid raw JSON metadata)
        let dlp_text = dlp::extract_dlp_text(body, &session.uri);
        let mut dlp_result = dlp::scan_text(&dlp_text);
        if dlp_result.is_empty() {
            return None;
        }

       // FP-3: email body contains recipient addresses; filter out email_address false positives
        dlp_result.matches.retain(|m| m != "email_address");
        dlp_result
            .details
            .retain(|(dtype, _)| dtype != "email_address");
        if dlp_result.is_empty() {
            return None;
        }
        let dlp_for_jrt = dlp_result.clone();

       // Build evidence
        let mut evidence = Vec::new();
        evidence.push(Evidence {
            description: format!(
                "Draft save contains sensitive data (URI: {})",
                session.uri
            ),
            location: Some("HTTP request body".to_string()),
            snippet: None,
        });

        for (dtype, values) in &dlp_result.details {
            let snippet = extract_snippet(&dlp_text, values);
            evidence.push(Evidence {
                description: format!(
                    "Detected {} ({} occurrences): {}",
                    super::dlp_type_cn(dtype),
                    values.len(),
                    values.join(", ")
                ),
                location: Some("draft content".to_string()),
                snippet,
            });
        }

       // Determine severity by highest JR/T classification level (JR/T 0197-2020)
        let severity = super::jrt::severity_from_max_jrt_level(&dlp_result.matches);
        let user = dlp::extract_user(session);

        let matches_cn: Vec<&str> = dlp_result
            .matches
            .iter()
            .map(|m| super::dlp_type_cn(m))
            .collect();
        let summary = format!(
            "Draft box abuse: {} from {} saved a draft containing {}",
            user.as_deref().unwrap_or("unknown user"),
            session.client_ip,
            matches_cn.join(", ")
        );

        Some((
            DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id: session.id,
                incident_type: DataSecurityIncidentType::DraftBoxAbuse,
                severity,
                confidence: 0.85,
                summary,
                evidence,
                details: None,
                dlp_matches: dlp_result.matches,
                client_ip: session.client_ip.clone(),
                detected_user: user,
                request_url: session.uri.clone(),
                host: session.host.clone(),
                method: session.method.to_string(),
                created_at: Utc::now(),
            },
            Some(dlp_for_jrt),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::DataSecuritySeverity;

    fn make_session(uri: &str, method: HttpMethod, body: Option<&str>) -> HttpSession {
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            method,
            uri.to_string(),
        );
        s.request_body = body.map(|b| b.to_string());
        s
    }

    #[test]
    fn test_draft_detect_save_draft_with_credit_card() {
        let detector = DraftBoxDetector::new();
       // 4532015112830366 is Luhn-valid
        let session = make_session(
            "/coremail/main/compose/save",
            HttpMethod::Post,
            Some("请将款项汇入Account 4532015112830366 确认"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (incident, _dlp) = result.unwrap();
        assert_eq!(
            incident.incident_type,
            DataSecurityIncidentType::DraftBoxAbuse
        );
        assert!(incident.dlp_matches.contains(&"credit_card".to_string()));
    }

    #[test]
    fn test_draft_detect_save_draft_with_id_number() {
        let detector = DraftBoxDetector::new();
        let session = make_session(
            "/api/draft",
            HttpMethod::Put,
            Some("ID cardNumber: 110101199001011237"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        assert!(
            result
                .unwrap()
                .0
                .dlp_matches
                .contains(&"id_number".to_string())
        );
    }

    #[test]
    fn test_draft_detect_normal_draft_no_alert() {
        let detector = DraftBoxDetector::new();
        let session = make_session(
            "/compose/save",
            HttpMethod::Post,
            Some("明Day下午3点开会，请准时参Add。"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_draft_detect_non_draft_uri_no_alert() {
        let detector = DraftBoxDetector::new();
        let session = make_session(
            "/inbox/list",
            HttpMethod::Post,
            Some("请将款项汇入Account 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_draft_detect_get_request_no_alert() {
        let detector = DraftBoxDetector::new();
        let session = make_session("/compose/save", HttpMethod::Get, None);
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_draft_detect_coremail_compose_jsp_save() {
        let detector = DraftBoxDetector::new();
       // Coremail compose.jsp + action=save + DLP Medium
        let body = r#"{"attrs":{"account":"user@corp.com","to":[],"subject":"draft","content":"信用卡: 4532015112830366"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc123",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail compose.jsp + action=save should be detected as draft"
        );
        let (incident, _dlp) = result.unwrap();
        assert_eq!(
            incident.incident_type,
            DataSecurityIncidentType::DraftBoxAbuse
        );
    }

    #[test]
    fn test_draft_detect_coremail_compose_jsp_autosave() {
        let detector = DraftBoxDetector::new();
        let body = r#"{"attrs":{"account":"user@corp.com","subject":"test","content":"ID card: 110101199001011237"},"action":"autosave"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=xyz",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail autosave should be detected as draft"
        );
    }

    #[test]
    fn test_draft_detect_coremail_compose_jsp_deliver_not_draft() {
        let detector = DraftBoxDetector::new();
       // action=deliver Sendemail,
        let body = r#"{"attrs":{"account":"user@corp.com","to":["other@corp.com"],"content":"信用卡: 4532015112830366"},"action":"deliver"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Coremail action=deliver should NOT be detected as draft"
        );
    }

    #[test]
    fn test_draft_detect_coremail_normal_content_no_alert() {
        let detector = DraftBoxDetector::new();
       // action=save But SensitiveContent
        let body = r#"{"attrs":{"account":"user@corp.com","to":[],"subject":"meeting","content":"明Day开会"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Coremail draft without sensitive content should not alert"
        );
    }

    
   // Test: Item
    

    #[test]
    fn test_draft_detect_email_only_filtered() {
       // FP-3: Mediumonly emailAddress Risk
        let detector = DraftBoxDetector::new();
        let body = r#"{"attrs":{"to":["a@corp.com"],"subject":"test","content":"recipient: a@test.com, b@test.com, c@test.com"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Draft with ONLY email addresses should NOT trigger (FP-3 filter)"
        );
    }

    #[test]
    fn test_draft_detect_email_plus_other_still_alerts() {
       // email + ID card -> email But id_number
        let detector = DraftBoxDetector::new();
        let body = r#"{"attrs":{"subject":"info","content":"联系人 a@t.com, b@t.com, c@t.com ID card 110101199001011237"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Draft with email + id_number should still alert"
        );
        let (inc, _) = result.unwrap();
        assert!(
            !inc.dlp_matches.contains(&"email_address".to_string()),
            "email_address should be filtered from matches"
        );
        assert!(
            inc.dlp_matches.contains(&"id_number".to_string()),
            "id_number should remain"
        );
    }

    #[test]
    fn test_draft_detect_empty_body_no_alert() {
        let detector = DraftBoxDetector::new();
        let session = make_session("/compose/save", HttpMethod::Post, Some(""));
        let result = detector.analyze(&session);
        assert!(result.is_none(), "Empty body should not trigger");
    }

    #[test]
    fn test_draft_detect_no_body_no_alert() {
        let detector = DraftBoxDetector::new();
        let session = make_session("/compose/save", HttpMethod::Post, None);
        let result = detector.analyze(&session);
        assert!(result.is_none(), "No body should not trigger");
    }

    #[test]
    fn test_draft_detect_coremail_malformed_json() {
        let detector = DraftBoxDetector::new();
       // Coremail URI But body Valid JSON -> extract_body_action Return None ->
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some("not json at all, credit card 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Malformed JSON body with Coremail URI should not trigger (can't determine action)"
        );
    }

    #[test]
    fn test_draft_detect_severity_c4_high() {
        let detector = DraftBoxDetector::new();
       // C4 leveldata (credential_leak) -> severity should be High
        let body = r#"{"attrs":{"subject":"info","content":"Password：admin123"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (inc, _) = result.unwrap();
        assert_eq!(
            inc.severity,
            DataSecuritySeverity::High,
            "C4 level data should produce High severity"
        );
    }

    #[test]
    fn test_draft_detect_coremail_xt_compose_uri() {
        let detector = DraftBoxDetector::new();
        let body = r#"{"attrs":{"content":"信用卡 4532015112830366"},"action":"save"}"#;
        let session = make_session(
            "/coremail/xt/compose?action=compose",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Coremail /xt/compose URI should also be detected"
        );
    }

    #[test]
    fn test_draft_detect_returns_dlp_result_for_jrt() {
        let detector = DraftBoxDetector::new();
        let body = r#"{"attrs":{"content":"ID card 110101199001011237"},"action":"save"}"#;
        let session = make_session(
            "/coremail/common/mbox/compose.jsp?sid=abc",
            HttpMethod::Post,
            Some(body),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (_inc, dlp_opt) = result.unwrap();
        assert!(
            dlp_opt.is_some(),
            "Should return DLP result for JRT compliance tracking"
        );
        let dlp = dlp_opt.unwrap();
        assert!(!dlp.is_empty(), "DLP result should not be empty");
    }
}
