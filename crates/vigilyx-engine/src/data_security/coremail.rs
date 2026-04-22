//! Coremail protocol shared utilities.
//!
//! Coremail uses the same compose.jsp URL for both send and save operations;
//! the JSON body `"action"` field distinguishes the operation type.
//! This module extracts shared constants and functions used by detectors.

/// Coremail compose.jsp URL patterns - same URL is used for both send and save.
pub const COREMAIL_COMPOSE_PATTERNS: &[&str] =
    &["/coremail/common/mbox/compose.jsp", "/coremail/xt/compose"];

/// Check whether URI is a Coremail compose.jsp (requires body action check to distinguish send/save).
pub fn is_coremail_compose_uri(uri: &str) -> bool {
    let uri_lower = uri.to_lowercase();
    COREMAIL_COMPOSE_PATTERNS
        .iter()
        .any(|pattern| uri_lower.contains(pattern))
}

/// Extract email content from Coremail compose JSON body for DLP scanning.
///
/// Coremail compose.jsp POST body structure:
/// ```json
/// {"id":"17744...", "attrs":{"content":"email body","subject":"subject",...}, "action":"deliver"}
/// ```
/// Avoids scanning raw JSON to prevent false positives (e.g., the `id` field and CSS class
/// names contain phone-number-like digit sequences).
/// Extracts only `attrs.content` + `attrs.subject` and concatenates them for scanning.
///
/// Returns None for non-Coremail JSON, with fallback to raw body by the caller.
pub fn extract_content_for_dlp(body: &str) -> Option<String> {
    // Full-audit mode: parse entire body, no truncation
    let mut end = body.len();
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let slice = &body[..end];
    let val: serde_json::Value = serde_json::from_str(slice).ok()?;
    let attrs = val.get("attrs")?;

    let mut parts = Vec::new();
    if let Some(subject) = attrs.get("subject").and_then(|v| v.as_str())
        && !subject.is_empty()
    {
        parts.push(subject.to_string());
    }
    if let Some(content) = attrs.get("content").and_then(|v| v.as_str())
        && !content.is_empty()
    {
        // content may be HTML (isHtml=true), need to strip tags so that
        // ID numbers split across <span> tags are rejoined for matching
        // e.g. <span>610582199</span><span>70624</span><span>0513</span>
        let text = strip_html_tags(content);
        if !text.is_empty() {
            parts.push(text);
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Extract user account from Coremail compose JSON body.
///
/// Extracts the `attrs.account` field, which may be:
/// - `"user@example.com"`
/// - `"\"Display Name\" <user@example.com>"`
///
/// Returns the normalized (lowercase) email address.
pub fn extract_user_from_body(body: &str) -> Option<String> {
    // Full-audit mode: parse entire body
    let mut end = body.len();
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let val: serde_json::Value = serde_json::from_str(&body[..end]).ok()?;
    let account = val.get("attrs")?.get("account")?.as_str()?;
    // Extract email from angle-bracket format
    if let Some(start) = account.find('<')
        && let Some(end_pos) = account.find('>')
    {
        let email = account[start + 1..end_pos].trim();
        if !email.is_empty() {
            return Some(email.to_lowercase());
        }
    }
    // Plain email format
    let trimmed = account.trim().trim_matches('"').trim();
    if trimmed.contains('@') {
        Some(trimmed.to_lowercase())
    } else {
        None
    }
}

/// Strip HTML tags and style blocks, extracting plain text.
fn strip_html_tags(html: &str) -> String {
    // Step 1: Remove <style>...</style> blocks (CSS class names contain phone-number-like digits)
    let mut no_style = String::with_capacity(html.len());
    let lower = html.to_lowercase();
    let mut pos = 0;
    while pos < html.len() {
        if let Some(start) = lower[pos..].find("<style") {
            no_style.push_str(&html[pos..pos + start]);
            if let Some(end) = lower[pos + start..].find("</style>") {
                pos = pos + start + end + 8; // skip past </style>
            } else {
                break; // unclosed style tag, stop
            }
        } else {
            no_style.push_str(&html[pos..]);
            break;
        }
    }

    // Step 2: Strip remaining HTML tags
    let mut result = String::with_capacity(no_style.len() / 2);
    let mut in_tag = false;
    for ch in no_style.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }

    // Normalize whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract top-level "action" field from Coremail compose JSON body.

/// Coremail places "action" AFTER the large "attrs.content" field, so it can be
/// at position 10K+ in the JSON. We search from the end of the body to avoid
/// parsing the entire (potentially huge) JSON, which is both slow and was previously
/// broken by a 4KB truncation that missed the action field entirely.
pub fn extract_body_action(body: &str) -> Option<String> {
    // Fast path: search for "action":"..." near the end of the JSON
    // Coremail format: {"id":"...","attrs":{...huge content...},"action":"save"}
    // Search last 512 bytes for the action field
    let search_start = body.len().saturating_sub(512);
    let mut start = search_start;
    while start > 0 && !body.is_char_boundary(start) {
        start += 1;
    }
    let tail = &body[start..];

    // Look for "action":" pattern
    if let Some(pos) = tail.find("\"action\"") {
        let after_key = &tail[pos + 8..]; // skip past "action"
        // Skip whitespace and colon
        let after_colon = after_key.trim_start().strip_prefix(':')?;
        let after_ws = after_colon.trim_start().strip_prefix('"')?;
        let end_quote = after_ws.find('"')?;
        return Some(after_ws[..end_quote].to_lowercase());
    }

    // Fallback: full JSON parse - no truncation
    let mut end = body.len();
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    serde_json::from_str::<serde_json::Value>(&body[..end])
        .ok()?
        .get("action")?
        .as_str()
        .map(|s| s.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_coremail_compose_uri_match() {
        assert!(is_coremail_compose_uri(
            "/coremail/common/mbox/compose.jsp?sid=abc"
        ));
        assert!(is_coremail_compose_uri("/coremail/xt/compose"));
    }

    #[test]
    fn test_is_coremail_compose_uri_no_match() {
        assert!(!is_coremail_compose_uri("/inbox/list"));
        assert!(!is_coremail_compose_uri("/compose/send"));
    }

    #[test]
    fn test_extract_body_action_save() {
        let body = r#"{"attrs":{},"action":"save"}"#;
        assert_eq!(extract_body_action(body), Some("save".to_string()));
    }

    #[test]
    fn test_extract_body_action_deliver() {
        let body = r#"{"attrs":{},"action":"Deliver"}"#;
        assert_eq!(extract_body_action(body), Some("deliver".to_string()));
    }

    #[test]
    fn test_extract_body_action_missing() {
        let body = r#"{"attrs":{}}"#;
        assert_eq!(extract_body_action(body), None);
    }

    #[test]
    fn test_extract_body_action_invalid_json() {
        assert_eq!(extract_body_action("not json"), None);
    }

    #[test]
    fn test_extract_body_action_empty() {
        assert_eq!(extract_body_action(""), None);
    }

    // extract_content_for_dlp Test

    #[test]
    fn test_extract_content_for_dlp_normal() {
        let body = r#"{"id":"1774418005615","attrs":{"subject":"Test主题","content":"emailbodyContent"},"action":"deliver"}"#;
        let result = extract_content_for_dlp(body);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Test主题"));
        assert!(text.contains("emailbodyContent"));
        // packetContains id Segment
        assert!(
            !text.contains("1774418005615"),
            "Should not contain JSON id field"
        );
    }

    #[test]
    fn test_extract_content_for_dlp_no_phone_in_id() {
        // found Scenario:id MediumContainsClassMobile phoneNumber
        let body = r#"{"id":"1774418005615","attrs":{"account":"support@example.com","content":"<div>38D3670BE3FE3409</div>"},"action":"deliver"}"#;
        let result = extract_content_for_dlp(body);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(
            !text.contains("17744180056"),
            "Extracted content should not contain digits from the id field"
        );
        assert!(
            text.contains("38D3670BE3FE3409"),
            "Should contain the actual email content"
        );
    }

    #[test]
    fn test_extract_content_for_dlp_non_json() {
        let body = "this is plain text, not JSON";
        assert!(extract_content_for_dlp(body).is_none());
    }

    #[test]
    fn test_extract_content_for_dlp_no_attrs() {
        let body = r#"{"action":"save"}"#;
        assert!(extract_content_for_dlp(body).is_none());
    }

    #[test]
    fn test_extract_content_for_dlp_empty_content() {
        let body = r#"{"attrs":{"content":"","subject":""},"action":"save"}"#;
        assert!(extract_content_for_dlp(body).is_none());
    }

    // extract_user_from_body Test

    #[test]
    fn test_extract_user_plain_email() {
        let body = r#"{"attrs":{"account":"user@example.com"}}"#;
        assert_eq!(
            extract_user_from_body(body),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn test_extract_user_display_name_format() {
        let body = r#"{"attrs":{"account":"\"Zhang San\" <zhangsan@corp.com>"}}"#;
        assert_eq!(
            extract_user_from_body(body),
            Some("zhangsan@corp.com".to_string())
        );
    }

    #[test]
    fn test_extract_user_uppercase_normalized() {
        let body = r#"{"attrs":{"account":"Admin@CORP.COM"}}"#;
        assert_eq!(
            extract_user_from_body(body),
            Some("admin@corp.com".to_string())
        );
    }

    #[test]
    fn test_extract_user_no_attrs() {
        let body = r#"{"action":"save"}"#;
        assert_eq!(extract_user_from_body(body), None);
    }

    #[test]
    fn test_extract_user_no_account() {
        let body = r#"{"attrs":{"subject":"test"}}"#;
        assert_eq!(extract_user_from_body(body), None);
    }

    #[test]
    fn test_extract_user_invalid_no_at() {
        let body = r#"{"attrs":{"account":"not-an-email"}}"#;
        assert_eq!(extract_user_from_body(body), None);
    }

    #[test]
    fn test_extract_user_quoted_email() {
        let body = r#"{"attrs":{"account":"\"user@domain.com\""}}"#;
        assert_eq!(
            extract_user_from_body(body),
            Some("user@domain.com".to_string())
        );
    }

    #[test]
    fn test_extract_user_invalid_json() {
        assert_eq!(extract_user_from_body("not json at all"), None);
    }

    #[test]
    fn test_extract_user_empty_body() {
        assert_eq!(extract_user_from_body(""), None);
    }

    // extract_content_for_dlp depthTest

    #[test]
    fn test_extract_content_strips_html_tags() {
        let body = r#"{"attrs":{"content":"<div>Hello <b>World</b></div>","subject":"Test"}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(
            result.contains("Hello World"),
            "HTML tags should be stripped"
        );
        assert!(!result.contains("<div>"), "Should not contain HTML tags");
    }

    #[test]
    fn test_extract_content_strips_style_block() {
        let body = r#"{"attrs":{"content":"<style>.cls{color:red;}</style><div>Content</div>","subject":""}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(result.contains("Content"));
        assert!(
            !result.contains("cls"),
            "CSS class names should be stripped"
        );
        assert!(
            !result.contains("color"),
            "CSS properties should be stripped"
        );
    }

    #[test]
    fn test_extract_content_concatenates_subject_and_body() {
        let body = r#"{"attrs":{"subject":"重要通知","content":"<p>bodyContent</p>"}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(result.contains("重要通知"), "Should contain subject");
        assert!(
            result.contains("bodyContent"),
            "Should contain body content"
        );
    }

    #[test]
    fn test_extract_content_subject_only() {
        let body = r#"{"attrs":{"subject":"only有主题","content":""}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(result.contains("only有主题"));
    }

    #[test]
    fn test_extract_content_body_only() {
        let body = r#"{"attrs":{"subject":"","content":"<p>only有body</p>"}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(result.contains("only有body"));
    }

    #[test]
    fn test_extract_content_preserves_id_number_across_tags() {
        // found: ID cardNumber HTML
        let body = r#"{"attrs":{"content":"<span>610582</span><span>19950624</span><span>0513</span>","subject":""}}"#;
        let result = extract_content_for_dlp(body).unwrap();
        assert!(
            result.contains("610582199506240513"),
            "ID number split across tags should be rejoined after stripping"
        );
    }

    // strip_html_tags

    #[test]
    fn test_strip_html_nested_tags() {
        let result = strip_html_tags("<div><p><b>Bold</b> text</p></div>");
        assert_eq!(result, "Bold text");
    }

    #[test]
    fn test_strip_html_unclosed_style() {
        let result = strip_html_tags("<style>.a{}</style><div>OK</div><style>.b{}");
        assert_eq!(result, "OK");
    }

    #[test]
    fn test_strip_html_empty() {
        let result = strip_html_tags("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_strip_html_no_tags() {
        let result = strip_html_tags("plain text content");
        assert_eq!(result, "plain text content");
    }

    #[test]
    fn test_strip_html_multiple_style_blocks() {
        let result =
            strip_html_tags("<style>.a{color:red}</style>Hello<style>.b{font:12px}</style> World");
        assert_eq!(result, "Hello World");
    }

    // is_coremail_compose_uri depthTest

    #[test]
    fn test_coremail_uri_case_insensitive() {
        assert!(is_coremail_compose_uri(
            "/COREMAIL/COMMON/MBOX/COMPOSE.JSP?sid=x"
        ));
    }

    #[test]
    fn test_coremail_uri_xt_compose() {
        assert!(is_coremail_compose_uri(
            "/coremail/xt/compose?action=deliver"
        ));
    }

    #[test]
    fn test_coremail_uri_partial_no_match() {
        assert!(!is_coremail_compose_uri("/coremail/xt/inbox"));
        assert!(!is_coremail_compose_uri("/other/compose.jsp"));
    }

    // extract_body_action depthTest

    #[test]
    fn test_extract_body_action_autosave() {
        let body = r#"{"attrs":{},"action":"AutoSave"}"#;
        assert_eq!(extract_body_action(body), Some("autosave".to_string()));
    }

    #[test]
    fn test_extract_body_action_non_string() {
        let body = r#"{"action":123}"#;
        assert_eq!(extract_body_action(body), None);
    }

    #[test]
    fn test_extract_body_action_multibyte_boundary_no_panic() {
        // construct1 4096 BytecharactersofString
        // of: Verify due to char boundary panic
        let mut body = String::with_capacity(4100);
        body.push_str(r#"{"action":"save","data":""#);
        while body.len() < 4090 {
            body.push('x');
        }
        // Add Bytecharacters 4096
        while body.len() < 4096 {
            body.push('中');
        }
        body.push_str("\"}");
        // : panic (JSON Break/Judge ParsepossiblyFailed, But panic)
        let _ = extract_body_action(&body);
    }
}
