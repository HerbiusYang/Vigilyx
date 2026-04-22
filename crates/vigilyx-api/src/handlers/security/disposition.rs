//! CRUD Process

use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use chrono::Utc;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use vigilyx_db::DispositionRuleRow;

use super::super::ApiResponse;
use super::alerts::encrypt_config_value;
use crate::AppState;
use crate::auth::AuthenticatedUser;


// Sensitive header masking for API responses


/// Header names (case-insensitive) whose values must be masked before
/// returning disposition rules to the browser. The full plaintext values
/// remain in the database so that the webhook executor can use them.
const MASKED_SECRET: &str = "***";
const MASKED_INVALID_ACTIONS_NOTICE: &str = "[sensitive actions hidden: invalid stored JSON]";

const SENSITIVE_HEADER_KEYWORDS: &[&str] = &[
    "authorization",
    "api-key",
    "api_key",
    "cookie",
    "secret",
    "token",
    "bearer",
];

/// Returns `true` if a header name looks sensitive.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADER_KEYWORDS
        .iter()
        .any(|kw| lower.contains(kw))
}

fn mask_webhook_url(raw: &str) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }

    let Ok(parsed) = Url::parse(raw) else {
        return MASKED_SECRET.to_string();
    };
    let Some(host) = parsed.host_str() else {
        return MASKED_SECRET.to_string();
    };

    let mut masked = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        masked.push(':');
        masked.push_str(&port.to_string());
    }
    masked.push_str("/***");
    masked
}

fn action_type(action: &serde_json::Value) -> Option<&str> {
    action.get("action_type").and_then(|value| value.as_str())
}

fn action_type_counts(actions: &[serde_json::Value]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for action in actions {
        if let Some(action_type) = action_type(action) {
            *counts.entry(action_type.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

fn masked_sensitive_header_names(action: &serde_json::Value) -> Vec<String> {
    action
        .get("headers")
        .and_then(|headers| headers.as_object())
        .map(|headers| {
            headers
                .iter()
                .filter(|(key, value)| {
                    is_sensitive_header(key) && value.as_str() == Some(MASKED_SECRET)
                })
                .map(|(key, _)| key.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn action_contains_masked_placeholders(action: &serde_json::Value) -> bool {
    !masked_sensitive_header_names(action).is_empty()
        || action
            .get("webhook_url")
            .and_then(|value| value.as_str())
            .is_some_and(|url| url == MASKED_SECRET || url.ends_with("/***"))
}

fn parse_actions_json(actions_json: &str) -> Result<Vec<serde_json::Value>, String> {
    serde_json::from_str(actions_json)
        .or_else(|_| {
            let inner: String = serde_json::from_str(actions_json)?;
            serde_json::from_str(&inner)
        })
        .map_err(|e| format!("动作解析失败: {e}"))
}

fn masked_invalid_actions_json() -> String {
    serde_json::to_string(MASKED_INVALID_ACTIONS_NOTICE)
        .unwrap_or_else(|_| "\"***\"".to_string())
}

fn encrypt_action_secrets(actions_json: &str, jwt_secret: &str) -> Result<String, String> {
    let mut actions = parse_actions_json(actions_json)?;

    for action in &mut actions {
        if let Some(webhook_url) = action.get_mut("webhook_url")
            && let Some(raw) = webhook_url.as_str()
            && !raw.trim().is_empty()
            && !raw.starts_with("ENC:")
        {
            let encrypted = encrypt_config_value(raw, jwt_secret)?;
            *webhook_url = serde_json::Value::String(encrypted);
        }

        if let Some(headers) = action.get_mut("headers").and_then(|value| value.as_object_mut()) {
            for (key, value) in headers.iter_mut() {
                if !is_sensitive_header(key) {
                    continue;
                }
                let Some(raw) = value.as_str() else {
                    continue;
                };
                if raw.is_empty() || raw == MASKED_SECRET || raw.starts_with("ENC:") {
                    continue;
                }
                let encrypted = encrypt_config_value(raw, jwt_secret)?;
                *value = serde_json::Value::String(encrypted);
            }
        }
    }

    serde_json::to_string(&actions).map_err(|e| format!("动作序列化失败: {e}"))
}

fn restore_masked_action_secrets(
    existing_actions_json: &str,
    incoming_actions_json: &str,
) -> Result<String, String> {
    let mut incoming_actions = parse_actions_json(incoming_actions_json)?;
    let incoming_has_masked_placeholders = incoming_actions
        .iter()
        .any(action_contains_masked_placeholders);
    let existing_actions: Vec<serde_json::Value> = match parse_actions_json(existing_actions_json) {
        Ok(value) => value,
        Err(_) if incoming_has_masked_placeholders => {
            return Err("现有规则中的敏感动作无法安全恢复，请重新输入 webhook URL 和敏感请求头".to_string());
        }
        Err(_) => return Ok(incoming_actions_json.to_string()),
    };

    let existing_type_counts = action_type_counts(&existing_actions);
    let incoming_type_counts = action_type_counts(&incoming_actions);

    for (index, incoming_action) in incoming_actions.iter_mut().enumerate() {
        let masked_header_names = masked_sensitive_header_names(incoming_action);
        let incoming_action_type = action_type(incoming_action);
        let has_masked_headers = !masked_header_names.is_empty();

        let Some(existing_action) = existing_actions.get(index) else {
            if has_masked_headers || action_contains_masked_placeholders(incoming_action) {
                return Err(format!(
                    "第 {} 个动作仍包含掩码敏感字段，但已无法与原动作安全匹配，请重新输入 webhook URL 和敏感请求头",
                    index + 1
                ));
            }
            continue;
        };

        let duplicated_action_type = incoming_action_type.is_some_and(|action_type| {
            existing_type_counts.get(action_type).copied().unwrap_or(0) > 1
                || incoming_type_counts.get(action_type).copied().unwrap_or(0) > 1
        });

        let existing_action_type = action_type(existing_action);
        let incoming_url = incoming_action
            .get("webhook_url")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        let existing_url = existing_action
            .get("webhook_url")
            .and_then(|value| value.as_str());
        let masked_existing_url = existing_url.map(mask_webhook_url);
        let uses_masked_webhook_url = incoming_url
            .as_deref()
            .zip(masked_existing_url.as_deref())
            .is_some_and(|(incoming, masked_existing)| incoming == masked_existing);

        if (has_masked_headers || uses_masked_webhook_url) && incoming_action_type != existing_action_type
        {
            return Err(format!(
                "第 {} 个动作类型已变更，不能安全复用已掩码的敏感字段，请重新输入 webhook URL 和敏感请求头",
                index + 1
            ));
        }

        if duplicated_action_type && (has_masked_headers || uses_masked_webhook_url) {
            return Err(format!(
                "第 {} 个动作存在多个同类型候选项，无法安全恢复已掩码的敏感字段，请重新输入 webhook URL 和敏感请求头",
                index + 1
            ));
        }

        let webhook_url_changed = match (incoming_url.as_deref(), existing_url, masked_existing_url.as_deref()) {
            (Some(incoming), Some(existing), Some(masked_existing)) => {
                incoming != existing && incoming != masked_existing
            }
            (Some(incoming), Some(existing), None) => incoming != existing,
            (None, Some(_), _) => true,
            _ => false,
        };

        if has_masked_headers && webhook_url_changed {
            return Err(format!(
                "第 {} 个 webhook URL 已变更，不能复用已掩码的敏感请求头，请重新输入这些字段",
                index + 1
            ));
        }

        if uses_masked_webhook_url {
            let Some(existing_url) = existing_url else {
                return Err(format!(
                    "第 {} 个动作缺少可恢复的 webhook URL，请重新输入",
                    index + 1
                ));
            };
            let Some(incoming_url) = incoming_action.get_mut("webhook_url") else {
                return Err(format!(
                    "第 {} 个动作缺少 webhook URL 字段，请重新输入",
                    index + 1
                ));
            };
            *incoming_url = serde_json::Value::String(existing_url.to_string());
        }

        if !has_masked_headers {
            continue;
        }

        let Some(existing_headers) = existing_action
            .get("headers")
            .and_then(|headers| headers.as_object())
        else {
            return Err(format!(
                "第 {} 个动作缺少可恢复的敏感请求头，请重新输入",
                index + 1
            ));
        };
        let Some(incoming_headers) = incoming_action
            .get_mut("headers")
            .and_then(|headers| headers.as_object_mut())
        else {
            return Err(format!(
                "第 {} 个动作的请求头格式无效，请重新输入",
                index + 1
            ));
        };

        for key in masked_header_names {
            let Some(existing_value) = existing_headers.get(&key).cloned() else {
                return Err(format!(
                    "第 {} 个动作缺少可恢复的敏感请求头 {}，请重新输入",
                    index + 1,
                    key
                ));
            };
            incoming_headers.insert(key, existing_value);
        }
    }

    serde_json::to_string(&incoming_actions).map_err(|e| format!("动作序列化失败: {e}"))
}

/// Mask sensitive header values inside the `actions` JSON string of a
/// [`DispositionRuleRow`]. The input is the raw JSON text stored in the DB
/// (an array of action objects). Each action's `headers` map is inspected
/// and sensitive values are replaced with `"***"`.

/// If parsing fails the original string is returned unchanged so that we
/// never break the response - the worst case is that an un-parseable rule
/// leaks no extra information (it was already opaque JSON text).
fn mask_actions_secrets(actions_json: &str) -> String {
    let mut actions: Vec<serde_json::Value> = match parse_actions_json(actions_json) {
        Ok(v) => v,
        Err(_) => return masked_invalid_actions_json(),
    };

    for action in &mut actions {
        if let Some(webhook_url) = action.get_mut("webhook_url") {
            let masked = webhook_url
                .as_str()
                .map(mask_webhook_url)
                .unwrap_or_else(|| MASKED_SECRET.to_string());
            *webhook_url = serde_json::Value::String(masked);
        }
        if let Some(headers) = action.get_mut("headers").and_then(|h| h.as_object_mut()) {
            for (key, value) in headers.iter_mut() {
                if is_sensitive_header(key) {
                    *value = serde_json::Value::String(MASKED_SECRET.to_string());
                }
            }
        }
    }

   // Serialization of a Vec<Value> cannot fail in practice.
    serde_json::to_string(&actions).unwrap_or_else(|_| masked_invalid_actions_json())
}

/// Return a copy of the rule with sensitive header values masked.
fn mask_rule_secrets(mut rule: DispositionRuleRow) -> DispositionRuleRow {
    rule.actions = mask_actions_secrets(&rule.actions);
    rule
}





/// Get
pub async fn list_disposition_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.list_disposition_rules().await {
        Ok(rules) => {
            let masked: Vec<DispositionRuleRow> =
                rules.into_iter().map(mask_rule_secrets).collect();
            ApiResponse::ok(serde_json::to_value(masked).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Create request
#[derive(Debug, Deserialize)]
pub struct CreateDispositionRuleRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: i64,
    pub conditions: serde_json::Value,
    pub actions: serde_json::Value,
}

fn default_true() -> bool {
    true
}
fn default_priority() -> i64 {
    100
}

/// Create
pub async fn create_disposition_rule(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<CreateDispositionRuleRequest>,
) -> axum::response::Response {
    let now = Utc::now().to_rfc3339();
    let actions_raw = match serde_json::to_string(&req.actions) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "序列化动作failed: {}",
                e
            ))
            .into_response();
        }
    };
    let actions = match encrypt_action_secrets(
        &actions_raw,
        state.auth.config.jwt_secret.expose_secret(),
    ) {
        Ok(actions) => actions,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    };

    let rule = vigilyx_db::DispositionRuleRow {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        description: req.description,
        enabled: req.enabled,
        priority: req.priority,
        conditions: match serde_json::to_string(&req.conditions) {
            Ok(s) => s,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "序列化items件failed: {}",
                    e
                ))
                .into_response();
            }
        },
        actions,
        created_at: now.clone(),
        updated_at: now,
    };

    match state.engine_db.insert_disposition_rule(&rule).await {
        Ok(()) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "create_disposition_rule",
                Some("security"),
                Some(rule.id.clone()),
                None,
            );
            let masked = mask_rule_secrets(rule);
            ApiResponse::ok(serde_json::to_value(&masked).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// New
pub async fn update_disposition_rule(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(req): Json<CreateDispositionRuleRequest>,
) -> axum::response::Response {
    let Some(existing_rule) = (match state.engine_db.get_disposition_rule(&id).await {
        Ok(rule) => rule,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    }) else {
        return ApiResponse::<serde_json::Value>::not_found("Rule not found").into_response();
    };

    let actions = match serde_json::to_string(&req.actions) {
        Ok(raw) => match restore_masked_action_secrets(&existing_rule.actions, &raw) {
            Ok(actions) => actions,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(e).into_response();
            }
        },
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "序列化动作failed: {}",
                e
            ))
            .into_response();
        }
    };
    let actions = match encrypt_action_secrets(&actions, state.auth.config.jwt_secret.expose_secret()) {
        Ok(actions) => actions,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    };

    let rule = vigilyx_db::DispositionRuleRow {
        id,
        name: req.name,
        description: req.description,
        enabled: req.enabled,
        priority: req.priority,
        conditions: match serde_json::to_string(&req.conditions) {
            Ok(s) => s,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "序列化items件failed: {}",
                    e
                ))
                .into_response();
            }
        },
        actions,
        created_at: existing_rule.created_at,
        updated_at: Utc::now().to_rfc3339(),
    };

    match state.engine_db.update_disposition_rule(&rule).await {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_disposition_rule",
                Some("security"),
                Some(rule.id.clone()),
                None,
            );
            let masked = mask_rule_secrets(rule);
            ApiResponse::ok(serde_json::to_value(&masked).unwrap_or_default()).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("Rule not found").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Delete
pub async fn delete_disposition_rule(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.engine_db.delete_disposition_rule(&id).await {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "delete_disposition_rule",
                Some("security"),
                Some(id),
                None,
            );
            ApiResponse::ok(serde_json::json!({"deleted": true})).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("Rule not found").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    
   // is_sensitive_header
    

    #[test]
    fn test_is_sensitive_header_authorization_lowercase() {
        assert!(is_sensitive_header("authorization"));
    }

    #[test]
    fn test_is_sensitive_header_authorization_mixed_case() {
        assert!(is_sensitive_header("Authorization"));
    }

    #[test]
    fn test_is_sensitive_header_api_key_hyphen() {
        assert!(is_sensitive_header("X-Api-Key"));
    }

    #[test]
    fn test_is_sensitive_header_api_key_underscore() {
        assert!(is_sensitive_header("x_api_key"));
    }

    #[test]
    fn test_is_sensitive_header_secret() {
        assert!(is_sensitive_header("X-Webhook-Secret"));
    }

    #[test]
    fn test_is_sensitive_header_token() {
        assert!(is_sensitive_header("X-Access-Token"));
    }

    #[test]
    fn test_is_sensitive_header_cookie() {
        assert!(is_sensitive_header("Set-Cookie"));
    }

    #[test]
    fn test_is_sensitive_header_bearer() {
        assert!(is_sensitive_header("Bearer-Credential"));
    }

    #[test]
    fn test_is_sensitive_header_safe_header_not_masked() {
        assert!(!is_sensitive_header("Content-Type"));
    }

    #[test]
    fn test_is_sensitive_header_accept_not_masked() {
        assert!(!is_sensitive_header("Accept"));
    }

    #[test]
    fn test_is_sensitive_header_custom_safe_not_masked() {
        assert!(!is_sensitive_header("X-Request-Id"));
    }

    
   // mask_actions_secrets
    

    #[test]
    fn test_mask_actions_secrets_masks_authorization_header() {
        let actions = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://example.com/hook",
            "headers": {
                "Authorization": "Bearer sk-live-abc123secret",
                "Content-Type": "application/json"
            }
        }]"#;

        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();

        let headers = parsed[0]["headers"].as_object().unwrap();
        assert_eq!(
            headers["Authorization"].as_str().unwrap(),
            "***",
            "Authorization value must be masked"
        );
        assert_eq!(
            headers["Content-Type"].as_str().unwrap(),
            "application/json",
            "Content-Type must NOT be masked"
        );
    }

    #[test]
    fn test_mask_actions_secrets_masks_api_key_header() {
        let actions = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://example.com",
            "headers": {
                "X-Api-Key": "key-12345",
                "Accept": "text/plain"
            }
        }]"#;

        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();

        let headers = parsed[0]["headers"].as_object().unwrap();
        assert_eq!(headers["X-Api-Key"].as_str().unwrap(), "***");
        assert_eq!(headers["Accept"].as_str().unwrap(), "text/plain");
    }

    #[test]
    fn test_mask_actions_secrets_masks_multiple_sensitive_headers() {
        let actions = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://example.com",
            "headers": {
                "Authorization": "Bearer secret-jwt",
                "X-Api-Key": "my-api-key",
                "X-Secret-Token": "tok_abc",
                "Content-Type": "application/json"
            }
        }]"#;

        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();

        let headers = parsed[0]["headers"].as_object().unwrap();
        assert_eq!(headers["Authorization"].as_str().unwrap(), "***");
        assert_eq!(headers["X-Api-Key"].as_str().unwrap(), "***");
        assert_eq!(headers["X-Secret-Token"].as_str().unwrap(), "***");
        assert_eq!(
            headers["Content-Type"].as_str().unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_mask_actions_secrets_no_headers_field_unchanged() {
        let actions = r#"[{"action_type": "log"}]"#;
        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();
        assert_eq!(parsed[0]["action_type"].as_str().unwrap(), "log");
    }

    #[test]
    fn test_mask_actions_secrets_empty_headers_unchanged() {
        let actions = r#"[{"action_type": "webhook", "headers": {}}]"#;
        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();
        assert!(parsed[0]["headers"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_mask_actions_secrets_multiple_actions() {
        let actions = r#"[
            {
                "action_type": "webhook",
                "headers": {"Authorization": "Bearer x"}
            },
            {
                "action_type": "webhook",
                "headers": {"X-Api-Key": "key-y", "Accept": "*/*"}
            },
            {
                "action_type": "log"
            }
        ]"#;

        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();

        assert_eq!(parsed[0]["headers"]["Authorization"].as_str().unwrap(), "***");
        assert_eq!(parsed[1]["headers"]["X-Api-Key"].as_str().unwrap(), "***");
        assert_eq!(parsed[1]["headers"]["Accept"].as_str().unwrap(), "*/*");
        assert_eq!(parsed[2]["action_type"].as_str().unwrap(), "log");
    }

    #[test]
    fn test_mask_actions_secrets_invalid_json_returns_redacted_placeholder() {
        let bad_json = "this is not valid json {{{}";
        let result = mask_actions_secrets(bad_json);
        let parsed: String = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed, MASKED_INVALID_ACTIONS_NOTICE);
    }

    #[test]
    fn test_mask_actions_secrets_supports_legacy_double_encoded_json() {
        let legacy = serde_json::to_string(
            r#"[{"action_type":"webhook","headers":{"Authorization":"Bearer legacy-secret"}}]"#,
        )
        .unwrap();

        let masked = mask_actions_secrets(&legacy);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();
        assert_eq!(parsed[0]["headers"]["Authorization"].as_str().unwrap(), "***");
    }

    #[test]
    fn test_restore_masked_action_secrets_supports_legacy_existing_json() {
        let existing = serde_json::to_string(
            r#"[{"action_type":"webhook","webhook_url":"https://hooks.slack.com/services/T00/B00/secret","headers":{"Authorization":"Bearer legacy-secret"}}]"#,
        )
        .unwrap();
        let incoming = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://hooks.slack.com/***",
            "headers": {"Authorization": "***"}
        }]"#;

        let restored = restore_masked_action_secrets(&existing, incoming).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&restored).unwrap();
        assert_eq!(
            parsed[0]["headers"]["Authorization"].as_str().unwrap(),
            "Bearer legacy-secret"
        );
    }

    #[test]
    fn test_mask_actions_secrets_empty_array() {
        let actions = "[]";
        let masked = mask_actions_secrets(actions);
        assert_eq!(masked, "[]");
    }

    #[test]
    fn test_mask_actions_secrets_masks_cookie_and_webhook_url() {
        let actions = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://hooks.slack.com/services/T00/B00/secret",
            "headers": {
                "Authorization": "Bearer xoxb-secret",
                "Cookie": "session=top-secret"
            }
        }]"#;

        let masked = mask_actions_secrets(actions);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked).unwrap();

        assert_eq!(
            parsed[0]["webhook_url"].as_str().unwrap(),
            "https://hooks.slack.com/***",
            "webhook_url should be masked before returning to the browser"
        );
        assert_eq!(parsed[0]["headers"]["Authorization"].as_str().unwrap(), "***");
        assert_eq!(parsed[0]["headers"]["Cookie"].as_str().unwrap(), "***");
    }

    
   // mask_rule_secrets
    

    #[test]
    fn test_mask_rule_secrets_masks_actions_field() {
        let rule = DispositionRuleRow {
            id: "rule-1".to_string(),
            name: "test".to_string(),
            description: None,
            enabled: true,
            priority: 1,
            conditions: r#"{"min_threat_level":"high"}"#.to_string(),
            actions: r#"[{"action_type":"webhook","headers":{"Authorization":"Bearer real-secret"}}]"#.to_string(),
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-01-01".to_string(),
        };

        let masked = mask_rule_secrets(rule);

       // Non-action fields should be unchanged
        assert_eq!(masked.id, "rule-1");
        assert_eq!(masked.name, "test");
        assert_eq!(masked.conditions, r#"{"min_threat_level":"high"}"#);

       // Actions should have the secret masked
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked.actions).unwrap();
        assert_eq!(parsed[0]["headers"]["Authorization"].as_str().unwrap(), "***");
    }

    #[test]
    fn test_mask_rule_secrets_does_not_mutate_non_sensitive_headers() {
        let rule = DispositionRuleRow {
            id: "rule-2".to_string(),
            name: "safe-headers".to_string(),
            description: None,
            enabled: true,
            priority: 1,
            conditions: "{}".to_string(),
            actions: r#"[{"action_type":"webhook","headers":{"Content-Type":"application/json","X-Custom":"hello"}}]"#.to_string(),
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-01-01".to_string(),
        };

        let masked = mask_rule_secrets(rule);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&masked.actions).unwrap();
        let headers = parsed[0]["headers"].as_object().unwrap();

        assert_eq!(headers["Content-Type"].as_str().unwrap(), "application/json");
        assert_eq!(headers["X-Custom"].as_str().unwrap(), "hello");
    }

    #[test]
    fn test_restore_masked_action_secrets_restores_existing_headers_and_webhook_url() {
        let existing = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://hooks.slack.com/services/T00/B00/secret",
            "headers": {
                "Authorization": "Bearer real-secret",
                "Cookie": "session=real-cookie",
                "Content-Type": "application/json"
            }
        }]"#;
        let incoming = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://hooks.slack.com/***",
            "headers": {
                "Authorization": "***",
                "Cookie": "***",
                "Content-Type": "application/json"
            }
        }]"#;

        let restored = restore_masked_action_secrets(existing, incoming).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&restored).unwrap();

        assert_eq!(
            parsed[0]["webhook_url"].as_str().unwrap(),
            "https://hooks.slack.com/services/T00/B00/secret"
        );
        assert_eq!(
            parsed[0]["headers"]["Authorization"].as_str().unwrap(),
            "Bearer real-secret"
        );
        assert_eq!(
            parsed[0]["headers"]["Cookie"].as_str().unwrap(),
            "session=real-cookie"
        );
        assert_eq!(
            parsed[0]["headers"]["Content-Type"].as_str().unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_restore_masked_action_secrets_keeps_explicit_changes() {
        let existing = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://hooks.slack.com/services/T00/B00/secret",
            "headers": {"Authorization": "Bearer old-secret"}
        }]"#;
        let incoming = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://example.com/new-hook",
            "headers": {"Authorization": "Bearer new-secret"}
        }]"#;

        let restored = restore_masked_action_secrets(existing, incoming).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&restored).unwrap();

        assert_eq!(
            parsed[0]["webhook_url"].as_str().unwrap(),
            "https://example.com/new-hook"
        );
        assert_eq!(
            parsed[0]["headers"]["Authorization"].as_str().unwrap(),
            "Bearer new-secret"
        );
    }

    #[test]
    fn test_restore_masked_action_secrets_rejects_masked_headers_when_webhook_url_changes() {
        let existing = r#"[{
            "action_type": "webhook",
            "webhook_url": "ENC:old-url",
            "headers": {"Authorization": "ENC:old-secret"}
        }]"#;
        let incoming = r#"[{
            "action_type": "webhook",
            "webhook_url": "https://example.com/new-hook",
            "headers": {"Authorization": "***"}
        }]"#;

        let error = restore_masked_action_secrets(existing, incoming).unwrap_err();
        assert!(error.contains("webhook URL 已变更"));
    }

    #[test]
    fn test_restore_masked_action_secrets_rejects_reordered_masked_actions() {
        let existing = r#"[
            {
                "action_type": "webhook",
                "webhook_url": "ENC:webhook-a",
                "headers": {"Authorization": "ENC:secret-a"}
            },
            {
                "action_type": "log"
            }
        ]"#;
        let incoming = r#"[
            {
                "action_type": "log"
            },
            {
                "action_type": "webhook",
                "webhook_url": "***",
                "headers": {"Authorization": "***"}
            }
        ]"#;

        let error = restore_masked_action_secrets(existing, incoming).unwrap_err();
        assert!(error.contains("动作类型已变更"));
    }

    #[test]
    fn test_restore_masked_action_secrets_rejects_ambiguous_duplicate_webhooks() {
        let existing = r#"[
            {
                "action_type": "webhook",
                "webhook_url": "ENC:webhook-a",
                "headers": {"Authorization": "ENC:secret-a"}
            },
            {
                "action_type": "webhook",
                "webhook_url": "ENC:webhook-b",
                "headers": {"Authorization": "ENC:secret-b"}
            }
        ]"#;
        let incoming = r#"[
            {
                "action_type": "webhook",
                "webhook_url": "***",
                "headers": {"Authorization": "***"}
            },
            {
                "action_type": "webhook",
                "webhook_url": "***",
                "headers": {"Authorization": "***"}
            }
        ]"#;

        let error = restore_masked_action_secrets(existing, incoming).unwrap_err();
        assert!(error.contains("多个同类型候选项"));
    }
}
