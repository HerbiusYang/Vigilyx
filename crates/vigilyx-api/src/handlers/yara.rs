//! YARA API Process

//! - GET /security/yara-rules - YARA
//! - POST /security/yara-rules - Create YARA
//! - PUT /security/yara-rules/{id} - New YARA
//! - DELETE /security/yara-rules/{id} - delete YARA
//! - PUT /security/yara-rules/{id}/toggle - YARA
//! - POST /security/yara-rules/validate - verify YARA

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::ApiResponse;
use super::security::publish_engine_reload;
use crate::AppState;

const MAX_YARA_RULE_SOURCE_BYTES: usize = 256 * 1024;
const MAX_YARA_RULES_PER_SOURCE: usize = 20;
const MAX_YARA_RULE_NAME_CHARS: usize = 128;
const MAX_YARA_CATEGORY_CHARS: usize = 64;
const MAX_YARA_DESCRIPTION_CHARS: usize = 1000;

// request/responseType

#[derive(Debug, Deserialize)]
pub struct YaraRuleQuery {
    pub category: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateYaraRuleRequest {
    pub rule_name: String,
    pub category: String,
    pub severity: String,
    pub rule_source: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateYaraRuleRequest {
    pub rule_name: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub rule_source: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ValidateRuleRequest {
    pub rule_source: String,
}

// Process

/// GET /api/security/yara-rules
pub async fn list_yara_rules(
    State(state): State<Arc<AppState>>,
    Query(params): Query<YaraRuleQuery>,
) -> impl IntoResponse {
    let rules = match params.category {
        Some(ref cat) if !cat.is_empty() => state.engine_db.list_yara_rules_by_category(cat).await,
        _ => state.engine_db.list_yara_rules(None).await,
    };
    match rules {
        Ok(items) => {
            let items: Vec<_> = match params.source {
                Some(ref s) if !s.is_empty() => {
                    items.into_iter().filter(|r| r.source == *s).collect()
                }
                _ => items,
            };
            let total = items.len();
            ApiResponse::ok(serde_json::json!({ "items": items, "total": total }))
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// POST /api/security/yara-rules
pub async fn create_yara_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateYaraRuleRequest>,
) -> axum::response::Response {
    let input = match validate_yara_rule_input(
        req.rule_name,
        req.category,
        req.severity,
        req.rule_source,
        req.description,
    ) {
        Ok(input) => input,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
        }
    };
    let now = Utc::now().to_rfc3339();
    let rule = vigilyx_db::YaraRuleRow {
        id: Uuid::new_v4().to_string(),
        rule_name: input.rule_name,
        category: input.category,
        severity: input.severity,
        source: "custom".to_string(),
        rule_source: input.rule_source,
        description: input.description,
        enabled: true,
        hit_count: 0,
        created_at: now.clone(),
        updated_at: now,
    };

    match state.engine_db.insert_yara_rule(&rule).await {
        Ok(()) => {
            publish_engine_reload(&state, "yara").await;
            ApiResponse::ok(serde_json::to_value(&rule).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed").into_response()
        }
    }
}

/// PUT /api/security/yara-rules/{id}
pub async fn update_yara_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateYaraRuleRequest>,
) -> axum::response::Response {
    // Fetch existing
    let existing = match state.engine_db.get_yara_rule(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return ApiResponse::<serde_json::Value>::not_found("规则不存在").into_response();
        }
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    };

    if existing.source == "builtin"
        && (req.rule_name.is_some()
            || req.category.is_some()
            || req.severity.is_some()
            || req.rule_source.is_some()
            || req.description.is_some())
    {
        return ApiResponse::<serde_json::Value>::bad_request("内置规则不可编辑，仅可启用或禁用")
            .into_response();
    }

    let now = Utc::now().to_rfc3339();
    let rule_name = req.rule_name.unwrap_or(existing.rule_name);
    let category = req.category.unwrap_or(existing.category);
    let severity = req.severity.unwrap_or(existing.severity);
    let rule_source = req.rule_source.unwrap_or(existing.rule_source);
    let description = req.description.unwrap_or(existing.description);

    let input = match validate_yara_rule_input(
        rule_name,
        category,
        severity,
        rule_source,
        Some(description),
    ) {
        Ok(input) => input,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
        }
    };

    let updated = vigilyx_db::YaraRuleRow {
        id: existing.id,
        rule_name: input.rule_name,
        category: input.category,
        severity: input.severity,
        source: existing.source,
        rule_source: input.rule_source,
        description: input.description,
        enabled: req.enabled.unwrap_or(existing.enabled),
        hit_count: existing.hit_count,
        created_at: existing.created_at,
        updated_at: now,
    };

    match state.engine_db.update_yara_rule(&updated).await {
        Ok(true) => {
            publish_engine_reload(&state, "yara").await;
            ApiResponse::ok(serde_json::to_value(&updated).unwrap_or_default()).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("更Newfailed").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// DELETE /api/security/yara-rules/{id}
pub async fn delete_yara_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    // Check if builtin
    if let Ok(Some(rule)) = state.engine_db.get_yara_rule(&id).await
        && rule.source == "builtin"
    {
        return ApiResponse::<serde_json::Value>::bad_request("内置规则不可delete，仅可disable")
            .into_response();
    }

    match state.engine_db.delete_yara_rule(&id).await {
        Ok(true) => {
            publish_engine_reload(&state, "yara").await;
            ApiResponse::ok(serde_json::json!({ "deleted": true })).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("规则不存在").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// PUT /api/security/yara-rules/{id}/toggle
pub async fn toggle_yara_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ToggleRequest>,
) -> axum::response::Response {
    match state.engine_db.toggle_yara_rule(&id, req.enabled).await {
        Ok(true) => {
            publish_engine_reload(&state, "yara").await;
            ApiResponse::ok(serde_json::json!({ "toggled": true, "enabled": req.enabled }))
                .into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("规则不存在").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// POST /api/security/yara-rules/validate
pub async fn validate_yara_rule(Json(req): Json<ValidateRuleRequest>) -> impl IntoResponse {
    if let Err(error) = validate_yara_rule_source(&req.rule_source) {
        return ApiResponse::ok(serde_json::json!({
            "valid": false,
            "error": error,
        }));
    }

    ApiResponse::ok(serde_json::json!({ "valid": true }))
}

struct ValidYaraRuleInput {
    rule_name: String,
    category: String,
    severity: String,
    rule_source: String,
    description: String,
}

fn validate_yara_rule_input(
    rule_name: String,
    category: String,
    severity: String,
    rule_source: String,
    description: Option<String>,
) -> Result<ValidYaraRuleInput, String> {
    let rule_name = validate_ascii_token(rule_name, "rule_name", MAX_YARA_RULE_NAME_CHARS)?;
    let category = validate_ascii_token(category, "category", MAX_YARA_CATEGORY_CHARS)?;
    let severity = severity.trim().to_ascii_lowercase();
    if !matches!(severity.as_str(), "critical" | "high" | "medium" | "low") {
        return Err("severity must be one of critical/high/medium/low".to_string());
    }
    let description = validate_description(description.unwrap_or_default())?;
    validate_yara_rule_source(&rule_source)?;

    Ok(ValidYaraRuleInput {
        rule_name,
        category,
        severity,
        rule_source,
        description,
    })
}

fn validate_ascii_token(value: String, field: &str, max_chars: usize) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.chars().count() > max_chars {
        return Err(format!("{field} exceeds {max_chars} characters"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(value.to_string())
}

fn validate_description(value: String) -> Result<String, String> {
    let value = value.trim();
    if value.chars().count() > MAX_YARA_DESCRIPTION_CHARS {
        return Err(format!(
            "description exceeds {MAX_YARA_DESCRIPTION_CHARS} characters"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("description contains control characters".to_string());
    }
    Ok(value.to_string())
}

fn validate_yara_rule_source(rule_source: &str) -> Result<(), String> {
    if rule_source.len() > MAX_YARA_RULE_SOURCE_BYTES {
        return Err(format!(
            "rule_source exceeds {} bytes",
            MAX_YARA_RULE_SOURCE_BYTES
        ));
    }
    if contains_yara_include(rule_source) {
        return Err("YARA include directives are not allowed".to_string());
    }

    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(rule_source)
        .map_err(|e| format!("YARA compile error: {e}"))?;
    let rules = compiler.build();
    let rule_count = rules.iter().count();
    if rule_count == 0 {
        return Err("rule_source must define at least one rule".to_string());
    }
    if rule_count > MAX_YARA_RULES_PER_SOURCE {
        return Err(format!(
            "rule_source defines too many rules: {}/{}",
            rule_count, MAX_YARA_RULES_PER_SOURCE
        ));
    }
    Ok(())
}

fn contains_yara_include(rule_source: &str) -> bool {
    rule_source.lines().map(str::trim_start).any(|line| {
        line == "include"
            || line.starts_with("include ")
            || line.starts_with("include\t")
            || line.starts_with("include\"")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = r#"
rule Custom_Test {
  strings:
    $a = "malicious" ascii
  condition:
    $a
}
"#;

    #[test]
    fn yara_rule_input_accepts_small_valid_rule() {
        let input = validate_yara_rule_input(
            "Custom_Test".to_string(),
            "custom".to_string(),
            "HIGH".to_string(),
            VALID_RULE.to_string(),
            Some("test rule".to_string()),
        )
        .expect("valid rule should pass");

        assert_eq!(input.severity, "high");
        assert_eq!(input.category, "custom");
    }

    #[test]
    fn yara_rule_input_rejects_oversized_source() {
        let source = format!(
            "rule Oversized {{ condition: true }}\n{}",
            "a".repeat(MAX_YARA_RULE_SOURCE_BYTES)
        );

        let error = validate_yara_rule_source(&source).expect_err("oversized source should fail");

        assert!(error.contains("rule_source exceeds"));
    }

    #[test]
    fn yara_rule_input_rejects_include_directives() {
        let source = "include \"local.yar\"\nrule A { condition: true }";

        let error = validate_yara_rule_source(source).expect_err("include should fail");

        assert!(error.contains("include"));
    }

    #[test]
    fn yara_rule_input_rejects_bad_metadata_fields() {
        assert!(validate_ascii_token("../bad".to_string(), "rule_name", 128).is_err());
        assert!(
            validate_yara_rule_input(
                "Rule".to_string(),
                "custom".to_string(),
                "emergency".to_string(),
                VALID_RULE.to_string(),
                None,
            )
            .is_err()
        );
    }
}
