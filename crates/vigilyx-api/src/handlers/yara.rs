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
) -> impl IntoResponse {
    let now = Utc::now().to_rfc3339();
    let rule = vigilyx_db::YaraRuleRow {
        id: Uuid::new_v4().to_string(),
        rule_name: req.rule_name,
        category: req.category,
        severity: req.severity,
        source: "custom".to_string(),
        rule_source: req.rule_source,
        description: req.description.unwrap_or_default(),
        enabled: true,
        hit_count: 0,
        created_at: now.clone(),
        updated_at: now,
    };

    match state.engine_db.insert_yara_rule(&rule).await {
        Ok(()) => {
            publish_engine_reload(&state, "yara").await;
            ApiResponse::ok(serde_json::to_value(&rule).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
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

    let now = Utc::now().to_rfc3339();
    let updated = vigilyx_db::YaraRuleRow {
        id: existing.id,
        rule_name: req.rule_name.unwrap_or(existing.rule_name),
        category: req.category.unwrap_or(existing.category),
        severity: req.severity.unwrap_or(existing.severity),
        source: existing.source,
        rule_source: req.rule_source.unwrap_or(existing.rule_source),
        description: req.description.unwrap_or(existing.description),
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
    let mut compiler = yara_x::Compiler::new();
    match compiler.add_source(req.rule_source.as_str()) {
        Ok(_) => ApiResponse::ok(serde_json::json!({ "valid": true })),
        Err(e) => ApiResponse::ok(serde_json::json!({
            "valid": false,
            "error": format!("{}", e),
        })),
    }
}
