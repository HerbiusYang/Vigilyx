//! log Process

use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

use super::ApiResponse;
use crate::AppState;

/// Auditlog
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50u32)
        .min(200);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0u32);
    match state.engine_db.list_audit_logs(limit, offset).await {
        Ok((items, total)) => {
            ApiResponse::ok(serde_json::json!({ "items": items, "total": total }))
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Login
pub async fn list_login_history(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50u32)
        .min(200);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0u32);
    match state.engine_db.list_login_history(limit, offset).await {
        Ok((items, total)) => {
            ApiResponse::ok(serde_json::json!({ "items": items, "total": total }))
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}
