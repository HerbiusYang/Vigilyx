//! Security, Statistics, Process

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::error_codes;

fn feedback_error_response(error: &anyhow::Error) -> axum::response::Response {
    let message = error.to_string();
    if message == vigilyx_engine::feedback::FEEDBACK_RATE_LIMIT_ERROR {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some("Too many feedback submissions; try again later".to_string()),
                error_code: Some(error_codes::AUTH_RATE_LIMITED.to_string()),
            }),
        )
            .into_response();
    }
    if message == vigilyx_engine::feedback::FEEDBACK_DUPLICATE_ERROR {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some("Feedback already submitted for this session".to_string()),
                error_code: Some(error_codes::RESOURCE_CONFLICT.to_string()),
            }),
        )
            .into_response();
    }
    if message == "Session verdict not found"
        || message.starts_with("Invalid feedback_type:")
        || message.starts_with("Feedback module_id exceeds")
        || message.starts_with("Feedback comment exceeds")
    {
        return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
    }

    ApiResponse::<serde_json::Value>::server_error(error, "Feedback operation failed")
        .into_response()
}

// Security Query

/// Get session Security
pub async fn get_session_verdict(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    match state.engine_db.get_verdict_by_session(session_id).await {
        Ok(Some(verdict)) => {
            ApiResponse::ok(serde_json::to_value(verdict).unwrap_or_default()).into_response()
        }
        Ok(None) => ApiResponse::ok(serde_json::json!(null)).into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Get session Moduledetect
pub async fn get_session_security_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    match state
        .engine_db
        .get_module_results_by_session(session_id)
        .await
    {
        Ok(results) => {
            ApiResponse::ok(serde_json::to_value(results).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

// risk table (+ metadata)

#[derive(Debug, Deserialize)]
pub struct VerdictListParams {
    #[serde(default = "default_verdict_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub threat_level: Option<String>,
}

fn default_verdict_limit() -> u32 {
    30
}

/// Security (metadata)
pub async fn list_recent_verdicts(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<VerdictListParams>,
) -> impl IntoResponse {
    params.limit = params.limit.clamp(1, 1000);
    match state
        .engine_db
        .list_recent_verdicts(params.threat_level.as_deref(), params.limit, params.offset)
        .await
    {
        Ok((items, total)) => ApiResponse::ok(serde_json::json!({
            "items": items,
            "total": total,
            "limit": params.limit,
            "offset": params.offset,
        })),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

// Statistics monitor

/// GetSecurityStatistics
pub async fn get_security_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_security_stats().await {
        Ok(stats) => ApiResponse::ok(serde_json::to_value(stats).unwrap_or_default()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// GetEngine status

/// DataSource Level:
/// 1. Redis TTL key (engine heartbeat)
/// 2. In-memory cache (engine_status RwLock)
/// 3. Fallback -> running: false
pub async fn get_engine_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(snapshot) = super::load_engine_status_snapshot(&state).await
        && snapshot.heartbeat_secs < 30
    {
        return ApiResponse::ok(super::normalize_engine_status_payload(snapshot.status));
    }

    ApiResponse::ok(super::default_engine_status_payload())
}

pub async fn submit_feedback(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(req): Json<vigilyx_engine::feedback::SubmitFeedbackRequest>,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    let feedback_mgr = vigilyx_engine::feedback::FeedbackManager::new(
        state.engine_db.clone(),
        state.managers.ioc_manager.clone(),
    );

    let can_save_training_sample = user.has_permission("ai.training");
    let can_adjust_ioc = user.has_permission("security.ioc.manage");
    match feedback_mgr
        .submit(
            session_id,
            &req,
            &user.username,
            can_save_training_sample,
            can_adjust_ioc,
        )
        .await
    {
        Ok(result) => {
            if result.training_sample_saved {
                let db = state.engine_db.clone();
                let username = user.username.clone();
                tokio::spawn(async move {
                    if let Err(e) = db
                        .write_audit_log(
                            &username,
                            "feedback_training_sample_saved",
                            Some("training"),
                            Some(&session_id.to_string()),
                            None,
                            None,
                        )
                        .await
                    {
                        tracing::error!(error = %e, "Audit: failed to write feedback training audit log");
                    }
                });
            }
            ApiResponse::ok(serde_json::to_value(result).unwrap_or_default()).into_response()
        }
        Err(e) => {
            feedback_error_response(&e)
        }
    }
}

/// Get Statistics
pub async fn get_feedback_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_feedback_stats().await {
        Ok(stats) => ApiResponse::ok(serde_json::to_value(stats).unwrap_or_default()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}
