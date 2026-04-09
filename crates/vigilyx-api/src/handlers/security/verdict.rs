//! Security, Statistics, Process

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::super::ApiResponse;
use crate::AppState;


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
/// 1. UDS/Redis status (engine_status RwLock)
/// 2. File data/engine-status.json (Engine 5)
/// 3. -> running: false
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

    match feedback_mgr.submit(session_id, &req).await {
        Ok(result) => {
            ApiResponse::ok(serde_json::to_value(result).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
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
