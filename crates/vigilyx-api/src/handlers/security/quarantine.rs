//! API

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

use super::super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

#[derive(Debug, Deserialize)]
pub struct QuarantineListQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseRequest {
   /// Ignored - operator is extracted from JWT. Kept for backward API compatibility.
    #[serde(default)]
    pub _released_by: Option<String>,
}

/// GET /security/quarantine
pub async fn list_quarantine(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QuarantineListQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    match state
        .db
        .quarantine_list(params.status.as_deref(), limit, offset)
        .await
    {
        Ok(entries) => ApiResponse::ok(serde_json::json!({
            "items": entries,
            "limit": limit,
            "offset": offset,
        }))
        .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Failed to list quarantine")
            .into_response(),
    }
}

/// GET /security/quarantine/stats
pub async fn quarantine_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let quarantined = state
        .db
        .quarantine_count(Some("quarantined"))
        .await
        .unwrap_or(0);
    let released = state
        .db
        .quarantine_count(Some("released"))
        .await
        .unwrap_or(0);
    let total = state.db.quarantine_count(None).await.unwrap_or(0);

    ApiResponse::ok(serde_json::json!({
        "quarantined": quarantined,
        "released": released,
        "total": total,
    }))
}

/// POST /security/quarantine/:id/release
pub async fn release_quarantine(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(_body): Json<ReleaseRequest>,
) -> impl IntoResponse {
   // SEC: Use authenticated username from JWT, never trust client-supplied released_by
    let released_by = &user.username;

    match state.db.quarantine_release(&id, released_by).await {
        Ok(true) => (
            StatusCode::OK,
            ApiResponse::ok(serde_json::json!({
                "id": id,
                "status": "released",
                "released_by": released_by,
            })),
        )
            .into_response(),
        Ok(false) => ApiResponse::<serde_json::Value>::not_found(
            "Quarantine entry not found or already released",
        )
        .into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Failed to release quarantine")
                .into_response()
        }
    }
}

/// DELETE /security/quarantine/:id
pub async fn delete_quarantine(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.quarantine_delete(&id).await {
        Ok(true) => (
            StatusCode::OK,
            ApiResponse::ok(serde_json::json!({"id": id, "deleted": true})),
        )
            .into_response(),
        Ok(false) => {
            ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
                .into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Failed to delete quarantine")
                .into_response()
        }
    }
}
