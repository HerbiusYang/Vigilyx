//! Session Process: table,, EML, Session

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;
use vigilyx_core::EmailSession;

use super::{ApiResponse, PaginatedResponse, PaginationParams, clamp_limit};
use crate::AppState;

/// GetSession table
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<PaginationParams>,
) -> impl IntoResponse {
    params.limit = clamp_limit(params.limit);
    let offset = (params.page.saturating_sub(1)) * params.limit;

    match state
        .db
        .list_sessions(
            params.limit,
            offset,
            params.protocol.as_deref(),
            params.status.as_deref(),
            params.since.as_deref(),
            params.content_filter.as_deref(),
            params.auth_filter.as_deref(),
            params.source_ips.as_deref(),
            params.dest_ips.as_deref(),
            params.search.as_deref(),
            &[],
            params.skip_count,
        )
        .await
    {
        Ok((sessions, total)) => {
            let total_pages = (total as f64 / params.limit as f64).ceil() as u32;
            ApiResponse::ok(PaginatedResponse {
                items: sessions,
                total,
                page: params.page,
                limit: params.limit,
                total_pages,
            })
        }
        Err(e) => {
            ApiResponse::<PaginatedResponse<EmailSession>>::internal_err(&e, "Operation failed")
        }
    }
}

/// Get Session
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                ApiResponse::<EmailSession>::err("Invalid UUID"),
            );
        }
    };

    match state.db.get_session(uuid).await {
        Ok(Some(session)) => (StatusCode::OK, ApiResponse::ok(session)),
        Ok(None) => (StatusCode::NOT_FOUND, ApiResponse::err("Session not found")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::internal_err(&e, "Operation failed"),
        ),
    }
}

/// Session EML File (RFC 2822 format)
pub async fn download_eml(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::header;

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UUID").into_response();
        }
    };

    match state.db.get_session(uuid).await {
        Ok(Some(session)) => {
            let eml_bytes = session.reconstruct_eml();
            if eml_bytes.is_empty() {
                return (StatusCode::NOT_FOUND, "No email content to reconstruct").into_response();
            }

           // Sanitize filename from subject
            let filename = session
                .subject
                .as_deref()
                .unwrap_or("email")
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .take(50)
                .collect::<String>();
            let filename = if filename.trim().is_empty() {
                "email".to_string()
            } else {
                filename
            };

            axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "message/rfc822")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}.eml\"", filename),
                )
                .body(Body::from(eml_bytes))
                .unwrap_or_else(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build response",
                    )
                        .into_response()
                })
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Session not found").into_response(),
       // SEC-H06: client Data error (CWE-209)
        Err(e) => {
            tracing::error!("EML 下载failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

/// Get Session(Message-ID)
pub async fn get_related_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                ApiResponse::<Vec<EmailSession>>::err("Invalid UUID"),
            );
        }
    };

    let session = match state.db.get_session(uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, ApiResponse::err("Session not found")),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::internal_err(&e, "Operation failed"),
            );
        }
    };

    let mut related: Vec<EmailSession> = Vec::new();

   // Message-ID
    if let Some(ref mid) = session.message_id
        && !mid.is_empty()
        && let Ok(msg_related) = state.db.find_related_sessions(mid, uuid).await
    {
        related = msg_related;
    }

    related.sort_by_key(|s| s.started_at);
    (StatusCode::OK, ApiResponse::ok(related))
}
