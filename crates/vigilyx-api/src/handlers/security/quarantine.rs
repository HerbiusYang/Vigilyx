//! API

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::warn;
use vigilyx_db::security::quarantine::QuarantineEntry;
use vigilyx_mta::config::MtaConfig;
use vigilyx_mta::relay::downstream::{DownstreamRelay, RelayResult};

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

fn release_requires_outbound_relay(entry: &QuarantineEntry) -> bool {
    // Current quarantine records do not persist direction. Outbound DLP entries are the
    // only ones that should bypass the inbound downstream relay, and they are tagged
    // with the canonical DLP reason prefix when stored by the MTA.
    entry
        .reason
        .as_deref()
        .is_some_and(|reason| reason.starts_with("DLP:"))
}

async fn load_release_relays() -> Result<(DownstreamRelay, Option<DownstreamRelay>), String> {
    let mut config =
        MtaConfig::from_env().map_err(|e| format!("Failed to load MTA release config: {e}"))?;
    let db_url = config.database_url.clone();
    if !db_url.is_empty()
        && let Err(error) = config.override_from_db(&db_url).await
    {
        warn!(error = %error, "Failed to load MTA DB overrides for quarantine release; falling back to env defaults");
    }

    let downstream = DownstreamRelay::new(&config.downstream)
        .await
        .map_err(|e| format!("Failed to initialize downstream relay: {e}"))?;
    let outbound = match config.outbound.as_ref() {
        Some(outbound_cfg) => Some(
            DownstreamRelay::new(outbound_cfg)
                .await
                .map_err(|e| format!("Failed to initialize outbound relay: {e}"))?,
        ),
        None => None,
    };

    Ok((downstream, outbound))
}

async fn relay_quarantine_release(
    entry: &QuarantineEntry,
    raw_eml: &[u8],
) -> Result<RelayResult, String> {
    let (downstream, outbound) = load_release_relays().await?;
    let relay = if release_requires_outbound_relay(entry) {
        outbound.as_ref().unwrap_or(&downstream)
    } else {
        &downstream
    };

    Ok(relay
        .relay(entry.mail_from.as_deref(), &entry.rcpt_to, raw_eml)
        .await)
}

fn release_conflict_response(status: Option<&str>) -> Response {
    match status {
        None => ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
            .into_response(),
        Some("released") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err("Quarantine entry was already released"),
        )
            .into_response(),
        Some("releasing") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Quarantine entry is already being released by another request",
            ),
        )
            .into_response(),
        Some(_) => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Quarantine entry cannot be released from its current state",
            ),
        )
            .into_response(),
    }
}

async fn rollback_failed_release(state: &AppState, id: &str) -> Result<(), Response> {
    match state.db.quarantine_release_reset(id).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            let rollback_error =
                format!("Release rollback lost ownership for quarantine entry {id}");
            Err(ApiResponse::<serde_json::Value>::server_error(
                &rollback_error,
                "Failed to restore quarantine state after release relay failure",
            )
            .into_response())
        }
        Err(e) => Err(ApiResponse::<serde_json::Value>::server_error(
            &e,
            "Failed to restore quarantine state after release relay failure",
        )
        .into_response()),
    }
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
    let releasing = state
        .db
        .quarantine_count(Some("releasing"))
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
        "releasing": releasing,
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
    let released_by = user.username.clone();

    let (raw_eml, entry) = match state.db.quarantine_claim_release(&id).await {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            let status = match state.db.quarantine_status(&id).await {
                Ok(status) => status,
                Err(e) => {
                    return ApiResponse::<serde_json::Value>::server_error(
                        &e,
                        "Failed to load quarantine release status",
                    )
                    .into_response();
                }
            };
            return release_conflict_response(status.as_deref());
        }
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &e,
                "Failed to claim quarantine entry for release",
            )
            .into_response();
        }
    };

    match relay_quarantine_release(&entry, &raw_eml).await {
        Ok(RelayResult::Accepted) => {}
        Ok(RelayResult::TempFail(msg)) | Ok(RelayResult::ConnError(msg)) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Failed to forward released message: {msg}"
                )),
            )
                .into_response();
        }
        Ok(RelayResult::PermFail(msg)) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::BAD_GATEWAY,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Downstream relay rejected released message: {msg}"
                )),
            )
                .into_response();
        }
        Err(msg) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::<serde_json::Value>::err(msg),
            )
                .into_response();
        }
    }

    match state.db.quarantine_finalize_release(&id, &released_by).await {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                released_by.clone(),
                "release_quarantine",
                Some("security"),
                Some(id.clone()),
                None,
            );
            (
                StatusCode::OK,
                ApiResponse::ok(serde_json::json!({
                    "id": id,
                    "status": "released",
                    "released_by": released_by,
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Message was forwarded, but release finalization failed; entry remains locked to prevent duplicate delivery",
            ),
        )
            .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::server_error(
            &e,
            "Released message was forwarded but database finalization failed; entry remains in releasing state",
        )
        .into_response(),
    }
}

/// DELETE /security/quarantine/:id
pub async fn delete_quarantine(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.quarantine_delete(&id).await {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "delete_quarantine",
                Some("security"),
                Some(id.clone()),
                None,
            );
            (
                StatusCode::OK,
                ApiResponse::ok(serde_json::json!({"id": id, "deleted": true})),
            )
                .into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
            .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::server_error(&e, "Failed to delete quarantine")
            .into_response(),
    }
}
