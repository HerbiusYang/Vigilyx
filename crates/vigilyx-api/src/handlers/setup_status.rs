use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

const SETUP_STATUS_KEY: &str = "ui_setup_status";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatus {
    pub completed: bool,
}

pub async fn get_setup_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_config(SETUP_STATUS_KEY).await {
        Ok(Some(raw)) => ApiResponse::ok(parse_setup_status(&raw)),
        Ok(None) => ApiResponse::ok(default_setup_status()),
        Err(e) => ApiResponse::<SetupStatus>::internal_err(&e, "load setup status failed"),
    }
}

pub async fn update_setup_status(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(status): Json<SetupStatus>,
) -> axum::response::Response {
    let json = match serde_json::to_string(&status) {
        Ok(json) => json,
        Err(e) => {
            return ApiResponse::<SetupStatus>::bad_request(format!(
                "setup status serialize failed: {}",
                e
            ))
            .into_response();
        }
    };

    match state.engine_db.set_config(SETUP_STATUS_KEY, &json).await {
        Ok(()) => {
            let db = state.engine_db.clone();
            let action = if status.completed {
                "complete_setup_wizard"
            } else {
                "reset_setup_wizard"
            }
            .to_string();

            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(&username, &action, Some("config"), None, None, None)
                    .await
                {
                    tracing::error!(error = %e, "audit: setup status write failed");
                }
            });

            ApiResponse::ok(status).into_response()
        }
        Err(e) => {
            ApiResponse::<SetupStatus>::internal_err(&e, "save setup status failed").into_response()
        }
    }
}

fn default_setup_status() -> SetupStatus {
    SetupStatus { completed: false }
}

fn parse_setup_status(raw: &str) -> SetupStatus {
    if let Ok(status) = serde_json::from_str::<SetupStatus>(raw) {
        return status;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(completed) = value.get("completed").and_then(|v| v.as_bool()) {
            return SetupStatus { completed };
        }
        if let Some(completed) = value.as_bool() {
            return SetupStatus { completed };
        }
    }

    let completed = matches!(raw.trim(), "true" | "\"true\"" | "1");
    SetupStatus { completed }
}
