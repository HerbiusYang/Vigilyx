//! Read-only diagnostics for feedback-driven D-S learning.
use super::super::ApiResponse;
use crate::{AppState, auth::AuthenticatedUser};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDsModel {
    pub expected_revision: u64,
    pub model: vigilyx_core::security::DsModelParameters,
    pub acceptance: vigilyx_engine::ds_learning::Acceptance,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackDsModel {
    pub expected_revision: u64,
}

async fn load_state(
    state: &AppState,
) -> anyhow::Result<(Option<String>, vigilyx_engine::ds_learning::LearningState)> {
    let raw = state
        .engine_db
        .get_config(vigilyx_engine::ds_learning::STATE_KEY)
        .await?;
    let value = raw
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();
    Ok((raw, value))
}

async fn store_model_change(
    state: &AppState,
    user: &AuthenticatedUser,
    raw: Option<String>,
    mut model_state: vigilyx_engine::ds_learning::LearningState,
    expected_revision: u64,
    action: &'static str,
) -> axum::response::Response {
    if model_state.revision != expected_revision {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"success":false,"error":"DS revision changed; reload before installing"}))).into_response();
    }
    if let Err(error) = model_state.validate() {
        return ApiResponse::<serde_json::Value>::bad_request(error).into_response();
    }
    model_state.revision += 1;
    model_state.updated_at = chrono::Utc::now().to_rfc3339();
    let result = async {
        let value = serde_json::to_string(&model_state)?;
        state
            .engine_db
            .compare_and_set_config(
                vigilyx_engine::ds_learning::STATE_KEY,
                raw.as_deref(),
                &value,
            )
            .await
    }
    .await;
    match result {
        Ok(true) => {
            super::publish_engine_reload(state, "ds_learning").await;
            crate::handlers::spawn_audit_log(state.engine_db.clone(), user.username.clone(), action,
                Some("security"), Some(vigilyx_engine::ds_learning::STATE_KEY.into()), None);
            ApiResponse::ok(model_state).into_response()
        }
        Ok(false) => (StatusCode::CONFLICT, Json(serde_json::json!({"success":false,"error":"DS revision changed; reload before installing"}))).into_response(),
        Err(error) => ApiResponse::<serde_json::Value>::server_error(&error,"DS model update failed").into_response(),
    }
}

pub async fn install_ds_model(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<InstallDsModel>,
) -> axum::response::Response {
    if !user.has_permission("ai.training") || !user.has_permission("security.manage") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"success":false,"error":"Permission denied"})),
        )
            .into_response();
    }
    match load_state(&state).await {
        Ok((raw, mut value)) => {
            value.previous_active = value.active.take();
            value.previous_acceptance = value.active_acceptance.take();
            value.active = Some(request.model);
            value.active_acceptance = Some(request.acceptance);
            store_model_change(
                &state,
                &user,
                raw,
                value,
                request.expected_revision,
                "install_validated_ds_model",
            )
            .await
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "DS state unavailable")
                .into_response()
        }
    }
}

pub async fn rollback_ds_model(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<RollbackDsModel>,
) -> axum::response::Response {
    if !user.has_permission("ai.training") || !user.has_permission("security.manage") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"success":false,"error":"Permission denied"})),
        )
            .into_response();
    }
    match load_state(&state).await {
        Ok((raw, mut value)) => {
            std::mem::swap(&mut value.active, &mut value.previous_active);
            std::mem::swap(&mut value.active_acceptance, &mut value.previous_acceptance);
            store_model_change(
                &state,
                &user,
                raw,
                value,
                request.expected_revision,
                "rollback_ds_model",
            )
            .await
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "DS state unavailable")
                .into_response()
        }
    }
}

pub async fn get_ds_learning_state(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> axum::response::Response {
    if !user.has_permission("security.read") && !user.has_permission("ai.training") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"success":false,"error":"Permission denied"})),
        )
            .into_response();
    }
    let result = async {
        let raw = state
            .engine_db
            .get_config(vigilyx_engine::ds_learning::STATE_KEY)
            .await?;
        let value: vigilyx_engine::ds_learning::LearningState = raw
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or_default();
        value.validate().map_err(anyhow::Error::msg)?;
        Ok::<_, anyhow::Error>(value)
    }
    .await;
    match result {
        Ok(value) => ApiResponse::ok(value).into_response(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "DS learning state unavailable")
                .into_response()
        }
    }
}
