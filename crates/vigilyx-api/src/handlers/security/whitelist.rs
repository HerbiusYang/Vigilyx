//! Process

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

use super::super::ApiResponse;
use super::publish_engine_reload;
use crate::AppState;
use crate::auth::AuthenticatedUser;





/// Get
pub async fn get_whitelist(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.managers.whitelist_manager.list().await {
        Ok(entries) => ApiResponse::ok(serde_json::to_value(entries).unwrap_or_default()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

fn normalize_whitelist_type(entry_type: &str) -> Result<String, String> {
    let normalized = entry_type.trim().to_lowercase();
    match normalized.as_str() {
        "domain" | "ip" | "email" | "hash" => Ok(normalized),
        _ => Err("Unsupported whitelist type".to_string()),
    }
}

fn normalize_whitelist_value(entry_type: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Whitelist value cannot be empty".to_string());
    }

    match entry_type {
        "domain" | "email" | "hash" => Ok(trimmed.to_lowercase()),
        "ip" => Ok(trimmed.to_string()),
        _ => Err("Unsupported whitelist type".to_string()),
    }
}

fn normalize_description(description: Option<String>) -> Option<String> {
    description.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// New request
#[derive(Debug, Deserialize)]
pub struct UpdateWhitelistRequest {
    pub entries: Vec<WhitelistEntryInput>,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistEntryInput {
    pub entry_type: String,
    pub value: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddWhitelistEntryRequest {
    pub entry_type: String,
    pub value: String,
    pub description: Option<String>,
}

fn normalize_whitelist_entries(
    entries: Vec<WhitelistEntryInput>,
    created_by: &str,
) -> Result<Vec<vigilyx_core::security::WhitelistEntry>, String> {
    let mut dedup = HashSet::new();
    let mut normalized = Vec::new();

    for entry in entries {
        let entry_type = normalize_whitelist_type(&entry.entry_type)?;
        let value = normalize_whitelist_value(&entry_type, &entry.value)?;
        if !dedup.insert((entry_type.clone(), value.clone())) {
            continue;
        }

        normalized.push(vigilyx_core::security::WhitelistEntry {
            id: Uuid::new_v4(),
            entry_type,
            value,
            description: normalize_description(entry.description),
            created_at: Utc::now(),
            created_by: created_by.to_string(),
        });
    }

    Ok(normalized)
}

/// New ()
pub async fn update_whitelist(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<UpdateWhitelistRequest>,
) -> Response {
    let entries = match normalize_whitelist_entries(req.entries, &user.username) {
        Ok(entries) => entries,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(&message).into_response();
        }
    };

    match state.managers.whitelist_manager.set_all(entries).await {
        Ok(()) => {
           // Engine process New
            publish_engine_reload(&state, "whitelist").await;
            match state.managers.whitelist_manager.list().await {
                Ok(saved) => {
                    ApiResponse::ok(serde_json::to_value(saved).unwrap_or_default()).into_response()
                }
                Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response(),
            }
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed").into_response()
        }
    }
}

/// Add
pub async fn add_whitelist_entry(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<AddWhitelistEntryRequest>,
) -> Response {
    let entry_type = match normalize_whitelist_type(&req.entry_type) {
        Ok(value) => value,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(&message).into_response();
        }
    };
    let value = match normalize_whitelist_value(&entry_type, &req.value) {
        Ok(value) => value,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(&message).into_response();
        }
    };
    let description = normalize_description(req.description);

    if state
        .managers
        .whitelist_manager
        .is_whitelisted(&entry_type, &value)
        .await
    {
        return match state.managers.whitelist_manager.list().await {
            Ok(entries) => {
                let existing = entries
                    .into_iter()
                    .find(|entry| entry.entry_type == entry_type && entry.value == value);
                match existing {
                    Some(entry) => {
                        ApiResponse::ok(serde_json::to_value(entry).unwrap_or_default())
                            .into_response()
                    }
                    None => ApiResponse::<serde_json::Value>::ok(serde_json::json!({
                        "entry_type": entry_type,
                        "value": value,
                    }))
                    .into_response(),
                }
            }
            Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                .into_response(),
        };
    }

    match state
        .managers
        .whitelist_manager
        .add_with_creator(entry_type, value, description, &user.username)
        .await
    {
        Ok(entry) => {
            publish_engine_reload(&state, "whitelist").await;
            ApiResponse::ok(serde_json::to_value(entry).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed").into_response()
        }
    }
}

/// delete
pub async fn delete_whitelist_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let whitelist_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid ID").into_response();
        }
    };

    match state.managers.whitelist_manager.remove(whitelist_id).await {
        Ok(true) => {
            publish_engine_reload(&state, "whitelist").await;
            ApiResponse::ok(serde_json::json!({ "deleted": true })).into_response()
        }
        Ok(false) => {
            ApiResponse::<serde_json::Value>::not_found("Whitelist entry not found").into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed").into_response()
        }
    }
}
