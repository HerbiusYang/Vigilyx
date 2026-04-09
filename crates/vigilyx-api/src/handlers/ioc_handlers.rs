//! IOC (Indicator of Compromise) management API handlers

//! Endpoints:
//! - GET /security/ioc - List IOCs
//! - POST /security/ioc - Add IOC
//! - DELETE /security/ioc/{id} - Delete IOC
//! - PUT /security/ioc/{id}/extend - Extend IOC expiry
//! - POST /security/ioc/import - Import IOC (CSV)
//! - POST /security/ioc/import-batch - Batch import IOC (JSON)
//! - GET /security/ioc/export - Export IOC (CSV)

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::ApiResponse;
use super::security::publish_engine_reload;
use crate::AppState;


// Request/response types


#[derive(Debug, Deserialize)]
pub struct IocQueryParams {
    #[serde(default = "default_ioc_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub ioc_type: Option<String>,
    pub source: Option<String>,
    pub search: Option<String>,
}

fn default_ioc_limit() -> u32 {
    50
}

/// Add IOC request
#[derive(Debug, Deserialize)]
pub struct AddIocRequest {
    pub indicator: String,
    pub ioc_type: String,
    #[serde(default = "default_suspicious")]
    pub verdict: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    pub description: Option<String>,
   /// Attack type: phishing, spoofing, malware, bec, spam, unknown
    #[serde(default)]
    pub attack_type: String,
}

fn default_suspicious() -> String {
    "suspicious".to_string()
}
fn default_confidence() -> f64 {
    0.7
}

/// IOC time
#[derive(Debug, Deserialize)]
pub struct ExtendIocRequest {
   /// Day (Default 30)
    #[serde(default = "default_extend_days")]
    pub days: i64,
}

fn default_extend_days() -> i64 {
    30
}

/// IOC request
#[derive(Debug, Deserialize)]
pub struct BatchImportIocRequest {
    pub items: Vec<vigilyx_engine::ioc::BatchIocInput>,
}

/// Export IOC Queryparameter
#[derive(Debug, Deserialize)]
pub struct ExportIocParams {
   /// verdict (Such as "malicious,suspicious")
    pub verdict: Option<String>,
}


// Process


/// IOC
pub async fn list_ioc(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<IocQueryParams>,
) -> impl IntoResponse {
    params.limit = params.limit.clamp(1, 1000);
    match state
        .engine_db
        .list_ioc(
            params.ioc_type.as_deref(),
            params.source.as_deref(),
            params.search.as_deref(),
            params.limit,
            params.offset,
        )
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

/// IOC
pub async fn add_ioc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddIocRequest>,
) -> impl IntoResponse {
    match state
        .managers
        .ioc_manager
        .add_manual_with_attack(
            req.indicator,
            req.ioc_type,
            req.verdict,
            req.confidence,
            req.description,
            req.attack_type,
        )
        .await
    {
        Ok(ioc) => {
            publish_engine_reload(&state, "ioc").await;
            ApiResponse::ok(serde_json::to_value(ioc).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Delete IOC
pub async fn delete_ioc(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let ioc_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid IOC ID").into_response();
        }
    };

    match state.engine_db.delete_ioc(ioc_id).await {
        Ok(true) => {
            publish_engine_reload(&state, "ioc").await;
            ApiResponse::ok(serde_json::json!({"deleted": true})).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("IOC not found").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// IOC time
pub async fn extend_ioc(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ExtendIocRequest>,
) -> axum::response::Response {
    let ioc_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid IOC ID").into_response();
        }
    };
    let days = req.days.clamp(1, 365);
    match state.engine_db.extend_ioc_expiry(ioc_id, days).await {
        Ok(true) => {
            ApiResponse::ok(serde_json::json!({"extended": true, "days": days})).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("IOC not found").into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Import IOC (CSV)
pub async fn import_ioc(State(state): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    match state.managers.ioc_manager.import_csv(&body).await {
        Ok(result) => {
            publish_engine_reload(&state, "ioc").await;
            ApiResponse::ok(serde_json::to_value(result).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// IOC (JSON)
pub async fn import_ioc_batch(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BatchImportIocRequest>,
) -> impl IntoResponse {
    match state.managers.ioc_manager.import_batch(req.items).await {
        Ok(result) => {
            publish_engine_reload(&state, "ioc").await;
            ApiResponse::ok(serde_json::to_value(result).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Export IOC (CSV)
/// ?verdict=malicious,suspicious (Default)
pub async fn export_ioc(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ExportIocParams>,
) -> impl IntoResponse {
    let verdicts: Option<Vec<String>> = params.verdict.map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });
    match state
        .managers
        .ioc_manager
        .export_csv_filtered(verdicts.as_deref())
        .await
    {
        Ok(csv) => (
            axum::http::StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"vigilyx-ioc-export.csv\"",
                ),
            ],
            csv,
        ),
       // SEC: client Data error (CWE-209)
        Err(e) => {
            tracing::error!("IOC 导出failed: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; charset=utf-8",
                    ),
                    (axum::http::header::CONTENT_DISPOSITION, "inline"),
                ],
                "Internal error".to_string(),
            )
        }
    }
}
