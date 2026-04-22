//! Shared API response helpers and handler exports.

pub mod audit;
pub mod data_security;
pub mod database;
pub mod deployment_mode;
pub mod health;
pub mod ioc_handlers;
pub mod security;
pub mod sessions;
pub mod setup_status;
pub mod stats;
pub mod syslog_config;
pub mod system;
pub mod training;
pub mod ui_preferences;
pub mod yara;

// Re-export all handler functions so routes.rs can use `handlers::function_name`
pub use audit::{list_audit_logs, list_login_history};
pub use database::{
    clear_database, factory_reset, get_rotate_config, import_sessions, precise_clear,
    update_rotate_config, update_stats,
};
pub use sessions::{download_eml, get_related_sessions, get_session, list_sessions};
pub use deployment_mode::{get_deployment_mode, update_deployment_mode};
pub use setup_status::{get_setup_status, update_setup_status};
pub use stats::{get_external_login_stats, get_stats};
pub use ui_preferences::{get_ui_preferences, update_ui_preferences};
pub use system::{
    MtaStatus, SnifferStatus, get_host_interfaces, get_system_metrics, get_system_status,
    update_mta_status, update_sniffer_status,
};

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::error_codes;

pub(crate) fn spawn_audit_log(
    db: vigilyx_db::VigilDb,
    operator: String,
    operation: &'static str,
    resource_type: Option<&'static str>,
    resource_id: Option<String>,
    detail: Option<String>,
) {
    tokio::spawn(async move {
        if let Err(error) = db
            .write_audit_log(
                &operator,
                operation,
                resource_type,
                resource_id.as_deref(),
                detail.as_deref(),
                None,
            )
            .await
        {
            tracing::error!(
                operation,
                error = %error,
                "Audit: failed to write audit log"
            );
        }
    });
}

/// Paginationparameter
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub protocol: Option<String>,
    pub status: Option<String>,
   /// time (ISO 8601)
    pub since: Option<String>,
   /// : "WITH_CONTENT" | "ENCRYPTED" | "NON_ENCRYPTED"
    pub content_filter: Option<String>,
   /// Authentication: "WITH_AUTH" | "AUTH_SUCCESS" | "AUTH_FAILED"
    pub auth_filter: Option<String>,
   /// Source IP (): client_ip (send / Connection)
    pub source_ips: Option<String>,
   /// target IP (): server_ip (receive / Service)
    pub dest_ips: Option<String>,
   /// : client_ip, server_ip, mail_from, rcpt_to, subject
    pub search: Option<String>,
   /// COUNT Query (table, ~4.5s)
    #[serde(default)]
    pub skip_count: bool,
}

fn default_page() -> u32 {
    1
}
fn default_limit() -> u32 {
    50
}
/// Pagination limit (client value OOM)
const MAX_LIMIT: u32 = 1000;

/// limit [1, MAX_LIMIT]
pub(crate) fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_LIMIT)
}

/// response

/// `error_code` field error found,successresponse Contains (skip_serializing_if).
/// client Processerror, errormessage.
/// Error [`crate::error_codes`].
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
   /// error (Such as "AUTH_001", "VAL_002", "RES_001"),successresponse Contains field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
            error_code: None,
        })
    }

   /// error (, error_code)
    pub fn err(error: impl Into<String>) -> Json<Self> {
        Json(Self {
            success: false,
            data: None,
            error: Some(error.into()),
            error_code: None,
        })
    }

   /// Log the internal error server-side while returning a masked client message.
    pub fn internal_err(error: &dyn std::fmt::Display, context: &str) -> Json<Self> {
        tracing::error!(error = %error, "{}", context);
        Json(Self {
            success: false,
            data: None,
            error: Some("Internal server error".to_string()),
            error_code: Some(error_codes::INTERNAL_DATABASE_ERROR.to_string()),
        })
    }

   /// 400 Bad Request - verifyerror, formaterror, parameter
    
   /// `bad_request_with_code` error,
   /// Default `VAL_002` (VALIDATION_INVALID_PARAMS).
    pub fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
                error_code: Some(error_codes::VALIDATION_INVALID_PARAMS.to_string()),
            }),
        )
    }

   /// 400 Bad Request - error
    #[allow(dead_code)]
    pub fn bad_request_with_code(msg: impl Into<String>, code: &str) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
                error_code: Some(code.to_string()),
            }),
        )
    }

   /// 404 Not Found - Source
    pub fn not_found(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::NOT_FOUND,
            Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
                error_code: Some(error_codes::RESOURCE_NOT_FOUND.to_string()),
            }),
        )
    }

   /// Return a masked 500 response while logging the detailed error server-side.
    pub fn server_error(error: &dyn std::fmt::Display, context: &str) -> (StatusCode, Json<Self>) {
        tracing::error!(error = %error, "{}", context);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self {
                success: false,
                data: None,
                error: Some("Internal server error".to_string()),
                error_code: Some(error_codes::INTERNAL_DATABASE_ERROR.to_string()),
            }),
        )
    }
}

/// Paginationresponse
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

/// Health check (, liveness)
pub async fn health_check() -> impl IntoResponse {
    health::liveness().await
}
