//! Sniffer Data securityConfiguration, time Configuration

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::super::ApiResponse;
use super::publish_sniffer_reload;
use crate::AppState;
use crate::auth::AuthenticatedUser;


// Sniffer Data securityConfiguration


/// Get Sniffer Data securityConfiguration (webmail_servers, http_ports)
pub async fn get_sniffer_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_sniffer_config().await {
        Ok(Some(json)) => match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(val) => ApiResponse::ok(val),
            Err(_) => ApiResponse::ok(default_sniffer_config()),
        },
        Ok(None) => ApiResponse::ok(default_sniffer_config()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// New Sniffer Data securityConfiguration
pub async fn update_sniffer_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
   // verifyformat: webmail_servers () http_ports ()
    if let Some(servers) = config.get("webmail_servers") {
        if !servers.is_array() {
            return ApiResponse::<serde_json::Value>::bad_request("webmail_servers 必须是数组")
                .into_response();
        }
       // verify IP format
        if let Some(arr) = servers.as_array() {
            for item in arr {
                if let Some(ip) = item.as_str()
                    && ip.parse::<std::net::IpAddr>().is_err()
                {
                    return ApiResponse::<serde_json::Value>::bad_request(format!(
                        "无效 IP Address: {}",
                        ip
                    ))
                    .into_response();
                }
            }
        }
    }
    if let Some(ports) = config.get("http_ports")
        && !ports.is_array()
    {
        return ApiResponse::<serde_json::Value>::bad_request("http_ports 必须是数组")
            .into_response();
    }

    let json_str = match serde_json::to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("序列化failed: {}", e))
                .into_response();
        }
    };
    match state.engine_db.set_sniffer_config(&json_str).await {
        Ok(()) => {
           // Sniffer process Configuration
            publish_sniffer_reload(&state).await;
            ApiResponse::ok(config).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// internal: Sniffer Start Configuration (JWT)
pub async fn get_sniffer_config_internal(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_sniffer_config().await {
        Ok(Some(json)) => match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(val) => ApiResponse::ok(val),
            Err(_) => ApiResponse::ok(default_sniffer_config()),
        },
        Ok(None) => ApiResponse::ok(default_sniffer_config()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

fn default_sniffer_config() -> serde_json::Value {
    serde_json::json!({
        "webmail_servers": [],
        "http_ports": [80, 443, 8080]
    })
}


// Data securitytime Configuration


/// GetData securitytime Configuration
pub async fn get_time_policy_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_time_policy_config().await {
        Ok(Some(json)) => match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(val) => ApiResponse::ok(val),
            Err(_) => ApiResponse::ok(default_time_policy_config()),
        },
        Ok(None) => ApiResponse::ok(default_time_policy_config()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// NewData securitytime Configuration
pub async fn update_time_policy_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
   // verify work_hour_start
    if let Some(start) = config.get("work_hour_start").and_then(|v| v.as_u64())
        && start > 23
    {
        return ApiResponse::<serde_json::Value>::bad_request("work_hour_start 必须在 0-23 之间")
            .into_response();
    }
   // verify work_hour_end
    if let Some(end) = config.get("work_hour_end").and_then(|v| v.as_u64())
        && (end > 24 || end == 0)
    {
        return ApiResponse::<serde_json::Value>::bad_request("work_hour_end 必须在 1-24 之间")
            .into_response();
    }
   // verify start <end
    let start = config
        .get("work_hour_start")
        .and_then(|v| v.as_u64())
        .unwrap_or(8);
    let end = config
        .get("work_hour_end")
        .and_then(|v| v.as_u64())
        .unwrap_or(18);
    if start >= end {
        return ApiResponse::<serde_json::Value>::bad_request(
            "work_hour_start 必须小于 work_hour_end",
        )
        .into_response();
    }
   // verify utc_offset_hours
    if let Some(offset) = config.get("utc_offset_hours").and_then(|v| v.as_i64())
        && !(-12..=14).contains(&offset)
    {
        return ApiResponse::<serde_json::Value>::bad_request(
            "utc_offset_hours 必须在 -12 到 +14 之间",
        )
        .into_response();
    }

    let json_str = match serde_json::to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("序列化failed: {}", e))
                .into_response();
        }
    };
    match state.engine_db.set_time_policy_config(&json_str).await {
        Ok(()) => {
           // log
            let db = state.engine_db.clone();
            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(
                        &username,
                        "update_time_policy_config",
                        Some("config"),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "审计: time策略Configuration审计log写入failed");
                }
            });
            ApiResponse::ok(config).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

fn default_time_policy_config() -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "work_hour_start": 8,
        "work_hour_end": 18,
        "utc_offset_hours": 8,
        "weekend_is_off_hours": true
    })
}
