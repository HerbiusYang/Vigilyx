//! Sniffer Data securityConfiguration, time Configuration

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::super::ApiResponse;
use super::{publish_engine_reload, publish_sniffer_reload};
use crate::AppState;
use crate::auth::AuthenticatedUser;
use vigilyx_engine::data_security::time_policy::TimePolicyConfig;

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
        Ok(Some(json)) => match parse_time_policy_json(&json) {
            Ok(config) => ApiResponse::ok(config),
            Err(_) => ApiResponse::ok(default_time_policy_config()),
        },
        Ok(None) => ApiResponse::ok(default_time_policy_config()),
        Err(e) => ApiResponse::<TimePolicyConfig>::internal_err(&e, "Operation failed"),
    }
}

/// NewData securitytime Configuration
pub async fn update_time_policy_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
    let config = match parse_time_policy_config(config) {
        Ok(config) => config,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::bad_request(error).into_response();
        }
    };

    let json_str = match serde_json::to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("序列化failed: {}", e))
                .into_response();
        }
    };
    match state.engine_db.set_time_policy_config(&json_str).await {
        Ok(()) => {
            publish_engine_reload(&state, "time_policy").await;
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

fn parse_time_policy_config(config: serde_json::Value) -> Result<TimePolicyConfig, String> {
    let config: TimePolicyConfig =
        serde_json::from_value(config).map_err(|e| format!("Invalid time policy config: {e}"))?;
    config.validate()?;
    Ok(config)
}

fn parse_time_policy_json(json: &str) -> Result<TimePolicyConfig, String> {
    let config: TimePolicyConfig =
        serde_json::from_str(json).map_err(|e| format!("Invalid time policy config: {e}"))?;
    config.validate()?;
    Ok(config)
}

fn default_time_policy_config() -> TimePolicyConfig {
    TimePolicyConfig::default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::parse_time_policy_config;

    #[test]
    fn accepts_half_hour_utc_offset() {
        let config = parse_time_policy_config(json!({
            "enabled": true,
            "work_hour_start": 8,
            "work_hour_end": 18,
            "utc_offset_hours": 5.5,
            "weekend_is_off_hours": true
        }))
        .expect("UTC+5:30 should be accepted");

        assert_eq!(config.utc_offset_hours, 5.5);
    }

    #[test]
    fn rejects_non_quarter_hour_utc_offset() {
        let result = parse_time_policy_config(json!({
            "utc_offset_hours": 5.1
        }));

        assert!(result.is_err());
    }
}
