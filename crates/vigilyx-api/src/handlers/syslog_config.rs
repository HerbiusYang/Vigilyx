//! Syslog configuration API handlers
//!
//! - GET /config/syslog - Get syslog configuration
//! - PUT /config/syslog - Update syslog configuration
//! - POST /config/syslog/test - Test syslog connection

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;
use vigilyx_core::{DEFAULT_BLOCKED_HOSTNAMES, is_sensitive_ip, validate_network_target};

use super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

// Handlers

/// Get syslog configuration
pub async fn get_syslog_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_syslog_config().await {
        Ok(Some(json)) => match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(val) => ApiResponse::ok(val),
            Err(_) => ApiResponse::ok(default_syslog_config()),
        },
        Ok(None) => ApiResponse::ok(default_syslog_config()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Update syslog configuration
pub async fn update_syslog_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
    // Validate protocol
    if let Some(proto) = config.get("protocol").and_then(|v| v.as_str())
        && proto != "tcp"
        && proto != "udp"
    {
        return ApiResponse::<serde_json::Value>::bad_request("Protocol must be tcp or udp")
            .into_response();
    }
    // Validate port
    if let Some(port) = config.get("port").and_then(|v| v.as_u64())
        && (port == 0 || port > 65535)
    {
        return ApiResponse::<serde_json::Value>::bad_request("Port must be between 1 and 65535")
            .into_response();
    }
    // Validate facility
    if let Some(facility) = config.get("facility").and_then(|v| v.as_u64())
        && facility > 23
    {
        return ApiResponse::<serde_json::Value>::bad_request("Facility must be between 0 and 23")
            .into_response();
    }
    // Validate format
    if let Some(fmt) = config.get("format").and_then(|v| v.as_str())
        && fmt != "rfc5424"
        && fmt != "rfc3164"
    {
        return ApiResponse::<serde_json::Value>::bad_request("Format must be rfc5424 or rfc3164")
            .into_response();
    }
    // Validate min_severity
    if let Some(sev) = config.get("min_severity").and_then(|v| v.as_str())
        && !["info", "low", "medium", "high", "critical"].contains(&sev)
    {
        return ApiResponse::<serde_json::Value>::bad_request(
            "min_severity must be one of: info, low, medium, high, critical",
        )
        .into_response();
    }
    // When enabled=true, server_address is required
    let enabled = config
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let addr = config
        .get("server_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if enabled && addr.is_empty() {
        return ApiResponse::<serde_json::Value>::bad_request(
            "Server address is required when syslog is enabled",
        )
        .into_response();
    }

    // SEC: Validate SSRF on save, matching test endpoint behavior (CWE-918)
    if !addr.is_empty() && is_blocked_address(addr) {
        return ApiResponse::<serde_json::Value>::bad_request("Disallowed syslog server address")
            .into_response();
    }

    let json_str = match serde_json::to_string(&config) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Serialization failed: {}",
                e
            ))
            .into_response();
        }
    };
    match state.engine_db.set_syslog_config(&json_str).await {
        Ok(()) => {
            let db = state.engine_db.clone();
            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(
                        &username,
                        "update_syslog_config",
                        Some("config"),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "Audit: failed to write syslog config audit log");
                }
            });
            ApiResponse::ok(config).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Test syslog connection
///
/// SEC: SSRF protection - block connections to metadata/internal addresses (CWE-918)
pub async fn test_syslog_connection(
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
    let syslog_config: vigilyx_engine::syslog::SyslogForwardConfig =
        match serde_json::from_value(config) {
            Ok(c) => c,
            Err(e) => {
                return ApiResponse::<String>::bad_request(format!(
                    "Configuration parse failed: {}",
                    e
                ))
                .into_response();
            }
        };

    // SSRF protection: block connections to metadata/internal addresses
    if is_blocked_address(&syslog_config.server_address) {
        return ApiResponse::<String>::bad_request("Connection to this address is not allowed")
            .into_response();
    }

    match vigilyx_engine::syslog::send_test_message(&syslog_config).await {
        Ok(msg) => ApiResponse::ok(msg).into_response(),
        Err(msg) => ApiResponse::<String>::err(msg).into_response(),
    }
}

/// SEC-M03: SSRF protection - parsed IP check + dangerous hostname blocklist (CWE-918)

/// On top of string prefix matching:
/// - Parsed IP check: block IPv6-mapped IPv4, private ranges
/// - Dangerous hostname blocklist: block localhost, Docker service names, cloud metadata
pub(super) fn is_blocked_address(addr: &str) -> bool {
    let addr_lower = addr.to_lowercase();
    let addr_trimmed = addr_lower.trim();
    // Block dangerous protocol schemes
    if addr_trimmed.starts_with("file:") || addr_trimmed.starts_with("gopher:") {
        return true;
    }

    let host = if addr_trimmed.starts_with('[') {
        // IPv6 [::1]:port format
        addr_trimmed
            .split(']')
            .next()
            .unwrap_or(addr_trimmed)
            .trim_start_matches('[')
    } else if addr_trimmed.contains("://") {
        // URL format: scheme://host:port/path
        addr_trimmed
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .and_then(|host_port| {
                host_port
                    .rsplit_once(':')
                    .map_or(Some(host_port), |(h, _)| Some(h))
            })
            .unwrap_or(addr_trimmed)
    } else {
        // host:port or bare host
        addr_trimmed
            .rsplit_once(':')
            .map_or(addr_trimmed, |(h, port)| {
                if port.parse::<u16>().is_ok() {
                    h
                } else {
                    addr_trimmed
                }
            })
    };

    // Parse as IP address
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_blocked_ip(ip);
    }

    if validate_network_target(host, DEFAULT_BLOCKED_HOSTNAMES).is_err() {
        return true;
    }

    // String fallback (169.254.* / fe80:* prefix)
    if addr_trimmed.starts_with("169.254.") || addr_trimmed.starts_with("fe80:") {
        return true;
    }
    false
}

/// Check if an IP address is blocked
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    is_sensitive_ip(ip)
}

fn default_syslog_config() -> serde_json::Value {
    serde_json::json!({
        "enabled": false,
        "server_address": "",
        "port": 514,
        "protocol": "udp",
        "facility": 4,
        "format": "rfc5424",
        "min_severity": "medium"
    })
}
