//! Deployment mode API handlers
//!
//! - `mirror`: passive traffic mirroring (Sniffer)
//! - `mta`: MTA proxy mode (SMTP relay + inline verdict)
//!
//! Detection logic: check Sniffer / MTA heartbeat status (in-memory, populated by
//! internal status endpoints that Sniffer and MTA call periodically).
//!
//! PUT saves MTA parameters to DB. Mode switching requires a redeploy
//! (compose profiles), not runtime container orchestration.

use axum::{Json, extract::State, response::IntoResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

const DEPLOYMENT_MODE_KEY: &str = "deployment_mode";

const HEARTBEAT_TIMEOUT_SECS: i64 = 30;

fn normalize_mta_config(mta_config: Option<serde_json::Value>) -> Option<serde_json::Value> {
    match mta_config {
        Some(serde_json::Value::Object(mut config)) => {
            config
                .entry("mta_fail_open".to_string())
                .or_insert(serde_json::Value::Bool(false));
            Some(serde_json::Value::Object(config))
        }
        Some(other) => Some(other),
        None => Some(serde_json::json!({ "mta_fail_open": false })),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMode {
    pub mode: String,
    pub source: String,
    /// True when the VIGILYX_MODE env var is set; the frontend should disable mode switching.
    #[serde(default)]
    pub locked: bool,
    /// Full MTA configuration (all fields loaded back from the DB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mta_config: Option<serde_json::Value>,
    pub detected_services: DetectedServices,
    /// Portal mode: the frontend should be limited to the simplified UI (data security + settings only).
    #[serde(default)]
    pub portal_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedServices {
    pub sniffer_online: bool,
    pub mta_online: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateDeploymentMode {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub mta_downstream_host: Option<String>,
    #[serde(default)]
    pub mta_downstream_port: Option<u16>,
    #[serde(default)]
    pub mta_inline_timeout_secs: Option<u32>,
    #[serde(default)]
    pub mta_hostname: Option<String>,
    #[serde(default)]
    pub mta_max_connections: Option<u32>,
    #[serde(default)]
    pub mta_starttls: Option<bool>,
    #[serde(default)]
    pub mta_fail_open: Option<bool>,
    #[serde(default)]
    pub mta_local_domains: Option<String>,
    #[serde(default)]
    pub mta_dlp_enabled: Option<bool>,
    #[serde(default)]
    pub mta_dlp_action: Option<String>,
}

/// GET /api/config/deployment-mode
pub async fn get_deployment_mode(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mode = resolve_deployment_mode(&state).await;
    ApiResponse::ok(mode)
}

/// PUT /api/config/deployment-mode
///
/// Saves MTA parameters to DB. Mode switching is a deploy-time decision
/// (compose profiles), not a runtime container operation.
pub async fn update_deployment_mode(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(body): Json<UpdateDeploymentMode>,
) -> axum::response::Response {
    // -- Guard: block mode switching when locked by env var --
    let env_locked = std::env::var("VIGILYX_MODE")
        .ok()
        .filter(|v| {
            let m = v.trim().to_lowercase();
            m == "mta" || m == "mirror"
        })
        .is_some();

    if env_locked && body.mode.is_some() {
        return ApiResponse::<serde_json::Value>::err(
            "Deployment mode is locked by VIGILYX_MODE env var. To change, edit .env and redeploy.",
        )
        .into_response();
    }

    // -- Guard: downstream host SSRF validation (CWE-918) --
    if let Some(ref host) = body.mta_downstream_host
        && !host.is_empty()
        && let Err(msg) = validate_downstream_host(host)
    {
        return ApiResponse::<serde_json::Value>::err(msg).into_response();
    }

    // -- Step 1: merge and save MTA parameters to DB --
    let mut merged = match state.engine_db.get_config(DEPLOYMENT_MODE_KEY).await {
        Ok(Some(raw)) => serde_json::from_str::<serde_json::Value>(&raw)
            .unwrap_or_else(|_| serde_json::json!({})),
        _ => serde_json::json!({}),
    };
    let incoming = serde_json::to_value(&body).unwrap_or_default();
    if let (Some(base), Some(patch)) = (merged.as_object_mut(), incoming.as_object()) {
        for (k, v) in patch {
            if !v.is_null() {
                base.insert(k.clone(), v.clone());
            }
        }
    }
    let json_str = serde_json::to_string(&merged).unwrap_or_default();

    if let Err(e) = state
        .engine_db
        .set_config(DEPLOYMENT_MODE_KEY, &json_str)
        .await
    {
        return ApiResponse::<serde_json::Value>::internal_err(
            &e,
            "Failed to save deployment config",
        )
        .into_response();
    }

    // -- Step 2: mode switching is now a deploy-time decision --
    // No longer call docker-proxy to start/stop containers at runtime.
    // The frontend should communicate that a redeploy is needed.
    if let Some(ref target_mode) = body.mode
        && (target_mode == "mta" || target_mode == "mirror")
    {
        tracing::info!(
            mode = %target_mode,
            user = %user.username,
            "Deployment mode config saved (requires redeploy to take effect)"
        );
    }

    // -- Step 3: audit log --
    let db = state.engine_db.clone();
    let username = user.username.clone();
    let mode_str = body.mode.clone().unwrap_or_default();
    tokio::spawn(async move {
        let _ = db
            .write_audit_log(
                &username,
                "update_deployment_config",
                Some("config"),
                Some(&mode_str),
                None,
                None,
            )
            .await;
    });

    let resolved = resolve_deployment_mode(&state).await;
    ApiResponse::ok(resolved).into_response()
}

/// Check if a heartbeat timestamp is within HEARTBEAT_TIMEOUT_SECS.
fn is_recently_updated(last_update: &str) -> bool {
    if last_update.is_empty() {
        return false;
    }
    match chrono::DateTime::parse_from_rfc3339(last_update) {
        Ok(ts) => {
            let elapsed = Utc::now().signed_duration_since(ts.with_timezone(&Utc));
            elapsed.num_seconds() < HEARTBEAT_TIMEOUT_SECS
        }
        Err(_) => false,
    }
}

/// Resolution priority:
/// 1. `VIGILYX_MODE` env var - highest priority, hard ops override, UI locked
/// 2. Database (user UI selection)
/// 3. Auto-detection (service heartbeat status from in-memory state)
/// 4. Default `mirror`
///
/// Service detection uses in-memory heartbeat status (populated by internal
/// endpoints that Sniffer and MTA call periodically), NOT docker-proxy.
async fn resolve_deployment_mode(state: &AppState) -> DeploymentMode {
    // Detect service status from in-memory heartbeats (no docker-proxy calls)
    let sniffer_online = {
        let status = state.monitoring.sniffer_status.read().await;
        is_recently_updated(&status.last_update)
    };
    let mta_online = {
        let status = state.monitoring.mta_status.read().await;
        is_recently_updated(&status.last_update)
    };

    let detected_services = DetectedServices {
        sniffer_online,
        mta_online,
    };

    let portal_mode = std::env::var("PORTAL_MODE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    // Always read MTA config parameters from the DB regardless of the mode source
    let db_config = normalize_mta_config(match state.engine_db.get_config(DEPLOYMENT_MODE_KEY).await {
        Ok(Some(raw)) => serde_json::from_str::<serde_json::Value>(&raw).ok(),
        _ => None,
    });

    // 1. VIGILYX_MODE env var - highest priority; locked=true tells the frontend to disallow switching
    if let Ok(env_mode) = std::env::var("VIGILYX_MODE") {
        let mode = env_mode.trim().to_lowercase();
        if mode == "mta" || mode == "mirror" {
            return DeploymentMode {
                mode,
                source: "env".into(),
                locked: true,
                mta_config: db_config.clone(),
                detected_services,
                portal_mode,
            };
        }
    }

    // 2. DB saved mode
    if let Some(ref cfg) = db_config
        && let Some(mode_str) = cfg.get("mode").and_then(|v| v.as_str())
    {
        let mode = mode_str.trim().to_lowercase();
        if mode == "mta" || mode == "mirror" {
            return DeploymentMode {
                mode,
                source: "db".into(),
                locked: false,
                mta_config: db_config.clone(),
                detected_services,
                portal_mode,
            };
        }
    }

    // 3. Auto-detection from service heartbeats
    if mta_online && !sniffer_online {
        return DeploymentMode {
            mode: "mta".into(),
            source: "auto".into(),
            locked: false,
            mta_config: db_config,
            detected_services,
            portal_mode,
        };
    }

    // 4. Default: mirror
    DeploymentMode {
        mode: "mirror".into(),
        source: "default".into(),
        locked: false,
        mta_config: db_config,
        detected_services,
        portal_mode,
    }
}

/// SSRF validation for MTA downstream host (CWE-918).
fn validate_downstream_host(host: &str) -> Result<(), String> {
    let lower = host.to_lowercase();
    // Block cloud metadata endpoints
    if lower.starts_with("169.254.") || lower.starts_with("fe80") {
        return Err("Blocked: cloud metadata / link-local address".into());
    }
    // Block localhost variants (downstream should be a real MTA)
    if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" {
        return Err("Downstream host cannot be localhost".into());
    }
    // Block protocol schemes
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("file:")
        || lower.starts_with("gopher:")
    {
        return Err("Downstream host should be a hostname or IP, not a URL".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_downstream_host_valid() {
        assert!(validate_downstream_host("10.1.246.33").is_ok());
        assert!(validate_downstream_host("mail.example.com").is_ok());
    }

    #[test]
    fn test_validate_downstream_host_blocked() {
        assert!(validate_downstream_host("169.254.169.254").is_err());
        assert!(validate_downstream_host("localhost").is_err());
        assert!(validate_downstream_host("127.0.0.1").is_err());
        assert!(validate_downstream_host("http://evil.com").is_err());
        assert!(validate_downstream_host("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_is_recently_updated_valid() {
        let now = Utc::now().to_rfc3339();
        assert!(is_recently_updated(&now));
    }

    #[test]
    fn test_is_recently_updated_stale() {
        let old = (Utc::now() - chrono::Duration::seconds(60)).to_rfc3339();
        assert!(!is_recently_updated(&old));
    }

    #[test]
    fn test_is_recently_updated_empty() {
        assert!(!is_recently_updated(""));
    }

    #[test]
    fn test_normalize_mta_config_injects_secure_fail_closed_default() {
        let config = normalize_mta_config(Some(serde_json::json!({
            "mta_downstream_host": "mail.example.com"
        })))
        .unwrap();

        assert_eq!(config["mta_fail_open"], serde_json::Value::Bool(false));
        assert_eq!(config["mta_downstream_host"], "mail.example.com");
    }
}
