use axum::{Json, extract::State, response::IntoResponse};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

const UI_PREFERENCES_KEY: &str = "ui_preferences";

pub async fn get_ui_preferences(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match load_ui_preferences(&state).await {
        Ok(config) => ApiResponse::ok(config),
        Err(e) => ApiResponse::<Value>::internal_err(&e, "load ui preferences failed"),
    }
}

pub async fn update_ui_preferences(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(patch): Json<Value>,
) -> axum::response::Response {
    if !patch.is_object() {
        return ApiResponse::<Value>::bad_request("ui preferences payload must be an object")
            .into_response();
    }

    let mut merged = match load_ui_preferences(&state).await {
        Ok(config) => config,
        Err(e) => {
            return ApiResponse::<Value>::internal_err(&e, "load ui preferences failed")
                .into_response();
        }
    };

    deep_merge(&mut merged, patch);

    let normalized = match normalize_ui_preferences(merged) {
        Ok(config) => config,
        Err(msg) => return ApiResponse::<Value>::bad_request(msg).into_response(),
    };

    let json_str = match serde_json::to_string(&normalized) {
        Ok(json_str) => json_str,
        Err(e) => {
            return ApiResponse::<Value>::bad_request(format!(
                "ui preferences serialize failed: {}",
                e
            ))
            .into_response();
        }
    };

    match state.engine_db.set_config(UI_PREFERENCES_KEY, &json_str).await {
        Ok(()) => {
            let db = state.engine_db.clone();
            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(
                        &username,
                        "update_ui_preferences",
                        Some("config"),
                        Some(UI_PREFERENCES_KEY),
                        None,
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "audit: ui preferences write failed");
                }
            });

            ApiResponse::ok(normalized).into_response()
        }
        Err(e) => ApiResponse::<Value>::internal_err(&e, "save ui preferences failed")
            .into_response(),
    }
}

async fn load_ui_preferences(state: &Arc<AppState>) -> anyhow::Result<Value> {
    let raw = state.engine_db.get_config(UI_PREFERENCES_KEY).await?;
    let parsed = raw
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .unwrap_or_else(default_ui_preferences);
    Ok(normalize_ui_preferences(parsed).unwrap_or_else(|_| default_ui_preferences()))
}

fn default_ui_preferences() -> Value {
    json!({
        "appearance": {
            "theme": "dark",
            "accent": "cyan"
        },
        "notifications": {
            "sound_enabled": true,
            "desktop_notify": false,
            "alert_threshold": 100
        },
        "capture": {
            "smtp": true,
            "pop3": true,
            "imap": true,
            "auto_restore": true,
            "max_packet_size": 65535,
            "inbound_src": [],
            "inbound_dst": [],
            "outbound_src": [],
            "outbound_dst": []
        },
        "about": {
            "ntp_servers": "ntp.aliyun.com",
            "ntp_interval_minutes": 60
        }
    })
}

fn deep_merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(base_obj), Value::Object(patch_obj)) => {
            for (key, patch_value) in patch_obj {
                match base_obj.get_mut(&key) {
                    Some(base_value) => deep_merge(base_value, patch_value),
                    None => {
                        base_obj.insert(key, patch_value);
                    }
                }
            }
        }
        (base_value, patch_value) => *base_value = patch_value,
    }
}

fn normalize_ui_preferences(value: Value) -> Result<Value, String> {
    let mut normalized = default_ui_preferences();
    deep_merge(&mut normalized, value);

    let root = normalized
        .as_object_mut()
        .ok_or_else(|| "ui preferences must be an object".to_string())?;

    normalize_appearance(root)?;
    normalize_notifications(root)?;
    normalize_capture(root)?;
    normalize_about(root)?;

    Ok(Value::Object(root.clone()))
}

fn normalize_appearance(root: &mut Map<String, Value>) -> Result<(), String> {
    let appearance = object_section_mut(root, "appearance")?;

    let theme = appearance
        .get("theme")
        .and_then(Value::as_str)
        .unwrap_or("dark");
    let theme = if matches!(theme, "dark" | "light") {
        theme
    } else {
        "dark"
    };
    appearance.insert("theme".to_string(), json!(theme));

    let accent = appearance
        .get("accent")
        .and_then(Value::as_str)
        .unwrap_or("cyan");
    let accent = match accent {
        "cyan" | "blue" | "purple" | "green" | "amber" | "rose" => accent,
        _ => "cyan",
    };
    appearance.insert("accent".to_string(), json!(accent));

    Ok(())
}

fn normalize_notifications(root: &mut Map<String, Value>) -> Result<(), String> {
    let notifications = object_section_mut(root, "notifications")?;

    let sound_enabled = notifications
        .get("sound_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let desktop_notify = notifications
        .get("desktop_notify")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let alert_threshold = notifications
        .get("alert_threshold")
        .and_then(Value::as_i64)
        .unwrap_or(100)
        .clamp(10, 10_000);

    notifications.insert("sound_enabled".to_string(), json!(sound_enabled));
    notifications.insert("desktop_notify".to_string(), json!(desktop_notify));
    notifications.insert("alert_threshold".to_string(), json!(alert_threshold));

    Ok(())
}

fn normalize_capture(root: &mut Map<String, Value>) -> Result<(), String> {
    let capture = object_section_mut(root, "capture")?;

    let smtp = capture.get("smtp").and_then(Value::as_bool).unwrap_or(true);
    let pop3 = capture.get("pop3").and_then(Value::as_bool).unwrap_or(true);
    let imap = capture.get("imap").and_then(Value::as_bool).unwrap_or(true);
    let auto_restore = capture
        .get("auto_restore")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let max_packet_size = capture
        .get("max_packet_size")
        .and_then(Value::as_i64)
        .unwrap_or(65_535)
        .clamp(512, 262_144);

    capture.insert("smtp".to_string(), json!(smtp));
    capture.insert("pop3".to_string(), json!(pop3));
    capture.insert("imap".to_string(), json!(imap));
    capture.insert("auto_restore".to_string(), json!(auto_restore));
    capture.insert("max_packet_size".to_string(), json!(max_packet_size));
    let inbound_src = normalize_ip_array(capture.get("inbound_src"), "capture.inbound_src")?;
    let inbound_dst = normalize_ip_array(capture.get("inbound_dst"), "capture.inbound_dst")?;
    let outbound_src = normalize_ip_array(capture.get("outbound_src"), "capture.outbound_src")?;
    let outbound_dst = normalize_ip_array(capture.get("outbound_dst"), "capture.outbound_dst")?;

    capture.insert("inbound_src".to_string(), inbound_src);
    capture.insert("inbound_dst".to_string(), inbound_dst);
    capture.insert("outbound_src".to_string(), outbound_src);
    capture.insert("outbound_dst".to_string(), outbound_dst);

    Ok(())
}

fn normalize_about(root: &mut Map<String, Value>) -> Result<(), String> {
    let about = object_section_mut(root, "about")?;

    let ntp_servers = about
        .get("ntp_servers")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ntp.aliyun.com");
    let ntp_interval = about
        .get("ntp_interval_minutes")
        .and_then(Value::as_i64)
        .unwrap_or(60)
        .clamp(1, 1440);

    about.insert("ntp_servers".to_string(), json!(ntp_servers));
    about.insert("ntp_interval_minutes".to_string(), json!(ntp_interval));

    Ok(())
}

fn object_section_mut<'a>(
    root: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    match root.get_mut(key) {
        Some(Value::Object(section)) => Ok(section),
        Some(_) => Err(format!("{key} must be an object")),
        None => Err(format!("{key} is missing")),
    }
}

fn normalize_ip_array(value: Option<&Value>, field: &str) -> Result<Value, String> {
    let Some(value) = value else {
        return Ok(json!([]));
    };

    let arr = value
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))?;

    let mut items = Vec::new();
    let mut seen = HashSet::new();
    for item in arr {
        let raw = item
            .as_str()
            .ok_or_else(|| format!("{field} must contain only strings"))?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.parse::<IpAddr>().is_err() {
            return Err(format!("{field} contains invalid IP: {trimmed}"));
        }
        if seen.insert(trimmed.to_string()) {
            items.push(trimmed.to_string());
        }
    }

    Ok(json!(items))
}
