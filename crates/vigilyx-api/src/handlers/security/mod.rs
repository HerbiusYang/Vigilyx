//! SecurityEngine API Process

//! - GET /sessions/:id/verdict - session Security
//! - GET /sessions/:id/security-results - session Module
//! - GET /security/pipeline - getStream Configuration
//! - PUT /security/pipeline - NewStream Configuration
//! - GET /security/modules - Modulemetadata
//! - CRUD /security/ioc - IOC
//! - GET /security/whitelist - get
//! - PUT /security/whitelist - New
//! - CRUD /security/rules -
//! - GET /security/stats - SecurityStatistics
//! - GET /security/engine-status - Engine status
//! - POST /security/rescan - scan
//! - POST /sessions/:id/feedback -
//! - GET /security/feedback/stats - Statistics

//! NOTE: Securityanalyze Engine process.
//! Module handler DB Data,
//! (rescan/reload) Redis send Engine process.

mod alerts;
mod disposition;
mod pipeline;
pub mod quarantine;
mod rescan;
mod sniffer_config;
pub mod threat_scene;
mod verdict;
mod whitelist;

// Re-export all public handlers so routes.rs paths remain unchanged
pub use alerts::{
    add_intel_clean, delete_intel_whitelist, get_ai_config, get_email_alert_config,
    get_intel_config, get_wechat_alert_config, list_intel_whitelist, test_ai_connection,
    test_email_alert, test_wechat_alert, update_ai_config, update_email_alert_config,
    update_intel_config, update_wechat_alert_config,
};
pub use disposition::{
    create_disposition_rule, delete_disposition_rule, list_disposition_rules,
    update_disposition_rule,
};
pub use pipeline::{
    get_content_rules, get_keyword_overrides, get_module_data_overrides, get_modules_metadata,
    get_pipeline_config, update_keyword_overrides, update_module_data_overrides,
    update_pipeline_config,
};
pub use rescan::{rescan_session, trigger_rescan};
pub use sniffer_config::{
    get_sniffer_config, get_sniffer_config_internal, get_time_policy_config, update_sniffer_config,
    update_time_policy_config,
};
pub use threat_scene::{
    acknowledge_scene, block_scene, delete_threat_scene, get_scene_emails, get_scene_rules,
    get_threat_scene, list_threat_scenes, resolve_scene, threat_scene_stats, update_scene_rules,
};
pub use verdict::{
    get_engine_status, get_feedback_stats, get_security_stats, get_session_security_results,
    get_session_verdict, list_recent_verdicts, submit_feedback,
};
pub use whitelist::{add_whitelist_entry, delete_whitelist_entry, get_whitelist, update_whitelist};

use vigilyx_db::mq::topics;

use crate::AppState;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct EngineStatusSnapshot {
    pub snapshot: serde_json::Value,
    pub status: serde_json::Value,
    pub heartbeat_secs: i64,
}

// (Module Module)

/// Engine process New (IOC/ /Configuration)
pub(in crate::handlers) async fn publish_engine_reload(state: &AppState, target: &str) {
    if let Some(ref mq) = state.messaging.mq
        && let Err(e) = mq.publish_cmd(topics::ENGINE_CMD_RELOAD, &target).await
    {
        tracing::warn!("send Engine reload 指令failed: {}", e);
    }
}

/// Sniffer process Configuration
pub(super) async fn publish_sniffer_reload(state: &AppState) {
    if let Some(ref mq) = state.messaging.mq
        && let Err(e) = mq.publish_cmd(topics::SNIFFER_CMD_RELOAD, &"config").await
    {
        tracing::warn!("send Sniffer reload 指令failed: {}", e);
    }
}

pub(crate) fn wrap_engine_status_snapshot(status: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
    })
}

pub(crate) fn engine_status_from_snapshot(
    snapshot: &serde_json::Value,
) -> Option<serde_json::Value> {
    snapshot.get("status").cloned()
}

pub(crate) fn normalize_engine_status_payload(status: serde_json::Value) -> serde_json::Value {
    let mut normalized = default_engine_status_payload();

    if let Some(nested) = status.get("engine_status").cloned() {
        merge_json(&mut normalized, &nested);
    }

    merge_json(&mut normalized, &status);
    if let Some(obj) = normalized.as_object_mut() {
        obj.remove("engine_status");
    }

    normalized
}

pub(crate) fn default_engine_status_payload() -> serde_json::Value {
    serde_json::json!({
        "running": false,
        "uptime_seconds": 0,
        "total_sessions_processed": 0,
        "total_verdicts_produced": 0,
        "sessions_per_second": 0.0,
        "ai_service_available": false,
        "module_metrics": [],
        "email_engine_active": false,
        "data_security_engine_active": false,
        "ds_sessions_processed": 0,
        "ds_incidents_detected": 0,
        "reason": "Engine process未Connection或未sendstatus"
    })
}

fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base_obj), serde_json::Value::Object(patch_obj)) => {
            for (key, patch_value) in patch_obj {
                match base_obj.get_mut(key) {
                    Some(base_value) => merge_json(base_value, patch_value),
                    None => {
                        base_obj.insert(key.clone(), patch_value.clone());
                    }
                }
            }
        }
        (base_value, patch_value) => *base_value = patch_value.clone(),
    }
}

pub(crate) fn engine_snapshot_age_secs(snapshot: &serde_json::Value) -> Option<i64> {
    snapshot
        .get("updated_at")
        .and_then(|v| v.as_str())
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
        .map(|ts| chrono::Utc::now().signed_duration_since(ts).num_seconds())
}

pub(crate) async fn load_engine_status_snapshot(
    state: &std::sync::Arc<AppState>,
) -> Option<EngineStatusSnapshot> {
    // 1. Try Redis heartbeat key (fastest, authoritative, auto-expires via TTL)
    if let Some(ref mq) = state.messaging.mq
        && let Ok(Some(heartbeat)) = mq
            .get_json::<serde_json::Value>(vigilyx_db::mq::keys::ENGINE_HEARTBEAT)
            .await
    {
        // Guard: engine heartbeat already has { "updated_at": ..., "status": {...} }
        // structure — don't double-wrap it (same guard as the Pub/Sub path in main.rs).
        let wrapper = if heartbeat.get("updated_at").is_some() && heartbeat.get("status").is_some()
        {
            heartbeat
        } else {
            wrap_engine_status_snapshot(heartbeat)
        };
        if let Some(snapshot) = parse_engine_status_snapshot(wrapper.clone()) {
            *state.monitoring.engine_status.write().await = Some(wrapper);
            return Some(snapshot);
        }
    }

    // 2. Fall back to in-memory cache (populated by Pub/Sub subscription)
    let guard = state.monitoring.engine_status.read().await;
    guard.clone().and_then(parse_engine_status_snapshot)
}

fn parse_engine_status_snapshot(value: serde_json::Value) -> Option<EngineStatusSnapshot> {
    let status = engine_status_from_snapshot(&value)?;
    let heartbeat_secs = engine_snapshot_age_secs(&value)?;
    Some(EngineStatusSnapshot {
        snapshot: value,
        status,
        heartbeat_secs,
    })
}

/// API Key desensitize (AI Service configuration)
pub(super) fn mask_api_key(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        let (masked, has_key) = match obj.get("api_key").and_then(|k| k.as_str()) {
            Some(key) if key.len() > 4 => {
                let masked = format!(
                    "{}...{}",
                    "*".repeat(key.len().min(8) - 4),
                    &key[key.len() - 4..]
                );
                (masked, true)
            }
            Some(key) if !key.is_empty() => ("****".to_string(), true),
            _ => (String::new(), false),
        };
        obj.insert("api_key".to_string(), serde_json::json!(masked));
        obj.insert("api_key_set".to_string(), serde_json::json!(has_key));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn wrap_and_extract_engine_status_snapshot() {
        let status = json!({
            "running": true,
            "email_engine_active": true,
        });

        let snapshot = wrap_engine_status_snapshot(status.clone());

        assert_eq!(engine_status_from_snapshot(&snapshot), Some(status));
        assert!(engine_snapshot_age_secs(&snapshot).is_some());
        let parsed = parse_engine_status_snapshot(snapshot).expect("snapshot should parse");
        assert_eq!(parsed.status["running"], true);
        assert!(parsed.heartbeat_secs <= 1);
    }
}
