//! Threat scene (bulk mailing / bounce harvest) API handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;

use vigilyx_core::security::ThreatSceneRule;

use crate::AppState;
use crate::auth::AuthenticatedUser;

// ─── Query params ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListScenesQuery {
    pub scene_type: Option<String>,
    pub status: Option<String>,
    pub threat_level: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ─── Handlers ───────────────────────────────────────────────────────────

/// GET /api/security/threat-scenes
pub async fn list_threat_scenes(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListScenesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let limit = q.limit.unwrap_or(50).min(500);
    let offset = q.offset.unwrap_or(0);

    let (scenes, total) = state
        .db
        .list_threat_scenes(
            q.scene_type.as_deref(),
            q.status.as_deref(),
            q.threat_level.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(|e| {
            tracing::error!("list_threat_scenes: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list threat scenes"})),
            )
        })?;

    Ok(Json(json!({
        "items": scenes,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// GET /api/security/threat-scenes/stats
pub async fn threat_scene_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let stats = state.db.threat_scene_stats().await.map_err(|e| {
        tracing::error!("threat_scene_stats: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene stats"})),
        )
    })?;

    Ok(Json(serde_json::to_value(stats).unwrap_or(json!({}))))
}

/// GET /api/security/threat-scenes/:id
pub async fn get_threat_scene(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let scene = state.db.get_threat_scene(&id).await.map_err(|e| {
        tracing::error!("get_threat_scene: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene"})),
        )
    })?;

    match scene {
        Some(s) => Ok(Json(serde_json::to_value(s).unwrap_or(json!({})))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        )),
    }
}

/// GET /api/security/threat-scenes/:id/emails
pub async fn get_scene_emails(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let scene = state.db.get_threat_scene(&id).await.map_err(|e| {
        tracing::error!("get_scene_emails: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene"})),
        )
    })?;

    let Some(scene) = scene else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        ));
    };

    let emails = state.db.get_scene_emails(&scene, 100).await.map_err(|e| {
        tracing::error!("get_scene_emails: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene emails"})),
        )
    })?;

    Ok(Json(json!({ "emails": emails })))
}

/// POST /api/security/threat-scenes/:id/acknowledge
pub async fn acknowledge_scene(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let updated = state
        .db
        .update_scene_status(&id, "acknowledged")
        .await
        .map_err(|e| {
            tracing::error!("acknowledge_scene: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to acknowledge scene"})),
            )
        })?;

    if updated {
        crate::handlers::spawn_audit_log(
            state.engine_db.clone(),
            user.username,
            "acknowledge_threat_scene",
            Some("security"),
            Some(id),
            None,
        );
        Ok(Json(json!({"ok": true})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        ))
    }
}

/// POST /api/security/threat-scenes/:id/block
pub async fn block_scene(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let scene = state.db.get_threat_scene(&id).await.map_err(|e| {
        tracing::error!("block_scene: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene"})),
        )
    })?;

    let Some(scene) = scene else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        ));
    };

    // Create IOC for the actor
    let now = chrono::Utc::now();
    let ioc_id = uuid::Uuid::new_v4();
    let ioc = vigilyx_core::security::IocEntry {
        id: ioc_id,
        indicator: scene.actor.clone(),
        ioc_type: "domain".to_string(),
        source: "scene_manual".to_string(),
        verdict: "malicious".to_string(),
        confidence: 0.90,
        attack_type: scene.scene_type.to_string(),
        first_seen: now,
        last_seen: now,
        hit_count: 0,
        context: Some(format!(
            "手动封禁: {} 场景, {} 封邮件, {} 个收件人",
            scene.scene_type, scene.email_count, scene.unique_recipients
        )),
        expires_at: Some(now + chrono::Duration::hours(72)),
        created_at: now,
        updated_at: now,
    };

    state.db.upsert_ioc(&ioc).await.map_err(|e| {
        tracing::error!("block_scene IOC: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create IOC"})),
        )
    })?;

    state
        .db
        .update_scene_status(&id, "auto_blocked")
        .await
        .map_err(|e| {
            tracing::error!("block_scene status: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to update scene status"})),
            )
        })?;

    crate::handlers::spawn_audit_log(
        state.engine_db.clone(),
        user.username,
        "block_threat_scene",
        Some("security"),
        Some(id),
        Some(format!("ioc_id={ioc_id}")),
    );

    Ok(Json(json!({
        "ok": true,
        "ioc_id": ioc_id.to_string(),
    })))
}

/// POST /api/security/threat-scenes/:id/resolve
pub async fn resolve_scene(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let updated = state
        .db
        .update_scene_status(&id, "resolved")
        .await
        .map_err(|e| {
            tracing::error!("resolve_scene: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to resolve scene"})),
            )
        })?;

    if updated {
        crate::handlers::spawn_audit_log(
            state.engine_db.clone(),
            user.username,
            "resolve_threat_scene",
            Some("security"),
            Some(id),
            None,
        );
        Ok(Json(json!({"ok": true})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        ))
    }
}

/// DELETE /api/security/threat-scenes/:id
pub async fn delete_threat_scene(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let deleted = state.db.delete_threat_scene(&id).await.map_err(|e| {
        tracing::error!("delete_threat_scene: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to delete scene"})),
        )
    })?;

    if deleted {
        crate::handlers::spawn_audit_log(
            state.engine_db.clone(),
            user.username,
            "delete_threat_scene",
            Some("security"),
            Some(id),
            None,
        );
        Ok(Json(json!({"ok": true})))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        ))
    }
}

/// GET /api/security/scene-rules
pub async fn get_scene_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let rules = state.db.get_scene_rules().await.map_err(|e| {
        tracing::error!("get_scene_rules: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to get scene rules"})),
        )
    })?;

    Ok(Json(serde_json::to_value(rules).unwrap_or(json!([]))))
}

/// PUT /api/security/scene-rules
pub async fn update_scene_rules(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(rules): Json<Vec<ThreatSceneRule>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    for rule in &rules {
        state.db.upsert_scene_rule(rule).await.map_err(|e| {
            tracing::error!("update_scene_rules: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to update scene rules"})),
            )
        })?;
    }

    crate::handlers::spawn_audit_log(
        state.engine_db.clone(),
        user.username,
        "update_threat_scene_rules",
        Some("security"),
        Some("scene_rules".to_string()),
        Some(format!("rules={}", rules.len())),
    );

    Ok(Json(json!({"ok": true})))
}
