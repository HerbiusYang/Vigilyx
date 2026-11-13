//! Threat scene (bulk mailing / bounce harvest) API handlers.

use std::{collections::HashSet, sync::Arc};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::json;

use vigilyx_core::security::{
    BounceHarvestConfig, BulkMailingConfig, InternalDomainImpersonationConfig, ThreatScene,
    ThreatSceneRule, ThreatSceneType,
};

use super::super::clamp_i64_pagination;
use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::handlers::privacy;

// ─── Query params ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListScenesQuery {
    pub scene_type: Option<String>,
    pub status: Option<String>,
    pub threat_level: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn validate_scene_rule(rule: &ThreatSceneRule) -> Result<(), String> {
    match rule.scene_type {
        ThreatSceneType::BulkMailing => {
            serde_json::from_value::<BulkMailingConfig>(rule.config.clone())
                .map_err(|error| format!("invalid bulk_mailing config: {error}"))?
                .validate()
        }
        ThreatSceneType::BounceHarvest => {
            serde_json::from_value::<BounceHarvestConfig>(rule.config.clone())
                .map_err(|error| format!("invalid bounce_harvest config: {error}"))?
                .validate()
        }
        ThreatSceneType::InternalDomainImpersonation => {
            serde_json::from_value::<InternalDomainImpersonationConfig>(rule.config.clone())
                .map_err(|error| format!("invalid internal_domain_impersonation config: {error}"))?
                .validate()
        }
    }
}

/// Aggregate samples cannot inherit a lease for any one contributing session.
/// Keep them masked while privacy is enabled; an operator can reveal that
/// session's metadata through the scene email endpoint with its header lease.
fn project_threat_scene(mut scene: ThreatScene, scopes: &HashSet<String>) -> ThreatScene {
    if !privacy::is_privacy_disabled(scopes) {
        scene.sample_subjects = scene
            .sample_subjects
            .iter()
            .map(|subject| privacy::mask_subject(subject))
            .collect();
        scene.sample_recipients = scene
            .sample_recipients
            .iter()
            .map(|address| privacy::mask_email_address(address))
            .collect();
        // Current scene actors are domains/groups, but legacy mailbox actors
        // must retain the same address projection as session metadata.
        if scene.actor.contains('@') {
            scene.actor = privacy::mask_email_address(&scene.actor);
        }
    }
    scene
}

fn project_scene_email(
    mut email: serde_json::Value,
    user: &AuthenticatedUser,
    scopes: &HashSet<String>,
) -> serde_json::Value {
    if privacy::can_reveal(user, scopes, "headers") {
        return email;
    }
    if let Some(address) = email.get("mail_from").and_then(serde_json::Value::as_str) {
        email["mail_from"] = json!(privacy::mask_email_address(address));
    }
    if let Some(subject) = email.get("subject").and_then(serde_json::Value::as_str) {
        email["subject"] = json!(privacy::mask_subject(subject));
    }
    if let Some(recipients) = email.get_mut("rcpt_to") {
        match recipients {
            // The database returns this TEXT column as a JSON-encoded array.
            serde_json::Value::String(encoded) => {
                *recipients = serde_json::from_str::<Vec<String>>(encoded)
                    .ok()
                    .and_then(|addresses| {
                        serde_json::to_string(
                            &addresses
                                .iter()
                                .map(|address| privacy::mask_email_address(address))
                                .collect::<Vec<_>>(),
                        )
                        .ok()
                    })
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null);
            }
            serde_json::Value::Array(addresses) => {
                for address in addresses {
                    *address = address
                        .as_str()
                        .map(|value| json!(privacy::mask_email_address(value)))
                        .unwrap_or(serde_json::Value::Null);
                }
            }
            _ => *recipients = serde_json::Value::Null,
        }
    }
    email
}

// ─── Handlers ───────────────────────────────────────────────────────────

/// GET /api/security/threat-scenes
pub async fn list_threat_scenes(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListScenesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (limit, offset) = clamp_i64_pagination(q.limit, q.offset, 50, 500);

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

    let scopes = privacy::default_scopes(&state).await;
    Ok(Json(json!({
        "items": scenes.into_iter().map(|scene| project_threat_scene(scene, &scopes)).collect::<Vec<_>>(),
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

    let scopes = privacy::default_scopes(&state).await;
    match scene {
        Some(scene) => Ok(Json(json!(project_threat_scene(scene, &scopes)))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scene not found"})),
        )),
    }
}

/// GET /api/security/threat-scenes/:id/emails
pub async fn get_scene_emails(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
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

    let default_scopes = privacy::default_scopes(&state).await;
    let request_id = privacy::request_id_header(&headers);
    let mut projected_emails = Vec::with_capacity(emails.len());
    for email in emails {
        // One header lease is bound to one session. It must never reveal the
        // other messages returned by this aggregate endpoint.
        let scopes = if privacy::is_privacy_disabled(&default_scopes) || request_id.is_none() {
            default_scopes.clone()
        } else if let Some(session_id) = email.get("session_id").and_then(serde_json::Value::as_str)
        {
            privacy::active_scopes(&state, &user, request_id, "session", session_id)
                .await
                .map_err(|error| {
                    tracing::error!(error = %error, "Scene email privacy lease validation failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Privacy lease validation failed"})),
                    )
                })?
        } else {
            HashSet::new()
        };
        projected_emails.push(project_scene_email(email, &user, &scopes));
    }

    Ok(Json(json!({ "emails": projected_emails })))
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

fn scene_domain_blocking_allowed(scene: &ThreatScene) -> bool {
    scene.details["source"] != "reported_alert"
        && scene.actor_type != "group"
        && scene.actor != "multiple_senders"
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

    if !scene_domain_blocking_allowed(&scene) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Review reported identities and select a verified domain before blocking"
            })),
        ));
    }

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
        if let Err(error) = validate_scene_rule(rule) {
            return Err((StatusCode::BAD_REQUEST, Json(json!({"error": error}))));
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::security::{ThreatLevel, ThreatSceneStatus};

    fn scene() -> ThreatScene {
        let now = chrono::Utc::now();
        ThreatScene {
            id: uuid::Uuid::nil(),
            scene_type: ThreatSceneType::BounceHarvest,
            actor: "sender@source.example.test".into(),
            actor_type: "mailbox".into(),
            target_domain: Some("corp.example.test".into()),
            time_window_start: now,
            time_window_end: now,
            email_count: 20,
            unique_recipients: 10,
            bounce_count: 20,
            sample_subjects: vec!["Private project budget".into()],
            sample_recipients: vec!["recipient@corp.example.test".into()],
            threat_level: ThreatLevel::High,
            status: ThreatSceneStatus::Active,
            auto_blocked: false,
            ioc_id: None,
            details: json!({"source": "network_bounce", "address_role": "sender_addresses"}),
            created_at: now,
            updated_at: now,
        }
    }

    fn user(permissions: &[&str]) -> AuthenticatedUser {
        AuthenticatedUser {
            id: "synthetic-scene-reader".into(),
            role_id: "role-custom".into(),
            username: "scene-reader".into(),
            display_name: "Scene Reader".into(),
            role: "viewer".into(),
            permissions: permissions
                .iter()
                .map(|permission| (*permission).into())
                .collect(),
            must_change_password: false,
            session_id: "synthetic-auth-session".into(),
        }
    }

    fn email() -> serde_json::Value {
        json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "mail_from": "sender@source.example.test",
            "rcpt_to": "[\"recipient@corp.example.test\",\"analyst@corp.example.test\"]",
            "subject": "Private project budget",
            "started_at": "2026-01-01T00:00:00Z",
            "client_ip": "192.0.2.10",
            "threat_level": "high",
        })
    }

    #[test]
    fn reported_identities_and_aggregate_groups_cannot_be_blocked_as_a_domain() {
        let mut value = scene();
        assert!(scene_domain_blocking_allowed(&value));
        value.details = json!({"source": "reported_alert"});
        assert!(!scene_domain_blocking_allowed(&value));
        value.details = json!({"source": "network_bounce"});
        value.actor_type = "group".into();
        assert!(!scene_domain_blocking_allowed(&value));
        value.actor_type = "domain".into();
        value.actor = "multiple_senders".into();
        assert!(!scene_domain_blocking_allowed(&value));
    }

    #[test]
    fn threat_scene_privacy_masks_list_and_detail_metadata_without_changing_analysis() {
        let original = scene();
        let projected = project_threat_scene(original.clone(), &HashSet::new());
        assert_eq!(projected.sample_subjects, vec!["P******t"]);
        assert_eq!(projected.sample_recipients, vec!["r****@corp.example.test"]);
        assert_eq!(projected.actor, "s****@source.example.test");
        assert_eq!(projected.threat_level, original.threat_level);
        assert_eq!(projected.email_count, original.email_count);
        assert_eq!(projected.details, original.details);
        assert_eq!(projected.target_domain, original.target_domain);
        let serialized = serde_json::to_string(&projected).unwrap();
        assert!(!serialized.contains("Private project budget"));
        assert!(!serialized.contains("recipient@corp.example.test"));

        // A lease for one email cannot reveal the aggregate's other samples.
        let headers = HashSet::from(["headers".to_string()]);
        let aggregate = project_threat_scene(original, &headers);
        assert_eq!(aggregate.sample_subjects, projected.sample_subjects);
        assert_eq!(aggregate.sample_recipients, projected.sample_recipients);
    }

    #[test]
    fn threat_scene_privacy_preserves_domain_actors_and_disabled_policy_content() {
        let mut original = scene();
        original.actor = "source.example.test".into();
        original.actor_type = "domain".into();
        let masked = project_threat_scene(original.clone(), &HashSet::new());
        assert_eq!(masked.actor, original.actor);
        let disabled = HashSet::from(["__privacy_disabled__".to_string()]);
        assert_eq!(
            serde_json::to_value(project_threat_scene(original.clone(), &disabled)).unwrap(),
            serde_json::to_value(original).unwrap()
        );
    }

    #[test]
    fn scene_email_privacy_masks_subject_and_all_envelope_addresses() {
        let original = email();
        let reader = user(&["security.read", "sessions.read"]);
        let projected = project_scene_email(original.clone(), &reader, &HashSet::new());
        assert_eq!(projected["mail_from"], "s****@source.example.test");
        assert_eq!(projected["subject"], "P******t");
        let recipients: Vec<String> =
            serde_json::from_str(projected["rcpt_to"].as_str().unwrap()).unwrap();
        assert_eq!(
            recipients,
            vec!["r****@corp.example.test", "a****@corp.example.test"]
        );
        for field in ["session_id", "started_at", "client_ip", "threat_level"] {
            assert_eq!(projected[field], original[field]);
        }
        let serialized = serde_json::to_string(&projected).unwrap();
        assert!(!serialized.contains("Private project budget"));
        assert!(!serialized.contains("recipient@corp.example.test"));
        assert!(!serialized.contains("analyst@corp.example.test"));
    }

    #[test]
    fn scene_email_headers_reveal_requires_scope_and_permission() {
        let original = email();
        let reader = user(&["security.read", "sessions.read"]);
        let authorized = user(&["security.read", "sessions.read", "privacy.reveal"]);
        let headers = HashSet::from(["headers".to_string()]);
        assert_ne!(
            project_scene_email(original.clone(), &reader, &headers),
            original
        );
        assert_eq!(
            project_scene_email(original.clone(), &authorized, &headers),
            original
        );
        let body_only = HashSet::from(["body".to_string(), "html".to_string()]);
        assert_ne!(
            project_scene_email(original.clone(), &authorized, &body_only),
            original
        );
        // Privacy-off is the authorized global policy; no lease is required.
        let disabled = HashSet::from(["__privacy_disabled__".to_string()]);
        assert_eq!(
            project_scene_email(original.clone(), &reader, &disabled),
            original
        );
    }

    #[test]
    fn scene_email_malformed_recipient_payload_fails_closed() {
        let reader = user(&["security.read", "sessions.read"]);
        let mut original = email();
        original["rcpt_to"] = json!("[\"recipient@corp.example.test\"");
        let projected = project_scene_email(original, &reader, &HashSet::new());
        assert!(projected["rcpt_to"].is_null());

        let mut array_email = email();
        array_email["rcpt_to"] = json!(["recipient@corp.example.test", null, 42]);
        let projected = project_scene_email(array_email, &reader, &HashSet::new());
        assert_eq!(
            projected["rcpt_to"],
            json!(["r****@corp.example.test", null, null])
        );
    }
}
