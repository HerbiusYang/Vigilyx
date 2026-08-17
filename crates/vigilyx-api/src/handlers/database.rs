//! Database handlers: session import, statistics, clear operations, rotation config

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use uuid::Uuid;
use vigilyx_core::{EmailSession, TrafficStats, WsMessage};
use vigilyx_db::mq::streams;

use super::ApiResponse;
use crate::AppState;
use crate::auth::{AuthenticatedUser, build_clear_cookie};
use crate::db::Database;

/// Unix timestamp of last rotation check (throttled: once per 60 seconds)
static LAST_ROTATE_CHECK: AtomicI64 = AtomicI64::new(0);

/// Import sessions (batch insert/upsert with merge).
///
/// Performance notes: uses batch UPSERT + IN query to merge existing sessions.
pub async fn import_sessions(
    State(state): State<Arc<AppState>>,
    Json(sessions): Json<Vec<EmailSession>>,
) -> impl IntoResponse {
    // 0. Throttled auto-rotation check (at most once per 60 seconds)
    {
        let now = chrono::Utc::now().timestamp();
        let last = LAST_ROTATE_CHECK.load(Ordering::Relaxed);
        if now - last >= 60 {
            LAST_ROTATE_CHECK.store(now, Ordering::Relaxed);
            if let Err(e) = state
                .db
                .check_and_rotate_if_needed(&state.config.database_url)
                .await
            {
                tracing::warn!("Auto-rotation check failed: {}", e);
            }
        }
    }

    // 1. Batch insert sessions (UPSERT + merge)
    let (success_count, is_new_vec, merged) = match state.db.insert_sessions_batch(&sessions).await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Batch session save failed: {}", e);
            return ApiResponse::ok(serde_json::json!({
                "imported": 0,
                "total": sessions.len()
            }));
        }
    };

    // 2. Build merged session lookup map
    let merged_map: std::collections::HashMap<Uuid, &EmailSession> =
        merged.iter().map(|s| (s.id, s)).collect();

    for (i, session) in sessions.iter().enumerate() {
        let broadcast_session = merged_map
            .get(&session.id)
            .map(|s| (*s).clone())
            .unwrap_or_else(|| session.clone());
        let session_signal = broadcast_session.ws_signal();

        let ws_msg = if i < is_new_vec.len() && is_new_vec[i] {
            WsMessage::NewSession(session_signal.clone())
        } else {
            WsMessage::SessionUpdate(session_signal)
        };
        if state.messaging.ws_tx.receiver_count() > 0 {
            let _ = state.messaging.ws_tx.send(ws_msg);
        }

        // Engine processes sessions via Redis Streams
        // API does not run SecurityEngine directly
    }

    ApiResponse::ok(serde_json::json!({
        "imported": success_count,
        "total": sessions.len()
    }))
}

/// Update traffic statistics and broadcast via WebSocket
pub async fn update_stats(
    State(state): State<Arc<AppState>>,
    Json(stats): Json<TrafficStats>,
) -> impl IntoResponse {
    // Broadcast stats update via WebSocket
    if state.messaging.ws_tx.receiver_count() > 0 {
        let _ = state.messaging.ws_tx.send(WsMessage::StatsUpdate(stats));
    }
    ApiResponse::ok(serde_json::json!({"status": "ok"}))
}

/// Request body for database clear operation
#[derive(Debug, Deserialize)]
pub struct ClearDatabaseRequest {
    #[serde(default = "default_clear_mode")]
    pub mode: String,
}

fn default_clear_mode() -> String {
    "safe".to_string()
}

/// Data-plane queues whose retained messages can recreate sessions and verdicts
/// immediately after a PostgreSQL cleanup. Keep this as an exact allowlist:
/// control-plane, configuration, heartbeat, and authentication keys must survive.
const OPERATIONAL_DATA_STREAMS: &[&str] = &[
    streams::EMAIL_SESSIONS,
    streams::HTTP_SESSIONS,
    streams::AI_TASKS,
    streams::RESCAN_REQUESTS,
    streams::EMAIL_SESSIONS_DLQ,
    streams::HTTP_SESSIONS_DLQ,
    streams::RESCAN_REQUESTS_DLQ,
];

async fn purge_operational_data_streams(state: &AppState) -> anyhow::Result<(u64, u64)> {
    let mq =
        state.messaging.mq.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Redis is unavailable; refusing partial full cleanup")
        })?;
    mq.purge_streams(OPERATIONAL_DATA_STREAMS)
        .await
        .map_err(|error| anyhow::anyhow!("failed to purge Redis data streams: {error}"))
}

/// Clear database (supports multiple modes)
pub async fn clear_database(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    body: Option<Json<ClearDatabaseRequest>>,
) -> axum::response::Response {
    let mode = body.map(|b| b.0.mode).unwrap_or_else(default_clear_mode);
    let start = std::time::Instant::now();

    if !matches!(mode.as_str(), "safe" | "quick" | "high_performance") {
        return ApiResponse::<serde_json::Value>::bad_request(format!(
            "Unknown clear mode: {}. Options: safe, quick, high_performance",
            mode
        ))
        .into_response();
    }

    // Purge before touching PostgreSQL. If Redis is unavailable or a target
    // key has an unexpected type, fail without claiming a partial success.
    let (pre_entries_deleted, pre_streams_deleted) =
        match purge_operational_data_streams(&state).await {
            Ok(result) => result,
            Err(error) => {
                tracing::error!(mode, error = %error, "Full cleanup blocked before DB mutation");
                return ApiResponse::<serde_json::Value>::server_error(&error, "Operation failed")
                    .into_response();
            }
        };

    let result = match mode.as_str() {
        "safe" => state.db.clear_safe().await,
        "quick" => state.db.clear_quick().await,
        "high_performance" => state.db.clear_high_performance().await,
        _ => unreachable!("clear mode was validated above"),
    };

    let elapsed_ms = start.elapsed().as_millis();

    match result {
        Ok(_) => {
            // Purge a second time to remove messages produced during table
            // recreation. Messages arriving after this barrier are new live
            // traffic and may legitimately appear after cleanup returns.
            let (post_entries_deleted, post_streams_deleted) =
                match purge_operational_data_streams(&state).await {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::error!(
                            mode,
                            error = %error,
                            "Database cleared but final Redis stream purge failed"
                        );
                        return ApiResponse::<serde_json::Value>::server_error(
                            &error,
                            "Database cleared, but queue cleanup failed; retry full cleanup",
                        )
                        .into_response();
                    }
                };
            let stream_entries_deleted = pre_entries_deleted.saturating_add(post_entries_deleted);
            let stream_keys_deleted = pre_streams_deleted.saturating_add(post_streams_deleted);

            *state.cache.traffic_stats.write().await = None;
            tracing::info!(
                mode,
                elapsed_ms,
                stream_entries_deleted,
                stream_keys_deleted,
                "Database and Redis operational data cleared"
            );

            // Write audit log for database clear operation
            let db = state.engine_db.clone();
            let mode_clone = mode.clone();
            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(
                        &username,
                        "clear_database",
                        Some("database"),
                        None,
                        Some(&format!(
                            "mode={}, elapsed={}ms, stream_entries_deleted={}",
                            mode_clone, elapsed_ms, stream_entries_deleted
                        )),
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "Audit: failed to write database clear audit log");
                }
            });

            // Broadcast zeroed stats to refresh the dashboard
            let zeroed_stats = TrafficStats {
                total_sessions: 0,
                active_sessions: 0,
                total_packets: 0,
                total_bytes: 0,
                smtp_sessions: 0,
                pop3_sessions: 0,
                imap_sessions: 0,
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
            };
            let _ = state
                .messaging
                .ws_tx
                .send(WsMessage::StatsUpdate(zeroed_stats));
            // Done

            ApiResponse::ok(serde_json::json!({
                "message": "Database cleared",
                "mode": mode,
                "elapsed_ms": elapsed_ms,
                "stream_entries_deleted": stream_entries_deleted,
                "stream_keys_deleted": stream_keys_deleted,
                "cleanup_scope": "point_in_time",
                "new_live_traffic_may_appear": true
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to clear database (mode={}): {}", mode, e);
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

#[cfg(test)]
mod clear_tests {
    use super::*;

    #[test]
    fn operational_cleanup_uses_exact_data_plane_stream_allowlist() {
        assert_eq!(
            OPERATIONAL_DATA_STREAMS,
            [
                "vigilyx:stream:sessions",
                "vigilyx:stream:http_sessions",
                "vigilyx:stream:ai_tasks",
                "vigilyx:stream:rescan_requests",
                "vigilyx:stream:sessions:dlq",
                "vigilyx:stream:http_sessions:dlq",
                "vigilyx:stream:rescan_requests:dlq",
            ]
        );
        assert!(
            OPERATIONAL_DATA_STREAMS
                .iter()
                .all(|key| key.starts_with("vigilyx:stream:"))
        );
    }
}

pub async fn factory_reset(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request_headers: HeaderMap,
    user: AuthenticatedUser,
) -> axum::response::Response {
    let start = std::time::Instant::now();

    if let Err(e) = crate::auth::AuthConfig::validate_factory_reset_prereqs() {
        tracing::error!("Factory reset blocked: {}", e);
        return ApiResponse::<serde_json::Value>::server_error(
            &e,
            "Factory reset requires API_PASSWORD to be configured in the environment",
        )
        .into_response();
    }

    let _ = state
        .engine_db
        .write_audit_log(
            &user.username,
            "factory_reset",
            Some("system"),
            None,
            Some("Full system factory reset initiated"),
            None,
        )
        .await;

    match state.db.factory_reset().await {
        Ok(()) => {
            let new_token_version = match state.auth.config.reset_after_factory_reset().await {
                Ok(version) => version,
                Err(e) => {
                    tracing::error!(
                        "Factory reset completed, but auth runtime reset failed: {}",
                        e
                    );
                    return ApiResponse::<serde_json::Value>::server_error(
                        &e,
                        "Factory reset completed but auth reset failed",
                    )
                    .into_response();
                }
            };

            let reset_hash = state.auth.config.password_hash.read().await.clone();
            if let Err(e) = state
                .engine_db
                .reset_platform_admin(&state.auth.config.username, &reset_hash)
                .await
            {
                tracing::error!(
                    "Factory reset completed, but platform admin bootstrap failed: {}",
                    e
                );
                return ApiResponse::<serde_json::Value>::server_error(
                    &e,
                    "Factory reset completed but platform admin bootstrap failed",
                )
                .into_response();
            }

            if let Err(e) = state
                .engine_db
                .set_config("auth_token_version", &new_token_version.to_string())
                .await
            {
                tracing::error!(
                    "Factory reset completed, but auth token version persistence failed: {}",
                    e
                );
                return ApiResponse::<serde_json::Value>::server_error(
                    &e,
                    "Factory reset completed but auth reset failed",
                )
                .into_response();
            }

            // SEC M-1: factory reset revokes every user's outstanding JWTs
            // through the per-user rows (the config counter above remains as
            // the legacy fallback only).
            if let Err(e) = state.engine_db.bump_all_platform_user_token_versions().await {
                tracing::error!(
                    "Factory reset completed, but per-user token revocation failed: {}",
                    e
                );
                return ApiResponse::<serde_json::Value>::server_error(
                    &e,
                    "Factory reset completed but auth reset failed",
                )
                .into_response();
            }

            state.auth.login_rate_limiter.clear_all();
            state.ws_tickets.clear();
            crate::websocket::invalidate_websocket_sessions(&state);

            let elapsed_ms = start.elapsed().as_millis();
            tracing::warn!(
                "FACTORY RESET completed in {}ms — all data and config cleared",
                elapsed_ms
            );

            let zeroed_stats = TrafficStats {
                total_sessions: 0,
                active_sessions: 0,
                total_packets: 0,
                total_bytes: 0,
                smtp_sessions: 0,
                pop3_sessions: 0,
                imap_sessions: 0,
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
            };
            let _ = state
                .messaging
                .ws_tx
                .send(WsMessage::StatsUpdate(zeroed_stats));

            let mut headers = axum::http::HeaderMap::new();
            let secure_cookie =
                crate::routes::request_is_secure(&request_headers, addr, state.secure_cookie);
            if let Ok(val) = build_clear_cookie(secure_cookie).parse() {
                headers.insert(axum::http::header::SET_COOKIE, val);
            }

            (
                headers,
                ApiResponse::ok(serde_json::json!({
                    "mode": "factory_reset",
                    "message": "System has been reset to factory defaults. All active sessions were invalidated. Please log in again with the configured admin password.",
                    "elapsed_ms": elapsed_ms,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Factory reset failed: {}", e);
            ApiResponse::<serde_json::Value>::server_error(&e, "Factory reset failed")
                .into_response()
        }
    }
}

/// Precise clear: selectively delete sessions and/or security analysis data
#[derive(Deserialize)]
pub struct PreciseClearRequest {
    /// "sessions" | "verdicts" | "both"
    pub target: String,
    /// For verdicts: filter by threat level ("high", "medium", "low", "safe", "all")
    pub threat_level: Option<String>,
    /// For sessions: delete data older than N days (0 = delete all)
    pub older_than_days: Option<u32>,
}

pub async fn precise_clear(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<PreciseClearRequest>,
) -> axum::response::Response {
    let start = std::time::Instant::now();

    if let Some(level) = req.threat_level.as_deref()
        && !matches!(
            level,
            "all" | "safe" | "low" | "medium" | "high" | "critical"
        )
    {
        return ApiResponse::<serde_json::Value>::bad_request(
            "Unknown threat_level. Options: all, safe, low, medium, high, critical",
        )
        .into_response();
    }

    let result = match req.target.as_str() {
        "sessions" => {
            let days = req.older_than_days.unwrap_or(0);
            if days > 0 {
                let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                let cutoff_str = cutoff.to_rfc3339();
                clear_sessions_precisely(&state.db, Some(&cutoff_str)).await
            } else {
                clear_sessions_precisely(&state.db, None).await
            }
        }
        "verdicts" => {
            let level = req.threat_level.as_deref().unwrap_or("all");
            if level == "all" {
                clear_verdicts_precisely(&state.db, None).await
            } else {
                clear_verdicts_precisely(&state.db, Some(level)).await
            }
        }
        "both" => clear_all_session_and_security_data(&state.db).await,
        _ => {
            return ApiResponse::<serde_json::Value>::bad_request(
                "Unknown target. Options: sessions, verdicts, both",
            )
            .into_response();
        }
    };

    let elapsed_ms = start.elapsed().as_millis();

    match result {
        Ok(_) => {
            let desc = format!(
                "target={}, threat_level={}, older_than_days={}, elapsed={}ms",
                req.target,
                req.threat_level.as_deref().unwrap_or("n/a"),
                req.older_than_days.unwrap_or(0),
                elapsed_ms
            );
            tracing::info!("Precise clear: {}", desc);
            let db = state.engine_db.clone();
            let desc_clone = desc.clone();
            let username = user.username.clone();
            tokio::spawn(async move {
                if let Err(e) = db
                    .write_audit_log(
                        &username,
                        "precise_clear",
                        Some("database"),
                        None,
                        Some(&desc_clone),
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "Audit: failed to write precise clear audit log");
                }
            });

            ApiResponse::ok(serde_json::json!({
                "message": "Clear completed",
                "details": desc,
                "elapsed_ms": elapsed_ms
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("Precise clear failed: {}", e);
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

async fn clear_sessions_precisely(db: &Database, cutoff: Option<&str>) -> anyhow::Result<()> {
    let mut tx = db.pool().begin().await?;
    let http_temp_ids = clear_http_session_data(&mut tx, cutoff).await?;

    if let Some(cutoff) = cutoff {
        delete_session_linked_rows(&mut tx, cutoff).await?;
        execute_tx(
            &mut tx,
            "DELETE FROM security_verdicts \
             WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1)",
            Some(cutoff),
        )
        .await?;
        execute_tx(
            &mut tx,
            "DELETE FROM sessions WHERE started_at < $1",
            Some(cutoff),
        )
        .await?;
    } else {
        clear_all_session_and_security_rows(&mut tx).await?;
        execute_tx(&mut tx, "DELETE FROM sessions", None).await?;
    }

    tx.commit().await?;
    // SEC-M01: avoid blocking the async runtime with std::fs operations
    let ids = http_temp_ids;
    let _ = tokio::task::spawn_blocking(move || cleanup_http_temp_files(&ids)).await;
    Ok(())
}

async fn clear_verdicts_precisely(db: &Database, threat_level: Option<&str>) -> anyhow::Result<()> {
    let mut tx = db.pool().begin().await?;

    if let Some(threat_level) = threat_level {
        delete_verdict_linked_rows(&mut tx, threat_level).await?;
        execute_tx(
            &mut tx,
            "DELETE FROM security_verdicts WHERE threat_level = $1",
            Some(threat_level),
        )
        .await?;
    } else {
        execute_tx(&mut tx, "DELETE FROM security_module_results", None).await?;
        execute_tx(
            &mut tx,
            "DELETE FROM security_feedback WHERE verdict_id IS NOT NULL",
            None,
        )
        .await?;
        execute_tx(&mut tx, "DELETE FROM security_alerts", None).await?;
        execute_tx(
            &mut tx,
            "DELETE FROM quarantine WHERE verdict_id IS NOT NULL",
            None,
        )
        .await?;
        execute_tx(
            &mut tx,
            "DELETE FROM training_samples WHERE verdict_id IS NOT NULL",
            None,
        )
        .await?;
        execute_tx(&mut tx, "DELETE FROM security_verdicts", None).await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn clear_all_session_and_security_data(db: &Database) -> anyhow::Result<()> {
    let mut tx = db.pool().begin().await?;
    let http_temp_ids = clear_http_session_data(&mut tx, None).await?;
    clear_all_session_and_security_rows(&mut tx).await?;
    execute_tx(&mut tx, "DELETE FROM sessions", None).await?;
    tx.commit().await?;
    // SEC-M01: avoid blocking the async runtime with std::fs operations
    let ids = http_temp_ids;
    let _ = tokio::task::spawn_blocking(move || cleanup_http_temp_files(&ids)).await;
    Ok(())
}

async fn clear_all_session_and_security_rows(
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<()> {
    execute_tx(tx, "DELETE FROM security_module_results", None).await?;
    execute_tx(tx, "DELETE FROM security_feedback", None).await?;
    execute_tx(tx, "DELETE FROM security_alerts", None).await?;
    execute_tx(tx, "DELETE FROM quarantine", None).await?;
    execute_tx(tx, "DELETE FROM security_threat_scenes", None).await?;
    execute_tx(tx, "DELETE FROM training_samples", None).await?;
    execute_tx(tx, "DELETE FROM security_verdicts", None).await?;
    Ok(())
}

async fn clear_http_session_data(
    tx: &mut Transaction<'_, Postgres>,
    cutoff: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let doomed_ids = if let Some(cutoff) = cutoff {
        sqlx::query_scalar::<_, String>(
            "SELECT id::text FROM data_security_http_sessions WHERE timestamp < $1",
        )
        .bind(cutoff)
        .fetch_all(&mut **tx)
        .await?
    } else {
        sqlx::query_scalar::<_, String>("SELECT id::text FROM data_security_http_sessions")
            .fetch_all(&mut **tx)
            .await?
    };

    if let Some(cutoff) = cutoff {
        execute_tx(
            tx,
            "DELETE FROM data_security_incidents \
             WHERE http_session_id IN ( \
                SELECT id FROM data_security_http_sessions WHERE timestamp < $1 \
             )",
            Some(cutoff),
        )
        .await?;
        execute_tx(
            tx,
            "DELETE FROM data_security_http_sessions WHERE timestamp < $1",
            Some(cutoff),
        )
        .await?;
    } else {
        execute_tx(tx, "DELETE FROM data_security_incidents", None).await?;
        execute_tx(tx, "DELETE FROM data_security_http_sessions", None).await?;
    }

    Ok(doomed_ids)
}

async fn delete_session_linked_rows(
    tx: &mut Transaction<'_, Postgres>,
    cutoff: &str,
) -> anyhow::Result<()> {
    execute_tx(
        tx,
        "DELETE FROM security_module_results \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM security_feedback \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM security_alerts \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM quarantine \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM training_samples \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
    execute_tx(tx, "DELETE FROM security_threat_scenes", None).await?;
    Ok(())
}

async fn delete_verdict_linked_rows(
    tx: &mut Transaction<'_, Postgres>,
    threat_level: &str,
) -> anyhow::Result<()> {
    execute_tx(
        tx,
        "DELETE FROM security_module_results \
         WHERE verdict_id IN (SELECT id FROM security_verdicts WHERE threat_level = $1)",
        Some(threat_level),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM security_feedback \
         WHERE verdict_id IN (SELECT id FROM security_verdicts WHERE threat_level = $1)",
        Some(threat_level),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM security_alerts \
         WHERE verdict_id IN (SELECT id FROM security_verdicts WHERE threat_level = $1)",
        Some(threat_level),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM quarantine \
         WHERE verdict_id IN (SELECT id FROM security_verdicts WHERE threat_level = $1)",
        Some(threat_level),
    )
    .await?;
    execute_tx(
        tx,
        "DELETE FROM training_samples \
         WHERE verdict_id IN (SELECT id FROM security_verdicts WHERE threat_level = $1)",
        Some(threat_level),
    )
    .await?;
    Ok(())
}

async fn execute_tx(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    bind_value: Option<&str>,
) -> anyhow::Result<()> {
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
    if let Some(bind_value) = bind_value {
        query = query.bind(bind_value);
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

fn cleanup_http_temp_files(ids: &[String]) {
    let mut files_cleaned = 0u64;
    for id in ids {
        let Some(path) = http_temp_file_path_for_id(id) else {
            tracing::warn!("Skipping invalid HTTP temp file id during cleanup");
            continue;
        };

        if !path.exists() {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(
                path = %path.display(),
                "Failed to remove HTTP temp file: {}",
                e
            );
        } else {
            files_cleaned += 1;
        }
    }

    if files_cleaned > 0 {
        tracing::info!(
            files_cleaned,
            "Cleaned HTTP body temp files during precise clear"
        );
    }
}

fn http_temp_file_path_for_id(id: &str) -> Option<std::path::PathBuf> {
    let id = Uuid::parse_str(id).ok()?;
    Some(std::path::Path::new("data/tmp/http").join(format!("{id}.bin")))
}

// ============================================
// Data Configuration API
// ============================================

/// Rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateConfig {
    pub enabled: bool,
    pub threshold_percent: u8,
    pub disk_usage_percent: u8,
}

/// Get rotation configuration
pub async fn get_rotate_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let disk_usage = Database::get_disk_usage_percent(&state.config.database_url);
    ApiResponse::ok(RotateConfig {
        enabled: Database::is_auto_rotate_enabled(),
        threshold_percent: Database::get_rotate_threshold(),
        disk_usage_percent: disk_usage,
    })
}

/// Update rotation configuration request
#[derive(Debug, Deserialize)]
pub struct UpdateRotateConfigRequest {
    pub enabled: Option<bool>,
    pub threshold_percent: Option<u8>,
}

/// Update rotation configuration
pub async fn update_rotate_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateRotateConfigRequest>,
) -> impl IntoResponse {
    if let Some(enabled) = req.enabled {
        Database::set_auto_rotate_enabled(enabled);
    }
    if let Some(threshold) = req.threshold_percent {
        Database::set_rotate_threshold(threshold);
    }
    let disk_usage = Database::get_disk_usage_percent(&state.config.database_url);
    ApiResponse::ok(RotateConfig {
        enabled: Database::is_auto_rotate_enabled(),
        threshold_percent: Database::get_rotate_threshold(),
        disk_usage_percent: disk_usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn http_temp_file_path_accepts_uuid_ids_only() {
        let id = "550e8400-e29b-41d4-a716-446655440000";

        assert_eq!(
            http_temp_file_path_for_id(id).as_deref(),
            Some(Path::new(
                "data/tmp/http/550e8400-e29b-41d4-a716-446655440000.bin"
            ))
        );
    }

    #[test]
    fn http_temp_file_path_rejects_path_traversal_ids() {
        for id in [
            "../550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000/../../x",
            "550e8400-e29b-41d4-a716-446655440000.bin",
            "",
        ] {
            assert!(http_temp_file_path_for_id(id).is_none());
        }
    }
}
