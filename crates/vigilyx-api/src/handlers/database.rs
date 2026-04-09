//! Database handlers: session import, statistics, clear operations, rotation config

use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use uuid::Uuid;
use vigilyx_core::{EmailSession, TrafficStats, WsMessage};

use super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;
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

       // Engine processes sessions via Redis topic
       // API does not run SecurityEngine directly

       // UDS: push completed sessions to Engine via Unix domain socket
        #[cfg(unix)]
        if let Some(ref uds_tx) = state.messaging.uds_tx
            && broadcast_session.status == vigilyx_core::SessionStatus::Completed
            && broadcast_session.is_email_complete()
            && let Ok(payload) = serde_json::to_value(&broadcast_session)
        {
            let msg = vigilyx_db::mq::UdsMessage {
                topic: vigilyx_db::mq::topics::SESSION_NEW.to_string(),
                payload,
            };
            if let Err(e) = uds_tx.try_send(msg) {
                tracing::warn!(
                    session_id = %broadcast_session.id,
                    "UDS push session to Engine failed (channel full or shutdown): {}",
                    e
                );
            }
        }
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

/// Clear database (supports multiple modes)
pub async fn clear_database(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    body: Option<Json<ClearDatabaseRequest>>,
) -> axum::response::Response {
    let mode = body.map(|b| b.0.mode).unwrap_or_else(default_clear_mode);
    let start = std::time::Instant::now();

    let result = match mode.as_str() {
        "safe" => state.db.clear_safe().await,
        "quick" => state.db.clear_quick().await,
        "high_performance" => state.db.clear_high_performance().await,
        _ => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Unknown clear mode: {}. Options: safe, quick, high_performance",
                mode
            ))
            .into_response();
        }
    };

    let elapsed_ms = start.elapsed().as_millis();

    match result {
        Ok(_) => {
            tracing::info!("Database cleared (mode={}) in {}ms", mode, elapsed_ms);

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
                        Some(&format!("mode={}, elapsed={}ms", mode_clone, elapsed_ms)),
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
                "elapsed_ms": elapsed_ms
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to clear database (mode={}): {}", mode, e);
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}




pub async fn factory_reset(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> axum::response::Response {
    let start = std::time::Instant::now();

    
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
            let elapsed_ms = start.elapsed().as_millis();
            tracing::warn!("FACTORY RESET completed in {}ms — all data and config cleared", elapsed_ms);

            
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
            let _ = state.messaging.ws_tx.send(WsMessage::StatsUpdate(zeroed_stats));

            ApiResponse::ok(serde_json::json!({
                "message": "System has been reset to factory defaults. All data and configuration cleared. Please log in with the default password.",
                "elapsed_ms": elapsed_ms,
            }))
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
        && !matches!(level, "all" | "safe" | "low" | "medium" | "high" | "critical")
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
    cleanup_http_temp_files(&http_temp_ids);
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
    cleanup_http_temp_files(&http_temp_ids);
    Ok(())
}

async fn clear_all_session_and_security_rows(
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<()> {
    execute_tx(tx, "DELETE FROM security_module_results", None).await?;
    execute_tx(tx, "DELETE FROM security_feedback", None).await?;
    execute_tx(tx, "DELETE FROM security_alerts", None).await?;
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
        "DELETE FROM training_samples \
         WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            OR verdict_id IN ( \
                SELECT id FROM security_verdicts \
                WHERE session_id IN (SELECT id FROM sessions WHERE started_at < $1) \
            )",
        Some(cutoff),
    )
    .await?;
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
    let mut query = sqlx::query(sql);
    if let Some(bind_value) = bind_value {
        query = query.bind(bind_value);
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

fn cleanup_http_temp_files(ids: &[String]) {
    let mut files_cleaned = 0u64;
    for id in ids {
        let path = format!("data/tmp/http/{}.bin", id);
        if !std::path::Path::new(&path).exists() {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(path, "Failed to remove HTTP temp file: {}", e);
        } else {
            files_cleaned += 1;
        }
    }

    if files_cleaned > 0 {
        tracing::info!(files_cleaned, "Cleaned HTTP body temp files during precise clear");
    }
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
