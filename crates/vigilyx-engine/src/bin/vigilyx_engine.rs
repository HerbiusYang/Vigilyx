//! Vigilyx Security Analysis Engine - standalone process

//! Responsibilities:
//! 1. Subscribe to Redis Streams to receive EmailSession / HttpSession
//! 2. Run SecurityEngine + DataSecurityEngine analysis (in parallel)
//! 3. Forward results via Redis Pub/Sub (Engine -> API)
//! 4. Listen for API commands (rescan / reload) via Pub/Sub
//! 5. Periodically publish engine status, clean up expired IOCs

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use vigilyx_core::models::{EmailSession, HttpSession, WsMessage};
use vigilyx_db::VigilDb;
use vigilyx_db::mq::{
    MqClient, MqConfig, StreamClient, consumer_groups, keys, streams, topics, verify_cmd_payload,
};

use vigilyx_engine::config::PipelineConfig;
use vigilyx_engine::data_security::engine::DataSecurityEngine;
use vigilyx_engine::engine::SecurityEngine;
use vigilyx_engine::module_data::init_module_data_from_db;
use vigilyx_engine::modules::registry::reload_runtime_ioc_caches;

/// Vigilyx Security Analysis Engine - standalone process
#[derive(Parser, Debug)]
#[command(name = "vigilyx-engine", about = "Vigilyx Security Analysis Engine")]
struct Args {
    /// database URL (overrides the DATABASE_URL environment variable)
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Redis URL (overrides the REDIS_URL environment variable)
    #[arg(long, env = "REDIS_URL")]
    redis_url: Option<String>,
}

/// Engine runtime status (published to Redis)

/// Uses `#[serde(flatten)]` to merge `EngineStatus` fields
/// (running, uptime_seconds, total_sessions_processed,...) into the same level,
/// with additional process-level fields appended.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineProcessStatus {
    // EngineStatus already contains running / uptime_seconds, no need to redefine
    pub email_engine_active: bool,
    pub data_security_engine_active: bool,
    pub ds_sessions_processed: u64,
    pub ds_incidents_detected: u64,
    #[serde(flatten)]
    pub engine_status: Option<serde_json::Value>,
}

/// Engine process shared state (engine only, excludes transport layer)
struct EngineState {
    /// Retain DB reference for command handling (config reload, etc.)
    #[allow(dead_code)]
    db: VigilDb,
    security_engine: SecurityEngine,
    data_security_engine: DataSecurityEngine,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Global panic hook
    std::panic::set_hook(Box::new(|info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!("[PANIC] {}\n\nBacktrace:\n{}", info, backtrace);
    }));

    // Load.env file (if present)
    let _ = dotenvy::dotenv();

    // Initialize logging (JSON format in production via LOG_FORMAT=json)
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_env_filter(env_filter)
            .init();
    }

    let args = Args::parse();

    info!("Vigilyx Engine 独立进程启动中...");

    // Database initialization

    // SEC-H01: No hardcoded fallback password - DATABASE_URL must be provided via env var or CLI
    let database_url = args
        .database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .expect(
            "DATABASE_URL 环境变量未设置且未通过 --database-url 指定。请在 .env 或环境变量中配置。",
        );
    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;
    // Seed built-in system whitelist so curated safe domains override stale external intel pollution.
    match db.seed_system_whitelist().await {
        Ok(n) if n > 0 => info!("系统白名单已注入/刷新: {} 条记录", n),
        Ok(_) => info!("系统白名单已是最新状态"),
        Err(e) => warn!("系统白名单注入失败: {}", e),
    }
    // SEC-H01: Mask password before logging (CWE-532)
    let masked_url = if let Some(at_pos) = database_url.find('@') {
        if let Some(colon_pos) = database_url[..at_pos].rfind(':') {
            format!(
                "{}:***@{}",
                &database_url[..colon_pos],
                &database_url[at_pos + 1..]
            )
        } else {
            "***masked***".to_string()
        }
    } else {
        database_url.clone()
    };
    info!("数据库连接成功: {}", masked_url);

    // Transport layer: Redis only (Streams data plane + Pub/Sub control plane)

    let mq_config = MqConfig::from_env();
    let mq = MqClient::new(mq_config);

    match tokio::time::timeout(std::time::Duration::from_secs(5), mq.connect()).await {
        Ok(Ok(_)) => {
            info!("Redis connection established (Streams + Pub/Sub)");
        }
        Ok(Err(e)) => {
            anyhow::bail!(
                "Redis connection failed: {e}. Engine requires Redis — check REDIS_URL and Redis container status."
            );
        }
        Err(_) => {
            anyhow::bail!(
                "Redis connection timed out (5s). Engine requires Redis — check REDIS_URL and Redis container status."
            );
        }
    };

    let stream = StreamClient::with_auto_consumer(mq.clone(), consumer_groups::ENGINE);

    // Load pipeline configuration

    let pipeline_config = load_pipeline_config(&db).await;

    // Create broadcast channel (engine internal communication)
    let (ws_tx, _) = broadcast::channel::<WsMessage>(10_000);

    // Start security engine

    let security_engine = SecurityEngine::start(db.clone(), pipeline_config, ws_tx.clone())
        .await
        .map_err(|e| anyhow::anyhow!("SecurityEngine 启动失败: {}", e))?;
    info!("SecurityEngine 启动成功");

    // Start data security engine

    let data_security_engine = DataSecurityEngine::start(db.clone(), ws_tx.clone());
    info!("DataSecurityEngine 启动成功");

    // Shared state

    let state = Arc::new(EngineState {
        db,
        security_engine,
        data_security_engine,
    });

    // IOC expiry cleanup: hourly

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = state.security_engine.ioc_manager.cleanup_expired().await {
                    warn!("IOC 过期清理失败: {}", e);
                }
            }
        });
    }

    // Catch-up scan: every 10 minutes, re-analyze
    // completed sessions that have no verdict

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
                match state.db.query_unanalyzed_sessions(&cutoff, 200).await {
                    Ok(session_ids) if !session_ids.is_empty() => {
                        info!(count = session_ids.len(), "补扫遗漏 Session");
                        for sid in &session_ids {
                            // Load session from DB
                            match state.db.get_session(*sid).await {
                                Ok(Some(session)) => {
                                    if let Err(e) = state.security_engine.submit(session).await {
                                        warn!(session_id = %sid, "补扫提交失败: {}", e);
                                    }
                                }
                                Ok(None) => warn!(session_id = %sid, "补扫: Session 不存在"),
                                Err(e) => warn!(session_id = %sid, "补扫: 读取失败: {}", e),
                            }
                            // Rate limit: 500ms between submissions
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => warn!("查询遗漏 Session 失败: {}", e),
                }
            }
        });
    }

    // Data retention cleanup: runs daily
    // Cleans sessions/verdicts/incidents older than 90 days + temporal data older than 180 days
    // Runs ANALYZE to update statistics (no VACUUM to avoid long table locks)
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // First run after 5 minutes (let engine process settle)
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            // Run once every 24 hours
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                info!("开始每日数据保留清理...");

                // Clean business data older than 90 days
                match state.db.cleanup_old_data(90).await {
                    Ok((sessions, security)) => {
                        if sessions > 0 || security > 0 {
                            info!(
                                sessions_deleted = sessions,
                                security_deleted = security,
                                "数据保留清理: 业务数据"
                            );
                        }
                    }
                    Err(e) => warn!("数据保留清理失败 (业务数据): {}", e),
                }

                // Clean temporal data older than 180 days
                match state.db.cleanup_stale_temporal(180).await {
                    Ok(total) if total > 0 => {
                        info!(deleted = total, "数据保留清理: 时序数据");
                    }
                    Ok(_) => {}
                    Err(e) => warn!("数据保留清理失败 (时序数据): {}", e),
                }

                // Optimize (ANALYZE + lightweight VACUUM)
                if let Err(e) = state.db.optimize().await {
                    warn!("数据库优化失败: {}", e);
                }
            }
        });
    }

    // Heartbeat file: write data/engine-status.json every 5s
    // Fallback for API readiness check when Redis status channel is unavailable
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let heartbeat_path = std::path::PathBuf::from("data/engine-status.json");
            let pid = std::process::id();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let heartbeat = build_engine_heartbeat(&state, pid).await;
                if let Ok(json) = serde_json::to_string(&heartbeat) {
                    // SEC-M13: Use tokio::fs to avoid blocking the async runtime (CWE-400)
                    // Atomic write: write to temp file then rename to prevent partial reads
                    let tmp_path = heartbeat_path.with_extension("json.tmp");
                    if tokio::fs::write(&tmp_path, &json).await.is_ok() {
                        let _ = tokio::fs::rename(&tmp_path, &heartbeat_path).await;
                    }
                }
            }
        });
    }

    // Start Redis IO loop (Streams data plane + Pub/Sub control plane)

    run_redis_mode(state, mq, stream, ws_tx).await?;

    Ok(())
}

// Redis mode

/// Redis mode: Streams for data plane, Pub/Sub for control plane + legacy
async fn run_redis_mode(
    state: Arc<EngineState>,
    mq: MqClient,
    stream: StreamClient,
    ws_tx: broadcast::Sender<WsMessage>,
) -> Result<()> {
    let pid = std::process::id();

    // Bridge: broadcast -> Redis
    {
        let mq = mq.clone();
        let mut ws_rx = ws_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match ws_rx.recv().await {
                    Ok(msg) => {
                        let result = match &msg {
                            WsMessage::SecurityVerdict(v) => {
                                mq.publish(topics::ENGINE_VERDICT, v).await
                            }
                            WsMessage::DataSecurityAlert(i) => {
                                mq.publish(topics::ENGINE_DS_INCIDENT, i).await
                            }
                            WsMessage::Alert(a) => mq.publish(topics::ENGINE_ALERT, a).await,
                            _ => Ok(()),
                        };
                        if let Err(e) = result {
                            warn!("Bridge: 发布到 Redis 失败: {}", e);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Bridge: 消息滞后, 跳过 {} 条消息", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Bridge: broadcast channel 已关闭");
                        break;
                    }
                }
            }
        });
    }

    // Stream input loop (PRIMARY — at-least-once delivery via consumer groups)
    {
        let state = Arc::clone(&state);
        let stream = stream.clone();
        tokio::spawn(async move {
            loop {
                match stream_input_loop(&state, &stream).await {
                    Ok(()) => warn!("Stream input loop ended normally, reconnecting in 5s..."),
                    Err(e) => error!("Stream input loop failed: {}, reconnecting in 5s...", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Redis command loop (control plane: rescan / reload)
    {
        let state = Arc::clone(&state);
        let mq = mq.clone();
        tokio::spawn(async move {
            loop {
                match redis_command_loop(&state, &mq).await {
                    Ok(()) => warn!("Redis 指令订阅正常结束, 5 秒后重连..."),
                    Err(e) => error!("Redis 指令订阅失败: {}, 5 秒后重连...", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Publish an initial heartbeat so API readiness recovers immediately after restart.
    {
        let heartbeat = build_engine_heartbeat(&state, pid).await;
        if let Err(e) = mq.publish(topics::ENGINE_STATUS, &heartbeat).await {
            warn!("Publish initial engine status failed: {}", e);
        }
    }

    // Status publish: Pub/Sub broadcast + Redis TTL key (heartbeat dead-man switch)
    {
        let state = Arc::clone(&state);
        let mq = mq.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let heartbeat = build_engine_heartbeat(&state, pid).await;
                // Pub/Sub broadcast (for API WebSocket)
                if let Err(e) = mq.publish(topics::ENGINE_STATUS, &heartbeat).await {
                    warn!("Publish engine status failed: {}", e);
                }
                // Redis key with 30s TTL (dead-man switch for readiness probes)
                if let Err(e) = mq.set_json(keys::ENGINE_HEARTBEAT, &heartbeat, 30).await {
                    warn!("Set engine heartbeat key failed: {}", e);
                }
            }
        });
    }

    info!("Vigilyx Engine 已启动 [Redis mode], 等待任务...");
    tokio::signal::ctrl_c().await?;
    info!("收到关闭信号, Engine 进程退出");
    Ok(())
}

// Shared helpers

/// Build engine status JSON.
///
/// Output merges EngineStatus fields with process-level fields.
async fn build_engine_status(state: &Arc<EngineState>) -> serde_json::Value {
    let engine_status = state.security_engine.metrics.get_status().await;
    let ds_stats = state.data_security_engine.stats();

    let status = EngineProcessStatus {
        email_engine_active: true,
        data_security_engine_active: true,
        ds_sessions_processed: ds_stats.http_sessions_processed,
        ds_incidents_detected: ds_stats.incidents_detected,
        engine_status: serde_json::to_value(&engine_status).ok(),
    };

    serde_json::to_value(&status).unwrap_or_default()
}

async fn build_engine_heartbeat(state: &Arc<EngineState>, pid: u32) -> serde_json::Value {
    let status = build_engine_status(state).await;
    serde_json::json!({
        "running": true,
        "pid": pid,
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
    })
}

/// Submit email session to SecurityEngine (non-blocking, retries on queue full)
fn submit_to_security_engine(state: &Arc<EngineState>, session: EmailSession) {
    match state.security_engine.try_submit(session.clone()) {
        Ok(()) => {}
        Err(_) => {
            let state = Arc::clone(state);
            let session_clone = session.clone();
            tokio::spawn(async move {
                if let Err(e) = state
                    .security_engine
                    .submit_with_backoff(session_clone.clone())
                    .await
                {
                    warn!(session_id = %session_clone.id, "提交 SecurityEngine 失败: {}", e);
                }
            });
        }
    }
}

/// Handle cache reload command
fn handle_reload_command(state: &Arc<EngineState>, target: &str) {
    info!("收到缓存刷新指令: {}", target);
    match target.trim_matches('"') {
        "whitelist" => {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                if let Err(e) = state.security_engine.whitelist_manager.load().await {
                    error!("白名单缓存刷新失败: {}", e);
                } else {
                    info!("白名单缓存已刷新");
                }
            });
        }
        "ioc" => {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                reload_runtime_ioc_caches(
                    &state.db,
                    state.security_engine.safe_domains_handle.as_ref(),
                )
                .await;
                info!("IOC runtime caches reloaded");
            });
        }
        "config" => {
            warn!("Pipeline 配置已变更, 需重启 Engine 进程生效");
        }
        "keywords" => {
            warn!("Keyword 规则已变更, 需重启 Engine 进程生效");
        }
        "module_data" => {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                init_module_data_from_db(&state.db).await;
                info!("Module data registry reloaded from DB");
            });
        }
        "ai_config" => {
            info!("AI 服务配置已更新 (运行时自动使用新配置)");
        }
        other => {
            warn!("未知的 reload 目标: {}", other);
        }
    }
}

/// Load pipeline configuration (from DB, fallback to defaults)
async fn load_pipeline_config(db: &VigilDb) -> PipelineConfig {
    match db.get_config("security_pipeline").await {
        Ok(Some(json)) => match serde_json::from_str::<PipelineConfig>(&json) {
            Ok(mut config) => {
                info!("从数据库加载安全 Pipeline 配置");

                // Auto-merge new modules from defaults
                let default_config = PipelineConfig::default();
                let existing_ids: std::collections::HashSet<String> =
                    config.modules.iter().map(|m| m.id.clone()).collect();
                let mut added = Vec::new();
                for default_mod in &default_config.modules {
                    if !existing_ids.contains(&default_mod.id) {
                        added.push(default_mod.id.clone());
                        config.modules.push(default_mod.clone());
                    }
                }
                if !added.is_empty() {
                    info!("自动合并新模块到 Pipeline: {:?}", added);
                }

                // Defensive validation: reject DB-stored config with unsafe values
                // (potential direct DB tampering indicator)
                if let Err(violations) = config.verdict_config.validate() {
                    warn!(
                        violations = ?violations,
                        "DB-stored VerdictConfig failed validation (possible DB tampering), falling back to safe defaults"
                    );
                    config.verdict_config = vigilyx_engine::config::VerdictConfig::default();
                }

                config
            }
            Err(e) => {
                warn!("Pipeline 配置解析失败: {}, 使用默认配置", e);
                PipelineConfig::default()
            }
        },
        _ => {
            info!("使用默认安全 Pipeline 配置");
            PipelineConfig::default()
        }
    }
}

/// How a Stream message should be acknowledged after processing.
enum AckDecision {
    /// Caller should batch-ACK this message ID.
    Immediate,
    /// A spawned task will ACK later (e.g. delayed content retry).
    Deferred,
    /// Do not ACK — leave in PEL for XAUTOCLAIM to reclaim.
    Skip,
}

/// Batch-ACK helper: sends a single XACK with all collected message IDs.
async fn batch_ack(stream: &StreamClient, stream_key: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let _ = stream.xack(stream_key, &refs).await;
}

/// Stream input loop: read email + HTTP sessions from Redis Streams with consumer groups.
///
/// Provides at-least-once delivery: messages are ACK'd only after successful processing.
/// Uses batch XACK to minimize Redis round-trips (1 XACK per read batch instead of per message).
/// Crashed consumer's messages are reclaimed via XAUTOCLAIM on startup.
async fn stream_input_loop(state: &Arc<EngineState>, stream: &StreamClient) -> Result<()> {
    // Ensure consumer groups exist (idempotent)
    stream.ensure_group(streams::EMAIL_SESSIONS).await?;
    stream.ensure_group(streams::HTTP_SESSIONS).await?;
    info!(
        consumer = stream.consumer_name(),
        "Stream consumer started (email + HTTP sessions)"
    );

    // Reclaim abandoned messages from crashed consumers (idle > 60s)
    let reclaimed: Vec<(String, EmailSession)> = stream
        .xautoclaim(streams::EMAIL_SESSIONS, 60_000, 100)
        .await
        .unwrap_or_default();
    {
        let mut ack_ids: Vec<String> = Vec::with_capacity(reclaimed.len());
        for (id, session) in reclaimed {
            if let AckDecision::Immediate = stream_process_email(state, stream, &id, session).await
            {
                ack_ids.push(id);
            }
        }
        batch_ack(stream, streams::EMAIL_SESSIONS, &ack_ids).await;
    }

    let reclaimed_http: Vec<(String, Vec<HttpSession>)> = stream
        .xautoclaim(streams::HTTP_SESSIONS, 60_000, 100)
        .await
        .unwrap_or_default();
    {
        let mut ack_ids: Vec<String> = Vec::with_capacity(reclaimed_http.len());
        for (id, sessions) in reclaimed_http {
            stream_process_http(state, sessions);
            ack_ids.push(id);
        }
        batch_ack(stream, streams::HTTP_SESSIONS, &ack_ids).await;
    }

    // Main read loop: alternate between email and HTTP streams
    loop {
        // Read email sessions (block up to 2s)
        let email_msgs: Vec<(String, EmailSession)> = stream
            .xreadgroup(streams::EMAIL_SESSIONS, 50, Some(2000))
            .await?;
        {
            let mut ack_ids: Vec<String> = Vec::with_capacity(email_msgs.len());
            for (id, session) in email_msgs {
                if let AckDecision::Immediate =
                    stream_process_email(state, stream, &id, session).await
                {
                    ack_ids.push(id);
                }
            }
            batch_ack(stream, streams::EMAIL_SESSIONS, &ack_ids).await;
        }

        // Read HTTP sessions without BLOCK so the command is truly non-blocking.
        let http_msgs: Vec<(String, Vec<HttpSession>)> =
            stream.xreadgroup(streams::HTTP_SESSIONS, 10, None).await?;
        {
            let mut ack_ids: Vec<String> = Vec::with_capacity(http_msgs.len());
            for (id, sessions) in http_msgs {
                stream_process_http(state, sessions);
                ack_ids.push(id);
            }
            batch_ack(stream, streams::HTTP_SESSIONS, &ack_ids).await;
        }
    }
}

/// Process a single email session from Stream, returning how it should be ACK'd.
///
/// `Immediate` — caller should batch-ACK this message ID.
/// `Deferred`  — a spawned task will ACK later (delayed content retry).
/// `Skip`      — do not ACK; XAUTOCLAIM will reclaim after idle timeout.
async fn stream_process_email(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    msg_id: &str,
    session: EmailSession,
) -> AckDecision {
    // Non-terminal sessions don't need analysis yet.
    if !session.is_terminal_for_analysis() {
        return AckDecision::Immediate;
    }

    // Persist every terminal SMTP session before any analysis-time filtering.
    // This keeps the UI/session table complete even when the security engine
    // intentionally skips intermediate relay hops or non-analyzable payloads.
    if let Err(e) = state.db.insert_session(&session).await {
        warn!(
            session_id = %session.id,
            error = %e,
            "Failed to persist terminal session before analysis"
        );
    }

    if !session.has_analyzable_content() {
        // Session arrived without analyzable content (e.g. partial SMTP session).
        // Retry from DB after a delay: a later Stream message for the same session
        // may have been processed and persisted with full content by then.
        // In HTTP-fallback mode, the Sniffer writes sessions directly to DB.
        // In Redis Streams mode, the Engine persists sessions after analysis
        // (see engine.rs run_loop), so a completed version may already be in DB.
        // The spawned task owns the ACK responsibility.
        let state = Arc::clone(state);
        let stream_clone = stream.clone();
        let msg_id = msg_id.to_string();
        let session_id = session.id;
        tokio::spawn(async move {
            for delay_ms in [2000u64, 5000] {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                match state.db.get_session(session_id).await {
                    Ok(Some(db_session)) if db_session.has_analyzable_content() => {
                        submit_to_security_engine(&state, db_session);
                        let _ = stream_clone.xack(streams::EMAIL_SESSIONS, &[&msg_id]).await;
                        return;
                    }
                    _ => {}
                }
            }
            // Give up after retries — ACK to prevent infinite redelivery
            let _ = stream_clone.xack(streams::EMAIL_SESSIONS, &[&msg_id]).await;
        });
        return AckDecision::Deferred;
    }

    // Submit to security engine
    match state.security_engine.submit_with_backoff(session).await {
        Ok(()) => AckDecision::Immediate,
        Err(e) => {
            // Don't ACK — XAUTOCLAIM will reclaim after 60s idle
            warn!(msg_id, error = %e, "Failed to submit session to engine");
            AckDecision::Skip
        }
    }
}

/// Process HTTP sessions (always succeeds — caller batch-ACKs).
fn stream_process_http(state: &Arc<EngineState>, sessions: Vec<HttpSession>) {
    let count = sessions.len();
    for session in sessions {
        if let Err(e) = state.data_security_engine.try_submit(session) {
            warn!(error = %e, "HTTP data security submit failed (channel full)");
        }
    }
    if count > 0 {
        info!(count, "HTTP data security: processed from Stream");
    }
}

/// Redis command loop: Listen for API rescan / reload commands
async fn redis_command_loop(state: &Arc<EngineState>, mq: &MqClient) -> Result<()> {
    let mut pubsub = mq
        .subscribe(&[topics::ENGINE_CMD_RESCAN, topics::ENGINE_CMD_RELOAD])
        .await?;

    // SEC-P06: Read shared token once at startup for control-plane message auth
    let cmd_token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
    if cmd_token.is_empty() {
        warn!("INTERNAL_API_TOKEN not set — control-plane commands will be rejected");
    }

    info!("Redis 指令订阅已启动 (cmd:rescan, cmd:reload)");

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let raw_payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("获取指令内容失败: {}", e);
                continue;
            }
        };

        // SEC-P06: Verify shared token prefix before processing
        let payload = match verify_cmd_payload(&raw_payload, &cmd_token) {
            Some(p) => p,
            None => {
                warn!(
                    channel,
                    "Rejected control command with invalid/missing token (SEC-P06)"
                );
                continue;
            }
        };

        match channel.as_str() {
            topics::ENGINE_CMD_RESCAN => {
                if let Ok(session) = serde_json::from_str::<EmailSession>(payload) {
                    info!(session_id = %session.id, "收到重新扫描指令");
                    submit_to_security_engine(state, session);
                }
            }
            topics::ENGINE_CMD_RELOAD => {
                handle_reload_command(state, payload);
            }
            _ => {}
        }
    }

    Ok(())
}
