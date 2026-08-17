//! Vigilyx Security Analysis Engine - standalone process

//! Responsibilities:
//! 1. Subscribe to Redis Streams to receive EmailSession / HttpSession
//! 2. Run SecurityEngine + DataSecurityEngine analysis (in parallel)
//! 3. Forward results via Redis Pub/Sub (Engine -> API)
//! 4. Consume durable rescan references and listen for reload commands via Pub/Sub
//! 5. Periodically publish engine status, clean up expired IOCs

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use vigilyx_core::models::{
    EmailSession, HttpSession, Protocol, SessionSource, SessionStatus, WsMessage,
};
use vigilyx_db::VigilDb;
use vigilyx_db::mq::{
    MqClient, MqConfig, PoisonedStreamMessage, RescanSessionReference, StreamClient,
    consumer_groups, keys, streams, topics, verify_cmd_payload,
};
use vigilyx_db::security::quarantine::QuarantineEntry;
use vigilyx_parser::mime::{MimeParser, decode_rfc2047};

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
            let lookback_hours = std::env::var("ENGINE_BACKFILL_LOOKBACK_HOURS")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(72)
                .clamp(1, 24 * 30);
            let batch_limit = std::env::var("ENGINE_BACKFILL_BATCH_LIMIT")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(500)
                .clamp(10, 2_000);
            let settle_seconds = std::env::var("ENGINE_BACKFILL_SETTLE_SECONDS")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(30)
                .clamp(0, 600);
            let submit_delay_ms = std::env::var("ENGINE_BACKFILL_SUBMIT_DELAY_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(100)
                .min(1_000);
            let mut cursor_started_at: Option<String> = None;
            let mut cursor_id: Option<String> = None;

            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(180));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now();
                let cutoff = (now - chrono::Duration::hours(lookback_hours)).to_rfc3339();
                let until = (now - chrono::Duration::seconds(settle_seconds)).to_rfc3339();
                if cursor_started_at
                    .as_deref()
                    .is_some_and(|cursor| cursor < cutoff.as_str())
                {
                    cursor_started_at = None;
                    cursor_id = None;
                }

                match state
                    .db
                    .query_unanalyzed_session_candidates(
                        &cutoff,
                        cursor_started_at.as_deref(),
                        cursor_id.as_deref(),
                        &until,
                        batch_limit,
                    )
                    .await
                {
                    Ok(candidates) if !candidates.is_empty() => {
                        info!(count = candidates.len(), lookback_hours, "补扫遗漏 Session");
                        for (sid, started_at) in &candidates {
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
                            cursor_started_at = Some(started_at.clone());
                            cursor_id = Some(sid.to_string());
                            if submit_delay_ms > 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    submit_delay_ms,
                                ))
                                .await;
                            }
                        }
                    }
                    Ok(_) => {
                        cursor_started_at = None;
                        cursor_id = None;
                    }
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

                // C6: enforce quarantine TTL (expired raw_eml entries).
                // Entries in `releasing` state are protected by the SQL guard.
                match state.db.quarantine_cleanup_expired().await {
                    Ok(deleted) if deleted > 0 => {
                        info!(deleted, "数据保留清理: 隔离区过期条目");
                    }
                    Ok(_) => {}
                    Err(e) => warn!("数据保留清理失败 (隔离区): {}", e),
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
        "time_policy" => {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                match state
                    .data_security_engine
                    .reload_time_policy(&state.db)
                    .await
                {
                    Ok(config) => info!(
                        offset_hours = config.utc_offset_hours,
                        work_hour_start = config.work_hour_start,
                        work_hour_end = config.work_hour_end,
                        "Data security time policy reloaded"
                    ),
                    Err(error) => error!(%error, "Data security time policy reload failed"),
                }
            });
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

                let added = config.merge_default_modules();
                if !added.is_empty() {
                    info!("自动合并新模块到 Pipeline: {:?}", added);
                }

                // Defensive validation: reject DB-stored config with unsafe values
                // (potential direct DB tampering indicator)
                if let Some(violations) = config.repair_unsafe_verdict_config() {
                    warn!(
                        violations = ?violations,
                        "DB-stored VerdictConfig failed validation (possible DB tampering), falling back to safe defaults"
                    );
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckDecision {
    /// Caller should batch-ACK this message ID.
    Immediate,
    /// A spawned task will ACK later (e.g. delayed content retry).
    Deferred,
    /// Do not ACK — leave in PEL for XAUTOCLAIM to reclaim.
    Skip,
}

/// C5: maximum delivery attempts before a message is considered permanently
/// failing and dead-lettered. Without this cap, a persistent error (e.g. a
/// database outage on `get_session`) left the message in the PEL forever,
/// retried every reclaim cycle.
const MAX_STREAM_DELIVERY_ATTEMPTS: u64 = 5;

/// C5: true when a reclaimed message has exhausted its delivery budget and
/// must be dead-lettered instead of retried again. Ids missing from the
/// delivery-count map are treated as a first delivery (retry once more).
fn exceeds_delivery_cap(
    delivery_counts: &std::collections::HashMap<String, u64>,
    id: &str,
) -> bool {
    delivery_counts.get(id).copied().unwrap_or(1) > MAX_STREAM_DELIVERY_ATTEMPTS
}

/// Drain both dead-letter lanes of a stream read: malformed entries and
/// entries rejected by data-plane authentication (C1).
fn take_dead_letters<T>(read: &mut vigilyx_db::mq::StreamRead<T>) -> Vec<PoisonedStreamMessage> {
    std::mem::take(&mut read.poisoned)
        .into_iter()
        .chain(std::mem::take(&mut read.rejected))
        .collect()
}

/// Batch-ACK helper: sends a single XACK with all collected message IDs.
async fn batch_ack(stream: &StreamClient, stream_key: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let _ = stream.xack(stream_key, &refs).await;
}

/// Move dead letters (malformed entries + auth-rejected forgeries) to a DLQ
/// and return only IDs safe to ACK.
async fn dead_letter_poisoned(
    stream: &StreamClient,
    source_stream: &str,
    dlq_stream: &str,
    poisoned: Vec<PoisonedStreamMessage>,
) -> Vec<String> {
    let mut ack_ids = Vec::with_capacity(poisoned.len());
    for message in poisoned {
        if message.id.is_empty() {
            error!(source_stream, error = %message.error, "Malformed Stream entry has no ACK-able id");
            continue;
        }
        match stream
            .xadd_dlq_raw(dlq_stream, &message.id, &message.raw_data, &message.error)
            .await
        {
            Ok(_) => ack_ids.push(message.id),
            Err(error) => warn!(
                source_stream,
                dlq_stream,
                message_id = %message.id,
                error = %error,
                "Failed to move poison Stream entry to DLQ; leaving it pending"
            ),
        }
    }
    ack_ids
}

/// Stream input loop: read live email, rescan references, and HTTP sessions.
///
/// Provides at-least-once delivery: messages are ACK'd only after successful processing.
/// Uses batch XACK to minimize Redis round-trips (1 XACK per read batch instead of per message).
/// Crashed consumer's messages are reclaimed via XAUTOCLAIM on startup.
async fn stream_input_loop(state: &Arc<EngineState>, stream: &StreamClient) -> Result<()> {
    // Ensure consumer groups exist (idempotent)
    stream.ensure_group(streams::EMAIL_SESSIONS).await?;
    stream.ensure_group(streams::RESCAN_REQUESTS).await?;
    stream.ensure_group(streams::HTTP_SESSIONS).await?;
    info!(
        consumer = stream.consumer_name(),
        "Stream consumer started (email + rescan references + HTTP sessions)"
    );

    // Reclaim abandoned messages from crashed consumers (idle > 60s). Drain
    // multiple batches on startup; the old path reclaimed only 100 messages,
    // so larger PELs could stay stuck indefinitely.
    if let Err(e) = reclaim_email_pending(state, stream, 5).await {
        warn!("Email Stream pending reclaim failed: {}", e);
    }
    if let Err(e) = reclaim_rescan_pending(state, stream, 5).await {
        warn!("Rescan Stream pending reclaim failed: {}", e);
    }
    if let Err(e) = reclaim_http_pending(state, stream, 5).await {
        warn!("HTTP Stream pending reclaim failed: {}", e);
    }

    // Main read loop: alternate between email and HTTP streams
    let mut last_pending_reclaim = std::time::Instant::now();
    loop {
        // Read email sessions (block up to 2s)
        let mut email_read = stream
            .xreadgroup_checked::<EmailSession>(streams::EMAIL_SESSIONS, 50, Some(2000))
            .await?;
        {
            let mut ack_ids = dead_letter_poisoned(
                stream,
                streams::EMAIL_SESSIONS,
                streams::EMAIL_SESSIONS_DLQ,
                take_dead_letters(&mut email_read),
            )
            .await;
            ack_ids.reserve(email_read.messages.len());
            for (id, session) in email_read.messages {
                if let AckDecision::Immediate =
                    stream_process_email(state, stream, &id, session).await
                {
                    ack_ids.push(id);
                }
            }
            batch_ack(stream, streams::EMAIL_SESSIONS, &ack_ids).await;
        }

        // Historical rescans contain only UUID references. Keep this read
        // non-blocking so new live SMTP sessions retain priority.
        let mut rescan_read = stream
            .xreadgroup_checked::<RescanSessionReference>(streams::RESCAN_REQUESTS, 25, None)
            .await?;
        {
            let mut ack_ids = dead_letter_poisoned(
                stream,
                streams::RESCAN_REQUESTS,
                streams::RESCAN_REQUESTS_DLQ,
                take_dead_letters(&mut rescan_read),
            )
            .await;
            ack_ids.reserve(rescan_read.messages.len());
            for (id, reference) in rescan_read.messages {
                if stream_process_rescan_reference(state, &id, reference).await
                    == AckDecision::Immediate
                {
                    ack_ids.push(id);
                }
            }
            batch_ack(stream, streams::RESCAN_REQUESTS, &ack_ids).await;
        }

        // Read HTTP sessions without BLOCK so the command is truly non-blocking.
        let mut http_read = stream
            .xreadgroup_checked::<Vec<HttpSession>>(streams::HTTP_SESSIONS, 10, None)
            .await?;
        {
            let mut ack_ids = dead_letter_poisoned(
                stream,
                streams::HTTP_SESSIONS,
                streams::HTTP_SESSIONS_DLQ,
                take_dead_letters(&mut http_read),
            )
            .await;
            ack_ids.reserve(http_read.messages.len());
            for (id, sessions) in http_read.messages {
                if stream_process_http(state, sessions) == AckDecision::Immediate {
                    ack_ids.push(id);
                }
            }
            batch_ack(stream, streams::HTTP_SESSIONS, &ack_ids).await;
        }

        if last_pending_reclaim.elapsed() >= std::time::Duration::from_secs(30) {
            log_pending_summary(stream).await;
            if let Err(e) = reclaim_email_pending(state, stream, 3).await {
                warn!("Email Stream periodic pending reclaim failed: {}", e);
            }
            if let Err(e) = reclaim_rescan_pending(state, stream, 3).await {
                warn!("Rescan Stream periodic pending reclaim failed: {}", e);
            }
            if let Err(e) = reclaim_http_pending(state, stream, 3).await {
                warn!("HTTP Stream periodic pending reclaim failed: {}", e);
            }
            last_pending_reclaim = std::time::Instant::now();
        }
    }
}

async fn reclaim_rescan_pending(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    max_batches: usize,
) -> Result<usize> {
    let mut total = 0usize;
    for _ in 0..max_batches {
        let mut reclaimed = stream
            .xautoclaim_checked::<RescanSessionReference>(streams::RESCAN_REQUESTS, 60_000, 200)
            .await?;
        if reclaimed.is_empty() {
            break;
        }
        let reclaimed_len = reclaimed.len();
        let mut ack_ids = dead_letter_poisoned(
            stream,
            streams::RESCAN_REQUESTS,
            streams::RESCAN_REQUESTS_DLQ,
            take_dead_letters(&mut reclaimed),
        )
        .await;
        ack_ids.reserve(reclaimed.messages.len());
        let delivery_counts = std::mem::take(&mut reclaimed.delivery_counts);
        for (id, reference) in reclaimed.messages {
            // C5: permanently failing references (e.g. repeated DB errors)
            // must be dead-lettered instead of retried forever.
            if exceeds_delivery_cap(&delivery_counts, &id) {
                match stream
                    .xadd_dlq(
                        streams::RESCAN_REQUESTS_DLQ,
                        &id,
                        &reference,
                        "exceeded max delivery attempts (permanent failure)",
                    )
                    .await
                {
                    Ok(_) => ack_ids.push(id),
                    Err(error) => warn!(
                        msg_id = %id,
                        %error,
                        "Failed to dead-letter over-retried rescan reference; leaving pending"
                    ),
                }
                continue;
            }
            if stream_process_rescan_reference(state, &id, reference).await
                == AckDecision::Immediate
            {
                ack_ids.push(id);
            }
        }
        batch_ack(stream, streams::RESCAN_REQUESTS, &ack_ids).await;
        total += reclaimed_len;
        if reclaimed_len < 200 {
            break;
        }
    }
    if total > 0 {
        info!(count = total, "Rescan Stream pending messages reclaimed");
    }
    Ok(total)
}

async fn reclaim_email_pending(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    max_batches: usize,
) -> Result<usize> {
    let mut total = 0usize;
    for _ in 0..max_batches {
        let mut reclaimed = stream
            .xautoclaim_checked::<EmailSession>(streams::EMAIL_SESSIONS, 60_000, 200)
            .await?;
        if reclaimed.is_empty() {
            break;
        }
        let reclaimed_len = reclaimed.len();
        let mut ack_ids = dead_letter_poisoned(
            stream,
            streams::EMAIL_SESSIONS,
            streams::EMAIL_SESSIONS_DLQ,
            take_dead_letters(&mut reclaimed),
        )
        .await;
        ack_ids.reserve(reclaimed.messages.len());
        let delivery_counts = std::mem::take(&mut reclaimed.delivery_counts);
        for (id, session) in reclaimed.messages {
            // C5: permanently failing sessions must be dead-lettered instead
            // of becoming PEL squatters retried every reclaim cycle.
            if exceeds_delivery_cap(&delivery_counts, &id) {
                match stream
                    .xadd_dlq(
                        streams::EMAIL_SESSIONS_DLQ,
                        &id,
                        &session,
                        "exceeded max delivery attempts (permanent failure)",
                    )
                    .await
                {
                    Ok(_) => ack_ids.push(id),
                    Err(error) => warn!(
                        msg_id = %id,
                        session_id = %session.id,
                        %error,
                        "Failed to dead-letter over-retried email session; leaving pending"
                    ),
                }
                continue;
            }
            if let AckDecision::Immediate = stream_process_email(state, stream, &id, session).await
            {
                ack_ids.push(id);
            }
        }
        batch_ack(stream, streams::EMAIL_SESSIONS, &ack_ids).await;
        total += reclaimed_len;
        if reclaimed_len < 200 {
            break;
        }
    }
    if total > 0 {
        info!(count = total, "Email Stream pending messages reclaimed");
    }
    Ok(total)
}

async fn reclaim_http_pending(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    max_batches: usize,
) -> Result<usize> {
    let mut total = 0usize;
    for _ in 0..max_batches {
        let mut reclaimed = stream
            .xautoclaim_checked::<Vec<HttpSession>>(streams::HTTP_SESSIONS, 60_000, 200)
            .await?;
        if reclaimed.is_empty() {
            break;
        }
        let reclaimed_len = reclaimed.len();
        let mut ack_ids = dead_letter_poisoned(
            stream,
            streams::HTTP_SESSIONS,
            streams::HTTP_SESSIONS_DLQ,
            take_dead_letters(&mut reclaimed),
        )
        .await;
        ack_ids.reserve(reclaimed.messages.len());
        let delivery_counts = std::mem::take(&mut reclaimed.delivery_counts);
        for (id, sessions) in reclaimed.messages {
            // C5: cap retries for permanently failing HTTP batches.
            if exceeds_delivery_cap(&delivery_counts, &id) {
                match stream
                    .xadd_dlq(
                        streams::HTTP_SESSIONS_DLQ,
                        &id,
                        &sessions,
                        "exceeded max delivery attempts (permanent failure)",
                    )
                    .await
                {
                    Ok(_) => ack_ids.push(id),
                    Err(error) => warn!(
                        msg_id = %id,
                        %error,
                        "Failed to dead-letter over-retried HTTP sessions; leaving pending"
                    ),
                }
                continue;
            }
            if stream_process_http(state, sessions) == AckDecision::Immediate {
                ack_ids.push(id);
            }
        }
        batch_ack(stream, streams::HTTP_SESSIONS, &ack_ids).await;
        total += reclaimed_len;
        if reclaimed_len < 200 {
            break;
        }
    }
    if total > 0 {
        info!(count = total, "HTTP Stream pending messages reclaimed");
    }
    Ok(total)
}

async fn log_pending_summary(stream: &StreamClient) {
    match stream.xpending_summary(streams::EMAIL_SESSIONS).await {
        Ok(summary) if summary.total > 0 => warn!(
            pending = summary.total,
            min_id = summary.min_id.as_deref().unwrap_or(""),
            max_id = summary.max_id.as_deref().unwrap_or(""),
            "Email Stream has pending messages"
        ),
        Ok(_) => {}
        Err(e) => warn!("Email Stream pending summary failed: {}", e),
    }

    match stream.xpending_summary(streams::HTTP_SESSIONS).await {
        Ok(summary) if summary.total > 0 => warn!(
            pending = summary.total,
            min_id = summary.min_id.as_deref().unwrap_or(""),
            max_id = summary.max_id.as_deref().unwrap_or(""),
            "HTTP Stream has pending messages"
        ),
        Ok(_) => {}
        Err(e) => warn!("HTTP Stream pending summary failed: {}", e),
    }

    match stream.xpending_summary(streams::RESCAN_REQUESTS).await {
        Ok(summary) if summary.total > 0 => warn!(
            pending = summary.total,
            min_id = summary.min_id.as_deref().unwrap_or(""),
            max_id = summary.max_id.as_deref().unwrap_or(""),
            "Rescan Stream has pending messages"
        ),
        Ok(_) => {}
        Err(e) => warn!("Rescan Stream pending summary failed: {}", e),
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

async fn stream_process_rescan_reference(
    state: &Arc<EngineState>,
    msg_id: &str,
    reference: RescanSessionReference,
) -> AckDecision {
    let session = match reference.quarantine_id.as_deref() {
        Some(quarantine_id) => {
            match load_quarantine_rescan_session(state, msg_id, &reference, quarantine_id).await {
                QuarantineRescanLoad::Ready(session) => session,
                // Permanent condition (entry gone, unparseable raw message):
                // acknowledge. The release handler fails closed on timeout.
                QuarantineRescanLoad::SkipMessage => return AckDecision::Immediate,
                // Transient database error: leave pending for XAUTOCLAIM retry.
                QuarantineRescanLoad::Retry => return AckDecision::Skip,
            }
        }
        None => match state.db.get_session(reference.session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                warn!(
                    msg_id,
                    session_id = %reference.session_id,
                    "Rescan reference targets a missing session; acknowledging"
                );
                return AckDecision::Immediate;
            }
            Err(error) => {
                warn!(
                    msg_id,
                    session_id = %reference.session_id,
                    %error,
                    "Rescan reference database load failed; leaving pending"
                );
                return AckDecision::Skip;
            }
        },
    };

    let Some(session) = prepare_rescan_session(session) else {
        warn!(
            msg_id,
            session_id = %reference.session_id,
            "Rescan reference has no analyzable content; acknowledging"
        );
        return AckDecision::Immediate;
    };

    match state.security_engine.submit_with_backoff(session).await {
        Ok(()) => AckDecision::Immediate,
        Err(error) => {
            warn!(
                msg_id,
                session_id = %reference.session_id,
                %error,
                "Rescan reference submit failed; leaving pending"
            );
            AckDecision::Skip
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum QuarantineRescanLoad {
    Ready(EmailSession),
    SkipMessage,
    Retry,
}

/// Load a quarantine-backed rescan: re-parse the stored raw_eml and rebuild
/// the session from it.
///
/// The release path relays the stored raw_eml bytes, so the pre-release rescan
/// must analyze those exact bytes. Reusing the persisted session row would
/// systematically miss content dropped by parser degradation paths (attachment
/// caps, size truncation): a poisoned raw_eml could then pass the gate.
///
/// Fail-closed: an unparseable raw message never falls back to the session
/// row. The message is acknowledged (retrying cannot fix the bytes) and the
/// release handler refuses the release after its verdict wait times out.
async fn load_quarantine_rescan_session(
    state: &Arc<EngineState>,
    msg_id: &str,
    reference: &RescanSessionReference,
    quarantine_id: &str,
) -> QuarantineRescanLoad {
    let (raw_eml, entry) = match state.db.quarantine_get_raw_eml(quarantine_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            warn!(
                msg_id,
                quarantine_id,
                "Quarantine rescan targets a missing entry; acknowledging"
            );
            return QuarantineRescanLoad::SkipMessage;
        }
        Err(error) => {
            warn!(
                msg_id,
                quarantine_id,
                %error,
                "Quarantine rescan database load failed; leaving pending"
            );
            return QuarantineRescanLoad::Retry;
        }
    };

    match quarantine_rescan_session_from_raw(
        reference.session_id,
        &entry,
        &raw_eml,
        reference.client_ip.as_deref(),
    ) {
        Some(session) => QuarantineRescanLoad::Ready(session),
        None => {
            warn!(
                msg_id,
                quarantine_id,
                session_id = %reference.session_id,
                "Quarantine rescan failed to parse stored raw_eml; acknowledging (release will fail closed)"
            );
            QuarantineRescanLoad::SkipMessage
        }
    }
}

/// Rebuild an analyzable session from the exact quarantined raw message.
///
/// Returns `None` when the raw message cannot be parsed; callers must treat
/// this as permanent (fail-closed) rather than retrying or substituting the
/// degraded session row.
///
/// `client_ip` (from the rescan reference) takes precedence over the
/// quarantine entry's own record; both beat the "unknown" placeholder. A5:
/// without the real client IP, every IP-reputation / behavior-baseline signal
/// is lost and an inline High verdict can degrade below the release gate.
fn quarantine_rescan_session_from_raw(
    session_id: uuid::Uuid,
    entry: &QuarantineEntry,
    raw_eml: &[u8],
    client_ip: Option<&str>,
) -> Option<EmailSession> {
    let mut content = MimeParser::new().parse(raw_eml).ok()?;
    // Fail closed on degraded parses: the release gate must vouch for the
    // exact bytes being relayed, and a truncated parse means part of those
    // bytes (e.g. dropped attachments) was never inspected.
    if content.truncated || content.dropped_attachments > 0 {
        return None;
    }
    content.is_complete = true;

    // The quarantine entry predates full transport-endpoint persistence;
    // restore the real client IP when known, keep the "unknown" placeholder
    // for the downstream server endpoint.
    let client_ip = client_ip
        .filter(|ip| !ip.is_empty())
        .or(entry.client_ip.as_deref().filter(|ip| !ip.is_empty()))
        .unwrap_or("unknown");
    let mut session = EmailSession::new(
        Protocol::Smtp,
        client_ip.to_string(),
        0,
        "unknown".to_string(),
        25,
    );
    // Keep the original session id so the release handler's verdict poll and
    // the persisted verdict row line up.
    session.id = session_id;
    session.status = SessionStatus::Completed;
    session.ended_at = Some(chrono::Utc::now());
    session.mail_from = entry.mail_from.clone();
    session.rcpt_to = entry.rcpt_to.clone();
    session.subject = entry.subject.clone();
    session.total_bytes = raw_eml.len();
    session.email_count = 1;

    // Mirror the MTA/sniffer path: RFC 2047 encoded-words must be decoded so
    // keyword detectors see the same text the MUA renders.
    if session.subject.is_none() {
        for (key, value) in &content.headers {
            if key.eq_ignore_ascii_case("subject") {
                let decoded = decode_rfc2047(value);
                let trimmed = decoded.trim();
                if !trimmed.is_empty() {
                    session.subject = Some(trimmed.to_string());
                }
                break;
            }
        }
    }

    session.content = content;
    Some(session)
}

/// Prepare a database-backed session for explicit historical analysis.
///
/// `Import` bypasses passive-hop and recent-session dedup while preserving the
/// normal detector, whitelist, verdict persistence, and alert paths.
fn prepare_rescan_session(mut session: EmailSession) -> Option<EmailSession> {
    if !session.has_analyzable_content() {
        return None;
    }
    session.source = SessionSource::Import;
    Some(session)
}

/// Process HTTP sessions and ACK only when the complete Stream message was queued.
fn stream_process_http(state: &Arc<EngineState>, sessions: Vec<HttpSession>) -> AckDecision {
    submit_http_sessions(sessions, |session| {
        state.data_security_engine.try_submit(session)
    })
}

fn submit_http_sessions<F>(sessions: Vec<HttpSession>, mut submit: F) -> AckDecision
where
    F: FnMut(HttpSession) -> Result<(), String>,
{
    let count = sessions.len();
    let mut all_submitted = true;
    for session in sessions {
        if let Err(e) = submit(session) {
            all_submitted = false;
            warn!(error = %e, "HTTP data security submit failed (channel full)");
        }
    }
    if count > 0 {
        info!(count, "HTTP data security: processed from Stream");
    }
    if all_submitted {
        AckDecision::Immediate
    } else {
        // Leave the message in the PEL. XAUTOCLAIM will retry it after the
        // consumer has capacity; DataSecurityEngine deduplication makes the
        // already-submitted prefix safe to replay.
        AckDecision::Skip
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

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::models::HttpMethod;

    fn http_session(id: usize) -> HttpSession {
        HttpSession::new(
            "10.0.0.10".to_string(),
            40_000 + id as u16,
            "10.0.0.20".to_string(),
            80,
            HttpMethod::Post,
            format!("/upload/{id}"),
        )
    }

    #[test]
    fn http_stream_message_is_acked_when_every_session_is_queued() {
        let sessions = vec![http_session(1), http_session(2), http_session(3)];
        let mut submitted = Vec::new();

        let decision = submit_http_sessions(sessions, |session| {
            submitted.push(session.uri);
            Ok(())
        });

        assert_eq!(decision, AckDecision::Immediate);
        assert_eq!(submitted, ["/upload/1", "/upload/2", "/upload/3"]);
    }

    #[test]
    fn http_stream_message_is_not_acked_when_queue_is_full() {
        let sessions = vec![http_session(1), http_session(2), http_session(3)];
        let mut attempts = 0usize;

        let decision = submit_http_sessions(sessions, |_| {
            attempts += 1;
            if attempts == 2 {
                Err("DataSecurityEngine channel full".to_string())
            } else {
                Ok(())
            }
        });

        assert_eq!(decision, AckDecision::Skip);
        assert_eq!(attempts, 3, "the whole batch should still be attempted");
    }

    #[test]
    fn empty_http_stream_message_is_safe_to_ack() {
        let decision = submit_http_sessions(Vec::new(), |_| {
            panic!("empty stream message must not call submit")
        });

        assert_eq!(decision, AckDecision::Immediate);
    }

    #[test]
    fn rescan_reference_marks_database_session_as_explicit_import() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            40_000,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.body_text = Some("historical email".to_string());

        let prepared = prepare_rescan_session(session).expect("session should be analyzable");

        assert_eq!(prepared.source, SessionSource::Import);
        assert_eq!(
            prepared.content.body_text.as_deref(),
            Some("historical email")
        );
    }

    #[test]
    fn rescan_reference_skips_empty_database_session() {
        let session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            40_000,
            "10.0.0.2".to_string(),
            25,
        );

        assert!(prepare_rescan_session(session).is_none());
    }

    fn quarantine_entry(session_id: &uuid::Uuid) -> QuarantineEntry {
        QuarantineEntry {
            id: "quar-entry-1".to_string(),
            session_id: session_id.to_string(),
            verdict_id: None,
            mail_from: Some("billing@evil-example.com".to_string()),
            rcpt_to: vec!["victim@corp.example".to_string()],
            subject: None,
            threat_level: "high".to_string(),
            reason: Some("inline verdict".to_string()),
            status: "releasing".to_string(),
            created_at: "2026-08-14T00:00:00Z".to_string(),
            released_at: None,
            released_by: None,
            ttl_days: 30,
            raw_eml_size: 0,
            client_ip: None,
        }
    }

    /// A multipart message nested deeper than the parser's maximum depth.
    fn overdeep_multipart_message(depth: usize) -> Vec<u8> {
        let mut message = String::from("From: attacker@evil.example\r\nSubject: nested\r\n");
        for level in 0..depth {
            message.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
            ));
        }
        message.push_str("Content-Type: text/plain\r\n\r\ndeep body\r\n");
        for level in (0..depth).rev() {
            message.push_str(&format!("\r\n--b{level}--\r\n"));
        }
        message.into_bytes()
    }

    #[test]
    fn quarantine_rescan_rebuilds_session_from_stored_raw_eml() {
        // PoC for the release-rescan object mismatch: the pre-release rescan
        // must analyze the exact raw_eml bytes that the relay would deliver,
        // not the (possibly truncated / attachment-capped) session row.
        let session_id = uuid::Uuid::new_v4();
        let entry = quarantine_entry(&session_id);
        let raw_eml = concat!(
            "From: billing@evil-example.com\r\n",
            "To: victim@corp.example\r\n",
            "Subject: =?UTF-8?B?6LSm5oi35byC5bi46YCa55+l?= 请立即验证\r\n",
            "Content-Type: multipart/mixed; boundary=\"mix\"\r\n",
            "\r\n",
            "--mix\r\n",
            "Content-Type: text/plain; charset=\"utf-8\"\r\n",
            "\r\n",
            "您的账户已被冻结，请打开附件完成验证。\r\n",
            "--mix\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"invoice.scr\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "TVpmYWtlIGV4ZSBib2R5\r\n",
            "--mix--\r\n",
        )
        .as_bytes();

        let session = quarantine_rescan_session_from_raw(
            session_id,
            &entry,
            raw_eml,
            Some("198.51.100.23"),
        )
        .expect("real raw_eml must parse");

        // The session identity is preserved so the release handler's verdict
        // poll matches the verdict row this analysis will produce.
        assert_eq!(session.id, session_id);
        // A5: the real client IP must be restored so IP-reputation signals
        // survive the release rescan.
        assert_eq!(session.client_ip, "198.51.100.23");
        assert_eq!(session.mail_from.as_deref(), Some("billing@evil-example.com"));
        assert_eq!(session.rcpt_to, vec!["victim@corp.example".to_string()]);
        assert_eq!(session.total_bytes, raw_eml.len());
        // RFC 2047 subject fallback: the entry stored no subject, so the
        // encoded-word subject must be decoded from the raw headers.
        let subject = session.subject.as_deref().expect("decoded subject");
        assert!(subject.contains("账户异常通知"), "subject: {subject}");
        assert!(subject.contains("请立即验证"), "subject: {subject}");
        // Content comes from the raw bytes, including the attachment that a
        // degraded session row might have dropped.
        assert!(
            session
                .content
                .attachments
                .iter()
                .any(|attachment| attachment.filename == "invoice.scr"),
            "attachment from the raw message must survive the rescan rebuild"
        );
        assert!(
            session
                .content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("账户已被冻结")),
            "body text must be re-parsed from the raw message"
        );
        assert!(session.has_analyzable_content());
    }

    #[test]
    fn quarantine_rescan_uses_entry_subject_when_present() {
        let session_id = uuid::Uuid::new_v4();
        let mut entry = quarantine_entry(&session_id);
        entry.subject = Some("stored subject".to_string());
        let raw_eml = b"From: a@b.example\r\nSubject: header subject\r\n\r\nbody\r\n";

        let session = quarantine_rescan_session_from_raw(session_id, &entry, raw_eml, None)
            .expect("message should parse");

        assert_eq!(session.subject.as_deref(), Some("stored subject"));
        // No client IP anywhere → keep the "unknown" placeholder.
        assert_eq!(session.client_ip, "unknown");
    }

    #[test]
    fn quarantine_rescan_falls_back_to_entry_client_ip() {
        // A5: references enqueued before the client_ip field existed must
        // still restore the entry's own recorded client IP.
        let session_id = uuid::Uuid::new_v4();
        let mut entry = quarantine_entry(&session_id);
        entry.client_ip = Some("203.0.113.7".to_string());
        let raw_eml = b"From: a@b.example\r\nSubject: hi\r\n\r\nbody\r\n";

        let session = quarantine_rescan_session_from_raw(session_id, &entry, raw_eml, None)
            .expect("message should parse");

        assert_eq!(session.client_ip, "203.0.113.7");
    }

    #[test]
    fn quarantine_rescan_unparseable_raw_eml_fails_closed() {
        // PoC: a poisoned raw_eml that cannot be fully parsed must NOT fall
        // back to the degraded session row (which would relay it after a
        // stale/clean verdict). Returning None makes the consumer acknowledge
        // without a verdict, so the release handler times out and refuses the
        // release. Since the parser degrades over-limit messages instead of
        // erroring (R4C), "unparseable" includes truncated/degraded results.
        let session_id = uuid::Uuid::new_v4();
        let entry = quarantine_entry(&session_id);
        let raw_eml = overdeep_multipart_message(12);

        let parsed = MimeParser::new().parse(&raw_eml).expect(
            "parser degrades over-deep messages instead of erroring",
        );
        assert!(
            parsed.truncated || parsed.dropped_attachments > 0,
            "test vector must exceed the parser's nesting limit"
        );
        assert!(
            quarantine_rescan_session_from_raw(session_id, &entry, &raw_eml, None).is_none()
        );
    }

    #[test]
    fn delivery_cap_dead_letters_after_five_attempts() {
        // C5: before the cap, a permanent error (e.g. get_session DB failure)
        // left the message un-ACKed forever, retried every 60s reclaim cycle.
        let mut counts = std::collections::HashMap::new();
        counts.insert("1-0".to_string(), 5u64);
        counts.insert("2-0".to_string(), 6u64);

        assert!(
            !exceeds_delivery_cap(&counts, "1-0"),
            "5th delivery gets one last attempt"
        );
        assert!(
            exceeds_delivery_cap(&counts, "2-0"),
            "6th delivery is a permanent failure → DLQ"
        );
        // Unknown ids (delivery-count lookup failed) are retried, not capped.
        assert!(!exceeds_delivery_cap(&counts, "9-9"));
    }
}
