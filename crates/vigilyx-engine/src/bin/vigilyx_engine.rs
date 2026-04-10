//! Vigilyx Security Analysis Engine - standalone process

//! Responsibilities:
//! 1. Subscribe to Redis (or UDS fallback) to receive EmailSession / HttpSession
//! 2. Run SecurityEngine + DataSecurityEngine analysis (in parallel)
//! 3. Forward results via bridge to Redis/UDS (Engine -> API)
//! 4. Listen for API commands (rescan / reload)
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
use vigilyx_db::mq::{MqClient, MqConfig, StreamClient, consumer_groups, keys, streams, topics};
#[cfg(unix)]
use vigilyx_db::mq::{UdsClient, UdsMessage};

use vigilyx_engine::config::PipelineConfig;
use vigilyx_engine::data_security::engine::DataSecurityEngine;
use vigilyx_engine::engine::SecurityEngine;
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

/// Engine runtime status (published to Redis/UDS)

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

/// Engine transport mode
enum EngineTransport {
    /// Redis mode: Streams (primary data plane) + Pub/Sub (control plane + legacy)
    Redis {
        mq: MqClient,
        stream: Box<StreamClient>,
    },
    /// UDS fallback mode (legacy, being removed)
    #[cfg(unix)]
    Uds {
        tx: tokio::sync::mpsc::Sender<UdsMessage>,
        rx: tokio::sync::mpsc::Receiver<UdsMessage>,
    },
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

    info!("Vigilyx Engine independent进程StartMedium...");

   // database initialization

   // SEC-H01: No hardcoded fallback password - DATABASE_URL must be provided via env var or CLI
    let database_url = args
        .database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .expect("DATABASE_URL EnvironmentVariable未Set且未通 --database-url 指定。请在 .env 或EnvironmentVariableMediumConfiguration。");
    let db = VigilDb::new(&database_url).await?;
    db.init_security_tables().await?;
   // Seed built-in system whitelist (ON CONFLICT DO NOTHING - does not overwrite existing entries)
    match db.seed_system_whitelist().await {
        Ok(n) if n > 0 => info!("System白Name单already注入: {} ItemNewentry", n),
        Ok(_) => info!("System白Name单alreadystored在，无需注入"),
        Err(e) => warn!("System白Name单注入Failed: {}", e),
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
    info!("data库ConnectionSuccess: {}", masked_url);

   // Transport layer: try Redis, fall back to UDS on failure

    let mq_config = MqConfig::from_env();
    let mq = MqClient::new(mq_config);

    let transport =
        match tokio::time::timeout(std::time::Duration::from_secs(5), mq.connect()).await {
            Ok(Ok(_)) => {
                info!("Redis connection established (Streams + Pub/Sub)");
                let stream = Box::new(
                    StreamClient::with_auto_consumer(mq.clone(), consumer_groups::ENGINE),
                );
                EngineTransport::Redis { mq, stream }
            }
            Ok(Err(e)) => {
                warn!("Redis ConnectionFailed: {}", e);
                try_uds_fallback().await?
            }
            Err(_) => {
                warn!("Redis ConnectionTimeout");
                try_uds_fallback().await?
            }
        };

   // Load pipeline configuration

    let pipeline_config = load_pipeline_config(&db).await;

   // Create broadcast channel (engine internal communication)
    let (ws_tx, _) = broadcast::channel::<WsMessage>(10_000);

   // StartSecurityEngine

    let security_engine = SecurityEngine::start(db.clone(), pipeline_config, ws_tx.clone())
        .await
        .map_err(|e| anyhow::anyhow!("SecurityEngine StartFailed: {}", e))?;
    info!("SecurityEngine StartSuccess");

   // Startdata security engine

    let data_security_engine = DataSecurityEngine::start(db.clone(), ws_tx.clone());
    info!("DataSecurityEngine StartSuccess");

   // SharedStatus

    let state = Arc::new(EngineState {
        db,
        security_engine,
        data_security_engine,
    });

   // IOC ExpiredCleanup handler: small

    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = state.security_engine.ioc_manager.cleanup_expired().await {
                    warn!("IOC ExpiredCleanupFailed: {}", e);
                }
            }
        });
    }

   // Session: 10
   // completed sessions (verdict)
    
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
                        info!(count = session_ids.len(), "补扫遗漏Session");
                        for sid in &session_ids {
                           // DB session,
                            match state.db.get_session(*sid).await {
                                Ok(Some(session)) => {
                                    if let Err(e) = state.security_engine.submit(session).await {
                                        warn!(session_id = %sid, "补扫提交失败: {}", e);
                                    }
                                }
                                Ok(None) => warn!(session_id = %sid, "补扫: Session不存在"),
                                Err(e) => warn!(session_id = %sid, "补扫: 读取失败: {}", e),
                            }
                           // : 500ms,
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                    Ok(_) => {} 
                    Err(e) => warn!("查询遗漏Session失败: {}", e),
                }
            }
        });
    }

   // datakeepCleanup handler: Day Executeline
   // Cleanup 90 Dayfirstof sessions/verdicts/incidents + 180 Dayfirstof Status
   // Cleanup Executeline ANALYZE UpdateStatisticsInfo(VACUUM,AvoidlongtimestampLocktable)
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
           // FirstStart 5 minute(Engine Process)
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
           // 24 small Executeline1Time/Count
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                info!("Start每SundaydatakeepCleanup...");

               // Cleanup 90 DayfirstofBusinessdata
                match state.db.cleanup_old_data(90).await {
                    Ok((sessions, security)) => {
                        if sessions > 0 || security > 0 {
                            info!(
                                sessions_deleted = sessions,
                                security_deleted = security,
                                "datakeepCleanup: Businessdata"
                            );
                        }
                    }
                    Err(e) => warn!("datakeepCleanupFailed (Businessdata): {}", e),
                }

               // Cleanup 180 Dayfirstof AnalyzeStatus
                match state.db.cleanup_stale_temporal(180).await {
                    Ok(total) if total > 0 => {
                        info!(deleted = total, "datakeepCleanup: 时序Status");
                    }
                    Ok(_) => {}
                    Err(e) => warn!("datakeepCleanupFailed (时序Status): {}", e),
                }

               // Cleanup Performance notesdata (ANALYZE + VACUUM, VACUUM readwrite)
                if let Err(e) = state.db.optimize().await {
                    warn!("data库OptimizeFailed: {}", e);
                }
            }
        });
    }

   // hopsFile handler: 5 write data/engine-status.json
   // UDS/Redis of Statuschannel,API ConnectreadGetFileJudgeEnginewhether
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
                   // SEC-M13: Use tokio::fs Avoid AsynchronousRuntime (CWE-400)
                   // write: writetempFile rename, prevent API read writedata
                    let tmp_path = heartbeat_path.with_extension("json.tmp");
                    if tokio::fs::write(&tmp_path, &json).await.is_ok() {
                        let _ = tokio::fs::rename(&tmp_path, &heartbeat_path).await;
                    }
                }
            }
        });
    }

   // according toTransmissionmodeStart of IO Loop

    match transport {
        EngineTransport::Redis { mq, stream } => {
            run_redis_mode(state, mq, *stream, ws_tx).await?;
        }
        #[cfg(unix)]
        EngineTransport::Uds { tx, rx } => {
            run_uds_mode(state, tx, rx, ws_tx).await?;
        }
    }

    Ok(())
}

/// UDS Connection
#[cfg(unix)]
async fn try_uds_fallback() -> Result<EngineTransport> {
    let socket_path = std::path::PathBuf::from("data/vigilyx.sock");
    warn!("回退到 UDS mode: {}", socket_path.display());
    let (tx, rx) = UdsClient::connect(&socket_path)
        .await
        .map_err(|e| anyhow::anyhow!("UDS ConnectionFailed: {}", e))?;
   // waitWait Connection (connect Returnimmediately, Connection spawn Medium)
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    info!("UDS ConnectionSuccess: {}", socket_path.display());
    Ok(EngineTransport::Uds { tx, rx })
}

#[cfg(not(unix))]
async fn try_uds_fallback() -> Result<EngineTransport> {
    anyhow::bail!("Redis 不可用且Whenfirst平台不支持 UDS 回退")
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
                            warn!("Bridge Publish到 Redis Failed: {}", e);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Bridge Message滞后, hops {} ItemMessage", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Bridge broadcast channel alreadyClose");
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

   // Redis Pub/Sub input loop (LEGACY — kept during migration, receives shadow writes)
    {
        let state = Arc::clone(&state);
        let mq = mq.clone();
        tokio::spawn(async move {
            loop {
                match redis_input_loop(&state, &mq).await {
                    Ok(()) => warn!("Redis Input订阅NormalEnd, 5 秒后重连..."),
                    Err(e) => error!("Redis Input订阅Failed: {}, 5 秒后重连...", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

   // Redis Loop
    {
        let state = Arc::clone(&state);
        let mq = mq.clone();
        tokio::spawn(async move {
            loop {
                match redis_command_loop(&state, &mq).await {
                    Ok(()) => warn!("Redis 指令订阅NormalEnd, 5 秒后重连..."),
                    Err(e) => error!("Redis 指令订阅Failed: {}, 5 秒后重连...", e),
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

    info!("Vigilyx Engine alreadyStart [Redis mode], waitWait任务...");
    tokio::signal::ctrl_c().await?;
    info!("ReceivedCloseSignal, Engine 进程Exit");
    Ok(())
}


// UDS mode


/// UDS mode
#[cfg(unix)]
async fn run_uds_mode(
    state: Arc<EngineState>,
    tx: tokio::sync::mpsc::Sender<UdsMessage>,
    mut rx: tokio::sync::mpsc::Receiver<UdsMessage>,
    ws_tx: broadcast::Sender<WsMessage>,
) -> Result<()> {
    let pid = std::process::id();

   // Bridge: broadcast -> UDS (EngineResult API)
    {
        let tx = tx.clone();
        let mut ws_rx = ws_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match ws_rx.recv().await {
                    Ok(msg) => {
                        let uds_msg = match &msg {
                            WsMessage::SecurityVerdict(v) => Some(UdsMessage {
                                topic: topics::ENGINE_VERDICT.to_string(),
                                payload: serde_json::to_value(v).unwrap_or_default(),
                            }),
                            WsMessage::DataSecurityAlert(i) => Some(UdsMessage {
                                topic: topics::ENGINE_DS_INCIDENT.to_string(),
                                payload: serde_json::to_value(i).unwrap_or_default(),
                            }),
                            WsMessage::Alert(a) => Some(UdsMessage {
                                topic: topics::ENGINE_ALERT.to_string(),
                                payload: serde_json::to_value(a).unwrap_or_default(),
                            }),
                            _ => None,
                        };
                        if let Some(m) = uds_msg
                            && tx.send(m).await.is_err()
                        {
                            warn!("UDS Bridge SendFailed (channel Close)");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("UDS Bridge Message滞后, hops {} ItemMessage", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("UDS Bridge broadcast channel alreadyClose");
                        break;
                    }
                }
            }
        });
    }

   // immediatelyPublish1Time/Count Status (Ensure API Engine)
    {
        let status_json = build_engine_heartbeat(&state, pid).await;
        let msg = UdsMessage {
            topic: topics::ENGINE_STATUS.to_string(),
            payload: status_json,
        };
        if let Err(e) = tx.send(msg).await {
            warn!("UDS 初始StatusPublishFailed: {}", e);
        } else {
            info!("UDS 初始StatusalreadyPublish");
        }
    }

   // StatusPublish handler (UDS, 10)
    {
        let state = Arc::clone(&state);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.tick().await; // hopsAfter1Time/Count immediately (already Publish)
            loop {
                interval.tick().await;
                let status_json = build_engine_heartbeat(&state, pid).await;
                let msg = UdsMessage {
                    topic: topics::ENGINE_STATUS.to_string(),
                    payload: status_json,
                };
                if tx.send(msg).await.is_err() {
                    warn!("UDS StatusPublishFailed (channel Close)");
                    break;
                }
            }
        });
    }

    info!("Vigilyx Engine alreadyStart [UDS mode], waitWait任务...");

   // UDS InputLoop: From API ReceiveSessionAnd
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            Some(msg) = rx.recv() => {
                dispatch_uds_input(&state, msg);
            }
            _ = &mut ctrl_c => {
                info!("ReceivedCloseSignal, Engine 进程Exit");
                break;
            }
        }
    }

    Ok(())
}

/// ProcessFrom API UDS ReceivedofMessage
#[cfg(unix)]
fn dispatch_uds_input(state: &Arc<EngineState>, msg: UdsMessage) {
    match msg.topic.as_str() {
        topics::SESSION_NEW | topics::SESSION_UPDATE => {
            if let Ok(session) = serde_json::from_value::<EmailSession>(msg.payload)
                && session.is_terminal_for_analysis()
            {
                if session.has_analyzable_content() {
                    submit_to_security_engine(state, session);
                } else {
                    let state = Arc::clone(state);
                    let session_id = session.id;
                    tokio::spawn(async move {
                        for delay_ms in [2000u64, 5000] {
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            match state.db.get_session(session_id).await {
                                Ok(Some(db_session)) if db_session.has_analyzable_content() => {
                                    submit_to_security_engine(&state, db_session);
                                    return;
                                }
                                _ => {}
                            }
                        }
                    });
                }
            }
        }
        topics::HTTP_SESSION_NEW => {
            if let Ok(sessions) = serde_json::from_value::<Vec<HttpSession>>(msg.payload) {
                let batch_count = sessions.len();
                info!(
                    count = batch_count,
                    "HTTP dataSecurity: From UDS Received {}  HTTP Session", batch_count
                );
                for session in sessions {
                    if let Err(e) = state.data_security_engine.try_submit(session) {
                        warn!(
                            "HTTP dataSecurity: 提交到EngineFailed (channelfull/Close): {}",
                            e
                        );
                    }
                }
            } else {
                warn!("HTTP dataSecurity: UDS MessageDeserializeFailed");
            }
        }
        topics::ENGINE_CMD_RESCAN => {
            if let Ok(session) = serde_json::from_value::<EmailSession>(msg.payload) {
                info!(session_id = %session.id, "Received重New扫描指令 (UDS)");
                submit_to_security_engine(state, session);
            }
        }
        topics::ENGINE_CMD_RELOAD => {
            if let Ok(target) = serde_json::from_value::<String>(msg.payload) {
                handle_reload_command(state, &target);
            }
        }
        _ => {}
    }
}


// Shared


/// BuildEngineStatus JSON

/// Outputstructure (): EngineStatus Segment + level Segment
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

/// emailSession SecurityEngine (non-blocking, Queuefull spawn retry)
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
                    warn!(session_id = %session_clone.id, "提交SecurityEngineFailed: {}", e);
                }
            });
        }
    }
}

/// Processcache New
fn handle_reload_command(state: &Arc<EngineState>, target: &str) {
    info!("Receivedcache刷New指令: {}", target);
    match target.trim_matches('"') {
        "whitelist" => {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                if let Err(e) = state.security_engine.whitelist_manager.load().await {
                    error!("白Name单cache刷NewFailed: {}", e);
                } else {
                    info!("白Name单cachealready刷New");
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
            warn!("PipelineConfigurationalready变更, 需重启 Engine 进程生效");
        }
        "keywords" => {
            warn!("Keyword rulealready变更, 需重启 Engine 进程生效");
        }
        "ai_config" => {
            info!("AI ServiceConfigurationalreadyUpdate (RuntimeAutoUseNewConfiguration)");
        }
        other => {
            warn!("Unknownof reload Target: {}", other);
        }
    }
}

/// LoadPipelineConfiguration (From DB UseDefault)
async fn load_pipeline_config(db: &VigilDb) -> PipelineConfig {
    match db.get_config("security_pipeline").await {
        Ok(Some(json)) => match serde_json::from_str::<PipelineConfig>(&json) {
            Ok(mut config) => {
                info!("Fromdata库LoadSecurityPipelineConfiguration");

               // AutoMergeAdd newModule
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
                    info!("AutoMergeAdd newModule到Pipeline: {:?}", added);
                }

                config
            }
            Err(e) => {
                warn!(
                    "PipelineConfigurationParseFailed: {}, UseDefaultConfiguration",
                    e
                );
                PipelineConfig::default()
            }
        },
        _ => {
            info!("UseDefaultSecurityPipelineConfiguration");
            PipelineConfig::default()
        }
    }
}

/// Stream input loop: read email + HTTP sessions from Redis Streams with consumer groups.
///
/// Provides at-least-once delivery: messages are ACK'd only after successful processing.
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
    for (id, session) in reclaimed {
        stream_process_email(state, stream, &id, session).await;
    }

    let reclaimed_http: Vec<(String, Vec<HttpSession>)> = stream
        .xautoclaim(streams::HTTP_SESSIONS, 60_000, 100)
        .await
        .unwrap_or_default();
    for (id, sessions) in reclaimed_http {
        stream_process_http(state, stream, &id, sessions).await;
    }

    // Main read loop: alternate between email and HTTP streams
    loop {
        // Read email sessions (block up to 2s)
        let email_msgs: Vec<(String, EmailSession)> = stream
            .xreadgroup(streams::EMAIL_SESSIONS, 50, Some(2000))
            .await?;
        for (id, session) in email_msgs {
            stream_process_email(state, stream, &id, session).await;
        }

        // Read HTTP sessions without BLOCK so the command is truly non-blocking.
        let http_msgs: Vec<(String, Vec<HttpSession>)> = stream
            .xreadgroup(streams::HTTP_SESSIONS, 10, None)
            .await?;
        for (id, sessions) in http_msgs {
            stream_process_http(state, stream, &id, sessions).await;
        }
    }
}

/// Process a single email session from Stream and ACK on success.
async fn stream_process_email(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    msg_id: &str,
    session: EmailSession,
) {
    // Only analyze terminal sessions.
    if !session.is_terminal_for_analysis() {
        // ACK immediately — non-terminal sessions don't need analysis yet.
        let _ = stream.xack(streams::EMAIL_SESSIONS, &[msg_id]).await;
        return;
    }

    if !session.has_analyzable_content() {
        // Retry from DB after a delay (sniffer may not have flushed to DB yet)
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
                        let _ = stream_clone
                            .xack(streams::EMAIL_SESSIONS, &[&msg_id])
                            .await;
                        return;
                    }
                    _ => {}
                }
            }
            // Give up after retries — ACK to prevent infinite redelivery
            let _ = stream_clone
                .xack(streams::EMAIL_SESSIONS, &[&msg_id])
                .await;
        });
        return;
    }

    // Submit to security engine
    match state.security_engine.submit_with_backoff(session).await {
        Ok(()) => {
            let _ = stream.xack(streams::EMAIL_SESSIONS, &[msg_id]).await;
        }
        Err(e) => {
            // Don't ACK — XAUTOCLAIM will reclaim after 60s idle
            warn!(msg_id, error = %e, "Failed to submit session to engine");
        }
    }
}

/// Process HTTP sessions from Stream and ACK on success.
async fn stream_process_http(
    state: &Arc<EngineState>,
    stream: &StreamClient,
    msg_id: &str,
    sessions: Vec<HttpSession>,
) {
    let count = sessions.len();
    for session in sessions {
        if let Err(e) = state.data_security_engine.try_submit(session) {
            warn!(error = %e, "HTTP data security submit failed (channel full)");
        }
    }
    if count > 0 {
        info!(count, "HTTP data security: processed from Stream");
    }
    let _ = stream.xack(streams::HTTP_SESSIONS, &[msg_id]).await;
}

/// Redis Pub/Sub input loop (LEGACY — kept during migration period)
///
/// Receives shadow writes from sniffer. Will be removed after full Stream migration.
async fn redis_input_loop(state: &Arc<EngineState>, mq: &MqClient) -> Result<()> {
    let mut pubsub = mq
        .subscribe(&[
            topics::SESSION_NEW,
            topics::SESSION_UPDATE,
            topics::HTTP_SESSION_NEW,
        ])
        .await?;

    info!("Redis Input订阅alreadyStart (session:new, session:update, http_session:new)");

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("GetMessageContentFailed: {}", e);
                continue;
            }
        };

        match channel.as_str() {
            topics::SESSION_NEW | topics::SESSION_UPDATE => {
                if let Ok(session) = serde_json::from_str::<EmailSession>(&payload)
                    && session.is_terminal_for_analysis()
                {
                    if session.has_analyzable_content() {
                       // : Redis
                        submit_to_security_engine(state, session);
                    } else {
                       // : Sniffer Redis,
                       // DB session(sniffer DB)
                        let state = Arc::clone(state);
                        let session_id = session.id;
                        tokio::spawn(async move {
                           // Sniffer Redis, DB.
                           // :2 + 5, sniffer.
                            for delay_ms in [2000u64, 5000] {
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                                match state.db.get_session(session_id).await {
                                    Ok(Some(db_session)) if db_session.has_analyzable_content() => {
                                        submit_to_security_engine(&state, db_session);
                                        return;
                                    }
                                    _ => {} 
                                }
                            }
                            
                        });
                    }
                }
            }
            topics::HTTP_SESSION_NEW => {
                if let Ok(sessions) = serde_json::from_str::<Vec<HttpSession>>(&payload) {
                    let batch_count = sessions.len();
                    info!(
                        count = batch_count,
                        "HTTP dataSecurity: From Redis Received {}  HTTP Session", batch_count
                    );
                    for session in sessions {
                        if let Err(e) = state.data_security_engine.try_submit(session) {
                            warn!(
                                "HTTP dataSecurity: 提交到EngineFailed (channelfull/Close): {}",
                                e
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Redis Loop: Listen API of rescan / reload
async fn redis_command_loop(state: &Arc<EngineState>, mq: &MqClient) -> Result<()> {
    let mut pubsub = mq
        .subscribe(&[topics::ENGINE_CMD_RESCAN, topics::ENGINE_CMD_RELOAD])
        .await?;

    info!("Redis 指令订阅alreadyStart (cmd:rescan, cmd:reload)");

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("Get指令ContentFailed: {}", e);
                continue;
            }
        };

        match channel.as_str() {
            topics::ENGINE_CMD_RESCAN => {
                if let Ok(session) = serde_json::from_str::<EmailSession>(&payload) {
                    info!(session_id = %session.id, "Received重New扫描指令");
                    submit_to_security_engine(state, session);
                }
            }
            topics::ENGINE_CMD_RELOAD => {
                handle_reload_command(state, &payload);
            }
            _ => {}
        }
    }

    Ok(())
}
