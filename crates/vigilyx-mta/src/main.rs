//! Vigilyx MTA

//! 2. PostgreSQL
//! 3. SecurityEngine
//! 4. SMTP/SMTPS

use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use vigilyx_core::models::WsMessage;
use vigilyx_db::VigilDb;
use vigilyx_db::mq::topics;
use vigilyx_db::mq::{MqClient, MqConfig, verify_cmd_payload};
use vigilyx_engine::config::PipelineConfig;
use vigilyx_engine::modules::registry::reload_runtime_ioc_caches;
use vigilyx_engine::pipeline::engine::SecurityEngine;

use vigilyx_mta::config::MtaConfig;
use vigilyx_mta::authentication::AuthenticationVerifier;
use vigilyx_mta::metrics::VerdictMetrics;
use vigilyx_mta::relay::downstream::DownstreamRelay;
use vigilyx_mta::server::listener::{self, PerIpLimiter};
use vigilyx_mta::server::tls;

#[derive(Parser, Debug)]
#[command(
    name = "vigilyx-mta",
    about = "Vigilyx MTA Proxy — SMTP relay with inline security"
)]
struct Args {
    /// DATABASE_URL
    #[arg(long)]
    database_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,vigilyx_mta=info,vigilyx_engine=info".into()),
        )
        .init();

    // .env
    let _ = dotenvy::dotenv();
    let args = Args::parse();

    // MTA config: env vars -> DB overrides (UI settings take priority)
    let mut config = MtaConfig::from_env()?;
    let db_url = args
        .database_url
        .clone()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_default();
    if !db_url.is_empty()
        && let Err(e) = config.override_from_db(&db_url).await
    {
        warn!("从数据库加载 MTA 配置失败（将使用环境变量默认值）: {e}");
    }
    let config = Arc::new(config);
    info!("MTA configuration loaded");
    info!(smtp = %config.listen_smtp, "SMTP listen address");
    if let Some(ref smtps) = config.listen_smtps {
        info!(smtps = %smtps, "SMTPS listen address");
    }
    if config.listen_submission.is_some() {
        warn!(
            "Submission listener requested, but SMTP AUTH is not implemented; port 587 remains disabled"
        );
    }
    if config.local_domains.is_empty() {
        warn!(
            "MTA_LOCAL_DOMAINS is empty; all RCPT TO commands will be denied until local domains are configured"
        );
    } else {
        info!(local_domains = ?config.local_domains, "Accepted local recipient domains");
    }
    info!(
        downstream = format!("{}:{}", config.downstream.host, config.downstream.port),
        "Downstream MTA"
    );

    let db_url = args
        .database_url
        .unwrap_or_else(|| config.database_url.clone());
    let db = VigilDb::new(&db_url).await?;
    db.init_security_tables().await?;
    info!("Database connected");

    let pipeline_config = load_pipeline_config(&db).await;

    // db (engine take ownership)
    let quarantine_db = db.clone();

    // SecurityEngine
    // WebSocket broadcast channel (MTA WebSocket,)
    let (ws_tx, _ws_rx) = broadcast::channel::<WsMessage>(256);
    let engine = SecurityEngine::start(db, pipeline_config, ws_tx).await?;
    let engine = Arc::new(engine);
    info!("Security engine started (embedded)");

    let relay = DownstreamRelay::new(&config.downstream).await?;
    let relay = Arc::new(relay);

    let outbound_relay = if let Some(ref outbound_cfg) = config.outbound {
        info!(
            outbound = format!("{}:{}", outbound_cfg.host, outbound_cfg.port),
            "Outbound relay configured (separate from inbound downstream)"
        );
        Arc::new(DownstreamRelay::new(outbound_cfg).await?)
    } else {
        warn!("MTA_OUTBOUND_HOST not set, outbound emails will use inbound downstream relay");
        Arc::clone(&relay)
    };
    let db = Arc::new(quarantine_db);
    let authentication = Arc::new(AuthenticationVerifier::new());

    // TLS acceptor ()
    let tls_acceptor = config
        .tls
        .as_ref()
        .map(tls::build_tls_acceptor)
        .transpose()?;

    // -- Redis subscription: hot-reload whitelist/IOC caches --
    let redis_url = config.redis_url.clone().unwrap_or_default();
    if !redis_url.is_empty() {
        let eng = engine.clone();
        let reload_db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = redis_reload_loop(&redis_url, &eng, &reload_db).await {
                error!("Redis reload subscription failed: {e}");
            }
        });
    } else {
        warn!("REDIS_URL not configured, config hot-reload disabled for MTA engine");
    }

    // (SMTP + SMTPS,)
    let active_connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Inline 判定分布计数器（随状态心跳上报到 API）
    let verdict_metrics = Arc::new(VerdictMetrics::default());
    // SEC: per-IP connection limiter shared between all listeners (CWE-400)
    let per_ip_limiter = Arc::new(PerIpLimiter::new(10));

    let mut tasks = Vec::new();

    // SMTP (+ STARTTLS)
    {
        let cfg = Arc::clone(&config);
        let eng = Arc::clone(&engine);
        let rl = Arc::clone(&relay);
        let orl = Arc::clone(&outbound_relay);
        let d = Arc::clone(&db);
        let ac = Arc::clone(&active_connections);
        let ipl = Arc::clone(&per_ip_limiter);
        let tls = tls_acceptor.clone();
        let met = Arc::clone(&verdict_metrics);
        let auth = Arc::clone(&authentication);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = listener::run_smtp_listener(
                cfg, eng, rl, orl, d, ac, ipl, tls, met, auth,
            )
            .await
            {
                error!("SMTP listener error: {e}");
            }
        }));
    }

    // SMTPS (TLS, 465)
    if config.listen_smtps.is_some()
        && let Some(ref acceptor) = tls_acceptor
    {
        let cfg = Arc::clone(&config);
        let eng = Arc::clone(&engine);
        let rl = Arc::clone(&relay);
        let orl = Arc::clone(&outbound_relay);
        let d = Arc::clone(&db);
        let ac = Arc::clone(&active_connections);
        let ipl = Arc::clone(&per_ip_limiter);
        let tls = acceptor.clone();
        let met = Arc::clone(&verdict_metrics);
        let auth = Arc::clone(&authentication);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = listener::run_smtps_listener(
                cfg, eng, rl, orl, d, ac, ipl, tls, met, auth,
            )
            .await
            {
                error!("SMTPS listener error: {e}");
            }
        }));
    }

    // 状态上报：MTA 状态 + inline 判定计数推送到 API（/api/system/mta）
    {
        let api_host = std::env::var("MTA_API_HOST").unwrap_or_else(|_| "vigilyx".into());
        let api_port = std::env::var("MTA_API_PORT").unwrap_or_else(|_| "8088".into());
        let api_url = format!("http://{api_host}:{api_port}");
        info!("Status报告任务: Target API = {}/api/system/mta", api_url);
        let report_config = Arc::clone(&config);
        let report_ac = Arc::clone(&active_connections);
        let report_metrics = Arc::clone(&verdict_metrics);
        tasks.push(tokio::spawn(async move {
            mta_status_report_loop(api_url, report_config, report_ac, report_metrics).await;
        }));
    }

    info!("Vigilyx MTA proxy running");

    for task in tasks {
        task.await?;
    }

    Ok(())
}

/// Load the same pipeline contract used by the standalone engine.
async fn load_pipeline_config(db: &VigilDb) -> PipelineConfig {
    match db.get_config("security_pipeline").await {
        Ok(Some(json)) => match serde_json::from_str::<PipelineConfig>(&json) {
            Ok(mut config) => {
                info!("从数据库加载安全 Pipeline 配置 (MTA)");

                let added = config.merge_default_modules();
                if !added.is_empty() {
                    info!("MTA 自动合并新模块到 Pipeline: {:?}", added);
                }

                if let Some(violations) = config.repair_unsafe_verdict_config() {
                    warn!(
                        violations = ?violations,
                        "MTA DB-stored VerdictConfig failed validation, falling back to safe defaults"
                    );
                }

                config
            }
            Err(e) => {
                error!("Pipeline config parse failed: {e}, using defaults");
                PipelineConfig::default()
            }
        },
        _ => {
            info!("No pipeline config in DB, using defaults");
            PipelineConfig::default()
        }
    }
}

/// Redis subscription loop: listen for ENGINE_CMD_RELOAD and hot-reload whitelist/IOC caches.
/// Matches the behavior of the standalone engine redis_command_loop.
async fn redis_reload_loop(
    redis_url: &str,
    engine: &Arc<SecurityEngine>,
    db: &Arc<VigilDb>,
) -> anyhow::Result<()> {
    let mq_config = MqConfig {
        redis_url: redis_url.to_string(),
        ..MqConfig::default()
    };
    let mq = MqClient::new(mq_config);
    // subscribe() creates its own dedicated connection internally, so no prior connect() is needed
    let mut pubsub = mq.subscribe(&[topics::ENGINE_CMD_RELOAD]).await?;

    // SEC-P06: Read shared token once at startup for control-plane message auth
    let cmd_token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
    if cmd_token.is_empty() {
        warn!("INTERNAL_API_TOKEN not set — MTA reload commands will be rejected");
    }

    info!("MTA Redis reload subscription started (cmd:reload)");

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let raw_payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to read reload payload: {e}");
                continue;
            }
        };

        // SEC-P06: Verify shared token prefix before processing
        let payload = match verify_cmd_payload(&raw_payload, &cmd_token) {
            Some(p) => p,
            None => {
                warn!("MTA rejected reload command with invalid/missing token (SEC-P06)");
                continue;
            }
        };

        let target = payload.trim_matches('"');
        info!("MTA received reload command: {target}");
        match target {
            "whitelist" => {
                if let Err(e) = engine.whitelist_manager.load().await {
                    error!("MTA whitelist reload failed: {e}");
                } else {
                    info!("MTA whitelist cache reloaded");
                }
            }
            "ioc" => {
                reload_runtime_ioc_caches(db, engine.safe_domains_handle.as_ref()).await;
                info!("MTA IOC runtime caches reloaded");
            }
            "config" | "keywords" => {
                warn!(
                    "Pipeline config/keywords changed, MTA engine restart required to take effect"
                );
            }
            "ai_config" => {
                info!("AI config updated (runtime auto-use new config)");
            }
            other => {
                warn!("Unknown reload target: {other}");
            }
        }
    }

    Ok(())
}

/// 构建带内部认证 token 的 HTTP 默认头（与 sniffer 的 internal_api_headers 一致）
fn internal_api_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(t) = std::env::var("INTERNAL_API_TOKEN")
        && let Ok(v) = t.parse()
    {
        h.insert("X-Internal-Token", v);
    }
    h
}

/// MTA 状态上报（与 API 侧 MtaStatus 结构对应）
#[derive(Serialize)]
struct MtaStatusReport {
    online: bool,
    downstream_host: String,
    downstream_port: u16,
    active_connections: u64,
    last_update: String,
    accepted: u64,
    quarantined: u64,
    rejected: u64,
    timeout_failopen: u64,
}

/// 周期性向 API 推送 MTA 状态与 inline 判定计数（镜像 sniffer 的状态报告任务）
async fn mta_status_report_loop(
    api_url: String,
    config: Arc<MtaConfig>,
    active_connections: Arc<std::sync::atomic::AtomicUsize>,
    metrics: Arc<VerdictMetrics>,
) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(internal_api_headers())
        .build()
        .expect("internal status HTTP client should build");
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut report_count = 0u32;

    loop {
        interval.tick().await;
        let counters = metrics.snapshot();
        let report = MtaStatusReport {
            online: true,
            downstream_host: config.downstream.host.clone(),
            downstream_port: config.downstream.port,
            active_connections: active_connections.load(Ordering::Relaxed) as u64,
            last_update: chrono::Utc::now().to_rfc3339(),
            accepted: counters.accepted,
            quarantined: counters.quarantined,
            rejected: counters.rejected,
            timeout_failopen: counters.timeout_failopen,
        };
        report_count += 1;

        match client
            .post(format!("{}/api/system/mta", api_url))
            .json(&report)
            .timeout(Duration::from_secs(2))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    if report_count <= 3 || report_count.is_multiple_of(60) {
                        info!(
                            "Status报告 #{}: connections={}, accepted={}, quarantined={}, rejected={}, timeout_failopen={} (HTTP {})",
                            report_count,
                            report.active_connections,
                            report.accepted,
                            report.quarantined,
                            report.rejected,
                            report.timeout_failopen,
                            status.as_u16()
                        );
                    }
                } else {
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        "Status报告 #{} HTTP Error: {} - {}",
                        report_count,
                        status.as_u16(),
                        body
                    );
                }
            }
            Err(e) => {
                if report_count <= 10 {
                    warn!("Status报告Failed: {}", e);
                }
            }
        }
    }
}
