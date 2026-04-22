//! Vigilyx High-performanceStream ListenEngine

//! Target: 1Gbps+ emailStream Capture

//! - Multi-threadParallelProcess (CPU - 1)
//! - LockSessionManagement (DashMap)
//! - BPF
//! - batch processing + Asynchronous MQ Publish
//! - 64MB CapturebufferDistrict

//!   RemoteCaptureMode:
//! - --stdin: FromStandardInputreadGet pcap Stream
//! - --remote-listen: Listen TCP PortReceiveRemote pcap Stream
//! - --remote-connect: ConnectionRemoteServicehandler Get pcap Stream (Used for NAT Environment)

mod capture;
mod parser;
mod session;
#[allow(dead_code)]
mod stream;
mod zerocopy;

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use vigilyx_core::{CaptureMode as ConfigCaptureMode, Config};
use vigilyx_db::mq::{MqClient, MqConfig, verify_cmd_payload};

/// BuildpacketContainsInternalAuthentication of HTTP DefaultHeader
pub(crate) fn internal_api_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(t) = std::env::var("INTERNAL_API_TOKEN")
        && let Ok(v) = t.parse()
    {
        h.insert("X-Internal-Token", v);
    }
    h
}

pub(crate) fn internal_api_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(internal_api_headers())
}

/// Sniffer Status (Used for API)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnifferStatusReport {
    pub online: bool,
    pub connection_status: String,
    pub remote_address: Option<String>,
    pub capture_mode: String,
    pub last_error: Option<String>,
    pub retry_count: u32,
    pub last_update: String,
    pub packets_processed: u64,
    pub bytes_processed: u64,
}

/// Sniffer Status
pub struct GlobalSnifferState {
    pub online: AtomicBool,
    pub connection_status: RwLock<String>,
    pub remote_address: RwLock<Option<String>>,
    pub capture_mode: RwLock<String>,
    pub last_error: RwLock<Option<String>>,
    pub retry_count: AtomicU32,
    pub packets_processed: AtomicU64,
    pub bytes_processed: AtomicU64,
}

impl Default for GlobalSnifferState {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalSnifferState {
    pub fn new() -> Self {
        Self {
            online: AtomicBool::new(false),
            connection_status: RwLock::new("disconnected".to_string()),
            remote_address: RwLock::new(None),
            capture_mode: RwLock::new("unknown".to_string()),
            last_error: RwLock::new(None),
            retry_count: AtomicU32::new(0),
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
        }
    }

    pub async fn to_report(&self) -> SnifferStatusReport {
        SnifferStatusReport {
            online: self.online.load(Ordering::Relaxed),
            connection_status: self.connection_status.read().await.clone(),
            remote_address: self.remote_address.read().await.clone(),
            capture_mode: self.capture_mode.read().await.clone(),
            last_error: self.last_error.read().await.clone(),
            retry_count: self.retry_count.load(Ordering::Relaxed),
            last_update: chrono::Utc::now().to_rfc3339(),
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
        }
    }

    pub async fn set_error(&self, error: &str) {
        *self.last_error.write().await = Some(error.to_string());
        *self.connection_status.write().await = "error".to_string();
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn set_connected(&self) {
        self.online.store(true, Ordering::Relaxed);
        *self.connection_status.write().await = "connected".to_string();
        *self.last_error.write().await = None;
        self.retry_count.store(0, Ordering::Relaxed);
    }

    pub async fn set_connecting(&self) {
        *self.connection_status.write().await = "connecting".to_string();
    }
}

/// StatusInstance
static SNIFFER_STATE: std::sync::OnceLock<Arc<GlobalSnifferState>> = std::sync::OnceLock::new();

pub fn get_sniffer_state() -> Arc<GlobalSnifferState> {
    SNIFFER_STATE
        .get_or_init(|| Arc::new(GlobalSnifferState::new()))
        .clone()
}

use crate::capture::HighPerformanceCapturer;
use crate::session::ShardedSessionManager;

/// Vigilyx High-performanceStream ListenEngine
#[derive(Parser, Debug)]
#[command(name = "vigilyx-sniffer")]
#[command(about = "High-performanceemailStream量Capture与AnalyzeEngine")]
#[command(version)]
struct Args {
    /// FromStandardInputreadGet pcap Stream (Used forRemoteCapture)

    /// UseMethod:
    /// ssh root@remote "tcpdump -i eth1 -U -s0 -w -" | vigilyx-sniffer --stdin
    #[arg(long, conflicts_with_all = ["remote_listen", "interface"])]
    stdin: bool,

    /// Listen TCP PortReceiveRemote pcap Stream

    /// UseMethod:
    /// 1. vigilyx-sniffer --remote-listen 5000
    /// 2. Remote: tcpdump -i eth1 -U -s0 -w - | nc <local_ip> 5000
    #[arg(long, value_name = "PORT", conflicts_with_all = ["stdin", "interface", "remote_connect"])]
    remote_listen: Option<u16>,

    /// ConnectionRemoteServicehandler Get pcap Stream (Used for NAT Environment)
    ///
    /// UseMethod:
    /// 1. Remote: socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"tcpdump -i eth1 -U -s0 -w -"
    ///    2.: vigilyx-sniffer --remote-connect 203.0.113.10:5000
    #[arg(long, value_name = "HOST:PORT", conflicts_with_all = ["stdin", "interface", "remote_listen", "remote_connect_v3"])]
    remote_connect: Option<String>,

    /// ConnectionRemote v3 FileProtocolServicehandler (pcapng + Break/Judge)
    ///
    /// v3 Protocol: SUBSCRIBE/RESUME, pcapng Segment, HEARTBEAT
    #[arg(long, value_name = "HOST:PORT", conflicts_with_all = ["stdin", "interface", "remote_listen", "remote_connect"])]
    remote_connect_v3: Option<String>,

    /// NetworkInterface (overrideEnvironmentVariable)
    #[arg(short, long, value_name = "INTERFACE")]
    interface: Option<String>,

    /// BPF table (overrideDefaultofemailPort)
    #[arg(long, value_name = "FILTER")]
    bpf_filter: Option<String>,

    /// .env Filepath (sudo EnvironmentVariable, ParameterEnsureConfiguration Load)
    #[arg(long, value_name = "PATH")]
    env_file: Option<String>,
}

/// CaptureMode
#[derive(Debug, Clone)]
pub enum CaptureMode {
    /// Capture
    Local { interface: String },
    /// FromStandardInputreadGet pcap Stream
    Stdin,
    /// Listen TCP Port
    RemoteListen { port: u16 },
    /// ConnectionRemoteServicehandler (Used for NAT Environment)
    RemoteConnect { host: String, port: u16 },
    /// ConnectionRemote v3 FileProtocolServicehandler (pcapng + Break/Judge)
    RemoteConnectV3 { host: String, port: u16 },
}

#[tokio::main]
async fn main() -> Result<()> {
    // ParseCommandlineParameter
    let args = Args::parse();

    // initializelog (if not Set RUST_LOG,UseDefaultvalue)
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Defaultloglevel: info (pathlogalreadydowngradelevel trace, RUST_LOG=trace Output)
        tracing_subscriber::EnvFilter::new("info,vigilyx_sniffer=info")
    });

    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_env_filter(env_filter)
            .with_target(false)
            .with_thread_ids(true)
            .init();
    }

    info!("============================================");
    info!("  Vigilyx High-performanceStream量ListenEngine");
    info!("  Target: 1Gbps+ emailStream量Capture");
    info!("============================================");

    // Load.env File (--env-file priority, sudo EnvironmentVariableof)
    if let Some(ref env_file) = args.env_file {
        info!("From指定RoadPathLoad .env: {}", env_file);
        match dotenvy::from_filename(env_file) {
            Ok(_) => info!(".env LoadSuccess"),
            Err(e) => warn!("Load .env Failed: {} (将UseDefaultvalue)", e),
        }
    }

    // LoadConfiguration (.env Defaultvalue)
    let mut config = Config::from_env()?;
    info!("API Target: {}:{}", config.api_host, config.api_port);

    // From API/DB GetdataSecurityConfiguration (webmail_servers / http_ports)
    // DB 1 source,infiniteretry API (, 30)
    {
        let mut retry_interval = Duration::from_secs(2);
        let max_retry_interval = Duration::from_secs(30);
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            match fetch_sniffer_config_from_api(&config).await {
                Ok(Some(sniffer_cfg)) => {
                    // webmail_servers: DB value Connectoverride(DB source)
                    if let Some(servers) = sniffer_cfg
                        .get("webmail_servers")
                        .and_then(|v| v.as_array())
                    {
                        config.webmail_servers = servers
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        info!(
                            "From DB ConfigurationLoad webmail_servers: {:?}",
                            config.webmail_servers
                        );
                    }
                    // http_ports: DB override
                    if let Some(ports) = sniffer_cfg.get("http_ports").and_then(|v| v.as_array()) {
                        let hp: Vec<u16> = ports
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u16))
                            .collect();
                        if !hp.is_empty() {
                            config.http_ports = hp;
                            info!(
                                "From DB ConfigurationLoad http_ports: {:?}",
                                config.http_ports
                            );
                        }
                    }
                    break;
                }
                Ok(None) => {
                    info!("DB Medium无 sniffer Configuration，UseEnvironmentVariableDefaultvalue");
                    break;
                }
                Err(e) => {
                    warn!(
                        "拉Get sniffer ConfigurationFailed (After{}Time/Count): {}，{}seconds retry",
                        attempt,
                        e,
                        retry_interval.as_secs()
                    );
                    tokio::time::sleep(retry_interval).await;
                    retry_interval = Duration::from_secs(
                        (retry_interval.as_secs() * 2).min(max_retry_interval.as_secs()),
                    );
                }
            }
        }
    }

    // CommandlineParameteroverride.env Configuration
    if let Some(interface) = &args.interface {
        config.sniffer_interface = interface.clone();
    }

    // CaptureMode (CommandlineParameter>.env Configuration)
    let capture_mode = if args.stdin {
        // Command line specified --stdin
        CaptureMode::Stdin
    } else if let Some(port) = args.remote_listen {
        // Command line specified --remote-listen
        CaptureMode::RemoteListen { port }
    } else if let Some(ref addr) = args.remote_connect {
        // Command line specified --remote-connect
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "InvalidofRemoteAddress格式，请Use host:port 格式，例if: 203.0.113.10:5000"
            );
        }
        let port: u16 = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("InvalidofPortNumber"))?;
        let host = parts[1].to_string();
        CaptureMode::RemoteConnect { host, port }
    } else if let Some(ref addr) = args.remote_connect_v3 {
        // Command line specified --remote-connect-v3
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "InvalidofRemoteAddress格式，请Use host:port 格式，例if: 203.0.113.10:5000"
            );
        }
        let port: u16 = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("InvalidofPortNumber"))?;
        let host = parts[1].to_string();
        CaptureMode::RemoteConnectV3 { host, port }
    } else if let Some(ref interface) = args.interface {
        // Command line specified --interface
        CaptureMode::Local {
            interface: interface.clone(),
        }
    } else {
        // not CommandlineParameter,Use.env Configuration
        match config.capture_mode {
            ConfigCaptureMode::RemoteConnect => {
                if let Some((host, port)) = config.parse_remote_address() {
                    CaptureMode::RemoteConnect { host, port }
                } else {
                    anyhow::bail!(
                        "CAPTURE_MODE=remote_connect Need/RequireSet REMOTE_ADDRESS EnvironmentVariable"
                    );
                }
            }
            ConfigCaptureMode::RemoteListen => CaptureMode::RemoteListen {
                port: config.remote_listen_port,
            },
            ConfigCaptureMode::Stdin => CaptureMode::Stdin,
            ConfigCaptureMode::Local => CaptureMode::Local {
                interface: config.sniffer_interface.clone(),
            },
        }
    };

    // Configurationsource
    let mode_source = if args.stdin
        || args.remote_listen.is_some()
        || args.remote_connect.is_some()
        || args.remote_connect_v3.is_some()
        || args.interface.is_some()
    {
        "CommandlineParameter"
    } else {
        ".env ConfigurationFile"
    };
    info!("Configurationsource: {}", mode_source);

    // ConfigurationInfo
    match &capture_mode {
        CaptureMode::Local { interface } => {
            info!("CaptureMode: 本地网卡");
            info!("  - NetworkInterface: {}", interface);
            info!("  - 混杂mode: {}", config.sniffer_promiscuous);
        }
        CaptureMode::Stdin => {
            info!("CaptureMode: StandardInput (Remote pcap Stream)");
            info!("  waitWaitFrom stdin Receive pcap data...");
            info!(
                "  提示: ssh root@remote \"tcpdump -i eth1 -U -s0 -w -\" | vigilyx-sniffer --stdin"
            );
        }
        CaptureMode::RemoteListen { port } => {
            info!("CaptureMode: TCP Listen");
            info!("  - ListenPort: {}", port);
            info!("  waitWaitRemoteConnectionSend pcap data...");
            info!(
                "  提示: RemoteExecuteline tcpdump -i eth1 -U -s0 -w - | nc <local_ip> {}",
                port
            );
        }
        CaptureMode::RemoteConnect { host, port } => {
            info!("CaptureMode: 主动ConnectionRemoteServiceDevice/Handler (v2 pcap)");
            info!("  - RemoteAddress: {}:{}", host, port);
            info!("  提示: Remote先Executeline:");
            info!(
                "    socat TCP-LISTEN:{},reuseaddr,fork EXEC:\"tcpdump -i eth1 -U -s0 -w -\"",
                port
            );
        }
        CaptureMode::RemoteConnectV3 { host, port } => {
            info!("CaptureMode: 主动ConnectionRemoteServiceDevice/Handler (v3 FileProtocol)");
            info!("  - RemoteAddress: {}:{}", host, port);
            info!("  - 支持Break/Judge点续传 (SUBSCRIBE/RESUME)");
            info!("  - 支持 pcapng Add量推送");
        }
    }

    info!("emailPortConfiguration:");
    info!("  - SMTP: {:?}", config.smtp_ports);
    info!("  - POP3: {:?}", config.pop3_ports);
    info!("  - IMAP: {:?}", config.imap_ports);
    if !config.webmail_servers.is_empty() {
        info!(
            "  - HTTP: {:?} (webmail: {:?})",
            config.http_ports, config.webmail_servers
        );
    }
    info!("  - CPU 核心数: {}", num_cpus::get());

    // initializeMessageQueueclient (withTimeout)
    let mq_config = MqConfig::from_env();
    let mq = MqClient::new(mq_config);

    // Connection Redis (3 Timeout)
    info!("正在Connection Redis...");
    let mq_client = match tokio::time::timeout(Duration::from_secs(3), mq.connect()).await {
        Ok(Ok(_)) => {
            info!("Redis MessageQueueConnectionSuccess");
            Some(mq)
        }
        Ok(Err(e)) => {
            warn!("Redis ConnectionFailed: {}，将Use本地mode", e);
            None
        }
        Err(_) => {
            warn!("Redis Connection超, 将Use本地mode");
            None
        }
    };

    // write NetworkInterfaceList Redis(Forfirst Setup Wizard readGet)
    if let Some(ref mq) = mq_client
        && let Err(e) = publish_host_interfaces(mq).await
    {
        warn!("write入NetworkInterfaceListFailed: {}", e);
    }

    // Start Redis Configuration Listen (Received sniffer:cmd:reload Exit,By Docker Auto)
    if let Some(ref mq) = mq_client {
        let reload_mq = mq.clone();
        tokio::spawn(async move {
            match reload_mq
                .subscribe(&[vigilyx_db::mq::topics::SNIFFER_CMD_RELOAD])
                .await
            {
                Ok(mut pubsub) => {
                    // SEC-P06: Read shared token once for control-plane message auth
                    let cmd_token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
                    if cmd_token.is_empty() {
                        warn!(
                            "INTERNAL_API_TOKEN not set — sniffer reload commands will be rejected"
                        );
                    }
                    info!("already订阅 Sniffer Configuration重载channel");
                    use futures::StreamExt;
                    let mut stream = pubsub.on_message();
                    while let Some(msg) = stream.next().await {
                        let raw: String = match msg.get_payload() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        // SEC-P06: Verify shared token prefix before processing
                        if verify_cmd_payload(&raw, &cmd_token).is_none() {
                            warn!(
                                "Sniffer rejected reload command with invalid/missing token (SEC-P06)"
                            );
                            continue;
                        }
                        warn!(
                            "ReceivedConfiguration重载指令，Sniffer immediately将重启以应用NewConfiguration..."
                        );
                        // giving1 timestamp logOutput
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        std::process::exit(0);
                    }
                }
                Err(e) => {
                    warn!(
                        "订阅 Sniffer 重载channelFailed: {}，Configuration变更需手动重启",
                        e
                    );
                }
            }
        });
    }

    // CreateSharded session manager (Lock)
    let session_manager = ShardedSessionManager::with_timeout(Duration::from_secs(900)); // 15minuteTimeout
    if !config.webmail_servers.is_empty() {
        info!(
            "HTTP dataSecuritydetectalready启用, TargetServiceDevice/Handler: {:?}",
            config.webmail_servers
        );
    }
    // From Redis Load sid -> user Mapping (keep)
    if let Some(ref mq) = mq_client {
        match mq.sid_user_load_all().await {
            Ok(entries) => session_manager.load_sid_user_from_redis(entries),
            Err(e) => warn!("Load sid→user MappingFailed: {}", e),
        }
    }

    let session_manager = Arc::new(session_manager);
    info!("SessionManagementDevice/Handlerinitializecomplete (分片无Lockmode, 15minuteTimeout)");

    // Start sid -> user Redis handler (30 Batchwrite)
    if let Some(ref mq) = mq_client {
        let persist_manager = session_manager.clone();
        let persist_mq = mq.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let pending = persist_manager.take_sid_user_pending();
                if !pending.is_empty()
                    && let Err(e) = persist_mq.sid_user_set_batch(&pending).await
                {
                    tracing::debug!("sid→user Redis write入Failed: {}", e);
                }
            }
        });
    }

    // StartSessionCleanup
    let cleanup_manager = session_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_manager.cleanup_timeout_sessions();
        }
    });

    // initialize Status
    let sniffer_state = get_sniffer_state();
    {
        let mode_str = match &capture_mode {
            CaptureMode::Local { interface } => format!("local:{}", interface),
            CaptureMode::Stdin => "stdin".to_string(),
            CaptureMode::RemoteListen { port } => format!("remote_listen:{}", port),
            CaptureMode::RemoteConnect { host, port } => {
                format!("remote_connect:{}:{}", host, port)
            }
            CaptureMode::RemoteConnectV3 { host, port } => {
                format!("remote_connect_v3:{}:{}", host, port)
            }
        };
        *sniffer_state.capture_mode.write().await = mode_str;

        match &capture_mode {
            CaptureMode::RemoteConnect { host, port }
            | CaptureMode::RemoteConnectV3 { host, port } => {
                *sniffer_state.remote_address.write().await = Some(format!("{}:{}", host, port));
            }
            _ => {}
        }
    }

    // StartStatistics
    let stats_manager = session_manager.clone();
    let stats_mq = mq_client.clone();
    let stats_sniffer_state = sniffer_state.clone();
    let stats_api_host = config.api_host.clone();
    let stats_api_port = config.api_port;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        // HTTP fallback client (Redis Use)
        let stats_http_client = crate::internal_api_client_builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("internal stats HTTP client should build");

        let mut prev_packets: u64 = 0;
        let mut prev_bytes: u64 = 0;

        loop {
            interval.tick().await;
            let mut stats = stats_manager.get_stats();

            // : (Whenfirstvalue - Time/Countvalue) / 5
            stats.packets_per_second =
                (stats.total_packets.saturating_sub(prev_packets)) as f64 / 5.0;
            stats.bytes_per_second = (stats.total_bytes.saturating_sub(prev_bytes)) as f64 / 5.0;
            prev_packets = stats.total_packets;
            prev_bytes = stats.total_bytes;

            // SynchronousStatisticsdata Status (Used forStatus)
            stats_sniffer_state
                .packets_processed
                .store(stats.total_packets, Ordering::Relaxed);
            stats_sniffer_state
                .bytes_processed
                .store(stats.total_bytes, Ordering::Relaxed);

            info!(
                "Statistics: Session={}/{}, datapacket={}, Stream量={}MB, pps={:.0}, bps={:.0}KB/s",
                stats.active_sessions,
                stats.total_sessions,
                stats.total_packets,
                stats.total_bytes / 1024 / 1024,
                stats.packets_per_second,
                stats.bytes_per_second / 1024.0,
            );

            if let Some(ref mq) = stats_mq {
                if let Err(e) = mq.publish_stats(&stats).await {
                    error!("PublishStatisticsInfoFailed: {}", e);
                }
            } else {
                // HTTP fallback: Redis Connect API
                let url = format!(
                    "http://{}:{}/api/import/stats",
                    stats_api_host, stats_api_port
                );
                let _ = stats_http_client.post(&url).json(&stats).send().await;
            }
        }
    });

    // StartStatus (API sniffer Status)
    let state_for_report = sniffer_state.clone();
    let api_url = format!("http://{}:{}", config.api_host, config.api_port);
    info!(
        "Status报告任务: Target API = {}/api/system/sniffer",
        api_url
    );
    tokio::spawn(async move {
        // Create Use of HTTP client (Avoid sudo Environment of 502 Error)
        let client = crate::internal_api_client_builder()
            .build()
            .expect("internal status HTTP client should build");
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let mut report_count = 0u32;

        loop {
            interval.tick().await;
            let report = state_for_report.to_report().await;
            report_count += 1;

            match client
                .post(format!("{}/api/system/sniffer", api_url))
                .json(&report)
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if report_count <= 3 || report_count.is_multiple_of(20) {
                            info!(
                                "Status报告 #{}: online={}, status={}, packets={} (HTTP {})",
                                report_count,
                                report.online,
                                report.connection_status,
                                report.packets_processed,
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
    });

    // CreateHigh-performance capture engine
    let capturer = HighPerformanceCapturer::new(config, session_manager, mq_client);

    // according tomodeStartCapture
    match capture_mode {
        CaptureMode::Local { .. } => {
            capturer.start()?;
            // CaptureStartSuccess,SetStatus alreadyConnection
            sniffer_state.set_connected().await;
        }
        CaptureMode::Stdin => {
            capturer.start_from_stdin()?;
            // stdin modeStartSuccess,SetStatus alreadyConnection
            sniffer_state.set_connected().await;
        }
        CaptureMode::RemoteListen { port } => {
            capturer.start_remote_listen(port).await?;
            // ListenmodeStartSuccess,SetStatus alreadyConnection
            sniffer_state.set_connected().await;
        }
        CaptureMode::RemoteConnect { host, port } => {
            // RemoteConnectionmode ConnectionSuccess AutoSetStatus
            capturer.start_remote_connect(&host, port).await?;
        }
        CaptureMode::RemoteConnectV3 { host, port } => {
            // v3 FileProtocolmode
            capturer.start_remote_connect_v3(&host, port).await?;
        }
    }

    info!("============================================");
    info!("  CaptureDevice/HandleralreadyStart，According to Ctrl+C 停止");
    info!("============================================");

    // waitWaitExitSignal
    tokio::signal::ctrl_c().await?;

    info!("正在停止...");
    capturer.stop();

    // Statistics
    let stats = capturer.stats();
    info!("最终Statistics:");
    info!(
        "  - Receivedatapacket: {}",
        stats
            .packets_received
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - Processdatapacket: {}",
        stats
            .packets_processed
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    info!(
        "  - dropdatapacket: {}",
        stats
            .packets_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    Ok(())
}

/// From API Get Sniffer dataSecurityConfiguration (webmail_servers, http_ports)
async fn fetch_sniffer_config_from_api(config: &Config) -> Result<Option<serde_json::Value>> {
    let url = format!(
        "http://{}:{}/api/internal/sniffer-config",
        config.api_host, config.api_port
    );
    let client = crate::internal_api_client_builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: serde_json::Value = resp.json().await?;
    // API Return { "success": true, "data": {... } }
    if let Some(data) = body.get("data") {
        Ok(Some(data.clone()))
    } else {
        Ok(None)
    }
}

/// readGet `/sys/class/net/` GetNetworkInterfaceListAndStream Statistics,write Redis
async fn publish_host_interfaces(mq: &vigilyx_db::mq::MqClient) -> anyhow::Result<()> {
    use std::path::Path;

    let net_dir = Path::new("/sys/class/net");
    if !net_dir.exists() {
        anyhow::bail!("/sys/class/net 不stored在");
    }

    let mut interfaces = Vec::new();
    let entries = std::fs::read_dir(net_dir)?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // hops lo And docker/veth Interface
        if name == "lo"
            || name.starts_with("veth")
            || name.starts_with("br-")
            || name.starts_with("docker")
        {
            continue;
        }

        let base = net_dir.join(&name);
        let rx_bytes = read_sys_stat(&base.join("statistics/rx_bytes")).unwrap_or(0);
        let tx_bytes = read_sys_stat(&base.join("statistics/tx_bytes")).unwrap_or(0);
        let operstate = std::fs::read_to_string(base.join("operstate"))
            .unwrap_or_default()
            .trim()
            .to_string();

        interfaces.push(serde_json::json!({
            "name": name,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "total_bytes": rx_bytes + tx_bytes,
            "status": operstate,
        }));
    }

    // According to total_bytes downgrade
    interfaces.sort_by(|a, b| {
        let ta = a["total_bytes"].as_u64().unwrap_or(0);
        let tb = b["total_bytes"].as_u64().unwrap_or(0);
        tb.cmp(&ta)
    });

    mq.set_json(
        vigilyx_db::mq::keys::SNIFFER_INTERFACES,
        &interfaces,
        3600, // 1 small TTL
    )
    .await?;

    info!(
        "alreadywrite入 {} NetworkInterface到 Redis (Stream量最large: {})",
        interfaces.len(),
        interfaces
            .first()
            .and_then(|i| i["name"].as_str())
            .unwrap_or("无")
    );
    Ok(())
}

fn read_sys_stat(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}
