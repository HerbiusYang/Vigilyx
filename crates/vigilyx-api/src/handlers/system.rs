//! systemstatusProcess: systemstatus, Sniffer status, system

use axum::{Json, extract::State, response::IntoResponse};
use chrono::{Local, Offset};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::ApiResponse;
use crate::AppState;

/// Sniffer status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnifferStatus {
    
    pub online: bool,
   /// Connectionstatus: connected, connecting, disconnected, error
    pub connection_status: String,
   /// remoteServer address
    pub remote_address: Option<String>,
   /// Capture mode: local, stdin, remote_listen, remote_connect
    pub capture_mode: String,
   /// 1 errorinfo
    pub last_error: Option<String>,
    
    pub retry_count: u32,
   /// Newtime
    pub last_update: String,
   /// ProcessData
    pub packets_processed: u64,
   /// Process
    pub bytes_processed: u64,
}

/// MTA proxy status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MtaStatus {
    
    pub online: bool,
   /// MTA
    pub downstream_host: String,
   /// MTA
    pub downstream_port: u16,
    
    pub active_connections: u64,
   /// (ISO 8601)
    pub last_update: String,
}

/// Systemstatus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
   /// API status
    pub api_online: bool,
   /// API
    pub api_version: String,
   /// Data status
    pub database_online: bool,
   /// Data ()
    pub database_size: u64,
   /// Redis status
    pub redis_online: bool,
   /// Sniffer status
    pub sniffer: SnifferStatus,
   /// MTA proxy status
    pub mta: MtaStatus,
   /// Service time
    pub server_time: String,
   /// Service timezone name (prefer IANA, fallback to UTC offset label)
    pub server_timezone: String,
   /// Service UTC offset in minutes
    pub server_utc_offset_minutes: i32,
}

/// System
#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub memory_percent: f32,
    pub uptime_secs: u64,
    pub active_sessions: u64,
}

/// Getsystemstatus
pub async fn get_system_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
   // Data status
    let db_online = state.db.health_check().await.unwrap_or(false);
    let db_size = state.db.get_db_size().await.map(|(s, _)| s).unwrap_or(0);

   // Redis status
    let redis_online = if let Some(ref mq) = state.messaging.mq {
        mq.is_connected().await
    } else {
        false
    };

   // get sniffer status
    let sniffer = state.monitoring.sniffer_status.read().await.clone();
   // get MTA status
    let mta = state.monitoring.mta_status.read().await.clone();

    let local_now = Local::now();
    let server_utc_offset_minutes = local_now.offset().fix().local_minus_utc() / 60;
    let status = SystemStatus {
        api_online: true,
        api_version: env!("CARGO_PKG_VERSION").to_string(),
        database_online: db_online,
        database_size: db_size,
        redis_online,
        sniffer,
        mta,
        server_time: local_now.to_rfc3339(),
        server_timezone: detect_server_timezone(server_utc_offset_minutes),
        server_utc_offset_minutes,
    };

    ApiResponse::ok(status)
}

fn detect_server_timezone(server_utc_offset_minutes: i32) -> String {
    if let Ok(tz) = std::env::var("TZ") {
        let tz = tz.trim();
        if !tz.is_empty() {
            return tz.to_string();
        }
    }

    if let Ok(target) = std::fs::canonicalize("/etc/localtime") {
        let zoneinfo_root = std::path::Path::new("/usr/share/zoneinfo");
        if let Ok(relative) = target.strip_prefix(zoneinfo_root) {
            let tz = relative.to_string_lossy().trim_start_matches('/').to_string();
            if !tz.is_empty() {
                return tz;
            }
        }
    }

    if let Ok(tz) = std::fs::read_to_string("/etc/timezone") {
        let tz = tz.trim();
        if !tz.is_empty() {
            return tz.to_string();
        }
    }

    format_utc_offset(server_utc_offset_minutes)
}

fn format_utc_offset(total_minutes: i32) -> String {
    let sign = if total_minutes >= 0 { '+' } else { '-' };
    let abs_minutes = total_minutes.abs();
    let hours = abs_minutes / 60;
    let minutes = abs_minutes % 60;
    format!("UTC{}{:02}:{:02}", sign, hours, minutes)
}

/// New Sniffer status (For sniffer)
pub async fn update_sniffer_status(
    State(state): State<Arc<AppState>>,
    Json(status): Json<SnifferStatus>,
) -> impl IntoResponse {
    let mut sniffer = state.monitoring.sniffer_status.write().await;
   *sniffer = status;
    ApiResponse::ok(serde_json::json!({"status": "ok"}))
}

/// MTA status (For MTA proxy)
pub async fn update_mta_status(
    State(state): State<Arc<AppState>>,
    Json(status): Json<MtaStatus>,
) -> impl IntoResponse {
    let mut mta = state.monitoring.mta_status.write().await;
   *mta = status;
    ApiResponse::ok(serde_json::json!({"status": "ok"}))
}


/// /sys/class/net/, Sniffer Redis
pub async fn get_host_interfaces(State(state): State<Arc<AppState>>) -> impl IntoResponse {
   // /sys/class/net/ (spawn_blocking to avoid blocking the async runtime)
    if let Ok(Ok(interfaces)) = tokio::task::spawn_blocking(read_host_interfaces).await
        && !interfaces.is_empty()
    {
        return ApiResponse::ok(interfaces);
    }

   // : Redis Sniffer
    if let Some(ref mq) = state.messaging.mq {
        match mq
            .get_json::<Vec<serde_json::Value>>(vigilyx_db::mq::keys::SNIFFER_INTERFACES)
            .await
        {
            Ok(Some(interfaces)) => ApiResponse::ok(interfaces),
            Ok(None) => ApiResponse::ok(Vec::<serde_json::Value>::new()),
            Err(e) => {
                tracing::warn!("读取网络接口列表失败: {}", e);
                ApiResponse::ok(Vec::<serde_json::Value>::new())
            }
        }
    } else {
        ApiResponse::ok(Vec::<serde_json::Value>::new())
    }
}

/// /host/sys/class/net/
/// /sys/class/net, volume /host/sys/class/net
fn read_host_interfaces() -> Result<Vec<serde_json::Value>, std::io::Error> {
    use std::path::Path;

    
    let net_dir = if Path::new("/host/sys/class/net").exists() {
        Path::new("/host/sys/class/net")
    } else if Path::new("/sys/class/net").exists() {
        Path::new("/sys/class/net")
    } else {
        return Ok(Vec::new());
    };

    let mut interfaces = Vec::new();
    for entry in std::fs::read_dir(net_dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
       // , Docker
        if name == "lo"
            || name.starts_with("veth")
            || name.starts_with("br-")
            || name.starts_with("docker")
            || name.starts_with("virbr")
        {
            continue;
        }

        let base = entry.path();

        let rx_bytes: u64 = std::fs::read_to_string(base.join("statistics/rx_bytes"))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);
        let tx_bytes: u64 = std::fs::read_to_string(base.join("statistics/tx_bytes"))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);
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

    
    interfaces.sort_by(|a, b| {
        let ta = a["total_bytes"].as_u64().unwrap_or(0);
        let tb = b["total_bytes"].as_u64().unwrap_or(0);
        tb.cmp(&ta)
    });

    Ok(interfaces)
}

/// Getsystem (CPU,, Session)
pub async fn get_system_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (cpu_usage, memory_used, memory_total) = {
        let mut sys = state.monitoring.sys.lock().await;
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        let cpu =
            sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len().max(1) as f32;
        (cpu, sys.used_memory(), sys.total_memory())
    };

    let memory_percent = if memory_total > 0 {
        (memory_used as f64 / memory_total as f64 * 100.0) as f32
    } else {
        0.0
    };

   // Stream Statistics (request 4.5s COUNT tablescan)
    let active_sessions = {
        let cache = state.cache.traffic_stats.read().await;
        cache.as_ref().map(|(_, s)| s.active_sessions).unwrap_or(0)
    };

    ApiResponse::ok(SystemMetrics {
        cpu_usage,
        memory_used,
        memory_total,
        memory_percent,
        uptime_secs: sysinfo::System::uptime(),
        active_sessions,
    })
}
