//! Application shared state.
//!
//! `AppState` is shared across all axum routes, organized into:
//! - `MessagingState` — WebSocket broadcast + Redis MQ
//! - `ManagerState` — IOC / Whitelist / Disposition engine
//! - `MonitoringState` — Sniffer, Engine, and system metrics
//! - `CacheState` — Cached statistics (login stats, traffic stats)

use std::time::Instant;
use std::sync::atomic::AtomicU64;
use tokio::sync::{broadcast, Mutex, RwLock};
use vigilyx_core::{Config, ExternalLoginStats, TrafficStats, WsMessage};
use vigilyx_db::mq::MqClient;
use vigilyx_db::VigilDb;

use vigilyx_engine::ioc::IocManager;
use vigilyx_engine::whitelist::WhitelistManager;
use vigilyx_soar::disposition::DispositionEngine;

use crate::auth::{AuthState, WsTicketStore};
use crate::db::Database;
use crate::handlers::{MtaStatus, SnifferStatus};

/// Application state
pub struct AppState {
    // Core
    pub db: Database,
    /// SecurityEngine DB (verdict/IOC/whitelist/config CRUD)
    pub engine_db: VigilDb,
    pub config: Config,
    pub auth: AuthState,

    // Sub-structures
    /// Messaging: WebSocket + Redis MQ
    pub messaging: MessagingState,
    /// Security managers: IOC / Whitelist / Disposition engine
    pub managers: ManagerState,
    /// Monitoring: Sniffer / Engine / system metrics
    pub monitoring: MonitoringState,
    /// Cached statistics: login stats + traffic stats
    pub cache: CacheState,

    // Standalone
    /// SEC-H02: One-time WebSocket ticket store (avoids JWT in URL)
    pub ws_tickets: WsTicketStore,
    /// Shared HTTP client (for AI service and connection testing)
    pub http_client: reqwest::Client,
    /// Whether cookies should carry the Secure flag (HTTPS = true, dev HTTP = false).
    pub secure_cookie: bool,
    /// Global WebSocket auth epoch; increment to force authenticated sockets to reconnect.
    pub ws_auth_epoch: AtomicU64,
}

/// Messaging state
pub struct MessagingState {
    /// WebSocket broadcast sender
    pub ws_tx: broadcast::Sender<WsMessage>,
    /// Redis message client (None = not connected)
    pub mq: Option<MqClient>,
}

/// Security manager state
pub struct ManagerState {
    /// IOC manager (API CRUD)
    pub ioc_manager: IocManager,
    /// Whitelist manager (API CRUD)
    pub whitelist_manager: WhitelistManager,
    /// Disposition engine (alerting)
    pub disposition_engine: DispositionEngine,
}

/// Monitoring state
pub struct MonitoringState {
    /// Sniffer status
    pub sniffer_status: RwLock<SnifferStatus>,
    /// MTA proxy status
    pub mta_status: RwLock<MtaStatus>,
    /// Engine status (published via Redis Pub/Sub)
    pub engine_status: RwLock<Option<serde_json::Value>>,
    /// System info (CPU / memory)
    pub sys: Mutex<sysinfo::System>,
    /// Sniffer throughput (pps, Bps) — merged via get_stats()
    pub latest_pps: std::sync::atomic::AtomicU64,
    pub latest_bps: std::sync::atomic::AtomicU64,
}

/// Cached statistics
pub struct CacheState {
    /// Login statistics (cached, refreshed every 29s)
    pub login_stats: RwLock<Option<(Instant, ExternalLoginStats)>>,
    /// Traffic statistics (cached, refreshed every 4.5s via COUNT scan)
    pub traffic_stats: RwLock<Option<(Instant, TrafficStats)>>,
}
