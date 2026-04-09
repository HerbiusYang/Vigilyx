//! status

//! `AppState` axum Road Shared status,According to:
//! - `MessagingState` - WebSocket, Redis MQ, UDS channel
//! - `ManagerState` - IOC / / Engine Security
//! - `MonitoringState` - Sniffer status, Engine status, systeminfo
//! - `CacheState` - table (loginStatistics, Stream Statistics)

use std::time::Instant;
use tokio::sync::{Mutex, RwLock, broadcast};
use vigilyx_core::{Config, ExternalLoginStats, TrafficStats, WsMessage};
use vigilyx_db::VigilDb;
use vigilyx_db::mq::MqClient;
#[cfg(unix)]
use vigilyx_db::mq::UdsMessage;

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
   /// messagechannel: WebSocket + Redis MQ + UDS
    pub messaging: MessagingState,
   /// Security: IOC / / Engine
    pub managers: ManagerState,
   /// Monitoring state: Sniffer / Engine / system
    pub monitoring: MonitoringState,
   /// table: loginStatistics + Stream Statistics
    pub cache: CacheState,

   // Standalone
   /// SEC-H02: WebSocket 1 (JWT found URL)
    pub ws_tickets: WsTicketStore,
   /// Shared HTTP client (Used for request Python AI Service, requestCreateConnection)
    pub http_client: reqwest::Client,
   /// Whether cookies should carry the Secure flag (HTTPS = true, dev HTTP = false).
    pub secure_cookie: bool,
}

/// messagechannelstatus
pub struct MessagingState {
   /// WebSocket send
    pub ws_tx: broadcast::Sender<WsMessage>,
   /// Redis message client (None = localMode)
    pub mq: Option<MqClient>,
   /// UDS send (Redis Engine Session/)
    #[cfg(unix)]
    pub uds_tx: Option<tokio::sync::mpsc::Sender<UdsMessage>>,
}

/// Security status
pub struct ManagerState {
   /// IOC (API CRUD)
    pub ioc_manager: IocManager,
   /// Whitelist (API CRUD)
    pub whitelist_manager: WhitelistManager,
   /// DispositionEngine (Alert)
    pub disposition_engine: DispositionEngine,
}

/// Monitoring state
pub struct MonitoringState {
   /// Sniffer status
    pub sniffer_status: RwLock<SnifferStatus>,
   /// MTA proxy status
    pub mta_status: RwLock<MtaStatus>,
   /// Engine status (Engine process Redis/UDS,)
    pub engine_status: RwLock<Option<serde_json::Value>>,
   /// Systeminfo (CPU /)
    pub sys: Mutex<sysinfo::System>,
   /// Sniffer (pps, Bps) - get_stats() Merge
    pub latest_pps: std::sync::atomic::AtomicU64,
    pub latest_bps: std::sync::atomic::AtomicU64,
}

/// table status
pub struct CacheState {
   /// loginStatistics (New, request 29s Query)
    pub login_stats: RwLock<Option<(Instant, ExternalLoginStats)>>,
   /// Stream Statistics (New, request 4.5s COUNT tablescan)
    pub traffic_stats: RwLock<Option<(Instant, TrafficStats)>>,
}
