//! Message Queue Module
//!
//! Provides message communication capabilities between components, supporting:
//! - Redis Streams with consumer groups for data plane (at-least-once delivery)
//! - Redis Pub/Sub for control plane signals (fire-and-forget, acceptable for commands)
//! - Local in-memory channel (single-process mode)
//!
//!   Architecture:
//! - Redis Streams for session delivery (Sniffer -> Engine) with ack + DLQ
//! - Redis Pub/Sub for notifications (Engine -> API -> Browser) and commands
//! - PostgreSQL as the sole persistent storage (handled at API layer)

mod channels;
mod client;
mod error;
pub mod reload_protocol;
mod stream;

pub use channels::*;
pub use client::{MqClient, MqConfig, verify_cmd_payload};
pub use error::{MqError, MqResult};
pub use stream::{PendingSummary, StreamClient};

/// Message queue topic names (Pub/Sub channels)
pub mod topics {
    /// Statistics update notification (Pub/Sub: Sniffer → API)
    pub const STATS_UPDATE: &str = "vigilyx:stats:update";
    /// AI analysis request
    pub const AI_ANALYZE_REQUEST: &str = "vigilyx:ai:request";
    /// AI analysis result
    pub const AI_ANALYZE_RESULT: &str = "vigilyx:ai:result";

    // Engine API Communication
    /// Security engine verdict result (Engine -> API)
    pub const ENGINE_VERDICT: &str = "vigilyx:engine:verdict";
    /// Security alert (Engine -> API)
    pub const ENGINE_ALERT: &str = "vigilyx:engine:alert";
    /// Data security incident (Engine -> API)
    pub const ENGINE_DS_INCIDENT: &str = "vigilyx:engine:ds_incident";
    /// Engine runtime status (Engine -> API)
    pub const ENGINE_STATUS: &str = "vigilyx:engine:status";
    /// Rescan command (API -> Engine)
    pub const ENGINE_CMD_RESCAN: &str = "vigilyx:engine:cmd:rescan";
    /// Cache refresh command (API -> Engine)
    pub const ENGINE_CMD_RELOAD: &str = "vigilyx:engine:cmd:reload";
    /// Sniffer config reload command (API -> Sniffer)
    pub const SNIFFER_CMD_RELOAD: &str = "vigilyx:sniffer:cmd:reload";
}

/// Redis key names
pub mod keys {
    /// Network interface list (written by Sniffer, read by API)
    pub const SNIFFER_INTERFACES: &str = "vigilyx:sniffer:interfaces";

    // ── Service heartbeats (key with TTL, dead-man switch) ──
    /// Engine heartbeat (30s TTL, written every 5-10s)
    pub const ENGINE_HEARTBEAT: &str = "vigilyx:engine:heartbeat";
    /// Sniffer heartbeat
    pub const SNIFFER_HEARTBEAT: &str = "vigilyx:sniffer:heartbeat";
    /// MTA heartbeat
    pub const MTA_HEARTBEAT: &str = "vigilyx:mta:heartbeat";
}

/// Redis Stream names (data plane, at-least-once delivery)
pub mod streams {
    /// Email sessions stream (Sniffer -> Engine)
    pub const EMAIL_SESSIONS: &str = "vigilyx:stream:sessions";
    /// HTTP sessions stream (Sniffer -> Engine, data security)
    pub const HTTP_SESSIONS: &str = "vigilyx:stream:http_sessions";
    /// AI tasks stream
    pub const AI_TASKS: &str = "vigilyx:stream:ai_tasks";

    // ── Dead-letter queues ──
    /// Email sessions DLQ (messages that failed processing after N attempts)
    pub const EMAIL_SESSIONS_DLQ: &str = "vigilyx:stream:sessions:dlq";
    /// HTTP sessions DLQ
    pub const HTTP_SESSIONS_DLQ: &str = "vigilyx:stream:http_sessions:dlq";
}

/// Consumer group names
pub mod consumer_groups {
    /// Engine consumer group
    pub const ENGINE: &str = "vigilyx-engine";
}
