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
pub use client::{DataPayloadAuth, MqClient, MqConfig, verify_cmd_payload, verify_data_payload};
pub use error::{MqError, MqResult};
pub use stream::{PendingSummary, PoisonedStreamMessage, StreamClient, StreamRead};

/// Bounded persistent reference used by bulk historical rescans.
///
/// The complete email remains in PostgreSQL. Keeping only its canonical UUID
/// in Valkey prevents attachment/body duplication from exhausting the message
/// bus while retaining Stream retry and dead-letter semantics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RescanSessionReference {
    pub session_id: uuid::Uuid,
    /// When set, the rescan must load the stored raw_eml from this quarantine
    /// entry and re-parse it, instead of trusting the persisted session row.
    /// Release-time rescans must analyze the exact bytes that would be relayed:
    /// the persisted session went through parser degradation paths (attachment
    /// caps, size truncation) that can hide a payload the raw message carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_id: Option<String>,
    /// Submitting client IP captured at quarantine time (A5). The pre-release
    /// rescan rebuilds a synthetic session; without the real client IP every
    /// IP-reputation / behavior-baseline signal is lost and an inline High
    /// verdict can degrade below the release-gate threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
}

impl RescanSessionReference {
    pub fn new(session_id: uuid::Uuid) -> Self {
        Self {
            session_id,
            quarantine_id: None,
            client_ip: None,
        }
    }

    /// Reference a quarantine-backed rescan (pre-release gate).
    pub fn for_quarantine(
        session_id: uuid::Uuid,
        quarantine_id: String,
        client_ip: Option<String>,
    ) -> Self {
        Self {
            session_id,
            quarantine_id: Some(quarantine_id),
            client_ip,
        }
    }
}

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
    /// Historical rescan session references (API -> Engine)
    pub const RESCAN_REQUESTS: &str = "vigilyx:stream:rescan_requests";

    // ── Dead-letter queues ──
    /// Email sessions DLQ (messages that failed processing after N attempts)
    pub const EMAIL_SESSIONS_DLQ: &str = "vigilyx:stream:sessions:dlq";
    /// HTTP sessions DLQ
    pub const HTTP_SESSIONS_DLQ: &str = "vigilyx:stream:http_sessions:dlq";
    /// Malformed historical rescan references
    pub const RESCAN_REQUESTS_DLQ: &str = "vigilyx:stream:rescan_requests:dlq";
}

/// Consumer group names
pub mod consumer_groups {
    /// Engine consumer group
    pub const ENGINE: &str = "vigilyx-engine";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescan_reference_serialization_is_bounded_and_round_trips() {
        let reference = RescanSessionReference::new(uuid::Uuid::new_v4());
        let encoded = serde_json::to_vec(&reference).unwrap();
        assert!(encoded.len() < 80, "reference unexpectedly large");
        let decoded: RescanSessionReference = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, reference);
        assert_eq!(decoded.quarantine_id, None);
    }

    #[test]
    fn rescan_reference_legacy_payload_without_optional_fields_still_parses() {
        // Messages enqueued before the quarantine_id / client_ip fields existed
        // (or by the generic admin rescan API) must keep deserializing after
        // the upgrade.
        let session_id = uuid::Uuid::new_v4();
        let legacy = format!("{{\"session_id\":\"{session_id}\"}}");
        let decoded: RescanSessionReference = serde_json::from_str(&legacy).unwrap();
        assert_eq!(decoded.session_id, session_id);
        assert_eq!(decoded.quarantine_id, None);
        assert_eq!(decoded.client_ip, None);
    }

    #[test]
    fn quarantine_rescan_reference_round_trips() {
        // A5: the real submitting client IP must survive the bus so the
        // pre-release rescan keeps IP-reputation signals.
        let reference = RescanSessionReference::for_quarantine(
            uuid::Uuid::new_v4(),
            "quar-123".to_string(),
            Some("198.51.100.23".to_string()),
        );
        let encoded = serde_json::to_vec(&reference).unwrap();
        let decoded: RescanSessionReference = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, reference);
        assert_eq!(decoded.quarantine_id.as_deref(), Some("quar-123"));
        assert_eq!(decoded.client_ip.as_deref(), Some("198.51.100.23"));
    }

    #[test]
    fn quarantine_rescan_reference_without_client_ip_still_parses() {
        // Rolling-upgrade window: references enqueued by an older API carry
        // no client_ip and must still deserialize.
        let session_id = uuid::Uuid::new_v4();
        let legacy = format!(
            "{{\"session_id\":\"{session_id}\",\"quarantine_id\":\"quar-9\"}}"
        );
        let decoded: RescanSessionReference = serde_json::from_str(&legacy).unwrap();
        assert_eq!(decoded.quarantine_id.as_deref(), Some("quar-9"));
        assert_eq!(decoded.client_ip, None);
    }
}
