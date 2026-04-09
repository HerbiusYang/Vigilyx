//! Reload ACK protocol for config apply verification.
//!
//! Replaces the fire-and-forget reload pattern with a request-response protocol:
//!
//! 1. **API** generates a unique `reload_id`, publishes a reload command with
//!    `{ target, reload_id, config_version }` to the Pub/Sub topic.
//! 2. **Engine/Sniffer** receives the command, performs the reload, then writes
//!    an ACK to a Redis key `{ack_prefix}:{reload_id}` with 60s TTL.
//! 3. **API** polls the ACK key (50ms interval, configurable timeout) and
//!    returns the result to the frontend.

use super::client::MqClient;
use super::error::MqResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

/// Command sent from API to Engine/Sniffer via Pub/Sub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadCommand {
    /// What to reload (e.g., "config", "whitelist", "ioc", "keywords")
    pub target: String,
    /// Unique request ID (UUID) for correlating the ACK
    pub reload_id: String,
    /// Config version after the DB write (consumer validates it matches)
    pub config_version: i64,
}

/// ACK written by Engine/Sniffer to Redis after processing the reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadAck {
    /// Whether the reload succeeded
    pub success: bool,
    /// The config version that was loaded
    pub config_version: i64,
    /// Error message if `success` is false
    pub error: Option<String>,
}

/// Result of a reload request from the API's perspective.
#[derive(Debug, Clone, Serialize)]
pub enum ReloadResult {
    /// Reload was applied successfully by the consumer.
    Applied { config_version: i64 },
    /// Reload timed out — consumer may be down or slow.
    TimedOut,
    /// Reload failed with an error from the consumer.
    Failed { error: String },
    /// Could not publish the reload command (Redis down).
    PublishFailed { error: String },
}

impl ReloadResult {
    /// Status string for API responses.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::TimedOut => "timed_out",
            Self::Failed { .. } => "failed",
            Self::PublishFailed { .. } => "publish_failed",
        }
    }

    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// ACK key prefix for engine reload.
pub const ENGINE_RELOAD_ACK_PREFIX: &str = "vigilyx:engine:reload:ack";
/// ACK key prefix for sniffer reload.
pub const SNIFFER_RELOAD_ACK_PREFIX: &str = "vigilyx:sniffer:reload:ack";

/// API side: publish a reload command and poll for the ACK.
///
/// Returns `ReloadResult::Applied` if the consumer acknowledged within `timeout`,
/// `ReloadResult::TimedOut` if the timeout expired.
pub async fn request_reload(
    mq: &MqClient,
    topic: &str,
    cmd: ReloadCommand,
    ack_prefix: &str,
    timeout: Duration,
) -> ReloadResult {
    let ack_key = format!("{}:{}", ack_prefix, cmd.reload_id);

    // Publish the reload command via Pub/Sub
    if let Err(e) = mq.publish(topic, &cmd).await {
        return ReloadResult::PublishFailed {
            error: e.to_string(),
        };
    }

    // Poll for ACK (50ms intervals)
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if start.elapsed() >= timeout {
            return ReloadResult::TimedOut;
        }

        match mq.get_json::<ReloadAck>(&ack_key).await {
            Ok(Some(ack)) => {
                debug!(reload_id = %cmd.reload_id, "Reload ACK received");
                if ack.success {
                    return ReloadResult::Applied {
                        config_version: ack.config_version,
                    };
                } else {
                    return ReloadResult::Failed {
                        error: ack.error.unwrap_or_else(|| "Unknown error".to_string()),
                    };
                }
            }
            Ok(None) => {
                // Not yet — keep polling
                tokio::time::sleep(poll_interval).await;
            }
            Err(e) => {
                warn!(reload_id = %cmd.reload_id, "Error polling reload ACK: {}", e);
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

/// Consumer side: write an ACK to Redis after processing the reload.
///
/// The ACK key has a 60-second TTL for automatic cleanup.
pub async fn send_reload_ack(
    mq: &MqClient,
    ack_prefix: &str,
    reload_id: &str,
    ack: ReloadAck,
) -> MqResult<()> {
    let key = format!("{}:{}", ack_prefix, reload_id);
    mq.set_json(&key, &ack, 60).await?;
    debug!(reload_id, success = ack.success, "Reload ACK sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reload_command_serialization() {
        let cmd = ReloadCommand {
            target: "config".to_string(),
            reload_id: "abc-123".to_string(),
            config_version: 42,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("abc-123"));
        assert!(json.contains("42"));

        let parsed: ReloadCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target, "config");
        assert_eq!(parsed.config_version, 42);
    }

    #[test]
    fn test_reload_ack_serialization() {
        let ack = ReloadAck {
            success: true,
            config_version: 42,
            error: None,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let parsed: ReloadAck = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.config_version, 42);
        assert!(parsed.error.is_none());
    }

    #[test]
    fn test_reload_result_status() {
        assert_eq!(
            ReloadResult::Applied { config_version: 1 }.status(),
            "applied"
        );
        assert_eq!(ReloadResult::TimedOut.status(), "timed_out");
        assert_eq!(
            ReloadResult::Failed {
                error: "x".to_string()
            }
            .status(),
            "failed"
        );
        assert_eq!(
            ReloadResult::PublishFailed {
                error: "x".to_string()
            }
            .status(),
            "publish_failed"
        );
    }
}
