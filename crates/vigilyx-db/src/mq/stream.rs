//! Redis Streams consumer group client for at-least-once delivery.
//!
//! Wraps [`MqClient`] with consumer group semantics:
//! - [`StreamClient::ensure_group`] — idempotent group creation
//! - [`StreamClient::xadd_batch`] — pipelined XADD for producers
//! - [`StreamClient::xreadgroup`] — blocking read with consumer identity
//! - [`StreamClient::xack`] — acknowledge processed messages
//! - [`StreamClient::xautoclaim`] — reclaim abandoned messages from crashed consumers
//! - [`StreamClient::xadd_dlq`] — write failed messages to dead-letter stream

use super::client::MqClient;
use super::error::{MqError, MqResult};
use redis::aio::MultiplexedConnection;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// High-level Redis Streams client with consumer group support.
///
/// Provides at-least-once delivery semantics on top of [`MqClient`].
/// Each instance is bound to a specific consumer group and consumer identity.
#[derive(Clone)]
pub struct StreamClient {
    mq: MqClient,
    group: String,
    consumer: String,
    read_conn: Arc<Mutex<Option<MultiplexedConnection>>>,
}

impl StreamClient {
    /// Create a new `StreamClient` bound to a consumer group.
    ///
    /// `consumer` should be unique per process (e.g., `"engine-<pid>"`).
    pub fn new(mq: MqClient, group: impl Into<String>, consumer: impl Into<String>) -> Self {
        Self {
            mq,
            group: group.into(),
            consumer: consumer.into(),
            read_conn: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a consumer with auto-generated name based on PID.
    pub fn with_auto_consumer(mq: MqClient, group: impl Into<String>) -> Self {
        let group = group.into();
        let consumer = format!("{}-{}", &group, std::process::id());
        Self {
            mq,
            group,
            consumer,
            read_conn: Arc::new(Mutex::new(None)),
        }
    }

    // ── Producer methods ──

    /// Batch XADD using Redis Pipeline.
    ///
    /// Returns the number of messages successfully added.
    /// Uses `MAXLEN ~` for approximate trimming (efficient).
    pub async fn xadd_batch<T: Serialize>(
        &self,
        stream: &str,
        messages: &[T],
    ) -> MqResult<usize> {
        if messages.is_empty() {
            return Ok(0);
        }

        let max_len = self.mq.config.stream_max_len;
        let mut conn = self.mq.get_conn().await?;
        let batch_size = self.mq.config.batch_size;

        let mut total = 0;
        for chunk in messages.chunks(batch_size) {
            let mut pipe = redis::pipe();
            for msg in chunk {
                let json = serde_json::to_string(msg)?;
                pipe.cmd("XADD")
                    .arg(stream)
                    .arg("MAXLEN")
                    .arg("~")
                    .arg(max_len)
                    .arg("*")
                    .arg("data")
                    .arg(json)
                    .ignore();
            }
            pipe.query_async::<()>(&mut conn).await?;
            total += chunk.len();
        }

        debug!(stream, count = total, "Batch XADD complete");
        Ok(total)
    }

    /// Single XADD (convenience wrapper over [`MqClient::xadd`]).
    pub async fn xadd_one<T: Serialize>(
        &self,
        stream: &str,
        message: &T,
    ) -> MqResult<String> {
        self.mq.xadd(stream, message).await
    }

    // ── Consumer group methods ──

    /// Idempotent consumer group creation.
    ///
    /// Creates the group starting from ID `"0"` (all existing messages).
    /// `MKSTREAM` creates the stream if it doesn't exist.
    /// Silently handles `BUSYGROUP` (group already exists).
    pub async fn ensure_group(&self, stream: &str) -> MqResult<()> {
        let mut conn = self.mq.get_conn().await?;
        let result: Result<String, redis::RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(stream)
            .arg(&self.group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => {
                info!(stream, group = %self.group, "Consumer group created");
                Ok(())
            }
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                debug!(stream, group = %self.group, "Consumer group already exists");
                Ok(())
            }
            Err(e) => Err(MqError::Redis(e)),
        }
    }

    /// Read new messages from a stream using consumer group.
    ///
    /// When `block_ms` is `Some`, blocks for that many milliseconds.
    /// When `block_ms` is `None`, the read is non-blocking.
    /// Returns `(message_id, deserialized_data)` pairs.
    /// The `>` special ID means "only new, undelivered messages".
    pub async fn xreadgroup<T: DeserializeOwned>(
        &self,
        stream: &str,
        count: usize,
        block_ms: Option<usize>,
    ) -> MqResult<Vec<(String, T)>> {
        // Blocking stream reads must not share the general-purpose Redis connection
        // manager used by publish/XADD traffic, or stream consumption can starve
        // producers and trigger timeout/reconnect loops under load.
        let mut guard = self.read_conn.lock().await;
        if guard.is_none() {
            let conn = self.mq.new_stream_read_connection().await?;
            debug!(stream, "Created dedicated Redis stream read connection");
            *guard = Some(conn);
        }
        let conn = guard
            .as_mut()
            .expect("stream read connection must exist after initialization");

        let mut cmd = redis::cmd("XREADGROUP");
        cmd.arg("GROUP")
            .arg(&self.group)
            .arg(&self.consumer)
            .arg("COUNT")
            .arg(count);
        let read_timeout = block_ms
            .map(|ms| Duration::from_millis(ms as u64).saturating_add(Duration::from_secs(2)))
            .unwrap_or_else(|| Duration::from_secs(2));
        if let Some(block_ms) = block_ms {
            cmd.arg("BLOCK").arg(block_ms);
        }
        let result = tokio::time::timeout(
            read_timeout,
            cmd.arg("STREAMS").arg(stream).arg(">").query_async(conn),
        )
        .await;

        let result = match result {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                warn!(stream, error = %err, "Dedicated Redis stream read connection failed; resetting it");
                *guard = None;
                return Err(MqError::Redis(err));
            }
            Err(_) => {
                warn!(
                    stream,
                    timeout_ms = read_timeout.as_millis(),
                    "Dedicated Redis stream read timed out; resetting connection"
                );
                *guard = None;
                return Err(MqError::Timeout);
            }
        };

        // XREADGROUP returns same format as XREAD:
        // [[stream_name, [[id, [field, value, ...]], ...]]]
        let messages = parse_xread_response::<T>(result)?;
        if !messages.is_empty() {
            debug!(stream, count = messages.len(), "XREADGROUP received");
        }
        Ok(messages)
    }

    /// Acknowledge successfully processed messages.
    ///
    /// Removes them from the Pending Entries List (PEL).
    pub async fn xack(&self, stream: &str, ids: &[&str]) -> MqResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }

        let mut conn = self.mq.get_conn().await?;
        let mut cmd = redis::cmd("XACK");
        cmd.arg(stream).arg(&self.group);
        for id in ids {
            cmd.arg(*id);
        }

        let acked: u64 = cmd.query_async(&mut conn).await?;
        debug!(stream, acked, "XACK complete");
        Ok(acked)
    }

    /// Reclaim messages idle for longer than `min_idle_ms` from crashed consumers.
    ///
    /// Messages are transferred to this consumer for reprocessing.
    /// Returns `(message_id, deserialized_data)` pairs.
    pub async fn xautoclaim<T: DeserializeOwned>(
        &self,
        stream: &str,
        min_idle_ms: u64,
        count: usize,
    ) -> MqResult<Vec<(String, T)>> {
        let mut conn = self.mq.get_conn().await?;

        let result: redis::Value = redis::cmd("XAUTOCLAIM")
            .arg(stream)
            .arg(&self.group)
            .arg(&self.consumer)
            .arg(min_idle_ms)
            .arg("0-0")
            .arg("COUNT")
            .arg(count)
            .query_async(&mut conn)
            .await?;

        // Response: [next_start_id, [[id, [field, value, ...]], ...], [deleted_ids...]]
        let messages = parse_xautoclaim_response::<T>(result)?;
        if !messages.is_empty() {
            info!(stream, count = messages.len(), "XAUTOCLAIM reclaimed messages");
        }
        Ok(messages)
    }

    // ── Dead-letter queue ──

    /// Write a failed message to the dead-letter stream.
    pub async fn xadd_dlq<T: Serialize>(
        &self,
        dlq_stream: &str,
        original_id: &str,
        data: &T,
        error: &str,
    ) -> MqResult<String> {
        let mut conn = self.mq.get_conn().await?;
        let json = serde_json::to_string(data)?;
        let max_len = self.mq.config.stream_max_len;

        let id: String = redis::cmd("XADD")
            .arg(dlq_stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .arg("*")
            .arg("data")
            .arg(&json)
            .arg("original_id")
            .arg(original_id)
            .arg("error")
            .arg(error)
            .arg("consumer")
            .arg(&self.consumer)
            .query_async(&mut conn)
            .await?;

        warn!(dlq_stream, original_id, error, "Message moved to DLQ");
        Ok(id)
    }

    // ── Observability ──

    /// Get stream length.
    pub async fn xlen(&self, stream: &str) -> MqResult<u64> {
        let mut conn = self.mq.get_conn().await?;
        let len: u64 = redis::cmd("XLEN")
            .arg(stream)
            .query_async(&mut conn)
            .await?;
        Ok(len)
    }

    /// Get pending entries summary for this consumer group.
    pub async fn xpending_summary(&self, stream: &str) -> MqResult<PendingSummary> {
        let mut conn = self.mq.get_conn().await?;
        let result: redis::Value = redis::cmd("XPENDING")
            .arg(stream)
            .arg(&self.group)
            .query_async(&mut conn)
            .await?;

        parse_xpending_summary(result)
    }

    /// Access the underlying [`MqClient`] (for Pub/Sub and key operations).
    pub fn mq(&self) -> &MqClient {
        &self.mq
    }

    /// Get the consumer group name.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Get the consumer name.
    pub fn consumer_name(&self) -> &str {
        &self.consumer
    }
}

// ── Response parsers ──

/// Parse XREAD / XREADGROUP response.
///
/// Format: `[[stream_name, [[id, [field, value, ...]], ...]]]`
fn parse_xread_response<T: DeserializeOwned>(
    value: redis::Value,
) -> MqResult<Vec<(String, T)>> {
    let mut messages = Vec::new();

    if let redis::Value::Array(streams) = value {
        for stream in streams {
            if let redis::Value::Array(stream_data) = stream
                && stream_data.len() >= 2
                && let redis::Value::Array(entries) = &stream_data[1]
            {
                for entry in entries {
                    if let Some(parsed) = parse_stream_entry::<T>(entry) {
                        messages.push(parsed);
                    }
                }
            }
        }
    }

    Ok(messages)
}

/// Parse XAUTOCLAIM response.
///
/// Format: `[next_start_id, [[id, [field, value, ...]], ...], [deleted_ids...]]`
fn parse_xautoclaim_response<T: DeserializeOwned>(
    value: redis::Value,
) -> MqResult<Vec<(String, T)>> {
    let mut messages = Vec::new();

    if let redis::Value::Array(parts) = value
        && parts.len() >= 2
        && let redis::Value::Array(entries) = &parts[1]
    {
        for entry in entries {
            if let Some(parsed) = parse_stream_entry::<T>(entry) {
                messages.push(parsed);
            }
        }
    }

    Ok(messages)
}

/// Parse a single stream entry: `[id, [field, value, field, value, ...]]`.
///
/// Looks for the `"data"` field and deserializes its value as JSON.
fn parse_stream_entry<T: DeserializeOwned>(
    entry: &redis::Value,
) -> Option<(String, T)> {
    let redis::Value::Array(entry_data) = entry else {
        return None;
    };
    if entry_data.len() < 2 {
        return None;
    }

    // Extract message ID
    let id = match &entry_data[0] {
        redis::Value::BulkString(b) => String::from_utf8_lossy(b).to_string(),
        _ => return None,
    };

    // Extract "data" field from field-value pairs
    let redis::Value::Array(fields) = &entry_data[1] else {
        return None;
    };

    let mut i = 0;
    while i + 1 < fields.len() {
        if let redis::Value::BulkString(key) = &fields[i]
            && key == b"data"
            && let redis::Value::BulkString(val) = &fields[i + 1]
        {
            let json = String::from_utf8_lossy(val);
            if let Ok(msg) = serde_json::from_str(&json) {
                return Some((id, msg));
            }
            return None;
        }
        i += 2;
    }

    None
}

/// Parse XPENDING summary response.
///
/// Format: `[total, min_id, max_id, [[consumer, count], ...]]`
fn parse_xpending_summary(value: redis::Value) -> MqResult<PendingSummary> {
    if let redis::Value::Array(parts) = value
        && parts.len() >= 4
    {
        let total = match &parts[0] {
            redis::Value::Int(n) => *n as u64,
            _ => 0,
        };
        let min_id = match &parts[1] {
            redis::Value::BulkString(b) => Some(String::from_utf8_lossy(b).to_string()),
            _ => None,
        };
        let max_id = match &parts[2] {
            redis::Value::BulkString(b) => Some(String::from_utf8_lossy(b).to_string()),
            _ => None,
        };

        Ok(PendingSummary {
            total,
            min_id,
            max_id,
        })
    } else {
        Ok(PendingSummary::default())
    }
}

/// Summary of pending entries in a consumer group.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PendingSummary {
    /// Total number of pending (unacknowledged) messages.
    pub total: u64,
    /// Smallest pending message ID.
    pub min_id: Option<String>,
    /// Largest pending message ID.
    pub max_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stream_entry_valid() {
        // Simulate [id, [field, value]] as redis::Value
        let entry = redis::Value::Array(vec![
            redis::Value::BulkString(b"1234-0".to_vec()),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"data".to_vec()),
                redis::Value::BulkString(b"\"hello\"".to_vec()),
            ]),
        ]);

        let result: Option<(String, String)> = parse_stream_entry(&entry);
        assert!(result.is_some());
        let (id, msg) = result.unwrap();
        assert_eq!(id, "1234-0");
        assert_eq!(msg, "hello");
    }

    #[test]
    fn test_parse_stream_entry_missing_data_field() {
        let entry = redis::Value::Array(vec![
            redis::Value::BulkString(b"1234-0".to_vec()),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"other".to_vec()),
                redis::Value::BulkString(b"\"hello\"".to_vec()),
            ]),
        ]);

        let result: Option<(String, String)> = parse_stream_entry(&entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_stream_entry_empty() {
        let entry = redis::Value::Array(vec![]);
        let result: Option<(String, String)> = parse_stream_entry(&entry);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_xread_response_nil() {
        // When XREAD times out, it returns Nil
        let result: MqResult<Vec<(String, String)>> =
            parse_xread_response(redis::Value::Nil);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_xautoclaim_response_empty() {
        let value = redis::Value::Array(vec![
            redis::Value::BulkString(b"0-0".to_vec()),
            redis::Value::Array(vec![]),
            redis::Value::Array(vec![]),
        ]);
        let result: MqResult<Vec<(String, String)>> = parse_xautoclaim_response(value);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_xpending_summary_empty() {
        let result = parse_xpending_summary(redis::Value::Nil);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().total, 0);
    }

    #[test]
    fn test_parse_xpending_summary_valid() {
        let value = redis::Value::Array(vec![
            redis::Value::Int(5),
            redis::Value::BulkString(b"1-0".to_vec()),
            redis::Value::BulkString(b"5-0".to_vec()),
            redis::Value::Array(vec![]),
        ]);
        let result = parse_xpending_summary(value).unwrap();
        assert_eq!(result.total, 5);
        assert_eq!(result.min_id.as_deref(), Some("1-0"));
        assert_eq!(result.max_id.as_deref(), Some("5-0"));
    }
}
