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
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// A stream entry whose `data` field could not be deserialized.
///
/// Callers must move it to a DLQ and ACK the original entry only after the
/// DLQ write succeeds, otherwise it will remain in the PEL for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoisonedStreamMessage {
    pub id: String,
    pub raw_data: String,
    pub error: String,
}

/// Checked stream read result that preserves malformed messages.
#[derive(Debug)]
pub struct StreamRead<T> {
    pub messages: Vec<(String, T)>,
    pub poisoned: Vec<PoisonedStreamMessage>,
    /// Entries whose data-plane auth token did not match (C1). Like
    /// `poisoned`, the caller must DLQ + ACK them so they cannot be
    /// redelivered forever; kept separate because these are potential
    /// forgeries, not producer bugs.
    pub rejected: Vec<PoisonedStreamMessage>,
    /// Delivery counts for reclaimed messages (C5), keyed by message id.
    /// Only populated by [`StreamClient::xautoclaim_checked`] (via XPENDING);
    /// absent ids should be treated as a first delivery.
    pub delivery_counts: std::collections::HashMap<String, u64>,
}

impl<T> StreamRead<T> {
    pub fn len(&self) -> usize {
        self.messages.len() + self.poisoned.len() + self.rejected.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty() && self.poisoned.is_empty() && self.rejected.is_empty()
    }
}

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
    /// Shared data-plane token captured at construction (C1). When `None`
    /// (unset/empty), entries are accepted without verification (legacy mode).
    auth_token: Option<String>,
    /// Log the unsigned-message downgrade warning only once per consumer.
    legacy_auth_warned: Arc<std::sync::atomic::AtomicBool>,
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
            auth_token: super::client::data_plane_token(),
            legacy_auth_warned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Create a consumer with an auto-generated unique name.
    ///
    /// C7: the PID alone is constant (1) inside containers, so two replicas
    /// would share a consumer identity and XAUTOCLAIM would steal each
    /// other's in-flight batches. The hostname distinguishes containers and
    /// the random suffix distinguishes restarts on the same host.
    pub fn with_auto_consumer(mq: MqClient, group: impl Into<String>) -> Self {
        let group = group.into();
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown-host".to_string());
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let consumer = format!("{}-{host}-{}-{unique}", group, std::process::id());
        Self::new(mq, group, consumer)
    }

    // ── Producer methods ──

    /// Batch XADD using Redis Pipeline.
    ///
    /// Returns the number of messages successfully added.
    /// Uses `MAXLEN ~` for approximate trimming (efficient).
    /// Entries carry an `auth` field holding the `v1` HMAC-SHA256 signature of
    /// the `data` bytes when `INTERNAL_API_TOKEN` is configured (C1/M-2); the
    /// shared token itself is never written to Redis, and consumers reject
    /// unsigned or badly signed entries.
    pub async fn xadd_batch<T: Serialize>(&self, stream: &str, messages: &[T]) -> MqResult<usize> {
        if messages.is_empty() {
            return Ok(0);
        }

        let max_len = self.mq.config.stream_max_len;
        let mut conn = self.mq.get_conn().await?;
        let batch_size = self.mq.config.batch_size;
        let auth_token = super::client::data_plane_token();

        let mut total = 0;
        for chunk in messages.chunks(batch_size) {
            let mut pipe = redis::pipe();
            for msg in chunk {
                let json = serde_json::to_string(msg)?;
                let cmd = pipe.cmd("XADD");
                cmd.arg(stream)
                    .arg("MAXLEN")
                    .arg("~")
                    .arg(max_len)
                    .arg("*")
                    .arg("data")
                    .arg(json.as_str());
                if let Some(token) = &auth_token {
                    let ts = super::client::unix_now_secs();
                    let nonce = super::client::fresh_nonce();
                    cmd.arg("ts").arg(ts.to_string());
                    cmd.arg("nonce").arg(&nonce);
                    cmd.arg("auth")
                        .arg(super::client::sign_v1(token, ts, &nonce, json.as_bytes()));
                }
                cmd.ignore();
            }
            pipe.query_async::<()>(&mut conn).await?;
            total += chunk.len();
        }

        debug!(stream, count = total, "Batch XADD complete");
        Ok(total)
    }

    /// Single XADD (convenience wrapper over [`MqClient::xadd`]).
    pub async fn xadd_one<T: Serialize>(&self, stream: &str, message: &T) -> MqResult<String> {
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
        Ok(self
            .xreadgroup_checked(stream, count, block_ms)
            .await?
            .messages)
    }

    /// Read new messages while retaining entries that fail deserialization.
    pub async fn xreadgroup_checked<T: DeserializeOwned>(
        &self,
        stream: &str,
        count: usize,
        block_ms: Option<usize>,
    ) -> MqResult<StreamRead<T>> {
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
        let parsed = parse_xread_response_parsed::<T>(result)?;
        let read = self.finalize_read(parsed);
        if !read.is_empty() {
            debug!(stream, count = read.len(), "XREADGROUP received");
        }
        Ok(read)
    }

    /// Authenticate parsed entries (C1) and build the final [`StreamRead`].
    ///
    /// Entries signed with a mismatched or missing signature are moved to
    /// `rejected` (the caller DLQs + ACKs them). Unsigned entries are accepted
    /// only because no token is configured — an explicitly insecure mode
    /// flagged at error level (SEC M-2 fail-closed).
    fn finalize_read<T>(&self, parsed: ParsedStreamRead<T>) -> StreamRead<T> {
        let mut read = StreamRead {
            messages: Vec::with_capacity(parsed.entries.len()),
            poisoned: parsed.poisoned,
            rejected: Vec::new(),
            delivery_counts: std::collections::HashMap::new(),
        };
        for entry in parsed.entries {
            match stream_entry_auth(
                entry.auth.as_deref(),
                self.auth_token.as_deref(),
                entry.ts,
                entry.nonce.as_deref(),
                entry.raw_data.as_bytes(),
            ) {
                StreamEntryAuth::Verified => read.messages.push((entry.id, entry.value)),
                StreamEntryAuth::Legacy => {
                    if !self
                        .legacy_auth_warned
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        error!(
                            group = %self.group,
                            "INTERNAL_API_TOKEN not set — accepting unsigned data-plane stream message (insecure mode)"
                        );
                    }
                    read.messages.push((entry.id, entry.value));
                }
                StreamEntryAuth::Rejected => {
                    warn!(
                        group = %self.group,
                        message_id = %entry.id,
                        "Rejected stream message with invalid or missing data-plane auth signature (possible forgery)"
                    );
                    read.rejected.push(PoisonedStreamMessage {
                        id: entry.id,
                        raw_data: entry.raw_data,
                        error: "data-plane message authentication failed".to_string(),
                    });
                }
            }
        }
        read
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
        Ok(self
            .xautoclaim_checked(stream, min_idle_ms, count)
            .await?
            .messages)
    }

    /// Reclaim pending messages while retaining entries that fail
    /// deserialization so the caller can DLQ and ACK them.
    ///
    /// Also populates [`StreamRead::delivery_counts`] (via XPENDING) so the
    /// caller can route permanently failing messages to the DLQ instead of
    /// retrying them forever (C5).
    pub async fn xautoclaim_checked<T: DeserializeOwned>(
        &self,
        stream: &str,
        min_idle_ms: u64,
        count: usize,
    ) -> MqResult<StreamRead<T>> {
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
        let parsed = parse_xautoclaim_response_parsed::<T>(result)?;
        let mut read = self.finalize_read(parsed);

        // C5: XAUTOCLAIM itself does not report delivery counts; fetch them
        // from the PEL so permanently failing messages can be capped and
        // dead-lettered. Just-claimed entries sit at the front of the PEL,
        // so `count` rows cover them; ids missing from the result are
        // treated as a first delivery (retry again next round).
        if !read.is_empty() {
            match self.fetch_delivery_counts(stream, count).await {
                Ok(counts) => read.delivery_counts = counts,
                Err(error) => warn!(
                    stream,
                    error = %error,
                    "Failed to fetch PEL delivery counts; retry cap disabled for this batch"
                ),
            }
        }

        if !read.is_empty() {
            info!(stream, count = read.len(), "XAUTOCLAIM reclaimed messages");
        }
        Ok(read)
    }

    /// Fetch per-message delivery counts from the PEL (extended XPENDING).
    async fn fetch_delivery_counts(
        &self,
        stream: &str,
        count: usize,
    ) -> MqResult<std::collections::HashMap<String, u64>> {
        let mut conn = self.mq.get_conn().await?;
        let result: redis::Value = redis::cmd("XPENDING")
            .arg(stream)
            .arg(&self.group)
            .arg("-")
            .arg("+")
            .arg(count.max(1))
            .query_async(&mut conn)
            .await?;
        Ok(parse_xpending_delivery_counts(result))
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

    /// Write an already-serialized poison message to a dead-letter stream.
    pub async fn xadd_dlq_raw(
        &self,
        dlq_stream: &str,
        original_id: &str,
        raw_data: &str,
        error: &str,
    ) -> MqResult<String> {
        let mut conn = self.mq.get_conn().await?;
        let max_len = self.mq.config.stream_max_len;

        let id: String = redis::cmd("XADD")
            .arg(dlq_stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .arg("*")
            .arg("data")
            .arg(raw_data)
            .arg("original_id")
            .arg(original_id)
            .arg("error")
            .arg(error)
            .arg("consumer")
            .arg(&self.consumer)
            .query_async(&mut conn)
            .await?;

        warn!(
            dlq_stream,
            original_id, error, "Poison message moved to DLQ"
        );
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

/// A successfully deserialized stream entry with its raw payload and the
/// optional data-plane auth field preserved for authentication (C1).
#[derive(Debug)]
struct ParsedStreamEntry<T> {
    id: String,
    raw_data: String,
    auth: Option<String>,
    /// Signing timestamp (unix seconds); RT-4 replay bound.
    ts: Option<i64>,
    /// Per-message nonce; RT-4 round-5 replay elimination.
    nonce: Option<String>,
    value: T,
}

/// Intermediate parse result: entries are not yet authenticated.
struct ParsedStreamRead<T> {
    entries: Vec<ParsedStreamEntry<T>>,
    poisoned: Vec<PoisonedStreamMessage>,
}

/// Parse XREAD / XREADGROUP response.
///
/// Format: `[[stream_name, [[id, [field, value, ...]], ...]]]`
#[cfg(test)]
fn parse_xread_response<T: DeserializeOwned>(value: redis::Value) -> MqResult<Vec<(String, T)>> {
    Ok(parse_xread_response_parsed(value)?
        .entries
        .into_iter()
        .map(|entry| (entry.id, entry.value))
        .collect())
}

fn parse_xread_response_parsed<T: DeserializeOwned>(
    value: redis::Value,
) -> MqResult<ParsedStreamRead<T>> {
    let mut entries = Vec::new();
    let mut poisoned = Vec::new();

    if let redis::Value::Array(streams) = value {
        for stream in streams {
            if let redis::Value::Array(stream_data) = stream
                && stream_data.len() >= 2
                && let redis::Value::Array(stream_entries) = &stream_data[1]
            {
                for entry in stream_entries {
                    match parse_stream_entry_checked::<T>(entry) {
                        Ok(parsed) => entries.push(parsed),
                        Err(poison) => poisoned.push(poison),
                    }
                }
            }
        }
    }

    Ok(ParsedStreamRead { entries, poisoned })
}

/// Parse XAUTOCLAIM response.
///
/// Format: `[next_start_id, [[id, [field, value, ...]], ...], [deleted_ids...]]`
#[cfg(test)]
fn parse_xautoclaim_response<T: DeserializeOwned>(
    value: redis::Value,
) -> MqResult<Vec<(String, T)>> {
    Ok(parse_xautoclaim_response_parsed(value)?
        .entries
        .into_iter()
        .map(|entry| (entry.id, entry.value))
        .collect())
}

fn parse_xautoclaim_response_parsed<T: DeserializeOwned>(
    value: redis::Value,
) -> MqResult<ParsedStreamRead<T>> {
    let mut entries = Vec::new();
    let mut poisoned = Vec::new();

    if let redis::Value::Array(parts) = value
        && parts.len() >= 2
        && let redis::Value::Array(stream_entries) = &parts[1]
    {
        for entry in stream_entries {
            match parse_stream_entry_checked::<T>(entry) {
                Ok(parsed) => entries.push(parsed),
                Err(poison) => poisoned.push(poison),
            }
        }
    }

    Ok(ParsedStreamRead { entries, poisoned })
}

/// Parse a single stream entry: `[id, [field, value, field, value, ...]]`.
///
/// Looks for the `"data"` field and deserializes its value as JSON.
#[cfg(test)]
fn parse_stream_entry<T: DeserializeOwned>(entry: &redis::Value) -> Option<(String, T)> {
    parse_stream_entry_checked(entry)
        .ok()
        .map(|parsed| (parsed.id, parsed.value))
}

fn parse_stream_entry_checked<T: DeserializeOwned>(
    entry: &redis::Value,
) -> Result<ParsedStreamEntry<T>, PoisonedStreamMessage> {
    let malformed = |id: String, raw_data: String, error: String| PoisonedStreamMessage {
        id,
        raw_data,
        error,
    };
    let redis::Value::Array(entry_data) = entry else {
        return Err(malformed(
            String::new(),
            String::new(),
            "stream entry is not an array".to_string(),
        ));
    };
    if entry_data.len() < 2 {
        return Err(malformed(
            String::new(),
            String::new(),
            "stream entry is missing id or fields".to_string(),
        ));
    }

    // Extract message ID
    let id = match &entry_data[0] {
        redis::Value::BulkString(b) => String::from_utf8_lossy(b).to_string(),
        _ => {
            return Err(malformed(
                String::new(),
                String::new(),
                "stream entry has an invalid id".to_string(),
            ));
        }
    };

    // Extract "data" and "auth" fields from field-value pairs
    let redis::Value::Array(fields) = &entry_data[1] else {
        return Err(malformed(
            id,
            String::new(),
            "stream entry fields are not an array".to_string(),
        ));
    };

    let mut data: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut ts: Option<i64> = None;
    let mut nonce: Option<String> = None;
    let mut i = 0;
    while i + 1 < fields.len() {
        if let redis::Value::BulkString(key) = &fields[i]
            && let redis::Value::BulkString(val) = &fields[i + 1]
        {
            if key == b"data" {
                data = Some(String::from_utf8_lossy(val).into_owned());
            } else if key == b"auth" {
                auth = Some(String::from_utf8_lossy(val).into_owned());
            } else if key == b"ts" {
                ts = String::from_utf8_lossy(val).parse::<i64>().ok();
            } else if key == b"nonce" {
                nonce = Some(String::from_utf8_lossy(val).into_owned());
            }
        }
        i += 2;
    }

    let Some(json) = data else {
        return Err(malformed(
            id,
            String::new(),
            "stream entry is missing the data field".to_string(),
        ));
    };

    match serde_json::from_str(&json) {
        Ok(value) => Ok(ParsedStreamEntry {
            id,
            raw_data: json,
            auth,
            ts,
            nonce,
            value,
        }),
        Err(error) => Err(malformed(
            id,
            json,
            format!("invalid JSON payload: {error}"),
        )),
    }
}

/// Authentication decision for a single stream entry (C1/M-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEntryAuth {
    /// `auth` field carries a valid `v1` HMAC over the entry's data bytes.
    Verified,
    /// No token configured: the entry is accepted because the deployment has
    /// an unauthenticated data plane (explicitly insecure mode).
    Legacy,
    /// `auth` field missing (with a token configured), malformed, or carrying
    /// a bad signature: forged message, must be dropped.
    Rejected,
}

fn stream_entry_auth(
    auth_field: Option<&str>,
    expected_token: Option<&str>,
    ts: Option<i64>,
    nonce: Option<&str>,
    data: &[u8],
) -> StreamEntryAuth {
    let Some(expected) = expected_token.filter(|t| !t.is_empty()) else {
        // Auth disabled (INTERNAL_API_TOKEN unset): nothing to verify against.
        return StreamEntryAuth::Legacy;
    };
    // RT-4: a missing timestamp or nonce is a pre-freshness entry — treat
    // unsigned traffic uniformly and reject.
    let Some(ts) = ts else {
        return StreamEntryAuth::Rejected;
    };
    let Some(nonce) = nonce.filter(|n| super::client::is_valid_nonce(n)) else {
        return StreamEntryAuth::Rejected;
    };
    let now = super::client::unix_now_secs();
    if !super::client::ts_within_window(ts, now) {
        return StreamEntryAuth::Rejected;
    }
    match auth_field {
        Some(auth) => {
            if !super::client::verify_v1_field(auth, expected, ts, nonce, data) {
                return StreamEntryAuth::Rejected;
            }
            // RT-4 round-5: an XADD'd copy of an already-consumed entry dies
            // here even inside the freshness window.
            if !super::client::replay_guard().check_and_record(nonce, now) {
                return StreamEntryAuth::Rejected;
            }
            StreamEntryAuth::Verified
        }
        // Fail closed: every in-repo producer signs, so an unsigned entry
        // alongside a configured token is forged traffic (SEC M-2).
        None => StreamEntryAuth::Rejected,
    }
}

/// Parse the extended XPENDING response into per-message delivery counts.
///
/// Format: `[[id, consumer, idle_ms, delivery_count], ...]` (C5).
fn parse_xpending_delivery_counts(value: redis::Value) -> std::collections::HashMap<String, u64> {
    let mut counts = std::collections::HashMap::new();
    if let redis::Value::Array(rows) = value {
        for row in rows {
            let redis::Value::Array(cols) = row else { continue };
            if cols.len() < 4 {
                continue;
            }
            let id = match &cols[0] {
                redis::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                _ => continue,
            };
            let deliveries = match &cols[3] {
                redis::Value::Int(n) if *n > 0 => *n as u64,
                _ => continue,
            };
            counts.insert(id, deliveries);
        }
    }
    counts
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
    use crate::mq::MqConfig;

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
    fn test_checked_parser_preserves_invalid_json_for_dlq() {
        let entry = redis::Value::Array(vec![
            redis::Value::BulkString(b"1234-0".to_vec()),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"data".to_vec()),
                redis::Value::BulkString(b"{not-json".to_vec()),
            ]),
        ]);

        let poison = parse_stream_entry_checked::<String>(&entry).unwrap_err();
        assert_eq!(poison.id, "1234-0");
        assert_eq!(poison.raw_data, "{not-json");
        assert!(poison.error.contains("invalid JSON payload"));
    }

    #[test]
    fn test_checked_xread_separates_valid_and_poison_messages() {
        let valid = redis::Value::Array(vec![
            redis::Value::BulkString(b"1-0".to_vec()),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"data".to_vec()),
                redis::Value::BulkString(b"\"ok\"".to_vec()),
            ]),
        ]);
        let poison = redis::Value::Array(vec![
            redis::Value::BulkString(b"2-0".to_vec()),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"data".to_vec()),
                redis::Value::BulkString(b"bad".to_vec()),
            ]),
        ]);
        let value = redis::Value::Array(vec![redis::Value::Array(vec![
            redis::Value::BulkString(b"stream".to_vec()),
            redis::Value::Array(vec![valid, poison]),
        ])]);

        let result = parse_xread_response_parsed::<String>(value).unwrap();
        let messages: Vec<(String, String)> = result
            .entries
            .into_iter()
            .map(|entry| (entry.id, entry.value))
            .collect();
        assert_eq!(messages, vec![("1-0".to_string(), "ok".to_string())]);
        assert_eq!(result.poisoned.len(), 1);
        assert_eq!(result.poisoned[0].id, "2-0");
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
        let result: MqResult<Vec<(String, String)>> = parse_xread_response(redis::Value::Nil);
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

    // ── C1: data-plane stream authentication ──

    #[allow(clippy::too_many_arguments)]
    fn stream_entry_at(
        id: &str,
        data: &str,
        ts: Option<i64>,
        auth: Option<&str>,
        nonce: Option<&str>,
    ) -> redis::Value {
        let mut fields = vec![
            redis::Value::BulkString(b"data".to_vec()),
            redis::Value::BulkString(data.as_bytes().to_vec()),
        ];
        if let Some(ts) = ts {
            fields.push(redis::Value::BulkString(b"ts".to_vec()));
            fields.push(redis::Value::BulkString(ts.to_string().into_bytes()));
        }
        if let Some(nonce) = nonce {
            fields.push(redis::Value::BulkString(b"nonce".to_vec()));
            fields.push(redis::Value::BulkString(nonce.as_bytes().to_vec()));
        }
        if let Some(auth) = auth {
            fields.push(redis::Value::BulkString(b"auth".to_vec()));
            fields.push(redis::Value::BulkString(auth.as_bytes().to_vec()));
        }
        redis::Value::Array(vec![
            redis::Value::BulkString(id.as_bytes().to_vec()),
            redis::Value::Array(fields),
        ])
    }

    fn signed_entry(id: &str, data: &str, token: &str, ts: i64) -> redis::Value {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        signed_entry_full(id, data, token, ts, &nonce)
    }

    fn signed_entry_full(
        id: &str,
        data: &str,
        token: &str,
        ts: i64,
        nonce: &str,
    ) -> redis::Value {
        let auth = super::super::client::sign_v1(token, ts, nonce, data.as_bytes());
        stream_entry_at(id, data, Some(ts), Some(&auth), Some(nonce))
    }

    #[test]
    fn forged_stream_entry_is_rejected_when_auth_configured() {
        // PoC (C1): with bare Redis access an attacker XADDs a fake session
        // driving the full 35-module pipeline + IOC writes + SOAR alerts.
        // After the fix, a mismatched auth field must drop the entry.
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = Some("s3cret-env-token".to_string());

        let forged = parse_stream_entry_checked::<serde_json::Value>(&signed_entry(
            "1-0",
            r#"{"id":"fake","protocol":"smtp"}"#,
            "guessed-token",
            super::super::client::unix_now_secs(),
        ))
        .unwrap();
        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![forged],
            poisoned: vec![],
        });

        assert!(read.messages.is_empty());
        assert_eq!(read.rejected.len(), 1);
        assert_eq!(read.rejected[0].id, "1-0");
        assert!(read.rejected[0].error.contains("authentication"));
        assert_eq!(read.rejected[0].raw_data, r#"{"id":"fake","protocol":"smtp"}"#);
    }

    #[test]
    fn correctly_signed_stream_entry_is_accepted() {
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = Some("s3cret-env-token".to_string());

        let signed = parse_stream_entry_checked::<String>(&signed_entry(
            "1-0",
            "\"hello\"",
            "s3cret-env-token",
            super::super::client::unix_now_secs(),
        ))
        .unwrap();
        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![signed],
            poisoned: vec![],
        });

        assert_eq!(read.messages, vec![("1-0".to_string(), "hello".to_string())]);
        assert!(read.rejected.is_empty());
    }

    #[test]
    fn unsigned_and_cleartext_stream_entries_rejected_when_auth_configured() {
        // PoC (M-2 fail-closed): with a token configured, unsigned entries and
        // the legacy cleartoken auth field are forged traffic — every in-repo
        // producer signs with the same binary.
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = Some("s3cret-env-token".to_string());

        let unsigned = parse_stream_entry_checked::<String>(&stream_entry_at(
            "1-0",
            "\"hello\"",
            None,
            None,
            None,
        ))
        .unwrap();
        let cleartext = parse_stream_entry_checked::<String>(&stream_entry_at(
            "1-0",
            "\"hello\"",
            Some(super::super::client::unix_now_secs()),
            Some("s3cret-env-token"),
            None,
        ))
        .unwrap();
        // RT-4: pre-freshness entry (signed but no ts field) also rejected.
        let no_ts = parse_stream_entry_checked::<String>(&stream_entry_at(
            "1-0",
            "\"hello\"",
            None,
            Some("v1:00"),
            Some(&uuid::Uuid::new_v4().simple().to_string()),
        ))
        .unwrap();
        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![unsigned, cleartext, no_ts],
            poisoned: vec![],
        });

        assert!(read.messages.is_empty());
        assert_eq!(read.rejected.len(), 3);
    }

    #[test]
    fn unsigned_stream_entry_is_accepted_only_without_token() {
        // Explicitly insecure mode: tokenless deployments keep an
        // unauthenticated data plane (documented in the ADR).
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = None;

        let unsigned = parse_stream_entry_checked::<String>(&stream_entry_at(
            "1-0",
            "\"hello\"",
            None,
            None,
            None,
        ))
        .unwrap();
        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![unsigned],
            poisoned: vec![],
        });

        assert_eq!(read.messages, vec![("1-0".to_string(), "hello".to_string())]);
        assert!(read.rejected.is_empty());
    }

    #[test]
    fn stream_entry_auth_decisions() {
        let ts = super::super::client::unix_now_secs();
        let data = b"hello";
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let signature = super::super::client::sign_v1("tok", ts, &nonce, data);
        assert_eq!(
            stream_entry_auth(Some(&signature), Some("tok"), Some(ts), Some(&nonce), data),
            StreamEntryAuth::Verified
        );
        let wrong_nonce = uuid::Uuid::new_v4().simple().to_string();
        assert_eq!(
            stream_entry_auth(
                Some("wrong"),
                Some("tok"),
                Some(ts),
                Some(&wrong_nonce),
                data,
            ),
            StreamEntryAuth::Rejected
        );
        assert_eq!(
            stream_entry_auth(None, Some("tok"), Some(ts), Some(&wrong_nonce), data),
            StreamEntryAuth::Rejected
        );
        // Auth disabled: everything is legacy regardless of the field.
        assert_eq!(
            stream_entry_auth(Some("x"), None, None, None, data),
            StreamEntryAuth::Legacy
        );
        assert_eq!(
            stream_entry_auth(Some("x"), Some(""), None, None, data),
            StreamEntryAuth::Legacy
        );
    }

    // ── C5: delivery-count parsing for the retry cap ──

    #[test]
    fn xpending_delivery_counts_are_parsed() {
        let value = redis::Value::Array(vec![
            redis::Value::Array(vec![
                redis::Value::BulkString(b"1-0".to_vec()),
                redis::Value::BulkString(b"consumer-1".to_vec()),
                redis::Value::Int(61_234),
                redis::Value::Int(6),
            ]),
            redis::Value::Array(vec![
                redis::Value::BulkString(b"2-0".to_vec()),
                redis::Value::BulkString(b"consumer-1".to_vec()),
                redis::Value::Int(5_000),
                redis::Value::Int(1),
            ]),
        ]);
        let counts = parse_xpending_delivery_counts(value);
        assert_eq!(counts.get("1-0"), Some(&6));
        assert_eq!(counts.get("2-0"), Some(&1));
        assert!(parse_xpending_delivery_counts(redis::Value::Nil).is_empty());
    }

    // ── C7: consumer identity uniqueness ──

    #[test]
    fn auto_consumer_names_are_unique_per_instance() {
        // PoC (C7): inside a container the PID is always 1, so `{group}-{pid}`
        // gave every replica the same consumer identity and XAUTOCLAIM stole
        // in-flight batches across instances.
        let mq = MqClient::new(MqConfig::default());
        let a = StreamClient::with_auto_consumer(mq.clone(), "vigilyx-engine");
        let b = StreamClient::with_auto_consumer(mq, "vigilyx-engine");
        assert_ne!(a.consumer_name(), b.consumer_name());
        assert!(a.consumer_name().starts_with("vigilyx-engine-"));
    }
    #[test]
    fn rt4_round5_stream_replay_same_nonce_is_rejected() {
        // PoC (RT-4 round-5): an XADD'd copy of an already-consumed entry
        // (new entry id, same nonce) dies at the dedup inside the window.
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = Some("s3cret-env-token".to_string());

        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let now = super::super::client::unix_now_secs();
        let entry =
            parse_stream_entry_checked::<String>(&signed_entry_full(
                "1-0", "\"hello\"", "s3cret-env-token", now, &nonce,
            ))
            .unwrap();
        let copy =
            parse_stream_entry_checked::<String>(&signed_entry_full(
                "2-0", "\"hello\"", "s3cret-env-token", now, &nonce,
            ))
            .unwrap();

        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![entry, copy],
            poisoned: vec![],
        });
        assert_eq!(read.messages.len(), 1, "original accepted");
        assert_eq!(read.rejected.len(), 1, "re-XADD'd copy rejected");
    }

    #[test]
    fn rt4_replayed_stream_entry_past_window_is_rejected() {
        // PoC (RT-4): a captured session entry replayed after the freshness
        // window must be dropped even with a valid signature.
        let mq = MqClient::new(MqConfig::default());
        let mut client = StreamClient::new(mq, "test-group", "test-consumer");
        client.auth_token = Some("s3cret-env-token".to_string());

        let stale_ts =
            super::super::client::unix_now_secs() - super::super::client::MAX_MESSAGE_AGE_SECS - 1;
        let replayed =
            parse_stream_entry_checked::<String>(&signed_entry("1-0", "\"hello\"", "s3cret-env-token", stale_ts))
                .unwrap();
        let read = client.finalize_read(ParsedStreamRead {
            entries: vec![replayed],
            poisoned: vec![],
        });

        assert!(read.messages.is_empty());
        assert_eq!(read.rejected.len(), 1);
    }

}
