//! Message Queue Client

//! Performance Optimizations:
//! - Connection pool management
//! - Batch operations (Pipeline)
//! - Automatic reconnection
//! - Message compression (for large messages)

use super::error::{MqError, MqResult};
use super::topics;
use redis::aio::{ConnectionManager, MultiplexedConnection};
use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use vigilyx_core::TrafficStats;

/// Message Queue Configuration
///
/// SEC: Custom Debug impl to mask password in redis_url (CWE-532)
#[derive(Clone)]
pub struct MqConfig {
    /// Redis URL
    pub redis_url: String,
    /// Message retention time (secs)
    pub message_ttl: u64,
    /// Stream max length
    pub stream_max_len: usize,
    /// Batch send threshold
    pub batch_size: usize,
    /// Batch send interval(ms)
    pub batch_interval_ms: u64,
    /// Reconnection interval (secs)
    pub reconnect_interval_secs: u64,
    /// Max retry count
    pub max_retries: u32,
}

impl std::fmt::Debug for MqConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SEC: mask password in redis_url (redis://:PASSWORD@host -> redis://:***@host)
        let masked_url = if let Some(at_pos) = self.redis_url.find('@') {
            if let Some(colon_pos) = self.redis_url[..at_pos].rfind(':') {
                format!(
                    "{}:***@{}",
                    &self.redis_url[..colon_pos],
                    &self.redis_url[at_pos + 1..]
                )
            } else {
                "redis://***".to_string()
            }
        } else {
            self.redis_url.clone()
        };
        f.debug_struct("MqConfig")
            .field("redis_url", &masked_url)
            .field("message_ttl", &self.message_ttl)
            .field("stream_max_len", &self.stream_max_len)
            .finish()
    }
}

impl Default for MqConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://127.0.0.1:6379".to_string(),
            message_ttl: 3600,
            stream_max_len: 10000,
            batch_size: 100,
            batch_interval_ms: 100,
            reconnect_interval_secs: 5,
            max_retries: 3,
        }
    }
}

impl MqConfig {
    /// Load config from environment variables
    pub fn from_env() -> Self {
        Self {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            message_ttl: std::env::var("MQ_MESSAGE_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            stream_max_len: std::env::var("MQ_STREAM_MAX_LEN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10000),
            batch_size: std::env::var("MQ_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            batch_interval_ms: std::env::var("MQ_BATCH_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            reconnect_interval_secs: std::env::var("MQ_RECONNECT_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            max_retries: std::env::var("MQ_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        }
    }
}

/// Message Queue Client (performance optimized version)
#[derive(Clone)]
pub struct MqClient {
    pub(crate) config: MqConfig,
    conn: Arc<RwLock<Option<ConnectionManager>>>,
    /// Sent message count
    pub sent_count: Arc<AtomicU64>,
    /// Error count
    pub error_count: Arc<AtomicU64>,
}

impl MqClient {
    /// Create new client
    pub fn new(config: MqConfig) -> Self {
        Self {
            config,
            conn: Arc::new(RwLock::new(None)),
            sent_count: Arc::new(AtomicU64::new(0)),
            error_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Connect to Redis (with retry)
    pub async fn connect(&self) -> MqResult<()> {
        let mut retries = 0;
        loop {
            match self.try_connect().await {
                Ok(_) => {
                    // Security: hide Redis password in logs
                    let redis_log = self.config.redis_url.find('@').map_or_else(
                        || self.config.redis_url.clone(),
                        |at| format!("redis://***@{}", &self.config.redis_url[at + 1..]),
                    );
                    info!("Connected to Redis: {}", redis_log);
                    return Ok(());
                }
                Err(e) => {
                    retries += 1;
                    if retries >= self.config.max_retries {
                        return Err(e);
                    }
                    warn!(
                        "Redis connection failed (attempt {}/{}): {}, retrying in {}s",
                        retries, self.config.max_retries, e, self.config.reconnect_interval_secs
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(
                        self.config.reconnect_interval_secs,
                    ))
                    .await;
                }
            }
        }
    }

    /// Create a fresh Redis connection manager.
    pub(crate) async fn new_connection_manager(&self) -> MqResult<ConnectionManager> {
        let client = Client::open(self.config.redis_url.clone())?;
        let conn = ConnectionManager::new(client).await?;
        Ok(conn)
    }

    /// Create a dedicated async connection for stream reads.
    ///
    /// Redis stream consumers intentionally issue blocking `XREADGROUP` calls, so
    /// the default 500ms async response timeout used by the redis crate would
    /// incorrectly abort healthy reads before Redis returns. Stream consumers use a
    /// separate connection with no built-in response timeout and rely on the caller
    /// to apply an explicit timeout matched to the chosen `BLOCK` window.
    pub(crate) async fn new_stream_read_connection(&self) -> MqResult<MultiplexedConnection> {
        let client = Client::open(self.config.redis_url.clone())?;
        let config = redis::AsyncConnectionConfig::new().set_response_timeout(None);
        let conn = client
            .get_multiplexed_async_connection_with_config(&config)
            .await?;
        Ok(conn)
    }

    /// Try connect
    async fn try_connect(&self) -> MqResult<()> {
        let conn = self.new_connection_manager().await?;

        let mut guard = self.conn.write().await;
        *guard = Some(conn);

        Ok(())
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        let guard = self.conn.read().await;
        if let Some(ref conn) = *guard {
            // Try PING to check connection
            let mut conn = conn.clone();
            redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
                .is_ok()
        } else {
            false
        }
    }

    /// Get connection (with automatic reconnection)
    pub(crate) async fn get_conn(&self) -> MqResult<ConnectionManager> {
        {
            let guard = self.conn.read().await;
            if let Some(ref conn) = *guard {
                return Ok(conn.clone());
            }
        }

        // Attempt reconnection
        self.try_connect().await?;

        let guard = self.conn.read().await;
        guard
            .clone()
            .ok_or_else(|| MqError::Connection("Not connected".to_string()))
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.sent_count.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed),
        )
    }

    /// Publish a **control-plane command** to a Pub/Sub channel.
    ///
    /// The on-wire payload becomes
    /// `v1:<ts>:<nonce>:<hmac-hex>:<json>` where the signature covers the
    /// timestamp, nonce, and JSON bytes (SEC M-2: the shared token never
    /// appears in cleartext). Receivers must call [`verify_cmd_payload`] to
    /// validate and strip the prefix.
    pub async fn publish_cmd<T: Serialize>(&self, topic: &str, message: &T) -> MqResult<()> {
        let json = serde_json::to_string(message)?;
        let token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
        if token.is_empty() {
            return Err(MqError::Publish(
                "INTERNAL_API_TOKEN is not configured; refusing to publish unauthenticated control command"
                    .to_string(),
            ));
        }
        let ts = unix_now_secs();
        let nonce = fresh_nonce();
        // Control frames already carry the leading `v1:` scheme marker, so
        // insert only the bare digest here. Data-plane `auth` fields use the
        // full `v1:<hex>` value returned by `sign_v1`.
        let signature = sign_v1_hex(&token, ts, &nonce, json.as_bytes());
        let payload = format!("{AUTH_SCHEME_V1}:{ts}:{nonce}:{signature}:{json}");
        self.publish_raw(topic, &payload).await
    }

    /// Publish message to Pub/Sub channel (with retry)
    ///
    /// SEC (C1): the payload is wrapped in a shared-token envelope
    /// ([`wrap_data_payload`]) so a forged PUBLISH from bare Redis access
    /// cannot inject fake verdicts/alerts. Receivers must pass the raw
    /// payload through [`verify_data_payload`].
    pub async fn publish<T: Serialize>(&self, topic: &str, message: &T) -> MqResult<()> {
        let json = serde_json::to_string(message)?;
        let payload = wrap_data_payload(&json);
        self.publish_raw(topic, &payload).await
    }

    /// Low-level publish of an already-formatted payload string (with retry).
    async fn publish_raw(&self, topic: &str, payload: &str) -> MqResult<()> {
        let mut retries = 0;

        loop {
            let mut conn = self.get_conn().await?;

            match conn.publish::<_, _, ()>(topic, payload).await {
                Ok(_) => {
                    self.sent_count.fetch_add(1, Ordering::Relaxed);
                    debug!("Published to {}: {} bytes", topic, payload.len());
                    return Ok(());
                }
                Err(e) => {
                    retries += 1;
                    self.error_count.fetch_add(1, Ordering::Relaxed);

                    if retries >= self.config.max_retries {
                        return Err(MqError::Redis(e));
                    }

                    warn!(
                        "Failed to publish message (attempt {}/{}): {}",
                        retries, self.config.max_retries, e
                    );

                    // Clear connection, force reconnection
                    {
                        let mut guard = self.conn.write().await;
                        *guard = None;
                    }

                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Write Redis key (with TTL secs)
    pub async fn set_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_secs: u64,
    ) -> MqResult<()> {
        let mut conn = self.get_conn().await?;
        let json = serde_json::to_string(value)?;
        conn.set_ex::<_, _, ()>(key, &json, ttl_secs).await?;
        Ok(())
    }

    /// Read Redis key
    pub async fn get_json<T: DeserializeOwned>(&self, key: &str) -> MqResult<Option<T>> {
        let mut conn = self.get_conn().await?;
        let val: Option<String> = conn.get(key).await?;
        match val {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Delete an explicit allowlist of Redis Stream keys.
    ///
    /// Returns `(entries_deleted, stream_keys_deleted)`. Every existing key is
    /// type-checked before deletion so a configuration mistake cannot erase a
    /// control-plane or configuration value that happens to reuse a name.
    pub async fn purge_streams(&self, stream_keys: &[&str]) -> MqResult<(u64, u64)> {
        if stream_keys.is_empty() {
            return Ok((0, 0));
        }

        let mut conn = self.get_conn().await?;
        let mut entries_deleted = 0u64;

        for key in stream_keys {
            let key_type: String = redis::cmd("TYPE").arg(key).query_async(&mut conn).await?;
            match key_type.as_str() {
                "none" => {}
                "stream" => {
                    let len: u64 = redis::cmd("XLEN").arg(key).query_async(&mut conn).await?;
                    entries_deleted = entries_deleted.saturating_add(len);
                }
                other => {
                    return Err(MqError::Connection(format!(
                        "refusing to purge non-stream Redis key {key} (type={other})"
                    )));
                }
            }
        }

        let mut delete = redis::cmd("DEL");
        for key in stream_keys {
            delete.arg(key);
        }
        let stream_keys_deleted: u64 = delete.query_async(&mut conn).await?;

        info!(
            entries_deleted,
            stream_keys_deleted, "Purged explicit Redis data-plane streams"
        );
        Ok((entries_deleted, stream_keys_deleted))
    }

    /// Publish message to Stream
    ///
    /// SEC (C1): entries carry an `auth` field with the shared data-plane
    /// token (when configured) so a forged XADD from bare Redis access is
    /// rejected by consumers instead of driving the full analysis pipeline.
    pub async fn xadd<T: Serialize>(&self, stream: &str, message: &T) -> MqResult<String> {
        let mut conn = self.get_conn().await?;
        let json = serde_json::to_string(message)?;

        // XADD with MAXLEN. SEC (M-2/RT-4): the auth field carries a v1 HMAC
        // over `<ts>:<data>` — never the shared token itself — and the
        // plaintext ts field bounds replay.
        let mut cmd = redis::cmd("XADD");
        cmd.arg(stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(self.config.stream_max_len)
            .arg("*")
            .arg("data")
            .arg(&json);
        if let Some(token) = data_plane_token() {
            let ts = unix_now_secs();
            let nonce = fresh_nonce();
            cmd.arg("ts").arg(ts.to_string());
            cmd.arg("nonce").arg(&nonce);
            cmd.arg("auth").arg(sign_v1(&token, ts, &nonce, json.as_bytes()));
        }
        let id: String = cmd.query_async(&mut conn).await?;

        debug!("Added to stream {}: {}", stream, id);
        Ok(id)
    }

    /// Read message from Stream
    pub async fn xread<T: DeserializeOwned>(
        &self,
        stream: &str,
        last_id: &str,
        count: usize,
        block_ms: usize,
    ) -> MqResult<Vec<(String, T)>> {
        let mut conn = self.get_conn().await?;

        let result: redis::Value = redis::cmd("XREAD")
            .arg("COUNT")
            .arg(count)
            .arg("BLOCK")
            .arg(block_ms)
            .arg("STREAMS")
            .arg(stream)
            .arg(last_id)
            .query_async(&mut conn)
            .await?;

        // Parse results
        let messages = self.parse_xread_result::<T>(result)?;
        Ok(messages)
    }

    /// Parse XREAD results
    fn parse_xread_result<T: DeserializeOwned>(
        &self,
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
                        if let redis::Value::Array(entry_data) = entry
                            && entry_data.len() >= 2
                        {
                            // Get ID
                            let id = match &entry_data[0] {
                                redis::Value::BulkString(b) => {
                                    String::from_utf8_lossy(b).to_string()
                                }
                                _ => continue,
                            };

                            // Get data
                            if let redis::Value::Array(fields) = &entry_data[1]
                                && fields.len() >= 2
                                && let redis::Value::BulkString(data) = &fields[1]
                            {
                                let json = String::from_utf8_lossy(data);
                                if let Ok(msg) = serde_json::from_str(&json) {
                                    messages.push((id, msg));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(messages)
    }

    // ==================== Convenience methods ====================

    /// Publish stats update
    pub async fn publish_stats(&self, stats: &TrafficStats) -> MqResult<()> {
        self.publish(topics::STATS_UPDATE, stats).await
    }

    // ==================== Batch publish methods (performance optimization) ====================

    /// Batch publish statistics (high-frequency update optimization)
    pub async fn publish_stats_throttled(
        &self,
        stats: &TrafficStats,
        min_interval_ms: u64,
    ) -> MqResult<bool> {
        use std::sync::atomic::AtomicU64;
        use std::time::{SystemTime, UNIX_EPOCH};

        static LAST_STATS_TIME: AtomicU64 = AtomicU64::new(0);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;

        let last = LAST_STATS_TIME.load(Ordering::Relaxed);
        if now.saturating_sub(last) < min_interval_ms {
            return Ok(false); // Skip, not yet time to send
        }

        if LAST_STATS_TIME
            .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            self.publish_stats(stats).await?;
            return Ok(true);
        }

        Ok(false)
    }

    // ============================================
    // sid -> user mapping persistence (Redis Hash)
    // ============================================

    const SID_USER_KEY: &'static str = "vigilyx:sid_to_user";

    /// F3: TTL applied to the sid→user hash on every write. A poisoned
    /// mapping must not persist indefinitely and reload after a restart.
    /// Key-level expiry (Valkey 8.0 has no per-field hash TTL); each write
    /// refreshes it, so active mappings survive while a one-time poisoning
    /// ages out within 24h.
    pub const SID_USER_TTL_SECS: u64 = 24 * 3600;

    /// Write sid -> user mapping to Redis Hash (single entry)
    pub async fn sid_user_set(&self, sid: &str, user: &str) -> MqResult<()> {
        let mut conn = self.get_conn().await?;
        redis::pipe()
            .hset(Self::SID_USER_KEY, sid, user)
            .ignore()
            .expire(Self::SID_USER_KEY, Self::SID_USER_TTL_SECS as i64)
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Batch write sid -> user mappings
    pub async fn sid_user_set_batch(&self, entries: &[(String, String)]) -> MqResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut conn = self.get_conn().await?;
        build_sid_user_set_pipe(entries)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Load all sid -> user mappings (called at startup)
    pub async fn sid_user_load_all(&self) -> MqResult<Vec<(String, String)>> {
        let mut conn = self.get_conn().await?;
        let map: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
            .arg(Self::SID_USER_KEY)
            .query_async(&mut conn)
            .await?;
        Ok(map.into_iter().collect())
    }

    /// Delete specified sid mapping (batch delete on LRU eviction)
    pub async fn sid_user_delete_batch(&self, sids: &[String]) -> MqResult<()> {
        if sids.is_empty() {
            return Ok(());
        }
        let mut conn = self.get_conn().await?;
        let mut pipe = redis::pipe();
        for sid in sids {
            pipe.hdel(Self::SID_USER_KEY, sid).ignore();
        }
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }

    /// Create Pub/Sub subscriber
    pub async fn subscribe(&self, topics: &[&str]) -> MqResult<redis::aio::PubSub> {
        let client = Client::open(self.config.redis_url.clone())?;
        let mut pubsub = client.get_async_pubsub().await?;

        for topic in topics {
            pubsub.subscribe(*topic).await?;
            info!("Subscribed to topic: {}", topic);
        }

        Ok(pubsub)
    }
}

/// Build the sid→user batch-write pipeline: one HSET per entry plus an
/// EXPIRE that (re)applies the 24h TTL to the whole hash (F3).
fn build_sid_user_set_pipe(entries: &[(String, String)]) -> redis::Pipeline {
    let mut pipe = redis::pipe();
    for (sid, user) in entries {
        pipe.hset(MqClient::SID_USER_KEY, sid, user).ignore();
    }
    pipe.expire(MqClient::SID_USER_KEY, MqClient::SID_USER_TTL_SECS as i64)
        .ignore();
    pipe
}

// ── Message authentication (v1 HMAC + timestamp) ───────────────────────
//
// SEC (M-2, 2026-08-15 red-team scan): the shared `INTERNAL_API_TOKEN` must
// never appear on the Redis wire in cleartext. Every authenticated producer
// attaches `v1:<hex(HMAC-SHA256(token, "<ts>:<payload>"))>` together with the
// plaintext `ts` (unix seconds), and consumers fail closed (reject unsigned /
// cleartext / bad-signature / stale / far-future messages) whenever the token
// is configured. Without a token the data plane stays in an explicitly
// insecure legacy mode (accept + error-level warning); the control plane
// keeps rejecting everything.
//
// SEC (RT-4, deep red-team round): authenticity alone allowed an attacker
// with Redis read+write to replay a previously valid message verbatim. The
// timestamp bounds replay to a short window; full replay prevention would
// require per-message nonces and a dedup store.

/// Signature scheme prefix for authenticated MQ messages.
pub const AUTH_SCHEME_V1: &str = "v1";

/// Maximum age of an authenticated message before it is treated as a replay.
pub const MAX_MESSAGE_AGE_SECS: i64 = 600;

/// Maximum tolerated producer/consumer clock skew into the future.
pub const MAX_FUTURE_SKEW_SECS: i64 = 60;

/// Process-wide replay dedup for authenticated MQ messages (RT-4 round-5:
/// the 600 s freshness window alone still allowed replays inside the window;
/// a captured message now dies with its nonce).
///
/// Only nonces of messages that already passed signature + window checks are
/// recorded, so an attacker without the token cannot flood the map. Entries
/// are pruned lazily once the map exceeds `MAX_TRACKED_NONCES`.
pub struct ReplayGuard {
    inner: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

const MAX_TRACKED_NONCES: usize = 131_072;

impl ReplayGuard {
    /// First observation of `nonce` returns true and records it; a repeat
    /// inside the retention horizon returns false (replay).
    pub fn check_and_record(&self, nonce: &str, now: i64) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("ReplayGuard lock was poisoned, recovering");
            poisoned.into_inner()
        });
        if map.len() > MAX_TRACKED_NONCES {
            let horizon = now - MAX_MESSAGE_AGE_SECS - MAX_FUTURE_SKEW_SECS;
            map.retain(|_, seen_at| *seen_at >= horizon);
        }
        match map.get(nonce) {
            Some(seen_at) if *seen_at >= now - MAX_MESSAGE_AGE_SECS - MAX_FUTURE_SKEW_SECS => {
                false
            }
            Some(_) | None => {
                map.insert(nonce.to_string(), now);
                true
            }
        }
    }
}

pub(crate) fn replay_guard() -> &'static ReplayGuard {
    static GUARD: std::sync::LazyLock<ReplayGuard> =
        std::sync::LazyLock::new(|| ReplayGuard {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
    &GUARD
}

pub(crate) fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn ts_within_window(ts: i64, now: i64) -> bool {
    now - ts <= MAX_MESSAGE_AGE_SECS && ts - now <= MAX_FUTURE_SKEW_SECS
}

/// MAC input construction: `<ts-ascii>:<nonce>:<payload>` (RT-4: the
/// signature binds the timestamp and the per-message nonce so neither can be
/// swapped after the fact).
fn mac_input(ts: i64, nonce: &str, payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(payload.len() + nonce.len() + 12);
    input.extend_from_slice(ts.to_string().as_bytes());
    input.push(b':');
    input.extend_from_slice(nonce.as_bytes());
    input.push(b':');
    input.extend_from_slice(payload);
    input
}

/// Validate the shape of a message nonce (uuid v4 simple form: 32 hex).
pub(crate) fn is_valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Generate a fresh per-message nonce.
pub(crate) fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Compute the bare HMAC hex digest for `payload` at `ts`/`nonce`.
fn sign_v1_hex(key: &str, ts: i64, nonce: &str, payload: &[u8]) -> String {
    // hmac 0.13 pairs with the digest 0.11 / sha2 0.11 line: KeyInit builds
    // the MAC, Update feeds it, FixedOutput finalizes.
    use digest::{FixedOutput, KeyInit, Update};
    type HmacSha256 = hmac::SimpleHmac<sha2::Sha256>;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    <HmacSha256 as Update>::update(&mut mac, mac_input(ts, nonce, payload).as_slice());
    let digest = <HmacSha256 as FixedOutput>::finalize_fixed(mac);
    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.iter() {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Compute the full `v1:<hex>` authentication field used by stream entries
/// and data-plane JSON envelopes.
pub(crate) fn sign_v1(key: &str, ts: i64, nonce: &str, payload: &[u8]) -> String {
    format!(
        "{AUTH_SCHEME_V1}:{}",
        sign_v1_hex(key, ts, nonce, payload)
    )
}

// ── Control-plane message authentication ──────────────────────────────

/// Verify and strip the authenticated prefix from a control-plane Pub/Sub
/// payload.
///
/// Wire format: `v1:<ts>:<hmac-hex>:<payload>` — the signature covers
/// `<ts>:<payload>`, so payloads containing colons (JSON with timestamps)
/// verify correctly and the timestamp cannot be swapped without breaking the
/// signature. Messages older than [`MAX_MESSAGE_AGE_SECS`] (replay) or
/// further ahead than [`MAX_FUTURE_SKEW_SECS`] are rejected (RT-4). The
/// pre-v1 cleartoken format is rejected: a rolling-upgrade window may drop
/// point-in-time reload commands once, which self-heals on the next change,
/// while accepting cleartext would keep the "read an old entry, recover the
/// token" hole open.
///
/// `expected_token` should be read once at startup from `INTERNAL_API_TOKEN`.
///
/// # Return value
/// * `Some(payload)` — timestamp within the window and signature matched.
/// * `None` — token not configured, malformed, stale, or mismatched; caller
///   should log a warning and skip the message.
pub fn verify_cmd_payload<'a>(raw: &'a str, expected_token: &str) -> Option<&'a str> {
    if expected_token.is_empty() {
        return None;
    }
    let rest = raw.strip_prefix(AUTH_SCHEME_V1)?.strip_prefix(':')?;
    let (ts, remainder) = rest.split_once(':')?;
    let ts: i64 = ts.parse().ok()?;
    let (nonce, remainder) = remainder.split_once(':')?;
    let (signature, payload) = remainder.split_once(':')?;
    if !is_valid_nonce(nonce) {
        return None;
    }
    let now = unix_now_secs();
    if !ts_within_window(ts, now) {
        return None;
    }
    if !verify_v1_signature_hex(signature, expected_token, ts, nonce, payload.as_bytes()) {
        return None;
    }
    // RT-4 round-5: reject a verified-but-already-seen message (replay).
    replay_guard().check_and_record(nonce, now).then_some(payload)
}

/// Constant-time check of a bare `<hmac-hex>` against `v1` scheme expectations.
fn verify_v1_signature_hex(hex: &str, key: &str, ts: i64, nonce: &str, payload: &[u8]) -> bool {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let expected = sign_v1_hex(key, ts, nonce, payload);
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let provided_hash = Sha256::digest(hex.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    provided_hash.ct_eq(&expected_hash).unwrap_u8() == 1
}

// ── Data-plane message authentication (C1) ──────────────────────────────

/// JSON key carrying the shared token inside a data-plane Pub/Sub envelope.
/// The name is deliberately distinctive so legitimate business payloads never
/// collide with it.
pub const DATA_ENVELOPE_AUTH_KEY: &str = "__vigilyx_auth";
/// JSON key carrying the actual payload inside a data-plane Pub/Sub envelope.
pub const DATA_ENVELOPE_PAYLOAD_KEY: &str = "payload";
/// JSON key carrying the signing timestamp (unix seconds, RT-4 replay bound).
pub const DATA_ENVELOPE_TS_KEY: &str = "__vigilyx_ts";
/// JSON key carrying the per-message nonce (RT-4 round-5 replay elimination).
pub const DATA_ENVELOPE_NONCE_KEY: &str = "__vigilyx_nonce";

/// Read the shared data-plane token (`INTERNAL_API_TOKEN`).
///
/// Returns `None` when unset/empty: the producer then sends legacy unsigned
/// payloads and consumers accept everything (dual-mode rollout window).
pub fn data_plane_token() -> Option<String> {
    std::env::var("INTERNAL_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

/// Wrap a serialized data-plane payload in an authenticated envelope:
/// `{"__vigilyx_auth":"v1:<hmac-hex>","payload":<canonical-json>}`.
///
/// The signature covers the canonical re-serialization of the payload through
/// `serde_json::Value` (deterministic key ordering), and that same canonical
/// form is what gets embedded, so consumers re-serialize the extracted value
/// identically before verifying. The shared token itself is never placed on
/// the wire.
///
/// Without a configured token the bare JSON is sent unchanged; consumers in
/// that mode accept it but log at error level — tokenless deployments have an
/// unauthenticated data plane by construction.
pub fn wrap_data_payload(json: &str) -> String {
    match data_plane_token() {
        Some(token) => {
            let canonical = serde_json::from_str::<serde_json::Value>(json)
                .and_then(|value| serde_json::to_string(&value))
                .unwrap_or_else(|_| json.to_string());
            let ts = unix_now_secs();
            let nonce = fresh_nonce();
            let auth = sign_v1(&token, ts, &nonce, canonical.as_bytes());
            format!(
                "{{\"{DATA_ENVELOPE_AUTH_KEY}\":\"{auth}\",\"{DATA_ENVELOPE_TS_KEY}\":{ts},\"{DATA_ENVELOPE_NONCE_KEY}\":\"{nonce}\",\"{DATA_ENVELOPE_PAYLOAD_KEY}\":{canonical}}}"
            )
        }
        None => {
            static MISSING_TOKEN_WARNED: AtomicBool = AtomicBool::new(false);
            if !MISSING_TOKEN_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "INTERNAL_API_TOKEN not set — publishing data-plane messages without authentication (legacy mode)"
                );
            }
            json.to_string()
        }
    }
}

/// Outcome of authenticating a data-plane Pub/Sub payload.
pub enum DataPayloadAuth<'a> {
    /// Authenticated envelope; carries the inner payload JSON (re-serialized
    /// from the envelope, so it is exactly what the producer signed).
    Verified(String),
    /// Bare payload without an envelope, accepted only because no token is
    /// configured (explicitly insecure mode). With a token configured this
    /// variant is never produced — unsigned traffic is `Rejected`.
    Legacy(&'a str),
    /// Unsigned/cleartext/badly signed envelope: treat as a forged message
    /// and drop it.
    Rejected,
}

/// Authenticate a data-plane Pub/Sub payload and unwrap its envelope.
///
/// `expected_token` should be read once at startup from `INTERNAL_API_TOKEN`.
/// With a token configured this fails closed: only a valid `v1` HMAC over the
/// canonical payload serialization is accepted (SEC M-2).
pub fn verify_data_payload<'a>(raw: &'a str, expected_token: &str) -> DataPayloadAuth<'a> {
    if expected_token.is_empty() {
        return DataPayloadAuth::Legacy(raw);
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw)
    else {
        return DataPayloadAuth::Rejected;
    };
    let Some(auth) = map.get(DATA_ENVELOPE_AUTH_KEY).and_then(|v| v.as_str()) else {
        return DataPayloadAuth::Rejected;
    };
    let Some(ts) = map.get(DATA_ENVELOPE_TS_KEY).and_then(|v| v.as_i64()) else {
        return DataPayloadAuth::Rejected;
    };
    let Some(nonce) = map
        .get(DATA_ENVELOPE_NONCE_KEY)
        .and_then(|v| v.as_str())
        .filter(|n| is_valid_nonce(n))
    else {
        return DataPayloadAuth::Rejected;
    };
    let Some(payload) = map.get(DATA_ENVELOPE_PAYLOAD_KEY) else {
        return DataPayloadAuth::Rejected;
    };
    let now = unix_now_secs();
    if !ts_within_window(ts, now) {
        return DataPayloadAuth::Rejected;
    }
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    if !verify_v1_field(auth, expected_token, ts, nonce, canonical.as_bytes()) {
        return DataPayloadAuth::Rejected;
    }
    // RT-4 round-5: a re-published copy of an already-delivered message dies
    // here even inside the freshness window.
    if !replay_guard().check_and_record(nonce, now) {
        return DataPayloadAuth::Rejected;
    }
    DataPayloadAuth::Verified(canonical)
}

/// Constant-time verification of a full `v1:<hex>` auth field over
/// `<ts>:<nonce>:<payload>`.
pub(crate) fn verify_v1_field(
    auth_field: &str,
    key: &str,
    ts: i64,
    nonce: &str,
    payload: &[u8],
) -> bool {
    let Some(hex) = auth_field
        .strip_prefix(AUTH_SCHEME_V1)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return false;
    };
    verify_v1_signature_hex(hex, key, ts, nonce, payload)
}

#[cfg(test)]
mod cmd_auth_tests {
    use super::{AUTH_SCHEME_V1, sign_v1_hex, unix_now_secs, verify_cmd_payload};

    fn signed_cmd(token: &str, payload: &str) -> String {
        signed_cmd_full(token, payload, unix_now_secs(), &fresh_test_nonce())
    }

    fn signed_cmd_at(token: &str, payload: &str, ts: i64) -> String {
        signed_cmd_full(token, payload, ts, &fresh_test_nonce())
    }

    fn signed_cmd_full(token: &str, payload: &str, ts: i64, nonce: &str) -> String {
        format!(
            "{AUTH_SCHEME_V1}:{ts}:{nonce}:{}:{payload}",
            sign_v1_hex(token, ts, nonce, payload.as_bytes())
        )
    }

    fn fresh_test_nonce() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn test_valid_signature() {
        let raw = signed_cmd("my-secret", r#"{"target":"ioc"}"#);
        assert!(
            !raw.contains(":v1:"),
            "control frame must contain the scheme marker exactly once"
        );
        let result = verify_cmd_payload(&raw, "my-secret");
        assert_eq!(result, Some(r#"{"target":"ioc"}"#));
    }

    #[test]
    fn test_invalid_signature() {
        let raw = signed_cmd("wrong-token", r#"{"target":"ioc"}"#);
        assert_eq!(verify_cmd_payload(&raw, "my-secret"), None);
    }

    #[test]
    fn test_no_token_configured_rejects_all() {
        assert_eq!(verify_cmd_payload(r#""whitelist""#, ""), None);
        assert_eq!(verify_cmd_payload(r#"v1:ab:{"x":1}"#, ""), None);
    }

    #[test]
    fn test_cleartext_legacy_format_rejected_when_token_configured() {
        // PoC (M-2): the pre-v1 format put the shared token itself on the
        // wire. A consumer that still accepted it would let an attacker
        // recover the token from an old stream entry and forge commands.
        assert_eq!(verify_cmd_payload(r#"my-secret:{"x":1}"#, "my-secret"), None);
        assert_eq!(verify_cmd_payload(r#""whitelist""#, "my-secret"), None);
    }

    #[test]
    fn test_payload_with_colons() {
        // Payload itself contains colons (e.g. JSON with timestamps): the
        // split happens at the second colon of the v1 frame only.
        let raw = signed_cmd("my-secret", r#"{"time":"2026-03-20T12:00:00Z"}"#);
        let result = verify_cmd_payload(&raw, "my-secret");
        assert_eq!(result, Some(r#"{"time":"2026-03-20T12:00:00Z"}"#));
    }

    #[test]
    fn test_malformed_signature_rejected() {
        let now = unix_now_secs();
        assert_eq!(verify_cmd_payload("v1:zz:{}", "my-secret"), None);
        assert_eq!(verify_cmd_payload("v1:{}", "my-secret"), None);
        assert_eq!(
            verify_cmd_payload(&format!("v1:{now}:not-hex:{{}}"), "my-secret"),
            None
        );
        let mut raw = signed_cmd_at("my-secret", "{}", now);
        // signature starts after "v1:<ts>:<nonce>" — corrupt one hex digit
        let sig_start = AUTH_SCHEME_V1.len() + 1 + now.to_string().len() + 1 + 32 + 1;
        let replacement = if &raw[sig_start..sig_start + 1] == "0" {
            "1"
        } else {
            "0"
        };
        raw.replace_range(sig_start..sig_start + 1, replacement);
        assert_eq!(verify_cmd_payload(&raw, "my-secret"), None);
    }

    #[test]
    fn rt4_replayed_cmd_past_window_is_rejected() {
        // PoC (RT-4): a captured command replayed after the freshness window
        // must be dropped even though its signature is valid.
        let stale_ts = unix_now_secs() - super::MAX_MESSAGE_AGE_SECS - 1;
        let raw = signed_cmd_at("my-secret", r#"{"target":"ioc"}"#, stale_ts);
        assert_eq!(verify_cmd_payload(&raw, "my-secret"), None);
    }

    #[test]
    fn rt4_far_future_cmd_is_rejected() {
        let future_ts = unix_now_secs() + super::MAX_FUTURE_SKEW_SECS + 1;
        let raw = signed_cmd_at("my-secret", "{}", future_ts);
        assert_eq!(verify_cmd_payload(&raw, "my-secret"), None);
    }

    #[test]
    fn rt4_round5_same_nonce_resubmission_is_rejected() {
        // PoC (RT-4 round-5): a captured command re-published verbatim inside
        // the freshness window dies at the process-wide nonce dedup.
        let nonce = fresh_test_nonce();
        let raw = signed_cmd_full("my-secret", r#"{"target":"ioc"}"#, unix_now_secs(), &nonce);
        assert!(verify_cmd_payload(&raw, "my-secret").is_some(), "first delivery");
        assert!(
            verify_cmd_payload(&raw, "my-secret").is_none(),
            "verbatim replay of the same nonce must be rejected"
        );
        // A fresh nonce on the same payload is a new message and passes.
        let fresh = signed_cmd("my-secret", r#"{"target":"ioc"}"#);
        assert!(verify_cmd_payload(&fresh, "my-secret").is_some());
    }

    #[test]
    fn rt4_timestamp_cannot_be_swapped() {
        // The signature binds the timestamp: re-dating a captured command
        // breaks verification even inside the window.
        let now = unix_now_secs();
        let raw = signed_cmd_at("my-secret", "{}", now - 30);
        let newer = raw.replacen(
            &format!("{AUTH_SCHEME_V1}:{}", now - 30),
            &format!("{AUTH_SCHEME_V1}:{now}"),
            1,
        );
        assert_ne!(raw, newer);
        assert_eq!(verify_cmd_payload(&newer, "my-secret"), None);
        assert!(verify_cmd_payload(&raw, "my-secret").is_some());
    }
}

#[cfg(test)]
mod data_auth_tests {
    use super::{
        DataPayloadAuth, MAX_FUTURE_SKEW_SECS, MAX_MESSAGE_AGE_SECS, sign_v1, unix_now_secs,
        verify_data_payload, wrap_data_payload,
    };

    fn envelope_at(token: &str, ts: i64, json: &str) -> String {
        envelope_full(token, ts, &fresh_test_nonce(), json)
    }

    fn envelope_full(token: &str, ts: i64, nonce: &str, json: &str) -> String {
        let canonical = serde_json::from_str::<serde_json::Value>(json)
            .and_then(|v| serde_json::to_string(&v))
            .unwrap_or_else(|_| json.to_string());
        format!(
            r#"{{"__vigilyx_auth":"{}","__vigilyx_ts":{ts},"__vigilyx_nonce":"{nonce}","payload":{canonical}}}"#,
            sign_v1(token, ts, nonce, canonical.as_bytes())
        )
    }

    fn fresh_test_nonce() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    fn assert_json_semantically_equal(actual: &str, expected: &str) {
        let actual: serde_json::Value =
            serde_json::from_str(actual).expect("verified payload must remain valid JSON");
        let expected: serde_json::Value =
            serde_json::from_str(expected).expect("test expectation must be valid JSON");
        assert_eq!(actual, expected);
    }

    #[test]
    fn signed_envelope_round_trips() {
        let json = r#"{"threat_level":"critical","score":0.97}"#;
        let raw = envelope_at("env-token-for-test", unix_now_secs(), json);
        match verify_data_payload(&raw, "env-token-for-test") {
            DataPayloadAuth::Verified(inner) => assert_json_semantically_equal(&inner, json),
            _ => panic!("signed envelope must verify"),
        }
    }

    #[test]
    fn wrap_uses_hmac_not_cleartext_token() {
        // PoC (M-2): the produced envelope must authenticate without ever
        // embedding the shared token itself.
        // SAFETY: single-threaded unit test; no other test reads this var.
        unsafe {
            std::env::set_var("INTERNAL_API_TOKEN", "env-token-for-wrap-test");
        }
        let wrapped = wrap_data_payload(r#"{"a":1}"#);
        // SAFETY: see above.
        unsafe {
            std::env::remove_var("INTERNAL_API_TOKEN");
        }
        assert!(!wrapped.contains("env-token-for-wrap-test"));
        match verify_data_payload(&wrapped, "env-token-for-wrap-test") {
            DataPayloadAuth::Verified(inner) => assert_eq!(inner, r#"{"a":1}"#),
            _ => panic!("wrapped envelope must verify against the signing token"),
        }
    }

    #[test]
    fn forged_envelope_with_wrong_token_is_rejected() {
        // PoC (C1/M-2): an attacker with bare Redis access publishes a fake
        // critical verdict; without verification it flowed straight to every
        // operator's WebSocket alert stream.
        let payload = r#"{"subject":"您的账户已被冻结，请立即验证","threat_level":"critical"}"#;
        let forged = envelope_at("guessed-token", unix_now_secs(), payload);
        assert!(matches!(
            verify_data_payload(&forged, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn rt4_replayed_envelope_past_window_is_rejected() {
        // PoC (RT-4): replaying a captured verdict/alert after the freshness
        // window must not reach WebSocket clients even with a valid signature.
        let stale_ts = unix_now_secs() - MAX_MESSAGE_AGE_SECS - 1;
        let replayed = envelope_at("env-token-for-test", stale_ts, r#"{"a":1}"#);
        assert!(matches!(
            verify_data_payload(&replayed, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn rt4_envelope_without_or_future_ts_is_rejected() {
        let now = unix_now_secs();
        // missing ts
        let nonce = fresh_test_nonce();
        let no_ts = format!(
            r#"{{"__vigilyx_auth":"{}","payload":{{"a":1}}}}"#,
            sign_v1("env-token-for-test", now, &nonce, r#"{"a":1}"#.as_bytes())
        );
        assert!(matches!(
            verify_data_payload(&no_ts, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
        // far future
        let future = envelope_at(
            "env-token-for-test",
            now + MAX_FUTURE_SKEW_SECS + 1,
            r#"{"a":1}"#,
        );
        assert!(matches!(
            verify_data_payload(&future, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn unsigned_and_cleartext_envelopes_rejected_when_token_configured() {
        // PoC (M-2 fail-closed): with a token configured, unsigned payloads
        // and the legacy cleartoken envelope are forged traffic, not legacy
        // producers — every in-repo producer signs with the same binary.
        assert!(matches!(
            verify_data_payload(r#"{"a":1}"#, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
        assert!(matches!(
            verify_data_payload(
                r#"{"__vigilyx_auth":"env-token-for-test","payload":{"a":1}}"#,
                "env-token-for-test"
            ),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn unsigned_payload_accepted_only_without_token() {
        // Explicitly insecure mode: tokenless deployments keep an
        // unauthenticated data plane (documented in the ADR).
        assert!(matches!(
            verify_data_payload(r#"{"a":1}"#, ""),
            DataPayloadAuth::Legacy(r#"{"a":1}"#)
        ));
    }

    #[test]
    fn rt4_round5_envelope_replay_same_nonce_is_rejected() {
        // PoC (RT-4 round-5): a re-published verdict/alert with the same
        // nonce dies at the dedup even inside the freshness window.
        let nonce = fresh_test_nonce();
        let raw = envelope_full("env-token-for-test", unix_now_secs(), &nonce, r#"{"a":1}"#);
        assert!(matches!(
            verify_data_payload(&raw, "env-token-for-test"),
            DataPayloadAuth::Verified(_)
        ));
        assert!(matches!(
            verify_data_payload(&raw, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn envelope_key_order_is_irrelevant_to_signature() {
        // The producer canonicalizes through serde_json::Value; a consumer
        // re-serializes the extracted value the same way, so equivalent JSON
        // with different key order still verifies when signed canonically.
        let raw = envelope_at("env-token-for-test", unix_now_secs(), r#"{"b":2,"a":1}"#);
        match verify_data_payload(&raw, "env-token-for-test") {
            DataPayloadAuth::Verified(inner) => {
                assert_json_semantically_equal(&inner, r#"{"a":1,"b":2}"#)
            }
            _ => panic!("canonically signed envelope must verify"),
        }
    }

    #[test]
    fn envelope_without_payload_is_rejected() {
        let raw = r#"{"__vigilyx_auth":"env-token-for-test"}"#;
        assert!(matches!(
            verify_data_payload(raw, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn legacy_bare_payload_is_rejected_when_token_configured() {
        // The accepted security boundary intentionally has no dual-mode
        // rollout once a token is configured: otherwise Redis write access
        // can bypass authentication with a bare payload.
        let legacy = r#"{"threat_level":"high"}"#;
        assert!(matches!(
            verify_data_payload(legacy, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn non_object_payload_is_rejected_when_token_configured() {
        // A bare JSON string is just as unsigned as a bare object. In-repo
        // publishers wrap it in an authenticated envelope before PUBLISH.
        let alert = r#""P1: phishing verdict for session abc""#;
        assert!(matches!(
            verify_data_payload(alert, "env-token-for-test"),
            DataPayloadAuth::Rejected
        ));
    }

    #[test]
    fn no_configured_token_accepts_everything_as_legacy() {
        let raw = r#"{"__vigilyx_auth":"x","payload":{}}"#;
        assert!(matches!(
            verify_data_payload(raw, ""),
            DataPayloadAuth::Legacy(_)
        ));
    }

    #[test]
    fn wrap_without_token_returns_bare_json() {
        // Only meaningful when INTERNAL_API_TOKEN is unset; guard so a
        // contaminated test environment cannot make it spuriously fail.
        if super::data_plane_token().is_some() {
            return;
        }
        let json = r#"{"ok":true}"#;
        assert_eq!(wrap_data_payload(json), json);
    }
}

#[cfg(test)]
mod sid_user_tests {
    use super::{MqClient, build_sid_user_set_pipe};

    #[test]
    fn sid_user_batch_pipe_refreshes_24h_ttl() {
        // F3 regression: previously the hash was written with no TTL, so one
        // poisoning persisted indefinitely and was reloaded after restarts.
        let pipe = build_sid_user_set_pipe(&[
            ("sid-1".to_string(), "alice".to_string()),
            ("sid-2".to_string(), "bob".to_string()),
        ]);
        let commands: Vec<Vec<Vec<u8>>> = pipe
            .cmd_iter()
            .map(|cmd| {
                cmd.args_iter()
                    .filter_map(|arg| match arg {
                        redis::Arg::Simple(bytes) => Some(bytes.to_vec()),
                        _ => None,
                    })
                    .collect()
            })
            .collect();

        assert_eq!(commands.len(), 3, "expected 2 HSET + 1 EXPIRE");
        assert_eq!(commands[0][0], b"HSET");
        assert_eq!(commands[1][0], b"HSET");
        let expire = &commands[2];
        assert_eq!(expire[0], b"EXPIRE");
        assert_eq!(expire[1], MqClient::SID_USER_KEY.as_bytes());
        assert_eq!(
            expire[2],
            (MqClient::SID_USER_TTL_SECS as i64).to_string().as_bytes()
        );
    }
}
