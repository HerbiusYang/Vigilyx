//! Message Queue Client

//! Performance Optimizations:
//! - Connection pool management
//! - Batch operations (Pipeline)
//! - Automatic reconnection
//! - Message compression (for large messages)

use super::error::{MqError, MqResult};
use super::topics;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use vigilyx_core::{EmailSession, TrafficStats};

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

   /// Try connect
    async fn try_connect(&self) -> MqResult<()> {
        let client = Client::open(self.config.redis_url.clone())?;
        let conn = ConnectionManager::new(client).await?;

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

   /// Publish message to Pub/Sub channel (with retry)
    pub async fn publish<T: Serialize>(&self, topic: &str, message: &T) -> MqResult<()> {
        let json = serde_json::to_string(message)?;
        let mut retries = 0;

        loop {
            let mut conn = self.get_conn().await?;

            match conn.publish::<_, _, ()>(topic, &json).await {
                Ok(_) => {
                    self.sent_count.fetch_add(1, Ordering::Relaxed);
                    debug!("Published to {}: {} bytes", topic, json.len());
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

   /// Publish message to Stream
    pub async fn xadd<T: Serialize>(&self, stream: &str, message: &T) -> MqResult<String> {
        let mut conn = self.get_conn().await?;
        let json = serde_json::to_string(message)?;

       // XADD with MAXLEN
        let id: String = redis::cmd("XADD")
            .arg(stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(self.config.stream_max_len)
            .arg("*")
            .arg("data")
            .arg(&json)
            .query_async(&mut conn)
            .await?;

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
   // Comment retained in English.
   // Architecture simplification: use only Pub/Sub for real-time notifications
   // Persistence handled by API layer writing to PostgreSQL
   // Comment retained in English.

   /// Publish new session (notification only, do not persist to Redis)
    pub async fn publish_session(&self, session: &EmailSession) -> MqResult<()> {
        self.publish(topics::SESSION_NEW, session).await
    }

   /// Publish session update
    pub async fn publish_session_update(&self, session: &EmailSession) -> MqResult<()> {
        self.publish(topics::SESSION_UPDATE, session).await
    }

   /// Publish stats update
    pub async fn publish_stats(&self, stats: &TrafficStats) -> MqResult<()> {
        self.publish(topics::STATS_UPDATE, stats).await
    }

   // ==================== Batch publish methods (performance optimization) ====================

   /// Batch publish sessions (using Redis Pipeline, process large batches in chunks)
    pub async fn publish_sessions_batch(&self, sessions: &[EmailSession]) -> MqResult<usize> {
        if sessions.is_empty() {
            return Ok(0);
        }

        let mut total_sent = 0;
        let batch_size = self.config.batch_size;

       // Process in chunks to avoid single Pipeline being too large
        for chunk in sessions.chunks(batch_size) {
            let sent = self.publish_sessions_chunk(chunk).await?;
            total_sent += sent;
        }

        debug!("Batch published {} sessions", total_sent);
        Ok(total_sent)
    }

   /// Publish a batch of sessions (internal method)
    async fn publish_sessions_chunk(&self, sessions: &[EmailSession]) -> MqResult<usize> {
        let mut conn = self.get_conn().await?;
        let mut pipe = redis::pipe();

        for session in sessions {
            let json = serde_json::to_string(session)?;
            pipe.publish(topics::SESSION_NEW, &json).ignore();
        }

        match pipe.query_async::<()>(&mut conn).await {
            Ok(_) => {
                self.sent_count
                    .fetch_add(sessions.len() as u64, Ordering::Relaxed);
                Ok(sessions.len())
            }
            Err(e) => {
                self.error_count
                    .fetch_add(sessions.len() as u64, Ordering::Relaxed);
                Err(MqError::Redis(e))
            }
        }
    }

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

   /// Write sid -> user mapping to Redis Hash (single entry)
    pub async fn sid_user_set(&self, sid: &str, user: &str) -> MqResult<()> {
        let mut conn = self.get_conn().await?;
        redis::cmd("HSET")
            .arg(Self::SID_USER_KEY)
            .arg(sid)
            .arg(user)
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
        let mut pipe = redis::pipe();
        for (sid, user) in entries {
            pipe.hset(Self::SID_USER_KEY, sid, user).ignore();
        }
        pipe.query_async::<()>(&mut conn).await?;
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
