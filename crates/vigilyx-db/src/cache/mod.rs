//! Shared read-cache client for bounded operational aggregates.
//!
//! This module is deliberately separate from [`crate::mq`].  The message bus
//! owns Streams, PEL/DLQ, heartbeats, and Pub/Sub and must remain `noeviction`.
//! This client only speaks to the optional, independently deployed read-cache
//! Valkey instance.  Cache errors are returned to the caller so the API can
//! fall back to PostgreSQL; no Engine, Sniffer, or MTA path uses this module.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::debug;

pub const READ_CACHE_SCHEMA_VERSION: u16 = 2;
pub const READ_CACHE_MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Only pre-registered datasets can be used to construct a cache key.
/// There is intentionally no free-form user input in this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheDataset {
    SecurityOverview24h,
    DeliveryComparisonAllHistory,
    ExternalLogin24h,
    SessionCounts,
}

impl CacheDataset {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SecurityOverview24h => "security_overview",
            Self::DeliveryComparisonAllHistory => "delivery_comparison",
            Self::ExternalLogin24h => "external_login",
            Self::SessionCounts => "session_counts",
        }
    }

    pub const fn window(self) -> &'static str {
        match self {
            Self::SecurityOverview24h | Self::ExternalLogin24h => "24h",
            Self::DeliveryComparisonAllHistory => "all_history",
            Self::SessionCounts => "current",
        }
    }

    pub const fn fresh_ttl_secs(self) -> u64 {
        match self {
            Self::SecurityOverview24h => 15,
            Self::DeliveryComparisonAllHistory => 30,
            Self::ExternalLogin24h => 60,
            Self::SessionCounts => 30,
        }
    }

    pub const fn hard_ttl_secs(self) -> u64 {
        match self {
            Self::SecurityOverview24h => 120,
            Self::DeliveryComparisonAllHistory => 180,
            Self::ExternalLogin24h => 600,
            Self::SessionCounts => 300,
        }
    }
}

/// A typed, versioned key.  Callers cannot insert email addresses, subjects,
/// IP search terms, or arbitrary filters into the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    dataset: CacheDataset,
}

impl CacheKey {
    pub const fn security_overview() -> Self {
        Self {
            dataset: CacheDataset::SecurityOverview24h,
        }
    }

    pub const fn delivery_comparison() -> Self {
        Self {
            dataset: CacheDataset::DeliveryComparisonAllHistory,
        }
    }

    pub const fn external_login() -> Self {
        Self {
            dataset: CacheDataset::ExternalLogin24h,
        }
    }

    pub const fn session_counts() -> Self {
        Self {
            dataset: CacheDataset::SessionCounts,
        }
    }

    pub const fn dataset(self) -> CacheDataset {
        self.dataset
    }

    /// Render the versioned Redis key for infrastructure tests and operator
    /// tooling. Production call sites should continue using the typed client.
    pub fn redis_key(self, deployment_id: &str) -> String {
        self.value(deployment_id)
    }

    fn value(self, deployment_id: &str) -> String {
        format!(
            "vigilyx:{deployment_id}:readcache:v{READ_CACHE_SCHEMA_VERSION}:{}:{}:default",
            self.dataset.slug(),
            self.dataset.window()
        )
    }

    fn lock_value(self, deployment_id: &str) -> String {
        format!(
            "vigilyx:{deployment_id}:readcache:v{READ_CACHE_SCHEMA_VERSION}:lock:{}:{}:default",
            self.dataset.slug(),
            self.dataset.window()
        )
    }
}

/// Cache payload envelope.  Timestamps are validated on every read instead of
/// relying only on Valkey key expiry, because a stale value must never be
/// extended accidentally by a layer-specific TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEnvelope<T> {
    pub schema_version: u16,
    pub generated_at: DateTime<Utc>,
    pub fresh_until: DateTime<Utc>,
    pub hard_expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_watermark: Option<String>,
    pub data: T,
}

impl<T> CacheEnvelope<T> {
    pub fn for_dataset(dataset: CacheDataset, data: T, source_watermark: Option<String>) -> Self {
        let generated_at = Utc::now();
        let fresh_ttl = jittered_fresh_ttl(dataset.fresh_ttl_secs());
        let hard_ttl = dataset.hard_ttl_secs();
        Self {
            schema_version: READ_CACHE_SCHEMA_VERSION,
            generated_at,
            fresh_until: generated_at + ChronoDuration::seconds(fresh_ttl),
            hard_expires_at: generated_at + ChronoDuration::seconds(hard_ttl as i64),
            source_watermark,
            data,
        }
    }

    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        self.is_well_formed(now) && now < self.fresh_until
    }

    pub fn is_within_hard_ttl(&self, now: DateTime<Utc>) -> bool {
        self.is_well_formed(now) && now < self.hard_expires_at
    }

    fn is_well_formed(&self, now: DateTime<Utc>) -> bool {
        self.schema_version == READ_CACHE_SCHEMA_VERSION
            && self.generated_at <= now
            && self.generated_at <= self.fresh_until
            && self.fresh_until <= self.hard_expires_at
    }
}

fn jittered_fresh_ttl(base_secs: u64) -> i64 {
    let jitter = (base_secs / 10).max(1) as i64;
    let span = (jitter * 2 + 1) as u32;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or_default();
    base_secs as i64 + (i64::from(nanos % span) - jitter)
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("read-cache Redis operation failed")]
    Redis(#[from] redis::RedisError),
    #[error("read-cache payload serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("read-cache operation timed out")]
    Timeout,
    #[error("read-cache payload exceeds {limit} bytes (actual {actual})")]
    PayloadTooLarge { limit: usize, actual: usize },
    #[error("read-cache schema version is unsupported: {0}")]
    UnsupportedSchema(u16),
}

/// Configuration for the independent Valkey read-cache instance.
#[derive(Clone)]
pub struct ReadCacheConfig {
    enabled: bool,
    shadow_write: bool,
    redis_url: String,
    deployment_id: String,
    operation_timeout: Duration,
    refresh_lease_secs: u64,
    max_payload_bytes: usize,
    security_stats_enabled: bool,
    security_stats_shadow_write: bool,
    delivery_stats_enabled: bool,
    login_stats_enabled: bool,
    session_counts_enabled: bool,
}

impl fmt::Debug for ReadCacheConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadCacheConfig")
            .field("enabled", &self.enabled)
            .field("shadow_write", &self.shadow_write)
            .field("redis_url", &mask_redis_url(&self.redis_url))
            .field("deployment_id", &self.deployment_id)
            .field("operation_timeout", &self.operation_timeout)
            .field("refresh_lease_secs", &self.refresh_lease_secs)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("security_stats_enabled", &self.security_stats_enabled)
            .field(
                "security_stats_shadow_write",
                &self.security_stats_shadow_write,
            )
            .field("delivery_stats_enabled", &self.delivery_stats_enabled)
            .field("login_stats_enabled", &self.login_stats_enabled)
            .field("session_counts_enabled", &self.session_counts_enabled)
            .finish()
    }
}

impl ReadCacheConfig {
    pub fn from_env() -> Result<Self, String> {
        let enabled = env_bool("READ_CACHE_ENABLED", false);
        let shadow_write = env_bool("READ_CACHE_SHADOW_WRITE", false);
        let security_stats_enabled = env_bool("CACHE_SECURITY_STATS_ENABLED", false);
        let security_stats_shadow_write = env_bool("CACHE_SECURITY_STATS_SHADOW_WRITE", false);
        let delivery_stats_enabled = env_bool("CACHE_DELIVERY_STATS_ENABLED", false);
        let login_stats_enabled = env_bool("CACHE_LOGIN_STATS_ENABLED", false);
        let session_counts_enabled = env_bool("CACHE_SESSION_COUNTS_ENABLED", false);
        let active = enabled || shadow_write || security_stats_shadow_write;

        let deployment_id = std::env::var("CACHE_DEPLOYMENT_ID")
            .unwrap_or_else(|_| "default".to_string())
            .trim()
            .to_string();
        if deployment_id.is_empty()
            || deployment_id.len() > 64
            || !deployment_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(
                "CACHE_DEPLOYMENT_ID must contain only [A-Za-z0-9._-] and be <=64 bytes"
                    .to_string(),
            );
        }

        let operation_timeout_ms = parse_u64("CACHE_OPERATION_TIMEOUT_MS", 150)?;
        if !(10..=5_000).contains(&operation_timeout_ms) {
            return Err("CACHE_OPERATION_TIMEOUT_MS must be between 10 and 5000".to_string());
        }
        let refresh_lease_secs = parse_u64("CACHE_REFRESH_LEASE_SECS", 45)?;
        if !(1..=300).contains(&refresh_lease_secs) {
            return Err("CACHE_REFRESH_LEASE_SECS must be between 1 and 300".to_string());
        }
        let max_payload_bytes = parse_u64(
            "CACHE_MAX_PAYLOAD_BYTES",
            READ_CACHE_MAX_PAYLOAD_BYTES as u64,
        )? as usize;
        if !(1..=READ_CACHE_MAX_PAYLOAD_BYTES).contains(&max_payload_bytes) {
            return Err(format!(
                "CACHE_MAX_PAYLOAD_BYTES must be between 1 and {}",
                READ_CACHE_MAX_PAYLOAD_BYTES
            ));
        }

        let password = std::env::var("CACHE_REDIS_PASSWORD").unwrap_or_default();
        if active && password.is_empty() {
            return Err(
                "CACHE_REDIS_PASSWORD must be set before enabling the read cache".to_string(),
            );
        }

        let redis_url = if let Ok(url) = std::env::var("CACHE_REDIS_URL") {
            if url.trim().is_empty() {
                return Err("CACHE_REDIS_URL cannot be empty when provided".to_string());
            }
            url
        } else {
            let host = std::env::var("CACHE_REDIS_HOST").unwrap_or_else(|_| "cache".to_string());
            if host.is_empty() || host.chars().any(char::is_whitespace) || host.contains('@') {
                return Err("CACHE_REDIS_HOST contains invalid characters".to_string());
            }
            let port = parse_u64("CACHE_REDIS_PORT", 6379)?;
            if !(1..=65_535).contains(&port) {
                return Err("CACHE_REDIS_PORT must be between 1 and 65535".to_string());
            }
            if password.is_empty() {
                format!("redis://{host}:{port}")
            } else {
                format!("redis://:{}@{host}:{port}", percent_encode(&password))
            }
        };

        Ok(Self {
            enabled,
            shadow_write,
            redis_url,
            deployment_id,
            operation_timeout: Duration::from_millis(operation_timeout_ms),
            refresh_lease_secs,
            max_payload_bytes,
            security_stats_enabled,
            security_stats_shadow_write,
            delivery_stats_enabled,
            login_stats_enabled,
            session_counts_enabled,
        })
    }

    pub fn should_initialize(&self) -> bool {
        self.enabled || self.shadow_write || self.security_stats_shadow_write
    }

    pub fn enabled(&self, dataset: CacheDataset) -> bool {
        self.enabled
            && match dataset {
                CacheDataset::SecurityOverview24h => self.security_stats_enabled,
                CacheDataset::DeliveryComparisonAllHistory => self.delivery_stats_enabled,
                CacheDataset::ExternalLogin24h => self.login_stats_enabled,
                CacheDataset::SessionCounts => self.session_counts_enabled,
            }
    }

    pub fn shadow_write_enabled(&self, dataset: CacheDataset) -> bool {
        (self.shadow_write
            && match dataset {
                CacheDataset::SecurityOverview24h => true,
                CacheDataset::DeliveryComparisonAllHistory => self.delivery_stats_enabled,
                CacheDataset::ExternalLogin24h => self.login_stats_enabled,
                CacheDataset::SessionCounts => self.session_counts_enabled,
            })
            || match dataset {
                CacheDataset::SecurityOverview24h => self.security_stats_shadow_write,
                _ => false,
            }
    }

    pub fn redis_url(&self) -> &str {
        &self.redis_url
    }

    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    pub fn refresh_lease_secs(&self) -> u64 {
        self.refresh_lease_secs
    }

    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    #[cfg(feature = "infra-tests")]
    pub fn for_integration_test(redis_url: String, deployment_id: String) -> Self {
        Self {
            enabled: true,
            shadow_write: true,
            redis_url,
            deployment_id,
            operation_timeout: Duration::from_secs(2),
            refresh_lease_secs: 5,
            max_payload_bytes: READ_CACHE_MAX_PAYLOAD_BYTES,
            security_stats_enabled: true,
            security_stats_shadow_write: true,
            delivery_stats_enabled: true,
            login_stats_enabled: true,
            session_counts_enabled: true,
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(default)
}

fn parse_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn percent_encode(value: &str) -> String {
    value.bytes().fold(String::new(), |mut encoded, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
        encoded
    })
}

fn mask_redis_url(url: &str) -> String {
    let Some(at) = url.rfind('@') else {
        return url.to_string();
    };
    let scheme_end = url.find("://").map(|index| index + 3).unwrap_or(0);
    format!("{}***@{}", &url[..scheme_end], &url[at + 1..])
}

/// Independent read-cache client.  It has no access to the MQ key registry or
/// Stream methods, which makes accidental data-plane use a type-level review
/// boundary.
#[derive(Clone)]
pub struct ReadCacheClient {
    config: ReadCacheConfig,
    conn: Arc<RwLock<Option<ConnectionManager>>>,
}

impl ReadCacheClient {
    pub fn new(config: ReadCacheConfig) -> Self {
        Self {
            config,
            conn: Arc::new(RwLock::new(None)),
        }
    }

    pub fn config(&self) -> &ReadCacheConfig {
        &self.config
    }

    pub async fn warm_up(&self) -> Result<(), CacheError> {
        let mut conn = self.get_conn().await?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        key: CacheKey,
    ) -> Result<Option<CacheEnvelope<T>>, CacheError> {
        let operation = async {
            let mut conn = self.get_conn().await?;
            let raw: Option<String> = conn.get(key.value(self.config.deployment_id())).await?;
            let Some(raw) = raw else {
                return Ok(None);
            };
            let envelope: CacheEnvelope<T> = serde_json::from_str(&raw)?;
            if envelope.schema_version != READ_CACHE_SCHEMA_VERSION {
                return Err(CacheError::UnsupportedSchema(envelope.schema_version));
            }
            if !envelope.is_within_hard_ttl(Utc::now()) {
                return Ok(None);
            }
            Ok(Some(envelope))
        };
        tokio::time::timeout(self.config.operation_timeout(), operation)
            .await
            .map_err(|_| CacheError::Timeout)?
    }

    pub async fn set<T: Serialize>(
        &self,
        key: CacheKey,
        envelope: &CacheEnvelope<T>,
    ) -> Result<usize, CacheError> {
        let payload = serde_json::to_string(envelope)?;
        let payload_bytes = payload.len();
        if payload.len() > self.config.max_payload_bytes() {
            return Err(CacheError::PayloadTooLarge {
                limit: self.config.max_payload_bytes(),
                actual: payload.len(),
            });
        }
        let operation = async {
            let mut conn = self.get_conn().await?;
            conn.set_ex::<_, _, ()>(
                key.value(self.config.deployment_id()),
                payload,
                key.dataset().hard_ttl_secs(),
            )
            .await?;
            Ok::<(), CacheError>(())
        };
        tokio::time::timeout(self.config.operation_timeout(), operation)
            .await
            .map_err(|_| CacheError::Timeout)??;
        Ok(payload_bytes)
    }

    /// Invalidate one registered aggregate after an authoritative management
    /// write. This is intentionally typed and cannot delete arbitrary keys.
    pub async fn delete(&self, key: CacheKey) -> Result<(), CacheError> {
        let operation = async {
            let mut conn = self.get_conn().await?;
            let _: u64 = conn.del(key.value(self.config.deployment_id())).await?;
            Ok::<(), CacheError>(())
        };
        tokio::time::timeout(self.config.operation_timeout(), operation)
            .await
            .map_err(|_| CacheError::Timeout)??;
        Ok(())
    }

    pub async fn try_acquire_refresh_lease(
        &self,
        key: CacheKey,
        token: &str,
    ) -> Result<bool, CacheError> {
        let operation = async {
            let mut conn = self.get_conn().await?;
            let result: Option<String> = redis::cmd("SET")
                .arg(key.lock_value(self.config.deployment_id()))
                .arg(token)
                .arg("NX")
                .arg("EX")
                .arg(self.config.refresh_lease_secs())
                .query_async(&mut conn)
                .await?;
            Ok::<bool, CacheError>(result.as_deref() == Some("OK"))
        };
        tokio::time::timeout(self.config.operation_timeout(), operation)
            .await
            .map_err(|_| CacheError::Timeout)?
    }

    pub async fn release_refresh_lease(
        &self,
        key: CacheKey,
        token: &str,
    ) -> Result<(), CacheError> {
        let operation = async {
            let mut conn = self.get_conn().await?;
            let _: i64 = redis::cmd("EVAL")
                .arg(concat!(
                    "if redis.call('GET', KEYS[1]) == ARGV[1] then ",
                    "return redis.call('DEL', KEYS[1]) else return 0 end"
                ))
                .arg(1)
                .arg(key.lock_value(self.config.deployment_id()))
                .arg(token)
                .query_async(&mut conn)
                .await?;
            Ok::<(), CacheError>(())
        };
        tokio::time::timeout(self.config.operation_timeout(), operation)
            .await
            .map_err(|_| CacheError::Timeout)??;
        Ok(())
    }

    async fn get_conn(&self) -> Result<ConnectionManager, CacheError> {
        if let Some(conn) = self.conn.read().await.as_ref() {
            return Ok(conn.clone());
        }

        let client = Client::open(self.config.redis_url().to_string())?;
        let connection = tokio::time::timeout(
            self.config.operation_timeout(),
            ConnectionManager::new(client),
        )
        .await
        .map_err(|_| CacheError::Timeout)??;

        let mut guard = self.conn.write().await;
        if let Some(conn) = guard.as_ref() {
            Ok(conn.clone())
        } else {
            *guard = Some(connection.clone());
            debug!("read-cache connection established");
            Ok(connection)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_keys_have_bounded_protocol_shape() {
        let key = CacheKey::security_overview().value("prod-01");
        assert_eq!(
            key,
            "vigilyx:prod-01:readcache:v2:security_overview:24h:default"
        );
        assert_eq!(
            CacheKey::delivery_comparison().value("prod-01"),
            "vigilyx:prod-01:readcache:v2:delivery_comparison:all_history:default"
        );
        assert!(!key.contains('@'));
        assert!(!key.contains("subject"));
    }

    #[test]
    fn envelope_hard_ttl_is_longer_than_jittered_fresh_ttl() {
        let envelope = CacheEnvelope::for_dataset(
            CacheDataset::SecurityOverview24h,
            serde_json::json!({"safe": 1}),
            Some("watermark-1".to_string()),
        );
        assert!(envelope.fresh_until > envelope.generated_at);
        assert!(envelope.hard_expires_at > envelope.fresh_until);
        assert!(envelope.is_fresh(envelope.generated_at));
        assert!(envelope.is_within_hard_ttl(envelope.fresh_until));
        assert!(!envelope.is_within_hard_ttl(envelope.hard_expires_at));
    }

    #[test]
    fn password_is_percent_encoded_and_masked() {
        let encoded = percent_encode("a:b@c/ d");
        assert_eq!(encoded, "a%3Ab%40c%2F%20d");
        assert_eq!(
            mask_redis_url("redis://:secret@cache:6379"),
            "redis://***@cache:6379"
        );
    }

    #[test]
    fn dataset_registry_has_explicit_ttl_bounds() {
        for dataset in [
            CacheDataset::SecurityOverview24h,
            CacheDataset::DeliveryComparisonAllHistory,
            CacheDataset::ExternalLogin24h,
            CacheDataset::SessionCounts,
        ] {
            assert!(dataset.fresh_ttl_secs() > 0);
            assert!(dataset.hard_ttl_secs() >= dataset.fresh_ttl_secs());
            assert!(dataset.hard_ttl_secs() <= 600);
        }
    }
}
