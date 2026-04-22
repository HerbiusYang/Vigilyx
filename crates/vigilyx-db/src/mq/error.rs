//! Message queue error types
use thiserror::Error;

/// Message queue errors
#[derive(Error, Debug)]
pub enum MqError {
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    /// Publish error
    #[error("Publish error: {0}")]
    Publish(String),
    /// Subscribe error
    #[error("Subscribe error: {0}")]
    Subscribe(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Redis error
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    /// Channel closed
    #[error("Channel closed")]
    ChannelClosed,
    /// Timeout
    #[error("Timeout")]
    Timeout,
}

/// Message queue result type
pub type MqResult<T> = Result<T, MqError>;
