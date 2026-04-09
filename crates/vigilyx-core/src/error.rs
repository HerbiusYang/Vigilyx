//! Error type definitions

use thiserror::Error;

/// Vigilyx error type
#[derive(Error, Debug)]
pub enum Error {
   /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

   /// Network capture error
    #[error("Capture error: {0}")]
    Capture(String),

   /// Protocol parse error
    #[error("Parse error: {0}")]
    Parse(String),

   /// Database error
    #[error("Database error: {0}")]
    Database(String),

   /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

   /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

   /// Channel send error
    #[error("Channel send error")]
    ChannelSend,

   /// Channel receive error
    #[error("Channel receive error")]
    ChannelRecv,

   /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
