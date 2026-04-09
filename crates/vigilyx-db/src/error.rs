//! Unified error types
use thiserror::Error;

/// Unified data layer errors
#[derive(Error, Debug)]
pub enum DbError {
   /// PostgreSQL error
    #[cfg(feature = "postgres")]
    #[error("PostgreSQL error: {0}")]
    Sqlx(#[from] sqlx::Error),
   /// Serialization error
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
   /// Migration error
    #[error("Migration error: {0}")]
    Migration(String),
   /// Data error
    #[error("Data error: {0}")]
    Data(String),
   /// Generic error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
