//! Vigilyx Core Library

//! Provides shared data models, configuration management, and error types

pub mod config;
pub mod error;
pub mod magic_bytes;
pub mod models;
pub mod ssrf;
pub mod security;

pub use config::{CaptureMode, Config};
pub use error::{Error, Result};
pub use models::*;
pub use ssrf::*;
pub use security::*;
