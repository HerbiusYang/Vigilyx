//! External service integrations: URL fetching, AI proxy, ClamAV, retrospective scanning.

pub mod clamav;
pub mod fetcher;
pub mod process_sandbox;
// Compatibility path; AI transport is owned by crate::ai.
pub use crate::ai::remote;
pub mod rescan;
pub mod sandbox;
