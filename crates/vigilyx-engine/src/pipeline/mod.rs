//! Analysis pipeline: orchestration, verdict aggregation, and configuration.

pub mod config;
pub mod context;
pub mod engine;
pub(crate) mod internal_domains;
pub mod orchestrator;
pub(crate) mod post_verdict;
pub mod verdict;
