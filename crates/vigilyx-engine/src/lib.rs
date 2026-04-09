// Domain-organized modules
pub mod data_security;
pub mod external;
pub mod fusion;
pub mod modules;
pub mod monitoring;
pub mod pipeline;
pub mod temporal;
pub mod yara;

// Root-level modules
pub mod db_service;
pub mod error;
pub mod feedback;
pub mod intel;
pub mod ioc;
pub mod module;
pub mod syslog;
pub mod threat_scene;
pub mod whitelist;

// Backward-compatible re-exports
// Preserves all existing `crate::X` and `vigilyx_engine::X` paths.

// Fusion layer
pub use fusion::bpa;
pub use fusion::engine_map;
pub use fusion::grouped_fusion;
pub use fusion::robustness;
pub use fusion::tbm;

// Pipeline layer
pub use pipeline::config;
pub use pipeline::context;
pub use pipeline::engine;
pub use pipeline::orchestrator;
pub use pipeline::verdict;

// External integrations
pub use external::fetcher;
pub use external::remote;
pub use external::rescan;

// Monitoring
pub use monitoring::alert;
pub use monitoring::metrics;
