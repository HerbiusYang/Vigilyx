use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::context::SecurityContext;
use crate::error::EngineError;

// Re-export security types from core (moved in Phase 3)
pub use vigilyx_core::security::{Bpa, Evidence, ModuleResult, Pillar, ThreatLevel};

/// Module execution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RunMode {
    #[default]
    Builtin,
    AiOnly,
    Hybrid,
}

/// Metadata describing a module's capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pillar: Pillar,
    pub depends_on: Vec<String>,
    pub timeout_ms: u64,
    pub is_remote: bool,
    pub supports_ai: bool,
    /// If true, `analyze()` is CPU-bound and will be dispatched to the blocking
    /// thread pool via `spawn_blocking`, freeing async worker threads for I/O.
    #[serde(default)]
    pub cpu_bound: bool,
    /// MTA inline verdict.
    /// - `Some(n)`: inline,n (Tier 1:)
    /// - `None`: (Tier 2: NLP/)
    #[serde(default)]
    pub inline_priority: Option<u8>,
}

/// The trait every security module must implement
#[async_trait]
pub trait SecurityModule: Send + Sync {
    fn metadata(&self) -> &ModuleMetadata;
    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError>;
    fn should_run(&self, _ctx: &SecurityContext) -> bool {
        true
    }
}
