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
    /// Optional inline execution priority hint. Lower values run first.
    /// Modules without an explicit hint use the built-in conservative map in
    /// [`ModuleMetadata::effective_inline_priority`]; unknown/custom modules
    /// are excluded from the synchronous MTA tier and still run asynchronously
    /// in the full pipeline.
    #[serde(default)]
    pub inline_priority: Option<u8>,
}

impl ModuleMetadata {
    /// Return the priority used by the bounded MTA inline tier.
    ///
    /// A missing priority must not accidentally turn a slow or remote module
    /// into a delivery-blocking module. The fallback map therefore contains
    /// only bounded local detectors and the composite verdict node. Remote
    /// modules (NLP, DNS/intel, landing-page fetches) are deliberately left to
    /// the asynchronous full pipeline unless they opt in explicitly.
    pub fn effective_inline_priority(&self) -> Option<u8> {
        if let Some(priority) = self.inline_priority {
            return Some(priority);
        }
        if self.is_remote {
            return None;
        }

        match self.id.as_str() {
            // Fast, bounded content and attachment checks.
            "mime_scan"
            | "header_scan"
            | "content_scan"
            | "html_scan"
            | "html_pixel_art"
            | "attach_scan"
            | "attach_content"
            | "attach_qr_scan"
            | "link_scan"
            | "link_content"
            | "anomaly_detect"
            | "aitm_detect"
            | "rmm_detect"
            | "prompt_injection_scan"
            | "toad_detect"
            | "yara_scan" => Some(20),
            // Local-only semantic fallback is safe to run inline; when the AI
            // proxy is present the module is marked remote and is deferred.
            "semantic_scan" => Some(30),
            // Verdict is cheap and only depends on whichever inline modules
            // were selected by the filtered DAG.
            "verdict" => Some(90),
            _ => None,
        }
    }
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
