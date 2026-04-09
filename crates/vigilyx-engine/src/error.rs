use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("module error [{module_id}]: {message}")]
    Module { module_id: String, message: String },

    #[error("orchestrator error: {0}")]
    Orchestrator(String),

    #[error("pipeline config error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("timeout: module {module_id} exceeded {timeout_ms}ms")]
    Timeout { module_id: String, timeout_ms: u64 },

    #[error("dependency cycle detected: {0}")]
    CyclicDependency(String),

    #[error("unknown module: {0}")]
    UnknownModule(String),

    #[error("AI service unavailable: {0}")]
    AiUnavailable(String),

    #[error("{0}")]
    Other(String),
}
