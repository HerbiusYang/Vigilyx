

//! Features:
//! - New IOC Import email New
//! - timestampRange
//! - ReuseSame1 DAG Engine

use serde::{Deserialize, Serialize};

/// Request
#[derive(Debug, Clone, Deserialize)]
pub struct RescanRequest {
   /// Starttimestamp (,)
    pub since: Option<String>,
   /// Endtimestamp ()
    pub until: Option<String>,
   /// session ()
    pub session_ids: Option<Vec<String>>,
}

/// Result
#[derive(Debug, Clone, Serialize)]
pub struct RescanResult {
    pub total_sessions: u64,
    pub rescanned: u64,
    pub new_threats_found: u64,
    pub upgraded_threats: u64,
    pub started_at: String,
    pub completed_at: String,
}

/// Status
#[derive(Debug, Clone, Serialize)]
pub struct RescanStatus {
    pub running: bool,
    pub progress: f64,
    pub current_session: Option<String>,
    pub total_sessions: u64,
    pub processed: u64,
}

/// handler
/// Note: engine.rs Medium
/// only ForRequest/Result datastructureAndStatustracing
#[derive(Clone)]
pub struct RescanTracker {
    status: std::sync::Arc<tokio::sync::RwLock<RescanStatus>>,
}

impl Default for RescanTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RescanTracker {
    pub fn new() -> Self {
        Self {
            status: std::sync::Arc::new(tokio::sync::RwLock::new(RescanStatus {
                running: false,
                progress: 0.0,
                current_session: None,
                total_sessions: 0,
                processed: 0,
            })),
        }
    }

    pub async fn start(&self, total: u64) {
        let mut s = self.status.write().await;
        s.running = true;
        s.progress = 0.0;
        s.total_sessions = total;
        s.processed = 0;
        s.current_session = None;
    }

    pub async fn update(&self, session_id: &str) {
        let mut s = self.status.write().await;
        s.processed += 1;
        s.current_session = Some(session_id.to_string());
        if s.total_sessions > 0 {
            s.progress = s.processed as f64 / s.total_sessions as f64;
        }
    }

    pub async fn complete(&self) {
        let mut s = self.status.write().await;
        s.running = false;
        s.progress = 1.0;
        s.current_session = None;
    }

    pub async fn get_status(&self) -> RescanStatus {
        self.status.read().await.clone()
    }

    pub async fn is_running(&self) -> bool {
        self.status.read().await.running
    }
}
