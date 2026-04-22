//! Engine lineMonitor

//! Features:
//! - Moduleof AllExecuteline, Success/Failed/Timeoutcount
//! - AI Service Check
//! - Pipeline (Processemail)

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// EngineMonitorIndicator
#[derive(Clone)]
pub struct EngineMetrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    module_stats: RwLock<HashMap<String, ModuleStats>>,
    total_sessions: AtomicU64,
    total_verdicts: AtomicU64,
    started_at: DateTime<Utc>,
    ai_available: AtomicBool,
    /// Unix timestamp in seconds (0 = never)
    last_session_ts: AtomicU64,
}

/// ModuleStatistics
#[derive(Debug, Clone, Default)]
struct ModuleStats {
    total_runs: u64,
    total_duration_ms: u64,
    success_count: u64,
    failure_count: u64,
    timeout_count: u64,
    max_duration_ms: u64,
    min_duration_ms: u64,
}

/// EngineStatus (API Return)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub running: bool,
    pub uptime_seconds: u64,
    pub total_sessions_processed: u64,
    pub total_verdicts_produced: u64,
    pub sessions_per_second: f64,
    pub ai_service_available: bool,
    pub last_session_at: Option<String>,
    pub module_metrics: Vec<ModuleMetrics>,
}

/// ModuleIndicator (API Return)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetrics {
    pub module_id: String,
    pub total_runs: u64,
    pub avg_duration_ms: f64,
    pub max_duration_ms: u64,
    pub min_duration_ms: u64,
    pub success_rate: f64,
    pub failure_count: u64,
    pub timeout_count: u64,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                module_stats: RwLock::new(HashMap::new()),
                total_sessions: AtomicU64::new(0),
                total_verdicts: AtomicU64::new(0),
                started_at: Utc::now(),
                ai_available: AtomicBool::new(false),
                last_session_ts: AtomicU64::new(0),
            }),
        }
    }

    /// RecordingModuleExecutelineResult
    pub async fn record_module_run(
        &self,
        module_id: &str,
        duration_ms: u64,
        success: bool,
        timed_out: bool,
    ) {
        let mut stats = self.inner.module_stats.write().await;
        let entry = stats.entry(module_id.to_string()).or_default();

        entry.total_runs += 1;
        entry.total_duration_ms += duration_ms;

        if timed_out {
            entry.timeout_count += 1;
        } else if success {
            entry.success_count += 1;
        } else {
            entry.failure_count += 1;
        }

        if duration_ms > entry.max_duration_ms {
            entry.max_duration_ms = duration_ms;
        }
        if entry.min_duration_ms == 0 || duration_ms < entry.min_duration_ms {
            entry.min_duration_ms = duration_ms;
        }
    }

    /// Recording session ProcessStart
    pub fn record_session_start(&self) {
        self.inner.total_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Recording verdict (lock-free)
    pub fn record_verdict(&self) {
        self.inner.total_verdicts.fetch_add(1, Ordering::Relaxed);
        let ts = Utc::now().timestamp() as u64;
        self.inner.last_session_ts.store(ts, Ordering::Relaxed);
    }

    /// Update AI Status (lock-free)
    pub fn set_ai_available(&self, available: bool) {
        self.inner.ai_available.store(available, Ordering::Relaxed);
    }

    /// GetEngineStatus
    pub async fn get_status(&self) -> EngineStatus {
        let uptime = (Utc::now() - self.inner.started_at).num_seconds().max(0) as u64;
        let total_sessions = self.inner.total_sessions.load(Ordering::Relaxed);
        let total_verdicts = self.inner.total_verdicts.load(Ordering::Relaxed);

        let sps = if uptime > 0 {
            total_sessions as f64 / uptime as f64
        } else {
            0.0
        };

        let ai_available = self.inner.ai_available.load(Ordering::Relaxed);
        let last_ts = self.inner.last_session_ts.load(Ordering::Relaxed);
        let last_session_str = if last_ts > 0 {
            DateTime::from_timestamp(last_ts as i64, 0).map(|t| t.to_rfc3339())
        } else {
            None
        };

        let stats = self.inner.module_stats.read().await;
        let mut module_metrics: Vec<ModuleMetrics> = stats
            .iter()
            .map(|(id, s)| {
                let avg = if s.total_runs > 0 {
                    s.total_duration_ms as f64 / s.total_runs as f64
                } else {
                    0.0
                };
                let success_rate = if s.total_runs > 0 {
                    s.success_count as f64 / s.total_runs as f64
                } else {
                    1.0
                };
                ModuleMetrics {
                    module_id: id.clone(),
                    total_runs: s.total_runs,
                    avg_duration_ms: avg,
                    max_duration_ms: s.max_duration_ms,
                    min_duration_ms: s.min_duration_ms,
                    success_rate,
                    failure_count: s.failure_count,
                    timeout_count: s.timeout_count,
                }
            })
            .collect();
        module_metrics.sort_by(|a, b| a.module_id.cmp(&b.module_id));

        EngineStatus {
            running: true,
            uptime_seconds: uptime,
            total_sessions_processed: total_sessions,
            total_verdicts_produced: total_verdicts,
            sessions_per_second: sps,
            ai_service_available: ai_available,
            last_session_at: last_session_str,
            module_metrics,
        }
    }
}
