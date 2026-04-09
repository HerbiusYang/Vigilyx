//! Temporal analysis layer - cross-time-window correlation for bypass monitoring.

//! This layer runs AFTER single-email verdict and provides time-series anomaly detection:
//! - CUSUM cumulative shift detection
//! - Dual-speed EWMA baseline drift
//! - Entity-level risk accumulation

//! All temporal state is persisted to PostgreSQL for durability across restarts.

pub mod comm_graph;
pub mod cusum;
pub mod dual_ewma;
pub mod entity_risk;
pub mod hawkes;
pub mod hmm_attack_phase;
pub mod temporal_analyzer;
