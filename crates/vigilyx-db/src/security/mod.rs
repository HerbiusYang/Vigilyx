//! Security engine data layer: verdicts, IOC, whitelist, alerts, temporal state, data security.

pub(crate) mod alert;
pub(crate) mod config;
pub(crate) mod data_security;
pub(crate) mod delivery;
pub(crate) mod disposition;
pub(crate) mod feedback;
pub(crate) mod ioc;
pub mod ioc_observation;
pub(crate) mod migrate;
mod module_data_seed;
pub mod privacy;
pub mod quarantine;
pub(crate) mod temporal;
pub mod threat_scene;
pub(crate) mod training;
pub(crate) mod verdict;
pub(crate) mod whitelist;
pub(crate) mod yara;

pub use alert::ALERT_DEDUP_WINDOW_MINUTES;
pub use feedback::LearningFeedbackInsert;
pub use ioc_observation::{
    IocCalibrationSummary, IocEvidenceCluster, IocIndicatorObservation, IocMessageObservation,
    IocOutcomeCounts, IocReliabilityBin, IocShadowTelemetry, IocTrafficStats,
};
pub use module_data_seed::embedded_module_data_seed;
