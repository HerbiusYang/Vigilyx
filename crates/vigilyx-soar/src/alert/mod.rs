//! EVT-based alert system with P0-P3 classification.

//! Uses Generalized Pareto Distribution (GPD) for tail risk estimation:
//! ```text
//! P(X> x | X> u) = (1 + (x-u)/)^{-1/}

//! Alert levels (8.3):
//! - **P0**: Critical - EL>= 3.0 or K_conflict> 0.7 or CUSUM breach or EVT T>= 10000
//! - **P1**: High - EL [1.5, 3.0) or K_conflict> 0.6 or EVT T [1000, 10000)
//! - **P2**: Medium - EL [0.5, 1.5) or u_final> 0.6 or EVT T [100, 1000)
//! - **P3**: Low - EL [0.2, 0.5) or Risk_final>= 0.15

mod gpd;
mod impact;

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use gpd::GpdEstimator;
pub use impact::ImpactConfig;

// Re-export core types
pub use vigilyx_core::security::{AlertLevel, AlertRecord};

// Alert signals (flattened temporal signals for decoupling)

/// Flattened temporal signals for alert evaluation.
///
/// Constructed by the engine from its internal `TemporalResult`.
/// This decouples the alert engine from the temporal analysis implementation.
#[derive(Debug, Clone, Default)]
pub struct AlertSignals {
    /// CUSUM change-point alarm
    pub cusum_alarm: bool,
    /// HMM trust-building phase probability (S2)
    pub hmm_trust_building: f64,
    /// HMM attack-execution phase probability (S3)
    pub hmm_attack_execution: f64,
    /// Whether sender is on watchlist
    pub sender_watchlisted: bool,
    /// Accumulated sender risk score
    pub sender_risk: f64,
    /// Whether EWMA drift was detected
    pub ewma_drifting: bool,
    /// EWMA drift score
    pub ewma_drift_score: f64,
    /// Whether communication graph anomaly was detected
    pub graph_anomalous: bool,
    /// Communication graph anomaly pattern label
    pub graph_pattern_label: String,
    /// Hawkes self-excitation intensity ratio (/)
    pub hawkes_intensity_ratio: f64,
}

// Alert decision (in-memory result before persistence)

/// Result of alert evaluation for one verdict.
#[derive(Debug, Clone)]
pub struct AlertDecision {
    pub level: AlertLevel,
    pub expected_loss: f64,
    pub return_period: f64,
    /// CVaR (Conditional Value at Risk): E[L | L> VaR]
    pub cvar: f64,
    pub risk_final: f64,
    pub k_conflict: f64,
    pub cusum_alarm: bool,
    pub rationale: Vec<String>,
}

// Alert engine

/// The EVT alert engine - evaluates each verdict and produces P0-P3 alerts.
pub struct AlertEngine {
    /// GPD tail estimator (fed by all risk scores).
    gpd: Arc<RwLock<GpdEstimator>>,
    /// Impact configuration.
    impact: ImpactConfig,
}

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEngine {
    /// Create a new alert engine.
    pub fn new() -> Self {
        Self {
            gpd: Arc::new(RwLock::new(GpdEstimator::new(2000))),
            impact: ImpactConfig::default(),
        }
    }

    /// Create with custom impact config.
    pub fn with_impact(impact: ImpactConfig) -> Self {
        Self {
            gpd: Arc::new(RwLock::new(GpdEstimator::new(2000))),
            impact,
        }
    }

    /// Feed a risk score observation (call for every verdict).
    pub async fn observe(&self, risk_score: f64) {
        self.gpd.write().await.push(risk_score);
    }

    /// Evaluate alert level for a verdict.
    ///
    /// # Arguments
    /// - `risk_final`: final risk score (after temporal adjustment)
    /// - `k_conflict`: Dempster-Shafer conflict coefficient
    /// - `u_final`: final uncertainty value
    /// - `novelty`: TBM novelty score (optional)
    /// - `k_cross`: tech vs blind-spot layer conflict (optional)
    /// - `signals`: flattened temporal analysis signals (optional)
    /// - `recipients`: list of recipient addresses
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate(
        &self,
        risk_final: f64,
        k_conflict: f64,
        u_final: f64,
        novelty: Option<f64>,
        k_cross: Option<f64>,
        signals: Option<&AlertSignals>,
        recipients: &[String],
    ) -> Option<AlertDecision> {
        // Don't alert on low-risk emails
        if risk_final < 0.15 {
            return None;
        }

        let mut rationale: Vec<String> = Vec::new();

        // Extract signals
        let cusum_alarm = signals.map(|s| s.cusum_alarm).unwrap_or(false);

        // Expected Loss
        let max_impact: f64 = recipients
            .iter()
            .map(|r| self.impact.weight_for(r))
            .fold(self.impact.default_weight, f64::max);
        let expected_loss = risk_final * max_impact;

        // EVT Return Period + CVaR (single GPD fit, no duplicate sort)
        let (return_period, cvar) = self.gpd.write().await.return_period_and_cvar(risk_final);

        // P0-P3 classification (documentation 8.3 alert level definitions)
        // EL threshold considers Impact amplification (CEO=5.0, CFO=4.5)
        let mut level = AlertLevel::P3;

        // Expected loss thresholds (documentation: P0>= 3.0, P1[1.5,3.0), P2[0.5,1.5), P3[0.2,0.5))
        if expected_loss >= 3.0 {
            level = AlertLevel::P0;
            rationale.push(format!("EL={:.2} ≥ 3.0", expected_loss));
        } else if expected_loss >= 1.5 {
            if level > AlertLevel::P1 {
                level = AlertLevel::P1;
            }
            rationale.push(format!("EL={:.2} ∈ [1.5, 3.0)", expected_loss));
        } else if expected_loss >= 0.5 {
            if level > AlertLevel::P2 {
                level = AlertLevel::P2;
            }
            rationale.push(format!("EL={:.2} ∈ [0.5, 1.5)", expected_loss));
        } else if expected_loss >= 0.2 {
            rationale.push(format!("EL={:.2} ∈ [0.2, 0.5)", expected_loss));
        }

        // K_conflict thresholds (documentation: K>0.7 -> P0)
        if k_conflict > 0.7 {
            level = AlertLevel::P0;
            rationale.push(format!(
                "K_conflict={:.2} > 0.7 (engine conflict → high-level evasion)",
                k_conflict
            ));
        }

        // CUSUM alarm (documentation: CUSUM breach threshold -> P0)
        if cusum_alarm {
            level = AlertLevel::P0;
            rationale.push("CUSUM breach threshold: risk continues to drift".to_string());
        }

        // Uncertainty (documentation: u_final> 0.6 -> P2)
        if u_final > 0.6 {
            if level > AlertLevel::P2 {
                level = AlertLevel::P2;
            }
            rationale.push(format!("u_final={:.2} > 0.6 (high uncertainty)", u_final));
        }

        // EVT return period (documentation: T>= 10000 -> P0, [1000,10000) -> P1, [100,1000) -> P2, [20,100) -> P3)
        if return_period >= 10000.0 {
            level = AlertLevel::P0;
            rationale.push(format!(
                "EVT T={:.0} ≥ 10000 (extreme tail event)",
                return_period
            ));
        } else if return_period >= 1000.0 {
            if level > AlertLevel::P1 {
                level = AlertLevel::P1;
            }
            rationale.push(format!("EVT T={:.0} ∈ [1000, 10000)", return_period));
        } else if return_period >= 100.0 {
            if level > AlertLevel::P2 {
                level = AlertLevel::P2;
            }
            rationale.push(format!("EVT T={:.0} ∈ [100, 1000)", return_period));
        } else if return_period >= 20.0 {
            rationale.push(format!("EVT T={:.0} ∈ [20, 100)", return_period));
        }

        // HMM attack phase signals (documentation 7.2: (S2)>0.25 -> P2)
        if let Some(s) = signals {
            if s.hmm_trust_building > 0.25 {
                if level > AlertLevel::P2 {
                    level = AlertLevel::P2;
                }
                rationale.push(format!(
                    "HMM trust-building phase γ(S2)={:.2} > 0.25",
                    s.hmm_trust_building
                ));
            }
            if s.hmm_attack_execution > 0.3 {
                if level > AlertLevel::P1 {
                    level = AlertLevel::P1;
                }
                rationale.push(format!(
                    "HMM attack-execution phase γ(S3)={:.2}",
                    s.hmm_attack_execution
                ));
            }
            if s.sender_watchlisted {
                rationale.push(format!(
                    "sender is on watchlist (risk={:.2})",
                    s.sender_risk
                ));
            }
            if s.ewma_drifting {
                rationale.push(format!("EWMA baseline drift={:.2}", s.ewma_drift_score));
            }
            if s.graph_anomalous {
                if level > AlertLevel::P2 {
                    level = AlertLevel::P2;
                }
                rationale.push(format!(
                    "communication graph anomaly: {}",
                    s.graph_pattern_label
                ));
            }

            // Hawkes burst detection (v5.0 8.3)
            if s.hawkes_intensity_ratio > 5.0 {
                level = AlertLevel::P0;
                rationale.push(format!(
                    "Hawkes burst λ/μ={:.1} > 5.0 (short-term intense high-risk)",
                    s.hawkes_intensity_ratio
                ));
            } else if s.hawkes_intensity_ratio > 3.0 {
                if level > AlertLevel::P1 {
                    level = AlertLevel::P1;
                }
                rationale.push(format!(
                    "Hawkes burst λ/μ={:.1} > 3.0",
                    s.hawkes_intensity_ratio
                ));
            }
        }

        // Novelty detection (v5.0 6.2)
        if let Some(nov) = novelty {
            if nov > 0.6 {
                if level > AlertLevel::P1 {
                    level = AlertLevel::P1;
                }
                rationale.push(format!(
                    "Novelty={:.2} > 0.6 (multi-engine reports unknown threat type)",
                    nov
                ));
            } else if nov > 0.3 {
                if level > AlertLevel::P2 {
                    level = AlertLevel::P2;
                }
                rationale.push(format!("Novelty={:.2} > 0.3", nov));
            }
        }

        // K_cross signal (v5.0: technical layer vs blind spot layer conflict)
        if let Some(kx) = k_cross
            && kx > 0.5
        {
            if level > AlertLevel::P1 {
                level = AlertLevel::P1;
            }
            rationale.push(format!(
                "K_cross={:.2} > 0.5 (technical layer vs blind spot layer conflict)",
                kx
            ));
        }

        if rationale.is_empty() {
            rationale.push(format!("Risk={:.3} ≥ 0.15", risk_final));
        }

        Some(AlertDecision {
            level,
            expected_loss,
            return_period,
            cvar,
            risk_final,
            k_conflict,
            cusum_alarm,
            rationale,
        })
    }

    /// Convert AlertDecision to AlertRecord for DB persistence.
    pub fn to_record(decision: &AlertDecision, verdict_id: Uuid, session_id: Uuid) -> AlertRecord {
        AlertRecord {
            id: Uuid::new_v4(),
            verdict_id,
            session_id,
            alert_level: decision.level,
            expected_loss: decision.expected_loss,
            cvar: decision.cvar,
            return_period: decision.return_period,
            risk_final: decision.risk_final,
            k_conflict: decision.k_conflict,
            cusum_alarm: decision.cusum_alarm,
            rationale: decision.rationale.join("; "),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            created_at: Utc::now(),
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_no_alert_for_safe() {
        let engine = AlertEngine::new();
        let decision = engine.evaluate(0.05, 0.0, 0.0, None, None, None, &[]).await;
        assert!(decision.is_none(), "Safe email should not generate alert");
    }

    #[tokio::test]
    async fn test_alert_p3_for_low_risk() {
        let engine = AlertEngine::new();
        let decision = engine
            .evaluate(
                0.20,
                0.0,
                0.0,
                None,
                None,
                None,
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().level, AlertLevel::P3);
    }

    #[tokio::test]
    async fn test_alert_p0_for_high_el() {
        let engine = AlertEngine::new();
        // risk=0.9, ceo target (weight=5.0) -> EL = 4.5>> 0.8 -> P0
        let decision = engine
            .evaluate(0.9, 0.0, 0.0, None, None, None, &["ceo@company.com".into()])
            .await;
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().level, AlertLevel::P0);
    }

    #[tokio::test]
    async fn test_alert_p0_for_high_conflict() {
        let engine = AlertEngine::new();
        let decision = engine
            .evaluate(
                0.58,
                0.75,
                0.4,
                None,
                None,
                None,
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        assert_eq!(decision.unwrap().level, AlertLevel::P0);
    }

    #[tokio::test]
    async fn test_alert_p2_for_cusum() {
        let engine = AlertEngine::new();
        let signals = AlertSignals {
            cusum_alarm: true,
            ..Default::default()
        };
        let decision = engine
            .evaluate(
                0.25,
                0.0,
                0.0,
                None,
                None,
                Some(&signals),
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(d.level <= AlertLevel::P2);
        assert!(d.cusum_alarm);
    }

    #[test]
    fn test_alert_level_ordering() {
        assert!(AlertLevel::P0 < AlertLevel::P1);
        assert!(AlertLevel::P1 < AlertLevel::P2);
        assert!(AlertLevel::P2 < AlertLevel::P3);
    }

    #[test]
    fn test_alert_record_conversion() {
        let decision = AlertDecision {
            level: AlertLevel::P1,
            expected_loss: 0.6,
            return_period: 150.0,
            cvar: 0.75,
            risk_final: 0.7,
            k_conflict: 0.3,
            cusum_alarm: false,
            rationale: vec!["test".into()],
        };
        let record = AlertEngine::to_record(&decision, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(record.alert_level, AlertLevel::P1);
        assert!(!record.acknowledged);
    }

    // v5.0 TBM alert tests

    #[tokio::test]
    async fn test_alert_hawkes_burst_p0() {
        let engine = AlertEngine::new();
        let signals = AlertSignals {
            hawkes_intensity_ratio: 6.0, // > 5.0 -> P0
            ..Default::default()
        };
        let decision = engine
            .evaluate(
                0.30,
                0.0,
                0.0,
                None,
                None,
                Some(&signals),
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert_eq!(d.level, AlertLevel::P0, "Hawkes ratio > 5.0 should be P0");
        assert!(d.rationale.iter().any(|r| r.contains("Hawkes burst")));
    }

    #[tokio::test]
    async fn test_alert_hawkes_burst_p1() {
        let engine = AlertEngine::new();
        let signals = AlertSignals {
            hawkes_intensity_ratio: 4.0, // > 3.0 but <5.0 -> P1
            ..Default::default()
        };
        let decision = engine
            .evaluate(
                0.25,
                0.0,
                0.0,
                None,
                None,
                Some(&signals),
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(
            d.level <= AlertLevel::P1,
            "Hawkes ratio > 3.0 should be at most P1, got {:?}",
            d.level
        );
    }

    #[tokio::test]
    async fn test_alert_novelty_p1() {
        let engine = AlertEngine::new();
        let decision = engine
            .evaluate(
                0.65,
                0.2,
                0.5,
                Some(0.7),
                None,
                None,
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(
            d.level <= AlertLevel::P1,
            "Novelty > 0.6 should be at most P1, got {:?}",
            d.level
        );
        assert!(d.rationale.iter().any(|r| r.contains("Novelty")));
    }

    #[tokio::test]
    async fn test_alert_novelty_p2() {
        let engine = AlertEngine::new();
        let decision = engine
            .evaluate(
                0.55,
                0.1,
                0.5,
                Some(0.4),
                None,
                None,
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(
            d.level <= AlertLevel::P2,
            "Novelty > 0.3 should be at most P2, got {:?}",
            d.level
        );
    }

    #[tokio::test]
    async fn test_alert_k_cross_p1() {
        let engine = AlertEngine::new();
        let decision = engine
            .evaluate(
                0.68,
                0.3,
                0.4,
                None,
                Some(0.6),
                None,
                &["user@example.com".into()],
            )
            .await;
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert!(
            d.level <= AlertLevel::P1,
            "K_cross > 0.5 should be at most P1, got {:?}",
            d.level
        );
        assert!(d.rationale.iter().any(|r| r.contains("K_cross")));
    }
}
