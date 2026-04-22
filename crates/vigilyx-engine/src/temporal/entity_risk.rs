//! Entity-level risk accumulation with exponential decay.

//! Tracks cumulative risk for entities (senders, domains, sender-recipient pairs):
//! ```text
//! R_entity(t) = R_entity(t-1) + (1 -) r_new

//! = 0.90~0.95 provides a "memory" that decays slowly, so:
//! - Repeated moderate threats accumulate to high risk
//! - A single false positive decays away naturally
//! - Entities exceeding threshold enter the monitoring watchlist

pub use vigilyx_core::security::EntityRiskState;

/// Entity risk parameters.
#[derive(Debug, Clone)]
pub struct EntityRiskParams {
    /// Decay factor (default: 0.92 - each new observation contributes 8%)
    pub alpha: f64,
    /// Threshold for watchlist inclusion
    pub watchlist_threshold: f64,
    /// Threshold for high-risk alert
    pub alert_threshold: f64,
}

impl Default for EntityRiskParams {
    fn default() -> Self {
        Self {
            alpha: 0.92,
            watchlist_threshold: 0.30,
            alert_threshold: 0.60,
        }
    }
}

/// Result of an entity risk update.
#[derive(Debug, Clone)]
pub struct EntityRiskResult {
    /// Updated risk value
    pub risk_value: f64,
    /// Whether entity is on watchlist
    pub watchlisted: bool,
    /// Whether entity risk is at alert level
    pub alert: bool,
    /// Total emails processed
    pub email_count: u64,
}

/// Update entity risk state with a new risk observation.
#[inline]
pub fn entity_risk_update(
    state: &mut EntityRiskState,
    risk_score: f64,
    params: &EntityRiskParams,
) -> EntityRiskResult {
    state.email_count += 1;

    if state.email_count == 1 {
        state.risk_value = risk_score;
    } else {
        // Use params.alpha (current config) rather than state.alpha (frozen at creation)
        state.risk_value = params.alpha * state.risk_value + (1.0 - params.alpha) * risk_score;
        state.alpha = params.alpha; // keep state in sync with latest config
    }

    EntityRiskResult {
        risk_value: state.risk_value,
        watchlisted: state.risk_value >= params.watchlist_threshold,
        alert: state.risk_value >= params.alert_threshold,
        email_count: state.email_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_risk_first_observation() {
        let mut state = EntityRiskState::with_defaults("test".to_string());
        let params = EntityRiskParams::default();

        let r = entity_risk_update(&mut state, 0.5, &params);
        assert!((r.risk_value - 0.5).abs() < 1e-10);
        assert!(r.watchlisted);
        assert!(!r.alert);
    }

    #[test]
    fn test_entity_risk_decay() {
        let mut state = EntityRiskState::with_defaults("test".to_string());
        let params = EntityRiskParams::default();

        // One high-risk observation
        entity_risk_update(&mut state, 0.8, &params);

        // Then many safe observations -> risk should decay
        for _ in 0..50 {
            entity_risk_update(&mut state, 0.0, &params);
        }

        assert!(
            state.risk_value < 0.05,
            "Risk should decay after many safe observations: {}",
            state.risk_value
        );
    }

    #[test]
    fn test_entity_risk_accumulation() {
        let mut state = EntityRiskState::with_defaults("test".to_string());
        let params = EntityRiskParams::default();

        // Repeated moderate-risk observations should accumulate
        for _ in 0..30 {
            entity_risk_update(&mut state, 0.4, &params);
        }

        assert!(
            state.risk_value > 0.35,
            "Risk should accumulate from repeated moderate threats: {}",
            state.risk_value
        );
        assert!(state.risk_value < 0.45);
    }

    #[test]
    fn test_entity_risk_alert_threshold() {
        let mut state = EntityRiskState::with_defaults("test".to_string());
        let params = EntityRiskParams::default();

        // Build up risk
        for _ in 0..20 {
            let r = entity_risk_update(&mut state, 0.8, &params);
            if r.alert {
                return; // Test passes - alert triggered
            }
        }

        panic!(
            "Should have triggered alert after repeated high-risk scores: {}",
            state.risk_value
        );
    }
}
