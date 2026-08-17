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
///
/// Asymmetric washout resistance (R4 hardening):
/// - Clean observations (below the current risk) wash out at **half** the
///   weight of malicious ones, so a burst of clean mail cannot quickly
///   launder a risky sender.
/// - While the entity is on the watchlist (risk >= watchlist_threshold),
///   clean observations decay at **quarter** weight — a stateless minimum
///   dwell: leaving the watchlist needs an order of magnitude more clean
///   mail than entering it took.
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
        let alpha = if risk_score < state.risk_value {
            let base_clean_weight = 1.0 - params.alpha;
            let on_watchlist = state.risk_value >= params.watchlist_threshold;
            // Clean weight is at most half the malicious weight; while
            // watchlisted it drops to a quarter (minimum dwell).
            let clean_weight = if on_watchlist {
                base_clean_weight / 4.0
            } else {
                base_clean_weight / 2.0
            };
            1.0 - clean_weight
        } else {
            params.alpha
        };
        state.risk_value = alpha * state.risk_value + (1.0 - alpha) * risk_score;
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

        // Asymmetric decay: clean observations wash out at half/quarter
        // weight, so decay takes far more than the old ~50 clean mails.
        for _ in 0..200 {
            entity_risk_update(&mut state, 0.0, &params);
        }

        assert!(
            state.risk_value < 0.05,
            "Risk should still decay after a long run of safe observations: {}",
            state.risk_value
        );
    }

    /// PoC (watchlist laundering): 50 clean observations used to wash an
    /// entity off the watchlist. With asymmetric updates + watchlist dwell,
    /// 30 clean mails must not be enough; a long clean run still exits.
    #[test]
    fn test_clean_burst_cannot_launder_watchlist_quickly() {
        let mut state = EntityRiskState::with_defaults("launderer".to_string());
        let params = EntityRiskParams::default();

        entity_risk_update(&mut state, 0.8, &params);
        assert!(state.risk_value >= params.watchlist_threshold);

        // 30 clean mails: entity must remain watchlisted (old symmetric EWMA
        // dropped below the 0.30 threshold after ~14).
        let mut result = None;
        for _ in 0..30 {
            result = Some(entity_risk_update(&mut state, 0.0, &params));
        }
        assert!(
            result.as_ref().unwrap().watchlisted,
            "30 clean mails must not launder the watchlist: risk={}",
            state.risk_value
        );

        // A genuinely long clean run (200 mails) does clear the watchlist.
        for _ in 0..170 {
            result = Some(entity_risk_update(&mut state, 0.0, &params));
        }
        assert!(
            !result.unwrap().watchlisted,
            "long clean history must eventually clear the watchlist: risk={}",
            state.risk_value
        );
    }

    /// Clean weight must never exceed half the malicious weight.
    #[test]
    fn test_clean_weight_is_at_most_half_of_malicious_weight() {
        let params = EntityRiskParams::default();

        // Malicious direction (upward): weight = 1 - alpha
        let mut up = EntityRiskState::with_defaults("up".to_string());
        entity_risk_update(&mut up, 0.4, &params);
        let before = up.risk_value;
        entity_risk_update(&mut up, 0.9, &params);
        let malicious_weight = (up.risk_value - before) / (0.9 - before);

        // Clean direction (downward, off-watchlist): weight must be <= half
        let mut down = EntityRiskState::with_defaults("down".to_string());
        entity_risk_update(&mut down, 0.2, &params); // below watchlist threshold
        let before = down.risk_value;
        entity_risk_update(&mut down, 0.0, &params);
        let clean_weight = (before - down.risk_value) / before;

        assert!(
            clean_weight <= malicious_weight / 2.0 + 1e-12,
            "clean weight {} must be <= half of malicious weight {}",
            clean_weight,
            malicious_weight
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
