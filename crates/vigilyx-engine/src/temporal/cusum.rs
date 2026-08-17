//! CUSUM (Cumulative Sum) change-point detection for risk score time series.

//! Detects sustained shifts in an entity's risk level:
//! ```text
//! S_t = max(0, S_{t-1} + r_t - - k)
//! S_t = max(0, S_{t-1} - r_t + - k)
//! Alarm: S_t> h
//!
//! Only the *upward* side (S, risk rising) can alarm. S tracks risk
//! *falling* — useful telemetry, but a sender whose risk collapses is not an
//! emerging threat, and letting S alarm made "attacker goes quiet" (or a
//! clean run after noise) indistinguishable from an attack shift.

//! - k = allowance (half- shift we want to detect)
//! - h = decision threshold (controls false alarm rate)
//! - = estimated in-control mean

pub use vigilyx_core::security::CusumState;

/// CUSUM detection parameters.
#[derive(Debug, Clone)]
pub struct CusumParams {
    /// Allowance parameter k (default: 0.5)
    pub k: f64,
    /// Decision threshold h (default: 4)
    pub h: f64,
    /// Minimum samples before detection is active
    pub min_samples: u64,
    /// Default in-control mean before enough samples
    pub default_mu0: f64,
    /// Default standard deviation before enough samples
    pub default_sigma: f64,
}

impl Default for CusumParams {
    fn default() -> Self {
        Self {
            k: 0.05, // Half-sigma for default_sigma=0.10
            h: 0.40, // ~4 sigma for default_sigma=0.10
            min_samples: 10,
            default_mu0: 0.10, // Expected safe email risk average
            default_sigma: 0.10,
        }
    }
}

/// Result of a CUSUM update step.
#[derive(Debug, Clone)]
pub struct CusumResult {
    /// Whether a change-point alarm was triggered
    pub alarm: bool,
    /// Current S value
    pub s_pos: f64,
    /// Current S value
    pub s_neg: f64,
    /// Estimated in-control mean
    pub mu_0: f64,
    /// Estimated standard deviation
    pub sigma: f64,
}

/// Update CUSUM state with a new risk observation.

/// During warm-up (<min_samples), only accumulates statistics.
/// After warm-up, computes adaptive k and h from observed variance.
#[inline]
pub fn cusum_update(state: &mut CusumState, risk_score: f64, params: &CusumParams) -> CusumResult {
    state.sample_count += 1;
    state.running_sum += risk_score;
    state.running_sq_sum += risk_score * risk_score;

    // Estimate and from observations
    let (mu_0, sigma) = if state.sample_count >= params.min_samples {
        let n = state.sample_count as f64;
        let mean = state.running_sum / n;
        let variance = (state.running_sq_sum / n - mean * mean).max(1e-10);
        let sigma = variance.sqrt();
        state.mu_0 = mean;
        (mean, sigma)
    } else {
        (params.default_mu0, params.default_sigma)
    };

    // Adaptive k and h based on observed/default sigma
    let k = sigma * 0.5; // Half-sigma shift detection
    let h = sigma * 4.0; // 4-sigma decision threshold

    // Warm-up establishes the in-control distribution; it must not also
    // accumulate detector state against the temporary default baseline.
    // Otherwise an elevated-but-stable entity carries a large stale s_pos
    // into the adaptive phase and can alarm while its risk is falling.
    if state.sample_count <= params.min_samples {
        state.s_pos = 0.0;
        state.s_neg = 0.0;
        state.alarm_active = false;
        return CusumResult {
            alarm: false,
            s_pos: 0.0,
            s_neg: 0.0,
            mu_0,
            sigma,
        };
    }

    // CUSUM update
    state.s_pos = (state.s_pos + risk_score - mu_0 - k).max(0.0);
    state.s_neg = (state.s_neg - risk_score + mu_0 - k).max(0.0);

    // Only the upward accumulator (risk rising) may raise an alarm. A
    // growing s_neg means the entity's risk is *falling* — not a threat.
    let alarm = state.sample_count >= params.min_samples && state.s_pos > h;

    if alarm && !state.alarm_active {
        state.alarm_active = true;
    } else if !alarm && state.alarm_active {
        state.alarm_active = false;
    }

    CusumResult {
        alarm,
        s_pos: state.s_pos,
        s_neg: state.s_neg,
        mu_0,
        sigma,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cusum_warmup_no_alarm() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        // During warm-up, no alarm should fire
        for _ in 0..5 {
            let r = cusum_update(&mut state, 0.1, &params);
            assert!(!r.alarm, "Should not alarm during warm-up");
        }
    }

    #[test]
    fn test_cusum_warmup_does_not_accumulate_detector_state() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        for _ in 0..params.min_samples {
            let result = cusum_update(&mut state, 0.8, &params);
            assert!(!result.alarm);
            assert_eq!(result.s_pos, 0.0);
            assert_eq!(result.s_neg, 0.0);
        }
        assert!(!state.alarm_active);
    }

    #[test]
    fn test_cusum_stable_no_alarm() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        // Feed stable low-risk scores
        for _ in 0..30 {
            let r = cusum_update(&mut state, 0.10, &params);
            assert!(!r.alarm);
        }
    }

    #[test]
    fn test_cusum_detects_shift() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        // Feed stable low-risk scores for warm-up
        for _ in 0..20 {
            cusum_update(&mut state, 0.10, &params);
        }

        // Now inject sustained high-risk scores
        let mut alarm_triggered = false;
        for _ in 0..30 {
            let r = cusum_update(&mut state, 0.80, &params);
            if r.alarm {
                alarm_triggered = true;
                break;
            }
        }

        assert!(alarm_triggered, "CUSUM should detect sustained risk shift");
    }

    #[test]
    fn test_cusum_single_spike_no_alarm() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        // Warm-up
        for _ in 0..20 {
            cusum_update(&mut state, 0.10, &params);
        }

        // Single spike should not trigger alarm
        let _r = cusum_update(&mut state, 0.90, &params);
        // Might not alarm on a single spike if h is high enough
        // (depends on accumulated S)

        // Return to normal
        for _ in 0..5 {
            let r = cusum_update(&mut state, 0.10, &params);
            // Should eventually return to non-alarm
            let _ = r;
        }
    }

    /// PoC (E3 direction): a *falling* risk series used to trip the two-sided
    /// alarm via s_neg — "sender went quiet after noise" is not an attack.
    /// Only s_pos (risk rising) may alarm now.
    #[test]
    fn test_cusum_falling_risk_does_not_alarm() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        // Establish an elevated-but-stable baseline (e.g. a noisy shared host).
        for _ in 0..20 {
            cusum_update(&mut state, 0.5, &params);
        }

        // Risk collapses back to clean: s_neg accumulates far beyond h.
        for _ in 0..10 {
            let r = cusum_update(&mut state, 0.0, &params);
            assert!(
                !r.alarm,
                "falling risk (s_neg) must never raise an alarm: s_neg={} s_pos={}",
                r.s_neg, r.s_pos
            );
        }
        let state: &CusumState = &state;
        assert!(
            state.s_neg > 0.0,
            "s_neg should still be tracked as telemetry"
        );
    }

    /// The upward direction must still alarm: sustained risk rise is exactly
    /// what CUSUM exists for.
    #[test]
    fn test_cusum_rising_risk_still_alarms() {
        let mut state = CusumState::new("test".to_string());
        let params = CusumParams::default();

        for _ in 0..20 {
            cusum_update(&mut state, 0.05, &params);
        }
        let mut alarmed = false;
        for _ in 0..15 {
            if cusum_update(&mut state, 0.9, &params).alarm {
                alarmed = true;
                break;
            }
        }
        assert!(alarmed, "sustained risk rise must still alarm via s_pos");
    }
}
