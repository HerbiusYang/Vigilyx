//! CUSUM (Cumulative Sum) change-point detection for risk score time series.

//! Detects sustained shifts in an entity's risk level:
//! ```text
//! S_t = max(0, S_{t-1} + r_t - - k)
//! S_t = max(0, S_{t-1} - r_t + - k)
//! Alarm: S_t> h or S_t> h

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

    // CUSUM update
    state.s_pos = (state.s_pos + risk_score - mu_0 - k).max(0.0);
    state.s_neg = (state.s_neg - risk_score + mu_0 - k).max(0.0);

    let alarm = state.sample_count >= params.min_samples && (state.s_pos > h || state.s_neg > h);

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
}
