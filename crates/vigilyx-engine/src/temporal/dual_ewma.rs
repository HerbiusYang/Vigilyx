//! Dual-speed EWMA baseline drift detection.

//! Maintains two Exponentially Weighted Moving Averages:
//! - **Fast** (=0.05, ~20-day memory): tracks recent trends
//! - **Slow** (=0.005, ~200-day memory): tracks long-term baseline

//! Drift score = |fast - slow| / max(slow,)

//! A sustained divergence (fast>> slow) is the mathematical fingerprint of
//! "boiling frog" attacks - gradual behavior changes designed to evade
//! snapshot-based anomaly detection.

pub use vigilyx_core::security::DualEwmaState;

/// EWMA parameters.
#[derive(Debug, Clone)]
pub struct EwmaParams {
    /// Fast EWMA smoothing factor (default: 0.05 20 observations half-life)
    pub alpha_fast: f64,
    /// Slow EWMA smoothing factor (default: 0.005 200 observations half-life)
    pub alpha_slow: f64,
    /// Drift threshold: drift_score above this is considered anomalous
    pub drift_threshold: f64,
    /// Epsilon to avoid division by zero
    pub epsilon: f64,
}

impl Default for EwmaParams {
    fn default() -> Self {
        Self {
            alpha_fast: 0.05,
            alpha_slow: 0.005,
            drift_threshold: 1.5,
            epsilon: 0.01,
        }
    }
}

/// Result of a dual EWMA update.
#[derive(Debug, Clone)]
pub struct EwmaResult {
    /// Current fast EWMA
    pub fast: f64,
    /// Current slow EWMA
    pub slow: f64,
    /// Drift score = |fast - slow| / max(slow,)
    pub drift_score: f64,
    /// Whether drift exceeds threshold
    pub drifting: bool,
}

/// Update dual EWMA state with a new observation.
#[inline]
pub fn ewma_update(state: &mut DualEwmaState, value: f64, params: &EwmaParams) -> EwmaResult {
    state.observation_count += 1;

    if !state.initialized {
        state.fast_value = value;
        state.slow_value = value;
        state.initialized = true;
        return EwmaResult {
            fast: value,
            slow: value,
            drift_score: 0.0,
            drifting: false,
        };
    }

    // EWMA update: new = * observation + (1 -) * old
    state.fast_value = params.alpha_fast * value + (1.0 - params.alpha_fast) * state.fast_value;
    state.slow_value = params.alpha_slow * value + (1.0 - params.alpha_slow) * state.slow_value;

    let drift_score =
        (state.fast_value - state.slow_value).abs() / state.slow_value.abs().max(params.epsilon);

    let drifting = drift_score > params.drift_threshold && state.observation_count > 20;

    EwmaResult {
        fast: state.fast_value,
        slow: state.slow_value,
        drift_score,
        drifting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ewma_initialization() {
        let mut state = DualEwmaState::new("test".to_string());
        let params = EwmaParams::default();

        let r = ewma_update(&mut state, 0.5, &params);
        assert!((r.fast - 0.5).abs() < 1e-10);
        assert!((r.slow - 0.5).abs() < 1e-10);
        assert!(!r.drifting);
    }

    #[test]
    fn test_ewma_stable_no_drift() {
        let mut state = DualEwmaState::new("test".to_string());
        let params = EwmaParams::default();

        // Feed constant values -> no drift
        for _ in 0..100 {
            let r = ewma_update(&mut state, 0.1, &params);
            assert!(!r.drifting, "Constant input should not drift");
        }
    }

    #[test]
    fn test_ewma_detects_gradual_shift() {
        let mut state = DualEwmaState::new("test".to_string());
        let params = EwmaParams::default();

        // Phase 1: establish baseline at 0.1
        for _ in 0..50 {
            ewma_update(&mut state, 0.1, &params);
        }

        // Phase 2: sustained high values - fast EWMA catches up quickly,
        // slow EWMA trails behind -> drift_score = |fast-slow|/slow peaks early
        let mut drifted = false;
        for _ in 0..100 {
            let r = ewma_update(&mut state, 0.8, &params);
            if r.drifting {
                drifted = true;
                break;
            }
        }

        assert!(
            drifted,
            "Should detect drift when input shifts from 0.1 to 0.8"
        );
    }

    #[test]
    fn test_ewma_fast_responds_quicker() {
        let mut state = DualEwmaState::new("test".to_string());
        let params = EwmaParams::default();

        // Baseline
        for _ in 0..30 {
            ewma_update(&mut state, 0.1, &params);
        }

        // Sudden change
        ewma_update(&mut state, 0.9, &params);

        // Fast should react more than slow
        assert!(
            state.fast_value > state.slow_value,
            "Fast EWMA should respond more to sudden change: fast={} slow={}",
            state.fast_value,
            state.slow_value
        );
    }
}
