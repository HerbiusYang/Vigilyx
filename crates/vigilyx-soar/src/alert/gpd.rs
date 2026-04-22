//! Generalized Pareto Distribution (GPD) tail estimator.

//! Uses probability-weighted moments (PWM) for parameter estimation:
//! ```text
//! P(X> x | X> u) = (1 + xi*(x-u)/sigma)^{-1/xi}

//! PWM is more stable than MLE for small samples and avoids iterative optimization.

use std::collections::VecDeque;

/// GPD parameters fitted from exceedances.
#[derive(Debug, Clone, Copy)]
pub(super) struct GpdParams {
    /// Shape parameter xi
    xi: f64,
    /// Scale parameter sigma
    sigma: f64,
    /// Threshold u (95th percentile)
    threshold: f64,
    /// Exceedance rate lambda = N_u / N
    exceedance_rate: f64,
}

/// Online GPD estimator using probability-weighted moments (PWM).
///
/// PWM is more stable than MLE for small samples and avoids iterative optimization.
/// For exceedances y_i = x_i - u:
/// beta_0 = mean(y)
/// beta_1 = sum (n-i)/(n*(n-1)) * y_{(i)} (order statistics)
/// sigma = 2*beta_0*beta_1 / (beta_0 - 2*beta_1)
/// xi = beta_0 / (beta_0 - 2*beta_1) - 2
pub(super) struct GpdEstimator {
    /// Rolling window of recent risk scores for percentile estimation.
    risk_window: VecDeque<f64>,
    /// Maximum window size.
    max_window: usize,
    /// Quantile for threshold (default: 0.95).
    quantile: f64,
    /// Cached GPD fit (invalidated on push).
    cached_params: Option<Option<GpdParams>>,
}

impl GpdEstimator {
    pub(super) fn new(max_window: usize) -> Self {
        Self {
            risk_window: VecDeque::with_capacity(max_window),
            max_window,
            quantile: 0.95,
            cached_params: None,
        }
    }

    /// Push a new risk score observation.
    #[inline]
    pub(super) fn push(&mut self, score: f64) {
        if self.risk_window.len() >= self.max_window {
            self.risk_window.pop_front();
        }
        self.risk_window.push_back(score);
        self.cached_params = None; // Invalidate cache
    }

    /// Fit GPD to current window. Returns None if insufficient data.
    /// Uses cached result if available (cache invalidated on push).
    pub(super) fn fit(&mut self) -> Option<GpdParams> {
        if let Some(cached) = self.cached_params {
            return cached;
        }
        let result = self.fit_inner();
        self.cached_params = Some(result);
        result
    }

    /// Internal GPD fitting (uncached).
    fn fit_inner(&self) -> Option<GpdParams> {
        let n = self.risk_window.len();
        if n < 30 {
            return None;
        }

        // Sort scores for percentile computation
        let mut sorted: Vec<f64> = self.risk_window.iter().copied().collect();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Threshold u = quantile
        let idx = ((n as f64) * self.quantile) as usize;
        let threshold = sorted[idx.min(n - 1)];

        // Extract exceedances - already sorted (from sorted tail), no re-sort needed
        let exceedances: Vec<f64> = sorted
            .iter()
            .filter(|&&x| x > threshold)
            .map(|&x| x - threshold)
            .collect();

        let n_exc = exceedances.len();
        if n_exc < 5 {
            return None;
        }

        // PWM estimation
        let beta_0: f64 = exceedances.iter().sum::<f64>() / n_exc as f64;

        // beta_1 from order statistics - exceedances already sorted (ascending)
        // Hoist invariant divisor out of the loop (was recomputed N_exc times)
        let inv_denom = 1.0 / ((n_exc * (n_exc - 1)) as f64).max(1.0);
        let beta_1: f64 = exceedances
            .iter()
            .enumerate()
            .map(|(i, &y)| {
                let weight = (n_exc - 1 - i) as f64 * inv_denom;
                weight * y
            })
            .sum();

        let denom = beta_0 - 2.0 * beta_1;
        if denom.abs() < 1e-12 {
            return Some(GpdParams {
                xi: 0.0,
                sigma: beta_0,
                threshold,
                exceedance_rate: n_exc as f64 / n as f64,
            });
        }

        let sigma = 2.0 * beta_0 * beta_1 / denom;
        let xi = beta_0 / denom - 2.0;

        if sigma <= 0.0 || !(-0.5..=2.0).contains(&xi) {
            return None;
        }

        Some(GpdParams {
            xi,
            sigma,
            threshold,
            exceedance_rate: n_exc as f64 / n as f64,
        })
    }

    /// Compute return period and CVaR in a single call (single GPD fit).
    ///
    /// Returns `(return_period, cvar)`.
    pub(super) fn return_period_and_cvar(&mut self, x: f64) -> (f64, f64) {
        let params = match self.fit() {
            Some(p) => p,
            None => return (0.0, x),
        };

        // -- Return period --
        let return_period = if x <= params.threshold {
            1.0
        } else {
            let y = x - params.threshold;
            let tail_prob = if params.xi.abs() < 1e-10 {
                (-y / params.sigma).exp()
            } else {
                let inner = 1.0 + params.xi * y / params.sigma;
                if inner <= 0.0 {
                    0.0
                } else {
                    inner.powf(-1.0 / params.xi)
                }
            };
            let exceedance_prob = params.exceedance_rate * tail_prob;
            if exceedance_prob > 1e-15 {
                1.0 / exceedance_prob
            } else {
                f64::INFINITY
            }
        };

        // -- CVaR --
        let cvar = if x <= params.threshold {
            // Below threshold: streaming mean of exceedances above x (no allocation)
            let (sum, count) = self
                .risk_window
                .iter()
                .filter(|&&v| v > x)
                .fold((0.0_f64, 0u32), |(s, c), &v| (s + v, c + 1));
            if count == 0 { x } else { sum / count as f64 }
        } else if params.xi >= 1.0 {
            f64::INFINITY
        } else {
            let y = x - params.threshold;
            x + (params.sigma + params.xi * y) / (1.0 - params.xi)
        };

        (return_period, cvar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpd_estimator_insufficient_data() {
        let mut est = GpdEstimator::new(100);
        assert!(est.fit().is_none());
    }

    #[test]
    fn test_gpd_estimator_with_data() {
        let mut est = GpdEstimator::new(200);
        // Feed 100 normal observations
        for i in 0..100 {
            est.push(0.1 + (i as f64) * 0.005);
        }
        // The fit may or may not succeed depending on tail structure
        // At minimum it shouldn't panic
        let _ = est.fit();
    }

    #[test]
    fn test_gpd_return_period_monotonic() {
        let mut est = GpdEstimator::new(500);
        // Create a distribution with a clear tail
        for _ in 0..80 {
            est.push(0.1);
        }
        for _ in 0..15 {
            est.push(0.3);
        }
        for _ in 0..5 {
            est.push(0.8);
        }
        // Higher risk should have higher return period (combined call)
        let (rp_low, _cvar_low) = est.return_period_and_cvar(0.3);
        let (rp_high, _cvar_high) = est.return_period_and_cvar(0.8);
        // rp_high should be>= rp_low (more extreme = rarer)
        assert!(
            rp_high >= rp_low,
            "Higher risk should have higher return period: rp(0.3)={}, rp(0.8)={}",
            rp_low,
            rp_high
        );
    }
}
