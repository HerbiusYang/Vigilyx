//! Adversarial robustness layer (Phase 5).

//! Ensures no single engine dominates the fusion output, making it harder
//! for an attacker to bypass detection by evading one dimension:

//! 1. **Diversity constraint**: `w_i <= 0.4 w_j` - no engine> 40% of total weight
//! 2. **Degradation analysis**: simulate removing each engine, measure worst-case drop
//! 3. **Weight redistribution**: if diversity violated, redistribute excess to other engines

use crate::bpa::Bpa;

/// Maximum fraction of total weight any single engine may hold.
const MAX_WEIGHT_FRACTION: f64 = 0.40;

/// Result of robustness checking/enforcement.
#[derive(Debug, Clone)]
pub struct RobustnessResult {
   /// Whether diversity constraint was already satisfied.
    pub diversity_ok: bool,
   /// Maximum single-engine weight fraction (before enforcement).
    pub max_weight_fraction: f64,
   /// Worst-case degradation: max drop in risk score when removing one engine.
    pub worst_case_degradation: f64,
   /// Index of engine whose removal causes worst degradation.
    pub most_critical_engine: usize,
   /// Number of engines that were weight-capped.
    pub engines_capped: usize,
}

/// Enforce diversity constraint on Murphy credibility weights.

/// Modifies `weights` in-place so that no single weight exceeds
/// `MAX_WEIGHT_FRACTION` of the total. Excess weight is redistributed
/// proportionally among non-capped engines.

/// # Arguments
/// - `weights`: Murphy credibility weights (will be modified in-place)

/// # Returns
/// Number of engines that were capped.
#[inline]
pub fn enforce_weight_diversity(weights: &mut [f64]) -> usize {
    let n = weights.len();
    if n <= 1 {
        return 0;
    }

    let mut capped = 0;
   // Iterate up to N times (convergence guaranteed since we only reduce weights)
    for _ in 0..n {
        let total: f64 = weights.iter().sum();
        if total < 1e-15 {
            break;
        }

        let cap = total * MAX_WEIGHT_FRACTION;
        let mut excess = 0.0_f64;
        let mut uncapped_total = 0.0_f64;
        let mut any_over = false;

        for w in weights.iter() {
            if *w > cap + 1e-12 {
                excess += *w - cap;
                any_over = true;
            } else {
                uncapped_total += *w;
            }
        }

        if !any_over {
            break;
        }

       // Cap overweight engines, redistribute excess proportionally
        for w in weights.iter_mut() {
            if *w > cap + 1e-12 {
               *w = cap;
                capped += 1;
            } else if uncapped_total > 1e-15 {
               // Proportional redistribution
               *w += excess * (*w / uncapped_total);
            }
        }
    }

   // Re-normalize to sum = 1.0
    let total: f64 = weights.iter().sum();
    if total > 1e-15 {
        for w in weights.iter_mut() {
           *w /= total;
        }
    }

    capped
}

/// Compute worst-case degradation: for each engine, simulate its removal
/// and measure how much the fused risk score drops.

/// # Arguments
/// - `engine_bpas`: per-engine BPAs (after within-engine combination)
/// - `weights`: Murphy credibility weights
/// - `eta`: risk score parameter (b + u)

/// # Returns
/// `(worst_degradation, most_critical_engine_index)`
pub fn worst_case_degradation(engine_bpas: &[Bpa], weights: &[f64], eta: f64) -> (f64, usize) {
    let n = engine_bpas.len();
    if n <= 1 {
        return (1.0, 0); // Single engine: removing it loses everything
    }

   // Full-ensemble risk
    let full_bpa = weighted_average_bpa(engine_bpas, weights);
    let full_risk = full_bpa.risk_score(eta);

    let compute_drop = |skip: usize| -> (f64, usize) {
        let mut sub_bpas: Vec<Bpa> = Vec::with_capacity(n - 1);
        let mut sub_weights: Vec<f64> = Vec::with_capacity(n - 1);
        for i in 0..n {
            if i != skip {
                sub_bpas.push(engine_bpas[i]);
                sub_weights.push(weights[i]);
            }
        }

        let total: f64 = sub_weights.iter().sum();
        if total > 1e-15 {
            for w in sub_weights.iter_mut() {
               *w /= total;
            }
        }

        let sub_bpa = weighted_average_bpa(&sub_bpas, &sub_weights);
        let sub_risk = sub_bpa.risk_score(eta);
        ((full_risk - sub_risk).abs(), skip)
    };

   // Sequential LOO: N <= 8, each iteration is weighted_average + risk_score (~50ns).
   // Rayon dispatch overhead exceeds total 8x50ns = 400ns computation.
    let (worst_drop, worst_idx) = (0..n)
        .map(compute_drop)
        .fold((0.0_f64, 0), |a, b| if b.0 > a.0 { b } else { a });

    (worst_drop, worst_idx)
}

/// Compute weighted average BPA (Murphy step).
#[inline]
fn weighted_average_bpa(bpas: &[Bpa], weights: &[f64]) -> Bpa {
    let mut b = 0.0_f64;
    let mut d = 0.0_f64;
    let mut u = 0.0_f64;

    for (bpa, &w) in bpas.iter().zip(weights.iter()) {
        b += w * bpa.b;
        d += w * bpa.d;
        u += w * bpa.u;
    }

    Bpa::new(b, d, u)
}

/// Full robustness check: enforce diversity + measure degradation.

/// # Arguments
/// - `engine_bpas`: per-engine BPAs
/// - `weights`: Murphy credibility weights (modified in-place)
/// - `eta`: risk score parameter
pub fn check_and_enforce(engine_bpas: &[Bpa], weights: &mut [f64], eta: f64) -> RobustnessResult {
    let n = weights.len();
    if n == 0 {
        return RobustnessResult {
            diversity_ok: true,
            max_weight_fraction: 0.0,
            worst_case_degradation: 0.0,
            most_critical_engine: 0,
            engines_capped: 0,
        };
    }

   // Check pre-enforcement state
    let total: f64 = weights.iter().sum();
    let max_w = weights.iter().cloned().fold(0.0_f64, f64::max);
    let max_fraction = if total > 1e-15 { max_w / total } else { 0.0 };
    let diversity_ok = max_fraction <= MAX_WEIGHT_FRACTION + 1e-12;

   // Enforce
    let engines_capped = enforce_weight_diversity(weights);

   // Degradation analysis (on post-enforcement weights)
    let (worst_deg, most_critical) = worst_case_degradation(engine_bpas, weights, eta);

    RobustnessResult {
        diversity_ok,
        max_weight_fraction: max_fraction,
        worst_case_degradation: worst_deg,
        most_critical_engine: most_critical,
        engines_capped,
    }
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforce_diversity_no_cap_needed() {
       // Three equal weights - no capping needed
        let mut weights = vec![0.33, 0.33, 0.34];
        let capped = enforce_weight_diversity(&mut weights);
        assert_eq!(capped, 0);
        let total: f64 = weights.iter().sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_enforce_diversity_caps_dominant() {
       // One engine dominates at 70%
        let mut weights = vec![0.70, 0.15, 0.15];
        let capped = enforce_weight_diversity(&mut weights);
        assert!(capped > 0);

       // After enforcement, max weight should be <= 40%
        let total: f64 = weights.iter().sum();
        let max_frac = weights.iter().cloned().fold(0.0_f64, f64::max) / total;
        assert!(
            max_frac <= MAX_WEIGHT_FRACTION + 0.01,
            "Max fraction {:.3} should be ≤ {:.3}",
            max_frac,
            MAX_WEIGHT_FRACTION
        );
    }

    #[test]
    fn test_enforce_diversity_preserves_sum() {
        let mut weights = vec![0.80, 0.10, 0.05, 0.05];
        enforce_weight_diversity(&mut weights);
        let total: f64 = weights.iter().sum();
        assert!(
            (total - 1.0).abs() < 1e-10,
            "Weights should sum to 1.0: got {:.6}",
            total
        );
    }

    #[test]
    fn test_worst_case_degradation_single_engine() {
        let bpas = vec![Bpa::new(0.5, 0.3, 0.2)];
        let weights = vec![1.0];
        let (deg, idx) = worst_case_degradation(&bpas, &weights, 0.7);
        assert_eq!(idx, 0);
        assert!(deg > 0.5, "Removing sole engine should lose all risk");
    }

    #[test]
    fn test_worst_case_degradation_two_engines() {
        let bpas = vec![
            Bpa::new(0.8, 0.1, 0.1), // High threat
            Bpa::new(0.1, 0.8, 0.1), // Safe
        ];
        let weights = vec![0.5, 0.5];
        let (deg, idx) = worst_case_degradation(&bpas, &weights, 0.7);
       // Removing the threat engine should cause the biggest drop
        assert_eq!(idx, 0);
        assert!(deg > 0.2);
    }

    #[test]
    fn test_check_and_enforce_full() {
        let bpas = vec![
            Bpa::new(0.6, 0.2, 0.2),
            Bpa::new(0.4, 0.3, 0.3),
            Bpa::new(0.3, 0.4, 0.3),
        ];
        let mut weights = vec![0.60, 0.25, 0.15];
        let result = check_and_enforce(&bpas, &mut weights, 0.7);

        assert!(!result.diversity_ok, "60% should violate 40% cap");
        assert!(result.engines_capped > 0);
       // After enforcement, check fraction
        let max_w = weights.iter().cloned().fold(0.0_f64, f64::max);
        assert!(max_w <= MAX_WEIGHT_FRACTION + 0.01);
    }

    #[test]
    fn test_weighted_average_bpa_basic() {
        let bpas = vec![Bpa::new(0.8, 0.1, 0.1), Bpa::new(0.2, 0.7, 0.1)];
        let weights = vec![0.5, 0.5];
        let avg = weighted_average_bpa(&bpas, &weights);
        assert!((avg.b - 0.5).abs() < 0.01);
        assert!((avg.d - 0.4).abs() < 0.01);
        assert!((avg.u - 0.1).abs() < 0.01);
    }
}
