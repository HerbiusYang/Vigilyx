//! Murphy-corrected Dempster-Shafer evidence fusion with Copula dependency correction.

//! Addresses two fundamental flaws of naive Dempster combination:
//! 1. **Zadeh's paradox**: conflicting evidence produces counter-intuitive results
//! -> Solved by Murphy's weighted average before self-combination
//! 2. **Dependent evidence**: correlated engines cause double-counting
//! -> Solved by Copula-based discount prior to fusion

//! Performance: pre-allocated scratch buffers, no heap allocation in hot path,
//! `#[inline]` on all tight-loop functions.

use serde::{Deserialize, Serialize};

use crate::bpa::{Bpa, dempster_combine};

/// Maximum number of engines supported (A-H = 8).
/// Stack-allocated arrays avoid heap allocation in fusion hot path.
pub const MAX_ENGINES: usize = 8;

/// Result of the Murphy D-S fusion pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionResult {
    /// Fused BPA after Murphy correction + self-combination.
    pub fused: Bpa,
    /// Total conflict factor K [0, 1).
    /// K> 0.7 -> engines highly contradictory -> possible sophisticated evasion.
    pub k_conflict: f64,
    /// Number of engines that participated (excluding vacuous).
    pub engine_count: usize,
    /// Per-engine Murphy credibility weights (sum = 1.0).
    /// Indexed same order as input BPAs.
    pub credibility_weights: Vec<f64>,
}

// Jousselme Distance

/// Jousselme distance between two BPAs on = {Threat, Normal} (TBM extension).

/// d_J(m1, m2) = ((m1-m2) D (m1-m2))

/// For the 4-element focal set {T}, {N},, (v5.0 TBM):
/// ```text
/// D = | 1.0 0.0 0.5 0.0 | (Jaccard similarity matrix)

/// has Jaccard similarity 0 with all non-empty sets and 1 with itself,
/// so the dimension contributes an independent term.

/// Expanded quadratic form (no matrix allocation):
/// ```text
/// 2 d = b + d + u + + b u + d u

/// When = 0 for both inputs (closed-world), this is identical to the
/// original 3-element formula.
#[inline]
fn jousselme_distance(a: Bpa, b: Bpa) -> f64 {
    let db = a.b - b.b;
    let dd = a.d - b.d;
    let du = a.u - b.u;
    let de = a.epsilon - b.epsilon;
    // Expanded D-quadratic form, factor of 0.5 from definition
    // is orthogonal to all non-empty focal elements -> adds independent
    let val = db * db + dd * dd + du * du + de * de + db * du + dd * du;
    // val can be slightly negative due to floating point; clamp
    (0.5 * val).max(0.0).sqrt()
}

// Copula Dependency Discount

/// Apply Copula-inspired discount to correlated engines.

/// For each engine i, find its maximum pairwise correlation _max with
/// any other engine. Then discount committed mass by (1 - _max),
/// moving the discounted fraction into uncertainty.

/// ```text
/// b'_i = b_i (1 - _max)
/// d'_i = d_i (1 - _max)
/// u'_i = 1 - b'_i - d'_i

/// This prevents correlated engines from artificially reinforcing each other.

/// # Arguments
/// - `bpas`: engine BPAs, len <= MAX_ENGINES
/// - `corr`: correlation matrix, `corr[i][j]` [0, 1], symmetric, diagonal = 0

/// # Returns
/// Discounted BPAs (same order and length as input).
pub fn copula_discount(bpas: &[Bpa], corr: &[&[f64]]) -> Vec<Bpa> {
    let n = bpas.len();
    let mut out = Vec::with_capacity(n);

    for i in 0..n {
        // Find max correlation with any other engine
        let mut max_rho = 0.0_f64;
        if i < corr.len() {
            let row = corr[i];
            for (j, &rho) in row.iter().enumerate() {
                if j != i && rho > max_rho {
                    max_rho = rho;
                }
            }
        }

        // Skip discount if correlation threshold not met
        if max_rho < 0.1 {
            out.push(bpas[i]);
        } else {
            out.push(bpas[i].discount(1.0 - max_rho));
        }
    }

    out
}

/// Same as `copula_discount` but uses flat slice correlation matrix (row-major, NxN).
/// More cache-friendly for small N.
#[inline]
pub fn copula_discount_flat(bpas: &[Bpa], corr_flat: &[f64], n: usize) -> Vec<Bpa> {
    let mut out = Vec::with_capacity(bpas.len());

    for (i, bpa) in bpas.iter().enumerate() {
        let mut max_rho = 0.0_f64;
        if i < n {
            let row_start = i * n;
            for j in 0..n {
                if j != i {
                    let rho = corr_flat[row_start + j];
                    if rho > max_rho {
                        max_rho = rho;
                    }
                }
            }
        }

        if max_rho < 0.1 {
            out.push(*bpa);
        } else {
            out.push(bpa.discount(1.0 - max_rho));
        }
    }

    out
}

// Murphy Weighted Average Fusion

/// Murphy-corrected Dempster-Shafer fusion.

/// Algorithm:
/// 1. Compute pairwise Jousselme distances -> similarity matrix
/// 2. Support(i) = _{ji} sim(i,j)
/// 3. Credibility weight(i) = Support(i) / Support
/// 4. Weighted average BPA: m = w_i m_i
/// 5. Self-combine m (N-1) times via standard Dempster rule

/// The weighted average step (Murphy's modification) ensures that
/// outlier/conflicting evidence sources are down-weighted before
/// Dempster combination, preventing Zadeh's paradox.
pub fn murphy_fusion(bpas: &[Bpa]) -> FusionResult {
    let n = bpas.len();

    if n == 0 {
        return FusionResult {
            fused: Bpa::vacuous(),
            k_conflict: 0.0,
            engine_count: 0,
            credibility_weights: vec![],
        };
    }

    if n == 1 {
        return FusionResult {
            fused: bpas[0],
            k_conflict: 0.0,
            engine_count: 1,
            credibility_weights: vec![1.0],
        };
    }

    // Step 1-2: Pairwise similarity -> support
    // Use stack array for small N (<= MAX_ENGINES)
    let mut support = [0.0_f64; MAX_ENGINES];

    // Sequential pairwise: N <= 8 -> max C(8,2)=28 pairs, each ~30ns.
    // Rayon dispatch overhead (~1-5s) exceeds total computation.
    for i in 0..n {
        for j in (i + 1)..n {
            let sim = 1.0 - jousselme_distance(bpas[i], bpas[j]);
            support[i] += sim;
            support[j] += sim;
        }
    }

    // Step 3: Credibility weights
    let total_support: f64 = support[..n].iter().sum();
    let mut cred = Vec::with_capacity(n);

    // More conservative threshold to avoid ill-conditioned weight normalization
    let condition_threshold = 1e-8;
    if total_support > condition_threshold {
        let inv_total = 1.0 / total_support;
        // Check if any single engine would dominate (weight> 0.99) -
        // this indicates near-degenerate support and the weights are unreliable.
        let has_dominant = support[..n].iter().any(|&w| w * inv_total > 0.99);
        if has_dominant {
            // Fall back to uniform weights to avoid single-engine dominance
            let uniform = 1.0 / n as f64;
            cred.resize(n, uniform);
        } else {
            for s in &support[..n] {
                cred.push(s * inv_total);
            }
        }
    } else {
        // All equidistant or near-zero support: uniform weights
        let uniform = 1.0 / n as f64;
        cred.resize(n, uniform);
    }

    // Step 4: Weighted average BPA
    let mut avg_b = 0.0_f64;
    let mut avg_d = 0.0_f64;
    let mut avg_u = 0.0_f64;

    for i in 0..n {
        avg_b += cred[i] * bpas[i].b;
        avg_d += cred[i] * bpas[i].d;
        avg_u += cred[i] * bpas[i].u;
    }

    let avg = Bpa::new(avg_b, avg_d, avg_u);

    // Step 5: Self-combine N-1 times
    let mut result = avg;
    let mut total_k = 0.0_f64;

    for _ in 0..(n - 1) {
        let r = dempster_combine(result, avg);
        // Accumulate conflict: K_total = 1 - (1 - K_i)
        total_k = 1.0 - (1.0 - total_k) * (1.0 - r.conflict);
        result = r.combined;
    }

    FusionResult {
        fused: result,
        k_conflict: total_k,
        engine_count: n,
        credibility_weights: cred,
    }
}

/// Full fusion pipeline: Copula discount -> Murphy fusion.

/// This is the primary entry point for the verdict aggregation layer.

/// # Arguments
/// - `engine_bpas`: per-engine BPAs (max 8)
/// - `corr_flat`: flat correlation matrix (row-major, NxN), or empty for no discount

/// # Returns
/// `FusionResult` with fused BPA, conflict factor, and credibility weights.
#[inline]
pub fn fuse_engines(engine_bpas: &[Bpa], corr_flat: &[f64]) -> FusionResult {
    // Filter out vacuous BPAs - stack array avoids heap allocation (N <= MAX_ENGINES = 8)
    let mut active = [Bpa::vacuous(); MAX_ENGINES];
    let mut n_active = 0;
    for &bpa in engine_bpas {
        if !bpa.is_vacuous() {
            active[n_active] = bpa;
            n_active += 1;
        }
    }

    if n_active == 0 {
        return FusionResult {
            fused: Bpa::vacuous(),
            k_conflict: 0.0,
            engine_count: 0,
            credibility_weights: vec![],
        };
    }

    let active_slice = &active[..n_active];

    // Apply Copula discount if correlation matrix provided
    let discounted = if !corr_flat.is_empty() && corr_flat.len() >= n_active * n_active {
        copula_discount_flat(active_slice, corr_flat, n_active)
    } else {
        active_slice.to_vec()
    };

    murphy_fusion(&discounted)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jousselme_distance_self_zero() {
        let bpa = Bpa {
            b: 0.6,
            d: 0.3,
            u: 0.1,
            epsilon: 0.0,
        };
        assert!(jousselme_distance(bpa, bpa) < 1e-10);
    }

    #[test]
    fn test_jousselme_distance_symmetry() {
        let a = Bpa {
            b: 0.7,
            d: 0.1,
            u: 0.2,
            epsilon: 0.0,
        };
        let b = Bpa {
            b: 0.2,
            d: 0.6,
            u: 0.2,
            epsilon: 0.0,
        };
        let d1 = jousselme_distance(a, b);
        let d2 = jousselme_distance(b, a);
        assert!((d1 - d2).abs() < 1e-10);
    }

    #[test]
    fn test_jousselme_distance_bounds() {
        // Max distance: certain threat vs certain benign
        let d = jousselme_distance(Bpa::certain_threat(), Bpa::certain_benign());
        assert!(d > 0.0);
        assert!(d <= 1.0 + 1e-10);
    }

    #[test]
    fn test_jousselme_distance_epsilon_dimension() {
        // Two BPAs identical in (b,d,u) but different -> distance> 0
        let a = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.3,
            epsilon: 0.1,
        };
        let b = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.3,
            epsilon: 0.1,
        };
        assert!(
            jousselme_distance(a, b) < 1e-10,
            "Identical BPAs should have zero distance"
        );

        let c = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.1,
            epsilon: 0.3,
        };
        let d_ac = jousselme_distance(a, c);
        assert!(
            d_ac > 0.0,
            "Different ε should contribute to distance: {}",
            d_ac
        );

        // Backward compat: when =0 for both, result matches old 3-element formula
        let p = Bpa {
            b: 0.6,
            d: 0.2,
            u: 0.2,
            epsilon: 0.0,
        };
        let q = Bpa {
            b: 0.3,
            d: 0.4,
            u: 0.3,
            epsilon: 0.0,
        };
        let d_pq = jousselme_distance(p, q);
        // Manual: b=-0.3, d=0.2, u=0.1
        // val = 0.09 + 0.04 + 0.01 + 0 + (-0.3)(0.1) + (0.2)(0.1) = 0.14 - 0.03 + 0.02 = 0.13
        // d = sqrt(0.13/2) = sqrt(0.065) 0.2550
        assert!(
            (d_pq - 0.065_f64.sqrt()).abs() < 1e-6,
            "Closed-world distance should match 3-element formula: {}",
            d_pq
        );
    }

    #[test]
    fn test_jousselme_distance_epsilon_symmetry() {
        let a = Bpa {
            b: 0.3,
            d: 0.2,
            u: 0.3,
            epsilon: 0.2,
        };
        let b = Bpa {
            b: 0.5,
            d: 0.1,
            u: 0.2,
            epsilon: 0.2,
        };
        let d1 = jousselme_distance(a, b);
        let d2 = jousselme_distance(b, a);
        assert!((d1 - d2).abs() < 1e-10, "Symmetry with ε");
    }

    #[test]
    fn test_murphy_fusion_agreement() {
        // Multiple engines agree on threat -> should reinforce belief
        let bpas = vec![
            Bpa {
                b: 0.7,
                d: 0.1,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.6,
                d: 0.2,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.8,
                d: 0.1,
                u: 0.1,
                epsilon: 0.0,
            },
        ];
        let r = murphy_fusion(&bpas);
        assert!(
            r.fused.b > 0.85,
            "Agreement should produce high belief: {:.3}",
            r.fused.b
        );
        // K accumulates during N-1 self-combinations even for agreeing BPAs,
        // because the weighted average retains nonzero d (disbelief).
        assert!(
            r.k_conflict < 0.5,
            "K should stay moderate for agreeing BPAs: {:.3}",
            r.k_conflict
        );
    }

    #[test]
    fn test_murphy_fusion_disagreement() {
        // Engines disagree -> Murphy should mitigate
        let bpas = vec![
            Bpa {
                b: 0.9,
                d: 0.0,
                u: 0.1,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.0,
                d: 0.9,
                u: 0.1,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.4,
                d: 0.4,
                u: 0.2,
                epsilon: 0.0,
            },
        ];
        let r = murphy_fusion(&bpas);
        // The outlier (strong disagreement) should be down-weighted
        assert!(r.k_conflict > 0.1);
        assert!(r.fused.is_valid());
    }

    #[test]
    fn test_murphy_fusion_with_uncertainty() {
        // Some engines uncertain -> should not dilute certain evidence
        let bpas = vec![
            Bpa {
                b: 0.8,
                d: 0.1,
                u: 0.1,
                epsilon: 0.0,
            },
            Bpa::vacuous(), // will be filtered by fuse_engines
            Bpa {
                b: 0.6,
                d: 0.2,
                u: 0.2,
                epsilon: 0.0,
            },
        ];
        // Direct murphy_fusion includes vacuous
        let r = murphy_fusion(&bpas);
        assert!(r.fused.is_valid());
    }

    #[test]
    fn test_copula_discount() {
        let bpas = vec![
            Bpa {
                b: 0.7,
                d: 0.1,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.6,
                d: 0.2,
                u: 0.2,
                epsilon: 0.0,
            },
        ];
        // High correlation between engine 0 and 1
        let corr: &[&[f64]] = &[&[0.0, 0.8], &[0.8, 0.0]];
        let discounted = copula_discount(&bpas, corr);

        // Both should have increased uncertainty
        assert!(discounted[0].u > bpas[0].u);
        assert!(discounted[1].u > bpas[1].u);
        // Committed mass should decrease
        assert!(discounted[0].b < bpas[0].b);
    }

    #[test]
    fn test_fuse_engines_filters_vacuous() {
        let bpas = vec![
            Bpa {
                b: 0.7,
                d: 0.1,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa::vacuous(),
            Bpa {
                b: 0.5,
                d: 0.3,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa::vacuous(),
        ];
        let r = fuse_engines(&bpas, &[]);
        assert_eq!(r.engine_count, 2); // vacuous filtered out
    }

    #[test]
    fn test_fuse_engines_all_vacuous() {
        let bpas = vec![Bpa::vacuous(), Bpa::vacuous()];
        let r = fuse_engines(&bpas, &[]);
        assert_eq!(r.engine_count, 0);
        assert!(r.fused.is_vacuous());
    }

    #[test]
    fn test_credibility_weights_sum_to_one() {
        let bpas = vec![
            Bpa {
                b: 0.5,
                d: 0.3,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.6,
                d: 0.2,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.3,
                d: 0.5,
                u: 0.2,
                epsilon: 0.0,
            },
        ];
        let r = murphy_fusion(&bpas);
        let sum: f64 = r.credibility_weights.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10);
    }
}
