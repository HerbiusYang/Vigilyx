//! v5.0 Grouped Fusion Pipeline - Tech layer + Blind-spot layer -> Cautious combine.

//! Architecture:
//! ```text
//! Tech Layer (A-E) Blind-spot Layer (F-G-H)

//! A: Sender Reputation F: Semantic Intent
//! B: Content Analysis G: Identity Anomaly
//! C: Behavior Baseline Copula H: Transaction Corr.
//! D: URL/Link Analysis -> Discount
//! E: Protocol Compli. -> Murphy Dempster combine
//! -> Self-comb
//! m_blind (with)
//! m_tech

//! Cautious Combine (max)

//! m_fused (b,d,u,)

//! K_cross, Novelty, BetP

//! The tech layer uses Murphy weighted-average fusion (Copula-discounted for
//! correlated engines A-E). The blind-spot layer uses standard Dempster
//! combination (F-G-H detect orthogonal aspects). The two layers are merged
//! via the Cautious rule (blind-spot can only upgrade threat, never downgrade).

use std::borrow::Cow;

use vigilyx_core::security::Bpa;

use crate::engine_map::{ENGINE_COUNT, EngineId};
use crate::fusion::{FusionResult, copula_discount_flat, murphy_fusion};
use crate::tbm::{cautious_combine, compute_k_cross, compute_novelty, pignistic_threat};

// Layer Definitions

/// Tech-layer engine IDs: traditional signal-based analysis.
const TECH_ENGINES: [EngineId; 5] = [
    EngineId::A, // Sender Reputation
    EngineId::B, // Content Analysis
    EngineId::C, // Behavior Baseline
    EngineId::D, // URL/Link Analysis
    EngineId::E, // Protocol Compliance
];

/// Blind-spot layer engine IDs: semantic/behavioral/business-logic analysis.
const BLIND_ENGINES: [EngineId; 3] = [
    EngineId::F, // Semantic Intent
    EngineId::G, // Identity Anomaly
    EngineId::H, // Transaction Correlation
];

// Result Type

/// Result of the v5.0 grouped fusion pipeline.
#[derive(Debug, Clone)]
pub struct GroupedFusionResult {
    /// Final fused BPA (after Cautious combine of tech x blind-spot).
    pub fused: Bpa,
    /// Tech layer fused BPA.
    pub tech_bpa: Bpa,
    /// Blind-spot layer fused BPA.
    pub blind_bpa: Bpa,
    /// Intra-tech-layer conflict factor (from Murphy fusion).
    pub k_conflict_tech: f64,
    /// Cross-layer conflict: m_tech.b m_blind.d + m_tech.d m_blind.b.
    pub k_cross: f64,
    /// Novelty signal: 1 - (1 -) across all engines.
    pub novelty: f64,
    /// Pignistic probability: BetP(Threat) on final fused BPA.
    pub betp: f64,
    /// Murphy credibility weights for tech-layer engines (A-E).
    pub tech_credibility_weights: Vec<f64>,
    /// Number of engines that contributed non-vacuous BPAs.
    pub engine_count: usize,
}

// Grouped Fusion Entry Point

/// v5.0 grouped fusion pipeline.

/// # Arguments
/// - `engine_bpas`: slice of `(EngineId, Bpa)` pairs from engine-level pre-fusion.
/// Each engine should have already combined its internal modules via
/// Dempster rule. Vacuous engines may be included (they'll be filtered).
/// - `corr_flat`: flat 8x8 (or NxN for active tech engines) correlation matrix
/// for Copula discount. Pass empty slice to skip Copula discount.
/// - `eta`: uncertainty -> threat conversion factor for risk_score (not directly
/// used here but passed through for consistency).

/// # Returns
/// `GroupedFusionResult` with all fusion metrics.
pub fn grouped_fusion(
    engine_bpas: &[(EngineId, Bpa)],
    corr_flat: &[f64],
    _eta: f64,
) -> GroupedFusionResult {
    // 1. Partition into tech vs blind-spot (stack arrays, no heap allocation)
    let mut tech_bpas = [Bpa::vacuous(); 5];
    let mut tech_ids = [EngineId::A; 5];
    let mut n_tech = 0usize;
    let mut blind_bpas = [Bpa::vacuous(); 3];
    let mut n_blind = 0usize;
    let mut all_epsilons = [0.0_f64; ENGINE_COUNT];
    let mut n_eps = 0usize;

    for &(engine_id, bpa) in engine_bpas {
        if bpa.is_vacuous() {
            continue;
        }
        all_epsilons[n_eps] = bpa.epsilon;
        n_eps += 1;

        if is_tech_engine(engine_id) {
            tech_bpas[n_tech] = bpa;
            tech_ids[n_tech] = engine_id;
            n_tech += 1;
        } else if is_blind_engine(engine_id) {
            blind_bpas[n_blind] = bpa;
            n_blind += 1;
        }
    }

    let tech_slice = &tech_bpas[..n_tech];
    let tech_id_slice = &tech_ids[..n_tech];
    let blind_slice = &blind_bpas[..n_blind];
    let eps_slice = &all_epsilons[..n_eps];
    let total_engines = n_tech + n_blind;

    // 2. Tech-layer fusion: Copula discount -> Murphy
    let tech_result = fuse_tech_layer(tech_slice, tech_id_slice, corr_flat);

    // 3. Blind-spot layer fusion: Dempster combination
    let blind_result = fuse_blind_layer(blind_slice);

    // 4. Cross-layer fusion: Cautious combine
    let (fused, k_cross) = if tech_result.engine_count > 0 && n_blind > 0 {
        let k = compute_k_cross(tech_result.fused, blind_result);
        let combined = cautious_combine(tech_result.fused, blind_result);
        (combined, k)
    } else if tech_result.engine_count > 0 {
        (tech_result.fused, 0.0)
    } else if n_blind > 0 {
        (blind_result, 0.0)
    } else {
        (Bpa::vacuous(), 0.0)
    };

    // 5. Compute derived metrics
    let novelty = compute_novelty(eps_slice);
    let betp = pignistic_threat(fused);

    GroupedFusionResult {
        fused,
        tech_bpa: tech_result.fused,
        blind_bpa: blind_result,
        k_conflict_tech: tech_result.k_conflict,
        k_cross,
        novelty,
        betp,
        tech_credibility_weights: tech_result.credibility_weights,
        engine_count: total_engines,
    }
}

// Internal Layer Fusion

/// Fuse tech-layer engines (A-E) via Copula discount -> Murphy fusion.
fn fuse_tech_layer(bpas: &[Bpa], engine_ids: &[EngineId], corr_flat: &[f64]) -> FusionResult {
    if bpas.is_empty() {
        return FusionResult {
            fused: Bpa::vacuous(),
            k_conflict: 0.0,
            engine_count: 0,
            credibility_weights: vec![],
        };
    }

    // Build sub-correlation matrix for active tech engines (stack array: 5x5 max = 25)
    let n = bpas.len();
    let mut sub_corr = [0.0_f64; 25]; // 5 tech engines max -> 5x5
    let has_corr = !corr_flat.is_empty() && corr_flat.len() >= ENGINE_COUNT * ENGINE_COUNT;
    if has_corr {
        for (i, &ei) in engine_ids.iter().enumerate() {
            for (j, &ej) in engine_ids.iter().enumerate() {
                sub_corr[i * n + j] = corr_flat[ei.as_index() * ENGINE_COUNT + ej.as_index()];
            }
        }
    }

    // Copula discount -> Murphy fusion (Cow avoids.to_vec() when discount skipped)
    let discounted: Cow<'_, [Bpa]> = if has_corr {
        Cow::Owned(copula_discount_flat(bpas, &sub_corr[..n * n], n))
    } else {
        Cow::Borrowed(bpas)
    };

    murphy_fusion(&discounted)
}

/// Fuse blind-spot layer engines (F-G-H) via standard Dempster combination.
///
/// These engines analyze orthogonal dimensions (semantic, identity, transaction),
/// so we use standard Dempster rule without Murphy averaging or Copula discount.
fn fuse_blind_layer(bpas: &[Bpa]) -> Bpa {
    match bpas.len() {
        0 => Bpa::vacuous(),
        1 => bpas[0],
        _ => {
            let mut acc = bpas[0];
            for &bpa in &bpas[1..] {
                let r = vigilyx_core::security::dempster_combine(acc, bpa);
                acc = r.combined;
            }
            acc
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

#[inline]
fn is_tech_engine(id: EngineId) -> bool {
    TECH_ENGINES.contains(&id)
}

#[inline]
fn is_blind_engine(id: EngineId) -> bool {
    BLIND_ENGINES.contains(&id)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_map::DEFAULT_CORRELATION_MATRIX;

    const TOL: f64 = 1e-6;

    /// Helper: create engine BPA pairs from a list of (EngineId, b, d, u, eps)
    fn make_bpas(specs: &[(EngineId, f64, f64, f64, f64)]) -> Vec<(EngineId, Bpa)> {
        specs
            .iter()
            .map(|&(id, b, d, u, eps)| {
                (
                    id,
                    Bpa {
                        b,
                        d,
                        u,
                        epsilon: eps,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn test_grouped_fusion_tech_only() {
        // Only tech engines present
        let bpas = make_bpas(&[
            (EngineId::A, 0.6, 0.2, 0.2, 0.0),
            (EngineId::B, 0.7, 0.1, 0.2, 0.0),
            (EngineId::D, 0.5, 0.3, 0.2, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert!(r.fused.is_valid(), "Fused BPA invalid: {:?}", r.fused);
        assert_eq!(r.engine_count, 3);
        // No blind-spot engines -> K_cross = 0
        assert!((r.k_cross - 0.0).abs() < TOL);
        // Tech result = fused (no blind layer to cautious-combine)
        assert!((r.fused.b - r.tech_bpa.b).abs() < TOL);
        assert!(r.blind_bpa.is_vacuous());
    }

    #[test]
    fn test_grouped_fusion_blind_only() {
        // Only blind-spot engines present
        let bpas = make_bpas(&[
            (EngineId::F, 0.5, 0.2, 0.3, 0.0),
            (EngineId::G, 0.6, 0.1, 0.3, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &[], 0.7);

        assert!(r.fused.is_valid(), "Fused BPA invalid: {:?}", r.fused);
        assert_eq!(r.engine_count, 2);
        assert!((r.k_cross - 0.0).abs() < TOL);
        assert!(r.tech_bpa.is_vacuous());
    }

    #[test]
    fn test_grouped_fusion_full_pipeline() {
        // All 8 engines present
        let bpas = make_bpas(&[
            (EngineId::A, 0.5, 0.2, 0.3, 0.0),
            (EngineId::B, 0.6, 0.1, 0.3, 0.0),
            (EngineId::C, 0.4, 0.3, 0.3, 0.0),
            (EngineId::D, 0.7, 0.1, 0.2, 0.0),
            (EngineId::E, 0.5, 0.2, 0.3, 0.0),
            (EngineId::F, 0.3, 0.4, 0.3, 0.0),
            (EngineId::G, 0.2, 0.5, 0.3, 0.0),
            (EngineId::H, 0.4, 0.3, 0.3, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert!(r.fused.is_valid(), "Fused BPA invalid: {:?}", r.fused);
        assert_eq!(r.engine_count, 8);
        // With both layers present, K_cross should be non-zero
        // (tech sees threat, blind sees more benign)
        assert!(r.k_cross > 0.0, "K_cross should be non-zero: {}", r.k_cross);
        // BetP should be between 0 and 1
        assert!(
            r.betp >= 0.0 && r.betp <= 1.0,
            "BetP out of range: {}",
            r.betp
        );
    }

    #[test]
    fn test_grouped_fusion_with_epsilon() {
        // Engines report unknown threats (ε > 0)
        let bpas = make_bpas(&[
            (EngineId::A, 0.4, 0.2, 0.3, 0.1),
            (EngineId::B, 0.5, 0.1, 0.3, 0.1),
            (EngineId::F, 0.3, 0.2, 0.4, 0.1),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert!(r.fused.is_valid(), "Fused BPA invalid: {:?}", r.fused);
        // Novelty should be non-trivial with 3 engines reporting ε = 0.1
        // Novelty = 1 - (0.9)^3 = 1 - 0.729 = 0.271
        assert!(
            (r.novelty - 0.271).abs() < 0.01,
            "Novelty should be ~0.271: {}",
            r.novelty
        );
    }

    #[test]
    fn test_k_cross_tech_vs_blind_disagreement() {
        // Tech sees threat, blind sees safe -> high K_cross
        let bpas = make_bpas(&[
            (EngineId::A, 0.8, 0.1, 0.1, 0.0),
            (EngineId::B, 0.7, 0.1, 0.2, 0.0),
            (EngineId::F, 0.1, 0.8, 0.1, 0.0),
            (EngineId::G, 0.1, 0.7, 0.2, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert!(
            r.k_cross > 0.4,
            "K_cross should be high for disagreement: {}",
            r.k_cross
        );
    }

    #[test]
    fn test_k_cross_tech_vs_blind_agreement() {
        // Both layers agree on threat -> low K_cross
        let bpas = make_bpas(&[
            (EngineId::A, 0.7, 0.1, 0.2, 0.0),
            (EngineId::B, 0.8, 0.1, 0.1, 0.0),
            (EngineId::F, 0.6, 0.2, 0.2, 0.0),
            (EngineId::G, 0.7, 0.1, 0.2, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert!(
            r.k_cross < 0.3,
            "K_cross should be low for agreement: {}",
            r.k_cross
        );
    }

    #[test]
    fn test_cautious_combine_upgrades_threat() {
        // Tech says safe, blind-spot detects threat -> final should upgrade
        let bpas = make_bpas(&[
            (EngineId::A, 0.1, 0.7, 0.2, 0.0),
            (EngineId::B, 0.1, 0.6, 0.3, 0.0),
            (EngineId::F, 0.8, 0.1, 0.1, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        // Cautious combine: max(b) -> blind-spot's 0.8 should dominate
        assert!(
            r.fused.b > r.tech_bpa.b,
            "Cautious should upgrade: fused.b={} > tech.b={}",
            r.fused.b,
            r.tech_bpa.b
        );
    }

    #[test]
    fn test_novelty_accumulation() {
        // Multiple engines with epsilon -> novelty> any single epsilon
        let bpas = make_bpas(&[
            (EngineId::A, 0.4, 0.2, 0.2, 0.2),
            (EngineId::B, 0.3, 0.2, 0.3, 0.2),
            (EngineId::C, 0.5, 0.1, 0.2, 0.2),
            (EngineId::F, 0.4, 0.1, 0.3, 0.2),
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        // Novelty = 1 - (0.8)^4 = 1 - 0.4096 = 0.5904
        assert!(r.novelty > 0.55, "Novelty should accumulate: {}", r.novelty);
    }

    #[test]
    fn test_grouped_fusion_vacuous_filtered() {
        // Some engines vacuous -> filtered out
        let bpas = make_bpas(&[
            (EngineId::A, 0.6, 0.2, 0.2, 0.0),
            (EngineId::B, 0.0, 0.0, 1.0, 0.0), // vacuous
            (EngineId::F, 0.5, 0.2, 0.3, 0.0),
            (EngineId::G, 0.0, 0.0, 1.0, 0.0), // vacuous
        ]);
        let r = grouped_fusion(&bpas, &DEFAULT_CORRELATION_MATRIX, 0.7);

        assert_eq!(r.engine_count, 2, "Vacuous should be filtered");
    }

    #[test]
    fn test_grouped_fusion_empty() {
        let r = grouped_fusion(&[], &[], 0.7);
        assert!(r.fused.is_vacuous());
        assert_eq!(r.engine_count, 0);
        assert!((r.novelty - 0.0).abs() < TOL);
        assert!((r.k_cross - 0.0).abs() < TOL);
    }

    #[test]
    fn test_betp_range() {
        let bpas = make_bpas(&[
            (EngineId::A, 0.5, 0.2, 0.3, 0.0),
            (EngineId::F, 0.6, 0.1, 0.3, 0.0),
        ]);
        let r = grouped_fusion(&bpas, &[], 0.7);

        assert!(
            r.betp >= 0.0 && r.betp <= 1.0,
            "BetP should be [0,1]: {}",
            r.betp
        );
    }
}
