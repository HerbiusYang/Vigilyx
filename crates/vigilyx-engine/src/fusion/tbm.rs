//! TBM (Transferable Belief Model) operations for v5.0 open-world fusion.

//! Unlike closed-world Dempster combination (which normalizes conflict away),
//! TBM retains conflict mass as m() = epsilon, allowing detection of novel
//! (unknown-type) threats that fall outside the standard {Threat, Normal} frame.

//! Key operations:
//! - **Conjunctive combination**: conflict -> instead of normalization
//! - **Cautious combination**: component-wise max(b,d), min(u) for cross-layer fusion
//! - **Novelty**: accumulated across engines detects novel threats
//! - **Pignistic probability**: decision-making on closed-world projection

use vigilyx_core::security::Bpa;

// TBM Conjunctive Combination

/// TBM conjunctive combination (non-normalized).

/// For frame = {Threat, Normal}, conflict mass flows to m() = epsilon
/// rather than being normalized away as in Dempster's rule.

/// Mass assignments:
/// conflict = m1.b m2.d + m1.d m2.b
/// b = m1.b m2.b + m1.b m2.u + m1.u m2.b
/// d = m1.d m2.d + m1.d m2.u + m1.u m2.d
/// u = m1.u m2.u
/// = conflict + propagated epsilon terms

/// When both inputs have = 0, this reduces to un-normalized Dempster
/// (conflict stored in rather than discarded/renormalized).
pub fn tbm_conjunctive(m1: Bpa, m2: Bpa) -> Bpa {
   // Core mass products (closed-world frame {Threat, Normal, })
    let b = m1.b * m2.b + m1.b * m2.u + m1.u * m2.b;
    let d = m1.d * m2.d + m1.d * m2.u + m1.u * m2.d;
    let u = m1.u * m2.u;

   // Conflict mass: belief vs disbelief
    let k = m1.b * m2.d + m1.d * m2.b;

   // Epsilon propagation: existing interacts with all focal elements
   // absorbs: (1) direct conflict, (2) anything, (3) anything
    let eps_prop =
        m1.epsilon * (m2.b + m2.d + m2.u + m2.epsilon) + m2.epsilon * (m1.b + m1.d + m1.u); // m1. m2. already counted above

    let raw_eps = k + eps_prop;

   // Assemble and ensure numerical consistency
    let sum = b + d + u + raw_eps;
    if sum < 1e-15 {
        return Bpa::vacuous();
    }
    let inv = 1.0 / sum;

    Bpa {
        b: b * inv,
        d: d * inv,
        u: u * inv,
        epsilon: raw_eps * inv,
    }
}

/// Combine N BPAs via TBM conjunctive rule (sequential left-fold).

/// Returns vacuous BPA if the slice is empty.
pub fn tbm_combine_n(bpas: &[Bpa]) -> Bpa {
    match bpas.len() {
        0 => Bpa::vacuous(),
        1 => bpas[0],
        _ => {
            let mut acc = bpas[0];
            for &bpa in &bpas[1..] {
                acc = tbm_conjunctive(acc, bpa);
            }
            acc
        }
    }
}

// Cautious Combination

/// Cautious combination for cross-layer (tech x blind-spot) fusion.

/// The blind-spot layer can only **upgrade** threat assessment, never downgrade.
/// This implements the conservative "max" rule:
/// b = max(m_tech.b, m_blind.b)
/// d = max(m_tech.d, m_blind.d) - but will be bounded by 1-b- below
/// u = min(m_tech.u, m_blind.u)
/// = max(m_tech., m_blind.)

/// After component-wise selection, the result is renormalized to sum to 1.0.
pub fn cautious_combine(m_tech: Bpa, m_blind: Bpa) -> Bpa {
    let b = m_tech.b.max(m_blind.b);
    let d = m_tech.d.max(m_blind.d);
    let u = m_tech.u.min(m_blind.u);
    let eps = m_tech.epsilon.max(m_blind.epsilon);

   // Renormalize to maintain invariant b + d + u + = 1.0
    let sum = b + d + u + eps;
    if sum < 1e-15 {
        return Bpa::vacuous();
    }
    let inv = 1.0 / sum;

    Bpa {
        b: b * inv,
        d: d * inv,
        u: u * inv,
        epsilon: eps * inv,
    }
}

// Novelty Detection

/// Compute Novelty signal from per-engine epsilon values.

/// Novelty = 1 - (1 -)

/// When multiple engines report> 0 (evidence for unknown-type threats),
/// the novelty score rises rapidly toward 1.0. A high Novelty indicates
/// the email exhibits characteristics that don't fit the {Threat, Normal}
/// frame - i.e., a potential zero-day or novel attack vector.

/// Thresholds (alert.rs):
/// Novelty> 0.6 -> P1 alert
/// Novelty> 0.3 -> P2 alert
pub fn compute_novelty(engine_epsilons: &[f64]) -> f64 {
    if engine_epsilons.is_empty() {
        return 0.0;
    }
    let product: f64 = engine_epsilons
        .iter()
        .map(|&e| 1.0 - e.clamp(0.0, 1.0))
        .product();
    1.0 - product
}

// Pignistic Probability

/// Pignistic transformation for TBM four-tuple.

/// BetP(Threat) = b/(1-) + u/(2 (1-))

/// Projects the open-world belief onto the closed-world {Threat, Normal}
/// frame for final decision making. The mass is excluded (as it belongs
/// to, not to any hypothesis).

/// Fallback: when 1.0 (complete ignorance), returns 0.5.
pub fn pignistic_threat(bpa: Bpa) -> f64 {
    bpa.pignistic_tbm()
}

// K_cross: Cross-Layer Conflict

/// Cross-layer conflict between tech and blind-spot layers.

/// K_cross = m_tech.b m_blind.d + m_tech.d m_blind.b

/// High K_cross means the technical indicators and the "intuition/blind-spot"
/// engines disagree - e.g., technical analysis says safe but semantic analysis
/// detects social engineering.

/// Thresholds (alert.rs):
/// K_cross> 0.5 -> P1 alert
pub fn compute_k_cross(m_tech: Bpa, m_blind: Bpa) -> f64 {
    m_tech.b * m_blind.d + m_tech.d * m_blind.b
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    const TOL: f64 = 1e-10;

   // tbm_conjunctive

    #[test]
    fn test_tbm_conjunctive_no_epsilon() {
       // Two closed-world sources agreeing on threat
        let m1 = Bpa {
            b: 0.7,
            d: 0.1,
            u: 0.2,
            epsilon: 0.0,
        };
        let m2 = Bpa {
            b: 0.6,
            d: 0.2,
            u: 0.2,
            epsilon: 0.0,
        };
        let r = tbm_conjunctive(m1, m2);

        assert!(r.is_valid(), "Result must be valid BPA: {:?}", r);

       // Conflict (0.7*0.2 + 0.1*0.6 = 0.14 + 0.06 = 0.20) ->
        assert!(r.epsilon > 0.15, "ε should capture conflict: {}", r.epsilon);

       // b should be reinforced
       // b = 0.7*0.6 + 0.7*0.2 + 0.2*0.6 = 0.42 + 0.14 + 0.12 = 0.68
        assert!(r.b > 0.5, "Threat belief should be high: {}", r.b);
    }

    #[test]
    fn test_tbm_conjunctive_high_conflict() {
       // Strongly opposing sources
        let m1 = Bpa {
            b: 0.9,
            d: 0.0,
            u: 0.1,
            epsilon: 0.0,
        };
        let m2 = Bpa {
            b: 0.0,
            d: 0.9,
            u: 0.1,
            epsilon: 0.0,
        };
        let r = tbm_conjunctive(m1, m2);

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
       // k = 0.9*0.9 = 0.81 -> high
        assert!(
            r.epsilon > 0.7,
            "High conflict should yield high ε: {}",
            r.epsilon
        );
    }

    #[test]
    fn test_tbm_conjunctive_with_epsilon() {
       // Sources with existing open-world mass
        let m1 = Bpa {
            b: 0.5,
            d: 0.1,
            u: 0.3,
            epsilon: 0.1,
        };
        let m2 = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.3,
            epsilon: 0.1,
        };
        let r = tbm_conjunctive(m1, m2);

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
       // should include both conflict and propagated epsilon
        assert!(r.epsilon > 0.1, "ε should accumulate: {}", r.epsilon);
    }

    #[test]
    fn test_tbm_conjunctive_vacuous() {
       // Combining with vacuous should not change (approximately)
        let m1 = Bpa {
            b: 0.6,
            d: 0.2,
            u: 0.2,
            epsilon: 0.0,
        };
        let r = tbm_conjunctive(m1, Bpa::vacuous());

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
        assert!((r.b - 0.6).abs() < TOL, "b preserved: {}", r.b);
        assert!((r.d - 0.2).abs() < TOL, "d preserved: {}", r.d);
        assert!((r.u - 0.2).abs() < TOL, "u preserved: {}", r.u);
        assert!(
            (r.epsilon).abs() < TOL,
            "no conflict with vacuous: {}",
            r.epsilon
        );
    }

    #[test]
    fn test_tbm_conjunctive_symmetric() {
       // Combination should be commutative
        let m1 = Bpa {
            b: 0.5,
            d: 0.3,
            u: 0.2,
            epsilon: 0.0,
        };
        let m2 = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.4,
            epsilon: 0.0,
        };
        let r1 = tbm_conjunctive(m1, m2);
        let r2 = tbm_conjunctive(m2, m1);

        assert!((r1.b - r2.b).abs() < TOL, "Commutativity b");
        assert!((r1.d - r2.d).abs() < TOL, "Commutativity d");
        assert!((r1.u - r2.u).abs() < TOL, "Commutativity u");
        assert!((r1.epsilon - r2.epsilon).abs() < TOL, "Commutativity ε");
    }

   // tbm_combine_n

    #[test]
    fn test_tbm_combine_n_empty() {
        let r = tbm_combine_n(&[]);
        assert!(r.is_vacuous());
    }

    #[test]
    fn test_tbm_combine_n_single() {
        let m = Bpa {
            b: 0.6,
            d: 0.2,
            u: 0.2,
            epsilon: 0.0,
        };
        let r = tbm_combine_n(&[m]);
        assert!((r.b - m.b).abs() < TOL);
    }

    #[test]
    fn test_tbm_combine_n_multiple() {
        let bpas = vec![
            Bpa {
                b: 0.6,
                d: 0.2,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.5,
                d: 0.3,
                u: 0.2,
                epsilon: 0.0,
            },
            Bpa {
                b: 0.7,
                d: 0.1,
                u: 0.2,
                epsilon: 0.0,
            },
        ];
        let r = tbm_combine_n(&bpas);

        assert!(r.is_valid(), "N-way result must be valid: {:?}", r);
       // b should be the largest focal element (agreement on threat)
        assert!(
            r.b > r.d,
            "b should exceed d with threat agreement: b={}, d={}",
            r.b,
            r.d
        );
        assert!(
            r.b > r.u,
            "b should exceed u with threat agreement: b={}, u={}",
            r.b,
            r.u
        );
       // Some conflict ->> 0 (TBM retains conflict as, unlike Dempster)
        assert!(
            r.epsilon > 0.0,
            "Multiple sources should produce some conflict ε"
        );
    }

   // cautious_combine

    #[test]
    fn test_cautious_combine_basic() {
        let tech = Bpa {
            b: 0.5,
            d: 0.3,
            u: 0.2,
            epsilon: 0.0,
        };
        let blind = Bpa {
            b: 0.7,
            d: 0.1,
            u: 0.2,
            epsilon: 0.0,
        };
        let r = cautious_combine(tech, blind);

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
       // b should be max(0.5, 0.7) 0.7
        assert!(r.b > tech.b, "Cautious should take higher threat: {}", r.b);
    }

    #[test]
    fn test_cautious_combine_blind_upgrades() {
       // Tech says safe, blind-spot detects threat
        let tech = Bpa {
            b: 0.1,
            d: 0.7,
            u: 0.2,
            epsilon: 0.0,
        };
        let blind = Bpa {
            b: 0.6,
            d: 0.1,
            u: 0.3,
            epsilon: 0.0,
        };
        let r = cautious_combine(tech, blind);

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
       // max(b) should be dominated by blind-spot's threat detection
        assert!(r.b > tech.b, "Blind-spot should upgrade threat");
    }

    #[test]
    fn test_cautious_combine_epsilon() {
        let tech = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.35,
            epsilon: 0.05,
        };
        let blind = Bpa {
            b: 0.3,
            d: 0.1,
            u: 0.5,
            epsilon: 0.1,
        };
        let r = cautious_combine(tech, blind);

        assert!(r.is_valid(), "Result must be valid: {:?}", r);
       // should be max(0.05, 0.1) 0.1 (before normalization)
        assert!(r.epsilon > 0.0, "ε should be preserved via max");
    }

   // compute_novelty

    #[test]
    fn test_novelty_empty() {
        assert!((compute_novelty(&[]) - 0.0).abs() < TOL);
    }

    #[test]
    fn test_novelty_single_zero() {
        assert!((compute_novelty(&[0.0]) - 0.0).abs() < TOL);
    }

    #[test]
    fn test_novelty_single_nonzero() {
       // Novelty = 1 - (1-0.2) = 0.2
        assert!((compute_novelty(&[0.2]) - 0.2).abs() < TOL);
    }

    #[test]
    fn test_novelty_multiple() {
       // Novelty = 1 - (1-0.1)(1-0.2)(1-0.3) = 1 - 0.9*0.8*0.7 = 1 - 0.504 = 0.496
        let n = compute_novelty(&[0.1, 0.2, 0.3]);
        assert!(
            (n - 0.496).abs() < 1e-6,
            "Novelty should be 0.496, got {}",
            n
        );
    }

    #[test]
    fn test_novelty_all_high() {
       // All engines report = 0.5 -> Novelty approaches 1.0 quickly
        let n = compute_novelty(&[0.5, 0.5, 0.5, 0.5]);
        
        assert!((n - 0.9375).abs() < TOL);
    }

    #[test]
    fn test_novelty_clamped() {
       // Values outside [0,1] should be clamped
        let n = compute_novelty(&[1.5, -0.5]);
       // 1.5 -> clamped to 1.0 -> (1-1.0) = 0.0
       // -0.5 -> clamped to 0.0 -> (1-0.0) = 1.0
       // Novelty = 1 - 0.0*1.0 = 1.0
        assert!((n - 1.0).abs() < TOL);
    }

   // pignistic_threat

    #[test]
    fn test_pignistic_closed_world() {
       // No -> same as b + u/2
        let bpa = Bpa {
            b: 0.6,
            d: 0.2,
            u: 0.2,
            epsilon: 0.0,
        };
        let p = pignistic_threat(bpa);
        assert!((p - 0.7).abs() < TOL, "BetP = 0.6 + 0.2/2 = 0.7, got {}", p);
    }

    #[test]
    fn test_pignistic_with_epsilon() {
       // b=0.4, d=0.2, u=0.3, =0.1
       // BetP = 0.4/0.9 + 0.3/(2*0.9) = 0.4444 + 0.1667 = 0.6111
        let bpa = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.3,
            epsilon: 0.1,
        };
        let p = pignistic_threat(bpa);
        let expected = 0.4 / 0.9 + 0.3 / (2.0 * 0.9);
        assert!(
            (p - expected).abs() < 1e-4,
            "BetP with ε, expected {}, got {}",
            expected,
            p
        );
    }

    #[test]
    fn test_pignistic_full_epsilon() {
       // = 1.0 -> total ignorance -> fallback 0.5
        let bpa = Bpa {
            b: 0.0,
            d: 0.0,
            u: 0.0,
            epsilon: 1.0,
        };
        let p = pignistic_threat(bpa);
        assert!((p - 0.5).abs() < TOL, "Full ε should give 0.5, got {}", p);
    }

   // compute_k_cross

    #[test]
    fn test_k_cross_agreement() {
       // Both layers agree on threat -> low K_cross
        let tech = Bpa {
            b: 0.7,
            d: 0.1,
            u: 0.2,
            epsilon: 0.0,
        };
        let blind = Bpa {
            b: 0.8,
            d: 0.1,
            u: 0.1,
            epsilon: 0.0,
        };
        let k = compute_k_cross(tech, blind);
       // K_cross = 0.7*0.1 + 0.1*0.8 = 0.07 + 0.08 = 0.15
        assert!((k - 0.15).abs() < TOL, "K_cross should be 0.15, got {}", k);
    }

    #[test]
    fn test_k_cross_disagreement() {
       // Tech says safe, blind says threat -> high K_cross
        let tech = Bpa {
            b: 0.1,
            d: 0.8,
            u: 0.1,
            epsilon: 0.0,
        };
        let blind = Bpa {
            b: 0.8,
            d: 0.1,
            u: 0.1,
            epsilon: 0.0,
        };
        let k = compute_k_cross(tech, blind);
       // K_cross = 0.1*0.1 + 0.8*0.8 = 0.01 + 0.64 = 0.65
        assert!((k - 0.65).abs() < TOL, "K_cross should be 0.65, got {}", k);
    }

    #[test]
    fn test_k_cross_vacuous() {
       // One vacuous -> K_cross = 0
        let tech = Bpa {
            b: 0.6,
            d: 0.3,
            u: 0.1,
            epsilon: 0.0,
        };
        let k = compute_k_cross(tech, Bpa::vacuous());
        assert!((k - 0.0).abs() < TOL);
    }
}
