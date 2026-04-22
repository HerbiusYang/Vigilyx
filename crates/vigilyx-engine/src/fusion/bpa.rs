//! Basic Probability Assignment (BPA) for Dempster-Shafer evidence theory.

//! Type definitions and core operations have been moved to vigilyx-core::security.
//! This module re-exports them for backward compatibility within the engine crate.

// Re-export all BPA types and functions from core
pub use vigilyx_core::security::{Bpa, DempsterResult, dempster_combine, dempster_combine_n};

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpa_normalization() {
        let bpa = Bpa::new(2.0, 3.0, 5.0);
        assert!((bpa.b - 0.2).abs() < 1e-10);
        assert!((bpa.d - 0.3).abs() < 1e-10);
        assert!((bpa.u - 0.5).abs() < 1e-10);
        assert!(bpa.is_valid());
    }

    #[test]
    fn test_bpa_negative_clamping() {
        let bpa = Bpa::new(-1.0, 0.5, 0.5);
        assert!(bpa.b >= 0.0);
        assert!(bpa.is_valid());
    }

    #[test]
    fn test_bpa_zero_input() {
        let bpa = Bpa::new(0.0, 0.0, 0.0);
        assert!(bpa.is_vacuous());
    }

    #[test]
    fn test_from_score_confidence() {
        // score=0.8, confidence=1.0 -> b=0.8, d=0.2, u=0.0
        let bpa = Bpa::from_score_confidence(0.8, 1.0);
        assert!((bpa.b - 0.8).abs() < 1e-10);
        assert!((bpa.d - 0.2).abs() < 1e-10);
        assert!((bpa.u).abs() < 1e-10);

        // score=0.5, confidence=0.0 -> vacuous
        let bpa2 = Bpa::from_score_confidence(0.5, 0.0);
        assert!((bpa2.u - 1.0).abs() < 1e-10);

        // score=1.0, confidence=0.6 -> b=0.6, d=0.0, u=0.4
        let bpa3 = Bpa::from_score_confidence(1.0, 0.6);
        assert!((bpa3.b - 0.6).abs() < 1e-10);
        assert!((bpa3.u - 0.4).abs() < 1e-10);
    }

    #[test]
    fn test_risk_score() {
        let bpa = Bpa {
            b: 0.3,
            d: 0.2,
            u: 0.5,
            epsilon: 0.0,
        };
        // risk(0.7) = 0.3 + 0.7*0.5 = 0.65
        assert!((bpa.risk_score(0.7) - 0.65).abs() < 1e-10);
    }

    #[test]
    fn test_pignistic() {
        let bpa = Bpa {
            b: 0.4,
            d: 0.2,
            u: 0.4,
            epsilon: 0.0,
        };
        // BetP = 0.4 + 0.4/2 = 0.6
        assert!((bpa.pignistic_threat() - 0.6).abs() < 1e-10);
    }

    #[test]
    fn test_discount() {
        let bpa = Bpa {
            b: 0.6,
            d: 0.3,
            u: 0.1,
            epsilon: 0.0,
        };
        let disc = bpa.discount(0.5);
        assert!((disc.b - 0.3).abs() < 1e-10);
        assert!((disc.d - 0.15).abs() < 1e-10);
        assert!((disc.u - 0.55).abs() < 1e-10);
    }

    #[test]
    fn test_dempster_combine_basic() {
        // Two sources agree on threat
        let m1 = Bpa {
            b: 0.8,
            d: 0.1,
            u: 0.1,
            epsilon: 0.0,
        };
        let m2 = Bpa {
            b: 0.7,
            d: 0.2,
            u: 0.1,
            epsilon: 0.0,
        };
        let r = dempster_combine(m1, m2);
        // Should reinforce threat belief
        assert!(r.combined.b > 0.9);
        assert!(r.conflict < 0.3);
    }

    #[test]
    fn test_dempster_combine_conflicting() {
        // One says threat, other says normal
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
        let r = dempster_combine(m1, m2);
        // High conflict
        assert!(r.conflict > 0.7);
    }

    #[test]
    fn test_dempster_combine_vacuous() {
        // Combining with vacuous should not change
        let m1 = Bpa {
            b: 0.6,
            d: 0.3,
            u: 0.1,
            epsilon: 0.0,
        };
        let r = dempster_combine(m1, Bpa::vacuous());
        assert!((r.combined.b - m1.b).abs() < 1e-10);
        assert!((r.combined.d - m1.d).abs() < 1e-10);
        assert!((r.combined.u - m1.u).abs() < 1e-10);
    }

    #[test]
    fn test_dempster_combine_n() {
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
        let r = dempster_combine_n(&bpas);
        assert!(r.combined.is_valid());
        assert!(r.combined.b > 0.8); // strong agreement on threat
    }
}
