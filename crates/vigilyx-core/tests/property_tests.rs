//! Property-based tests for vigilyx-core types.

//! Focused on BPA (Basic Probability Assignment) mathematical invariants
//! and ThreatLevel ordering properties.

use proptest::prelude::*;
use vigilyx_core::security::{Bpa, ThreatLevel, dempster_combine, dempster_combine_n};


// Strategy: arbitrary valid BPA


/// Generate an arbitrary closed-world BPA by sampling three positive floats
/// and normalizing them to sum to 1.0.
fn arb_bpa() -> impl Strategy<Value = Bpa> {
    (0.001f64..100.0, 0.001f64..100.0, 0.001f64..100.0).prop_map(|(a, b, c)| {
        let sum = a + b + c;
        Bpa::new(a / sum, b / sum, c / sum)
    })
}

/// Generate a BPA that may include zero components (edge cases).
fn arb_bpa_with_zeros() -> impl Strategy<Value = Bpa> {
    (0.0f64..100.0, 0.0f64..100.0, 0.0f64..100.0).prop_map(|(a, b, c)| {
        let sum = a + b + c;
        if sum < 1e-15 {
            return Bpa::vacuous();
        }
        Bpa::new(a / sum, b / sum, c / sum)
    })
}

/// Generate a TBM (open-world) BPA with epsilon component.
fn arb_bpa_tbm() -> impl Strategy<Value = Bpa> {
    (
        0.001f64..100.0,
        0.001f64..100.0,
        0.001f64..100.0,
        0.0f64..50.0,
    )
        .prop_map(|(a, b, c, e)| {
            let sum = a + b + c + e;
            Bpa::new_tbm(a / sum, b / sum, c / sum, e / sum)
        })
}


// BPA construction invariants


proptest! {
   /// Invariant: Bpa::new always produces a valid BPA (sum = 1.0, non-negative).
    #[test]
    fn test_bpa_new_always_valid(
        a in -10.0f64..100.0,
        b in -10.0f64..100.0,
        c in -10.0f64..100.0
    ) {
        let bpa = Bpa::new(a, b, c);
        prop_assert!(bpa.is_valid(), "Bpa::new({}, {}, {}) invalid: {:?}", a, b, c, bpa);
    }

   /// Invariant: Bpa::new_tbm always produces a valid BPA (sum = 1.0, non-negative).
    #[test]
    fn test_bpa_new_tbm_always_valid(
        a in -10.0f64..100.0,
        b in -10.0f64..100.0,
        c in -10.0f64..100.0,
        e in -10.0f64..100.0
    ) {
        let bpa = Bpa::new_tbm(a, b, c, e);
        prop_assert!(bpa.is_valid(), "Bpa::new_tbm({}, {}, {}, {}) invalid: {:?}", a, b, c, e, bpa);
    }

   /// Invariant: Closed-world BPA has epsilon = 0.
    #[test]
    fn test_bpa_new_has_zero_epsilon(bpa in arb_bpa()) {
        prop_assert!(
            bpa.epsilon.abs() < 1e-15,
            "closed-world BPA should have epsilon=0, got {}", bpa.epsilon
        );
    }

   /// Invariant: Discounting preserves validity and is monotone in alpha.
   /// discount(alpha=a) should have b <= discount(alpha=b).b when a <= b.
    #[test]
    fn test_discount_monotone_in_alpha(
        bpa in arb_bpa(),
        alpha_lo in 0.0f64..=1.0,
        alpha_hi in 0.0f64..=1.0
    ) {
        let (lo, hi) = if alpha_lo <= alpha_hi {
            (alpha_lo, alpha_hi)
        } else {
            (alpha_hi, alpha_lo)
        };

        let disc_lo = bpa.discount(lo);
        let disc_hi = bpa.discount(hi);

        prop_assert!(disc_lo.is_valid(), "discounted BPA (alpha={}) invalid: {:?}", lo, disc_lo);
        prop_assert!(disc_hi.is_valid(), "discounted BPA (alpha={}) invalid: {:?}", hi, disc_hi);

       // Higher alpha => more belief preserved
        prop_assert!(
            disc_lo.b <= disc_hi.b + 1e-9,
            "discount monotonicity: alpha={} b={} > alpha={} b={}",
            lo, disc_lo.b, hi, disc_hi.b
        );
    }

   /// Invariant: TBM BPA pignistic_tbm is in [0, 1].
    #[test]
    fn test_pignistic_tbm_bounded(bpa in arb_bpa_tbm()) {
        let p = bpa.pignistic_tbm();
        prop_assert!(
            (-1e-9..=1.0 + 1e-9).contains(&p),
            "pignistic_tbm must be in [0, 1], got {} for {:?}", p, bpa
        );
    }

   /// Invariant: is_vacuous returns true only when u is approximately 1.0.
    #[test]
    fn test_is_vacuous_consistent(bpa in arb_bpa_with_zeros()) {
        if bpa.is_vacuous() {
            prop_assert!(
                bpa.u > 1.0 - 1e-9,
                "is_vacuous=true but u={}", bpa.u
            );
        }
    }
}


// Dempster combination deeper invariants


proptest! {
   /// Invariant: Combining two identical BPAs with high belief should increase belief
   /// (or at least not decrease it compared to the original).
    #[test]
    fn test_agreeing_evidence_strengthens_belief(b_val in 0.5f64..0.95) {
        let bpa = Bpa::new(b_val, 0.0, 1.0 - b_val);
        let result = dempster_combine(bpa, bpa);
        prop_assert!(
            result.combined.b >= bpa.b - 1e-9,
            "Agreeing evidence should not decrease belief: {} < {}",
            result.combined.b, bpa.b
        );
    }

   /// Invariant: Combining two contradictory BPAs produces high conflict.
   /// BPA1 = (b=high, d=0, u=low), BPA2 = (b=0, d=high, u=low).
    #[test]
    fn test_contradictory_evidence_produces_conflict(strength in 0.7f64..0.99) {
        let bpa_threat = Bpa::new(strength, 0.0, 1.0 - strength);
        let bpa_benign = Bpa::new(0.0, strength, 1.0 - strength);
        let result = dempster_combine(bpa_threat, bpa_benign);
        prop_assert!(
            result.conflict > 0.1,
            "Contradictory BPAs should produce conflict > 0.1, got {}",
            result.conflict
        );
    }

   /// Invariant: dempster_combine_n with 2 elements equals dempster_combine.
    #[test]
    fn test_combine_n_equals_combine_for_two(
        a in arb_bpa(),
        b in arb_bpa()
    ) {
        let pair = dempster_combine(a, b);
        let n_pair = dempster_combine_n(&[a, b]);

        let tol = 1e-9;
        prop_assert!(
            (pair.combined.b - n_pair.combined.b).abs() < tol,
            "combine vs combine_n belief mismatch"
        );
        prop_assert!(
            (pair.combined.d - n_pair.combined.d).abs() < tol,
            "combine vs combine_n disbelief mismatch"
        );
        prop_assert!(
            (pair.combined.u - n_pair.combined.u).abs() < tol,
            "combine vs combine_n uncertainty mismatch"
        );
    }
}


// ThreatLevel properties


proptest! {
   /// Invariant: ThreatLevel::from_score is monotonically non-decreasing.
    #[test]
    fn test_threat_level_monotonic(
        a in 0.0f64..=1.0,
        b in 0.0f64..=1.0
    ) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let level_lo = ThreatLevel::from_score(lo);
        let level_hi = ThreatLevel::from_score(hi);
        prop_assert!(
            level_lo <= level_hi,
            "Monotonicity: from_score({})={:?} > from_score({})={:?}",
            lo, level_lo, hi, level_hi
        );
    }

   /// Invariant: as_numeric is consistent with ordering.
    #[test]
    fn test_threat_level_numeric_ordering(
        a in 0.0f64..=1.0,
        b in 0.0f64..=1.0
    ) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let level_lo = ThreatLevel::from_score(lo);
        let level_hi = ThreatLevel::from_score(hi);
        prop_assert!(
            level_lo.as_numeric() <= level_hi.as_numeric(),
            "Numeric ordering: {:?}({}) > {:?}({})",
            level_lo, level_lo.as_numeric(), level_hi, level_hi.as_numeric()
        );
    }
}
