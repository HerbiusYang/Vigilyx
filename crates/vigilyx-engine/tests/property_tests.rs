//! Property-based tests for core algorithms.

//! Uses `proptest` to verify mathematical invariants of:
//! - BPA (Basic Probability Assignment) construction and Dempster combination
//! - Luhn checksum algorithm
//! - IBAN mod-97 validation
//! - ThreatLevel score -> level monotonicity

use proptest::prelude::*;
use vigilyx_core::security::{Bpa, ThreatLevel, dempster_combine, dempster_combine_n};
use vigilyx_engine::data_security::dlp::finders::{iban_mod97_check, luhn_check};

// Strategy: arbitrary valid BPA

/// Generate an arbitrary closed-world BPA by sampling three non-negative
/// floats and normalizing them to sum to 1.0.
fn arb_bpa() -> impl Strategy<Value = Bpa> {
    // Use small positive ranges to avoid extreme denormalized floats
    (0.001f64..100.0, 0.001f64..100.0, 0.001f64..100.0).prop_map(|(a, b, c)| {
        let sum = a + b + c;
        // sum is guaranteed> 0 because all components> 0.001
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

// BPA invariants

proptest! {
   /// Invariant: For any valid BPA, b + d + u + epsilon = 1.0 (within f64 tolerance).
    #[test]
    fn test_bpa_components_sum_to_one(bpa in arb_bpa()) {
        let sum = bpa.b + bpa.d + bpa.u + bpa.epsilon;
        prop_assert!(
            (sum - 1.0).abs() < 1e-9,
            "BPA components must sum to 1.0, got {} (b={}, d={}, u={}, eps={})",
            sum, bpa.b, bpa.d, bpa.u, bpa.epsilon
        );
    }

   /// Invariant: All BPA components are non-negative.
    #[test]
    fn test_bpa_components_non_negative(bpa in arb_bpa_with_zeros()) {
        prop_assert!(bpa.b >= 0.0, "belief must be non-negative, got {}", bpa.b);
        prop_assert!(bpa.d >= 0.0, "disbelief must be non-negative, got {}", bpa.d);
        prop_assert!(bpa.u >= 0.0, "uncertainty must be non-negative, got {}", bpa.u);
        prop_assert!(bpa.epsilon >= 0.0, "epsilon must be non-negative, got {}", bpa.epsilon);
    }

   /// Invariant: Dempster combination is commutative: combine(a,b) ~ combine(b,a).
    #[test]
    fn test_dempster_combine_is_commutative(
        a in arb_bpa(),
        b in arb_bpa()
    ) {
        let ab = dempster_combine(a, b);
        let ba = dempster_combine(b, a);

        let tol = 1e-9;
        prop_assert!(
            (ab.combined.b - ba.combined.b).abs() < tol,
            "belief not commutative: {} vs {}", ab.combined.b, ba.combined.b
        );
        prop_assert!(
            (ab.combined.d - ba.combined.d).abs() < tol,
            "disbelief not commutative: {} vs {}", ab.combined.d, ba.combined.d
        );
        prop_assert!(
            (ab.combined.u - ba.combined.u).abs() < tol,
            "uncertainty not commutative: {} vs {}", ab.combined.u, ba.combined.u
        );
        prop_assert!(
            (ab.conflict - ba.conflict).abs() < tol,
            "conflict not commutative: {} vs {}", ab.conflict, ba.conflict
        );
    }

   /// Invariant: Combining any BPA with the vacuous BPA (total uncertainty)
   /// returns the original BPA unchanged. Vacuous is the identity element.
    #[test]
    fn test_vacuous_is_identity(bpa in arb_bpa()) {
        let vacuous = Bpa::vacuous();
        let result = dempster_combine(bpa, vacuous);

        let tol = 1e-9;
        prop_assert!(
            (result.combined.b - bpa.b).abs() < tol,
            "vacuous identity: belief {} vs {}", result.combined.b, bpa.b
        );
        prop_assert!(
            (result.combined.d - bpa.d).abs() < tol,
            "vacuous identity: disbelief {} vs {}", result.combined.d, bpa.d
        );
        prop_assert!(
            (result.combined.u - bpa.u).abs() < tol,
            "vacuous identity: uncertainty {} vs {}", result.combined.u, bpa.u
        );
        prop_assert!(
            result.conflict < tol,
            "vacuous combination should have zero conflict, got {}", result.conflict
        );
    }

   /// Invariant: risk_score(eta) is bounded in [0.0, 1.0] for any eta in [0, 1].
    #[test]
    fn test_risk_score_bounded(
        bpa in arb_bpa(),
        eta in 0.0f64..=1.0
    ) {
        let score = bpa.risk_score(eta);
        prop_assert!(
            (0.0..=1.0).contains(&score) || (score - 1.0).abs() < 1e-9 || score.abs() < 1e-9,
            "risk_score must be in [0, 1], got {} for bpa={:?}, eta={}",
            score, bpa, eta
        );
    }

   /// Invariant: The combined BPA from Dempster's rule is itself a valid BPA
   /// (components sum to 1, all non-negative).
    #[test]
    fn test_dempster_combine_produces_valid_bpa(
        a in arb_bpa(),
        b in arb_bpa()
    ) {
        let result = dempster_combine(a, b);
        let c = result.combined;

        prop_assert!(c.b >= 0.0, "combined belief negative: {}", c.b);
        prop_assert!(c.d >= 0.0, "combined disbelief negative: {}", c.d);
        prop_assert!(c.u >= 0.0, "combined uncertainty negative: {}", c.u);

        let sum = c.b + c.d + c.u + c.epsilon;
        prop_assert!(
            (sum - 1.0).abs() < 1e-6,
            "combined BPA must sum to 1.0, got {} (b={}, d={}, u={}, eps={})",
            sum, c.b, c.d, c.u, c.epsilon
        );
    }

   /// Invariant: Conflict K is in [0, 1].
    #[test]
    fn test_dempster_conflict_bounded(
        a in arb_bpa(),
        b in arb_bpa()
    ) {
        let result = dempster_combine(a, b);
        prop_assert!(
            result.conflict >= 0.0 && result.conflict <= 1.0 + 1e-9,
            "conflict must be in [0, 1], got {}", result.conflict
        );
    }

   /// Invariant: Combining N BPAs via dempster_combine_n produces a valid BPA.
    #[test]
    fn test_dempster_combine_n_produces_valid_bpa(
        bpas in prop::collection::vec(arb_bpa(), 1..=6)
    ) {
        let result = dempster_combine_n(&bpas);
        let c = result.combined;

        prop_assert!(c.b >= 0.0, "combined_n belief negative: {}", c.b);
        prop_assert!(c.d >= 0.0, "combined_n disbelief negative: {}", c.d);
        prop_assert!(c.u >= 0.0, "combined_n uncertainty negative: {}", c.u);

        let sum = c.b + c.d + c.u + c.epsilon;
        prop_assert!(
            (sum - 1.0).abs() < 1e-6,
            "combined_n BPA must sum to 1.0, got {} for {} inputs",
            sum, bpas.len()
        );
    }

   /// Invariant: Pignistic probability (b + u/2) is in [0, 1] for any valid BPA.
    #[test]
    fn test_pignistic_threat_bounded(bpa in arb_bpa()) {
        let p = bpa.pignistic_threat();
        prop_assert!(
            (-1e-9..=1.0 + 1e-9).contains(&p),
            "pignistic_threat must be in [0, 1], got {} for {:?}", p, bpa
        );
    }

   /// Invariant: Discounting with alpha=1.0 preserves the BPA;
   /// discounting with alpha=0.0 yields vacuous.
    #[test]
    fn test_discount_boundary_values(bpa in arb_bpa()) {
        let tol = 1e-9;

       // alpha = 1.0 => no change
        let full = bpa.discount(1.0);
        prop_assert!(
            (full.b - bpa.b).abs() < tol && (full.d - bpa.d).abs() < tol,
            "discount(1.0) should preserve BPA"
        );

       // alpha = 0.0 => vacuous (all mass goes to uncertainty)
        let zero = bpa.discount(0.0);
        prop_assert!(
            zero.b.abs() < tol && zero.d.abs() < tol,
            "discount(0.0) should yield vacuous: b={}, d={}", zero.b, zero.d
        );
    }

   /// Invariant: from_score_confidence produces valid BPA for any inputs in [0,1].
    #[test]
    fn test_from_score_confidence_valid(
        score in 0.0f64..=1.0,
        confidence in 0.0f64..=1.0
    ) {
        let bpa = Bpa::from_score_confidence(score, confidence);
        prop_assert!(bpa.is_valid(), "from_score_confidence({}, {}) invalid: {:?}", score, confidence, bpa);
    }
}

// ThreatLevel ordering

proptest! {
   /// Invariant: ThreatLevel::from_score is monotonically non-decreasing.
   /// If score_a <= score_b, then from_score(a) <= from_score(b).
    #[test]
    fn test_threat_level_from_score_monotonic(
        a in 0.0f64..=1.0,
        b in 0.0f64..=1.0
    ) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let level_lo = ThreatLevel::from_score(lo);
        let level_hi = ThreatLevel::from_score(hi);
       // ThreatLevel derives PartialOrd with Safe <Low <Medium <High <Critical
        prop_assert!(
            level_lo <= level_hi,
            "Monotonicity violated: from_score({}) = {:?} > from_score({}) = {:?}",
            lo, level_lo, hi, level_hi
        );
    }

   /// Invariant: ThreatLevel::from_score always returns a value for any f64 score.
   /// (No panics, no undefined behavior.)
    #[test]
    fn test_threat_level_from_score_total(score in prop::num::f64::ANY) {
       // Just verify it doesn't panic
        let _level = ThreatLevel::from_score(score);
    }
}

// Luhn algorithm

/// Compute the Luhn check digit for a given sequence of digits (without check digit).
/// Returns the single digit that, when appended, makes the full number pass Luhn.
fn compute_luhn_check_digit(payload: &str) -> Option<char> {
    // Standard Luhn: double every second digit from the right of the *full* number.
    // For the payload (without check digit), we double starting from the rightmost digit.
    let mut sum = 0u32;
    for (i, ch) in payload.chars().rev().enumerate() {
        let d = ch.to_digit(10)?;
        let val = if i % 2 == 0 {
            // These positions will be "odd from right" in the full number
            // (since check digit will be appended), so they get doubled.
            let v = d * 2;
            if v > 9 { v - 9 } else { v }
        } else {
            d
        };
        sum += val;
    }
    let check = (10 - (sum % 10)) % 10;
    char::from_digit(check, 10)
}

proptest! {
   /// Invariant: A number constructed with a valid Luhn check digit passes luhn_check.
    #[test]
    fn test_luhn_generated_number_is_valid(
       // Generate a random payload of 12-18 digits, then append the correct check digit
        payload in "[0-9]{12,18}"
    ) {
        if let Some(check) = compute_luhn_check_digit(&payload) {
            let full = format!("{}{}", payload, check);
            prop_assert!(
                luhn_check(&full),
                "Generated Luhn number should be valid: {}", full
            );
        }
    }

   /// Invariant: Changing a single digit in a valid Luhn number (almost always)
   /// invalidates it. The exception is changing digit X to X (no-op), which we skip.
    #[test]
    fn test_luhn_single_digit_change_invalidates(
        payload in "[0-9]{15}",
        position in 0usize..16,
        new_digit in 0u32..10
    ) {
        if let Some(check) = compute_luhn_check_digit(&payload) {
            let full = format!("{}{}", payload, check);
            let original_digit = full.as_bytes()[position] - b'0';
           // Skip no-op changes
            if new_digit == original_digit as u32 {
                return Ok(());
            }
            let mut chars: Vec<u8> = full.into_bytes();
            chars[position] = b'0' + new_digit as u8;
            let modified = String::from_utf8(chars).unwrap();
            prop_assert!(
                !luhn_check(&modified),
                "Changing digit {} from {} to {} should invalidate Luhn: {}",
                position, original_digit, new_digit, modified
            );
        }
    }

   /// Invariant: Non-digit input never passes Luhn.
    #[test]
    fn test_luhn_rejects_non_digits(s in "[a-zA-Z]{5,20}") {
        prop_assert!(
            !luhn_check(&s),
            "Non-digit input should fail Luhn: {}", s
        );
    }

   /// Note: luhn_check("") returns true because sum=0 is divisible by 10.
   /// This is acceptable because callers always validate length/prefix first.
   /// We verify this documented behavior here rather than asserting rejection.
    #[test]
    fn test_luhn_empty_returns_true(_dummy in Just(())) {
       // Empty string: sum=0, 0 % 10 == 0 => true.
       // Production code guards with length checks before calling luhn_check.
        prop_assert!(luhn_check(""), "Empty string: sum=0 is divisible by 10");
    }
}

// IBAN mod-97

/// Compute the check digits for an IBAN given country code and BBAN.
/// Returns the two-character check digit string.
fn compute_iban_check_digits(country: &str, bban: &str) -> Option<String> {
    // Rearrange: BBAN + country + "00"
    let rearranged = format!("{}{}00", bban, country);
    // Convert to numeric string
    let mut numeric = String::with_capacity(rearranged.len() * 2);
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            numeric.push(ch);
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u32) - ('A' as u32) + 10;
            numeric.push_str(&val.to_string());
        } else {
            return None;
        }
    }
    // Compute mod 97
    let mut remainder: u32 = 0;
    for ch in numeric.chars() {
        remainder = (remainder * 10 + (ch as u32 - '0' as u32)) % 97;
    }
    let check = 98 - remainder;
    Some(format!("{:02}", check))
}

proptest! {
   /// Invariant: An IBAN constructed with valid mod-97 check digits passes iban_mod97_check.
    #[test]
    fn test_iban_generated_number_is_valid(
       // Generate a random BBAN of 10-30 alphanumeric uppercase chars
        bban in "[A-Z0-9]{10,30}"
    ) {
       // Use "GB" as country code (common, well-defined)
        let country = "GB";
        if let Some(check) = compute_iban_check_digits(country, &bban) {
            let iban = format!("{}{}{}", country, check, bban);
            prop_assert!(
                iban_mod97_check(&iban),
                "Generated IBAN should be valid: {}", iban
            );
        }
    }

   /// Invariant: IBANs shorter than 5 characters always fail.
    #[test]
    fn test_iban_rejects_short_input(s in "[A-Z0-9]{0,4}") {
        prop_assert!(
            !iban_mod97_check(&s),
            "Short input should fail IBAN check: {}", s
        );
    }

   /// Invariant: Lowercase input fails (algorithm expects uppercase).
    #[test]
    fn test_iban_rejects_lowercase(s in "[a-z]{5,20}") {
        prop_assert!(
            !iban_mod97_check(&s),
            "Lowercase input should fail IBAN check: {}", s
        );
    }
}

// Known-value sanity checks (not property-based, but included for completeness)

#[test]
fn test_luhn_known_valid_cards() {
    // Visa test number
    assert!(luhn_check("4111111111111111"));
    // Mastercard test number
    assert!(luhn_check("5425233430109903"));
    // AMEX test number
    assert!(luhn_check("374245455400126"));
}

#[test]
fn test_iban_known_valid() {
    // GB standard test IBAN
    assert!(iban_mod97_check("GB29NWBK60161331926819"));
    // DE standard test IBAN
    assert!(iban_mod97_check("DE89370400440532013000"));
    // FR standard test IBAN
    assert!(iban_mod97_check("FR7630006000011234567890189"));
}

#[test]
fn test_iban_known_invalid() {
    // Wrong check digits
    assert!(!iban_mod97_check("GB00NWBK60161331926819"));
    // Tampered BBAN
    assert!(!iban_mod97_check("GB29NWBK60161331926810"));
}

#[test]
fn test_bpa_certain_threat_risk_score_is_one() {
    let bpa = Bpa::certain_threat();
    let score = bpa.risk_score(0.5);
    assert!(
        (score - 1.0).abs() < 1e-12,
        "certain_threat risk_score should be 1.0"
    );
}

#[test]
fn test_bpa_certain_benign_risk_score_is_zero() {
    let bpa = Bpa::certain_benign();
    let score = bpa.risk_score(0.0);
    assert!(
        score.abs() < 1e-12,
        "certain_benign risk_score(0) should be 0.0"
    );
}

#[test]
fn test_dempster_combine_n_single_element() {
    let bpa = Bpa::new(0.6, 0.3, 0.1);
    let result = dempster_combine_n(&[bpa]);
    assert!((result.combined.b - bpa.b).abs() < 1e-12);
    assert!((result.combined.d - bpa.d).abs() < 1e-12);
    assert!((result.combined.u - bpa.u).abs() < 1e-12);
    assert!(result.conflict.abs() < 1e-12);
}

#[test]
fn test_dempster_combine_n_empty() {
    let result = dempster_combine_n(&[]);
    assert!(result.combined.is_vacuous());
    assert!(result.conflict.abs() < 1e-12);
}
