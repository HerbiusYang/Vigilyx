//! Shared, side-effect-free math for the IOC Shadow model.
//!
//! This module is deliberately independent of the database and engine.  The
//! API can therefore render exactly the same score that the future engine
//! candidate will use, while the current production verdict remains unchanged.

use serde::{Deserialize, Serialize};

const JEFFREYS_ALPHA: f64 = 0.5;
const MIN_PROBABILITY: f64 = 1e-9;
const DEFAULT_INTERVAL_Z: f64 = 1.96;

/// A probability plus the independent evidence uncertainty around it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IocShadowScore {
    pub prior_log_odds: f64,
    pub raw_log_likelihood_ratio: f64,
    pub decayed_log_likelihood_ratio: f64,
    pub log_odds: f64,
    pub probability: f64,
    pub decay_factor: f64,
    pub evidence_count: u64,
    pub evidence_interval_lower: f64,
    pub evidence_interval_upper: f64,
}

/// A finite Jeffreys-smoothed rate. Unknown observations are not included in
/// either numerator or denominator by the caller.
pub fn smoothed_rate(successes: u64, trials: u64) -> f64 {
    ((successes as f64) + JEFFREYS_ALPHA) / ((trials as f64) + (2.0 * JEFFREYS_ALPHA))
}

pub fn logit(probability: f64) -> f64 {
    let p = probability.clamp(MIN_PROBABILITY, 1.0 - MIN_PROBABILITY);
    (p / (1.0 - p)).ln()
}

pub fn sigmoid(log_odds: f64) -> f64 {
    if log_odds >= 0.0 {
        1.0 / (1.0 + (-log_odds).exp())
    } else {
        let exp = log_odds.exp();
        exp / (1.0 + exp)
    }
}

/// Compare a feature's frequency in malicious and normal messages.
pub fn log_likelihood_ratio(
    malicious_feature_count: u64,
    malicious_message_count: u64,
    normal_feature_count: u64,
    normal_message_count: u64,
) -> f64 {
    (smoothed_rate(malicious_feature_count, malicious_message_count)
        / smoothed_rate(normal_feature_count, normal_message_count))
    .ln()
}

/// Pull evidence toward no evidence, which means the local prior.  It never
/// pulls the probability directly toward zero.
pub fn decay_log_evidence(log_evidence: f64, age_seconds: i64, half_life_hours: f64) -> f64 {
    if !log_evidence.is_finite() || !half_life_hours.is_finite() || half_life_hours <= 0.0 {
        return 0.0;
    }
    let age_hours = (age_seconds.max(0) as f64) / 3600.0;
    let factor = (-std::f64::consts::LN_2 * age_hours / half_life_hours).exp();
    log_evidence * factor.clamp(0.0, 1.0)
}

/// Approximate the central 95% credible interval of a Beta posterior with a
/// normal approximation. Jeffreys' alpha/beta prior keeps sparse evidence
/// finite and intentionally leaves the interval wide when evidence is thin.
pub fn jeffreys_beta_interval(successes: u64, failures: u64) -> (f64, f64) {
    let alpha = successes as f64 + JEFFREYS_ALPHA;
    let beta = failures as f64 + JEFFREYS_ALPHA;
    let total = alpha + beta;
    let mean = alpha / total;
    let variance = (alpha * beta) / (total * total * (total + 1.0));
    let margin = DEFAULT_INTERVAL_Z * variance.sqrt();
    (
        (mean - margin).clamp(0.0, 1.0),
        (mean + margin).clamp(0.0, 1.0),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn score_from_counts(
    prior_malicious_count: u64,
    prior_message_count: u64,
    malicious_feature_count: u64,
    normal_feature_count: u64,
    malicious_message_count: u64,
    normal_message_count: u64,
    age_seconds: i64,
    half_life_hours: f64,
) -> IocShadowScore {
    let prior_log_odds = logit(smoothed_rate(prior_malicious_count, prior_message_count));
    let raw = log_likelihood_ratio(
        malicious_feature_count,
        malicious_message_count,
        normal_feature_count,
        normal_message_count,
    );
    let decayed = decay_log_evidence(raw, age_seconds, half_life_hours);
    let total_messages = malicious_message_count.saturating_add(normal_message_count);
    let decay_factor = if raw.abs() < f64::EPSILON {
        1.0
    } else {
        (decayed / raw).clamp(0.0, 1.0)
    };
    let (lower, upper) = jeffreys_beta_interval(malicious_feature_count, normal_feature_count);
    IocShadowScore {
        prior_log_odds,
        raw_log_likelihood_ratio: raw,
        decayed_log_likelihood_ratio: decayed,
        log_odds: prior_log_odds + decayed,
        probability: sigmoid(prior_log_odds + decayed),
        decay_factor,
        evidence_count: total_messages,
        evidence_interval_lower: lower,
        evidence_interval_upper: upper,
    }
}

#[cfg(test)]
mod tests {
    use super::{decay_log_evidence, jeffreys_beta_interval, score_from_counts};
    use proptest::prelude::*;

    #[test]
    fn decay_returns_to_prior_without_making_evidence_clean() {
        let half = decay_log_evidence(4.0, 24 * 3_600, 24.0);
        assert!((half - 2.0).abs() < 1e-12);
        assert_eq!(decay_log_evidence(4.0, 0, 24.0), 4.0);
    }

    #[test]
    fn sparse_beta_interval_is_wider_than_dense_interval() {
        let sparse = jeffreys_beta_interval(1, 1);
        let dense = jeffreys_beta_interval(100, 100);
        assert!(sparse.1 - sparse.0 > dense.1 - dense.0);
        assert!(sparse.0 >= 0.0 && sparse.1 <= 1.0);
    }

    #[test]
    fn score_is_finite_for_empty_buckets() {
        let score = score_from_counts(5, 1000, 0, 0, 0, 0, 0, 168.0);
        assert!(score.probability.is_finite());
        assert!(score.evidence_interval_lower <= score.evidence_interval_upper);
    }

    proptest! {
        #[test]
        fn arbitrary_counts_keep_score_bounded(
            prior_malicious in 0u64..10_000,
            prior_messages in 0u64..10_000,
            malicious_feature in 0u64..10_000,
            normal_feature in 0u64..10_000,
            malicious_messages in 0u64..10_000,
            normal_messages in 0u64..10_000,
            age_seconds in 0i64..31_536_000,
            half_life_hours in 0.01f64..100_000.0,
        ) {
            let score = score_from_counts(
                prior_malicious,
                prior_messages,
                malicious_feature,
                normal_feature,
                malicious_messages,
                normal_messages,
                age_seconds,
                half_life_hours,
            );
            prop_assert!(score.probability.is_finite());
            prop_assert!((0.0..=1.0).contains(&score.probability));
            prop_assert!((0.0..=1.0).contains(&score.evidence_interval_lower));
            prop_assert!((0.0..=1.0).contains(&score.evidence_interval_upper));
            prop_assert!(score.evidence_interval_lower <= score.evidence_interval_upper);
            prop_assert!(score.decayed_log_likelihood_ratio.abs()
                <= score.raw_log_likelihood_ratio.abs() + 1e-9);
        }
    }
}
