//! Engine-side tests for the shared IOC Shadow math.
//!
//! The production verdict does not call this module. It is compiled here so
//! the candidate model remains covered beside the IOC pipeline while rollout
//! is still shadow-only.

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use vigilyx_core::security::ioc_shadow::{log_likelihood_ratio, score_from_counts};

    #[test]
    fn equal_feature_rates_have_no_evidence() {
        assert_eq!(log_likelihood_ratio(10, 100, 10, 100), 0.0);
    }

    #[test]
    fn rare_in_normal_but_common_in_malicious_is_positive() {
        let ratio = log_likelihood_ratio(30, 100, 1, 200);
        assert!(ratio > 0.0);
    }

    #[test]
    fn empty_buckets_remain_finite() {
        let ratio = log_likelihood_ratio(0, 0, 0, 0);
        assert!(ratio.is_finite());
    }

    #[test]
    fn evidence_is_added_in_log_odds_space() {
        let score = score_from_counts(1, 199, 30, 5, 100, 100, 0, 168.0);
        assert!(score.log_odds.is_finite());
        assert!(score.probability > 0.0 && score.probability < 1.0);
    }
}
