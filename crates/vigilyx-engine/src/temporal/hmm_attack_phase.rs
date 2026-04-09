//! 5-state HMM attack phase inference (7.2).

//! Models BEC/ATO multi-stage attacks as a Hidden Markov Model:

//! | State | Description | Weight |

//! | S0 | Normal | 0.0 |
//! | S1 | Reconnaissance | 0.3 |
//! | S2 | Trust building | 0.5 |
//! | S3 | Attack execution | 1.0 |
//! | S4 | Harvest / exfil | 1.0 |

//! Observation vector per email:
//! (risk_single, u_final, k_conflict, time_interval_hours, content_similarity_delta)

//! Uses the forward algorithm for online posterior inference:
//! _t(s) = [_{t-1}(s') a_{s's}] P(o_t | s)
//! _t(s) = _t(s) / _s' _t(s')

//! Temporal risk from HMM:
//! Risk_temporal = _t(s) w_s

use serde::{Deserialize, Serialize};

/// Number of HMM states.
const NUM_STATES: usize = 5;

/// State risk weights: w = {0.0, 0.3, 0.5, 1.0, 1.0}
const STATE_WEIGHTS: [f64; NUM_STATES] = [0.0, 0.3, 0.5, 1.0, 1.0];

/// State labels.
const STATE_LABELS: [&str; NUM_STATES] = [
    "normal",
    "reconnaissance",
    "trust_building",
    "attack_execution",
    "harvest",
];

/// Transition matrix A[from][to] (row-stochastic).

/// Key properties:
/// - S0 -> S0 = 0.990 (most emails are normal)
/// - S0 -> S1 = 0.008 (rare transition to recon)
/// - S1 -> S2 = 0.05 (recon -> trust building)
/// - S2 -> S3 = 0.03 (trust -> attack)
/// - S3 -> S4 = 0.10 (attack -> harvest)
/// - S4 -> S0 = 0.05 (harvest -> return to normal)
/// - Self-loops dominate in each state (attack campaign persistence)
const TRANSITION: [[f64; NUM_STATES]; NUM_STATES] = [
   // S0 -> S0 S1 S2 S3 S4
    [0.990, 0.008, 0.001, 0.001, 0.000],
   // S1 ->
    [0.020, 0.920, 0.050, 0.008, 0.002],
   // S2 ->
    [0.010, 0.010, 0.940, 0.030, 0.010],
   // S3 ->
    [0.005, 0.005, 0.010, 0.880, 0.100],
   // S4 ->
    [0.050, 0.010, 0.010, 0.030, 0.900],
];

/// Initial state distribution (mostly normal).
const INITIAL_PROBS: [f64; NUM_STATES] = [0.95, 0.03, 0.01, 0.005, 0.005];

/// Observation for one email event.
#[derive(Debug, Clone)]
pub struct HmmObservation {
   /// D-S fused risk score
    pub risk_single: f64,
   /// Final uncertainty from D-S fusion
    pub u_final: f64,
   /// Conflict factor K
    pub k_conflict: f64,
   /// Hours since last email from same sender-recipient pair
    pub time_interval_hours: f64,
   /// Content similarity change rate (0=identical, 1=completely different)
    pub content_similarity_delta: f64,
}

/// Per-pair HMM state (maintained across emails).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhaseState {
   /// Pair key: "sender -> recipient"
    pub pair_key: String,
   /// Forward variable (unnormalized posterior)
    pub alpha: [f64; NUM_STATES],
   /// Number of observations processed
    pub observation_count: u64,
}

/// Result of HMM inference for one observation.
#[derive(Debug, Clone)]
pub struct AttackPhaseResult {
   /// Posterior probability of each state (s)
    pub posteriors: [f64; NUM_STATES],
   /// Dominant (most probable) state index
    pub dominant_state: usize,
   /// Temporal risk contribution: (s) w_s
    pub temporal_risk: f64,
}

impl AttackPhaseState {
   /// Create new HMM state for a sender-recipient pair.
    pub fn new(pair_key: String) -> Self {
        Self {
            pair_key,
            alpha: INITIAL_PROBS,
            observation_count: 0,
        }
    }

   /// Run one forward-algorithm step with a new observation.
    
   /// Updates in-place and returns posterior probabilities.
    pub fn update(&mut self, obs: &HmmObservation) -> AttackPhaseResult {
        self.observation_count += 1;

       // Step 1: Predict (transition)
       // _predict(s) = _{s'} _{t-1}(s') A[s'][s]
        let mut predicted = [0.0_f64; NUM_STATES];
        for to in 0..NUM_STATES {
            for (from, alpha_val) in self.alpha.iter().enumerate() {
                predicted[to] += alpha_val * TRANSITION[from][to];
            }
        }

       // Step 2: Update (emission likelihood)
       // _t(s) = _predict(s) P(obs | s)
        let emissions = compute_emission_likelihoods(obs);
        let mut alpha_new = [0.0_f64; NUM_STATES];
        for s in 0..NUM_STATES {
            alpha_new[s] = predicted[s] * emissions[s];
        }

       // Step 3: Normalize to get posterior
        let total: f64 = alpha_new.iter().sum();
        let posteriors = if total > 1e-30 {
            let mut p = [0.0_f64; NUM_STATES];
            for s in 0..NUM_STATES {
                p[s] = alpha_new[s] / total;
            }
            p
        } else {
           // Numerical underflow: reset to initial
            INITIAL_PROBS
        };

       // Store normalized for next step (prevents underflow accumulation)
        self.alpha = posteriors;

       // Step 4: Compute temporal risk
        let mut temporal_risk = 0.0_f64;
        for s in 0..NUM_STATES {
            temporal_risk += posteriors[s] * STATE_WEIGHTS[s];
        }

       // Find dominant state
        let mut dominant = 0;
        let mut max_prob = 0.0;
        for (s, &p) in posteriors.iter().enumerate() {
            if p > max_prob {
                max_prob = p;
                dominant = s;
            }
        }

        AttackPhaseResult {
            posteriors,
            dominant_state: dominant,
            temporal_risk,
        }
    }

   /// Get the current dominant state label.
    pub fn dominant_label(&self) -> &'static str {
        let mut max_idx = 0;
        let mut max_val = 0.0;
        for (i, &v) in self.alpha.iter().enumerate() {
            if v > max_val {
                max_val = v;
                max_idx = i;
            }
        }
        STATE_LABELS[max_idx]
    }
}

/// Compute emission likelihood P(obs | state) for each state.
///
/// Uses a product-of-sigmoids model (each observation feature independently
/// contributes to the likelihood of each state via a soft activation):
///
/// - **S0 (normal)**: high P when risk_single low, u low, k low
/// - **S1 (recon)**: moderate P when risk moderate, u high (probing)
/// - **S2 (trust)**: moderate P when risk low-moderate, content changing slowly
/// - **S3 (attack)**: high P when risk high, k moderate-high
/// - **S4 (harvest)**: high P when risk high, u dropping (attacker confident)
#[inline]
fn compute_emission_likelihoods(obs: &HmmObservation) -> [f64; NUM_STATES] {
    let r = obs.risk_single.clamp(0.0, 1.0);
    let u = obs.u_final.clamp(0.0, 1.0);
    let k = obs.k_conflict.clamp(0.0, 1.0);
    let dt = obs.time_interval_hours.clamp(0.0, 720.0); // cap at 30 days
    let cs = obs.content_similarity_delta.clamp(0.0, 1.0);

   // Soft features
    let risk_low = 1.0 - r; // P(obs | low risk)
    let risk_high = r; // P(obs | high risk)
    let u_high = u; // P(obs | uncertain)
    let u_low = 1.0 - u;
    let k_mod = k.min(0.5) * 2.0; // Scale K to [0,1]
    let slow_content_change = 1.0 - cs; // Content staying similar

   // Time interval features: normal=random timing, recon=regular probing
    let regular_timing = (-((dt - 24.0).powi(2)) / 200.0).exp(); // Peak at ~24h intervals

   // State emission likelihoods (unnormalized - that's fine, forward algo normalizes)
    let p_s0 = 0.1 + risk_low * 0.7 + u_low * 0.15 + (1.0 - k_mod) * 0.05;
    let p_s1 = 0.05 + (r * 0.3 + 0.3) * u_high * 0.5 + regular_timing * 0.15;
    let p_s2 = 0.05 + risk_low * 0.2 + slow_content_change * 0.3 + u_high * 0.2 + (r * 0.2 + 0.05);
    let p_s3 = 0.02 + risk_high * 0.6 + k_mod * 0.2 + cs * 0.15 + u_low * 0.03;
    let p_s4 = 0.02 + risk_high * 0.5 + u_low * 0.25 + (1.0 - regular_timing) * 0.1 + cs * 0.13;

    [p_s0, p_s1, p_s2, p_s3, p_s4]
}

/// Get the label for a state index.
#[inline]
pub fn state_label(idx: usize) -> &'static str {
    STATE_LABELS.get(idx).unwrap_or(&"unknown")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_obs() -> HmmObservation {
        HmmObservation {
            risk_single: 0.05,
            u_final: 0.15,
            k_conflict: 0.02,
            time_interval_hours: 48.0,
            content_similarity_delta: 0.1,
        }
    }

    fn recon_obs() -> HmmObservation {
        HmmObservation {
            risk_single: 0.25,
            u_final: 0.60,
            k_conflict: 0.10,
            time_interval_hours: 24.0,
            content_similarity_delta: 0.3,
        }
    }

    fn attack_obs() -> HmmObservation {
        HmmObservation {
            risk_single: 0.85,
            u_final: 0.20,
            k_conflict: 0.50,
            time_interval_hours: 2.0,
            content_similarity_delta: 0.8,
        }
    }

    #[test]
    fn test_initial_state_mostly_normal() {
        let state = AttackPhaseState::new("test".to_string());
        assert!(state.alpha[0] > 0.9);
        assert_eq!(state.dominant_label(), "normal");
    }

    #[test]
    fn test_normal_emails_stay_normal() {
        let mut state = AttackPhaseState::new("pair:a→b".to_string());
        let obs = normal_obs();

        for _ in 0..20 {
            let r = state.update(&obs);
            assert_eq!(r.dominant_state, 0, "Should stay in normal state");
        }
        assert!(state.alpha[0] > 0.9);
    }

    #[test]
    fn test_attack_sequence_raises_risk() {
        let mut state = AttackPhaseState::new("pair:attacker→victim".to_string());

       // Phase 1: Normal emails (build history)
        for _ in 0..10 {
            state.update(&normal_obs());
        }

       // Phase 2: Recon-like probing
        for _ in 0..5 {
            state.update(&recon_obs());
        }

       // Phase 3: Attack execution
        let mut max_temporal_risk = 0.0;
        for _ in 0..5 {
            let r = state.update(&attack_obs());
            if r.temporal_risk > max_temporal_risk {
                max_temporal_risk = r.temporal_risk;
            }
        }

        assert!(
            max_temporal_risk > 0.2,
            "Attack sequence should produce elevated temporal risk: {:.3}",
            max_temporal_risk
        );
    }

    #[test]
    fn test_emission_likelihoods_normal() {
        let obs = normal_obs();
        let e = compute_emission_likelihoods(&obs);
       // Normal state should have highest emission for safe email
        assert!(
            e[0] > e[3],
            "S0 emission should exceed S3 for normal obs: S0={:.3} S3={:.3}",
            e[0],
            e[3]
        );
    }

    #[test]
    fn test_emission_likelihoods_attack() {
        let obs = attack_obs();
        let e = compute_emission_likelihoods(&obs);
       // Attack state should have highest emission for high-risk email
        assert!(
            e[3] > e[0],
            "S3 emission should exceed S0 for attack obs: S3={:.3} S0={:.3}",
            e[3],
            e[0]
        );
    }

    #[test]
    fn test_posteriors_sum_to_one() {
        let mut state = AttackPhaseState::new("test".to_string());
        let obs = recon_obs();

        for _ in 0..10 {
            let r = state.update(&obs);
            let sum: f64 = r.posteriors.iter().sum();
            assert!(
                (sum - 1.0).abs() < 1e-6,
                "Posteriors should sum to 1.0: got {:.6}",
                sum
            );
        }
    }

    #[test]
    fn test_temporal_risk_bounded() {
        let mut state = AttackPhaseState::new("test".to_string());

       // Mix of observations
        for obs in &[normal_obs(), recon_obs(), attack_obs()] {
            let r = state.update(obs);
            assert!(
                r.temporal_risk >= 0.0 && r.temporal_risk <= 1.0,
                "Temporal risk should be in [0,1]: {:.3}",
                r.temporal_risk
            );
        }
    }

    #[test]
    fn test_transition_matrix_row_stochastic() {
        for (from, row) in TRANSITION.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            assert!(
                (sum - 1.0).abs() < 1e-10,
                "Row {} sums to {:.6}, expected 1.0",
                from,
                sum
            );
        }
    }
}
