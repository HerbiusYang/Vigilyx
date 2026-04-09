//! L1 Marked Univariate Hawkes Self-Exciting Process (v5.0 8).

//! Models the self-exciting nature of email attack campaigns:
//! after a high-risk email, subsequent emails from the same sender-recipient
//! pair are more likely to be malicious (attack "momentum").

//! Intensity function:
//! (t) = + (r) g(t - t)

//! Where:
//! = baseline intensity (emails/hour, adaptive EWMA)
//! = self-excitation coefficient
//! (r) = r^1.5 (mark kernel - high-risk emails excite more strongly)
//! g(t) = exp(- t) (exponential decay kernel)

//! Output: (t)/ = intensity ratio
//! > 3.0 -> "burst" warning
//! > 5.0 -> "burst" alarm (P0/P1 in alert.rs)

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Default parameters for the Hawkes process.
const DEFAULT_ALPHA: f64 = 0.8; // Self-excitation coefficient
const DEFAULT_BETA: f64 = 2.0; // Decay rate (per hour) - half-life 0.35h 21min
const DEFAULT_MU_INIT: f64 = 0.5; // Initial baseline intensity (emails/hour)
const DEFAULT_MU_EWMA: f64 = 0.005; // EWMA smoothing factor for adaptation (slow - baseline should be stable)
const DEFAULT_MAX_EVENTS: usize = 100; // Max history length

/// Result of Hawkes process observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HawkesResult {
   /// Current conditional intensity (t).
    pub intensity: f64,
   /// Intensity ratio (t)/ - how many times above baseline.
    pub intensity_ratio: f64,
   /// Whether a burst was detected (ratio> 3.0).
    pub burst_detected: bool,
}

/// Per-pair Hawkes process state.
#[derive(Debug, Clone)]
pub struct HawkesState {
   /// Historical events: (timestamp_hours, risk_score).
    events: VecDeque<(f64, f64)>,
   /// Adaptive baseline intensity (EWMA over long window).
    mu: f64,
   /// Self-excitation coefficient.
    alpha: f64,
   /// Decay rate (per hour).
    beta: f64,
   /// EWMA smoothing factor for.
    mu_ewma_alpha: f64,
   /// Maximum event history length.
    max_events: usize,
   /// Event counter (for warmup).
    total_events: u64,
}

impl HawkesState {
   /// Create a new Hawkes process state with default parameters.
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(DEFAULT_MAX_EVENTS),
            mu: DEFAULT_MU_INIT,
            alpha: DEFAULT_ALPHA,
            beta: DEFAULT_BETA,
            mu_ewma_alpha: DEFAULT_MU_EWMA,
            max_events: DEFAULT_MAX_EVENTS,
            total_events: 0,
        }
    }

   /// Observe a new event and return the current intensity assessment.
    
   /// # Arguments
   /// - `now_hours`: current time in hours (monotonic, can be relative)
   /// - `risk_score`: risk score of the current email [0, 1]
    
   /// # Returns
   /// `HawkesResult` with intensity, ratio, and burst detection.
    pub fn observe(&mut self, now_hours: f64, risk_score: f64) -> HawkesResult {
        let risk = risk_score.clamp(0.0, 1.0);

       // Compute conditional intensity (t)
       // Sum of excitation contributions from past events
       // Events are always recorded with monotonically increasing timestamps,
       // so dt = now_hours - t_j is always>= 0. No need for dt <0 guard.
        let excitation: f64 = self
            .events
            .iter()
            .map(|&(t_j, r_j)| {
                let dt = now_hours - t_j;
                self.alpha * mark_kernel(r_j) * decay_kernel(dt, self.beta)
            })
            .sum();

        let intensity = self.mu + excitation;

       // Update baseline via EWMA
       // Compute instantaneous rate: 1 event at this time
       // We adapt slowly to track the sender's "normal" email frequency
        if self.total_events > 3 {
           // Only adapt after warmup period
            if let Some(&(t_prev, _)) = self.events.back() {
                let dt = (now_hours - t_prev).max(0.001);
                let instantaneous_rate = 1.0 / dt; // events per hour
               // Clamp to prevent from exploding
                let clamped_rate = instantaneous_rate.min(100.0);
                self.mu = self.mu * (1.0 - self.mu_ewma_alpha) + clamped_rate * self.mu_ewma_alpha;
               // floor to prevent division by near-zero
                self.mu = self.mu.max(0.01);
            }
        }

       // Record event
        self.events.push_back((now_hours, risk));
        self.total_events += 1;

       // Trim old events
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }

       // Also trim events that have decayed below threshold (> 5 half-lives)
        let cutoff = now_hours - 5.0 * (1.0 / self.beta) * std::f64::consts::LN_2;
        while self
            .events
            .front()
            .map(|&(t, _)| t < cutoff)
            .unwrap_or(false)
        {
            self.events.pop_front();
        }

       // Compute ratio and burst detection
        let intensity_ratio = intensity / self.mu.max(0.01);
        let burst_detected = intensity_ratio > 3.0;

        HawkesResult {
            intensity,
            intensity_ratio,
            burst_detected,
        }
    }
}

impl Default for HawkesState {
    fn default() -> Self {
        Self::new()
    }
}

/// Mark kernel: (r) = r^1.5
/// High-risk emails (r -> 1.0) produce stronger self-excitation.
/// Uses `r * r.sqrt()` instead of `r.powf(1.5)`: sqrt is a single CPU
/// instruction (fsqrt/vsqrtsd) vs iterative powf - 8-15x faster.
#[inline]
fn mark_kernel(risk: f64) -> f64 {
    risk * risk.sqrt()
}

/// Exponential decay kernel: g(t) = exp(- t)
#[inline]
fn decay_kernel(dt: f64, beta: f64) -> f64 {
    (-beta * dt).exp()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hawkes_initial_state() {
        let state = HawkesState::new();
        assert!((state.mu - DEFAULT_MU_INIT).abs() < 1e-10);
        assert_eq!(state.events.len(), 0);
    }

    #[test]
    fn test_hawkes_single_event() {
        let mut state = HawkesState::new();
        let r = state.observe(0.0, 0.5);

       // First event: intensity = (no prior events to excite)
        assert!(
            (r.intensity - DEFAULT_MU_INIT).abs() < 0.1,
            "First event intensity should be ~μ: got {}",
            r.intensity
        );
        assert!(!r.burst_detected, "Single event should not burst");
    }

    #[test]
    fn test_hawkes_self_excitation() {
        let mut state = HawkesState::new();

       // Send several high-risk emails in quick succession
        let t0 = 0.0;
        state.observe(t0, 0.9); // t=0
        state.observe(t0 + 0.1, 0.9); // t=6min
        state.observe(t0 + 0.2, 0.9); // t=12min
        let r = state.observe(t0 + 0.3, 0.9); // t=18min

       // Self-excitation should raise intensity above baseline
        assert!(
            r.intensity > DEFAULT_MU_INIT * 2.0,
            "Self-excitation should raise intensity: {}",
            r.intensity
        );
    }

    #[test]
    fn test_hawkes_decay() {
        let mut state = HawkesState::new();

       // One high-risk event, then wait a long time
        state.observe(0.0, 1.0);
        let r_soon = state.observe(0.1, 0.0); // 6min later (low risk)
        let r_later = state.observe(3.0, 0.0); // 3 hours later

       // Excitation from initial event should have decayed significantly
        assert!(
            r_later.intensity < r_soon.intensity,
            "Intensity should decay: soon={}, later={}",
            r_soon.intensity,
            r_later.intensity
        );
    }

    #[test]
    fn test_hawkes_burst_detection() {
        let mut state = HawkesState::new();

       // Phase 1: Establish normal baseline with sparse low-risk emails
        for i in 0..6 {
            let t = i as f64 * 2.0; // Every 2 hours - normal pace
            state.observe(t, 0.1);
        }

       // Phase 2: Sudden burst of high-risk emails
        let burst_start = 12.0;
        for i in 0..10 {
            let t = burst_start + i as f64 * 0.03; // Every ~2 minutes
            state.observe(t, 0.95);
        }

        let r = state.observe(burst_start + 0.35, 0.95);
       // After establishing low baseline then bursting, ratio should be high
        assert!(
            r.burst_detected,
            "Rapid burst after baseline should be detected, ratio={}",
            r.intensity_ratio
        );
        assert!(
            r.intensity_ratio > 3.0,
            "Ratio should exceed 3.0: {}",
            r.intensity_ratio
        );
    }

    #[test]
    fn test_hawkes_low_risk_no_burst() {
        let mut state = HawkesState::new();

       // Many low-risk emails -> mark kernel dampens excitation
        for i in 0..10 {
            let t = i as f64 * 0.1;
            state.observe(t, 0.05);
        }

        let r = state.observe(1.1, 0.05);
       // Low-risk emails shouldn't trigger burst (mark kernel = 0.05^1.5 0.01)
        assert!(
            !r.burst_detected,
            "Low-risk emails should not burst, ratio={}",
            r.intensity_ratio
        );
    }

    #[test]
    fn test_mark_kernel() {
        assert!((mark_kernel(0.0) - 0.0).abs() < 1e-10);
        assert!((mark_kernel(1.0) - 1.0).abs() < 1e-10);
       // 0.5^1.5 = 0.5 * sqrt(0.5) 0.3536
        assert!((mark_kernel(0.5) - 0.3536).abs() < 0.001);
    }

    #[test]
    fn test_decay_kernel() {
        assert!((decay_kernel(0.0, 2.0) - 1.0).abs() < 1e-10);
       // exp(-2*1) 0.1353
        assert!((decay_kernel(1.0, 2.0) - (-2.0_f64).exp()).abs() < 1e-6);
    }

    #[test]
    fn test_hawkes_event_trimming() {
        let mut state = HawkesState::new();
        state.max_events = 5;

       // Add more events than max_events
        for i in 0..10 {
            state.observe(i as f64, 0.5);
        }

        assert!(
            state.events.len() <= 5,
            "Events should be trimmed to max: {}",
            state.events.len()
        );
    }
}
