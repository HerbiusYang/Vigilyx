//! Temporal analysis orchestrator.

//! Runs asynchronously after single-email verdict, performing cross-time-window
//! correlation analysis:

//! 1. CUSUM change-point detection on sender risk time series
//! 2. Dual EWMA drift detection on sender behavior baseline
//! 3. Entity risk accumulation for sender and domain
//! 4. HMM 5-state attack phase inference (per sender-recipient pair)
//! 5. Communication graph anomaly detection

//! Temporal analysis runs *after* the single-email verdict is stored; it does
//! **not** rewrite the stored verdict. Its result feeds post-verdict alert
//! grading only (`risk_upgraded` / `temporal_risk` are converted to
//! `AlertSignals` in `pipeline::post_verdict`).

use std::hash::BuildHasherDefault;
use std::sync::Arc;

use dashmap::DashMap;
use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// FxHash-backed BuildHasher for DashMap (same pattern as sniffer).
type FxBuildHasher = BuildHasherDefault<FxHasher>;

/// Capacity bound for every temporal state map (E6). Sender→recipient pair
/// maps and per-sender maps are keyed by attacker-influenced strings; without
/// a bound a spray of unique senders/recipients grows them linearly forever.
/// At capacity, *new* keys are computed statelessly (not persisted) instead of
/// being inserted — existing keys keep working, so this is never a global
/// fail-open.
const MAX_TEMPORAL_KEYS: usize = 100_000;

/// Maximum recipients tracked per email for pair-level state and graph edges
/// (E6). A single message with N RCPT TO must not create O(N) pairs.
const MAX_TRACKED_RECIPIENTS: usize = 20;

use super::comm_graph::{CommGraph, GraphParams};
use super::cusum::{CusumParams, CusumState, cusum_update};
use super::dual_ewma::{DualEwmaState, EwmaParams, ewma_update};
use super::entity_risk::{EntityRiskParams, EntityRiskState, entity_risk_update};
use super::hawkes::{HawkesResult, HawkesState};
use super::hmm_attack_phase::{self, AttackPhaseState, HmmObservation};

/// HMM attack phase posterior probabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmmPhaseResult {
    pub normal: f64,
    pub reconnaissance: f64,
    pub trust_building: f64,
    pub attack_execution: f64,
    pub harvest: f64,
    pub dominant_state: String,
    pub temporal_risk: f64,
}

/// Communication graph anomaly result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnomalyResult {
    pub is_anomalous: bool,
    pub pattern_label: String,
    pub anomaly_score: f64,
}

/// Result of temporal analysis for a single email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalResult {
    /// Baseline entity key actually used for CUSUM/EWMA/entity state:
    /// `domain:<registrable>` for normal domains, `sender:<email>` for public
    /// mailbox providers (qq.com, gmail.com, …) where a domain-scope baseline
    /// is both weaponizable and useless (E3/E4).
    pub sender_key: String,
    /// CUSUM alarm status
    pub cusum_alarm: bool,
    /// CUSUM S value
    pub cusum_s_pos: f64,
    /// EWMA drift score
    pub ewma_drift_score: f64,
    /// Whether EWMA drift was detected
    pub ewma_drifting: bool,
    /// Accumulated entity risk for sender
    pub sender_risk: f64,
    /// Whether sender is on watchlist
    pub sender_watchlisted: bool,
    /// HMM attack phase inference (5-state)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmm_phase: Option<HmmPhaseResult>,
    /// Communication graph anomaly
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_anomaly: Option<GraphAnomalyResult>,
    /// Hawkes self-excitation process result (v5.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hawkes: Option<HawkesResult>,
    /// Temporal risk contribution (max of all temporal signals)
    pub temporal_risk: f64,
    /// Whether temporal analysis upgraded the risk
    pub risk_upgraded: bool,
}

/// Extended observation context for temporal analysis.
pub struct TemporalObservation<'a> {
    /// Sender email
    pub sender: &'a str,
    /// Recipients
    pub recipients: &'a [String],
    /// D-S fused risk score
    pub risk_single: f64,
    /// Uncertainty from D-S fusion (u component)
    pub u_final: f64,
    /// Conflict factor K
    pub k_conflict: f64,
    /// Content similarity delta (0=identical, 1=completely different)
    pub content_similarity_delta: f64,
}

fn temporal_risk_upgraded(temporal_risk: f64, single_email_risk: f64) -> bool {
    temporal_risk.is_finite() && single_email_risk.is_finite() && temporal_risk > single_email_risk
}

fn registered_sender_domain(sender: &str) -> Option<String> {
    let domain = sender.rsplit_once('@')?.1.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    let lower = domain.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 2 {
        return Some(lower);
    }
    let tld_labels = crate::module_data::module_data()
        .get_list("compound_tlds")
        .iter()
        .find(|compound| lower == **compound || lower.ends_with(&format!(".{compound}")))
        .map_or(1, |_| 2);
    let keep = tld_labels + 1;
    Some(if parts.len() >= keep {
        parts[parts.len() - keep..].join(".")
    } else {
        lower
    })
}

/// In-memory temporal state cache for fast lookups.
/// Backed by PostgreSQL for persistence (loaded on startup, flushed periodically).
pub struct TemporalAnalyzer {
    cusum_states: Arc<DashMap<String, CusumState, FxBuildHasher>>,
    ewma_states: Arc<DashMap<String, DualEwmaState, FxBuildHasher>>,
    entity_states: Arc<DashMap<String, EntityRiskState, FxBuildHasher>>,
    hmm_states: Arc<DashMap<String, AttackPhaseState, FxBuildHasher>>,
    hawkes_states: Arc<DashMap<String, HawkesState, FxBuildHasher>>,
    comm_graph: Arc<RwLock<CommGraph>>,
    cusum_params: CusumParams,
    ewma_params: EwmaParams,
    entity_params: EntityRiskParams,
    graph_params: GraphParams,
    /// Track last email timestamp per sender for HMM interval calculation
    last_email_ts: Arc<DashMap<String, std::time::Instant, FxBuildHasher>>,
    /// Engine-local time origin for Hawkes event timestamps (E1). Hawkes
    /// event times must be monotonically increasing per key; they are
    /// measured as hours since analyzer creation, never as inter-arrival
    /// intervals (intervals are not monotone and explode the decay kernel).
    started_at: std::time::Instant,
    /// Capacity bound for all temporal state maps (E6).
    max_keys: usize,
}

impl Default for TemporalAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TemporalAnalyzer {
    /// Create a new temporal analyzer with default parameters.
    pub fn new() -> Self {
        Self {
            cusum_states: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            ewma_states: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            entity_states: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            hmm_states: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            hawkes_states: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            comm_graph: Arc::new(RwLock::new(CommGraph::new())),
            cusum_params: CusumParams::default(),
            ewma_params: EwmaParams::default(),
            entity_params: EntityRiskParams::default(),
            graph_params: GraphParams::default(),
            last_email_ts: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            started_at: std::time::Instant::now(),
            max_keys: MAX_TEMPORAL_KEYS,
        }
    }

    /// Override the state-map capacity bound (tests use a tiny bound to
    /// exercise the capacity path deterministically).
    #[cfg(test)]
    fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    /// Simple analysis (backward compatible) - sender + risk_single only.
    pub async fn analyze(&self, sender: &str, risk_single: f64) -> TemporalResult {
        let obs = TemporalObservation {
            sender,
            recipients: &[],
            risk_single,
            u_final: 0.3, // default uncertainty
            k_conflict: 0.0,
            content_similarity_delta: 0.0,
        };
        self.analyze_full(&obs).await
    }

    /// Whether `key` may be inserted into `map`: already present, or the map
    /// is below the capacity bound. At capacity new keys are refused; callers
    /// fall back to a temporary, unpersisted state so detection still runs
    /// for that email without letting the map grow without bound.
    fn has_temporal_capacity<V>(&self, map: &DashMap<String, V, FxBuildHasher>, key: &str) -> bool {
        map.len() < self.max_keys || map.contains_key(key)
    }

    /// Full analysis with all observation context.
    pub async fn analyze_full(&self, obs: &TemporalObservation<'_>) -> TemporalResult {
        let sender_lower = obs.sender.to_ascii_lowercase();
        // Keep HMM/Hawkes sender-recipient identity granular; only the
        // long-lived baseline state is generalized to the domain.
        let sender_identity_key = format!("sender:{sender_lower}");
        // Aggregate slow behavioral baselines at registrable-domain scope so
        // rotating local-parts (user1@ / user2@) cannot cold-start every time.
        //
        // Exception (E3/E4): public mailbox providers (qq.com, gmail.com, …)
        // are shared by millions of unrelated users. A domain-scope baseline
        // there is both weaponizable (one risky mail trips the whole domain's
        // CUSUM alarm) and useless (a compromised webmail account's risk is
        // diluted by the domain's clean traffic). Those senders fall back to
        // sender-scope baselines.
        let sender_domain = registered_sender_domain(&sender_lower)
            .unwrap_or_else(|| sender_lower.clone());
        let sender_key = if crate::pipeline::internal_domains::is_public_mail_domain(&sender_domain)
        {
            sender_identity_key.clone()
        } else {
            format!("domain:{sender_domain}")
        };

        // 1-3. CUSUM + EWMA + Entity (DashMap per-shard locks, no whole-map lock needed)
        let cusum_result = if self.has_temporal_capacity(&self.cusum_states, &sender_key) {
            let mut entry = self
                .cusum_states
                .entry(sender_key.clone())
                .or_insert_with(|| CusumState::new(sender_key.clone()));
            cusum_update(entry.value_mut(), obs.risk_single, &self.cusum_params)
        } else {
            debug!(key = sender_key.as_str(), "temporal cusum map at capacity; computing statelessly");
            let mut tmp = CusumState::new(sender_key.clone());
            cusum_update(&mut tmp, obs.risk_single, &self.cusum_params)
        };
        let ewma_result = if self.has_temporal_capacity(&self.ewma_states, &sender_key) {
            let mut entry = self
                .ewma_states
                .entry(sender_key.clone())
                .or_insert_with(|| DualEwmaState::new(sender_key.clone()));
            ewma_update(entry.value_mut(), obs.risk_single, &self.ewma_params)
        } else {
            debug!(key = sender_key.as_str(), "temporal ewma map at capacity; computing statelessly");
            let mut tmp = DualEwmaState::new(sender_key.clone());
            ewma_update(&mut tmp, obs.risk_single, &self.ewma_params)
        };
        let entity_result = if self.has_temporal_capacity(&self.entity_states, &sender_key) {
            let mut entry = self
                .entity_states
                .entry(sender_key.clone())
                .or_insert_with(|| EntityRiskState::with_defaults(sender_key.clone()));
            entity_risk_update(entry.value_mut(), obs.risk_single, &self.entity_params)
        } else {
            debug!(key = sender_key.as_str(), "temporal entity map at capacity; computing statelessly");
            let mut tmp = EntityRiskState::with_defaults(sender_key.clone());
            entity_risk_update(&mut tmp, obs.risk_single, &self.entity_params)
        };

        if cusum_result.alarm {
            warn!(
                sender = obs.sender,
                s_pos = cusum_result.s_pos,
                "CUSUM alarm triggered for sender"
            );
        }
        if ewma_result.drifting {
            warn!(
                sender = obs.sender,
                drift = ewma_result.drift_score,
                "EWMA drift detected for sender"
            );
        }

        // 4. Timestamp + HMM + Hawkes time (DashMap per-key lock)
        //
        // Hawkes event time MUST be monotone per key: use hours since this
        // analyzer was created (E1). The previous code fed the *inter-arrival
        // interval* as the event timestamp — intervals are not monotone, so a
        // shrinking interval made dt < 0 and exploded the decay kernel.
        let now = std::time::Instant::now();
        let now_hours = now.duration_since(self.started_at).as_secs_f64() / 3600.0;
        let time_interval_hours = self
            .last_email_ts
            .get(&sender_identity_key)
            .map(|prev| now.duration_since(*prev).as_secs_f64() / 3600.0)
            .unwrap_or(48.0);
        if self.has_temporal_capacity(&self.last_email_ts, &sender_identity_key) {
            self.last_email_ts.insert(sender_identity_key.clone(), now);
        }
        // Lock released - no second acquisition needed for Hawkes

        // 5. HMM attack phase (per sender-recipient pair)
        // Pre-allocate pair_key buffer - reused across HMM + Hawkes loops
        let prefix_len = sender_lower.len() + "→".len();
        let mut pair_key_buf = String::with_capacity(prefix_len + 32);

        // Pre-compute lowercased recipients once (reused by HMM + Hawkes +
        // CommGraph). Truncated (E6): a single message with N RCPT TO must
        // not create O(N) pair states / graph edges.
        let recipients_lower: Vec<String> = obs
            .recipients
            .iter()
            .take(MAX_TRACKED_RECIPIENTS)
            .map(|r| r.to_ascii_lowercase())
            .collect();

        let hmm_phase = if !obs.recipients.is_empty() {
            let hmm_obs = HmmObservation {
                risk_single: obs.risk_single,
                u_final: obs.u_final,
                k_conflict: obs.k_conflict,
                time_interval_hours,
                content_similarity_delta: obs.content_similarity_delta,
            };

            let mut worst_hmm: Option<HmmPhaseResult> = None;
            {
                for recipient_lower in &recipients_lower {
                    pair_key_buf.clear();
                    pair_key_buf.push_str(&sender_lower);
                    pair_key_buf.push('→');
                    pair_key_buf.push_str(recipient_lower);

                    let result = if self.has_temporal_capacity(&self.hmm_states, &pair_key_buf) {
                        let mut entry = self
                            .hmm_states
                            .entry(pair_key_buf.clone())
                            .or_insert_with(|| AttackPhaseState::new(pair_key_buf.clone()));
                        entry.value_mut().update(&hmm_obs)
                    } else {
                        debug!(pair = pair_key_buf.as_str(), "temporal hmm map at capacity; computing statelessly");
                        let mut tmp = AttackPhaseState::new(pair_key_buf.clone());
                        tmp.update(&hmm_obs)
                    };

                    let phase = HmmPhaseResult {
                        normal: result.posteriors[0],
                        reconnaissance: result.posteriors[1],
                        trust_building: result.posteriors[2],
                        attack_execution: result.posteriors[3],
                        harvest: result.posteriors[4],
                        dominant_state: hmm_attack_phase::state_label(result.dominant_state)
                            .to_string(),
                        temporal_risk: result.temporal_risk,
                    };

                    let is_worse = worst_hmm
                        .as_ref()
                        .map(|w| phase.temporal_risk > w.temporal_risk)
                        .unwrap_or(true);
                    if is_worse {
                        worst_hmm = Some(phase);
                    }
                }
            }
            worst_hmm
        } else {
            None
        };

        // 6. Communication graph (recipients already truncated to
        // MAX_TRACKED_RECIPIENTS above — reuse the lowercased list).
        let graph_anomaly = if !obs.recipients.is_empty() {
            let result = {
                let mut graph = self.comm_graph.write().await;
                graph.observe(
                    obs.sender,
                    &recipients_lower,
                    obs.risk_single,
                    &self.graph_params,
                )
            };
            if result.is_anomalous {
                warn!(
                    sender = obs.sender,
                    pattern = result.pattern_label.as_str(),
                    score = result.anomaly_score,
                    "Communication graph anomaly detected"
                );
                Some(GraphAnomalyResult {
                    is_anomalous: true,
                    pattern_label: result.pattern_label,
                    anomaly_score: result.anomaly_score,
                })
            } else {
                None
            }
        } else {
            None
        };

        // 7. Hawkes self-excitation (reuses now_hours from step 4, pair_key_buf from step 5)
        let hawkes_result = if !obs.recipients.is_empty() {
            let mut worst_hawkes: Option<HawkesResult> = None;
            {
                for (i, recipient_lower) in recipients_lower.iter().enumerate() {
                    pair_key_buf.clear();
                    pair_key_buf.push_str(&sender_lower);
                    pair_key_buf.push('→');
                    pair_key_buf.push_str(recipient_lower);

                    let result = if self.has_temporal_capacity(&self.hawkes_states, &pair_key_buf)
                    {
                        let mut entry =
                            self.hawkes_states.entry(pair_key_buf.clone()).or_default();
                        entry.value_mut().observe(now_hours, obs.risk_single)
                    } else {
                        debug!(pair = pair_key_buf.as_str(), "temporal hawkes map at capacity; computing statelessly");
                        let mut tmp = HawkesState::new();
                        tmp.observe(now_hours, obs.risk_single)
                    };

                    if result.burst_detected {
                        warn!(
                            sender = obs.sender,
                            recipient = obs.recipients[i].as_str(),
                            ratio = result.intensity_ratio,
                            "Hawkes burst detected"
                        );
                    }

                    let is_worse = worst_hawkes
                        .as_ref()
                        .map(|w| result.intensity_ratio > w.intensity_ratio)
                        .unwrap_or(true);
                    if is_worse {
                        worst_hawkes = Some(result);
                    }
                }
            }
            worst_hawkes
        } else {
            let result = if self.has_temporal_capacity(&self.hawkes_states, &sender_identity_key) {
                let mut entry = self
                    .hawkes_states
                    .entry(sender_identity_key.clone())
                    .or_default();
                entry.value_mut().observe(now_hours, obs.risk_single)
            } else {
                debug!(sender = obs.sender, "temporal hawkes map at capacity; computing statelessly");
                let mut tmp = HawkesState::new();
                tmp.observe(now_hours, obs.risk_single)
            };
            Some(result)
        };

        // 8. Composite temporal risk
        let cusum_risk: f64 = if cusum_result.alarm { 0.3 } else { 0.0 };
        let ewma_risk: f64 = if ewma_result.drifting {
            (ewma_result.drift_score * 0.1).min(0.3)
        } else {
            0.0
        };
        let entity_bonus: f64 = if entity_result.watchlisted {
            entity_result.risk_value * 0.2
        } else {
            0.0
        };
        let hmm_risk: f64 = hmm_phase.as_ref().map(|h| h.temporal_risk).unwrap_or(0.0);
        let graph_risk: f64 = graph_anomaly
            .as_ref()
            .map(|g| g.anomaly_score * 0.3) // Scale graph score
            .unwrap_or(0.0);
        let hawkes_risk: f64 = hawkes_result
            .as_ref()
            .map(|h| {
                if h.intensity_ratio > 5.0 {
                    0.5 // Strong burst -> significant risk contribution
                } else if h.burst_detected {
                    0.3 // Moderate burst
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0);

        let temporal_risk = cusum_risk
            .max(ewma_risk)
            .max(entity_bonus)
            .max(hmm_risk)
            .max(graph_risk)
            .max(hawkes_risk);

        let risk_upgraded = temporal_risk_upgraded(temporal_risk, obs.risk_single);

        if risk_upgraded {
            debug!(
                sender = obs.sender,
                temporal_risk = temporal_risk,
                cusum = cusum_risk,
                ewma = ewma_risk,
                entity = entity_bonus,
                hmm = hmm_risk,
                graph = graph_risk,
                hawkes = hawkes_risk,
                "Temporal analysis contributed additional risk"
            );
        }

        TemporalResult {
            sender_key,
            cusum_alarm: cusum_result.alarm,
            cusum_s_pos: cusum_result.s_pos,
            ewma_drift_score: ewma_result.drift_score,
            ewma_drifting: ewma_result.drifting,
            sender_risk: entity_result.risk_value,
            sender_watchlisted: entity_result.watchlisted,
            hmm_phase,
            graph_anomaly,
            hawkes: hawkes_result,
            temporal_risk,
            risk_upgraded,
        }
    }

    /// Get the current watchlist (entities above watchlist threshold).
    pub async fn get_watchlist(&self) -> Vec<(String, f64)> {
        self.entity_states
            .iter()
            .filter(|entry| entry.value().risk_value >= self.entity_params.watchlist_threshold)
            .map(|entry| (entry.value().entity_key.clone(), entry.value().risk_value))
            .collect()
    }

    /// Get CUSUM alarm list.
    pub async fn get_cusum_alarms(&self) -> Vec<String> {
        self.cusum_states
            .iter()
            .filter(|entry| entry.value().alarm_active)
            .map(|entry| entry.value().entity_key.clone())
            .collect()
    }

    /// Export all temporal state for DB persistence.
    pub async fn export_states(
        &self,
    ) -> (Vec<CusumState>, Vec<DualEwmaState>, Vec<EntityRiskState>) {
        let cusum = self
            .cusum_states
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        let ewma = self
            .ewma_states
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        let entity = self
            .entity_states
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        (cusum, ewma, entity)
    }

    /// Import temporal state from DB (called on startup).
    pub async fn import_states(
        &self,
        cusum: Vec<CusumState>,
        ewma: Vec<DualEwmaState>,
        entity: Vec<EntityRiskState>,
    ) {
        for s in cusum {
            self.cusum_states.insert(s.entity_key.clone(), s);
        }
        for s in ewma {
            self.ewma_states.insert(s.entity_key.clone(), s);
        }
        for s in entity {
            self.entity_states.insert(s.entity_key.clone(), s);
        }
    }

    /// Export communication graph edges.
    pub async fn export_graph_edges(&self) -> Vec<super::comm_graph::CommEdge> {
        self.comm_graph.read().await.export_edges()
    }

    /// Import communication graph edges from DB.
    pub async fn import_graph_edges(&self, edges: Vec<super::comm_graph::CommEdge>) {
        self.comm_graph.write().await.import_edges(edges);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporal_risk_only_upgrades_when_it_exceeds_single_email_risk() {
        assert!(temporal_risk_upgraded(0.61, 0.60));
        assert!(!temporal_risk_upgraded(0.60, 0.60));
        assert!(!temporal_risk_upgraded(0.59, 0.60));
    }

    #[test]
    fn non_finite_risk_never_triggers_an_upgrade() {
        assert!(!temporal_risk_upgraded(f64::NAN, 0.2));
        assert!(!temporal_risk_upgraded(0.8, f64::NAN));
        assert!(!temporal_risk_upgraded(f64::INFINITY, 0.8));
    }

    /// PoC (E3): with domain-scoped baselines, one risky mail from
    /// bob@qq.com rode the warmed `domain:qq.com` CUSUM state (tight σ after
    /// alice's clean run) and tripped a domain-wide alarm — every other
    /// qq.com user then inherited the alarm window. Public mailbox providers
    /// must fall back to sender-scoped baselines.
    #[tokio::test]
    async fn public_mail_domain_baselines_are_per_sender() {
        let analyzer = TemporalAnalyzer::new();
        // Warm up one qq.com user's baseline with clean mail.
        for _ in 0..30 {
            analyzer.analyze("alice@qq.com", 0.10).await;
        }
        // A different qq.com user's single risky mail must not inherit the
        // warmed domain baseline.
        let r = analyzer.analyze("bob@qq.com", 0.90).await;
        assert!(
            !r.cusum_alarm,
            "public mail domain CUSUM must be sender-scoped, not domain-wide"
        );
        assert_eq!(r.sender_key, "sender:bob@qq.com");
        assert!(!analyzer.cusum_states.contains_key("domain:qq.com"));
        assert!(analyzer.cusum_states.contains_key("sender:alice@qq.com"));

        // Non-public domains still aggregate at registrable-domain scope.
        let corp = analyzer.analyze("carol@corp-example.cn", 0.10).await;
        assert_eq!(corp.sender_key, "domain:corp-example.cn");
    }

    /// PoC (E4): a compromised webmail account (the most common real-world
    /// BEC carrier) used to get zero temporal upgrade because the shared
    /// domain baseline diluted its risk with the whole domain's clean
    /// traffic. Sender-scoped baselines fix that; unrelated users on the same
    /// domain stay unaffected.
    #[tokio::test]
    async fn compromised_webmail_account_accumulates_sender_level_entity_risk() {
        let analyzer = TemporalAnalyzer::new();
        // Clean background traffic from many unrelated qq.com users.
        for i in 0..50 {
            analyzer.analyze(&format!("user{i}@qq.com"), 0.02).await;
        }
        // A compromised webmail account sends a short run of high-risk BEC.
        let mut last = None;
        for _ in 0..3 {
            last = Some(analyzer.analyze("finance-dept@qq.com", 0.9).await);
        }
        let r = last.unwrap();
        assert_eq!(r.sender_key, "sender:finance-dept@qq.com");
        assert!(
            r.sender_watchlisted,
            "compromised webmail account must accumulate sender-level risk: {}",
            r.sender_risk
        );
        // Unrelated users on the same public domain are unaffected.
        let clean = analyzer.analyze("user0@qq.com", 0.02).await;
        assert!(!clean.sender_watchlisted);
    }

    /// E1 wiring: Hawkes event times come from a monotone engine-local clock,
    /// so rapid-fire analysis can never explode the intensity ratio.
    #[tokio::test]
    async fn hawkes_ratio_stays_finite_and_bounded_through_analyzer() {
        let analyzer = TemporalAnalyzer::new();
        let mut last_ratio = 0.0f64;
        for _ in 0..10 {
            let r = analyzer.analyze("attacker@evil-example.com", 0.9).await;
            let hawkes = r.hawkes.expect("hawkes result must exist");
            assert!(
                hawkes.intensity_ratio.is_finite(),
                "ratio must be finite: {}",
                hawkes.intensity_ratio
            );
            assert!(
                hawkes.intensity_ratio <= 100.0,
                "ratio must be capped: {}",
                hawkes.intensity_ratio
            );
            last_ratio = hawkes.intensity_ratio;
        }
        assert!(last_ratio > 0.0);
    }

    /// E6: all temporal state maps honor the capacity bound; senders beyond
    /// capacity are computed statelessly instead of growing the maps.
    #[tokio::test]
    async fn state_maps_respect_capacity_bound() {
        let analyzer = TemporalAnalyzer::new().with_max_keys(2);
        for name in ["alice", "bob", "carol", "dave"] {
            analyzer
                .analyze(&format!("{name}@{name}-example.com"), 0.5)
                .await;
        }
        assert_eq!(analyzer.cusum_states.len(), 2);
        assert_eq!(analyzer.ewma_states.len(), 2);
        assert_eq!(analyzer.entity_states.len(), 2);
        assert_eq!(analyzer.hawkes_states.len(), 2);
        assert_eq!(analyzer.last_email_ts.len(), 2);

        // Detection still runs for an untracked sender (stateless fallback).
        let r = analyzer.analyze("eve@eve-example.com", 0.9).await;
        assert!(r.hawkes.is_some());
        assert_eq!(analyzer.cusum_states.len(), 2);
    }

    /// E6: a single message with 50 RCPT TO creates at most
    /// MAX_TRACKED_RECIPIENTS pair states / graph edges.
    #[tokio::test]
    async fn recipients_are_truncated_for_pair_state_and_graph() {
        let analyzer = TemporalAnalyzer::new();
        let rcpts: Vec<String> = (0..50)
            .map(|i| format!("victim{i}@corp-example.com"))
            .collect();
        let obs = TemporalObservation {
            sender: "attacker@evil-example.com",
            recipients: &rcpts,
            risk_single: 0.6,
            u_final: 0.3,
            k_conflict: 0.0,
            content_similarity_delta: 0.0,
        };
        analyzer.analyze_full(&obs).await;
        assert!(analyzer.hmm_states.len() <= MAX_TRACKED_RECIPIENTS);
        assert!(analyzer.hawkes_states.len() <= MAX_TRACKED_RECIPIENTS);
        assert!(
            analyzer.comm_graph.read().await.edge_count() <= MAX_TRACKED_RECIPIENTS
        );
    }
}
