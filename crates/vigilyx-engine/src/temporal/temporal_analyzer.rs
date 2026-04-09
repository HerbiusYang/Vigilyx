//! Temporal analysis orchestrator.

//! Runs asynchronously after single-email verdict, performing cross-time-window
//! correlation analysis:

//! 1. CUSUM change-point detection on sender risk time series
//! 2. Dual EWMA drift detection on sender behavior baseline
//! 3. Entity risk accumulation for sender and domain
//! 4. HMM 5-state attack phase inference (per sender-recipient pair)
//! 5. Communication graph anomaly detection

//! If temporal analysis upgrades the risk level, the verdict is updated
//! and a WebSocket notification is broadcast.

use std::sync::Arc;

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

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
   /// Sender entity key
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

/// In-memory temporal state cache for fast lookups.
/// Backed by PostgreSQL for persistence (loaded on startup, flushed periodically).
pub struct TemporalAnalyzer {
    cusum_states: Arc<RwLock<FxHashMap<String, CusumState>>>,
    ewma_states: Arc<RwLock<FxHashMap<String, DualEwmaState>>>,
    entity_states: Arc<RwLock<FxHashMap<String, EntityRiskState>>>,
    hmm_states: Arc<RwLock<FxHashMap<String, AttackPhaseState>>>,
    hawkes_states: Arc<RwLock<FxHashMap<String, HawkesState>>>,
    comm_graph: Arc<RwLock<CommGraph>>,
    cusum_params: CusumParams,
    ewma_params: EwmaParams,
    entity_params: EntityRiskParams,
    graph_params: GraphParams,
   /// Track last email timestamp per sender for HMM interval calculation
    last_email_ts: Arc<RwLock<FxHashMap<String, std::time::Instant>>>,
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
            cusum_states: Arc::new(RwLock::new(FxHashMap::default())),
            ewma_states: Arc::new(RwLock::new(FxHashMap::default())),
            entity_states: Arc::new(RwLock::new(FxHashMap::default())),
            hmm_states: Arc::new(RwLock::new(FxHashMap::default())),
            hawkes_states: Arc::new(RwLock::new(FxHashMap::default())),
            comm_graph: Arc::new(RwLock::new(CommGraph::new())),
            cusum_params: CusumParams::default(),
            ewma_params: EwmaParams::default(),
            entity_params: EntityRiskParams::default(),
            graph_params: GraphParams::default(),
            last_email_ts: Arc::new(RwLock::new(FxHashMap::default())),
        }
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

   /// Full analysis with all observation context.
    pub async fn analyze_full(&self, obs: &TemporalObservation<'_>) -> TemporalResult {
        let sender_lower = obs.sender.to_ascii_lowercase();
        let mut sender_key = String::with_capacity(7 + sender_lower.len());
        sender_key.push_str("sender:");
        sender_key.push_str(&sender_lower);

       // 1-3. CUSUM + EWMA + Entity (independent -> concurrent lock acquisition)
        let (cusum_result, ewma_result, entity_result) = tokio::join!(
            async {
                let mut states = self.cusum_states.write().await;
                let state = states
                    .entry(sender_key.clone())
                    .or_insert_with(|| CusumState::new(sender_key.clone()));
                cusum_update(state, obs.risk_single, &self.cusum_params)
            },
            async {
                let mut states = self.ewma_states.write().await;
                let state = states
                    .entry(sender_key.clone())
                    .or_insert_with(|| DualEwmaState::new(sender_key.clone()));
                ewma_update(state, obs.risk_single, &self.ewma_params)
            },
            async {
                let mut states = self.entity_states.write().await;
                let state = states
                    .entry(sender_key.clone())
                    .or_insert_with(|| EntityRiskState::with_defaults(sender_key.clone()));
                entity_risk_update(state, obs.risk_single, &self.entity_params)
            }
        );

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

       // 4. Timestamp + HMM + Hawkes time (single last_email_ts lock)
        let now = std::time::Instant::now();
        let (time_interval_hours, now_hours) = {
            let mut ts_map = self.last_email_ts.write().await;
            let interval = ts_map
                .get(&sender_key)
                .map(|prev| now.duration_since(*prev).as_secs_f64() / 3600.0)
                .unwrap_or(48.0);
            let elapsed = ts_map
                .get(&sender_key)
                .map(|prev| prev.elapsed().as_secs_f64() / 3600.0)
                .unwrap_or(0.0);
            ts_map.insert(sender_key.clone(), now);
            (interval, elapsed)
        };
       // Lock released - no second acquisition needed for Hawkes

       // 5. HMM attack phase (per sender-recipient pair)
       // Pre-allocate pair_key buffer - reused across HMM + Hawkes loops
        let prefix_len = sender_lower.len() + "→".len();
        let mut pair_key_buf = String::with_capacity(prefix_len + 32);

       // Pre-compute lowercased recipients once (reused by HMM + Hawkes + CommGraph)
        let recipients_lower: Vec<String> = obs
            .recipients
            .iter()
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
                let mut hmm_states = self.hmm_states.write().await;
                for recipient_lower in &recipients_lower {
                    pair_key_buf.clear();
                    pair_key_buf.push_str(&sender_lower);
                    pair_key_buf.push('→');
                    pair_key_buf.push_str(recipient_lower);

                    let state = hmm_states
                        .entry(pair_key_buf.clone())
                        .or_insert_with(|| AttackPhaseState::new(pair_key_buf.clone()));

                    let result = state.update(&hmm_obs);

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

       // 6. Communication graph
        let graph_anomaly = if !obs.recipients.is_empty() {
            let result = {
                let mut graph = self.comm_graph.write().await;
                graph.observe(
                    obs.sender,
                    obs.recipients,
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
                let mut states = self.hawkes_states.write().await;
                for (i, recipient_lower) in recipients_lower.iter().enumerate() {
                    pair_key_buf.clear();
                    pair_key_buf.push_str(&sender_lower);
                    pair_key_buf.push('→');
                    pair_key_buf.push_str(recipient_lower);

                    let state = states
                        .entry(pair_key_buf.clone())
                        .or_insert_with(HawkesState::new);

                    let result = state.observe(now_hours, obs.risk_single);

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
            let mut states = self.hawkes_states.write().await;
            let state = states
                .entry(sender_key.clone())
                .or_insert_with(HawkesState::new);
            Some(state.observe(now_hours, obs.risk_single))
        };

       // 7. Composite temporal risk
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

        let risk_upgraded = temporal_risk > 0.0;

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
        let states = self.entity_states.read().await;
        states
            .values()
            .filter(|s| s.risk_value >= self.entity_params.watchlist_threshold)
            .map(|s| (s.entity_key.clone(), s.risk_value))
            .collect()
    }

   /// Get CUSUM alarm list.
    pub async fn get_cusum_alarms(&self) -> Vec<String> {
        let states = self.cusum_states.read().await;
        states
            .values()
            .filter(|s| s.alarm_active)
            .map(|s| s.entity_key.clone())
            .collect()
    }

   /// Export all temporal state for DB persistence.
    pub async fn export_states(
        &self,
    ) -> (Vec<CusumState>, Vec<DualEwmaState>, Vec<EntityRiskState>) {
        let cusum = self.cusum_states.read().await.values().cloned().collect();
        let ewma = self.ewma_states.read().await.values().cloned().collect();
        let entity = self.entity_states.read().await.values().cloned().collect();
        (cusum, ewma, entity)
    }

   /// Import temporal state from DB (called on startup).
    pub async fn import_states(
        &self,
        cusum: Vec<CusumState>,
        ewma: Vec<DualEwmaState>,
        entity: Vec<EntityRiskState>,
    ) {
        {
            let mut states = self.cusum_states.write().await;
            for s in cusum {
                states.insert(s.entity_key.clone(), s);
            }
        }
        {
            let mut states = self.ewma_states.write().await;
            for s in ewma {
                states.insert(s.entity_key.clone(), s);
            }
        }
        {
            let mut states = self.entity_states.write().await;
            for s in entity {
                states.insert(s.entity_key.clone(), s);
            }
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
