//! Feedback-trained D-S parameters, isolated from evidence admission and policy.
//!
//! Online feedback trains a candidate only. An independently accepted artifact
//! is required to change the active model. Absence of labels is not a clean label.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{Bpa, DsLearningEvidence, DsModelParameters, DsSourceParameters};
use vigilyx_db::VigilDb;

pub const STATE_KEY: &str = "ds_learning_state";
const MAX_ITEMS: usize = 512;
const MAX_TRAIN_CASES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningState {
    pub schema_version: u32,
    pub revision: u64,
    pub active: Option<DsModelParameters>,
    pub candidate: Option<DsModelParameters>,
    pub active_acceptance: Option<Acceptance>,
    pub feedback_count: u64,
    pub eligible_count: u64,
    pub excluded_count: u64,
    pub validation_status: String,
    pub pending_gates: Vec<String>,
    pub updated_at: String,
    #[serde(default)]
    pub training_dataset_sha256: Option<String>,
    #[serde(default)]
    pub sample_window_limit: u32,
    #[serde(default)]
    pub previous_active: Option<DsModelParameters>,
    #[serde(default)]
    pub previous_acceptance: Option<Acceptance>,
}

/// Acceptance is produced by an external, frozen evaluation, not by fitting.
/// Binding to parameter bytes prevents stale reports accepting changed weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub release_signature: String,
    pub parameter_sha256: String,
    pub report_sha256: String,
    pub capability_manifest_sha256: String,
    pub holdout_negatives: u64,
    pub holdout_positives: u64,
    pub false_positive_budget: f64,
    pub decision_threshold: f64,
    pub false_positive_upper_bound: f64,
    pub recall_lower_bound: f64,
    pub baseline_recall_lower_bound: f64,
    pub brier: f64,
    pub baseline_brier: f64,
    pub review_cost: f64,
    pub baseline_review_cost: f64,
    pub baseline_passing_case_ids: BTreeSet<String>,
    pub candidate_passing_case_ids: BTreeSet<String>,
}

impl Default for LearningState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            revision: 0,
            active: None,
            candidate: None,
            active_acceptance: None,
            feedback_count: 0,
            eligible_count: 0,
            excluded_count: 0,
            validation_status: "awaiting_feedback".into(),
            pending_gates: vec![
                "independent_calibration".into(),
                "sealed_holdout".into(),
                "capability_preservation".into(),
            ],
            updated_at: String::new(),
            training_dataset_sha256: None,
            sample_window_limit: MAX_TRAIN_CASES as u32,
            previous_active: None,
            previous_acceptance: None,
        }
    }
}

pub fn parameter_sha256(model: &DsModelParameters) -> String {
    // Float bit strings avoid Python/Rust exponent and integer formatting differences.
    let mut value = serde_json::to_value(model).expect("finite validated DS parameters");
    let bits = |number: f64| {
        format!(
            "{:016x}",
            if number == 0.0 {
                0.0_f64.to_bits()
            } else {
                number.to_bits()
            }
        )
    };
    value["base_rate"] = bits(model.base_rate).into();
    for (source, p) in &model.sources {
        for (key, number) in [
            ("slope", p.slope),
            ("intercept", p.intercept),
            ("reliability", p.reliability),
        ] {
            value["sources"][source][key] = bits(number).into();
        }
    }
    if let Some(c) = &model.calibration {
        value["calibration"]["slope"] = bits(c.slope).into();
        value["calibration"]["intercept"] = bits(c.intercept).into();
    }
    let mut hash = Sha256::new();
    // serde_json's preserve_order feature can be enabled transitively by
    // another crate; canonical hashing must never depend on feature unification.
    value.sort_all_objects();
    hash.update(b"vigilyx-ds-parameters-ieee754-v1\0");
    hash.update(serde_json::to_vec(&value).expect("DS parameters serialize"));
    hex::encode(hash.finalize())
}

fn verify_release(acceptance: &Acceptance, key: &[u8]) -> bool {
    use digest::{FixedOutput, KeyInit, Update};
    use subtle::ConstantTimeEq;
    if key.len() < 32 {
        return false;
    }
    let Ok(signature) = hex::decode(&acceptance.release_signature) else {
        return false;
    };
    let input = format!(
        "vigilyx-ds-release-v1\n{}\n{}\n{}",
        acceptance.parameter_sha256,
        acceptance.report_sha256,
        acceptance.capability_manifest_sha256
    );
    type HmacSha256 = hmac::SimpleHmac<sha2::Sha256>;
    let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(key) else {
        return false;
    };
    <HmacSha256 as Update>::update(&mut mac, input.as_bytes());
    let expected = <HmacSha256 as FixedOutput>::finalize_fixed(mac);
    bool::from(expected.as_slice().ct_eq(&signature))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl LearningState {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("Unsupported DS learning state schema".into());
        }
        if let Some(candidate) = &self.candidate {
            candidate.validate()?;
            if candidate.training_status != "candidate" {
                return Err("Candidate must retain candidate training status".into());
            }
        }
        if let Some(active) = &self.active {
            active.validate()?;
            let acceptance = self
                .active_acceptance
                .as_ref()
                .ok_or("Active DS parameters require bound evaluation")?;
            // Feedback and config JSON cannot self-certify a trained model.
            // The protected release signer runs independent acceptance validation.
            let key_path = std::env::var("DS_MODEL_RELEASE_KEY_FILE")
                .map_err(|_| "DS release verification key is not configured")?;
            let key = std::fs::read(key_path)
                .map_err(|_| "DS release verification key is unavailable")?;
            if !verify_release(acceptance, &key) {
                return Err("DS model has no valid independent release certificate".into());
            }
            let values = [
                acceptance.false_positive_budget,
                acceptance.false_positive_upper_bound,
                acceptance.recall_lower_bound,
                acceptance.baseline_recall_lower_bound,
                acceptance.brier,
                acceptance.baseline_brier,
            ];
            if active.training_status != "validated"
                || acceptance.parameter_sha256 != parameter_sha256(active)
                || !is_sha256(&acceptance.report_sha256)
                || !is_sha256(&acceptance.capability_manifest_sha256)
                || acceptance.holdout_negatives == 0
                || acceptance.holdout_positives == 0
                || values
                    .iter()
                    .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
                || acceptance.false_positive_budget <= 0.0
                || acceptance.false_positive_budget > 0.01
                || acceptance.decision_threshold != 0.40
                || acceptance.false_positive_upper_bound > acceptance.false_positive_budget
                || acceptance.recall_lower_bound < acceptance.baseline_recall_lower_bound
                || acceptance.brier > acceptance.baseline_brier
                || !acceptance.review_cost.is_finite()
                || !acceptance.baseline_review_cost.is_finite()
                || acceptance.review_cost < 0.0
                || acceptance.review_cost > acceptance.baseline_review_cost
                || acceptance.baseline_passing_case_ids.is_empty()
                || !acceptance
                    .baseline_passing_case_ids
                    .is_subset(&acceptance.candidate_passing_case_ids)
                || active.calibration.is_none()
            {
                return Err("DS activation acceptance gates failed".into());
            }
        }
        Ok(())
    }
}

static RUNTIME: OnceLock<RwLock<Arc<LearningState>>> = OnceLock::new();

pub fn runtime_state() -> Arc<LearningState> {
    RUNTIME
        .get_or_init(|| RwLock::new(Arc::new(LearningState::default())))
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub async fn reload_from_db(db: &VigilDb) -> anyhow::Result<()> {
    let raw = db.get_config(STATE_KEY).await?;
    let state: LearningState = match raw {
        Some(raw) => serde_json::from_str(&raw)?,
        None => LearningState::default(),
    };
    state.validate().map_err(anyhow::Error::msg)?;
    let mut runtime = RUNTIME
        .get_or_init(|| RwLock::new(Arc::new(LearningState::default())))
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if state.revision >= runtime.revision {
        *runtime = Arc::new(state);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Prediction {
    pub bpa: Bpa,
    pub probability: f64,
    pub calibrated: Option<f64>,
    pub learned_items: u32,
    pub fallback_items: u32,
    pub dependency_groups: u32,
}

fn sigmoid(value: f64) -> f64 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let e = value.exp();
        e / (1.0 + e)
    }
}

fn valid_item(item: &DsLearningEvidence) -> bool {
    item.source_id
        .split_once(':')
        .is_some_and(|(module, category)| !module.trim().is_empty() && !category.trim().is_empty())
        && item.source_id.len() <= 256
        && !item.cluster.trim().is_empty()
        && item.cluster.len() <= 256
        && item
            .causal_key
            .as_ref()
            .is_none_or(|k| !k.trim().is_empty() && k.len() <= 8192)
        && [
            item.raw_score,
            item.confidence,
            item.legacy_mass,
            item.confirmed_anchor_mass,
        ]
        .iter()
        .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
        && item.confirmed_anchor_mass <= item.legacy_mass
}

fn admitted(item: &DsLearningEvidence) -> bool {
    item.raw_score > 0.0 && item.confidence > 0.0 && (item.item_scored || item.legacy_mass > 0.0)
}

fn item_mass(item: &DsLearningEvidence, model: &DsModelParameters) -> (f64, bool) {
    if !admitted(item) {
        return (0.0, false);
    }
    if item.item_scored
        && let Some(p) = model.sources.get(&item.source_id)
    {
        // 1-exp(-softplus(z)) == sigmoid(z), computed stably.
        (
            p.reliability * item.confidence * sigmoid(p.slope * item.raw_score + p.intercept),
            true,
        )
    } else {
        (item.legacy_mass, false)
    }
}

fn root(parents: &[usize], mut i: usize) -> usize {
    while parents[i] != i {
        i = parents[i];
    }
    i
}

pub fn predict(
    items: &[DsLearningEvidence],
    model: &DsModelParameters,
) -> Result<Prediction, String> {
    model.validate()?;
    if items.len() > MAX_ITEMS || items.iter().any(|item| !valid_item(item)) {
        return Err("Invalid or excessive DS evidence items".into());
    }
    let eligible: Vec<_> = items.iter().filter(|i| admitted(i)).collect();
    let mut parents: Vec<_> = (0..eligible.len()).collect();
    let mut by_source = BTreeMap::new();
    let mut by_cause = BTreeMap::new();
    // Source dependence is conservative, explicit and independent of the
    // current learned weights. Different URLs/hosts do not establish independence.
    for (i, item) in eligible.iter().enumerate() {
        if let Some(key) = &item.causal_key {
            for prior in [
                by_source.insert(item.source_id.as_str(), i),
                by_cause.insert(key.as_str(), i),
            ]
            .into_iter()
            .flatten()
            {
                let left = root(&parents, i);
                let right = root(&parents, prior);
                parents[left] = right;
            }
        }
    }
    let mut groups: BTreeMap<usize, f64> = BTreeMap::new();
    let mut unbound: f64 = 0.0;
    let (mut learned_items, mut fallback_items) = (0, 0);
    for (i, item) in eligible.iter().enumerate() {
        let (mass, learned) = item_mass(item, model);
        if learned {
            learned_items += 1;
        } else {
            fallback_items += 1;
        }
        if item.causal_key.is_none() {
            unbound = unbound.max(mass);
        } else {
            let entry = groups.entry(root(&parents, i)).or_default();
            *entry = entry.max(mass);
        }
    }
    let bound = 1.0 - groups.values().map(|b| 1.0 - b).product::<f64>();
    // N-ary Yager on one-sided sources is noisy-OR. Unknown overlap is a
    // single residual, not another independent vote: final support=max(S,F).
    let belief = bound.max(unbound);
    let probability = belief + model.base_rate * (1.0 - belief);
    let calibrated = model.calibration.as_ref().map(|c| {
        let p = probability.clamp(1e-12, 1.0 - 1e-12);
        sigmoid(c.slope * (p / (1.0 - p)).ln() + c.intercept)
    });
    Ok(Prediction {
        bpa: Bpa::new(belief, 0.0, 1.0 - belief),
        probability,
        calibrated,
        learned_items,
        fallback_items,
        dependency_groups: groups.len() as u32 + u32::from(unbound > bound),
    })
}

#[derive(Clone)]
struct TrainingCase {
    items: Vec<DsLearningEvidence>,
    label: f64,
}

fn loss(cases: &[TrainingCase], model: &DsModelParameters, initial: &DsModelParameters) -> f64 {
    let error = cases
        .iter()
        .map(|case| {
            let p = predict(&case.items, model)
                .expect("validated training evidence")
                .probability;
            (p - case.label).powi(2)
        })
        .sum::<f64>()
        / cases.len().max(1) as f64;
    let shrinkage = model
        .sources
        .iter()
        .map(|(id, p)| {
            let initial = &initial.sources[id];
            (p.slope - initial.slope).powi(2)
                + (p.intercept - initial.intercept).powi(2)
                + (p.reliability - initial.reliability).powi(2)
        })
        .sum::<f64>()
        / model.sources.len().max(1) as f64;
    error + 0.01 * shrinkage
}

fn fit_candidate(
    cases: &[TrainingCase],
    prior: Option<&DsModelParameters>,
) -> Option<DsModelParameters> {
    let mut seeds: BTreeMap<String, Vec<(f64, f64)>> = BTreeMap::new();
    for case in cases {
        for i in &case.items {
            if i.item_scored && admitted(i) {
                seeds.entry(i.source_id.clone()).or_default().push((
                    i.raw_score,
                    (i.legacy_mass / i.confidence).clamp(0.001, 0.999),
                ));
            }
        }
    }
    if seeds.is_empty() {
        return None;
    }
    let mut sources = prior.map(|p| p.sources.clone()).unwrap_or_default();
    let learned_sources: Vec<_> = seeds.keys().take(64).cloned().collect();
    for (id, values) in seeds.into_iter().take(64) {
        if sources.contains_key(&id) || sources.len() >= 512 {
            continue;
        }
        let mean_score = values.iter().map(|v| v.0).sum::<f64>() / values.len() as f64;
        let mass = values.iter().map(|v| v.1).sum::<f64>() / values.len() as f64;
        let reliability = 0.95_f64.max(mass);
        let q = (mass / reliability).clamp(0.001, 0.999);
        sources.insert(
            id,
            DsSourceParameters {
                slope: 1.0,
                intercept: ((q / (1.0 - q)).ln() - mean_score).clamp(-16.0, 16.0),
                reliability,
            },
        );
    }
    let mut model = DsModelParameters {
        schema_version: 1,
        parameter_version: "fitting".into(),
        training_status: "candidate".into(),
        sources,
        base_rate: prior.map_or(0.0, |p| p.base_rate),
        calibration: None,
        training_sample_count: cases.len() as u64,
    };
    let initial = model.clone();
    let keys: Vec<_> = learned_sources
        .into_iter()
        .filter(|id| model.sources.contains_key(id))
        .collect();
    let mut best = loss(cases, &model, &initial);
    // Deterministic bounded coordinate search. Refit from the deduplicated
    // feedback ledger rather than applying the same click repeatedly as SGD.
    for step in [0.25, 0.10] {
        for key in &keys {
            for dimension in 0..3 {
                let before = model.sources[key].clone();
                let mut winner = before.clone();
                for direction in [-1.0, 1.0] {
                    let p = model.sources.get_mut(key).expect("known source");
                    *p = before.clone();
                    match dimension {
                        0 => p.slope = (p.slope + direction * step).clamp(0.0, 16.0),
                        1 => p.intercept = (p.intercept + direction * step).clamp(-16.0, 16.0),
                        _ => p.reliability = (p.reliability + direction * step).clamp(0.0, 1.0),
                    }
                    let value = loss(cases, &model, &initial);
                    if value < best - 1e-12 {
                        best = value;
                        winner = model.sources[key].clone();
                    }
                }
                model.sources.insert(key.clone(), winner);
            }
        }
    }
    model.parameter_version = format!("feedback-{}", &parameter_sha256(&model)[..16]);
    Some(model)
}

/// Refit a shadow candidate when new authorized human feedback arrives.
/// CAS prevents overlapping API replicas from overwriting a newer model state.
pub async fn refresh_candidate(db: &VigilDb) -> anyhow::Result<()> {
    static FIT_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    // Queue bounded feedback requests behind one learner per process. Every job
    // reads the newest ledger after locking; unchanged batches are no-ops.
    let _guard = FIT_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    for _ in 0..3 {
        let prior = db.get_config(STATE_KEY).await?;
        let mut state: LearningState = prior
            .as_ref()
            .map(|raw| serde_json::from_str(raw))
            .transpose()?
            .unwrap_or_default();
        state.validate().map_err(anyhow::Error::msg)?;
        let data = db.ds_learning_samples(MAX_TRAIN_CASES as u32).await?;
        let rows = data["cases"].as_array().cloned().unwrap_or_default();
        let mut cases = Vec::new();
        let mut by_hash: BTreeMap<String, Vec<TrainingCase>> = BTreeMap::new();
        let mut levels_by_hash: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for row in &rows {
            if row["label_source"] != "analyst_feedback"
                || row["split"] != "train"
                || row["data_origin"] != "analyst_feedback"
            {
                continue;
            }
            let Some(label) = row["label"].as_u64().filter(|v| *v <= 1) else {
                continue;
            };
            let Some(hash) = row["content_sha256"].as_str().filter(|h| is_sha256(h)) else {
                continue;
            };
            let Ok(items) = serde_json::from_value::<Vec<DsLearningEvidence>>(row["items"].clone())
            else {
                continue;
            };
            if items.len() > MAX_ITEMS
                || items.iter().any(|i| !valid_item(i))
                || !items.iter().any(|i| i.item_scored && admitted(i))
            {
                continue;
            }
            let Some(level) = row["corrected_threat_level"].as_str() else {
                continue;
            };
            levels_by_hash
                .entry(hash.into())
                .or_default()
                .insert(level.into());
            by_hash.entry(hash.into()).or_default().push(TrainingCase {
                items,
                label: label as f64,
            });
        }
        let mut dataset = Vec::new();
        for (hash, same_content) in &by_hash {
            if levels_by_hash[hash].len() == 1
                && same_content
                    .iter()
                    .all(|case| case.label == same_content[0].label)
            {
                cases.push(same_content[0].clone());
                dataset.push(serde_json::json!({"content_sha256":hash,"label":same_content[0].label,"items":same_content[0].items}));
            }
        }
        // IDs, timestamps and repeat clicks are audit metadata, not new evidence.
        let dataset_hash = hex::encode(Sha256::digest(serde_json::to_vec(&dataset)?));
        let feedback_count = data["session_count"].as_u64().unwrap_or(rows.len() as u64);
        let same_dataset = state.training_dataset_sha256.as_ref() == Some(&dataset_hash);
        if same_dataset && state.feedback_count == feedback_count {
            return Ok(());
        }
        let candidate = if same_dataset {
            state.candidate.clone()
        } else {
            let fitting = cases.clone();
            // Rebuild unvalidated candidates from accepted parameters, so a
            // withdrawn/conflicting label cannot survive as an inherited weight.
            let initial = state.active.clone();
            tokio::task::spawn_blocking(move || fit_candidate(&fitting, initial.as_ref())).await?
        };
        state.revision += 1;
        state.feedback_count = feedback_count;
        state.sample_window_limit = MAX_TRAIN_CASES as u32;
        state.eligible_count = cases.len() as u64;
        state.excluded_count = state.feedback_count.saturating_sub(state.eligible_count);
        state.validation_status = if candidate.is_some() {
            "candidate_unvalidated"
        } else {
            "insufficient_evidence"
        }
        .into();
        state.candidate = candidate;
        state.pending_gates = vec![
            "independent_calibration".into(),
            "sealed_holdout".into(),
            "capability_preservation".into(),
        ];
        if !cases.iter().any(|c| c.label == 0.0) || !cases.iter().any(|c| c.label == 1.0) {
            state.pending_gates.push("both_classes".into());
        }
        state.updated_at = chrono::Utc::now().to_rfc3339();
        state.training_dataset_sha256 = Some(dataset_hash);
        let json = serde_json::to_string(&state)?;
        if db
            .compare_and_set_config(STATE_KEY, prior.as_deref(), &json)
            .await?
        {
            reload_from_db(db).await?;
            return Ok(());
        }
    }
    anyhow::bail!("DS candidate refresh raced with another update; retry on next feedback")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> DsModelParameters {
        DsModelParameters {
            schema_version: 1,
            parameter_version: "test".into(),
            training_status: "candidate".into(),
            sources: BTreeMap::from([(
                "a:x".into(),
                DsSourceParameters {
                    slope: 2.0,
                    intercept: -1.0,
                    reliability: 0.8,
                },
            )]),
            base_rate: 0.02,
            calibration: None,
            training_sample_count: 2,
        }
    }
    fn item(source: &str, key: Option<&str>, score: f64) -> DsLearningEvidence {
        DsLearningEvidence {
            source_id: source.into(),
            causal_key: key.map(str::to_owned),
            cluster: "test".into(),
            raw_score: score,
            confidence: 0.9,
            item_scored: true,
            legacy_mass: 0.3,
            confirmed_anchor_mass: 0.0,
        }
    }
    #[test]
    fn empty_and_missing_are_vacuous_not_normal() {
        let p = predict(&[], &model()).unwrap();
        assert_eq!(p.bpa.b, 0.0);
        assert_eq!(p.bpa.d, 0.0);
        assert_eq!(p.bpa.u, 1.0);
        assert_eq!(p.probability, 0.02);
        assert!(p.calibrated.is_none());
    }
    #[test]
    fn softplus_mapping_and_probability_are_separate() {
        let p = predict(&[item("a:x", Some("url:1"), 0.5)], &model()).unwrap();
        assert!((p.bpa.b - 0.36).abs() < 1e-12);
        assert!((p.probability - 0.3728).abs() < 1e-12);
    }
    #[test]
    fn duplicates_and_same_source_do_not_accumulate() {
        let one = item("a:x", Some("url:1"), 0.5);
        let other = item("a:x", Some("url:2"), 0.5);
        let p = predict(&[one.clone()], &model()).unwrap();
        let q = predict(&[one.clone(), one, other], &model()).unwrap();
        assert_eq!(p.bpa.b, q.bpa.b);
        assert_eq!(q.dependency_groups, 1);
    }
    #[test]
    fn source_and_cause_dependencies_are_transitive() {
        let items = [
            item("a:x", Some("x"), 0.5),
            item("a:x", Some("y"), 0.5),
            item("b:x", Some("y"), 0.5),
        ];
        let p = predict(&items, &model()).unwrap();
        assert_eq!(p.dependency_groups, 1);
        assert!((p.bpa.b - 0.36).abs() < 1e-12);
    }
    #[test]
    fn zero_reliability_cannot_split_dependency_graph() {
        let mut m = model();
        m.sources.get_mut("a:x").unwrap().reliability = 0.0;
        let items = [
            item("b:x", Some("x"), 0.5),
            item("a:x", Some("x"), 0.5),
            item("a:x", Some("y"), 0.5),
            item("c:x", Some("y"), 0.5),
        ];
        let p = predict(&items, &m).unwrap();
        assert_eq!(p.dependency_groups, 1);
        assert!((p.bpa.b - 0.3).abs() < 1e-12);
    }
    #[test]
    fn unbound_does_not_invent_independence() {
        let items = [item("a:x", Some("x"), 0.5), item("b:x", None, 0.5)];
        let p = predict(&items, &model()).unwrap();
        assert!((p.bpa.b - 0.36).abs() < 1e-12);
    }
    #[test]
    fn raw_zero_never_uses_intercept_or_legacy_mass() {
        let p = predict(&[item("a:x", Some("x"), 0.0)], &model()).unwrap();
        assert_eq!(p.bpa.b, 0.0);
    }
    #[test]
    fn bad_parameters_and_bad_items_are_rejected() {
        let mut m = model();
        m.sources.get_mut("a:x").unwrap().slope = -1.0;
        assert!(predict(&[], &m).is_err());
        let mut i = item("a:x", None, 0.5);
        i.confidence = f64::NAN;
        assert!(predict(&[i], &model()).is_err());
    }
    #[test]
    fn learning_uses_label_and_leaves_activation_unvalidated() {
        let i = item("a:x", Some("x"), 0.5);
        let clean = fit_candidate(
            &[TrainingCase {
                items: vec![i.clone()],
                label: 0.0,
            }],
            None,
        )
        .unwrap();
        let bad = fit_candidate(
            &[TrainingCase {
                items: vec![i.clone()],
                label: 1.0,
            }],
            None,
        )
        .unwrap();
        assert!(predict(&[i.clone()], &clean).unwrap().bpa.b < predict(&[i], &bad).unwrap().bpa.b);
        assert_eq!(clean.training_status, "candidate");
        assert!(clean.calibration.is_none());
    }
    #[test]
    fn active_model_without_acceptance_is_rejected() {
        let state = LearningState {
            active: Some(model()),
            ..Default::default()
        };
        assert!(state.validate().is_err());
    }
    #[test]
    fn python_rust_release_signature_parity() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ds-release-parity.json"
        ))
        .unwrap();
        let acceptance: Acceptance = serde_json::from_value(fixture["acceptance"].clone()).unwrap();
        let key = fixture["test_key_utf8"].as_str().unwrap().as_bytes();
        assert!(verify_release(&acceptance, key));
        assert!(!verify_release(&acceptance, &key[..31]));
        assert!(!verify_release(&acceptance, &[0; 32]));
        let mut changed = acceptance.clone();
        changed.report_sha256 = "d".repeat(64);
        assert!(!verify_release(&changed, key));
        changed = acceptance;
        changed.release_signature = fixture["invalid_trailing_newline_hmac_sha256"]
            .as_str()
            .unwrap()
            .into();
        assert!(!verify_release(&changed, key));
    }
    #[test]
    fn python_rust_inference_parity() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ds-learning-parity.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let items: Vec<DsLearningEvidence> =
                serde_json::from_value(case["items"].clone()).unwrap();
            let model: DsModelParameters = serde_json::from_value(case["model"].clone()).unwrap();
            let output = predict(&items, &model).unwrap();
            for (key, actual) in [
                ("belief", output.bpa.b),
                ("disbelief", output.bpa.d),
                ("uncertainty", output.bpa.u),
                ("probability_uncalibrated", output.probability),
                (
                    "probability",
                    output.calibrated.unwrap_or(output.probability),
                ),
            ] {
                assert!(
                    (actual - case["expected"][key].as_f64().unwrap()).abs() < 1e-12,
                    "{} {key}",
                    case["id"]
                );
            }
            assert_eq!(
                output.learned_items,
                case["expected"]["learned_items"].as_u64().unwrap() as u32
            );
            assert_eq!(
                output.fallback_items,
                case["expected"]["fallback_items"].as_u64().unwrap() as u32
            );
            assert_eq!(
                output.dependency_groups,
                case["expected"]["dependency_groups"].as_u64().unwrap() as u32
            );
            assert_eq!(
                parameter_sha256(&model),
                case["parameter_content_sha256"].as_str().unwrap()
            );
        }
    }
}
