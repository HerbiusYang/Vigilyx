//! Offline trainer for the semantic text classifier (`src/semantic/classifier.rs`).
//!
//! Inputs are the train and dev files written by
//! scripts/prepare_semantic_classifier_split.py; the test split is never read.
//! Features come from `SemanticScanModule` itself (feature export), so training
//! and inference share one extraction path. Run explicitly on the remote
//! builder with VIGILYX_CLASSIFIER_TRAIN, VIGILYX_CLASSIFIER_DEV and a fresh
//! VIGILYX_CLASSIFIER_OUTPUT directory.
//!
//! Optional settings:
//! * VIGILYX_CLASSIFIER_VARIANTS: JSON array of training variants (see
//!   `Variant`); features are extracted once and every variant writes its own
//!   model and report under OUTPUT/<name>. Default: one variant `default`.
//! * VIGILYX_CLASSIFIER_ALLOW_CHINESE=1: accept Chinese rows in train/dev
//!   (split v3 and later); otherwise Chinese text is test-only.
//! * VIGILYX_CLASSIFIER_EVAL: an extra labelled JSONL that is only scored with
//!   the module decision rule and reported; it never affects training,
//!   hyperparameters or thresholds.
//!
//! Each model part is trained and thresholded on the examples its route
//! actually scores: the lexical part on text below the CJK route ratio, the
//! cross-lingual part on CJK-dominant text (optionally trained on all text).

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::RegexSet;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::SecurityModule;
use vigilyx_engine::semantic::{
    SemanticScanModule, TEXT_CLASSIFIER_FEATURE_SPEC, TEXT_CLASSIFIER_LEXICON_SOURCES,
    text_classifier_feature_index,
};
use vigilyx_parser::MimeParser;

const HASH_BITS: u32 = 22;
const CJK_ROUTE_RATIO: f64 = 0.3;
const MIN_ACTIVE_FEATURES: usize = 3;
/// Training length floor, written to the model as `min_text_units`. Shorter
/// text is left out of route training and dev metrics; the module still
/// scores it and marks the outcome `below_training_length`.
const MIN_TEXT_UNITS: usize = 30;
const DEFAULT_TARGET_FPR: f64 = 0.01;
/// Configurations within this dev balanced-accuracy margin of the best are
/// treated as equivalent; the sparsest one wins.
const SELECTION_TOLERANCE: f64 = 0.0025;
const SYNTHETIC_DATASET: &str = "vigilyx-synthetic-benign";
const CROSS_LINGUAL_FAMILIES: [&str; 2] = ["concept", "structure"];

#[derive(Deserialize)]
struct Case {
    content_id: String,
    subject: Option<String>,
    body: String,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
struct Source {
    dataset: String,
    language: String,
    label: String,
    #[serde(default)]
    category: String,
}

/// One training configuration. Feature filters and sign constraints are
/// regular expressions over exported feature names; a hashed index whose
/// names fall under conflicting rules is excluded.
#[derive(Deserialize, Clone)]
struct Variant {
    name: String,
    #[serde(default = "default_lexical_families")]
    lexical_families: Vec<String>,
    #[serde(default = "default_true")]
    cross_lingual: bool,
    /// Train the cross-lingual part on CJK-routed text only.
    #[serde(default)]
    cross_lingual_cjk_only: bool,
    /// Sample-weight multiplier for synthetic benign mail; 0 drops it.
    #[serde(default = "default_one")]
    synthetic_weight: f64,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    nonneg: Vec<String>,
    #[serde(default)]
    nonpos: Vec<String>,
    /// Overrides VIGILYX_CLASSIFIER_TARGET_FPR for this variant.
    #[serde(default)]
    target_fpr: Option<f64>,
}

fn default_lexical_families() -> Vec<String> {
    ["lexical", "concept", "structure"]
        .map(str::to_string)
        .to_vec()
}

fn default_true() -> bool {
    true
}

fn default_one() -> f64 {
    1.0
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Lexical,
    Concept,
    Structure,
}

impl Family {
    fn parse(name: &str) -> Self {
        match name {
            "lexical" => Self::Lexical,
            "concept" => Self::Concept,
            "structure" => Self::Structure,
            other => panic!("unknown family {other}"),
        }
    }
}

struct Example {
    positive: bool,
    synthetic: bool,
    dataset: String,
    language: String,
    category: String,
    cjk: bool,
    text_units: usize,
    features: Vec<(u32, f32, Family)>,
}

impl Example {
    fn view(&self, families: &[Family]) -> Vec<(u32, f32)> {
        self.features
            .iter()
            .filter(|(_, _, family)| families.contains(family))
            .map(|(index, value, _)| (*index, *value))
            .collect()
    }

    fn stratum(&self) -> String {
        format!(
            "{}/{}/{}",
            self.dataset,
            self.language,
            if self.positive { "malicious" } else { "benign" }
        )
    }
}

fn read_cases(path: &Path) -> (Vec<Case>, String) {
    let bytes = std::fs::read(path).expect("read split");
    let digest = hex::encode(Sha256::digest(&bytes));
    let cases = BufReader::new(File::open(path).expect("open split"))
        .lines()
        .map(|line| line.expect("read split line"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(&line).expect("valid split record"))
        .collect();
    (cases, digest)
}

async fn extract(
    module: Arc<SemanticScanModule>,
    cases: Vec<Case>,
    allow_chinese: bool,
    names: &mut HashMap<u32, Vec<String>>,
) -> Vec<Example> {
    let mut tasks = tokio::task::JoinSet::new();
    for (position, case) in cases.into_iter().enumerate() {
        let module = Arc::clone(&module);
        tasks.spawn(async move {
            let labels = case
                .sources
                .iter()
                .map(|source| source.label.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(labels.len(), 1, "conflicting labels {}", case.content_id);
            let positive = match *labels.iter().next().unwrap() {
                "malicious" => true,
                "benign" => false,
                other => panic!("train/dev/eval must not contain label {other}"),
            };
            assert!(
                allow_chinese
                    || case.sources.iter().all(|source| {
                        !matches!(source.language.as_str(), "Chinese" | "zh-cn" | "zh")
                    }),
                "Chinese text is test-only unless VIGILYX_CLASSIFIER_ALLOW_CHINESE=1"
            );
            // Same transport wrapper as semantic_external_harness.
            let raw = format!(
                "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
                case.body
            );
            let mut session = EmailSession::new(
                Protocol::Smtp,
                "203.0.113.1".into(),
                40000,
                "192.0.2.1".into(),
                25,
            );
            session.content = MimeParser::new()
                .parse(raw.as_bytes())
                .expect("parse text transport wrapper");
            session.subject = case.subject.clone();
            let result = module
                .analyze(&SecurityContext::new(Arc::new(session)))
                .await
                .expect("semantic module result");
            let exported = result.details["semantic_text_classifier_features"].clone();
            let outcome = result.details["semantic_text_classifier"].clone();
            (position, positive, case.sources, exported, outcome)
        });
    }
    let mut rows = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        rows.push(joined.expect("extraction task"));
    }
    rows.sort_by_key(|row| row.0);
    rows.into_iter()
        .map(|(_, positive, sources, exported, outcome)| {
            let mut features = Vec::new();
            for feature in exported.as_array().map(Vec::as_slice).unwrap_or_default() {
                let name = feature["name"].as_str().expect("exported feature name");
                let index = u32::try_from(feature["index"].as_u64().unwrap()).unwrap();
                assert_eq!(
                    text_classifier_feature_index(name, HASH_BITS),
                    index,
                    "trainer and module disagree on the hash of {name}"
                );
                let value = feature["value"].as_f64().unwrap() as f32;
                features.push((
                    index,
                    value,
                    Family::parse(feature["family"].as_str().unwrap()),
                ));
                let known = names.entry(index).or_default();
                if !known.iter().any(|known| known == name) {
                    known.push(name.to_string());
                }
            }
            Example {
                positive,
                synthetic: sources[0].dataset == SYNTHETIC_DATASET,
                dataset: sources[0].dataset.clone(),
                language: sources[0].language.clone(),
                category: sources[0].category.clone(),
                cjk: outcome["cjk_ratio"].as_f64().expect("exported CJK ratio") >= CJK_ROUTE_RATIO,
                text_units: outcome["text_units"].as_u64().expect("exported text units") as usize,
                features,
            }
        })
        .collect()
}

/// Per-coordinate constraint applied to the FTRL closed-form weight.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Constraint {
    Free,
    NonNegative,
    NonPositive,
    Zero,
}

fn constraints(variant: &Variant, names: &HashMap<u32, Vec<String>>) -> (Vec<Constraint>, Value) {
    let set = |patterns: &[String]| RegexSet::new(patterns).expect("valid variant pattern");
    let (exclude, nonneg, nonpos) = (
        set(&variant.exclude),
        set(&variant.nonneg),
        set(&variant.nonpos),
    );
    let mut result = vec![Constraint::Free; (1usize << HASH_BITS) + 1];
    let mut counts = BTreeMap::<&str, usize>::new();
    for (index, names) in names {
        let matches = |set: &RegexSet| names.iter().any(|name| set.is_match(name));
        let constraint = match (matches(&exclude), matches(&nonneg), matches(&nonpos)) {
            (false, false, false) => continue,
            (true, _, _) | (false, true, true) => Constraint::Zero,
            (false, true, false) => Constraint::NonNegative,
            (false, false, true) => Constraint::NonPositive,
        };
        *counts
            .entry(match constraint {
                Constraint::Zero => "zero",
                Constraint::NonNegative => "nonnegative",
                Constraint::NonPositive => "nonpositive",
                Constraint::Free => unreachable!(),
            })
            .or_default() += 1;
        result[*index as usize] = constraint;
    }
    (result, json!(counts))
}

#[derive(Clone, Copy, Debug)]
struct Params {
    alpha: f64,
    l1: f64,
    l2: f64,
    epochs: usize,
}

/// FTRL-Proximal logistic regression with per-coordinate sign constraints;
/// the bias is the last coordinate and is neither L1-regularized nor
/// constrained. For one coordinate the constrained minimizer of the FTRL
/// objective is the unconstrained one clipped to the allowed half-line.
struct Ftrl<'c> {
    params: Params,
    constraints: &'c [Constraint],
    z: Vec<f64>,
    n: Vec<f64>,
}

impl<'c> Ftrl<'c> {
    const BETA: f64 = 1.0;

    fn new(params: Params, constraints: &'c [Constraint]) -> Self {
        let dimension = (1usize << HASH_BITS) + 1;
        Self {
            params,
            constraints,
            z: vec![0.0; dimension],
            n: vec![0.0; dimension],
        }
    }

    fn bias_index(&self) -> usize {
        self.z.len() - 1
    }

    fn weight(&self, index: usize) -> f64 {
        let bias = index == self.bias_index();
        let l1 = if bias { 0.0 } else { self.params.l1 };
        let z = self.z[index];
        if z.abs() <= l1 {
            return 0.0;
        }
        let weight = -(z - z.signum() * l1)
            / ((Self::BETA + self.n[index].sqrt()) / self.params.alpha + self.params.l2);
        if bias {
            return weight;
        }
        match self.constraints[index] {
            Constraint::Free => weight,
            Constraint::NonNegative => weight.max(0.0),
            Constraint::NonPositive => weight.min(0.0),
            Constraint::Zero => 0.0,
        }
    }

    fn margin(&self, features: &[(u32, f32)]) -> f64 {
        self.weight(self.bias_index())
            + features
                .iter()
                .map(|(index, value)| self.weight(*index as usize) * f64::from(*value))
                .sum::<f64>()
    }

    fn update(&mut self, features: &[(u32, f32)], positive: bool, sample_weight: f64) {
        let probability = sigmoid(self.margin(features));
        let gradient = (probability - f64::from(u8::from(positive))) * sample_weight;
        let bias = self.bias_index();
        for (index, value) in features
            .iter()
            .map(|(index, value)| (*index as usize, f64::from(*value)))
            .chain(std::iter::once((bias, 1.0)))
        {
            let g = gradient * value;
            let weight = self.weight(index);
            let sigma = ((self.n[index] + g * g).sqrt() - self.n[index].sqrt()) / self.params.alpha;
            self.z[index] += g - sigma * weight;
            self.n[index] += g * g;
        }
    }

    fn weights(&self) -> (f64, HashMap<u32, f32>) {
        let mut weights = HashMap::new();
        for index in 0..self.bias_index() {
            let weight = self.weight(index);
            if weight != 0.0 {
                weights.insert(index as u32, weight as f32);
            }
        }
        (self.weight(self.bias_index()), weights)
    }
}

fn sigmoid(margin: f64) -> f64 {
    1.0 / (1.0 + (-margin).exp())
}

/// A route's training or evaluation rows: label, sample weight and features.
struct RouteSet<'e> {
    examples: Vec<&'e Example>,
    weights: Vec<f64>,
    views: Vec<Vec<(u32, f32)>>,
}

impl<'e> RouteSet<'e> {
    /// Class-balanced weights; synthetic rows are scaled before balancing.
    fn new(
        examples: impl Iterator<Item = &'e Example>,
        families: &[Family],
        synthetic_weight: f64,
    ) -> Self {
        let examples = examples
            .filter(|example| !(example.synthetic && synthetic_weight == 0.0))
            .collect::<Vec<_>>();
        let raw = examples
            .iter()
            .map(|example| {
                if example.synthetic {
                    synthetic_weight
                } else {
                    1.0
                }
            })
            .collect::<Vec<_>>();
        let class_total = |positive: bool| {
            examples
                .iter()
                .zip(&raw)
                .filter(|(example, _)| example.positive == positive)
                .map(|(_, weight)| weight)
                .sum::<f64>()
        };
        let (positive_total, negative_total) = (class_total(true), class_total(false));
        let total = positive_total + negative_total;
        let weights = examples
            .iter()
            .zip(&raw)
            .map(|(example, weight)| {
                let class = if example.positive {
                    positive_total
                } else {
                    negative_total
                };
                weight * total / (2.0 * class.max(f64::MIN_POSITIVE))
            })
            .collect();
        let views = examples
            .iter()
            .map(|example| example.view(families))
            .collect();
        Self {
            examples,
            weights,
            views,
        }
    }
}

fn train(
    set: &RouteSet<'_>,
    params: Params,
    constraints: &[Constraint],
) -> (f64, HashMap<u32, f32>) {
    let mut model = Ftrl::new(params, constraints);
    let mut order = (0..set.examples.len()).collect::<Vec<_>>();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..params.epochs {
        // Deterministic Fisher-Yates with xorshift64.
        for position in (1..order.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            order.swap(position, (state % (position as u64 + 1)) as usize);
        }
        for &position in &order {
            model.update(
                &set.views[position],
                set.examples[position].positive,
                set.weights[position],
            );
        }
    }
    model.weights()
}

/// Probability and whether the example is eligible to fire: enough active
/// (nonzero-weight) features whose own contribution, without the intercept,
/// is positive. Mirrors `classify` in src/semantic/classifier.rs.
fn score(bias: f64, weights: &HashMap<u32, f32>, view: &[(u32, f32)]) -> (f64, bool) {
    let mut evidence = 0.0;
    let mut active = 0;
    for (index, value) in view {
        if let Some(weight) = weights.get(index) {
            evidence += f64::from(*weight) * f64::from(*value);
            active += 1;
        }
    }
    (
        sigmoid(bias + evidence),
        active >= MIN_ACTIVE_FEATURES && evidence > 0.0,
    )
}

/// Lowest threshold whose benign false-positive count stays within the target.
fn threshold_for(scored: &[(bool, f64, bool)], target_fpr: f64) -> f64 {
    let mut benign = scored
        .iter()
        .filter(|(positive, _, eligible)| !positive && *eligible)
        .map(|(_, probability, _)| *probability)
        .collect::<Vec<_>>();
    let benign_total = scored.iter().filter(|(positive, _, _)| !positive).count();
    benign.sort_by(|left, right| right.total_cmp(left));
    let allowed = (target_fpr * benign_total as f64).floor() as usize;
    benign
        .get(allowed)
        .map_or(0.5, |boundary| (boundary + 1e-9).min(0.999_999))
        .max(1e-6)
}

fn metrics(examples: &[&Example], scored: &[(bool, f64, bool)], threshold: f64) -> Value {
    let mut strata = BTreeMap::<String, [usize; 2]>::new();
    let (mut tp, mut fp, mut positives, mut negatives) = (0usize, 0usize, 0usize, 0usize);
    for (example, (positive, probability, eligible)) in examples.iter().zip(scored) {
        let fired = *eligible && *probability >= threshold;
        let entry = strata.entry(example.stratum()).or_default();
        entry[0] += 1;
        entry[1] += usize::from(fired);
        if *positive {
            positives += 1;
            tp += usize::from(fired);
        } else {
            negatives += 1;
            fp += usize::from(fired);
        }
    }
    let recall = tp as f64 / positives.max(1) as f64;
    let fpr = fp as f64 / negatives.max(1) as f64;
    json!({
        "threshold": threshold, "tp": tp, "fp": fp, "positives": positives, "negatives": negatives,
        "recall": recall, "fpr": fpr, "balanced_accuracy": (recall + 1.0 - fpr) / 2.0,
        "strata_flagged": strata.into_iter()
            .map(|(key, [total, flagged])| (key, json!({"n": total, "flagged": flagged})))
            .collect::<serde_json::Map<_, _>>(),
    })
}

struct Fitted {
    params: Params,
    families: Vec<String>,
    bias: f64,
    weights: HashMap<u32, f32>,
    threshold: f64,
    dev: Value,
}

fn fit(
    train_set: &RouteSet<'_>,
    dev_set: &RouteSet<'_>,
    families: &[String],
    constraints: &[Constraint],
    target_fpr: f64,
    grid: &[Params],
) -> (Fitted, Vec<Value>) {
    let results = std::thread::scope(|scope| {
        grid.iter()
            .map(|params| {
                scope.spawn(move || {
                    let (bias, weights) = train(train_set, *params, constraints);
                    let scored = dev_set
                        .examples
                        .iter()
                        .zip(&dev_set.views)
                        .map(|(example, view)| {
                            let (probability, eligible) = score(bias, &weights, view);
                            (example.positive, probability, eligible)
                        })
                        .collect::<Vec<_>>();
                    let threshold = threshold_for(&scored, target_fpr);
                    let dev = metrics(&dev_set.examples, &scored, threshold);
                    Fitted {
                        params: *params,
                        families: families.to_vec(),
                        bias,
                        weights,
                        threshold,
                        dev,
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("training thread"))
            .collect::<Vec<_>>()
    });
    let summary = results
        .iter()
        .map(|fitted| {
            json!({
                "alpha": fitted.params.alpha, "l1": fitted.params.l1, "l2": fitted.params.l2,
                "epochs": fitted.params.epochs, "nonzero_weights": fitted.weights.len(),
                "dev_balanced_accuracy": fitted.dev["balanced_accuracy"],
                "dev_recall": fitted.dev["recall"], "dev_fpr": fitted.dev["fpr"],
            })
        })
        .collect();
    let accuracy = |fitted: &Fitted| fitted.dev["balanced_accuracy"].as_f64().unwrap();
    let best_accuracy = results.iter().map(accuracy).fold(f64::MIN, f64::max);
    let best = results
        .into_iter()
        .filter(|fitted| accuracy(fitted) >= best_accuracy - SELECTION_TOLERANCE)
        .min_by(|left, right| {
            left.weights
                .len()
                .cmp(&right.weights.len())
                .then(accuracy(right).total_cmp(&accuracy(left)))
        })
        .expect("non-empty grid");
    (best, summary)
}

fn model_part(fitted: &Fitted) -> Value {
    let mut weights = fitted.weights.iter().collect::<Vec<_>>();
    weights.sort_by_key(|(index, _)| **index);
    json!({
        "bias": fitted.bias,
        "threshold": fitted.threshold,
        "families": fitted.families,
        "weights": weights.into_iter().map(|(index, weight)| json!([index, weight])).collect::<Vec<_>>(),
    })
}

/// Probability that a malicious example outranks a benign one (ties count half).
fn auc(scored: &[(bool, f64)]) -> Option<f64> {
    let mut benign = scored
        .iter()
        .filter(|(positive, _)| !positive)
        .map(|(_, probability)| *probability)
        .collect::<Vec<_>>();
    benign.sort_by(f64::total_cmp);
    let malicious = scored
        .iter()
        .filter(|(positive, _)| *positive)
        .collect::<Vec<_>>();
    if benign.is_empty() || malicious.is_empty() {
        return None;
    }
    let wins = malicious
        .iter()
        .map(|(_, probability)| {
            let below = benign.partition_point(|value| value < probability);
            let tied = benign.partition_point(|value| value <= probability) - below;
            below as f64 + tied as f64 / 2.0
        })
        .sum::<f64>();
    Some(wins / (benign.len() * malicious.len()) as f64)
}

/// Recall at the threshold that admits the given share of eligible benign
/// rows; analysis of the ranking only, never used to set a threshold.
fn recall_at_fpr(scored: &[(bool, f64, bool)], fpr: f64) -> Option<f64> {
    let threshold = threshold_for(scored, fpr);
    let positives = scored.iter().filter(|(positive, _, _)| *positive).count();
    (positives > 0).then(|| {
        scored
            .iter()
            .filter(|(positive, probability, eligible)| {
                *positive && *eligible && *probability >= threshold
            })
            .count() as f64
            / positives as f64
    })
}

/// Coarse category for evaluation-only strata.
fn category_bucket(example: &Example) -> String {
    let category = example.category.as_str();
    if category.starts_with("legit_") {
        "legit_notice".to_string()
    } else if category.is_empty() {
        "uncategorized".to_string()
    } else {
        category.to_string()
    }
}

/// Apply the module decision rule (route, length floor, positive evidence,
/// threshold) to an evaluation set and report per route, label and category.
fn evaluate_module_rule(
    examples: &[Example],
    lexical: &Fitted,
    cross_lingual: Option<&Fitted>,
) -> Value {
    let lexical_families = lexical
        .families
        .iter()
        .map(|name| Family::parse(name))
        .collect::<Vec<_>>();
    let cross_families = CROSS_LINGUAL_FAMILIES.map(Family::parse);
    let mut counts = BTreeMap::<String, [usize; 3]>::new();
    let mut categories = BTreeMap::<String, [usize; 2]>::new();
    let mut by_route = BTreeMap::<&str, Vec<(bool, f64)>>::new();
    let mut eligible_by_route = BTreeMap::<&str, Vec<(bool, f64, bool)>>::new();
    let (mut fired_by_label, mut total_by_label) = ([0usize; 2], [0usize; 2]);
    for example in examples {
        let (route, fitted, families) = if example.cjk {
            ("cross_lingual", cross_lingual, &cross_families[..])
        } else {
            ("lexical", Some(lexical), &lexical_families[..])
        };
        let label = if example.positive {
            "malicious"
        } else {
            "benign"
        };
        let slot = usize::from(example.positive);
        total_by_label[slot] += 1;
        let entry = counts.entry(format!("{route}/{label}")).or_default();
        entry[0] += 1;
        let category = categories
            .entry(format!("{label}/{}", category_bucket(example)))
            .or_default();
        category[0] += 1;
        let Some(fitted) = fitted else { continue };
        if example.text_units < MIN_TEXT_UNITS {
            continue;
        }
        let (probability, eligible) = score(fitted.bias, &fitted.weights, &example.view(families));
        let fired = eligible && probability >= fitted.threshold;
        entry[1] += 1;
        entry[2] += usize::from(fired);
        category[1] += usize::from(fired);
        fired_by_label[slot] += usize::from(fired);
        by_route
            .entry(route)
            .or_default()
            .push((example.positive, probability));
        eligible_by_route
            .entry(route)
            .or_default()
            .push((example.positive, probability, eligible));
    }
    json!({
        "recall": fired_by_label[1] as f64 / total_by_label[1].max(1) as f64,
        "fpr": fired_by_label[0] as f64 / total_by_label[0].max(1) as f64,
        "counts": counts.into_iter()
            .map(|(key, [total, scored, fired])| (key, json!({"n": total, "scored": scored, "fired": fired})))
            .collect::<serde_json::Map<_, _>>(),
        "categories": categories.into_iter()
            .map(|(key, [total, fired])| (key, json!({"n": total, "fired": fired})))
            .collect::<serde_json::Map<_, _>>(),
        "auc_scored": by_route.into_iter()
            .map(|(route, scored)| (route.to_string(), json!(auc(&scored))))
            .collect::<serde_json::Map<_, _>>(),
        "scored_recall_at_fpr": eligible_by_route.into_iter()
            .map(|(route, scored)| (route.to_string(), json!({
                "0.02": recall_at_fpr(&scored, 0.02), "0.05": recall_at_fpr(&scored, 0.05),
                "0.10": recall_at_fpr(&scored, 0.10),
            })))
            .collect::<serde_json::Map<_, _>>(),
    })
}

fn top_features(fitted: &Fitted, names: &HashMap<u32, Vec<String>>, positive: bool) -> Vec<Value> {
    let mut weights = fitted
        .weights
        .iter()
        .filter(|(_, weight)| (**weight > 0.0) == positive)
        .collect::<Vec<_>>();
    weights.sort_by(|left, right| right.1.abs().total_cmp(&left.1.abs()));
    weights
        .into_iter()
        .take(40)
        .map(|(index, weight)| {
            json!([
                names
                    .get(index)
                    .map_or("<unseen>".to_string(), |names| names.join(" | ")),
                weight
            ])
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_variant(
    variant: &Variant,
    output: &Path,
    train_set: &[Example],
    dev_set: &[Example],
    eval_set: &[Example],
    names: &HashMap<u32, Vec<String>>,
    target_fpr: f64,
    grid: &[Params],
    shared: &Value,
) {
    let started = std::time::Instant::now();
    let target_fpr = variant.target_fpr.unwrap_or(target_fpr);
    let (constraints, constraint_counts) = constraints(variant, names);
    let lexical_families = variant
        .lexical_families
        .iter()
        .map(|name| Family::parse(name))
        .collect::<Vec<_>>();
    assert!(!lexical_families.is_empty(), "lexical part needs a family");
    let cross_families = CROSS_LINGUAL_FAMILIES.map(Family::parse);
    let scored_length = |example: &&Example| example.text_units >= MIN_TEXT_UNITS;

    let lexical_train = RouteSet::new(
        train_set
            .iter()
            .filter(|example| !example.cjk)
            .filter(scored_length),
        &lexical_families,
        variant.synthetic_weight,
    );
    let lexical_dev = RouteSet::new(
        dev_set
            .iter()
            .filter(|example| !example.cjk)
            .filter(scored_length),
        &lexical_families,
        1.0,
    );
    let (lexical, lexical_grid) = fit(
        &lexical_train,
        &lexical_dev,
        &variant.lexical_families,
        &constraints,
        target_fpr,
        grid,
    );
    let cross_lingual = variant.cross_lingual.then(|| {
        let cross_train = RouteSet::new(
            train_set
                .iter()
                .filter(|example| example.cjk || !variant.cross_lingual_cjk_only)
                .filter(scored_length),
            &cross_families,
            variant.synthetic_weight,
        );
        let cross_dev = RouteSet::new(
            dev_set
                .iter()
                .filter(|example| example.cjk)
                .filter(scored_length),
            &cross_families,
            1.0,
        );
        let families = CROSS_LINGUAL_FAMILIES.map(str::to_string).to_vec();
        fit(
            &cross_train,
            &cross_dev,
            &families,
            &constraints,
            target_fpr,
            grid,
        )
    });
    let evaluation = (!eval_set.is_empty()).then(|| {
        evaluate_module_rule(
            eval_set,
            &lexical,
            cross_lingual.as_ref().map(|(fitted, _)| fitted),
        )
    });
    let compact = |fitted: &Fitted| {
        json!({
            "params": format!("{:?}", fitted.params),
            "threshold": fitted.dev["threshold"], "recall": fitted.dev["recall"],
            "fpr": fitted.dev["fpr"], "balanced_accuracy": fitted.dev["balanced_accuracy"],
            "nonzero_weights": fitted.weights.len(),
        })
    };
    let summary = json!({
        "variant": variant.name,
        "lexical_dev": compact(&lexical),
        "cross_lingual_dev": cross_lingual.as_ref().map(|(fitted, _)| compact(fitted)),
        "evaluation_only": evaluation.as_ref().map(|evaluation| json!({
            "recall": evaluation["recall"], "fpr": evaluation["fpr"], "auc_scored": evaluation["auc_scored"],
            "scored_recall_at_fpr": evaluation["scored_recall_at_fpr"],
        })),
        "seconds": started.elapsed().as_secs_f64(),
    });
    println!("variant summary: {summary}");

    let directory = output.join(&variant.name);
    std::fs::create_dir(&directory).expect("create a fresh variant directory");
    let training = json!({
        "shared": shared,
        "variant": {
            "name": variant.name, "lexical_families": variant.lexical_families,
            "cross_lingual": variant.cross_lingual, "cross_lingual_cjk_only": variant.cross_lingual_cjk_only,
            "synthetic_weight": variant.synthetic_weight, "exclude": variant.exclude,
            "nonneg": variant.nonneg, "nonpos": variant.nonpos,
            "constrained_indices": constraint_counts,
        },
        "target_dev_fpr": target_fpr,
        "selection": "sparsest configuration within 0.0025 route-dev balanced accuracy of the best, at the route-dev benign threshold",
        "lexical": {"params": format!("{:?}", lexical.params), "dev": lexical.dev},
        "cross_lingual": cross_lingual.as_ref().map(|(fitted, _)| json!({
            "params": format!("{:?}", fitted.params), "dev": fitted.dev,
        })),
    });
    let model = json!({
        "schema_version": 1,
        "model_id": format!("semantic_text_classifier_v2_{}", variant.name),
        "feature_spec": TEXT_CLASSIFIER_FEATURE_SPEC,
        "hash_bits": HASH_BITS,
        "trained": true,
        "cjk_route_ratio": CJK_ROUTE_RATIO,
        "min_active_features": MIN_ACTIVE_FEATURES,
        "min_text_units": MIN_TEXT_UNITS,
        "require_positive_evidence": true,
        "lexicon_sources": TEXT_CLASSIFIER_LEXICON_SOURCES,
        "lexical": model_part(&lexical),
        "cross_lingual": cross_lingual.as_ref().map(|(fitted, _)| model_part(fitted)),
        "training": training,
    });
    std::fs::write(
        directory.join("text_classifier_v1.json"),
        serde_json::to_vec(&model).unwrap(),
    )
    .unwrap();
    let report = json!({
        "summary": summary,
        "training": model["training"],
        "evaluation_only": evaluation,
        "lexical_grid": lexical_grid,
        "cross_lingual_grid": cross_lingual.as_ref().map(|(_, grid)| grid),
        "lexical_top_positive": top_features(&lexical, names, true),
        "lexical_top_negative": top_features(&lexical, names, false),
        "cross_lingual_top_positive": cross_lingual.as_ref().map(|(fitted, _)| top_features(fitted, names, true)),
        "cross_lingual_top_negative": cross_lingual.as_ref().map(|(fitted, _)| top_features(fitted, names, false)),
    });
    std::fs::write(
        directory.join("training_report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "offline classifier training; run explicitly on the remote builder"]
async fn train_semantic_text_classifier() {
    let env_path =
        |name: &str| PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name}")));
    let output = env_path("VIGILYX_CLASSIFIER_OUTPUT");
    std::fs::create_dir(&output).expect("create a fresh output directory");
    let target_fpr = std::env::var("VIGILYX_CLASSIFIER_TARGET_FPR")
        .ok()
        .map_or(DEFAULT_TARGET_FPR, |value| {
            value.parse().expect("target FPR")
        });
    let allow_chinese = std::env::var("VIGILYX_CLASSIFIER_ALLOW_CHINESE").as_deref() == Ok("1");
    let variants: Vec<Variant> = match std::env::var("VIGILYX_CLASSIFIER_VARIANTS") {
        Ok(value) => serde_json::from_str(&value).expect("valid variant list"),
        Err(_) => serde_json::from_value(json!([{"name": "default"}])).unwrap(),
    };
    assert!(!variants.is_empty(), "at least one variant");
    let (train_cases, train_sha256) = read_cases(&env_path("VIGILYX_CLASSIFIER_TRAIN"));
    let (dev_cases, dev_sha256) = read_cases(&env_path("VIGILYX_CLASSIFIER_DEV"));
    let module = Arc::new(SemanticScanModule::new(None).with_text_classifier_feature_export());
    let mut names = HashMap::new();
    let started = std::time::Instant::now();
    let train_set = extract(Arc::clone(&module), train_cases, allow_chinese, &mut names).await;
    let dev_set = extract(Arc::clone(&module), dev_cases, allow_chinese, &mut names).await;
    let (eval_set, eval_sha256) = match std::env::var("VIGILYX_CLASSIFIER_EVAL") {
        Ok(path) => {
            let (cases, digest) = read_cases(Path::new(&path));
            (extract(module, cases, true, &mut names).await, Some(digest))
        }
        Err(_) => (Vec::new(), None),
    };
    let extraction_seconds = started.elapsed().as_secs_f64();
    println!(
        "classifier features: {} train, {} dev, {} eval, {:.1}s",
        train_set.len(),
        dev_set.len(),
        eval_set.len(),
        extraction_seconds
    );

    let mut grid = Vec::new();
    for alpha in [0.05, 0.1, 0.3, 0.5] {
        for l1 in [0.01, 0.1, 0.5, 1.0, 2.0] {
            for epochs in [4, 8, 16] {
                grid.push(Params {
                    alpha,
                    l1,
                    l2: 1.0,
                    epochs,
                });
            }
        }
    }
    let shared = json!({
        "train_sha256": train_sha256, "dev_sha256": dev_sha256,
        "evaluation_only_sha256": eval_sha256,
        "train_examples": train_set.len(), "dev_examples": dev_set.len(),
        "allow_chinese": allow_chinese, "extraction_seconds": extraction_seconds,
    });
    for variant in &variants {
        run_variant(
            variant, &output, &train_set, &dev_set, &eval_set, &names, target_fpr, &grid, &shared,
        );
    }
    println!("classifier models written to {}", output.display());
}
