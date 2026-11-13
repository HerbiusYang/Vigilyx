//! Optional semantic intent model: a fine-tuned encoder ensemble (bge + e5)
//! run in-process with ONNX Runtime on CPU. The outcome is recorded in
//! semantic_scan details under `semantic_intent_model`.
//!
//! By default it runs in shadow mode beside the local rule analysis and never
//! changes the module result. SEMANTIC_INTENT_SCORE_THRESHOLD switches it to
//! scored mode: the model replaces the local rule analysis, and an ensemble
//! score at or above that threshold is a review-level Low semantic_scan
//! result that enters verdict fusion. The packaged dev threshold is not used
//! for scoring because it was tuned on research corpora and flags most real
//! mail; the operator sets the scoring threshold from the real-traffic score
//! distribution.
//!
//! Enabled when SEMANTIC_INTENT_MODEL_DIR names a packaged ensemble
//! (`ensemble.json` plus one directory per member holding model.onnx,
//! tokenizer.json and classifier_config.json, written by
//! scripts/semantic_intent_poc/package_final.py) and ORT_DYLIB_PATH names the
//! ONNX Runtime library. Any loading problem disables the model with a warning.
//!
//! Scoring follows the training pipeline exactly: `intent_text::model_text`,
//! the member prefix, special tokens, head+tail truncation to max_len tokens.
//! Each member logit is standardised with the dev mean and standard deviation
//! recorded at packaging time; the equal-weight mean is compared with the dev
//! accuracy-maximising threshold. One email is scored at a time on the
//! blocking pool, members in parallel, within a fixed share of the module budget.

use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Tensor;
use serde::{Deserialize, Serialize};
use tokenizers::Tokenizer;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::module::{Bpa, Evidence, ModuleMetadata, ModuleResult, ThreatLevel};

use super::budget::SEMANTIC_INSPECTION_LIMITED;
use super::intent_text::model_text;
use super::text::floor_char_boundary;

pub const INTENT_MODEL_DETAILS_KEY: &str = "semantic_intent_model";
/// Category added to semantic_scan when the scored model fires.
pub const INTENT_MODEL_CATEGORY: &str = "semantic_intent_model";
/// Review-level Low score supplied by a scored model hit.
pub(super) const INTENT_MODEL_SCORE: f64 = 0.20;
const ENSEMBLE_SCHEMA: &str = "vigilyx-semantic-intent-ensemble/v1";
/// Share of the 3 s semantic module budget the outcome may be awaited for.
const INTENT_WAIT_BUDGET: Duration = Duration::from_millis(2400);
const SUBJECT_MAX_BYTES: usize = 8 * 1024;
/// Long bodies keep both ends; the model keeps head and tail tokens anyway.
const BODY_HEAD_BYTES: usize = 128 * 1024;
const BODY_TAIL_BYTES: usize = 64 * 1024;
const DEFAULT_THREADS: usize = 4;
const MAX_MEMBERS: usize = 4;

#[derive(Deserialize)]
struct EnsembleSpec {
    schema: String,
    model_version: String,
    threshold: f64,
    members: Vec<MemberSpec>,
}

#[derive(Deserialize)]
struct MemberSpec {
    name: String,
    dir: String,
    dev_mean: f64,
    dev_std: f64,
}

#[derive(Deserialize)]
struct ClassifierConfig {
    prefix: String,
    max_len: usize,
    head_tokens: usize,
}

struct Member {
    name: String,
    mean: f64,
    std: f64,
    prefix: String,
    max_len: usize,
    head: usize,
    tokenizer: Tokenizer,
    session: Mutex<Session>,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// A member directory must be one plain path component inside the model directory.
fn plain_component(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    )
}

impl Member {
    fn load(
        environment: &ort::environment::Environment,
        dir: &Path,
        spec: &MemberSpec,
        threads: usize,
    ) -> Result<Self, String> {
        let config: ClassifierConfig = read_json(&dir.join("classifier_config.json"))?;
        if config.head_tokens >= config.max_len || config.max_len == 0 {
            return Err(format!("{}: invalid truncation settings", spec.name));
        }
        let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|error| format!("{}: tokenizer: {error}", spec.name))?;
        tokenizer
            .with_truncation(None)
            .map_err(|error| format!("{}: tokenizer: {error}", spec.name))?;
        tokenizer.with_padding(None);
        let mut builder = Session::builder(environment)
            .and_then(|builder| {
                builder
                    .with_optimization_level(GraphOptimizationLevel::All)
                    .map_err(Into::into)
            })
            .and_then(|builder| builder.with_intra_threads(threads).map_err(Into::into))
            .and_then(|builder| builder.with_inter_threads(1).map_err(Into::into))
            .map_err(|error| format!("{}: session options: {error}", spec.name))?;
        let session = builder
            .commit_from_file(dir.join("model.onnx"))
            .map_err(|error| format!("{}: model: {error}", spec.name))?;
        Ok(Self {
            name: spec.name.clone(),
            mean: spec.dev_mean,
            std: spec.dev_std,
            prefix: config.prefix,
            max_len: config.max_len,
            head: config.head_tokens,
            tokenizer,
            session: Mutex::new(session),
        })
    }

    fn logit(&self, text: &str) -> Result<f64, String> {
        let encoding = self
            .tokenizer
            .encode(format!("{}{}", self.prefix, text), true)
            .map_err(|error| format!("{}: tokenize: {error}", self.name))?;
        let mut ids: Vec<i64> = encoding.get_ids().iter().map(|&id| i64::from(id)).collect();
        if ids.len() > self.max_len {
            let tail = ids.split_off(ids.len() - (self.max_len - self.head));
            ids.truncate(self.head);
            ids.extend(tail);
        }
        let length = ids.len() as i64;
        let mask = vec![1_i64; ids.len()];
        let input_ids =
            Tensor::from_array((vec![1_i64, length], ids)).map_err(|error| error.to_string())?;
        let attention_mask =
            Tensor::from_array((vec![1_i64, length], mask)).map_err(|error| error.to_string())?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| "model session is unavailable".to_string())?;
        let outputs = session
            .run(ort::inputs!["input_ids" => input_ids, "attention_mask" => attention_mask])
            .map_err(|error| format!("{}: inference: {error}", self.name))?;
        let output = outputs
            .get("logit")
            .ok_or_else(|| format!("{}: no logit output", self.name))?;
        let (_, values) = output
            .try_extract_tensor::<f32>()
            .map_err(|error| format!("{}: output: {error}", self.name))?;
        values
            .first()
            .map(|&value| f64::from(value))
            .filter(|value| value.is_finite())
            .ok_or_else(|| format!("{}: invalid logit", self.name))
    }
}

struct Scored {
    score: f64,
    members: BTreeMap<String, f64>,
    inference_ms: u64,
}

pub struct IntentModel {
    version: String,
    threshold: f64,
    /// Real-traffic scoring threshold; `None` keeps the model in shadow mode.
    score_threshold: Option<f64>,
    members: Vec<Member>,
    /// One email at a time: inference is CPU bound and each member already uses several threads.
    gate: Arc<Semaphore>,
    _environment: ort::environment::Environment,
}

impl IntentModel {
    /// The process-wide model, loaded on first use; `None` when not configured or not loadable.
    pub fn from_env() -> Option<Arc<Self>> {
        static MODEL: OnceLock<Option<Arc<IntentModel>>> = OnceLock::new();
        MODEL
            .get_or_init(|| {
                let dir = std::env::var("SEMANTIC_INTENT_MODEL_DIR").unwrap_or_default();
                if dir.trim().is_empty() {
                    return None;
                }
                let dylib = std::env::var("ORT_DYLIB_PATH").unwrap_or_default();
                let threads = std::env::var("SEMANTIC_INTENT_THREADS")
                    .ok()
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(DEFAULT_THREADS)
                    .clamp(1, 16);
                let score_threshold = parse_score_threshold(
                    &std::env::var("SEMANTIC_INTENT_SCORE_THRESHOLD").unwrap_or_default(),
                );
                let started = Instant::now();
                match Self::load(Path::new(dir.trim()), dylib.trim(), threads) {
                    Ok(mut model) => {
                        model.score_threshold = score_threshold;
                        info!(
                            version = %model.version,
                            members = model.members.len(),
                            threads,
                            mode = model.mode(),
                            score_threshold = ?model.score_threshold,
                            load_ms = started.elapsed().as_millis() as u64,
                            "semantic intent model loaded"
                        );
                        Some(Arc::new(model))
                    }
                    Err(error) => {
                        warn!(error = %error, "semantic intent model disabled");
                        None
                    }
                }
            })
            .clone()
    }

    fn load(dir: &Path, dylib: &str, threads: usize) -> Result<Self, String> {
        let spec: EnsembleSpec = read_json(&dir.join("ensemble.json"))?;
        if spec.schema != ENSEMBLE_SCHEMA {
            return Err(format!("unsupported ensemble schema {:?}", spec.schema));
        }
        if spec.members.is_empty()
            || spec.members.len() > MAX_MEMBERS
            || !spec.threshold.is_finite()
        {
            return Err(
                "ensemble has no members, too many members or an invalid threshold".to_string(),
            );
        }
        for member in &spec.members {
            if !plain_component(&member.dir) {
                return Err(format!(
                    "member directory {:?} must be a plain name",
                    member.dir
                ));
            }
            if !member.dev_mean.is_finite() || !member.dev_std.is_finite() || member.dev_std <= 0.0
            {
                return Err(format!(
                    "member {:?} has invalid dev statistics",
                    member.name
                ));
            }
        }
        if dylib.is_empty() {
            return Err("ORT_DYLIB_PATH is not set".to_string());
        }
        let environment = ort::init_from(dylib)
            .map_err(|error| format!("ONNX Runtime library: {error}"))?
            .with_name("vigilyx-semantic-intent")
            .build()
            .map_err(|error| format!("ONNX Runtime environment: {error}"))?;
        let members = spec
            .members
            .iter()
            .map(|member| Member::load(&environment, &dir.join(&member.dir), member, threads))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: spec.model_version.chars().take(64).collect(),
            threshold: spec.threshold,
            score_threshold: None,
            members,
            gate: Arc::new(Semaphore::new(1)),
            _environment: environment,
        })
    }

    /// Scored mode: the model replaces the local rule analysis of semantic_scan.
    pub(super) fn is_scored(&self) -> bool {
        self.score_threshold.is_some()
    }

    fn mode(&self) -> &'static str {
        if self.is_scored() { "scored" } else { "shadow" }
    }

    fn score(&self, subject: Option<&str>, body: &str) -> Result<Scored, String> {
        let started = Instant::now();
        let text = model_text(subject, body).map_err(|error| error.to_string())?;
        // Members run concurrently, each on its own intra-op threads: the email
        // costs the slowest member rather than the sum of all of them.
        let logits: Vec<Result<f64, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .members
                .iter()
                .map(|member| scope.spawn(|| member.logit(&text)))
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err("member scoring panicked".to_string()))
                })
                .collect()
        });
        let mut members = BTreeMap::new();
        let mut sum = 0.0;
        for (member, logit) in self.members.iter().zip(logits) {
            let logit = logit?;
            sum += (logit - member.mean) / member.std;
            members.insert(member.name.clone(), logit);
        }
        Ok(Scored {
            score: sum / self.members.len() as f64,
            members,
            inference_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// Recorded under `semantic_intent_model`. In scored mode a flagged outcome
/// raises the semantic_scan result (see `scores`).
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct IntentModelOutcome {
    /// `ok`, `busy` (another email held the model for the whole budget),
    /// `timeout` (scoring started but did not finish in time) or `error`.
    pub status: &'static str,
    /// `scored` or `shadow`.
    pub mode: &'static str,
    pub model_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// The threshold `flagged` is measured against: the scoring threshold in
    /// scored mode, the packaged dev threshold in shadow mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flagged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<BTreeMap<String, f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_ms: Option<u64>,
    pub round_trip_ms: u64,
    pub input_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl IntentModelOutcome {
    /// Whether this outcome may raise the module result.
    pub(super) fn scores(&self) -> bool {
        self.status == "ok" && self.mode == "scored" && self.flagged == Some(true)
    }
}

/// A scoring threshold must be a finite number; anything else keeps shadow mode.
fn parse_score_threshold(value: &str) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match value.parse::<f64>() {
        Ok(threshold) if threshold.is_finite() => Some(threshold),
        _ => {
            warn!(
                value,
                "SEMANTIC_INTENT_SCORE_THRESHOLD is not a finite number; intent model stays in shadow mode"
            );
            None
        }
    }
}

pub(crate) struct IntentRequest {
    handle: JoinHandle<Result<Scored, String>>,
    started_scoring: Arc<AtomicBool>,
    started: Instant,
    input_truncated: bool,
    version: String,
    threshold: f64,
    score_threshold: Option<f64>,
}

/// Bound the input size; cuts land on UTF-8 boundaries.
fn bounded_input(subject: Option<&str>, body: &str) -> (Option<String>, String, bool) {
    let mut truncated = false;
    let subject = subject.map(|subject| {
        let end = floor_char_boundary(subject, SUBJECT_MAX_BYTES);
        truncated |= end < subject.len();
        subject[..end].to_string()
    });
    let body = if body.len() > BODY_HEAD_BYTES + BODY_TAIL_BYTES {
        truncated = true;
        let head = &body[..floor_char_boundary(body, BODY_HEAD_BYTES)];
        let tail = &body[ceil_char_boundary(body, body.len() - BODY_TAIL_BYTES)..];
        format!("{head}\n{tail}")
    } else {
        body.to_string()
    };
    (subject, body, truncated)
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Queue scoring in the background; `None` when the model is not configured.
pub(crate) fn start_intent_request(
    model: Option<&Arc<IntentModel>>,
    subject: Option<&str>,
    body: &str,
) -> Option<IntentRequest> {
    let model = Arc::clone(model?);
    let (subject, body, input_truncated) = bounded_input(subject, body);
    let started_scoring = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&started_scoring);
    let (version, threshold, score_threshold) = (
        model.version.clone(),
        model.threshold,
        model.score_threshold,
    );
    let handle = tokio::spawn(async move {
        let permit = Arc::clone(&model.gate)
            .acquire_owned()
            .await
            .map_err(|_| "model gate closed".to_string())?;
        flag.store(true, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || {
            // The permit lives until scoring returns, even if the caller stopped waiting.
            let _permit = permit;
            model.score(subject.as_deref(), &body)
        })
        .await
        .map_err(|_| "scoring task failed".to_string())?
    });
    Some(IntentRequest {
        handle,
        started_scoring,
        started: Instant::now(),
        input_truncated,
        version,
        threshold,
        score_threshold,
    })
}

/// Await the outcome within the module's intent budget.
pub(crate) async fn complete_intent_request(
    request: Option<IntentRequest>,
    module_start: Instant,
) -> Option<IntentModelOutcome> {
    complete_within(request, module_start, INTENT_WAIT_BUDGET).await
}

async fn complete_within(
    request: Option<IntentRequest>,
    module_start: Instant,
    budget: Duration,
) -> Option<IntentModelOutcome> {
    let mut request = request?;
    let remaining = budget.saturating_sub(module_start.elapsed());
    let waited = tokio::time::timeout(remaining, &mut request.handle).await;
    let round_trip_ms = request.started.elapsed().as_millis() as u64;
    let mode = if request.score_threshold.is_some() {
        "scored"
    } else {
        "shadow"
    };
    let failed = |status, reason: Option<String>| IntentModelOutcome {
        status,
        mode,
        model_version: request.version.clone(),
        score: None,
        threshold: None,
        dev_threshold: None,
        flagged: None,
        members: None,
        inference_ms: None,
        round_trip_ms,
        input_truncated: request.input_truncated,
        reason,
    };
    let outcome = match waited {
        Ok(Ok(Ok(scored))) => {
            let flagged = match request.score_threshold {
                Some(threshold) => scored.score >= threshold,
                None => scored.score > request.threshold,
            };
            IntentModelOutcome {
                status: "ok",
                mode,
                model_version: request.version.clone(),
                score: Some(scored.score),
                threshold: Some(request.score_threshold.unwrap_or(request.threshold)),
                dev_threshold: Some(request.threshold),
                flagged: Some(flagged),
                members: Some(scored.members),
                inference_ms: Some(scored.inference_ms),
                round_trip_ms,
                input_truncated: request.input_truncated,
                reason: None,
            }
        }
        Ok(Ok(Err(reason))) => failed("error", Some(reason)),
        Ok(Err(_)) => failed("error", Some("scoring task failed".to_string())),
        Err(_) => {
            // Stop waiting for the model gate; a started scoring finishes on its own.
            request.handle.abort();
            if request.started_scoring.load(Ordering::Relaxed) {
                failed("timeout", None)
            } else {
                failed("busy", None)
            }
        }
    };
    Some(outcome)
}

/// semantic_scan result in scored mode, where the model replaces the local
/// rule analysis. A hit is a review-level Low score that enters verdict
/// fusion; a miss is an ordinary safe result; a model that did not finish
/// (busy, timeout, error) carries no belief and marks the inspection incomplete.
pub(super) fn intent_model_result(
    meta: &ModuleMetadata,
    outcome: Option<IntentModelOutcome>,
    duration_ms: u64,
) -> ModuleResult {
    let status = outcome.as_ref().map_or("error", |outcome| outcome.status);
    let score = outcome
        .as_ref()
        .and_then(|outcome| outcome.score)
        .unwrap_or_default();
    let threshold = outcome
        .as_ref()
        .and_then(|outcome| outcome.threshold)
        .unwrap_or_default();
    let mut result = ModuleResult {
        module_id: meta.id.clone(),
        module_name: meta.name.clone(),
        pillar: meta.pillar,
        threat_level: ThreatLevel::Safe,
        confidence: 0.70,
        categories: Vec::new(),
        summary: format!(
            "Semantic intent model score {score:.2} is below threshold {threshold:.2}"
        ),
        evidence: Vec::new(),
        details: serde_json::json!({ "score": 0.0, "semantic_mode": "intent_model" }),
        duration_ms,
        analyzed_at: Utc::now(),
        bpa: None,
        engine_id: None,
    };
    if outcome.as_ref().is_some_and(IntentModelOutcome::scores) {
        result.threat_level = ThreatLevel::from_score(INTENT_MODEL_SCORE);
        result.confidence = 0.55;
        result.categories.push(INTENT_MODEL_CATEGORY.to_string());
        result.summary = format!(
            "Semantic intent model score {score:.2} reached threshold {threshold:.2}; review required"
        );
        result.evidence.push(Evidence {
            description: result.summary.clone(),
            location: Some(format!("body:{INTENT_MODEL_DETAILS_KEY}")),
            snippet: None,
        });
        result.details["score"] = serde_json::json!(INTENT_MODEL_SCORE);
    } else if status != "ok" {
        result.confidence = 0.0;
        result
            .categories
            .push(SEMANTIC_INSPECTION_LIMITED.to_string());
        result.summary =
            format!("Semantic intent model did not complete ({status}); no semantic judgment");
        result.bpa = Some(Bpa::vacuous());
    }
    result.details[INTENT_MODEL_DETAILS_KEY] = serde_json::to_value(&outcome).unwrap_or_default();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_input_keeps_head_and_tail_on_char_boundaries() {
        let body = format!(
            "{}{}{}",
            "账".repeat(BODY_HEAD_BYTES / 3 + 7),
            "中".repeat(20_000),
            "尾".repeat(BODY_TAIL_BYTES / 3 + 5)
        );
        let subject = "主".repeat(SUBJECT_MAX_BYTES);
        let (subject, bounded, truncated) = bounded_input(Some(&subject), &body);
        assert!(truncated);
        assert!(subject.expect("subject").len() <= SUBJECT_MAX_BYTES);
        assert!(bounded.starts_with('账') && bounded.ends_with('尾'));
        assert!(bounded.len() <= BODY_HEAD_BYTES + BODY_TAIL_BYTES + 1);
        let (_, short, truncated) = bounded_input(None, "short body");
        assert_eq!((short.as_str(), truncated), ("short body", false));
    }

    #[test]
    fn member_directories_must_stay_inside_the_model_directory() {
        assert!(plain_component("bge"));
        for name in ["../bge", "/abs", "a/b", "", ".", ".."] {
            assert!(!plain_component(name), "{name:?}");
        }
    }

    #[test]
    fn invalid_ensembles_are_rejected_before_loading_onnx_runtime() {
        let dir = std::env::temp_dir().join(format!("vigilyx-intent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let write = |spec: &str| std::fs::write(dir.join("ensemble.json"), spec).expect("write");
        write(r#"{"schema":"other","model_version":"v","threshold":0.1,"members":[]}"#);
        assert!(IntentModel::load(&dir, "", 1).is_err());
        write(
            r#"{"schema":"vigilyx-semantic-intent-ensemble/v1","model_version":"v","threshold":0.1,"members":[{"name":"a","dir":"../a","dev_mean":0,"dev_std":1}]}"#,
        );
        assert!(
            IntentModel::load(&dir, "", 1)
                .err()
                .expect("rejected")
                .contains("plain name")
        );
        write(
            r#"{"schema":"vigilyx-semantic-intent-ensemble/v1","model_version":"v","threshold":0.1,"members":[{"name":"a","dir":"a","dev_mean":0,"dev_std":0}]}"#,
        );
        assert!(
            IntentModel::load(&dir, "", 1)
                .err()
                .expect("rejected")
                .contains("dev statistics")
        );
        write(
            r#"{"schema":"vigilyx-semantic-intent-ensemble/v1","model_version":"v","threshold":0.1,"members":[{"name":"a","dir":"a","dev_mean":0,"dev_std":1}]}"#,
        );
        assert!(
            IntentModel::load(&dir, "", 1)
                .err()
                .expect("rejected")
                .contains("ORT_DYLIB_PATH")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn finished_request(score: f64, score_threshold: Option<f64>) -> IntentRequest {
        IntentRequest {
            handle: tokio::spawn(async move {
                Ok(Scored {
                    score,
                    members: BTreeMap::from([("m3".to_string(), 1.5)]),
                    inference_ms: 3,
                })
            }),
            started_scoring: Arc::new(AtomicBool::new(true)),
            started: Instant::now(),
            input_truncated: false,
            version: "test".to_string(),
            threshold: -0.24,
            score_threshold,
        }
    }

    #[tokio::test]
    async fn scored_mode_flags_against_the_scoring_threshold_only() {
        let budget = Duration::from_secs(5);
        let hit = complete_within(
            Some(finished_request(0.91, Some(0.90))),
            Instant::now(),
            budget,
        )
        .await
        .expect("outcome");
        assert_eq!(
            (hit.mode, hit.flagged, hit.threshold),
            ("scored", Some(true), Some(0.90))
        );
        assert_eq!(hit.dev_threshold, Some(-0.24));
        assert!(hit.scores());

        // Above the dev threshold but below the scoring threshold: recorded, not scored.
        let miss = complete_within(
            Some(finished_request(0.5, Some(0.90))),
            Instant::now(),
            budget,
        )
        .await
        .expect("outcome");
        assert_eq!(miss.flagged, Some(false));
        assert!(!miss.scores());

        let shadow = complete_within(Some(finished_request(0.5, None)), Instant::now(), budget)
            .await
            .expect("outcome");
        assert_eq!(
            (shadow.mode, shadow.flagged, shadow.threshold),
            ("shadow", Some(true), Some(-0.24))
        );
        assert!(!shadow.scores(), "shadow mode never scores");
    }

    #[tokio::test]
    async fn scored_mode_result_is_low_on_a_hit_safe_on_a_miss_and_vacuous_when_unfinished() {
        use crate::module::SecurityModule;
        let module = crate::semantic::SemanticScanModule::new(None);
        let meta = module.metadata();
        let budget = Duration::from_secs(5);

        let hit = complete_within(
            Some(finished_request(0.95, Some(0.90))),
            Instant::now(),
            budget,
        )
        .await;
        let result = intent_model_result(meta, hit, 7);
        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert_eq!(result.categories, vec![INTENT_MODEL_CATEGORY.to_string()]);
        assert_eq!(result.details["score"], INTENT_MODEL_SCORE);
        assert_eq!(result.details["semantic_mode"], "intent_model");
        assert_eq!(result.details[INTENT_MODEL_DETAILS_KEY]["mode"], "scored");
        assert!(result.bpa.is_none());

        let miss = complete_within(
            Some(finished_request(0.2, Some(0.90))),
            Instant::now(),
            budget,
        )
        .await;
        let result = intent_model_result(meta, miss, 7);
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.is_empty());
        assert!((result.confidence - 0.70).abs() < 1e-9);

        let mut timeout = finished_request(0.95, Some(0.90));
        timeout.handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Err("never".to_string())
        });
        let outcome =
            complete_within(Some(timeout), Instant::now(), Duration::from_millis(10)).await;
        let result = intent_model_result(meta, outcome, 7);
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.confidence, 0.0);
        assert_eq!(
            result.categories,
            vec![SEMANTIC_INSPECTION_LIMITED.to_string()]
        );
        assert!(result.bpa.is_some_and(|bpa| bpa.b <= 1e-12));
    }

    #[test]
    fn scoring_threshold_must_be_a_finite_number() {
        assert_eq!(parse_score_threshold(" 0.9 "), Some(0.9));
        assert_eq!(parse_score_threshold("-0.25"), Some(-0.25));
        for value in ["", "  ", "high", "NaN", "inf"] {
            assert_eq!(parse_score_threshold(value), None, "{value:?}");
        }
    }

    #[tokio::test]
    async fn not_configured_adds_nothing() {
        assert!(start_intent_request(None, None, "b").is_none());
        assert!(
            complete_intent_request(None, Instant::now())
                .await
                .is_none()
        );
    }

    /// End-to-end parity with the Python ensemble on 77 (needs ONNX Runtime and the packaged models):
    /// INTENT_PARITY_MODEL_DIR=... INTENT_PARITY_CASES=cases.jsonl ORT_DYLIB_PATH=... cargo test -- --ignored intent_model_parity
    /// Each case line: {"subject", "body", "text", "logits": {member: value}}.
    #[test]
    #[ignore = "needs ONNX Runtime, packaged models and Python reference outputs"]
    fn intent_model_parity() {
        let dir = std::env::var("INTENT_PARITY_MODEL_DIR").expect("INTENT_PARITY_MODEL_DIR");
        let cases = std::env::var("INTENT_PARITY_CASES").expect("INTENT_PARITY_CASES");
        let dylib = std::env::var("ORT_DYLIB_PATH").expect("ORT_DYLIB_PATH");
        let model = IntentModel::load(Path::new(&dir), &dylib, DEFAULT_THREADS).expect("model");
        let mut worst = 0.0_f64;
        let mut count = 0;
        for line in std::fs::read_to_string(&cases).expect("cases").lines() {
            let case: serde_json::Value = serde_json::from_str(line).expect("case");
            let subject = case["subject"].as_str();
            let body = case["body"].as_str().unwrap_or("");
            assert_eq!(
                model_text(subject, body).expect("text"),
                case["text"].as_str().expect("text"),
                "line {count}"
            );
            let scored = model.score(subject, body).expect("score");
            for (name, logit) in &scored.members {
                let expected = case["logits"][name].as_f64().expect("python logit");
                worst = worst.max((logit - expected).abs());
            }
            count += 1;
        }
        println!("intent parity: {count} cases, max |rust - python| logit = {worst:e}");
        assert!(count > 0 && worst < 1e-3, "max logit difference {worst}");
    }
}
