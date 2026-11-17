//! Local statistical text classifier for the semantic module.
//!
//! A hashed linear model scores three feature families:
//!
//! * lexical: word, word-bigram and character n-grams of non-CJK script text;
//! * concept: hits on the existing multilingual semantic lexicon groups, both
//!   anywhere in the text and inside current-recipient requests;
//! * structure: typed claim roles, request/link counts and scenario candidates.
//!
//! Text dominated by CJK script is routed to a second model that uses only
//! the language-neutral concept and structure families. The research corpora
//! have no notice-style benign mail and no Chinese benign mail at all, so the
//! trainer adds synthetic benign notices and correspondence
//! (scripts/generate_semantic_synthetic_benign.py); see semantic/README.md for
//! what that does and does not cover.
//! Weights are compiled in; inference is bounded CPU work with no network or
//! model service. A positive result is a review-only Low signal and is kept
//! out of verdict fusion until it has been validated on real traffic.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};
use vigilyx_core::security::{
    SemanticClaim, SemanticMessageContext, SemanticPolarity, SemanticScenarioFinding,
    SemanticSourcePart,
};

use crate::module_data::ModuleDataRegistry;
use crate::modules::content_scan::normalize_text;

use super::compiled::CompiledSemanticData;
use super::source::SemanticSource;
use super::statistics::is_cjk_any;
use super::text::{normalized_lowercase_body, semantic_phrase_at};

pub const TEXT_CLASSIFIER_CATEGORY: &str = "semantic_text_classifier";
pub const TEXT_CLASSIFIER_FEATURE_SPEC: &str = "semantic_text_features_v1";
pub(super) const TEXT_CLASSIFIER_SCORE: f64 = 0.20;
const TEXT_CLASSIFIER_POLICY: &str = "semantic_text_classifier_policy_v1";
const MODEL_JSON: &str = include_str!("model/text_classifier_v1.json");
const MAX_TOKEN_CHARS: usize = 32;
const EXPLANATION_FEATURES: usize = 8;
/// Upper bound on group conjunctions emitted for one request claim.
const MAX_GROUP_PAIRS_PER_CLAIM: usize = 64;
/// Deadline checks are amortized over this many emitted tokens.
const DEADLINE_STRIDE: usize = 256;

/// Lexicon sources for concept features. The model file records the same
/// list; a mismatch disables the model instead of scoring shifted features.
pub const TEXT_CLASSIFIER_LEXICON_SOURCES: &[&str] = &[
    "semantic_request_markers_v1",
    "semantic_instruction_markers_v1",
    "semantic_anti_action_markers_v1",
    "semantic_report_markers_v1",
    "semantic_recipient_directed_markers_v2",
    "semantic_nominal_html_cta_markers_v2",
    "semantic_scenario_policy_v1",
    "semantic_cross_claim_candidate_policy_v1",
    "sextortion_threat_signals",
    "sextortion_payment_signals",
    "semantic_extortion_policy_v2",
    "semantic_nlp_authority_policy_v2",
    "semantic_secret_return_policy_v1",
    "semantic_verification_transfer_policy_v1",
    "semantic_funds_release_fee_policy_v1",
    "semantic_workflow_policy_v1",
    "semantic_combination_risk_policy_v1",
    "semantic_phishing_intent_policy_v1",
    "semantic_economic_intent_risk_policy_v1",
    "semantic_coercive_intent_policy_v1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextClassifierFamily {
    Lexical,
    Concept,
    Structure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextClassifierRoute {
    /// Text that is not CJK-dominant.
    Lexical,
    /// CJK-dominant text; the model part may be absent, which leaves such
    /// text to the rules.
    CrossLingual,
}

/// One exported feature with its per-family normalized value.
#[derive(Debug, Clone, Serialize)]
pub struct TextClassifierFeature {
    pub family: TextClassifierFamily,
    pub name: String,
    pub index: u32,
    pub value: f32,
}

/// FNV-1a over the feature name; shared by inference and the offline trainer.
pub fn text_classifier_feature_index(name: &str, hash_bits: u32) -> u32 {
    let mut hash = FeatureHash::new();
    hash.write(name.as_bytes());
    hash.index(hash_bits)
}

#[derive(Clone, Copy)]
struct FeatureHash(u64);

impl FeatureHash {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn index(self, hash_bits: u32) -> u32 {
        ((self.0 ^ (self.0 >> 29)) as u32) & ((1u32 << hash_bits) - 1)
    }
}

#[derive(Deserialize)]
struct LinearModelFile {
    bias: f64,
    threshold: f64,
    /// Feature families this part scores; the trainer records its choice.
    families: Vec<TextClassifierFamily>,
    weights: Vec<(u32, f32)>,
}

#[derive(Deserialize)]
struct ModelFile {
    schema_version: u8,
    model_id: String,
    feature_spec: String,
    hash_bits: u32,
    trained: bool,
    cjk_route_ratio: f64,
    min_active_features: usize,
    min_text_units: usize,
    require_positive_evidence: bool,
    lexicon_sources: Vec<String>,
    #[serde(default)]
    lexical: Option<LinearModelFile>,
    #[serde(default)]
    cross_lingual: Option<LinearModelFile>,
}

struct LinearModel {
    bias: f64,
    threshold: f64,
    families: Vec<TextClassifierFamily>,
    weights: HashMap<u32, f32>,
}

struct TextClassifierModel {
    model_id: String,
    hash_bits: u32,
    cjk_route_ratio: f64,
    min_active_features: usize,
    /// Document-level statistics were trained on whole messages (over 99.5%
    /// have 30+ words). Shorter text is out of distribution and left to the
    /// sentence-level rules; units are Latin word tokens plus CJK chars / 2.
    min_text_units: usize,
    /// Fire only when the features themselves push toward malicious. The
    /// intercept alone encodes "no benign marker recognized", which is not
    /// evidence for mail unlike the training controls.
    require_positive_evidence: bool,
    lexical: LinearModel,
    cross_lingual: Option<LinearModel>,
}

impl TextClassifierModel {
    fn route(&self, route: TextClassifierRoute) -> Option<&LinearModel> {
        match route {
            TextClassifierRoute::Lexical => Some(&self.lexical),
            TextClassifierRoute::CrossLingual => self.cross_lingual.as_ref(),
        }
    }
}

fn linear_model(file: LinearModelFile, hash_bits: u32) -> Result<LinearModel, String> {
    if !(file.bias.is_finite() && file.threshold > 0.0 && file.threshold < 1.0) {
        return Err("model bias or threshold is invalid".to_string());
    }
    if file.families.is_empty() {
        return Err("model part scores no feature family".to_string());
    }
    let mut weights = HashMap::with_capacity(file.weights.len());
    for (index, weight) in file.weights {
        if index >> hash_bits != 0 || !weight.is_finite() {
            return Err("model weight index or value is invalid".to_string());
        }
        weights.insert(index, weight);
    }
    Ok(LinearModel {
        bias: file.bias,
        threshold: file.threshold,
        families: file.families,
        weights,
    })
}

fn load_model() -> Result<TextClassifierModel, String> {
    let file: ModelFile =
        serde_json::from_str(MODEL_JSON).map_err(|error| format!("model is malformed: {error}"))?;
    if file.schema_version != 1 || file.feature_spec != TEXT_CLASSIFIER_FEATURE_SPEC {
        return Err("model schema or feature specification is not supported".to_string());
    }
    if !(12..=24).contains(&file.hash_bits) {
        return Err("model hash width is invalid".to_string());
    }
    if file.lexicon_sources != TEXT_CLASSIFIER_LEXICON_SOURCES {
        return Err("model lexicon sources differ from the feature extractor".to_string());
    }
    if !file.trained {
        return Err("untrained".to_string());
    }
    if !(file.cjk_route_ratio > 0.0 && file.cjk_route_ratio <= 1.0) {
        return Err("model CJK route ratio is invalid".to_string());
    }
    Ok(TextClassifierModel {
        model_id: file.model_id,
        hash_bits: file.hash_bits,
        cjk_route_ratio: file.cjk_route_ratio,
        min_active_features: file.min_active_features,
        min_text_units: file.min_text_units,
        require_positive_evidence: file.require_positive_evidence,
        lexical: linear_model(
            file.lexical.ok_or("lexical model part is missing")?,
            file.hash_bits,
        )?,
        cross_lingual: file
            .cross_lingual
            .map(|part| linear_model(part, file.hash_bits))
            .transpose()?,
    })
}

fn model() -> &'static Result<TextClassifierModel, String> {
    static MODEL: OnceLock<Result<TextClassifierModel, String>> = OnceLock::new();
    MODEL.get_or_init(load_model)
}

/// Hash width for feature export even when the shipped model is untrained.
fn model_hash_bits() -> u32 {
    serde_json::from_str::<serde_json::Value>(MODEL_JSON)
        .ok()
        .and_then(|value| value["hash_bits"].as_u64())
        .and_then(|bits| u32::try_from(bits).ok())
        .filter(|bits| (12..=24).contains(bits))
        .unwrap_or(22)
}

/// `review` lets a positive result raise the module to a review-only Low;
/// `shadow` records the outcome in details without changing the result.
/// Policies written before the mode existed meant `review`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TextClassifierMode {
    #[default]
    Review,
    Shadow,
}

#[derive(Deserialize)]
struct TextClassifierPolicy {
    enabled: bool,
    #[serde(default)]
    mode: TextClassifierMode,
}

struct TextClassifierPolicyState {
    enabled: bool,
    shadow: bool,
    diagnostic: Option<&'static str>,
}

fn parse_text_classifier_policy(value: Option<&serde_json::Value>) -> TextClassifierPolicyState {
    let disabled = |diagnostic| TextClassifierPolicyState {
        enabled: false,
        shadow: false,
        diagnostic: Some(diagnostic),
    };
    match value.map(|value| serde_json::from_value::<TextClassifierPolicy>(value.clone())) {
        Some(Ok(policy)) => TextClassifierPolicyState {
            enabled: policy.enabled,
            shadow: policy.mode == TextClassifierMode::Shadow,
            diagnostic: None,
        },
        Some(Err(_)) => disabled(
            "semantic text classifier policy (semantic_text_classifier_policy_v1) is malformed; the classifier is disabled",
        ),
        None => disabled(
            "semantic text classifier policy (semantic_text_classifier_policy_v1) is missing; the classifier is disabled",
        ),
    }
}

/// Missing or malformed policy disables scoring and is reported as a policy
/// diagnostic. The classifier is additive, so its absence is not a gap in
/// the inspection that the rule engine already completed.
fn text_classifier_policy(data: &CompiledSemanticData) -> Arc<TextClassifierPolicyState> {
    data.cached(TEXT_CLASSIFIER_POLICY, |registry| {
        parse_text_classifier_policy(registry.get_structured(TEXT_CLASSIFIER_POLICY))
    })
}

pub(super) fn text_classifier_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    text_classifier_policy(data).diagnostic
}

/// Multilingual lexicon groups compiled once per module-data snapshot.
struct LexiconIndex {
    matcher: Option<AhoCorasick>,
    terms: Vec<String>,
    term_positions: HashMap<String, usize>,
    term_groups: Vec<Vec<usize>>,
    groups: Vec<String>,
    /// Groups from relation and scenario policies, as opposed to the generic
    /// speech-act marker lists; only these form request conjunctions.
    relational: Vec<bool>,
}

fn collect_groups(value: &serde_json::Value, path: String, out: &mut Vec<(String, Vec<String>)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                collect_groups(item, format!("{path}/{key}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            let strings = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !strings.is_empty() && strings.len() == items.len() {
                out.push((path, strings));
                return;
            }
            for (position, item) in items.iter().enumerate() {
                if item.is_object() || item.is_array() {
                    collect_groups(item, format!("{path}[{position}]"), out);
                }
            }
        }
        _ => {}
    }
}

impl LexiconIndex {
    fn new(registry: &ModuleDataRegistry) -> Self {
        let mut groups = Vec::new();
        for source in TEXT_CLASSIFIER_LEXICON_SOURCES {
            if let Some(value) = registry.get_structured(source) {
                collect_groups(value, (*source).to_string(), &mut groups);
            } else {
                let list = registry.get_list(source);
                if !list.is_empty() {
                    groups.push(((*source).to_string(), list.to_vec()));
                }
            }
        }
        let mut term_positions = HashMap::<String, usize>::new();
        let mut terms = Vec::new();
        let mut term_groups: Vec<Vec<usize>> = Vec::new();
        let mut names = Vec::with_capacity(groups.len());
        for (group, items) in groups {
            let group_id = names.len();
            names.push(group);
            for item in items {
                let term = normalize_text(&item.to_lowercase()).trim().to_string();
                if term.is_empty() {
                    continue;
                }
                let position = *term_positions.entry(term.clone()).or_insert_with(|| {
                    terms.push(term);
                    term_groups.push(Vec::new());
                    terms.len() - 1
                });
                if !term_groups[position].contains(&group_id) {
                    term_groups[position].push(group_id);
                }
            }
        }
        let relational = names
            .iter()
            .map(|name| {
                !TEXT_CLASSIFIER_LEXICON_SOURCES[..6]
                    .iter()
                    .any(|source| name.starts_with(source))
            })
            .collect();
        Self {
            matcher: AhoCorasick::new(&terms).ok(),
            terms,
            term_positions,
            term_groups,
            groups: names,
            relational,
        }
    }

    /// Groups that list an extracted action or object term verbatim.
    fn term_groups(&self, term: &str) -> &[usize] {
        let term = normalize_text(&term.to_lowercase());
        self.term_positions
            .get(term.trim())
            .map_or(&[], |position| self.term_groups[*position].as_slice())
    }

    /// Group ids hit in `text`; ASCII terms must stand on word boundaries.
    fn hits(&self, text: &str) -> Vec<usize> {
        let Some(matcher) = &self.matcher else {
            return Vec::new();
        };
        let mut found = HashSet::new();
        for hit in matcher.find_overlapping_iter(text) {
            let term = &self.terms[hit.pattern().as_usize()];
            if term.is_ascii() && !semantic_phrase_at(text, term, hit.start()) {
                continue;
            }
            found.extend(self.term_groups[hit.pattern().as_usize()].iter().copied());
        }
        let mut found = found.into_iter().collect::<Vec<_>>();
        found.sort_unstable();
        found
    }
}

fn lexicon(data: &CompiledSemanticData) -> Arc<LexiconIndex> {
    data.cached("semantic_text_classifier_lexicon_v1", LexiconIndex::new)
}

/// URLs and mail addresses are removed before text features. Link evidence
/// belongs to the link modules, and the research corpora replaced malicious
/// links with generator placeholders, so link text would teach the model that
/// a real URL indicates benign mail. ASCII classes stop at adjoining CJK text.
fn without_addresses(text: &str) -> std::borrow::Cow<'_, str> {
    static ADDRESS: OnceLock<Regex> = OnceLock::new();
    ADDRESS
        .get_or_init(|| {
            Regex::new(
                r"(?:(?:https?|hxxps?)://|www\.)[A-Za-z0-9\-._~:/?#@!$&*+,;=%]+|[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+",
            )
            .expect("valid address pattern")
        })
        .replace_all(text, " ")
}

fn is_cjk_script(character: char) -> bool {
    is_cjk_any(character)
        || matches!(character, '\u{3040}'..='\u{30ff}' | '\u{1100}'..='\u{11ff}' | '\u{ac00}'..='\u{d7af}')
}

fn enum_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn count_bucket(count: usize, edges: &[(usize, &'static str)]) -> &'static str {
    edges
        .iter()
        .find(|(upper, _)| count <= *upper)
        .map_or("many", |(_, label)| label)
}

struct FeatureBag<'m> {
    hash_bits: u32,
    export: bool,
    weights: Option<&'m HashMap<u32, f32>>,
    families: BTreeMap<TextClassifierFamily, HashMap<u32, Option<String>>>,
}

impl FeatureBag<'_> {
    fn add(&mut self, family: TextClassifierFamily, parts: &[&str]) {
        let mut hash = FeatureHash::new();
        for part in parts {
            hash.write(part.as_bytes());
        }
        let index = hash.index(self.hash_bits);
        let named = self.export
            || self
                .weights
                .is_some_and(|weights| weights.contains_key(&index));
        let entry = self
            .families
            .entry(family)
            .or_default()
            .entry(index)
            .or_insert(None);
        if named && entry.is_none() {
            *entry = Some(parts.concat());
        }
    }

    /// Binary presence, L2-normalized within each family so long messages do
    /// not dominate and one family cannot swamp another by size alone.
    fn features(&self) -> Vec<TextClassifierFeature> {
        let mut result = Vec::new();
        for (family, entries) in &self.families {
            if entries.is_empty() {
                continue;
            }
            let value = 1.0 / (entries.len() as f32).sqrt();
            for (index, name) in entries {
                result.push(TextClassifierFeature {
                    family: *family,
                    name: name.clone().unwrap_or_default(),
                    index: *index,
                    value,
                });
            }
        }
        result.sort_by_key(|feature| (feature.family, feature.index));
        result
    }
}

fn add_token(
    bag: &mut FeatureBag<'_>,
    token: &mut String,
    token_chars: usize,
    previous: &mut Option<String>,
    subject: bool,
) {
    if !(2..=MAX_TOKEN_CHARS).contains(&token_chars) {
        token.clear();
        return;
    }
    if subject {
        bag.add(TextClassifierFamily::Lexical, &["s:", token]);
    } else {
        bag.add(TextClassifierFamily::Lexical, &["t:", token]);
        if let Some(previous) = previous.as_deref() {
            bag.add(TextClassifierFamily::Lexical, &["b:", previous, " ", token]);
        }
        let padded = format!("#{token}#");
        let offsets = padded
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(padded.len()))
            .collect::<Vec<_>>();
        for width in 3..=5 {
            for start in 0..offsets.len().saturating_sub(width) {
                bag.add(
                    TextClassifierFamily::Lexical,
                    &["c:", &padded[offsets[start]..offsets[start + width]]],
                );
            }
        }
    }
    *previous = Some(std::mem::take(token));
}

/// Tokens of non-CJK alphanumeric runs; digits are folded so amounts and
/// phone numbers share features. Returns false when the deadline passed.
fn add_lexical_features(
    bag: &mut FeatureBag<'_>,
    text: &str,
    subject: bool,
    deadline: Instant,
) -> bool {
    let mut previous = None;
    let mut emitted = 0usize;
    let mut token = String::new();
    let mut token_chars = 0usize;
    for character in text.chars() {
        if character.is_alphanumeric() && !is_cjk_script(character) {
            token.push(if character.is_numeric() {
                '0'
            } else {
                character
            });
            token_chars += 1;
            continue;
        }
        if token_chars > 0 {
            add_token(bag, &mut token, token_chars, &mut previous, subject);
            token_chars = 0;
            emitted += 1;
            if emitted.is_multiple_of(DEADLINE_STRIDE) && Instant::now() >= deadline {
                return false;
            }
        }
    }
    if token_chars > 0 {
        add_token(bag, &mut token, token_chars, &mut previous, subject);
    }
    true
}

pub(super) struct TextClassifierInput<'a> {
    pub(super) subject: Option<&'a str>,
    pub(super) body: &'a str,
    pub(super) source_part: SemanticSourcePart,
    pub(super) context: &'a SemanticMessageContext,
    pub(super) scenarios: &'a [SemanticScenarioFinding],
    pub(super) data: &'a CompiledSemanticData,
    pub(super) deadline: Instant,
    pub(super) export_features: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TextClassifierOutcome {
    /// disabled, unavailable, untrained, budget_exhausted or scored.
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) route: Option<TextClassifierRoute>,
    pub(super) cjk_ratio: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) probability: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) threshold: Option<f64>,
    pub(super) active_features: usize,
    pub(super) text_units: usize,
    /// Text is shorter than the model's training length floor; the score is
    /// recorded but lies outside the evaluated distribution.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) below_training_length: bool,
    pub(super) fired: bool,
    /// Shadow mode: `fired` is recorded but does not affect the result.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) shadow: bool,
    pub(super) top_features: Vec<(String, f64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) diagnostic: Option<String>,
    #[serde(skip)]
    pub(super) exported: Option<Vec<TextClassifierFeature>>,
}

impl TextClassifierOutcome {
    fn inactive(status: &'static str, diagnostic: Option<String>) -> Self {
        Self {
            status,
            model_id: None,
            route: None,
            cjk_ratio: 0.0,
            probability: None,
            threshold: None,
            active_features: 0,
            text_units: 0,
            below_training_length: false,
            fired: false,
            shadow: false,
            top_features: Vec::new(),
            diagnostic,
            exported: None,
        }
    }

    pub(super) fn budget_exhausted(&self) -> bool {
        self.status == "budget_exhausted"
    }

    /// Whether a positive result may raise the module result.
    pub(super) fn scores(&self) -> bool {
        self.fired && !self.shadow
    }
}

fn claim_source<'a>(claim: &SemanticClaim, input: &TextClassifierInput<'a>) -> Option<&'a str> {
    if claim.source_part == SemanticSourcePart::Header {
        SemanticSource::new(input.subject?, SemanticSourcePart::Header).claim_text(claim)
    } else {
        SemanticSource::new(input.body, input.source_part).claim_text(claim)
    }
}

fn add_semantic_features(bag: &mut FeatureBag<'_>, input: &TextClassifierInput<'_>, text: &str) {
    let lexicon = lexicon(input.data);
    let message_groups = lexicon.hits(text);
    for group in &message_groups {
        bag.add(
            TextClassifierFamily::Concept,
            &["g:", &lexicon.groups[*group]],
        );
    }
    let group_edges = [(0, "0"), (3, "1-3"), (7, "4-7"), (15, "8-15")];
    bag.add(
        TextClassifierFamily::Structure,
        &[
            "k:groups=",
            count_bucket(message_groups.len(), &group_edges),
        ],
    );
    let mut request_groups = HashSet::new();
    let mut requests = 0usize;
    for claim in &input.context.claims {
        let speech_act = enum_label(&claim.speech_act);
        let target = enum_label(&claim.target_role);
        bag.add(
            TextClassifierFamily::Structure,
            &[
                "k:sa|",
                &speech_act,
                "|",
                &enum_label(&claim.quote_or_forward_status),
            ],
        );
        if claim.polarity == SemanticPolarity::Action {
            let destination = enum_label(&claim.action_destination);
            bag.add(
                TextClassifierFamily::Structure,
                &["k:act|", &speech_act, "|", &target],
            );
            bag.add(
                TextClassifierFamily::Structure,
                &["k:act|", &speech_act, "|", &target, "|", &destination],
            );
        }
        if !claim.counter_context_ids.is_empty() {
            bag.add(TextClassifierFamily::Structure, &["k:countered"]);
        }
        if !super::is_current_recipient_action(claim) {
            continue;
        }
        requests += 1;
        for (prefix, terms) in [("ga:", &claim.actions), ("go:", &claim.objects)] {
            for term in terms {
                for group in lexicon.term_groups(term) {
                    bag.add(
                        TextClassifierFamily::Concept,
                        &[prefix, &lexicon.groups[*group]],
                    );
                }
            }
        }
        for provenance in &claim.provenance {
            bag.add(TextClassifierFamily::Structure, &["kp:", provenance]);
        }
        if let Some(claim_text) = claim_source(claim, input) {
            let claim_text = normalized_lowercase_body(claim_text);
            let claim_groups = lexicon.hits(&without_addresses(&claim_text));
            for group in &claim_groups {
                bag.add(
                    TextClassifierFamily::Concept,
                    &["gr:", &lexicon.groups[*group]],
                );
            }
            // Conjunctions such as "verification action & account object" in
            // one request are language-neutral relations the linear model
            // cannot form from separate group hits.
            let relational = claim_groups
                .iter()
                .copied()
                .filter(|group| lexicon.relational[*group])
                .collect::<Vec<_>>();
            let mut pairs = 0usize;
            'pairs: for (position, left) in relational.iter().enumerate() {
                for right in &relational[position + 1..] {
                    if pairs == MAX_GROUP_PAIRS_PER_CLAIM {
                        break 'pairs;
                    }
                    bag.add(
                        TextClassifierFamily::Concept,
                        &["gp:", &lexicon.groups[*left], "&", &lexicon.groups[*right]],
                    );
                    pairs += 1;
                }
            }
            request_groups.extend(claim_groups);
        }
    }
    bag.add(
        TextClassifierFamily::Structure,
        &[
            "k:req=",
            count_bucket(requests, &[(0, "0"), (1, "1"), (2, "2")]),
        ],
    );
    bag.add(
        TextClassifierFamily::Structure,
        &[
            "k:req_groups=",
            count_bucket(request_groups.len(), &group_edges),
        ],
    );
    for finding in input.scenarios {
        bag.add(
            TextClassifierFamily::Structure,
            &[
                "sc:",
                &enum_label(&finding.scenario_id),
                "|",
                &enum_label(&finding.resolution),
            ],
        );
    }
}

pub(super) fn classify(input: TextClassifierInput<'_>) -> TextClassifierOutcome {
    let policy = text_classifier_policy(input.data);
    let enabled = policy.enabled;
    let model = match model() {
        Ok(model) => Some(model),
        Err(reason) if reason == "untrained" => {
            if !input.export_features {
                return TextClassifierOutcome::inactive("untrained", None);
            }
            None
        }
        Err(reason) => {
            if !input.export_features {
                return TextClassifierOutcome::inactive("unavailable", Some(reason.clone()));
            }
            None
        }
    };
    if !enabled && !input.export_features {
        return TextClassifierOutcome::inactive("disabled", None);
    }

    let subject = input
        .subject
        .map(|subject| without_addresses(&normalized_lowercase_body(subject)).into_owned())
        .unwrap_or_default();
    let body = without_addresses(&normalized_lowercase_body(input.body)).into_owned();
    let (mut cjk, mut latin, mut words) = (0usize, 0usize, 0usize);
    let mut run = 0usize;
    for character in subject.chars().chain(['\n']).chain(body.chars()) {
        if character.is_alphanumeric() && !is_cjk_script(character) {
            run += 1;
            latin += usize::from(character.is_alphabetic());
            continue;
        }
        words += usize::from((2..=MAX_TOKEN_CHARS).contains(&run));
        run = 0;
        cjk += usize::from(is_cjk_script(character));
    }
    words += usize::from((2..=MAX_TOKEN_CHARS).contains(&run));
    let text_units = words + cjk / 2;
    let cjk_ratio = if cjk + latin == 0 {
        0.0
    } else {
        cjk as f64 / (cjk + latin) as f64
    };
    // Short text is scored like any other text. The model was trained only on
    // text at or above its length floor, so shorter input is marked as outside
    // the training distribution. min_active_features and positive evidence
    // still guard sparse input from firing.
    let below_training_length = model.is_some_and(|model| text_units < model.min_text_units);
    let route = if model.is_some_and(|model| cjk_ratio >= model.cjk_route_ratio) {
        TextClassifierRoute::CrossLingual
    } else {
        TextClassifierRoute::Lexical
    };
    let linear = model.and_then(|model| model.route(route));
    if model.is_some() && linear.is_none() && !input.export_features {
        return TextClassifierOutcome {
            cjk_ratio,
            text_units,
            below_training_length,
            route: Some(route),
            ..TextClassifierOutcome::inactive("route_disabled", None)
        };
    }
    let weights = linear.map(|linear| &linear.weights);
    let mut bag = FeatureBag {
        hash_bits: model.map_or_else(model_hash_bits, |model| model.hash_bits),
        export: input.export_features,
        weights,
        families: BTreeMap::new(),
    };
    // Export always carries every family; inference skips work for families
    // the routed model does not use.
    let lexical_needed = input.export_features
        || linear.is_none_or(|linear| linear.families.contains(&TextClassifierFamily::Lexical));
    let completed = !lexical_needed
        || (add_lexical_features(&mut bag, &subject, true, input.deadline)
            && add_lexical_features(&mut bag, &body, false, input.deadline));
    if !completed || Instant::now() >= input.deadline {
        return TextClassifierOutcome {
            cjk_ratio,
            text_units,
            ..TextClassifierOutcome::inactive("budget_exhausted", None)
        };
    }
    add_semantic_features(&mut bag, &input, &format!("{subject}\n{body}"));
    let features = bag.features();

    let (Some(model), Some(linear), true) = (model, linear, enabled) else {
        return TextClassifierOutcome {
            cjk_ratio,
            text_units,
            route: Some(route),
            exported: Some(features),
            ..TextClassifierOutcome::inactive(if enabled { "untrained" } else { "disabled" }, None)
        };
    };
    let mut margin = linear.bias;
    let mut active = 0usize;
    let mut contributions = Vec::new();
    for feature in &features {
        if !linear.families.contains(&feature.family) {
            continue;
        }
        if let Some(weight) = linear.weights.get(&feature.index) {
            active += 1;
            let contribution = f64::from(*weight) * f64::from(feature.value);
            margin += contribution;
            if contribution > 0.0 {
                contributions.push((feature.name.clone(), contribution));
            }
        }
    }
    contributions.sort_by(|left, right| right.1.total_cmp(&left.1));
    contributions.truncate(EXPLANATION_FEATURES);
    let evidence = margin - linear.bias;
    let probability = 1.0 / (1.0 + (-margin).exp());
    TextClassifierOutcome {
        status: "scored",
        model_id: Some(model.model_id.clone()),
        route: Some(route),
        cjk_ratio,
        probability: Some(probability),
        threshold: Some(linear.threshold),
        active_features: active,
        text_units,
        below_training_length,
        fired: active >= model.min_active_features
            && (!model.require_positive_evidence || evidence > 0.0)
            && probability >= linear.threshold,
        shadow: policy.shadow,
        top_features: contributions,
        diagnostic: None,
        exported: input.export_features.then_some(features),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_mode_defaults_to_review_and_accepts_shadow() {
        let review = parse_text_classifier_policy(Some(&serde_json::json!({"enabled": true})));
        assert!(review.enabled && !review.shadow && review.diagnostic.is_none());
        let shadow = parse_text_classifier_policy(Some(
            &serde_json::json!({"enabled": true, "mode": "shadow"}),
        ));
        assert!(shadow.enabled && shadow.shadow && shadow.diagnostic.is_none());
        let unknown = parse_text_classifier_policy(Some(
            &serde_json::json!({"enabled": true, "mode": "block"}),
        ));
        assert!(!unknown.enabled && unknown.diagnostic.is_some());
        let missing = parse_text_classifier_policy(None);
        assert!(!missing.enabled && missing.diagnostic.is_some());
    }

    #[test]
    fn shadow_outcome_is_recorded_but_does_not_score() {
        let mut outcome = TextClassifierOutcome::inactive("scored", None);
        outcome.fired = true;
        assert!(outcome.scores());
        outcome.shadow = true;
        assert!(!outcome.scores());
        let details = serde_json::to_value(&outcome).unwrap();
        assert_eq!(details["fired"], true);
        assert_eq!(details["shadow"], true);
    }

    #[test]
    fn shipped_policy_runs_the_classifier_in_shadow_mode() {
        let registry = ModuleDataRegistry::from_seed_and_overrides(
            vigilyx_db::security::embedded_module_data_seed(),
            &crate::module_data::ModuleDataOverrides::default(),
        )
        .unwrap();
        let data = CompiledSemanticData::new(Arc::new(registry));
        let policy = text_classifier_policy(&data);
        assert!(policy.enabled && policy.shadow && policy.diagnostic.is_none());
    }
}
