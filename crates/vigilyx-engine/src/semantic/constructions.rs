//! Stage B request constructions over the existing action/object facts.
//! Enabled in the bundled policy through `stage_b_enabled`; operators can
//! disable it with that key without editing the legacy `enabled` scalar.

use serde::Deserialize;
use std::sync::Arc;

use super::compiled::CompiledSemanticData;
use super::guards::{clause_content, contains};

#[derive(Deserialize)]
struct ConstructionPolicy {
    enabled: bool,
    /// Additive activation flag. Persisted seeds keep their stored scalar
    /// `enabled` value, so a newer binary activates Stage B through this key.
    #[serde(default)]
    stage_b_enabled: Option<bool>,
    modal_markers: Vec<String>,
    purpose_prefixes: Vec<String>,
    permissive_prefixes: Vec<String>,
    permissive_markers: Vec<String>,
    result_markers: Vec<String>,
    collective_prefixes: Vec<String>,
    system_directed_prefixes: Vec<String>,
    query_markers: Vec<String>,
    query_recipient_markers: Vec<String>,
    sensitive_objects: Vec<String>,
    implicit_return_action: String,
    #[serde(default)]
    request_tail_tags: Vec<String>,
    #[serde(default)]
    request_tail_recipients: Vec<String>,
    #[serde(default)]
    recipient_disposal_prefixes: Vec<String>,
    #[serde(default)]
    disposal_request_markers: Vec<String>,
    #[serde(default)]
    disposal_completed_markers: Vec<String>,
    #[serde(default)]
    disposal_completed_tails: Vec<String>,
    #[serde(default)]
    colloquial_transfer_subjects: Vec<String>,
    #[serde(default)]
    colloquial_transfer_modifiers: Vec<String>,
    #[serde(default)]
    colloquial_transfer_verbs: Vec<String>,
    #[serde(default)]
    colloquial_transfer_recipients: Vec<String>,
    #[serde(default)]
    colloquial_transfer_action: String,
    #[serde(default)]
    recipient_modal_subjects: Vec<String>,
    #[serde(default)]
    recipient_obligation_modals: Vec<String>,
    #[serde(default)]
    recipient_modal_adverbs: Vec<String>,
    #[serde(default)]
    recipient_directive_adverbs: Vec<String>,
    #[serde(default)]
    instrumental_request_prepositions: Vec<String>,
    #[serde(default)]
    instrumental_communication_objects: Vec<String>,
    #[serde(default)]
    instrumental_completed_states: Vec<String>,
    #[serde(default)]
    procedural_obligation_patients: Vec<String>,
    #[serde(default)]
    procedural_submission_actions: Vec<String>,
    #[serde(default)]
    procedural_channel_labels: Vec<String>,
    #[serde(default)]
    procedural_append_markers: Vec<String>,
    #[serde(default)]
    procedural_append_nominals: Vec<String>,
    #[serde(default)]
    procedural_append_action: String,
    #[serde(default)]
    head_form_instruction_actions: Vec<String>,
    #[serde(default)]
    head_form_determiners: Vec<String>,
    #[serde(default)]
    recipient_share_assets: Vec<String>,
    #[serde(default)]
    recipient_share_benefit_frames: Vec<String>,
    #[serde(default)]
    recipient_share_outcomes: Vec<String>,
    #[serde(default)]
    recipient_share_action: String,
    #[serde(default)]
    recipient_share_object: String,
    #[serde(default)]
    deadline_obligation_markers: Vec<String>,
    #[serde(default)]
    deadline_time_openers: Vec<String>,
    #[serde(default)]
    deadline_time_endings: Vec<String>,
    #[serde(default)]
    deadline_time_tokens: Vec<String>,
    #[serde(default)]
    deadline_relative_times: Vec<String>,
    #[serde(default)]
    obligation_third_party_subjects: Vec<String>,
    #[serde(default)]
    compact_financial_enabled: bool,
    #[serde(default)]
    compact_currency_units: Vec<String>,
    #[serde(default)]
    compact_currency_prefixes: Vec<String>,
    #[serde(default)]
    compact_transfer_prepositions: Vec<String>,
    #[serde(default)]
    compact_financial_targets: Vec<String>,
    #[serde(default)]
    compact_target_modifiers: Vec<String>,
    #[serde(default)]
    compact_loan_products: Vec<String>,
    #[serde(default)]
    compact_loan_directions: Vec<String>,
    #[serde(default)]
    compact_loan_origin_prepositions: Vec<String>,
    #[serde(default)]
    compact_loan_predicate_suffixes: Vec<String>,
    #[serde(default)]
    compact_disposal_heads: Vec<String>,
    #[serde(default)]
    compact_disposal_actions: Vec<String>,
    #[serde(default)]
    compact_english_borrow_objects: Vec<String>,
    #[serde(default)]
    compact_english_borrow_observation_prefixes: Vec<String>,
    #[serde(default)]
    compact_english_borrow_nominal_suffixes: Vec<String>,
    #[serde(default)]
    compact_completed_markers: Vec<String>,
    #[serde(default)]
    compact_inspection_markers: Vec<String>,
    #[serde(default)]
    compact_nominal_suffixes: Vec<String>,
    #[serde(default)]
    compact_fresh_connectors: Vec<String>,
}

impl ConstructionPolicy {
    fn active(&self) -> bool {
        self.stage_b_enabled.unwrap_or(self.enabled)
    }
}

#[derive(Default)]
pub(super) struct ConstructionCue {
    pub(super) requested: bool,
    pub(super) recipient_override: bool,
    pub(super) implicit_action: Option<String>,
    pub(super) rule: Option<&'static str>,
    pub(super) completed_disposal: bool,
    pub(super) implicit_object: Option<String>,
    pub(super) recipient_share_notice: bool,
    pub(super) deadline_marker: Option<String>,
    pub(super) third_party_obligation: bool,
}

fn construction_policy(data: &CompiledSemanticData) -> Arc<Result<ConstructionPolicy, String>> {
    data.cached("semantic_request_construction_policy_v1", |registry| {
        let value = registry
            .get_structured("semantic_request_construction_policy_v1")
            .ok_or_else(|| "semantic request construction policy is missing".to_string())?;
        let policy: ConstructionPolicy =
            serde_json::from_value(value.clone()).map_err(|error| {
                format!("semantic request construction policy is malformed: {error}")
            })?;
        if policy.active()
            && (policy.query_markers.is_empty()
                || policy.query_recipient_markers.is_empty()
                || policy.sensitive_objects.is_empty()
                || !registry.contains("semantic_action_markers_v1", &policy.implicit_return_action))
        {
            return Err("semantic request construction policy has invalid query roles".to_string());
        }
        if policy.compact_financial_enabled
            && [
                &policy.compact_currency_units,
                &policy.compact_currency_prefixes,
                &policy.compact_transfer_prepositions,
                &policy.compact_financial_targets,
                &policy.compact_target_modifiers,
                &policy.compact_loan_products,
                &policy.compact_loan_directions,
                &policy.compact_loan_origin_prepositions,
                &policy.compact_loan_predicate_suffixes,
                &policy.compact_disposal_heads,
                &policy.compact_disposal_actions,
                &policy.compact_english_borrow_objects,
                &policy.compact_english_borrow_observation_prefixes,
                &policy.compact_english_borrow_nominal_suffixes,
                &policy.compact_completed_markers,
                &policy.compact_inspection_markers,
                &policy.compact_nominal_suffixes,
                &policy.compact_fresh_connectors,
            ]
            .iter()
            .any(|terms| {
                terms.is_empty()
                    || terms.len() > 96
                    || terms
                        .iter()
                        .any(|term| term.trim().is_empty() || term.len() > 128)
            })
        {
            return Err(
                "semantic compact financial predicate policy exceeds its bounded schema".into(),
            );
        }
        Ok(policy)
    })
}

pub(super) fn construction_policy_coverage_reason(data: &CompiledSemanticData) -> Option<String> {
    construction_policy(data).as_ref().as_ref().err().cloned()
}

/// A sentence-final request tag scopes the preceding coordinated actions;
/// a self/third-party subject, report or local negation can still override it.
pub(super) fn sentence_request_tag(text: &str, data: &CompiledSemanticData) -> bool {
    let snapshot = construction_policy(data);
    let Ok(policy) = snapshot.as_ref() else {
        return false;
    };
    if !policy.active() {
        return false;
    }
    let text = crate::modules::content_scan::normalize_text(&text.to_lowercase());
    let text = text.trim_end_matches(|c: char| {
        c.is_whitespace() || matches!(c, '?' | '？' | '!' | '！' | '。' | '.')
    });
    policy
        .request_tail_tags
        .iter()
        .any(|tag| text.ends_with(tag.as_str()))
        && policy
            .request_tail_recipients
            .iter()
            .any(|marker| contains(text, marker))
}

pub(super) struct ConstructionScope {
    pub(super) reminder: bool,
    pub(super) enumerated: bool,
    pub(super) procedural_child: bool,
    pub(super) procedural_heading: bool,
}

pub(super) fn request_construction(
    text: &str,
    actions: &[String],
    objects: &[String],
    scope: ConstructionScope,
    data: &CompiledSemanticData,
) -> ConstructionCue {
    let ConstructionScope {
        reminder,
        enumerated,
        procedural_child,
        procedural_heading,
    } = scope;
    let snapshot = construction_policy(data);
    let Ok(policy) = snapshot.as_ref() else {
        return ConstructionCue::default();
    };
    if !policy.active() {
        return ConstructionCue::default();
    }
    let text = clause_content(text);
    if let Some(predicate) = compact_financial_predicates(text, data).iter().find(|p| {
        !p.observation_only
            && actions.iter().any(|action| action == p.action)
            && compact_command_head(text, p, policy)
    }) {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            rule: Some(if predicate.action == "转" {
                "semantic_compact_transfer_request_v1"
            } else {
                "semantic_compact_borrow_request_v1"
            }),
            ..Default::default()
        };
    }
    // A subjectless monetary disposal has its own imperative shape:
    // 将/把 + explicit money + live transfer predicate + financial destination.
    // Neither a bare 将 nor an account noun grants request authority.
    if financial_disposal_command(text, actions, policy) {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            rule: Some("semantic_compact_financial_disposal_request_v1"),
            ..Default::default()
        };
    }
    let any = |values: &[String]| values.iter().any(|value| contains(text, value));
    let prefix = |values: &[String]| values.iter().any(|value| text.starts_with(value.as_str()));
    let disposal = prefix(&policy.recipient_disposal_prefixes);
    // Completion describes this disposal verb, not arbitrary commentary
    // later in the sentence (“先发我…我已经迫不及待”). Match a marker
    // before the first local action, or its explicitly configured aspect
    // suffix; a later independent action cannot close this request.
    let local_end = text
        .char_indices()
        .find_map(|(index, character)| {
            let separator = matches!(
                character,
                ',' | '，' | ';' | '；' | '~' | '～' | '\n' | '。' | '!' | '！' | '?' | '？'
            );
            let numeric_comma = matches!(character, ',' | '，')
                && text[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_digit() || ('０'..='９').contains(&c))
                && text[index + character.len_utf8()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() || ('０'..='９').contains(&c));
            (separator && !numeric_comma).then_some(index)
        })
        .unwrap_or(text.len());
    let local = text[..local_end].trim_end();
    let first_action = actions
        .iter()
        .filter_map(|action| {
            local
                .find(action.as_str())
                .map(|start| (start, start + action.len()))
        })
        .min_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)));
    let completed = first_action.is_some_and(|(start, end)| {
        policy
            .disposal_completed_markers
            .iter()
            .any(|marker| contains(&local[..start], marker))
            || policy
                .disposal_completed_tails
                .iter()
                .any(|tail| local[end..].trim() == tail)
    });
    if disposal && completed {
        return ConstructionCue {
            completed_disposal: true,
            ..Default::default()
        };
    }
    if !objects.is_empty()
        && !policy.colloquial_transfer_action.is_empty()
        && data.contains(
            "semantic_action_markers_v1",
            &policy.colloquial_transfer_action,
        )
        && colloquial_transfer(local, policy)
    {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            implicit_action: Some(policy.colloquial_transfer_action.clone()),
            rule: Some("semantic_construction_colloquial_transfer_v1"),
            completed_disposal: false,
            ..Default::default()
        };
    }
    if procedural_child
        && !policy.procedural_append_action.is_empty()
        && data.contains(
            "semantic_action_markers_v1",
            &policy.procedural_append_action,
        )
        && procedural_append(text, objects, policy)
    {
        return ConstructionCue {
            requested: true,
            implicit_action: Some(policy.procedural_append_action.clone()),
            rule: Some("semantic_procedural_channel_append_v1"),
            ..Default::default()
        };
    }
    let patient = enumerated
        .then(|| strip_policy_prefix(text, &policy.procedural_obligation_patients))
        .flatten();
    if let Some(deadline) = deadline_obligation(patient.unwrap_or(text), actions, policy) {
        let procedural = patient.is_some()
            && deadline
                .predicate
                .as_ref()
                .is_some_and(|action| policy.procedural_submission_actions.contains(action));
        let requested = deadline.requested && (patient.is_none() || procedural);
        return ConstructionCue {
            requested,
            recipient_override: requested,
            deadline_marker: Some(deadline.marker),
            third_party_obligation: deadline.third_party,
            rule: Some(if requested && procedural {
                "semantic_construction_procedural_obligation_v1"
            } else if requested {
                "semantic_construction_deadline_obligation_v1"
            } else {
                "semantic_deadline_obligation_observation_v1"
            }),
            ..Default::default()
        };
    }
    if ((enumerated && !objects.is_empty()) || procedural_heading)
        && bare_modal_action(text, actions, policy)
    {
        return ConstructionCue {
            requested: true,
            rule: Some("semantic_construction_procedural_modal_v1"),
            ..Default::default()
        };
    }
    if head_form_request(text, actions, objects, policy, data) {
        return ConstructionCue {
            requested: true,
            rule: Some("semantic_construction_head_form_request_v1"),
            ..Default::default()
        };
    }
    if !objects.is_empty() && recipient_adverb_action(local, actions, policy) {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            rule: Some("semantic_construction_recipient_directive_v1"),
            ..Default::default()
        };
    }
    if instrumental_request(text, actions, objects, policy) {
        return ConstructionCue {
            requested: true,
            rule: Some("semantic_construction_instrumental_request_v1"),
            ..Default::default()
        };
    }
    if !objects.is_empty() && recipient_modal_action(text, actions, policy) {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            rule: Some("semantic_construction_recipient_modal_v1"),
            ..Default::default()
        };
    }
    if !policy.recipient_share_action.is_empty()
        && !policy.recipient_share_object.is_empty()
        && data.contains("semantic_action_markers_v1", &policy.recipient_share_action)
        && data.contains("semantic_object_markers_v1", &policy.recipient_share_object)
        && !data
            .markers("semantic_anti_action_markers_v1")
            .entries
            .iter()
            .any(|marker| contains(text, &marker.normalized))
        && recipient_modal_remainder(text, policy).is_none()
        && !any(&policy.modal_markers)
        && recipient_share(text, policy)
    {
        return ConstructionCue {
            implicit_action: Some(policy.recipient_share_action.clone()),
            implicit_object: Some(policy.recipient_share_object.clone()),
            recipient_share_notice: true,
            rule: Some("semantic_construction_recipient_share_notice_v1"),
            ..Default::default()
        };
    }
    let sensitive_query = objects
        .iter()
        .any(|object| policy.sensitive_objects.contains(object))
        && any(&policy.query_markers)
        && any(&policy.query_recipient_markers)
        && data.contains("semantic_action_markers_v1", &policy.implicit_return_action);
    if sensitive_query {
        return ConstructionCue {
            requested: true,
            recipient_override: true,
            implicit_action: Some(policy.implicit_return_action.clone()),
            rule: Some("semantic_construction_sensitive_query_v1"),
            completed_disposal: false,
            ..Default::default()
        };
    }
    if actions.is_empty() || objects.is_empty() {
        return ConstructionCue::default();
    }
    let collective =
        prefix(&policy.collective_prefixes) || prefix(&policy.system_directed_prefixes);
    let rule = if collective {
        Some("semantic_construction_collective_request_v1")
    } else if disposal && any(&policy.disposal_request_markers) {
        Some("semantic_construction_recipient_disposal_v1")
    } else if reminder {
        Some("semantic_construction_reminder_v1")
    } else if any(&policy.modal_markers) {
        Some("semantic_construction_modal_request_v1")
    } else if (prefix(&policy.purpose_prefixes)
        || prefix(&policy.permissive_prefixes)
        || prefix(&policy.permissive_markers))
        && any(&policy.permissive_markers)
    {
        Some("semantic_construction_conditional_request_v1")
    } else if any(&policy.result_markers) {
        Some("semantic_construction_result_request_v1")
    } else {
        None
    };
    ConstructionCue {
        requested: rule.is_some(),
        recipient_override: collective,
        implicit_action: None,
        rule,
        completed_disposal: false,
        ..Default::default()
    }
}

/// The single characters 转/借 are predicates only when their right argument
/// has a monetary shape. No global action matcher is widened by this rule.
pub(super) struct CompactFinancialPredicate {
    pub(super) action: &'static str,
    pub(super) object: &'static str,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) observation_only: bool,
}

fn money_prefix(text: &str, policy: &ConstructionPolicy) -> Option<usize> {
    let mut rest = text.trim_start();
    let prefixed = if let Some(next) = strip_policy_prefix(rest, &policy.compact_currency_prefixes)
    {
        rest = next;
        true
    } else {
        false
    };
    let mut end = 0;
    let mut digits = 0;
    for (at, ch) in rest.char_indices().take(28) {
        if ch.is_ascii_digit() || "零〇一二两兩三四五六七八九十百千万萬亿億点點".contains(ch)
        {
            digits += 1;
        } else if !matches!(ch, ',' | '，' | '.') || digits == 0 {
            break;
        }
        end = at + ch.len_utf8();
    }
    if digits == 0 || digits > 24 {
        return None;
    }
    let tail = rest[end..].trim_start();
    let unit = strip_policy_prefix(tail, &policy.compact_currency_units);
    if unit.is_none() && !prefixed {
        return None;
    }
    let after = unit.unwrap_or(tail);
    if after
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(text.len() - after.len())
}

fn financial_target_prefix(text: &str, policy: &ConstructionPolicy) -> Option<usize> {
    let mut rest = text.trim_start();
    for _ in 0..3 {
        let Some(next) = strip_policy_prefix(rest, &policy.compact_target_modifiers) else {
            break;
        };
        rest = next;
    }
    let target = policy
        .compact_financial_targets
        .iter()
        .filter(|target| {
            rest.starts_with(target.as_str()) && super::text::semantic_phrase_at(rest, target, 0)
        })
        .max_by_key(|target| target.len())?;
    let mut tail = rest[target.len()..].trim_start();
    let identifier_end = tail
        .char_indices()
        .take(64)
        .take_while(|(_, ch)| ch.is_ascii_digit() || matches!(*ch, '-' | '*' | '＊' | ' '))
        .map(|(at, ch)| at + ch.len_utf8())
        .last()
        .unwrap_or(0);
    tail = &tail[identifier_end..];
    Some(text.len() - tail.len())
}

fn compact_command_head(
    text: &str,
    predicate: &CompactFinancialPredicate,
    policy: &ConstructionPolicy,
) -> bool {
    // English infinitive projection supplies a predicate inside an existing
    // request ("Please open ... to borrow money"). It does not grant a new
    // imperative to an otherwise unframed nominal "borrow money" fragment.
    if predicate.action == "borrow" {
        return false;
    }
    let mut before = text[..predicate.start].trim();
    if before.is_empty() {
        return true;
    }
    if let Some(next) = strip_policy_prefix(before, &policy.recipient_modal_subjects) {
        before = next;
    } else {
        return false;
    }
    if let Some(next) = strip_policy_prefix(before, &policy.recipient_obligation_modals) {
        before = next;
    }
    for _ in 0..2 {
        let Some(next) = strip_policy_prefix(before, &policy.recipient_directive_adverbs) else {
            break;
        };
        before = next;
    }
    if before.is_empty() {
        return true;
    }
    matches!(predicate.action, "借" | "借款")
        && before.strip_prefix('从').is_some_and(|product| {
            policy
                .compact_loan_products
                .iter()
                .any(|known| product.trim() == known)
        })
}

fn financial_disposal_command(text: &str, actions: &[String], policy: &ConstructionPolicy) -> bool {
    if !policy.compact_financial_enabled {
        return false;
    }
    let Some(patient) = strip_policy_prefix(text, &policy.compact_disposal_heads) else {
        return false;
    };
    let Some(amount_end) = money_prefix(patient, policy) else {
        return false;
    };
    let predicate = patient[amount_end..].trim_start();
    let Some(action) = policy
        .compact_disposal_actions
        .iter()
        .filter(|action| actions.contains(action) && predicate.starts_with(action.as_str()))
        .max_by_key(|action| action.len())
    else {
        return false;
    };
    let after = predicate[action.len()..].trim_start();
    let target = if matches!(action.as_str(), "转" | "转账") {
        let Some(target) = strip_policy_prefix(after, &policy.compact_transfer_prepositions) else {
            return false;
        };
        target
    } else {
        after
    };
    let Some(target_end) = financial_target_prefix(target, policy) else {
        return false;
    };
    let tail = target[target_end..].trim_start();
    !policy
        .compact_nominal_suffixes
        .iter()
        .chain(&policy.disposal_completed_tails)
        .any(|suffix| tail.starts_with(suffix.as_str()))
}

pub(super) fn compact_financial_predicates(
    text: &str,
    data: &CompiledSemanticData,
) -> Vec<CompactFinancialPredicate> {
    let snapshot = construction_policy(data);
    let Ok(policy) = snapshot.as_ref() else {
        return Vec::new();
    };
    if !policy.active() || !policy.compact_financial_enabled {
        return Vec::new();
    }
    let mut result = Vec::new();
    for action in ["转", "借", "borrow"] {
        for (start, _) in text.match_indices(action).take(8) {
            if !super::text::semantic_phrase_at(text, action, start) {
                continue;
            }
            let after = &text[start + action.len()..];
            let mut amount = money_prefix(after, policy);
            let mut projected_action = action;
            if amount.is_none() && action == "借" {
                // 借款 + amount is a monetary predicate; 借款 elsewhere stays
                // a noun (history, account type or future access privilege).
                if let Some(remainder) =
                    strip_policy_prefix(after, &policy.compact_loan_predicate_suffixes)
                {
                    amount = money_prefix(remainder, policy)
                        .map(|end| after.len() - remainder.len() + end);
                    if amount.is_some() {
                        projected_action = "借款";
                    }
                }
                let before = text[..start].trim_end();
                let loan_origin = policy.compact_loan_products.iter().any(|product| {
                    before.strip_suffix(product.as_str()).is_some_and(|prefix| {
                        policy
                            .compact_loan_origin_prepositions
                            .iter()
                            .any(|prep| prefix.trim_end().ends_with(prep.as_str()))
                    })
                });
                if amount.is_none() && loan_origin {
                    amount = strip_policy_prefix(after, &policy.compact_loan_directions).and_then(
                        |remainder| {
                            money_prefix(remainder, policy)
                                .map(|end| after.len() - remainder.len() + end)
                        },
                    );
                }
            }
            let directed = if action == "转" {
                strip_policy_prefix(after, &policy.compact_transfer_prepositions).and_then(
                    |target| {
                        financial_target_prefix(target, policy)
                            .map(|end| after.len() - target.len() + end)
                    },
                )
            } else if action == "borrow" {
                strip_policy_prefix(after.trim_start(), &policy.compact_english_borrow_objects)
                    .map(|remainder| after.len() - remainder.len())
            } else {
                None
            };
            if amount.is_none() && directed.is_none() {
                continue;
            }
            let before = &text[..start];
            let reset = policy
                .compact_fresh_connectors
                .iter()
                .filter_map(|connector| {
                    before
                        .rfind(connector.as_str())
                        .map(|at| at + connector.len())
                })
                .max()
                .unwrap_or(0);
            let local = &before[reset..];
            let amount_tail = amount
                .or(directed)
                .and_then(|end| after.get(end..))
                .unwrap_or(after);
            let observation_only = policy
                .compact_completed_markers
                .iter()
                .any(|marker| local.contains(marker.as_str()))
                || policy
                    .compact_inspection_markers
                    .iter()
                    .any(|marker| local.contains(marker.as_str()))
                || policy
                    .compact_nominal_suffixes
                    .iter()
                    .any(|suffix| amount_tail.trim_start().starts_with(suffix.as_str()))
                || (action == "borrow"
                    && (policy
                        .compact_english_borrow_observation_prefixes
                        .iter()
                        .any(|marker| contains(local, marker))
                        || policy
                            .compact_english_borrow_nominal_suffixes
                            .iter()
                            .any(|suffix| {
                                contains(amount_tail.trim_start(), suffix)
                                    && amount_tail.trim_start().starts_with(suffix.as_str())
                            })));
            result.push(CompactFinancialPredicate {
                action: projected_action,
                object: if action == "转" { "资金" } else { "借款" },
                start,
                end: start + projected_action.len(),
                observation_only,
            });
        }
    }
    result
}

/// “你先转我49000到账户” is an amount-bearing transfer construction.
/// The single character 转 is never installed as a general action marker.
fn colloquial_transfer(text: &str, policy: &ConstructionPolicy) -> bool {
    fn strip<'a>(text: &'a str, values: &[String]) -> Option<&'a str> {
        values
            .iter()
            .filter_map(|value| text.strip_prefix(value.as_str()))
            .min_by_key(|rest| rest.len())
            .map(str::trim_start)
    }
    let Some(text) = strip(text, &policy.colloquial_transfer_subjects) else {
        return false;
    };
    let Some(text) = strip(text, &policy.colloquial_transfer_modifiers) else {
        return false;
    };
    let Some(text) = strip(text, &policy.colloquial_transfer_verbs) else {
        return false;
    };
    let Some(text) = strip(text, &policy.colloquial_transfer_recipients) else {
        return false;
    };
    let mut end = 0;
    let mut digits = 0;
    for (index, character) in text.char_indices().take(19) {
        if character.is_ascii_digit() || ('０'..='９').contains(&character) {
            digits += 1;
        } else if !matches!(character, ',' | '，' | '.' | '．') || digits == 0 {
            break;
        }
        end = index + character.len_utf8();
    }
    if digits == 0 || digits > 18 {
        return false;
    }
    let rest = text[end..].trim_start();
    let rest = rest
        .strip_prefix(['元', '块', '塊'])
        .unwrap_or(rest)
        .trim_start();
    rest.starts_with(['到', '至'])
}

fn strip_policy_prefix<'a>(text: &'a str, values: &[String]) -> Option<&'a str> {
    values
        .iter()
        .filter_map(|value| {
            text.strip_prefix(value.as_str())
                .filter(|_| super::text::semantic_phrase_at(text, value, 0))
        })
        .min_by_key(|rest| rest.len())
        .map(str::trim_start)
}

/// Recipient → obligation → optional bounded adverbs → predicate. A modal
/// object such as “您需提供的表格” is a relative clause, not this request.
fn recipient_modal_remainder<'a>(text: &'a str, policy: &ConstructionPolicy) -> Option<&'a str> {
    let text = strip_policy_prefix(text, &policy.recipient_modal_subjects)?;
    let mut text = strip_policy_prefix(text, &policy.recipient_obligation_modals)?;
    for _ in 0..2 {
        let Some(rest) = strip_policy_prefix(text, &policy.recipient_modal_adverbs) else {
            break;
        };
        text = rest;
    }
    Some(text)
}

fn recipient_modal_action(text: &str, actions: &[String], policy: &ConstructionPolicy) -> bool {
    recipient_modal_remainder(text, policy).is_some_and(|text| {
        actions.iter().any(|action| {
            text.strip_prefix(action.as_str()).is_some_and(|rest| {
                super::text::semantic_phrase_at(text, action, 0)
                    && !rest.trim_start().starts_with(['的', '过', '過'])
            })
        })
    })
}

/// A percentage becomes a share fact only with a preceding money referent
/// and a local explicit recipient-benefit frame and allocation outcome.
/// Ordinary percentages, discounts, costs, or third-party benefits do not
/// synthesize an action/object pair.
fn recipient_share(text: &str, policy: &ConstructionPolicy) -> bool {
    text.match_indices('%').any(|(percent, _)| {
        let token = text[..percent]
            .rsplit(|c: char| !c.is_ascii_digit() && c != '.')
            .next()
            .unwrap_or("");
        let Ok(value) = token.parse::<f64>() else {
            return false;
        };
        if !value.is_finite() || value <= 0.0 || value > 100.0 {
            return false;
        }
        let amount_start = percent - token.len();
        let asset = policy.recipient_share_assets.iter().any(|asset| {
            text[..amount_start]
                .match_indices(asset.as_str())
                .any(|(start, _)| {
                    contains(&text[start..amount_start], asset) && amount_start - start <= 96
                })
        });
        if !asset {
            return false;
        }
        let rest = text[percent + 1..].trim_end_matches(|c: char| {
            c.is_whitespace() || matches!(c, '。' | '.' | '!' | '！' | '?' | '？')
        });
        let end = rest.floor_char_boundary(rest.len().min(192));
        let rest = &rest[..end];
        !rest.contains([',', '，', ';', '；', '\n', '。', '!', '！', '?', '？'])
            && policy
                .recipient_share_benefit_frames
                .iter()
                .any(|frame| contains(rest, frame))
            && policy
                .recipient_share_outcomes
                .iter()
                .any(|outcome| contains(rest, outcome))
    })
}

struct DeadlineCue {
    marker: String,
    requested: bool,
    third_party: bool,
    predicate: Option<String>,
}

/// A closed temporal slot sits between an obligation and its predicate.
/// Seeing “must” somewhere in a sentence cannot authorize an unrelated
/// later action. The caller retains subject/report/negation precedence.
fn deadline_obligation(
    text: &str,
    actions: &[String],
    policy: &ConstructionPolicy,
) -> Option<DeadlineCue> {
    let recipient = strip_policy_prefix(text, &policy.recipient_modal_subjects);
    let third_party = strip_policy_prefix(text, &policy.obligation_third_party_subjects);
    let text = recipient.or(third_party).unwrap_or(text);
    let marker = policy
        .deadline_obligation_markers
        .iter()
        .filter(|marker| {
            text.starts_with(marker.as_str()) && super::text::semantic_phrase_at(text, marker, 0)
        })
        .max_by_key(|marker| marker.len())?;
    let rest = text[marker.len()..].trim_start();
    let rest = if let Some(rest) = strip_policy_prefix(rest, &policy.deadline_time_openers) {
        rest
    } else if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || "零〇一二三四五六七八九十".contains(c))
        || policy
            .deadline_relative_times
            .iter()
            .any(|time| rest.starts_with(time.as_str()))
    {
        rest
    } else {
        return None;
    };
    let mut cue = DeadlineCue {
        marker: marker.clone(),
        requested: false,
        third_party: third_party.is_some(),
        predicate: None,
    };
    let boundary = policy
        .deadline_time_endings
        .iter()
        .flat_map(|ending| {
            rest.match_indices(ending.as_str())
                .map(move |(start, _)| (start, ending.len()))
        })
        .min_by_key(|(start, length)| (*start, std::cmp::Reverse(*length)));
    let Some((end, length)) = boundary else {
        return Some(cue);
    };
    let time = &rest[..end];
    if time.len() > 192 || time.contains([',', '，', ';', '；', '\n', '。', '!', '！', '?', '？'])
    {
        return Some(cue);
    }
    // An amount/unit bound such as “5000元内付款” is not a temporal
    // slot, so this parser must not revoke the ordinary obligation cue.
    if !bounded_time(time, policy) {
        return None;
    }
    let mut predicate = rest[end + length..].trim_start();
    for _ in 0..2 {
        let Some(rest) = strip_policy_prefix(predicate, &policy.recipient_modal_adverbs) else {
            break;
        };
        predicate = rest;
    }
    cue.predicate = actions
        .iter()
        .filter(|action| {
            predicate.strip_prefix(action.as_str()).is_some_and(|rest| {
                super::text::semantic_phrase_at(predicate, action, 0)
                    && !rest.trim_start().starts_with(['的', '了', '过', '過'])
            })
        })
        .max_by_key(|action| action.len())
        .cloned();
    cue.requested = cue.predicate.is_some() && !cue.third_party;
    Some(cue)
}

fn bounded_time(text: &str, policy: &ConstructionPolicy) -> bool {
    if policy
        .deadline_relative_times
        .iter()
        .any(|relative| contains(text, relative))
    {
        return true;
    }
    let digit = |c: char| c.is_ascii_digit() || "零〇一二三四五六七八九十".contains(c);
    let unit_time = policy.deadline_time_tokens.iter().any(|unit| {
        text.match_indices(unit.as_str()).any(|(start, _)| {
            let before = text[..start].chars().next_back().is_some_and(digit);
            let after = text[start + unit.len()..].chars().next().is_some_and(digit);
            before && (unit != ":" || after)
        })
    });
    let iso_date = text.as_bytes().windows(10).any(|window| {
        window[..4].iter().all(u8::is_ascii_digit)
            && matches!(window[4], b'-' | b'/')
            && window[5..7].iter().all(u8::is_ascii_digit)
            && window[7] == window[4]
            && window[8..].iter().all(u8::is_ascii_digit)
    });
    unit_time || iso_date
}

/// Recipient + an immediate/manner adverb + a predicate is a local command
/// even without a modal (“你直接加这个微信”). Habitual and past statements
/// and relative clauses do not satisfy this slot.
fn recipient_adverb_action(text: &str, actions: &[String], policy: &ConstructionPolicy) -> bool {
    let Some(rest) = strip_policy_prefix(text, &policy.recipient_modal_subjects) else {
        return false;
    };
    let Some(mut rest) = strip_policy_prefix(rest, &policy.recipient_directive_adverbs) else {
        return false;
    };
    if let Some(next) = strip_policy_prefix(rest, &policy.recipient_directive_adverbs)
        .or_else(|| strip_policy_prefix(rest, &policy.recipient_modal_adverbs))
    {
        rest = next;
    }
    let tail = rest.trim_end_matches(|c: char| {
        c.is_whitespace() || matches!(c, '。' | '.' | '!' | '！' | '?' | '？' | ':' | '：')
    });
    !tail.ends_with(['了', '过', '過'])
        && actions.iter().any(|action| {
            rest.strip_prefix(action.as_str()).is_some_and(|after| {
                super::text::semantic_phrase_at(rest, action, 0)
                    && !after.trim_start().starts_with(['的', '了', '过', '過'])
            })
        })
}

/// A predicate followed immediately by an instrumental communication
/// argument is a bounded request frame, rather than a list of all verb
/// prefixes. The target must also be a recognized claim object.
fn instrumental_request(
    text: &str,
    actions: &[String],
    objects: &[String],
    policy: &ConstructionPolicy,
) -> bool {
    actions.iter().any(|action| {
        let Some(rest) = text
            .strip_prefix(action.as_str())
            .filter(|_| super::text::semantic_phrase_at(text, action, 0))
        else {
            return false;
        };
        let Some(rest) =
            strip_policy_prefix(rest.trim_start(), &policy.instrumental_request_prepositions)
        else {
            return false;
        };
        policy
            .instrumental_communication_objects
            .iter()
            .any(|target| {
                if !objects.contains(target) {
                    return false;
                }
                let Some(after) = rest
                    .strip_prefix(target.as_str())
                    .filter(|_| super::text::semantic_phrase_at(rest, target, 0))
                else {
                    return false;
                };
                let after = after.trim_start_matches(|c: char| {
                    c.is_whitespace()
                        || matches!(c, '*' | '`' | ':' | '：' | '"' | '\'' | '“' | '”')
                });
                !policy.instrumental_completed_states.iter().any(|state| {
                    after.starts_with(state.as_str())
                        && super::text::semantic_phrase_at(after, state, 0)
                })
            })
    })
}

fn append_occurrences<'a>(
    text: &'a str,
    policy: &'a ConstructionPolicy,
) -> impl Iterator<Item = (usize, usize)> + 'a {
    policy
        .procedural_append_markers
        .iter()
        .flat_map(move |marker| {
            text.match_indices(marker.as_str())
                .filter_map(move |(at, _)| {
                    let before = text[..at].trim_end();
                    let framed = before.is_empty() || before.ends_with(['(', '（', ':', '：']);
                    if !framed || !super::text::semantic_phrase_at(text, marker, at) {
                        return None;
                    }
                    let nominal = policy
                        .procedural_append_nominals
                        .iter()
                        .any(|nominal| text[at..].starts_with(nominal.as_str()));
                    (!nominal).then_some((at, at + marker.len()))
                })
        })
}

fn procedural_append(text: &str, objects: &[String], policy: &ConstructionPolicy) -> bool {
    append_occurrences(text, policy).any(|(_, end)| {
        objects.iter().any(|object| {
            text[end..].match_indices(object.as_str()).any(|(gap, _)| {
                gap <= 48
                    && !text[end..end + gap].contains([',', '，', ';', '；', '。', '\n'])
                    && super::text::semantic_phrase_at(text, object, end + gap)
            })
        })
    })
}

/// A procedural parent authorizes only a deeper, contiguous channel/append
/// item, never an arbitrary following numbered step or a footer address.
/// The caller precomputes this once for each physical normalized line.
pub(super) fn procedural_list_field(text: &str, data: &CompiledSemanticData) -> bool {
    let snapshot = construction_policy(data);
    let Ok(policy) = snapshot.as_ref() else {
        return false;
    };
    if !policy.active() {
        return false;
    }
    if append_occurrences(text, policy).next().is_some() {
        return true;
    }
    policy.procedural_channel_labels.iter().any(|label| {
        text.strip_prefix(label.as_str()).is_some_and(|rest| {
            let Some(value) = rest.trim_start().strip_prefix([':', '：']) else {
                return false;
            };
            let email = value.split_whitespace().any(|token| {
                token
                    .split_once('@')
                    .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
            });
            email || value.bytes().filter(u8::is_ascii_digit).take(7).count() == 7
        })
    })
}

fn bare_modal_action(text: &str, actions: &[String], policy: &ConstructionPolicy) -> bool {
    let Some(mut rest) = strip_policy_prefix(text, &policy.recipient_obligation_modals) else {
        return false;
    };
    for _ in 0..2 {
        let Some(next) = strip_policy_prefix(rest, &policy.recipient_modal_adverbs) else {
            break;
        };
        rest = next;
    }
    actions.iter().any(|action| {
        rest.strip_prefix(action.as_str()).is_some_and(|tail| {
            super::text::semantic_phrase_at(rest, action, 0)
                && !tail.trim_start().starts_with(['的', '了', '过', '過'])
        })
    })
}

fn head_form_request(
    text: &str,
    actions: &[String],
    objects: &[String],
    policy: &ConstructionPolicy,
    data: &CompiledSemanticData,
) -> bool {
    let Some(action) = policy
        .head_form_instruction_actions
        .iter()
        .filter(|a| {
            actions.contains(a)
                && text.starts_with(a.as_str())
                && super::text::semantic_phrase_at(text, a, 0)
        })
        .max_by_key(|a| a.len())
    else {
        return false;
    };
    let Some(rest) = strip_policy_prefix(
        text[action.len()..].trim_start(),
        &policy.head_form_determiners,
    ) else {
        return false;
    };
    let Some(forms) = data
        .get_structured("semantic_workflow_policy_v1")
        .and_then(|p| p.get("financial_pin"))
        .and_then(|p| p.get("form_terms"))
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    forms
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|form| {
            let form = crate::modules::content_scan::normalize_text(&form.to_lowercase());
            objects.contains(&form)
                && rest.match_indices(form.as_str()).any(|(at, _)| {
                    if at > 96
                        || !super::text::semantic_phrase_at(rest, &form, at)
                        || rest[..at].contains([',', '，', ';', '；', '\n'])
                    {
                        return false;
                    }
                    let after = rest[at + form.len()..].trim_start_matches(|c: char| {
                        c.is_whitespace()
                            || matches!(c, '*' | '`' | ':' | '：' | '"' | '\'' | '“' | '”')
                    });
                    !policy.instrumental_completed_states.iter().any(|state| {
                        after.starts_with(state.as_str())
                            && super::text::semantic_phrase_at(after, state, 0)
                    })
                })
        })
}
