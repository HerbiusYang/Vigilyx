//! Existing native coercion and current-recipient secret-return relations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticActorRole, SemanticClaim, SemanticMessageContext, SemanticPolarity,
    SemanticQuoteStatus, SemanticSourcePart, SemanticSpeechAct, SemanticTargetRole,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::source::{ClaimWindowIndex, SemanticSource};
use super::text::{lowercase_view, normalized_lowercase_body, semantic_phrase_at};
use super::{is_current_recipient_action, semantic_phrase_present};

/// Provenance and relation flag for a subject-line threat paired with a
/// local body payment/consequence relation. Header offsets are never read as
/// body coordinates; only the header claim's own text is consulted.
pub(super) const CROSS_SOURCE_SUBJECT_THREAT: &str = "cross_source_subject_threat";
/// Upper bound on configured marker occurrences retained per claim and role.
const MAX_ROLE_OCCURRENCES: usize = 16;

fn default_max_relation_paragraph_breaks() -> usize {
    2
}

fn default_max_relation_envelope_bytes() -> usize {
    8192
}

fn default_nominal_payment_min_value_chars() -> usize {
    6
}

#[derive(Deserialize)]
struct SemanticExtortionPolicy {
    /// Legacy single-paragraph envelope. It remains a validated lower bound;
    /// `max_relation_envelope_bytes` is the effective three-claim envelope.
    max_relation_bytes: usize,
    sender_threats: Vec<String>,
    payment_actions: Vec<String>,
    consequences: Vec<String>,
    consequence_actions: Vec<String>,
    /// Paragraph breaks allowed between the earliest and latest body claim
    /// (2 = at most three consecutive paragraphs).
    #[serde(default = "default_max_relation_paragraph_breaks")]
    max_relation_paragraph_breaks: usize,
    #[serde(default = "default_max_relation_envelope_bytes")]
    max_relation_envelope_bytes: usize,
    /// Clause-initial payment labels admitted in nominal form only when
    /// followed by a configured separator and a value token, e.g.
    /// "付款地址：bc1q…" or "BTC address: bc1q…".
    #[serde(default)]
    nominal_payment_labels: Vec<String>,
    #[serde(default)]
    nominal_payment_separators: Vec<String>,
    #[serde(default = "default_nominal_payment_min_value_chars")]
    nominal_payment_min_value_chars: usize,
}

#[derive(Serialize)]
pub(super) struct ExtortionRelation {
    pub(super) source_part: SemanticSourcePart,
    pub(super) threat_claim: SemanticClaim,
    pub(super) payment_claim: SemanticClaim,
    pub(super) consequence_claim: SemanticClaim,
    pub(super) admission_rule: &'static str,
    /// The threat claim came from the subject (Header source); payment and
    /// consequence are local to each other in one body source.
    pub(super) cross_source_subject_threat: bool,
    /// Projection-independent key: a hash of the normalized texts of the
    /// three claims. Plain-text and HTML projections of the same relation
    /// share this key, so fusion counts the fact once.
    pub(super) causal_key: String,
}

/// Body text formatted as a reply or forward without envelope thread
/// evidence. Its claims carry content attribution and still count here: a
/// forged "original message" block must not exempt a coercion relation.
fn unverified_thread(claim: &SemanticClaim) -> bool {
    claim
        .provenance
        .iter()
        .any(|value| value == UNVERIFIED_THREAD_PROVENANCE)
}

/// Current-recipient action, treating an unverified thread claim as original.
fn relation_recipient_action(claim: &SemanticClaim) -> bool {
    if !unverified_thread(claim) {
        return is_current_recipient_action(claim);
    }
    let mut attributed = claim.clone();
    attributed.quote_or_forward_status = SemanticQuoteStatus::Original;
    is_current_recipient_action(&attributed)
}

fn original_assertion(claim: &SemanticClaim) -> bool {
    (claim.quote_or_forward_status == SemanticQuoteStatus::Original || unverified_thread(claim))
        && !matches!(
            claim.speech_act,
            SemanticSpeechAct::Quotation | SemanticSpeechAct::Report | SemanticSpeechAct::Warning
        )
        && claim.target_role != SemanticTargetRole::NamedThirdParty
        && !matches!(
            claim.actor_role,
            SemanticActorRole::QuotedAuthor
                | SemanticActorRole::Reporter
                | SemanticActorRole::System
        )
        && claim.counter_context_ids.is_empty()
}

/// Normalization and paragraph indexes shared by native relations and NLP
/// authority checks for one exact source projection.
pub(super) struct PreparedSemanticClaims<'a> {
    source: SemanticSource<'a>,
    context: &'a SemanticMessageContext,
    normalized: Vec<Option<String>>,
    /// Normalized subject text for Header claims only. Body offsets are never
    /// applied to these claims and these texts never enter body envelopes.
    header_normalized: Vec<Option<String>>,
    /// Merged, non-overlapping runs of blank-line paragraph separators.
    paragraph_breaks: Vec<(usize, usize)>,
}

#[cfg(test)]
pub(super) fn prepare_semantic_claims<'a>(
    source: SemanticSource<'a>,
    context: &'a SemanticMessageContext,
    budget: &SemanticCpuBudget,
) -> Result<PreparedSemanticClaims<'a>, String> {
    prepare_semantic_claims_with_header(source, None, context, budget)
}

pub(super) fn prepare_semantic_claims_with_header<'a>(
    source: SemanticSource<'a>,
    header: Option<SemanticSource<'a>>,
    context: &'a SemanticMessageContext,
    budget: &SemanticCpuBudget,
) -> Result<PreparedSemanticClaims<'a>, String> {
    let header = header.filter(|header| {
        header.part == SemanticSourcePart::Header && source.part != SemanticSourcePart::Header
    });
    let mut normalized = Vec::with_capacity(context.claims.len());
    let mut header_normalized = Vec::with_capacity(context.claims.len());
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("semantic relation preparation exceeded its wall-clock budget".into());
        }
        let text = source.claim_text(claim);
        if claim.source_part == source.part && text.is_none() {
            return Err("semantic relation claim has an invalid source span".into());
        }
        normalized.push(text.map(normalized_lowercase_body));
        header_normalized.push(
            header
                .filter(|_| claim.source_part == SemanticSourcePart::Header)
                .and_then(|header| header.claim_text(claim))
                .map(normalized_lowercase_body),
        );
    }
    let bytes = source.text.as_bytes();
    let mut paragraph_breaks: Vec<(usize, usize)> = Vec::new();
    for index in 0..bytes.len() {
        if index % 4096 == 0 && budget.exhausted() {
            return Err("semantic paragraph indexing exceeded its wall-clock budget".into());
        }
        let stop = if bytes[index..].starts_with(b"\n\n") {
            Some(index + 2)
        } else if bytes[index..].starts_with(b"\r\n\r\n") {
            Some(index + 4)
        } else {
            None
        };
        let Some(stop) = stop else {
            continue;
        };
        // A run of blank lines is one paragraph boundary, not several.
        match paragraph_breaks.last_mut() {
            Some((_, previous_stop)) if *previous_stop >= index => {
                *previous_stop = (*previous_stop).max(stop);
            }
            _ => paragraph_breaks.push((index, stop)),
        }
    }
    Ok(PreparedSemanticClaims {
        source,
        context,
        normalized,
        header_normalized,
        paragraph_breaks,
    })
}

impl PreparedSemanticClaims<'_> {
    fn paragraph_breaks_between(&self, begin: usize, end: usize) -> usize {
        let first = self
            .paragraph_breaks
            .partition_point(|(start, _)| *start < begin);
        self.paragraph_breaks[first..]
            .iter()
            .take_while(|(_, stop)| *stop <= end)
            .count()
    }

    /// All claims must belong to this body source; their joint envelope must
    /// fit the byte limit and span at most `max_breaks` paragraph breaks.
    fn body_envelope(&self, claims: &[usize], limit: usize, max_breaks: usize) -> bool {
        if claims.is_empty() || claims.iter().any(|index| self.normalized[*index].is_none()) {
            return false;
        }
        let begin = claims
            .iter()
            .map(|index| self.context.claims[*index].span.start_byte)
            .min()
            .unwrap_or(0);
        let end = claims
            .iter()
            .map(|index| self.context.claims[*index].span.end_byte)
            .max()
            .unwrap_or(0);
        end.saturating_sub(begin) <= limit
            && self.paragraph_breaks_between(begin, end) <= max_breaks
    }
}

/// Byte ranges (in the lowercase view of `text`) of configured phrase
/// occurrences, using the same token-boundary rule as `semantic_phrase_present`.
fn phrase_ranges(text: &str, phrases: &[String], ranges: &mut Vec<(usize, usize)>) {
    let text = lowercase_view(text);
    for phrase in phrases {
        let phrase = lowercase_view(phrase);
        if phrase.is_empty() {
            continue;
        }
        for (offset, _) in text.match_indices(&*phrase) {
            if ranges.len() >= MAX_ROLE_OCCURRENCES {
                return;
            }
            if semantic_phrase_at(&text, &phrase, offset) {
                ranges.push((offset, offset + phrase.len()));
            }
        }
    }
}

fn disjoint(left: (usize, usize), right: (usize, usize)) -> bool {
    left.1 <= right.0 || right.1 <= left.0
}

fn distinct_role_occurrences(
    groups: &[&[(usize, usize)]],
    chosen: &mut Vec<(usize, usize)>,
) -> bool {
    let Some((first, rest)) = groups.split_first() else {
        return true;
    };
    for range in *first {
        if chosen.iter().all(|other| disjoint(*range, *other)) {
            chosen.push(*range);
            if distinct_role_occurrences(rest, chosen) {
                return true;
            }
            chosen.pop();
        }
    }
    false
}

/// One claim may fill several roles only when its text holds a distinct,
/// non-overlapping configured marker occurrence for every role it fills.
/// The same words can therefore never count twice.
fn shared_claim_roles_are_distinct(roles: &[(usize, &[(usize, usize)])]) -> bool {
    roles.iter().all(|(claim, _)| {
        let groups = roles
            .iter()
            .filter(|(other, _)| other == claim)
            .map(|(_, ranges)| *ranges)
            .collect::<Vec<_>>();
        groups.len() < 2 || distinct_role_occurrences(&groups, &mut Vec::new())
    })
}

/// A threat needs a sextortion threat signal attributed to the sender: an
/// explicit first-person sender assertion, or a configured sender-threat
/// phrase. The two lexicons no longer need to hit the same claim together.
fn sender_threat_occurrences(
    claim: &SemanticClaim,
    text: &str,
    policy: &SemanticExtortionPolicy,
    threat_signals: &[String],
) -> Option<Vec<(usize, usize)>> {
    let mut occurrences = Vec::new();
    phrase_ranges(text, threat_signals, &mut occurrences);
    if occurrences.is_empty() {
        return None;
    }
    let mut sender_phrases = Vec::new();
    phrase_ranges(text, &policy.sender_threats, &mut sender_phrases);
    let first_person_assertion = matches!(
        claim.actor_role,
        SemanticActorRole::Sender | SemanticActorRole::AuthenticatedSender
    ) && claim.speech_act == SemanticSpeechAct::Notice;
    if !first_person_assertion && sender_phrases.is_empty() {
        return None;
    }
    occurrences.extend(sender_phrases);
    Some(occurrences)
}

/// Conservative nominal payment line: an original, non-negated claim whose
/// text starts with a configured payment label, then a configured separator,
/// then a value token with enough alphanumeric characters.
fn nominal_payment_label(
    claim: &SemanticClaim,
    text: &str,
    policy: &SemanticExtortionPolicy,
) -> Option<(usize, usize)> {
    if !original_assertion(claim) || claim.polarity == SemanticPolarity::AntiAction {
        return None;
    }
    let text = lowercase_view(text);
    let line = text.trim_start();
    let lead = text.len() - line.len();
    for label in &policy.nominal_payment_labels {
        let label = lowercase_view(label);
        if label.is_empty() || !line.starts_with(&*label) || !semantic_phrase_at(line, &label, 0) {
            continue;
        }
        let rest = line[label.len()..].trim_start();
        for separator in &policy.nominal_payment_separators {
            if separator.is_empty() {
                continue;
            }
            let Some(value) = rest.strip_prefix(separator.as_str()) else {
                continue;
            };
            let value_chars = value
                .trim_start()
                .chars()
                .take_while(|character| !character.is_whitespace())
                .filter(|character| character.is_alphanumeric())
                .count();
            if value_chars >= policy.nominal_payment_min_value_chars {
                return Some((lead, lead + label.len()));
            }
        }
    }
    None
}

/// Payment: a current-recipient Request/Instruction with a payment action, or
/// a nominal payment line. Both require a configured payment signal.
fn payment_occurrences(
    claim: &SemanticClaim,
    text: &str,
    policy: &SemanticExtortionPolicy,
    payment_signals: &[String],
) -> Option<Vec<(usize, usize)>> {
    let mut occurrences = Vec::new();
    phrase_ranges(text, payment_signals, &mut occurrences);
    if occurrences.is_empty() {
        return None;
    }
    if relation_recipient_action(claim) {
        let mut actions = Vec::new();
        phrase_ranges(text, &policy.payment_actions, &mut actions);
        if !actions.is_empty() {
            occurrences.extend(actions);
            return Some(occurrences);
        }
    }
    let label = nominal_payment_label(claim, text, policy)?;
    occurrences.push(label);
    Some(occurrences)
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn relation_causal_key(threat: &str, payment: &str, consequence: &str) -> String {
    let tuple = format!(
        "extortion_relation_v3\u{1f}{}\u{1f}{}\u{1f}{}",
        collapse_whitespace(threat),
        collapse_whitespace(payment),
        collapse_whitespace(consequence)
    );
    format!(
        "body_relation:{}",
        hex::encode(Sha256::digest(tuple.as_bytes()))
    )
}

#[cfg(test)]
pub(super) fn qualified_extortion_relations(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<ExtortionRelation>, String> {
    let prepared = prepare_semantic_claims(source, context, budget)?;
    qualified_extortion_relations_prepared(&prepared, budget, data)
}

#[cfg(test)]
pub(super) fn qualified_extortion_relations_with_header(
    source: SemanticSource<'_>,
    header: Option<SemanticSource<'_>>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<ExtortionRelation>, String> {
    let prepared = prepare_semantic_claims_with_header(source, header, context, budget)?;
    qualified_extortion_relations_prepared(&prepared, budget, data)
}

/// Preserve original claim order after narrowing candidates by position.
/// Body claims must share one source, fit one envelope and span at most the
/// configured number of paragraph breaks. Only the threat may come from the
/// subject, and only when no same-source body threat qualifies.
pub(super) fn qualified_extortion_relations_prepared(
    prepared: &PreparedSemanticClaims<'_>,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<ExtortionRelation>, String> {
    let policy = data.cached("semantic_extortion_policy_v2", |registry| {
        registry
            .get_structured("semantic_extortion_policy_v2")
            .cloned()
            .and_then(|value| serde_json::from_value::<SemanticExtortionPolicy>(value).ok())
            .filter(|policy| {
                policy.max_relation_bytes > 0
                    && policy.max_relation_bytes <= 4096
                    && policy.max_relation_envelope_bytes >= policy.max_relation_bytes
                    && policy.max_relation_envelope_bytes <= 16384
                    && policy.max_relation_paragraph_breaks <= 4
                    && policy.nominal_payment_min_value_chars > 0
                    && !policy.sender_threats.is_empty()
                    && !policy.payment_actions.is_empty()
                    && !policy.consequences.is_empty()
                    && !policy.consequence_actions.is_empty()
                    && policy
                        .nominal_payment_labels
                        .iter()
                        .chain(&policy.nominal_payment_separators)
                        .all(|value| !value.trim().is_empty())
            })
    });
    let policy = policy
        .as_ref()
        .as_ref()
        .ok_or_else(|| "semantic extortion admission policy is missing or invalid".to_string())?;
    let threat_signals = data.get_list("sextortion_threat_signals");
    if threat_signals.iter().all(|signal| signal.trim().is_empty()) {
        return Err(
            "semantic extortion threat signal list (sextortion_threat_signals) is missing or empty"
                .into(),
        );
    }
    let payment_signals = data.get_list("sextortion_payment_signals");
    if payment_signals
        .iter()
        .all(|signal| signal.trim().is_empty())
    {
        return Err("semantic extortion payment signal list (sextortion_payment_signals) is missing or empty".into());
    }
    let limit = policy
        .max_relation_envelope_bytes
        .max(policy.max_relation_bytes);
    let max_breaks = policy.max_relation_paragraph_breaks;
    let context = prepared.context;
    let claim_count = context.claims.len();
    let mut threat_ranges: Vec<Vec<(usize, usize)>> = vec![Vec::new(); claim_count];
    let mut consequence_ranges: Vec<Vec<(usize, usize)>> = vec![Vec::new(); claim_count];
    let mut body_threats = Vec::new();
    let mut header_threats = Vec::new();
    let mut consequences = Vec::new();
    for (index, claim) in context.claims.iter().enumerate() {
        if budget.exhausted() {
            return Err("semantic rule inspection exceeded its wall-clock budget".into());
        }
        if !original_assertion(claim) {
            continue;
        }
        if let Some(text) = prepared.normalized[index].as_deref() {
            if let Some(ranges) = sender_threat_occurrences(claim, text, policy, threat_signals) {
                threat_ranges[index] = ranges;
                body_threats.push(index);
            }
            let mut ranges = Vec::new();
            phrase_ranges(text, &policy.consequences, &mut ranges);
            phrase_ranges(text, &policy.consequence_actions, &mut ranges);
            if !ranges.is_empty() {
                consequence_ranges[index] = ranges;
                consequences.push(index);
            }
        } else if let Some(text) = prepared.header_normalized[index].as_deref()
            && sender_threat_occurrences(claim, text, policy, threat_signals).is_some()
        {
            header_threats.push(index);
        }
    }
    let threat_index = ClaimWindowIndex::new(
        body_threats
            .iter()
            .map(|index| (*index, context.claims[*index].span)),
    );
    let consequence_index = ClaimWindowIndex::new(
        consequences
            .iter()
            .map(|index| (*index, context.claims[*index].span)),
    );
    let mut admitted = Vec::new();
    for (index, payment) in context.claims.iter().enumerate() {
        if budget.exhausted() {
            return Err("semantic rule inspection exceeded its wall-clock budget".into());
        }
        let Some(text) = prepared.normalized[index].as_deref() else {
            continue;
        };
        let Some(payment_ranges) = payment_occurrences(payment, text, policy, payment_signals)
        else {
            continue;
        };
        let nearby_threats = threat_index.within_envelope(payment.span, limit);
        let nearby_consequences = consequence_index.within_envelope(payment.span, limit);
        let mut relation = None;
        let mut inspected = 0usize;
        'search: for threat in &nearby_threats {
            if !prepared.body_envelope(&[index, *threat], limit, max_breaks) {
                continue;
            }
            for consequence in &nearby_consequences {
                if inspected.is_multiple_of(32) && budget.exhausted() {
                    return Err("semantic rule inspection exceeded its wall-clock budget".into());
                }
                inspected += 1;
                if prepared.body_envelope(&[index, *threat, *consequence], limit, max_breaks)
                    && shared_claim_roles_are_distinct(&[
                        (*threat, threat_ranges[*threat].as_slice()),
                        (index, payment_ranges.as_slice()),
                        (*consequence, consequence_ranges[*consequence].as_slice()),
                    ])
                {
                    relation = Some((*threat, *consequence, false));
                    break 'search;
                }
            }
        }
        if relation.is_none()
            && let Some(header_threat) = header_threats.first().copied()
        {
            for consequence in &nearby_consequences {
                if inspected.is_multiple_of(32) && budget.exhausted() {
                    return Err("semantic rule inspection exceeded its wall-clock budget".into());
                }
                inspected += 1;
                if prepared.body_envelope(&[index, *consequence], limit, max_breaks)
                    && shared_claim_roles_are_distinct(&[
                        (index, payment_ranges.as_slice()),
                        (*consequence, consequence_ranges[*consequence].as_slice()),
                    ])
                {
                    relation = Some((header_threat, *consequence, true));
                    break;
                }
            }
        }
        if let Some((threat, consequence, cross_source)) = relation {
            let threat_text = if cross_source {
                prepared.header_normalized[threat].as_deref()
            } else {
                prepared.normalized[threat].as_deref()
            }
            .unwrap_or_default();
            let consequence_text = prepared.normalized[consequence]
                .as_deref()
                .unwrap_or_default();
            let mut qualified_threat = context.claims[threat].clone();
            qualified_threat.actor_role = SemanticActorRole::Sender;
            qualified_threat.target_role = SemanticTargetRole::Recipient;
            qualified_threat.speech_act = SemanticSpeechAct::Notice;
            qualified_threat.polarity = SemanticPolarity::Neutral;
            qualified_threat
                .provenance
                .push("sender_threat_assertion_policy_v2".to_string());
            if cross_source {
                qualified_threat
                    .provenance
                    .push(CROSS_SOURCE_SUBJECT_THREAT.to_string());
            }
            admitted.push(ExtortionRelation {
                source_part: prepared.source.part,
                causal_key: relation_causal_key(threat_text, text, consequence_text),
                threat_claim: qualified_threat,
                payment_claim: payment.clone(),
                consequence_claim: context.claims[consequence].clone(),
                admission_rule: if cross_source {
                    "subject_threat_body_payment_coercion_v1"
                } else {
                    "sender_threat_current_payment_coercion_v2"
                },
                cross_source_subject_threat: cross_source,
            });
        }
    }
    Ok(admitted)
}

#[derive(Deserialize)]
struct SemanticNlpAuthorityPolicy {
    actions_any: Vec<String>,
    objects_any: Vec<String>,
    sender_return_targets: Vec<String>,
}

#[cfg(test)]
pub(super) fn qualified_nlp_authorities(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<SemanticClaim>, String> {
    let prepared = prepare_semantic_claims(source, context, budget)?;
    qualified_nlp_authorities_prepared(&prepared, budget, data)
}

pub(super) fn qualified_nlp_authorities_prepared(
    prepared: &PreparedSemanticClaims<'_>,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<SemanticClaim>, String> {
    let policy = data.cached("semantic_nlp_authority_policy_v2", |registry| {
        registry
            .get_structured("semantic_nlp_authority_policy_v2")
            .cloned()
            .and_then(|value| serde_json::from_value::<SemanticNlpAuthorityPolicy>(value).ok())
            .filter(|policy| {
                !policy.actions_any.is_empty()
                    && !policy.objects_any.is_empty()
                    && !policy.sender_return_targets.is_empty()
            })
    });
    let policy = policy
        .as_ref()
        .as_ref()
        .ok_or_else(|| "NLP semantic authority policy is missing or invalid".to_string())?;
    let mut authorities = Vec::new();
    for (index, claim) in prepared.context.claims.iter().enumerate() {
        if budget.exhausted() {
            return Err("NLP semantic authority inspection exceeded its wall-clock budget".into());
        }
        if !is_current_recipient_action(claim) {
            continue;
        }
        let Some(text) = prepared.normalized[index].as_deref() else {
            continue;
        };
        if policy
            .actions_any
            .iter()
            .any(|phrase| claim.actions.iter().any(|action| action == phrase))
            && policy
                .objects_any
                .iter()
                .any(|phrase| claim.objects.iter().any(|object| object == phrase))
            && policy
                .sender_return_targets
                .iter()
                .any(|phrase| semantic_phrase_present(text, phrase))
        {
            let mut authority = claim.clone();
            authority
                .provenance
                .push("current_recipient_secret_return_policy_v2".to_string());
            authorities.push(authority);
        }
    }
    Ok(authorities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_claim_fills_several_roles_only_with_distinct_marker_occurrences() {
        // Payment ("send", "bitcoin") and consequence ("or i", "share") occupy
        // different bytes of one claim: the claim may fill both roles.
        let payment = [(0, 4), (5, 12)];
        let consequence = [(26, 30), (31, 36)];
        assert!(shared_claim_roles_are_distinct(&[
            (1, payment.as_slice()),
            (1, consequence.as_slice()),
        ]));

        // A single word cannot satisfy two roles of the same claim.
        let only = [(0, 4)];
        assert!(!shared_claim_roles_are_distinct(&[
            (1, only.as_slice()),
            (1, only.as_slice()),
        ]));

        // Three roles in one claim need three pairwise disjoint occurrences.
        let threat = [(0, 10)];
        let overlapping_payment = [(5, 12)];
        assert!(!shared_claim_roles_are_distinct(&[
            (2, threat.as_slice()),
            (2, overlapping_payment.as_slice()),
            (2, consequence.as_slice()),
        ]));

        // Different claims never compete for occurrences.
        assert!(shared_claim_roles_are_distinct(&[
            (1, only.as_slice()),
            (2, only.as_slice()),
        ]));
    }

    #[test]
    fn paragraph_break_runs_count_once() {
        let body = "a\n\n\n\nb\r\n\r\n\r\nc";
        let context = SemanticMessageContext::default();
        let prepared = prepare_semantic_claims(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
        )
        .unwrap();
        assert_eq!(prepared.paragraph_breaks.len(), 2);
        assert_eq!(prepared.paragraph_breaks_between(0, body.len()), 2);
    }
}
