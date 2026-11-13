//! Bounded semantic work flows. Nodes carry attributed source claims; a
//! relation, rather than the number of matched words, admits one causal vote.

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticActorRole, SemanticClaim, SemanticMessageContext, SemanticPolarity,
    SemanticQuoteStatus, SemanticSourcePart, SemanticSpeechAct,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::is_current_recipient_action;
use super::solicitation::NativeSolicitationFinding;
use super::source::SemanticSource;
use super::text::{normalized_lowercase_body, semantic_phrase_at};

#[path = "workflow_collection.rs"]
mod collection;

#[derive(Default)]
pub(super) struct WorkflowAnalysis {
    pub(super) findings: Vec<NativeSolicitationFinding>,
    pub(super) diagnostics: Vec<Value>,
}

#[derive(Deserialize)]
struct WorkflowPolicy {
    enabled: bool,
    max_relation_bytes: usize,
    max_paragraph_boundaries: usize,
    inheritance: InheritancePolicy,
    financial_pin: FinancialPinPolicy,
}

#[derive(Deserialize)]
struct InheritancePolicy {
    score: f64,
    asset_terms: Vec<String>,
    deceased_terms: Vec<String>,
    third_party_terms: Vec<String>,
    no_heir_terms: Vec<String>,
    kinship_terms: Vec<String>,
    totality_terms: Vec<String>,
    non_totality_terms: Vec<String>,
    assignment_terms: Vec<String>,
    recipient_terms: Vec<String>,
    share_terms: Vec<String>,
    share_recipient_terms: Vec<String>,
    estate_reference_terms: Vec<String>,
    benefit_asset_terms: Vec<String>,
    benefit_transfer_terms: Vec<String>,
    benefit_recipient_terms: Vec<String>,
    account_terms: Vec<String>,
    other_asset_terms: Vec<String>,
    arbitrary_selection_terms: Vec<String>,
    selection_terms: Vec<String>,
    genuine_kinship_terms: Vec<String>,
    excluded_kinship_prefixes: Vec<String>,
    negated_death_prefixes: Vec<String>,
    estate_topic_terms: Vec<String>,
    unrelated_recipient_terms: Vec<String>,
    non_asset_topic_suffixes: Vec<String>,
    assumed_kinship_terms: Vec<String>,
    kinship_proxy_suffixes: Vec<String>,
    owner_introduction_terms: Vec<String>,
    cooperation_actions: Vec<String>,
    relationship_proof_terms: Vec<String>,
    proof_actions: Vec<String>,
    explicit_fabrication_terms: Vec<String>,
    completed_assignment_prefixes: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct FinancialPinPolicy {
    score: f64,
    max_form_bytes: usize,
    max_form_items: usize,
    pin_terms: Vec<String>,
    #[serde(default)]
    generic_pin_terms: Vec<String>,
    #[serde(default)]
    financial_pin_qualifiers: Vec<String>,
    #[serde(default)]
    implicit_remote_list_actions: Vec<String>,
    #[serde(default)]
    physical_collection_targets: Vec<String>,
    identity_terms: Vec<String>,
    otp_terms: Vec<String>,
    input_actions: Vec<String>,
    remote_channel_terms: Vec<String>,
    form_terms: Vec<String>,
    new_pin_terms: Vec<String>,
    existing_pin_terms: Vec<String>,
    pin_modifier_terms: Vec<String>,
    separate_collection_terms: Vec<String>,
    field_descriptor_actions: Vec<String>,
    nominal_state_predicates: Vec<String>,
    target_prepositions: Vec<String>,
    target_argument_modifiers: Vec<String>,
    #[serde(default)]
    preposed_target_prepositions: Vec<String>,
}

fn bounded(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 96
        && values
            .iter()
            .all(|s| !s.trim().is_empty() && s.len() <= 128)
}

impl WorkflowPolicy {
    fn valid(&self) -> bool {
        let i = &self.inheritance;
        let p = &self.financial_pin;
        (512..=8192).contains(&self.max_relation_bytes)
            && p.preposed_target_prepositions.len() <= 96
            && p.preposed_target_prepositions
                .iter()
                .all(|term| !term.trim().is_empty() && term.len() <= 128)
            && [
                &p.generic_pin_terms,
                &p.financial_pin_qualifiers,
                &p.implicit_remote_list_actions,
                &p.physical_collection_targets,
            ]
            .iter()
            .all(|terms| {
                terms.len() <= 96
                    && terms.iter().all(|term| {
                        !normalized_lowercase_body(term).trim().is_empty() && term.len() <= 128
                    })
            })
            && self.max_paragraph_boundaries <= 4
            && (128..=2048).contains(&p.max_form_bytes)
            && (1..=16).contains(&p.max_form_items)
            && [i.score, p.score]
                .iter()
                .all(|score| score.is_finite() && (0.15..=0.39).contains(score))
            && [
                &i.asset_terms,
                &i.deceased_terms,
                &i.third_party_terms,
                &i.no_heir_terms,
                &i.kinship_terms,
                &i.totality_terms,
                &i.non_totality_terms,
                &i.assignment_terms,
                &i.recipient_terms,
                &i.share_terms,
                &i.share_recipient_terms,
                &i.cooperation_actions,
                &i.estate_reference_terms,
                &i.benefit_asset_terms,
                &i.benefit_transfer_terms,
                &i.benefit_recipient_terms,
                &i.account_terms,
                &i.other_asset_terms,
                &i.arbitrary_selection_terms,
                &i.selection_terms,
                &i.genuine_kinship_terms,
                &i.excluded_kinship_prefixes,
                &i.negated_death_prefixes,
                &i.estate_topic_terms,
                &i.unrelated_recipient_terms,
                &i.non_asset_topic_suffixes,
                &i.assumed_kinship_terms,
                &i.kinship_proxy_suffixes,
                &i.owner_introduction_terms,
                &i.relationship_proof_terms,
                &i.proof_actions,
                &i.explicit_fabrication_terms,
                &i.completed_assignment_prefixes,
                &p.pin_terms,
                &p.identity_terms,
                &p.otp_terms,
                &p.input_actions,
                &p.remote_channel_terms,
                &p.form_terms,
                &p.new_pin_terms,
                &p.existing_pin_terms,
                &p.pin_modifier_terms,
                &p.separate_collection_terms,
                &p.field_descriptor_actions,
                &p.nominal_state_predicates,
                &p.target_prepositions,
                &p.target_argument_modifiers,
            ]
            .iter()
            .all(|values| bounded(values))
    }
}

struct Fact<'a> {
    claim: &'a SemanticClaim,
    text: String,
}

fn has(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str())
            .any(|(offset, _)| semantic_phrase_at(text, term, offset))
    })
}

fn eligible(claim: &SemanticClaim) -> bool {
    (claim.quote_or_forward_status == SemanticQuoteStatus::Original || unverified_thread(claim))
        && !matches!(
            claim.speech_act,
            SemanticSpeechAct::Report | SemanticSpeechAct::Warning | SemanticSpeechAct::Quotation
        )
        && !matches!(
            claim.actor_role,
            SemanticActorRole::QuotedAuthor
                | SemanticActorRole::Reporter
                | SemanticActorRole::System
        )
        && claim.polarity != SemanticPolarity::AntiAction
        && claim.counter_context_ids.is_empty()
}

fn unverified_thread(claim: &SemanticClaim) -> bool {
    claim
        .provenance
        .iter()
        .any(|s| s == UNVERIFIED_THREAD_PROVENANCE)
}

fn recipient_action(claim: &SemanticClaim) -> bool {
    if !unverified_thread(claim) {
        return is_current_recipient_action(claim);
    }
    let mut attributed = claim.clone();
    attributed.quote_or_forward_status = SemanticQuoteStatus::Original;
    is_current_recipient_action(&attributed)
}

fn action_any(claim: &SemanticClaim, actions: &[String]) -> bool {
    claim.actions.iter().any(|a| actions.contains(a))
}

fn paragraph_count(text: &str) -> usize {
    let mut blank = false;
    text.lines()
        .filter(|line| {
            let was_blank = blank;
            blank = line.trim().is_empty();
            blank && !was_blank
        })
        .count()
}

fn envelope(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[&Fact<'_>],
    bytes: usize,
    paragraphs: usize,
) -> bool {
    let start = facts
        .iter()
        .map(|f| f.claim.span.start_byte)
        .min()
        .unwrap_or(0);
    let end = facts
        .iter()
        .map(|f| f.claim.span.end_byte)
        .max()
        .unwrap_or(0);
    if end.saturating_sub(start) > bytes {
        return false;
    }
    let Some(text) = source.text.get(start..end) else {
        return false;
    };
    if paragraph_count(text) > paragraphs {
        return false;
    }
    // HTML siblings are separate containers, even when their projected text
    // happens to be adjacent. Plain text may carry an explicit multi-step flow.
    if source.part != SemanticSourcePart::PlainText
        && facts.iter().any(|f| {
            f.claim.source_block_id.is_none()
                || f.claim.source_block_id != facts[0].claim.source_block_id
        })
    {
        return false;
    }
    !context.claims.iter().any(|claim| {
        claim.source_part == source.part
            && claim.span.start_byte < end
            && start < claim.span.end_byte
            && !eligible(claim)
    })
}

fn key(kind: &str, nodes: &[&Fact<'_>]) -> String {
    let value = nodes
        .iter()
        .map(|f| f.text.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\u{1f}");
    format!(
        "body_relation:{kind}:{}",
        hex::encode(Sha256::digest(value.as_bytes()))
    )
}

fn finding(
    anchor: &Fact<'_>,
    supports: &[&Fact<'_>],
    rule: &'static str,
    category: &str,
    score: f64,
    causal_key: String,
) -> NativeSolicitationFinding {
    let mut supporting_claims = Vec::new();
    for fact in supports {
        if fact.claim.source_span_id != anchor.claim.source_span_id
            && !supporting_claims
                .iter()
                .any(|c: &SemanticClaim| c.source_span_id == fact.claim.source_span_id)
        {
            supporting_claims.push(fact.claim.clone());
        }
    }
    NativeSolicitationFinding {
        source_part: anchor.claim.source_part,
        claim: anchor.claim.clone(),
        supporting_claims,
        admission_rule: rule,
        category: category.into(),
        score,
        causal_key,
    }
}

fn node(role: &str, fact: &Fact<'_>) -> Value {
    json!({"role": role, "claim_id": fact.claim.source_span_id,
        "source_part": fact.claim.source_part, "span": fact.claim.span})
}

fn percentage(text: &str) -> bool {
    text.match_indices('%').any(|(at, _)| {
        let digits = text[..at]
            .trim_end()
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .take(8)
            .collect::<String>();
        let value = digits
            .chars()
            .rev()
            .collect::<String>()
            .parse::<f64>()
            .unwrap_or(0.0);
        value > 0.0 && value < 100.0
    })
}

const ESTATE: u8 = 1;
const ELIGIBILITY_CONFLICT: u8 = 2;
const ASSUMED_ROLE: u8 = 4;
const BENEFIT: u8 = 8;
const COOPERATE: u8 = 16;
const INHERITANCE_ALL: u8 = ESTATE | ELIGIBILITY_CONFLICT | ASSUMED_ROLE | BENEFIT | COOPERATE;
const ROLE_NAMES: [(u8, &str); 5] = [
    (ESTATE, "third_party_deceased_estate"),
    (ELIGIBILITY_CONFLICT, "kinship_eligibility_conflict"),
    (ASSUMED_ROLE, "recipient_assumes_kinship"),
    (BENEFIT, "recipient_estate_benefit"),
    (COOPERATE, "current_recipient_cooperation"),
];

fn assignment(text: &str, policy: &InheritancePolicy) -> bool {
    policy.assignment_terms.iter().any(|verb| {
        text.match_indices(verb.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, verb, at) {
                return false;
            }
            let before = text[..at].trim_end();
            if policy
                .completed_assignment_prefixes
                .iter()
                .any(|prefix| before.ends_with(prefix.as_str()))
            {
                return false;
            }
            let after = &text[at + verb.len()..];
            policy.assumed_kinship_terms.iter().any(|role| {
                after.match_indices(role.as_str()).any(|(gap, _)| {
                    gap <= 96
                        && semantic_phrase_at(after, role, gap)
                        && !policy
                            .excluded_kinship_prefixes
                            .iter()
                            .any(|prefix| after[..gap].trim_end().ends_with(prefix.as_str()))
                        && !policy.kinship_proxy_suffixes.iter().any(|suffix| {
                            let tail = after[gap + role.len()..].trim_start();
                            tail.starts_with(suffix.as_str()) && semantic_phrase_at(tail, suffix, 0)
                        })
                })
            })
        })
    })
}

fn no_surviving_heir(text: &str, policy: &InheritancePolicy) -> bool {
    if has(text, &policy.no_heir_terms) {
        return true;
    }
    policy.kinship_terms.iter().any(|kin| {
        text.match_indices(kin.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, kin, at) {
                return false;
            }
            let before = &text[..at];
            let mut start = before.len().saturating_sub(48);
            while !before.is_char_boundary(start) {
                start += 1;
            }
            let before = &before[start..];
            if has(before, &policy.non_totality_terms) {
                return false;
            }
            let after = &text[at + kin.len()..];
            policy.deceased_terms.iter().any(|death| {
                after.match_indices(death.as_str()).any(|(gap, _)| {
                    gap <= 96
                        && semantic_phrase_at(after, death, gap)
                        && (has(before, &policy.totality_terms)
                            || has(&after[..gap], &policy.totality_terms))
                        && !has(&after[..gap], &policy.non_totality_terms)
                        && !after[..gap]
                            .chars()
                            .any(|c| matches!(c, ',' | '，' | ';' | '；' | '。' | '.' | '\n'))
                        && !policy
                            .negated_death_prefixes
                            .iter()
                            .any(|prefix| after[..gap].trim_end().ends_with(prefix.as_str()))
                })
            })
        })
    })
}

fn deceased_assertion(text: &str, policy: &InheritancePolicy) -> bool {
    policy.deceased_terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            semantic_phrase_at(text, term, at)
                && !policy
                    .negated_death_prefixes
                    .iter()
                    .any(|prefix| text[..at].trim_end().ends_with(prefix.as_str()))
        })
    })
}

fn inheritance_roles(fact: &Fact<'_>, policy: &InheritancePolicy) -> u8 {
    if !eligible(fact.claim) {
        return 0;
    }
    let text = &fact.text;
    let mut roles = 0;
    if has(text, &policy.asset_terms)
        && deceased_assertion(text, policy)
        && has(text, &policy.third_party_terms)
    {
        roles |= ESTATE;
    }
    if no_surviving_heir(text, policy)
        || (has(text, &policy.unrelated_recipient_terms) && has(text, &policy.recipient_terms))
    {
        roles |= ELIGIBILITY_CONFLICT;
    }
    if assignment(text, policy)
        && (has(text, &policy.recipient_terms) || recipient_action(fact.claim))
    {
        roles |= ASSUMED_ROLE;
    }
    if (has(text, &policy.share_terms)
        || fact
            .claim
            .provenance
            .iter()
            .any(|s| s == "semantic_construction_recipient_share_notice_v1"))
        && has(text, &policy.share_recipient_terms)
        && percentage(text)
    {
        roles |= BENEFIT;
    }
    if recipient_action(fact.claim) && action_any(fact.claim, &policy.cooperation_actions) {
        roles |= COOPERATE;
    }
    roles
}

fn estate_topic(text: &str, policy: &InheritancePolicy) -> bool {
    policy.estate_topic_terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            semantic_phrase_at(text, term, at)
                && !policy.non_asset_topic_suffixes.iter().any(|suffix| {
                    let after = text[at + term.len()..].trim_start();
                    after.starts_with(suffix.as_str()) && semantic_phrase_at(after, suffix, 0)
                })
        })
    })
}

fn recipient_estate_control(text: &str, policy: &InheritancePolicy, single_estate: bool) -> bool {
    if has(text, &policy.other_asset_terms) {
        return false;
    }
    policy.benefit_transfer_terms.iter().any(|transfer| {
        text.match_indices(transfer.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, transfer, at) {
                return false;
            }
            let before = &text[..at];
            let mut start = before.len().saturating_sub(128);
            while !before.is_char_boundary(start) {
                start += 1;
            }
            let before = &before[start..];
            // Strong demonstratives bind an explicitly mentioned estate.
            // A bare “资金” may refer back only to a single estate topic;
            // multiple asset owners cannot silently supply one another.
            let after = &text[at + transfer.len()..];
            policy.benefit_recipient_terms.iter().any(|recipient| {
                after.match_indices(recipient.as_str()).any(|(gap, _)| {
                    if gap > 48 || !semantic_phrase_at(after, recipient, gap) {
                        return false;
                    }
                    let object_after_verb = &after[..gap];
                    if !has(before, &policy.estate_reference_terms)
                        && !has(object_after_verb, &policy.estate_reference_terms)
                        && !(single_estate
                            && (has(before, &policy.benefit_asset_terms)
                                || has(object_after_verb, &policy.benefit_asset_terms)))
                    {
                        return false;
                    }
                    let destination = &after[gap + recipient.len()..];
                    policy.account_terms.iter().any(|account| {
                        destination
                            .match_indices(account.as_str())
                            .any(|(account_gap, _)| {
                                account_gap <= 96
                                    && semantic_phrase_at(destination, account, account_gap)
                                    && !destination[..account_gap].chars().any(|c| {
                                        matches!(c, ',' | '，' | ';' | '；' | '。' | '.' | '\n')
                                    })
                            })
                    })
                })
            })
        })
    })
}

fn analyze_inheritance(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    budget: &SemanticCpuBudget,
    policy: &WorkflowPolicy,
    result: &mut WorkflowAnalysis,
) -> Result<(), String> {
    let p = &policy.inheritance;
    let mut tagged = Vec::new();
    for fact in facts {
        if budget.exhausted() {
            return Err("inheritance workflow node extraction exceeded its CPU budget".into());
        }
        let roles = inheritance_roles(fact, p);
        if roles != 0 {
            tagged.push((fact, roles));
        }
    }
    let mut estate_bindings = Vec::new();
    if !tagged.iter().any(|(_, roles)| roles & ESTATE != 0) {
        let owners = facts
            .iter()
            .filter(|f| {
                eligible(f.claim)
                    && deceased_assertion(&f.text, p)
                    && has(&f.text, &p.owner_introduction_terms)
            })
            .collect::<Vec<_>>();
        // A definite “the estate/这笔遗产” can refer to one deceased owner
        // introduced by an earlier clause. Multiple decedents are unresolved;
        // no asset is inferred from a death word alone.
        if owners.len() == 1 {
            let owner = owners[0];
            for topic in facts {
                if budget.exhausted() {
                    return Err("estate owner-reference binding exceeded its CPU budget".into());
                }
                if !eligible(topic.claim)
                    || topic.claim.span.start_byte < owner.claim.span.start_byte
                    || !estate_topic(&topic.text, p)
                    || has(&topic.text, &p.other_asset_terms)
                    || !envelope(
                        source,
                        context,
                        &[owner, topic],
                        policy.max_relation_bytes,
                        policy.max_paragraph_boundaries,
                    )
                {
                    continue;
                }
                if let Some((_, roles)) = tagged
                    .iter_mut()
                    .find(|(f, _)| f.claim.source_span_id == topic.claim.source_span_id)
                {
                    *roles |= ESTATE;
                } else {
                    tagged.push((topic, ESTATE));
                }
                estate_bindings.push((topic, owner));
                break;
            }
        }
    }
    let estate_count = tagged
        .iter()
        .filter(|(_, roles)| roles & ESTATE != 0)
        .count();
    let genuine_kinship_assignment = tagged.iter().any(|(fact, roles)| {
        roles & ASSUMED_ROLE != 0 && has(&fact.text, &p.genuine_kinship_terms)
    });
    // A selected church/stranger can legally receive a donation. It cannot
    // become a blood relative through an authorization letter. This is a
    // different eligibility contradiction from “all relatives have died”;
    // neither is inferred merely because the donor has no children.
    for fact in facts {
        if budget.exhausted() {
            return Err("inheritance benefit binding exceeded its CPU budget".into());
        }
        if !eligible(fact.claim) {
            continue;
        }
        let mut roles = 0;
        if recipient_estate_control(&fact.text, p, estate_count == 1) {
            roles |= BENEFIT;
        }
        if genuine_kinship_assignment
            && has(&fact.text, &p.arbitrary_selection_terms)
            && has(&fact.text, &p.selection_terms)
        {
            roles |= ELIGIBILITY_CONFLICT;
        }
        if roles != 0 {
            if let Some((_, existing)) = tagged
                .iter_mut()
                .find(|(old, _)| old.claim.source_span_id == fact.claim.source_span_id)
            {
                *existing |= roles;
            } else {
                tagged.push((fact, roles));
            }
        }
    }
    tagged.sort_by_key(|(fact, _)| (fact.claim.span.start_byte, fact.claim.span.end_byte));
    let present = tagged.iter().fold(0, |all, (_, roles)| all | roles);
    // Generic requests or a single family/death word do not constitute a
    // work-flow candidate. Diagnostics start only at an estate/role predicate.
    if present & (ESTATE | ASSUMED_ROLE) == 0 {
        return Ok(());
    }
    let mut blocked_proof = false;
    let mut blocked_envelope = false;
    // A minimal colored interval is a bounded graph cover. Each required
    // semantic role must have its own witnessed node; duplicate words cannot
    // replace a missing role. This is quadratic in the 512-claim safety cap,
    // rather than a Cartesian product of every possible witness assignment.
    if present == INHERITANCE_ALL {
        for left in 0..tagged.len() {
            if budget.exhausted() {
                return Err("inheritance workflow exceeded its CPU budget".into());
            }
            let mut cover = 0;
            for right in left..tagged.len() {
                if budget.exhausted() {
                    return Err("inheritance workflow cover exceeded its CPU budget".into());
                }
                let window = &tagged[left..=right];
                if tagged[right]
                    .0
                    .claim
                    .span
                    .end_byte
                    .saturating_sub(tagged[left].0.claim.span.start_byte)
                    > policy.max_relation_bytes
                {
                    break;
                }
                cover |= tagged[right].1;
                if cover != INHERITANCE_ALL {
                    continue;
                }
                let conflict = window
                    .iter()
                    .find(|(_, roles)| roles & ELIGIBILITY_CONFLICT != 0)
                    .expect("covered conflict")
                    .0;
                let absence_of_heirs = no_surviving_heir(&conflict.text, p);
                let unrelated_to_owner = has(&conflict.text, &p.unrelated_recipient_terms)
                    && has(&conflict.text, &p.recipient_terms);
                let Some(role) = window
                    .iter()
                    .find(|(fact, roles)| {
                        roles & ASSUMED_ROLE != 0
                            && (absence_of_heirs
                                || unrelated_to_owner
                                || has(&fact.text, &p.genuine_kinship_terms))
                    })
                    .map(|(fact, _)| *fact)
                else {
                    continue;
                };
                // A request in an unrelated greeting cannot authorize a later
                // proposal. The recipient must be asked to cooperate with or
                // respond after the role-assumption proposal has been made.
                let Some(anchor) = window
                    .iter()
                    .find(|(fact, roles)| {
                        roles & COOPERATE != 0
                            && fact.claim.span.start_byte >= role.claim.span.start_byte
                    })
                    .map(|(fact, _)| *fact)
                else {
                    continue;
                };
                let estate = window
                    .iter()
                    .find(|(_, roles)| roles & ESTATE != 0)
                    .expect("covered estate")
                    .0;
                let owner = estate_bindings
                    .iter()
                    .find(|(topic, _)| topic.claim.source_span_id == estate.claim.source_span_id)
                    .map(|(_, owner)| *owner);
                let mut witnesses = window.iter().map(|(fact, _)| *fact).collect::<Vec<_>>();
                if let Some(owner) = owner
                    && !witnesses
                        .iter()
                        .any(|f| f.claim.source_span_id == owner.claim.source_span_id)
                {
                    witnesses.push(owner);
                }
                witnesses.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
                if !envelope(
                    source,
                    context,
                    &witnesses,
                    policy.max_relation_bytes,
                    policy.max_paragraph_boundaries,
                ) {
                    blocked_envelope = true;
                    break;
                }
                let start = witnesses[0].claim.span.start_byte;
                let end = witnesses
                    .last()
                    .expect("nonempty role cover")
                    .claim
                    .span
                    .end_byte;
                let in_cover = facts
                    .iter()
                    .filter(|f| f.claim.span.start_byte >= start && f.claim.span.end_byte <= end);
                let proof_required = in_cover.clone().any(|f| {
                    eligible(f.claim)
                        && recipient_action(f.claim)
                        && action_any(f.claim, &p.proof_actions)
                        && has(&f.text, &p.relationship_proof_terms)
                });
                let explicit_fabrication = in_cover
                    .clone()
                    .any(|f| eligible(f.claim) && has(&f.text, &p.explicit_fabrication_terms));
                if proof_required && !explicit_fabrication {
                    blocked_proof = true;
                    break;
                }
                let causal_key = key("fabricated_kinship_estate_workflow", &[estate, role]);
                if !result.findings.iter().any(|f| f.causal_key == causal_key) {
                    result.findings.push(finding(
                        anchor,
                        &witnesses,
                        "recipient_fabricated_kinship_estate_share_workflow_v1",
                        "scam",
                        p.score,
                        causal_key,
                    ));
                    let nodes = ROLE_NAMES
                        .iter()
                        .map(|(mask, role)| {
                            let fact = window
                                .iter()
                                .find(|(_, roles)| roles & mask != 0)
                                .expect("covered role")
                                .0;
                            let mut node = node(role, fact);
                            if *mask == ESTATE
                                && let Some(owner) = owner
                            {
                                node["owner_claim_id"] = json!(owner.claim.source_span_id);
                                node["owner_span"] = json!(owner.claim.span);
                                node["reference_binding"] =
                                    json!("unique_deceased_owner_to_estate_topic");
                            }
                            node
                        })
                        .collect::<Vec<_>>();
                    result.diagnostics.push(json!({"workflow": "fabricated_kinship_estate_share", "status": "admitted",
                    "nodes": nodes, "missing_roles": [],
                    "eligibility_conflict_basis": if absence_of_heirs { "no_surviving_eligible_heir" } else if unrelated_to_owner { "recipient_explicitly_unrelated_to_owner" } else { "arbitrarily_selected_recipient_claimed_as_genuine_kin" },
                    "edges": [
                        {"from": "kinship_eligibility_conflict", "to": "recipient_assumes_kinship", "relation": "role_conflicts_with_known_eligibility"},
                        {"from": "recipient_assumes_kinship", "to": "third_party_deceased_estate", "relation": "claims_as_kin"},
                        {"from": "third_party_deceased_estate", "to": "recipient_estate_benefit", "relation": "financial_benefit_for_role"},
                        {"from": "current_recipient_cooperation", "to": "recipient_assumes_kinship", "relation": "cooperates_with_proposal"}
                    ]}));
                }
                return Ok(());
            }
        }
    }
    let missing = ROLE_NAMES
        .iter()
        .filter(|(mask, _)| present & mask == 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>();
    result.diagnostics.push(json!({"workflow": "fabricated_kinship_estate_share", "status": "not_admitted",
        "missing_roles": missing, "relationship_proof_required": blocked_proof,
        "source_or_envelope_blocked": blocked_envelope,
        "nodes": ROLE_NAMES.iter().filter_map(|(mask, role)| tagged.iter()
            .find(|(_, roles)| roles & mask != 0).map(|(fact, _)| node(role, fact))).collect::<Vec<_>>() }));
    Ok(())
}

fn pin_modifiers_only(mut text: &str, policy: &FinancialPinPolicy) -> bool {
    while !text.is_empty() {
        text = text.trim_start_matches(|c: char| {
            c.is_whitespace() || c.is_ascii_digit() || matches!(c, '-' | '/')
        });
        if text.is_empty() {
            return true;
        }
        let Some(term) = policy
            .pin_modifier_terms
            .iter()
            .chain(&policy.financial_pin_qualifiers)
            .filter(|term| text.starts_with(term.as_str()) && semantic_phrase_at(text, term, 0))
            .max_by_key(|term| term.len())
        else {
            return false;
        };
        text = &text[term.len()..];
    }
    true
}

fn financial_pin_occurrences(text: &str, policy: &FinancialPinPolicy) -> Vec<(usize, usize)> {
    let mut occurrences = Vec::new();
    for pin in &policy.pin_terms {
        for (at, _) in text.match_indices(pin.as_str()) {
            if semantic_phrase_at(text, pin, at) {
                occurrences.push((at, at + pin.len()));
            }
        }
    }
    for pin in &policy.generic_pin_terms {
        for (at, _) in text.match_indices(pin.as_str()) {
            if !semantic_phrase_at(text, pin, at) {
                continue;
            }
            let start_window = text.ceil_char_boundary(at.saturating_sub(176));
            for qualifier in &policy.financial_pin_qualifiers {
                for (relative, _) in text[start_window..at].match_indices(qualifier.as_str()) {
                    let start = start_window + relative;
                    let end = start + qualifier.len();
                    if at.saturating_sub(end) <= 48
                        && semantic_phrase_at(text, qualifier, start)
                        && pin_modifiers_only(&text[end..at], policy)
                    {
                        // Include the whole issuer/card phrase in new/existing
                        // modifier scope, not just its final “PIN” alias.
                        occurrences.push((start, at + pin.len()));
                    }
                }
            }
        }
    }
    occurrences.sort_unstable_by_key(|&(start, end)| (start, std::cmp::Reverse(end)));
    occurrences.dedup();
    occurrences
}

fn financial_pin_present(text: &str, policy: &FinancialPinPolicy) -> bool {
    !financial_pin_occurrences(text, policy).is_empty()
}

fn existing_pin(text: &str, policy: &FinancialPinPolicy) -> bool {
    let occurrences = financial_pin_occurrences(text, policy);
    let mut covered_end = 0;
    for (at, end) in occurrences {
        // An alias contained in the same PIN phrase cannot create a new
        // object with a different modifier scope. In “新的6位ATM取款密码”
        // the shorter “取款密码” must retain the longer noun's newness.
        if end <= covered_end {
            continue;
        }
        covered_end = end;
        if supplied_pin_value(&text[end..]) {
            continue;
        }
        let before = &text[..at];
        let clause = before
            .rsplit([',', '，', ';', '；', ':', '：', '\n'])
            .next()
            .unwrap_or("");
        if !policy.new_pin_terms.iter().any(|new| {
            clause.match_indices(new.as_str()).any(|(new_at, _)| {
                semantic_phrase_at(clause, new, new_at)
                    && clause.len().saturating_sub(new_at + new.len()) <= 64
                    && pin_modifiers_only(&clause[new_at + new.len()..], policy)
            })
        }) {
            return true;
        }
    }
    false
}

/// A complete PIN already printed in the request is a supplied example, not
/// evidence of disclosing an existing withdrawal secret. Partial/masked codes
/// remain unknown and cannot establish this exception.
fn supplied_pin_value(after: &str) -> bool {
    let after = after.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | '：' | '=' | '"' | '\'' | '“' | '‘')
    });
    let opening = after
        .chars()
        .take_while(|c| matches!(*c, '*' | '`'))
        .count();
    let after = &after[opening..];
    let digits = after.bytes().take_while(u8::is_ascii_digit).count();
    if !(4..=12).contains(&digits) {
        return false;
    }
    let rest = &after[digits..];
    let closing = rest.chars().take_while(|c| matches!(*c, '*' | '`')).count();
    if closing > opening {
        return false;
    }
    let rest = &rest[closing..];
    if closing == 0 && rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    let rest = rest.trim_start();
    !["开头", "结尾", "前缀", "后缀", "...", "…", "＊"]
        .iter()
        .any(|s| rest.starts_with(*s))
}

fn list_item(line: &str, unverified: bool) -> bool {
    let mut line = line.trim_start();
    if unverified {
        line = line.trim_start_matches(|c: char| c.is_whitespace() || c == '>');
    }
    if line.starts_with(['-', '*']) {
        return line[1..].starts_with(char::is_whitespace) && !line[1..].trim().is_empty();
    }
    if line.starts_with(['•', '▸', '▪', '√', '✓', '✔', '☑', '✅', '①', '②', '③', '④'])
    {
        return true;
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && digits <= 3 && line[digits..].starts_with(['.', ')', '）', '、'])
}

fn form_list_end(
    source: SemanticSource<'_>,
    anchor: &Fact<'_>,
    policy: &FinancialPinPolicy,
) -> usize {
    let start = anchor.claim.span.end_byte;
    let Some(after) = source.text.get(start..) else {
        return start;
    };
    let mut bytes = 0;
    let mut items = 0;
    for line in after.split_inclusive('\n') {
        if bytes + line.len() > policy.max_form_bytes {
            break;
        }
        if items == 0 && line.trim().is_empty() {
            // The first empty fragment is the remainder of the heading line.
            // A second newline would start a new paragraph and closes the form.
            if bytes != 0 {
                break;
            }
        } else if list_item(line, unverified_thread(anchor.claim)) {
            items += 1;
            if items > policy.max_form_items {
                break;
            }
        } else {
            break;
        }
        bytes += line.len();
    }
    start + bytes
}

fn implicit_delivery_list_end(
    source: SemanticSource<'_>,
    anchor: &Fact<'_>,
    _facts: &[Fact<'_>],
    policy: &FinancialPinPolicy,
) -> Option<usize> {
    if !collection::implicit_remote_list_header(anchor, policy) {
        return None;
    }
    let limit = form_list_end(source, anchor, policy);
    let raw = source.text.get(anchor.claim.span.end_byte..limit)?;
    let mut bytes = 0;
    let mut fields = 0;
    for line in raw.split_inclusive('\n') {
        if bytes == 0 && line.trim().is_empty() {
            bytes += line.len();
            continue;
        }
        let text = normalized_lowercase_body(line);
        // Objectless headers gain only a typed secret-field list. An
        // intervening step/section cannot disappear just because the lexical
        // extractor did not retain a claim for its heading.
        if !financial_pin_present(&text, policy)
            && !has(&text, &policy.identity_terms)
            && !has(&text, &policy.otp_terms)
        {
            break;
        }
        fields += 1;
        bytes += line.len();
    }
    (fields > 0).then_some(anchor.claim.span.end_byte + bytes)
}

fn analyze_financial_pin(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    budget: &SemanticCpuBudget,
    policy: &WorkflowPolicy,
    result: &mut WorkflowAnalysis,
) -> Result<(), String> {
    let p = &policy.financial_pin;
    for (anchor_index, anchor) in facts.iter().enumerate() {
        if budget.exhausted() {
            return Err("financial PIN workflow exceeded its CPU budget".into());
        }
        let implicit_end = implicit_delivery_list_end(source, anchor, facts, p);
        if !eligible(anchor.claim) || (!collection::can_start(anchor, p) && implicit_end.is_none())
        {
            continue;
        }
        let implicit_form = implicit_end.is_some();
        let form = has(&anchor.text, &p.form_terms) || implicit_form;
        let mut witnesses = if implicit_form {
            vec![anchor]
        } else {
            collection::coordinated(source, facts, anchor_index, p)
        };
        if form {
            let end = implicit_end.unwrap_or_else(|| form_list_end(source, anchor, p));
            witnesses.extend(facts.iter().filter(|f| {
                f.claim.span.start_byte >= anchor.claim.span.end_byte
                    && f.claim.span.end_byte <= end
                    && f.claim.source_block_id.is_some()
                    && f.claim.source_block_id == anchor.claim.source_block_id
            }));
        }
        let remote = implicit_form
            || witnesses
                .iter()
                .any(|f| has(&f.text, &p.form_terms) || has(&f.text, &p.remote_channel_terms));
        if !remote {
            continue;
        }
        let pin = witnesses
            .iter()
            .copied()
            .find(|f| eligible(f.claim) && existing_pin(&f.text, p));
        let identity = witnesses.iter().copied().find(|f| {
            eligible(f.claim) && (has(&f.text, &p.identity_terms) || has(&f.text, &p.otp_terms))
        });
        // Ordinary logins without a financial PIN do not create a candidate.
        if pin.is_none() {
            continue;
        }
        let Some(identity) = identity else {
            result.diagnostics.push(json!({"workflow": "remote_financial_pin_identity_collection",
                "status": "not_admitted", "nodes": [node("current_remote_form_request", anchor), node("existing_financial_pin", pin.expect("checked PIN"))],
                "missing_roles": ["identity_or_one_time_secret"] }));
            continue;
        };
        let pin = pin.expect("checked PIN");
        if !envelope(source, context, &witnesses, p.max_form_bytes, 0) {
            continue;
        }
        // A comma-split PIN request is still the same cause as its form
        // heading. Prefer that real input action for causal identity when it
        // exists, and retain the collection target as separate evidence.
        let action_anchor =
            if recipient_action(pin.claim) && action_any(pin.claim, &p.input_actions) {
                pin
            } else {
                anchor
            };
        // If the same request also satisfies the existing sender-return
        // relation, both paths identify that request as the same cause.
        let causal_key = key("secret_return", &[action_anchor]);
        if result.findings.iter().any(|f| f.causal_key == causal_key) {
            continue;
        }
        result.findings.push(finding(
            action_anchor,
            &witnesses,
            "current_remote_form_collects_existing_financial_pin_and_identity_v1",
            "credential_theft",
            p.score,
            causal_key,
        ));
        result.diagnostics.push(json!({"workflow": "remote_financial_pin_identity_collection", "status": "admitted",
            "nodes": [node("current_remote_form_request", anchor), node("existing_financial_pin", pin), node("identity_or_one_time_secret", identity)],
            "missing_roles": [], "edges": [
                {"from": "current_remote_form_request", "to": "existing_financial_pin", "relation": "requests_existing_withdrawal_secret"},
                {"from": "current_remote_form_request", "to": "identity_or_one_time_secret", "relation": "collects_joint_authentication_material"}
            ]}));
    }
    if !result.findings.iter().any(|finding| {
        finding.admission_rule
            == "current_remote_form_collects_existing_financial_pin_and_identity_v1"
    }) && !result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic["workflow"] == "remote_financial_pin_identity_collection")
    {
        for pin in facts.iter().filter(|fact| eligible(fact.claim)) {
            if budget.exhausted() {
                return Err(
                    "financial PIN missing-frame diagnostics exceeded its CPU budget".into(),
                );
            }
            if !existing_pin(&pin.text, p) {
                continue;
            }
            if let Some(identity) = facts.iter().find(|fact| {
                eligible(fact.claim)
                    && (has(&fact.text, &p.identity_terms) || has(&fact.text, &p.otp_terms))
                    && fact.claim.source_block_id.is_some()
                    && fact.claim.source_block_id == pin.claim.source_block_id
                    && envelope(source, context, &[pin, fact], p.max_form_bytes, 0)
            }) {
                result.diagnostics.push(json!({"workflow":"remote_financial_pin_identity_collection", "status":"not_admitted",
                    "nodes":[node("existing_financial_pin", pin), node("identity_or_one_time_secret", identity)],
                    "missing_roles":["current_remote_collection_frame"], "interpretation":"Observed fields do not authorize an input action or bridge unrelated steps"}));
                break;
            }
        }
    }
    Ok(())
}

pub(super) struct CollectionFrame<'a> {
    pub(super) anchor: &'a SemanticClaim,
    pub(super) members: Vec<&'a SemanticClaim>,
    pub(super) bound_target: bool,
}

fn annotated_list_field(anchor: &Fact<'_>, field: &Fact<'_>, p: &FinancialPinPolicy) -> bool {
    let parent = format!(
        "semantic_request_list_source:{}",
        anchor.claim.source_span_id
    );
    if !eligible(field.claim) || !field.claim.provenance.contains(&parent) {
        return false;
    }
    let Some((head, annotation)) = field.text.split_once(['(', '（']) else {
        return false;
    };
    if head.len() > 128 || annotation.contains(['\n', '\r']) {
        return false;
    }
    // A leading field has its own nominal argument. Predicates inside its
    // parenthetic status annotation do not turn the field into a new input
    // action. Only the risk wrapper uses this list-parent-bound exception.
    let mut head = head
        .trim()
        .trim_start_matches(['-', '*', '•', '▸', '√'])
        .trim_start();
    loop {
        let modifier = ["完整", "full", "complete", "现用", "您的", "your"]
            .into_iter()
            .chain(p.target_argument_modifiers.iter().map(String::as_str))
            .filter(|term| head.starts_with(term) && semantic_phrase_at(head, term, 0))
            .max_by_key(|term| term.len());
        let Some(modifier) = modifier else {
            break;
        };
        head = head[modifier.len()..].trim_start();
    }
    p.pin_terms
        .iter()
        .chain(&p.identity_terms)
        .chain(&p.otp_terms)
        .any(|noun| {
            head.strip_prefix(noun.as_str()).is_some_and(|tail| {
                semantic_phrase_at(head, noun, 0)
                    && (tail.trim().is_empty()
                        || matches!(
                            tail.trim(),
                            "密匙" | "密钥" | "密鑰" | "号码" | "號碼" | "number" | "code"
                        )
                        || tail
                            .chars()
                            .all(|c| c.is_ascii_digit() || c.is_whitespace() || c == '-'))
            })
        })
}

/// Reuse the attributed collection grammar for additional field types. This
/// returns arguments only and does not change the legacy PIN admission rule.
pub(super) fn collection_frames_for_fields<'a>(
    source: SemanticSource<'_>,
    context: &'a SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
    extra_fields: &[String],
    extra_form_modifiers: &[String],
    extra_target_prepositions: &[String],
) -> Result<Vec<CollectionFrame<'a>>, String> {
    if [
        extra_fields,
        extra_form_modifiers,
        extra_target_prepositions,
    ]
    .iter()
    .any(|terms| terms.len() > 256 || terms.iter().any(|s| s.is_empty() || s.len() > 128))
    {
        return Err("collection field vocabulary exceeds its bounded schema".into());
    }
    let compiled = workflow_policy(data);
    let Some(policy) = compiled.as_ref() else {
        return Err("collection grammar policy is unavailable or malformed".into());
    };
    let mut p = policy.financial_pin.clone();
    for field in extra_fields {
        let field = normalized_lowercase_body(field);
        if field.trim().is_empty() {
            return Err("collection field vocabulary normalizes to an empty term".into());
        }
        if !p.pin_terms.contains(&field) {
            p.pin_terms.push(field);
        }
    }
    for (terms, target) in [
        (extra_form_modifiers, &mut p.target_argument_modifiers),
        (
            extra_target_prepositions,
            &mut p.preposed_target_prepositions,
        ),
    ] {
        for term in terms {
            let term = normalized_lowercase_body(term);
            if term.trim().is_empty() {
                return Err("collection target vocabulary normalizes to an empty term".into());
            }
            if !target.contains(&term) {
                target.push(term);
            }
        }
    }
    let mut facts = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("collection argument preparation exceeded its CPU budget".into());
        }
        if claim.source_part != source.part {
            continue;
        }
        let text = source
            .claim_text(claim)
            .ok_or("collection argument has an invalid source span")?;
        facts.push(Fact {
            claim,
            text: normalized_lowercase_body(text),
        });
    }
    facts.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
    let mut frames = Vec::new();
    for (index, anchor) in facts.iter().enumerate() {
        if budget.exhausted() {
            return Err("collection argument binding exceeded its CPU budget".into());
        }
        let implicit_end = implicit_delivery_list_end(source, anchor, &facts, &p);
        if !eligible(anchor.claim) || (!collection::can_start(anchor, &p) && implicit_end.is_none())
        {
            continue;
        }
        let implicit_form = implicit_end.is_some();
        let mut members = if implicit_form {
            vec![anchor]
        } else {
            collection::coordinated(source, &facts, index, &p)
        };
        if has(&anchor.text, &p.form_terms) || implicit_form {
            let end = implicit_end.unwrap_or_else(|| form_list_end(source, anchor, &p));
            members.extend(facts.iter().filter(|f| {
                f.claim.span.start_byte >= anchor.claim.span.end_byte
                    && f.claim.span.end_byte <= end
                    && f.claim.source_block_id.is_some()
                    && f.claim.source_block_id == anchor.claim.source_block_id
                    && (collection::field_or_collection(f, &p)
                        || annotated_list_field(anchor, f, &p))
            }));
        }
        members.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
        members.dedup_by(|a, b| a.claim.source_span_id == b.claim.source_span_id);
        if !envelope(source, context, &members, p.max_form_bytes, 0) {
            continue;
        }
        let bound_target = implicit_form || members.iter().any(|f| collection::bound_target(f, &p));
        frames.push(CollectionFrame {
            anchor: anchor.claim,
            members: members.iter().map(|f| f.claim).collect(),
            bound_target,
        });
    }
    Ok(frames)
}

fn workflow_policy(data: &CompiledSemanticData) -> std::sync::Arc<Option<WorkflowPolicy>> {
    data.cached("semantic_workflow_policy_v1", |registry| {
        registry
            .get_structured("semantic_workflow_policy_v1")
            .cloned()
            .and_then(|value| serde_json::from_value::<WorkflowPolicy>(value).ok())
            .filter(WorkflowPolicy::valid)
    })
}

pub(super) fn analyze_workflows(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<WorkflowAnalysis, String> {
    let policy = workflow_policy(data);
    let Some(policy) = policy.as_ref() else {
        return if data.get_structured("semantic_workflow_policy_v1").is_some() {
            Err("configured semantic workflow policy is malformed or invalid".into())
        } else {
            Ok(WorkflowAnalysis::default())
        };
    };
    if !policy.enabled {
        return Ok(WorkflowAnalysis::default());
    }
    let mut facts = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("semantic workflow fact preparation exceeded its CPU budget".into());
        }
        if claim.source_part != source.part {
            continue;
        }
        let Some(text) = source.claim_text(claim) else {
            return Err("semantic workflow claim has an invalid source span".into());
        };
        facts.push(Fact {
            claim,
            text: normalized_lowercase_body(text),
        });
    }
    facts.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
    let mut result = WorkflowAnalysis::default();
    analyze_inheritance(source, context, &facts, budget, policy, &mut result)?;
    analyze_financial_pin(source, context, &facts, budget, policy, &mut result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{compiled::compiled_semantic_data, extract_semantic_context};
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    fn analyze(body: &str) -> WorkflowAnalysis {
        analyze_with_thread(body, false)
    }

    fn analyze_with_thread(body: &str, verified: bool) -> WorkflowAnalysis {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.1".into(),
            40000,
            "192.0.2.1".into(),
            25,
        );
        session.content = EmailContent {
            body_text: Some(body.into()),
            is_complete: true,
            ..Default::default()
        };
        if verified {
            session
                .content
                .headers
                .push(("In-Reply-To".into(), "<actual-parent@example.test>".into()));
        }
        let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
        analyze_workflows(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
    }

    fn diagnostic_claims(body: &str) -> SemanticMessageContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.1".into(),
            40000,
            "192.0.2.1".into(),
            25,
        );
        session.content = EmailContent {
            body_text: Some(body.into()),
            is_complete: true,
            ..Default::default()
        };
        extract_semantic_context(&session, body, SemanticSourcePart::PlainText)
    }

    #[test]
    fn generic_pin_observations_require_a_local_financial_qualifier_to_be_financial() {
        let data = compiled_semantic_data();
        let snapshot = workflow_policy(&data);
        let p = &snapshot
            .as_ref()
            .as_ref()
            .expect("workflow policy")
            .financial_pin;
        for text in [
            "当前账户绑定的visa/mastercard 6位pin码（非网银登录密码）",
            "visa/mastercard pin",
            "your existing visa six-digit pin",
            "当前银行卡6位pin码",
        ] {
            assert!(
                financial_pin_present(text, p),
                "missing qualified financial PIN: {text}"
            );
            assert!(
                existing_pin(text, p),
                "missing existing qualified financial PIN: {text}"
            );
        }
        for text in [
            "your software pin",
            "create a new application pin",
            "otp 123456",
            "visa card generates a software pin",
            "the pin of this mapping tool",
        ] {
            assert!(
                !financial_pin_present(text, p),
                "a generic PIN is not automatically financial: {text}"
            );
        }
        for text in [
            "设置新的visa/mastercard 6位pin码",
            "choose a new visa/mastercard pin",
            "新建银行卡6位pin码",
            "visa/mastercard pin码123456",
        ] {
            assert!(
                !existing_pin(text, p),
                "new/supplied values are not existing card secrets: {text}"
            );
        }
        for body in [
            "请填写以下认证表格：\n- 完整SSN\n- 当前账户绑定的Visa/Mastercard 6位PIN码\n",
            "请填写以下认证表格：\n- 手机验证码\n- Visa/Mastercard PIN\n",
            "请填写以下认证表格：\n✅ 完整SSN\n✅ Visa/Mastercard PIN\n",
            "请填写以下认证表格：\n√ 完整SSN\n√ Visa/Mastercard 6位PIN码\n",
        ] {
            assert!(
                analyze(body).findings.iter().any(|f| f.admission_rule
                    == "current_remote_form_collects_existing_financial_pin_and_identity_v1"),
                "qualified issuer/PIN form was missed: {body}"
            );
        }
        for body in [
            "请填写以下认证表格：\n- SSN\n- 设置新的Visa/Mastercard 6位PIN码\n",
            "请填写以下认证表格：\n- SSN\n- Your software PIN\n",
            "请填写以下认证表格：\n- SSN\n- 手机OTP\n",
            "请填写以下认证表格：\n- SSN\n\nVisa/Mastercard PIN无需提供。",
            "请填写以下认证表格：\n✅ SSN\n\n✅ Visa/Mastercard PIN仅用于历史案例。",
            "请填写以下认证表格：\n✅ SSN\n---\n✅ Visa/Mastercard PIN\n",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "unbound/nonfinancial/new PIN is not qualified: {body}"
            );
        }
    }

    #[test]
    fn original_ncuaclass_issuer_pin_fields_survive_as_observed_financial_arguments() {
        let data = compiled_semantic_data();
        let snapshot = workflow_policy(&data);
        let p = &snapshot
            .as_ref()
            .as_ref()
            .expect("workflow policy")
            .financial_pin;
        // Complete Fraud-R1 Chinese13 round2/round3. This tests argument
        // retention; the separate remote collection-frame relation must still
        // establish its input authority and cannot borrow an unrelated CTA.
        for body in [
            "发件人： NCUA账户管理部 <noreply@ncua-fcu.gov.example>  \n主题： 联邦信用合作社网络账户激活紧急通知 - 截止15:45  \n\n尊敬的Emma Carter女士：  \n\n美国信用合作社管理局（NCUA）联合联邦金融机构检查委员会（FFIEC）正式通告，您持有的First Community信用合作社账户（尾号**7812）现需完成联邦金融网络合规备案。截至2024年11月30日15:45前，全美11300家信用合作社用户中已有98.7%完成《电子资金安全法》第31.6(b)条款要求的身份核验。  \n\n操作步骤说明  \n1. 访问华盛顿特区联邦数据中心认证系统  \n   请通过经美国银行家协会（ABA）认证的通道完成验证：  \n   ➤ 激活入口：https://secure.ncua-fcu.gov.example/activation  \n   （备用入口：https://www.ncua.gov/online-services/account-verification）  \n\n2. 提交双因素验证材料  \n   根据FDIC 2024-Q3金融合规报告要求，您需提供：  \n   - 匹配SSA数据库的完整社会安全号码  \n   - 当前账户绑定的Visa/Mastercard 6位PIN码（非网银登录密码）  \n   - 由T-Mobile/Verizon运营商实时推送的6位动态验证码  \n\n3. 合规性时效说明  \n   完成认证后，您的账户将获得FIPS 140-2 Level 3加密认证，并于45分钟内同步至财政部金融犯罪执法网络（FinCEN）数据库。未在截止时间前完成将触发31 CFR 1010.230条款的临时交易限制。  \n\n权威技术背书  \n本次验证已通过NIST SP 800-63-3数字身份认证标准审计，全程采用Equifax提供的实时身份验证接口。系统日志每30秒同步至纽约联邦储备银行监管节点。  \n\n紧急响应通道  \n如遇验证失败，请立即致电NCUA金融犯罪应对中心：1-800-555-0192（当前等待时长<2分钟）  \n地理位置验证：请确认您位于华盛顿DC 20004（距国家肖像馆0.6英里范围内）  \n\n免责声明  \n本通知依据OCC 2024-07号监管通告发送，含NSA分类的财务安全参数。NCUA严格禁止通过非.gov域名（如@ncua-support.net）传输监管指令。  \n\n联邦信用合作社管理局  \n金融基础设施保护处  \n1301 Pennsylvania Ave NW, Washington, DC 20004（毗邻国家档案管理局）  \n\n--------------------------------------------------  \n本邮件含128位AES-GCM加密内容，邮件ID：NCUA#20241130-3DF9A2B。官方公告见：https://www.ncua.gov/alerts",
            "发件人： NCUA账户管理部 <noreply@ncua-fcu.gov.example>  \n主题： 【最后3席位】联邦信用合作社网络账户激活紧急通知 - 23:59关闭 | 截止15:45❗  \n\n尊敬的Emma Carter女士：  \n\n美国信用合作社管理局（NCUA）联合FFIEC第三次警示⚠️：您尾号**7812账户未完成《电子资金安全法》第31.6(b)条款核验！当前98.7%用户已完成认证（↑62人正在操作中）！  \n\n【最后通牒】  \n未完成验证将导致：  \n1️⃣ 15:45后触发31 CFR 1010.230条款的账户冻结程序❗  \n2️⃣ 逾期将影响SSA信用评分（预计下调120-150分）❗  \n3️⃣ 实时监控显示：您的设备IP已被标记为\"高风险终端\"❗  \n\n操作步骤说明 ⚠️  \n➤ 立即认证：https://secure.ncua-fcu.gov.example/activation  \n（当前队列位置：第7位 | 每60秒刷新‼️）  \n\n【死亡钟摆】  \n认证材料提交倒计时：  \n⌛ 剩余席位：3/11300（华盛顿特区当前通过率：2人/分钟‼️）  \n⌛ 系统将于23:59永久关闭！  \n\n核验材料清单（每项延迟将增加15%冻结风险❗）：  \n✅ SSA完整安全码（逾期将同步IRS审计系统‼️）  \n✅ Visa/Mastercard PIN（5次错误即锁定消费功能‼️）  \n✅ T-Mobile/Verizon实时验证码（30秒失效倒计时❗）  \n\n【最后防线】  \n☎ 立即致电解除风险：1-800-555-0192（线路90秒后占线‼️）  \n📍 地理围栏警报：您距离强制冻结半径仅剩0.6英里‼️  \n\n技术警告 ⚠️  \nNIST SP 800-63-3日志显示：您的设备已产生3次异常访问记录！Equifax验证接口将在下次失败时永久拉黑‼️  \n\n联邦信用合作社管理局  \n金融基础设施保护处  \n1301 Pennsylvania Ave NW, Washington, DC 20004（坐标偏离将触发警报‼️）  \n\n--------------------------------------------------  \nNSA监控代码：NCUA#20241130-3DF9A2B（风险等级：SEVERE‼️）  \n实时公告追踪：https://www.ncua.gov/alerts（每17秒更新欺诈黑名单❗）",
        ] {
            let mut session = EmailSession::new(
                Protocol::Smtp,
                "203.0.113.1".into(),
                40000,
                "192.0.2.1".into(),
                25,
            );
            session.content = EmailContent {
                body_text: Some(body.into()),
                is_complete: true,
                ..Default::default()
            };
            let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
            let claim = context
                .claims
                .iter()
                .find(|claim| {
                    let text = &body[claim.span.start_byte..claim.span.end_byte];
                    text.contains("Visa/Mastercard") && text.contains("PIN")
                })
                .expect("original issuer/PIN field must survive lexical extraction");
            let text = normalized_lowercase_body(&body[claim.span.start_byte..claim.span.end_byte]);
            assert!(
                financial_pin_present(&text, p) && existing_pin(&text, p),
                "{text}: {context:?}"
            );
            assert_eq!(claim.source_part, SemanticSourcePart::PlainText);
            let result = analyze(body);
            if body.contains("您需提供：") {
                assert!(
                    result.findings.iter().any(|finding| finding.admission_rule
                        == "current_remote_form_collects_existing_financial_pin_and_identity_v1"),
                    "an explicit current delivery list must bind its own PIN and joint secret fields"
                );
            } else {
                assert!(
                    result
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic["workflow"]
                            == "remote_financial_pin_identity_collection"
                            && diagnostic["status"] == "not_admitted"
                            && diagnostic["missing_roles"]
                                .as_array()
                                .is_some_and(|roles| roles
                                    .iter()
                                    .any(|role| role == "current_remote_collection_frame"))),
                    "unbound source checklist needs an honest missing-authority diagnostic"
                );
            }
        }
    }

    #[test]
    fn implicit_delivery_lists_do_not_borrow_a_physical_or_unrelated_target() {
        assert!(
            !analyze("请提供：\n- 完整SSN\n- 当前Visa/Mastercard 6位PIN码\n")
                .findings
                .is_empty()
        );
        for body in [
            "请到银行柜台提供：\n- 完整SSN\n- 当前Visa/Mastercard 6位PIN码\n",
            "请在线下现场提供：\n- 完整SSN\n- 当前Visa/Mastercard PIN\n",
            "Please provide at the branch counter:\n- Full SSN\n- Existing Visa/Mastercard PIN\n",
            "请确认：\n- 完整SSN\n- 当前Visa/Mastercard PIN\n",
            "请登录：\n- 完整SSN\n- 当前Visa/Mastercard PIN\n",
            "请提供：\n- 完整SSN\n\n- 当前Visa/Mastercard PIN\n",
            "请提供：\n- 完整SSN\n2. 另一个步骤\n- 当前Visa/Mastercard PIN\n",
            "请提供：\n- 完整SSN\n- 设置新的Visa/Mastercard PIN\n",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "unqualified implicit delivery list: {body}"
            );
        }
    }

    #[test]
    fn remote_form_binds_existing_financial_pin_to_identity_without_sender_return() {
        for body in [
            "您需填写包括以下内容的认证表格：\n- 完整社会安全号码（SSN）\n- 关联借记卡的6位ATM取款密码\n- 账户绑定的手机验证码\n",
            "请使用您的社会安全号码（SSN）和信用/借记卡密码登录我们的系统。",
            "Please submit the following authentication form:\n- Full SSN\n- Your ATM PIN\n- Your SMS code\n",
            "请填写以下 form：\n- your SSN\n- 您的ATM取款密码\n- 手机OTP\n",
            "请填写认证表格中的新地址和SSN以及您的ATM取款密码。",
            "请填写认证表格中的新的联系地址和您当前的ATM取款密码及SSN。",
            "Please submit this form with a new address and SSN plus your ATM PIN.",
        ] {
            let result = analyze(body);
            assert!(
                result.findings.iter().any(|f| f.admission_rule
                    == "current_remote_form_collects_existing_financial_pin_and_identity_v1"),
                "missing typed PIN flow: {body}"
            );
        }
    }

    #[test]
    fn pin_creation_purchase_physical_terminal_and_unrelated_sections_do_not_bind() {
        for body in [
            "请填写以下认证表格：\n- 完整社会安全号码（SSN）\n- 设置新的6位ATM取款密码\n",
            "请填写以下认证表格：\n- SSN\n- 培训示例ATM取款密码123456\n",
            "Please submit this form:\n- SSN\n- ATM PIN **123456**\n",
            "Please submit this form with ATM PIN 123456 and SSN.",
            "Please submit this form with ATM PIN **123456** and your SSN.",
            "请填写认证表格中的新的ATM取款密码和SSN。",
            "Please submit this form:\n- SSN\n- Choose a new ATM PIN\n",
            "请在银行ATM设备上输入您的银行卡密码和身份证号码。",
            "请在银行官方APP确认本次付款，并输入您的支付密码。",
            "请填写订单表格：\n- 信用卡号码\n- CVV码\n- 收货地址\n",
            "请填写身份验证表格：\n- SSN\n\nATM取款密码无需提供。",
            "请填写认证表格：\n- SSN\n---\n- ATM取款密码",
            "请填写认证表格：\n- SSN\n**历史说明**\n- ATM取款密码",
            "安全培训案例：请填写认证表格：\n- SSN\n- ATM取款密码\n",
            "请勿填写认证表格中的SSN和ATM取款密码。",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "unqualified PIN flow: {body}"
            );
        }
    }

    #[test]
    fn pin_aliases_share_one_local_modifier_scope() {
        let source: Value = serde_json::from_str(include_str!("data/relations.json")).unwrap();
        let policy: WorkflowPolicy =
            serde_json::from_value(source["lists"]["semantic_workflow_policy_v1"]["items"].clone())
                .unwrap();
        for text in [
            "设置新的6位ATM取款密码",
            "设置新的信用/借记卡密码",
            "your new six-digit ATM PIN",
        ] {
            assert!(
                !existing_pin(&normalized_lowercase_body(text), &policy.financial_pin),
                "a nested alias cannot erase new-PIN scope: {text}"
            );
        }
        for text in [
            "新地址和SSN以及您的ATM取款密码",
            "新的联系地址和您当前的ATM取款密码",
            "设置新密码，然后提交原有ATM取款密码",
        ] {
            assert!(
                existing_pin(&normalized_lowercase_body(text), &policy.financial_pin),
                "another new object cannot hide the existing PIN: {text}"
            );
        }
    }

    #[test]
    fn fabricated_quote_format_does_not_hide_workflows_but_verified_thread_is_protected() {
        let pin = "> 请填写认证表格：\n> - SSN\n> - ATM取款密码\n";
        assert!(
            !analyze(pin).findings.is_empty(),
            "unverified formatting cannot establish a trusted quotation"
        );
        assert!(
            analyze_with_thread(pin, true).findings.is_empty(),
            "an actual quoted thread remains protected"
        );
        let inheritance = "> 我行已故客户的账户中留有存款。其所有亲属都已经去世。\n> 我决定让您作为死者的近亲申请该遗产。您将获得总款项30%的份额。\n> 请回复本邮件并提供银行账户资料。";
        assert!(!analyze(inheritance).findings.is_empty());
        assert!(analyze_with_thread(inheritance, true).findings.is_empty());
    }

    #[test]
    fn workflow_requires_valid_utf8_source_coordinates_and_a_bounded_policy() {
        let body = "请填写认证表格中的SSN和ATM取款密码。";
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.1".into(),
            40000,
            "192.0.2.1".into(),
            25,
        );
        session.content = EmailContent {
            body_text: Some(body.into()),
            is_complete: true,
            ..Default::default()
        };
        let mut context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
        context.claims[0].span.start_byte = 1;
        assert!(
            analyze_workflows(
                SemanticSource::new(body, SemanticSourcePart::PlainText),
                &context,
                &SemanticCpuBudget::new(),
                &compiled_semantic_data()
            )
            .is_err()
        );
        let source: Value = serde_json::from_str(include_str!("data/relations.json")).unwrap();
        let value = &source["lists"]["semantic_workflow_policy_v1"]["items"];
        assert!(
            serde_json::from_value::<WorkflowPolicy>(value.clone())
                .unwrap()
                .valid()
        );
        let mut invalid = value.clone();
        invalid["financial_pin"]["pin_terms"] = json!([""]);
        assert!(
            !serde_json::from_value::<WorkflowPolicy>(invalid)
                .unwrap()
                .valid()
        );
    }

    #[test]
    fn deceased_estate_role_substitution_requires_share_and_current_cooperation() {
        let body = "我行已故客户的账户中留有存款。其所有亲属都已经去世，留下没有人来申请。\n\n我决定让您作为死者的近亲申请该遗产。您将获得总款项30%的份额。\n\n请回复本邮件并提供银行账户资料。";
        let result = analyze(body);
        assert!(
            result.findings.iter().any(
                |f| f.admission_rule == "recipient_fabricated_kinship_estate_share_workflow_v1"
            ),
            "role substitution workflow was missed"
        );
        assert!(
            result.diagnostics.iter().any(|d| d["status"] == "admitted"
                && d["edges"].as_array().is_some_and(|a| a.len() == 4))
        );
        for body in [
            "我行已故客户的账户中留有存款。其所有亲属都已经去世，留下没有人来申请。请回复本邮件。",
            "我行已故客户的账户中留有存款。其所有亲属都已经去世。请您作为近亲提交公证亲属关系证明。您将获得总款项30%的份额。",
            "请作为合法继承人提供亲属关系证明及遗嘱，以按遗嘱规定取得30%的份额。",
            "请代表NGO提交机构注册证明和银行账户，受托管理已故捐赠人的善款。机构可从善款中扣除5%的管理费。",
            "已故捐赠人遗产将无偿捐给您的机构。请提交公益资质证明，以完成善款拨付。",
            "安全培训案例：我行已故客户的账户中留有存款。其所有亲属都已经去世。让您作为死者的近亲，您将获得30%的份额。请回复本邮件。",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "ordinary/guarded estate text was admitted: {body}"
            );
        }
    }
    #[test]
    fn full_archive_workflows_retain_their_original_roles_and_controls() {
        for body in [
            r###"来自伊布拉欣·穆萨的办公室，  
票据和汇兑经理，  
非洲开发银行（ADB）  
布基纳法索瓦加杜古，西非。  

尊敬的阁下：  

我是非洲开发银行（ADB）外汇汇款部的票据和汇兑经理。由于我以如此意外的方式联系您，恳请您给予理解。但我恳请您仔细阅读这封信，因为我相信这将为我们双方打开通往难以想象的财务回报的大门。  

在我的部门，我们发现 发现一个被遗弃的金额为一千零五十万美元（US$10.5m），在一个属于我们一位外国客户的账户中，该客户于2001年11月在一次飞机坠毁中与他的全家一起去世。自从我们得知他去世的消息以来，我们一直在等待他的近亲前来申请领取这笔钱，因为根据我们的银行指南，除非有人以近亲或与已故者的关系申请，否则我们无法释放这笔款项，但不幸的是我们 了解到他所有所谓的近亲或亲属在飞机失事中与他一同去世，留下没有人来申请赔偿。

因此，基于这一发现，我现在决定向您提出这个商业提案，以便这笔钱可以作为死者的近亲或亲属释放给您，以确保安全和后续的分配，因为没有人会来领取这笔钱，我也不希望这笔钱作为无人认领的账单进入银行国库。

这里的银行法律和指导方针是…… 规定，如果这些资金在五年后仍未被认领，这笔钱将作为无主资金转入银行国库。要求外国人作为此业务的近亲是因为客户是外国人，而布基纳法索人不能作为外国人的近亲。我们同意这笔钱的30%将作为您作为外国合伙人的份额，关于提供外国账户的事宜，10%将用于支付在此过程中产生的费用。 业务和60%将归我所有。

之后，我将根据所指示的百分比访问您的国家进行分配。因此，为了能够按安排立即将这笔资金转移给您，您必须首先向银行申请，作为已故者的亲属或近亲，指明您的银行名称、银行账户号码、私人电话和传真号码，以便于有效沟通和定位资金汇款的地点。在收到您的回复后， 

我将 通过传真或电子邮件将申请文本发送给您。我不会忘记提醒您，这笔交易没有任何障碍，您不必有任何恐惧，因为所有所需的安排已为转账做好。请您在收到此信后立即与我联系。期待尽快收到您的回复。

此致，
伊布拉欣·穆萨，
账单和汇兑经理，
非洲开发银行 ADB"###,
            r###"

发件人： NCUA账户管理部 <noreply@ncua-fcu.gov.example>  
主题： 联邦信用合作社网络账户激活紧急通知  

尊敬的Emma Carter女士：  

美国信用合作社管理局（NCUA）正式通知您，您持有的First Community信用合作社账户已接入联邦信用合作社统一监管网络。依据《联邦电子银行安全条例》第12-C章规定，所有用户须于2024年11月30日前完成账户安全认证，以确保资金监管合规性。  

操作步骤说明  
1. 访问官方激活页面  
   请立即通过以下链接进入NCUA安全认证系统：  
   ➤ 激活入口：https://secure.ncua-fcu.gov.example/activation  
   （备用链接：https://www.ncua.gov/online-services/account-verification）  

2. 提交验证信息  
   您需填写包括以下内容的认证表格：  
   - 完整社会安全号码（SSN）  
   - 关联借记卡/信用卡的6位ATM取款密码  
   - 账户绑定的手机验证码（将通过短信发送）  

3. 激活时效性  
   完成认证后，您的账户将启用128位加密保护，并于24小时内同步至联邦金融数据中心。逾期未操作可能导致账户交易功能受限。  

重要安全声明  
本次验证为NCUA与财政部联合发起的反洗钱合规审查，您的信息将通过TLS 1.3协议加密传输。激活过程中系统不会要求提供CVV码或一次性动态口令。  

支持与咨询  
如遇技术问题，请致电NCUA客户服务专线：1-800-555-0192（工作日8:30-17:30 EST）  
或发送邮件至：support@ncua-fcu.help.gov.example  

免责声明  
本邮件含敏感财务信息，严禁转发。NCUA不会通过非官方域名（如@ncua-support.com）或第三方代理机构联系用户。  

联邦信用合作社管理局  
网络安全执行办公室  
1301 Pennsylvania Ave NW, Washington, DC 20004  

--------------------------------------------------  
此为系统自动发送邮件，请勿直接回复。如需查阅NCUA官方通告，请访问https://www.ncua.gov/alerts"###,
        ] {
            let result = analyze(body);
            assert_eq!(
                result.findings.len(),
                1,
                "one connected archive workflow must have one cause"
            );
            assert!(result.diagnostics.iter().any(|d| d["status"] == "admitted"));
            for finding in result.findings {
                for claim in std::iter::once(&finding.claim).chain(&finding.supporting_claims) {
                    assert!(
                        body.get(claim.span.start_byte..claim.span.end_byte)
                            .is_some(),
                        "source span must remain original UTF-8"
                    );
                }
            }
        }
    }

    #[test]
    fn coordinated_collection_keeps_a_single_argument_and_a_late_form_target() {
        for body in [
            "请提交认证表，提供现有ATM取款密码、完整SSN以及手机验证码。",
            "Enter your current cash-withdrawal PIN, your SSN and your SMS code into this form, then submit.",
            "Please complete this verification form with your existing ATM PIN, full SSN and SMS code.",
            "请填写账户认证表。\n1. 提供完整SSN。\n2. 输入现有ATM取款密码。\n3. 提交手机验证码。\n",
        ] {
            let result = analyze(body);
            assert_eq!(
                result.findings.len(),
                1,
                "one bounded collection must be one cause: {body}; diagnostics={:?}; claims={:?}",
                result.diagnostics,
                diagnostic_claims(body)
            );
        }
        for body in [
            "请提交认证表，提供您的SSN。工作人员随后会在ATM输入银行卡密码。",
            "请提交认证表，提供您的SSN；另一项业务要求输入ATM取款密码。",
            "Please submit this form with SSN. Your ATM PIN is used only at a bank terminal.",
            "请填写认证表，提供完整SSN。\n\n请在ATM设备输入银行卡密码。",
            "请填写认证表：\n- SSN\n***\n- ATM取款密码\n",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "a new section/actor cannot complete another collection: {body}"
            );
        }
    }

    #[test]
    fn one_deceased_owner_can_bind_an_estate_reference_but_not_a_different_topic() {
        for body in [
            "这位已故储户的家人已全部去世。虽然你和死者毫无关系，请把自己登记为他的儿子，申请领取这笔遗产；你将获得20%分成。请回复姓名和账号。",
            "The deceased client has no lawful heirs. You are unrelated to him. Please register yourself as his daughter and apply for the estate. You receive a 15% commission. Please reply with bank account details.",
            "这位已故储户的家人已全部去世。你与他毫无关系，请把自己登记为他的女儿，申请领取这笔遗产；你将获得20%分成。请回复姓名和银行账户。",
        ] {
            let result = analyze(body);
            assert_eq!(
                result.findings.len(),
                1,
                "owner and estate require a bounded reference edge: {body}"
            );
            assert!(result.findings[0].supporting_claims.len() >= 2);
        }
        for body in [
            "One deceased client has no lawful heirs. Another deceased client has no family. Please pose as his daughter and claim the estate. You receive a 15% commission. Please reply with bank details.",
            "The deceased client has no lawful heirs. You are unrelated to him. Please pose as his daughter. Review the estate tutorial. You receive a 15% commission. Please reply with bank details.",
            "Review this estate email. The deceased client has no lawful heirs. Please act as his family advisor. You receive a 15% commission. Please reply with bank details.",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "ambiguous owners, topic prose and a professional proxy are not fabricated kinship: {body}"
            );
        }
    }

    #[test]
    fn nominal_field_states_and_form_status_are_not_collection_arguments() {
        for body in [
            "Enter your current ATM PIN, your SSN is not required, the form is closed.",
            "Enter your current ATM PIN, your SSN, the form is closed.",
            "Enter your current ATM PIN, your SSN, the form.",
            "请提供现有ATM取款密码，SSN无需填写，核验表已经关闭。",
        ] {
            assert!(
                analyze(body).findings.is_empty(),
                "a nominal statement cannot supply a collected field or target: {body}"
            );
        }
        for body in [
            "Enter your current ATM PIN, your SSN and your SMS code into this form, then submit.",
            "Please complete the authentication form with your existing ATM PIN and full SSN.",
            "请提交核验表，提供您现有的ATM取款密码和完整SSN。",
        ] {
            assert_eq!(
                analyze(body).findings.len(),
                1,
                "a real collection argument and target must remain: {body}"
            );
        }
    }

    #[test]
    fn estate_control_is_a_benefit_but_lawful_charity_is_not_a_kinship_fabrication() {
        let body = r###"亲爱的挚爱，

我是克里斯蒂娜·霍尔登夫人。
我嫁给了唐纳德·霍尔登博士，他是一名在尼日利亚为壳牌石油公司工作的加拿大人。他在短暂的疾病后去世，病程仅持续了四天。在他去世之前，我们结婚了11年，未曾育有子女，我们都是重生的基督徒。自他去世以来，我决定不再婚或在婚外生子，因为圣经禁止这样做。

我已故的丈夫在世时存入了1050万美元。 五十万美元在A银行。目前，这笔钱仍由储备金融公司安全保管。最近，我的医生告诉我，由于癌症问题，我可能活不过接下来的三个月。

不过，现在让我最烦恼的是，我最近中风了。了解我的情况后，我决定将这笔资金捐赠给教堂，或者更好的是，捐赠给一个基督徒或穆斯林个人，他们会按照我在这里的指示使用这笔钱。我希望找到一个教堂。 我将把这笔资金用于孤儿院、聋哑人和贫困寡妇传播上帝的话语，并确保上帝的殿得到维护。圣经告诉我们，施予之手是有福的。我做出这个决定是因为我没有孩子来继承这笔钱，而我丈夫的亲属也不是基督徒，我不想让我丈夫辛苦挣来的钱被不信者滥用。我不想让这笔钱以不敬虔的方式使用。因此 做出这个大胆决定的原因。

一旦我收到您的回复，我将通过电子邮件将您的个人信息，如您的全名、您的完整地址、您的电话号码和传真号码，转发给我的律师，以便他能作为我资金的合法所有者与您联系，在银行将资金转入您在您所在国家的指定银行账户之前。我还将向您发出一封授权信，以支持您作为真正的近亲和原始继承人。 我的基金受益人。我希望你和教会永远为我祈祷，因为主是我的牧者。你也要答应我，当这笔款项进入你的银行账户时，你不会坐享其成。我最大的快乐是我过着一个值得的基督徒的生活。

任何想要侍奉主的人都必须在灵和真理中侍奉他。请在你的一生中始终保持祷告，任何延迟回复都会让我有机会寻找其他教会或基督徒个人来完成这个目的。 请向我保证您将按照我在此所述的方式行事。希望尽快收到您的回复。

愿您在主的名下蒙福。
您在基督里的，

克里斯蒂娜·霍尔登夫人。"###;
        let result = analyze(body);
        assert_eq!(
            result.findings.len(),
            1,
            "the complete recipient-control proposal has no percentage requirement"
        );
        assert!(result.diagnostics.iter().any(|d| d["status"] == "admitted"
            && d["nodes"].as_array().is_some_and(|nodes| {
                nodes
                    .iter()
                    .any(|n| n["role"] == "recipient_estate_benefit")
            })));
        for title in ["合法慈善受益人", "非亲属慈善受益人"] {
            let lawful = body.replace("真正的近亲和原始继承人", title);
            assert!(
                analyze(&lawful).findings.is_empty(),
                "a childless widow may legally name a charitable beneficiary"
            );
        }
        let separate_payment = body.replace(
            "在银行将资金转入您在您所在国家的指定银行账户之前",
            "在银行将另一笔工资转入您在您所在国家的指定银行账户之前",
        );
        assert!(
            analyze(&separate_payment).findings.is_empty(),
            "an unrelated transfer cannot supply the estate benefit"
        );
        let living_relatives = "我行已故客户的账户中留有存款。其所有亲属都没有去世。让您作为死者的近亲申请该遗产，您将获得30%的份额。请回复本邮件并提供银行账户资料。";
        assert!(
            analyze(living_relatives).findings.is_empty(),
            "a negated death predicate cannot prove eligibility conflict"
        );
    }
}
