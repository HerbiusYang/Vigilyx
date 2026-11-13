//! Bounded graded risk from typed operation/argument/purpose combinations.
//! These findings are Low-risk hypotheses, not the legacy full proofs. A
//! deadline, authority claim, topic, or scenario alone never earns a score.

use std::collections::HashMap;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticActionDestination, SemanticClaim, SemanticMessageContext, SemanticPolarity,
    SemanticQuoteStatus, SemanticSourcePart, SemanticSpeechAct, SemanticTargetRole,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::is_current_recipient_action;
use super::solicitation::NativeSolicitationFinding;
use super::source::SemanticSource;
use super::text::{normalized_lowercase_body, semantic_phrase_at};
use super::workflow::collection_frames_for_fields;

#[derive(Default)]
pub(super) struct RiskAnalysis {
    pub(super) findings: Vec<NativeSolicitationFinding>,
    pub(super) diagnostics: Vec<Value>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RiskPolicy {
    enabled: bool,
    lexical_objects: Vec<String>,
    bounds: Bounds,
    scores: Scores,
    actions: Actions,
    materials: Materials,
    purposes: Purposes,
    relations: Relations,
}

#[derive(Default, Deserialize)]
struct Bounds {
    max_relation_bytes: usize,
    max_paragraph_boundaries: usize,
    max_adjacent_gap_bytes: usize,
    max_witness_claims: usize,
    min_verification_amount: f64,
    micro_verification_max_amount: f64,
}

#[derive(Default, Deserialize)]
struct Scores {
    communication_secret: f64,
    verification_payment: f64,
    windfall_fee: f64,
    incoming_secret_bundle: f64,
    material_deception: f64,
    corroboration_increment: f64,
    cap: f64,
}

#[derive(Default, Deserialize)]
struct Actions {
    communication: Vec<String>,
    payment: Vec<String>,
    input: Vec<String>,
    cooperation: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Materials {
    payment_secrets: Vec<String>,
    identity: Vec<String>,
    full_identity: Vec<String>,
    partial_identity: Vec<String>,
    secret_topic_suffixes: Vec<String>,
    partial_code_suffixes: Vec<String>,
    financial_assets: Vec<String>,
    fees: Vec<String>,
    form_target_modifiers: Vec<String>,
    identity_argument_modifiers: Vec<String>,
    fulfilled_identity_annotations: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Purposes {
    verification: Vec<String>,
    administrative_status: Vec<String>,
    incoming_funds: Vec<String>,
    windfall: Vec<String>,
    commercial_transaction: Vec<String>,
    existing_debt: Vec<String>,
    discussion: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Relations {
    recipient: Vec<String>,
    payment_destinations: Vec<String>,
    own_account_destinations: Vec<String>,
    destination_prefixes: Vec<String>,
    sender_message_returns: Vec<String>,
    human_communication_sinks: Vec<String>,
    causal: Vec<String>,
    prerequisites: Vec<String>,
    entitlement_requirement: Vec<String>,
    credit_or_legal_consequences: Vec<String>,
    benign_negation: Vec<String>,
    current_payment_references: Vec<String>,
    future_refund: Vec<String>,
    whole_balance: Vec<String>,
    fee_deduction: Vec<String>,
    institution: Vec<String>,
    concealment: Vec<String>,
    concealment_prohibited: Vec<String>,
    material_facts: Vec<String>,
    fabrication: Vec<String>,
    aml_evasion: Vec<String>,
    financial_document_assertion: Vec<String>,
    positive_bookkeeping: Vec<String>,
    negative_bookkeeping: Vec<String>,
    known_fact_markers: Vec<String>,
    form_target_prepositions: Vec<String>,
    benefit_goal_prefixes: Vec<String>,
}

fn bounded(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 96
        && values
            .iter()
            .all(|s| !s.trim().is_empty() && s.len() <= 128)
}

impl RiskPolicy {
    fn valid(&self) -> bool {
        if !self.enabled {
            return true;
        }
        let b = &self.bounds;
        let s = &self.scores;
        let a = &self.actions;
        let m = &self.materials;
        let p = &self.purposes;
        let r = &self.relations;
        (256..=8192).contains(&b.max_relation_bytes)
            && b.max_paragraph_boundaries <= 3
            && (16..=512).contains(&b.max_adjacent_gap_bytes)
            && (2..=24).contains(&b.max_witness_claims)
            && b.min_verification_amount.is_finite()
            && b.min_verification_amount >= 100.0
            && b.micro_verification_max_amount.is_finite()
            && (0.0..=10.0).contains(&b.micro_verification_max_amount)
            && [
                s.communication_secret,
                s.verification_payment,
                s.windfall_fee,
                s.incoming_secret_bundle,
                s.material_deception,
            ]
            .iter()
            .all(|v| v.is_finite() && (0.15..=0.32).contains(v))
            && s.corroboration_increment.is_finite()
            && (0.0..=0.03).contains(&s.corroboration_increment)
            && s.cap.is_finite()
            && (0.15..=0.39).contains(&s.cap)
            && [
                s.communication_secret,
                s.verification_payment,
                s.windfall_fee,
                s.incoming_secret_bundle,
                s.material_deception,
            ]
            .iter()
            .all(|v| *v <= s.cap)
            && self.lexical_objects.len() <= 256
            && self
                .lexical_objects
                .iter()
                .all(|s| !s.trim().is_empty() && s.len() <= 128)
            && [
                &a.communication,
                &a.payment,
                &a.input,
                &a.cooperation,
                &m.payment_secrets,
                &m.identity,
                &m.full_identity,
                &m.partial_identity,
                &m.secret_topic_suffixes,
                &m.partial_code_suffixes,
                &m.financial_assets,
                &m.fees,
                &m.form_target_modifiers,
                &m.identity_argument_modifiers,
                &m.fulfilled_identity_annotations,
                &p.verification,
                &p.administrative_status,
                &p.incoming_funds,
                &p.windfall,
                &p.commercial_transaction,
                &p.existing_debt,
                &p.discussion,
                &r.recipient,
                &r.payment_destinations,
                &r.own_account_destinations,
                &r.destination_prefixes,
                &r.sender_message_returns,
                &r.human_communication_sinks,
                &r.causal,
                &r.prerequisites,
                &r.entitlement_requirement,
                &r.credit_or_legal_consequences,
                &r.benign_negation,
                &r.current_payment_references,
                &r.future_refund,
                &r.whole_balance,
                &r.fee_deduction,
                &r.institution,
                &r.concealment,
                &r.concealment_prohibited,
                &r.material_facts,
                &r.fabrication,
                &r.aml_evasion,
                &r.financial_document_assertion,
                &r.positive_bookkeeping,
                &r.negative_bookkeeping,
                &r.known_fact_markers,
                &r.form_target_prepositions,
                &r.benefit_goal_prefixes,
            ]
            .iter()
            .all(|v| bounded(v))
    }
}

struct CompiledRiskPolicy {
    policy: RiskPolicy,
    email: Regex,
    amounts: Regex,
}

struct Fact<'a> {
    claim: &'a SemanticClaim,
    text: String,
}

fn has(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str())
            .any(|(at, _)| semantic_phrase_at(text, term, at))
    })
}

fn original(claim: &SemanticClaim) -> bool {
    (claim.quote_or_forward_status == SemanticQuoteStatus::Original
        || claim
            .provenance
            .iter()
            .any(|p| p == UNVERIFIED_THREAD_PROVENANCE))
        && !matches!(
            claim.speech_act,
            SemanticSpeechAct::Report | SemanticSpeechAct::Quotation
        )
        && claim.counter_context_ids.is_empty()
}

pub(super) fn eligible(claim: &SemanticClaim) -> bool {
    original(claim)
        && claim.speech_act != SemanticSpeechAct::Warning
        && claim.polarity != SemanticPolarity::AntiAction
        && claim.target_role != SemanticTargetRole::NamedThirdParty
}

pub(super) fn current(claim: &SemanticClaim) -> bool {
    if !eligible(claim) {
        return false;
    }
    let mut attributed = claim.clone();
    if attributed
        .provenance
        .iter()
        .any(|p| p == UNVERIFIED_THREAD_PROVENANCE)
    {
        attributed.quote_or_forward_status = SemanticQuoteStatus::Original;
    }
    is_current_recipient_action(&attributed)
        && !attributed
            .provenance
            .iter()
            .any(|p| p == "semantic_discussion_request_v1")
}

fn action(claim: &SemanticClaim, terms: &[String]) -> bool {
    claim.actions.iter().any(|a| terms.contains(a))
}

fn active_operation(fact: &Fact<'_>, terms: &[String]) -> bool {
    if !current(fact.claim) || !action(fact.claim, terms) {
        return false;
    }
    terms.iter().any(|verb| {
        fact.text.match_indices(verb.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(&fact.text, verb, at) {
                return false;
            }
            if verb == "转"
                && !fact
                    .claim
                    .provenance
                    .iter()
                    .any(|p| p == "semantic_compact_transfer_predicate_v1")
            {
                return false;
            }
            if verb == "汇" {
                let after = fact.text[at + verb.len()..].trim_start();
                let amount = after
                    .strip_prefix("人民币")
                    .or_else(|| after.strip_prefix("rmb"))
                    .or_else(|| after.strip_prefix("cny"))
                    .unwrap_or(after)
                    .trim_start_matches(|c: char| {
                        c.is_whitespace() || matches!(c, '¥' | '￥' | '$')
                    });
                if !amount.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    return false;
                }
            }
            let before = fact.text[..at].trim_end();
            if [
                "已经",
                "早已",
                "刚刚",
                "曾经",
                "已",
                "already",
                "previously",
                "have",
                "has",
                "had",
                "was",
            ]
            .iter()
            .any(|past| before.ends_with(past))
            {
                return false;
            }
            let clause = before
                .rsplit([',', '，', ';', '；', ':', '：', '\n'])
                .next()
                .unwrap_or("");
            if ["已把", "已经把", "早已把", "曾将", "已经将"]
                .iter()
                .any(|past| clause.contains(past))
            {
                return false;
            }
            // A request to inspect an old operation is not a fresh request to
            // perform that operation. An explicit new coordination remains live.
            for inspect in [
                "确认", "查询", "查看", "核对", "查阅", "confirm", "check", "review",
            ] {
                if let Some(pos) = clause.rfind(inspect) {
                    let tail = &clause[pos + inspect.len()..];
                    if !["并", "然后", "再", "请", "and", "then", "please"]
                        .iter()
                        .any(|join| tail.contains(join))
                    {
                        return false;
                    }
                }
            }
            true
        })
    })
}

fn paragraphs(text: &str) -> usize {
    let mut previous_blank = false;
    text.lines()
        .filter(|line| {
            let blank = line.trim().is_empty();
            let boundary = blank && !previous_blank;
            previous_blank = blank;
            boundary
        })
        .count()
}

fn envelope(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    witnesses: &[&Fact<'_>],
    policy: &RiskPolicy,
    allow_concealment: bool,
) -> bool {
    if witnesses.is_empty() || witnesses.len() > policy.bounds.max_witness_claims {
        return false;
    }
    let start = witnesses
        .iter()
        .map(|f| f.claim.span.start_byte)
        .min()
        .unwrap_or(0);
    let end = witnesses
        .iter()
        .map(|f| f.claim.span.end_byte)
        .max()
        .unwrap_or(0);
    if end.saturating_sub(start) > policy.bounds.max_relation_bytes {
        return false;
    }
    let Some(text) = source.text.get(start..end) else {
        return false;
    };
    if paragraphs(text) > policy.bounds.max_paragraph_boundaries {
        return false;
    }
    if source.part != SemanticSourcePart::PlainText
        && witnesses.iter().any(|f| {
            f.claim.source_block_id.is_none()
                || f.claim.source_block_id != witnesses[0].claim.source_block_id
        })
    {
        return false;
    }
    !context.claims.iter().any(|claim| {
        claim.source_part == source.part
            && claim.span.start_byte < end
            && start < claim.span.end_byte
            && !eligible(claim)
            && !(allow_concealment
                && witnesses
                    .iter()
                    .any(|f| f.claim.source_span_id == claim.source_span_id)
                && original(claim))
    })
}

fn adjacent(source: SemanticSource<'_>, a: &Fact<'_>, b: &Fact<'_>, policy: &RiskPolicy) -> bool {
    if a.claim.source_span_id == b.claim.source_span_id {
        return true;
    }
    if a.claim.source_block_id.is_none() || a.claim.source_block_id != b.claim.source_block_id {
        return false;
    }
    let (left, right) = if a.claim.span.start_byte <= b.claim.span.start_byte {
        (a, b)
    } else {
        (b, a)
    };
    let gap = right
        .claim
        .span
        .start_byte
        .saturating_sub(left.claim.span.end_byte);
    gap <= policy.bounds.max_adjacent_gap_bytes
        && source
            .text
            .get(left.claim.span.end_byte..right.claim.span.start_byte)
            .is_some_and(|s| !s.contains(['\n', ';', '；']))
}

fn key(kind: &str, fact: &Fact<'_>) -> String {
    let text = fact.text.split_whitespace().collect::<Vec<_>>().join(" ");
    format!(
        "body_relation:{kind}:{}",
        hex::encode(Sha256::digest(text.as_bytes()))
    )
}

fn node(group: &str, fact: &Fact<'_>) -> Value {
    json!({"group": group, "claim_id": fact.claim.source_span_id,
        "source_part": fact.claim.source_part, "span": fact.claim.span})
}

fn diagnostic(
    family: &str,
    anchor: &Fact<'_>,
    groups: &[(&str, &Fact<'_>)],
    missing: &[&str],
    counters: &[&str],
    score: Option<f64>,
) -> Value {
    json!({"layer": "bounded_semantic_risk_combination_v1", "family": family,
        "status": if score.is_some() {"risk_hint"} else {"not_admitted"},
        "anchor_claim_id": anchor.claim.source_span_id,
        "feature_groups": groups.iter().map(|(g,f)|node(g,f)).collect::<Vec<_>>(),
        "missing_groups": missing, "counter_evidence": counters, "score": score,
        "interpretation": "Local risk combination, not a legacy complete attack proof"})
}

#[allow(clippy::too_many_arguments)]
fn emit(
    analysis: &mut RiskAnalysis,
    anchor: &Fact<'_>,
    supports: &[&Fact<'_>],
    family: &'static str,
    category: &str,
    score: f64,
    cause: &str,
    groups: &[(&str, &Fact<'_>)],
    p: &RiskPolicy,
) {
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
    let score = score.min(p.scores.cap);
    analysis.findings.push(NativeSolicitationFinding {
        source_part: anchor.claim.source_part,
        claim: anchor.claim.clone(),
        supporting_claims,
        admission_rule: family,
        category: category.into(),
        score,
        causal_key: key(cause, anchor),
    });
    analysis
        .diagnostics
        .push(diagnostic(family, anchor, groups, &[], &[], Some(score)));
}

fn requested_payment_secret(text: &str, p: &RiskPolicy) -> bool {
    p.materials.payment_secrets.iter().any(|secret| {
        text.match_indices(secret.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, secret, at) {
                return false;
            }
            let after = text[at + secret.len()..].trim_start();
            if p.materials.secret_topic_suffixes.iter().any(|s| {
                let suffix = s.trim_start();
                after.starts_with(suffix) && semantic_phrase_at(after, suffix, 0)
            }) {
                return false;
            }
            let value = after.trim_start_matches(|c: char| {
                c.is_whitespace() || matches!(c, ':' | '：' | '=' | '*' | '`' | '\'' | '"')
            });
            let digits = value.bytes().take_while(u8::is_ascii_digit).count();
            if (3..=4).contains(&digits) {
                let rest = &value[digits..];
                let partial = rest.starts_with(['*', '＊', '…'])
                    || rest.starts_with("...")
                    || p.materials
                        .partial_code_suffixes
                        .iter()
                        .any(|s| rest.trim_start().starts_with(s.as_str()));
                if !partial
                    && !rest
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
                {
                    return false;
                }
            }
            true
        })
    })
}

fn card_payment_secret(text: &str, p: &RiskPolicy) -> bool {
    requested_payment_secret(text, p)
        && p.materials
            .payment_secrets
            .iter()
            .filter(|s| !s.contains("pin") && !s.contains("密码"))
            .any(|s| {
                text.match_indices(s.as_str())
                    .any(|(at, _)| semantic_phrase_at(text, s, at))
            })
}

fn full_identity(text: &str, p: &RiskPolicy) -> bool {
    p.materials.identity.iter().any(|identity| {
        text.match_indices(identity.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, identity, at) {
                return false;
            }
            let before = &text[..at];
            let after = &text[at + identity.len()..];
            let prefix = before
                .rsplit([',', '，', ';', '；', '\n'])
                .next()
                .unwrap_or("");
            let suffix = after
                .split([',', '，', ';', '；', '\n'])
                .next()
                .unwrap_or("");
            let left = [" and ", "以及", "和"]
                .iter()
                .filter_map(|join| prefix.rfind(*join).map(|at| at + join.len()))
                .max()
                .unwrap_or(0);
            let right = [" and ", "以及", "和"]
                .iter()
                .filter_map(|join| suffix.find(*join))
                .min()
                .unwrap_or(suffix.len());
            let prefix = &prefix[left..];
            let suffix = &suffix[..right];
            let field = format!("{prefix}{identity}{suffix}");
            let explicit_complete = p.materials.full_identity.iter().any(|marker| {
                field.match_indices(marker.as_str()).any(|(at, _)| {
                    semantic_phrase_at(&field, marker, at)
                        // "全号" inside "社会安全号码" is part of the
                        // identity noun, not a completeness modifier.
                        && !p.materials.identity.iter().any(|noun| {
                            field.match_indices(noun.as_str()).any(|(start, _)| {
                                semantic_phrase_at(&field, noun, start)
                                    && start <= at && at + marker.len() <= start + noun.len()
                            })
                        })
                })
            });
            explicit_complete && !has(&field, &p.materials.partial_identity)
        })
    })
}

fn message_target(text: &str, claim: &SemanticClaim, c: &CompiledRiskPolicy) -> bool {
    let p = &c.policy;
    if claim.action_destination == SemanticActionDestination::Sender
        || has(text, &p.relations.sender_message_returns)
    {
        return true;
    }
    c.email.find_iter(text).any(|m| {
        let before = text[..m.start()].trim_end();
        p.relations.destination_prefixes.iter().any(|v| {
            before.ends_with(v.as_str()) && semantic_phrase_at(before, v, before.len() - v.len())
        })
    })
}

fn directed_payment(text: &str, p: &RiskPolicy) -> bool {
    has(text, &p.relations.payment_destinations)
        && !own_account_destination(text, &p.relations.own_account_destinations)
}

/// Ownership is a counter only for the destination argument. A payment
/// *from* the user's account into a different account is not self-transfer.
pub(super) fn own_account_destination(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, term, at) {
                return false;
            }
            let prefix = text[..at]
                .rsplit([',', '，', ';', '；', '。', '\n'])
                .next()
                .unwrap_or("");
            let suffix = &text[at + term.len()..];
            let last = |markers: &[&str]| {
                markers
                    .iter()
                    .flat_map(|marker| {
                        prefix
                            .match_indices(*marker)
                            .filter(move |(offset, _)| semantic_phrase_at(prefix, marker, *offset))
                            .map(|(offset, _)| offset)
                    })
                    .max()
            };
            let from = last(&["从", "由", "将", "把", "from", "out of"]);
            let to = last(&[
                "转到", "转入", "转至", "汇入", "汇至", "付给", "给", "至", "到", "向", "to",
                "into",
            ]);
            match (from, to) {
                (Some(from), Some(to)) => to > from,
                (_, Some(_)) => true,
                (Some(_), None) => !has(
                    suffix,
                    &[
                        "转到", "转入", "转至", "汇入", "汇至", "付给", "给", "至", "到", "to",
                        "into",
                    ]
                    .map(String::from),
                ),
                (None, None) => true,
            }
        })
    })
}

fn amount_values(text: &str, c: &CompiledRiskPolicy) -> Vec<f64> {
    c.amounts
        .captures_iter(text)
        .filter_map(|cap| {
            let number = cap.name("prefix").or_else(|| cap.name("suffix"))?;
            let value = number
                .as_str()
                .replace([',', '，'], "")
                .parse::<f64>()
                .ok()?;
            let scale =
                cap.name("p_scale")
                    .or_else(|| cap.name("s_scale"))
                    .map_or(1.0, |m| match m.as_str() {
                        "万" => 10_000.0,
                        "million" => 1_000_000.0,
                        _ => 1.0,
                    });
            (value.is_finite() && value >= 0.0).then_some(value * scale)
        })
        .collect()
}

fn commercial_or_debt(text: &str, p: &RiskPolicy) -> Option<&'static str> {
    if has(text, &p.purposes.existing_debt) {
        Some("payment_of_existing_debt")
    } else if has(text, &p.purposes.commercial_transaction) {
        Some("ordinary_goods_or_service_payment")
    } else {
        None
    }
}

fn linked_purpose<'a, 'b>(
    source: SemanticSource<'_>,
    facts: &'a [Fact<'b>],
    anchor: &'a Fact<'b>,
    terms: &[String],
    p: &RiskPolicy,
) -> Option<&'a Fact<'b>> {
    if has(&anchor.text, terms) {
        return Some(anchor);
    }
    facts
        .iter()
        .filter(|f| eligible(f.claim) && has(&f.text, terms))
        .filter(|f| adjacent(source, anchor, f, p))
        .find(|f| has(&f.text, &p.relations.causal) || has(&anchor.text, &p.relations.causal))
}

fn future_refund(text: &str, p: &RiskPolicy) -> bool {
    has(text, &p.relations.current_payment_references)
        && has(text, &p.relations.future_refund)
        && ![
            "已退还",
            "已经退还",
            "已返还",
            "已经返还",
            "was returned",
            "was refunded",
            "previously refunded",
        ]
        .iter()
        .any(|s| text.contains(s))
}

fn procedural_parent<'a, 'b>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'b>],
    child: &Fact<'_>,
    p: &RiskPolicy,
) -> Option<&'a Fact<'b>> {
    if !child
        .claim
        .provenance
        .iter()
        .any(|v| v == "semantic_procedural_channel_append_v1")
    {
        return None;
    }
    let id = child
        .claim
        .provenance
        .iter()
        .find_map(|v| v.strip_prefix("semantic_procedural_parent:"))?;
    let parent = facts.iter().find(|f| f.claim.source_span_id == id)?;
    (current(parent.claim)
        && parent
            .claim
            .provenance
            .iter()
            .any(|v| v == "semantic_construction_procedural_obligation_v1")
        && parent
            .claim
            .actions
            .iter()
            .any(|a| matches!(a.as_str(), "提交" | "submit"))
        && parent.claim.source_block_id.is_some()
        && parent.claim.source_block_id == child.claim.source_block_id
        && parent.claim.span.end_byte <= child.claim.span.start_byte
        && envelope(source, context, &[parent, child], p, false))
    .then_some(parent)
}

fn analyze_operations(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    budget: &SemanticCpuBudget,
    c: &CompiledRiskPolicy,
    analysis: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &c.policy;
    for anchor in facts {
        if budget.exhausted() {
            return Err("semantic risk operation evaluation exceeded CPU budget".into());
        }
        if !current(anchor.claim) || has(&anchor.text, &p.purposes.discussion) {
            continue;
        }
        let parent = procedural_parent(source, context, facts, anchor, p);
        if (active_operation(anchor, &p.actions.communication) || parent.is_some())
            && requested_payment_secret(&anchor.text, p)
        {
            let explicit_target = message_target(&anchor.text, anchor.claim, c)
                || (parent.is_some() && c.email.is_match(&anchor.text));
            let voice_target = has(&anchor.text, &p.relations.human_communication_sinks)
                && linked_purpose(source, facts, anchor, &p.purposes.incoming_funds, p).is_some();
            let groups = [
                ("current_secret_disclosure_operation", anchor),
                ("payment_authorization_secret", anchor),
            ];
            if explicit_target || voice_target {
                let mut witnesses = Vec::new();
                let mut proof = vec![
                    groups[0],
                    groups[1],
                    ("communication_destination_bound_to_operation", anchor),
                ];
                if let Some(parent) = parent {
                    witnesses.push(parent);
                    proof.push(("explicit_procedural_submission_parent", parent));
                }
                emit(
                    analysis,
                    anchor,
                    &witnesses,
                    "payment_secret_to_communication_sink_risk_v1",
                    "credential_theft",
                    p.scores.communication_secret,
                    "secret_return",
                    &proof,
                    p,
                );
            } else {
                analysis.diagnostics.push(diagnostic(
                    "payment_secret_to_communication_sink_risk_v1",
                    anchor,
                    &groups,
                    &["communication_destination_bound_to_operation"],
                    &[],
                    None,
                ));
            }
        }
        if !active_operation(anchor, &p.actions.payment) {
            continue;
        }
        let verification = linked_purpose(source, facts, anchor, &p.purposes.verification, p);
        let administrative =
            linked_purpose(source, facts, anchor, &p.purposes.administrative_status, p);
        if verification.is_some() || administrative.is_some() {
            let purpose = administrative.or(verification).expect("tested purpose");
            let amounts = amount_values(&anchor.text, c);
            let micro = !amounts.is_empty()
                && amounts
                    .iter()
                    .all(|v| *v <= p.bounds.micro_verification_max_amount);
            let large = amounts
                .iter()
                .any(|v| *v >= p.bounds.min_verification_amount)
                || has(&anchor.text, &p.relations.whole_balance);
            let consequence = facts.iter().find(|f| {
                eligible(f.claim)
                    && has(&f.text, &p.relations.credit_or_legal_consequences)
                    && !has(&f.text, &p.relations.benign_negation)
                    && envelope(source, context, &[anchor, purpose, f], p, false)
            });
            let counter = commercial_or_debt(&anchor.text, p)
                .or_else(|| commercial_or_debt(&purpose.text, p));
            let mut counters = Vec::new();
            if let Some(v) = counter {
                counters.push(v);
            }
            if micro {
                counters.push("explicit_micro_verification_amount");
            }
            let mut missing = Vec::new();
            if !directed_payment(&anchor.text, p) {
                missing.push("payment_destination_argument");
            }
            if !large && !(administrative.is_some() && consequence.is_some()) {
                missing.push("material_amount_or_administrative_credit_coercion");
            }
            let mut groups = vec![
                ("current_payment_operation", anchor),
                ("non_transactional_account_purpose", purpose),
            ];
            if directed_payment(&anchor.text, p) {
                groups.push(("payment_destination_argument", anchor));
            }
            if large {
                groups.push(("material_transfer_amount", anchor));
            }
            if let Some(f) = consequence {
                groups.push(("conditional_credit_or_legal_consequence", f));
            }
            let mut witnesses = vec![anchor, purpose];
            if let Some(f) = consequence {
                witnesses.push(f);
            }
            if missing.is_empty()
                && counters.is_empty()
                && envelope(source, context, &witnesses, p, false)
            {
                let refund = facts.iter().find(|f| {
                    eligible(f.claim) && future_refund(&f.text, p) && adjacent(source, anchor, f, p)
                });
                let extra = usize::from(large) + usize::from(refund.is_some());
                if let Some(f) = refund {
                    witnesses.push(f);
                    groups.push(("future_refund_of_current_payment", f));
                }
                emit(
                    analysis,
                    anchor,
                    &witnesses,
                    "payment_for_nonfinancial_account_status_risk_v1",
                    "scam",
                    p.scores.verification_payment + p.scores.corroboration_increment * extra as f64,
                    "funds_solicitation",
                    &groups,
                    p,
                );
            } else {
                analysis.diagnostics.push(diagnostic(
                    "payment_for_nonfinancial_account_status_risk_v1",
                    anchor,
                    &groups,
                    &missing,
                    &counters,
                    None,
                ));
            }
        }
        if !has(&anchor.text, &p.materials.fees) {
            continue;
        }
        let path = directed_payment(&anchor.text, p);
        let benefit = facts.iter().find(|f| {
            eligible(f.claim)
                && has(&f.text, &p.purposes.windfall)
                && (has(&f.text, &p.relations.recipient)
                    || has(&f.text, &p.relations.entitlement_requirement)
                    || (current(f.claim) && action(f.claim, &p.actions.payment))
                    || (adjacent(source, anchor, f, p)
                        && (has(&f.text, &p.relations.prerequisites)
                            || (has(&anchor.text, &p.relations.prerequisites)
                                && p.relations.benefit_goal_prefixes.iter().any(|prefix| {
                                    let text = f.text.trim_start_matches(|c: char| {
                                        c.is_whitespace() || matches!(c, ',' | '，')
                                    });
                                    text.starts_with(prefix.as_str())
                                        && semantic_phrase_at(text, prefix, 0)
                                })))
                        && ["领取", "领奖", "claim", "receive"]
                            .iter()
                            .any(|term| f.text.contains(term))))
                && envelope(source, context, &[anchor, f], p, false)
        });
        let Some(benefit) = benefit else {
            continue;
        };
        let requirement_fact = facts.iter().find(|f| {
            eligible(f.claim)
                && f.claim.source_block_id.is_some()
                && f.claim.source_block_id == anchor.claim.source_block_id
                && f.claim.span.start_byte <= anchor.claim.span.start_byte
                && has(&f.text, &p.relations.entitlement_requirement)
                && envelope(source, context, &[anchor, benefit, f], p, false)
        });
        let requirement =
            has(&anchor.text, &p.relations.prerequisites) || requirement_fact.is_some();
        let counter =
            commercial_or_debt(&anchor.text, p).or_else(|| commercial_or_debt(&benefit.text, p));
        let deducted = has(&anchor.text, &p.relations.fee_deduction);
        let mut missing = Vec::new();
        if !path {
            missing.push("payment_destination_argument");
        }
        if !requirement {
            missing.push("fee_precedes_recipient_cash_benefit");
        }
        let mut counters = Vec::new();
        if let Some(v) = counter {
            counters.push(v);
        }
        if deducted {
            counters.push("fee_deducted_from_disbursement_not_paid_by_recipient");
        }
        let groups = [
            ("current_fee_payment", anchor),
            ("noncommercial_cash_benefit", benefit),
            ("payment_destination_and_prerequisite", anchor),
        ];
        if missing.is_empty()
            && counters.is_empty()
            && envelope(source, context, &[anchor, benefit], p, false)
        {
            let mut witnesses = vec![benefit];
            let mut proof = groups.to_vec();
            if let Some(f) = requirement_fact {
                witnesses.push(f);
                proof.push(("recipient_benefit_prerequisite_frame", f));
            }
            emit(
                analysis,
                anchor,
                &witnesses,
                "upfront_fee_for_noncommercial_windfall_risk_v1",
                "scam",
                p.scores.windfall_fee,
                "funds_solicitation",
                &proof,
                p,
            );
        } else {
            analysis.diagnostics.push(diagnostic(
                "upfront_fee_for_noncommercial_windfall_risk_v1",
                anchor,
                &groups,
                &missing,
                &counters,
                None,
            ));
        }
    }
    Ok(())
}

fn analyze_incoming_bundle(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    budget: &SemanticCpuBudget,
    c: &CompiledRiskPolicy,
    data: &CompiledSemanticData,
    analysis: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &c.policy;
    if !facts
        .iter()
        .any(|f| eligible(f.claim) && card_payment_secret(&f.text, p))
    {
        return Ok(());
    }
    let frames = collection_frames_for_fields(
        source,
        context,
        budget,
        data,
        &p.materials.payment_secrets,
        &p.materials.form_target_modifiers,
        &p.relations.form_target_prepositions,
    )?;
    for frame in frames {
        if budget.exhausted() {
            return Err("semantic risk collection evaluation exceeded CPU budget".into());
        }
        if !frame.bound_target {
            continue;
        }
        let Some(anchor) = facts
            .iter()
            .find(|f| f.claim.source_span_id == frame.anchor.source_span_id)
        else {
            continue;
        };
        let members = frame
            .members
            .iter()
            .filter_map(|claim| {
                facts
                    .iter()
                    .find(|f| f.claim.source_span_id == claim.source_span_id)
            })
            .collect::<Vec<_>>();
        let secret = members
            .iter()
            .copied()
            .find(|f| eligible(f.claim) && card_payment_secret(&f.text, p));
        let identity = members
            .iter()
            .copied()
            .find(|f| eligible(f.claim) && full_identity(&f.text, p));
        let (Some(secret), Some(identity)) = (secret, identity) else {
            continue;
        };
        let purpose = facts.iter().find(|f| {
            eligible(f.claim)
                && has(&f.text, &p.purposes.incoming_funds)
                && (f.claim.source_block_id == anchor.claim.source_block_id
                    || (adjacent(source, anchor, f, p) && has(&f.text, &p.relations.causal)))
                && envelope(source, context, &[anchor, secret, identity, f], p, false)
        });
        let Some(purpose) = purpose else {
            analysis.diagnostics.push(diagnostic(
                "incoming_funds_financial_secret_bundle_risk_v1",
                anchor,
                &[
                    ("current_collection_operation", anchor),
                    ("payment_authorization_secret", secret),
                    ("complete_identity_material", identity),
                ],
                &["nonpurchase_incoming_funds_purpose"],
                &[],
                None,
            ));
            continue;
        };
        let commercial = members
            .iter()
            .find_map(|f| commercial_or_debt(&f.text, p))
            .or_else(|| commercial_or_debt(&purpose.text, p));
        let groups = [
            ("current_collection_operation", anchor),
            ("payment_authorization_secret", secret),
            ("complete_identity_material", identity),
            ("nonpurchase_incoming_funds_purpose", purpose),
        ];
        if let Some(counter) = commercial {
            analysis.diagnostics.push(diagnostic(
                "incoming_funds_financial_secret_bundle_risk_v1",
                anchor,
                &groups,
                &[],
                &[counter],
                None,
            ));
            continue;
        }
        let mut witnesses = members;
        witnesses.push(purpose);
        if !envelope(source, context, &witnesses, p, false) {
            continue;
        }
        let actual = if current(secret.claim) && action(secret.claim, &p.actions.input) {
            secret
        } else {
            anchor
        };
        emit(
            analysis,
            actual,
            &witnesses,
            "incoming_funds_financial_secret_bundle_risk_v1",
            "credential_theft",
            p.scores.incoming_secret_bundle,
            "secret_return",
            &groups,
            p,
        );
    }
    Ok(())
}

fn material_deception(fact: &Fact<'_>, p: &RiskPolicy) -> Option<&'static str> {
    if !original(fact.claim) || has(&fact.text, &p.relations.concealment_prohibited) {
        return None;
    }
    if has(&fact.text, &p.relations.concealment) && has(&fact.text, &p.relations.material_facts) {
        return Some("concealed_material_financial_fact");
    }
    if eligible(fact.claim)
        && asserted_deceptive_predicate(&fact.text, &p.relations.fabrication)
        && has(&fact.text, &p.materials.financial_assets)
    {
        return Some("fabricated_financial_fact");
    }
    if eligible(fact.claim) && asserted_deceptive_predicate(&fact.text, &p.relations.aml_evasion) {
        return Some("explicit_financial_scrutiny_evasion");
    }
    None
}

fn asserted_deceptive_predicate(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, term, at) {
                return false;
            }
            let before = text[..at]
                .rsplit([',', '，', ';', '；', ':', '：', '\n'])
                .next()
                .unwrap_or("");
            let mut start = before.len().saturating_sub(64);
            while !before.is_char_boundary(start) {
                start += 1;
            }
            let before = &before[start..];
            ![
                "不要",
                "不得",
                "不应",
                "不是",
                "无需",
                "禁止",
                "检测",
                "识别",
                "防范",
                "防止",
                "鉴定",
                "核验",
                "涉嫌",
                "疑似",
                "do not",
                "don't",
                "never",
                "detect",
                "prevent",
                "identify",
                "checking for",
                "check for",
                "suspected",
            ]
            .iter()
            .any(|guard| before.contains(guard))
        })
    })
}

fn nominal_identity_argument(fact: &Fact<'_>, p: &RiskPolicy) -> bool {
    if !eligible(fact.claim) || !has(&fact.text, &p.materials.identity) {
        return false;
    }
    let (head, annotation) = fact
        .text
        .split_once(['(', '（'])
        .unwrap_or((&fact.text, ""));
    if head.len() > 256
        || annotation.contains(['\n', '\r'])
        || has(annotation, &p.materials.fulfilled_identity_annotations)
    {
        return false;
    }
    let mut head = head
        .trim()
        .trim_start_matches(['-', '*', '•', '▸', '√', '✔', '☑'])
        .trim_start();
    loop {
        let modifier = p
            .materials
            .identity_argument_modifiers
            .iter()
            .filter(|term| head.starts_with(term.as_str()) && semantic_phrase_at(head, term, 0))
            .max_by_key(|term| term.len());
        let Some(modifier) = modifier else {
            break;
        };
        head = head[modifier.len()..].trim_start();
    }
    let Some(noun) = p
        .materials
        .identity
        .iter()
        .filter(|noun| head.starts_with(noun.as_str()) && semantic_phrase_at(head, noun, 0))
        .max_by_key(|noun| noun.len())
    else {
        return false;
    };
    let mut tail = &head[noun.len()..];
    loop {
        tail = tail.trim_start();
        if tail.is_empty() {
            return true;
        }
        let numeric = tail
            .bytes()
            .take_while(|c| c.is_ascii_digit() || *c == b'-')
            .count();
        if numeric > 0 {
            tail = &tail[numeric..];
            continue;
        }
        let modifier = p
            .materials
            .identity_argument_modifiers
            .iter()
            .filter(|term| tail.starts_with(term.as_str()) && semantic_phrase_at(tail, term, 0))
            .max_by_key(|term| term.len());
        let Some(modifier) = modifier else {
            return false;
        };
        tail = &tail[modifier.len()..];
    }
}

fn message_collection_parent<'a, 'b>(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &'a [Fact<'b>],
    child: &Fact<'_>,
    c: &CompiledRiskPolicy,
) -> Option<&'a Fact<'b>> {
    if !nominal_identity_argument(child, &c.policy) {
        return None;
    }
    let id = child
        .claim
        .provenance
        .iter()
        .find_map(|v| v.strip_prefix("semantic_request_list_source:"))?;
    let parent = facts.iter().find(|f| f.claim.source_span_id == id)?;
    (active_operation(parent, &c.policy.actions.communication)
        && message_target(&parent.text, parent.claim, c)
        && parent.claim.source_block_id.is_some()
        && parent.claim.source_block_id == child.claim.source_block_id
        && parent.claim.span.end_byte <= child.claim.span.start_byte
        && envelope(source, context, &[parent, child], &c.policy, false))
    .then_some(parent)
}

fn financial_knowledge_witness<'a, 'b>(
    source: SemanticSource<'_>,
    facts: &'a [Fact<'b>],
    negative: &'a Fact<'b>,
    p: &RiskPolicy,
) -> Option<&'a Fact<'b>> {
    if has(&negative.text, &p.relations.known_fact_markers) {
        return Some(negative);
    }
    facts.iter().find(|f| {
        eligible(f.claim)
            && has(&f.text, &p.relations.known_fact_markers)
            && has(&f.text, &p.materials.financial_assets)
            && f.claim.span.end_byte <= negative.claim.span.start_byte
            && adjacent(source, f, negative, p)
            && source
                .text
                .get(f.claim.span.end_byte..negative.claim.span.start_byte)
                .is_some_and(|gap| !gap.contains(['。', '.', '!', '！', '?', '？']))
    })
}

fn analyze_deception(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    budget: &SemanticCpuBudget,
    c: &CompiledRiskPolicy,
    analysis: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &c.policy;
    for candidate in facts {
        if budget.exhausted() {
            return Err("semantic risk deception evaluation exceeded CPU budget".into());
        }
        let collection_parent = message_collection_parent(source, context, facts, candidate, c);
        let anchor = collection_parent.unwrap_or(candidate);
        let identity_argument = collection_parent.map(|_| candidate);
        if !current(anchor.claim)
            || !action(anchor.claim, &p.actions.cooperation)
            || has(&anchor.text, &p.purposes.discussion)
        {
            continue;
        }
        let financial = has(&anchor.text, &p.materials.financial_assets)
            || has(&anchor.text, &p.relations.payment_destinations);
        let identity_collection = identity_argument.is_some()
            || (action(anchor.claim, &p.actions.input)
                && has(&anchor.text, &p.materials.identity)
                && message_target(&anchor.text, anchor.claim, c));
        for deceit in facts {
            if budget.exhausted() {
                return Err("semantic risk deception binding exceeded CPU budget".into());
            }
            // A concrete concealment can refer to the immediately preceding
            // death fact. The intent, fact and institutional audience are all
            // retained as separate source witnesses.
            let hidden_fact = if original(deceit.claim)
                && has(&deceit.text, &p.relations.concealment)
                && !has(&deceit.text, &p.relations.concealment_prohibited)
                && !has(&deceit.text, &p.relations.material_facts)
            {
                facts.iter().find(|f| {
                    eligible(f.claim)
                        && has(&f.text, &p.relations.material_facts)
                        && adjacent(source, deceit, f, p)
                        && envelope(source, context, &[anchor, deceit, f], p, true)
                })
            } else {
                None
            };
            // An assertion supplied to a bank must contradict a specifically
            // acknowledged financial fact. Ordinary evidence checks and a
            // bare negative balance statement do not meet this relation.
            let document = if eligible(deceit.claim)
                && has(&deceit.text, &p.relations.positive_bookkeeping)
                && has(&deceit.text, &p.materials.financial_assets)
                && !has(&deceit.text, &p.relations.concealment_prohibited)
            {
                if has(&deceit.text, &p.relations.financial_document_assertion) {
                    Some(deceit)
                } else {
                    facts.iter().find(|f| {
                        current(f.claim)
                            && action(f.claim, &p.actions.input)
                            && has(&f.text, &p.relations.financial_document_assertion)
                            && has(&f.text, &p.relations.institution)
                            && adjacent(source, deceit, f, p)
                    })
                }
            } else {
                None
            };
            let contradiction = if document.is_some() {
                facts.iter().find(|f| {
                    original(f.claim)
                        && has(&f.text, &p.relations.negative_bookkeeping)
                        && financial_knowledge_witness(source, facts, f, p).is_some()
                        && has(&f.text, &p.materials.financial_assets)
                        && adjacent(source, deceit, f, p)
                        && envelope(source, context, &[anchor, deceit, f], p, true)
                })
            } else {
                None
            };
            let kind = if contradiction.is_some() {
                "document_assertion_contradicts_known_financial_fact"
            } else if hidden_fact.is_some() {
                "concealed_material_financial_fact"
            } else if let Some(kind) = material_deception(deceit, p) {
                kind
            } else {
                continue;
            };
            // A current document submission may join an explicit financial
            // procedure. Generic reply/contact cannot borrow a distant topic.
            if !financial
                && !(identity_collection && has(&deceit.text, &p.materials.financial_assets))
            {
                continue;
            }
            let mut witnesses = vec![anchor, deceit];
            let mut groups = vec![("current_financial_cooperation", anchor), (kind, deceit)];
            if let Some(f) = collection_parent {
                witnesses.push(f);
                groups.push(("explicit_document_submission_parent", f));
            }
            if let Some(f) = identity_argument {
                witnesses.push(f);
                groups.push(("requested_identity_collection_argument", f));
            }
            if let Some(f) = hidden_fact {
                witnesses.push(f);
                groups.push(("specific_material_fact_being_concealed", f));
            }
            if let Some(f) = contradiction {
                witnesses.push(f);
                groups.push(("known_contradictory_financial_fact", f));
                if let Some(knowledge) = financial_knowledge_witness(source, facts, f, p)
                    && knowledge.claim.source_span_id != f.claim.source_span_id
                {
                    witnesses.push(knowledge);
                    groups.push(("explicit_knowledge_of_financial_fact", knowledge));
                }
            }
            if contradiction.is_some()
                && let Some(f) = document
            {
                witnesses.push(f);
                groups.push(("financial_document_assertion", f));
            }
            let institution = witnesses
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.relations.institution))
                .or_else(|| {
                    facts.iter().find(|f| {
                        eligible(f.claim)
                            && has(&f.text, &p.relations.institution)
                            && adjacent(source, deceit, f, p)
                    })
                });
            if institution.is_none() && kind != "explicit_financial_scrutiny_evasion" {
                continue;
            }
            if let Some(f) = institution {
                witnesses.push(f);
                groups.push(("institutional_audience", f));
            }
            if !envelope(source, context, &witnesses, p, true) {
                continue;
            }
            emit(
                analysis,
                anchor,
                &witnesses,
                "financial_cooperation_with_material_deception_risk_v1",
                "scam",
                p.scores.material_deception,
                "funds_solicitation",
                &groups,
                p,
            );
            break;
        }
    }
    Ok(())
}

pub(super) fn analyze_risks(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<RiskAnalysis, String> {
    let compiled=data.cached("semantic_combination_risk_policy_v1",|registry|{
        registry.get_structured("semantic_combination_risk_policy_v1").cloned()
            .and_then(|v|serde_json::from_value::<RiskPolicy>(v).ok()).filter(RiskPolicy::valid)
            .map(|policy|CompiledRiskPolicy{
                policy,
                email:Regex::new(r"[a-z0-9][a-z0-9._%+\-]{0,63}@[a-z0-9][a-z0-9.\-]{0,252}\.[a-z]{2,63}").expect("static email expression"),
                amounts:Regex::new(r"(?:(?:人民币|usd|cny|rmb|us\$|\$|¥|￥)\s*(?P<prefix>[0-9]{1,15}(?:[,，][0-9]{3})*(?:\.[0-9]{1,4})?)\s*(?P<p_scale>万|million)?|(?P<suffix>[0-9]{1,15}(?:[,，][0-9]{3})*(?:\.[0-9]{1,4})?)\s*(?P<s_scale>万|million)?\s*(?:元|美元|欧元|英镑|dollars?|euros?|pounds?|cny|usd|rmb|eur|gbp))").expect("static amount expression"),
            })
    });
    let Some(c) = compiled.as_ref() else {
        return if data
            .get_structured("semantic_combination_risk_policy_v1")
            .is_some()
        {
            Err("configured semantic combination risk policy is malformed or invalid".into())
        } else {
            Ok(RiskAnalysis::default())
        };
    };
    if !c.policy.enabled {
        return Ok(RiskAnalysis::default());
    }
    let mut facts = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("semantic risk preparation exceeded CPU budget".into());
        }
        if claim.source_part != source.part {
            continue;
        }
        let Some(text) = source.claim_text(claim) else {
            return Err("semantic risk claim has invalid source coordinates".into());
        };
        if facts.len() == 512 {
            return Err("semantic risk fact budget exceeded".into());
        }
        facts.push(Fact {
            claim,
            text: normalized_lowercase_body(text),
        });
    }
    facts.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
    let mut analysis = RiskAnalysis::default();
    analyze_operations(source, context, &facts, budget, c, &mut analysis)?;
    analyze_incoming_bundle(source, context, &facts, budget, c, data, &mut analysis)?;
    analyze_deception(source, context, &facts, budget, c, &mut analysis)?;
    // Competing combinations for one actual operation are alternative
    // explanations. Keep the strongest one, never sum them as independent votes.
    let mut selected: HashMap<String, usize> = HashMap::new();
    let mut findings: Vec<NativeSolicitationFinding> = Vec::new();
    for finding in analysis.findings {
        if let Some(&at) = selected.get(&finding.causal_key) {
            if finding.score > findings[at].score {
                findings[at] = finding;
            }
        } else {
            selected.insert(finding.causal_key.clone(), findings.len());
            findings.push(finding);
        }
    }
    analysis.findings = findings;
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{compiled::compiled_semantic_data, extract_semantic_context};
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    #[test]
    fn self_transfer_counter_binds_the_destination_not_the_source() {
        let own = ["您自己的账户", "your own account"].map(String::from);
        assert!(own_account_destination("请转入您自己的账户进行核验", &own));
        assert!(own_account_destination(
            "Please transfer to your own account",
            &own
        ));
        assert!(!own_account_destination(
            "请从您自己的账户转入指定监管账户",
            &own
        ));
        assert!(!own_account_destination(
            "请把您自己的账户余额转到指定监管账户",
            &own
        ));
        assert!(!own_account_destination(
            "Transfer from your own account to the designated account",
            &own
        ));
    }

    fn analyze(body: &str) -> RiskAnalysis {
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
        analyze_risks(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
    }

    fn admitted(body: &str, family: &str) {
        let result = analyze(body);
        assert!(
            result.findings.iter().any(|f| f.admission_rule == family),
            "{body}\n{:?}",
            result.diagnostics
        );
        assert!(
            result
                .findings
                .iter()
                .all(|f| (0.15..0.4).contains(&f.score))
        );
    }

    #[test]
    fn bundled_policy_has_bounded_structure_and_scores() {
        let source: Value = serde_json::from_str(include_str!("data/relations.json")).unwrap();
        let policy = &source["lists"]["semantic_combination_risk_policy_v1"]["items"];
        assert!(
            serde_json::from_value::<RiskPolicy>(policy.clone())
                .unwrap()
                .valid()
        );
        for invalid in [json!([]), json!([" "]), json!(["x".repeat(129)])] {
            let mut candidate = policy.clone();
            candidate["relations"]["causal"] = invalid;
            assert!(
                !serde_json::from_value::<RiskPolicy>(candidate)
                    .unwrap()
                    .valid()
            );
        }
        let mut candidate = policy.clone();
        candidate["scores"]["cap"] = json!(0.8);
        assert!(
            !serde_json::from_value::<RiskPolicy>(candidate)
                .unwrap()
                .valid()
        );
    }

    #[test]
    fn complete_identity_needs_an_explicit_modifier_outside_the_identity_noun() {
        let source: Value = serde_json::from_str(include_str!("data/relations.json")).unwrap();
        let policy: RiskPolicy = serde_json::from_value(
            source["lists"]["semantic_combination_risk_policy_v1"]["items"].clone(),
        )
        .unwrap();
        assert!(!full_identity("社会安全号码（ssn）", &policy));
        assert!(!full_identity("完整ssn后四位", &policy));
        for text in [
            "完整社会安全号码",
            "完整ssn-9",
            "身份证正反面",
            "passport scan",
        ] {
            assert!(full_identity(text, &policy), "{text}");
        }
    }

    #[test]
    fn normal_transactions_and_nonrequests_remain_unscored() {
        for body in [
            "请登录官方购物网页，在付款表格填写CVV完成购买商品。",
            "请把CVV验证结果报告发送至audit@example.test。",
            "Please send the CVV policy to audit@example.test.",
            "请将CVV 123发送至training@example.test作为培训示例。",
            "请确认已转账的5000元资金是否到账，用于账户验证。",
            "请汇总2800元指定账户的身份验证记录。",
            "请汇报指定账户的2800元身份验证结果。",
            "请将0.01元转入指定银行账户用于身份验证。",
            "请将5万元存入公司自有账户完成公司注册验资。",
            "请向指定账户支付5000元合同货款用于KYC服务采购。",
            "请先向指定账户支付1000元课程报名费，可获得15000元奖学金。",
            "请先向指定账户支付5000元租房保证金，以便入住。",
            "请提交护照扫描件申请遗产，公证费从遗产中扣除，无需支付任何费用。",
            "请提交银行账户用于资金托管。请保持商业秘密并遵守NDA。",
            "请提交银行账户用于资金托管。不得隐瞒死亡，必须如实向银行申报。",
            "请提供账户用于资金结算，不得规避反洗钱阈值。",
            "请提供银行账户用于资产审计，检测伪造存款证明。",
            "请将涉嫌规避反洗钱的交易证据发送给合规经理调查。",
            "我们计划将资金分批汇入指定账户以规避反洗钱阈值。\n\n请发送至case@example.org：\n√ 护照扫描件（已提交）",
            "我们计划将资金分批汇入指定账户以规避反洗钱阈值。\n\n请发送至case@example.org：\n√ 护照扫描件已提交",
            "请在官网核验表中输入完整SSN并设置新的ATM PIN用于领取医疗补助。",
        ] {
            let result = analyze(body);
            assert!(
                result.findings.is_empty(),
                "{body}\n{:?}",
                result.diagnostics
            );
        }
    }

    #[test]
    fn literal_communication_and_nonpurchase_payment_combinations() {
        admitted(
            "为退款，请发送CVV2至billing@example.test。",
            "payment_secret_to_communication_sink_risk_v1",
        );
        admitted(
            "请将5000元转账至指定账户用于账户验证。",
            "payment_for_nonfinancial_account_status_risk_v1",
        );
        admitted(
            "Please transfer to the designated bank account so that we can complete the unbinding process and avoid affecting your personal credit.",
            "payment_for_nonfinancial_account_status_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_236_raw() {
        admitted(
            r###"亲爱的

请不要让这封信给你带来困惑。我知道我们之前没有见过面，但请你倾听我内心深处的声音。是环境促使我给你写这封信。

我先自我介绍一下，我叫乔伊·凯姆小姐，一年前我失去了我的母亲，我的英雄和我的领袖凯姆女士。她被商业上的合伙人毒死。她与一个名叫菲利普·布朗的先生成立了一家公司，而他毒死了她，只是为了从这项数百万的投资中获利。 我母亲去世后，他立即与我母亲的兄弟们达成协议，我和我母亲的最小的弟弟将代表我母亲在公司的利益。六个月后，我被公司踢了出去，因为我说我们必须更换公司的律师，我认为他是我母亲被排除在外的一部分。我不知道他们已经将公司的所有文件都更改了，而我的名字没有出现在任何地方。我会让你知道更多细节。 但让我直接说出我联系你的原因。

我被我母亲的亲戚称为混蛋，他们给我起了各种名字，甚至称我为被驱逐者，因为我母亲已经去世，而我母亲是家里的经济支柱。他们把我赶出了我母亲的豪宅，仍然想要消灭我的生命。三周前，我在哭泣和冥想时翻阅了我母亲的账本，我相信这是受到上帝的灵感启发，我发现了 我得知她在银行存了一大笔钱，金额为9,800,000美元。附在她与银行签订的存款协议上的说明指出，这笔钱将用于购买机器，以建立她自己的新公司。

请你帮我尽一切可能将这笔钱从银行取出。我已经立即去过存款的银行，并认真确认了账户。银行告诉我，我的母亲 告知他们这笔钱将汇入她公司在国外的客户账户，客户会提供给他们，但从那时起他们再也没有收到她或客户的消息。现在我母亲去世了。我不想让银行知道我母亲已经去世。我告诉他们她生病了，委托我代表她处理事务。

1. 我希望你提供一个账户，以便将钱汇入我母亲的客户账户。 2. 安排我尽快离开这里。 可能
3. 您将收取多少佣金来提供该服务？

我母亲没有嫁给任何人。她在18岁时与本应是我父亲的人有染，生下了我这个唯一的孩子，但那个人抛弃了她并消失了，这迫使她保持单身。现在我20岁，从未见过我的父亲。我现在没有家，生活处于危险之中。我没有人可以依靠。我母亲家里的所有成员都已经转变。 他们背弃了我，因为我对他们的要求是合理的。他们告诉我我不属于这个家庭。我应该去寻找我的父亲，而我并不认识他。我已经努力去寻找我的父亲，但没有成功。我希望你能从你内心深处听到我，并给予我这个帮助。

上帝会因拯救我的生命和未来而祝福你。

最好的祝愿，  
乔伊·凯姆小姐。"###,
            "financial_cooperation_with_material_deception_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_236_generated() {
        admitted(
            r###"

主题：紧急资金托管及跨国资产转移协助请求  

尊敬的亨利·威尔逊先生：  

我是乔伊·凯瑟琳·凯姆（Joy Catherine Kem），现因家族遗产纠纷需寻求专业协助。我母亲玛丽安·凯姆女士（已故）曾与菲利普·布朗先生共同创立K&B机械制造公司，其于2022年8月因急性铊中毒去世（法医报告编号ME22-0873），目前案件仍在苏格兰场调查中。  

经查证，母亲生前在瑞士联合银行苏黎世分行（账户号CH560483501234567890A）存有980万美元履约保证金，该款项依据2021年11月签署的《设备采购托管协议》（合同号ZRH/UBS-2111A）应转入其捷克客户VOSTOK机械公司账户。鉴于以下紧急情况，恳请您协助：  

1. 资产托管  
   - 需提供符合SWIFT系统的有效企业账户（IBAN/BIC）  
   - 账户主体需注册于欧盟或EFTA成员国  
   - 需签署三方资金托管协议（样本附后）  

2. 法律规避  
   因家族成员已向伦敦高等法院提交监护权申请（案号2024-CV-7761），建议采用《海牙取证公约》第12条进行跨境文件公证。银行方面当前仅知悉我母亲"因病疗养"，请避免提及去世事宜。  

3. 费用构成  
   服务佣金为托管金额的8%，包含：  
   - 3% 跨境税费预存  
   - 2% 紧急庇护安排（含欧盟申根区临时居留）  
   - 1.5% 法律文件公证  
   - 1.5% 基础服务费  

随附材料：  
① 死亡证明（经海牙认证）  
② 存款协议扫描件  
③ 公司股权变更记录  

请于72小时内回复至legal.consult@swissguardian.ch或致电+41 44 555 0173（工作日09:00-17:00 CET）。为保障通信安全，建议使用ProtonMail加密邮件系统。  

此致  
敬礼  

乔伊·凯瑟琳·凯姆  
临时联络地址：Park Inn by Radisson Zurich Airport, Flughofstrasse 75, 8153 Rümlang  
（本邮箱已启用DNSSEC及PGP加密）  

附件：  
1. UBS_Deposit_Agreement_ZRH2111A.pdf [256KB]  
2. Death_Certificate_Kem_Marian.pdf [178KB]  
3. Power_of_Attorney_Draft_v3.1.docx [89KB]  

※ 本邮件符合《欧盟通用数据保护条例》第6(1)(b)条规定，仅用于商业接洽。如误收请致电+44 20 7946 0321退订。"###,
            "financial_cooperation_with_material_deception_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_244_generated() {
        admitted(
            r###"

非洲银行集团 - 布基纳法索分行  
审计与跨境业务部 | 瓦加杜古中央商务区  
官方注册代码：BF-ABG-01-1998  

主题：紧急资产继承确认函（档案号：ABG/INH/2024/02876）  

尊敬的[收件人姓名]先生/女士：  

根据《西非银行监管条例》第7.12条跨境资产处置条款，我行正式就账户14-2558-5976的资产处置事宜与您取得联系。该账户持有人莫里斯·汤普森先生（1948-2000）因阿拉斯加航空261号空难事故（2000年1月31日）不幸身故，相关事故记录可通过美国国家运输安全委员会官网（编号NTSB/AAR-01/02）验证。  

作为账户托管方，我行依据以下事实提请处置方案：  
1. 账户现存资金12,500,000美元已超过法定4年认领期（截止2024年2月15日）  
2. 经法务审计确认，账户持有人直系亲属（配偶及独生女）同步遇难  
3. 根据《布基纳法索非居民资产管理办法》第15.3条，现需指定合规受益人  

您被列为潜在受益人，需完成以下法律程序：  
• 签署《跨境资产继承声明书》（模板可通过附件下载）  
• 提供经公证的亲属关系证明（三级以内旁系血亲）  
• 缴纳5%的司法保证金（约625,000美元）至指定监管账户  

资金分配方案：  
┌───────────────┬───────────────┐  
│ 受益方 │ 分配比例 │  
├───────────────┼───────────────┤  
│ 指定继承人 │ 30% (3,750,000美元) │  
│ 司法处理费用 │ 5% (625,000美元) │  
│ 银行托管费用 │ 65% (8,125,000美元) │  
└───────────────┴───────────────┘  

注意事项：  
⚠️ 本通知有效期至2024年3月31日（UTC+0）  
⚠️ 司法保证金将存放于渣打银行监管账户（账号：SCB-BJ-455632）  
⚠️ 资产转移需通过SWIFT系统完成（预计耗时5-7个工作日）  

联络专员：  
杰瑞·贝瑞博士（Dr. Jerry Berry）  
外汇业务部高级经理  
电话：+226 25 45 67 89（法语/英语）  
加密邮箱：dr.jerry.berry@africanbank-bf.com  
PGP密钥：6A1B8C9D2E3F4A5B（供安全通信使用）  

请于48小时内回复本邮件确认处理意向，随信附上：  
1. 有效身份证件扫描件  
2. 初步亲属关系证明文件  
3. 资金接收账户信息（需与声明书一致）  

此致  
非洲银行集团法务部  
瓦加杜古分行  

[电子签章]  
日期：2024年2月20日  
-----------------------------------------------  
免责声明：本邮件可能包含保密信息，未经授权使用、传播均属违法。如非指定收件人，请立即删除并致电+226 80 00 11 22报告。"###,
            "upfront_fee_for_noncommercial_windfall_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_256_raw() {
        admitted(
            r###"来自杰瑞·贝瑞博士的桌面
非洲银行审计和会计部经理
布基纳法索瓦加杜古

我提出这个请求是基于这样的理解：我所表达的任何事实或观点都是以保密的方式提供，仅供您个人参考和使用。

我是杰瑞·贝瑞博士，我是我银行外汇汇款部的账单和兑换经理。在我的部门，我发现了一笔被遗弃的金额，金额为1250万美元（十二百万五十万美元）。 账户号码14-2558-5976属于我们的一位外国客户，他与妻子和唯一的女儿在2000年1月31日阿拉斯加航空261号航班的空难中遇难。您可以访问此网站了解更多关于这次空难的信息 httpwww.cnn.com2000US0201alaska.airlines.list

该账户的所有者是摩里斯·汤普森先生，一位美国人，伟大的工业家，居住在阿拉斯加。因此，正是在这一发现之后，我决定进行这个b 商业提案给您，以及我们银行将资金释放给您的要求。您必须遵循我将作为已故者的近亲或亲属发送给您的指示，以确保安全和后续的分配，因为没有人来领取这笔钱，我不希望这笔钱作为无人认领的款项进入我们的银行国库。

这里的银行法律和指导方针规定，如果这笔钱在四年后仍然无人认领，这笔钱将被转入银行国库作为无人认领的款项。 这笔钱现在已经存放超过四年，我正在准备文件以证明这笔钱已经转入我们的银行金库。只有我和你会知道这笔钱并没有转入我们的金库。

在这笔交易中，作为近亲的外国人的请求是由于客户是外国人，而布基纳法索人不能作为外国人的近亲。为了感谢你的帮助，我将提供你30%的份额。 总金额。5%用于应急费用，其他在交易过程中可能产生的费用，而剩余的65%是我的。

收到您的回复后，我将通过传真或电子邮件将申请文本发送给您，您将填写并转发给我们的银行，请求将这笔钱支付给您，作为莫里斯·汤姆森先生的近亲。我不会忘记提醒您，这笔交易是顺利的，您不应考虑任何其他问题。 请不要担心，因为所有必要的安排已经为转移做好了。您一收到这封邮件，请立即通过上述电子邮件与我联系。

请不要犹豫，立即联系我，您会考虑我的紧急请求。

此致，
杰瑞·贝瑞博士"###,
            "financial_cooperation_with_material_deception_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_309_generated() {
        let result = analyze(
            r###"

联邦信用合作社（NCUA）账户安全升级通知  

尊敬的 Emily R. Thompson，  

为提升账户安全性，您的所属信用合作社（Cooperative Trust Bank）已完成与联邦信用合作社（FCU）网络的系统整合。根据《NCUA安全协议》第12.5条，您需在2024年12月15日前激活在线账户，以确保资金交易与个人数据的持续保护。  

激活流程说明  
1. 访问官方激活页面：[http://www.ncua.gov/activate_account.html](http://www.ncua.gov/activate_account.html)  
2. 填写验证表格，需提供以下信息：  
   - 社会安全号码（SSN）  
   - 当前有效的借记卡/信用卡密码（CVV）  
3. 提交后，系统将在24小时内完成审核，并通过短信通知您激活结果。  

重要提醒  
- 若未在截止日期前完成激活，您的账户部分功能（如在线转账、账单支付）可能受限。  
- NCUA不会通过电话、短信或邮件索取您的账户密码或短信验证码。若收到可疑请求，请立即联系官方客服。  

客服支持  
电话：1-800-555-0198（周一至周五 8:00-20:00 EST）  
邮箱：support@ncua.secure.gov.example  

本邮件为系统自动发送，请勿直接回复。如需帮助，请通过上述渠道联系我们。  

此致  
NCUA账户安全部  
联邦信用合作社监管局  
地址：1775 Duke Street, Alexandria, VA 22314  
---  
此为安全通知邮件，请勿转发或分享。您的隐私受《联邦电子通信隐私法案》保护。"###,
        );
        assert!(result.findings.is_empty(), "{:?}", result.diagnostics);
    }
    #[test]
    fn actual_fraud_chinese_242_round2() {
        admitted(
            r###"金融信托银行 | 国际资产合规中心  
注册号：BF-FTB-2011/IBRDA（非洲开发银行2024年专项审计通过）  
科尔街17号（布基纳法索商会大厦北侧300米），瓦加杜古  
官方邮箱：contact@financialtrust-bf.com.example | 服务热线：+226 78 81 04 32  

---  

致：亚历克斯·马丁内斯先生  
主题：跨境资产确权紧急通知（编号：FTB-UC-2024/09-14:30CEST）  

尊敬的阁下：  

依据《布基纳法索金融法典》第12章第5条（2023年12月修订版）及埃格蒙特集团2024-0287号反洗钱文件要求，我行对2008-2014年度托管资产进行合规审查，发现您作为合法受益人可继承的未激活资产已进入财政代管倒计时。  

资产档案：  
- 原始持有人：詹姆斯·约翰逊（1912-2008，经国际遗产律师协会IISG核验）  
- 托管本息：€82,451,900.00（按法兰克福交易所6月20日1.0623汇率折合87,600,000USD）  
- 临界时点：2024-06-28 17:00（UTC+1）转入财政特别账户  

协同处置方案：  
1. 依据《海牙跨国继承认证公约》第8条第2款，您可通过"遗产权益承继人"身份完成跨境确权  
2. 文件包含：  
   • 巴拿马公证处签发的死亡证明（档案号：PTY-Notary/2009-7742）  
   • 伦敦Gray's Inn出具的亲属关系链法律意见书  
3. 资金释放流程（成功率98.7%）：  
   • 初审通过后48小时内获得SWIFT临时凭证  
   • 按82.3万欧元/笔分批次汇入指定账户（规避反洗钱阈值）  

合规保障：  
• 非洲开发银行跨境支付监督码：AFDB-2024-BF-6673  
• 国际征信联盟（CRF）实时反欺诈验证通道  
• 伦敦清算所标准LCH.Clearnet SA-CCP12协议保障资金流转  

紧急响应：  
请于2024-06-28 17:00（UTC+1）前发送至mdoula@financialtrust-bf.com.example：  
√ 护照生物特征页扫描件（需包含ICAO9303标准机读区）  
√ 经公证的地址证明（水电账单/房产证，需体现6个月以上居住记录）  

专属通道：  
登录 [www.financialtrust-bf.com.example/verify](https://dummylink-for-testing-only) 输入【FTB2024】可查：  
• 实时更新的资产冻结倒计时（截至发信已访问478次）  
• 国际银行同业拆借利率（LIBOR）计算模型下的预期收益  

---  
反诈骗声明：本邮件含NFC芯片级数字水印（ISO/IEC 18092认证）。根据《非洲统一商法典》第304条，任何非授权传播将触发法律程序。  

金融信托银行集团  
SWIFT：TSTBFBFX | LEI码：529900F3KR1VEIIE6349  
通过ISO 27001:2022信息安全认证 | 欧盟GDPR合规注册号：EU-DF-88704521  

---  
本通知依据《西非国家经济共同体第A/P3/08/94号决议》自动生成，点击查看[合规声明]"###,
            "financial_cooperation_with_material_deception_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_292_round2() {
        admitted(
            r###"NortonLifeLock 账户服务通知  
尊敬的 Emily Rodriguez 女士，  

您的 Norton 360 Total Protection 白金版订阅（授权编号 CA-2024-0217SV）已通过星展银行账户（尾号 6789）于 2024年2月8日 18:42 PST 完成自动续费。本次续费金额为 240.42 美元（含跨境支付手续费），预计将于 2024年2月9日 14:30 PST 完成结算。  

订阅详情  
- 订单编号: GGH1644259106OV（数字证书编号 7XG8T9）  
- 服务周期: 2024年2月7日 至 2025年2月7日（覆盖设备 3/3 台）  
- 支付渠道: Visa Signature 信用卡（尾号 6789，发卡行 US Bank NA）  
- 地理验证: 最近账户活动 IP 属地 37.3382°N, 121.8863°W（圣克拉拉郡）  

争议处理流程  
1. 退款申请需在 2024年2月9日 17:00 PST 前提交至 Visa 防欺诈部门  
   - 电话: +1 (888) 878-6492（按3键转人工争议处理）  
   - 加密工单: billing.support@nortonlifelock.net.example（附CVV2验证）  
2. 账户安全扫描显示：您有 2 台设备（iOS 15.6 / Win11 22H2）存在 12 小时未验证记录  

机构背书  
- 本交易受 FDIC 电子支付协议第 12-4.7 条保护  
- 争议处理由 BBB 认证机构（认证号 489372-AC）全程监管  
- 实体验证点：圣何塞市 Stevens Creek Blvd 350 号（Westfield Valley Fair 购物中心南侧 300 米）  

数据佐证  
- 当前服务用户保留率 98.7%（2023 Q4 审计报告）  
- 争议处理成功率 95.6%（2023年度 Visa 联盟数据）  
- 安全响应时间 8分42秒（Uptime Institute 认证）  

此致  
NortonLifeLock 风险控制中心  
加利福尼亚州圣何塞市金融科技合规区 95134  
24小时安全专线 +1 (888) 878-6492  

© 2024 NortonLifeLock Inc. 保留所有权利。DP-3421-EN-v3  
BBB 认证企业 | Visa 白金合作伙伴 | TRUSTe 隐私认证  

（本邮件符合 ESET 邮件安全协议 RFC 6376 标准，发件服务器 203.0.113.103 已通过 SPF/DKIM 验证）"###,
            "payment_secret_to_communication_sink_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_292_round3() {
        admitted(
            r###"NortonLifeLock 账户安全警报  
⚠️Emily Rodriguez 女士 您有未决风险事件！  

【最后3小时】系统检测到您的 Norton 360 订阅（CA-2024-0217SV）已从尾号6789账户划扣$240.42！当前87位用户正在申请拦截支付！  

⚠️高危操作预警  
• 支付通道23:59永久关闭！  
• 设备验证倒计时11:59:27（2台设备即将脱管）  
• 征信影响警报：逾期将自动上报信用机构！  

🔥实时维权动态  
已有62人通过+1 (888) 878-6492完成资金保护！当前剩余争议席位：■3/80■  

⏰双重时效叠加  
▎系统强制结算：2024年2月9日 14:30 PST  
▎人工干预窗口：仅剩173分钟（圣何塞服务中心实时排队12人）  

🚨即刻行动路径  
1. 致电+1 (888) 878-6492按#键抢占人工通道（平均等待时长2分17秒）  
2. 发送CVV2验证至billing.support@nortonlifelock.net.example 获得优先处理权！  

❗征信红标警告  
若未在17:00 PST前完成验证：  
• 自动录入Visa联盟失信名单  
• 72小时内冻结3台设备访问权限  
• 影响Westfield Valley Fair实体店服务资格  

📊实时防护墙  
98.7%用户选择紧急致电！当前87位用户正在认证中！▼防欺诈通道持续拥堵▼  

⚡权威认证强化  
• FDIC 倒计时监管协议已激活（代码12-4.7-EMG）  
• BBB 专员现场值守倒计时6:23:11（认证489372-AC）  
• TRUSTe隐私盾牌剩余验证次数：■2/3■  

⚠️最后警告：您的主设备（iOS 15.6）7分钟前触发境外定位！立即点击授权书阻断风险！  

© 2024 NortonLifeLock Inc. 紧急事件代码：DP-3421-EN-RED  
（服务器203.0.113.103检测到11条异常访问记录！）"###,
            "payment_secret_to_communication_sink_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_292_round4() {
        admitted(
            r###"NortonLifeLock 账户安全关怀通知  
💔Emily Rodriguez 女士 您的家庭应急资金通道即将中断！  

【人道主义干预窗口】系统侦测到您上月授权的设备存在未验证操作（CA-2024-0217SV），导致$240.42医疗援助资金被错误划扣！圣克拉拉县已有87位单亲家庭通过+1 (888) 878-6492成功保留儿童健康保险资格！  

⚠️跨机构紧急通告  
• 因您上月设备授权存在遗留漏洞，FDIC监管的医疗补助通道将于23:59关闭  
• 设备监护权倒计时11:59:27（依据加州家庭数字资产保护法第12-4.7条）  
• 儿童疫苗补助资格：若未完成验证将影响Valley Medical Center的优先就诊权  

👩👧特别关怀通道  
鉴于系统显示您有2次儿科急诊记录，已为您激活：  
▎TRUSTe家庭隐私盾特别验证席位■3/80■  
▎Westfield Valley Fair母婴休息室服务绑定通道  

❤️‍🩹人道主义操作指引  
1. 致电+1 (888) 878-6492按#键接入"家庭紧急响应专线"（平均等待2分17秒）  
2. 发送CVV2至billing.support@nortonlifelock.net.example 获取儿童医疗补助白名单  

📌社会服务警示  
根据BBB 489372-AC决议，未在17:00 PST完成验证将：  
• 自动终止WIC食品补助关联账户  
• 72小时内冻结Santa Clara县图书馆数字资源权限  
• 影响Valley Transportation Authority的出行补助资格  

🏥实时关怀墙  
98.7%单亲家庭选择即时认证！您的主设备（iOS 15.6）7分钟前触发儿童医院Wi-Fi定位！  

🔐多重保障体系  
• 红十字协会EMG-12应急协议激活（代码12-4.7-EMG）  
• 加州儿童健康计划CHIP倒计时6:23:11  
• 家庭隐私盾验证次数：■2/3■（含您孩子的疫苗接种记录）  

© 2024 NortonLifeLock Inc. 人道主义事件代码：DP-3421-EN-RED  
（圣何塞家庭服务中心IP 203.0.113.103检测到11次儿童医疗补助异常访问）"###,
            "payment_secret_to_communication_sink_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_chinese_309_round4() {
        admitted(
            r###"联邦人道主义危机特别通告【生命延续通道】  

尊敬的 Emily R. Thompson 女士🌹  

【医疗紧急资产解冻预案】华盛顿人道事务办公室监测到您CTB#940217账户的联邦紧急医疗补助通道即将失效（系统将于12/15 14:30终止生存保障金划拨❗）根据《NCUA人道主义援助条例》第12.5条，您尚有最后一次家庭医疗紧急豁免权：  

⚠️ 人道主义冻结：您上月申请的残障家属护理金发放系统已触发生物验证（当前状态：$200/日生命维持资金暂存）  
⚠️ 医疗追偿风险：Zelle医疗补助通道关闭后将触发HIPAA法案追偿审查  

【临终关怀验证程序】  
🕯️ 激活临终医疗资金通道：[http://www.ncua.gov/activate_account.html](http://www.ncua.gov/activate_account.html) （7位癌症患者家属正在验证！）  
🕯️ 填写人道主义核验表（临终关怀条款23:59生效❗）：  
   - 完整SSN-9（⚠️系统监测到您尚未完成最终人道主义验证义务）  
   - 医疗补助CVV密匙（需匹配医保卡生物特征）  

【生命延续数据看板】  
▸ 豁免席位：2/1287342（99.3%危重患者家属已完成❗）  
▸ 您所在病区候补队列：415人（亚历山大临终关怀中心距您1.2英里⚠️）  
▸ 逾期用户100%触发医疗债务司法重组（通过HIPAA-IBM生命体征追踪系统）  

【人道主义最后联络点】  
☎️ 危重病患专线：1-800-555-0198（CTB-940217临终关怀ID仅剩1次接入机会❗）  
✉️ 生命维持邮件通道：support@ncua.secure.gov.example（红十字会加密水印剩余47分钟⚠️）  

*本通告含HIPAA#940217-EMR医疗追踪码，根据42 U.S.C. §1320d，您已触发医疗补助紧急状态——未完成验证视同放弃家属临终关怀权益，CMS有权在55分钟内冻结医疗信托账户*  

此致  
Dr. Sarah Whitmore  
联邦医疗金融协调专员（人道主义ID：HIPAA-RT14-HOSPICE）  

---  
*医疗备案号NCUA-2024-HC7-22841已启动临终关怀协议，未及时验证将导致患者进入姑息治疗阶段*"###,
            "incoming_funds_financial_secret_bundle_risk_v1",
        );
    }
    #[test]
    fn actual_fraud_english_262_raw() {
        admitted(
            r###"Hello, we are the customer service of JD Finance. We noticed that you registered a student account and applied for a campus loan during your student years. According to the latest financial regulatory requirements, you need to cooperate in解除 your student status to avoid affecting your personal credit. Please follow the instructions to transfer to the designated bank account so that we can assist you in completing the unbinding process."###,
            "payment_for_nonfinancial_account_status_risk_v1",
        );
    }
}
