//! Economic risk is an attributed offer or a directed exchange, not a topic.
//! The output remains a Low review hypothesis, separate from native proofs.

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{SemanticClaim, SemanticMessageContext};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::risk::{RiskAnalysis, current, eligible};
use super::solicitation::NativeSolicitationFinding;
use super::source::SemanticSource;
use super::text::{normalized_lowercase_body, semantic_phrase_at};

const POLICY: &str = "semantic_economic_intent_risk_policy_v1";

#[derive(Default, Deserialize)]
#[serde(default)]
struct Policy {
    enabled: bool,
    max_relation_bytes: usize,
    max_neighbor_claims: usize,
    score: f64,
    investment_terms: Vec<String>,
    lossless_promises: Vec<String>,
    return_assurances: Vec<String>,
    daily_return_terms: Vec<String>,
    monthly_return_terms: Vec<String>,
    annual_return_terms: Vec<String>,
    disclosure_counters: Vec<String>,
    report_counters: Vec<String>,
    provider_frames: Vec<String>,
    invitation_actions: Vec<String>,
    channel_terms: Vec<String>,
    payment_actions: Vec<String>,
    fresh_transfer_actions: Vec<String>,
    inactive_payment_prefixes: Vec<String>,
    inactive_payment_suffixes: Vec<String>,
    payment_objects: Vec<String>,
    task_terms: Vec<String>,
    manipulated_task_terms: Vec<String>,
    principal_return_terms: Vec<String>,
    commission_terms: Vec<String>,
    prerequisite_terms: Vec<String>,
    employment_terms: Vec<String>,
    employment_fees: Vec<String>,
    employment_gates: Vec<String>,
    payout_terms: Vec<String>,
    loan_products: Vec<String>,
    loan_route_prefixes: Vec<String>,
    loan_route_counters: Vec<String>,
    recipient_benefit_frames: Vec<String>,
    release_terms: Vec<String>,
    fee_terms: Vec<String>,
    deduction_counters: Vec<String>,
    private_investment_destinations: Vec<String>,
    delegated_trading_terms: Vec<String>,
    own_account_counters: Vec<String>,
    principal_components: Vec<String>,
    return_actions: Vec<String>,
    work_access_terms: Vec<String>,
    grant_access_actions: Vec<String>,
    existing_funds_terms: Vec<String>,
    fund_access_actions: Vec<String>,
    incoming_payout_frames: Vec<String>,
    payout_route_heads: Vec<String>,
    outgoing_payout_frames: Vec<String>,
}

fn bounded(terms: &[String]) -> bool {
    !terms.is_empty()
        && terms.len() <= 96
        && terms.iter().all(|s| !s.trim().is_empty() && s.len() <= 128)
}

impl Policy {
    fn valid(&self) -> bool {
        if !self.enabled {
            return true;
        }
        (256..=2048).contains(&self.max_relation_bytes)
            && (1..=12).contains(&self.max_neighbor_claims)
            && self.score.is_finite()
            && (0.15..=0.34).contains(&self.score)
            && [
                &self.investment_terms,
                &self.lossless_promises,
                &self.return_assurances,
                &self.daily_return_terms,
                &self.monthly_return_terms,
                &self.annual_return_terms,
                &self.disclosure_counters,
                &self.report_counters,
                &self.provider_frames,
                &self.invitation_actions,
                &self.channel_terms,
                &self.payment_actions,
                &self.fresh_transfer_actions,
                &self.inactive_payment_prefixes,
                &self.inactive_payment_suffixes,
                &self.payment_objects,
                &self.task_terms,
                &self.manipulated_task_terms,
                &self.principal_return_terms,
                &self.commission_terms,
                &self.prerequisite_terms,
                &self.employment_terms,
                &self.employment_fees,
                &self.employment_gates,
                &self.payout_terms,
                &self.loan_products,
                &self.loan_route_prefixes,
                &self.loan_route_counters,
                &self.recipient_benefit_frames,
                &self.release_terms,
                &self.fee_terms,
                &self.deduction_counters,
                &self.private_investment_destinations,
                &self.delegated_trading_terms,
                &self.own_account_counters,
                &self.principal_components,
                &self.return_actions,
                &self.work_access_terms,
                &self.grant_access_actions,
                &self.existing_funds_terms,
                &self.fund_access_actions,
                &self.incoming_payout_frames,
                &self.payout_route_heads,
                &self.outgoing_payout_frames,
            ]
            .iter()
            .all(|v| bounded(v))
    }
}

struct CompiledPolicy {
    policy: Policy,
    percent: Regex,
    amount: Regex,
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

fn asserted(fact: &Fact<'_>, p: &Policy) -> bool {
    eligible(fact.claim)
        && !has(&fact.text, &p.report_counters)
        && !fact
            .claim
            .provenance
            .iter()
            .any(|value| value == "semantic_discussion_request_v1")
}

fn active_action(fact: &Fact<'_>, actions: &[String], p: &Policy) -> bool {
    current(fact.claim)
        && asserted(fact, p)
        && actions.iter().any(|verb| {
            let compact_provenance = match verb.as_str() {
                "转" => Some("semantic_compact_transfer_predicate_v1"),
                "借" => Some("semantic_compact_borrow_predicate_v1"),
                _ => None,
            };
            if compact_provenance.is_some_and(|provenance| {
                !fact.claim.actions.contains(verb)
                    || !fact.claim.provenance.iter().any(|p| p == provenance)
            }) {
                return false;
            }
            fact.text.match_indices(verb.as_str()).any(|(at, _)| {
                if !semantic_phrase_at(&fact.text, verb, at) {
                    return false;
                }
                let before = fact.text[..at].trim_end();
                let after = fact.text[at + verb.len()..].trim_start();
                let clause = before
                    .rsplit([',', '，', ';', '；', ':', '：', '\n'])
                    .next()
                    .unwrap_or("");
                let reset = [
                    "并现在",
                    "并立即",
                    "并",
                    "然后",
                    "再次",
                    "重新",
                    "and now",
                    "and then",
                    "then",
                    "please",
                ]
                .iter()
                .filter_map(|join| clause.rfind(join).map(|pos| pos + join.len()))
                .max()
                .unwrap_or(0);
                let governed = &clause[reset..];
                if ["已把", "已经把", "已将", "已经将", "早已", "曾把", "曾将"]
                    .iter()
                    .any(|past| governed.contains(past))
                    || [
                        "确认", "查询", "查看", "核对", "查阅", "检查", "confirm", "check",
                        "review",
                    ]
                    .iter()
                    .any(|inspect| governed.contains(inspect))
                {
                    return false;
                }
                !p.inactive_payment_prefixes
                    .iter()
                    .any(|prefix| before.ends_with(prefix.as_str()))
                    && !p
                        .inactive_payment_suffixes
                        .iter()
                        .any(|suffix| after.starts_with(suffix.as_str()))
            })
        })
}

fn local_pair(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    left: &Fact<'_>,
    right: &Fact<'_>,
    p: &Policy,
) -> bool {
    let start = left.claim.span.start_byte.min(right.claim.span.start_byte);
    let end = left.claim.span.end_byte.max(right.claim.span.end_byte);
    if end.saturating_sub(start) > p.max_relation_bytes
        || left.claim.source_block_id.is_none()
        || left.claim.source_block_id != right.claim.source_block_id
    {
        return false;
    }
    if source.text.get(start..end).is_none() {
        return false;
    }
    !context.claims.iter().any(|claim| {
        claim.source_part == source.part
            && claim.span.start_byte >= start
            && claim.span.end_byte <= end
            && !eligible(claim)
    })
}

fn neighbor_range(facts: &[Fact<'_>], at: usize, p: &Policy) -> std::ops::Range<usize> {
    at.saturating_sub(p.max_neighbor_claims)..(at + p.max_neighbor_claims + 1).min(facts.len())
}

fn money_argument(fact: &Fact<'_>, c: &CompiledPolicy) -> bool {
    has(&fact.text, &c.policy.payment_objects) || c.amount.is_match(&fact.text)
}

fn outlier_return(fact: &Fact<'_>, c: &CompiledPolicy) -> bool {
    let p = &c.policy;
    if !has(&fact.text, &p.return_assurances) {
        return false;
    }
    let minimum = if has(&fact.text, &p.daily_return_terms) {
        1.0
    } else if has(&fact.text, &p.monthly_return_terms) {
        20.0
    } else if has(&fact.text, &p.annual_return_terms) {
        100.0
    } else {
        return false;
    };
    c.percent
        .captures_iter(&fact.text)
        .any(|cap| cap[1].parse::<f64>().is_ok_and(|number| number >= minimum))
}

fn invitation(fact: &Fact<'_>, p: &Policy) -> bool {
    active_action(fact, &p.invitation_actions, p)
        && (has(&fact.text, &p.channel_terms) || has(&fact.text, &p.investment_terms))
}

fn directed_offer(fact: &Fact<'_>, p: &Policy) -> bool {
    asserted(fact, p)
        && has(&fact.text, &p.provider_frames)
        && (has(&fact.text, &p.investment_terms) || has(&fact.text, &p.recipient_benefit_frames))
}

fn node(group: &str, fact: &Fact<'_>) -> Value {
    json!({"group": group, "claim_id": fact.claim.source_span_id,
        "source_part": fact.claim.source_part, "span": fact.claim.span})
}

fn emit(
    result: &mut RiskAnalysis,
    anchor: &Fact<'_>,
    family: &'static str,
    witnesses: &[(&str, &Fact<'_>)],
    score: f64,
) {
    let mut supporting_claims = Vec::new();
    for (_, fact) in witnesses {
        if fact.claim.source_span_id != anchor.claim.source_span_id
            && !supporting_claims
                .iter()
                .any(|c: &SemanticClaim| c.source_span_id == fact.claim.source_span_id)
        {
            supporting_claims.push(fact.claim.clone());
        }
    }
    let normalized = anchor.text.split_whitespace().collect::<Vec<_>>().join(" ");
    result.findings.push(NativeSolicitationFinding {
        source_part: anchor.claim.source_part,
        claim: anchor.claim.clone(),
        supporting_claims,
        admission_rule: family,
        category: "scam".into(),
        score,
        causal_key: format!(
            "body_relation:funds_solicitation:{}",
            hex::encode(Sha256::digest(normalized.as_bytes()))
        ),
    });
    result.diagnostics.push(json!({"layer":"economic_intent_risk_v1", "family":family,
        "status":"risk_hint", "evidence_tier":"risk_combination", "anchor_claim_id":anchor.claim.source_span_id,
        "feature_groups":witnesses.iter().map(|(group,f)|node(group,f)).collect::<Vec<_>>(),
        "score":score, "interpretation":"Attributed economic offer/exchange risk; not a complete native attack proof"}));
}

fn investment_risk(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    c: &CompiledPolicy,
    budget: &SemanticCpuBudget,
    result: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &c.policy;
    for (index, promise) in facts.iter().enumerate() {
        if budget.exhausted() {
            return Err("economic offer analysis exceeded CPU budget".into());
        }
        if !asserted(promise, p)
            || has(&promise.text, &p.disclosure_counters)
            || !(has(&promise.text, &p.lossless_promises) || outlier_return(promise, c))
        {
            continue;
        }
        let range = neighbor_range(facts, index, p);
        let financial = facts[range.clone()].iter().find(|f| {
            asserted(f, p)
                && has(&f.text, &p.investment_terms)
                && local_pair(source, context, promise, f, p)
        });
        let Some(financial) = financial else {
            continue;
        };
        if facts[range.clone()].iter().any(|f| {
            asserted(f, p)
                && has(&f.text, &p.disclosure_counters)
                && local_pair(source, context, promise, f, p)
        }) {
            continue;
        }
        let anchor = facts[range]
            .iter()
            .find(|f| {
                invitation(f, p)
                    && local_pair(source, context, promise, f, p)
                    && local_pair(source, context, financial, f, p)
            })
            .or_else(|| directed_offer(financial, p).then_some(financial))
            .or_else(|| directed_offer(promise, p).then_some(promise));
        if let Some(anchor) = anchor {
            emit(
                result,
                anchor,
                "investment_lossless_or_outsized_return_offer_risk_v1",
                &[
                    ("attributed_investment_offer_or_invitation", anchor),
                    ("financial_investment_subject", financial),
                    ("asserted_lossless_or_outsized_return", promise),
                ],
                p.score,
            );
        } else {
            result.diagnostics.push(json!({"layer":"economic_intent_risk_v1",
                "family":"investment_lossless_or_outsized_return_offer_risk_v1", "status":"not_admitted",
                "claim_id":promise.claim.source_span_id,"missing_groups":["attributed_offer_or_directed_invitation"]}));
        }
    }
    Ok(())
}

fn credited_payout(fact: &Fact<'_>, p: &Policy) -> bool {
    asserted(fact, p)
        && has(&fact.text, &p.payout_terms)
        && !has(&fact.text, &p.loan_route_counters)
        && p.loan_products.iter().any(|product| {
            fact.text.match_indices(product.as_str()).any(|(at, _)| {
                if !semantic_phrase_at(&fact.text, product, at) {
                    return false;
                }
                let before = &fact.text[..at];
                // Refund/compensation must be the claimed inflow to this
                // recipient. Borrowing to pay somebody else's damages is a
                // different money direction, even in the same paragraph.
                let clause_start = before
                    .rfind(|ch: char| {
                        matches!(
                            ch,
                            ',' | '，' | ';' | '；' | '。' | '!' | '！' | '?' | '？' | '\n'
                        )
                    })
                    .map(|offset| offset + before[offset..].chars().next().unwrap().len_utf8())
                    .unwrap_or(0);
                let suffix = &fact.text[at + product.len()..];
                let clause_end = suffix
                    .find(|ch: char| {
                        matches!(
                            ch,
                            ',' | '，' | ';' | '；' | '。' | '!' | '！' | '?' | '？' | '\n'
                        )
                    })
                    .map(|offset| at + product.len() + offset)
                    .unwrap_or(fact.text.len());
                let local = &fact.text[clause_start..clause_end];
                if !has(local, &p.payout_terms)
                    || has(local, &p.outgoing_payout_frames)
                    || !(has(local, &p.incoming_payout_frames) || has(local, &p.payout_route_heads))
                {
                    return false;
                }
                p.loan_route_prefixes.iter().any(|prefix| {
                    before.rfind(prefix.as_str()).is_some_and(|start| {
                        before.len().saturating_sub(start + prefix.len()) <= 24
                            && !before[start..].contains([',', '，', ';', '；', '。', '\n'])
                    })
                })
            })
        })
}

fn coordinated_principal_reward(fact: &Fact<'_>, p: &Policy) -> bool {
    p.return_actions.iter().any(|action| {
        fact.text.match_indices(action.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(&fact.text, action, at) {
                return false;
            }
            let prefix = &fact.text[..at];
            has(prefix, &p.principal_components)
                && has(prefix, &p.commission_terms)
                && ![
                    "不", "未", "无法", "不能", "不会", "不予", "尚未", "未能", "not", "never",
                    "cannot", "can't", "not yet",
                ]
                .iter()
                .any(|negative| prefix.trim_end().ends_with(negative))
        })
    })
}

fn work_access_after_payment(fact: &Fact<'_>, p: &Policy) -> bool {
    has(&fact.text, &p.prerequisite_terms)
        && p.work_access_terms.iter().any(|access| {
            fact.text.match_indices(access.as_str()).any(|(at, _)| {
                if !semantic_phrase_at(&fact.text, access, at) {
                    return false;
                }
                let before = &fact.text[..at];
                p.grant_access_actions
                    .iter()
                    .filter_map(|action| {
                        before
                            .rfind(action.as_str())
                            .map(|verb| (verb, action.len()))
                    })
                    .max_by_key(|(verb, len)| verb + len)
                    .is_some_and(|(verb, len)| {
                        let prefix = before[..verb].trim_end();
                        let modifiers = &before[verb + len..];
                        at.saturating_sub(verb + len) <= 48
                            && ![
                                "模拟", "练习", "教学", "学习", "不", "未", "拒绝", "但", "而",
                                "发票",
                            ]
                            .iter()
                            .any(|term| modifiers.contains(term))
                            && !["不", "未", "不会", "不予", "无需", "拒绝"]
                                .iter()
                                .any(|s| prefix.ends_with(s))
                    })
            })
        })
}

fn exchange_risks(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    c: &CompiledPolicy,
    budget: &SemanticCpuBudget,
    result: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &c.policy;
    for (index, anchor) in facts.iter().enumerate() {
        if budget.exhausted() {
            return Err("economic exchange analysis exceeded CPU budget".into());
        }
        if credited_payout(anchor, p) {
            let invitation = facts[neighbor_range(facts, index, p)].iter().find(|f| {
                current(f.claim) && asserted(f, p) && local_pair(source, context, anchor, f, p)
            });
            if current(anchor.claim)
                || has(&anchor.text, &p.recipient_benefit_frames)
                || invitation.is_some()
            {
                let actual = invitation.unwrap_or(anchor);
                emit(
                    result,
                    actual,
                    "credit_product_misrepresented_as_refund_risk_v1",
                    &[
                        ("current_contact_or_payout_offer", actual),
                        ("refund_routed_through_borrowing_product", anchor),
                    ],
                    p.score,
                );
            }
        } else if asserted(anchor, p)
            && has(&anchor.text, &p.payout_terms)
            && has(&anchor.text, &p.loan_products)
        {
            result.diagnostics.push(json!({"layer":"economic_intent_risk_v1",
                "family":"credit_product_misrepresented_as_refund_risk_v1","status":"not_admitted",
                "claim_id":anchor.claim.source_span_id,
                "missing_groups":["loan_product_claimed_as_payout_inflow_to_recipient"],
                "interpretation":"Payout and borrowing nouns alone do not establish the recipient as refund beneficiary"}));
        }
        if !active_action(anchor, &p.payment_actions, p)
            || !money_argument(anchor, c)
            || has(&anchor.text, &p.deduction_counters)
        {
            continue;
        }
        let nearby = &facts[neighbor_range(facts, index, p)];
        let candidates = nearby
            .iter()
            .filter(|f| asserted(f, p) && local_pair(source, context, anchor, f, p))
            .collect::<Vec<_>>();
        if active_action(anchor, &p.fresh_transfer_actions, p)
            && has(&anchor.text, &p.private_investment_destinations)
            && !has(&anchor.text, &p.own_account_counters)
        {
            let investment = candidates
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.investment_terms));
            let management = candidates
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.delegated_trading_terms));
            if let (Some(investment), Some(management)) = (investment, management) {
                emit(
                    result,
                    anchor,
                    "personal_account_transfer_for_delegated_investment_risk_v1",
                    &[
                        ("current_funds_transfer_to_personal_or_safe_account", anchor),
                        ("financial_investment_purpose", investment),
                        ("sender_controls_subsequent_trading", management),
                    ],
                    p.score,
                );
            }
        }
        let task = candidates
            .iter()
            .copied()
            .find(|f| has(&f.text, &p.task_terms));
        if let Some(task) = task {
            let reward = candidates.iter().copied().find(|f| {
                has(&f.text, &p.principal_return_terms)
                    || coordinated_principal_reward(f, p)
                    || (has(&task.text, &p.manipulated_task_terms)
                        && has(&f.text, &p.commission_terms))
            });
            let dependency = candidates
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.prerequisite_terms));
            if let (Some(reward), Some(dependency)) = (reward, dependency) {
                emit(
                    result,
                    anchor,
                    "advance_recipient_funds_for_task_commission_risk_v1",
                    &[
                        ("current_recipient_funding", anchor),
                        ("task_workflow", task),
                        ("principal_or_manipulated_task_reward", reward),
                        ("funding_precedes_task_entitlement", dependency),
                    ],
                    p.score,
                );
            }
        }
        if has(&anchor.text, &p.employment_fees) {
            let employment = candidates.iter().copied().find(|f| {
                has(&f.text, &p.employment_terms) && !has(&f.text, &p.disclosure_counters)
            });
            let gate = candidates
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.employment_gates) || work_access_after_payment(f, p));
            if let (Some(employment), Some(gate)) = (employment, gate) {
                emit(
                    result,
                    anchor,
                    "pay_before_employment_access_risk_v1",
                    &[
                        ("current_recipient_fee_payment", anchor),
                        ("employment_offer", employment),
                        ("payment_conditions_employment_access", gate),
                    ],
                    p.score,
                );
            }
        }
        if active_action(anchor, &p.fresh_transfer_actions, p) {
            let existing_funds = candidates
                .iter()
                .copied()
                .find(|f| has(&f.text, &p.existing_funds_terms));
            let fee_based = has(&anchor.text, &p.fee_terms);
            let release = candidates.iter().copied().find(|f| {
                has(&f.text, &p.release_terms)
                    || (has(&f.text, &p.fund_access_actions)
                        && has(&f.text, &p.existing_funds_terms))
            });
            let gate = candidates.iter().copied().find(|f| {
                has(&f.text, &p.prerequisite_terms)
                    && (fee_based
                        || (has(&f.text, &p.fund_access_actions)
                            && has(&f.text, &p.existing_funds_terms)))
            });
            if let (Some(release), Some(gate)) = (release, gate)
                && (fee_based || existing_funds.is_some())
                && !candidates
                    .iter()
                    .any(|f| has(&f.text, &p.deduction_counters))
            {
                let mut groups = vec![
                    ("current_fresh_transfer_for_fee_or_access", anchor),
                    ("withdrawal_or_disbursement", release),
                    ("fresh_funding_precedes_access_to_funds", gate),
                ];
                if let Some(existing) = existing_funds {
                    groups.push(("funds_already_held_or_earned", existing));
                }
                emit(
                    result,
                    anchor,
                    "fresh_payment_before_withdrawal_release_risk_v1",
                    &groups,
                    p.score,
                );
            }
        }
    }
    Ok(())
}

pub(super) fn analyze(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<RiskAnalysis, String> {
    let compiled = data.cached(POLICY, |registry| {
        registry
            .get_structured(POLICY)
            .cloned()
            .and_then(|v| serde_json::from_value::<Policy>(v).ok())
            .filter(Policy::valid)
            .map(|policy| CompiledPolicy {
                policy,
                percent: Regex::new(r"([0-9]{1,4}(?:\.[0-9]{1,3})?)\s*%")
                    .expect("static percentage regex"),
                amount: Regex::new(
                    r"(?:[¥￥$]\s*[0-9]|[0-9][0-9,.，]*\s*(?:元|美元|usdt|cny|usd))",
                )
                .expect("static money regex"),
            })
    });
    let Some(c) = compiled.as_ref() else {
        return if data.get_structured(POLICY).is_some() {
            Err("economic intent policy is malformed".into())
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
            return Err("economic fact preparation exceeded CPU budget".into());
        }
        if claim.source_part == source.part {
            let text = source
                .claim_text(claim)
                .ok_or("economic claim has an invalid source span")?;
            facts.push(Fact {
                claim,
                text: normalized_lowercase_body(text),
            });
        }
    }
    facts.sort_by_key(|f| (f.claim.span.start_byte, f.claim.span.end_byte));
    let mut analysis = RiskAnalysis::default();
    investment_risk(source, context, &facts, c, budget, &mut analysis)?;
    exchange_risks(source, context, &facts, c, budget, &mut analysis)?;
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{compiled::compiled_semantic_data, extract_semantic_context};
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    use vigilyx_core::security::SemanticSourcePart;

    fn check(body: &str) -> RiskAnalysis {
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
        analyze(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
    }

    #[test]
    fn investment_offer_requires_asserted_financial_return_and_an_offer_edge() {
        for body in [
            "我们是一家股票投资平台，保证稳赚不赔。详情请添加我们的微信投资顾问。",
            "我们提供investment trading，guaranteed profit。Please contact our investment platform.",
        ] {
            assert!(!check(body).findings.is_empty(), "{body}");
        }
        for body in [
            "我们提供股票投资服务，预期年收益8%，市场有风险且可能亏损。请联系投资顾问。",
            "防骗提醒：有人声称投资稳赚不赔，请不要转账，也不要添加陌生微信。",
            "案例分析：广告保证稳赚不赔，攻击者要求投资。请联系警方核实。",
            "招聘数据分析师，月薪30000元，零经验可培训。请发送简历，无押金无收费。",
            "请解释为什么投资稳赚不赔的说法不可信。",
            "请分析我们保证投资收益的说法是否可信。",
        ] {
            assert!(check(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn incoming_reimbursement_cannot_be_implemented_as_new_borrowing() {
        let result =
            check("您好，我们将通过支付宝借呗为您理赔130元。请添加我的QQ号123456789完成理赔。");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.admission_rule == "credit_product_misrepresented_as_refund_risk_v1")
        );
        for body in [
            "理赔款将由保险公司退回您的银行卡，不需要使用借呗，也无需转账。",
            "请使用支付宝支付130元商品货款，发货后提供物流单号。",
            "请按合同偿还借呗欠款130元，避免正常贷款逾期。",
            "我们提供贷款保障保险，保险公司代偿借呗贷款余额。请提交理赔申请。",
            "请先用借呗借钱赔偿对方，绩效到账后我还12600元和588元利息。",
            "急诊科说转账能冻结二次医疗赔偿，工资卡被冻结的话先用借呗套现，绩效到账我立刻还款。",
            "理赔方式：通过借呗支付给对方作为事故赔偿，我发工资后偿还。",
        ] {
            assert!(check(body).findings.is_empty(), "{body}");
        }
        let nominal = check("理赔方式：通过支付宝借呗备用金渠道先行垫付。请联系理赔专员领取赔款。");
        assert!(
            nominal
                .findings
                .iter()
                .any(|f| f.admission_rule == "credit_product_misrepresented_as_refund_risk_v1")
        );
    }

    #[test]
    fn third_party_accident_debt_is_not_a_refund_to_the_recipient() {
        let body = r###"宝宝！南山隧道北出口海岸城购物中心这里出大事了！【系统警报】赔付通道仅剩3席位｜19:23永久关闭‼️14:08避让快递车擦倒雅迪电瓶车，散落的2018飞天茅台碎了两瓶！三个纹九龙一凤的男人围着车（实时弹幕：张*豪10秒前刚完成转账解封车辆🚗），前海律师事务所的人亮出安盾调解协议——98.7%事故都在这里结案⚠️CT显示腓骨骨裂，行车记录仪深港系统升级后持续黑屏（已有126人遭遇同款系统故障📉）！

【血红色弹窗】622848112834509XXXX对公账户必须在01:52:11内到账！超时将上传征信系统并收取每日3%滞纳金💸！急诊科张医生说现在转账能冻结二次医疗赔偿（滚动通知：李*薇等7人正在排队支付中...）工资卡被冻结的话，先用借呗套现！身份证正反面+手写借条马上拍给你，绩效到账立刻还12600+补偿588利息💰！国资委纪检组的人带着茅台碎片在调解室倒计时了——【最后通牒】17:30:00准时提交司法档案！"###;
        let result = check(body);
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.admission_rule == "credit_product_misrepresented_as_refund_risk_v1"),
            "{:?}",
            result.diagnostics
        );
    }

    #[test]
    fn task_and_employment_funding_preserve_normal_work_and_purchases() {
        for body in [
            "请先充值500元本金到任务钱包用于刷单，完成任务后本金和佣金一并返还。",
            "请先向指定账户转账800元入职押金，付款后才能入职上岗。",
            "请先转账2000元提现保证金到指定账户，完成后才能提现账户余额。",
        ] {
            assert!(!check(body).findings.is_empty(), "{body}");
        }
        for body in [
            "兼职调研任务无需垫付任何本金，佣金由公司直接发到您的账户。请发送简历。",
            "请支付800元课程培训费，完成报名后可参加课程，不承诺录用。",
            "请先支付2000元商品定金，收到电缆货物后再支付尾款。",
            "提现手续费每笔2元将从提现金额中扣除，您无需另行转账。",
            "请核对已转账的入职押金，不需要再次付款。",
            "请确认已把2000元提现保证金转账到指定账户，核对旧的提现记录即可。",
        ] {
            assert!(check(body).findings.is_empty(), "{body}");
        }
        assert!(
            !check("请确认并现在转账2000元提现保证金到指定账户，完成后才能提现账户余额。")
                .findings
                .is_empty()
        );
    }

    #[test]
    fn investment_custody_needs_a_sender_directed_private_funding_route() {
        assert!(
            !check(
                "我们提供股票投资服务，请将资金转账至我们提供的银行卡，我们会为您操作股票交易。"
            )
            .findings
            .is_empty()
        );
        for body in [
            "请将投资资金存入您自己的证券账户，交易由您自行决定，市场有风险。",
            "请支付公司股票认购款到公司对公账户，完成后自行持有股票，不提供代操作。",
            "风险提示：请勿把投资资金转入个人账户，切勿相信陌生人代您操作。",
        ] {
            assert!(check(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn funding_conditions_bind_earned_money_work_access_and_quantified_principal_reward() {
        for body in [
            "您的佣金已经到账。请先转1200元到专用账户，完成充值后才能解锁已有佣金。",
            "我们招聘线上接线员，请转600元开通费给个人收款账户，交费后将开通工作账号。",
            "要完成返佣任务，请在网贷APP借出6000元并充值到任务平台账户。完成任务后本金与25%佣金一起返还。",
        ] {
            assert!(!check(body).findings.is_empty(), "{body}");
        }
        for body in [
            "您的佣金已经到账。请充值手机话费100元，已有佣金将在周五自动提现，无须额外转账。",
            "请支付入职技能课程800元培训费，交费后开通模拟工作账号用于练习，不承诺录用。",
            "需要出差请先垫付住宿费800元，完成后原款通过报销返还，不提供任务佣金。",
        ] {
            assert!(check(body).findings.is_empty(), "{body}");
        }
    }
}
