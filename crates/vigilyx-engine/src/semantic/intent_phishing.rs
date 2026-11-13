//! Local inconsistencies in verification and voluntary-benefit workflows.
//! No hostname reputation, fetching, legal verification or model is used.

use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use vigilyx_core::security::{
    SemanticClaim, SemanticMessageContext, SemanticQuoteStatus, SemanticSourcePart,
    SemanticSpeechAct, SemanticTargetRole,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::risk::{RiskAnalysis, current, eligible};
use super::solicitation::NativeSolicitationFinding;
use super::source::SemanticSource;
use super::text::{normalized_lowercase_body, semantic_phrase_at};

#[derive(Default, Deserialize)]
#[serde(default)]
struct Policy {
    enabled: bool,
    max_relation_bytes: usize,
    max_paragraphs: usize,
    link_score: f64,
    benefit_score: f64,
    verification_actions: Vec<String>,
    verification_objects: Vec<String>,
    official_channel_claims: Vec<String>,
    gateway_explanations: Vec<String>,
    gateway_query_keys: Vec<String>,
    channel_pointers: Vec<String>,
    relation_breaks: Vec<String>,
    voluntary_actions: Vec<String>,
    voluntary_contexts: Vec<String>,
    refusal_markers: Vec<String>,
    refusal_prefixes: Vec<String>,
    existing_financial_assets: Vec<String>,
    asset_restrictions: Vec<String>,
    benefit_terms: Vec<String>,
    claim_actions: Vec<String>,
    financial_penalties: Vec<String>,
    conditional_terms: Vec<String>,
    refusal_to_claim: Vec<String>,
    benefit_expiry: Vec<String>,
    existing_obligations: Vec<String>,
    obligation_denials: Vec<String>,
    reported_speakers: Vec<String>,
    reporting_predicates: Vec<String>,
    sender_resumptions: Vec<String>,
    counter_predicates: Vec<String>,
    outcome_denials: Vec<String>,
    sanction_terms: Vec<String>,
    credit_objects: Vec<String>,
    credit_harm_predicates: Vec<String>,
    credit_neutral_results: Vec<String>,
}

impl Policy {
    fn valid(&self) -> bool {
        !self.enabled
            || ((256..=8192).contains(&self.max_relation_bytes)
                && self.max_paragraphs <= 4
                && [self.link_score, self.benefit_score]
                    .iter()
                    .all(|s| s.is_finite() && (0.15..=0.34).contains(s))
                && [
                    &self.verification_actions,
                    &self.verification_objects,
                    &self.official_channel_claims,
                    &self.gateway_explanations,
                    &self.gateway_query_keys,
                    &self.channel_pointers,
                    &self.relation_breaks,
                    &self.voluntary_actions,
                    &self.voluntary_contexts,
                    &self.refusal_markers,
                    &self.refusal_prefixes,
                    &self.existing_financial_assets,
                    &self.asset_restrictions,
                    &self.benefit_terms,
                    &self.claim_actions,
                    &self.financial_penalties,
                    &self.conditional_terms,
                    &self.refusal_to_claim,
                    &self.benefit_expiry,
                    &self.existing_obligations,
                    &self.obligation_denials,
                    &self.reported_speakers,
                    &self.reporting_predicates,
                    &self.sender_resumptions,
                    &self.counter_predicates,
                    &self.outcome_denials,
                    &self.sanction_terms,
                    &self.credit_objects,
                    &self.credit_harm_predicates,
                    &self.credit_neutral_results,
                ]
                .iter()
                .all(|v| {
                    !v.is_empty()
                        && v.len() <= 96
                        && v.iter().all(|t| !t.trim().is_empty() && t.len() <= 128)
                }))
    }
}

struct Compiled {
    policy: Policy,
    markdown: Regex,
    refusal: Regex,
}
struct Fact<'a> {
    claim: &'a SemanticClaim,
    text: String,
}

fn has(text: &str, terms: &[String]) -> bool {
    terms.iter().any(|t| {
        text.match_indices(t.as_str())
            .any(|(at, _)| semantic_phrase_at(text, t, at))
    })
}

fn bounded(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[&Fact<'_>],
    p: &Policy,
) -> bool {
    if facts.is_empty() || facts.len() > 5 {
        return false;
    }
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
    let Some(raw) = source.text.get(start..end) else {
        return false;
    };
    if raw.len() > p.max_relation_bytes {
        return false;
    }
    let mut previous_blank = false;
    let paragraphs = raw
        .lines()
        .filter(|line| {
            let blank = line.trim().is_empty();
            let new = blank && !previous_blank;
            previous_blank = blank;
            new
        })
        .count();
    if paragraphs > p.max_paragraphs {
        return false;
    }
    if source.part != SemanticSourcePart::PlainText
        && facts.iter().any(|f| {
            f.claim.source_block_id.is_none()
                || f.claim.source_block_id != facts[0].claim.source_block_id
        })
    {
        return false;
    }
    !context.claims.iter().any(|c| {
        c.source_part == source.part
            && c.span.start_byte < end
            && start < c.span.end_byte
            && matches!(
                c.speech_act,
                SemanticSpeechAct::Report | SemanticSpeechAct::Quotation
            )
    })
}

fn cause(kind: &str, text: &str) -> String {
    let normalized = normalized_lowercase_body(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "body_relation:{kind}:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

fn emit(
    result: &mut RiskAnalysis,
    anchor: &Fact<'_>,
    support: &[&Fact<'_>],
    rule: &'static str,
    score: f64,
) {
    let mut supporting_claims = Vec::new();
    for f in support {
        if f.claim.source_span_id != anchor.claim.source_span_id
            && !supporting_claims
                .iter()
                .any(|c: &SemanticClaim| c.source_span_id == f.claim.source_span_id)
        {
            supporting_claims.push(f.claim.clone());
        }
    }
    result.findings.push(NativeSolicitationFinding {
        source_part: anchor.claim.source_part,
        claim: anchor.claim.clone(),
        supporting_claims,
        admission_rule: rule,
        category: if rule.starts_with("voluntary_") {
            "scam"
        } else {
            "phishing"
        }
        .into(),
        score,
        causal_key: cause(
            if rule.starts_with("voluntary_") {
                "funds_solicitation"
            } else {
                "secret_return"
            },
            &anchor.text,
        ),
    });
}

fn equivalent_host(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches('.').trim_start_matches("www.");
    let right = right.trim_end_matches('.').trim_start_matches("www.");
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

fn neighbor(source: SemanticSource<'_>, left: &Fact<'_>, right: &Fact<'_>, p: &Policy) -> bool {
    if left.claim.source_span_id == right.claim.source_span_id {
        return true;
    }
    if !eligible(right.claim)
        || p.relation_breaks
            .iter()
            .any(|term| right.text.trim_start().starts_with(term.as_str()))
    {
        return false;
    }
    let (first, last) = if left.claim.span.start_byte < right.claim.span.start_byte {
        (left, right)
    } else {
        (right, left)
    };
    let Some(gap) = source
        .text
        .get(first.claim.span.end_byte..last.claim.span.start_byte)
    else {
        return false;
    };
    if gap.len() > 256 || gap.contains("\n\n") || gap.contains("\r\n\r\n") {
        return false;
    }
    !gap.lines().any(|l| {
        let l = l.trim();
        l.starts_with('#') || l.starts_with("**") || l.starts_with("---")
    })
}

fn link_conflict(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    anchor: &Fact<'_>,
    facts: &[Fact<'_>],
    c: &Compiled,
    result: &mut RiskAnalysis,
) {
    let p = &c.policy;
    if source.part != SemanticSourcePart::PlainText
        || !current(anchor.claim)
        || interrogative(&anchor.text)
        || !anchor
            .claim
            .actions
            .iter()
            .any(|a| p.verification_actions.contains(a))
        || !has(&anchor.text, &p.verification_objects)
    {
        return;
    }
    for representation in facts {
        if !neighbor(source, anchor, representation, p)
            || (representation.claim.source_span_id != anchor.claim.source_span_id
                && !has(&representation.text, &p.channel_pointers))
        {
            continue;
        }
        let Some(raw) = source.claim_text(representation.claim) else {
            continue;
        };
        for pair in c.markdown.captures_iter(raw).take(8) {
            let (Some(display), Some(target)) = (pair.get(1), pair.get(2)) else {
                continue;
            };
            let (Ok(display_url), Ok(target_url)) =
                (Url::parse(display.as_str()), Url::parse(target.as_str()))
            else {
                continue;
            };
            let (Some(display_host), Some(target_host)) =
                (display_url.host_str(), target_url.host_str())
            else {
                continue;
            };
            if display_url.scheme() != "https" || equivalent_host(display_host, target_host) {
                continue;
            }
            let Some(authority) = facts.iter().find(|f| {
                eligible(f.claim)
                    && has(&f.text, &p.official_channel_claims)
                    && neighbor(source, representation, f, p)
                    && bounded(source, context, &[anchor, representation, f], p)
            }) else {
                continue;
            };
            let explained_wrapper = [anchor, representation, authority]
                .iter()
                .any(|f| has(&f.text, &p.gateway_explanations))
                && target_url.query_pairs().any(|(key, value)| {
                    p.gateway_query_keys.iter().any(|k| k == key.as_ref())
                        && Url::parse(&value).ok().is_some_and(|destination| {
                            destination.scheme() == "https"
                                && destination
                                    .host_str()
                                    .is_some_and(|host| equivalent_host(host, display_host))
                        })
                });
            if explained_wrapper {
                continue;
            }
            emit(
                result,
                anchor,
                &[representation, authority],
                "verification_literal_url_target_conflict_risk_v1",
                p.link_score,
            );
            // Two live verification verbs can point at the same physical
            // Markdown link. That representation conflict is one event.
            if let Some(finding) = result.findings.last_mut() {
                finding.causal_key = format!(
                    "body_relation:literal_url_target_conflict:{:?}:{}:{}:{}:{}:{}",
                    source.part,
                    representation.claim.span.start_byte + display.start(),
                    representation.claim.span.start_byte + display.end(),
                    representation.claim.span.start_byte + target.start(),
                    representation.claim.span.start_byte + target.end(),
                    hex::encode(Sha256::digest(
                        format!("{}|{}", display.as_str(), target.as_str()).as_bytes()
                    ))
                );
            }
            result.diagnostics.push(json!({"layer":"static_intent_relation_v1","family":"verification_literal_url_target_conflict_risk_v1",
            "status":"risk_hint","evidence_tier":"risk_combination","anchor_claim_id":anchor.claim.source_span_id,
            "feature_groups":[{"group":"current_account_verification","claim_id":anchor.claim.source_span_id,"span":anchor.claim.span},
                {"group":"claims_official_or_secure_channel","claim_id":authority.claim.source_span_id,"span":authority.claim.span},
                {"group":"literal_display_and_target_conflict","claim_id":representation.claim.source_span_id,"span":representation.claim.span}],
            "transport_downgrade":target_url.scheme()=="http",
            "display_url":display.as_str(),"target_url":target.as_str(),
            "display_span":{"start_byte":representation.claim.span.start_byte+display.start(),"end_byte":representation.claim.span.start_byte+display.end()},
            "target_span":{"start_byte":representation.claim.span.start_byte+target.start(),"end_byte":representation.claim.span.start_byte+target.end()},
            "score":p.link_score,"ownership_or_reputation_verified":false}));
            return;
        }
    }
}

// Negation belongs to the consequence predicate, not the earlier refusal.
// “不申请” is a condition; “不会影响征信” denies harm.
fn outcome_denied(text: &str, term: &str, at: usize, p: &Policy) -> bool {
    p.counter_predicates.iter().any(|counter| {
        text.match_indices(counter.as_str())
            .any(|(start, _)| start <= at && at + term.len() <= start + counter.len())
    }) || p.outcome_denials.iter().any(|denial| {
        text[..at]
            .rmatch_indices(denial.as_str())
            .next()
            .is_some_and(|(start, _)| {
                let between = &text[start + denial.len()..at];
                at.saturating_sub(start + denial.len()) <= 48
                    && !between.contains(['，', ',', '。', '；', ';', '!', '！', '?', '？', '\n'])
                    && !["但", "然而", "不过", "but", "however"]
                        .iter()
                        .any(|t| between.contains(t))
            })
    })
}

fn asserted_sanction(text: &str, p: &Policy) -> bool {
    if p.sanction_terms.iter().any(|term| {
        text.match_indices(term.as_str())
            .any(|(at, _)| semantic_phrase_at(text, term, at) && !outcome_denied(text, term, at, p))
    }) {
        return true;
    }
    p.credit_objects.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            if !semantic_phrase_at(text, term, at) || outcome_denied(text, term, at, p) {
                return false;
            }
            let before = text[..at]
                .rsplit(['，', ',', '。', '；', ';', '!', '！', '?', '？', '\n'])
                .next()
                .unwrap_or("");
            let after = text[at + term.len()..]
                .split(['，', ',', '。', '；', ';', '!', '！', '?', '？', '\n'])
                .next()
                .unwrap_or("");
            if has(after, &p.credit_neutral_results) {
                return false;
            }
            p.credit_harm_predicates.iter().any(|v| {
                before.rfind(v.as_str()).is_some_and(|start| {
                    before.len() - start <= 64
                        && !outcome_denied(text, v, at - before.len() + start, p)
                }) || after.match_indices(v.as_str()).any(|(start, _)| {
                    start <= 64 && !outcome_denied(text, v, at + term.len() + start, p)
                })
            })
        })
    })
}

fn asserted_asset_restriction(text: &str, p: &Policy) -> bool {
    has(text, &p.existing_financial_assets)
        && p.asset_restrictions.iter().any(|term| {
            text.match_indices(term.as_str()).any(|(at, _)| {
                semantic_phrase_at(text, term, at) && !outcome_denied(text, term, at, p)
            })
        })
}

fn asserted_obligation(text: &str, p: &Policy) -> bool {
    p.existing_obligations.iter().any(|term| {
        text.match_indices(term.as_str()).any(|(at, _)| {
            semantic_phrase_at(text, term, at)
                && !p.obligation_denials.iter().any(|denial| {
                    text[..at]
                        .rmatch_indices(denial.as_str())
                        .next()
                        .is_some_and(|(start, _)| {
                            at.saturating_sub(start + denial.len()) <= 48
                                && !text[start + denial.len()..at]
                                    .contains(['，', ',', '。', '；', ';', '\n'])
                        })
                })
        })
    })
}

fn interrogative(text: &str) -> bool {
    let text = text
        .trim()
        .trim_end_matches(['*', '_', '"', '”'])
        .trim_end();
    text.ends_with(['?', '？'])
        || ["q:", "q：", "问:", "问：", "问题:", "问题："]
            .iter()
            .any(|prefix| text.trim_start_matches(['-', '*', ' ']).starts_with(prefix))
}

fn voluntary_benefit(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    p: &Policy,
    budget: &SemanticCpuBudget,
    result: &mut RiskAnalysis,
) -> Result<(), String> {
    let benefits = facts
        .iter()
        .filter(|f| eligible(f.claim) && !interrogative(&f.text) && has(&f.text, &p.benefit_terms))
        .collect::<Vec<_>>();
    if benefits.is_empty() {
        return Ok(());
    }
    for anchor in facts {
        if budget.exhausted() {
            return Err("benefit coercion evaluation exceeded CPU budget".into());
        }
        if !current(anchor.claim)
            || interrogative(&anchor.text)
            || !anchor
                .claim
                .actions
                .iter()
                .any(|a| p.claim_actions.contains(a))
        {
            continue;
        }
        for penalty in facts {
            if budget.exhausted() {
                return Err("benefit consequence binding exceeded CPU budget".into());
            }
            if !eligible(penalty.claim)
                || interrogative(&penalty.text)
                || !asserted_sanction(&penalty.text, p)
                || asserted_obligation(&penalty.text, p)
            {
                continue;
            }
            let condition = if has(&penalty.text, &p.conditional_terms) {
                Some(penalty)
            } else {
                facts.iter().find(|f| {
                    f.claim.quote_or_forward_status == SemanticQuoteStatus::Original
                        && !interrogative(&f.text)
                        && !matches!(
                            f.claim.speech_act,
                            SemanticSpeechAct::Report | SemanticSpeechAct::Quotation
                        )
                        && f.claim.target_role != SemanticTargetRole::NamedThirdParty
                        && has(&f.text, &p.refusal_to_claim)
                        && ["您", "你", "you"].iter().any(|subject| {
                            f.text
                                .match_indices(*subject)
                                .any(|(at, _)| semantic_phrase_at(&f.text, subject, at))
                        })
                        && f.claim.span.end_byte <= penalty.claim.span.start_byte
                        && penalty
                            .claim
                            .span
                            .start_byte
                            .saturating_sub(f.claim.span.end_byte)
                            <= 256
                        && source
                            .text
                            .get(f.claim.span.end_byte..penalty.claim.span.start_byte)
                            .is_some_and(|gap| {
                                !gap.contains(['。', '.', '!', '！', '?', '？', '\n'])
                            })
                })
            };
            let Some(condition) = condition else {
                continue;
            };
            if facts.iter().any(|f| {
                eligible(f.claim)
                    && asserted_obligation(&f.text, p)
                    && bounded(source, context, &[anchor, penalty, f], p)
            }) {
                continue;
            }
            // Expiring a voluntary benefit is ordinary. Actual fines, credit
            // records or debt consequences for not claiming it are different.
            if has(&penalty.text, &p.benefit_expiry) && !has(&penalty.text, &p.refusal_to_claim) {
                continue;
            }
            let Some(benefit) = benefits.iter().copied().find(|benefit| {
                bounded(source, context, &[anchor, penalty, benefit, condition], p)
                    && (has(&penalty.text, &p.benefit_terms)
                        || has(&penalty.text, &p.refusal_to_claim)
                        || has(&condition.text, &p.refusal_to_claim)
                        || (has(&anchor.text, &p.benefit_terms)
                            && anchor.claim.source_block_id.is_some()
                            && anchor.claim.source_block_id == penalty.claim.source_block_id))
            }) else {
                continue;
            };
            emit(
                result,
                anchor,
                &[benefit, penalty, condition],
                "voluntary_benefit_conditioned_credit_or_fine_risk_v1",
                p.benefit_score,
            );
            result.diagnostics.push(json!({"layer":"static_intent_relation_v1","family":"voluntary_benefit_conditioned_credit_or_fine_risk_v1",
                "status":"risk_hint","evidence_tier":"risk_combination","score":p.benefit_score,
                "anchor_claim_id":anchor.claim.source_span_id,
                "feature_groups":[{"group":"current_claim_or_verification","claim_id":anchor.claim.source_span_id,"span":anchor.claim.span},
                    {"group":"voluntary_reward_or_coupon","claim_id":benefit.claim.source_span_id,"span":benefit.claim.span},
                    {"group":"claim_refusal_condition","claim_id":condition.claim.source_span_id,"span":condition.claim.span},
                    {"group":"refusal_triggers_financial_punishment","claim_id":penalty.claim.source_span_id,"span":penalty.claim.span}],
                "ordinary_expiry_is_not_a_financial_punishment":true}));
            break;
        }
    }
    Ok(())
}

/// A conditional threat can perform an indirect demand even without an
/// imperative verb. Preserve the original claim type; record this as a risk
/// intent frame, not a fabricated current-action or complete native proof.
fn reported_refusal(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    condition: &Fact<'_>,
    c: &Compiled,
) -> bool {
    let Some(before) = source.text.get(..condition.claim.span.start_byte) else {
        return false;
    };
    let start = before
        .rfind(['。', '.', '!', '！', '?', '？', ';', '；', '\n'])
        .map_or(0, |at| {
            at + before[at..].chars().next().map_or(0, char::len_utf8)
        });
    if condition.claim.span.end_byte.saturating_sub(start) > 768
        || context.claims.iter().any(|claim| {
            claim.source_part == source.part
                && claim.span.start_byte < condition.claim.span.end_byte
                && start < claim.span.end_byte
                && (claim.source_block_id != condition.claim.source_block_id
                    || claim.quote_or_forward_status != SemanticQuoteStatus::Original)
        })
    {
        return false;
    }
    let Some(raw) = source.text.get(start..condition.claim.span.end_byte) else {
        return false;
    };
    let text = normalized_lowercase_body(raw);
    let Some(refusal) = c.refusal.find(&text) else {
        return false;
    };
    let prefix = &text[..refusal.start()];
    c.policy.reported_speakers.iter().any(|actor| {
        prefix.match_indices(actor.as_str()).any(|(actor_at, _)| {
            if !semantic_phrase_at(prefix, actor, actor_at)
                || ["不是", "并非", "并无", "没有", "not a "]
                    .iter()
                    .any(|n| prefix[..actor_at].trim_end().ends_with(n))
            {
                return false;
            }
            let after_actor = &prefix[actor_at + actor.len()..];
            c.policy.reporting_predicates.iter().any(|verb| {
                after_actor.match_indices(verb.as_str()).any(|(at, _)| {
                    at <= 48
                        && !after_actor[..at].contains(['，', ',', ':', '：'])
                        && !has(
                            &after_actor[at + verb.len()..],
                            &c.policy.sender_resumptions,
                        )
                })
            })
        })
    })
}

fn participation_condition(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    facts: &[Fact<'_>],
    compiled: &Compiled,
    budget: &SemanticCpuBudget,
    out: &mut RiskAnalysis,
) -> Result<(), String> {
    let p = &compiled.policy;
    for condition in facts {
        if budget.exhausted() {
            return Err("participation condition exceeded CPU budget".into());
        }
        if condition.claim.quote_or_forward_status != SemanticQuoteStatus::Original
            || interrogative(&condition.text)
            || matches!(
                condition.claim.speech_act,
                SemanticSpeechAct::Report
                    | SemanticSpeechAct::Quotation
                    | SemanticSpeechAct::Warning
            )
            || !condition.claim.counter_context_ids.is_empty()
            || reported_refusal(source, context, condition, compiled)
            || (condition.claim.target_role == SemanticTargetRole::NamedThirdParty
                && !["申请者", "应聘者", "申请人", "应聘人员", "候选人", "收件人"]
                    .iter()
                    .any(|t| condition.text.contains(t)))
            || !(compiled.refusal.is_match(&condition.text)
                || (has(&condition.text, &p.voluntary_actions)
                    && has(&condition.text, &p.refusal_markers)))
        {
            continue;
        }
        let Some(choice) = facts.iter().find(|f| {
            eligible(f.claim)
                && !interrogative(&f.text)
                && has(&f.text, &p.voluntary_contexts)
                && bounded(source, context, &[condition, f], p)
        }) else {
            continue;
        };
        for penalty in facts {
            if budget.exhausted() {
                return Err("participation consequence exceeded CPU budget".into());
            }
            if !eligible(penalty.claim)
                || interrogative(&penalty.text)
                || asserted_obligation(&penalty.text, p)
                || penalty.claim.span.start_byte < condition.claim.span.start_byte
                || penalty
                    .claim
                    .span
                    .start_byte
                    .saturating_sub(condition.claim.span.end_byte)
                    > 768
                || !bounded(source, context, &[condition, choice, penalty], p)
            {
                continue;
            }
            if condition.claim.source_span_id != penalty.claim.source_span_id {
                let Some(bridge) = source
                    .text
                    .get(condition.claim.span.end_byte..penalty.claim.span.start_byte)
                else {
                    continue;
                };
                if bridge.contains(['。', '；', ';', '!', '！', '?', '？', '\n'])
                    || condition
                        .text
                        .trim_end()
                        .ends_with(['。', '；', ';', '!', '！', '?', '？'])
                {
                    continue;
                }
            }
            let money = asserted_sanction(&penalty.text, p);
            let restricted = asserted_asset_restriction(&penalty.text, p);
            if !money && !restricted {
                continue;
            }
            if facts.iter().any(|f| {
                eligible(f.claim)
                    && asserted_obligation(&f.text, p)
                    && bounded(source, context, &[condition, penalty, f], p)
            }) {
                continue;
            }
            emit(
                out,
                condition,
                &[choice, penalty],
                "voluntary_participation_financial_sanction_risk_v1",
                p.benefit_score,
            );
            out.diagnostics.push(json!({"layer":"static_intent_relation_v1","family":"voluntary_participation_financial_sanction_risk_v1",
                "status":"risk_hint","evidence_tier":"risk_combination","score":p.benefit_score,
                "intent":"conditional_demand","original_speech_act_preserved":true,
                "feature_groups":[{"group":"negated_voluntary_participation_condition","claim_id":condition.claim.source_span_id,"span":condition.claim.span},
                    {"group":"voluntary_opportunity","claim_id":choice.claim.source_span_id,"span":choice.claim.span},
                    {"group":"unrelated_existing_financial_sanction","claim_id":penalty.claim.source_span_id,"span":penalty.claim.span}]}));
            break;
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
    let cached = data.cached("semantic_phishing_intent_policy_v1", |registry| {
        registry
            .get_structured("semantic_phishing_intent_policy_v1")
            .cloned()
            .and_then(|v| serde_json::from_value::<Policy>(v).ok())
            .filter(Policy::valid)
            .and_then(|policy| {
                let prefixes = policy
                    .refusal_prefixes
                    .iter()
                    .map(|t| regex::escape(t))
                    .collect::<Vec<_>>()
                    .join("|");
                let actions = policy
                    .voluntary_actions
                    .iter()
                    .map(|t| regex::escape(t))
                    .collect::<Vec<_>>()
                    .join("|");
                let refusal = Regex::new(&format!(
                    r"(?:{prefixes})[^，,。；;!?！？\n]{{0,24}}(?:{actions})"
                ))
                .ok()?;
                Some(Compiled {
                policy,
                refusal,
                markdown: Regex::new(
                    r"(?i)\[(https://[^\s\]<>]{1,2048})\]\(\s*<?(https?://[^\s)<>]{1,2048})>?\s*\)",
                )
                .expect("static Markdown URL expression"),
            })
            })
    });
    let Some(c) = cached.as_ref() else {
        return if data
            .get_structured("semantic_phishing_intent_policy_v1")
            .is_some()
        {
            Err("phishing intent policy is malformed".into())
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
            return Err("phishing intent preparation exceeded CPU budget".into());
        }
        if claim.source_part != source.part {
            continue;
        }
        let text = source
            .claim_text(claim)
            .ok_or("phishing intent has invalid source span")?;
        facts.push(Fact {
            claim,
            text: normalized_lowercase_body(text),
        });
    }
    facts.sort_by_key(|f| f.claim.span.start_byte);
    let mut result = RiskAnalysis::default();
    for anchor in &facts {
        link_conflict(source, context, anchor, &facts, c, &mut result);
    }
    voluntary_benefit(source, context, &facts, &c.policy, budget, &mut result)?;
    participation_condition(source, context, &facts, c, budget, &mut result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::compiled::compiled_semantic_data;
    use crate::semantic::context::extract_semantic_context;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    fn evaluate(body: &str) -> RiskAnalysis {
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
    fn literal_url_conflict_is_bound_to_a_live_verification_claim() {
        for body in [
            "请登录账户核对信息：[https://accounts.bank.example/auth](http://different.invalid/login)（此链接为官方安全页面）。",
            "Please verify your account at our official secure page [https://bank.example/auth](https://bank.example@different.invalid/login).",
        ] {
            let result = evaluate(body);
            assert!(result.findings.iter().any(|f|f.admission_rule=="verification_literal_url_target_conflict_risk_v1"),"{body}\n{:?}",result.diagnostics);
        }
        for body in [
            "请登录账户验证：[https://bank.example/auth](https://bank.example/verify)（官方安全页面）。",
            "请登录账户验证：[https://bank.example/auth](https://secure.bank.example/verify)（官方安全页面）。",
            "Please verify your account using our official security gateway [https://bank.example/auth](https://gateway.example/route?url=https%3A%2F%2Fbank.example%2Fauth).",
            "安全事件报告：攻击者曾要求用户登录官方页面：[https://bank.example/auth](http://different.invalid/login)。",
            "请登录账户完成验证。\n\n历史案例附录：[https://bank.example/auth](http://different.invalid/login)（攻击者声称是官方安全页面）。",
            "领取优惠券：[https://shop.example/](https://marketing.example/track)。",
        ] {
            assert!(evaluate(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn voluntary_reward_penalty_requires_a_harmful_condition() {
        let body = "您的50美元优惠券即将失效。请立即领取优惠券，逾期未领取将影响您的征信并产生50美元滞纳金。";
        assert!(evaluate(body).findings.iter().any(|f|f.admission_rule=="voluntary_benefit_conditioned_credit_or_fine_risk_v1"));
        for body in [
            "请领取50元优惠券，逾期未领取优惠券将失效，未使用的积分也会过期。",
            "请领取优惠券。本活动不会影响征信，不收取滞纳金。",
            "您的账单存在欠款，请按合同还款；逾期将产生滞纳金。另可领取客户优惠券。",
            "安全培训案例：骗子要求用户领取优惠券，否则影响征信并产生滞纳金。",
        ] {
            assert!(evaluate(body).findings.is_empty(), "{body}");
        }
    }

    #[test]
    fn financial_consequences_keep_neutral_credit_and_negation_scopes() {
        let data = compiled_semantic_data();
        let p: Policy = serde_json::from_value(
            data.get_structured("semantic_phishing_intent_policy_v1")
                .unwrap()
                .clone(),
        )
        .unwrap();
        for text in [
            "您的信用评分保持不变",
            "不会影响您的征信",
            "无需支付罚款",
            "拒绝参加活动并不降低信用评分",
            "信用评分不会降低",
            "信用记录没有下降",
            "征信并不会受到影响",
            "不用担心拒绝申请会降低征信",
        ] {
            assert!(!asserted_sanction(text, &p), "{text}");
        }
        for text in [
            "未申请将降低您的信用评分",
            "拒绝领取将收取罚款",
            "不会影响您的征信，但将产生罚款",
        ] {
            assert!(asserted_sanction(text, &p), "{text}");
        }
        assert!(asserted_asset_restriction(
            "不会影响征信，但将冻结银行卡",
            &p
        ));
        assert!(!asserted_asset_restriction("不会冻结银行卡", &p));
        assert!(asserted_obligation("已签合同规定应支付违约金", &p));
        assert!(!asserted_obligation("并不涉及偿还任何欠款", &p));
        assert!(!asserted_obligation("不属于执业许可或已签合同", &p));
    }

    #[test]
    fn reported_conditional_threats_do_not_hide_a_fresh_sender_condition() {
        assert!(
            evaluate("有人声称招聘完全自愿，却威胁不应聘就降低征信。")
                .findings
                .is_empty()
        );
        for body in [
            "有人声称招聘完全自愿，却威胁不应聘降低征信。现在我们通知您，本岗位自愿申请，未申请将降低您的征信。",
            "骗子曾宣称招聘自愿，但我们现在要求您申请本岗位，不申请就降低征信。",
            "本岗位自愿应聘，不应聘就降低您的信用评分。后附反诈培训案例：骗子曾宣称招聘自愿，却威胁不应聘就降低征信。",
        ] {
            assert!(
                evaluate(body)
                    .findings
                    .iter()
                    .any(|f| f.admission_rule
                        == "voluntary_participation_financial_sanction_risk_v1"),
                "{body}"
            );
        }
    }

    #[test]
    fn questions_do_not_supply_asserted_financial_consequences() {
        assert!(
            evaluate("请领取奖励。奖励未领取影响征信？")
                .findings
                .is_empty()
        );
        let body = "请领取奖励。补救金未领取将转为不良征信记录。Q：奖励未领取影响征信？";
        let result = evaluate(body);
        assert!(!result.findings.is_empty());
        for finding in &result.findings {
            assert!(!interrogative(
                &body[finding.claim.span.start_byte..finding.claim.span.end_byte]
            ));
            assert!(
                finding
                    .supporting_claims
                    .iter()
                    .all(|claim| !interrogative(&body[claim.span.start_byte..claim.span.end_byte]))
            );
        }
    }
}
