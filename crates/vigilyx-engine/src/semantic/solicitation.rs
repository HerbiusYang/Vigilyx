//! Bounded local admission for secret disclosure and funds-release solicitations.
//! A scenario, an account noun or an unverified link alone never qualifies.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticActionDestination, SemanticClaim, SemanticMessageContext, SemanticPolarity,
    SemanticQuoteStatus, SemanticSourcePart, SemanticSpeechAct, SemanticTargetRole,
};

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::source::{ClaimWindowIndex, SemanticSource};
use super::text::{normalized_lowercase_body, semantic_phrase_at};
use super::{is_current_recipient_action, semantic_phrase_present};

#[derive(Deserialize)]
struct SecretReturnPolicy {
    enabled: bool,
    score: f64,
    category: String,
    actions_any: Vec<String>,
    secrets_any: Vec<String>,
    sender_return_markers: Vec<String>,
    query_provenance: String,
    #[serde(default)]
    completed_prefixes: Vec<String>,
    #[serde(default)]
    excluded_secret_prefixes: Vec<String>,
    #[serde(default)]
    secret_topic_suffixes: Vec<String>,
    #[serde(default)]
    nominal_action_suffixes: Vec<String>,
    #[serde(default)]
    inactive_action_states: Vec<String>,
    #[serde(default)]
    partial_code_suffixes: Vec<String>,
    #[serde(default)]
    device_capability_prefixes: Vec<String>,
    #[serde(default)]
    device_capability_suffixes: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct NativeSolicitationFinding {
    pub(super) source_part: SemanticSourcePart,
    pub(super) claim: SemanticClaim,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) supporting_claims: Vec<SemanticClaim>,
    pub(super) admission_rule: &'static str,
    pub(super) category: String,
    pub(super) score: f64,
    pub(super) causal_key: String,
}

fn phrase_any(text: &str, values: &[String]) -> bool {
    values
        .iter()
        .any(|value| semantic_phrase_present(text, value))
}

fn active_anchor(claim: &SemanticClaim) -> bool {
    is_current_recipient_action(claim)
        && !claim.provenance.iter().any(|value| {
            matches!(
                value.as_str(),
                "semantic_inherited_list_action_v1" | "semantic_discussion_request_v1"
            )
        })
}

fn support_eligible(claim: &SemanticClaim) -> bool {
    claim.quote_or_forward_status == SemanticQuoteStatus::Original
        && !matches!(
            claim.speech_act,
            SemanticSpeechAct::Report | SemanticSpeechAct::Warning | SemanticSpeechAct::Quotation
        )
        && claim.polarity != SemanticPolarity::AntiAction
        && claim.target_role != SemanticTargetRole::NamedThirdParty
        && claim.counter_context_ids.is_empty()
}

/// Use the requested action, rather than the number of matching policies or
/// witness clauses, as the cause. Equivalent plain/HTML projections and an
/// overlapping funds-verification/advance-fee admission get one causal vote.
fn solicitation_key(kind: &str, text: &str) -> String {
    let text = normalized_lowercase_body(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "body_relation:{kind}:{}",
        hex::encode(Sha256::digest(text.as_bytes()))
    )
}

fn requested_secret(text: &str, policy: &SecretReturnPolicy) -> bool {
    policy.secrets_any.iter().any(|secret| {
        text.match_indices(secret.as_str()).any(|(offset, _)| {
            if !semantic_phrase_at(text, secret, offset) {
                return false;
            }
            let before = text[..offset].trim_end();
            let after = text[offset + secret.len()..].trim_start();
            let device_attribute = policy.device_capability_prefixes.iter().any(|prefix| {
                before.ends_with(prefix.as_str())
                    && semantic_phrase_at(before, prefix, before.len() - prefix.len())
            }) && policy.device_capability_suffixes.iter().any(|suffix| {
                after.starts_with(suffix.as_str()) && semantic_phrase_at(after, suffix, 0)
            });
            !device_attribute
                && !inline_supplied_code(after, policy)
                && !policy.excluded_secret_prefixes.iter().any(|prefix| {
                    before.ends_with(prefix.as_str())
                        && semantic_phrase_at(before, prefix, before.len() - prefix.len())
                })
                && !policy.secret_topic_suffixes.iter().any(|suffix| {
                    after.starts_with(suffix.as_str()) && semantic_phrase_at(after, suffix, 0)
                })
        })
    })
}

/// “reply with verification code **ABCD-20231101**” supplies the exact value
/// in this message. Echoing that notification token does not establish
/// disclosure of an existing recipient login secret. This rejects only this
/// object occurrence; another request for “your password/OTP” still qualifies.
fn inline_supplied_code(after: &str, policy: &SecretReturnPolicy) -> bool {
    let decoration = after.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | '：' | '=' | '"' | '\'' | '“' | '‘')
    });
    let opening_format = decoration
        .chars()
        .take_while(|c| matches!(*c, '*' | '`'))
        .count();
    let after = after.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | '：' | '=' | '*' | '`' | '"' | '\'' | '“' | '‘')
    });
    let token = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_'))
        .take(65)
        .collect::<String>();
    if !(4..=64).contains(&token.len()) || !token.bytes().any(|c| c.is_ascii_digit()) {
        return false;
    }
    // A known prefix or masked value is not the full
    // value: “把验证码1234开头的那条发给我” still asks for a secret.
    let remainder = after[token.len()..]
        .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '”' | '’'));
    let closing_format = remainder
        .chars()
        .take_while(|c| matches!(*c, '*' | '`'))
        .count();
    if closing_format > opening_format {
        return false;
    }
    let remainder = remainder[closing_format..]
        .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '”' | '’'));
    !["...", "…", "＊"]
        .iter()
        .any(|suffix| remainder.starts_with(*suffix))
        && !policy.partial_code_suffixes.iter().any(|suffix| {
            remainder.starts_with(suffix.as_str()) && semantic_phrase_at(remainder, suffix, 0)
        })
}

/// A bare command-shaped verb can be the subject of a status description:
/// “发送验证码给我的功能已经关闭”. Keep a new, explicitly requested return
/// executable, even when an earlier feature/status description shares a span.
fn nominal_action_is_inactive(
    text: &str,
    offset: usize,
    action: &str,
    policy: &SecretReturnPolicy,
    data: &CompiledSemanticData,
) -> bool {
    let before = &text[..offset];
    if data
        .markers("semantic_request_markers_v1")
        .entries
        .iter()
        .any(|marker| semantic_phrase_present(before, &marker.normalized))
    {
        return false;
    }
    let after = &text[offset + action.len()..];
    policy.nominal_action_suffixes.iter().any(|suffix| {
        after.match_indices(suffix.as_str()).any(|(start, _)| {
            start <= 128
                && semantic_phrase_at(after, suffix, start)
                && policy.inactive_action_states.iter().any(|state| {
                    let tail = &after[start + suffix.len()..];
                    tail.match_indices(state.as_str()).any(|(state_start, _)| {
                        state_start <= 96 && semantic_phrase_at(tail, state, state_start)
                    })
                })
        })
    })
}

fn qualified_secret_returns(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<NativeSolicitationFinding>, String> {
    let policy = data.cached("semantic_secret_return_policy_v1", |registry| {
        registry
            .get_structured("semantic_secret_return_policy_v1")
            .cloned()
            .and_then(|value| serde_json::from_value::<SecretReturnPolicy>(value).ok())
            .filter(|policy| {
                policy.score.is_finite()
                    && (0.15..=0.39).contains(&policy.score)
                    && policy.category == "credential_theft"
                    && !policy.actions_any.is_empty()
                    && !policy.secrets_any.is_empty()
                    && !policy.sender_return_markers.is_empty()
                    && !policy.query_provenance.is_empty()
            })
    });
    let Some(policy) = policy.as_ref() else {
        if data
            .get_structured("semantic_secret_return_policy_v1")
            .is_some()
        {
            return Err("configured secret-return policy is malformed or invalid".into());
        }
        // This additive rule is optional on older persisted registries.
        return Ok(Vec::new());
    };
    if !policy.enabled {
        return Ok(Vec::new());
    }
    let discussions = data.markers("semantic_discussion_action_markers_v1");
    if discussions.entries.is_empty() {
        return Err("secret-return discussion predicate policy is missing".into());
    }
    let mut findings = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("secret-return inspection exceeded its CPU budget".into());
        }
        if !active_anchor(claim)
            || !policy
                .actions_any
                .iter()
                .any(|action| claim.actions.contains(action))
        {
            continue;
        }
        let Some(text) = source.claim_text(claim) else {
            continue;
        };
        let text = normalized_lowercase_body(text);
        if !requested_secret(&text, policy) {
            continue;
        }
        let active_return = policy.actions_any.iter().any(|action| {
            text.match_indices(action.as_str()).any(|(offset, _)| {
                let before = text[..offset].trim_end();
                semantic_phrase_at(&text, action, offset)
                    && !nominal_action_is_inactive(&text, offset, action, policy, data)
                    && !policy
                        .completed_prefixes
                        .iter()
                        .any(|prefix| before.ends_with(prefix.as_str()))
                    && !discussions
                        .entries
                        .iter()
                        .any(|verb| semantic_phrase_present(before, &verb.normalized))
            })
        });
        let direct_return = active_return
            && claim.action_destination == SemanticActionDestination::Sender
            && policy
                .sender_return_markers
                .iter()
                .any(|marker| semantic_phrase_present(&text, marker));
        let secret_question = claim.provenance.contains(&policy.query_provenance);
        if !direct_return && !secret_question {
            continue;
        }
        findings.push(NativeSolicitationFinding {
            source_part: source.part,
            claim: claim.clone(),
            supporting_claims: Vec::new(),
            admission_rule: "current_recipient_login_secret_disclosure_v1",
            category: policy.category.clone(),
            score: policy.score,
            causal_key: solicitation_key("secret_return", &text),
        });
    }
    Ok(findings)
}

#[derive(Deserialize)]
struct VerificationTransferPolicy {
    enabled: bool,
    score: f64,
    category: String,
    min_amount: f64,
    max_relation_bytes: usize,
    amount_pattern: String,
    actions_any: Vec<String>,
    purposes_any: Vec<String>,
    refunds_any: Vec<String>,
    whole_amount_markers: Vec<String>,
    #[serde(default)]
    completed_refund_prefixes: Vec<String>,
    #[serde(default)]
    historical_refund_subjects: Vec<String>,
    #[serde(default)]
    completed_refund_suffixes: Vec<String>,
    #[serde(default)]
    bare_refunds_any: Vec<String>,
    #[serde(default)]
    future_refund_prefixes: Vec<String>,
    #[serde(default)]
    current_refund_subjects: Vec<String>,
}

fn current_refund_witness(text: &str, policy: &VerificationTransferPolicy) -> bool {
    policy
        .refunds_any
        .iter()
        .chain(&policy.bare_refunds_any)
        .any(|refund| {
            text.match_indices(refund.as_str()).any(|(offset, _)| {
                if !semantic_phrase_at(text, refund, offset) {
                    return false;
                }
                let before = text[..offset].trim_end();
                if policy.completed_refund_prefixes.iter().any(|prefix| {
                    before.ends_with(prefix.as_str())
                        && semantic_phrase_at(before, prefix, before.len() - prefix.len())
                }) {
                    return false;
                }
                let after = text[offset + refund.len()..].trim_start();
                if policy.completed_refund_suffixes.iter().any(|suffix| {
                    after.starts_with(suffix.as_str()) && semantic_phrase_at(after, suffix, 0)
                }) {
                    return false;
                }
                let mut local_start = before.len().saturating_sub(96);
                while !before.is_char_boundary(local_start) {
                    local_start += 1;
                }
                let local_before = &before[local_start..];
                if phrase_any(local_before, &policy.historical_refund_subjects) {
                    return false;
                }
                // A bare “退还” can describe any refund. It qualifies only in a
                // future predicate about this very payment, e.g. “该款项验证后
                // 将退还”. The amount/verification action remains a separate,
                // bounded and attributed requirement at relation admission.
                !policy.bare_refunds_any.contains(refund)
                    || (policy.future_refund_prefixes.iter().any(|prefix| {
                        before.ends_with(prefix.as_str())
                            && semantic_phrase_at(before, prefix, before.len() - prefix.len())
                    }) && phrase_any(local_before, &policy.current_refund_subjects))
            })
        })
}

pub(super) fn qualified_native_solicitations(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<NativeSolicitationFinding>, String> {
    let mut findings = qualified_secret_returns(source, context, budget, data)?;
    findings.extend(qualified_verification_transfers(
        source, context, budget, data,
    )?);
    findings.extend(qualified_advance_fees(source, context, budget, data)?);
    let mut seen = HashSet::new();
    findings.retain(|finding| seen.insert(finding.causal_key.clone()));
    Ok(findings)
}

fn qualified_verification_transfers(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<NativeSolicitationFinding>, String> {
    let compiled = data.cached("semantic_verification_transfer_policy_v1", |registry| {
        let value = registry.get_structured("semantic_verification_transfer_policy_v1")?;
        let policy: VerificationTransferPolicy = serde_json::from_value(value.clone()).ok()?;
        if !policy.score.is_finite()
            || !(0.15..=0.39).contains(&policy.score)
            || policy.category != "scam"
            || !policy.min_amount.is_finite()
            || policy.min_amount < 1000.0
            || !(128..=2048).contains(&policy.max_relation_bytes)
            || policy.actions_any.is_empty()
            || policy.purposes_any.is_empty()
            || policy.refunds_any.is_empty()
            || policy.whole_amount_markers.is_empty()
        {
            return None;
        }
        let amounts = regex::RegexBuilder::new(&policy.amount_pattern)
            .size_limit(64 * 1024)
            .build()
            .ok()?;
        Some((policy, amounts))
    });
    let Some((policy, amounts)) = compiled.as_ref() else {
        return if data
            .get_structured("semantic_verification_transfer_policy_v1")
            .is_some()
        {
            Err("configured verification-transfer policy is invalid".into())
        } else {
            Ok(Vec::new())
        };
    };
    if !policy.enabled {
        return Ok(Vec::new());
    }
    if !context.claims.iter().any(|claim| {
        is_current_recipient_action(claim)
            && policy
                .actions_any
                .iter()
                .any(|action| claim.actions.contains(action))
    }) {
        return Ok(Vec::new());
    }
    let mut facts = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("verification-transfer inspection exceeded its CPU budget".into());
        }
        if !support_eligible(claim) {
            continue;
        }
        if let Some(text) = source.claim_text(claim) {
            facts.push((claim, normalized_lowercase_body(text)));
        }
    }
    let mut findings = Vec::new();
    for (anchor, text) in &facts {
        if budget.exhausted() {
            return Err("verification-transfer relation exceeded its CPU budget".into());
        }
        if !active_anchor(anchor)
            || !policy.actions_any.iter().any(|action| {
                anchor.actions.contains(action) && semantic_phrase_present(text, action)
            })
        {
            continue;
        }
        let large_amount = amounts.captures_iter(text).any(|captures| {
            let amount = captures.name("prefix").or_else(|| captures.name("suffix"));
            let Some(amount) = amount else {
                return false;
            };
            let number = amount
                .as_str()
                .replace([',', '，'], "")
                .parse::<f64>()
                .unwrap_or(0.0);
            let scale = if captures.name("punit").is_some() || captures.name("sunit").is_some() {
                10_000.0
            } else {
                1.0
            };
            number.is_finite() && number * scale >= policy.min_amount
        });
        if !large_amount
            && !policy
                .whole_amount_markers
                .iter()
                .any(|marker| semantic_phrase_present(text, marker))
        {
            continue;
        }
        let nearby = |other: &SemanticClaim| {
            anchor.source_block_id.is_some()
                && anchor.source_block_id == other.source_block_id
                && anchor
                    .span
                    .end_byte
                    .max(other.span.end_byte)
                    .saturating_sub(anchor.span.start_byte.min(other.span.start_byte))
                    <= policy.max_relation_bytes
        };
        let purpose = facts.iter().find(|(claim, text)| {
            nearby(claim)
                && policy
                    .purposes_any
                    .iter()
                    .any(|marker| semantic_phrase_present(text, marker))
        });
        let refund = facts
            .iter()
            .find(|(claim, text)| nearby(claim) && current_refund_witness(text, policy));
        let (Some((purpose, _)), Some((refund, _))) = (purpose, refund) else {
            continue;
        };
        let start = anchor
            .span
            .start_byte
            .min(purpose.span.start_byte)
            .min(refund.span.start_byte);
        let end = anchor
            .span
            .end_byte
            .max(purpose.span.end_byte)
            .max(refund.span.end_byte);
        if end - start > policy.max_relation_bytes {
            continue;
        }
        let mut supporting_claims = Vec::new();
        for support in [*purpose, *refund] {
            if support.source_span_id != anchor.source_span_id
                && !supporting_claims
                    .iter()
                    .any(|old: &SemanticClaim| old.source_span_id == support.source_span_id)
            {
                supporting_claims.push(support.clone());
            }
        }
        findings.push(NativeSolicitationFinding {
            source_part: source.part,
            claim: (*anchor).clone(),
            supporting_claims,
            admission_rule: "current_recipient_refundable_funds_verification_v1",
            category: policy.category.clone(),
            score: policy.score,
            causal_key: solicitation_key("funds_solicitation", text),
        });
    }
    Ok(findings)
}

#[derive(Deserialize)]
struct AdvanceFeePolicy {
    enabled: bool,
    score: f64,
    category: String,
    max_relation_bytes: usize,
    payment_actions_any: Vec<String>,
    fees_any: Vec<String>,
    held_assets_any: Vec<String>,
    release_actions_any: Vec<String>,
    payment_dependencies_any: Vec<String>,
    #[serde(default)]
    recipient_asset_possessives: Vec<String>,
    #[serde(default)]
    other_asset_possessives: Vec<String>,
    #[serde(default)]
    paragraph_fee_reference_terms: Vec<String>,
    #[serde(default)]
    generic_fee_reference_terms: Vec<String>,
    #[serde(default)]
    max_paragraph_boundaries: usize,
}

/// Ownership qualifies the matched asset, not the sentence's speaker. “We
/// will release your funds” is compatible with recipient ownership; “we will
/// release our account balance” cannot support a fee requested of them.
fn asset_ownership(text: &str, policy: &AdvanceFeePolicy) -> (bool, bool, bool) {
    let mut recipient_asset = false;
    let mut explicit_recipient = false;
    let mut other_asset = false;
    for asset in &policy.held_assets_any {
        for (offset, _) in text.match_indices(asset.as_str()) {
            if !semantic_phrase_at(text, asset, offset) {
                continue;
            }
            let before = text[..offset].trim_end();
            let possessive_at_end = |values: &[String]| {
                values.iter().any(|value| {
                    before.ends_with(value.as_str())
                        && (value.starts_with('\'')
                            || semantic_phrase_at(before, value, before.len() - value.len()))
                })
            };
            let explicitly_owned = possessive_at_end(&policy.recipient_asset_possessives)
                || policy.recipient_asset_possessives.iter().any(|prefix| {
                    asset.starts_with(prefix.as_str()) && semantic_phrase_at(asset, prefix, 0)
                });
            let elsewhere_owned = possessive_at_end(&policy.other_asset_possessives);
            explicit_recipient |= explicitly_owned && !elsewhere_owned;
            other_asset |= elsewhere_owned;
            recipient_asset |= !elsewhere_owned;
        }
    }
    (recipient_asset, explicit_recipient, other_asset)
}

impl AdvanceFeePolicy {
    fn valid(&self) -> bool {
        let bounded = |values: &[String]| {
            !values.is_empty()
                && values.len() <= 96
                && values
                    .iter()
                    .all(|value| !value.trim().is_empty() && value.len() <= 128)
        };
        self.score.is_finite()
            && (0.15..=0.39).contains(&self.score)
            && self.category == "scam"
            && (128..=2048).contains(&self.max_relation_bytes)
            && bounded(&self.payment_actions_any)
            && bounded(&self.fees_any)
            && bounded(&self.held_assets_any)
            && bounded(&self.release_actions_any)
            && bounded(&self.payment_dependencies_any)
            && bounded(&self.recipient_asset_possessives)
            && bounded(&self.other_asset_possessives)
            && self.max_paragraph_boundaries <= 2
            && (self.paragraph_fee_reference_terms.is_empty()
                || bounded(&self.paragraph_fee_reference_terms))
            && (self.generic_fee_reference_terms.is_empty()
                || bounded(&self.generic_fee_reference_terms))
    }
}

fn same_fee_reference(anchor: &str, dependency: &str, policy: &AdvanceFeePolicy) -> bool {
    let longest = |text: &str| {
        policy
            .paragraph_fee_reference_terms
            .iter()
            .filter(|term| semantic_phrase_present(text, term))
            .max_by_key(|term| term.len())
    };
    let (Some(payment_fee), Some(referenced_fee)) = (longest(anchor), longest(dependency)) else {
        return false;
    };
    payment_fee == referenced_fee
        || (policy.generic_fee_reference_terms.contains(referenced_fee)
            && payment_fee.ends_with(referenced_fee.as_str()))
}

fn blank_paragraph_boundaries(text: &str, stop_after: usize) -> usize {
    let mut boundaries = 0;
    let mut in_blank = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            if !in_blank {
                boundaries += 1;
                if boundaries > stop_after {
                    return boundaries;
                }
            }
            in_blank = true;
        } else {
            in_blank = false;
        }
    }
    boundaries
}

struct FeeWitness<'a> {
    claim: &'a SemanticClaim,
    text: String,
    asset: bool,
    release: bool,
    payment_dependency: bool,
}

/// A request to pay is insufficient. A locally attributed relation must say
/// that paying a fee unlocks the recipient's own balance, loan or proceeds.
/// Ordinary invoices, shopping deposits and payroll announcements stay
/// observations. Missing policy is compatible with older persisted registries.
fn qualified_advance_fees(
    source: SemanticSource<'_>,
    context: &SemanticMessageContext,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Result<Vec<NativeSolicitationFinding>, String> {
    let compiled = data.cached("semantic_funds_release_fee_policy_v1", |registry| {
        registry
            .get_structured("semantic_funds_release_fee_policy_v1")
            .cloned()
            .and_then(|value| serde_json::from_value::<AdvanceFeePolicy>(value).ok())
            .filter(AdvanceFeePolicy::valid)
    });
    let Some(policy) = compiled.as_ref() else {
        return if data
            .get_structured("semantic_funds_release_fee_policy_v1")
            .is_some()
        {
            Err("configured funds-release fee policy is malformed or invalid".into())
        } else {
            Ok(Vec::new())
        };
    };
    if !policy.enabled {
        return Ok(Vec::new());
    }
    let mut witnesses = Vec::new();
    for claim in &context.claims {
        if budget.exhausted() {
            return Err("funds-release witness inspection exceeded its CPU budget".into());
        }
        if !support_eligible(claim) {
            continue;
        }
        let Some(text) = source.claim_text(claim) else {
            continue;
        };
        let text = normalized_lowercase_body(text);
        let (asset, explicit_recipient, other_asset) = asset_ownership(&text, policy);
        witnesses.push(FeeWitness {
            claim,
            asset: asset
                && (claim.target_role != SemanticTargetRole::SenderSelf || explicit_recipient),
            release: phrase_any(&text, &policy.release_actions_any)
                && !other_asset
                && (claim.target_role != SemanticTargetRole::SenderSelf || explicit_recipient),
            payment_dependency: phrase_any(&text, &policy.payment_dependencies_any),
            text,
        });
    }
    // Comma splitting may separate “保证金到账审核通过后，资金将返还”.
    // Only the immediately adjacent, same-block, attributed dependency is
    // inherited; arbitrary payment words elsewhere in the paragraph cannot
    // qualify an unrelated release statement.
    let release_dependencies = witnesses
        .iter()
        .enumerate()
        .map(|(release_index, release)| {
            if !release.release {
                return None;
            }
            if release.payment_dependency {
                return Some(release_index);
            }
            witnesses
                .iter()
                .enumerate()
                .filter(|(_, dependency)| {
                    dependency.payment_dependency
                        && dependency.claim.source_block_id == release.claim.source_block_id
                        && dependency.claim.span.end_byte <= release.claim.span.start_byte
                        && release.claim.span.start_byte - dependency.claim.span.end_byte <= 16
                        && source
                            .text
                            .get(dependency.claim.span.end_byte..release.claim.span.start_byte)
                            .is_some_and(|gap| {
                                gap.chars().all(|c| {
                                    c.is_whitespace() || matches!(c, ',' | '，' | ':' | '：')
                                })
                            })
                })
                .max_by_key(|(_, dependency)| dependency.claim.span.end_byte)
                .map(|(index, _)| index)
        })
        .collect::<Vec<_>>();
    let index = ClaimWindowIndex::new(
        witnesses
            .iter()
            .enumerate()
            .map(|(index, witness)| (index, witness.claim.span)),
    );
    let mut findings = Vec::new();
    for anchor in &witnesses {
        if budget.exhausted() {
            return Err("funds-release relation inspection exceeded its CPU budget".into());
        }
        if !active_anchor(anchor.claim)
            || !policy.payment_actions_any.iter().any(|action| {
                anchor.claim.actions.contains(action)
                    && semantic_phrase_present(&anchor.text, action)
            })
            || !phrase_any(&anchor.text, &policy.fees_any)
        {
            continue;
        }
        let candidates = index.within_envelope(anchor.claim.span, policy.max_relation_bytes);
        let nearby = |witness: &FeeWitness<'_>| {
            anchor.claim.source_block_id.is_some()
                && anchor.claim.source_block_id == witness.claim.source_block_id
        };
        let mut relation = None;
        for &release_index in &candidates {
            if budget.exhausted() {
                return Err("funds-release witness search exceeded its CPU budget".into());
            }
            let release = &witnesses[release_index];
            let Some(dependency_index) = release_dependencies[release_index] else {
                continue;
            };
            let dependency = &witnesses[dependency_index];
            let same_block = nearby(release) && nearby(dependency);
            let typed_reference = !same_block
                && source.part == SemanticSourcePart::PlainText
                && policy.max_paragraph_boundaries > 0
                && release.claim.source_block_id.is_some()
                && release.claim.source_block_id == dependency.claim.source_block_id
                && same_fee_reference(&anchor.text, &dependency.text, policy);
            if !same_block && !typed_reference {
                continue;
            }
            for &asset_index in &candidates {
                if budget.exhausted() {
                    return Err("funds-release asset search exceeded its CPU budget".into());
                }
                let asset = &witnesses[asset_index];
                if !asset.asset
                    || (same_block && !nearby(asset))
                    || (typed_reference
                        && asset.claim.source_block_id != release.claim.source_block_id)
                {
                    continue;
                }
                let start = anchor
                    .claim
                    .span
                    .start_byte
                    .min(release.claim.span.start_byte)
                    .min(asset.claim.span.start_byte)
                    .min(dependency.claim.span.start_byte);
                let end = anchor
                    .claim
                    .span
                    .end_byte
                    .max(release.claim.span.end_byte)
                    .max(asset.claim.span.end_byte)
                    .max(dependency.claim.span.end_byte);
                if end.saturating_sub(start) <= policy.max_relation_bytes {
                    if typed_reference {
                        let Some(envelope) = source.text.get(start..end) else {
                            continue;
                        };
                        if blank_paragraph_boundaries(envelope, policy.max_paragraph_boundaries)
                            > policy.max_paragraph_boundaries
                            || context.claims.iter().any(|other| {
                                other.source_part == source.part
                                    && other.span.start_byte < end
                                    && start < other.span.end_byte
                                    && (!support_eligible(other)
                                        || other
                                            .provenance
                                            .iter()
                                            .any(|value| value == UNVERIFIED_THREAD_PROVENANCE))
                            })
                        {
                            continue;
                        }
                    }
                    relation = Some((release, asset, dependency, typed_reference));
                    break;
                }
            }
            if relation.is_some() {
                break;
            }
        }
        let Some((release, asset, dependency, typed_reference)) = relation else {
            continue;
        };
        let mut supporting_claims = Vec::new();
        for witness in [release, asset, dependency] {
            if witness.claim.source_span_id != anchor.claim.source_span_id
                && !supporting_claims.iter().any(|claim: &SemanticClaim| {
                    claim.source_span_id == witness.claim.source_span_id
                })
            {
                supporting_claims.push(witness.claim.clone());
            }
        }
        findings.push(NativeSolicitationFinding {
            source_part: source.part,
            claim: anchor.claim.clone(),
            supporting_claims,
            admission_rule: if typed_reference {
                "current_recipient_typed_fee_reference_for_own_funds_v1"
            } else {
                "current_recipient_advance_fee_for_own_funds_v1"
            },
            category: policy.category.clone(),
            score: policy.score,
            causal_key: solicitation_key("funds_solicitation", &anchor.text),
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::compiled::compiled_semantic_data;
    use crate::semantic::extract_semantic_context;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    use vigilyx_core::security::SemanticCoverageStatus;

    #[test]
    fn funds_release_policy_requires_bounded_nonempty_asset_ownership_lists() {
        let source: serde_json::Value =
            serde_json::from_str(include_str!("data/relations.json")).unwrap();
        let policy = &source["lists"]["semantic_funds_release_fee_policy_v1"]["items"];
        let parsed: AdvanceFeePolicy = serde_json::from_value(policy.clone()).unwrap();
        assert!(parsed.valid(), "bundled funds-release policy must be valid");
        for field in ["recipient_asset_possessives", "other_asset_possessives"] {
            for invalid in [
                serde_json::json!([]),
                serde_json::json!(["   "]),
                serde_json::json!(["a".repeat(129)]),
                serde_json::json!(vec!["your"; 97]),
            ] {
                let mut candidate = policy.clone();
                candidate[field] = invalid;
                let parsed: AdvanceFeePolicy = serde_json::from_value(candidate).unwrap();
                assert!(!parsed.valid(), "invalid ownership list accepted: {field}");
            }
        }
    }

    fn findings(body: &str) -> Vec<NativeSolicitationFinding> {
        findings_for_source(body, SemanticSourcePart::PlainText)
    }

    fn findings_for_source(body: &str, part: SemanticSourcePart) -> Vec<NativeSolicitationFinding> {
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
        let context = extract_semantic_context(&session, body, part);
        assert_eq!(
            context.coverage,
            SemanticCoverageStatus::Complete,
            "{context:?}"
        );
        qualified_native_solicitations(
            SemanticSource::new(body, part),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
    }

    #[test]
    fn secret_device_attributes_and_provided_reference_codes_are_not_secret_values() {
        for body in [
            "Please reply with an OTP-enabled mobile number.",
            "Please reply with your OTP-capable phone.",
            "请把你支持 OTP 的手机型号发给我们。",
            "请把你兼容 OTP 的设备型号发给我。",
            "请把支持验证码的设备型号发给我。",
            "Please reply with the verification code NOTICE-20231101.",
            "Please reply with verification code **NOTICE-20231101**.",
            "请回复短信验证码123456。",
            "Please reply with verification code **NOTICE-20231101**?",
        ] {
            assert!(
                findings(body).is_empty(),
                "not an existing secret disclosure: {body}"
            );
        }
        for body in [
            "Please reply with your OTP.",
            "Case reference NOTICE-20231101. Please reply with your password.",
            "Please reply with verification code NOTICE-20231101 and your password.",
            "Please reply with the OTP sent to your phone.",
            "请把你的OTP发给我。",
            "请把支持OTP的手机型号和你的验证码发给我们。",
            "请把你的OTP和支持OTP的设备型号发给我们。",
            "请把你支持OTP的手机型号发给我，随后把你的OTP发给我。",
            "请把短信验证码1234开头的那条发给我。",
            "请把验证码1234…的完整号码发给我。",
            "请把短信验证码1234****的完整号码发给我。",
            "Please reply with your verification code 1234**** in full.",
        ] {
            assert!(
                findings(body)
                    .iter()
                    .any(|row| row.category == "credential_theft"),
                "independent recipient secret was lost: {body}"
            );
        }
    }

    #[test]
    fn typed_fee_reference_connects_only_bounded_plain_text_procedure_sections() {
        let body = "请预先缴纳投资本金的20%作为清退保证金。\n\n请将身份证材料发送至审核部门。\n\n保证金到账审核通过后，您账户内的待清退资金将分批返还。";
        let rows = findings(body);
        assert!(
            rows.iter().any(|row| {
                row.admission_rule == "current_recipient_typed_fee_reference_for_own_funds_v1"
                    && !row.supporting_claims.is_empty()
            }),
            "same fee and conditional own-asset release must bind"
        );
        assert!(
            findings_for_source(body, SemanticSourcePart::Html).is_empty(),
            "HTML container boundaries are never relaxed"
        );
        for body in [
            "请预先缴纳清退保证金。\n\n付款后，您账户内的待清退资金将全额返还。".to_string(),
            "请支付提现手续费。\n\n保证金到账审核通过后，您账户内的待清退资金将全额返还。".to_string(),
            "请缴纳贷款保证金。\n\n清退保证金到账审核通过后，您的账户余额将全额返还。".to_string(),
            "请预先缴纳清退保证金。\n\n安全培训案例：以下为案例描述。\n\n保证金到账审核通过后，您的待清退资金将全额返还。".to_string(),
            "请预先缴纳清退保证金。\n\n请勿透露您的验证码。\n\n保证金到账审核通过后，您的待清退资金将全额返还。".to_string(),
            "请预先缴纳清退保证金。\n\n> 完成账户验证。\n\n保证金到账审核通过后，您的待清退资金将全额返还。".to_string(),
            "请预先缴纳清退保证金。\n\n一般资料登记。\n\n普通通知。\n\n保证金到账审核通过后，您的待清退资金将全额返还。".to_string(),
            format!("请预先缴纳清退保证金。\n\n{}\n\n保证金到账审核通过后，您的待清退资金将全额返还。", "普通记录。".repeat(120)),
        ] {
            assert!(findings(&body).is_empty(), "unrelated fee/condition/scope must not bind: {body}");
        }
    }

    #[test]
    fn refundable_transfer_does_not_borrow_other_users_completed_refunds() {
        for body in [
            "请转账人民币5000元进行资金验证。实时存管动态：07:32分完成用户已全额返还（查看案例）。",
            "请转账人民币5000元进行资金验证。这笔款项已经原路返还。",
            "请转账人民币5000元进行资金验证。这笔款项昨日原路返还。",
            "请转账人民币5000元进行资金验证。这笔款项原路返还完毕。",
            "Please transfer USD5000 for identity verification. This deposit was returned in full.",
            "Please transfer USD5000 for identity verification. This deposit has been returned in full.",
            "Please transfer USD5000 for identity verification. This deposit was previously returned in full.",
            "Please transfer USD5000 for identity verification. This deposit returned in full yesterday.",
        ] {
            assert!(
                findings(body).is_empty(),
                "past refunds are not current refund promises: {body}"
            );
        }
        for body in [
            "请转账人民币5000元进行资金验证。该款项将在验证完成后原路返还。",
            "请转账人民币5000元进行资金验证。已审核通过的该款项将在验证完成后原路返还。",
            "请转账人民币5000元进行资金验证。已缴押金将在验证完成后原路返还。",
            "Please transfer USD5000 for identity verification. This deposit will be returned in full.",
            "Please transfer USD5000 for identity verification. The already reviewed deposit will be returned in full.",
        ] {
            assert!(
                findings(body).iter().any(|row| {
                    row.admission_rule == "current_recipient_refundable_funds_verification_v1"
                }),
                "current refund promise must remain: {body}"
            );
        }
    }

    #[test]
    fn bare_refund_requires_a_future_predicate_about_the_current_payment() {
        for body in [
            "请完成账户验证，将已审核的5000元转入指定账户；该款项验证后将退还。",
            "请完成账户验证，将已审核的5000元转入指定账户；这笔款项核验后会返还。",
            "请完成账户验证，将已审核的5000元转入指定账户；该款项将在验证完成后退还。",
        ] {
            assert!(
                findings(body).iter().any(|row| {
                    row.admission_rule == "current_recipient_refundable_funds_verification_v1"
                }),
                "current reviewed funds still have a future refund promise: {body}"
            );
        }
        for body in [
            "请完成账户验证，将已审核的5000元转入指定账户；他人款项验证后将退还。",
            "请完成账户验证，将已审核的5000元转入指定账户；该款项昨日退还。",
            "请完成账户验证，将已审核的5000元转入指定账户；该款项已经退还。",
            "请完成账户验证，将已审核的5000元转入指定账户；该款项退还说明请查阅政策。",
            "请完成账户验证，将已审核的5000元转入指定账户；此前用户的该款项验证后将退还。",
        ] {
            assert!(
                findings(body).is_empty(),
                "bare refund words are insufficient witnesses: {body}"
            );
        }
    }

    #[test]
    fn login_secret_disclosure_keeps_meaning_across_language_switches() {
        for body in [
            "请把短信验证码发送给我。",
            "请把验证码先发我。",
            "Please send us your password.",
            "Please reply with your one-time password.",
            "请 send your OTP to me。",
            "Please 把验证码发给我。",
            "Please send us your recovery codes.",
            "Please give me your passwords.",
            "Please tell us your passcodes.",
            "请把验证码发给我以恢复已关闭的功能。",
        ] {
            let rows = findings(body);
            assert!(
                rows.iter().any(|row| row.category == "credential_theft"),
                "missing secret return: {body}"
            );
        }
    }

    #[test]
    fn login_secret_mentions_exclusions_and_discussions_are_not_disclosure() {
        for body in [
            "请勿把短信验证码发送给我。",
            "Do not send us your password.",
            "I will send you my password.",
            "Please explain whether you should send us your password.",
            "安全培训案例：骗子要求发送验证码给我。",
            "Security training: the attacker requests: Please send us your password.",
            "Please log in to your account using your password.",
            "Please send us your password policy.",
            "Please send us your password reset instructions.",
            "Please send us the invoice, not your password.",
            "Please send us the backup code format.",
            "发送验证码给我的功能已经关闭。",
            "发我验证码的操作已经禁用。",
            "Send us your password function is disabled.",
        ] {
            assert!(
                findings(body).is_empty(),
                "incorrect secret admission: {body}"
            );
        }
    }

    #[test]
    fn advance_fee_requires_payment_dependent_release_of_own_assets() {
        for body in [
            "您的账户余额已冻结。请先支付提现手续费，付款后才能解冻账户余额。",
            "请预先缴纳清退保证金。保证金到账审核通过后，待清退资金将全额返还。",
            "Please pay the withdrawal fee to release your funds.",
            "Please pay the processing fee before we can release your loan.",
            "请先 pay the withdrawal fee，付款后才能 unlock your balance。",
            "请支付提现费。我们将在付款后为您解冻您的账户余额。",
            "Please pay the withdrawal fee. We will release your account balance after payment.",
        ] {
            assert!(
                findings(body)
                    .iter()
                    .any(|row| row.admission_rule
                        == "current_recipient_advance_fee_for_own_funds_v1"),
                "missing fee relation: {body}"
            );
        }
    }

    #[test]
    fn normal_purchases_reports_and_unrelated_assets_do_not_admit_advance_fees() {
        for body in [
            "请支付订单货款，付款后即可发货。",
            "请缴纳租房押金，押金将在退租后返还。",
            "请将五万元存入公司对公账户进行注册验资，验资后会退回。",
            "Your loan processing fee will be deducted from the disbursed amount.",
            "Please pay the invoice. Your funds are available for withdrawal.",
            "Please pay the processing fee to release your business license.",
            "请支付会员认证费。您可查询账户余额，提现申请已经完成。",
            "安全培训案例：骗子要求先支付提现手续费，付款后才能解冻账户余额。",
            "Do not pay the withdrawal fee to release your funds.",
            "Incident report: the attacker requests: Please pay the withdrawal fee to release your funds.",
            "No upfront funds are required. Please contact the supplier to confirm the procurement order.",
            "请支付提现手续费。\n\n以下为另一个案例：付款后才能解冻您的账户余额。",
            "请支付认证费。我们将在付款后解冻我们的账户余额。",
            "Please pay the processing fee. We will release our account balance after payment.",
            "请支付认证费。付款后才能解冻第三方的账户余额。",
            "请支付认证费。我们将在付款后解冻我司账户余额。",
        ] {
            assert!(findings(body).is_empty(), "incorrect fee relation: {body}");
        }
    }

    #[test]
    fn nominal_status_does_not_hide_a_later_independent_secret_request() {
        for body in [
            "发送验证码给我的功能已经关闭。请把验证码发送给我。",
            "发我验证码的操作已经禁用。\n\nPlease send us your OTP.",
        ] {
            assert!(
                findings(body)
                    .iter()
                    .any(|row| row.category == "credential_theft"),
                "later request lost: {body}"
            );
        }
    }

    #[test]
    fn native_findings_validate_source_coordinates_and_deduplicate_same_cause() {
        let body = "Please pay the withdrawal fee to release your funds.";
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
        let original = qualified_native_solicitations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap();
        assert_eq!(original.len(), 1);
        context.claims.extend(context.claims.clone());
        let doubled = qualified_native_solicitations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap();
        assert_eq!(doubled.len(), 1);
        assert_eq!(original[0].causal_key, doubled[0].causal_key);
        let wrong_source = qualified_native_solicitations(
            SemanticSource::new(body, SemanticSourcePart::Header),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap();
        assert!(wrong_source.is_empty());
    }
}
