//! Semantic scenario policy layer.
//!
//! This layer converts typed semantic claims into reusable scenario
//! observations.  It intentionally has no threat score, threshold, or MTA
//! disposition side effect.  A later, separately evaluated policy may admit a
//! scenario into fusion.

use super::{is_current_recipient_action, semantic_counter_context_qualifies};
use serde::Deserialize;
use std::sync::Arc;

use super::compiled::{CompiledSemanticData, compiled_semantic_data};
use super::context::is_original_recipient_action;
use vigilyx_core::security::{
    SemanticClaim, SemanticCoverageStatus, SemanticLinkExtractionSource, SemanticMessageContext,
    SemanticPolarity, SemanticQuoteStatus, SemanticScenarioFinding, SemanticScenarioId,
    SemanticScenarioResolution, SemanticSourcePart, SemanticSpeechAct,
};

const PROVENANCE: &str = "semantic_scenario_policy_v1";
const POLICY_LIST: &str = "semantic_scenario_policy_v1";
const CROSS_CLAIM_PROVENANCE: &str = "semantic_cross_claim_candidate_policy_v1";
const CROSS_CLAIM_POLICY_LIST: &str = "semantic_cross_claim_candidate_policy_v1";

#[derive(Debug, Clone, Deserialize)]
struct SemanticScenarioVariant {
    #[serde(default)]
    actions_any: Vec<String>,
    #[serde(default)]
    objects_any: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SemanticScenarioPolicyEntry {
    scenario_id: SemanticScenarioId,
    #[serde(default)]
    variants: Vec<SemanticScenarioVariant>,
}

#[derive(Debug, Clone, Deserialize)]
struct SemanticCrossClaimScenarioPolicyEntry {
    scenario_id: SemanticScenarioId,
    #[serde(default)]
    context_scenario_id: Option<SemanticScenarioId>,
    #[serde(default)]
    context_objects_any: Vec<String>,
    #[serde(default)]
    linked_variants_any: Vec<SemanticScenarioVariant>,
    #[serde(default)]
    ambiguous_linked_actions_any: Vec<String>,
    #[serde(default)]
    ambiguous_linked_objects_any: Vec<String>,
    #[serde(default)]
    allow_header_context: bool,
}

/// Accepted scenario rules plus an observation-only diagnostic. Scenario
/// findings never score, so a missing or invalid policy is reported as a
/// diagnostic rather than as an inspection coverage gap.
struct ScenarioPolicy {
    entries: Vec<SemanticScenarioPolicyEntry>,
    diagnostic: Option<&'static str>,
}

fn scenario_policy(data: &CompiledSemanticData) -> Arc<ScenarioPolicy> {
    data.cached(POLICY_LIST, |registry| {
        let Some(value) = registry
            .get_structured(POLICY_LIST)
            .cloned()
        else {
            return ScenarioPolicy {
                entries: Vec::new(),
                diagnostic: Some(
                    "semantic scenario policy (semantic_scenario_policy_v1) is missing; scenario observations are disabled",
                ),
            };
        };
        let Ok(entries) = serde_json::from_value::<Vec<SemanticScenarioPolicyEntry>>(value) else {
            return ScenarioPolicy {
                entries: Vec::new(),
                diagnostic: Some(
                    "semantic scenario policy (semantic_scenario_policy_v1) is malformed; scenario observations are disabled",
                ),
            };
        };

        let mut accepted = Vec::new();
        let mut rejected = false;
        for entry in entries {
            if accepted
                .iter()
                .any(|existing: &SemanticScenarioPolicyEntry| existing.scenario_id == entry.scenario_id)
                || entry.variants.is_empty()
                || entry
                    .variants
                    .iter()
                    .any(|variant| variant.actions_any.is_empty() || variant.objects_any.is_empty())
            {
                rejected = true;
                continue;
            }
            accepted.push(entry);
        }
        let diagnostic = if accepted.is_empty() {
            Some("semantic scenario policy (semantic_scenario_policy_v1) has no valid rules; scenario observations are disabled")
        } else if rejected {
            Some("semantic scenario policy (semantic_scenario_policy_v1) contains invalid or duplicate rules that were ignored")
        } else {
            None
        };
        ScenarioPolicy {
            entries: accepted,
            diagnostic,
        }
    })
}

pub(super) fn scenario_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    scenario_policy(data).diagnostic
}

fn contains_policy_value(observed: &[String], configured: &[String]) -> bool {
    observed.iter().any(|value| {
        configured
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value))
    })
}

fn variant_matches(claim: &SemanticClaim, variant: &SemanticScenarioVariant) -> bool {
    contains_policy_value(&claim.actions, &variant.actions_any)
        && contains_policy_value(&claim.objects, &variant.objects_any)
}

fn generic_cta_matches(
    claim: &SemanticClaim,
    policy: &SemanticCrossClaimScenarioPolicyEntry,
) -> bool {
    let is_configured_generic_cta =
        matches_any(&claim.actions, &policy.ambiguous_linked_actions_any)
            && matches_any(&claim.objects, &policy.ambiguous_linked_objects_any);
    let has_only_link_or_scenario_objects = claim.objects.iter().all(|object| {
        object == "链接" || matches_any(std::slice::from_ref(object), &policy.context_objects_any)
    });
    is_configured_generic_cta && has_only_link_or_scenario_objects
}

fn parse_cross_claim_policy_entries(
    value: serde_json::Value,
) -> Result<Vec<SemanticCrossClaimScenarioPolicyEntry>, &'static str> {
    let entries = serde_json::from_value::<Vec<SemanticCrossClaimScenarioPolicyEntry>>(value)
        .map_err(|_| "semantic cross-claim candidate policy is malformed")?;
    if entries.is_empty() {
        return Err("semantic cross-claim candidate policy is empty");
    }

    let mut accepted = Vec::new();
    let mut scenario_ids = Vec::new();
    for entry in entries {
        let valid_shape = match entry.scenario_id {
            SemanticScenarioId::AccountSecurityVerification => {
                entry.context_scenario_id == Some(SemanticScenarioId::AccountAccessRequest)
                    && !entry.context_objects_any.is_empty()
                    && !entry.linked_variants_any.is_empty()
                    && entry.linked_variants_any.iter().all(|variant| {
                        !variant.actions_any.is_empty() && !variant.objects_any.is_empty()
                    })
                    && !entry.ambiguous_linked_actions_any.is_empty()
                    && !entry.ambiguous_linked_objects_any.is_empty()
                    && entry.allow_header_context
            }
            SemanticScenarioId::StorageQuotaReward => {
                entry.context_scenario_id.is_none()
                    && !entry.context_objects_any.is_empty()
                    && !entry.linked_variants_any.is_empty()
                    && entry.linked_variants_any.iter().all(|variant| {
                        !variant.actions_any.is_empty() && !variant.objects_any.is_empty()
                    })
                    && entry.ambiguous_linked_actions_any.is_empty()
                    && entry.ambiguous_linked_objects_any.is_empty()
                    && entry.allow_header_context
            }
            _ => false,
        };
        let marker_is_empty = entry
            .context_objects_any
            .iter()
            .chain(
                entry
                    .linked_variants_any
                    .iter()
                    .flat_map(|variant| variant.actions_any.iter().chain(&variant.objects_any)),
            )
            .chain(&entry.ambiguous_linked_actions_any)
            .chain(&entry.ambiguous_linked_objects_any)
            .any(|value| value.trim().is_empty());
        if !valid_shape || marker_is_empty || scenario_ids.contains(&entry.scenario_id) {
            return Err(
                "semantic cross-claim candidate policy contains an invalid or duplicate rule",
            );
        }
        scenario_ids.push(entry.scenario_id);
        accepted.push(entry);
    }
    Ok(accepted)
}

fn cross_claim_policy_entries(
    data: &CompiledSemanticData,
) -> Arc<Result<Vec<SemanticCrossClaimScenarioPolicyEntry>, &'static str>> {
    data.cached(CROSS_CLAIM_POLICY_LIST, |registry| {
        let value = registry
            .get_structured(CROSS_CLAIM_POLICY_LIST)
            .cloned()
            .ok_or("semantic cross-claim candidate policy is missing")?;
        parse_cross_claim_policy_entries(value)
    })
}

/// Observation-only diagnostic; it is never a coverage reason.
pub(super) fn cross_claim_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    cross_claim_policy_entries(data)
        .as_ref()
        .as_ref()
        .err()
        .copied()
}

fn matches_any(observed: &[String], configured: &[String]) -> bool {
    observed.iter().any(|value| {
        configured
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value))
    })
}

fn original_non_counter_context(claim: &SemanticClaim) -> bool {
    claim.quote_or_forward_status == SemanticQuoteStatus::Original
        && claim.counter_context_ids.is_empty()
        && claim.polarity != SemanticPolarity::AntiAction
        && !matches!(
            claim.speech_act,
            SemanticSpeechAct::Report | SemanticSpeechAct::Quotation | SemanticSpeechAct::Warning
        )
}

fn is_physical_nominal_cta(claim: &SemanticClaim, context: &SemanticMessageContext) -> bool {
    matches!(
        claim.actor_role,
        vigilyx_core::security::SemanticActorRole::Sender
            | vigilyx_core::security::SemanticActorRole::AuthenticatedSender
    ) && claim.target_role == vigilyx_core::security::SemanticTargetRole::Recipient
        && matches!(
            claim.speech_act,
            SemanticSpeechAct::Request | SemanticSpeechAct::Instruction
        )
        && claim.polarity == SemanticPolarity::Action
        && claim.quote_or_forward_status == SemanticQuoteStatus::Original
        && claim.source_part == SemanticSourcePart::Html
        && claim.link_ids.len() == 1
        && claim
            .provenance
            .iter()
            .any(|value| value == "nominal_html_submit_or_anchor_instruction_v2")
        && context.links.iter().any(|link| {
            link.link_id == claim.link_ids[0]
                && link.source_span_id.as_deref() == Some(claim.source_span_id.as_str())
                && matches!(
                    link.extraction_source,
                    SemanticLinkExtractionSource::Href | SemanticLinkExtractionSource::FormAction
                )
        })
}

fn context_and_cta_share_scope(
    context_claim: &SemanticClaim,
    cta: &SemanticClaim,
    allow_header_context: bool,
) -> bool {
    if context_claim.source_part == cta.source_part {
        context_claim.source_span_id == cta.source_span_id
            || context_claim
                .source_block_id
                .as_ref()
                .zip(cta.source_block_id.as_ref())
                .is_some_and(|(left, right)| left == right)
    } else {
        allow_header_context && context_claim.source_part == SemanticSourcePart::Header
    }
}

fn cross_part_counter_context_ids(
    context: &SemanticMessageContext,
    cta: &SemanticClaim,
) -> Vec<String> {
    context
        .claims
        .iter()
        .filter(|counter| {
            counter.source_part == cta.source_part
                && cta
                    .source_block_id
                    .as_ref()
                    .is_some_and(|block| counter.source_block_id.as_ref() == Some(block))
                && semantic_counter_context_qualifies(cta, counter)
        })
        .map(|counter| counter.source_span_id.clone())
        .collect()
}

fn cross_claim_findings(
    context: &SemanticMessageContext,
    existing: &[SemanticScenarioFinding],
    data: &CompiledSemanticData,
) -> Vec<SemanticScenarioFinding> {
    let policies = cross_claim_policy_entries(data);
    let Ok(policies) = policies.as_ref() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for policy in policies {
        let contexts = context
            .claims
            .iter()
            .filter(|claim| original_non_counter_context(claim))
            .filter(|claim| {
                if let Some(scenario_id) = policy.context_scenario_id {
                    let supports_scenario = existing.iter().any(|finding| {
                        finding.scenario_id == scenario_id
                            && finding
                                .claim_ids
                                .iter()
                                .any(|id| id == &claim.source_span_id)
                    });
                    supports_scenario && matches_any(&claim.objects, &policy.context_objects_any)
                } else {
                    matches_any(&claim.objects, &policy.context_objects_any)
                }
            })
            .collect::<Vec<_>>();
        let [supporting_claim] = contexts.as_slice() else {
            continue;
        };
        let mut ctas = context
            .claims
            .iter()
            .filter(|claim| {
                is_physical_nominal_cta(claim, context)
                    && context_and_cta_share_scope(
                        supporting_claim,
                        claim,
                        policy.allow_header_context,
                    )
            })
            .filter(|claim| {
                policy
                    .linked_variants_any
                    .iter()
                    .any(|variant| variant_matches(claim, variant))
                    || generic_cta_matches(claim, policy)
            })
            .collect::<Vec<_>>();
        if ctas.is_empty() {
            continue;
        }
        ctas.sort_by(|left, right| left.source_span_id.cmp(&right.source_span_id));
        ctas.dedup_by(|left, right| left.source_span_id == right.source_span_id);

        let mut link_ids = ctas
            .iter()
            .flat_map(|cta| cta.link_ids.iter().cloned())
            .collect::<Vec<_>>();
        link_ids.sort();
        link_ids.dedup();
        let all_link_ids = context
            .links
            .iter()
            .map(|link| link.link_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let all_ctas_are_specific = ctas.iter().all(|cta| {
            policy
                .linked_variants_any
                .iter()
                .any(|variant| variant_matches(cta, variant))
        });
        let header_cross_claim = supporting_claim.source_part == SemanticSourcePart::Header;
        let mut counter_context_ids = supporting_claim.counter_context_ids.clone();
        for cta in &ctas {
            counter_context_ids.extend(cta.counter_context_ids.iter().cloned());
            counter_context_ids.extend(cross_part_counter_context_ids(context, cta));
        }
        counter_context_ids.sort();
        counter_context_ids.dedup();

        let resolution_reason = if !counter_context_ids.is_empty() {
            Some("cross_part_counter_context")
        } else if context.coverage != SemanticCoverageStatus::Complete {
            Some("inspection_incomplete")
        } else if ctas.len() > 1 {
            if header_cross_claim {
                link_ids = all_link_ids.iter().cloned().collect();
            }
            Some("multiple_candidate_ctas")
        } else if header_cross_claim && all_link_ids.len() > 1 {
            link_ids = all_link_ids.iter().cloned().collect();
            Some("multiple_interactive_targets")
        } else if header_cross_claim && !all_ctas_are_specific {
            Some("generic_cta_label")
        } else {
            None
        };
        let resolution = if !counter_context_ids.is_empty() {
            SemanticScenarioResolution::Countered
        } else if resolution_reason.is_some() {
            SemanticScenarioResolution::Ambiguous
        } else {
            SemanticScenarioResolution::Candidate
        };
        let scenario = serde_json::to_value(policy.scenario_id)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_string());
        let mut claim_ids = vec![supporting_claim.source_span_id.clone()];
        claim_ids.extend(ctas.iter().map(|cta| cta.source_span_id.clone()));
        claim_ids.sort();
        claim_ids.dedup();
        let causal_inputs = std::iter::once(supporting_claim.causal_key.as_str())
            .chain(ctas.iter().map(|cta| cta.causal_key.as_str()))
            .collect::<Vec<_>>()
            .join(":");
        let link_key = link_ids.join(",");
        let confidence = ctas
            .iter()
            .map(|cta| cta.confidence)
            .fold(supporting_claim.confidence, f64::min);
        findings.push(SemanticScenarioFinding {
            scenario_id: policy.scenario_id,
            resolution,
            resolution_reason: resolution_reason.map(str::to_owned),
            claim_ids,
            link_ids,
            counter_context_ids,
            coverage: context.coverage,
            coverage_reason: context.coverage_reason.clone(),
            provenance: vec![CROSS_CLAIM_PROVENANCE.to_string()],
            confidence,
            causal_key: format!("semantic_cross_claim:{scenario}:{causal_inputs}:{link_key}"),
        });
    }
    findings
}

fn finding(
    scenario_id: SemanticScenarioId,
    claim: &SemanticClaim,
    context: &SemanticMessageContext,
) -> SemanticScenarioFinding {
    let scenario = serde_json::to_value(scenario_id)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string());
    let incomplete = context.coverage != SemanticCoverageStatus::Complete;
    SemanticScenarioFinding {
        scenario_id,
        resolution: if !claim.counter_context_ids.is_empty() {
            SemanticScenarioResolution::Countered
        } else if incomplete {
            SemanticScenarioResolution::Ambiguous
        } else {
            SemanticScenarioResolution::Candidate
        },
        resolution_reason: if !claim.counter_context_ids.is_empty() {
            Some("linked_instruction_conflict_requires_review".to_string())
        } else {
            incomplete.then_some("inspection_incomplete".to_string())
        },
        claim_ids: vec![claim.source_span_id.clone()],
        link_ids: claim.link_ids.clone(),
        counter_context_ids: claim.counter_context_ids.clone(),
        coverage: context.coverage,
        coverage_reason: context.coverage_reason.clone(),
        provenance: vec![PROVENANCE.to_string()],
        confidence: claim.confidence,
        causal_key: format!("semantic_scenario:{scenario}:{}", claim.source_span_id),
    }
}

/// Evaluate typed claims into reusable, non-scoring scenario observations.
pub fn evaluate_semantic_scenarios(
    context: &SemanticMessageContext,
) -> Vec<SemanticScenarioFinding> {
    evaluate_semantic_scenarios_with_data(context, &compiled_semantic_data())
}

pub(super) fn evaluate_semantic_scenarios_with_data(
    context: &SemanticMessageContext,
    data: &CompiledSemanticData,
) -> Vec<SemanticScenarioFinding> {
    let mut findings = Vec::new();
    let policy = scenario_policy(data);
    for claim in &context.claims {
        if !is_current_recipient_action(claim)
            && !(is_original_recipient_action(claim) && !claim.link_ids.is_empty())
        {
            continue;
        }
        for entry in policy.entries.iter() {
            if entry
                .variants
                .iter()
                .any(|variant| variant_matches(claim, variant))
            {
                findings.push(finding(entry.scenario_id, claim, context));
            }
        }
    }
    let cross_claims = cross_claim_findings(context, &findings, data);
    findings.extend(cross_claims);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{extract_semantic_context, select_semantic_projection};
    use vigilyx_core::models::{EmailLink, EmailSession, Protocol};
    use vigilyx_core::security::{
        SemanticLinkOwnershipStatus, SemanticScenarioResolution, SemanticSourcePart,
    };

    fn context(body: &str) -> SemanticMessageContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.20".to_string(),
            25_000,
            "192.0.2.20".to_string(),
            25,
        );
        session.mail_from = Some("sender@external.example".to_string());
        session.rcpt_to.push("employee@corp.internal".to_string());
        extract_semantic_context(&session, body, SemanticSourcePart::PlainText)
    }

    fn html_email_context(subject: &str, anchor: &str, url: &str) -> SemanticMessageContext {
        let html = format!("<html><body><p><a href=\"{url}\">{anchor}</a></p></body></html>");
        html_email_context_with_html(Some(subject), &html)
    }

    fn html_email_context_with_html(subject: Option<&str>, html: &str) -> SemanticMessageContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.20".to_string(),
            25_000,
            "192.0.2.20".to_string(),
            25,
        );
        session.mail_from = Some("sender@external.example".to_string());
        session.rcpt_to.push("employee@corp.internal".to_string());
        session.subject = subject.map(str::to_string);
        session.content.body_html = Some(html.to_string());
        session.content.is_complete = true;
        session.content.extract_links_from_html();

        let projection =
            select_semantic_projection(subject, None, Some(html)).expect("HTML body projection");
        let mut context =
            extract_semantic_context(&session, &projection.body, projection.source_part);
        if let Some(subject) = subject {
            let header = extract_semantic_context(&session, subject, SemanticSourcePart::Header);
            context.claims.extend(header.claims);
        }
        context
    }

    #[test]
    fn credential_access_and_payment_requests_are_distinguished() {
        let semantic_context =
            context("请点击链接验证账户。请提交验证码验证账户。请确认付款到新账户。");
        let findings = evaluate_semantic_scenarios(&semantic_context);
        assert!(
            findings
                .iter()
                .any(|finding| finding.scenario_id == SemanticScenarioId::CredentialRequest),
            "expected credential scenario, context={semantic_context:?}, findings={findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| { finding.scenario_id == SemanticScenarioId::AccountAccessRequest })
        );
        assert!(
            findings.iter().any(|finding| {
                finding.scenario_id == SemanticScenarioId::PaymentAccountChangeRequest
            }),
            "expected payment scenario, context={semantic_context:?}, findings={findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.causal_key.starts_with("semantic_scenario:"))
        );
    }

    #[test]
    fn chinese_vocabulary_preserves_request_and_counter_context_pairs() {
        use vigilyx_core::security::{
            SemanticActorRole, SemanticPolarity, SemanticQuoteStatus, SemanticTargetRole,
        };

        for (action, scenario) in [
            ("回传动态口令", SemanticScenarioId::CredentialRequest),
            ("上传身份证号码", SemanticScenarioId::SensitiveDataRequest),
            (
                "将款项划转到对公账户",
                SemanticScenarioId::PaymentAccountChangeRequest,
            ),
            (
                "更换收款信息",
                SemanticScenarioId::PaymentAccountChangeRequest,
            ),
            ("解锁您的账户", SemanticScenarioId::AccountAccessRequest),
            (
                "联系钉钉客服",
                SemanticScenarioId::OffPlatformContactRequest,
            ),
        ] {
            let body = format!("劳烦您{action}。");
            let direct = context(&body);
            let findings = evaluate_semantic_scenarios(&direct);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.scenario_id == scenario),
                "{body}: {direct:?}, {findings:?}"
            );
            assert!(direct.claims.iter().any(|claim| {
                is_current_recipient_action(claim)
                    && claim.actor_role == SemanticActorRole::Sender
                    && claim.target_role == SemanticTargetRole::Recipient
                    && claim.polarity == SemanticPolarity::Action
                    && claim.quote_or_forward_status == SemanticQuoteStatus::Original
            }));

            for guarded in [
                format!("无需{action}。"),
                format!("切勿{action}。"),
                format!("> {body}"),
                format!("原文写道：{body}"),
                format!("安全演练案例：{body}"),
            ] {
                let guarded_context = context(&guarded);
                assert!(
                    !guarded_context
                        .claims
                        .iter()
                        .any(is_current_recipient_action),
                    "{guarded}: {guarded_context:?}"
                );
                assert!(
                    evaluate_semantic_scenarios(&guarded_context).is_empty(),
                    "{guarded}: {guarded_context:?}"
                );
            }
        }
    }

    #[test]
    fn chinese_vocabulary_keeps_roles_and_mixed_polarity_local() {
        use vigilyx_core::security::{SemanticPolarity, SemanticSpeechAct};

        for body in [
            "我们希望您填写校验码。",
            "填写您的校验码。",
            "即刻回传动态口令。",
            "麻烦您回传动态口令。",
        ] {
            let requested = context(body);
            assert!(
                evaluate_semantic_scenarios(&requested)
                    .iter()
                    .any(|finding| finding.scenario_id == SemanticScenarioId::CredentialRequest),
                "{body}: {requested:?}"
            );
        }
        for body in [
            "我们填写校验码。",
            "关于动态口令填写流程的说明。",
            "请扫描二维码查看菜单。",
        ] {
            let mentioned = context(body);
            assert!(
                evaluate_semantic_scenarios(&mentioned).is_empty(),
                "{body}: {mentioned:?}"
            );
        }

        let mixed = context("无需回传动态口令。劳烦您上传身份证号码。");
        let findings = evaluate_semantic_scenarios(&mixed);
        assert!(mixed.claims.iter().any(|claim| {
            claim.speech_act == SemanticSpeechAct::Warning
                && claim.polarity == SemanticPolarity::AntiAction
                && claim.objects.iter().any(|object| object == "动态口令")
        }));
        assert!(
            findings
                .iter()
                .any(|finding| { finding.scenario_id == SemanticScenarioId::SensitiveDataRequest })
        );
        assert!(
            !findings
                .iter()
                .any(|finding| { finding.scenario_id == SemanticScenarioId::CredentialRequest })
        );
    }

    #[test]
    fn chinese_nominal_cta_uses_its_own_link_and_preserves_unknown_ownership() {
        let target = "https://portal.example.invalid/identity";
        for label in ["核验身份", "重置密码", "解锁账户", "上传资料"] {
            let direct = html_email_context("", label, target);
            assert!(
                direct.claims.iter().any(|claim| {
                    is_current_recipient_action(claim)
                        && direct.links.iter().any(|link| {
                            link.original_url == target
                                && claim.link_ids.contains(&link.link_id)
                                && link.ownership_status == SemanticLinkOwnershipStatus::Unknown
                        })
                }),
                "{label}: {direct:?}"
            );

            for html in [
                format!(
                    "<blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div><a href='{target}'>{label}</a></blockquote>"
                ),
                format!("<p>切勿<a href='{target}'>{label}</a></p>"),
                format!("<p>{label}</p><a href='{target}'>参考文档</a>"),
            ] {
                let guarded = html_email_context_with_html(None, &html);
                assert!(
                    !guarded.claims.iter().any(|claim| {
                        is_current_recipient_action(claim) && !claim.link_ids.is_empty()
                    }),
                    "{html}: {guarded:?}"
                );
            }
        }
    }

    #[test]
    fn routine_account_view_is_not_a_credential_request() {
        for body in [
            "请登录手机银行在我的账户对账单中查看。",
            "请登录手机银行在我的账户对账单中查看。本邮件不含任何链接，银行不会索要密码与验证码。",
        ] {
            let findings = evaluate_semantic_scenarios(&context(body));
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.scenario_id == SemanticScenarioId::CredentialRequest),
                "routine account view must not be classified as credential collection: {findings:?}"
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.scenario_id == SemanticScenarioId::AccountAccessRequest),
                "legitimate account access remains a non-scoring semantic observation: {findings:?}"
            );
        }
    }

    #[test]
    fn routine_account_request_does_not_borrow_password_description_from_next_sentence() {
        let findings = evaluate_semantic_scenarios(&context(
            "Please confirm the account status. Users enter passwords to sign in.",
        ));

        assert!(
            findings
                .iter()
                .all(|finding| finding.scenario_id != SemanticScenarioId::CredentialRequest),
            "a routine status request must not absorb a later password description: {findings:?}"
        );
    }

    #[test]
    fn quoted_and_anti_action_claims_do_not_create_current_action_scenarios() {
        let findings = evaluate_semantic_scenarios(&context(
            "> 请点击链接验证账户。安全提醒：请勿发送验证码给任何人。",
        ));
        assert!(
            findings.is_empty(),
            "quoted/anti-action claims: {findings:?}"
        );
    }

    #[test]
    fn scoped_counter_context_blocks_only_the_qualified_scenario() {
        let findings = evaluate_semantic_scenarios(&context(
            "请点击链接验证账户。安全提醒：请勿点击链接。请确认付款到新账户。",
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| { finding.scenario_id == SemanticScenarioId::AccountAccessRequest })
        );
        assert!(findings.iter().any(|finding| {
            finding.scenario_id == SemanticScenarioId::PaymentAccountChangeRequest
        }));
    }

    #[test]
    fn scenario_finding_retains_link_reference_and_coverage() {
        let body = "请点击 https://portal.example.invalid/login 验证账户。";
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.20".to_string(),
            25_000,
            "192.0.2.20".to_string(),
            25,
        );
        session.mail_from = Some("sender@external.example".to_string());
        session.rcpt_to.push("employee@corp.internal".to_string());
        session.content.body_text = Some(body.to_string());
        session.content.links.push(EmailLink {
            url: "https://portal.example.invalid/login".to_string(),
            text: None,
            suspicious: false,
        });
        let semantic_context =
            extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
        let findings = evaluate_semantic_scenarios(&semantic_context);
        let finding = findings
            .iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountAccessRequest)
            .expect("account-access scenario");

        assert_eq!(finding.link_ids.len(), 1);
        assert_eq!(finding.coverage, semantic_context.coverage);
        assert_eq!(finding.coverage_reason, semantic_context.coverage_reason);
    }

    #[test]
    fn sensitive_and_off_platform_requests_are_reusable_scenarios() {
        let findings =
            evaluate_semantic_scenarios(&context("请回复本邮件附上身份证照片。请加我微信。"));
        assert!(
            findings
                .iter()
                .any(|finding| finding.scenario_id == SemanticScenarioId::SensitiveDataRequest)
        );
        assert!(findings
            .iter()
            .any(|finding| finding.scenario_id == SemanticScenarioId::OffPlatformContactRequest));
    }

    #[test]
    fn security_subject_is_linked_only_to_its_unique_recipient_cta() {
        let semantic_context = html_email_context(
            "安全中心通知：请完成身份验证",
            "立即处理",
            "https://portal.example.invalid/?token=fixture-token",
        );
        let findings = evaluate_semantic_scenarios(&semantic_context);
        let finding = findings
            .iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("source-attributed account-security CTA candidate");

        assert_eq!(finding.resolution, SemanticScenarioResolution::Ambiguous);
        assert_eq!(
            finding.resolution_reason.as_deref(),
            Some("generic_cta_label")
        );
        assert_eq!(finding.claim_ids.len(), 2);
        assert_eq!(finding.link_ids.len(), 1);
        assert!(finding.claim_ids.iter().any(|id| id.starts_with("header:")));
        assert!(finding.claim_ids.iter().any(|id| id.starts_with("html:")));
        let link = semantic_context
            .links
            .iter()
            .find(|link| link.link_id == finding.link_ids[0])
            .expect("physical link observation");
        assert_eq!(link.ownership_status, SemanticLinkOwnershipStatus::Unknown);
        assert!(link.coverage_reason.is_some());
    }

    #[test]
    fn explicit_verification_cta_is_specific_and_other_links_make_header_pairing_ambiguous() {
        let specific = html_email_context(
            "安全中心通知：请完成身份验证",
            "立即验证账户",
            "https://portal.example.invalid/verify",
        );
        let specific_finding = evaluate_semantic_scenarios(&specific)
            .into_iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("specific identity-verification CTA candidate");
        assert_eq!(
            specific_finding.resolution,
            SemanticScenarioResolution::Candidate
        );
        assert_eq!(specific_finding.link_ids.len(), 1);

        let multiple_targets = html_email_context_with_html(
            Some("安全中心通知：请完成身份验证"),
            "<html><body><p><a href=\"https://portal.example.invalid/verify\">立即验证账户</a></p><p><a href=\"https://portal.example.invalid/policy\">隐私政策</a></p></body></html>",
        );
        let ambiguous = evaluate_semantic_scenarios(&multiple_targets)
            .into_iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("header relation retained as ambiguous");
        assert_eq!(ambiguous.resolution, SemanticScenarioResolution::Ambiguous);
        assert_eq!(
            ambiguous.resolution_reason.as_deref(),
            Some("multiple_interactive_targets")
        );
        assert_eq!(ambiguous.link_ids.len(), 2);
    }

    #[test]
    fn unrelated_generic_action_object_is_not_paired_to_security_subject() {
        let unrelated = html_email_context(
            "安全中心通知：请完成身份验证",
            "立即处理工单",
            "https://portal.example.invalid/ticket",
        );
        assert!(
            evaluate_semantic_scenarios(&unrelated)
                .iter()
                .all(|finding| {
                    finding.scenario_id != SemanticScenarioId::AccountSecurityVerification
                })
        );
    }

    #[test]
    fn quota_reward_candidate_requires_free_storage_cta_not_a_generic_details_link() {
        let suspicious = html_email_context(
            "您已触达存储空间上限，请尽快扩容",
            "立即领取 6GB 免费空间",
            "https://portal.example.invalid/?token=fixture-token",
        );
        assert!(
            evaluate_semantic_scenarios(&suspicious)
                .iter()
                .any(|finding| finding.scenario_id == SemanticScenarioId::StorageQuotaReward)
        );

        let benign = html_email_context(
            "存储空间使用率已达 80%，请按流程清理文件",
            "查看详情",
            "https://portal.example.invalid/storage",
        );
        assert!(
            evaluate_semantic_scenarios(&benign)
                .iter()
                .all(|finding| finding.scenario_id != SemanticScenarioId::StorageQuotaReward)
        );
    }

    #[test]
    fn quota_reward_does_not_borrow_context_across_html_blocks() {
        let separate_blocks = html_email_context_with_html(
            None,
            "<html><body><p>存储空间已触达上限，请尽快扩容。</p><p><a href=\"https://portal.example.invalid/free\">立即领取 6GB 免费空间</a></p></body></html>",
        );
        assert!(
            evaluate_semantic_scenarios(&separate_blocks)
                .iter()
                .all(|finding| finding.scenario_id != SemanticScenarioId::StorageQuotaReward)
        );

        let same_block = html_email_context_with_html(
            None,
            "<html><body><p>存储空间已触达上限，请尽快扩容；<a href=\"https://portal.example.invalid/free\">立即领取 6GB 免费空间</a></p></body></html>",
        );
        assert!(
            evaluate_semantic_scenarios(&same_block)
                .iter()
                .any(|finding| finding.scenario_id == SemanticScenarioId::StorageQuotaReward)
        );

        for html in [
            "<html><body><p>存储空间已触达上限，请尽快扩容。</p><a href=\"https://portal.example.invalid/free\">立即领取 6GB 免费空间</a></body></html>",
            "<html><body><section>存储空间已触达上限，请尽快扩容。</section><section><a href=\"https://portal.example.invalid/free\">立即领取 6GB 免费空间</a></section></body></html>",
        ] {
            let separate_container = html_email_context_with_html(None, html);
            assert!(
                evaluate_semantic_scenarios(&separate_container)
                    .iter()
                    .all(|finding| finding.scenario_id != SemanticScenarioId::StorageQuotaReward)
            );
        }
    }

    #[test]
    fn cross_part_same_action_and_object_warning_counters_the_candidate() {
        let semantic_context = html_email_context_with_html(
            Some("安全中心通知：请完成身份验证"),
            "<html><body><p>安全提醒：请勿验证账户。<a href=\"https://portal.example.invalid/verify\">立即验证账户</a></p></body></html>",
        );
        let finding = evaluate_semantic_scenarios(&semantic_context)
            .into_iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("countered cross-part candidate");
        assert_eq!(finding.resolution, SemanticScenarioResolution::Countered);
        assert_eq!(
            finding.resolution_reason.as_deref(),
            Some("cross_part_counter_context")
        );
        assert!(!finding.counter_context_ids.is_empty());
    }

    #[test]
    fn unrelated_anti_action_does_not_counter_security_verification_candidate() {
        let semantic_context = html_email_context_with_html(
            Some("安全中心通知：请完成身份验证"),
            "<html><body><p>安全提醒：请勿点击身份验证链接。<a href=\"https://portal.example.invalid/verify\">立即验证账户</a></p></body></html>",
        );
        let finding = evaluate_semantic_scenarios(&semantic_context)
            .into_iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("specific verification relation remains observed");
        assert_eq!(finding.resolution, SemanticScenarioResolution::Candidate);
        assert!(finding.counter_context_ids.is_empty());
    }

    #[test]
    fn incomplete_inspection_marks_linked_semantic_relation_ambiguous() {
        let mut semantic_context = html_email_context(
            "安全中心通知：请完成身份验证",
            "立即验证账户",
            "https://portal.example.invalid/verify",
        );
        semantic_context.coverage = SemanticCoverageStatus::Incomplete;
        semantic_context.coverage_reason = Some("fixture body was truncated".to_string());
        let finding = evaluate_semantic_scenarios(&semantic_context)
            .into_iter()
            .find(|finding| finding.scenario_id == SemanticScenarioId::AccountSecurityVerification)
            .expect("partial content still retains its bounded observation");
        assert_eq!(finding.resolution, SemanticScenarioResolution::Ambiguous);
        assert_eq!(
            finding.resolution_reason.as_deref(),
            Some("inspection_incomplete")
        );
        assert_eq!(
            finding.coverage_reason.as_deref(),
            Some("fixture body was truncated")
        );
    }

    #[test]
    fn malformed_cross_claim_policy_is_reported_instead_of_silently_ignored() {
        let invalid = serde_json::json!([{
            "scenario_id": "account_security_verification",
            "context_scenario_id": "account_access_request",
            "context_objects_any": ["身份验证"],
            "linked_variants_any": [],
            "ambiguous_linked_actions_any": ["处理"],
            "ambiguous_linked_objects_any": ["链接"],
            "allow_header_context": true
        }]);
        assert!(parse_cross_claim_policy_entries(invalid).is_err());
    }

    #[test]
    fn reported_security_training_does_not_create_a_linked_security_candidate() {
        let semantic_context = html_email_context(
            "安全培训案例：请完成身份验证",
            "立即处理",
            "https://portal.example.invalid/?token=fixture-token",
        );
        assert!(
            evaluate_semantic_scenarios(&semantic_context)
                .iter()
                .all(|finding| {
                    finding.scenario_id != SemanticScenarioId::AccountSecurityVerification
                })
        );
    }
}
