//! Synthetic controls derived from the report's examples, not its original
//! unavailable 48-case Python corpus. These are source-level pending tests.

use std::sync::Arc;

use serde::Deserialize;
use vigilyx_core::models::{EmailLink, EmailSession, Protocol};
use vigilyx_core::security::{
    SemanticActionDestination, SemanticCoverageStatus, SemanticQuoteStatus, SemanticScenarioId,
    SemanticScenarioResolution, SemanticSourcePart,
};

use crate::module_data::{ModuleDataOverrides, ModuleDataRegistry};

use super::compiled::CompiledSemanticData;
use super::context::extract_semantic_context_with_data;
use super::policy::evaluate_semantic_scenarios_with_data;
use super::{is_current_recipient_action, semantic_counter_context_qualifies};

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    body: String,
    stage: String,
    scenarios: Vec<SemanticScenarioId>,
    forbidden_scenarios: Vec<SemanticScenarioId>,
    current_request: Option<bool>,
    #[serde(default)]
    forwarded: bool,
    #[serde(default)]
    countered: bool,
}

fn seed() -> serde_json::Value {
    serde_json::from_str(vigilyx_db::security::embedded_module_data_seed()).unwrap()
}

fn data(seed: &serde_json::Value) -> CompiledSemanticData {
    CompiledSemanticData::new(Arc::new(
        ModuleDataRegistry::from_seed_and_overrides(
            &seed.to_string(),
            &ModuleDataOverrides::default(),
        )
        .unwrap(),
    ))
}

fn session(body: &str) -> EmailSession {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.10".to_string(),
        25_000,
        "192.0.2.10".to_string(),
        25,
    );
    session.content.is_complete = true;
    session.content.body_text = Some(body.to_string());
    let target = "https://portal.example.invalid/login";
    if body.contains(target) {
        session.content.links.push(EmailLink {
            url: target.to_string(),
            text: None,
            suspicious: false,
        });
    }
    session
}

#[test]
fn report_examples_preserve_paired_semantic_expectations() {
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../tests/semantic_hardening_cases.json")).unwrap();
    let mut stage_a_seed = seed();
    stage_a_seed["lists"]["semantic_request_construction_policy_v1"]["items"]["stage_b_enabled"] =
        false.into();
    let mut stage_b_seed = stage_a_seed.clone();
    stage_b_seed["lists"]["semantic_request_construction_policy_v1"]["items"]["stage_b_enabled"] =
        true.into();
    let stage_a = data(&stage_a_seed);
    let stage_b = data(&stage_b_seed);
    for case in corpus.cases {
        let policy = if case.stage == "B" {
            &stage_b
        } else {
            &stage_a
        };
        let context = extract_semantic_context_with_data(
            &session(&case.body),
            &case.body,
            SemanticSourcePart::PlainText,
            policy,
        );
        let findings = evaluate_semantic_scenarios_with_data(&context, policy);
        assert_eq!(
            context.coverage,
            SemanticCoverageStatus::Complete,
            "{}: {context:?}",
            case.id
        );
        if let Some(expected) = case.current_request {
            assert_eq!(
                context.claims.iter().any(is_current_recipient_action),
                expected,
                "{}: {context:?}",
                case.id
            );
        }
        for expected in &case.scenarios {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.scenario_id == *expected),
                "{}: {context:?}, {findings:?}",
                case.id
            );
        }
        for forbidden in &case.forbidden_scenarios {
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.scenario_id == *forbidden),
                "{}: {context:?}, {findings:?}",
                case.id
            );
        }
        if case.forwarded {
            assert!(
                context
                    .claims
                    .iter()
                    .any(|claim| claim.quote_or_forward_status == SemanticQuoteStatus::Forwarded),
                "{}: {context:?}",
                case.id
            );
        }
        if case.countered {
            assert!(
                findings.iter().any(|finding| finding.resolution
                    == SemanticScenarioResolution::Countered
                    && !finding.link_ids.is_empty()),
                "{}: {findings:?}",
                case.id
            );
        }
        for claim in &context.claims {
            assert!(
                case.body
                    .get(claim.span.start_byte..claim.span.end_byte)
                    .is_some(),
                "{}: {claim:?}",
                case.id
            );
        }
    }
}

#[test]
fn additive_constructions_are_enabled_in_bundled_policy_and_can_be_disabled() {
    let body = "您刚收到的验证码是多少？";
    let enabled = data(&seed());
    let context = extract_semantic_context_with_data(
        &session(body),
        body,
        SemanticSourcePart::PlainText,
        &enabled,
    );
    assert!(
        context.claims.iter().any(is_current_recipient_action),
        "{context:?}"
    );

    // A persisted seed keeps its stored legacy `enabled=false`; the additive
    // key still activates Stage B, and an explicit `false` disables it.
    let mut disabled_seed = seed();
    disabled_seed["lists"]["semantic_request_construction_policy_v1"]["items"]["stage_b_enabled"] =
        false.into();
    let disabled = data(&disabled_seed);
    let context = extract_semantic_context_with_data(
        &session(body),
        body,
        SemanticSourcePart::PlainText,
        &disabled,
    );
    assert!(!context.claims.iter().any(is_current_recipient_action));
    assert!(evaluate_semantic_scenarios_with_data(&context, &disabled).is_empty());
}

#[test]
fn missing_guard_policy_is_coverage_instead_of_a_trusted_request() {
    let mut invalid = seed();
    invalid["lists"]
        .as_object_mut()
        .unwrap()
        .remove("semantic_context_guard_policy_v1");
    let policy = data(&invalid);
    let body = "请发送密码给我。";
    let context = extract_semantic_context_with_data(
        &session(body),
        body,
        SemanticSourcePart::PlainText,
        &policy,
    );
    assert_eq!(context.coverage, SemanticCoverageStatus::Incomplete);
    assert!(!context.claims.iter().any(is_current_recipient_action));
}

#[test]
fn an_unspecified_destination_cannot_borrow_an_other_party_warning() {
    let policy = data(&seed());
    let body = "请提交验证码。请勿向他人提交验证码。";
    let context = extract_semantic_context_with_data(
        &session(body),
        body,
        SemanticSourcePart::PlainText,
        &policy,
    );
    let request = context
        .claims
        .iter()
        .find(|claim| is_current_recipient_action(claim))
        .unwrap();
    assert_eq!(
        request.action_destination,
        SemanticActionDestination::Unknown
    );
    let warning = context
        .claims
        .iter()
        .find(|claim| claim.action_destination == SemanticActionDestination::Other)
        .unwrap();
    assert!(!semantic_counter_context_qualifies(request, warning));
}

#[test]
fn a_request_frame_survives_a_clause_without_a_known_action() {
    let policy = data(&seed());
    let body = "请参加会议并提交验证码。";
    let context = extract_semantic_context_with_data(
        &session(body),
        body,
        SemanticSourcePart::PlainText,
        &policy,
    );
    assert!(
        context
            .claims
            .iter()
            .any(|claim| is_current_recipient_action(claim)
                && claim.actions.iter().any(|action| action == "提交"))
    );
    assert!(
        !context
            .claims
            .iter()
            .any(|claim| claim.actions.iter().any(|action| action == "加"))
    );
}

#[test]
fn short_entropy_sample_and_cjk_extension_d_do_not_use_the_wrong_observation() {
    let (_, evidence, _) = super::statistics::score_semantics(&"请查收".repeat(8));
    assert!(
        !evidence
            .iter()
            .any(|item| item.description.contains("entropy"))
    );
    let (_, retained, _) = super::statistics::score_semantics(&"甲乙".repeat(128));
    assert!(
        retained
            .iter()
            .any(|item| item.description.contains("entropy"))
    );
    assert!(super::statistics::is_cjk_any('\u{2B740}'));
    assert!(super::statistics::is_cjk_any('\u{2B81F}'));
    assert!(super::statistics::is_cjk_any('\u{2B820}'));
}

#[tokio::test]
async fn linked_conflict_retains_review_metadata_without_fabricating_threat() {
    use crate::module::{SecurityModule, ThreatLevel};
    use crate::pipeline::context::SecurityContext;

    let body = "请点击链接 https://portal.example.invalid/login 验证账户。请勿点击链接。";
    let context = SecurityContext::new(Arc::new(session(body)));
    let result = super::SemanticScanModule::new(None)
        .analyze(&context)
        .await
        .unwrap();
    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert_eq!(result.details["semantic_review_required"], true);
    assert!(
        result.details["semantic_scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["resolution"] == "countered"
                    && !finding["link_ids"].as_array().unwrap().is_empty()
            })
    );
}
