//! Chinese minimal pairs and bounded-context invariants.

use super::{SemanticScanModule, extract_semantic_context, is_current_recipient_action};
use crate::module::{SecurityModule, ThreatLevel};
use crate::pipeline::context::SecurityContext;
use serde::Deserialize;
use std::sync::Arc;
use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
use vigilyx_core::security::SemanticSourcePart;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    id: String,
    body: String,
    current_request: bool,
    threat: bool,
    scenario: Option<String>,
}

fn session(body: &str) -> EmailSession {
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
    session
}

#[test]
fn compiled_semantic_seed_matches_the_source_files() {
    let seed: serde_json::Value =
        serde_json::from_str(vigilyx_db::security::embedded_module_data_seed()).unwrap();
    for source in [
        include_str!("data/context.json"),
        include_str!("data/scenarios.json"),
        include_str!("data/relations.json"),
        include_str!("data/scan.json"),
    ] {
        let data: serde_json::Value = serde_json::from_str(source).unwrap();
        for (name, entry) in data["lists"].as_object().unwrap() {
            assert_eq!(
                &seed["lists"][name], entry,
                "stale embedded semantic dataset: {name}"
            );
        }
    }
}

#[test]
fn account_update_is_not_a_new_payment_account() {
    let body = "请更新账户信息，并更新账号资料。";
    let facts = extract_semantic_context(&session(body), body, SemanticSourcePart::PlainText);
    assert!(facts.claims.iter().any(is_current_recipient_action));
    assert!(
        facts.claims.iter().all(|claim| {
            !claim
                .objects
                .iter()
                .any(|object| matches!(object.as_str(), "新账户" | "新账号"))
        }),
        "{facts:?}"
    );
    assert!(
        !super::evaluate_semantic_scenarios(&facts)
            .iter()
            .any(|finding| {
                serde_json::to_value(finding.scenario_id).unwrap()
                    == "payment_account_change_request"
            })
    );

    let body = "请更新账户信息。请将付款转入新账户。";
    let facts = extract_semantic_context(&session(body), body, SemanticSourcePart::PlainText);
    assert!(
        facts.claims.iter().any(|claim| {
            is_current_recipient_action(claim)
                && claim.objects.iter().any(|object| object == "新账户")
        }),
        "{facts:?}"
    );
}

#[tokio::test]
async fn mixed_secret_words_are_bounded_and_warning_scoped() {
    let body = "请将您的 one-time password 回复给我。";
    let result = SemanticScanModule::new(None)
        .analyze(&SecurityContext::new(Arc::new(session(body))))
        .await
        .unwrap();
    assert!(result.threat_level > ThreatLevel::Safe, "{result:?}");
    for body in [
        "请勿将您的 one-time password 回复给我。",
        "我们不会要求您 share your OTP with us。",
        "Please provide your passportholder reference and update your desktoprice report.",
    ] {
        let result = SemanticScanModule::new(None)
            .analyze(&SecurityContext::new(Arc::new(session(body))))
            .await
            .unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{body}: {result:?}");
    }
}

#[tokio::test]
async fn otp_capability_is_a_phone_property_not_a_requested_secret() {
    let body = "Please reply to this email with your OTP-enabled mobile number.";
    let result = SemanticScanModule::new(None)
        .analyze(&SecurityContext::new(Arc::new(session(body))))
        .await
        .unwrap();
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    let context: vigilyx_core::security::SemanticMessageContext =
        serde_json::from_value(result.details["semantic_context"].clone()).unwrap();
    assert!(
        context
            .claims
            .iter()
            .all(|claim| { !claim.objects.iter().any(|object| object == "otp") }),
        "{context:?}"
    );

    let body = "Please reply to this email with your OTP.";
    let result = SemanticScanModule::new(None)
        .analyze(&SecurityContext::new(Arc::new(session(body))))
        .await
        .unwrap();
    assert!(result.threat_level > ThreatLevel::Safe, "{result:?}");
}

#[test]
fn english_and_mixed_contact_requests_share_the_observation_concepts() {
    for body in [
        "Please add our WeChat account.",
        "请 add 我们的 WeChat account。",
    ] {
        let facts = extract_semantic_context(&session(body), body, SemanticSourcePart::PlainText);
        assert!(
            facts.claims.iter().any(is_current_recipient_action),
            "{facts:?}"
        );
        assert!(
            super::evaluate_semantic_scenarios(&facts)
                .iter()
                .any(|finding| {
                    serde_json::to_value(finding.scenario_id).unwrap()
                        == "off_platform_contact_request"
                }),
            "{facts:?}"
        );
    }
}

#[tokio::test]
async fn chinese_paired_intents_and_native_admission() {
    let corpus: Corpus =
        serde_json::from_str(include_str!("../../tests/semantic_zh_controls.json")).unwrap();
    let mut failures = Vec::new();
    for case in corpus.cases {
        let result = SemanticScanModule::new(None)
            .analyze(&SecurityContext::new(Arc::new(session(&case.body))))
            .await
            .unwrap();
        let context = &result.details["semantic_context"];
        let facts: vigilyx_core::security::SemanticMessageContext =
            serde_json::from_value(context.clone()).unwrap();
        let current = facts.claims.iter().any(is_current_recipient_action);
        let threat = result.threat_level > ThreatLevel::Safe;
        let scene = case.scenario.as_ref().is_none_or(|wanted| {
            result.details["semantic_scenarios"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["scenario_id"] == wanted.as_str())
        });
        // The fixture retains the original whole-module expectation. The
        // combination layer intentionally warns about large verification
        // transfers without asserting the missing refund promise as proof.
        let graded_verification = case.id == "verification_without_refund_promise";
        if graded_verification {
            assert!(!case.threat, "preserve the original fixture contract");
            assert!(
                result.details["semantic_native_findings"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !result.details["semantic_risk_findings"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(result.threat_level, ThreatLevel::Low, "{result:?}");
            assert!(result.confidence <= 0.55, "{result:?}");
            assert_eq!(result.details["semantic_review_required"], true);
        }
        if current != case.current_request
            || threat != (case.threat || graded_verification)
            || !scene
        {
            failures.push(format!(
                "{}: current={current}, threat={threat}, scene={scene}; {context}",
                case.id
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_request_list_does_not_extend_to_an_independent_paragraph_or_subject() {
    let body = "请提供以下信息：\n- 姓名\n\n我会提交我的身份证号码。";
    let facts = extract_semantic_context(&session(body), body, SemanticSourcePart::PlainText);
    let self_claim = facts
        .claims
        .iter()
        .find(|claim| body[claim.span.start_byte..claim.span.end_byte].contains("我会"))
        .unwrap();
    assert!(!is_current_recipient_action(self_claim), "{facts:?}");
    assert!(
        !self_claim
            .provenance
            .iter()
            .any(|value| value == "semantic_request_list_frame_v1")
    );
}

#[tokio::test]
async fn neutral_sentences_do_not_exhaust_the_semantic_claim_budget() {
    let body = "Status.\n".repeat(513);
    let result = SemanticScanModule::new(None)
        .analyze(&SecurityContext::new(Arc::new(session(&body))))
        .await
        .unwrap();
    assert_eq!(result.details["semantic_coverage_limited"], false);
    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(
        result.details["semantic_context"]["claims"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn benign_padding_does_not_cancel_an_explicit_login_secret_request() {
    for body in [
        "请把短信验证码发送给我。".to_string(),
        format!(
            "{}\n\n请把短信验证码发送给我。\n\n{}",
            "会议安排已确认。".repeat(40),
            "请按时参加会议。".repeat(40)
        ),
        "请把短信验证码发送给我。请勿向他人发送验证码。".to_string(),
    ] {
        let result = SemanticScanModule::new(None)
            .analyze(&SecurityContext::new(Arc::new(session(&body))))
            .await
            .unwrap();
        assert_eq!(result.details["score"], 0.30, "{result:?}");
        assert!(
            result
                .categories
                .iter()
                .any(|category| category == "credential_theft")
        );
    }
}
