//! Regression tests for native extortion admission, causal-key dedup, and
//! policy validation tiers.

use std::sync::Arc;

use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
use vigilyx_core::security::SemanticSourcePart;

use crate::module::{SecurityModule, ThreatLevel};
use crate::module_data::{ModuleDataOverrides, ModuleDataRegistry};
use crate::pipeline::context::SecurityContext;

use super::budget::SemanticCpuBudget;
use super::compiled::{CompiledSemanticData, compiled_semantic_data};
use super::relations::{
    CROSS_SOURCE_SUBJECT_THREAT, ExtortionRelation, qualified_extortion_relations,
    qualified_extortion_relations_with_header,
};
use super::scan::semantic_policy_diagnostics;
use super::source::SemanticSource;
use super::{SemanticScanModule, extract_semantic_context, select_semantic_projection};

fn make_session(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> EmailSession {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".to_string(),
        25_000,
        "198.51.100.10".to_string(),
        25,
    );
    session.mail_from = Some("sender@example.net".to_string());
    session.rcpt_to.push("recipient@example.com".to_string());
    session.subject = subject.map(str::to_string);
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        body_html: body_html.map(str::to_string),
        is_complete: true,
        ..Default::default()
    };
    session
}

fn plain_relations(body: &str) -> Vec<ExtortionRelation> {
    let session = make_session(None, Some(body), None);
    let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
    qualified_extortion_relations(
        SemanticSource::new(body, SemanticSourcePart::PlainText),
        &context,
        &SemanticCpuBudget::new(),
        &compiled_semantic_data(),
    )
    .unwrap()
}

fn data_without(list: &str) -> CompiledSemanticData {
    let mut seed: serde_json::Value =
        serde_json::from_str(vigilyx_db::security::embedded_module_data_seed()).unwrap();
    assert!(
        seed["lists"]
            .as_object_mut()
            .expect("seed lists object")
            .remove(list)
            .is_some(),
        "{list} must exist in the compiled seed"
    );
    let registry = ModuleDataRegistry::from_seed_and_overrides(
        &seed.to_string(),
        &ModuleDataOverrides::default(),
    )
    .unwrap();
    CompiledSemanticData::new(Arc::new(registry))
}

#[test]
fn paragraph_split_sextortion_is_admitted_within_three_paragraphs() {
    for body in [
        "我录下了你的私密视频。\n\n请在48小时内支付比特币到钱包地址。\n\n否则我会公开视频。",
        "I recorded you.\n\nSend bitcoin to my wallet.\n\nOtherwise I will publish the video.",
        "I recorded you.\r\n\r\n\r\nSend bitcoin to my wallet or I share it.",
    ] {
        let relations = plain_relations(body);
        assert!(!relations.is_empty(), "{body:?}");
        assert!(!relations[0].cross_source_subject_threat);
        assert!(relations[0].causal_key.starts_with("body_relation:"));
    }
}

#[test]
fn more_than_three_paragraphs_are_not_admitted() {
    for body in [
        "我录下了你的私密视频。\n\n这是第二段。\n\n这是第三段。\n\n请在48小时内支付比特币到钱包地址，否则我会公开视频。",
        "I recorded you.\n\nStatus update.\n\nNext item.\n\nSend bitcoin to my wallet or I share it.",
    ] {
        assert!(plain_relations(body).is_empty(), "{body:?}");
    }
}

#[test]
fn relation_envelope_over_the_byte_limit_is_not_admitted() {
    let short_filler = "lorem ipsum ".repeat(16);
    let near =
        format!("I recorded you.\n\n{short_filler}\n\nSend bitcoin to my wallet or I share it.");
    assert!(
        !plain_relations(&near).is_empty(),
        "control must be admitted"
    );

    // One filler paragraph keeps the break count at two, but the envelope
    // exceeds the 8192-byte policy limit.
    let long_filler = "lorem ipsum ".repeat(800);
    let far =
        format!("I recorded you.\n\n{long_filler}\n\nSend bitcoin to my wallet or I share it.");
    assert!(plain_relations(&far).is_empty());
}

#[test]
fn paraphrased_first_person_threat_is_admitted_from_the_lexicon() {
    let body = "我拍下了你的私密视频。请在48小时内支付比特币到钱包地址，否则我会公开视频。";
    let relations = plain_relations(body);
    assert!(!relations.is_empty(), "{body}");
    let threat = &relations[0].threat_claim;
    assert!(body[threat.span.start_byte..threat.span.end_byte].contains("拍下了你"));
}

#[test]
fn nominal_payment_address_line_is_admitted_only_with_a_value() {
    let body = "我录下了你的私密视频。\n比特币付款地址：bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n48小时内不付款，我会公开视频。";
    let relations = plain_relations(body);
    assert!(!relations.is_empty(), "{body}");
    let payment = &relations[0].payment_claim;
    assert!(body[payment.span.start_byte..payment.span.end_byte].starts_with("比特币付款地址"));

    let without_value = "我录下了你的私密视频。\n比特币付款地址：\n48小时内不付款，我会公开视频。";
    assert!(plain_relations(without_value).is_empty());
}

#[test]
fn subject_threat_pairs_only_with_local_body_payment_and_consequence() {
    let subject = "我录下了你的私密视频";
    let body = "请在48小时内支付比特币到钱包地址，否则我会公开视频。";
    let session = make_session(Some(subject), Some(body), None);
    let mut context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
    let header = extract_semantic_context(&session, subject, SemanticSourcePart::Header);
    context.claims.extend(header.claims);
    let data = compiled_semantic_data();
    let source = SemanticSource::new(body, SemanticSourcePart::PlainText);

    let relations = qualified_extortion_relations_with_header(
        source,
        Some(SemanticSource::new(subject, SemanticSourcePart::Header)),
        &context,
        &SemanticCpuBudget::new(),
        &data,
    )
    .unwrap();
    assert_eq!(relations.len(), 1, "{context:?}");
    let relation = &relations[0];
    assert!(relation.cross_source_subject_threat);
    assert_eq!(
        relation.threat_claim.source_part,
        SemanticSourcePart::Header
    );
    assert_eq!(
        relation.payment_claim.source_part,
        SemanticSourcePart::PlainText
    );
    assert!(
        relation
            .threat_claim
            .provenance
            .iter()
            .any(|value| value == CROSS_SOURCE_SUBJECT_THREAT)
    );
    assert_eq!(
        relation.admission_rule,
        "subject_threat_body_payment_coercion_v1"
    );

    // Without the subject source the header claim has no readable text and
    // its offsets are never interpreted as body coordinates.
    assert!(
        qualified_extortion_relations(source, &context, &SemanticCpuBudget::new(), &data)
            .unwrap()
            .is_empty()
    );

    // Payment and consequence must still be local to each other.
    let split_body =
        "请在48小时内支付比特币到钱包地址。\n\n第二段。\n\n第三段。\n\n否则我会公开视频。";
    let split_session = make_session(Some(subject), Some(split_body), None);
    let mut split_context =
        extract_semantic_context(&split_session, split_body, SemanticSourcePart::PlainText);
    split_context.claims.extend(
        extract_semantic_context(&split_session, subject, SemanticSourcePart::Header).claims,
    );
    assert!(
        qualified_extortion_relations_with_header(
            SemanticSource::new(split_body, SemanticSourcePart::PlainText),
            Some(SemanticSource::new(subject, SemanticSourcePart::Header)),
            &split_context,
            &SemanticCpuBudget::new(),
            &data,
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn benign_descriptions_training_and_quotes_are_not_admitted() {
    for body in [
        // News / awareness article describing the scam in the third person.
        "诈骗者通常声称已经录下了你的视频，要求支付比特币，否则会公开视频。",
        // Training example with a report marker.
        "安全培训案例：我录下了你的私密视频。请在48小时内支付比特币到钱包地址，否则我会公开视频。",
        "Security training: I recorded you. Send bitcoin to my wallet or I share it.",
    ] {
        assert!(plain_relations(body).is_empty(), "{body}");
    }
}

#[test]
fn plain_and_html_projections_of_one_relation_share_one_causal_key() {
    let plain = "I recorded you. Send bitcoin to my wallet or I share it.";
    let html = "<p>I recorded you.</p><p>Send bitcoin to my wallet or I share it.</p>";
    let plain_key = plain_relations(plain)
        .first()
        .map(|relation| relation.causal_key.clone())
        .expect("plain relation");

    let projection = select_semantic_projection(None, None, Some(html)).expect("html projection");
    let html_session = make_session(None, None, Some(html));
    let html_context =
        extract_semantic_context(&html_session, &projection.body, projection.source_part);
    let html_relations = qualified_extortion_relations(
        SemanticSource::new(&projection.body, projection.source_part),
        &html_context,
        &SemanticCpuBudget::new(),
        &compiled_semantic_data(),
    )
    .unwrap();
    assert_eq!(
        html_relations
            .first()
            .map(|relation| relation.causal_key.clone()),
        Some(plain_key),
        "{html_context:?}"
    );
}

#[tokio::test]
async fn plain_and_html_alternatives_yield_one_relation_and_one_causal_finding() {
    let plain = "I recorded you. Send bitcoin to my wallet or I share it.";
    let html = "<p>I recorded you.</p><p>Send bitcoin to my wallet or I share it.</p>";
    let ctx = SecurityContext::new(Arc::new(make_session(None, Some(plain), Some(html))));
    let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();
    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    assert_eq!(
        result.details["qualified_extortion_relations"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{result:?}"
    );
    assert_eq!(
        result.details["causal_findings"].as_array().map(Vec::len),
        Some(1),
        "{result:?}"
    );
}

#[test]
fn missing_scenario_policy_is_a_diagnostic_not_coverage() {
    let data = data_without("semantic_scenario_policy_v1");
    let diagnostics = semantic_policy_diagnostics(&data);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("semantic_scenario_policy_v1")),
        "{diagnostics:?}"
    );
    // Relation admission (the scoring path) is unaffected by the missing
    // observation-only policy and reports no coverage error.
    let body = "I recorded you. Send bitcoin to my wallet or I share it.";
    let session = make_session(None, Some(body), None);
    let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
    assert!(
        !qualified_extortion_relations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &data,
        )
        .unwrap()
        .is_empty()
    );
    assert!(semantic_policy_diagnostics(&compiled_semantic_data()).is_empty());
}

#[test]
fn missing_observation_only_policies_are_reported_as_diagnostics() {
    for (list, marker) in [
        (
            "semantic_cross_claim_candidate_policy_v1",
            "cross-claim candidate policy",
        ),
        (
            "semantic_llm_style_policy_v1",
            "semantic_llm_style_policy_v1",
        ),
        (
            "semantic_body_selection_policy_v1",
            "semantic_body_selection_policy_v1",
        ),
    ] {
        let diagnostics = semantic_policy_diagnostics(&data_without(list));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains(marker)),
            "{list}: {diagnostics:?}"
        );
    }
}

#[test]
fn missing_threat_signal_list_is_an_explicit_coverage_reason() {
    for list in ["sextortion_threat_signals", "sextortion_payment_signals"] {
        let data = data_without(list);
        let body = "I recorded you. Send bitcoin to my wallet or I share it.";
        let session = make_session(None, Some(body), None);
        let context = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
        let error = qualified_extortion_relations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &data,
        )
        .err()
        .expect("missing scoring vocabulary must be visible");
        assert!(error.contains(list), "{error}");
    }
}
