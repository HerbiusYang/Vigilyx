//! Regression tests moved intact from the former semantic_scan module.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};
use vigilyx_core::security::SemanticSourcePart;

use crate::ai::nlp::NLP_BODY_MAX_BYTES;
use crate::ai::remote::{RemoteModuleProxy, VisualOcrResponse};
use crate::module::{SecurityModule, ThreatLevel};
use crate::modules::content_scan::html_utils::strip_html_tags;
use crate::pipeline::context::SecurityContext;

use super::budget::{SEMANTIC_BODY_MAX_BYTES, SEMANTIC_INSPECTION_LIMITED, SemanticCpuBudget};
use super::compiled::compiled_semantic_data;
use super::ocr::{bounded_visual_ocr_request, bounded_visual_ocr_semantics};
use super::projection::{SemanticBodySource, sanitize_semantic_inputs, select_semantic_body};
use super::relations::qualified_extortion_relations;
use super::source::SemanticSource;
use super::statistics::{score_semantics, score_semantics_with_budget};
use super::style::detect_llm_generated_text;
use super::text::normalized_lowercase_body;
use super::{SemanticScanModule, extract_semantic_context, select_semantic_projection};

#[test]
fn extortion_cannot_borrow_header_payment_offsets() {
    use super::context::extract_semantic_context_with_data;

    let body = "I recorded you. Send bitcoin to my wallet or I share it.";
    let ctx = complete_ctx(Some(body), None);
    let data = compiled_semantic_data();
    let source = SemanticSource::new(body, SemanticSourcePart::PlainText);
    let mut context = extract_semantic_context_with_data(
        &ctx.session,
        body,
        SemanticSourcePart::PlainText,
        &data,
    );
    assert!(
        !qualified_extortion_relations(source, &context, &SemanticCpuBudget::new(), &data)
            .unwrap()
            .is_empty(),
        "the direct native positive must survive"
    );

    for claim in &mut context.claims {
        if super::is_current_recipient_action(claim) {
            // Identical numeric offsets in a subject are a different source.
            claim.source_part = SemanticSourcePart::Header;
        }
    }
    assert!(
        qualified_extortion_relations(source, &context, &SemanticCpuBudget::new(), &data)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn secret_return_authority_is_bound_to_the_body_projection() {
    use super::context::extract_semantic_context_with_data;
    use super::relations::qualified_nlp_authorities;

    let body = "Please send your password to me.";
    let ctx = complete_ctx(Some(body), None);
    let data = compiled_semantic_data();
    let source = SemanticSource::new(body, SemanticSourcePart::PlainText);
    let body_context = extract_semantic_context_with_data(
        &ctx.session,
        body,
        SemanticSourcePart::PlainText,
        &data,
    );
    let header_context =
        extract_semantic_context_with_data(&ctx.session, body, SemanticSourcePart::Header, &data);
    let baseline =
        qualified_nlp_authorities(source, &body_context, &SemanticCpuBudget::new(), &data).unwrap();
    assert!(
        !baseline.is_empty(),
        "retain the direct secret-return positive"
    );
    assert!(
        qualified_nlp_authorities(source, &header_context, &SemanticCpuBudget::new(), &data)
            .unwrap()
            .is_empty()
    );

    let mut combined = body_context;
    combined.claims.extend(header_context.claims);
    let authorities =
        qualified_nlp_authorities(source, &combined, &SemanticCpuBudget::new(), &data).unwrap();
    assert_eq!(
        authorities, baseline,
        "header coordinates cannot add authority"
    );
}

#[test]
fn invalid_relation_offsets_remain_an_inspection_error() {
    use super::context::extract_semantic_context_with_data;
    use super::relations::qualified_nlp_authorities;

    let body = "Please send your password to me.";
    let ctx = complete_ctx(Some(body), None);
    let data = compiled_semantic_data();
    let source = SemanticSource::new(body, SemanticSourcePart::PlainText);
    let mut context = extract_semantic_context_with_data(
        &ctx.session,
        body,
        SemanticSourcePart::PlainText,
        &data,
    );
    context.claims[0].span.end_byte = body.len() + 1;
    assert!(qualified_nlp_authorities(source, &context, &SemanticCpuBudget::new(), &data).is_err());
    assert!(
        qualified_extortion_relations(source, &context, &SemanticCpuBudget::new(), &data).is_err()
    );
}

#[test]
fn sampled_authority_rejects_another_source_and_non_utf8_boundaries() {
    use super::source::sampled_claim_present;

    let body = "Please send your password to me.";
    let ctx = complete_ctx(Some(body), None);
    let context = extract_semantic_context(&ctx.session, body, SemanticSourcePart::PlainText);
    let mut claim = context.claims[0].clone();
    let source = SemanticSource::new(body, SemanticSourcePart::PlainText);
    assert!(sampled_claim_present(source, body, &claim));
    claim.source_part = SemanticSourcePart::Header;
    assert!(!sampled_claim_present(source, body, &claim));

    claim.source_part = SemanticSourcePart::PlainText;
    claim.span.start_byte = 1;
    claim.span.end_byte = 2;
    let source = SemanticSource::new("密码", SemanticSourcePart::PlainText);
    assert!(source.claim_text(&claim).is_none());
    assert!(!sampled_claim_present(source, "密码", &claim));
}

#[test]
fn lowercase_matching_preserves_titlecase_and_expanding_unicode_mappings() {
    for text in [
        "already lower",
        "中文验证码",
        "VERIFY PASSWORD",
        "İ ǅ ΟΣ",
        "e\u{301}",
    ] {
        assert_eq!(
            super::text::lowercase_view(text).as_ref(),
            text.to_lowercase()
        );
    }
}

// ─── LLM-generated prose detection ───

#[test]
fn llm_detector_flags_multi_signal_text() {
    // Boilerplate opener + dense connectives + zero contractions
    let text = "I hope this email finds you well. I am writing to inform you that \
                we have detected unusual activity on your account. Furthermore, \
                you do not appear to have responded to our previous notice. \
                Moreover, we cannot proceed without your verification. \
                Additionally, you are required to confirm your identity. \
                Should you have any questions, please do not hesitate to contact us.";
    let (score, hits) = detect_llm_generated_text(text);
    assert!(
        score > 0.0,
        "should fire on multi-signal LLM text, got hits={:?}",
        hits
    );
    assert!(
        hits.len() >= 2,
        "expected >=2 independent fingerprints, got {:?}",
        hits
    );
}

#[test]
fn llm_detector_ignores_short_text() {
    let text = "Hi, your invoice is attached.";
    let (score, _) = detect_llm_generated_text(text);
    assert_eq!(score, 0.0, "short text must not fire LLM detector");
}

#[test]
fn llm_detector_ignores_natural_human_writing() {
    // Plenty of contractions, no LLM boilerplate, varied sentence length
    let text = "Hey team — quick heads-up: I won't be able to join standup tomorrow. \
                I've got a doctor's appointment that ran long. Can someone cover the \
                deployment? Thanks!";
    let (score, hits) = detect_llm_generated_text(text);
    assert_eq!(
        score, 0.0,
        "natural human prose must not fire, got hits={:?}",
        hits
    );
}

#[test]
fn llm_detector_single_signal_does_not_fire() {
    // Only one boilerplate phrase, nothing else suspicious
    let text = "Hello, I hope this email finds you well. Attached is the report \
                you asked for last week. Let me know if anything looks off. \
                Thanks, Bob.";
    let (score, _) = detect_llm_generated_text(text);
    assert_eq!(score, 0.0, "single weak signal must not fire LLM detector");
}

#[test]
fn llm_detector_chinese_signals() {
    let text = "尊敬的用户，我希望这封邮件能在一切顺利时找到您。\
                此外，您的账户存在异常登录记录。\
                然而，我们尚未收到您的回复。\
                与此同时，请您务必在24小时内完成身份验证，\
                如有任何疑问，请随时联系我们。\
                感谢您的理解与配合。";
    let (score, hits) = detect_llm_generated_text(text);
    assert!(
        score > 0.0,
        "Chinese LLM-style text should fire, got hits={:?}",
        hits
    );
}

fn make_ctx(body_text: Option<&str>, body_html: Option<&str>) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        12345,
        "10.0.0.2".to_string(),
        25,
    );
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        body_html: body_html.map(str::to_string),
        is_complete: true,
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[tokio::test]
async fn test_raw_mime_container_text_is_skipped() {
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx(
        Some(
            "--=_NextPart_123\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\nU29tZSBiYXNlNjQgcGF5bG9hZA==\r\n",
        ),
        None,
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(result.summary.contains("raw MIME container text"));
    assert!(
        result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
}

#[tokio::test]
async fn test_semantic_scan_reports_nlp_disabled_when_unconfigured() {
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx(Some("这是一封正常的中文业务邮件。"), None);

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert_eq!(result.details["nlp_configured"], serde_json::json!(false));
    assert_eq!(result.details["nlp_status"], serde_json::json!("disabled"));
    assert_eq!(
        result.details["analysis_type"],
        serde_json::json!("rules_only")
    );
    assert!(result.summary.contains("AI/NLP not configured"));
    assert!(
        !result
            .categories
            .iter()
            .any(|category| category == "semantic_ai_inspection_limited"),
        "short rules-only messages must keep the existing no-gap behavior"
    );
}

#[tokio::test]
async fn native_secret_return_preserves_envelope_and_header_context() {
    let module = SemanticScanModule::new(None);
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        12345,
        "10.0.0.2".to_string(),
        25,
    );
    session.mail_from = Some("external@example.net".to_string());
    session.rcpt_to.push("employee@example.com".to_string());
    session.content.headers.push((
        "To".to_string(),
        "Manager <manager@example.com>".to_string(),
    ));
    session.content.body_text = Some("请把验证码发送给我。".to_string());
    session.content.is_complete = true;
    let ctx = SecurityContext::new(Arc::new(session));

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Low);
    assert_eq!(
        result.details["semantic_native_findings"][0]["admission_rule"],
        "current_recipient_login_secret_disclosure_v1"
    );
    assert_eq!(result.details["semantic_context"]["schema_version"], 4);
    assert_eq!(
        result.details["semantic_context"]["actual_recipients"][0],
        "employee@example.com"
    );
    assert_eq!(
        result.details["semantic_context"]["header_recipients"][0],
        "manager@example.com"
    );
    assert_eq!(
        result.details["semantic_context"]["claims"][0]["speech_act"],
        "request"
    );
    assert_eq!(
        result.details["semantic_context"]["claims"][0]["target_role"],
        "recipient"
    );
}

#[tokio::test]
async fn semantic_scan_marks_generic_header_link_relation_ambiguous_as_observation() {
    let module = SemanticScanModule::new(None);
    let url = "https://portal.example.invalid/?token=fixture-token";
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.20".to_string(),
        25_000,
        "192.0.2.20".to_string(),
        25,
    );
    session.mail_from = Some("sender@external.example".to_string());
    session.rcpt_to.push("employee@corp.internal".to_string());
    session.subject = Some("安全中心通知：请完成身份验证".to_string());
    session.content = EmailContent {
        body_html: Some(format!(
            "<html><body><p><a href=\"{url}\">立即处理</a></p></body></html>"
        )),
        links: vec![EmailLink {
            url: url.to_string(),
            text: Some("立即处理".to_string()),
            suspicious: false,
        }],
        is_complete: true,
        ..Default::default()
    };
    let context = SecurityContext::new(Arc::new(session));

    let result = module.analyze(&context).await.unwrap();
    let semantic_context = &result.details["semantic_context"];
    let candidate = result.details["semantic_scenarios"]
        .as_array()
        .and_then(|scenarios| {
            scenarios
                .iter()
                .find(|scenario| scenario["scenario_id"] == "account_security_verification")
        })
        .expect("linked account-security observation candidate");

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert_eq!(candidate["resolution"], "ambiguous");
    assert_eq!(candidate["resolution_reason"], "generic_cta_label");
    assert_eq!(candidate["claim_ids"].as_array().map(Vec::len), Some(2));
    assert_eq!(candidate["link_ids"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        candidate["provenance"][0],
        "semantic_cross_claim_candidate_policy_v1"
    );
    assert!(semantic_context["claims"].as_array().is_some_and(|claims| {
        claims.iter().any(|claim| claim["source_part"] == "header")
            && claims.iter().any(|claim| claim["source_part"] == "html")
    }));
    assert!(
        result.details["semantic_header_context"]["claims"]
            .as_array()
            .is_some_and(|claims| claims.iter().any(|claim| claim["source_part"] == "header"))
    );
}

#[tokio::test]
async fn semantic_scan_retains_header_only_quota_context_as_incomplete_unbound_observation() {
    let module = SemanticScanModule::new(None);
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.20".to_string(),
        25_000,
        "192.0.2.20".to_string(),
        25,
    );
    session.subject = Some("您已触达存储空间上限，请尽快扩容".to_string());
    session.content = EmailContent {
        links: vec![EmailLink {
            url: "https://storage.example.invalid/?token=fixture-token".to_string(),
            text: Some("立即领取 6GB 免费空间".to_string()),
            suspicious: false,
        }],
        is_complete: false,
        ..Default::default()
    };
    let context = SecurityContext::new(Arc::new(session));

    let result = module.analyze(&context).await.unwrap();
    let header_context = &result.details["semantic_header_context"];

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(
        result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
    assert_eq!(header_context["coverage"], "incomplete");
    assert!(
        header_context["coverage_reason"].as_str().is_some_and(
            |reason| reason.contains("subject-only facts cannot bind link text or target")
        )
    );
    assert!(
        header_context["claims"]
            .as_array()
            .is_some_and(|claims| { claims.iter().any(|claim| claim["source_part"] == "header") })
    );
    assert!(header_context["links"].as_array().is_some_and(|links| {
        links.iter().any(|link| {
            link["ownership_status"] == "unknown"
                && link["source_span_id"].is_null()
                && link["extraction_source"] == "unknown"
        })
    }));
    assert!(
        result.details["semantic_scenarios"]
            .as_array()
            .is_some_and(|scenarios| {
                scenarios
                    .iter()
                    .all(|scenario| scenario["scenario_id"] != "storage_quota_reward")
            })
    );
}

#[tokio::test]
async fn semantic_alternate_candidate_inherits_primary_projection_coverage_gap() {
    let module = SemanticScanModule::new(None);
    let long_text = format!("{}x", "A".repeat(SEMANTIC_BODY_MAX_BYTES));
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.20".to_string(),
        25_000,
        "192.0.2.20".to_string(),
        25,
    );
    session.subject = Some("安全中心通知：请完成身份验证".to_string());
    session.content = EmailContent {
        body_text: Some(long_text),
        body_html: Some(
            "<html><body><p><a href=\"https://portal.example.invalid/verify\">立即验证账户</a></p></body></html>".to_string(),
        ),
        is_complete: true,
        ..Default::default()
    };
    session.content.extract_links_from_html();
    let context = SecurityContext::new(Arc::new(session));

    let result = module.analyze(&context).await.unwrap();
    let alternate = result.details["semantic_alternative_contexts"]
        .as_array()
        .and_then(|alternates| alternates.first())
        .expect("HTML alternate projection");
    assert_eq!(alternate["source_part"], "html");
    assert_eq!(alternate["semantic_context"]["coverage"], "incomplete");
    let candidate = alternate["semantic_scenarios"]
        .as_array()
        .and_then(|scenarios| {
            scenarios
                .iter()
                .find(|scenario| scenario["scenario_id"] == "account_security_verification")
        })
        .expect("bounded HTML semantic relation retained");
    assert_eq!(candidate["resolution"], "ambiguous");
    assert_eq!(candidate["resolution_reason"], "inspection_incomplete");
}

/// RT-011: a long body is an intrinsic bounded-inspection gap even when
/// the optional AI service is disabled. Otherwise `AI_ENABLED=false`
/// suppresses the only signal that prevents a deep payload plus benign
/// cluster dilution from being accepted by the inline MTA.
#[tokio::test]
async fn test_semantic_scan_reports_long_body_coverage_when_nlp_unconfigured() {
    let module = SemanticScanModule::new(None);
    let body = "A".repeat(NLP_BODY_MAX_BYTES + 1);
    let ctx = make_ctx(Some(&body), None);

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(result.details["nlp_configured"], serde_json::json!(false));
    assert_eq!(result.details["nlp_status"], serde_json::json!("disabled"));
    assert_eq!(
        result.details["nlp_body_coverage_limited"],
        serde_json::json!(true)
    );
    assert_eq!(
        result.details["semantic_ai_coverage_limited"],
        serde_json::json!(true)
    );
    assert!(
        result
            .categories
            .iter()
            .any(|category| category == "semantic_ai_inspection_limited"),
        "long rules-only messages must arm the existing MTA coverage gate"
    );
}

#[test]
fn normalized_lowercase_body_fast_path_handles_plain_ascii() {
    assert_eq!(
        normalized_lowercase_body("PAYMENT TERMS and ACCOUNT REVIEW"),
        "payment terms and account review"
    );
}

#[test]
fn normalized_lowercase_body_keeps_entity_and_unicode_normalization() {
    assert_eq!(
        normalized_lowercase_body("&#xFF21;CCOUNT &amp; VE\u{301}RIFY"),
        "account & verify"
    );
}

#[test]
fn sanitize_semantic_inputs_strips_gateway_banner_noise() {
    crate::pipeline::verdict::set_runtime_scenario_patterns(
        crate::pipeline::verdict::ScenarioPatternLists {
            gateway_banner_patterns: vec![
                "[注意风险邮件]".to_string(),
                "该邮件可能存在恶意内容，请谨慎甄别邮件".to_string(),
                "检测结果：垃圾邮件".to_string(),
            ],
            notice_banner_patterns: vec![],
            dsn_patterns: vec![],
            auto_reply_patterns: vec![],
        },
    );

    let (subject, body) = sanitize_semantic_inputs(
        Some("[注意风险邮件]工资清单"),
        "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n检测结果：垃圾邮件。\n\n请查收本月工资清单。",
    );

    assert_eq!(subject.as_deref(), Some("工资清单"));
    assert_eq!(body, "请查收本月工资清单。");
}

#[test]
fn semantic_body_uses_richer_html_when_plain_part_is_gateway_stub() {
    crate::pipeline::verdict::set_runtime_scenario_patterns(
        crate::pipeline::verdict::ScenarioPatternLists {
            gateway_banner_patterns: vec!["[外部邮件]".to_string()],
            notice_banner_patterns: vec![],
            dsn_patterns: vec![],
            auto_reply_patterns: vec![],
        },
    );

    let selected = select_semantic_body(
        Some("[外部邮件]"),
        Some("[外部邮件]"),
        Some(
            "<html><body><h1>Account security notice</h1><p>Verify your account immediately to keep access.</p></body></html>",
        ),
    )
    .expect("the substantive HTML alternative must be selected");

    assert_eq!(selected.2, SemanticBodySource::HtmlFallback);
    assert!(selected.1.contains("Verify your account"));
    assert_eq!(selected.0.as_deref(), None);
}

#[test]
fn semantic_body_keeps_plain_text_without_gateway_evidence() {
    let selected = select_semantic_body(
        Some("Monthly report"),
        Some("Monthly report"),
        Some("<html><body>Very long but ordinary report content.</body></html>"),
    )
    .expect("plain text must remain eligible");

    assert_eq!(selected.2, SemanticBodySource::PlainText);
    assert_eq!(selected.1, "Monthly report");
}

#[tokio::test]
async fn semantic_scan_uses_richer_html_when_plain_text_is_a_gateway_stub() {
    crate::pipeline::verdict::set_runtime_scenario_patterns(
        crate::pipeline::verdict::ScenarioPatternLists {
            gateway_banner_patterns: vec!["[synthetic gateway notice]".to_string()],
            notice_banner_patterns: vec![],
            dsn_patterns: vec![],
            auto_reply_patterns: vec![],
        },
    );
    let html = format!(
        "<html><body><h1>Workspace account security review</h1><p>{}</p><a href=\"https://qxvzr.invalid/\">Complete verification</a></body></html>",
        "A previously unrecognized device attempted to access the protected workspace. ".repeat(4)
    );
    let ctx = make_ctx(
        Some(
            "[synthetic gateway notice] [外部邮件] [注意风险邮件]\nThis message passed through the mail gateway.",
        ),
        Some(&html),
    );

    let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();

    assert_eq!(
        result.details["semantic_body_source"],
        serde_json::json!("html_fallback"),
        "the short gateway stub must not hide the substantive HTML body: {result:?}"
    );
    assert!(
        result.details["nlp_body_original_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 160),
        "semantic input must reflect the richer HTML-derived text: {result:?}"
    );
}

#[tokio::test]
async fn semantic_scan_keeps_meaningful_plain_alternative_without_banner_evidence() {
    let html = format!(
        "<html><body><p>{}</p></body></html>",
        "Decorative newsletter presentation and repeated navigation content. ".repeat(8)
    );
    let plain = "Quarterly project status: the synthetic migration completed successfully.";
    let ctx = make_ctx(Some(plain), Some(&html));

    let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();

    assert_eq!(
        result.details["semantic_body_source"],
        serde_json::json!("plain_text"),
        "richer HTML alone must not override a meaningful plain-text alternative: {result:?}"
    );
    assert_eq!(
        result.details["nlp_body_original_bytes"],
        serde_json::json!(plain.len())
    );
}

// ─── P2-2: foreign_to_cn_corp known sender domain tests ───

fn make_ctx_with_sender(
    mail_from: &str,
    rcpt_to: &[&str],
    body_text: Option<&str>,
) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        12345,
        "10.0.0.2".to_string(),
        25,
    );
    session.mail_from = Some(mail_from.to_string());
    for &r in rcpt_to {
        session.rcpt_to.push(r.to_string());
    }
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[tokio::test]
async fn test_foreign_to_cn_corp_skipped_for_163_sender() {
    // P2-2: 163.com is a Chinese domestic email provider.
    // An English-only email from 163.com to a .cn recipient should NOT
    // trigger foreign_to_cn_corp.
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx_with_sender(
        "user@163.com",
        &["recipient@company.cn"],
        Some(
            "This is a pure English business email with enough characters to exceed the 30 char threshold for language detection.",
        ),
    );

    let result = module.analyze(&ctx).await.unwrap();
    assert_eq!(
        result.details["language_observations"],
        serde_json::json!([])
    );
    assert_eq!(result.threat_level, ThreatLevel::Safe);

    assert!(
        !result
            .categories
            .contains(&"foreign_to_cn_corp".to_string()),
        "163.com sender to .cn recipient should not trigger foreign_to_cn_corp, got categories={:?}",
        result.categories
    );
}

#[tokio::test]
async fn test_foreign_to_cn_corp_skipped_for_qq_sender() {
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx_with_sender(
        "user@qq.com",
        &["recipient@company.com.cn"],
        Some(
            "This is another pure English email with sufficient length to trigger the non-Chinese content detection logic.",
        ),
    );

    let result = module.analyze(&ctx).await.unwrap();
    assert_eq!(
        result.details["language_observations"],
        serde_json::json!([])
    );
    assert_eq!(result.threat_level, ThreatLevel::Safe);

    assert!(
        !result
            .categories
            .contains(&"foreign_to_cn_corp".to_string()),
        "qq.com sender to .com.cn recipient should not trigger foreign_to_cn_corp, got categories={:?}",
        result.categories
    );
}

#[tokio::test]
async fn test_foreign_to_cn_corp_skipped_for_swift_sender() {
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx_with_sender(
        "fixture-deployment@swift.com",
        &["recipient@company.com.cn"],
        Some(
            "Dear customer, your invoice remains open. Please review the billing portal and settle within payment terms.",
        ),
    );

    let result = module.analyze(&ctx).await.unwrap();
    assert_eq!(
        result.details["language_observations"],
        serde_json::json!([])
    );
    assert_eq!(result.threat_level, ThreatLevel::Safe);

    assert!(
        !result
            .categories
            .contains(&"foreign_to_cn_corp".to_string()),
        "known transactional senders like swift.com should not trip foreign_to_cn_corp, got categories={:?}",
        result.categories
    );
}

#[tokio::test]
async fn test_foreign_to_cn_corp_is_context_not_threat_for_unknown_sender() {
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx_with_sender(
        "attacker@evil-domain.xyz",
        &["victim@bank.com.cn"],
        Some(
            "Dear valued customer, your account has been compromised. Please click here to verify your identity immediately.",
        ),
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert_eq!(
        result.details["language_observations"][0]["kind"],
        "foreign_to_cn_corp"
    );
}

// ─── P2-4: nonsensical_spam only on gibberish evidence tests ───

#[test]
fn short_normal_chinese_does_not_trip_high_bigram_uniqueness() {
    let text = "苏州九月组织文化与人才战略分享将围绕团队创造力业务协同管理实践案例复盘展开现场互动问答并提供会务安排参会指引课程资料和后续交流渠道欢迎相关负责人根据工作计划选择参加";
    let (_, evidence, _) = score_semantics(text);

    assert!(
        !evidence
            .iter()
            .any(|item| item.description.contains("Bigram uniqueness ratio")),
        "short normal announcements naturally have unique bigrams: {evidence:?}"
    );
}

#[test]
fn sufficiently_long_unique_cjk_sample_keeps_bigram_detection() {
    let text: String = (0..200)
        .filter_map(|offset| char::from_u32(0x4e00 + offset))
        .collect();
    let (_, evidence, _) = score_semantics(&text);

    assert!(
        evidence
            .iter()
            .any(|item| item.description.contains("Bigram uniqueness ratio")),
        "long highly unique CJK sequences must remain observable: {evidence:?}"
    );
}

#[tokio::test]
async fn test_nonsensical_spam_not_triggered_by_normal_chinese_text() {
    // Normal readable Chinese text should NOT produce nonsensical_spam
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx(
        Some(
            "尊敬的客户，您好！感谢您对我们公司的支持。本月账单已经生成，请查收。如有疑问请联系客服。",
        ),
        None,
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        !result.categories.contains(&"nonsensical_spam".to_string()),
        "Normal Chinese text should not trigger nonsensical_spam, got categories={:?}",
        result.categories
    );
}

#[tokio::test]
async fn repetitive_monthly_report_is_observation_not_threat() {
    let section = "产品运营月报：本月申请量、批核量、渠道排名、系统运行状态和服务建议如下。各系统运行平稳，项目按计划推进，请相关负责人审阅并反馈。";
    let body = (1..=24)
        .map(|month| format!("第{month}期\n{section}\n{section}\n"))
        .collect::<String>();
    let ctx = make_ctx(Some(&body), None);
    let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        result
            .categories
            .contains(&"repetitive_template_text".to_string()),
        "template repetition should remain visible as context: {result:?}"
    );
    assert!(
        !result.categories.contains(&"nonsensical_spam".to_string()),
        "a legitimate repetitive report must not become spam threat evidence: {result:?}"
    );
}

#[tokio::test]
async fn long_random_like_cjk_sequence_retains_spam_classification() {
    let body: String = (0..200)
        .filter_map(|offset| char::from_u32(0x4e00 + offset))
        .collect();
    let ctx = make_ctx(Some(&body), None);
    let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert_eq!(result.details["score"], 0.0);
    assert!(
        result.details["semantic_statistics_observation"]["raw_score"]
            .as_f64()
            .is_some_and(|score| score > 0.0)
    );
    assert_eq!(
        result.details["semantic_statistics_observation"]["disposition"],
        "classification_only"
    );
    assert!(
        !result.details["semantic_statistics_observation"]["evidence"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        result.categories.contains(&"nonsensical_spam".to_string()),
        "the positive gibberish/obfuscation neighbor must retain classification: {result:?}"
    );
}

#[tokio::test]
async fn gibberish_does_not_inflate_an_independent_native_extortion_score() {
    let gibberish: String = (0..200)
        .filter_map(|offset| char::from_u32(0x4e00 + offset))
        .collect();
    let body = format!("{gibberish}\n\nI recorded you. Send bitcoin to my wallet or I share it.");
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(&body), None))
        .await
        .unwrap();
    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "{result:?}"
    );
    assert!(
        result.categories.contains(&"nonsensical_spam".to_string()),
        "{result:?}"
    );
    assert_eq!(
        result.details["score"], 0.60,
        "statistics must not change native malicious score"
    );
    assert!(
        result.details["semantic_statistics_observation"]["raw_score"]
            .as_f64()
            .is_some_and(|score| score > 0.0)
    );
    assert_eq!(
        result.details["semantic_statistics_observation"]["disposition"],
        "classification_only"
    );
}

#[tokio::test]
async fn test_nonsensical_spam_not_triggered_by_english_only_email() {
    // English-only email — may trigger language mismatch but NOT nonsensical_spam
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx(
        Some(
            "Dear customer, please find attached your monthly invoice. If you have any questions, please contact our support team at support@example.com.",
        ),
        None,
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        !result.categories.contains(&"nonsensical_spam".to_string()),
        "English email should not trigger nonsensical_spam, got categories={:?}",
        result.categories
    );
}

// ─── Normalization evasion regression tests ───

#[test]
fn strip_html_tags_decodes_entities_like_content_scan() {
    // The module previously carried a private strip_html_tags copy that
    // did NOT entity-decode, unlike content_scan::html_utils. The copy
    // is gone; the shared implementation must decode numeric entities.
    assert_eq!(strip_html_tags("<p>b&#105;tcoin</p>"), " bitcoin ");
    assert_eq!(strip_html_tags("<b>密&#x7801;</b>"), " 密码 ");
}

#[tokio::test]
async fn sextortion_entity_and_zero_width_evasion_fires() {
    // Evasion PoC: zero-width splice inside "recorded you" plus an
    // entity-encoded "bitcoin" previously defeated the raw lowercase
    // substring matching in the sextortion rule.
    let module = SemanticScanModule::new(None);
    let body = "I recor\u{200B}ded you while you were browsing an adult site. \
                I have embarrassing footage of you. \
                Send b&#105;tcoin to my wallet within 24 hours or I share it.";
    let ctx = make_ctx(Some(body), None);

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "entity/zero-width obfuscated sextortion must fire, cats={:?}",
        result.categories
    );
    assert!(result.threat_level >= ThreatLevel::Medium);
}

#[tokio::test]
async fn single_cjk_token_does_not_disable_foreign_language_observation() {
    // Evasion PoC: sprinkling a single "的" into a pure English lure
    // previously made cjk_count != 0 and disabled the foreign-language
    // anomaly entirely.
    let module = SemanticScanModule::new(None);
    let ctx = make_ctx_with_sender(
        "attacker@evil-domain.xyz",
        &["victim@bank.com.cn"],
        Some(
            "Dear valued customer, your account has been compromised. Please click here to verify your identity immediately. 的",
        ),
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert_eq!(
        result.details["language_observations"][0]["kind"], "foreign_to_cn_corp",
        "single CJK token must not disable the contextual language observation"
    );
}

fn complete_ctx(body_text: Option<&str>, body_html: Option<&str>) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".to_string(),
        25_000,
        "198.51.100.10".to_string(),
        25,
    );
    session.mail_from = Some("sender@example.net".to_string());
    session.rcpt_to.push("recipient@example.com".to_string());
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        body_html: body_html.map(str::to_string),
        is_complete: true,
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[tokio::test]
async fn extortion_requires_current_coercion_not_camera_or_currency_mentions() {
    let module = SemanticScanModule::new(None);
    for body in [
        "Your camera has been replaced. The method for joining the meeting is unchanged.",
        "Do not pay bitcoin to anyone who says 'I recorded you'.",
        "Security training: I recorded you. Send bitcoin to my wallet or I share it.",
        "Incident report: the attacker said I recorded you. Please send bitcoin or I will publish it.",
        "I recorded you.\n\nPlease pay the bitcoin invoice for the new camera.",
    ] {
        let result = module
            .analyze(&complete_ctx(Some(body), None))
            .await
            .unwrap();
        assert!(
            !result
                .categories
                .iter()
                .any(|category| category == "sextortion" || category == "extortion_threat"),
            "{body}: {result:?}"
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{body}: {result:?}");
    }
}

#[tokio::test]
async fn extortion_positive_retains_typed_relationship_and_encoded_neighbor() {
    for body in [
        "I recorded you. Send bitcoin to my wallet or I share it.",
        "I recor\u{200B}ded you. Send b&#105;tcoin to my wallet or I share it.",
    ] {
        let result = SemanticScanModule::new(None)
            .analyze(&complete_ctx(Some(body), None))
            .await
            .unwrap();
        assert!(
            result.categories.contains(&"sextortion".to_string()),
            "{result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
        let relation = &result.details["qualified_extortion_relations"][0];
        assert_eq!(
            relation["admission_rule"],
            "sender_threat_current_payment_coercion_v2"
        );
        assert_eq!(relation["payment_claim"]["polarity"], "action");
        assert_eq!(relation["payment_claim"]["actor_role"], "sender");
        assert_eq!(relation["payment_claim"]["target_role"], "recipient");
        assert_eq!(
            relation["payment_claim"]["quote_or_forward_status"],
            "original"
        );
    }
}

#[tokio::test]
async fn mixed_training_context_does_not_suppress_an_independent_extortion_request() {
    let body = "Security training: do not pay bitcoin for a reported incident.\n\nI recorded you. Send bitcoin to my wallet or I share it.";
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(body), None))
        .await
        .unwrap();
    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "{result:?}"
    );
}

#[tokio::test]
async fn html_quote_and_plain_alternative_preserve_independent_provenance() {
    let module = SemanticScanModule::new(None);
    // Quoted HTML extortion is covered with and without envelope thread
    // evidence in attribution_regression_tests.rs.
    let direct = "<p>I recorded you. Send bitcoin to my wallet or I share it.</p>";
    let result = module
        .analyze(&complete_ctx(
            Some("Monthly status report is attached."),
            Some(direct),
        ))
        .await
        .unwrap();
    assert_eq!(result.details["semantic_body_source"], "plain_text");
    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "{result:?}"
    );
    assert_eq!(
        result.details["qualified_extortion_relations"][0]["source_part"],
        "html"
    );
    assert_eq!(
        result.details["semantic_alternative_contexts"][0]["source_part"],
        "html"
    );
}

#[tokio::test]
async fn formal_language_observation_cannot_authorize_style_threat() {
    let body = "I hope this email finds you well. I am writing to inform you that the monthly operations report is attached. Furthermore, the tables include quarterly totals. Moreover, the appendix explains the methodology. Additionally, we will discuss the results next week.";
    assert!(detect_llm_generated_text(body).0 > 0.0);
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(body), None))
        .await
        .unwrap();
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        !result
            .categories
            .contains(&"llm_generated_prose".to_string()),
        "{result:?}"
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.location.as_deref() == Some("body:style"))
    );
}

#[tokio::test]
async fn style_does_not_inflate_an_independent_native_extortion_score() {
    let native = "I recorded you. Send bitcoin to my wallet or I share it.";
    let baseline = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(native), None))
        .await
        .unwrap();
    let body = format!(
        "{native}\n\nI hope this email finds you well. I am writing to inform you of our decision. Furthermore, this is our final notice. Moreover, the deadline is today. Additionally, this message needs your attention."
    );
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(&body), None))
        .await
        .unwrap();
    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "{result:?}"
    );
    assert_eq!(
        result.details["score"],
        serde_json::json!(0.60),
        "{result:?}"
    );
    assert_eq!(result.details["score"], baseline.details["score"]);
    assert!(
        result.details["llm_style_observation"]["style_score"]
            .as_f64()
            .is_some_and(|score| score > 0.0),
        "the style observation must remain detected"
    );
    assert_eq!(
        result.details["llm_style_observation"]["disposition"],
        "context_only"
    );
    assert!(
        !result
            .categories
            .contains(&"llm_generated_prose".to_string())
    );
}

#[tokio::test]
async fn semantic_span_limit_reaches_module_coverage_without_threat() {
    let body = "请提供资料。\n".repeat(513);
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(&body), None))
        .await
        .unwrap();
    assert!(
        result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string()),
        "{result:?}"
    );
    assert_eq!(result.details["semantic_coverage_limited"], true);
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(result.summary.contains("incomplete"), "{result:?}");
    assert!(
        !result.summary.to_lowercase().contains("normal"),
        "{result:?}"
    );
    assert!(!result.categories.contains(&"sextortion".to_string()));
}

#[test]
fn projection_budget_is_utf8_safe_and_does_not_join_distant_claims() {
    let body = "测".repeat(SEMANTIC_BODY_MAX_BYTES / 3 + 100);
    let projection = select_semantic_projection(None, Some(&body), None).unwrap();
    assert!(projection.body.len() <= SEMANTIC_BODY_MAX_BYTES);
    assert!(body.is_char_boundary(projection.body.len()));
    assert!(!projection.coverage_reasons.is_empty());
    assert_eq!(projection.original_body_bytes, body.len());
}

#[tokio::test]
async fn maximum_single_span_body_is_coverage_not_partial_statistical_threat() {
    let body = "㐀".repeat(20 * 1024 * 1024 / 3);
    let result = SemanticScanModule::new(None)
        .analyze(&complete_ctx(Some(&body), None))
        .await
        .unwrap();
    assert!(
        result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string()),
        "{result:?}"
    );
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert_eq!(result.details["score"], serde_json::json!(0.0));
    assert_eq!(result.details["semantic_source_original_bytes"], body.len());
    assert!(result.summary.contains("incomplete"), "{result:?}");
    assert!(
        !result.summary.to_lowercase().contains("normal"),
        "{result:?}"
    );
    assert!(!result.categories.contains(&"nonsensical_spam".to_string()));
    assert!(result.bpa.is_some_and(|bpa| bpa.is_vacuous()));
}

#[test]
fn exhausted_cpu_budget_discards_partial_statistics_and_rules() {
    let budget = SemanticCpuBudget {
        deadline: Instant::now() - Duration::from_millis(1),
    };
    assert!(score_semantics_with_budget(&"测".repeat(1000), &budget).is_none());
    let ctx = complete_ctx(
        Some("I recorded you. Send bitcoin to my wallet or I share it."),
        None,
    );
    let body = ctx.session.content.body_text.as_deref().unwrap();
    let context = extract_semantic_context(&ctx.session, body, SemanticSourcePart::PlainText);
    assert!(
        qualified_extortion_relations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &budget,
            &compiled_semantic_data(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn configured_nlp_failure_and_cooldown_remain_visible_as_coverage() {
    let cooling = RemoteModuleProxy::new("http://127.0.0.1:9".to_string());
    cooling.note_timeout();
    let failed = RemoteModuleProxy::new("invalid AI URL".to_string());
    for remote in [cooling, failed] {
        let module = SemanticScanModule::new(Some(remote));
        assert!(
            module.metadata().cpu_bound,
            "remote configuration must keep CPU work off async workers"
        );
        let result = module
            .analyze(&complete_ctx(
                Some("Monthly operations report is attached."),
                None,
            ))
            .await
            .unwrap();
        assert!(
            result
                .categories
                .contains(&SEMANTIC_INSPECTION_LIMITED.to_string()),
            "{result:?}"
        );
        assert_eq!(result.details["semantic_coverage_limited"], true);
        assert_eq!(result.details["semantic_fact_coverage"], "complete");
        assert_eq!(result.details["semantic_context"]["coverage"], "complete");
        assert!(
            result.details["semantic_coverage_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason
                    .as_str()
                    .is_some_and(|reason| reason.contains("AI/NLP")))
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert_eq!(result.details["nlp_contributed"], false);
    }
    let disabled = SemanticScanModule::new(None)
        .analyze(&complete_ctx(
            Some("Monthly operations report is attached."),
            None,
        ))
        .await
        .unwrap();
    assert!(
        !disabled
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string()),
        "{disabled:?}"
    );
}

async fn mock_nlp_prediction(category: &str) -> (RemoteModuleProxy, tokio::task::JoinHandle<()>) {
    mock_nlp_prediction_with_integrity_note(category, false).await
}

async fn mock_nlp_prediction_with_integrity_note(
    category: &str,
    injection_suspected: bool,
) -> (RemoteModuleProxy, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let response_body = serde_json::json!({
        "threat_level": "critical", "confidence": 0.96,
        "categories": [category], "summary": "Synthetic controlled prediction",
        "details": {"model_type": "fine-tuned-5class", "top_label": "phishing",
            "top_score": 0.96, "malicious_probability": 0.96,
            "probabilities": {"phishing": 0.96, "legitimate": 0.04},
            "llm_analysis": {"injection_suspected": injection_suspected}}
    })
    .to_string();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (RemoteModuleProxy::new(format!("http://{address}")), handle)
}

#[tokio::test]
async fn enabled_nlp_preserves_strong_current_secret_return_neighbor() {
    let (remote, response) = mock_nlp_prediction("nlp_phishing").await;
    let result = SemanticScanModule::new(Some(remote))
        .analyze(&complete_ctx(
            Some("Please send your password to me."),
            None,
        ))
        .await
        .unwrap();
    response.await.unwrap();
    assert_eq!(result.details["nlp_used"], true);
    assert_eq!(result.details["nlp_contributed"], true, "{result:?}");
    assert!(
        result.categories.contains(&"nlp_phishing".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level > ThreatLevel::Safe, "{result:?}");
    assert_eq!(
        result.details["qualified_nlp_authorities"][0]["polarity"],
        "action"
    );
    assert_eq!(
        result.details["nlp_semantic_provenance"],
        "native_current_recipient_relation"
    );
    assert!(
        result.details["causal_findings"][0]["causal_key"]
            .as_str()
            .is_some_and(|key| key.starts_with("body_relation:"))
    );
}

#[tokio::test]
async fn enabled_nlp_cannot_borrow_authority_from_quotes_negation_or_unrelated_requests() {
    for body in [
        "> Please send your password to me.",
        "Please do not send your password to me.",
        "Security training: Please send your password to me.",
        "Please confirm the account status. Users enter passwords to sign in. Please send the report to me.",
    ] {
        let (remote, response) = mock_nlp_prediction("nlp_phishing").await;
        let result = SemanticScanModule::new(Some(remote))
            .analyze(&complete_ctx(Some(body), None))
            .await
            .unwrap();
        response.await.unwrap();
        assert_eq!(result.details["nlp_used"], true, "{result:?}");
        assert_eq!(
            result.details["nlp_contributed"], false,
            "{body}: {result:?}"
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{body}: {result:?}");
        assert!(
            !result.categories.contains(&"nlp_phishing".to_string()),
            "{result:?}"
        );
        assert_eq!(result.details["nlp_semantic_provenance"], "unknown");
    }
}

#[tokio::test]
async fn nlp_spam_label_remains_independent_classification_observation() {
    let (remote, response) = mock_nlp_prediction("nlp_spam").await;
    let result = SemanticScanModule::new(Some(remote))
        .analyze(&complete_ctx(
            Some("Our monthly newsletter is attached."),
            None,
        ))
        .await
        .unwrap();
    response.await.unwrap();
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert_eq!(result.details["nlp_contributed"], false);
    assert!(
        result.categories.contains(&"nlp_spam".to_string()),
        "{result:?}"
    );
}

#[tokio::test]
async fn llm_integrity_note_is_diagnostic_without_native_threat_score() {
    let (remote, response) = mock_nlp_prediction_with_integrity_note("nlp_phishing", true).await;
    let result = SemanticScanModule::new(Some(remote))
        .analyze(&complete_ctx(
            Some("The monthly operations report is attached."),
            None,
        ))
        .await
        .unwrap();
    response.await.unwrap();
    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert_eq!(result.details["score"], 0.0);
    assert_eq!(result.details["nlp_contributed"], false);
    assert_eq!(
        result.details["nlp_details"]["llm_analysis"]["injection_suspected"],
        true
    );
    assert!(
        result
            .categories
            .contains(&"llm_injection_suspected".to_string())
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.location.as_deref() == Some("body:llm"))
    );
}

#[test]
fn oversized_ocr_source_is_skipped_with_explicit_inspection_gap() {
    let oversized = "<p>".to_string() + &"x".repeat(20 * 1024 * 1024) + "</p>";
    let ctx = complete_ctx(None, Some(&oversized));
    let (request, limited) = bounded_visual_ocr_request(&ctx.session);
    assert!(request.is_none());
    assert!(limited);
    let ordinary = complete_ctx(None, Some("<p>Monthly report</p>"));
    let (request, limited) = bounded_visual_ocr_request(&ordinary.session);
    assert!(request.is_none());
    assert!(
        !limited,
        "absence of an inline image is successful inspection"
    );
}

#[test]
fn ocr_response_bounds_sources_utf8_text_and_shared_budget() {
    use crate::remote::VisualOcrImageResponse;
    let ctx = complete_ctx(Some("Monthly report"), None);
    let response = VisualOcrResponse {
        status: "ok".to_string(),
        coverage_limited: false,
        results: (0..4)
            .map(|index| VisualOcrImageResponse {
                source_id: format!("image_{index}"),
                status: "ok".to_string(),
                text: "界".repeat(SEMANTIC_BODY_MAX_BYTES),
                confidence: 1.0,
                reason: None,
            })
            .collect(),
    };
    let budget = SemanticCpuBudget {
        deadline: Instant::now() - Duration::from_millis(1),
    };
    let (details, contexts, reasons) =
        bounded_visual_ocr_semantics(&ctx.session, response, &budget);
    assert_eq!(details["results"].as_array().unwrap().len(), 3);
    assert_eq!(details["coverage_limited"], true);
    assert!(
        details["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["text"].as_str().unwrap().len() <= SEMANTIC_BODY_MAX_BYTES)
    );
    assert!(contexts.as_array().unwrap().is_empty());
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("wall-clock budget"))
    );
}

#[test]
fn ocr_empty_success_is_complete_and_context_gap_is_visible() {
    use crate::remote::VisualOcrImageResponse;
    let ctx = complete_ctx(Some("Monthly report"), None);
    let empty = VisualOcrResponse {
        status: "ok".to_string(),
        coverage_limited: false,
        results: vec![VisualOcrImageResponse {
            source_id: "image_empty".to_string(),
            status: "empty".to_string(),
            text: String::new(),
            confidence: 0.0,
            reason: None,
        }],
    };
    let (details, contexts, reasons) =
        bounded_visual_ocr_semantics(&ctx.session, empty, &SemanticCpuBudget::new());
    assert!(reasons.is_empty(), "{reasons:?}");
    assert_eq!(details["coverage_limited"], false);
    assert!(contexts.as_array().unwrap().is_empty());
    let many_spans = VisualOcrResponse {
        status: "ok".to_string(),
        coverage_limited: false,
        results: vec![VisualOcrImageResponse {
            source_id: "image_text".to_string(),
            status: "ok".to_string(),
            text: "请提供资料。\n".repeat(513),
            confidence: 1.0,
            reason: None,
        }],
    };
    let (details, contexts, reasons) =
        bounded_visual_ocr_semantics(&ctx.session, many_spans, &SemanticCpuBudget::new());
    assert!(!reasons.is_empty());
    assert_eq!(details["coverage_limited"], true);
    assert_eq!(contexts[0]["semantic_context"]["coverage"], "incomplete");
}

#[test]
fn paragraph_boundaries_prevent_native_coercion_from_crossing_business_contexts() {
    // Policy v2 extension: one relation may span at most three consecutive
    // paragraphs (two breaks; a run of blank lines is one break). Wider
    // spans remain separate business contexts.
    for (boundary, admitted) in [
        ("\n\n", true),
        ("\r\n\r\n", true),
        ("\n\n\n", true),
        ("\n\nStatus update.\n\nNext item.\n\n", false),
    ] {
        let body = format!("I recorded you.{boundary}Send bitcoin to my wallet or I share it.");
        let ctx = complete_ctx(Some(&body), None);
        let context = extract_semantic_context(&ctx.session, &body, SemanticSourcePart::PlainText);
        let relations = qualified_extortion_relations(
            SemanticSource::new(&body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap();
        assert_eq!(!relations.is_empty(), admitted, "{boundary:?}: {body}");
    }
    let body = "I recorded you. Send bitcoin to my wallet or I share it.";
    let ctx = complete_ctx(Some(body), None);
    let context = extract_semantic_context(&ctx.session, body, SemanticSourcePart::PlainText);
    assert!(
        !qualified_extortion_relations(
            SemanticSource::new(body, SemanticSourcePart::PlainText),
            &context,
            &SemanticCpuBudget::new(),
            &compiled_semantic_data(),
        )
        .unwrap()
        .is_empty(),
        "retain the adjacent attack-positive neighbor"
    );
}

#[tokio::test]
async fn existing_registry_scenarios_reach_the_final_semantic_result() {
    for (body, expected) in [
        ("请发送密码给我。", "credential_request"),
        ("请点击链接验证账户。", "account_access_request"),
        ("请确认付款到新账户。", "payment_account_change_request"),
        ("请回复本邮件附上身份证照片。", "sensitive_data_request"),
        ("请加我微信。", "off_platform_contact_request"),
    ] {
        let ctx = complete_ctx(Some(body), None);
        let context = extract_semantic_context(&ctx.session, body, SemanticSourcePart::PlainText);
        let expected_findings = super::evaluate_semantic_scenarios(&context);
        let result = SemanticScanModule::new(None).analyze(&ctx).await.unwrap();
        assert_eq!(
            result.details["semantic_scenarios"],
            serde_json::to_value(expected_findings).unwrap(),
            "existing scenario output must survive result assembly: {body}",
        );
        assert!(
            result.details["semantic_scenarios"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["scenario_id"] == expected),
            "{body}: {result:?}"
        );
    }
}

#[test]
fn ocr_reuses_the_existing_credential_scenario_policy() {
    use crate::remote::VisualOcrImageResponse;
    let ctx = complete_ctx(Some("Monthly report"), None);
    let response = VisualOcrResponse {
        status: "ok".into(),
        coverage_limited: false,
        results: vec![VisualOcrImageResponse {
            source_id: "image_request".into(),
            status: "ok".into(),
            text: "Please send your password to me.".into(),
            confidence: 1.0,
            reason: None,
        }],
    };
    let (_, sources, reasons) =
        bounded_visual_ocr_semantics(&ctx.session, response, &SemanticCpuBudget::new());
    assert!(reasons.is_empty(), "{reasons:?}");
    assert_eq!(sources[0]["source_id"], "image_request");
    assert_eq!(
        sources[0]["semantic_context"]["claims"][0]["source_part"],
        "ocr"
    );
    assert!(
        sources[0]["semantic_scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["scenario_id"] == "credential_request")
    );
}

// ─── Attachment text and short text through the semantic engine ───

const ATTACHMENT_SEXTORTION: &str = "I recorded you while you were browsing an adult site. \
     I have embarrassing footage of you. \
     Send bitcoin to my wallet within 24 hours or I share it.";

fn text_attachment(filename: &str, text: &str) -> vigilyx_core::models::EmailAttachment {
    use base64::Engine as _;
    vigilyx_core::models::EmailAttachment {
        filename: filename.to_string(),
        content_type: "text/plain".to_string(),
        size: text.len(),
        hash: format!("fixture-{filename}"),
        content_base64: Some(base64::engine::general_purpose::STANDARD.encode(text.as_bytes())),
    }
}

fn attachment_ctx(
    subject: Option<&str>,
    body_text: Option<&str>,
    attachments: Vec<vigilyx_core::models::EmailAttachment>,
    is_complete: bool,
) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        12345,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject = subject.map(str::to_string);
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        attachments,
        is_complete,
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[tokio::test]
async fn attachment_only_message_runs_semantic_engine_on_attachment_text() {
    // Field case: phone screenshots and documents sent with an empty body
    // were reported as "body not retained" and their content never reached
    // the semantic relation rules.
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(
        Some("Notice"),
        None,
        vec![text_attachment("notice.txt", ATTACHMENT_SEXTORTION)],
        true,
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "attachment relation must score, cats={:?}",
        result.categories
    );
    assert!(result.threat_level >= ThreatLevel::Medium);
    assert!(
        !result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
    assert_eq!(result.details["semantic_body_source"], "empty");
    let source = &result.details["semantic_attachment_sources"]["sources"][0];
    assert_eq!(source["filename"], "notice.txt");
    assert!(
        source["finding_count"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert!(result.evidence.iter().any(|evidence| {
        evidence.location.as_deref() == Some("attachment:semantic")
            && evidence.description.contains("notice.txt")
    }));
}

#[tokio::test]
async fn attachment_relation_scores_beside_a_benign_body() {
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(
        Some("Documents"),
        Some("Please see the attached file for the details we discussed."),
        vec![text_attachment("details.txt", ATTACHMENT_SEXTORTION)],
        true,
    );

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        result.categories.contains(&"sextortion".to_string()),
        "cats={:?}",
        result.categories
    );
    let relations = result.details["qualified_extortion_relations"]
        .as_array()
        .unwrap();
    assert!(
        relations
            .iter()
            .all(|relation| relation["source_part"] == "attachment")
    );
}

#[tokio::test]
async fn identical_body_and_attachment_relation_is_counted_once() {
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(
        None,
        Some(ATTACHMENT_SEXTORTION),
        vec![text_attachment("copy.txt", ATTACHMENT_SEXTORTION)],
        true,
    );

    let result = module.analyze(&ctx).await.unwrap();

    let relations = result.details["qualified_extortion_relations"]
        .as_array()
        .unwrap();
    assert_eq!(
        relations.len(),
        1,
        "same text in body and attachment is one fact"
    );
    assert_eq!(
        relations[0]["source_part"], "plain_text",
        "the body copy wins"
    );
}

#[tokio::test]
async fn attachment_claims_are_attributed_to_the_attachment() {
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(
        None,
        None,
        vec![text_attachment("notice.txt", ATTACHMENT_SEXTORTION)],
        true,
    );

    let result = module.analyze(&ctx).await.unwrap();

    let claims =
        result.details["semantic_attachment_sources"]["sources"][0]["semantic_context"]["claims"]
            .as_array()
            .unwrap();
    assert!(!claims.is_empty());
    assert!(claims.iter().all(|claim| {
        claim["source_part"] == "attachment"
            && claim["source_span_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("attachment:fixture-notice.txt:"))
    }));
}

#[tokio::test]
async fn oversized_attachment_is_skipped_without_a_coverage_gap() {
    let module = SemanticScanModule::new(None);
    let mut attachment = text_attachment("large.txt", ATTACHMENT_SEXTORTION);
    attachment.size = 5 * 1024 * 1024;
    let ctx = attachment_ctx(
        Some("Large file"),
        Some("See attached."),
        vec![attachment],
        true,
    );

    let result = module.analyze(&ctx).await.unwrap();

    let skipped = result.details["semantic_attachment_sources"]["skipped"]
        .as_array()
        .unwrap();
    assert!(
        skipped
            .iter()
            .any(|entry| { entry["filename"] == "large.txt" && entry["reason"] == "size_limit" })
    );
    assert!(
        !result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
}

#[tokio::test]
async fn short_subject_only_message_is_classified_when_capture_is_complete() {
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(Some("账户验证通知"), None, Vec::new(), true);

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        !result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
    assert_eq!(result.details["semantic_body_source"], "empty");
    let classifier = &result.details["semantic_text_classifier"];
    assert_eq!(
        classifier["status"], "scored",
        "short text is no longer skipped"
    );
    assert_eq!(classifier["below_training_length"], true);
}

#[tokio::test]
async fn header_only_incomplete_capture_still_classifies_the_subject() {
    let module = SemanticScanModule::new(None);
    let ctx = attachment_ctx(Some("账户验证通知"), None, Vec::new(), false);

    let result = module.analyze(&ctx).await.unwrap();

    assert!(
        result
            .categories
            .contains(&SEMANTIC_INSPECTION_LIMITED.to_string())
    );
    assert_eq!(
        result.details["semantic_text_classifier"]["status"],
        "scored"
    );
}
