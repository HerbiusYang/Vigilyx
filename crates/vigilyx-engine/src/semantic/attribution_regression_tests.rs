//! Regression tests for quote/thread corroboration, negation scope, report
//! scope, recipient direction, bounded-extraction sampling and the shared
//! deadline. Each attack case is paired with a benign or verified control.

use std::sync::Arc;
use std::time::Instant;

use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
use vigilyx_core::security::{
    SemanticCoverageStatus, SemanticMessageContext, SemanticPolarity, SemanticQuoteStatus,
    SemanticSourcePart,
};

use crate::module::{ModuleResult, SecurityModule};
use crate::pipeline::context::SecurityContext;

use super::compiled::compiled_semantic_data;
use super::context::{UNVERIFIED_THREAD_PROVENANCE, extract_semantic_context_until};
use super::{
    SemanticScanModule, exclude_non_action_claims, extract_semantic_context,
    is_current_recipient_action, semantic_text_projection,
};

const SEXTORTION: &str = "I recorded you. Send bitcoin to my wallet or I share it.";

fn session(
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

fn plain(subject: Option<&str>, body: &str) -> SemanticMessageContext {
    extract_semantic_context(
        &session(subject, Some(body), None),
        body,
        SemanticSourcePart::PlainText,
    )
}

fn html(subject: Option<&str>, markup: &str) -> SemanticMessageContext {
    let body = semantic_text_projection(markup, SemanticSourcePart::Html);
    extract_semantic_context(
        &session(subject, None, Some(markup)),
        &body,
        SemanticSourcePart::Html,
    )
}

fn current(context: &SemanticMessageContext) -> bool {
    context.claims.iter().any(is_current_recipient_action)
}

async fn scan(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> ModuleResult {
    SemanticScanModule::new(None)
        .analyze(&SecurityContext::new(Arc::new(session(
            subject, body_text, body_html,
        ))))
        .await
        .unwrap()
}

fn sextortion(result: &ModuleResult) -> bool {
    result
        .categories
        .iter()
        .any(|category| category == "sextortion")
}

#[tokio::test]
async fn forged_original_message_separator_does_not_exempt_extortion() {
    let body = format!("-----Original Message-----\n{SEXTORTION}");
    let result = scan(None, Some(&body), None).await;
    assert!(sextortion(&result), "{result:?}");
}

#[tokio::test]
async fn reply_header_block_without_envelope_thread_still_admits_extortion() {
    let body =
        format!("From: boss@corp.example\nSent: Mon 26 Oct 2026\nSubject: urgent\n\n{SEXTORTION}");
    let forged = scan(None, Some(&body), None).await;
    assert!(sextortion(&forged), "{forged:?}");
    assert!(
        forged.details["semantic_unverified_thread_actions"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "{forged:?}"
    );
    assert_eq!(forged.details["semantic_review_required"], true);

    // A real reply carries envelope thread evidence; its quotation stays exempt.
    let reply = scan(Some("Re: urgent"), Some(&body), None).await;
    assert!(!sextortion(&reply), "{reply:?}");
}

#[tokio::test]
async fn bare_quote_prefix_is_exempt_only_inside_a_verified_thread() {
    let body = "> I recorded you.\n> Send bitcoin to my wallet or I share it.";
    assert!(sextortion(&scan(None, Some(body), None).await));
    assert!(!sextortion(
        &scan(Some("Re: hello"), Some(body), None).await
    ));

    let markup = "<blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div><p>I recorded you.</p><p>Send bitcoin to my wallet or I share it.</p></blockquote>";
    assert!(sextortion(&scan(None, None, Some(markup)).await));
    assert!(!sextortion(
        &scan(Some("Re: hello"), None, Some(markup)).await
    ));
}

#[test]
fn unverified_thread_claims_keep_quote_status_but_not_trusted_quotation() {
    let context = plain(None, "> Please enter your password.");
    let claim = context.claims.first().expect("claim");
    assert_eq!(claim.quote_or_forward_status, SemanticQuoteStatus::Quoted);
    assert!(
        claim
            .provenance
            .iter()
            .any(|value| value == UNVERIFIED_THREAD_PROVENANCE)
    );
    assert!(!is_current_recipient_action(claim));

    let verified = plain(Some("Re: account"), "> Please enter your password.");
    assert!(
        !verified.claims[0]
            .provenance
            .iter()
            .any(|value| value == UNVERIFIED_THREAD_PROVENANCE)
    );
}

#[test]
fn unverified_thread_text_is_not_masked_for_other_detectors() {
    let body = "> Enter your password here.";
    let (retained, _) = exclude_non_action_claims(
        &session(None, Some(body), None),
        body,
        SemanticSourcePart::PlainText,
    );
    assert!(retained.contains("Enter your password"));
    let (masked, _) = exclude_non_action_claims(
        &session(Some("Re: support"), Some(body), None),
        body,
        SemanticSourcePart::PlainText,
    );
    assert!(!masked.contains("Enter your password"));
}

#[test]
fn forward_separator_requires_a_following_sender_header() {
    let forged = plain(
        Some("Fw: notice"),
        "---------- 转发邮件 ----------\n请点击链接验证账户。",
    );
    assert!(current(&forged), "{forged:?}");
    let real = plain(
        Some("Fw: notice"),
        "---------- 转发邮件 ----------\n发件人: vendor@example.invalid\n请点击链接验证账户。",
    );
    assert!(!current(&real), "{real:?}");
    assert!(
        real.claims
            .iter()
            .any(|claim| claim.quote_or_forward_status == SemanticQuoteStatus::Forwarded)
    );
}

#[test]
fn html_quote_container_needs_reply_attribution() {
    let bare = html(
        Some("Re: account"),
        "<p>Hello</p><blockquote><p>Please enter your password.</p></blockquote>",
    );
    assert!(current(&bare), "{bare:?}");
    let attributed = html(
        Some("Re: account"),
        "<p>Hello</p><blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div><p>Please enter your password.</p></blockquote><p>Thanks.</p>",
    );
    assert!(!current(&attributed), "{attributed:?}");
    let inline = html(
        Some("Re: account"),
        "<p>Note <q>Please enter your password.</q></p>",
    );
    assert!(current(&inline), "{inline:?}");
}

#[test]
fn inline_quotation_requires_a_same_line_speech_frame() {
    assert!(current(&plain(None, "“请立即点击链接验证账户。”")));
    assert!(!current(&plain(None, "他说：“请立即点击链接验证账户。”")));
    assert!(current(&plain(None, "例如“请立即点击\n链接验证账户。”")));
    let overlong = format!("例如“{}请立即点击链接验证账户。”", "内容，".repeat(1500));
    assert!(current(&plain(None, &overlong)));
}

#[test]
fn negated_urgency_verbs_urge_the_following_action() {
    for body in [
        "Don't hesitate to verify your account.",
        "不要错过今天验证账户的最后期限。",
        "请勿忽略：点击链接验证账户。",
    ] {
        let context = plain(None, body);
        assert!(current(&context), "{body}: {context:?}");
        assert!(
            !context
                .claims
                .iter()
                .any(|claim| claim.polarity == SemanticPolarity::AntiAction),
            "{body}: {context:?}"
        );
    }
    // Genuine refusals stay warnings.
    for body in ["请勿把验证码发送给任何人。", "Never share your password."] {
        assert!(!current(&plain(None, body)), "{body}");
    }
}

#[test]
fn urgency_negation_cannot_counter_a_payment_request() {
    let context = plain(
        None,
        "请在48小时内支付比特币到以下钱包地址。不要拖延支付比特币，否则视频会发给你所有联系人。",
    );
    let payment = context
        .claims
        .iter()
        .find(|claim| claim.actions.iter().any(|action| action == "支付"))
        .expect("payment claim");
    assert!(payment.counter_context_ids.is_empty(), "{context:?}");
    assert!(is_current_recipient_action(payment), "{context:?}");
}

#[test]
fn negation_scope_ends_at_a_dash_or_consequence_connector() {
    let dashed = plain(
        None,
        "Don't let your mailbox be suspended — verify your account now.",
    );
    assert!(current(&dashed), "{dashed:?}");
    let consequence = plain(None, "请立即验证账户，否则您将不能登录邮箱。");
    assert!(current(&consequence), "{consequence:?}");
}

#[test]
fn unframed_report_marker_does_not_exempt_a_following_request() {
    for body in [
        "安全中心发现钓鱼邮件，请立即点击链接验证账户。",
        "发现钓鱼邮件请立即点击链接验证账户。",
    ] {
        assert!(current(&plain(None, body)), "{body}");
    }
    for body in [
        "安全培训案例：攻击者要求收件人点击链接验证账户。",
        "邮件中写道：请立即点击链接验证账户。",
    ] {
        assert!(!current(&plain(None, body)), "{body}");
    }
}

#[test]
fn first_person_organization_request_is_recipient_directed() {
    for body in [
        "我司财务要求您今天把款项转入新账户。",
        "We kindly ask you to verify your account.",
    ] {
        let context = plain(None, body);
        assert!(current(&context), "{body}: {context:?}");
    }
    // The speaker's own action toward the recipient is not a request.
    assert!(!current(&plain(None, "I need to send you my password.")));
}

#[test]
fn collective_subject_constructions_are_active() {
    let context = plain(None, "所有用户需要点击链接验证账户。");
    assert!(current(&context), "{context:?}");
}

#[test]
fn url_token_ends_before_following_cjk_prose() {
    let context = plain(None, "点击https://portal.example.invalid/a验证您的账户密码");
    assert!(
        context
            .claims
            .iter()
            .any(|claim| claim.objects.iter().any(|object| object == "密码")),
        "{context:?}"
    );
}

#[test]
fn leading_filler_cannot_push_a_trailing_request_out_of_inspection() {
    let punctuation = format!("{}请点击链接验证账户。", "。\n".repeat(600));
    assert!(current(&plain(None, &punctuation)));

    let lines = format!("{}请点击链接验证账户。", "a\n".repeat(5000));
    let context = plain(None, &lines);
    assert!(
        current(&context),
        "head/tail sampling keeps the trailing request"
    );

    let overlong = format!("{}请点击链接验证账户", "x ".repeat(3000));
    assert!(current(&plain(None, &overlong)));

    let claims = format!("{}请点击链接验证账户。", "附件已上传。\n".repeat(600));
    let context = plain(None, &claims);
    assert!(
        current(&context),
        "a later current request evicts lower-value claims"
    );
    assert_eq!(context.coverage, SemanticCoverageStatus::Incomplete);
}

#[test]
fn dense_connectors_and_long_html_lines_stay_within_the_extraction_budget() {
    let budget_reason = |context: &SemanticMessageContext| {
        context
            .coverage_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("budget"))
    };
    let commas = format!("{}请点击链接验证账户。", "，".repeat(1365));
    assert!(!budget_reason(&plain(None, &commas)));
    let and_connectors = format!("{}please verify your account.", "and ".repeat(1000));
    assert!(!budget_reason(&plain(None, &and_connectors)));
    let single_line_html = format!(
        "<p>{}</p>",
        "请查看附件！确认后回复。".repeat(120 * 1024 / 36)
    );
    assert!(!budget_reason(&html(None, &single_line_html)));
}

#[test]
fn caller_deadline_bounds_extraction() {
    let body = "请点击链接验证账户。";
    let expired = extract_semantic_context_until(
        &session(None, Some(body), None),
        body,
        SemanticSourcePart::PlainText,
        &compiled_semantic_data(),
        Instant::now(),
    );
    assert_eq!(expired.coverage, SemanticCoverageStatus::Incomplete);
    assert!(
        expired
            .coverage_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("budget"))
    );
}

#[test]
fn repeated_extraction_of_one_session_is_shared() {
    let body = "请点击链接验证账户。";
    let session = session(None, Some(body), None);
    let first = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
    let second = extract_semantic_context(&session, body, SemanticSourcePart::PlainText);
    assert_eq!(first, second);
}
