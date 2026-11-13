use super::{
    attachment_credential_context, attachment_has_credential_lure, attachment_link_span,
    extract_html_attachment_text,
};
use crate::semantic::is_current_recipient_action;
use vigilyx_core::models::{EmailSession, Protocol};

fn session() -> EmailSession {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.50".to_string(),
        40000,
        "10.0.0.2".to_string(),
        25,
    );
    session.mail_from = Some("sender@external.example".to_string());
    session.rcpt_to.push("recipient@corp.internal".to_string());
    session
}

#[test]
fn rendered_request_with_deadline_retains_only_the_original_target_authority() {
    let target = "http://203.0.113.50/verify/login";
    let html = format!(
        "<p>请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p><a href='{target}'>{target}</a></p>"
    );
    let extracted = extract_html_attachment_text(&html).expect("rendered HTML is retained");
    let context = attachment_credential_context(
        &session(),
        &extracted.text,
        "synthetic-request-deadline",
        &extracted.semantic_source_ranges,
    );
    let bound = context
        .claims
        .iter()
        .filter(|claim| is_current_recipient_action(claim) && !claim.link_ids.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        bound.len(),
        1,
        "the deadline cannot compete with the CTA: {context:?}"
    );
    let request = bound[0];
    let original = &extracted.text[request.span.start_byte..request.span.end_byte];
    assert!(
        original.contains("请立即点击下方链接验证身份"),
        "{context:?}"
    );
    assert!(
        !original.contains("24小时"),
        "the original CTA span is retained"
    );
    assert!(
        !original.contains(target),
        "the actual target keeps its own span"
    );
    let targets = context
        .links
        .iter()
        .filter(|link| link.original_url == target)
        .collect::<Vec<_>>();
    assert!(
        !targets.is_empty(),
        "the physical target is retained: {context:?}"
    );
    for link in targets {
        let span = attachment_link_span(&link.link_id).expect("physical target offsets");
        let authority = attachment_has_credential_lure(&context, target, span)
            .expect("the original request binds its observed target");
        assert_eq!(authority.source_span_id, request.source_span_id);
        assert!(request.span.end_byte < span.start_byte);
    }
}

#[test]
fn rendered_deadline_quotes_and_unrelated_targets_do_not_supply_request_authority() {
    let target = "http://203.0.113.50/verify/login";
    for body in [
        "<p>24小时内未验证将冻结账户。</p>".to_string(),
        "<p>请勿点击下方链接验证身份，24小时内未验证将冻结账户。</p>".to_string(),
        "<blockquote><p>请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p></blockquote>".to_string(),
        "<p>请立即点击下方链接验证身份，24小时内未验证将冻结账户。</p><p>普通测试报告记录服务地址：</p>".to_string(),
    ] {
        let html = format!("{body}<p><a href='{target}'>{target}</a></p>");
        let extracted = extract_html_attachment_text(&html).expect("visible HTML is retained");
        let context = attachment_credential_context(
            &session(),
            &extracted.text,
            "synthetic-deadline-negative",
            &extracted.semantic_source_ranges,
        );
        let targets = context
            .links
            .iter()
            .filter(|link| link.original_url == target)
            .collect::<Vec<_>>();
        assert!(!targets.is_empty(), "the observed target is retained: {context:?}");
        for link in targets {
            let span = attachment_link_span(&link.link_id).expect("physical target offsets");
            assert!(
                attachment_has_credential_lure(&context, target, span).is_none(),
                "a deadline, quote, anti-action or unrelated paragraph cannot authorize the target: {body}: {context:?}"
            );
        }
    }
}
