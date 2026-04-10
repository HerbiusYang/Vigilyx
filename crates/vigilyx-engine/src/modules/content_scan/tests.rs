use super::*;
use std::sync::Arc;

use crate::context::SecurityContext;
use crate::module::SecurityModule;
use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

#[test]
fn system_seed_keywords_are_normalized_out_of_user_added() {
    let system_seed = KeywordOverrides {
        phishing_keywords: KeywordCategoryOverride {
            added: vec!["account suspended".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let legacy_overrides = KeywordOverrides {
        phishing_keywords: KeywordCategoryOverride {
            added: vec!["account suspended".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let normalized = normalize_user_keyword_overrides(&system_seed, &legacy_overrides);
    assert!(normalized.phishing_keywords.added.is_empty());

    let builtin = get_builtin_keyword_lists(&system_seed);
    let builtin_phishing = builtin["phishing_keywords"]
        .as_array()
        .expect("builtin phishing keyword array");
    assert!(
        builtin_phishing
            .iter()
            .any(|value| value.as_str() == Some("account suspended"))
    );
}

#[test]
fn seeded_keywords_can_still_be_removed_as_user_delta() {
    let system_seed = KeywordOverrides {
        bec_phrases: KeywordCategoryOverride {
            added: vec!["same day wire".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let overrides = KeywordOverrides {
        bec_phrases: KeywordCategoryOverride {
            added: vec![],
            removed: vec!["same day wire".to_string()],
        },
        ..KeywordOverrides::default()
    };

    let normalized = normalize_user_keyword_overrides(&system_seed, &overrides);
    assert_eq!(
        normalized.bec_phrases.removed,
        vec!["same day wire".to_string()]
    );

    let effective = ContentScanModule::new_with_keyword_lists(build_effective_keyword_lists(
        &system_seed,
        &normalized,
    ))
    .effective_keywords();
    let effective_bec = effective["bec_phrases"]
        .as_array()
        .expect("effective bec phrase array");
    assert!(
        !effective_bec
            .iter()
            .any(|value| value.as_str() == Some("same day wire"))
    );
}

#[test]
fn scenario_pattern_seed_categories_flow_into_effective_lists() {
    let system_seed = KeywordOverrides {
        gateway_banner_patterns: KeywordCategoryOverride {
            added: vec!["[外部邮件]".to_string()],
            removed: vec![],
        },
        auto_reply_patterns: KeywordCategoryOverride {
            added: vec!["auto reply".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let overrides = KeywordOverrides {
        gateway_banner_patterns: KeywordCategoryOverride {
            added: vec![],
            removed: vec!["[外部邮件]".to_string()],
        },
        auto_reply_patterns: KeywordCategoryOverride {
            added: vec!["vacation reply".to_string()],
            removed: vec![],
        },
        ..KeywordOverrides::default()
    };

    let normalized = normalize_user_keyword_overrides(&system_seed, &overrides);
    let effective = build_effective_keyword_lists(&system_seed, &normalized);

    assert!(effective.gateway_banner_patterns.is_empty());
    assert_eq!(
        effective.auto_reply_patterns,
        vec!["auto reply".to_string(), "vacation reply".to_string()]
    );
}

#[test]
fn api_key_detection_requires_nearby_secret_context() {
    let text = "流水号 A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6 已处理完毕";
    assert!(find_api_keys(text).is_empty());
}

#[test]
fn api_key_detection_accepts_contextual_secret_like_strings() {
    let text = "API key: A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6，请妥善保管";
    let matches = find_api_keys(text);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6");
}

#[test]
fn api_key_detection_ignores_pure_hex_hashes_even_with_context() {
    let text = "token: aabbccddeeff00112233445566778899";
    assert!(find_api_keys(text).is_empty());
}

#[test]
fn sanitize_body_for_keyword_scan_strips_gateway_banner_and_separator_footer() {
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件，如有疑问，请联系邮件系统管理员。请注意，一定仔细核对发件人地址是否为正确地址，不要在外网电脑单击任何链接。\n\n检测结果：垃圾邮件。\n\n______ 声明： 此邮件仅发送给指定收件人。其内容可能包含某些享有专有法律权利或需要保密的信息。Any unauthorized use, disclosure, distribution or copy of this mail is strictly prohibited. If you are not the intended recipient, please immediately notify the sender by return e-mail and destroy this message.\n";
    let sanitized = sanitize_body_for_keyword_scan(
        text,
        &[
            "该邮件可能存在恶意内容，请谨慎甄别邮件".to_string(),
            "检测结果：垃圾邮件".to_string(),
        ],
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
    );
    assert!(sanitized.is_empty());
}

#[test]
fn sanitize_body_for_keyword_scan_preserves_real_content_after_notice_block() {
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n检测结果：垃圾邮件。\n\n请查收本次理财电子数据，详见附件。\n";
    let sanitized = sanitize_body_for_keyword_scan(
        text,
        &[
            "该邮件可能存在恶意内容，请谨慎甄别邮件".to_string(),
            "检测结果：垃圾邮件".to_string(),
        ],
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
    );
    assert_eq!(sanitized, "请查收本次理财电子数据，详见附件。");
}

#[test]
fn collect_gateway_prior_hits_uses_configured_patterns() {
    let hits = collect_gateway_prior_hits(
        "该邮件可能存在恶意内容，请谨慎甄别邮件。如有疑问请联系管理员。",
        &["该邮件可能存在恶意内容，请谨慎甄别邮件".to_string()],
    );
    assert_eq!(hits, vec!["该邮件可能存在恶意内容，请谨慎甄别邮件".to_string()]);
}

#[test]
fn single_token_bec_phrase_is_treated_as_weak_signal() {
    assert!(!is_strong_bec_phrase("immediately"));
    assert!(!is_strong_bec_phrase("asap"));
}

#[test]
fn multi_token_or_long_cjk_bec_phrase_is_treated_as_strong_signal() {
    assert!(is_strong_bec_phrase("release payment immediately"));
    assert!(is_strong_bec_phrase("立即完成转账"));
}

#[test]
fn single_weak_bec_hint_does_not_create_bec_category() {
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "Please review invoice INV-2048 immediately.",
        &Vec::new(),
        &Vec::new(),
        &["immediately".to_string()],
        &mut evidence,
        &mut categories,
    );

    assert_eq!(score, 0.0);
    assert!(categories.is_empty());
    assert!(evidence.is_empty());
}

fn analyze_with_runtime(module: &ContentScanModule, ctx: &SecurityContext) -> ModuleResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(module.analyze(ctx))
        .unwrap()
}

fn make_ctx(
    body_text: Option<&str>,
    body_html: Option<&str>,
    links: Vec<EmailLink>,
    mail_from: Option<&str>,
) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.mail_from = mail_from.map(str::to_string);
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        body_html: body_html.map(str::to_string),
        links,
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[test]
fn embedded_business_card_layout_is_not_marked_as_image_only_phishing() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some("弦上沽酒\n347831865@qq.com"),
        Some(
            r#"<div><a class="xm_write_card" href="https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=347831865%40qq.com&code=abc"><img src="http://thirdqq.qlogo.cn/qq_product/AQWJ/example.jpg" />弦上沽酒 347831865@qq.com</a></div>"#,
        ),
        vec![
            EmailLink {
                url: "https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=347831865%40qq.com&code=abc".to_string(),
                text: Some("弦上沽酒 347831865@qq.com".to_string()),
                suspicious: false,
            },
            EmailLink {
                url: "http://thirdqq.qlogo.cn/qq_product/AQWJ/example.jpg".to_string(),
                text: None,
                suspicious: false,
            },
        ],
        Some("347831865@qq.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"image_only_phishing".to_string()),
        "contact-card layouts should not be classified as image-only phishing: {:?}",
        result.categories
    );
}

#[test]
fn real_short_text_image_lure_still_triggers_image_only_phishing() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some("请查看"),
        Some(
            r#"<html><body><a href="https://evil.example/verify"><img src="https://evil.example/banner.png" /></a></body></html>"#,
        ),
        vec![EmailLink {
            url: "https://evil.example/verify".to_string(),
            text: Some("立即查看".to_string()),
            suspicious: false,
        }],
        Some("notify@example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"image_only_phishing".to_string()),
        "true short-text image lures should still be flagged: {:?}",
        result.categories
    );
}
