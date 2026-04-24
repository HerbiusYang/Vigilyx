use super::*;
use std::sync::Arc;

use crate::context::SecurityContext;
use crate::module::{SecurityModule, ThreatLevel};
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
    assert_eq!(
        hits,
        vec!["该邮件可能存在恶意内容，请谨慎甄别邮件".to_string()]
    );
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

fn make_ctx_with_subject_and_body(
    subject: &str,
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
    session.subject = Some(subject.to_string());
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
        Some("测试联系人\ntest.contact@example.test"),
        Some(
            r#"<div><a class="xm_write_card" href="https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=test.contact%40example.test&code=test-card"><img src="http://thirdqq.qlogo.cn/qq_product/AQWJ/example.jpg" />测试联系人 test.contact@example.test</a></div>"#,
        ),
        vec![
            EmailLink {
                url: "https://wx.mail.qq.com/home/index?t=readmail_businesscard_midpage&mail=test.contact%40example.test&code=test-card".to_string(),
                text: Some("测试联系人 test.contact@example.test".to_string()),
                suspicious: false,
            },
            EmailLink {
                url: "http://thirdqq.qlogo.cn/qq_product/AQWJ/example.jpg".to_string(),
                text: None,
                suspicious: false,
            },
        ],
        Some("test.contact@example.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"image_only_phishing".to_string()),
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
        result
            .categories
            .contains(&"image_only_phishing".to_string()),
        "true short-text image lures should still be flagged: {:?}",
        result.categories
    );
}

#[test]
fn wps_share_notice_is_not_marked_as_image_only_phishing() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "分享给你 'dzfp_test_invoice_示例商贸有限公司_20260416160403.pdf'，来自WPS Office",
        Some("请查收"),
        Some(
            r#"<html><body><a href="https://wx.mail.qq.com/info/get_mailhead_icon?key=TESTWPSICONKEY123&amp;r=2085971486"><img src="https://wx.mail.qq.com/info/get_mailhead_icon?key=TESTWPSICONKEY123&amp;r=2085971486" /></a></body></html>"#,
        ),
        vec![EmailLink {
            url: "https://wx.mail.qq.com/info/get_mailhead_icon?key=TESTWPSICONKEY123&r=2085971486"
                .to_string(),
            text: None,
            suspicious: false,
        }],
        Some("wps_share_test@qq.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"image_only_phishing".to_string()),
        "WPS share notices sent from public mailboxes should not be treated as image-only phishing: {:?}",
        result.categories
    );
}

// ─── P2-3: phone_in_subject chat export skip regression tests ───

fn make_ctx_with_subject(
    subject: &str,
    body_text: Option<&str>,
    mail_from: Option<&str>,
) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject = Some(subject.to_string());
    session.mail_from = mail_from.map(str::to_string);
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = EmailContent {
        body_text: body_text.map(str::to_string),
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[test]
fn phone_in_subject_skipped_for_chat_record_export() {
    // P2-3: WeChat chat record forwarding subjects naturally contain phone numbers
    // Chat-record style subjects that contain a phone number should not trigger phone_in_subject.
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "13800138000和李四的聊天记录",
        Some("这是一段聊天记录的内容。"),
        Some("sender@example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"phone_in_subject".to_string()),
        "Chat record export subject should not trigger phone_in_subject, got categories={:?}",
        result.categories
    );
}

#[test]
fn phone_in_subject_skipped_for_group_chat_export() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "项目群聊 13600136000",
        Some("群聊内容。"),
        Some("sender@example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"phone_in_subject".to_string()),
        "Group chat subject should not trigger phone_in_subject, got categories={:?}",
        result.categories
    );
}

#[test]
fn phone_in_subject_still_triggers_for_suspicious_email() {
    // A subject with a phone number but NOT a chat export should still trigger
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "紧急通知 13800138000 请回电",
        Some("尊敬的客户，您的账户有异常。"),
        Some("notify@unknown-domain.xyz"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phone_in_subject".to_string()),
        "Non-chat subject with phone number should trigger phone_in_subject, got categories={:?}",
        result.categories
    );
}

#[test]
fn verification_code_notice_is_not_marked_as_phishing() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "邮箱验证码(Email Verification Code)",
        Some("您的验证码为 123456，5 分钟内有效。"),
        None,
        vec![],
        Some("noreply@notice.example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(
        !result.categories.contains(&"phishing_subject".to_string()),
        "verification-code subjects should not trigger phishing_subject: {:?}",
        result.categories
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "verification-code bodies should not trigger phishing: {:?}",
        result.categories
    );
}

#[test]
fn verification_code_lure_with_untrusted_link_still_flags() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Email Verification Code - account suspended",
        Some(
            "Your verification code is 123456. Your account will be suspended unless you verify your account immediately.",
        ),
        None,
        vec![EmailLink {
            url: "https://evil.example/verify".to_string(),
            text: Some("Verify now".to_string()),
            suspicious: false,
        }],
        Some("noreply@example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing_subject".to_string())
            || result.categories.contains(&"phishing".to_string())
            || result
                .categories
                .contains(&"account_security_phishing".to_string()),
        "verification-code lures with untrusted links must still be flagged: {:?}",
        result.categories
    );
}

#[test]
fn subsidy_subject_variant_without_body_still_flags() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]2026年入职综合补贴申请通知！",
        None,
        None,
        vec![],
        Some("service@cdsnkj.com.cn"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "subsidy scam subject variants should trigger subsidy_fraud even when body is empty: {:?}",
        result.categories
    );
}

#[test]
fn japanese_icloud_billing_subject_triggers_account_security_detection() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]<iCloud+ 支払い情報異常のご通知 >",
        Some("お支払い方法を更新してください。確認はこちら。"),
        None,
        vec![EmailLink {
            url: "https://github-jp.homes/account/update".to_string(),
            text: Some("お支払い方法を更新".to_string()),
            suspicious: false,
        }],
        Some("feww.applestore.updateservice.mailmaky@ana.co.jp"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "Japanese iCloud billing lures should trigger account_security_phishing: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "Japanese iCloud billing lures should not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn invoice_spam_with_qq_and_wechat_contact_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]开增值税普票加Q:3826878185陈姐 +薇yygx778",
        Some("开电子普票加Q-3826878185陈姐 +薇yygx778"),
        None,
        vec![],
        Some("fieifltq@crjj.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "invoice spam solicitations should trigger invoice_spam: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "invoice spam solicitations should not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn obfuscated_invoice_spam_with_separators_is_still_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]21:12\"正▎规▎税 票\"(“扣扣-3826878185陈姐) +薇yygx778",
        Some("正 规 税 票，扣扣3826878185，陈姐，+薇yygx778"),
        None,
        vec![],
        Some("vyoyysq@lnlpfrcpd.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "invoice spam with separator obfuscation should still trigger invoice_spam: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "invoice spam with separator obfuscation should not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn legitimate_bank_invoice_notice_is_not_invoice_spam() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "示例银行电子发票",
        Some("尊敬的用户您好，您在我行申请的电子发票已开具成功，请点此链接进行下载。"),
        None,
        vec![EmailLink {
            url: "https://billing.example-bank.test/invoice/download?invoice=test-2046757649382641664".to_string(),
            text: Some("下载电子发票".to_string()),
            suspicious: false,
        }],
        Some("billing@example-bank.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"invoice_spam".to_string()),
        "legitimate bank invoice delivery should not trigger invoice_spam: {:?}",
        result.categories
    );
}
