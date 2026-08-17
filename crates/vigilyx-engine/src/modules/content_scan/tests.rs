use super::*;
use std::collections::HashSet;
use std::sync::Arc;

use crate::context::SecurityContext;
use crate::module::{SecurityModule, ThreatLevel};
use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

fn normalized_patterns(values: &[&str]) -> Vec<String> {
    collect_normalized_keywords(values.iter().copied())
}

#[test]
fn canonical_keyword_seed_has_2000_multilingual_entries_per_category() {
    let seed: KeywordOverrides = serde_json::from_str(include_str!(
        "../../../../../shared/schemas/keyword_overrides_seed.json"
    ))
    .expect("canonical keyword seed must parse");
    let normalized = normalize_system_keyword_seed(&seed);
    let categories = [
        ("phishing_keywords", &normalized.phishing_keywords.added),
        (
            "weak_phishing_keywords",
            &normalized.weak_phishing_keywords.added,
        ),
        ("bec_phrases", &normalized.bec_phrases.added),
        (
            "internal_authority_phrases",
            &normalized.internal_authority_phrases.added,
        ),
        (
            "gateway_banner_patterns",
            &normalized.gateway_banner_patterns.added,
        ),
        (
            "notice_banner_patterns",
            &normalized.notice_banner_patterns.added,
        ),
        ("dsn_patterns", &normalized.dsn_patterns.added),
        ("auto_reply_patterns", &normalized.auto_reply_patterns.added),
    ];

    for (category, entries) in categories {
        assert!(
            entries.len() >= 2_000,
            "{category} must contain at least 2000 normalized entries, got {}",
            entries.len()
        );
        let unique_entries = entries.iter().collect::<HashSet<_>>();
        assert_eq!(
            unique_entries.len(),
            entries.len(),
            "{category} must not contain normalized duplicates"
        );
        assert!(
            entries.iter().any(|entry| {
                entry
                    .chars()
                    .any(|ch| ('\u{0400}'..='\u{052F}').contains(&ch))
            }),
            "{category} must contain Cyrillic entries"
        );
        assert!(
            entries.iter().any(|entry| {
                entry
                    .chars()
                    .any(|ch| ('\u{0600}'..='\u{06FF}').contains(&ch))
            }),
            "{category} must contain Arabic entries"
        );
        assert!(
            entries.iter().any(|entry| {
                entry
                    .chars()
                    .any(|ch| ('\u{0900}'..='\u{097F}').contains(&ch))
            }),
            "{category} must contain Devanagari entries"
        );
        assert!(
            entries.iter().any(|entry| {
                entry
                    .chars()
                    .any(|ch| ('\u{0E00}'..='\u{0E7F}').contains(&ch))
            }),
            "{category} must contain Thai entries"
        );
        assert!(
            entries.iter().any(|entry| {
                entry
                    .chars()
                    .any(|ch| ('\u{AC00}'..='\u{D7AF}').contains(&ch))
            }),
            "{category} must contain Hangul entries"
        );
    }
}

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
fn normalize_text_folds_common_confusable_letters() {
    assert_eq!(normalize_text("pаsswоrd раyment"), "password payment");
}

#[test]
fn normalize_text_folds_traditional_security_vocabulary() {
    assert_eq!(
        normalize_text("親愛的用戶：系統偵測到您的帳戶存在異常登入，請立即點擊驗證身分"),
        "亲爱的用户:系统侦测到您的账户存在异常登入,请立即点击验证身分"
    );
}

#[test]
fn sanitize_body_for_keyword_scan_strips_gateway_banner_and_separator_footer() {
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件，如有疑问，请联系邮件系统管理员。请注意，一定仔细核对发件人地址是否为正确地址，不要在外网电脑单击任何链接。\n\n检测结果：垃圾邮件。\n\n______ 声明： 此邮件仅发送给指定收件人。其内容可能包含某些享有专有法律权利或需要保密的信息。Any unauthorized use, disclosure, distribution or copy of this mail is strictly prohibited. If you are not the intended recipient, please immediately notify the sender by return e-mail and destroy this message.\n";
    let patterns = normalized_patterns(&[
        "该邮件可能存在恶意内容，请谨慎甄别邮件",
        "检测结果：垃圾邮件",
    ]);
    let sanitized =
        sanitize_body_for_keyword_scan(text, &patterns, &Vec::new(), &Vec::new(), &Vec::new());
    assert!(sanitized.is_empty());
}

#[test]
fn sanitize_body_for_keyword_scan_preserves_real_content_after_notice_block() {
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n检测结果：垃圾邮件。\n\n请查收本次理财电子数据，详见附件。\n";
    let patterns = normalized_patterns(&[
        "该邮件可能存在恶意内容，请谨慎甄别邮件",
        "检测结果：垃圾邮件",
    ]);
    let sanitized =
        sanitize_body_for_keyword_scan(text, &patterns, &Vec::new(), &Vec::new(), &Vec::new());
    assert_eq!(sanitized, "请查收本次理财电子数据，详见附件。");
}

#[test]
fn collect_gateway_prior_hits_uses_configured_patterns() {
    let patterns = normalized_patterns(&["该邮件可能存在恶意内容，请谨慎甄别邮件"]);
    let hits = collect_gateway_prior_hits(
        "该邮件可能存在恶意内容，请谨慎甄别邮件。如有疑问请联系管理员。",
        &patterns,
    );
    assert_eq!(hits, patterns);
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
fn validated_personal_data_is_informational_not_threat_score() {
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "身份证号 11010519491231002X",
        &[],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );

    assert_eq!(score, 0.0);
    assert!(
        categories
            .iter()
            .any(|category| category == "dlp_id_number")
    );
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

#[test]
fn html_alternative_risk_is_scanned_even_when_plain_text_is_clean() {
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        phishing_keywords: vec![
            normalize_text("verify your account"),
            normalize_text("immediately"),
        ],
        ..Default::default()
    });
    let ctx = make_ctx(
        Some("Hello, please see the routine update."),
        Some("<html><body>Please verify your account immediately.</body></html>"),
        vec![],
        Some("vendor@example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"multipart_alternative_mismatch".to_string()),
        "HTML/text mismatch should be surfaced: {:?}",
        result.categories
    );
    assert!(
        result.categories.contains(&"phishing".to_string()),
        "HTML alternative should still use runtime phishing keywords: {:?}",
        result.categories
    );
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
fn neutral_enterprise_account_lure_with_untrusted_sso_link_is_medium() {
    // RT-DYN-03: no urgency, attachment, forged auth header, or mutable
    // phishing keyword is required for a credential-harvesting structure to
    // remain visible when AI is disabled.
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Workspace access",
        Some("Use your enterprise account to continue."),
        None,
        vec![EmailLink {
            url: "https://login-secure.example/sso/continue".to_string(),
            text: Some("Continue with your enterprise account".to_string()),
            suspicious: false,
        }],
        Some("notifications@random-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"credential_link_lure".to_string()),
        "neutral credential lures must emit a structural category: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "external credential instruction + untrusted SSO link must not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn credential_instruction_with_official_sso_destination_is_not_structural_lure() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Workspace access",
        Some("Use your enterprise account to continue."),
        None,
        vec![EmailLink {
            url: "https://login.microsoftonline.com/common/oauth2/authorize".to_string(),
            text: Some("Continue with your enterprise account".to_string()),
            suspicious: false,
        }],
        Some("notifications@vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"credential_link_lure".to_string()),
        "official SSO destinations are a negative control: {:?}",
        result.categories
    );
}

#[test]
fn new_device_login_lure_with_untrusted_link_is_account_security_phishing() {
    let seed: KeywordOverrides = serde_json::from_str(include_str!(
        "../../../../../shared/schemas/keyword_overrides_seed.json"
    ))
    .expect("keyword seed must parse");
    let module = ContentScanModule::new_with_keyword_lists(build_effective_keyword_lists(
        &seed,
        &KeywordOverrides::default(),
    ));
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]新设备登录提醒",
        Some("新设备登录提醒。"),
        None,
        vec![EmailLink {
            url: "http://jdoyunzv.18tou.com/?m=yzy@ccabchina.com".to_string(),
            text: Some("查看登录详情".to_string()),
            suspicious: false,
        }],
        Some("center.lin@cqfengqing1.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "targeted new-device login lure should be classified as account-security phishing: {:?}",
        result.categories
    );
    assert!(result.threat_level >= ThreatLevel::Medium);
}

#[test]
fn storage_quota_claim_lure_is_at_least_medium() {
    let seed: KeywordOverrides = serde_json::from_str(include_str!(
        "../../../../../shared/schemas/keyword_overrides_seed.json"
    ))
    .expect("keyword seed must parse");
    let module = ContentScanModule::new_with_keyword_lists(build_effective_keyword_lists(
        &seed,
        &KeywordOverrides::default(),
    ));
    let ctx = make_ctx_with_subject_and_body(
        "存储空间不足影响上传与同步：请尽快领取",
        None,
        Some(
            "<h2>存储空间已满</h2><p>当前存储空间已达到上限，建议尽快扩容。</p><p>6GB 免费扩容</p><a>立即领取 6GB 免费空间</a>",
        ),
        vec![EmailLink {
            url: "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=https%3A%2F%2Fwww.cy1109.top%2F%3Ftoken%3DIPx02BJ5syULgAJjwyJngqP5wDKnhEb"
                .to_string(),
            text: Some("立即领取 6GB 免费空间".to_string()),
            suspicious: false,
        }],
        Some("xiaoxiao@cy1109.top"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "storage-quota claim lure must be medium or above: level={:?}, categories={:?}",
        result.threat_level,
        result.categories
    );
    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "storage lure must not be mislabeled as an account-login alert"
    );
}

#[test]
fn new_device_login_notice_without_clickable_link_is_not_promoted() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "新设备登录提醒",
        Some("您已成功登录，本邮件不包含链接，无需操作。"),
        None,
        vec![],
        Some("notice@unknown.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string())
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
fn legitimate_credit_training_article_does_not_trigger_fraud_or_language_rules() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]",
        Some(
            "该邮件可能存在恶意内容，请谨慎甄别。检测结果：垃圾邮件。\n\
             银行工作人员应严格审查贷款材料。某客户申请办理商品质押融资，剩余资金由客户使用。\n\
             客户经理通过电话查询材料，案例中涉及增值税专用发票和票据承兑。\n\
             更多内容请关注信贷风险管理微信视频号，某支行总经理参加了本次培训。",
        ),
        None,
        vec![],
        Some("972279456@qq.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    for category in ["subsidy_fraud", "invoice_spam", "lang_inconsistency"] {
        assert!(
            !result.categories.iter().any(|value| value == category),
            "legitimate credit-training prose must not trigger {category}: {:?}",
            result.categories
        );
    }
}

#[test]
fn english_department_signature_after_chinese_body_still_flags() {
    let body = "这是正常的中文业务正文，用于说明项目安排、交付时间和会议计划。\n\
                如有问题请在例会中反馈。\n\
                Best regards,\n\
                Finance Department";
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    detectors::detect_lang_inconsistency(Some(body), &mut score, &mut categories, &mut evidence);

    assert!(
        categories.contains(&"lang_inconsistency".to_string()),
        "a real English department signature after Chinese prose should remain detectable: {:?}",
        categories
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
fn obfuscated_subject_contact_lure_is_detected_without_invoice_keyword() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]VT （发Q-3826878185 嘌 陈姐 ） 加微chenbw682 CEYx富得闯供树喷阮骚冠北",
        None,
        None,
        vec![],
        Some("fjlmodtf@diic.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"subject_contact_lure".to_string()),
        "obfuscated QQ/WeChat subject lure should be visible to content_scan: {:?}",
        result.categories
    );
    assert_eq!(
        result.threat_level,
        ThreatLevel::Low,
        "contact lure alone should remain a low-weight finding: {:?}",
        result
    );
    assert!(
        !result.categories.contains(&"invoice_spam".to_string()),
        "without a recognized invoice cue this should not be promoted to invoice_spam: {:?}",
        result.categories
    );
}

#[test]
fn subject_contact_lure_requires_both_marker_and_qq_identifier() {
    let module = ContentScanModule::new();

    let contact_without_id = make_ctx_with_subject_and_body(
        "请加微联系业务",
        None,
        None,
        vec![],
        Some("external@example.test"),
    );
    let id_without_contact = make_ctx_with_subject_and_body(
        "Q-3826878185 业务资料",
        None,
        None,
        vec![],
        Some("external@example.test"),
    );

    let contact_result = analyze_with_runtime(&module, &contact_without_id);
    let id_result = analyze_with_runtime(&module, &id_without_contact);

    assert!(
        !contact_result
            .categories
            .contains(&"subject_contact_lure".to_string()),
        "a contact marker without an identifier should not trigger: {:?}",
        contact_result.categories
    );
    assert!(
        !id_result
            .categories
            .contains(&"subject_contact_lure".to_string()),
        "an identifier without a contact marker should not trigger: {:?}",
        id_result.categories
    );
}

#[test]
fn subject_contact_lure_excludes_internal_senders() {
    let module = ContentScanModule::new();
    let base_ctx = make_ctx_with_subject_and_body(
        "发Q-3826878185 加微联系",
        None,
        None,
        vec![],
        Some("colleague@internal.example"),
    );
    let ctx = SecurityContext::with_internal_domains(
        base_ctx.session.clone(),
        Arc::new(HashSet::from(["internal.example".to_string()])),
    );
    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"subject_contact_lure".to_string()),
        "internal senders should not trigger the external contact-lure signal: {:?}",
        result.categories
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

#[test]
fn payment_account_change_bec_is_detected_without_ai() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Updated wire instructions",
        Some(
            "Hi finance team, our beneficiary account changed. Please use the new bank account for today's invoice payment. I am in a meeting, reply by email only.",
        ),
        None,
        vec![],
        Some("vendor-payments@example-vendor.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "payment account change BEC should be detected without AI: {:?}",
        result.categories
    );
    assert!(
        result.categories.contains(&"bec_no_ioc_social".to_string()),
        "no-link/no-attachment payment-change BEC should expose the social-only category: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "payment-change BEC should not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn chinese_payment_account_change_bec_with_separators_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "供应商收款账户变更通知",
        Some(
            "财务您好，客户新 的 账 号 已启用，今天款项请立即转账到新的账户。老板在开会，不方便电话。",
        ),
        None,
        vec![],
        Some("notice@vendor-example.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "Chinese payment-change BEC with separator obfuscation should be detected: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "Chinese payment-change BEC should not remain Safe/Low: {:?}",
        result.threat_level
    );
}

#[test]
fn benign_single_dimension_bank_update_notice_is_not_payment_change_bec() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Bank account maintenance notice",
        Some(
            "We updated our customer service bank account FAQ page. No payment action is required.",
        ),
        None,
        vec![],
        Some("newsletter@example-vendor.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "benign informational notices should not trigger payment-change BEC: {:?}",
        result.categories
    );
}

#[test]
fn payment_change_without_two_support_dimensions_is_not_bec() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Updated vendor account",
        Some("The new account reference is now available in the vendor portal for your records."),
        None,
        vec![],
        Some("updates@example-vendor.test"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "payment-change wording without enough support dimensions should not trigger BEC: {:?}",
        result.categories
    );
}

// ─── Slice A: normalization & sanitization bypass regression tests ───

#[test]
fn normalize_text_strips_extended_invisible_characters() {
    // These characters are NOT folded by NFKC; attackers insert them to break
    // keyword contiguity. All of them must be filtered out.
    assert_eq!(normalize_text("账\u{FE0F}户"), "账户"); // variation selector
    assert_eq!(normalize_text("账\u{E0001}户"), "账户"); // tags block
    assert_eq!(normalize_text("账\u{E0100}户"), "账户"); // variation selector supplement
    assert_eq!(normalize_text("账\u{180E}户"), "账户"); // mongolian vowel separator
    assert_eq!(normalize_text("账\u{2800}户"), "账户"); // braille pattern blank
    assert_eq!(normalize_text("账\u{3164}户"), "账户"); // hangul filler
    assert_eq!(normalize_text("账\u{115F}\u{1160}户"), "账户"); // hangul jamo fillers
    assert_eq!(normalize_text("账\u{202A}\u{202E}户"), "账户"); // bidi embedding/override
    assert_eq!(normalize_text("账\u{2066}\u{2069}户"), "账户"); // bidi isolates
}

#[test]
fn scan_text_detects_keyword_broken_by_tag_characters() {
    // PoC: before the fix, tag-block / bidi / filler characters between
    // keyword characters made the phrase invisible to the scan.
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "您的\u{E0001}账户\u{202E}存在\u{3164}异常",
        &["账户存在异常".to_string()],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert!(score > 0.0);
    assert!(
        categories.contains(&"phishing".to_string()),
        "invisible-char obfuscated keywords must still hit: {categories:?}"
    );
}

#[test]
fn scan_text_recovers_a_css_hidden_separator_between_cjk_keyword_chars() {
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "您的账 x 户存在异常，请立即登录",
        &["账户存在异常".to_string(), "请立即登录".to_string()],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert!(score > 0.0, "hidden single-letter separator must not erase CJK hits");
    assert!(categories.contains(&"phishing".to_string()));
}

#[test]
fn sanitize_body_for_keyword_scan_forged_banner_does_not_hide_body() {
    // PoC: an attacker forges a gateway banner followed by a separator line;
    // the old logic then wiped the entire body before keyword scanning.
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n____________________\n\n您的账户存在异常，请立即登录验证，否则将被冻结。";
    let sanitized = sanitize_body_for_keyword_scan(
        text,
        &["该邮件可能存在恶意内容，请谨慎甄别邮件".to_string()],
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
    );
    assert!(
        sanitized.contains("请立即登录验证"),
        "a forged banner must not blank the real body, got: {sanitized:?}"
    );
}

#[test]
fn sanitize_body_for_keyword_scan_keeps_attacker_text_after_separator() {
    // PoC: phishing prose placed after a '____' separator used to be silently
    // discarded as a "footer".
    let tail = "您的账户已被冻结，请立即登录验证，否则将永久关闭，切勿拖延。".repeat(4);
    let text = format!(
        "尊敬的客户您好，以下是本月对账单和交易明细，请查收附件并核对。\n\n____________________\n{tail}"
    );
    let sanitized =
        sanitize_body_for_keyword_scan(&text, &Vec::new(), &Vec::new(), &Vec::new(), &Vec::new());
    assert!(
        sanitized.contains("请立即登录验证"),
        "attacker-visible text after a separator must remain scanned, got: {sanitized:?}"
    );
}

#[test]
fn sanitize_body_for_keyword_scan_still_truncates_disclaimer_footer() {
    // Legitimate signature/disclaimer tails must still be truncated.
    let text = "本周会议纪要和项目进度安排如下，请各位查收附件并按时反馈。\n\n____________________\n声明：此邮件仅发送给指定收件人。其内容可能包含保密信息。Any unauthorized use, disclosure, distribution or copy of this mail is strictly prohibited. If you are not the intended recipient, please notify the sender immediately.";
    let sanitized =
        sanitize_body_for_keyword_scan(text, &Vec::new(), &Vec::new(), &Vec::new(), &Vec::new());
    assert!(sanitized.contains("会议纪要"));
    assert!(
        !sanitized.contains("指定收件人"),
        "known disclaimer footers should still be truncated, got: {sanitized:?}"
    );
}

#[test]
fn strip_subject_banner_prefixes_matches_case_insensitively() {
    // Patterns are stored lowercased; banners in original-case subjects used
    // to survive stripping and pollute keyword matching.
    let cleaned = strip_subject_banner_prefixes(
        "[External Mail] 请查收",
        &["[external mail]".to_string()],
        &Vec::new(),
    );
    assert_eq!(cleaned, "请查收");
}

#[test]
fn phishing_after_bare_angle_bracket_is_scanned() {
    // PoC (module level): a bare '<' in the HTML body used to swallow the
    // phishing prose up to the next '>'.
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        // 两个关键词命中 (0.16) 以越过 Safe 阈值: Safe 结果会丢弃 categories
        phishing_keywords: vec!["请立即登录".to_string(), "账户异常".to_string()],
        ..Default::default()
    });
    let ctx = make_ctx(
        None,
        Some("<html><body>成本 < 预算。您的账户异常，请立即登录处理。</body></html>"),
        vec![],
        Some("attacker@evil-example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing".to_string()),
        "text after a bare '<' must remain visible to keyword scanning: {:?}",
        result.categories
    );
}

#[test]
fn entity_sabotage_does_not_stop_keyword_decoding() {
    // PoC (module level): one undecodable entity ("&#xZZ;") used to abort
    // entity decoding for the rest of the body.
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        // 两个关键词命中 (0.16) 以越过 Safe 阈值: Safe 结果会丢弃 categories
        phishing_keywords: vec!["请立即登录".to_string(), "账户异常".to_string()],
        ..Default::default()
    });
    let ctx = make_ctx(
        None,
        // 请[&#xZZ;]立即登录 + 账户异常 (全部实体编码)
        Some(
            "<p>&#x8BF7;&#xZZ;&#x7ACB;&#x5373;&#x767B;&#x5F55;&#x8D26;&#x6237;&#x5F02;&#x5E38;</p>",
        ),
        vec![],
        Some("attacker@evil-example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing".to_string()),
        "one bad entity must not stop decoding of the remaining entities: {:?}",
        result.categories
    );
}

#[test]
fn external_impersonation_matches_despite_zero_width_obfuscation() {
    // PoC: authority phrases broken up with zero-width characters used to
    // evade the external-impersonation match (raw lowercase, no normalize).
    let body = "财\u{200B}务部与人\u{200B}事部联合通知：请立即登录完成验证。";
    let ctx = make_ctx(Some(body), None, vec![], Some("attacker@evil-example.com"));
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    detectors::detect_external_impersonation(
        &ctx,
        Some(body),
        &["财务部".to_string(), "人事部".to_string()],
        &mut score,
        &mut categories,
        &mut evidence,
    );
    assert!(
        categories.contains(&"external_impersonation".to_string()),
        "zero-width obfuscated authority phrases must still match: {categories:?}"
    );
}

#[test]
fn industry_newsletter_with_unknown_link_is_not_external_impersonation() {
    let body = "本期课程聚焦反洗钱合规与监管要求，八月活动席位有限，立即报名。";
    let ctx = make_ctx(
        Some(body),
        None,
        vec![EmailLink {
            url: "https://connect.acams.org/event".to_string(),
            text: Some("立即报名".to_string()),
            suspicious: false,
        }],
        Some("info@contact.acams.org"),
    );
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();

    detectors::detect_external_impersonation(
        &ctx,
        Some(body),
        &["反洗钱合规".to_string(), "监管要求".to_string()],
        &mut score,
        &mut categories,
        &mut evidence,
    );

    assert_eq!(score, 0.0);
    assert!(
        !categories.contains(&"external_impersonation".to_string()),
        "industry nouns plus an unknown link are not an identity claim: {categories:?}"
    );
}

#[test]
fn full_width_phone_number_in_subject_is_detected() {
    // PoC: full-width digits used to evade the ASCII-only phone regex.
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "紧急通知 １３８００１３８０００ 请回电",
        Some("尊敬的客户，您的账户有异常。"),
        Some("notify@unknown-domain.xyz"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phone_in_subject".to_string()),
        "full-width digits must be folded before phone matching: {:?}",
        result.categories
    );
}

#[test]
fn full_width_phone_numbers_in_body_are_detected() {
    // PoC: full-width digits in the body used to evade the phone regex.
    let body = "请联系 １３８００１３８０００ 或 １３９００１３９０００ 办理退款。";
    let mut score = 0.0;
    let mut categories = vec!["phishing".to_string()];
    let mut evidence = Vec::new();
    detectors::detect_body_phone_numbers(Some(body), &mut score, &mut categories, &mut evidence);
    assert!(
        categories.contains(&"phone_in_body".to_string()),
        "full-width body phone numbers must be detected: {categories:?}"
    );
}

// ─── 2026-08 第二轮红队修复 PoC ───

#[test]
fn normalize_text_strips_combining_marks() {
    // Combining marks render identically to the base character
    // ("账\u{301}户" displays as "账户") but splice every keyword.
    assert_eq!(normalize_text("账\u{301}户"), "账户");
    assert_eq!(normalize_text("密码\u{30C}"), "密码");
    assert_eq!(normalize_text("verify\u{20D0}"), "verify");
    assert_eq!(normalize_text("ign\u{1AB0}ore"), "ignore");
}

#[test]
fn combining_mark_spliced_keywords_are_detected() {
    // PoC (module level): combining marks (U+0301) spliced into every
    // keyword used to bypass the whole keyword layer.
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        // 两个关键词命中 (0.16) 以越过 Safe 阈值: Safe 结果会丢弃 categories
        phishing_keywords: vec!["账户".to_string(), "请立即验证".to_string()],
        ..Default::default()
    });
    let ctx = make_ctx(
        Some("您的账\u{301}户\u{301}存在异常，请\u{301}立\u{301}即\u{301}验\u{301}证\u{301}。"),
        None,
        vec![],
        Some("attacker@evil-example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing".to_string()),
        "combining-mark spliced keywords must be detected after normalization: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Low,
        "two keyword hits (0.16) must reach Low, got {:?}",
        result.threat_level
    );
}

#[test]
fn per_character_spaced_keywords_match_via_compact_second_pass() {
    // PoC: "请 立 即 验 证 您 的 账 户" (one space per character) used to
    // bypass the direct substring scan; the compact second pass recovers it.
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "安全提醒：请 立 即 验 证 您 的 账 户，您 的 账 户 已 被 冻 结。",
        &[
            "请立即验证您的账户".to_string(),
            "账户已被冻结".to_string(),
        ],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );

    assert!(
        (score - 0.16).abs() < f64::EPSILON,
        "two spaced CJK keywords must score 0.16, got {score}"
    );
    assert!(categories.contains(&"phishing".to_string()));
}

#[test]
fn compact_second_pass_does_not_collapse_english_prose() {
    // Guard: collapsing English prose ("as a precaution" -> "asap...")
    // must not create false keyword hits; the compact pass is CJK-only.
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "As a precaution, please review the attached report.",
        &["asap".to_string()],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );

    assert_eq!(score, 0.0, "English prose must not compact-match, got {score}");
    assert!(categories.is_empty());
}

#[test]
fn compact_second_pass_recovers_letter_spaced_english_lure() {
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "v e r i f y  y o u r  a c c o u n t  n o w",
        &["verify your account now".to_string()],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert!(score > 0.0);
    assert!(categories.contains(&"phishing".to_string()));
}

#[test]
fn disclaimer_prefixed_phishing_lines_do_not_clear_body() {
    // PoC: attacker forges a gateway banner + separator, then prefixes the
    // phishing line with "声明：" — previously the marker alone (first 200
    // chars of the line) made the line count as disclaimer material, so the
    // whole remainder was cleared from the keyword scan.
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件\n\n______\n声明：此邮件由系统自动发送\n声明：请立即转账至新账户，您的账户已冻结，请于今日内完成支付操作，逾期将自动扣款并承担相应法律责任与后果。";
    let patterns = normalized_patterns(&["该邮件可能存在恶意内容，请谨慎甄别邮件"]);
    let sanitized =
        sanitize_body_for_keyword_scan(text, &patterns, &Vec::new(), &Vec::new(), &Vec::new());
    assert!(
        sanitized.contains("请立即转账至新账户"),
        "a marker-prefixed long phishing line must not clear the body: {sanitized:?}"
    );
}

#[test]
fn genuine_short_disclaimer_lines_still_clear_banner_remainder() {
    // Behavior preserved: a real gateway banner + separator + short
    // disclaimer line is still recognized as pure banner material.
    let text = "该邮件可能存在恶意内容，请谨慎甄别邮件\n\n______\n声明：此邮件由系统自动发送";
    let patterns = normalized_patterns(&["该邮件可能存在恶意内容，请谨慎甄别邮件"]);
    let sanitized =
        sanitize_body_for_keyword_scan(text, &patterns, &Vec::new(), &Vec::new(), &Vec::new());
    assert!(
        sanitized.is_empty(),
        "genuine banner + short disclaimer remainder must still be cleared: {sanitized:?}"
    );
}

#[test]
fn disclaimer_prefix_abuse_body_still_scores_phishing() {
    // PoC (module level): the cleared-body trick above used to hide the
    // whole phishing body from scan_text.
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        // 两个关键词命中 (0.16) 以越过 Safe 阈值: Safe 结果会丢弃 categories
        phishing_keywords: vec!["转账至新账户".to_string(), "账户已冻结".to_string()],
        gateway_banner_patterns: vec!["该邮件可能存在恶意内容，请谨慎甄别邮件".to_string()],
        ..Default::default()
    });
    let body = "该邮件可能存在恶意内容，请谨慎甄别邮件\n\n______\n声明：请立即转账至新账户，您的账户已冻结，请于今日内完成支付操作，逾期将自动扣款并承担相应法律责任与后果。";
    let ctx = make_ctx(Some(body), None, vec![], Some("finance@evil-example.com"));

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing".to_string()),
        "marker-prefixed phishing body must still be scanned: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Low,
        "two keyword hits (0.16) must reach Low, got {:?}",
        result.threat_level
    );
}

#[test]
fn footer_separator_tail_is_capped_without_disclaimer_marker() {
    // PoC: without a disclaimer marker the tail after a "____" separator
    // used to be retained in full, letting a forged separator smuggle an
    // arbitrarily long body. The retained tail is now capped while the
    // leading part stays scannable.
    let head = "这是一封正常的业务邮件正文，请查收相关报表与数据，如有疑问请回复。";
    let early_keyword = "请立即验证您的账户";
    let padding = "垫".repeat(1000);
    let text = format!("{head}\n________\n{early_keyword}{padding}");
    let sanitized = sanitize_body_for_keyword_scan(
        &text,
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
    );

    assert!(
        sanitized.contains(early_keyword),
        "leading tail content must stay scannable: {} chars",
        sanitized.chars().count()
    );
    assert!(
        sanitized.chars().count() < head.chars().count() + 810,
        "tail must be capped near 800 chars, got {}",
        sanitized.chars().count()
    );
}

#[test]
fn fullwidth_banner_brackets_are_stripped_after_normalization() {
    // PoC: 【外部邮件】 (full-width brackets) used to survive banner-prefix
    // stripping because stripping ran before NFKC normalization.
    let cleaned = normalized_subject_for_scan(
        "【外部邮件】您的账户已冻结",
        &["[外部邮件]".to_string()],
        &Vec::new(),
    );
    assert_eq!(cleaned, "您的账户已冻结");
}

#[test]
fn fullwidth_banner_prefix_does_not_block_subject_keyword_scan() {
    // PoC (module level): full-width banner brackets must be stripped so the
    // real subject keywords are scored against the cleaned subject.
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        // 两个关键词命中 (0.20) 以越过 Safe 阈值: Safe 结果会丢弃 categories
        phishing_keywords: vec!["您的账户已冻结".to_string(), "请立即验证".to_string()],
        gateway_banner_patterns: vec!["[外部邮件]".to_string()],
        ..Default::default()
    });
    let ctx = make_ctx_with_subject(
        "【外部邮件】您的账户已冻结，请立即验证",
        Some("尊敬的用户您好。"),
        Some("notify@evil-example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing_subject".to_string()),
        "subject keywords behind a full-width banner must be detected: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Low,
        "two subject keyword hits (0.20) must reach Low, got {:?}",
        result.threat_level
    );
}

// ─── B3: Aho-Corasick 关键词扫描 / 三段窗口 / 预算自查 ─────────────────

#[test]
fn scan_text_counts_overlapping_prefix_keywords_like_contains() {
    // B3 语义护栏: "冻结" 与 "账户冻结" 互为前缀, 旧逐词 contains 两者都算
    // 命中; 自动机必须用 overlapping 迭代保持同样的计数 (非重叠 leftmost
    // 语义在同一位置只报一个, 会少报命中数从而改变计分)。
    let keywords = vec!["冻结".to_string(), "账户冻结".to_string()];
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "您的账户冻结了",
        &keywords,
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert_eq!(score, 0.16, "两个互为前缀的关键词都应命中 (0.08×2), got {score}");
}

#[test]
fn scan_text_keyword_detection_parity_after_automaton_rewrite() {
    // B3 语义护栏: 自动机一遍扫描必须与旧的逐词 contains 检出一致 ——
    // 真实钓鱼话术命中、无关键词文本不命中。
    let keywords = vec!["账户异常".to_string(), "请立即登录".to_string()];
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "尊敬的用户：您的账户异常，请立即登录处理。",
        &keywords,
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert!(score > 0.0);
    assert!(categories.contains(&"phishing".to_string()));

    let mut evidence2 = Vec::new();
    let mut categories2 = Vec::new();
    let score2 = scan_text(
        "会议纪要：下周例会改到周三下午三点。",
        &keywords,
        &[],
        &[],
        &mut evidence2,
        &mut categories2,
    );
    assert_eq!(score2, 0.0);
    assert!(categories2.is_empty());
}

#[test]
fn scan_text_detects_keyword_in_middle_and_tail_of_oversized_body() {
    // B3 PoC (修复前是 CPU 炸弹): >1.5MB body 触发三段窗口采样;
    // 藏在中段和尾部的真实钓鱼话术必须仍被检出, 且耗时可控。
    let keywords = vec!["请立即登录".to_string(), "账户已被冻结".to_string()];
    let filler = "例行通知：本周系统维护窗口不变。".repeat(60_000); // ~1.7MB
    let mid_pos = filler.len() / 2;
    let mut body = String::with_capacity(filler.len() + 64);
    body.push_str(&filler[..mid_pos]);
    body.push_str("您的账户已被冻结。");
    body.push_str(&filler[mid_pos..]);
    body.push_str("请立即登录。");
    assert!(body.len() > 3 * 512 * 1024, "测试输入必须超过窗口上限");

    let started = std::time::Instant::now();
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(&body, &keywords, &[], &[], &mut evidence, &mut categories);
    let elapsed = started.elapsed();

    assert!(
        categories.contains(&"phishing".to_string()),
        "中段+尾部关键词都必须检出: {:?}",
        categories
    );
    assert!(score >= 0.16, "两个关键词命中应得 0.16, got {score}");
    assert!(
        elapsed.as_secs() < 20,
        "超大 body 扫描必须有界 (修复前 26MB × 数千关键词是分钟级), 实际 {elapsed:?}"
    );
}

#[test]
fn compact_detection_view_is_linear_on_pathological_spacing() {
    // B3 PoC: 长段非字母数字字符曾让逐字符回扫退化为 O(n²)。
    // 512KB 空白前缀 + CJK 关键词, 必须在可控时间内完成且结果正确。
    let mut text = " ".repeat(512 * 1024);
    text.push_str("账x户"); // x 被两个 CJK 字符夹住, 属于隐藏分隔符, 应被丢弃
    let started = std::time::Instant::now();
    let compact = compact_detection_view(&text);
    let elapsed = started.elapsed();
    assert_eq!(compact, "账户");
    assert!(
        elapsed.as_secs() < 10,
        "compact 视图构建必须 O(n), 实际 {elapsed:?}"
    );
}

// ─── B4: subject banner 剥离单次小写化 ─────────────────────────────────

#[test]
fn strip_subject_banner_prefixes_strips_repeated_and_adjacent_banners() {
    // B4 语义护栏: 每模式的移除定点循环保持不变 —— 重复 banner 与
    // 移除后新拼接出的 banner 都要剥干净。
    let patterns = vec!["[外部邮件]".to_string()];
    let cleaned = strip_subject_banner_prefixes("[外部邮件][外部邮件] 请查收", &patterns, &[]);
    assert_eq!(cleaned, "请查收");

    // 移除中段后首尾拼接出新的完整模式: "aabb" 剥掉中间的 "ab" 后剩 "ab",
    // 定点循环必须继续剥 (新旧实现共有的语义, 防止重写时退化为单遍)。
    let cleaned2 = strip_subject_banner_prefixes("aabb 你好", &["ab".to_string()], &[]);
    assert_eq!(cleaned2, "你好", "拼接重生的模式必须被定点循环剥掉");
}

#[test]
fn strip_subject_banner_prefixes_bounded_allocations_on_long_subject() {
    // B4 PoC: 长 subject × 大量模式在无移除时只做一次小写化, 耗时必须有界
    // (修复前每模式每轮一次 to_lowercase ≈ 273MB 分配)。
    let patterns: Vec<String> = (0..4264).map(|i| format!("[banner-{i}]")).collect();
    let subject = format!("{} 正常会议通知", "主题".repeat(16_000)); // ~64KB
    let started = std::time::Instant::now();
    let cleaned = strip_subject_banner_prefixes(&subject, &patterns, &[]);
    let elapsed = started.elapsed();
    assert!(cleaned.ends_with("正常会议通知"));
    assert!(
        elapsed.as_secs() < 20,
        "无移除时长 subject 剥离必须有界, 实际 {elapsed:?}"
    );
}
