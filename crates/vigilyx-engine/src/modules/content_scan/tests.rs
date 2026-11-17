use super::*;
use std::collections::HashSet;
use std::sync::Arc;

use crate::context::SecurityContext;
use crate::module::{SecurityModule, ThreatLevel};
use vigilyx_core::models::{EmailAttachment, EmailContent, EmailLink, EmailSession, Protocol};
use vigilyx_parser::MimeParser;

fn normalized_patterns(values: &[&str]) -> Vec<String> {
    collect_normalized_keywords(values.iter().copied())
}

#[test]
fn generic_action_link_calibration_seed_is_embedded() {
    let registry = crate::module_data::module_data();
    assert!(registry.contains(
        "external_action_link_benign_markers",
        "本邮件不含直接支付链接"
    ));
    assert!(registry.contains("external_action_link_benign_markers", "existing account"));
}

fn assert_no_scoped_collection(result: &crate::module::ModuleResult) {
    for category in ["external_action_link_lure", "pii_collection_lure"] {
        assert!(
            !result.categories.iter().any(|value| value == category),
            "{result:?}"
        );
    }
    assert_eq!(
        result.details["qualified_compounds"],
        serde_json::json!([]),
        "{result:?}"
    );
}

#[test]
fn qualified_threat_action_binds_account_request_to_observed_route() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "Account notice",
        Some("您的账户存在异常，请立即登录验证：http://203.0.113.50/verify"),
        None,
        vec![EmailLink {
            url: "http://203.0.113.50/verify".into(),
            text: None,
            suspicious: true,
        }],
        Some("notice@sender.invalid"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    let records = result.details["qualified_threat_actions"]
        .as_array()
        .unwrap();
    let record = records
        .iter()
        .find(|record| record["category"] == "account_security_phishing")
        .unwrap_or_else(|| panic!("missing bounded action certificate: {result:?}"));
    assert_eq!(record["score"], 0.65);
    assert_eq!(record["causal_key"], "host:203.0.113.50");
    assert_eq!(record["link_content_status"], "not_observed");
    assert_eq!(record["link_ownership_status"], "unknown");
    assert_eq!(record["source_part"], "plain_text");
    assert!(record.get("source_text").is_none());
    assert_eq!(record["source_text_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn qualified_threat_action_reads_html_alternative_and_resolves_actual_targets() {
    let module = seeded_content_module();
    for (html, url, host) in [
        (
            "<html><body><p>您的账户存在异常登录，请立即点击链接验证身份，24小时内未验证将冻结账户。<a href='http://203.0.113.60/verify/login'>立即验证</a></p></body></html>",
            "http://203.0.113.60/verify/login",
            "203.0.113.60",
        ),
        (
            "<html><body><base href='http://203.0.113.60/verify/'>您的帳戶已被凍結，請立即綁定手機並驗證身份，否則匯款功能將嚴重受限。<a href='login'>立即驗證</a></body></html>",
            "http://203.0.113.60/verify/login",
            "203.0.113.60",
        ),
        (
            "<html><body><p>Tài khoản của bạn sẽ bị khóa trong vòng 24 giờ. Vui lòng xác minh danh tính ngay:</p><p><a href='https://docs.google.com/url?q=http://203.0.113.60/login'>Xác minh</a></p></body></html>",
            "https://docs.google.com/url?q=http://203.0.113.60/login",
            "203.0.113.60",
        ),
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "账户安全通知",
            Some("您好，请查收通知。"),
            Some(html),
            vec![EmailLink {
                url: url.into(),
                text: None,
                suspicious: true,
            }],
            Some("notice@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        let records = result.details["qualified_threat_actions"]
            .as_array()
            .unwrap();
        let record = records
            .iter()
            .find(|record| record["category"] == "account_security_phishing")
            .unwrap_or_else(|| panic!("missing HTML bound request: {html} {result:?}"));
        assert_eq!(record["causal_key"], format!("host:{host}"));
        assert_eq!(record["source_part"], "html_visible_text");
        assert_eq!(record["link_extraction_source"], "href");
    }
}

#[test]
fn qualified_threat_action_preserves_css_projection_and_explicit_link_reference() {
    let module = seeded_content_module();
    let html = "<html><head><style>.x{font-size:0;opacity:0}</style></head><body><p>尊敬的用户：您的账<span class='x'>x</span>户存在异常，请立即点击链接完成身<span class='x'>y</span>份验证，否则账户将被冻结。</p><p><a href='https://account-check.invalid/login'>https://account-check.invalid/login</a></p></body></html>";
    let ctx = make_ctx_with_subject_and_body(
        "账户异常",
        None,
        Some(html),
        vec![EmailLink {
            url: "https://account-check.invalid/login".into(),
            text: None,
            suspicious: true,
        }],
        Some("notice@sender.invalid"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result.details["qualified_threat_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["causal_key"] == "host:account-check.invalid"),
        "{result:?}"
    );
}

#[test]
fn qualified_threat_action_binds_displayed_authentication_url_to_actual_href() {
    let module = seeded_content_module();
    let href = "https://sso.corp.internal@attacker-mail.example/login?sso=1";
    for (prefix, expected) in [
        ("域密码即将过期，请登录统一认证平台修改密码。", true),
        (
            "安全培训：下面是密码过期钓鱼案例中的示例链接，请勿登录或修改密码。",
            false,
        ),
        ("本周团建活动安排如下。", false),
    ] {
        let html =
            format!("<p>{prefix}</p><p><a href='{href}'>https://sso.corp.internal/login</a></p>");
        let ctx = make_ctx_with_subject_and_body(
            "域密码到期通知",
            None,
            Some(&html),
            vec![EmailLink {
                url: href.into(),
                text: Some("https://sso.corp.internal/login".into()),
                suspicious: true,
            }],
            Some("notice@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        let record = result.details["qualified_threat_actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["causal_key"] == "host:attacker-mail.example");
        assert_eq!(record.is_some(), expected, "{prefix} {result:?}");
        if let Some(record) = record {
            assert_eq!(
                record["link_binding_basis"],
                "displayed_url_target_mismatch"
            );
            assert_eq!(record["original_url"], href);
        }
    }
}

#[test]
fn qualified_threat_action_rejects_quotes_reports_and_unrelated_signature_links() {
    let module = seeded_content_module();
    let url = "https://account-check.invalid/login";
    for (plain, html) in [
        (
            Some(
                "您的账户存在异常，请立即点击链接验证身份。另：本周团建活动日程：https://account-check.invalid/login",
            ),
            None,
        ),
        (
            None,
            Some(
                "<p>您的账户存在异常，请立即登录验证。</p><p><a href='https://account-check.invalid/login'>无法访问</a></p>",
            ),
        ),
        (
            None,
            Some(
                "<div style='display:none'><p>您的账户存在异常，请立即登录验证。<a href='https://account-check.invalid/login'>立即验证</a></p></div><p><a href='https://account-check.invalid/login'>Company information</a></p>",
            ),
        ),
        (
            None,
            Some(
                "<p>您的账户存在异常，请立即登录验证。</p><p><a href='https://account-check.invalid/login'>firm</a></p>",
            ),
        ),
        (
            None,
            Some(
                "<q>您的账户存在异常，请立即点击链接验证身份。<a href='https://account-check.invalid/login'>立即验证</a></q>",
            ),
        ),
        (
            Some(
                "您的账户存在异常，请立即登录验证。另：本周团建活动日程：https://account-check.invalid/login",
            ),
            None,
        ),
        (
            None,
            Some(
                "<p>您的账户存在异常，请立即登录验证。另：本周团建安排见 <a href='https://account-check.invalid/login'>活动日程</a>。</p>",
            ),
        ),
        (
            Some("`您的账户存在异常，请立即登录验证：https://account-check.invalid/login`"),
            None,
        ),
        (
            Some(
                "安全培训：骗子声称您的账户存在异常，要求立即登录验证：https://account-check.invalid/login",
            ),
            None,
        ),
        (
            Some("请勿相信账户冻结通知，不要点击链接验证身份：https://account-check.invalid/login"),
            None,
        ),
        (
            None,
            Some(
                "<p>您的账户存在异常，请立即登录验证。</p><p><a href='https://account-check.invalid/login'>Company information</a></p>",
            ),
        ),
        (
            None,
            Some(
                "<blockquote><p>您的账户存在异常，请立即点击链接验证身份。<a href='https://account-check.invalid/login'>立即验证</a></p></blockquote>",
            ),
        ),
        (
            None,
            Some(
                "<div><p>您的账户存在异常，请立即点击链接验证身份。</p><p>独立的公司新闻。</p><a href='https://account-check.invalid/login'>立即验证</a></div>",
            ),
        ),
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "通知",
            plain,
            html,
            vec![EmailLink {
                url: url.into(),
                text: None,
                suspicious: true,
            }],
            Some("notice@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert_eq!(
            result.details["qualified_threat_actions"],
            serde_json::json!([]),
            "{plain:?} {html:?} {result:?}"
        );
    }
}

#[test]
fn qualified_threat_action_payment_requires_current_redirect_and_concrete_bank_destination() {
    let module = seeded_content_module();
    let action = "Our supplier changed their bank account. Any payments due must go to the new account below today:\nBeneficiary: Example Trading\nAccount No.: 6225 8812 3456 7890\nPlease process the wire transfer urgently and confirm by email. CEO Office";
    let ctx = make_ctx_with_subject_and_body(
        "Payment update",
        Some(action),
        None,
        vec![],
        Some("finance@sender.invalid"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    let records = result.details["qualified_threat_actions"]
        .as_array()
        .unwrap();
    let record = records
        .iter()
        .find(|record| record["category"] == "bec_payment_change")
        .unwrap_or_else(|| panic!("missing actual bank redirect: {result:?}"));
    assert!(record["score"].as_f64().unwrap() >= 0.65);
    assert!(
        record["causal_key"]
            .as_str()
            .unwrap()
            .starts_with("body_relation:")
    );
    assert_eq!(record["link_extraction_source"], "none");
    assert_eq!(record["coverage_reason"], "not_link_applicable");
    assert!(!record.to_string().contains("6225"));
    for body in [
        "Our supplier account changed. Please use the new account for payment today, CEO Office.\nAccount No.: 1111 2222 3333 4444\nThis is the first destination.\nAccount No.: 6225 8812 3456 7890\nPlease confirm the payment.",
        "Our supplier account changed. Please use the new account for payment today.\nAccount No.: pending; call 6225 8812 3456 7890 for details\nCEO Office",
        "Our supplier account changed. Please use the new account for payment today.\nOld bank destination:\nAccount No.: 1111 2222 3333 4444\nNew bank destination:\nAccount No.: 6225 8812 3456 7890\nCEO Office",
        "Our beneficiary account changed. Please use the new account for today's payment. CEO Office",
        "Security training: the attacker requests payments due must go to the new account. Account No.: 6225 8812 3456 7890. Do not pay.",
        "`Our beneficiary account changed. Please use the new account. Account No.: 6225 8812 3456 7890. CEO Office`",
        "Our beneficiary account changed. Please use the new account for today's payment.\nTelephone: 6225 8812 3456 7890\nCEO Office",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "Payment update",
            Some(body),
            None,
            vec![],
            Some("finance@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert_eq!(
            result.details["qualified_threat_actions"],
            serde_json::json!([]),
            "{body} {result:?}"
        );
    }
}

#[test]
fn qualified_threat_action_payment_keeps_current_target_after_quoted_account() {
    use sha2::Digest;
    let module = seeded_content_module();
    let current = "Our supplier account changed. Please use the new account for today's payment.\nAccount No.: 6225 8812 3456 7890\nPlease confirm by email. CEO Office";
    for quote in [
        "> Account No.: 1111 2222 3333 4444",
        "`Account No.: 1111 2222 3333 4444`",
    ] {
        let body = format!("{quote}\n\n{current}");
        let ctx = make_ctx_with_subject_and_body(
            "Payment update",
            Some(&body),
            None,
            vec![],
            Some("finance@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        let records = result.details["qualified_threat_actions"]
            .as_array()
            .unwrap();
        assert_eq!(records.len(), 1, "{quote} {result:?}");
        assert_eq!(
            records[0]["destination_sha256"],
            hex::encode(sha2::Sha256::digest(b"6225881234567890"))
        );
    }
}

#[test]
fn qualified_threat_action_keeps_quoted_html_banking_information_separate() {
    let module = seeded_content_module();
    let html = "<blockquote><p>Our beneficiary account changed. Please use the new account below today.</p><p>Account No.: 6225 8812 3456 7890</p><p>CEO Office</p></blockquote><p>Please read the attached audit report.</p>";
    let ctx = make_ctx_with_subject_and_body(
        "Payment review",
        None,
        Some(html),
        vec![],
        Some("finance@sender.invalid"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert_eq!(
        result.details["qualified_threat_actions"],
        serde_json::json!([]),
        "{result:?}"
    );
}

#[test]
fn qualified_threat_action_keeps_current_request_after_an_unrelated_quote() {
    let module = seeded_content_module();
    let body = "`历史样本：您的账户存在异常，请验证 https://quoted.invalid/login`\n\n您的账户存在异常，请立即登录验证：http://203.0.113.50/verify";
    let ctx = make_ctx_with_subject_and_body(
        "Account notice",
        Some(body),
        None,
        vec![EmailLink {
            url: "http://203.0.113.50/verify".into(),
            text: None,
            suspicious: true,
        }],
        Some("notice@sender.invalid"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    let records = result.details["qualified_threat_actions"]
        .as_array()
        .unwrap();
    assert_eq!(records.len(), 1, "{result:?}");
    assert_eq!(records[0]["causal_key"], "host:203.0.113.50");
}

fn external_action_lure_categories_for_stage(
    ctx: &SecurityContext,
    stage_b_enabled: bool,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    let mut compounds = Vec::new();
    super::detectors::detect_external_action_link_lure_with_stage_b(
        ctx,
        ctx.session.content.body_text.as_deref(),
        &mut score,
        &mut categories,
        &mut evidence,
        &mut compounds,
        stage_b_enabled,
    );
    (categories, compounds)
}

fn reply_to_lure_categories_for_stage(body: &str, stage_b_enabled: bool) -> Vec<String> {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".into(),
        2525,
        "192.0.2.20".into(),
        25,
    );
    session.mail_from = Some("wang.fang@corp.internal".into());
    session.rcpt_to.push("recipient@example.com".into());
    session.subject = Some("报销的单据我转给小蔡了".into());
    session.content.body_text = Some(body.into());
    session.content.headers = vec![
        ("From".into(), "Wang Fang <wang.fang@corp.internal>".into()),
        (
            "Reply-To".into(),
            "Wang Fang <wang.fang.cf@gmail-relay.example>".into(),
        ),
    ];
    let ctx = SecurityContext::with_internal_domains(
        Arc::new(session),
        Arc::new(HashSet::from(["corp.internal".to_string()])),
    );
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    super::detectors::detect_reply_to_social_engineering_lure_with_stage_b(
        &ctx,
        ctx.session.content.body_text.as_deref(),
        &mut score,
        &mut categories,
        &mut evidence,
        stage_b_enabled,
    );
    categories
}

#[test]
fn stage_b_recovers_bounded_bank_japanese_and_service_password_link_lures() {
    let cases = [
        (
            "银行预留信息维护",
            "为配合总行系统升级，请在本周五前完成预留信息核对，未核对账户升级后将无法办理转账业务。\n核对地址：http://198.51.100.77/ebank/check",
            "http://198.51.100.77/ebank/check",
            "service@ebank-notice.example",
        ),
        (
            "アカウントの確認",
            "お客様のアカウントに対して不正なログイン試行が確認されました。24時間以内に下記より本人確認を行わない場合、アカウントを停止します。\nhttp://198.51.100.78/confirm",
            "http://198.51.100.78/confirm",
            "id-manage@example-svc.example",
        ),
        (
            "积分即将清零，可兑好礼",
            "您的 8640 积分将于月底清零，兑换通道：\nhttp://198.51.100.79/s\n需核验手机服务密码完成抵扣。",
            "http://198.51.100.79/s",
            "point@svc-mall.example",
        ),
    ];

    for (subject, body, url, sender) in cases {
        let ctx = make_ctx_with_subject_and_body(
            subject,
            Some(body),
            None,
            vec![EmailLink {
                url: url.to_string(),
                text: None,
                suspicious: false,
            }],
            Some(sender),
        );

        let (baseline_categories, _) = external_action_lure_categories_for_stage(&ctx, false);
        assert!(
            !baseline_categories.contains(&"external_action_link_lure".to_string()),
            "the focused controls should exercise an additive Stage-B path: {subject}; {baseline_categories:?}"
        );

        let (candidate_categories, compounds) =
            external_action_lure_categories_for_stage(&ctx, true);
        assert!(
            candidate_categories.contains(&"external_action_link_lure".to_string())
                && candidate_categories.contains(&"phishing".to_string()),
            "Stage B should admit the same-span threat/credential request and untrusted link: {subject}; {candidate_categories:?}"
        );
        assert_eq!(compounds.len(), 1, "{subject}: {compounds:?}");
        assert_eq!(compounds[0]["actor_role"], "sender");
        assert_eq!(compounds[0]["target_role"], "recipient");
        assert_eq!(compounds[0]["speech_act"], "request");
        assert_eq!(compounds[0]["polarity"], "action");
        assert_eq!(compounds[0]["quote_or_forward_status"], "original");
        assert_eq!(compounds[0]["link_ownership_status"], "unproven");
        assert_eq!(compounds[0]["link_transport_status"], "not_attempted");
    }
}

#[test]
fn stage_b_link_window_does_not_promote_reports_unrelated_links_or_secret_mentions() {
    let controls = [
        (
            "security training",
            "セキュリティ研修の事例です。偽メール例：\n> 不正なログイン試行が確認されました。24時間以内に本人確認を行わない場合、アカウントを停止します。http://198.51.100.78/confirm\nこの例のリンクは開かず、公式ブックマークから確認してください。",
            "http://198.51.100.78/confirm",
            "notice@security-awareness.example",
        ),
        (
            "unrelated destination",
            "不正なログイン試行が確認されました。24時間以内に本人確認を行わない場合、アカウントを停止します。\n\n社内福利厚生の案内はこちら：http://198.51.100.81/guide",
            "http://198.51.100.81/guide",
            "notice@security-awareness.example",
        ),
        (
            "secret mentioned without request",
            "手机服务密码仅用于运营商官方 App 登录，请勿通过邮件提交。\n\n常规服务说明：http://198.51.100.80/terms",
            "http://198.51.100.80/terms",
            "notice@security-awareness.example",
        ),
        (
            "ambiguous Japanese access review",
            "ご利用環境の更新に伴い、登録情報の確認が必要です。現在の設定を維持するには、案内ページで本人確認を完了してください：https://account-review.example.test/status\n本日中に確認できない場合、一部の機能を一時停止することがあります。",
            "https://account-review.example.test/status",
            "notice@service-update.example",
        ),
    ];

    for (subject, body, url, sender) in controls {
        let ctx = make_ctx_with_subject_and_body(
            subject,
            Some(body),
            None,
            vec![EmailLink {
                url: url.to_string(),
                text: None,
                suspicious: false,
            }],
            Some(sender),
        );
        let (categories, compounds) = external_action_lure_categories_for_stage(&ctx, true);
        assert!(
            !categories.contains(&"external_action_link_lure".to_string())
                && !categories.contains(&"phishing".to_string()),
            "Stage B must keep scoped counter-context and unrelated/observational links below threat admission ({subject}): {categories:?}"
        );
        assert!(compounds.is_empty(), "{subject}: {compounds:?}");
    }
}

#[test]
fn known_brand_sibling_reply_to_is_not_social_engineering() {
    let body = "请立即回复本邮件，把银行卡号和密码发来，今天必须完成付款。";
    let sibling = reply_to_lure_for_pair(
        "service@rep.hundsun.cn",
        "service@hundsun.com",
        body,
    );
    assert!(
        !sibling.contains(&"external_reply_to_social_engineering".to_string()),
        "hundsun.cn and hundsun.com are the same known brand: {sibling:?}"
    );
    let unrelated = reply_to_lure_for_pair(
        "service@hundsun.com",
        "service@evil.example",
        body,
    );
    assert!(
        unrelated.contains(&"external_reply_to_social_engineering".to_string()),
        "a known brand replying to an unrelated domain still alerts: {unrelated:?}"
    );
}

#[test]
fn same_vendor_console_download_is_not_an_action_lure() {
    let body = "请非标2.0所有用户更新工作日。使用脚本下载日历配置：https://www.hs.net/online-console/downloadDetail?id=fixture";
    let ctx = make_ctx_with_subject_and_body(
        "非标2.0系统交易日历维护",
        Some(body),
        None,
        vec![EmailLink {
            url: "https://www.hs.net/online-console/downloadDetail?id=fixture".into(),
            text: Some("下载".into()),
            suspicious: false,
        }],
        Some("service@rep.hundsun.cn"),
    );
    let (categories, _) = external_action_lure_categories_for_stage(&ctx, false);
    assert!(
        !categories.contains(&"external_action_link_lure".to_string()),
        "a Hundsun console download is still the sender organization: {categories:?}"
    );

    let credential = make_ctx_with_subject_and_body(
        "账号验证",
        Some("请更新并输入系统密码：https://www.hs.net/online-console/downloadDetail?id=fixture"),
        None,
        vec![EmailLink {
            url: "https://www.hs.net/online-console/downloadDetail?id=fixture".into(),
            text: Some("登录".into()),
            suspicious: false,
        }],
        Some("service@rep.hundsun.cn"),
    );
    let (categories, _) = external_action_lure_categories_for_stage(&credential, false);
    assert!(
        categories.contains(&"external_action_link_lure".to_string()),
        "a password request on the vendor console still alerts: {categories:?}"
    );
}

fn institutional_announcement_page_is_not_an_action_lure() {
    let notice = "请非标2.0所有用户注意进行2027年工作日历维护。使用脚本“交易日历20WorkDateConfig”更新工作日。详情见 http://www.shcpe.com.cn/content/shcpe/news/announce.html?articleType=news-announce&articleId=1";
    let url = "http://www.shcpe.com.cn/content/shcpe/news/announce.html?articleType=news-announce&articleId=1";
    let ctx = make_ctx_with_subject_and_body(
        "非标2.0系统关于2027年交易日历维护的提示",
        Some(notice),
        None,
        vec![EmailLink {
            url: url.to_string(),
            text: Some("公告".to_string()),
            suspicious: false,
        }],
        Some("service@rep.hundsun.cn"),
    );
    let (categories, compounds) = external_action_lure_categories_for_stage(&ctx, false);
    assert!(
        !categories.contains(&"external_action_link_lure".to_string()),
        "a Shanghai Commercial Paper Exchange announcement is not an action lure: {categories:?} {compounds:?}"
    );

    let credential = make_ctx_with_subject_and_body(
        "账号验证",
        Some("请更新并输入系统密码：https://account-check.example/verify"),
        None,
        vec![EmailLink {
            url: "https://account-check.example/verify".to_string(),
            text: Some("登录验证".to_string()),
            suspicious: false,
        }],
        Some("notice@sender.example"),
    );
    let (categories, _) = external_action_lure_categories_for_stage(&credential, false);
    assert!(
        categories.contains(&"external_action_link_lure".to_string()),
        "a credential request on an ordinary external link still alerts: {categories:?}"
    );
}

fn reply_to_lure_for_pair(from: &str, reply_to: &str, body: &str) -> Vec<String> {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".into(),
        2525,
        "192.0.2.20".into(),
        25,
    );
    session.mail_from = Some(from.into());
    session.rcpt_to.push("recipient@example.com".into());
    session.subject = Some("付款确认".into());
    session.content.body_text = Some(body.into());
    session.content.headers = vec![
        ("From".into(), format!("Service <{from}>")),
        ("Reply-To".into(), format!("Service <{reply_to}>")),
    ];
    let ctx = SecurityContext::new(Arc::new(session));
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    super::detectors::detect_reply_to_social_engineering_lure_with_stage_b(
        &ctx,
        ctx.session.content.body_text.as_deref(),
        &mut score,
        &mut categories,
        &mut evidence,
        false,
    );
    categories
}

#[test]
fn reply_to_stage_b_recovers_local_sensitive_handoff_and_keeps_controls_safe() {
    let attack = "她说缺一份发票原件照片，你直接回她邮箱就行，纸质的我这边补。";
    let baseline = reply_to_lure_categories_for_stage(attack, false);
    assert!(
        !baseline.contains(&"external_reply_to_social_engineering".to_string()),
        "the fixture should exercise the additive Reply-To path: {baseline:?}"
    );
    let candidate = reply_to_lure_categories_for_stage(attack, true);
    assert!(
        candidate.contains(&"external_reply_to_social_engineering".to_string())
            && candidate.contains(&"phishing".to_string()),
        "an internal-looking sender routing invoice-photo handoff to an external Reply-To should be promoted: {candidate:?}"
    );

    for control in [
        "她说会议改到下午三点，请直接回她邮箱确认是否参加。",
        "> 她说缺一份发票原件照片，你直接回她邮箱就行，纸质的我这边补。\n\n以上是钓鱼样本，请勿回复或发送资料。",
    ] {
        let categories = reply_to_lure_categories_for_stage(control, true);
        assert!(
            !categories.contains(&"external_reply_to_social_engineering".to_string())
                && !categories.contains(&"phishing".to_string()),
            "ordinary routing or quoted counter-context must not be promoted: {categories:?}"
        );
    }
}

#[test]
fn scoped_compounds_do_not_read_actions_or_secrets_from_gateway_url_or_css() {
    let module = seeded_content_module();
    let html = r#"<html><head><style>.notice { content: 'open click password token'; }</style></head>
<body><p>机房及办公室卫生打扫通知：本周安排见附件，请知悉。</p>
<p>办公室联系电话：010-55550123。</p><p>公司网站：
<a href="https://gateway.example/click?open=1&amp;token=fixture&amp;url=https%3A%2F%2Fvendor.example%2F">https://vendor.example/</a></p>
<img src="https://assets.example/image.png?click=password" /></body></html>"#;
    let ctx = make_ctx_with_subject_and_body("办公室日常通知", None, Some(html), vec![
        EmailLink { url: "https://gateway.example/click?open=1&token=fixture&url=https%3A%2F%2Fvendor.example%2F".into(), text: Some("https://vendor.example/".into()), suspicious: false },
        EmailLink { url: "https://assets.example/image.png?click=password".into(), text: None, suspicious: false },
    ], Some("notice@sender.example"));
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
}

#[test]
fn scoped_compounds_keep_credential_request_on_same_gateway_link() {
    let module = seeded_content_module();
    let html = r#"<p>检测到您的企业账号异常，请点击验证并输入系统密码：
<a href="https://gateway.example/click?url=https%3A%2F%2Faccount-check.example%2Fverify">登录验证</a>。</p>"#;
    let ctx = make_ctx_with_subject_and_body(
        "账号验证",
        None,
        Some(html),
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "{result:?}"
    );
    let record = result.details["qualified_compounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["category"] == "external_action_link_lure")
        .unwrap();
    assert_eq!(record["link_extraction_source"], "href");
    assert_eq!(record["polarity"], "action");
    assert_eq!(record["quote_or_forward_status"], "original");
    assert_eq!(record["link_ownership_status"], "unproven");
    assert_eq!(record["link_transport_status"], "not_attempted");
    assert_eq!(record["score"], 0.56);
    assert_eq!(record["confidence"], 0.85);
    let causes = record["causal_keys"].as_array().unwrap();
    assert_eq!(causes.len(), 2);
    assert_ne!(causes[0], causes[1]);
    assert_eq!(causes[0], record["source_span_id"]);
    assert!(record.get("body").is_none());
}

#[test]
fn scoped_action_item_does_not_borrow_preexisting_module_score() {
    let ctx = make_ctx_with_subject_and_body(
        "账号验证",
        None,
        Some(
            r#"<p>检测到您的企业账号异常，请点击验证并输入系统密码：
<a href="https://account-check.example/verify">登录验证</a>。</p>"#,
        ),
        vec![],
        Some("notice@sender.example"),
    );
    let mut recorded = Vec::new();
    for prior_score in [0.0, 0.90] {
        let mut score = prior_score;
        let mut categories = Vec::new();
        let mut evidence = Vec::new();
        let mut compounds = Vec::new();
        super::detectors::detect_external_action_link_lure_with_stage_b(
            &ctx,
            None,
            &mut score,
            &mut categories,
            &mut evidence,
            &mut compounds,
            false,
        );
        assert!(categories.contains(&"external_action_link_lure".to_string()));
        assert!((score - prior_score - 0.56).abs() < 1e-12);
        assert_eq!(compounds.len(), 1);
        assert_eq!(compounds[0]["score"], 0.56);
        assert_eq!(compounds[0]["confidence"], 0.85);
        recorded.push(compounds.remove(0));
    }
    assert_eq!(
        recorded[0], recorded[1],
        "unrelated module score is not item evidence"
    );
}

#[test]
fn scoped_compounds_do_not_attach_report_or_invoice_actions_to_signature_links() {
    let module = seeded_content_module();
    for body in [
        "供参阅，银行固定收益日报附后。\n\n公司网站：http://vendor.example/",
        "您好，如沟通，付款申请已修改，请查收，谢谢。\n\n附件为付款申请单及电子发票，请留意查收并协调发起相关支付流程。\n\n张某\n财务部\nhttp://vendor.example/",
        "企业年检报告已完成，请查看附件。\n\n公司网站：https://gateway.example/open?url=https%3A%2F%2Fvendor.example%2F",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "业务资料",
            Some(body),
            None,
            vec![],
            Some("report@sender.example"),
        );
        assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
    }
}

#[test]
fn scoped_compounds_distinguish_recruitment_registration_from_secret_handoff() {
    let module = seeded_content_module();
    let html = r#"<p>欢迎各用人单位参加校园招聘会。参会单位请登录
<a href="https://careers.example/registration">校园招聘报名入口</a>，提交企业名称和联系方式完成报名。</p>"#;
    let ctx = make_ctx_with_subject_and_body(
        "校园招聘会邀请",
        None,
        Some(html),
        vec![],
        Some("careers@sender.example"),
    );
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
    let dangerous = html.replace("企业名称和联系方式", "企业账号密码、身份证照片和银行卡信息");
    let ctx = make_ctx_with_subject_and_body(
        "校园招聘会邀请",
        None,
        Some(&dangerous),
        vec![],
        Some("careers@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "{result:?}"
    );
    assert!(
        result
            .categories
            .contains(&"pii_collection_lure".to_string()),
        "{result:?}"
    );
}

#[test]
fn scoped_compounds_keep_never_provide_password_advice_local() {
    let module = seeded_content_module();
    let advice = "Never provide your password, security questions, verification codes, or other personal details to anyone else. You can identify a message by telephone or other ways.You should keep your email address and bank account secure.";
    let ctx = make_ctx_with_subject_and_body(
        "Fixed income daily for your review",
        Some(advice),
        None,
        vec![],
        Some("report@sender.example"),
    );
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
    let mixed =
        format!("{advice}\n\n企业账号异常，请输入密码验证：https://account-check.example/verify");
    let ctx = make_ctx_with_subject_and_body(
        "账号验证",
        Some(&mixed),
        None,
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "{result:?}"
    );
}

#[test]
fn scoped_compounds_do_not_adopt_quoted_credential_request_or_visual_destination() {
    let module = seeded_content_module();
    for html in [
        r#"<p>安全团队提供以下攻击示例。</p><blockquote>账号异常，请输入密码验证：<a href="https://account-check.example/verify">登录验证</a></blockquote>"#,
        r#"<p>账号验证提示仅供培训材料说明。</p><p><img src="https://account-check.example/verify.png" /></p><p>公司网站：<a href="https://vendor.example/">https://vendor.example/</a></p>"#,
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "安全说明",
            None,
            Some(html),
            vec![],
            Some("security@sender.example"),
        );
        assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
    }
}

#[test]
fn scoped_compounds_preserve_reply_only_sensitive_collection_provenance() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "工资卡信息核对",
        Some("财务要求核对工资卡，请直接回复本邮件提供身份证号、银行卡号和预留手机号。"),
        None,
        vec![],
        Some("payroll@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"pii_collection_lure".to_string()),
        "{result:?}"
    );
    let record = result.details["qualified_compounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["category"] == "pii_collection_lure")
        .unwrap();
    assert_eq!(record["link_extraction_source"], "none");
    assert_eq!(record["score"], 0.58);
    assert_eq!(record["confidence"], 0.85);
    assert!(
        record["reply_target"]
            .as_str()
            .unwrap()
            .starts_with("reply_target:")
    );
    assert_eq!(record["causal_keys"][1], record["reply_target"]);
}

#[test]
fn scoped_compounds_bind_reply_request_to_reply_to_header() {
    use sha2::{Digest, Sha256};
    let module = seeded_content_module();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.1".into(),
        2525,
        "192.0.2.2".into(),
        25,
    );
    session.mail_from = Some("payroll@sender.example".into());
    session.subject = Some("工资卡信息核对".into());
    session.content.body_text =
        Some("财务要求核对工资卡，请回复本邮件提供身份证号、银行卡号和预留手机号。".into());
    session.content.headers = vec![
        ("From".into(), "Payroll <payroll@sender.example>".into()),
        (
            "Reply-To".into(),
            "Records <records@collector.example>".into(),
        ),
    ];
    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
    let record = result.details["qualified_compounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["category"] == "pii_collection_lure")
        .expect("qualified reply request");
    let expected = format!(
        "reply_target:{}",
        hex::encode(Sha256::digest(b"records@collector.example"))
    );
    assert_eq!(record["reply_target"], expected);
}

#[test]
fn scoped_compounds_keep_all_sentences_of_plain_credential_quote_counter_context() {
    let module = seeded_content_module();
    let body =
        "> 旧邮件：账号存在异常。请点击验证并输入系统密码：https://account-check.example/verify";
    let ctx = make_ctx_with_subject_and_body(
        "安全团队提供攻击示例",
        Some(body),
        None,
        vec![],
        Some("security@sender.example"),
    );
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
}

#[test]
fn scoped_compounds_bind_parser_bare_domains_to_the_actual_local_request() {
    let module = seeded_content_module();
    let raw = b"From: notice@sender.example\r\nTo: recipient@example.com\r\nSubject: Account verification\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlease enter your password for account verification: account-check.example/verify\r\n";
    let content = MimeParser::new()
        .parse(raw)
        .expect("bare-domain fixture parses");
    assert!(
        content
            .links
            .iter()
            .any(|link| link.url.contains("account-check.example") && link.text.is_none()),
        "{:?}",
        content.links
    );
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.1".into(),
        2525,
        "192.0.2.2".into(),
        25,
    );
    session.mail_from = Some("notice@sender.example".into());
    session.subject = Some("Account verification".into());
    session.content = content;
    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".into()),
        "{result:?}"
    );
    assert!(
        result.details["qualified_compounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["category"] == "external_action_link_lure"
                && record["link_extraction_source"] == "plain_text")
    );

    let ctx = make_ctx_with_subject_and_body(
        "Business report",
        Some("账号核对事项见附件，请知悉。\n\n公司网站：account-check.example/verify"),
        None,
        vec![EmailLink {
            url: "https://account-check.example/verify".into(),
            text: None,
            suspicious: false,
        }],
        Some("notice@sender.example"),
    );
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
}

#[test]
fn scoped_compounds_do_not_read_actions_from_bare_link_paths() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "办公室通知",
        Some("机房清洁安排见附件，请知悉。公司网站：vendor.example/click/open/password"),
        None,
        vec![EmailLink {
            url: "https://vendor.example/click/open/password".into(),
            text: None,
            suspicious: false,
        }],
        Some("notice@sender.example"),
    );
    assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
}

#[test]
fn scoped_compounds_budget_prose_independently_of_long_gateway_parameters() {
    let module = seeded_content_module();
    let url = format!(
        "https://gateway.example/click?padding={}&url=https%3A%2F%2Faccount-check.example%2Fverify",
        "x".repeat(2048)
    );
    let body = format!("企业账号异常，请输入密码验证：{url}");
    let ctx = make_ctx_with_subject_and_body(
        "账号验证",
        Some(&body),
        None,
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".into()),
        "{result:?}"
    );
    let record = result.details["qualified_compounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["category"] == "external_action_link_lure")
        .unwrap();
    assert_eq!(record["original_url"], url);
    assert!(
        record["effective_url"]
            .as_str()
            .unwrap()
            .contains("account-check.example")
    );
}

#[test]
fn scoped_compounds_do_not_adopt_sibling_quote_or_paragraph_claims() {
    let module = seeded_content_module();
    for html in [
        r#"<div><blockquote>账号异常，请输入密码验证</blockquote><a href="https://vendor.example/">公司网站</a></div>"#,
        r#"<div><p>账号异常，请输入密码验证</p><a href="https://vendor.example/">公司网站</a></div>"#,
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "安全资料",
            None,
            Some(html),
            vec![],
            Some("notice@sender.example"),
        );
        assert_no_scoped_collection(&analyze_with_runtime(&module, &ctx));
    }
    let html = r#"<div><blockquote>历史资料仅供参考</blockquote>账号异常，请输入密码验证：<a href="https://account-check.example/verify">登录验证</a></div>"#;
    let ctx = make_ctx_with_subject_and_body(
        "账号验证",
        None,
        Some(html),
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".into()),
        "{result:?}"
    );
}

#[test]
fn scoped_compounds_keep_request_after_a_warning_url_sentence_visible() {
    let module = seeded_content_module();
    let body = "Never provide your password to anyone else: https://help.example/. Please enter your password for account verification: https://account-check.example/verify";
    let ctx = make_ctx_with_subject_and_body(
        "Account verification",
        Some(body),
        None,
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".into()),
        "{result:?}"
    );
    let records = result.details["qualified_compounds"].as_array().unwrap();
    assert!(records.iter().any(|record| {
        record["category"] == "external_action_link_lure"
            && record["effective_url"]
                .as_str()
                .unwrap()
                .contains("account-check.example")
    }));
    assert!(!records.iter().any(|record| {
        record["effective_url"]
            .as_str()
            .is_some_and(|url| url.contains("help.example"))
    }));
}

#[test]
fn scoped_compounds_distinguish_completed_upload_reports_from_current_pii_requests() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "工资卡核对记录",
        Some(
            "财务工资卡信息核对记录：员工已上传身份证号、银行卡号及预留手机号至 https://records.example/upload，核对已完成。",
        ),
        None,
        vec![],
        Some("payroll@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        !result.categories.contains(&"pii_collection_lure".into()),
        "{result:?}"
    );
    let ctx = make_ctx_with_subject_and_body(
        "工资卡信息核对",
        Some(
            "财务要求核对工资卡，请上传身份证号、银行卡号及预留手机号至 https://records.example/upload。",
        ),
        None,
        vec![],
        Some("payroll@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result.categories.contains(&"pii_collection_lure".into()),
        "{result:?}"
    );
}

#[test]
fn scoped_compounds_bound_repeated_large_html_parent_scans() {
    let module = seeded_content_module();
    let anchors = (0..128)
        .map(|index| {
            format!(r#"<a href="https://vendor.example/news/{index}">公司公告{index}</a>"#)
        })
        .collect::<String>();
    let html = format!(
        "<div>{}<blockquote>账号异常，请输入密码验证</blockquote>{anchors}</div>",
        "办公室日常通知。".repeat(55_000)
    );
    assert!(html.len() > 1024 * 1024);
    let ctx = make_ctx_with_subject_and_body(
        "日常公告",
        None,
        Some(&html),
        vec![],
        Some("notice@sender.example"),
    );
    let started = std::time::Instant::now();
    let result = analyze_with_runtime(&module, &ctx);
    assert_no_scoped_collection(&result);
    assert!(
        started.elapsed().as_secs() < 20,
        "repeated HTML blocks exceeded bounded scan time: {:?}",
        started.elapsed()
    );
}

#[test]
fn scoped_compounds_keep_identical_anchor_labels_bound_to_their_own_request() {
    let module = seeded_content_module();
    let html = r#"<div>请提交密码完成账号验证：<a href="https://account-check.example/verify">这里</a>。公司网站：<a href="https://vendor.example/">这里</a>。</div>"#;
    let ctx = make_ctx_with_subject_and_body(
        "账号核验",
        None,
        Some(html),
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    let records = result.details["qualified_compounds"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record["category"] == "external_action_link_lure"
                && record["effective_url"]
                    .as_str()
                    .unwrap()
                    .contains("account-check.example")),
        "{result:?}"
    );
    assert!(
        !records.iter().any(|record| record["effective_url"]
            .as_str()
            .is_some_and(|url| url.contains("vendor.example"))),
        "{result:?}"
    );
    assert!(
        !records
            .iter()
            .any(|record| record.to_string().contains("anchor:")),
        "internal node markers cannot persist in evidence: {records:?}"
    );
}

#[test]
fn scoped_compounds_keep_neighboring_account_threat_with_a_targeted_cta() {
    let module = seeded_content_module();
    let html = r#"<p>您的企业账号即将停用。请点击<a href="https://account-check.example/verify">这里</a>完成核验。</p>"#;
    let ctx = make_ctx_with_subject_and_body(
        "企业账号状态",
        None,
        Some(html),
        vec![],
        Some("notice@sender.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".into()),
        "{result:?}"
    );
}

#[test]
fn scoped_compounds_do_not_borrow_review_cues_for_completed_collection() {
    let module = seeded_content_module();
    for body in [
        "请查看工资卡核对记录。员工已上传身份证号和银行卡号至 https://records.example/upload。",
        "Please review the salary card verification record. Employees have uploaded identity number and bank account data to https://records.example/upload.",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "Collection record",
            Some(body),
            None,
            vec![],
            Some("payroll@sender.example"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            !result.categories.contains(&"pii_collection_lure".into()),
            "{result:?}"
        );
    }
}

fn seeded_content_module() -> ContentScanModule {
    let system_seed: KeywordOverrides = serde_json::from_str(include_str!(
        "../../../../../shared/schemas/keyword_overrides_seed.json"
    ))
    .expect("keyword override seed must parse");
    let normalized = normalize_system_keyword_seed(&system_seed);
    ContentScanModule::new_with_keyword_lists(build_effective_keyword_lists(
        &system_seed,
        &normalized,
    ))
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
fn normalize_text_folds_zh_confusable_char_variants() {
    // 形近/生僻异体字 + 词级链式折叠: 荩→尽 之后再触发 尽块→尽快 / 转帐→转账
    assert_eq!(
        normalize_text("请荩块转帐到安全账户"),
        "请尽快转账到安全账户"
    );
    assert_eq!(normalize_text("支付寳提现"), "支付宝提现");
    assert_eq!(normalize_text("貪汙洗錢案"), "贪污洗钱案");
}

#[test]
fn normalize_text_folds_zh_split_characters() {
    // 拆字拼接: 组件序列折叠回单字; 车专帐 需要两轮链式折叠
    assert_eq!(normalize_text("这是一个马扁局"), "这是一个骗局");
    assert_eq!(normalize_text("钅艮行卡已被冻结"), "银行卡已被冻结");
    assert_eq!(normalize_text("车专帐两万元"), "转账两万元");
    // 零宽插入的拆字也要拼回 (不可见字符剔除先于变体折叠)
    assert_eq!(normalize_text("马\u{200B}扁"), "骗");
}

#[test]
fn normalize_text_folds_zh_homophone_word_variants() {
    assert_eq!(normalize_text("请加V信咨询"), "请加微信咨询");
    assert_eq!(normalize_text("网袋通道秒批"), "网贷通道秒批");
    assert_eq!(normalize_text("拼夕夕砍价"), "拼多多砍价");
}

#[test]
fn normalize_text_folds_rare_traditional_and_zh_hk_lures() {
    assert_eq!(
        normalize_text("您的帳戶已被凍結，請立即綁定手機，嚴重受限，緊急處理"),
        "您的账户已被冻结,请立即绑定手机,严重受限,紧急处理"
    );
    assert_eq!(
        normalize_text("你嘅帳戶已被凍結，請立即登入驗證，唔係24小時內會被停用，快啲處理"),
        "你的账户已被冻结,请立即登入验证,否则24小时内会被停用,尽快处理"
    );
}

#[test]
fn normalize_text_keeps_legit_zh_text_stable() {
    // 词边界陷阱对照: 这些正常表述不得被折叠 (更不得造出关键词命中)
    assert_eq!(normalize_text("一块钱十块钱"), "一块钱十块钱");
    assert_eq!(normalize_text("本人责任重大"), "本人责任重大");
    assert_eq!(normalize_text("参加vip大会"), "参加vip大会");
    assert_eq!(normalize_text("tv信号良好"), "tv信号良好");
}

#[test]
fn zh_variant_folds_reach_real_seed_keywords() {
    // 折叠产物必须命中真实种子条目: 尽快 ∈ bec_local_pressure_markers,
    // 转账 相关关键词经同一 normalize 管道对正文生效。
    assert!(module_data().contains(
        "bec_local_pressure_markers",
        &normalize_text("荩块").to_lowercase()
    ));
    let folded = normalize_text("请尽块转帐到以下账户");
    assert!(folded.contains("尽快") && folded.contains("转账"));
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
        "身份证号 000000194912310027",
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
fn neutral_contract_transfer_phrase_requires_local_bec_pressure() {
    let bec = vec!["划转资金".to_string()];
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "本协议用于审查资产划转资金的法律依据、审批程序和会计处理方式。",
        &[],
        &[],
        &bec,
        &mut evidence,
        &mut categories,
    );

    assert_eq!(score, 0.0);
    assert!(
        !categories.contains(&"bec".to_string()),
        "a neutral legal noun phrase must not become standalone BEC evidence: {categories:?}"
    );
}

#[test]
fn pressured_transfer_phrase_remains_actionable_bec() {
    let bec = vec!["划转资金".to_string()];
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "请立即划转资金，并对此事严格保密。",
        &[],
        &[],
        &bec,
        &mut evidence,
        &mut categories,
    );

    assert!(score >= 0.15);
    assert!(categories.contains(&"bec".to_string()));
}

#[test]
fn generic_bec_prose_is_runtime_configured_as_weak() {
    for phrase in ["right now", "请发邮件", "严格保密"] {
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let score = scan_text(
            phrase,
            &[],
            &[],
            &[phrase.to_string()],
            &mut evidence,
            &mut categories,
        );

        assert_eq!(score, 0.0, "generic phrase must remain weak: {phrase}");
        assert!(
            !categories.contains(&"bec".to_string()),
            "generic phrase must not create BEC by itself: {phrase} {categories:?}"
        );
    }
}

#[test]
fn generic_reply_channel_phrases_are_weak_without_bec_context() {
    for phrase in [
        "reply only to this email",
        "reply directly to me",
        "please don't email back",
        "only respond to this address",
        "reply here only",
        "use this email only",
        "仅回复这封邮件",
        "直接回复给我",
        "请不要回复之前的地址",
        "仅回复此地址",
        "只用这封邮件回复",
        "使用此邮件",
    ] {
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let score = scan_text(
            phrase,
            &[],
            &[],
            &[phrase.to_string()],
            &mut evidence,
            &mut categories,
        );

        assert_eq!(
            score, 0.0,
            "generic reply-channel phrase must remain weak: {phrase}"
        );
        assert!(
            !categories.contains(&"bec".to_string()),
            "generic reply-channel phrase must not create BEC: {phrase} {categories:?}"
        );
    }
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

#[test]
fn html_alternative_account_lure_is_detected_with_untrusted_link() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some("您好，最新系统通知请见网页版。"),
        Some(
            "<p>系统检测到您的账户存在异常登录，为保障您的资金安全，请立即点击下方链接验证身份。</p>",
        ),
        vec![EmailLink {
            url: "http://203.0.113.50/verify/login".to_string(),
            text: Some("http://203.0.113.50/verify/login".to_string()),
            suspicious: true,
        }],
        Some("it-support@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "HTML-only account lure must remain visible to rule-based scanning: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn html_gateway_banner_does_not_hide_following_phishing_body() {
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        phishing_keywords: vec![
            normalize_text("账户存在异常登录"),
            normalize_text("立即点击验证"),
        ],
        gateway_banner_patterns: vec![
            normalize_text("该邮件可能存在恶意内容，请谨慎甄别邮件"),
            normalize_text("检测结果：垃圾邮件"),
        ],
        ..Default::default()
    });
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><font>检测结果：垃圾邮件。</font><div><p>账户存在异常登录，请立即点击验证。</p><a href=\"https://login.example.invalid/verify\">立即点击验证</a></div>",
        ),
        vec![EmailLink {
            url: "https://login.example.invalid/verify".to_string(),
            text: Some("立即点击验证".to_string()),
            suspicious: true,
        }],
        Some("sender@external.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .iter()
            .any(|category| { category == "phishing" || category == "account_security_phishing" }),
        "HTML gateway warning must not erase the following phishing body: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Low, "{result:?}");
}

#[test]
fn html_gateway_banner_prefix_preserves_following_body_after_tag_strip() {
    let html = "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><font>检测结果：垃圾邮件。</font><div>账户存在异常登录，请立即点击验证。</div>";
    let flattened = html_utils::strip_html_tags(html);
    let patterns = normalized_patterns(&[
        "该邮件可能存在恶意内容，请谨慎甄别邮件",
        "检测结果：垃圾邮件",
    ]);

    let sanitized = sanitize_body_for_keyword_scan(
        &flattened,
        &patterns,
        &Vec::new(),
        &Vec::new(),
        &Vec::new(),
    );

    assert!(
        sanitized.contains("账户存在异常登录"),
        "gateway notice cleanup must preserve body text after inline HTML tags; flattened={flattened:?}, sanitized={sanitized:?}"
    );
}

#[test]
fn html_gateway_subsidy_portal_lure_is_not_erased() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><font>检测结果：垃圾邮件。</font><div>关于年度社保及公积金返还事宜，推荐您进入申领系统办理领取补贴。入口：benefits-portal.example.invalid</div>",
        ),
        vec![EmailLink {
            url: "https://benefits-portal.example.invalid".to_string(),
            text: Some("benefits-portal.example.invalid".to_string()),
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "gateway banner must not erase a subsidy portal lure: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn html_gateway_subsidy_href_only_portal_lure_is_detected() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><div>关于年度社保及公积金返还事宜，推荐您进入申领系统办理领取补贴。</div><a href=\"https://benefits-portal.example.invalid/apply\">进入申领系统</a>",
        ),
        vec![EmailLink {
            url: "https://benefits-portal.example.invalid/apply".to_string(),
            text: Some("进入申领系统".to_string()),
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "an href-only subsidy portal lure must use its anchor text as body context: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn html_gateway_subsidy_decorated_anchor_text_is_detected() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><div>关于年度社保及公积金返还事宜，请进入申领系统办理。</div><a href=\"https://benefits-portal.example.invalid/apply\">🔗 进入申领系统</a>",
        ),
        vec![EmailLink {
            url: "https://benefits-portal.example.invalid/apply".to_string(),
            text: Some("🔗 进入申领系统".to_string()),
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "decorative link glyphs must not hide a subsidy portal lure: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn html_gateway_adult_phrase_remains_analyst_visible() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><font>检测结果：垃圾邮件。</font><div>免费看片</div>",
        ),
        vec![],
        Some("promo@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"adult_content_observed".to_string()),
        "gateway cleanup must preserve adult-content observations: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"adult_content_lure".to_string()),
        "an adult phrase without an independent destination is not a lure: {result:?}"
    );
}

#[test]
fn html_gateway_account_lure_with_unsuspicious_link_is_detected() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        None,
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件</p><font>检测结果：垃圾邮件。</font><div>检测到您的邮箱在新设备登录，为保护账户请完成安全验证。</div><a href=\"https://account-login.example.invalid/auth\">完成安全验证</a>",
        ),
        vec![EmailLink {
            url: "https://account-login.example.invalid/auth".to_string(),
            text: Some("完成安全验证".to_string()),
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.iter().any(|category| {
            category == "account_security_phishing"
                || category == "credential_link_lure"
                || category == "aitm_hosted_credential_lure"
        }),
        "gateway cleanup must preserve account-security lure evidence: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

fn analyze_with_runtime(module: &ContentScanModule, ctx: &SecurityContext) -> ModuleResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(module.analyze(ctx))
        .unwrap()
}

#[test]
fn content_scan_does_not_duplicate_semantic_scan_observations() {
    let module = seeded_content_module();
    let base_ctx = make_ctx_with_subject_and_body(
        "验证码",
        Some("您正在登录统一认证平台，验证码 884213，10 分钟内有效。如非本人操作请及时修改密码。"),
        None,
        vec![],
        Some("noreply@sso.corp.internal"),
    );
    let ctx = SecurityContext::with_internal_domains(
        base_ctx.session.clone(),
        Arc::new(HashSet::from(["corp.internal".to_string()])),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        result.details.get("semantic_context").is_none(),
        "semantic_scan is the canonical owner of semantic facts: {result:?}"
    );
    assert!(
        result.details.get("semantic_scenarios").is_none(),
        "content_scan must not persist duplicate semantic scenarios: {result:?}"
    );
}

#[test]
fn subthreshold_content_observation_survives_without_changing_legacy_safe_fields() {
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        phishing_keywords: vec!["账户异常".to_string()],
        ..Default::default()
    });
    let ctx = make_ctx(
        Some("关于账户异常的说明。"),
        None,
        vec![],
        Some("sender@partner.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        result.categories.is_empty(),
        "legacy categories remain empty: {result:?}"
    );
    assert!(
        result.details["observation_snapshot"]["categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "phishing")
    );
    assert!(
        result.details["observation_snapshot"]["evidence_count"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn large_plaintext_content_module_stays_within_inline_budget() {
    let module = seeded_content_module();
    let body = ("X".repeat(254) + "\r\n").repeat(1024);
    let ctx = make_ctx(Some(&body), None, vec![], Some("sender@external.example"));
    let started = std::time::Instant::now();
    analyze_with_runtime(&module, &ctx);
    assert!(
        // `cargo test` uses the debug test profile and competes with the
        // workspace's other CPU-heavy crates. Keep this as a regression guard
        // against the former unbounded scan, while leaving the production
        // module timeout at five seconds.
        started.elapsed() < std::time::Duration::from_secs(10),
        "256 KiB plain-text content scan exceeded the test-profile budget: {} ms",
        started.elapsed().as_millis()
    );
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
fn legitimate_project_weekly_report_does_not_become_collection_or_protocol_lure() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "项目周报_长安银行票据管理系统秒开业务等需求优化及系统架构改造项目_20260824-20260828",
        Some(
            "【本周进度简报】（20260824-20260828）\n项目进展：目前阶段：开发测试阶段；\n8月目标：基本完成信创环境的搭建，程序运行不报错；基本完成数据落标改造方案；\n完成与ESB间的通讯验证；完成与授信平台的通讯验证；详情见附件。\n手机 157-6920-9752，rente@chinasofti.com，www.chinasofti.com",
        ),
        None,
        vec![EmailLink {
            url: "https://www.chinasofti.com/".to_string(),
            text: Some("中软国际".to_string()),
            suspicious: false,
        }],
        Some("rente@chinasofti.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        !result
            .categories
            .contains(&"pii_collection_lure".to_string()),
        "ordinary project report must not be treated as external PII collection: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"protocol_execution_lure".to_string()),
        "ordinary engineering wording must not be treated as protocol execution: {result:?}"
    );
}

#[test]
fn routine_product_release_notice_does_not_become_external_action_lure() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "全悉情报升级包发布通知",
        Some(
            "全悉产品新发布了情报升级包全悉情报更新包-20260828103623。更新日志为：changelog。点击上方链接查看升级包详细消息，如遇其他使用问题可咨询官方技术支持。如需取消升级包发布邮件通知，可前往产品升级平台、消息通知、通知设置进行关闭。",
        ),
        None,
        vec![
            EmailLink {
                url: "https://product-support.chaitin.cn/package/detail?id=20260828103623"
                    .to_string(),
                text: Some("查看升级包详细消息".to_string()),
                suspicious: false,
            },
            EmailLink {
                url: "https://product-support.chaitin.cn/message/receive".to_string(),
                text: Some("消息通知设置".to_string()),
                suspicious: false,
            },
        ],
        Some("info@product-support.chaitin.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "routine vendor release notice must not be treated as an action-link lure: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "routine vendor release notice must not inherit the generic phishing category: {result:?}"
    );
}

#[test]
fn long_form_vendor_bulletin_with_gateway_and_asset_links_is_not_action_lure() {
    let module = seeded_content_module();
    let bulletin_body = "本期业务说明：系统根据交易所文件生成回售申报和回售撤销流水，系统会结合参数维护的值生成记录。回售转出和回售到账流水数据可以在估值系统中查看，凭证如下。上述业务流程也可登录service.hundsun.com查看智能客服，选择估值FD技能组对话。相关数据、业务处理、系统参数、债券估值和交易所规则的详细说明请参阅本公告。如有疑问，欢迎联系客服热线。\n\n本证券速报用于发布市场信息和系统操作说明，内容以业务规则、处理流程、参数说明和客服指引为主。本文同时说明交易所文件、回售日期、流水关联、凭证生成、估值方法、到账处理以及客服入口等业务细节，供相关岗位查阅。\n\n系统参数说明：业务人员可按照现有权限查看估值结果、交易日数据和回售状态，系统生成的流水用于内部核对。若发现数据差异，请按既有流程联系业务支持，由客服协助确认，按照既有业务流程处理即可。";
    let bulletin_html = format!("<html><body><p>{bulletin_body}</p></body></html>");
    let ctx = make_ctx_with_subject_and_body(
        "【证券速报】【估值系统】FD3.0关于交易所债券回售的证券速报(2026-08-28)",
        None,
        Some(&bulletin_html),
        vec![
            EmailLink {
                url: "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=https%3a%2f%2fwww.hs.net%2fonline%2dconsole%2fannouncementList&umid=fixture".to_string(),
                text: None,
                suspicious: false,
            },
            EmailLink {
                url: "https://ddei3-0-ctp.asiainfo-sec.com/wis/clicktime/v1/query?url=https%3a%2f%2fwww.hs.net%2fuplus%2dasst%2dclient%2f%23%2findex&umid=fixture".to_string(),
                text: None,
                suspicious: false,
            },
            EmailLink {
                url: "https://uplusimg.hundsun.com/img/M00/04/32/fixture.png".to_string(),
                text: None,
                suspicious: false,
            },
        ],
        Some("service@rep.hundsun.cn"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "long-form vendor bulletin with safe gateway/asset links must not be treated as an action-link lure: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "long-form vendor bulletin must not inherit the generic phishing category: {result:?}"
    );
}

#[test]
fn gateway_warning_wrapped_official_fund_report_is_not_action_lure() {
    let module = seeded_content_module();
    let body_html = r##"<p style="color:#FF0000">该邮件可能存在恶意内容，请谨慎甄别邮件，如有疑问，请联系邮件系统管理员。请注意，一定仔细核对发件人地址是否为正确地址，不要在外网电脑单击任何链接。</p><font color="#FF0000">检测结果：垃圾邮件。</font><html><body><p>您好！</p><p>基金经理报告已更新，请您查阅，谢谢。</p><p>本电子邮件由系统自动发送，请勿直接回复。如有任何问题，欢迎联系您的客户经理。</p><p>For more information, please visit <a href="https://fund.example/">https://fund.example/</a>。</p><p>------</p><p>此邮件包括附件仅发给指定收件人或机构。如您误收此邮件，请立即通过回邮发件人通知我们，并从系统删除此邮件。本邮件不构成任何投资建议。</p></body></html>"##;
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]【基金资讯】WindTalk：商品指数配置价值",
        None,
        Some(body_html),
        vec![EmailLink {
            url: "https://gateway.example/click?url=https%3A%2F%2Ffund.example%2F".to_string(),
            text: Some("https://fund.example/".to_string()),
            suspicious: false,
        }],
        Some("notice@fund.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"gateway_pre_classified".to_string()),
        "the gateway warning should remain visible as context: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "gateway warning language must not become an external action-link lure: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "a routine fund report must not inherit the generic phishing category: {result:?}"
    );
}

#[test]
fn gateway_wrapped_academic_recruitment_notice_with_visual_and_printed_urls_is_not_action_lure() {
    let module = seeded_content_module();
    let body_html = r##"<p style="color:#FF0000">该邮件可能存在恶意内容，请谨慎甄别邮件，如有疑问，请联系邮件系统管理员。请注意，一定仔细核对发件人地址是否为正确地址，不要在外网电脑单击任何链接。</p><p>检测结果：垃圾邮件。</p><h2>示例理工学院2027届毕业生秋季双选会暨宏志助航计划招聘会邀请函</h2><p>诚邀各用人单位参加学校举办的校园招聘会。参会单位通过网络进行报名，具体方法如下：登录示例理工学院就业信息网（https://careers.example.edu.cn/），按照“单位登录/注册-申请入驻-校园招聘-双选会报名”的程序完成报名。活动时间、地点、参会须知和联系方式详见本邀请函。就业指导中心欢迎各单位参加，报名不收取任何费用。</p><p><img src="https://assets.example.edu.cn/upload/image/recruitment.png" alt="招聘会信息" /></p><p>示例理工学院大学生就业指导中心</p>"##;
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]示例理工学院2027届毕业生秋季双选会招聘会邀请函",
        None,
        Some(body_html),
        vec![EmailLink {
            url: "https://assets.example.edu.cn/upload/image/recruitment.png".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("qy@mail-delivery.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"gateway_pre_classified".to_string()),
        "the gateway context should remain visible: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "an image resource plus a printed official information URL is not an action link: {result:?}"
    );
    assert!(
        result.threat_level < ThreatLevel::Medium,
        "gateway metadata and visual coverage gaps must not make a routine recruitment notice medium risk: {result:?}"
    );
}

#[test]
fn explicit_gateway_spam_result_is_retained_as_spam_classification() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]克",
        Some("该邮件可能存在"),
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件，如有疑问，请联系邮件系统管理员。请注意，一定仔细核对发件人地址是否为正确地址，不要在外网电脑单击任何链接。</p><p>检测结果：垃圾邮件。</p><p>（SKTS12 +V），..\u{3008}fapiao\u{3009}括号拼中文</p>",
        ),
        vec![],
        Some("yrnrv@llci.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"gateway_pre_classified".to_string()),
        "gateway warning should be retained in the seeded module result: {result:?}"
    );
    assert!(
        result
            .categories
            .contains(&"gateway_spam_classified".to_string()),
        "explicit gateway spam verdict must not be discarded: {result:?}"
    );
}

#[test]
fn chinese_pinyin_account_lure_aliases_are_loaded_from_seed() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "zhanghufengjie",
        Some("检测到 yichangdenglu，请 lijiyanzheng 并 qingdenglu，否则账号将被冻结。"),
        None,
        vec![EmailLink {
            url: "https://account-check.example.net/verify".to_string(),
            text: Some("chongxinrenzheng".to_string()),
            suspicious: true,
        }],
        Some("notice@external.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "Chinese pinyin account-threat/action aliases must drive the guarded account detector: {result:?}"
    );
}

#[test]
fn release_shaped_message_with_credential_or_install_action_remains_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "安全升级包发布通知",
        Some(
            "检测到您的企业账号存在异常，请立即登录验证密码并通过 https://security-update.example.net/install 下载安装包，完成安全升级。",
        ),
        None,
        vec![EmailLink {
            url: "https://security-update.example.net/install".to_string(),
            text: Some("下载安装包".to_string()),
            suspicious: true,
        }],
        Some("notice@vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "credential/install actions must defeat the routine-release veto: {result:?}"
    );
}

#[test]
fn cross_domain_sensitive_collection_remains_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "员工理赔资料补充",
        Some(
            "请提供身份证照片并上传至理赔平台 https://claims-portal.example.net/upload 完成审核。",
        ),
        None,
        vec![EmailLink {
            url: "https://claims-portal.example.net/upload".to_string(),
            text: Some("上传理赔资料".to_string()),
            suspicious: false,
        }],
        Some("claims@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"pii_collection_lure".to_string()),
        "cross-domain sensitive-field collection must remain actionable: {result:?}"
    );
}

#[test]
fn payroll_card_request_by_reply_is_detected_as_external_pii_collection() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "工资卡信息核对（本月生效）",
        Some(
            "财务要求本月重新核对工资卡，请直接回复本邮件：姓名 / 身份证号 / 银行卡号 / 预留手机号。今晚 20:00 前回复的并入本月批次，逾期顺延。",
        ),
        None,
        vec![],
        Some("payroll@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"pii_collection_lure".to_string()),
        "external payroll collection of identity and bank-card fields must be actionable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn explicit_dangerous_protocol_execution_remains_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("请复制 file://server/share/update.exe 到运行窗口执行。"),
        None,
        vec![],
        Some("support@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"protocol_execution_lure".to_string()),
        "explicit dangerous protocol plus execution instruction must remain actionable: {result:?}"
    );
}

#[test]
fn local_external_url_action_relation_detects_short_payment_lure_without_polite_marker() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "认筹享 98 折（今日登记截止）",
        Some(
            "认筹金 5 万（可退），线上登记通道：\nhttps://loupan-rc.example.info/d\n（姓名+身份证+银行卡）",
        ),
        None,
        vec![],
        Some("sales@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "a local action + external URL relation must not depend on 请/立即: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn ordinary_newsletter_download_link_without_risk_context_is_not_promoted() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("每周资讯下载：https://news.example.invalid/weekly"),
        None,
        vec![],
        Some("newsletter@publisher.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "locality without an independent risk context must remain below the lure gate: {result:?}"
    );
}

#[test]
fn same_organization_tracking_pixel_is_not_an_external_action_lure() {
    let module = seeded_content_module();
    let body_html = r#"<html><body>
<p>机构服务平台通知：</p>
<p>您好！您当前有【106】条客户问题未处理。</p>
<p>本消息来自机构服务平台，请勿回复。</p>
</body></html>
<div style="visibility:hidden"><img src="https://metrics.synthetic-vendor.example/pixel?id=fixture"></div>"#;
    let ctx = make_ctx_with_subject_and_body(
        "未处理统计工单通知",
        None,
        Some(body_html),
        vec![EmailLink {
            url: "https://metrics.synthetic-vendor.example/pixel?id=fixture".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("service@mail.synthetic-vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"html_external_visual_unresolved".to_string()),
        "external-image coverage metadata must remain visible: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "a same-organization tracking pixel is not a recipient action link: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "routine notification text must not inherit phishing from its tracking pixel: {result:?}"
    );
}

#[test]
fn same_organization_sibling_credential_lure_remains_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "企业账号异常",
        Some(
            "检测到您的企业账号存在异常，请通过 https://login.synthetic-vendor.example/verify 立即重新登录验证，并输入系统密码登录确认。",
        ),
        None,
        vec![EmailLink {
            url: "https://login.synthetic-vendor.example/verify".to_string(),
            text: Some("重新登录验证".to_string()),
            suspicious: false,
        }],
        Some("notice@mail.synthetic-vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "explicit credential requests on a sibling host must remain detectable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn routine_vendor_maintenance_with_business_archive_is_not_phishing() {
    let module = seeded_content_module();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject =
        Some("重要：【维护提示】【估值系统】交易所新竞价改造补充脚本发布".to_string());
    session.mail_from = Some("notice@vendor.example".to_string());
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = EmailContent {
        body_text: Some(
            "目前发现交易所过户文件中的成交金额存在尾差，系统处理时需要执行附件脚本。脚本执行后会自动四舍五入保留两位小数；执行后请编译无效对象并重启读数工具、中间件和客户端。该版本更新用于说明估值系统的业务流程、参数处理和支持版本，详情可查看业务说明或联系客服。".to_string(),
        ),
        links: vec![EmailLink {
            url: "https://vendor-portal.example.net/maintenance".to_string(),
            text: Some("业务说明".to_string()),
            suspicious: false,
        }],
        attachments: vec![EmailAttachment {
            filename: "20260827_interface_trade_amount_rounding.zip".to_string(),
            content_type: "application/zip".to_string(),
            size: 1_245,
            hash: "synthetic-business-package".to_string(),
            content_base64: None,
        }],
        ..Default::default()
    };

    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));

    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "routine vendor maintenance package must not be promoted as an external link lure: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "routine vendor maintenance package must not inherit phishing: {result:?}"
    );
}

#[test]
fn routine_vendor_maintenance_with_credential_request_remains_actionable() {
    let module = seeded_content_module();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject =
        Some("重要：【维护提示】【估值系统】交易所新竞价改造补充脚本发布".to_string());
    session.mail_from = Some("notice@vendor.example".to_string());
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = EmailContent {
        body_text: Some(
            "版本更新说明：请通过 https://vendor-portal.example.net/maintenance 登录企业账号并输入密码验证后，再执行附件脚本完成估值系统改造。该业务说明包含交易所文件、参数处理和支持版本信息。".to_string(),
        ),
        links: vec![EmailLink {
            url: "https://vendor-portal.example.net/maintenance".to_string(),
            text: Some("登录验证".to_string()),
            suspicious: false,
        }],
        attachments: vec![EmailAttachment {
            filename: "20260827_interface_trade_amount_rounding.zip".to_string(),
            content_type: "application/zip".to_string(),
            size: 1_245,
            hash: "synthetic-business-package".to_string(),
            content_base64: None,
        }],
        ..Default::default()
    };

    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));

    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "a credential request must defeat routine-maintenance calibration: {result:?}"
    );
}

#[test]
fn routine_vendor_maintenance_coverage_gap_is_observation_and_keeps_credential_attack() {
    let module = seeded_content_module();
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject =
        Some("重要：【维护提示】【估值系统】交易所新竞价改造补充脚本发布".to_string());
    session.mail_from = Some("notice@vendor.example".to_string());
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = EmailContent {
        body_text: Some(
            "目前发现交易所过户文件中的成交金额存在尾差，系统处理时需要执行附件脚本。脚本执行后会自动四舍五入保留两位小数；执行后请编译无效对象并重启读数工具、中间件和客户端。该版本更新用于说明估值系统的业务流程、参数处理和支持版本，详情可查看业务说明或联系客服.".to_string(),
        ),
        links: vec![EmailLink {
            url: "https://vendor-portal.example.net/maintenance".to_string(),
            text: Some("业务说明".to_string()),
            suspicious: false,
        }],
        attachments: vec![EmailAttachment {
            filename: "20260827_interface_trade_amount_rounding.zip".to_string(),
            content_type: "application/zip".to_string(),
            size: 1_245,
            hash: "synthetic-business-package".to_string(),
            content_base64: None,
        }],
        truncated: true,
        links_truncated: true,
        ..Default::default()
    };

    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session.clone())));

    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "incomplete MIME/link coverage alone cannot fabricate a recipient request: {result:?}"
    );
    assert!(result.threat_level < ThreatLevel::Medium, "{result:?}");
    session.content.body_text = Some("版本更新说明：请通过 https://vendor-portal.example.net/maintenance 登录企业账号并输入密码验证后，再执行附件脚本完成估值系统改造。".into());
    let attack = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
    assert!(
        attack
            .categories
            .contains(&"external_action_link_lure".into()),
        "a real credential request must remain actionable with incomplete coverage: {attack:?}"
    );
    assert!(attack.threat_level >= ThreatLevel::Medium, "{attack:?}");
}

#[test]
fn implicit_protocol_execution_phrase_is_actionable_without_polite_marker() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some(
            "文档已放到协同目录，直接打开编辑（保持在线）：\n\\\\doc-share.example@dav\\review\\report.docx",
        ),
        None,
        vec![],
        Some("share@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"protocol_execution_lure".to_string()),
        "a direct protocol execution phrase is recipient-directed even without 请: {result:?}"
    );
}

#[test]
fn ordinary_signature_website_and_email_are_not_hidden_external_phishing() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "服务满意度回访",
        None,
        Some(
            "<p>感谢使用本服务。</p><p style='font-family:serif;color:#000000'>企业服务热线<br>邮箱：support@sig-svc.example.info<br>官网：<a href='https://sig-svc.example.info/x'>https://sig-svc.example.info/x</a></p>",
        ),
        vec![EmailLink {
            url: "https://sig-svc.example.info/x".to_string(),
            text: Some("官网".to_string()),
            suspicious: false,
        }],
        Some("svc@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"hidden_external_action_lure".to_string()),
        "ordinary signature markup must not become a hidden-link relation: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level < ThreatLevel::Medium, "{result:?}");
}

#[test]
fn truly_hidden_external_action_anchor_remains_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "服务满意度回访",
        None,
        Some(
            "<p>服务通知：<a href='https://sig-svc.example.info/preferences' style='display:none'>退订/管理订阅</a></p>",
        ),
        vec![EmailLink {
            url: "https://sig-svc.example.info/preferences".to_string(),
            text: Some("退订/管理订阅".to_string()),
            suspicious: false,
        }],
        Some("svc@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"hidden_external_action_lure".to_string()),
        "a concretely hidden external action anchor must remain detectable: {result:?}"
    );
}

#[test]
fn hidden_offscreen_opacity_and_collapsed_details_destinations_are_actionable() {
    let module = seeded_content_module();
    let html_cases = [
        "<p>有 3 个新职位与您匹配。</p><div style='position:absolute;left:-9999px'>您的账号存在风险，请登录 https://job-sec-fix.example.vip/r 完成安全验证，否则简历将被隐藏</div>",
        "<details><summary>点击展开详情</summary><p>根据最新核对结果，您需完成身份补录：https://gg-bulu29.example.info/f</p></details>",
        "<p>地面车位改为预约制。</p><p style='opacity:0.02'>系统维护：全员需重新激活邮箱 https://corp-relay36.example/act</p>",
    ];

    for html in html_cases {
        let ctx = make_ctx_with_subject_and_body(
            "外部通知",
            None,
            Some(html),
            vec![],
            Some("notice@external-sender.example"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result
                .categories
                .contains(&"hidden_external_action_lure".to_string()),
            "concealed or collapsed local action and destination must remain related: {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    }
}

#[test]
fn completed_login_alert_with_adjacent_anti_phishing_advice_is_benign() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "账号安全提醒",
        Some("检测到异地登录已下线。请勿向任何人提供验证码。"),
        None,
        vec![],
        Some("weixin@wechat.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string())
            && !result.categories.contains(&"phishing_subject".to_string()),
        "a completed sign-out notice with adjacent anti-phishing advice is not a lure: {result:?}"
    );
    assert!(result.threat_level < ThreatLevel::Medium, "{result:?}");
}

#[test]
fn domain_expiry_with_no_payment_link_disclaimer_is_not_an_action_link_lure() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "域名 30 天后到期",
        Some(
            "example.dev 将于 30 天后到期，请及时续费避免释放。登录控制台操作；本邮件不含直接支付链接。",
        ),
        None,
        vec![EmailLink {
            // MIME parsing normalizes a bare host to HTTPS for link analysis;
            // it remains a name mentioned by the notice, not an explicit URL.
            url: "https://example.dev".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("support@registrar.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "domain renewal wording and a named domain without a direct payment URL must stay informational: {result:?}"
    );
    assert!(result.threat_level < ThreatLevel::Medium, "{result:?}");
}

#[test]
fn rare_traditional_account_lure_is_actionable_but_benign_notice_is_not() {
    let module = seeded_content_module();
    let lure = make_ctx(
        Some("您的帳戶已被凍結，請立即綁定手機並驗證身份，否則匯款功能將嚴重受限，緊急處理。"),
        None,
        vec![],
        Some("it-support@partner.example"),
    );
    let lure_result = analyze_with_runtime(&module, &lure);
    assert!(
        lure_result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "rare Traditional variants must reach the account-lure detector: {lure_result:?}"
    );
    assert!(lure_result.threat_level >= ThreatLevel::Medium);

    let benign = make_ctx(
        Some("您的帳戶資料已更新完成，無需任何操作。如有疑問請聯繫既有客服。"),
        None,
        vec![],
        Some("service@partner.example"),
    );
    let benign_result = analyze_with_runtime(&module, &benign);
    assert!(
        !benign_result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "normal Traditional status notice must not become an account threat: {benign_result:?}"
    );
    assert!(benign_result.threat_level < ThreatLevel::Medium);
}

#[test]
fn zh_hk_account_freeze_lure_is_actionable() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("你嘅帳戶已被凍結，請立即登入驗證，唔係24小時內會被停用，快啲處理。"),
        None,
        vec![],
        Some("it-support@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "zh-HK threat/action language must reach the account-lure detector: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium);
}

#[test]
fn vietnamese_thai_and_indonesian_account_paraphrases_are_actionable() {
    let module = seeded_content_module();
    for body in [
        "Tài khoản của bạn sẽ bị khóa trong vòng 24 giờ. Vui lòng xác minh danh tính ngay.",
        "บัญชีของคุณจะถูกระงับภายใน 24 ชั่วโมง โปรดยืนยันตัวตนทันที",
        "Akun Anda akan dinonaktifkan dalam 24 jam. Segera verifikasi identitas Anda.",
    ] {
        let ctx = make_ctx(Some(body), None, vec![], Some("it-support@partner.example"));
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result
                .categories
                .contains(&"account_security_phishing".to_string()),
            "language gap must be closed by content evidence: {body}; {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    }

    let benign = make_ctx(
        Some("Akun Anda berhasil diperbarui. Tidak ada tindakan yang diperlukan."),
        None,
        vec![],
        Some("service@partner.example"),
    );
    let benign_result = analyze_with_runtime(&module, &benign);
    assert!(
        !benign_result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "ordinary status notices must not be promoted: {benign_result:?}"
    );
}

#[test]
fn gift_card_procurement_with_secret_reply_is_bec_but_policy_notice_is_not() {
    let module = seeded_content_module();
    let lure = make_ctx_with_subject_and_body(
        "在吗",
        Some("帮我采购二十张一千面值的购物卡，买好转我，卡的密码拍照回复这个邮箱。"),
        None,
        vec![],
        Some("it-support@partner.example"),
    );
    let lure_result = analyze_with_runtime(&module, &lure);
    assert!(
        lure_result.categories.contains(&"bec".to_string()),
        "{lure_result:?}"
    );
    assert!(
        lure_result
            .categories
            .contains(&"bec_no_ioc_social".to_string()),
        "{lure_result:?}"
    );
    assert!(
        lure_result.threat_level >= ThreatLevel::High,
        "{lure_result:?}"
    );

    let policy = make_ctx(
        Some("安全培训：公司禁止采购购物卡，也禁止通过邮件发送卡密或密码照片。"),
        None,
        vec![],
        Some("trainer@partner.example"),
    );
    let policy_result = analyze_with_runtime(&module, &policy);
    assert!(
        !policy_result.categories.contains(&"bec".to_string()),
        "{policy_result:?}"
    );
}

#[test]
fn reply_style_document_and_biometric_collection_is_phishing() {
    let module = seeded_content_module();
    let lure = make_ctx_with_subject_and_body(
        "入职通知",
        Some("恭喜通过终面，请回复本邮件附上身份证正反面照片与人脸视频，完成入职核验。"),
        None,
        vec![],
        Some("recruit@partner.example"),
    );
    let lure_result = analyze_with_runtime(&module, &lure);
    assert!(
        lure_result.categories.contains(&"phishing".to_string()),
        "{lure_result:?}"
    );
    assert!(
        lure_result.threat_level >= ThreatLevel::High,
        "{lure_result:?}"
    );

    let policy = make_ctx_with_subject_and_body(
        "入职安全提醒",
        Some("请勿通过邮件发送身份证正反面照片或人脸视频，也请勿回复本邮件。"),
        None,
        vec![],
        Some("hr@partner.example"),
    );
    let policy_result = analyze_with_runtime(&module, &policy);
    assert!(
        !policy_result.categories.contains(&"phishing".to_string()),
        "negative policy guidance must not be promoted: {policy_result:?}"
    );
}

#[test]
fn tax_rebate_lookup_with_untrusted_bare_domain_is_subsidy_fraud() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some(
            "2026年度个税专项扣除核对已开启，符合条件可核对退回金额，入口：tax-refund-check.example.info",
        ),
        None,
        vec![EmailLink {
            url: "https://tax-refund-check.example.info".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("notice@partner.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn data_leak_real_name_reenrollment_paraphrase_is_account_lure() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("您的重要资料存在泄露风险，为避免影响使用，请尽快完成实名补录，逾期将限制相关功能。"),
        None,
        vec![],
        Some("it-support@partner.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

fn make_reply_thread_ctx(target_host: &str, include_action: bool) -> SecurityContext {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.subject = Some("Re: 采购付款安排".to_string());
    session.mail_from = Some("it-support@partner.example".to_string());
    session.rcpt_to.push("employee@corp.internal".to_string());
    session.content = EmailContent {
        body_text: Some(if include_action {
            format!("按上次沟通的口径，请查收本期安排并在线确认：\n{target_host}")
        } else {
            format!("按上次沟通的口径，请查收本期安排：\n{target_host}")
        }),
        headers: vec![
            (
                "In-Reply-To".to_string(),
                "<pur-2026@corp.internal>".to_string(),
            ),
            (
                "References".to_string(),
                "<pur-2026@corp.internal>".to_string(),
            ),
        ],
        links: vec![EmailLink {
            url: format!("https://{target_host}"),
            text: None,
            suspicious: true,
        }],
        ..Default::default()
    };
    SecurityContext::new(Arc::new(session))
}

#[test]
fn forged_reply_thread_with_bare_cross_domain_action_target_is_bec() {
    let module = seeded_content_module();
    let ctx = make_reply_thread_ctx("update-center.example.info", true);

    let result = analyze_with_runtime(&module, &ctx);
    assert!(result.categories.contains(&"bec".to_string()), "{result:?}");
    assert!(result.threat_level >= ThreatLevel::High, "{result:?}");
    assert!(result.raw_score() >= 0.75, "{result:?}");
}

#[test]
fn reply_thread_without_cross_domain_or_action_is_not_promoted() {
    let module = seeded_content_module();
    for ctx in [
        make_reply_thread_ctx("update.partner.example", true),
        make_reply_thread_ctx("update-center.example.info", false),
    ] {
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            !result.categories.contains(&"bec".to_string()),
            "reply metadata or a destination alone must not create BEC evidence: {result:?}"
        );
        assert!(result.threat_level < ThreatLevel::Medium, "{result:?}");
    }
}

#[test]
fn confusable_public_suffix_with_body_action_is_phishing() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("详情见内部通告，确认入口：security-check.cοm"),
        None,
        vec![EmailLink {
            url: "https://security-check.cοm".to_string(),
            text: None,
            suspicious: true,
        }],
        Some("it-support@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        result
            .categories
            .contains(&"obfuscated_domain_lure".to_string()),
        "{result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::High, "{result:?}");
}

#[test]
fn confusable_suffix_with_browser_open_instruction_is_phishing() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "录用通知与校样",
        Some(
            "大作已通过外审，录用通知与校样文件见编辑部系统：j-sci-papers.cοm（浏览器打开，账号为投稿邮箱）",
        ),
        None,
        vec![EmailLink {
            url: "https://j-sci-papers.cοm".to_string(),
            text: None,
            suspicious: true,
        }],
        Some("editor@j-sci.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"obfuscated_domain_lure".to_string()),
        "a bare homograph suffix paired with an explicit open instruction must be actionable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn confusable_suffix_or_action_alone_is_not_promoted() {
    let module = seeded_content_module();
    for ctx in [
        make_ctx(
            Some("详情见内部通告：security-check.cοm"),
            None,
            vec![EmailLink {
                url: "https://security-check.cοm".to_string(),
                text: None,
                suspicious: true,
            }],
            Some("it-support@partner.example"),
        ),
        make_ctx(
            Some("详情见内部通告，确认入口：security-check.com"),
            None,
            vec![EmailLink {
                url: "https://security-check.com".to_string(),
                text: None,
                suspicious: false,
            }],
            Some("it-support@partner.example"),
        ),
    ] {
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            !result
                .categories
                .contains(&"obfuscated_domain_lure".to_string()),
            "a homograph or confirmation phrase alone must not become phishing: {result:?}"
        );
    }
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
            suspicious: true,
        }],
        Some("notify@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"image_only_phishing".to_string()),
        "true short-text image lures should still be flagged: {:?}",
        result.categories
    );
    assert_eq!(result.details["score"], serde_json::json!(0.15));
    assert!(result.evidence.iter().any(|evidence| {
        evidence
            .description
            .contains("parser-marked suspicious link")
    }));
}

#[test]
fn ordinary_image_link_is_layout_observation_without_threat_score() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some("证"),
        Some(
            r#"<html><body><a href="https://notice.sender.invalid/view"><img src="https://notice.sender.invalid/banner.png" /></a></body></html>"#,
        ),
        vec![EmailLink {
            url: "https://notice.sender.invalid/view".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(
        result
            .categories
            .contains(&"image_only_layout_observed".to_string()),
        "ordinary image mail should remain visible as layout context: {:?}",
        result.categories
    );
    assert!(
        !result
            .categories
            .contains(&"image_only_phishing".to_string()),
        "ordinary image mail must not be labeled as phishing: {:?}",
        result.categories
    );
    assert_eq!(result.details["score"], serde_json::json!(0.0));
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.description.contains("body contains 1 characters")),
        "Unicode character count must not expose UTF-8 byte length: {:?}",
        result.evidence
    );
    assert!(result.summary.contains("no actionable threat evidence"));
}

#[test]
fn html_visual_text_gap_is_visible_without_threat_score() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        None,
        Some(r#"<html><body><img src="cid:notice-banner" /></body></html>"#),
        vec![],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert_eq!(result.details["score"], serde_json::json!(0.0));
    assert!(
        result
            .categories
            .contains(&"html_visual_text_uncovered".to_string()),
        "empty DOM text with an image must expose the visual-text coverage gap: {:?}",
        result.categories
    );
    assert!(result.evidence.iter().any(|item| {
        item.description
            .contains("OCR/rendered-text analysis is unavailable")
    }));
}

#[test]
fn html_visual_text_gap_ignores_non_rendered_css_text() {
    let module = ContentScanModule::new();
    for html in [
        r#"<style>.banner{background-image:url('cid:banner')}</style><div class="banner"></div>"#,
        r#"<svg><path d="M0 0"></path></svg>"#,
        r#"<canvas width="600" height="300"></canvas>"#,
    ] {
        let ctx = make_ctx(None, Some(html), vec![], Some("notice@sender.invalid"));
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"html_visual_text_uncovered".to_string()),
            "visual carrier without DOM text must expose coverage gap: html={html:?}, result={result:?}"
        );
        assert_eq!(result.details["score"], serde_json::json!(0.0));
    }
}

#[test]
fn external_visual_resource_is_coverage_gap_even_with_dom_text() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        None,
        Some(
            r#"<html><body><p>系统通知</p><img src="https://cdn.example.invalid/banner.png"></body></html>"#,
        ),
        vec![],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.details["score"], serde_json::json!(0.0));
    assert!(
        result
            .categories
            .contains(&"html_external_visual_unresolved".to_string())
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| { item.description.contains("not fetched/rendered") })
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
        Some("fixture-wps-share@qq.com"),
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
        "13000000000和测试用户的聊天记录",
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
        "项目群聊 13000000000",
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
    // A subject with a phone number and an explicit callback lure should trigger.
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "紧急通知 13000000000 请回电",
        Some("尊敬的客户，您的账户有异常。"),
        Some("notify@unknown.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phone_in_subject".to_string()),
        "Non-chat subject with phone number should trigger phone_in_subject, got categories={:?}",
        result.categories
    );
}

#[test]
fn applicant_phone_in_subject_is_business_context_not_a_lure() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject(
        "金融消费争议调处申请书 - 申请人 测试用户13000000000",
        None,
        Some("applicant@consumer.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"phone_in_subject".to_string()),
        "an applicant identifier must not be treated as a callback lure: {:?}",
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
fn verification_code_safety_warning_is_not_a_current_account_lure() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "验证码",
        Some("您正在登录统一认证平台，验证码 884213，10 分钟内有效。如非本人操作请及时修改密码。"),
        None,
        vec![],
        Some("noreply@notice.example.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "a one-time-code safety warning is not a current credential request: {result:?}"
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
fn completed_password_reset_notice_is_transactional_not_phishing() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "重置密码",
        Some("您的密码已重置成功，登录时请使用新密码。"),
        None,
        vec![],
        Some("human@amac.org.cn"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        result
            .categories
            .contains(&"transactional_notice".to_string()),
        "completed account notices must retain their non-threat classification: {result:?}"
    );
    for category in [
        "phishing",
        "phishing_subject",
        "account_security_phishing",
        "subject_account_expiry_lure",
    ] {
        assert!(
            !result.categories.iter().any(|item| item == category),
            "transactional reset notice must not emit {category}: {result:?}"
        );
    }
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
fn cn_account_security_confirmation_with_untrusted_root_token_link_is_medium() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "安全核验请求：确认您的账号登录行为",
        Some(
            "企业邮箱已启用新版账号安全认证机制。请您按页面提示完成安全状态确认，用于核实账号身份。",
        ),
        None,
        vec![EmailLink {
            url: "https://verify-account.sender.invalid/?token=FixtureToken1234567890".to_string(),
            text: Some("立即完成安全验证".to_string()),
            suspicious: false,
        }],
        Some("security@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"credential_link_lure".to_string())
            || result
                .categories
                .contains(&"account_security_phishing".to_string()),
        "account verification plus an untrusted destination must emit the named lure: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn traditional_account_threat_with_untrusted_auth_link_keeps_structural_evidence() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "帳戶安全驗證提醒",
        Some(
            "親愛的用戶：系統偵測到您的帳戶存在異常登入，為保障您的資金安全，請立即點擊下方連結驗證身分。",
        ),
        None,
        vec![EmailLink {
            url: "https://login-secure.sender.invalid/sso/login".to_string(),
            text: Some("立即驗證身分".to_string()),
            suspicious: false,
        }],
        Some("it-support@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "the recipient-facing threat/action must retain its account classification: {result:?}"
    );
    assert!(
        result
            .categories
            .contains(&"credential_link_lure".to_string()),
        "the paired untrusted auth destination must survive into final fusion: {result:?}"
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
            url: "http://xqrvptkm.sender.invalid/?m=fixture%40internal.example".to_string(),
            text: Some("查看登录详情".to_string()),
            suspicious: false,
        }],
        Some("security-center@sender.invalid"),
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
fn body_variant_new_device_login_with_security_auth_link_is_at_least_medium() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]身份验证请求已发起：请尽快确认",
        Some(
            "新设备登录提醒。系统检测到您的邮箱账号存在异常网页登录行为。根据安全策略，您的邮箱账号需完成安全认证后继续使用。",
        ),
        None,
        vec![EmailLink {
            url: "http://login-check.sender.invalid/?m=fixture%40internal.example".to_string(),
            text: Some("前往安全认证".to_string()),
            suspicious: false,
        }],
        Some("security@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "body paraphrases of new-device login lures must be classified: {:?}",
        result.categories
    );
    assert!(
        result
            .categories
            .contains(&"credential_link_lure".to_string()),
        "security-auth CTA must correlate with the untrusted destination: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "complete body/link account lure must not remain low: {result:?}"
    );
}

#[test]
fn business_income_data_subject_does_not_match_account_security_keyword_substring() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "服务单“CS-0541-2026-0178 关于银联侧分期收入数据提取”有一条新的处理记录，请关注。",
        None,
        None,
        vec![],
        Some("service@cupdata.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe);
    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "business subject must not match a threat phrase as a substring: {:?}",
        result.categories
    );
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
            url: "https://redirector.invalid/query?url=https%3A%2F%2Fquota-lure.invalid%2F%3Ftoken%3Dfixture-token"
                .to_string(),
            text: Some("立即领取 6GB 免费空间".to_string()),
            suspicious: false,
        }],
        Some("fixture-quota-lure@sender.invalid"),
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
        Some("service@vendor.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "subsidy scam subject variants should trigger subsidy_fraud even when body is empty: {:?}",
        result.categories
    );
}

#[test]
fn subsidy_external_bare_domain_portal_lure_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some(
            "关于2026年度员工福利申领通知：请登录企业福利自助系统提交申请领取补助。\n\n员工福利服务入口：benefits-portal.example.invalid",
        ),
        None,
        vec![EmailLink {
            url: "https://benefits-portal.example.invalid".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "benefit + local portal action + external bare-domain lure must be detected: {:?}",
        result.categories
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "the named compound scenario must not remain Safe/Low: {:?}",
        result
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.description.contains("subsidy_external_portal_lure")),
        "the named scenario must be visible in evidence: {:?}",
        result.evidence
    );
}

#[test]
fn subsidy_bare_domain_without_local_action_is_not_promoted() {
    let module = ContentScanModule::new();
    let ctx = make_ctx(
        Some("2026年度员工福利政策说明，相关制度请参考：benefits-portal.example.invalid。"),
        None,
        vec![EmailLink {
            url: "https://benefits-portal.example.invalid".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("newsletter@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"subsidy_fraud".to_string()),
        "a bare domain plus benefit vocabulary without a recipient action must stay non-actionable: {:?}",
        result.categories
    );
}

#[test]
fn internal_hr_portal_benefit_notice_is_not_external_portal_lure() {
    let module = ContentScanModule::new();
    let mut ctx = make_ctx(
        Some(
            "关于年度员工福利办理通知：请登录官网自助系统提交申请领取。\n\n官网：hr.corp.example.invalid",
        ),
        None,
        vec![EmailLink {
            url: "https://hr.corp.example.invalid".to_string(),
            text: None,
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );
    ctx.internal_domains = Arc::new(HashSet::from(["hr.corp.example.invalid".to_string()]));

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"subsidy_fraud".to_string()),
        "an internal HR portal must not be promoted as an external lure: {:?}",
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
        Some("fixture-training@sender.invalid"),
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
fn credit_research_terms_do_not_form_a_subsidy_fraud_compound() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "区域重点产业链风险敞口与信贷机遇研究",
        Some(
            "行业研究显示部分贷款客户出现逾期风险。\n\
             新能源项目需要评估补贴退坡后的收益缺口，信贷人员应持续跟踪。",
        ),
        None,
        vec![],
        Some("fixture-research@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"subsidy_fraud".to_string()),
        "personnel + one substantive benefit term + delinquency language is research context, not a fraud compound: {result:?}"
    );
}

#[test]
fn subsidy_fraud_does_not_borrow_distant_credit_delinquency_language() {
    let module = ContentScanModule::new();
    let body = format!(
        "存量贷款客户出现逾期风险，需要加强贷后管理。\n{}\n财政补贴和民政补贴政策退坡可能影响项目收益。",
        "产业链风险敞口研究与授信结构分析。".repeat(80)
    );
    let ctx = make_ctx_with_subject_and_body(
        "产业研究材料",
        Some(&body),
        None,
        vec![],
        Some("fixture-research@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"subsidy_fraud".to_string()),
        "urgency outside the bounded benefit context must not be borrowed: {result:?}"
    );
}

#[test]
fn local_multi_benefit_urgency_lure_remains_subsidy_fraud() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "社保补贴办理提醒",
        Some("您的社保补贴申领即将逾期，请尽快办理。"),
        None,
        vec![],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"subsidy_fraud".to_string()),
        "two substantive benefits plus local urgency must remain actionable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn anti_fraud_case_report_does_not_turn_quoted_terms_into_threat_intent() {
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        phishing_keywords: vec!["短信验证码".to_string()],
        bec_phrases: vec!["跨行转账".to_string()],
        ..EffectiveKeywordLists::default()
    });
    let ctx = make_ctx_with_subject_and_body(
        "",
        Some(
            "季度电信网络诈骗风险提示。\n\
             案例一：诈骗分子谎称受害人账户异常，诱导其立即验证身份，并套取短信验证码。\n\
             案例二：骗子冒充平台客服，诱导受害人多次跨行转账，受害人随后报警。\n\
             风险分析：以上案例用于内部反诈培训和客户风险教育。",
        ),
        None,
        vec![],
        Some("fixture-awareness@qq.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    for category in ["phishing", "bec", "account_security_phishing"] {
        assert!(
            !result.categories.iter().any(|value| value == category),
            "quoted anti-fraud case material must not create {category}: {result:?}"
        );
    }
}

#[test]
fn anti_fraud_preamble_cannot_hide_a_real_recipient_credential_request() {
    let module = ContentScanModule::new_with_keyword_lists(EffectiveKeywordLists {
        phishing_keywords: vec!["短信验证码".to_string()],
        bec_phrases: vec!["跨行转账".to_string()],
        ..EffectiveKeywordLists::default()
    });
    let ctx = make_ctx_with_subject_and_body(
        "",
        Some(
            "反诈案例提示：诈骗分子曾诱导受害人跨行转账。\n\
             您的账户异常，请立即验证，并把短信验证码发给我。",
        ),
        None,
        vec![],
        Some("fixture-lure@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"phishing".to_string()),
        "direct credential request must remain phishing evidence: {result:?}"
    );
    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "a direct account threat and CTA after the report preamble must remain detectable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn context_required_transfer_phrase_needs_local_pressure() {
    let bec = vec!["跨行转账".to_string()];
    let mut neutral_evidence = Vec::new();
    let mut neutral_categories = Vec::new();
    let neutral_score = scan_text(
        "案例记录显示受害人先后多次跨行转账，随后向警方报案。",
        &[],
        &[],
        &bec,
        &mut neutral_evidence,
        &mut neutral_categories,
    );
    assert_eq!(neutral_score, 0.0);
    assert!(!neutral_categories.contains(&"bec".to_string()));

    let mut lure_evidence = Vec::new();
    let mut lure_categories = Vec::new();
    let lure_score = scan_text(
        "请立即跨行转账，今天完成且不要告诉其他人。",
        &[],
        &[],
        &bec,
        &mut lure_evidence,
        &mut lure_categories,
    );
    assert!(lure_score > 0.0);
    assert!(lure_categories.contains(&"bec".to_string()));
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
            url: "https://github-jp.invalid/account/update".to_string(),
            text: Some("お支払い方法を更新".to_string()),
            suspicious: false,
        }],
        Some("fixture-icloud-lure@sender.invalid"),
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
        "[注意风险邮件]开增值税普票加Q:10000000测试客服 +微test_contact",
        Some("开电子普票加Q-10000000测试客服 +微test_contact"),
        None,
        vec![],
        Some("fixture-invoice-lure@sender.invalid"),
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
fn invoice_spam_pinyin_in_angle_brackets_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "资料办理通知",
        Some("<fapiao> 可开专票，加微信 13800138000。"),
        None,
        vec![],
        Some("fixture-invoice-pinyin@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "invoice pinyin inside angle brackets should hit the managed keyword list: {:?}",
        result.categories
    );
}

#[test]
fn invoice_offer_with_obfuscated_wechat_and_mobile_is_invoice_fraud() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "linshan",
        Some(
            "客户您好：本公司可开正规增值税票 电子普票（全）国各地各行业可开。\n\n需要请+薇信：19865914215 秀子",
        ),
        None,
        vec![],
        Some("snxvrvc@gmailqq.com"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_fraud".to_string()),
        "invoice offer + obfuscated WeChat CTA + mobile number must be actionable: {result:?}"
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "the named invoice-fraud compound must not remain Safe/Low: {result:?}"
    );
}

#[test]
fn contextual_wechat_phone_invoice_solicitation_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "-开-普-通-漂",
        Some("可开普通漂 专用增值税\n实体经营，验后付；\n微信: 13000000000 测试会计"),
        None,
        vec![],
        Some("fixture-contextual-invoice-lure@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "invoice offer + payment condition + contextual WeChat phone must be detected: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn contextual_wechat_invoice_compound_requires_two_solicitation_cues_and_phone() {
    let module = ContentScanModule::new();
    for body in [
        "电子增值税发票可开具。如有疑问请联系测试会计，微信: 13000000000。",
        "可开增值税专票，验后付；微信: 测试财务服务号。",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "示例发票通知",
            Some(body),
            None,
            vec![],
            Some("billing@vendor.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"invoice_spam".to_string()),
            "partial contextual-contact compounds must remain benign: body={body} result={result:?}"
        );
    }
}

#[test]
fn obfuscated_subject_contact_lure_is_detected_without_invoice_keyword() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]VT （发Q-10000000 嘌 测试客服 ） 加微test_contact 合成干扰文本",
        None,
        None,
        vec![],
        Some("fixture-contact-lure@sender.invalid"),
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
        "Q-10000000 业务资料",
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
        "发Q-10000000 加微联系",
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
        "[注意风险邮件]21:12\"正▎规▎税 票\"(“扣扣-10000000测试客服) +微test_contact",
        Some("正 规 税 票，扣扣10000000，测试客服，+微test_contact"),
        None,
        vec![],
        Some("fixture-obfuscated-invoice@sender.invalid"),
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
fn homophone_invoice_and_adjacent_wechat_lure_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "FixtureToken 普通发 票 FixtureRef",
        Some("Fixture实体 普通嘌\n加微；tu80064（测试客服）"),
        None,
        vec![],
        Some("invoice-offer@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "homophone invoice wording plus an adjacent off-platform CTA must be detected: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn adult_lure_with_chinese_dot_domain_is_detected() {
    let module = ContentScanModule::new();
    for body in [
        "免费抖阴132456点cc",
        "美女视频132456点cc",
        "91看片132456点cc",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "fixture-recipient",
            Some(body),
            None,
            vec![],
            Some("notify-fixture@sender.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"obfuscated_domain_lure".to_string()),
            "adult lure plus an obfuscated destination must be detected: body={body} result={result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    }
}

#[test]
fn adult_or_domain_observation_alone_is_not_a_threat() {
    let module = ContentScanModule::new();
    for body in [
        "美女视频制作课程，请在内部学习平台查看。",
        "活动编号132456点cc，请核对记录。",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "Synthetic benign notice",
            Some(body),
            None,
            vec![],
            Some("notice@vendor.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"obfuscated_domain_lure".to_string()),
            "both independent inputs are required: body={body} result={result:?}"
        );
    }
}

#[test]
fn standalone_adult_phrase_is_visible_without_becoming_threat_evidence() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Synthetic content notice",
        Some("本合成样本包含色情视频字样，但没有链接、联系方式或操作指令。"),
        None,
        vec![],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert_eq!(result.details["score"], serde_json::json!(0.0));
    assert!(
        result
            .categories
            .contains(&"adult_content_observed".to_string()),
        "standalone adult wording must remain analyst-visible: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"adult_content_lure".to_string())
    );
}

#[test]
fn adult_phrase_with_external_destination_is_low_weight_lure() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Synthetic viewing invitation",
        Some("色情视频，立即观看。"),
        None,
        vec![EmailLink {
            url: "https://watch-target.invalid/view".to_string(),
            text: Some("立即观看".to_string()),
            suspicious: false,
        }],
        Some("promo@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"adult_content_lure".to_string()),
        "adult phrase plus an external destination must be surfaced: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"adult_content_observed".to_string())
    );
    assert_eq!(result.details["score"], serde_json::json!(0.24));
    assert_eq!(result.threat_level, ThreatLevel::Low, "{result:?}");
}

#[test]
fn generic_urgency_and_action_are_observation_only_without_target() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Synthetic schedule notice",
        Some("仅限今天，请联系项目秘书确认会议安排。"),
        None,
        vec![],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        result
            .categories
            .contains(&"generic_lure_observed".to_string()),
        "generic urgency/action must remain visible without a target: {result:?}"
    );
    assert_eq!(result.details["score"], serde_json::json!(0.0));
}

#[test]
fn complete_empty_message_is_observed_but_incomplete_message_is_coverage_only() {
    let module = ContentScanModule::new();
    let mut complete = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    complete.mail_from = Some("empty@sender.invalid".to_string());
    complete.content.is_complete = true;
    complete.content.raw_size = 42;
    complete
        .content
        .headers
        .push(("Subject".to_string(), "Synthetic empty body".to_string()));
    let complete_result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(complete)));
    assert!(
        complete_result
            .categories
            .contains(&"empty_body_observed".to_string())
    );
    assert_eq!(complete_result.details["score"], serde_json::json!(0.0));

    let incomplete = make_ctx(None, None, vec![], Some("empty@sender.invalid"));
    let incomplete_result = analyze_with_runtime(&module, &incomplete);
    assert!(
        !incomplete_result
            .categories
            .contains(&"empty_body_observed".to_string())
    );
}

#[test]
fn russian_account_lure_can_span_adjacent_body_segments() {
    let module = ContentScanModule::new();
    let body = concat!(
        "Мы обнаружили подозрительный вход в вашу учётную запись.\n\n",
        "Проверьте настройки безопасности и подтвердите свою учётную запись,\n",
        "затем немедленно войдите в систему.\n\n",
        "https://account-verify.example.invalid/sso/login"
    );
    let ctx = make_ctx_with_subject_and_body(
        "Synthetic security notice",
        Some(body),
        None,
        vec![EmailLink {
            url: "https://account-verify.example.invalid/sso/login".to_string(),
            text: Some("войдите в систему".to_string()),
            suspicious: false,
        }],
        Some("sender@partner.example"),
    );

    assert!(
        crate::matcher::account_security_threats()
            .is_match("Мы обнаружили подозрительный вход в вашу учётную запись")
    );
    assert!(
        crate::matcher::account_security_actions().is_match("затем немедленно войдите в систему")
    );

    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();
    super::detectors::detect_account_security_phishing(
        &ctx,
        Some(body),
        &mut score,
        &mut categories,
        &mut evidence,
        &mut Vec::new(),
    );
    assert!(
        categories.contains(&"account_security_phishing".to_string()),
        "direct account detector output: score={score} categories={categories:?} evidence={evidence:?}"
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "adjacent Russian threat/action segments must remain detectable: {result:?}"
    );
}

#[test]
fn russian_account_lure_with_intervening_security_lines_is_detected() {
    let module = ContentScanModule::new();
    let body = concat!(
        "Внимание! Мы обнаружили подозрительный вход в вашу учётную запись.\n\n",
        "Проверьте свои настройки безопасности и подтвердите свою учётную запись,\n",
        "иначе учётная запись будет заблокирована в течение 24 часов.\n",
        "Подтвердите личность немедленно: войдите в систему и введите пароль,\n",
        "затем проверьте свой пароль в настройках безопасности:\n\n",
        "https://account-verify.example.invalid/sso/login\n\n",
        "Служба безопасности корпоративной сети"
    );
    let ctx = make_ctx_with_subject_and_body(
        "Notification",
        Some(body),
        None,
        vec![EmailLink {
            url: "https://account-verify.example.invalid/sso/login".to_string(),
            text: None,
            suspicious: true,
        }],
        Some("sender@partner.example"),
    );
    let result = analyze_with_runtime(&module, &ctx);
    assert!(
        crate::matcher::account_security_threats()
            .is_match("Внимание! Мы обнаружили подозрительный вход в вашу учётную запись.")
    );
    assert!(
        crate::matcher::account_security_actions()
            .is_match("Подтвердите личность немедленно: войдите в систему и введите пароль,")
    );
    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "full Russian lure must be detected: {result:?}"
    );
}

#[test]
fn bracketed_contact_id_plus_v_invoice_lure_is_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "随机短主题",
        Some("15时41分11秒\n实体/发/票&lt;AB12CD &gt;&nbsp;&nbsp;+V&nbsp;&nbsp;15时41分11秒"),
        Some("<p>15时41分11秒</p><p>实体/发/票<strong>&lt;AB12CD &gt;&nbsp;&nbsp;+V</strong></p>"),
        vec![],
        Some("fixture-invoice-lure@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "bracketed contact ID followed by +V must recover the invoice lure: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn plus_v_invoice_recovery_requires_complete_compound_shape() {
    let module = ContentScanModule::new();
    for body in [
        "示例电子发票版本 V2，订单编号 AB12CD。",
        "示例电子发票 +V",
        "示例电子发票 <VERSION> +V",
        "示例电子发票 <123456> +V",
        "示例电子发票 <AB12CD> +V2",
    ] {
        let ctx = make_ctx_with_subject_and_body(
            "示例发票通知",
            Some(body),
            None,
            vec![],
            Some("billing@vendor.invalid"),
        );
        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"invoice_spam".to_string()),
            "partial +V/contact-ID shapes must remain benign: body={body} result={result:?}"
        );
    }
}

#[test]
fn malformed_invoice_contact_id_policy_fails_closed() {
    assert!(
        detectors::parse_invoice_contact_id_policy(serde_json::json!({
            "enabled": true,
            "marker_list": "invoice_spam_contact_id_suffix_markers",
            "result_category": "invoice_spam",
            "min_id_chars": 6,
            "max_id_chars": 4,
            "max_marker_gap_chars": 8,
            "require_ascii_letter": true,
            "require_ascii_digit": true,
            "score": 0.52,
            "wrappers": [{"open": "<", "close": ">"}]
        }))
        .is_none()
    );
}

#[test]
fn malformed_obfuscated_domain_lure_policy_fails_closed() {
    assert!(
        detectors::parse_obfuscated_domain_lure_policy(serde_json::json!({
            "enabled": true,
            "lure_list": "obfuscated_domain_lure_phrases",
            "separator_list": "obfuscated_domain_lure_separators",
            "tld_list": "obfuscated_domain_lure_tlds",
            "result_category": "obfuscated_domain_lure",
            "min_label_chars": 12,
            "max_label_chars": 4,
            "require_digit": true,
            "score": 0.58
        }))
        .is_none(),
        "invalid bounds must disable only the additive compound path"
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
fn legitimate_invoice_notice_with_service_phone_is_not_invoice_spam() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "示例旅行服务电子报销凭证",
        Some(
            "您的电子报销凭证已经开具，可在订单中心下载。如有疑问请联系客户经理，联系电话 13000000000。",
        ),
        None,
        vec![],
        Some("notify@travel-service.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"invoice_spam".to_string()),
        "invoice delivery plus a service phone is not off-platform solicitation: {:?}",
        result.categories
    );
}

#[test]
fn commented_invoice_template_qr_copy_is_not_semantic_evidence() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "电子发票已开具",
        None,
        Some(
            r#"<html><body>
                <p>尊敬的顾客，您好！</p>
                <!--
                <p>您的电子发票已经开具成功，请点击下方链接或扫描二维码下载并查看您的发票：</p>
                <a th:href="${links}"></a>
                <p>此领票码将于30日后失效请尽快扫码领票。</p>
                <img class="invoice-qr" th:src="${qrCode}" alt="">
                -->
                <p>发票信息如下：销方名称：示例药房；合计金额：266.00。</p>
            </body></html>"#,
        ),
        vec![],
        Some("billing@vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
    assert!(
        !result.categories.contains(&"qr_text_lure".to_string()),
        "inactive template QR copy must not become quishing evidence: {result:?}"
    );
    assert!(
        !result
            .categories
            .contains(&"generic_lure_observed".to_string()),
        "inactive template urgency/action copy must not become a generic lure: {result:?}"
    );
}

#[test]
fn active_plaintext_qr_invoice_lure_remains_detectable() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "电子发票扫码查验",
        Some("您的电子发票已开具，请使用微信扫描下方二维码查验并保存。二维码7日内有效。"),
        None,
        vec![],
        Some("invoice@sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"qr_text_lure".to_string()),
        "active plain-text QR invoice lure must remain detectable: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn invoice_reply_with_repeated_business_signature_contacts_is_not_invoice_spam() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Re: 示例机构2026年第二季度账单",
        Some(
            "尊敬的客户您好：\n附件为电子版发票和账单，请您查收，谢谢！\n\n祝：工作顺利！\n\
             测试联系人 示例事业部\n示例科技有限公司\n电话：[SERVICE_PHONE]\n\
             手机（微信）：[MESSAGING_ID]\nQQ ：[MESSAGING_ID]\n\n-----原始邮件-----\n\
             附件为贵司2026年第二季度账单，烦请查收。\n手机（微信）：[MESSAGING_ID]\nQQ：[MESSAGING_ID]",
        ),
        None,
        vec![],
        Some("account.manager@vendor.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result.categories.contains(&"invoice_spam".to_string()),
        "invoice delivery and repeated signature labels are not an off-platform solicitation: {result:?}"
    );
}

#[test]
fn invoice_solicitation_and_contact_action_on_adjacent_lines_stays_detected() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "增值税专票服务",
        Some("可代开增值税专票\n请加QQ [CONTACT_ID] 联系办理"),
        None,
        vec![],
        Some("billing-offer@external.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(result.categories.contains(&"invoice_spam".to_string()));
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn gateway_prefixed_fragmented_invoice_solicitation_stays_detected() {
    let module = seeded_content_module();
    let plain = "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n检测结果：垃圾邮件。\n可办普通漂 专用增值税\r\n实体经营，验后付；\r\n微信: 13800000000&nbsp;&nbsp;&nbsp; 示例联系人";
    let sanitized = sanitize_body_for_keyword_scan(
        plain,
        &module.gateway_banner_patterns,
        &module.notice_banner_patterns,
        &module.dsn_patterns,
        &module.auto_reply_patterns,
    );
    assert!(
        sanitized.contains("可办普通漂"),
        "gateway cleanup erased the synthetic fixture body: {sanitized:?}"
    );
    let ctx = make_ctx_with_subject_and_body(
        "[注意风险邮件]-代-开-普-通-漂",
        Some(plain),
        Some(
            "<p>该邮件可能存在恶意内容，请谨慎甄别邮件。</p><font>检测结果：垃圾邮件。</font><p>可办普通漂 专用增值税</p><p>实体经营，验后付；</p><p>微信: 13800000000 示例联系人</p>",
        ),
        vec![],
        Some("fixture-invoice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result.categories.contains(&"invoice_spam".to_string()),
        "a gateway banner must not erase the fragmented invoice solicitation: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn gateway_inserted_units_do_not_split_fragmented_invoice_compound() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "[External notice] document service",
        Some(
            "This external message was inspected.\n可办普通漂 专用增值税\n示例分隔行\n实体经营，验后付\n微信: 13800000000 示例联系人",
        ),
        None,
        vec![],
        Some("fixture-offer@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);
    assert!(result.categories.contains(&"invoice_spam".to_string()));
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn raw_body_fallback_recovers_compound_omitted_from_primary_scan_view() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "[External notice] document service",
        Some(
            "Synthetic inspection notice.\n可开普通漂 专用增值税\n实体经营，验后付\n微信: 13800000000 示例联系人",
        ),
        None,
        vec![],
        Some("fixture-fallback@sender.invalid"),
    );
    let mut score = 0.0;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();

    detectors::detect_invoice_spam(
        &ctx,
        Some("Synthetic primary scan view without the solicitation."),
        &module.gateway_banner_patterns,
        &module.notice_banner_patterns,
        &mut score,
        &mut categories,
        &mut evidence,
    );

    assert!(categories.contains(&"invoice_spam".to_string()));
    assert!(score >= 0.62, "score={score} evidence={evidence:?}");
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
fn paraphrased_remittance_change_with_new_destination_instruction_is_bec() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Payment run today",
        Some(
            "Hi,\n\nThe supplier sent revised remittance details this morning — the old coordinates are void. Today's run must use the new ones:\n\nBeneficiary: Pacific Trade Ltd\nIBAN: GB29 NWBK 6016 1331 9268 19\n\nConfirm once the transfer is queued; I'm airborne most of the day.\n\n— CFO office",
        ),
        None,
        vec![],
        Some("it-support@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "paraphrased payment destination change should be detected: {result:?}"
    );
    assert!(
        result.threat_level >= ThreatLevel::Medium,
        "payment destination change must not remain below quarantine: {result:?}"
    );
}

#[test]
fn revised_remittance_reference_without_redirect_is_not_bec() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Remittance details for the archive",
        Some(
            "The supplier sent revised remittance details for our records. Today's payment run will use the approved beneficiary already on file; no destination change is requested.",
        ),
        None,
        vec![],
        Some("notice@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "reference-only remittance details must not become BEC: {result:?}"
    );
    assert!(
        result.threat_level <= ThreatLevel::Low,
        "reference-only remittance details must stay below quarantine: {result:?}"
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
fn explicit_new_account_redirect_phrases_cover_supplier_and_split_payment_bec() {
    let module = seeded_content_module();
    for (subject, body) in [
        (
            "收款账户变更说明（华信贸易）",
            "因公司开户行网点撤并，自本月 20 日起货款请汇至：户名：华信国际贸易有限公司，账号：6225 8817 3392 0041，开户行：中信银行杭州分行营业部。原账户同日作废，请更新应付资料并回复确认，谢谢。",
        ),
        (
            "模具款拆两笔支付的通知",
            "按与供应商最新约定，模具款拆两笔：首笔 60% 付新账户，尾款 40% 付原账户。新账户资料在其邮件里，今天先出首笔。",
        ),
    ] {
        let ctx = make_ctx_with_subject_and_body(
            subject,
            Some(body),
            None,
            vec![],
            Some("ap-share@partner.example"),
        );
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result
                .categories
                .contains(&"bec_payment_change".to_string()),
            "an explicit destination replacement must be classified as payment-change BEC: {result:?}"
        );
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    }
}

#[test]
fn routine_fee_deduction_notice_with_conditional_account_update_is_not_payment_change_bec() {
    let module = ContentScanModule::new();
    let ctx = make_ctx_with_subject_and_body(
        "Custody fee deduction completed notice",
        None,
        Some(
            "<p>我司已完成产品相关费用的扣划，请知悉并关注贵司费用收款账户的资金到账情况。</p>\
             <p>以上信息仅表示所述费用已从托管户划出，并不作为收款方账户收妥入账的依据。</p>\
             <p>如贵司产品存在尚未支付的自动费用，请检查托管户余额和收款方账户信息。</p>\
             <p>如相关收款账户信息已更改，请及时在管理人服务平台修改账户收款账户。</p>\
             <p>账户划款→付费指令→自动扣费；如需恢复支付，可在平台申请立即恢复支付。</p>",
        ),
        vec![EmailLink {
            url: "https://portal.sender.invalid/fees".to_string(),
            text: Some("管理人服务平台".to_string()),
            suspicious: false,
        }],
        Some("notice@sender.invalid"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"bec_payment_change".to_string()),
        "conditional account-maintenance wording must not become payment-change BEC: {result:?}"
    );
    assert!(
        result.threat_level <= ThreatLevel::Low,
        "routine fee deduction notice must not reach Medium from account metadata: {result:?}"
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
    assert!(
        score > 0.0,
        "hidden single-letter separator must not erase CJK hits"
    );
    assert!(categories.contains(&"phishing".to_string()));
}

#[test]
fn scan_text_recovers_a_two_letter_css_hidden_separator_between_cjk_keyword_chars() {
    let mut evidence = Vec::new();
    let mut categories = Vec::new();
    let score = scan_text(
        "您的账 kq 户存在异常，请立即登录",
        &["账户存在异常".to_string(), "请立即登录".to_string()],
        &[],
        &[],
        &mut evidence,
        &mut categories,
    );
    assert!(
        score > 0.0,
        "hidden two-letter separator must not erase CJK hits"
    );
    assert!(categories.contains(&"phishing".to_string()));
}

#[test]
fn compact_detection_view_keeps_three_letter_runs() {
    assert_eq!(compact_detection_view("账kq户"), "账户");
    assert_eq!(compact_detection_view("账kqx户"), "账kqx户");
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
        Some("attacker@evil.invalid"),
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
        Some("attacker@evil.invalid"),
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
    let ctx = make_ctx(Some(body), None, vec![], Some("attacker@evil.invalid"));
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
            url: "https://industry-association.invalid/event".to_string(),
            text: Some("立即报名".to_string()),
            suspicious: false,
        }],
        Some("info@industry-association.invalid"),
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
        "紧急通知 １３０００００００００ 请回电",
        Some("尊敬的客户，您的账户有异常。"),
        Some("notify@unknown.invalid"),
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
    let body = "请联系 １３０００００００００ 或 １３１００００００００ 办理退款。";
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
    assert_eq!(
        normalize_text("账\u{FFF9}户\u{FFFA}存在\u{FFFB}异常登录"),
        "账户存在异常登录"
    );
}

#[test]
fn normalize_text_decomposes_latin_diacritics() {
    assert_eq!(
        normalize_text("vérify yóur àccount immediately"),
        "verify your account immediately"
    );
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
        Some("attacker@evil.invalid"),
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

    let interlinear_ctx = make_ctx(
        Some("您的账\u{FFF9}户\u{FFFA}存在\u{FFFB}异常，请立即验\u{FFF9}证。"),
        None,
        vec![],
        Some("attacker@evil.invalid"),
    );
    let interlinear_result = analyze_with_runtime(&module, &interlinear_ctx);
    assert!(
        interlinear_result
            .categories
            .contains(&"phishing".to_string()),
        "interlinear annotation controls must not split configured account/action keywords: {:?}",
        interlinear_result.categories
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
        &["请立即验证您的账户".to_string(), "账户已被冻结".to_string()],
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

    assert_eq!(
        score, 0.0,
        "English prose must not compact-match, got {score}"
    );
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
    let ctx = make_ctx(Some(body), None, vec![], Some("finance@evil.invalid"));

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
    let sanitized =
        sanitize_body_for_keyword_scan(&text, &Vec::new(), &Vec::new(), &Vec::new(), &Vec::new());

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
        Some("notify@evil.invalid"),
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
    assert_eq!(
        score, 0.16,
        "两个互为前缀的关键词都应命中 (0.08×2), got {score}"
    );
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

#[test]
fn reverse_context_does_not_suppress_an_unrelated_direct_account_request() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("安全培训：诈骗案例，请勿回复本邮件。\n检测到您的账户存在异常登录，请立即登录验证。"),
        None,
        vec![],
        Some("notice@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "a direct request in another span must remain detectable: {result:?}"
    );
}

#[test]
fn reverse_context_suppresses_only_reported_account_instructions() {
    let module = seeded_content_module();
    let ctx = make_ctx(
        Some("安全培训：诈骗案例，请勿回复本邮件。攻击者会要求立即验证账户。"),
        None,
        vec![],
        Some("notice@partner.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"account_security_phishing".to_string()),
        "reported/training text must not become a current account lure: {result:?}"
    );
}

#[test]
fn official_manual_entry_notice_is_not_an_external_action_lure() {
    let module = seeded_content_module();
    let body = "数据出境安全评估申报材料补正通知。贵司申报材料已完成初审，现告知需要补正的事项、申报编号和办理期限。请通过浙江政务服务网在线提交，操作方式是在浏览器中手动输入 www.zjzwfw.gov.example，使用法人账号登录，在我的办件中找到对应编号并上传补正材料。重要提示：政务服务网是唯一的官方申报渠道，我办不会通过邮件链接收取任何申报材料，不会索要企业账号密码，不会要求在非政务域名网站上传任何数据。如收到此类邮件请视为假冒并举报。该通知仅用于说明补正流程、材料目录、截止时间和咨询渠道。";
    let ctx = make_ctx_with_subject_and_body(
        "关于数据出境安全评估申报材料的补正通知",
        Some(body),
        None,
        vec![EmailLink {
            url: "https://www.zjzwfw.gov.example/application".to_string(),
            text: Some("浙江政务服务网".to_string()),
            suspicious: false,
        }],
        Some("sjcc@zjwx.gov.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "official manual-entry guidance with explicit anti-phishing context must not be a link lure: {result:?}"
    );
    assert!(
        !result.categories.contains(&"phishing".to_string()),
        "official notice must not inherit generic phishing evidence: {result:?}"
    );
}

#[test]
fn official_notice_counter_context_does_not_hide_a_direct_credential_request() {
    let module = seeded_content_module();
    let body = "数据出境安全评估申报材料补正通知。贵司申报编号已进入补正流程，办理期限和材料目录如下，请通过浙江政务服务网完成操作。唯一的官方入口是 www.zjzwfw.gov.example/application，手动输入地址后，请登录并输入企业账号密码，上传全部补正材料，完成身份验证。该流程涉及申报材料、在线办件、法人账号和数据提交，逾期将影响申报进度。";
    let ctx = make_ctx_with_subject_and_body(
        "申报材料在线补正",
        Some(body),
        None,
        vec![EmailLink {
            url: "https://www.zjzwfw.gov.example/application".to_string(),
            text: Some("官方入口".to_string()),
            suspicious: false,
        }],
        Some("notice@external-sender.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"external_action_link_lure".to_string()),
        "a direct credential request must defeat the official-notice calibration: {result:?}"
    );
}

#[test]
fn no_ioc_service_fee_solicitation_is_detected_as_external_bec() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "补贴申报核准通道通知",
        Some(
            "您本次补贴申报的材料尚未核验，申报窗口即将关闭，逾期申报无效。第三方核准通道可在期限内完成材料办理，需缴纳服务费 2600 元。请在截止日前回复“核准-合作社简称”，账户回传后我们安排组卷交付；如不办理，补贴可能无法核定。",
        ),
        None,
        vec![],
        Some("service@external-verification.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"bec_external_compound".to_string()),
        "no-link fee solicitation must use the independent external BEC compound: {result:?}"
    );
    assert!(
        result.categories.contains(&"bec_no_ioc_social".to_string()),
        "no-link fee solicitation must expose the social-only evidence class: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn no_ioc_service_solicitation_with_reply_to_is_detected() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "学时核验补录窗口即将关闭",
        Some(
            "社会实践学时缺失，补录窗口 8 月 28 日关闭，逾期档案不完整。我们提供学时核验与佐证材料装订服务，服务费 1,200 元。请回复本邮件学生姓名和学籍辅号以锁定名额，先到先得。",
        ),
        None,
        vec![],
        Some("shixue@ceec-record.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        result
            .categories
            .contains(&"bec_external_compound".to_string()),
        "no-link service solicitation with a reply handoff must be detected: {result:?}"
    );
    assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
}

#[test]
fn redteam_activity_hours_fixture_retains_and_detects_plaintext_body() {
    let raw = include_bytes!("../../../tests/redteam_cases/synth/mal_1113_activity_hours.eml");
    let content = MimeParser::new()
        .parse(raw)
        .expect("activity-hours fixture must parse");
    let body = content.body_text.as_deref().unwrap_or_default();
    assert!(
        body.contains("服务费") && body.contains("回复本邮件"),
        "body={body:?}"
    );
    let module = seeded_content_module();
    let sanitized = sanitize_body_for_keyword_scan(
        body,
        &module.gateway_banner_patterns,
        &module.notice_banner_patterns,
        &module.dsn_patterns,
        &module.auto_reply_patterns,
    );
    assert!(
        sanitized.contains("服务费") && sanitized.contains("回复本邮件"),
        "sanitized body={sanitized:?}"
    );

    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.1".to_string(),
        2525,
        "10.0.0.2".to_string(),
        25,
    );
    session.mail_from = Some("shixue@ceec-record.example".to_string());
    session.subject = Some("学时核验补录窗口即将关闭".to_string());
    session.rcpt_to.push("victim@example.com".to_string());
    session.content = content;
    let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
    assert!(
        result
            .categories
            .contains(&"bec_external_compound".to_string()),
        "parsed activity-hours fixture must retain its solicitation evidence: {result:?}"
    );
}

#[test]
fn ordinary_service_fee_notice_without_pressure_is_not_no_ioc_social_bec() {
    let module = seeded_content_module();
    let ctx = make_ctx_with_subject_and_body(
        "服务费发票及费用明细",
        Some(
            "本月服务费发票已开具，费用明细和合同约定请查收。请按既有财务流程完成付款，相关凭证可在月末对账时一并核对。如需开票信息调整，请联系供应商服务人员。",
        ),
        None,
        vec![],
        Some("billing@vendor.example"),
    );

    let result = analyze_with_runtime(&module, &ctx);

    assert!(
        !result
            .categories
            .contains(&"bec_external_compound".to_string()),
        "ordinary service-fee correspondence without pressure or an account handoff must not be BEC: {result:?}"
    );
}
