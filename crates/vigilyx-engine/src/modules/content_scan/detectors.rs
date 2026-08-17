//! Detection sub-functions extracted from ContentScanModule::analyze().
//!
//! Each function takes read-only inputs plus `&mut` shared state
//! (`total_score`, `categories`, `evidence`).

use std::sync::LazyLock;

use regex::Regex;

use super::html_utils::{is_embedded_contact_card_layout, strip_html_tags};
use super::{
    RE_CHINESE_PHONE, collect_gateway_prior_hits, compact_detection_view, normalize_text,
    normalized_subject_for_scan, sanitize_body_for_keyword_scan, scan_text,
};
use crate::context::SecurityContext;
use crate::matcher::{
    account_security_actions, account_security_threats, subject_threat_keywords,
    subsidy_keywords_body, subsidy_keywords_subject, subsidy_urgency_body,
};
use crate::module::Evidence;
use crate::module_data::module_data;
use crate::modules::common::{extract_domain_from_url, is_probable_non_clickable_render_asset_url};

static RE_VERIFICATION_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^0-9])[0-9]{4,8}(?:[^0-9]|$)").unwrap());

/// QQ-style numeric identifiers used in subject-only off-platform contact
/// lures.  The boundary deliberately accepts CJK characters around the
/// identifier while excluding longer arbitrary digit strings.
static RE_QQ_STYLE_CONTACT_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^a-z0-9])q{1,2}\s*[-_:#：]?\s*[0-9]{7,12}(?:$|[^0-9])")
        .expect("valid QQ-style contact identifier regex")
});

fn is_benign_verification_keyword(keyword: &str) -> bool {
    let normalized = normalize_text(&keyword.to_ascii_lowercase());
    module_data()
        .get_list("benign_verification_keywords")
        .iter()
        .any(|candidate| normalized.contains(candidate.as_str()))
}

fn has_untrusted_clickable_link(ctx: &SecurityContext) -> bool {
    ctx.session.content.links.iter().any(|link| {
        extract_domain_from_url(&link.url)
            .is_none_or(|domain| !crate::modules::link_scan::is_trusted_url_domain(&domain))
    })
}

fn has_external_impersonation_lure(text: &str) -> bool {
    // Single words such as "支付" or "银行" are common in legitimate
    // business plans and financial reports.  Require an actionable lure
    // phrase instead of treating those business-domain words as phishing.
    const ACTIONABLE_LURE_PHRASES: &[&str] = &[
        "请立即登录",
        "立即登录",
        "请登录",
        "点击登录",
        "登录验证",
        "请验证",
        "验证账户",
        "验证账号",
        "输入密码",
        "密码过期",
        "账号异常",
        "账户异常",
        "请付款",
        "立即付款",
        "付款链接",
        "请支付",
        "立即支付",
        "支付链接",
        "转账至",
        "转账到",
        "收款账户",
        "urgent",
        "immediately",
        "login to",
        "verify your",
        "enter your password",
        "payment link",
        "transfer to",
    ];
    let normalized = normalize_text(&text.to_lowercase());
    ACTIONABLE_LURE_PHRASES
        .iter()
        .any(|term| normalized.contains(term))
}

fn has_explicit_authority_claim(text: &str, authority_phrases: &[String]) -> bool {
    const CLAIM_MARKERS: &[&str] = &[
        "我是",
        "我们是",
        "本部门",
        "本单位",
        "本公司",
        "我司",
        "代表",
        "委托",
        "联合通知",
        "现通知",
        "特此通知",
        "要求您",
        "we are",
        "on behalf of",
        "representing",
        "official notice",
    ];
    let normalized = normalize_text(&text.to_lowercase());
    normalized
        .split(['\n', '\r', '。', '！', '？', '!', '?', ';', '；'])
        .any(|block| {
            authority_phrases
                .iter()
                .any(|phrase| block.contains(phrase))
                && CLAIM_MARKERS.iter().any(|marker| block.contains(marker))
        })
}

fn is_targeted_account_login_alert(ctx: &SecurityContext, normalized_subject: &str) -> bool {
    module_data()
        .get_list("account_login_alert_subjects")
        .iter()
        .any(|phrase| normalized_subject.contains(phrase.as_str()))
        && has_untrusted_clickable_link(ctx)
}

/// Return true when a message asks the recipient to use or enter an account
/// credential without depending on the mutable phishing keyword seed.  This
/// intentionally uses phrases rather than single words such as `account` or
/// `continue`, which are common in legitimate product mail.
fn has_credential_continuation_instruction(text: &str) -> bool {
    const CREDENTIAL_LURE_PHRASES: &[&str] = &[
        "use your enterprise account",
        "use your work account",
        "use your company account",
        "use your business account",
        "continue with your account",
        "continue with your enterprise account",
        "continue with your work account",
        "sign in with your",
        "log in with your",
        "access your account",
        "authenticate your account",
        "verify your account",
        "confirm your account",
        "keep access to your account",
        "enter your password",
        "enter your credentials",
        "enter the verification code",
        "single sign-on",
        "single sign on",
        "use your sso",
        "使用企业账号",
        "使用企业账户",
        "继续使用企业账号",
        "继续使用企业账户",
        "使用工作账号",
        "使用工作账户",
        "登录您的账户",
        "登录您的账号",
        "验证账户",
        "验证账号",
        "输入密码",
        "输入验证码",
        "单点登录",
    ];

    let normalized = normalize_text(&text.to_lowercase());
    CREDENTIAL_LURE_PHRASES
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

/// Official identity-provider hosts are not treated as untrusted link
/// destinations.  This is deliberately separate from the sender allowlist:
/// an external sender may legitimately link to a customer's configured SSO
/// provider, while an attacker-controlled lookalike host must not inherit that
/// trust merely from a familiar brand string in its URL.
fn is_official_sso_destination(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    module_data()
        .get_list("official_sso_domains")
        .iter()
        .any(|official| domain == *official || domain.ends_with(&format!(".{official}")))
}

/// Detect a clickable, externally hosted authentication destination.  A
/// normal-looking HTTPS link is not enough: the path/anchor must describe an
/// authentication flow and the destination must be outside the configured
/// URL trust set and official SSO hosts.
fn has_untrusted_authentication_link(ctx: &SecurityContext) -> bool {
    const AUTH_PATH_SEGMENTS: &[&str] = &[
        "login",
        "log-in",
        "signin",
        "sign-in",
        "auth",
        "authenticate",
        "verify",
        "verification",
        "sso",
        "oauth",
        "account",
        "session",
        "credential",
        "password",
        "mfa",
        "2fa",
    ];
    const AUTH_ANCHOR_PHRASES: &[&str] = &[
        "sign in",
        "log in",
        "continue with",
        "verify your account",
        "enterprise account",
        "work account",
        "single sign-on",
        "single sign on",
        "单点登录",
        "登录",
        "验证",
    ];

    ctx.session.content.links.iter().any(|link| {
        let effective = crate::modules::link_scan::unwrap_mail_security_gateway_target(&link.url)
            .unwrap_or_else(|| link.url.clone());
        let Ok(parsed) = url::Url::parse(&effective) else {
            return false;
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            return false;
        }
        let Some(domain) = parsed.host_str() else {
            return false;
        };
        if crate::modules::link_scan::is_trusted_url_domain(domain)
            || is_official_sso_destination(domain)
        {
            return false;
        }

        let path_auth = parsed.path_segments().is_some_and(|segments| {
            segments
                .map(str::to_ascii_lowercase)
                .any(|segment| AUTH_PATH_SEGMENTS.contains(&segment.as_str()))
        });
        let anchor_auth = link.text.as_deref().is_some_and(|text| {
            let normalized = normalize_text(&text.to_lowercase());
            AUTH_ANCHOR_PHRASES
                .iter()
                .any(|phrase| normalized.contains(phrase))
        });
        path_auth || anchor_auth
    })
}

fn looks_like_benign_verification_notice(ctx: &SecurityContext, body_hint: Option<&str>) -> bool {
    if !ctx.session.content.attachments.is_empty() {
        return false;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or("");
    let fallback_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .map(str::to_string)
        .or_else(|| {
            ctx.session
                .content
                .body_html
                .as_deref()
                .map(strip_html_tags)
        })
        .unwrap_or_default();
    let body = body_hint.unwrap_or(&fallback_body);
    let combined = normalize_text(&format!("{subject}\n{body}").to_ascii_lowercase());

    if !module_data()
        .get_list("benign_verification_keywords")
        .iter()
        .any(|kw| combined.contains(kw.as_str()))
    {
        return false;
    }

    let has_code_or_expiry = RE_VERIFICATION_CODE.is_match(&combined)
        || ((combined.contains("valid") || combined.contains("expire"))
            && combined.contains("minute"))
        || ((combined.contains("有效") || combined.contains("失效")) && combined.contains("分钟"));
    if !has_code_or_expiry {
        return false;
    }

    ctx.session.content.links.iter().all(|link| {
        is_probable_non_clickable_render_asset_url(&link.url)
            || extract_domain_from_url(&link.url)
                .is_some_and(|domain| crate::modules::link_scan::is_trusted_url_domain(&domain))
    })
}

fn detector_body_fallback_text(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
) -> Option<String> {
    body_for_cross
        .map(str::trim)
        .filter(|body| !body.is_empty())
        .map(str::to_string)
        .or_else(|| {
            ctx.session
                .content
                .body_text
                .as_deref()
                .map(str::trim)
                .filter(|body| !body.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            ctx.session
                .content
                .body_html
                .as_deref()
                .map(strip_html_tags)
                .map(|body| body.trim().to_string())
                .filter(|body| !body.is_empty())
        })
}

fn count_config_terms(haystack: &str, compact_haystack: &str, terms: &[String]) -> usize {
    terms
        .iter()
        .filter(|term| {
            let normalized = normalize_text(&term.to_lowercase());
            if normalized.is_empty() {
                return false;
            }
            if haystack.contains(normalized.as_str()) {
                return true;
            }
            let compact_term: String = normalized
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect();
            !compact_term.is_empty() && compact_haystack.contains(compact_term.as_str())
        })
        .count()
}

fn normalized_and_compact(text: &str) -> (String, String) {
    let normalized = normalize_text(&text.to_lowercase())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let compact = compact_detection_view(&normalized);
    (normalized, compact)
}

#[allow(clippy::too_many_arguments)]
fn detect_multipart_alternative_mismatch(
    ctx: &SecurityContext,
    sanitized_plain: &str,
    phishing_keywords: &[String],
    weak_phishing_keywords: &[String],
    bec_phrases: &[String],
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
    dsn_patterns: &[String],
    auto_reply_patterns: &[String],
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(body_html) = ctx.session.content.body_html.as_deref() else {
        return;
    };

    let sanitized_html = sanitize_body_for_keyword_scan(
        &strip_html_tags(body_html),
        gateway_banner_patterns,
        notice_banner_patterns,
        dsn_patterns,
        auto_reply_patterns,
    );
    if sanitized_html.trim().is_empty() {
        return;
    }

    let (plain_norm, plain_compact) = normalized_and_compact(sanitized_plain);
    let (html_norm, html_compact) = normalized_and_compact(&sanitized_html);
    if html_norm == plain_norm || html_norm.len() < 20 {
        return;
    }

    let plain_hits = count_config_terms(&plain_norm, &plain_compact, phishing_keywords)
        + count_config_terms(&plain_norm, &plain_compact, weak_phishing_keywords)
        + count_config_terms(&plain_norm, &plain_compact, bec_phrases);
    let html_hits = count_config_terms(&html_norm, &html_compact, phishing_keywords)
        + count_config_terms(&html_norm, &html_compact, weak_phishing_keywords)
        + count_config_terms(&html_norm, &html_compact, bec_phrases);
    if html_hits <= plain_hits {
        return;
    }

    let html_score = scan_text(
        &sanitized_html,
        phishing_keywords,
        weak_phishing_keywords,
        bec_phrases,
        evidence,
        categories,
    );
    if html_score <= 0.0 {
        return;
    }

    *total_score += (0.05 + html_score * 0.85).min(0.45);
    categories.push("multipart_alternative_mismatch".to_string());
    evidence.push(Evidence {
        description: "HTML alternative carries risky semantics absent from text/plain".to_string(),
        location: Some("body:html_alternative".to_string()),
        snippet: Some(sanitized_html.chars().take(160).collect()),
    });
}

fn external_sender_domain(ctx: &SecurityContext) -> Option<String> {
    ctx.session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.rsplit('@').next())
        .map(|d| d.to_lowercase())
}

fn is_external_sender_for_bec(ctx: &SecurityContext, sender_domain: Option<&str>) -> bool {
    match sender_domain {
        Some(domain) => {
            !ctx.is_internal_domain(domain)
                && !module_data().contains("protected_domains", domain)
                && !crate::modules::link_scan::is_well_known_safe_domain(domain)
        }
        None => true,
    }
}

// ─── Step 1: Gateway banner detection ────────────────────────────────

/// Detects upstream security gateway banners in subject and body prefix.
/// Adds `gateway_pre_classified` category (+0.05, informational).
/// Low weight because gateway tags are metadata, not independent evidence.
pub(super) fn detect_gateway_banner(
    ctx: &SecurityContext,
    gateway_banner_patterns: &[String],
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // (Coremail/Exchange).

    let body_for_gw = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or(ctx.session.content.body_html.as_deref())
        .unwrap_or("");

    let gw_prefix: String = body_for_gw.chars().take(500).collect();
    let mut gw_hits = collect_gateway_prior_hits(&gw_prefix, gateway_banner_patterns);
    if let Some(subject) = ctx.session.subject.as_deref() {
        let subject_hits = collect_gateway_prior_hits(subject, gateway_banner_patterns);
        for hit in subject_hits {
            if !gw_hits.contains(&hit) {
                gw_hits.push(hit);
            }
        }
    }

    if !gw_hits.is_empty() {
        *total_score += 0.05;
        categories.push("gateway_pre_classified".to_string());
        evidence.push(Evidence {
            description: format!(
                "Upstream security banner or gateway prior detected: {}",
                gw_hits.join(", ")
            ),
            location: Some("body:gateway_tag".to_string()),
            snippet: Some(gw_prefix.chars().take(120).collect()),
        });
    }
}

// ─── Step 2: Subject phishing keywords + phone numbers ───────────────

/// Scans subject line for phishing keywords and phone numbers.
/// Adds `phishing_subject` (+0.10/kw, max 0.5) and/or `phone_in_subject` (+0.15).
pub(super) fn detect_subject_phishing(
    ctx: &SecurityContext,
    phishing_keywords: &[String],
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // line (PhishingKeywords + Mobile phoneNumber)
    // Attack Medium,if "Need/Require Add 13662542997"
    // Note: email first AddSecurity if "[]",
    // packetContains"Risk"waitKeywords, first, Internal email.
    if let Some(ref subject) = ctx.session.subject {
        // Normalize (NFKC + invisible/combining marks) BEFORE banner-prefix
        // stripping: patterns are stored normalized, so full-width brackets
        // like 【外部邮件】 must fold to [外部邮件] first or the strip misses.
        let cleaned_subject = normalized_subject_for_scan(
            subject,
            gateway_banner_patterns,
            notice_banner_patterns,
        );
        let sub_lower = cleaned_subject.to_lowercase();
        let benign_verification = looks_like_benign_verification_notice(ctx, None);

        // Mediumof PhishingKeywords
        let mut subject_hits: Vec<&str> = phishing_keywords
            .iter()
            .filter(|kw| sub_lower.contains(kw.as_str()))
            .map(|kw| kw.as_str())
            .collect();
        if benign_verification {
            subject_hits.retain(|kw| !is_benign_verification_keyword(kw));
        }
        if !subject_hits.is_empty() {
            let count = subject_hits.len();
            *total_score += (count as f64 * 0.10).min(0.5);
            categories.push("phishing_subject".to_string());
            evidence.push(Evidence {
                description: format!(
                    "主题lineFound {} PhishingKeywords: {}",
                    count,
                    subject_hits.join(", ")
                ),
                location: Some("subject".to_string()),
                snippet: Some(subject.clone()),
            });
        }

        // /bodyMediumofMobile phoneNumberCode/Digit - Legitimate email Medium Mobile phoneNumber
        // P2-3 fix: skip phone detection for WeChat chat record exports.
        // Forwarded chat records often use participant-style subjects which
        // naturally contain phone numbers embedded in usernames.
        let is_chat_export = subject.contains("聊天记录")
            || subject.contains("群聊")
            || subject.contains("消息记录")
            || subject.contains("对话记录");
        // NFKC folds full-width digits and the filter drops zero-width
        // characters, so obfuscated numbers still match the ASCII-only regex.
        let normalized_subject = normalize_text(subject);
        let phone_matches: Vec<String> = RE_CHINESE_PHONE
            .captures_iter(&normalized_subject)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        if !phone_matches.is_empty() && !is_chat_export {
            *total_score += 0.15;
            categories.push("phone_in_subject".to_string());
            evidence.push(Evidence {
                description: format!(
                    "主题linepacketContainsMobile phoneNumberCode/Digit: {} (疑似微信/电话引Stream诈骗)",
                    phone_matches.join(", ")
                ),
                location: Some("subject".to_string()),
                snippet: Some(subject.clone()),
            });
        }
    }
}

// ─── Step 2b: Subject-only off-platform contact lure ─────────────────

/// Detects an explicit chat/contact lure that is carried only in the subject.
/// This is intentionally a low-weight signal: a QQ-style identifier plus an
/// off-platform contact marker is suspicious, but it is not by itself proof of
/// invoice fraud or credential phishing.
pub(super) fn detect_subject_contact_lure(
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(subject) = ctx.session.subject.as_deref() else {
        return;
    };

    let sender_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.rsplit('@').next())
        .map(str::to_lowercase);
    let is_external = match sender_domain.as_deref() {
        Some(domain) => {
            !ctx.is_internal_domain(domain)
                && !module_data().contains("protected_domains", domain)
        }
        None => true,
    };
    if !is_external {
        return;
    }

    let normalized = normalize_text(&subject.to_lowercase());
    let compact = compact_detection_text(&normalized);
    let has_contact_marker = explicit_invoice_contact_hits(&normalized, &compact) > 0;
    let has_qq_identifier = RE_QQ_STYLE_CONTACT_ID.is_match(&normalized);
    if !has_contact_marker || !has_qq_identifier {
        return;
    }

    *total_score += 0.18;
    categories.push("subject_contact_lure".to_string());
    evidence.push(Evidence {
        description:
            "Subject contains an off-platform contact marker and a QQ-style numeric identifier"
                .to_string(),
        location: Some("subject".to_string()),
        snippet: Some(subject.to_string()),
    });
}

// ─── Step 3: Body text preparation ───────────────────────────────────

/// Prepares body text for cross-step scanning: picks plain text or falls back
/// to HTML-stripped text, sanitizes banners/footers, and runs `scan_text`.
///
/// Returns `Option<String>` — the sanitized body used by later detectors.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_body_text(
    ctx: &SecurityContext,
    phishing_keywords: &[String],
    weak_phishing_keywords: &[String],
    bec_phrases: &[String],
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
    dsn_patterns: &[String],
    auto_reply_patterns: &[String],
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) -> Option<String> {
    // only 1bodyVersion,Avoid text + html Content
    // priorityUsePlain text (); Plain text HTML ofText
    let text_candidate = ctx
        .session
        .content
        .body_text
        .as_ref()
        .map(|body_text| {
            sanitize_body_for_keyword_scan(
                body_text,
                gateway_banner_patterns,
                notice_banner_patterns,
                dsn_patterns,
                auto_reply_patterns,
            )
        })
        .filter(|sanitized| !sanitized.trim().is_empty());

    let selected_from_plain = text_candidate.is_some();
    let selected = if let Some(text) = text_candidate {
        Some(text)
    } else {
        ctx.session
            .content
            .body_html
            .as_ref()
            .and_then(|body_html| {
                let stripped = sanitize_body_for_keyword_scan(
                    &strip_html_tags(body_html),
                    gateway_banner_patterns,
                    notice_banner_patterns,
                    dsn_patterns,
                    auto_reply_patterns,
                );
                if stripped.trim().is_empty() {
                    None
                } else {
                    Some(stripped)
                }
            })
    };

    if let Some(ref sanitized) = selected {
        let benign_verification = looks_like_benign_verification_notice(ctx, Some(sanitized));
        let filtered_phishing_keywords: Vec<String> = if benign_verification {
            phishing_keywords
                .iter()
                .filter(|kw| !is_benign_verification_keyword(kw))
                .cloned()
                .collect()
        } else {
            phishing_keywords.to_vec()
        };
        *total_score += scan_text(
            sanitized,
            &filtered_phishing_keywords,
            weak_phishing_keywords,
            bec_phrases,
            evidence,
            categories,
        );
        if selected_from_plain {
            detect_multipart_alternative_mismatch(
                ctx,
                sanitized,
                &filtered_phishing_keywords,
                weak_phishing_keywords,
                bec_phrases,
                gateway_banner_patterns,
                notice_banner_patterns,
                dsn_patterns,
                auto_reply_patterns,
                total_score,
                categories,
                evidence,
            );
        }
    }

    selected
}

// ─── Step 4: Image-only phishing ─────────────────────────────────────

/// Detects image-only phishing: body has very little text but contains
/// images and links (text content cannot be analyzed by NLP).
/// Adds `image_only_phishing` (+0.15).
pub(super) fn detect_image_only_phishing(
    ctx: &SecurityContext,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // ImagePhishingdetect: body + HTML Image
    // Attack PhishingContent Image email, TextKeywordsdetectAnd NLP.
    // : body_text short,body_html not (only Image)
    // Note: email body_text=None But body_html complete Content(if),
    // Check HTML of Length,Avoid.
    let body_text_len = ctx
        .session
        .content
        .body_text
        .as_ref()
        .map_or(0, |t| t.trim().len());
    // if body_text,Check body_html whether
    let effective_text_len = if body_text_len < 50 {
        ctx.session
            .content
            .body_html
            .as_ref()
            .map_or(0, |html| strip_html_tags(html).trim().len())
            .max(body_text_len)
    } else {
        body_text_len
    };

    let has_html_images = ctx.session.content.body_html.as_ref().is_some_and(|html| {
        let html_lower = html.to_lowercase();
        html_lower.contains("<img") || html_lower.contains("background-image")
    });
    let has_links = !ctx.session.content.links.is_empty();
    let is_contact_card_layout = is_embedded_contact_card_layout(ctx);
    let is_wps_share_notice = ctx.session.subject.as_deref().is_some_and(|subject| {
        let subject_lower = subject.to_ascii_lowercase();
        let has_wps_brand = subject_lower.contains("wps office");
        let has_share_phrase =
            subject.contains("分享给你") || subject_lower.contains("shared with you");
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|addr| addr.split('@').nth(1))
            .map(|domain| domain.to_ascii_lowercase());
        let sender_is_public_or_safe = sender_domain.as_deref().is_some_and(|domain| {
            crate::pipeline::internal_domains::is_public_mail_domain(domain)
                || crate::modules::link_scan::is_well_known_safe_domain(domain)
        });

        has_wps_brand && has_share_phrase && sender_is_public_or_safe
    });

    // Internal-domain exemption: employee scan reports and screenshot summaries naturally contain little text plus many images and links.
    let sender_is_internal = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1))
        .map(|d| ctx.is_internal_domain(&d.to_lowercase()))
        .unwrap_or(false);

    // Well-known safe-domain exemption: brand marketing mail naturally contains many images and relatively little text.
    let sender_is_safe = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1))
        .map(|d| crate::modules::link_scan::is_well_known_safe_domain(&d.to_lowercase()))
        .unwrap_or(false);

    // Legitimate document-attachment exemption: mail with PDF/DOC/XLS business documents often uses branded HTML wrappers,
    // and the substantive content lives in the attachment rather than the HTML body.
    let has_document_attachments = ctx.session.content.attachments.iter().any(|att| {
        let ct = att.content_type.to_lowercase();
        let fname = att.filename.to_lowercase();
        ct == "application/pdf"
            || ct == "application/msword"
            || ct.starts_with("application/vnd.openxmlformats-officedocument.")
            || ct == "application/vnd.ms-excel"
            || ct == "application/vnd.ms-powerpoint"
            || ct == "text/csv"
            || fname.ends_with(".pdf")
            || fname.ends_with(".doc")
            || fname.ends_with(".docx")
            || fname.ends_with(".xls")
            || fname.ends_with(".xlsx")
            || fname.ends_with(".ppt")
            || fname.ends_with(".pptx")
            || fname.ends_with(".csv")
    });

    // ofImagePhishing: Plain textAnd HTML allnot
    if effective_text_len < 50
        && has_html_images
        && has_links
        && !is_contact_card_layout
        && !is_wps_share_notice
        && !sender_is_internal
        && !sender_is_safe
        && !has_document_attachments
    {
        *total_score += 0.15;
        categories.push("image_only_phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "ImagePhishing嫌疑: body文字仅 {} charactersButpacketContainsImageAndlinkConnect (文字Content无法被 NLP Analyze)",
                effective_text_len
            ),
            location: Some("body".to_string()),
            snippet: None,
        });
    }
}

// ─── Step 5: Account security phishing (merged original steps 4+6) ───

/// Detects account-security phishing by checking body AND subject for
/// threat + action phrase combos (for example, an "abnormal login" lure paired with an immediate verification prompt).
///
/// This merges original step 4 (body threat+action) and step 6 (subject-only
/// fallback) into a single function.
/// Adds `account_security_phishing` (+0.20~0.65 depending on domain trust).
pub(super) fn detect_account_security_phishing(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1))
        .map(|d| d.to_lowercase());
    let is_external = match &sender_domain {
        Some(d) => !ctx.is_internal_domain(d) && !module_data().contains("protected_domains", d),
        None => true,
    };

    if !is_external {
        return;
    }

    // Structural credential-link detection is intentionally evaluated before
    // the legacy threat+action matcher.  A phishing message can avoid words
    // such as "urgent" or "abnormal" while still telling the recipient to
    // continue with a work account through an attacker-controlled SSO page.
    // This is the inline-safe signal that remains available when AI and
    // reputation services are disabled.
    let structural_lure_text = body_for_cross
        .map(str::to_string)
        .into_iter()
        .chain(ctx.session.subject.iter().cloned())
        .chain(
            ctx.session
                .content
                .links
                .iter()
                .filter_map(|link| link.text.clone()),
        )
        .collect::<Vec<_>>();
    let has_credential_instruction = structural_lure_text
        .iter()
        .any(|text| has_credential_continuation_instruction(text));
    if has_credential_instruction && has_untrusted_authentication_link(ctx) {
        let sender_domain = sender_domain.as_deref().unwrap_or("");
        let sender_is_well_known =
            crate::modules::link_scan::is_well_known_safe_domain(sender_domain);
        // A well-known sender still receives a visible Low finding; an
        // unknown external sender gets the Medium inline floor because the
        // two structural facts jointly describe credential harvesting.
        let lure_score = if sender_is_well_known { 0.20 } else { 0.45 };
        *total_score += lure_score;
        categories.push("credential_link_lure".to_string());
        evidence.push(Evidence {
            description: format!(
                "External sender {} combines a credential-continuation instruction with an untrusted authentication link",
                sender_domain
            ),
            location: Some("body + links".to_string()),
            snippet: None,
        });
        // Keep the legacy threat/action detector as a possible corroborating
        // signal, but do not allow it to add a duplicate account finding for
        // this same structural combination.
    }

    // --- Part A: body-based detection (original step 4) ---
    // AccountSecurity Phishing detect
    // mode: Sender + body "AbnormalLogin/Account number / immediatelyProcess"
    // of GetPhishingAttack,Need/Requireindependentdetect giving High.
    if let Some(body) = detector_body_fallback_text(ctx, body_for_cross) {
        let body_lower = normalize_text(&body.to_lowercase());
        let body_compact = compact_detection_view(&body_lower);

        // AccountSecurity Keywords (: Description + line)
        // Keep a small structural fallback for the common “account exists
        // abnormal” wording.  It is intentionally paired with an action
        // below; the noun alone is not a finding.  This also covers CJK
        // hidden-letter/entity separators after compact recovery.
        let has_account_anomaly_phrase = [
            "账户存在异常",
            "账号存在异常",
            "异常登入",
            "异常登录",
            "账户异常",
            "账号异常",
            "account is abnormal",
        ]
            .iter()
            .any(|term| body_lower.contains(term) || body_compact.contains(term));
        let has_spaced_english_credential_lure =
            body_compact.contains("verifyyouraccount")
                && [
                    "disabled",
                    "suspended",
                    "blocked",
                    "keepaccess",
                    "mailbox",
                ]
                .iter()
                .any(|term| body_compact.contains(term));
        let has_threat = account_security_threats().is_match(&body_lower)
            || account_security_threats().is_match(&body_compact)
            || has_account_anomaly_phrase
            || has_spaced_english_credential_lure;
        let has_structural_action = [
            "立即点击",
            "点击验证",
            "请立即",
            "验证",
            "认证",
            "verify",
            "confirm",
        ]
        .iter()
        .any(|term| body_lower.contains(term) || body_compact.contains(term));
        let has_action = account_security_actions().is_match(&body_lower)
            || account_security_actions().is_match(&body_compact)
            || has_structural_action
            || has_spaced_english_credential_lure;
        if has_threat && has_action {
            // DomainSendAccountSecurity email - according toDomainTrusted
            // TrustedDomain (if microsoft.com) possibly ofSecurity, Low
            // Unknown/randomDomain (if damuzhisofa.com) Phishing
            let domain_str = sender_domain.as_deref().unwrap_or("");
            let is_well_known = crate::modules::link_scan::is_well_known_safe_domain(domain_str);
            let phish_score = if is_well_known { 0.30 } else { 0.65 };
            *total_score += phish_score;
            categories.push("account_security_phishing".to_string());
            evidence.push(Evidence {
                description: format!(
                    "外部Domain {} SendAccountSecurity威胁email: Same时packetContains威胁DescriptionAndline动催促，典型凭证窃GetPhishingmode{}",
                    domain_str,
                    if is_well_known { " (TrustedDomain, possibly NormalSecurity通知)" } else { "" },
                ),
                location: Some("body + envelope".to_string()),
                snippet: None,
            });
            return; // Body detection succeeded — skip subject fallback
        }
    }

    // --- Part B: subject-only fallback (original step 6) ---
    // (body body)
    // body,.
    // body account_security_phishing,.
    if let Some(ref subject) = ctx.session.subject {
        let sub_lower = normalize_text(&subject.to_lowercase());
        let has_subject_threat = subject_threat_keywords().is_match(&sub_lower)
            || is_targeted_account_login_alert(ctx, &sub_lower);
        if has_subject_threat {
            let domain_str = sender_domain.as_deref().unwrap_or("");
            let is_well_known = crate::modules::link_scan::is_well_known_safe_domain(domain_str);
            let phish_score = if is_well_known { 0.20 } else { 0.50 };
            *total_score += phish_score;
            categories.push("account_security_phishing".to_string());
            evidence.push(Evidence {
                description: format!("主题行含账户安全威胁关键词，外部域名 {} 发送", domain_str,),
                location: Some("subject".to_string()),
                snippet: Some(subject.clone()),
            });
        }
    }
}

// ─── Step 6: Subsidy/tax fraud (merged original steps 5+7) ──────────

/// Procedural or generic words that can support a subsidy lure but are not,
/// by themselves, evidence that the message is about a benefit. Keeping this
/// distinction in code also protects installations that still have an older
/// runtime module-data snapshot containing these broad terms.
fn is_substantive_subsidy_phrase(phrase: &str) -> bool {
    let normalized = normalize_text(&phrase.to_lowercase());
    !matches!(
        normalized.as_str(),
        "人员"
            | "入职"
            | "在职"
            | "申请"
            | "办理"
            | "通知"
            | "申报领取"
            | "申请领取"
            | "办理领取"
            | "申请办理"
            | "官方办理"
            | "官方大厅"
            | "程序地址"
            | "办理通知"
    )
}

/// `剩余` describes ordinary remainder values in financial prose far more
/// often than it expresses a deadline. Strong variants such as `仅剩` remain
/// in the runtime list and continue to count as urgency.
fn is_strong_subsidy_urgency(phrase: &str) -> bool {
    !matches!(
        normalize_text(&phrase.to_lowercase()).as_str(),
        "剩余" | "剩餘"
    )
}

/// Detects government subsidy/tax fraud patterns by checking body AND subject
/// for benefit keywords + urgency phrases.
///
/// This merges original step 5 (body-based) and step 7 (subject-only fallback)
/// into a single function.
/// Adds `subsidy_fraud` (+0.45~0.60 depending on signal strength).
pub(super) fn detect_subsidy_fraud(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1))
        .map(|d| d.to_lowercase());
    let is_external = match &sender_domain {
        Some(d) => !ctx.is_internal_domain(d) && !module_data().contains("protected_domains", d),
        None => true,
    };

    if !is_external {
        return;
    }

    // --- Part A: body-based detection (original step 5) ---
    // Government subsidy/tax fraud pattern (/ /)
    // Signature: benefit keywords + urgency/deadline + suspicious URL or fake authority
    if let Some(body) = detector_body_fallback_text(ctx, body_for_cross) {
        let body_lower = normalize_text(&body.to_lowercase());
        let subsidy_hits = subsidy_keywords_body()
            .scan(&body_lower)
            .distinct_patterns();
        let urgency_hits = subsidy_urgency_body().scan(&body_lower).distinct_patterns();
        let has_substantive_benefit = subsidy_hits
            .iter()
            .any(|phrase| is_substantive_subsidy_phrase(phrase));
        let has_urgency = urgency_hits
            .iter()
            .any(|phrase| is_strong_subsidy_urgency(phrase));
        // 2+ subsidy keywords + urgency = strong fraud signal
        // Score 0.60: after BPA conversion (x0.85 confidence) and consensus gating
        // (x0.50 for 2-engine support), floor = 0.60x0.85x0.50 = 0.255 which,
        // combined with other keyword hits, comfortably reaches Medium (>= 0.40).
        if subsidy_hits.len() >= 2 && has_substantive_benefit && has_urgency {
            *total_score += 0.60;
            categories.push("subsidy_fraud".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Government subsidy fraud pattern: {} benefit keywords + urgency phrase from external domain",
                    subsidy_hits.len(),
                ),
                location: Some("body + envelope".to_string()),
                snippet: None,
            });
            return; // Body detection succeeded — skip subject fallback
        }
    }

    // --- Part B: subject-only fallback (original step 7) ---
    // (body)
    if let Some(ref subject) = ctx.session.subject {
        let sub_lower = normalize_text(&subject.to_lowercase());
        let subsidy_hits = subsidy_keywords_subject()
            .scan(&sub_lower)
            .distinct_patterns();
        let has_substantive_benefit = subsidy_hits
            .iter()
            .any(|phrase| is_substantive_subsidy_phrase(phrase));
        if subsidy_hits.len() >= 2 && has_substantive_benefit {
            *total_score += 0.45;
            categories.push("subsidy_fraud".to_string());
            evidence.push(Evidence {
                description: format!(
                    "主题行含 {} 个补贴/税务关键词，疑似补贴诈骗",
                    subsidy_hits.len(),
                ),
                location: Some("subject".to_string()),
                snippet: ctx.session.subject.clone(),
            });
        }
    }
}

fn compact_detection_text(text: &str) -> String {
    compact_detection_view(&normalize_text(&text.to_lowercase()))
}

fn keyword_matches_text(combined: &str, compact: &str, keyword: &str) -> bool {
    let normalized = normalize_text(&keyword.to_lowercase());
    let keyword_compact: String = normalized
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect();
    combined.contains(&normalized)
        || (!keyword_compact.is_empty() && compact.contains(&keyword_compact))
}

/// Collapse nested phrases such as `发票`, `增值税` and
/// `增值税专用发票` into one semantic cue instead of counting the same span
/// three times.
fn count_non_nested_keyword_hits(combined: &str, compact: &str, keywords: &[String]) -> usize {
    let mut hits: Vec<String> = keywords
        .iter()
        .filter(|keyword| keyword_matches_text(combined, compact, keyword))
        .map(|keyword| compact_detection_text(keyword))
        .filter(|keyword| !keyword.is_empty())
        .collect();
    hits.sort_by(|left, right| {
        right
            .chars()
            .count()
            .cmp(&left.chars().count())
            .then_with(|| left.cmp(right))
    });
    hits.dedup();

    let mut selected: Vec<String> = Vec::new();
    for hit in hits {
        if selected.iter().any(|existing| existing.contains(&hit)) {
            continue;
        }
        selected.push(hit);
    }
    selected.len()
}

fn explicit_invoice_contact_hits(combined: &str, compact: &str) -> usize {
    const DIRECT_CONTACT_MARKERS: &[&str] = &[
        "加q",
        "加qq",
        "发q",
        "发qq",
        "扣扣",
        "加微",
        "加微信",
        "加vx",
        "加v",
        "加我微",
        "加我vx",
        "扣扣号",
        "微信号",
        "qq:",
        "qq：",
        "wechat:",
        "wechat：",
        "telegram",
        "whatsapp",
        "私聊",
        "line id",
        "line追加",
        "カカオトーク",
    ];

    DIRECT_CONTACT_MARKERS
        .iter()
        .filter(|marker| {
            let normalized = normalize_text(&marker.to_lowercase());
            if combined.contains(&normalized) {
                return true;
            }
            let marker_compact: String = normalized
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect();
            let contains_cjk = normalized
                .chars()
                .any(|ch| ('\u{4E00}'..='\u{9FFF}').contains(&ch));
            contains_cjk && !marker_compact.is_empty() && compact.contains(&marker_compact)
        })
        .count()
}

/// Detects Chinese invoice-spam / fake invoice solicitation patterns such as
/// "invoice solicitation + off-platform contact details". This targets off-platform contact lures rather
/// than legitimate invoice delivery notices.
pub(super) fn detect_invoice_spam(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1))
        .map(|d| d.to_lowercase());
    let is_external = match &sender_domain {
        Some(d) => !ctx.is_internal_domain(d) && !module_data().contains("protected_domains", d),
        None => true,
    };

    if !is_external {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or("");
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = normalize_text(&format!("{subject}\n{body}").to_lowercase());
    let compact = compact_detection_text(&combined);
    let invoice_keywords = module_data().get_list("invoice_spam_keywords").to_vec();
    let contact_keywords = module_data()
        .get_list("invoice_spam_contact_keywords")
        .to_vec();
    let invoice_hits = count_non_nested_keyword_hits(&combined, &compact, &invoice_keywords);
    let contact_hits = contact_keywords
        .iter()
        .filter(|keyword| keyword_matches_text(&combined, &compact, keyword))
        .count();
    let direct_contact_hits = explicit_invoice_contact_hits(&combined, &compact);
    let phone_hits = RE_CHINESE_PHONE.captures_iter(&combined).count();
    let has_phone_contact = phone_hits >= 1 && contact_hits >= 1;

    if invoice_hits >= 1 && (direct_contact_hits >= 1 || has_phone_contact) {
        *total_score += if phone_hits >= 1 { 0.62 } else { 0.52 };
        categories.push("invoice_spam".to_string());
        evidence.push(Evidence {
            description: format!(
                "Detected invoice-spam solicitation: {} invoice cues + {} off-platform contact cues + {} phone cue(s)",
                invoice_hits,
                direct_contact_hits.max(if has_phone_contact { contact_hits } else { 0 }),
                phone_hits
            ),
            location: Some("subject + body".to_string()),
            snippet: if subject.is_empty() {
                Some(body.chars().take(120).collect())
            } else {
                Some(subject.to_string())
            },
        });
    }
}

/// Detects payment-account-change BEC lures without relying on AI.
///
/// The wording lists are runtime module data so operations teams can tune
/// language coverage through the existing JSON/DB override path.
pub(super) fn detect_payment_change_bec(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or("");
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = normalize_text(&format!("{subject}\n{body}").to_lowercase());
    if combined.trim().is_empty() {
        return;
    }
    let compact: String = combined.chars().filter(|ch| ch.is_alphanumeric()).collect();

    let md = module_data();
    let change_hits =
        count_config_terms(&combined, &compact, md.get_list("payment_change_keywords"));
    if change_hits == 0 {
        return;
    }

    let action_hits =
        count_config_terms(&combined, &compact, md.get_list("bec_payment_action_terms"));
    let authority_hits =
        count_config_terms(&combined, &compact, md.get_list("bec_authority_terms"));
    let urgency_hits = count_config_terms(
        &combined,
        &compact,
        md.get_list("transaction_urgency_keywords"),
    );
    let confidentiality_hits = count_config_terms(
        &combined,
        &compact,
        md.get_list("bec_confidentiality_terms"),
    );

    let support_dimensions = usize::from(action_hits > 0)
        + usize::from(authority_hits > 0)
        + usize::from(urgency_hits > 0)
        + usize::from(confidentiality_hits > 0);
    if support_dimensions < 2 {
        return;
    }

    let mut score = 0.38_f64;
    if action_hits > 0 {
        score += 0.10;
    }
    if authority_hits > 0 {
        score += 0.08;
    }
    if urgency_hits > 0 {
        score += 0.08;
    }
    if confidentiality_hits > 0 {
        score += 0.10;
    }
    if ctx.session.content.links.is_empty() && ctx.session.content.attachments.is_empty() {
        score += 0.05;
        categories.push("bec_no_ioc_social".to_string());
    }

    *total_score += score.min(0.78_f64);
    categories.push("bec_payment_change".to_string());
    evidence.push(Evidence {
        description: format!(
            "Payment-account-change BEC pattern from external domain {}: change={}, action={}, authority={}, urgency={}, confidentiality={}",
            sender_domain.as_deref().unwrap_or("unknown"),
            change_hits,
            action_hits,
            authority_hits,
            urgency_hits,
            confidentiality_hits,
        ),
        location: Some("subject + body + envelope".to_string()),
        snippet: if subject.is_empty() {
            Some(body.chars().take(160).collect())
        } else {
            Some(subject.to_string())
        },
    });
}

// ─── Step 7: Body phone number detection ─────────────────────────────

/// Detects phone numbers in body text. Only scores when ≥2 numbers found
/// AND other signals already exist (avoids false positives on signatures).
/// Adds `phone_in_body` (+0.04/number, max 0.12).
pub(super) fn detect_body_phone_numbers(
    body_for_cross: Option<&str>,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // bodyMobile phoneNumberdetect
    // Note: Chinese emailbodypacketContainsMobile phoneNumber (Method, Signwait).
    // Same stored PhishingSignal Mobile phoneNumber Add,
    // >=2 NumberCode/Digit (NumberCode/Digit Normal Method).
    if let Some(body) = body_for_cross {
        // Normalize first: NFKC folds full-width digits to ASCII and the
        // filter strips zero-width characters used to break up numbers.
        let normalized_body = normalize_text(body);
        let phone_matches: Vec<String> = RE_CHINESE_PHONE
            .captures_iter(&normalized_body)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        let has_other_signals = !categories.is_empty();
        if phone_matches.len() >= 2
            && has_other_signals
            && !categories.contains(&"phone_in_subject".to_string())
        {
            *total_score += (phone_matches.len() as f64 * 0.04).min(0.12);
            categories.push("phone_in_body".to_string());
            evidence.push(Evidence {
                description: format!(
                    "bodypacketContains {} Mobile phoneNumberCode/Digit: {}",
                    phone_matches.len(),
                    phone_matches.join(", ")
                ),
                location: Some("body".to_string()),
                snippet: Some(phone_matches.join(", ")),
            });
        }
    }
}

// ─── Step 8: External impersonation ──────────────────────────────────

/// Detects external senders impersonating internal departments (e.g.
/// an internal finance-team label coming from an external domain). Requires
/// >=2 authority phrase hits, an explicit local identity claim, and an
/// actionable credential/payment lure.
/// Adds `external_impersonation` (+0.30).
pub(super) fn detect_external_impersonation(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    internal_authority_phrases: &[String],
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // Signal 1: Sender Internal (+0.25)
    if let Some(body) = body_for_cross {
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|addr| addr.split('@').nth(1))
            .map(|d| d.to_lowercase());

        let is_external = match &sender_domain {
            Some(d) => {
                !ctx.is_internal_domain(d) && !module_data().contains("protected_domains", d)
            }
            None => true,
        };

        if is_external {
            // Chat-log / forwarded-message exemption: forwarded messenger conversations naturally contain department labels
            // and similar authority phrases, so they should not be treated as external impersonation.
            let subject = ctx.session.subject.as_deref().unwrap_or("");
            let is_chat_forward = subject.contains("聊天记录")
                || subject.contains("群聊")
                || subject.contains("消息记录")
                || subject.contains("对话记录")
                || subject.contains("文件传输助手");
            if is_chat_forward {
                return;
            }

            // QQ personal-mailbox exemption (numeric local-part@qq.com): users often forward internal work files from personal mailboxes,
            // and those messages can naturally include department names without being external impersonation.
            let is_qq_personal = sender_domain
                .as_ref()
                .is_some_and(|d| d == "qq.com" || d == "foxmail.com")
                && ctx
                    .session
                    .mail_from
                    .as_deref()
                    .and_then(|addr| addr.split('@').next())
                    .is_some_and(|user| user.chars().all(|c| c.is_ascii_digit()));
            if is_qq_personal {
                return;
            }

            let body_lower = normalize_text(&body.to_lowercase());
            let mut impersonation_hits = Vec::new();
            for phrase in internal_authority_phrases {
                if body_lower.contains(phrase.as_str()) {
                    impersonation_hits.push(phrase.clone());
                }
            }
            // Authority phrases also occur in legitimate policies, reports,
            // industry newsletters, and event invitations. Unknown links are
            // not identity claims. Require both an explicit local claim and an
            // actionable credential/payment lure.
            let has_claim = has_explicit_authority_claim(body, &impersonation_hits);
            let has_lure = has_external_impersonation_lure(body);
            if impersonation_hits.len() >= 2 && has_claim && has_lure {
                *total_score += 0.30;
                categories.push("external_impersonation".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "外部Domain {} 冒充Internal部门: {}",
                        sender_domain.as_deref().unwrap_or("unknown"),
                        impersonation_hits.join(", "),
                    ),
                    location: Some("body + envelope".to_string()),
                    snippet: Some(impersonation_hits.join(", ")),
                });
            }
        }
    }
}

// ─── Step 9: Language inconsistency ──────────────────────────────────

/// Detects Chinese body text with English department signatures — a common
/// BEC / impersonation indicator.
/// Adds `lang_inconsistency` (+0.08).
pub(super) fn detect_lang_inconsistency(
    body_for_cross: Option<&str>,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // Signal 2: Medium Sign 1 (+0.08)
    if let Some(body) = body_for_cross {
        // Checkbody whether Chinese
        let cjk_count = body
            .chars()
            .filter(|c| ('\u{4E00}'..='\u{9FFF}').contains(c))
            .count();
        let total_chars = body.chars().filter(|c| !c.is_whitespace()).count();
        let is_chinese_body = total_chars > 20 && cjk_count as f64 / total_chars as f64 > 0.3;

        if is_chinese_body {
            let mut signature_lines: Vec<String> = body
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .rev()
                .take(12)
                .map(|line| line.to_lowercase())
                .collect();
            signature_lines.reverse();
            let mut en_sig_hits = Vec::new();
            for sig in module_data().get_list("en_department_signatures") {
                // This detector is specifically for an English signature
                // following a Chinese body. Non-Latin seed entries belong to
                // other locale checks and must not satisfy this condition.
                if !sig.chars().any(|ch| ch.is_ascii_alphabetic()) {
                    continue;
                }
                let normalized_sig = sig.to_lowercase();
                let is_signature_line = signature_lines.iter().any(|line| {
                    line.chars().count() <= 120 && line.contains(normalized_sig.as_str())
                });
                if is_signature_line {
                    en_sig_hits.push(sig.clone());
                }
            }
            if !en_sig_hits.is_empty() {
                *total_score += 0.08;
                categories.push("lang_inconsistency".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "body以Chinese 主ButSignUse英文部门Name: {}",
                        en_sig_hits.join(", "),
                    ),
                    location: Some("signature".to_string()),
                    snippet: Some(en_sig_hits.join(", ")),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{has_explicit_authority_claim, has_external_impersonation_lure};

    #[test]
    fn routine_business_prose_is_not_an_impersonation_lure() {
        assert!(!has_external_impersonation_lure(
            "严格执行，全员参与，系统升级，业务合规，支付业务与银行渠道协同。"
        ));
        assert!(has_external_impersonation_lure(
            "请立即登录账户完成安全验证。"
        ));
    }

    #[test]
    fn industry_terms_are_not_an_explicit_authority_claim() {
        let phrases = vec!["反洗钱合规".to_string(), "监管要求".to_string()];
        assert!(!has_explicit_authority_claim(
            "本期课程聚焦反洗钱合规与监管要求，欢迎立即报名。",
            &phrases
        ));
        assert!(has_explicit_authority_claim(
            "财务部与人事部联合通知：请立即登录完成验证。",
            &["财务部".to_string(), "人事部".to_string()]
        ));
    }
}
