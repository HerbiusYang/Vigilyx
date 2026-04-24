//! Detection sub-functions extracted from ContentScanModule::analyze().
//!
//! Each function takes read-only inputs plus `&mut` shared state
//! (`total_score`, `categories`, `evidence`).

use std::sync::LazyLock;

use regex::Regex;

use super::html_utils::{is_embedded_contact_card_layout, strip_html_tags};
use super::{
    RE_CHINESE_PHONE, collect_gateway_prior_hits, normalize_text, sanitize_body_for_keyword_scan,
    scan_text, strip_subject_banner_prefixes,
};
use crate::context::SecurityContext;
use crate::module::Evidence;
use crate::module_data::module_data;
use crate::modules::common::{extract_domain_from_url, is_probable_non_clickable_render_asset_url};

static RE_VERIFICATION_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^0-9])[0-9]{4,8}(?:[^0-9]|$)").unwrap());

const BENIGN_VERIFICATION_KEYWORDS: &[&str] = &[
    "verification code",
    "email verification",
    "邮箱验证码",
    "验证码",
    "校验码",
    "动态码",
    "otp",
    "one-time code",
    "one time code",
    "passcode",
];

fn is_benign_verification_keyword(keyword: &str) -> bool {
    let normalized = normalize_text(&keyword.to_ascii_lowercase());
    BENIGN_VERIFICATION_KEYWORDS
        .iter()
        .any(|candidate| normalized.contains(candidate))
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

    if !BENIGN_VERIFICATION_KEYWORDS
        .iter()
        .any(|kw| combined.contains(kw))
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
        let cleaned_subject =
            strip_subject_banner_prefixes(subject, gateway_banner_patterns, notice_banner_patterns);
        let sub_lower = normalize_text(&cleaned_subject.to_lowercase());
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
        let phone_matches: Vec<String> = RE_CHINESE_PHONE
            .captures_iter(subject)
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

    // --- Part A: body-based detection (original step 4) ---
    // AccountSecurity Phishing detect
    // mode: Sender + body "AbnormalLogin/Account number / immediatelyProcess"
    // of GetPhishingAttack,Need/Requireindependentdetect giving High.
    if let Some(body) = detector_body_fallback_text(ctx, body_for_cross) {
        let body_lower = normalize_text(&body.to_lowercase());

        // AccountSecurity Keywords (: Description + line)
        let has_threat = module_data()
            .get_list("account_security_threat_phrases_body")
            .iter()
            .any(|p| body_lower.contains(p.as_str()));
        let has_action = module_data()
            .get_list("account_security_action_phrases_body")
            .iter()
            .any(|p| body_lower.contains(p.as_str()));
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
        let has_subject_threat = module_data()
            .get_list("subject_threat_keywords")
            .iter()
            .any(|kw| sub_lower.contains(kw.as_str()));
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
        let has_subsidy = module_data()
            .get_list("subsidy_keywords_body")
            .iter()
            .filter(|k| body_lower.contains(k.as_str()))
            .count();
        let has_urgency = module_data()
            .get_list("subsidy_urgency_keywords_body")
            .iter()
            .any(|k| body_lower.contains(k.as_str()));
        // 2+ subsidy keywords + urgency = strong fraud signal
        // Score 0.60: after BPA conversion (x0.85 confidence) and consensus gating
        // (x0.50 for 2-engine support), floor = 0.60x0.85x0.50 = 0.255 which,
        // combined with other keyword hits, comfortably reaches Medium (>= 0.40).
        if has_subsidy >= 2 && has_urgency {
            *total_score += 0.60;
            categories.push("subsidy_fraud".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Government subsidy fraud pattern: {} benefit keywords + urgency phrase from external domain",
                    has_subsidy,
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
        let has_subsidy = module_data()
            .get_list("subsidy_keywords_subject")
            .iter()
            .filter(|k| sub_lower.contains(k.as_str()))
            .count();
        if has_subsidy >= 2 {
            *total_score += 0.45;
            categories.push("subsidy_fraud".to_string());
            evidence.push(Evidence {
                description: format!("主题行含 {} 个补贴/税务关键词，疑似补贴诈骗", has_subsidy,),
                location: Some("subject".to_string()),
                snippet: ctx.session.subject.clone(),
            });
        }
    }
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
    let compact: String = combined.chars().filter(|ch| ch.is_alphanumeric()).collect();
    let contains_obfuscated_keyword = |keyword: &str| {
        combined.contains(keyword)
            || compact.contains(
                &keyword
                    .chars()
                    .filter(|ch| ch.is_alphanumeric())
                    .collect::<String>(),
            )
    };
    let invoice_hits = module_data()
        .get_list("invoice_spam_keywords")
        .iter()
        .filter(|keyword| contains_obfuscated_keyword(keyword))
        .count();
    let contact_hits = module_data()
        .get_list("invoice_spam_contact_keywords")
        .iter()
        .filter(|keyword| contains_obfuscated_keyword(keyword))
        .count();
    let phone_hits = RE_CHINESE_PHONE.captures_iter(&combined).count();

    if invoice_hits >= 1 && (contact_hits >= 2 || (contact_hits >= 1 && phone_hits >= 1)) {
        *total_score += if phone_hits >= 1 { 0.62 } else { 0.52 };
        categories.push("invoice_spam".to_string());
        evidence.push(Evidence {
            description: format!(
                "Detected invoice-spam solicitation: {} invoice cues + {} off-platform contact cues + {} phone cue(s)",
                invoice_hits, contact_hits, phone_hits
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
        let phone_matches: Vec<String> = RE_CHINESE_PHONE
            .captures_iter(body)
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
/// an internal finance-team label coming from an external domain). Requires >=2 authority phrase hits.
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

            let body_lower = body.to_lowercase();
            let mut impersonation_hits = Vec::new();
            for phrase in internal_authority_phrases {
                if body_lower.contains(phrase.as_str()) {
                    impersonation_hits.push(phrase.clone());
                }
            }
            // Need/Require 2+ Internal short Medium: " "
            if impersonation_hits.len() >= 2 {
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
        let body_lower = body.to_lowercase();
        // Checkbody whether Chinese
        let cjk_count = body
            .chars()
            .filter(|c| ('\u{4E00}'..='\u{9FFF}').contains(c))
            .count();
        let total_chars = body.chars().filter(|c| !c.is_whitespace()).count();
        let is_chinese_body = total_chars > 20 && cjk_count as f64 / total_chars as f64 > 0.3;

        if is_chinese_body {
            let mut en_sig_hits = Vec::new();
            for sig in module_data().get_list("en_department_signatures") {
                if body_lower.contains(sig.as_str()) {
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
