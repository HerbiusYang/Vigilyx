//! Detection sub-functions extracted from ContentScanModule::analyze().
//!
//! Each function takes read-only inputs plus `&mut` shared state
//! (`total_score`, `categories`, `evidence`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::html_utils::{
    decode_html_entities, hidden_external_destination_facts, hidden_text_region_facts,
    is_embedded_contact_card_layout, strip_html_tags, visible_anchor_facts,
};
use super::{
    RE_CHINESE_PHONE, collect_gateway_prior_hits, compact_detection_view, keyword_set,
    normalize_text, normalized_subject_for_scan, sanitize_body_for_keyword_scan, scan_text,
};
use crate::context::SecurityContext;
use crate::matcher::{
    account_security_actions, account_security_threats, subject_threat_keywords,
    subsidy_keywords_body, subsidy_keywords_subject, subsidy_urgency_body,
};
use crate::module::Evidence;
use crate::module_data::module_data;
use crate::modules::common::{
    domains_share_organizational_domain, extract_domain_from_email, extract_domain_from_url,
    is_probable_non_clickable_render_asset_url,
};

mod threat_actions;

static RE_VERIFICATION_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^0-9])[0-9]{4,8}(?:[^0-9]|$)").unwrap());

/// IBAN-shaped payment destinations used in external payment lures.  This
/// is only a destination signal; it is never sufficient without configured
/// payment context and an explicit payment action.
static RE_IBAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b").expect("valid IBAN regex")
});

/// Card-shaped payment destinations used by the direct-payment compound.
/// Unlike DLP credit-card findings this intentionally does not require Luhn:
/// payment lures often contain masked, test, or institution-specific numbers.
/// The BEC path still requires narrow business context and an explicit action.
static RE_CARD_LIKE_PAYMENT_DESTINATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
        .expect("valid payment destination regex")
});

/// Grouped bank account numbers used as payment destinations in direct-pay
/// lures. This only participates in the Reply-To compound, which also needs a
/// mismatched external route, explicit payment action, and pressure/context.
static RE_GROUPED_BANK_ACCOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{2,4}(?:[\s-]\d{2,4}){3,6}\b").expect("valid grouped bank-account regex")
});

static RE_CRYPTO_WALLET_DESTINATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b0x[a-f0-9]{40}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
        .expect("valid crypto wallet destination regex")
});

fn has_iban_payment_destination(text: &str) -> bool {
    let compact = compact_detection_view(&normalize_text(&text.to_lowercase()));
    RE_IBAN.is_match(text) || RE_IBAN.is_match(&compact)
}

/// Recognize a concrete bank destination presented as a labeled field. BEC
/// messages may use ABA, sort-code, escrow, or local account formats that are
/// not shaped like a card number or IBAN. A label and at least six digits
/// must occur on the same line, so amounts and unrelated reference numbers do
/// not qualify by themselves.
fn has_explicit_account_destination(text: &str) -> bool {
    const ACCOUNT_LABELS: &[&str] = &[
        "account no",
        "account number",
        "bank account",
        "bank account no",
        "beneficiary account",
        "payment account",
        "settlement account",
        "new account",
        "acct no",
        "acct number",
        "aba",
        "routing",
        "sort code",
        "iban",
        "账号号码",
        "账号",
        "银行账号",
        "银行账户",
        "收款账号",
        "收款账户",
        "结算账户",
        "共管账户",
        "对公账户",
        "账户",
        "专户",
        "卡号",
    ];

    text.lines().any(|line| {
        let Some(separator) = line.find([':', '：']) else {
            return false;
        };
        let (label, rest) = line.split_at(separator);
        let value = &rest[rest.chars().next().map_or(0, char::len_utf8)..];
        let normalized_label = normalize_text(&label.to_lowercase());
        let normalized_label = normalized_label
            .trim()
            .trim_start_matches(|character: char| {
                matches!(character, '-' | '*' | '+' | '•' | '·' | '▪' | '◦' | '‣')
            });
        ACCOUNT_LABELS.contains(&normalized_label)
            && value.chars().filter(char::is_ascii_digit).count() >= 6
    })
}

/// QQ-style numeric identifiers used in subject-only off-platform contact
/// lures.  The boundary deliberately accepts CJK characters around the
/// identifier while excluding longer arbitrary digit strings.
static RE_QQ_STYLE_CONTACT_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^a-z0-9])q{1,2}\s*[-_:#：]?\s*[0-9]{7,12}(?:$|[^0-9])")
        .expect("valid QQ-style contact identifier regex")
});

static RE_HTML_BASE_HREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<base\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("valid HTML base href regex")
});

static RE_HTML_HREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\bhref\s*=\s*[\"']([^\"']+)[\"']"#).expect("valid HTML href regex")
});

static RE_HTML_ALT_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)https?://[^\s"'<>]+|https?：//[^\s"'<>]+"#).expect("valid HTML alt URL regex")
});

// Internal node-position tokens are inserted only after raw DOM text has
// been stripped of this reserved spelling. They never become speech or stored
// evidence, and let identical anchor labels keep distinct source provenance.
static RE_SCOPED_ANCHOR_POSITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("\u{e000}anchor:[0-9]+\u{e001}").expect("valid anchor position token")
});

static RE_SEMANTIC_SENTENCE_BOUNDARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[。！？!?;；]|\.[ \t]+").expect("valid semantic sentence boundary")
});

static RE_SEMANTIC_MAILBOX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+").expect("valid semantic mailbox")
});

static RE_HTML_ALT_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\balt\s*=\s*[\"']([^\"']*)[\"']"#).expect("valid HTML alt attribute regex")
});

static RE_HTML_IMAGE_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("valid HTML image src regex")
});

/// SVG `<image href>` resources are visual content, not recipient-facing
/// navigation. Keep this separate from ordinary anchor hrefs because the
/// legacy `EmailLink` shape does not carry HTML attribute provenance.
static RE_HTML_SVG_IMAGE_HREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<image\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("valid SVG image href regex")
});

static RE_HTML_BACKGROUND_IMAGE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)background-image\s*:\s*url\(\s*[\"']?([^\"')\s]+)"#)
        .expect("valid CSS background image URL regex")
});

/// External visual resources require a separate, SSRF-safe fetch/render
/// boundary.  Do not treat an ordinary anchor href as a visual resource.
static RE_EXTERNAL_HTML_VISUAL_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<(?:img|image)\b[^>]*\b(?:src|href)\s*=\s*["']\s*https?://|background-image\s*:\s*url\(\s*["']?https?://"#,
    )
    .expect("valid external HTML visual reference regex")
});

static RE_HTML_IFRAME_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<iframe\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("valid HTML iframe src regex")
});

static RE_NON_RENDERED_HTML_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<(?:style|script|head|title|noscript)\b[^>]*>.*?</(?:style|script|head|title|noscript)\s*>")
        .expect("valid non-rendered HTML block regex")
});

static RE_INLINE_SEMANTIC_LIST_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s+[-*+•·▪◦‣]\s+").expect("valid inline semantic-list marker regex")
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
        !is_visual_resource_link(ctx, &link.url) && is_untrusted_clickable_link(ctx, &link.url)
    })
}

fn is_untrusted_clickable_link(ctx: &SecurityContext, url: &str) -> bool {
    let effective_url = effective_structural_url(url);
    let Some(domain) = extract_domain_from_url(&effective_url) else {
        return false;
    };
    !ctx.is_internal_domain(&domain)
        && !module_data().contains("protected_domains", &domain)
        && !crate::modules::link_scan::is_trusted_url_domain(&domain)
        && !crate::modules::link_scan::is_well_known_safe_domain(&domain)
}

/// Use the destination that the URL/link analyzers use for structural checks.
/// Mail-security gateways are transport wrappers, not the recipient's actual
/// destination; treating their hostname as the destination creates a false
/// cross-domain relationship for ordinary notification mail.
fn effective_structural_url(url: &str) -> String {
    crate::modules::link_scan::unwrap_redirect_target_for_analysis(url)
        .unwrap_or_else(|| url.to_string())
}

/// The wire-compatible `EmailLink` model intentionally does not persist
/// whether a URL came from `href`, `src`, or CSS. Recover just enough
/// provenance from the retained HTML to prevent an external image/visual
/// resource from being promoted to a recipient action destination.
fn html_attribute_url_matches(html: &str, pattern: &Regex, url: &str) -> bool {
    let target = effective_structural_url(url);
    pattern.captures_iter(html).any(|captures| {
        let Some(raw) = captures
            .get(1)
            .map(|value| decode_html_entities(value.as_str()))
        else {
            return false;
        };
        let candidate = effective_structural_url(raw.trim());
        candidate == target
    })
}

fn is_visual_resource_link(ctx: &SecurityContext, url: &str) -> bool {
    if is_probable_non_clickable_render_asset_url(url) {
        return true;
    }

    ctx.session
        .content
        .body_html
        .as_deref()
        .is_some_and(|html| {
            html_attribute_url_matches(html, &RE_HTML_IMAGE_SRC, url)
                || html_attribute_url_matches(html, &RE_HTML_SVG_IMAGE_HREF, url)
                || html_attribute_url_matches(html, &RE_HTML_BACKGROUND_IMAGE_URL, url)
        })
}

fn has_substantive_plaintext_body(ctx: &SecurityContext) -> bool {
    ctx.session
        .content
        .body_text
        .as_deref()
        .is_some_and(|body| !body.trim().is_empty())
}

/// HTML text projections contain printed URLs that may be ordinary reference
/// material. When there is no retained plain-text part, only parser-retained
/// links (especially anchor hrefs) are strong destination evidence; visual
/// text URLs are not independently promoted by this compound.
fn should_scan_projected_html_urls(ctx: &SecurityContext) -> bool {
    ctx.session.content.body_html.is_none() || has_substantive_plaintext_body(ctx)
}

fn link_is_actionable_in_context(
    ctx: &SecurityContext,
    link: &vigilyx_core::models::EmailLink,
    body: &str,
) -> bool {
    if body.trim().is_empty() || is_visual_resource_link(ctx, &link.url) {
        return false;
    }
    let normalized_body = normalize_text(&body.to_lowercase());
    let url = normalize_text(&decode_html_entities(&link.url.to_lowercase()));
    if !url.is_empty() && normalized_body.contains(&url) {
        return true;
    }
    link.text.as_deref().is_some_and(|text| {
        let normalized_text = normalize_text(&decode_html_entities(&text.to_lowercase()));
        if normalized_text.chars().count() < 2 {
            return false;
        }
        if normalized_body.contains(&normalized_text) {
            return true;
        }

        // Some MIME parsers preserve a link's short action label separately
        // from visible body text. Keep such a link actionable only when the
        // label and body share a configured action plus a risk/context term,
        // or two distinct configured actions. A generic "view" label alone
        // must not attach an unrelated destination to the body.
        let md = module_data();
        let shared_terms = |list_names: &[&str]| {
            let mut terms = HashSet::new();
            for list_name in list_names {
                for term in md.get_list(list_name) {
                    let normalized_term = normalize_text(&term.to_lowercase());
                    if normalized_term.chars().count() >= 2
                        && normalized_text.contains(&normalized_term)
                        && normalized_body.contains(&normalized_term)
                    {
                        terms.insert(normalized_term);
                    }
                }
            }
            terms
        };
        let shared_actions = shared_terms(&[
            "external_action_link_action_terms",
            "external_action_link_extra_action_terms",
            "external_action_link_extra_action_terms_v2",
            "external_action_link_locale_action_terms",
            "pii_external_collection_action_terms",
            "pii_external_collection_action_terms_extra",
            "external_sensitive_exfiltration_action_terms",
        ]);
        let shared_context = shared_terms(&[
            "external_action_link_context_terms",
            "external_action_link_extra_context_terms",
            "external_action_link_extra_context_terms_v2",
            "external_action_link_locale_context_terms",
            "external_action_link_high_risk_terms",
            "pii_external_collection_context_terms",
            "pii_external_collection_context_terms_extra",
        ]);
        (!shared_actions.is_empty() && !shared_context.is_empty()) || shared_actions.len() >= 2
    })
}

fn any_actionable_html_anchor_domain<F>(ctx: &SecurityContext, body: &str, mut predicate: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    ctx.session
        .content
        .body_html
        .as_deref()
        .is_some_and(|html| {
            let anchors = visible_anchor_facts(html);
            if anchors.is_empty() {
                return false;
            }
            let normalized_body = normalize_text(&body.to_lowercase());
            anchors.iter().any(|anchor| {
                let effective = effective_structural_url(&anchor.href);
                let Ok(parsed) = url::Url::parse(&effective) else {
                    return false;
                };
                let Some(domain) = parsed.host_str() else {
                    return false;
                };
                let anchor_in_actionable_context = {
                    let normalized_anchor = normalize_text(&anchor.anchor_text.to_lowercase());
                    let normalized_href = normalize_text(&anchor.href.to_lowercase());
                    (!normalized_anchor.is_empty() && normalized_body.contains(&normalized_anchor))
                        || (!normalized_href.is_empty()
                            && normalized_body.contains(&normalized_href))
                };
                anchor_in_actionable_context && predicate(domain)
            })
        })
}

/// ContentScan runs before LinkScan in the inline module order, so plain-text
/// URLs are not necessarily present in `session.content.links` yet.  Keep the
/// destination test structural and reuse the same trusted-domain policy; the
/// semantic decision remains in the JSON-backed detector compounds.
fn has_untrusted_body_destination(ctx: &SecurityContext, body: &str) -> bool {
    if ctx.session.content.links.iter().any(|link| {
        link_is_actionable_in_context(ctx, link, body)
            && is_untrusted_clickable_link(ctx, &link.url)
    }) {
        return true;
    }
    if any_actionable_html_anchor_domain(ctx, body, |domain| {
        !ctx.is_internal_domain(domain)
            && !module_data().contains("protected_domains", domain)
            && !crate::modules::link_scan::is_trusted_url_domain(domain)
            && !crate::modules::link_scan::is_well_known_safe_domain(domain)
    }) {
        return true;
    }
    if !should_scan_projected_html_urls(ctx) {
        return false;
    }
    RE_HTML_ALT_URL.find_iter(body).any(|matched| {
        let raw = matched
            .as_str()
            .replace('：', ":")
            .trim_end_matches([
                '.', ',', ';', ':', '!', '?', '，', '。', '；', '：', '！', '？', '）', '】',
            ])
            .to_string();
        let effective = effective_structural_url(&raw);
        let Ok(parsed) = url::Url::parse(&effective) else {
            return false;
        };
        let Some(domain) = parsed.host_str().map(str::to_ascii_lowercase) else {
            return false;
        };
        !ctx.is_internal_domain(&domain)
            && !module_data().contains("protected_domains", &domain)
            && !crate::modules::link_scan::is_trusted_url_domain(&domain)
            && !crate::modules::link_scan::is_well_known_safe_domain(&domain)
    })
}

/// Generic action-link detection needs a stronger destination relation than
/// the broad untrusted-link observation used by the other detectors. A
/// sender's own host (or a subdomain of it) is a normal transactional path;
/// keep it available to the dedicated detectors, but do not let it become a
/// generic phishing cluster by itself.
fn has_cross_domain_untrusted_body_destination(
    ctx: &SecurityContext,
    body: &str,
    sender_domain: Option<&str>,
) -> bool {
    let sender_domain =
        sender_domain.map(|domain| domain.trim_end_matches('.').to_ascii_lowercase());
    let is_cross_domain = |domain: &str| {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let sender_related = sender_domain.as_deref().is_some_and(|sender| {
            domain == sender
                || domain.ends_with(&format!(".{sender}"))
                || domains_share_organizational_domain(&domain, sender)
        });
        !sender_related
            && !ctx.is_internal_domain(&domain)
            && !module_data().contains("protected_domains", &domain)
            && !crate::modules::link_scan::is_trusted_url_domain(&domain)
            && !crate::modules::link_scan::is_well_known_safe_domain(&domain)
    };

    if ctx.session.content.links.iter().any(|link| {
        link_is_actionable_in_context(ctx, link, body) && {
            let effective_url = effective_structural_url(&link.url);
            extract_domain_from_url(&effective_url).is_some_and(|domain| is_cross_domain(&domain))
        }
    }) {
        return true;
    }

    if any_actionable_html_anchor_domain(ctx, body, |domain| is_cross_domain(domain)) {
        return true;
    }

    if !should_scan_projected_html_urls(ctx) {
        return false;
    }

    RE_HTML_ALT_URL.find_iter(body).any(|matched| {
        let raw = matched
            .as_str()
            .replace('：', ":")
            .trim_end_matches([
                '.', ',', ';', ':', '!', '?', '，', '。', '；', '：', '！', '？', '）', '】',
            ])
            .to_string();
        let effective = effective_structural_url(&raw);
        let Ok(parsed) = url::Url::parse(&effective) else {
            return false;
        };
        parsed.host_str().is_some_and(is_cross_domain)
    })
}

fn has_shortener_destination(ctx: &SecurityContext) -> bool {
    let md = module_data();
    ctx.session.content.links.iter().any(|link| {
        let Some(domain) = extract_domain_from_url(&link.url) else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        md.get_list("url_shorteners")
            .iter()
            .any(|shortener| domain == *shortener || domain.ends_with(&format!(".{shortener}")))
            || md
                .get_list("url_shortener_lookalike_tokens")
                .iter()
                .any(|token| domain.contains(token))
    })
}

fn first_untrusted_embedded_url(
    ctx: &SecurityContext,
    html: &str,
    pattern: &Regex,
) -> Option<String> {
    pattern.captures_iter(html).find_map(|captures| {
        let raw = captures.get(1)?.as_str().trim();
        let parsed = url::Url::parse(raw).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let untrusted = !ctx.is_internal_domain(&host)
            && !module_data().contains("protected_domains", &host)
            && !crate::modules::link_scan::is_trusted_url_domain(&host)
            && !crate::modules::link_scan::is_well_known_safe_domain(&host);
        (untrusted && matches!(parsed.scheme(), "http" | "https")).then_some(raw.to_string())
    })
}

fn has_external_impersonation_lure(text: &str) -> bool {
    // Single words such as "支付" or "银行" are common in legitimate
    // business plans and financial reports.  Require an actionable lure
    // phrase instead of treating those business-domain words as phishing.
    let normalized = normalize_text(&text.to_lowercase());
    module_data()
        .get_list("external_impersonation_actionable_lure_phrases")
        .iter()
        .any(|term| normalized.contains(term))
}

fn has_explicit_authority_claim(text: &str, authority_phrases: &[String]) -> bool {
    let md = module_data();
    let claim_markers = md.get_list("external_impersonation_claim_markers");
    let normalized = normalize_text(&text.to_lowercase());
    normalized
        .split(['\n', '\r', '。', '！', '？', '!', '?', ';', '；'])
        .any(|block| {
            authority_phrases
                .iter()
                .any(|phrase| block.contains(phrase))
                && claim_markers.iter().any(|marker| block.contains(marker))
        })
}

fn is_targeted_account_login_alert(ctx: &SecurityContext, normalized_subject: &str) -> bool {
    module_data()
        .get_list("account_login_alert_subjects")
        .iter()
        .any(|phrase| normalized_subject.contains(phrase.as_str()))
        && has_untrusted_clickable_link(ctx)
}

fn is_reported_security_case_segment(segment: &str) -> bool {
    let md = module_data();
    let has_report_actor = md
        .get_list("security_case_actor_markers")
        .iter()
        .any(|marker| segment.contains(&normalize_text(&marker.to_lowercase())));
    let has_report_narrative = md
        .get_list("security_case_narrative_markers")
        .iter()
        .any(|marker| segment.contains(&normalize_text(&marker.to_lowercase())));
    has_report_actor && has_report_narrative
}

#[derive(Debug)]
struct SemanticSegment {
    text: String,
    list_item: bool,
}

fn starts_semantic_list_item(line: &str) -> bool {
    let line = line.trim_start();
    if line
        .chars()
        .next()
        .is_some_and(|character| matches!(character, '-' | '*' | '+' | '•' | '·' | '▪' | '◦' | '‣'))
    {
        return true;
    }
    let digit_prefix = line
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    digit_prefix > 0
        && line
            .chars()
            .nth(digit_prefix)
            .is_some_and(|character| matches!(character, '.' | ')' | '、'))
}

fn append_semantic_line(
    output: &mut Vec<SemanticSegment>,
    buffer: &mut String,
    list_item: &mut bool,
    quoted: &mut bool,
) {
    if buffer.trim().is_empty() {
        buffer.clear();
        *list_item = false;
        *quoted = false;
        return;
    }

    // Do not split on URL punctuation: the same helper is used to build the
    // positive detector view, and destroying `https://host/path` would lose
    // the link relation while trying to scope a negative sentence.
    let url_ranges = RE_HTML_ALT_URL
        .find_iter(buffer)
        .map(|url| {
            // A printed destination's trailing sentence punctuation belongs
            // to prose, not to the transport token. Protect its internal
            // dots without hiding the independent request in the next sentence.
            let url_text = trim_printed_url_punctuation(url.as_str());
            url.start()..url.start() + url_text.len()
        })
        .collect::<Vec<_>>();
    let mut range_index = 0;
    let mut boundaries = Vec::new();
    for boundary in RE_SEMANTIC_SENTENCE_BOUNDARY.find_iter(buffer) {
        while url_ranges
            .get(range_index)
            .is_some_and(|url| url.end <= boundary.start())
        {
            range_index += 1;
        }
        if !url_ranges
            .get(range_index)
            .is_some_and(|url| url.contains(&boundary.start()))
        {
            boundaries.push((boundary.start(), boundary.end()));
        }
    }
    boundaries.push((buffer.len(), buffer.len()));
    let mut start = 0;
    for (end, next) in boundaries {
        let segment = &buffer[start..end];
        start = next;
        let segment = segment.trim();
        if !segment.is_empty() {
            output.push(SemanticSegment {
                text: if *quoted && !segment.starts_with('>') {
                    format!("> {segment}")
                } else {
                    segment.to_string()
                },
                list_item: *list_item,
            });
        }
    }
    buffer.clear();
    *list_item = false;
    *quoted = false;
}

fn semantic_segments(text: &str) -> impl Iterator<Item = SemanticSegment> {
    let mut output = Vec::new();
    for paragraph in text.split("\n\n") {
        let mut buffer = String::new();
        let mut list_item = false;
        let mut quoted = false;
        for physical_line in paragraph.lines() {
            let line_indent = physical_line
                .chars()
                .take_while(|character| character.is_whitespace())
                .count();
            let line = physical_line.trim();
            if line.is_empty() {
                append_semantic_line(&mut output, &mut buffer, &mut list_item, &mut quoted);
                continue;
            }

            if let Some((intro, items)) = split_inline_counter_context_list(line) {
                append_semantic_line(&mut output, &mut buffer, &mut list_item, &mut quoted);
                output.push(SemanticSegment {
                    text: intro,
                    list_item: false,
                });
                output.extend(items.into_iter().map(|text| SemanticSegment {
                    text,
                    list_item: true,
                }));
                continue;
            }

            let starts_list_item = starts_semantic_list_item(line);
            let starts_quote = line.starts_with('>');
            if starts_list_item || starts_quote {
                append_semantic_line(&mut output, &mut buffer, &mut list_item, &mut quoted);
                buffer.push_str(line);
                list_item = starts_list_item;
                quoted = starts_quote;
            } else if (list_item || quoted) && line_indent < 2 {
                // Indented physical lines are ordinary wraps of a bullet;
                // an unindented line starts a new span and must not inherit
                // the warning-list or forwarded-quote scope.
                append_semantic_line(&mut output, &mut buffer, &mut list_item, &mut quoted);
                buffer.push_str(line);
            } else if buffer.is_empty() {
                buffer.push_str(line);
            } else {
                // RFC 5322 soft wraps frequently split a negation and its
                // object across physical lines. Fold those lines before
                // testing semantics; explicit list items and quotes remain
                // separate spans above.
                buffer.push(' ');
                buffer.push_str(line);
            }
        }
        append_semantic_line(&mut output, &mut buffer, &mut list_item, &mut quoted);
    }
    output.into_iter()
}

/// Build short positive-evidence windows without joining unrelated sections
/// or spans that were explicitly marked as warnings, reports, or quotations.
fn bounded_actionable_windows(text: &str, max_segments: usize, max_chars: usize) -> Vec<String> {
    let segments = semantic_segments(text)
        .map(|segment| segment.text)
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    // Neighboring windows overlap heavily. Classify each segment once instead
    // of normalizing the same text again for every window that contains it.
    let counter_context = segments
        .iter()
        .map(|segment| is_counter_context_segment(segment))
        .collect::<Vec<_>>();
    let segment_char_counts = segments
        .iter()
        // Gateway rewrites can add kilobytes of URL parameters to a short
        // request. Bound semantic prose while preserving the source URL in
        // the emitted window for independent destination binding.
        .map(|segment| {
            semantic_prose_without_transport_tokens(segment)
                .chars()
                .count()
        })
        .collect::<Vec<_>>();
    let mut windows = Vec::new();
    for start in 0..segments.len() {
        let mut window_chars = 0usize;
        for length in 1..=max_segments.min(segments.len() - start) {
            let segment_index = start + length - 1;
            window_chars += segment_char_counts[segment_index] + usize::from(length > 1);
            if window_chars > max_chars || counter_context[segment_index] {
                // Any longer window from this start can only be larger or
                // continue to include the same counter-context segment.
                break;
            }
            windows.push(segments[start..=segment_index].join(" "));
        }
    }
    windows
}

/// Return true only when a no-IOC message contains an explicit handoff inside
/// one paragraph.  Counting `submit`, `account`, or `deadline` across a long
/// notice joins unrelated process descriptions; a real social-engineering
/// solicitation has a local action + delivery/contact relation instead.
fn has_local_no_ioc_solicitation_demand(text: &str) -> bool {
    let md = module_data();
    semantic_paragraphs(text).any(|paragraph| {
        if is_counter_context_segment(paragraph) {
            return false;
        }
        let (normalized, compact) = normalized_and_compact(paragraph);
        let explicit_action = count_config_terms(
            &normalized,
            &compact,
            md.get_list("bec_no_ioc_explicit_solicitation_action_terms"),
        ) > 0;
        explicit_action
            && count_config_terms(
                &normalized,
                &compact,
                md.get_list("bec_no_ioc_solicitation_contact_terms"),
            ) > 0
    })
}

/// Keep no-IOC BEC pressure local to the actual payment/contact request.
/// A long warning can quote an attacker's deadline and fee while describing a
/// separate routine payment process; those distant phrases must not complete
/// the same fraud compound.
fn has_local_no_ioc_solicitation_compound(text: &str) -> bool {
    let md = module_data();
    bounded_actionable_windows(text, 3, 512)
        .iter()
        .any(|window| {
            let (normalized, compact) = normalized_and_compact(window);
            count_config_terms(
                &normalized,
                &compact,
                md.get_list("bec_no_ioc_solicitation_context_terms"),
            ) > 0
                && count_config_terms(
                    &normalized,
                    &compact,
                    md.get_list("bec_no_ioc_solicitation_value_terms"),
                ) > 0
                && count_config_terms(
                    &normalized,
                    &compact,
                    md.get_list("bec_no_ioc_solicitation_pressure_terms"),
                ) > 0
                && (count_config_terms(
                    &normalized,
                    &compact,
                    md.get_list("bec_no_ioc_solicitation_secrecy_terms"),
                ) > 0
                    || count_config_terms(
                        &normalized,
                        &compact,
                        md.get_list("bec_no_ioc_solicitation_contact_terms"),
                    ) > 0)
                && has_local_no_ioc_solicitation_demand(window)
                && has_recipient_directed_action(window)
        })
}

fn semantic_paragraphs(text: &str) -> impl Iterator<Item = &str> {
    text.split("\n\n")
        .map(str::trim)
        .filter(|paragraph| !paragraph.is_empty())
}

fn is_quoted_or_forwarded_segment(segment: &str) -> bool {
    let lower = segment.trim_start().to_ascii_lowercase();
    lower.starts_with('>')
        || lower.starts_with("fwd:")
        || lower.starts_with("fw:")
        || lower.starts_with("forwarded message")
        || lower.starts_with("转发")
        || lower.starts_with("转寄")
        || lower.starts_with("以下为原邮件")
        || lower.starts_with("原邮件")
}

/// Return true when a message asks the recipient to use or enter an account
/// credential without depending on the mutable phishing keyword seed.  This
/// intentionally uses phrases rather than single words such as `account` or
/// `continue`, which are common in legitimate product mail.
fn has_credential_continuation_instruction(text: &str, list_name: &str) -> bool {
    let normalized = normalize_text(&text.to_lowercase());
    module_data()
        .get_list(list_name)
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialContentLurePolicy {
    enabled: bool,
    credential_link_category: String,
    content_instruction_list: String,
    content_auth_path_list: String,
    content_auth_anchor_list: String,
    official_sso_domains_list: String,
    content_external_sender_score: f64,
    content_well_known_sender_score: f64,
}

fn parse_credential_content_lure_policy(
    value: serde_json::Value,
) -> Option<CredentialContentLurePolicy> {
    let policy = serde_json::from_value::<CredentialContentLurePolicy>(value).ok()?;
    (policy.enabled
        && !policy.credential_link_category.trim().is_empty()
        && !policy.content_instruction_list.trim().is_empty()
        && !policy.content_auth_path_list.trim().is_empty()
        && !policy.content_auth_anchor_list.trim().is_empty()
        && !policy.official_sso_domains_list.trim().is_empty()
        && (0.0..=1.0).contains(&policy.content_external_sender_score)
        && (0.0..=1.0).contains(&policy.content_well_known_sender_score))
    .then_some(policy)
}

fn credential_content_lure_policy() -> Option<CredentialContentLurePolicy> {
    parse_credential_content_lure_policy(
        module_data()
            .get_structured("credential_brand_target_policy_v1")?
            .clone(),
    )
}

/// Official identity-provider hosts are not treated as untrusted link
/// destinations.  This is deliberately separate from the sender allowlist:
/// an external sender may legitimately link to a customer's configured SSO
/// provider, while an attacker-controlled lookalike host must not inherit that
/// trust merely from a familiar brand string in its URL.
fn is_official_sso_destination(domain: &str, list_name: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    module_data()
        .get_list(list_name)
        .iter()
        .any(|official| domain == *official || domain.ends_with(&format!(".{official}")))
}

/// Detect a clickable, externally hosted authentication destination.  A
/// normal-looking HTTPS link is not enough: the path/anchor must describe an
/// authentication flow and the destination must be outside the configured
/// URL trust set and official SSO hosts.
fn has_untrusted_authentication_link(
    ctx: &SecurityContext,
    auth_path_list: &str,
    auth_anchor_list: &str,
    official_sso_list: &str,
) -> bool {
    let md = module_data();
    let auth_path_segments = md.get_list(auth_path_list);
    let auth_anchor_phrases = md.get_list(auth_anchor_list);
    ctx.session.content.links.iter().any(|link| {
        let effective = crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
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
            || is_official_sso_destination(domain, official_sso_list)
        {
            return false;
        }

        let path_auth = parsed.path_segments().is_some_and(|segments| {
            segments
                .map(str::to_ascii_lowercase)
                .any(|segment| auth_path_segments.iter().any(|term| term == &segment))
        });
        let anchor_auth = link.text.as_deref().is_some_and(|text| {
            let normalized = normalize_text(&text.to_lowercase());
            auth_anchor_phrases
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
    let fallback_body = if body_hint.is_none() {
        ctx.session
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
            .unwrap_or_default()
    } else {
        String::new()
    };
    let body = body_hint.unwrap_or(&fallback_body);
    let combined = normalize_text(&format!("{subject}\n\n{body}").to_ascii_lowercase());

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

/// Recognize a completed password/account notification as transactional mail.
/// A subject keyword such as "重置密码" is not enough to suppress detection:
/// the body must describe a completed account operation, contain no
/// attachments, and have no untrusted clickable destination.
pub(super) fn looks_like_benign_account_notice(
    ctx: &SecurityContext,
    body_hint: Option<&str>,
) -> bool {
    if !ctx.session.content.attachments.is_empty() {
        return false;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or("");
    let fallback_body = if body_hint.is_none() {
        ctx.session
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
            .unwrap_or_default()
    } else {
        String::new()
    };
    let body = body_hint.unwrap_or(&fallback_body);
    let subject_norm = normalize_text(&subject.to_lowercase());
    let body_norm = normalize_text(&body.to_lowercase());
    let combined = format!("{subject_norm}\n{body_norm}");

    let configured_marker_present = |list_name: &str, text: &str| {
        module_data()
            .get_list(list_name)
            .iter()
            .any(|marker| text.contains(normalize_text(&marker.to_lowercase()).as_str()))
    };
    // These local exceptions require every marker in one of three candidate
    // groups. Check that necessary condition against a cheap flattened view
    // first; otherwise an ordinary long message would eagerly enumerate every
    // semantic window just to prove that none can satisfy the exception.
    // Flattening is a superset of semantic wrapping, so this gate cannot hide
    // a locally matching marker group.
    let prefilter_text = combined.replace(['\r', '\n'], " ");
    let reset_notice_candidate =
        configured_marker_present("benign_account_notice_reset_markers", &prefilter_text)
            && configured_marker_present(
                "benign_account_notice_completion_markers",
                &prefilter_text,
            );
    let reset_request_candidate = [
        "benign_account_notice_reset_request_markers",
        "benign_account_notice_reset_single_use_markers",
        "benign_account_notice_reset_expiry_markers",
        "benign_account_notice_reset_noninitiator_markers",
    ]
    .iter()
    .all(|list_name| configured_marker_present(list_name, &prefilter_text));
    let no_action_alert_candidate = configured_marker_present(
        "benign_account_notice_completed_alert_markers",
        &prefilter_text,
    ) && configured_marker_present(
        "benign_account_notice_anti_phishing_markers",
        &prefilter_text,
    );
    if !reset_notice_candidate && !reset_request_candidate && !no_action_alert_candidate {
        return false;
    }

    let links_are_non_actionable = ctx.session.content.links.iter().all(|link| {
        is_probable_non_clickable_render_asset_url(&link.url)
            || extract_domain_from_url(&link.url)
                .is_some_and(|domain| crate::modules::link_scan::is_trusted_url_domain(&domain))
    });

    // A completed security alert with a configured no-action warning is a
    // notification, not a credential lure. Keep this narrow and data-driven:
    // require both event and warning markers, plus no clickable destination.
    let scoped_reset_notice = reset_notice_candidate
        && semantic_segments(&combined).any(|segment| {
            configured_marker_present("benign_account_notice_reset_markers", &segment.text)
                && configured_marker_present(
                    "benign_account_notice_completion_markers",
                    &segment.text,
                )
                && !configured_marker_present(
                    "benign_account_notice_credential_request_markers",
                    &segment.text,
                )
        });
    let scoped_reset_request_notice = reset_request_candidate
        && bounded_actionable_windows(&combined, 4, 512)
            .iter()
            .any(|window| {
                configured_marker_present("benign_account_notice_reset_request_markers", window)
                    && configured_marker_present(
                        "benign_account_notice_reset_single_use_markers",
                        window,
                    )
                    && configured_marker_present(
                        "benign_account_notice_reset_expiry_markers",
                        window,
                    )
                    && configured_marker_present(
                        "benign_account_notice_reset_noninitiator_markers",
                        window,
                    )
                    && !configured_marker_present(
                        "benign_account_notice_credential_request_markers",
                        window,
                    )
            });
    let scoped_no_action_alert = no_action_alert_candidate && {
        let alert_segments = semantic_segments(&body_norm)
            .map(|segment| segment.text)
            .collect::<Vec<_>>();
        (1..=2).any(|window_len| {
            alert_segments.windows(window_len).any(|window| {
                let combined = window.join(" ");
                combined.chars().count() <= 320
                    && configured_marker_present(
                        "benign_account_notice_completed_alert_markers",
                        &combined,
                    )
                    && configured_marker_present(
                        "benign_account_notice_anti_phishing_markers",
                        &combined,
                    )
            })
        })
    };

    (scoped_reset_notice && links_are_non_actionable)
        || (scoped_reset_request_notice && has_aligned_password_reset_destination(ctx))
        || (scoped_no_action_alert && ctx.session.content.links.is_empty())
}

/// A narrowly scoped password-reset request notice can contain a one-time
/// reset link without asking the recipient to disclose a password. Keep it
/// transactional only when the request receipt, short expiry, single-use
/// property, and non-initiator warning occur together, and every destination
/// is an HTTPS reset path on the sender's organizational domain. Domain
/// alignment is a content calibration fact, not proof of ownership or auth.
fn has_aligned_password_reset_destination(ctx: &SecurityContext) -> bool {
    let Some(sender_domain) = external_sender_domain(ctx) else {
        return false;
    };
    let links = &ctx.session.content.links;
    !links.is_empty()
        && !ctx.session.content.links_truncated
        && links.iter().all(|link| {
            let effective = effective_structural_url(&link.url);
            let Ok(parsed) = url::Url::parse(&effective) else {
                return false;
            };
            if parsed.scheme() != "https"
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || has_shortener_destination(ctx)
            {
                return false;
            }
            let Some(host) = parsed.host_str() else {
                return false;
            };
            let host = host.to_ascii_lowercase();
            let path = parsed.path().to_ascii_lowercase();
            domains_share_organizational_domain(&host, &sender_domain)
                && host.parse::<std::net::IpAddr>().is_err()
                && ["reset", "recover", "password"]
                    .iter()
                    .any(|marker| path.contains(marker))
        })
}

/// Security-awareness messages often reproduce a password-expiry lure in a
/// training/report section. Do not treat that quoted lure as the current
/// subject's action when the message explicitly says password mail has no
/// links and routes changes through the internal portal or help desk.
fn is_routine_password_awareness_notice(ctx: &SecurityContext) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.iter().any(|link| link.suspicious)
    {
        return false;
    }
    let sender_domain = external_sender_domain(ctx);
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or_else(|| ctx.session.content.body_html.as_deref())
        .unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let (normalized, compact) = normalized_and_compact(&combined);
    count_config_terms(
        &normalized,
        &compact,
        module_data().get_list("routine_password_awareness_markers"),
    ) >= 3
        && !has_cross_domain_untrusted_body_destination(ctx, &combined, sender_domain.as_deref())
}

fn detector_body_fallback_text<'a>(
    ctx: &'a SecurityContext,
    body_for_cross: Option<&'a str>,
) -> Option<Cow<'a, str>> {
    body_for_cross
        .map(str::trim)
        .filter(|body| !body.is_empty())
        .map(bounded_detector_text)
        .or_else(|| {
            ctx.session
                .content
                .body_text
                .as_deref()
                .map(str::trim)
                .filter(|body| !body.is_empty())
                .map(bounded_detector_text)
        })
        .or_else(|| {
            ctx.session
                .content
                .body_html
                .as_deref()
                .map(strip_html_tags)
                .map(|body| body.trim().to_string())
                .filter(|body| !body.is_empty())
                .map(|body| Cow::Owned(bounded_detector_text(&body).into_owned()))
        })
}

const MAX_COMPOUND_DETECTOR_BYTES: usize = 32 * 1024;

fn bounded_detector_text<'a>(text: &'a str) -> Cow<'a, str> {
    if text.len() <= MAX_COMPOUND_DETECTOR_BYTES {
        return Cow::Borrowed(text);
    }
    let head_bytes = MAX_COMPOUND_DETECTOR_BYTES / 2;
    let mut head_end = head_bytes.min(text.len());
    while head_end > 0 && !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let tail_bytes = MAX_COMPOUND_DETECTOR_BYTES - head_end;
    let mut tail_start = text.len().saturating_sub(tail_bytes);
    while tail_start < text.len() && !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    Cow::Owned(format!(
        "{}\n[content-window-gap]\n{}",
        &text[..head_end],
        &text[tail_start..]
    ))
}

#[derive(Clone)]
struct NormalizedConfigTerm {
    normalized: String,
    compact: String,
}

type NormalizedConfigTermCacheEntry = (Vec<String>, Arc<Vec<NormalizedConfigTerm>>);

fn normalized_config_terms(terms: &[String]) -> Arc<Vec<NormalizedConfigTerm>> {
    static CACHE: Mutex<Vec<NormalizedConfigTermCacheEntry>> = Mutex::new(Vec::new());

    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, normalized)) = guard
        .iter()
        .find(|(cached_terms, _)| cached_terms.as_slice() == terms)
    {
        return Arc::clone(normalized);
    }

    let normalized = terms
        .iter()
        .map(|term| {
            let normalized = normalize_text(&term.to_lowercase());
            let compact = normalized
                .chars()
                .filter(|character| character.is_alphanumeric())
                .collect();
            NormalizedConfigTerm {
                normalized,
                compact,
            }
        })
        .collect::<Vec<_>>();
    let normalized = Arc::new(normalized);
    if guard.len() >= 256 {
        guard.clear();
    }
    guard.push((terms.to_vec(), Arc::clone(&normalized)));
    normalized
}

fn count_config_terms(haystack: &str, compact_haystack: &str, terms: &[String]) -> usize {
    // Most detector calls share the same long body. Reject terms whose first
    // character cannot occur before doing the more expensive normalization and
    // substring checks; this keeps large benign bodies within the inline
    // budget without changing a positive match.
    let mut haystack_first_bytes = [false; 256];
    let mut compact_first_bytes = [false; 256];
    for byte in haystack.bytes() {
        haystack_first_bytes[byte as usize] = true;
    }
    for byte in compact_haystack.bytes() {
        compact_first_bytes[byte as usize] = true;
    }
    terms
        .iter()
        .zip(normalized_config_terms(terms).iter())
        .filter(|(_, pattern)| {
            let normalized = &pattern.normalized;
            if normalized.is_empty() {
                return false;
            }
            let first_byte = normalized.as_bytes().first().copied().unwrap_or_default();
            if !haystack_first_bytes[first_byte as usize]
                && !compact_first_bytes[first_byte as usize]
            {
                return false;
            }
            if haystack.contains(normalized.as_str()) {
                return true;
            }
            !pattern.compact.is_empty() && compact_haystack.contains(pattern.compact.as_str())
        })
        .count()
}

fn first_config_term_hit(
    haystack: &str,
    compact_haystack: &str,
    terms: &[String],
) -> Option<String> {
    terms
        .iter()
        .zip(normalized_config_terms(terms).iter())
        .find(|(_, pattern)| {
            (!pattern.normalized.is_empty() && haystack.contains(pattern.normalized.as_str()))
                || (!pattern.compact.is_empty()
                    && compact_haystack.contains(pattern.compact.as_str()))
        })
        .map(|(term, _)| term)
        .cloned()
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
    qualified_threat_actions: &mut Vec<serde_json::Value>,
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

    // A clean text/plain alternative can hide a complete account lure in the
    // richer HTML alternative.  Keep this path deterministic and bounded:
    // require an external sender, a recipient-facing account threat/action
    // pair, and an untrusted clickable destination before admitting the
    // account-security category.
    let html_raw_lower = sanitized_html.to_lowercase();
    let md = module_data();
    let html_has_account_threat = count_config_terms(
        &html_norm,
        &html_compact,
        md.get_list("account_security_threat_phrases_body"),
    ) > 0
        || count_config_terms(
            &html_norm,
            &html_compact,
            md.get_list("account_security_extra_threat_phrases_body"),
        ) > 0
        || account_security_threats().is_match(&html_norm)
        || account_security_threats().is_match(&html_raw_lower);
    let html_has_account_action = count_config_terms(
        &html_norm,
        &html_compact,
        md.get_list("account_security_action_phrases_body"),
    ) > 0
        || count_config_terms(
            &html_norm,
            &html_compact,
            md.get_list("account_security_extra_action_phrases_body"),
        ) > 0
        || account_security_actions().is_match(&html_norm)
        || account_security_actions().is_match(&html_raw_lower)
        || (html_norm.contains("点击") && html_norm.contains("验证"));
    let sender_domain = external_sender_domain(ctx);
    if html_has_account_threat
        && html_has_account_action
        && is_external_sender_for_bec(ctx, sender_domain.as_deref())
        && has_untrusted_clickable_link(ctx)
        && !categories
            .iter()
            .any(|category| category == "account_security_phishing")
    {
        *total_score += 0.65;
        categories.push("account_security_phishing".to_string());
        threat_actions::record_html_account_actions(
            ctx,
            0.65,
            &|text| {
                let (normalized, compact) = normalized_and_compact(text);
                let raw = text.to_lowercase();
                let threat = [
                    "account_security_threat_phrases_body",
                    "account_security_extra_threat_phrases_body",
                ]
                .iter()
                .any(|name| count_config_terms(&normalized, &compact, md.get_list(name)) > 0)
                    || account_security_threats().is_match(&normalized)
                    || account_security_threats().is_match(&raw);
                let action = [
                    "account_security_action_phrases_body",
                    "account_security_extra_action_phrases_body",
                ]
                .iter()
                .any(|name| count_config_terms(&normalized, &compact, md.get_list(name)) > 0)
                    || account_security_actions().is_match(&normalized)
                    || account_security_actions().is_match(&raw)
                    || (normalized.contains("点击") && normalized.contains("验证"));
                threat && action
            },
            qualified_threat_actions,
        );
        evidence.push(Evidence {
            description:
                "HTML alternative combines an account-security warning, a recipient action, and an untrusted destination"
                    .to_string(),
            location: Some("body:html_alternative + links".to_string()),
            snippet: Some(sanitized_html.chars().take(160).collect()),
        });
    }

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

    // Some gateways expose only a short plain-text stub while the actual
    // warning and classification live in the richer HTML alternative.  Do
    // not let that transport representation hide an upstream verdict.
    let body_for_gw = match ctx.session.content.body_text.as_deref() {
        Some(body_text) if body_text.chars().count() >= 80 => body_text.to_string(),
        Some(body_text) => ctx
            .session
            .content
            .body_html
            .as_deref()
            .map(strip_html_tags)
            .filter(|html| !html.trim().is_empty())
            .unwrap_or_else(|| body_text.to_string()),
        None => ctx
            .session
            .content
            .body_html
            .as_deref()
            .map(strip_html_tags)
            .unwrap_or_default(),
    };

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
        if gateway_prior_reports_spam(&gw_prefix)
            || ctx
                .session
                .subject
                .as_deref()
                .is_some_and(gateway_prior_reports_spam)
        {
            categories.push("gateway_spam_classified".to_string());
            evidence.push(Evidence {
                description: "Upstream security gateway explicitly classified the message as spam"
                    .to_string(),
                location: Some("body:gateway_spam_result".to_string()),
                snippet: Some(gw_prefix.chars().take(120).collect()),
            });
        }
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

/// Return true only for an explicit spam verdict from the gateway wrapper.
/// Generic words such as "external email" and "potentially malicious" remain
/// contextual evidence and must not silently become a spam classification.
fn gateway_prior_reports_spam(text: &str) -> bool {
    let normalized = normalize_text(&text.to_lowercase());
    [
        "检测结果:垃圾邮件",
        "检测结果：垃圾邮件",
        "检测结果: 垃圾邮件",
        "检测结果： 垃圾邮件",
        "detection result: spam",
        "detection result： spam",
        "result: spam",
        "result： spam",
    ]
    .iter()
    .any(|pattern| normalized.contains(pattern))
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
    // Attack Medium, if a request to add a synthetic mobile fixture is present.
    // Note: email first AddSecurity if "[]",
    // packetContains"Risk"waitKeywords, first, Internal email.
    if let Some(ref subject) = ctx.session.subject {
        // Normalize (NFKC + invisible/combining marks) BEFORE banner-prefix
        // stripping: patterns are stored normalized, so full-width brackets
        // like 【外部邮件】 must fold to [外部邮件] first or the strip misses.
        let cleaned_subject =
            normalized_subject_for_scan(subject, gateway_banner_patterns, notice_banner_patterns);
        let sub_lower = cleaned_subject.to_lowercase();
        // Mediumof PhishingKeywords
        let mut subject_hits: Vec<&str> = phishing_keywords
            .iter()
            .filter(|kw| sub_lower.contains(kw.as_str()))
            .map(|kw| kw.as_str())
            .collect();

        let sender_is_external = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|address| address.rsplit('@').next())
            .is_none_or(|domain| !ctx.is_internal_domain(domain));
        let subject_security = normalize_text(&subject.to_lowercase());
        let has_mailbox_or_password = ["邮箱", "邮件", "mailbox", "password", "密码"]
            .iter()
            .any(|term| subject_security.contains(term));
        let has_expiry = ["过期", "到期", "失效", "expired", "expiry"]
            .iter()
            .any(|term| subject_security.contains(term));
        let has_update_action = ["更新", "修改", "重置", "验证", "update", "verify", "reset"]
            .iter()
            .any(|term| subject_security.contains(term));
        let account_expiry_candidate =
            sender_is_external && has_mailbox_or_password && has_expiry && has_update_action;

        // Body exceptions can only change a keyword hit or expiry candidate.
        // Ordinary subjects do not require repeated full-body normalization.
        let benign_verification =
            !subject_hits.is_empty() && looks_like_benign_verification_notice(ctx, None);
        let benign_account_notice = (!subject_hits.is_empty() || account_expiry_candidate)
            && looks_like_benign_account_notice(ctx, None);
        if benign_verification {
            subject_hits.retain(|kw| !is_benign_verification_keyword(kw));
        }
        if benign_account_notice {
            subject_hits.clear();
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

        // Subject-only mailbox/password expiry lures are common in short
        // external messages and are easy to miss when the body is benign.
        // Require all three semantic components and an external sender so an
        // internal IT notice is not promoted by the subject alone.
        if !benign_account_notice
            && account_expiry_candidate
            && !is_routine_password_awareness_notice(ctx)
        {
            *total_score += 0.20;
            categories.push("subject_account_expiry_lure".to_string());
            evidence.push(Evidence {
                description:
                    "External subject combines mailbox/password expiry with an update or verification action"
                        .to_string(),
                location: Some("subject".to_string()),
                snippet: Some(subject.clone()),
            });
        }

        // NFKC folds full-width digits and the filter drops zero-width
        // characters, so obfuscated numbers still match the ASCII-only regex.
        let normalized_subject = normalize_text(subject);
        let phone_matches: Vec<String> = RE_CHINESE_PHONE
            .captures_iter(&normalized_subject)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        let md = module_data();
        let has_phone_lure = md
            .get_list("subject_phone_lure_markers")
            .iter()
            .any(|marker| {
                normalized_subject
                    .to_lowercase()
                    .contains(&normalize_text(&marker.to_lowercase()))
            });
        let has_benign_phone_context = md
            .get_list("subject_phone_benign_context_markers")
            .iter()
            .any(|marker| {
                normalized_subject
                    .to_lowercase()
                    .contains(&normalize_text(&marker.to_lowercase()))
            });
        if !phone_matches.is_empty() && has_phone_lure && !has_benign_phone_context {
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
            !ctx.is_internal_domain(domain) && !module_data().contains("protected_domains", domain)
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
    qualified_threat_actions: &mut Vec<serde_json::Value>,
) -> Option<String> {
    // only 1bodyVersion,Avoid text + html Content
    // priorityUsePlain text (); Plain text HTML ofText
    let text_candidate = ctx
        .session
        .content
        .body_text
        .as_ref()
        .map(|body_text| {
            let decoded_body = decode_html_entities(body_text);
            sanitize_body_for_keyword_scan(
                &decoded_body,
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
        let benign_account_notice = looks_like_benign_account_notice(ctx, Some(sanitized));
        let filtered_phishing_keywords: Cow<'_, [String]> = if benign_account_notice {
            Cow::Owned(Vec::new())
        } else if benign_verification {
            Cow::Owned(
                phishing_keywords
                    .iter()
                    .filter(|kw| !is_benign_verification_keyword(kw))
                    .cloned()
                    .collect(),
            )
        } else {
            Cow::Borrowed(phishing_keywords)
        };
        *total_score += scan_text(
            sanitized,
            filtered_phishing_keywords.as_ref(),
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
                qualified_threat_actions,
            );
        }
    }

    selected
}

// ─── Step 4: Image-only phishing/layout ──────────────────────────────

/// Separates image-heavy layout observation from image phishing with a
/// parser-marked suspicious link. Ordinary image notifications remain visible
/// as context, but they do not receive threat score by themselves.
pub(super) fn detect_image_only_phishing(
    ctx: &SecurityContext,
    // mutable shared state
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let body_text_len = ctx
        .session
        .content
        .body_text
        .as_ref()
        .map_or(0, |t| t.trim().chars().count());
    let effective_text_len = if body_text_len < 50 {
        ctx.session
            .content
            .body_html
            .as_deref()
            .map_or(0, visible_html_text_len)
            .max(body_text_len)
    } else {
        body_text_len
    };

    let has_html_images = ctx.session.content.body_html.as_ref().is_some_and(|html| {
        let html_lower = html.to_lowercase();
        html_lower.contains("<img") || html_lower.contains("background-image")
    });
    let visual_carriers = ctx
        .session
        .content
        .body_html
        .as_deref()
        .map(visual_text_carriers)
        .unwrap_or_default();
    let external_visual_count = ctx
        .session
        .content
        .body_html
        .as_deref()
        .map(|html| RE_EXTERNAL_HTML_VISUAL_REFERENCE.find_iter(html).count())
        .unwrap_or(0);
    let has_links = !ctx.session.content.links.is_empty();
    let has_suspicious_links = ctx.session.content.links.iter().any(|link| link.suspicious);
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

    // A DOM text projection cannot see text painted into an image, SVG,
    // canvas, CSS background, or generated-content pseudo-element. Keep this
    // as a coverage observation even without a link; otherwise an image-only
    // Chinese lure can be presented as an analyzed empty message.
    if effective_text_len == 0 && !visual_carriers.is_empty() {
        categories.push("html_visual_text_uncovered".to_string());
        evidence.push(Evidence {
            description: format!(
                "HTML visible-text projection is empty but rendered visual text may be present in {}; OCR/rendered-text analysis is unavailable",
                visual_carriers.join(", ")
            ),
            location: Some("body_html visual content".to_string()),
            snippet: None,
        });
    }

    // External images can contain the substantive Chinese/English message
    // even when the DOM has normal text.  Until a dedicated SSRF-safe fetch
    // and offline render/OCR result is attached to this message, preserve the
    // missing-coverage fact instead of claiming the visual layer was scanned.
    if external_visual_count > 0 {
        categories.push("html_external_visual_unresolved".to_string());
        evidence.push(Evidence {
            description: format!(
                "{} external HTML visual resource(s) were not fetched/rendered in the isolated OCR path; visual text coverage is incomplete",
                external_visual_count
            ),
            location: Some("body_html external visual content".to_string()),
            snippet: None,
        });
    }

    // Image-only layout is useful analyst context, but a threat score requires
    // independent evidence. A narrow reward CTA compound also qualifies: a
    // reward/expiry subject, an explicit image-claim instruction, and a link
    // outside the sender's organization are actionable even when the URL itself
    // has no parser-level reputation signal.
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let subject_normalized = normalize_text(&subject.to_lowercase());
    let subject_compact = compact_detection_view(&subject_normalized);
    let md = module_data();
    let reward_subject = count_config_terms(
        &subject_normalized,
        &subject_compact,
        md.get_list("image_only_reward_cta_subject_terms"),
    ) > 0;
    let reward_action = count_config_terms(
        &subject_normalized,
        &subject_compact,
        md.get_list("image_only_reward_cta_action_terms"),
    ) > 0
        || ctx.session.content.links.iter().any(|link| {
            link.text.as_deref().is_some_and(|text| {
                let (normalized, compact) = normalized_and_compact(text);
                count_config_terms(
                    &normalized,
                    &compact,
                    md.get_list("image_only_reward_cta_action_terms"),
                ) > 0
            })
        });
    let sender_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|addr| addr.split('@').nth(1));
    let reward_external_destination = sender_domain.is_some_and(|sender_domain| {
        ctx.session.content.links.iter().any(|link| {
            if is_visual_resource_link(ctx, &link.url)
                || !is_untrusted_clickable_link(ctx, &link.url)
            {
                return false;
            }
            extract_domain_from_url(&link.url).is_some_and(|destination| {
                !domains_share_organizational_domain(&destination, sender_domain)
            })
        })
    });
    let image_reward_lure = reward_subject && reward_action && reward_external_destination;
    if effective_text_len < 50
        && has_html_images
        && has_links
        && !is_contact_card_layout
        && !is_wps_share_notice
        && !sender_is_internal
        && !sender_is_safe
        && !has_document_attachments
    {
        let (category, description) = if has_suspicious_links || image_reward_lure {
            *total_score += if image_reward_lure { 0.55 } else { 0.15 };
            (
                "image_only_phishing",
                if image_reward_lure {
                    "Image-only reward lure: reward CTA and an external organization-mismatched destination are paired with an HTML image".to_string()
                } else {
                    format!(
                        "Image-only phishing candidate: body contains {} characters, an HTML image, and a parser-marked suspicious link; text is too short for NLP analysis",
                        effective_text_len
                    )
                },
            )
        } else {
            (
                "image_only_layout_observed",
                format!(
                    "Image-heavy layout observed: body contains {} characters, an HTML image, and a link, but no independently suspicious link evidence",
                    effective_text_len
                ),
            )
        };
        categories.push(category.to_string());
        evidence.push(Evidence {
            description,
            location: Some("body".to_string()),
            snippet: None,
        });
    }
}

fn visual_text_carriers(html: &str) -> Vec<&'static str> {
    let lower = html.to_ascii_lowercase();
    let mut carriers = Vec::new();
    if lower.contains("<img") || lower.contains("data:image/") {
        carriers.push("image");
    }
    if lower.contains("<svg") {
        carriers.push("svg");
    }
    if lower.contains("<canvas") {
        carriers.push("canvas");
    }
    if lower.contains("background-image") {
        carriers.push("css_background");
    }
    if lower.contains("content:") {
        carriers.push("css_generated_content");
    }
    carriers
}

fn visible_html_text_len(html: &str) -> usize {
    let without_non_rendered_blocks = RE_NON_RENDERED_HTML_BLOCK.replace_all(html, " ");
    strip_html_tags(&without_non_rendered_blocks)
        .trim()
        .chars()
        .count()
}

// ─── Step 5: Account security phishing (merged original steps 4+6) ───

/// Delivery-failure and auto-reply framing is not trusted identity proof. It
/// only narrows this compound: a local, recipient-directed account threat,
/// explicit verification request, and suspension deadline must all co-occur
/// in a short canonical-body window, with no attachment or destination.
fn has_dsn_account_suspension_collision(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
) -> bool {
    if !ctx.session.content.attachments.is_empty() || !ctx.session.content.links.is_empty() {
        return false;
    }

    let raw_subject = ctx.session.subject.as_deref().unwrap_or_default();
    let normalized_subject = normalize_text(&raw_subject.to_lowercase());
    let subject_compact = compact_detection_view(&normalized_subject);
    let envelope_local = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|address| address.rsplit_once('@'))
        .map(|(local, _)| local.to_ascii_lowercase())
        .unwrap_or_default();
    let envelope_local_normalized = normalize_text(&envelope_local);
    let envelope_local_compact = compact_detection_view(&envelope_local_normalized);
    let md = module_data();
    let dsn_or_autoreply_subject = count_config_terms(
        &normalized_subject,
        &subject_compact,
        md.get_list("dsn_account_suspension_collision_subject_markers"),
    ) > 0;
    let automated_sender = count_config_terms(
        &envelope_local_normalized,
        &envelope_local_compact,
        md.get_list("dsn_account_suspension_collision_sender_markers"),
    ) > 0;
    if !dsn_or_autoreply_subject || !automated_sender {
        return false;
    }

    let html_fallback = if ctx.session.content.body_text.is_none() && body_for_cross.is_none() {
        ctx.session
            .content
            .body_html
            .as_deref()
            .map(strip_html_tags)
    } else {
        None
    };
    let canonical_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or(body_for_cross)
        .or(html_fallback.as_deref());
    let Some(canonical_body) = canonical_body else {
        return false;
    };
    let bounded_body = bounded_detector_text(canonical_body);
    let raw_body_lower = bounded_body.to_lowercase();
    let actionable_body = strip_counter_context_segments(&raw_body_lower);
    let segments = semantic_segments(&actionable_body)
        .map(|segment| segment.text)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    (1..=4).any(|window_len| {
        segments.windows(window_len).any(|window| {
            let combined = window.join(" ");
            if combined.chars().count() > 512 {
                return false;
            }
            let (normalized, compact) = normalized_and_compact(&combined);
            let has_account_threat = count_config_terms(
                &normalized,
                &compact,
                md.get_list("dsn_account_suspension_collision_threat_markers"),
            ) > 0;
            let has_verification_action = count_config_terms(
                &normalized,
                &compact,
                md.get_list("dsn_account_suspension_collision_action_markers"),
            ) > 0;
            let has_suspension_deadline = count_config_terms(
                &normalized,
                &compact,
                md.get_list("dsn_account_suspension_collision_deadline_markers"),
            ) > 0;
            has_account_threat
                && has_verification_action
                && has_recipient_directed_action(&combined)
                && has_suspension_deadline
        })
    })
}

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
    qualified_threat_actions: &mut Vec<serde_json::Value>,
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

    if has_dsn_account_suspension_collision(ctx, body_for_cross) {
        *total_score += 0.62;
        categories.push("account_security_phishing".to_string());
        evidence.push(Evidence {
            description: "Automated delivery-notice identity carries an unrelated 24-hour account-suspension verification demand".to_string(),
            location: Some("headers + account-security body".to_string()),
            snippet: Some(
                format!(
                    "{}\n{}",
                    ctx.session.subject.as_deref().unwrap_or_default(),
                    ctx.session
                        .content
                        .body_text
                        .as_deref()
                        .or(body_for_cross)
                        .unwrap_or_default()
                )
                .chars()
                .take(180)
                .collect(),
            ),
        });
        return;
    }

    if looks_like_benign_account_notice(ctx, body_for_cross) {
        return;
    }

    // A one-time-code notification may mention what to do when the recipient
    // did not initiate the login. That warning is safety guidance, not a
    // current request to submit credentials or change the account. Keep the
    // exemption narrow: attachments or untrusted links make the notice
    // ineligible for this benign path and remain actionable below.
    if looks_like_benign_verification_notice(ctx, body_for_cross) {
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
        .map(|text| strip_counter_context_segments(&text).into_owned())
        .collect::<Vec<_>>();
    let credential_policy = credential_content_lure_policy();
    let has_credential_instruction = credential_policy.as_ref().is_some_and(|policy| {
        structural_lure_text.iter().any(|text| {
            has_credential_continuation_instruction(text, &policy.content_instruction_list)
                && has_recipient_directed_action(text)
        })
    });
    let has_untrusted_auth_link = credential_policy.as_ref().is_some_and(|policy| {
        has_untrusted_authentication_link(
            ctx,
            &policy.content_auth_path_list,
            &policy.content_auth_anchor_list,
            &policy.official_sso_domains_list,
        )
    });
    if has_credential_instruction
        && has_untrusted_auth_link
        && let Some(policy) = credential_policy.as_ref()
    {
        let sender_domain = sender_domain.as_deref().unwrap_or("");
        let sender_is_well_known =
            crate::modules::link_scan::is_well_known_safe_domain(sender_domain);
        let lure_score = if sender_is_well_known {
            policy.content_well_known_sender_score
        } else {
            policy.content_external_sender_score
        };
        *total_score += lure_score;
        categories.push(policy.credential_link_category.clone());
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
        // Threat and action must occur in the same local segment. A long
        // report that mentions an account anomaly in one case and operational
        // training elsewhere must not be treated as a direct lure. Segments
        // explicitly framed as third-person scam narratives remain analyst
        // context, while a real recipient-facing CTA in a separate sentence
        // is still evaluated normally.
        let account_actionable_body = strip_counter_context_segments(&body_lower);
        let account_segments = semantic_segments(&account_actionable_body)
            .map(|segment| segment.text)
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let md = module_data();
        let segment_has_threat = |segment: &str| {
            let compact = compact_detection_view(segment);
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
            .any(|term| segment.contains(term) || compact.contains(term));
            let has_spaced_english_credential_lure = compact.contains("verifyyouraccount")
                && ["disabled", "suspended", "blocked", "keepaccess", "mailbox"]
                    .iter()
                    .any(|term| compact.contains(term));
            let configured_threat = count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_threat_phrases_body"),
            ) > 0;
            let configured_extra_threat = count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_extra_threat_phrases_body"),
            ) > 0;
            configured_threat
                || configured_extra_threat
                || account_security_threats().is_match(segment)
                || account_security_threats().is_match(&compact)
                || has_account_anomaly_phrase
                || has_spaced_english_credential_lure
        };
        let segment_has_action = |segment: &str| {
            let compact = compact_detection_view(segment);
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
            .any(|term| segment.contains(term) || compact.contains(term));
            let has_spaced_english_credential_lure = compact.contains("verifyyouraccount")
                && ["disabled", "suspended", "blocked", "keepaccess", "mailbox"]
                    .iter()
                    .any(|term| compact.contains(term));
            let configured_action = count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_action_phrases_body"),
            ) > 0;
            let configured_extra_action = count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_extra_action_phrases_body"),
            ) > 0;
            configured_action
                || configured_extra_action
                || account_security_actions().is_match(segment)
                || account_security_actions().is_match(&compact)
                || has_structural_action
                || has_spaced_english_credential_lure
        };
        let has_local_account_lure = account_segments.iter().any(|segment| {
            segment_has_threat(segment)
                && segment_has_action(segment)
                && has_recipient_directed_action(segment)
        });
        // Legitimate notices often place the warning and the action on two or
        // several adjacent short lines. Treat that bounded group as one local
        // window, but never bridge a reported third-person case narrative or
        // a long unrelated paragraph.
        let has_adjacent_account_lure = (2..=4).any(|window_len| {
            account_segments.windows(window_len).any(|window| {
                let combined = window.join(" ");
                combined.chars().count() <= 512
                    && segment_has_threat(&combined)
                    && segment_has_action(&combined)
                    && has_recipient_directed_action(&combined)
            })
        });
        // `normalize_text` folds a small set of Cyrillic/Latin confusables for
        // mixed-script detection.  That is useful for obfuscation, but it can
        // break a genuine Russian phrase before the multilingual matcher sees
        // it.  Re-run the same bounded locality check on the raw lower-case
        // projection so declared and auto-detected CP1251 mail keep the
        // native-language rule coverage.
        // Keep this narrow collision check on the parser's canonical plain
        // body, not only the sanitized cross-module projection. Gateway
        // banners can cause the latter to discard the very short account
        // instruction under review; the raw view is bounded before matching.
        let collision_body = ctx
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or(body.as_ref());
        let raw_body_lower = bounded_detector_text(collision_body).to_lowercase();
        let raw_actionable_body = strip_counter_context_segments(&raw_body_lower);
        let raw_account_segments = semantic_segments(&raw_actionable_body)
            .map(|segment| segment.text)
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let raw_segment_has_threat = |segment: &str| {
            let compact = compact_detection_view(segment);
            count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_threat_phrases_body"),
            ) > 0
                || count_config_terms(
                    segment,
                    &compact,
                    md.get_list("account_security_extra_threat_phrases_body"),
                ) > 0
                || account_security_threats().is_match(segment)
        };
        let raw_segment_has_action = |segment: &str| {
            let compact = compact_detection_view(segment);
            count_config_terms(
                segment,
                &compact,
                md.get_list("account_security_action_phrases_body"),
            ) > 0
                || account_security_actions().is_match(segment)
        };
        let has_raw_local_account_lure = raw_account_segments.iter().any(|segment| {
            raw_segment_has_threat(segment)
                && raw_segment_has_action(segment)
                && has_recipient_directed_action(segment)
        });
        let has_raw_adjacent_account_lure = (2..=4).any(|window_len| {
            raw_account_segments.windows(window_len).any(|window| {
                let combined = window.join(" ");
                combined.chars().count() <= 512
                    && raw_segment_has_threat(&combined)
                    && raw_segment_has_action(&combined)
                    && has_recipient_directed_action(&combined)
            })
        });
        let has_local_account_lure = has_local_account_lure
            || has_adjacent_account_lure
            || has_raw_local_account_lure
            || has_raw_adjacent_account_lure;
        // A threat phrase plus an ordinary account action is common in
        // legitimate security guidance, payroll onboarding, and policy
        // notices. Without an untrusted authentication destination, keep it
        // as context; direct secret collection and callback lures have their
        // own admission paths below.
        let has_untrusted_account_destination =
            has_untrusted_body_destination(ctx, &account_actionable_body)
                || has_untrusted_auth_link;
        // Small no-link exceptions cover high-consequence account takeover
        // patterns: phone rebinding/identity verification with transfer
        // restrictions; credential verification with an imminent disable
        // deadline; or a support-verification callback with a short freeze
        // deadline. Each dimension is ordinary on its own; require all of
        // them in the same short, recipient-directed window and reject
        // well-known senders. This keeps broader no-IOC social engineering
        // opt-in.
        let sender_is_well_known = sender_domain
            .as_deref()
            .is_some_and(crate::modules::link_scan::is_well_known_safe_domain);
        let has_high_consequence_no_link_account_lure = !has_untrusted_account_destination
            && !sender_is_well_known
            && (1..=3).any(|window_len| {
                account_segments.windows(window_len).any(|window| {
                    let combined = window.join(" ");
                    if combined.chars().count() > 512 {
                        return false;
                    }
                    let compact = compact_detection_view(&combined);
                    let rebind_action = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_takeover_action_terms"),
                    ) > 0;
                    let transfer_impact = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_transfer_impact_terms"),
                    ) > 0;
                    let credential_verification_action = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_credential_verification_terms"),
                    ) > 0;
                    let imminent_disable = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_imminent_disable_terms"),
                    ) > 0;
                    let support_verification = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_support_verification_terms"),
                    ) > 0;
                    let freeze_deadline = count_config_terms(
                        &combined,
                        &compact,
                        md.get_list("account_security_no_link_freeze_deadline_terms"),
                    ) > 0;
                    let urgent_direct_credential_request = credential_verification_action
                        && count_config_terms(
                            &combined,
                            &compact,
                            md.get_list("transaction_urgency_keywords"),
                        ) > 0;
                    let explicit_account_anomaly = [
                        "账户存在异常",
                        "账号存在异常",
                        "异常登入",
                        "异常登录",
                        "账户异常",
                        "账号异常",
                        "account is abnormal",
                    ]
                    .iter()
                    .any(|term| combined.contains(term) || compact.contains(term));
                    let urgent_account_anomaly_request = explicit_account_anomaly
                        && count_config_terms(
                            &combined,
                            &compact,
                            md.get_list("transaction_urgency_keywords"),
                        ) > 0;
                    segment_has_threat(&combined)
                        && segment_has_action(&combined)
                        && (has_recipient_directed_action(&combined) || support_verification)
                        && ((rebind_action && transfer_impact)
                            || (credential_verification_action && imminent_disable)
                            || (support_verification && freeze_deadline)
                            || urgent_direct_credential_request
                            || urgent_account_anomaly_request)
                })
            });
        if (has_local_account_lure && has_untrusted_account_destination)
            || has_high_consequence_no_link_account_lure
        {
            // DomainSendAccountSecurity email - according toDomainTrusted
            // TrustedDomain (if microsoft.com) possibly ofSecurity, Low
            // Unknown/randomDomain (if damuzhisofa.com) Phishing
            let domain_str = sender_domain.as_deref().unwrap_or("");
            let is_well_known = crate::modules::link_scan::is_well_known_safe_domain(domain_str);
            let phish_score = if has_untrusted_account_destination {
                if is_well_known { 0.30 } else { 0.65 }
            } else {
                0.40
            };
            *total_score += phish_score;
            categories.push("account_security_phishing".to_string());
            if has_untrusted_account_destination {
                threat_actions::record_account_actions(
                    ctx,
                    phish_score,
                    |text| {
                        let normalized = normalize_text(&text.to_lowercase());
                        let raw = text.to_lowercase();
                        (segment_has_threat(&normalized) && segment_has_action(&normalized))
                            || (raw_segment_has_threat(&raw) && raw_segment_has_action(&raw))
                    },
                    qualified_threat_actions,
                );
            }
            evidence.push(Evidence {
                description: if has_high_consequence_no_link_account_lure {
                    format!(
                        "外部发件域 {} 在同一收件人指向片段中要求账户身份/登录核验或联系支持，并以转账受限/短时冻结施压；未发现不可信链接",
                        domain_str
                    )
                } else {
                    format!(
                        "外部发件域 {} 的同一正文片段同时包含账户安全威胁和收件人操作指令，符合凭证钓鱼模式{}",
                        domain_str,
                        if is_well_known { "（常见公共域，保留较低权重）" } else { "" },
                    )
                },
                location: Some("body + envelope".to_string()),
                snippet: None,
            });
            // The legacy threat+action matcher already establishes the
            // recipient-facing account-security intent.  When the same
            // message also carries an untrusted authentication destination,
            // retain that structural half of the compound explicitly so the
            // final fusion layer does not dilute a complete credential lure
            // below the quarantine threshold.  A threat phrase without a
            // link, or the same text pointing at an official SSO domain,
            // remains social evidence only.
            if has_untrusted_auth_link
                && let Some(policy) = credential_policy.as_ref()
                && !categories.contains(&policy.credential_link_category)
            {
                categories.push(policy.credential_link_category.clone());
                evidence.push(Evidence {
                    description:
                        "Account-security threat and action are paired with an untrusted authentication link"
                            .to_string(),
                    location: Some("body + links".to_string()),
                    snippet: None,
                });
            }
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
        let linked_action_text = ctx
            .analysis_links()
            .into_iter()
            .filter_map(|link| link.text)
            .collect::<Vec<_>>()
            .join(" ");
        let body_action_text = detector_body_fallback_text(ctx, body_for_cross)
            .map(|body| body.into_owned())
            .unwrap_or_default();
        let subject_and_body = format!("{subject}\n{body_action_text} {linked_action_text}");
        if has_subject_threat
            && has_recipient_directed_action(&format!(
                "{subject} {body_action_text} {linked_action_text}"
            ))
            && has_untrusted_body_destination(ctx, &subject_and_body)
        {
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

/// Maximum context on either side of an urgency phrase that may participate
/// in the legacy no-link subsidy compound. This prevents a long research or
/// policy document from borrowing an unrelated credit-delinquency sentence to
/// promote benefit vocabulary thousands of characters away.
const SUBSIDY_BODY_LOCAL_WINDOW_CHARS: usize = 240;

fn local_subsidy_urgency_compound(body: &str) -> Option<(Vec<String>, Vec<String>)> {
    let strong_urgency_hits: Vec<String> = subsidy_urgency_body()
        .scan(body)
        .distinct_patterns()
        .into_iter()
        .filter(|phrase| is_strong_subsidy_urgency(phrase))
        .collect();

    for urgency in strong_urgency_hits {
        let normalized_urgency = normalize_text(&urgency.to_lowercase());
        if normalized_urgency.is_empty() {
            continue;
        }

        for (position, _) in body.match_indices(normalized_urgency.as_str()) {
            let local_window = text_window_around(body, position, SUBSIDY_BODY_LOCAL_WINDOW_CHARS);
            let substantive_benefit_hits: Vec<String> = subsidy_keywords_body()
                .scan(local_window)
                .distinct_patterns()
                .into_iter()
                .filter(|phrase| is_substantive_subsidy_phrase(phrase))
                .collect();
            let local_urgency_hits: Vec<String> = subsidy_urgency_body()
                .scan(local_window)
                .distinct_patterns()
                .into_iter()
                .filter(|phrase| is_strong_subsidy_urgency(phrase))
                .collect();

            if substantive_benefit_hits.len() >= 2
                && !local_urgency_hits.is_empty()
                && has_recipient_directed_action(local_window)
            {
                return Some((substantive_benefit_hits, local_urgency_hits));
            }
        }
    }

    None
}

#[derive(Debug, Clone, Deserialize)]
struct SubsidyExternalPortalPolicy {
    enabled: bool,
    scenario_id: String,
    observation_inputs: Vec<String>,
    benefit_list: String,
    action_list: String,
    portal_list: String,
    result_category: String,
    min_substantive_benefit_hits: usize,
    max_local_window_chars: usize,
    score: f64,
    require_external_destination: bool,
    require_same_body_window: bool,
}

fn parse_subsidy_external_portal_policy(
    value: serde_json::Value,
) -> Option<SubsidyExternalPortalPolicy> {
    let policy = serde_json::from_value::<SubsidyExternalPortalPolicy>(value).ok()?;
    let has_named_inputs = policy.observation_inputs.len() == 3
        && policy
            .observation_inputs
            .iter()
            .all(|input| !input.trim().is_empty());
    (policy.enabled
        && !policy.scenario_id.trim().is_empty()
        && has_named_inputs
        && !policy.benefit_list.trim().is_empty()
        && !policy.action_list.trim().is_empty()
        && !policy.portal_list.trim().is_empty()
        && !policy.result_category.trim().is_empty()
        && policy.min_substantive_benefit_hits > 0
        && (32..=1024).contains(&policy.max_local_window_chars)
        && (0.0..=1.0).contains(&policy.score)
        && policy.require_external_destination
        && policy.require_same_body_window)
        .then_some(policy)
}

fn subsidy_external_portal_policy() -> Option<SubsidyExternalPortalPolicy> {
    let data = module_data();
    parse_subsidy_external_portal_policy(
        data.get_structured("subsidy_external_portal_policy_v1")?
            .clone(),
    )
}

fn text_window_around(text: &str, byte_pos: usize, max_chars: usize) -> &str {
    let start = text[..byte_pos]
        .char_indices()
        .rev()
        .nth(max_chars)
        .map_or(0, |(index, _)| index);
    let end = text[byte_pos..]
        .char_indices()
        .nth(max_chars)
        .map_or(text.len(), |(index, _)| byte_pos + index);
    &text[start..end]
}

fn trim_printed_url_punctuation(url: &str) -> &str {
    url.trim_end_matches(['.', ',', ';', ')', ']', '}', '。', '，', '；', '）', '】'])
}

/// Locate a parser-retained bare destination in its actual source text. The
/// normalized URL alone is not provenance: a matching host in a mailbox,
/// another hostname or a remote signature cannot supply this claim's route.
fn bare_url_source_span(text: &str, url: &str) -> Option<std::ops::Range<usize>> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let source = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?
        .trim_end_matches('/');
    if source.is_empty() || !source.is_ascii() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let source = source.to_ascii_lowercase();
    lower.match_indices(&source).find_map(|(start, matched)| {
        let end = start + matched.len();
        let preceding = text[..start].chars().next_back();
        let following = text[end..].chars().next();
        let atom_character = |character: char| {
            character.is_ascii_alphanumeric() || matches!(character, '@' | '.' | '-' | '_')
        };
        (!preceding.is_some_and(atom_character)
            && !following.is_some_and(atom_character)
            && !RE_HTML_ALT_URL
                .find_iter(text)
                .any(|transport| transport.range().contains(&start)))
        .then(|| {
            let suffix_end = text[end..]
                .char_indices()
                .find(|(_, character)| {
                    character.is_whitespace()
                        || matches!(
                            character,
                            '\"' | '\'' | '<' | '>' | '。' | '，' | '；' | '！' | '？'
                        )
                })
                .map_or(text.len(), |(offset, _)| end + offset);
            let raw = trim_printed_url_punctuation(&text[start..suffix_end]);
            start..start + raw.len()
        })
    })
}

/// Render only the current block's inline children. Nested block-level
/// sections and quoted subtrees are separate speakers/claims; they cannot
/// contribute prose to an adjacent company-site anchor in their parent div.
/// Cache this bounded view per block instead of serializing its whole subtree
/// for every anchor.
fn local_html_action_sections<F>(block: scraper::ElementRef<'_>, anchor_position: &F) -> Vec<String>
where
    F: Fn(scraper::ElementRef<'_>) -> Option<String>,
{
    fn flush(sections: &mut Vec<String>, buffer: &mut String) {
        if !buffer.trim().is_empty() {
            sections.push(std::mem::take(buffer));
        }
    }
    fn collect<F>(
        element: scraper::ElementRef<'_>,
        sections: &mut Vec<String>,
        buffer: &mut String,
        remaining_bytes: &mut usize,
        remaining_nodes: &mut usize,
        depth: usize,
        anchor_position: &F,
    ) where
        F: Fn(scraper::ElementRef<'_>) -> Option<String>,
    {
        if depth > 64 {
            flush(sections, buffer);
            return;
        }
        for child in element.children() {
            if *remaining_nodes == 0 || *remaining_bytes == 0 {
                return;
            }
            *remaining_nodes -= 1;
            if let Some(text) = child.value().as_text() {
                let mut end = text.len().min(*remaining_bytes);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                buffer.push_str(&RE_SCOPED_ANCHOR_POSITION.replace_all(&text[..end], " "));
                *remaining_bytes -= end;
            } else if let Some(child) = scraper::ElementRef::wrap(child) {
                let name = child.value().name();
                if matches!(
                    name,
                    "blockquote"
                        | "p"
                        | "li"
                        | "td"
                        | "div"
                        | "table"
                        | "ul"
                        | "ol"
                        | "section"
                        | "article"
                        | "header"
                        | "footer"
                        | "style"
                        | "script"
                        | "head"
                        | "template"
                        | "noscript"
                ) || child.attr("hidden").is_some()
                    || child.attr("style").is_some_and(|style| {
                        let style = style.to_ascii_lowercase().replace(' ', "");
                        style.contains("display:none") || style.contains("visibility:hidden")
                    })
                {
                    flush(sections, buffer);
                } else if name == "br" {
                    buffer.push('\n');
                } else {
                    if let Some(position) = anchor_position(child) {
                        buffer.push_str(&position);
                    }
                    collect(
                        child,
                        sections,
                        buffer,
                        remaining_bytes,
                        remaining_nodes,
                        depth + 1,
                        anchor_position,
                    );
                }
            }
        }
    }
    let mut sections = Vec::new();
    let mut buffer = String::new();
    collect(
        block,
        &mut sections,
        &mut buffer,
        &mut (32 * 1024),
        &mut 8192,
        0,
        anchor_position,
    );
    flush(&mut sections, &mut buffer);
    sections
}

/// Transport tokens are not speech acts. In particular, a gateway's `/click`
/// path, a query's `open`/`token`, and a mailbox local-part do not describe what
/// the current author asks the recipient to do.
fn semantic_prose_without_transport_tokens(text: &str) -> String {
    let without_positions = RE_SCOPED_ANCHOR_POSITION.replace_all(text, "");
    let without_urls = RE_HTML_ALT_URL.replace_all(&without_positions, " ");
    RE_SEMANTIC_MAILBOX
        .replace_all(&without_urls, " ")
        .into_owned()
}

#[derive(Debug, Clone)]
struct ScopedActionLink {
    original_url: String,
    effective_url: String,
    extraction_source: &'static str,
    prose: String,
    target_prose: String,
    stage_b_neighboring_link: bool,
}

fn push_scoped_action_link(
    ctx: &SecurityContext,
    candidates: &mut Vec<ScopedActionLink>,
    url: &str,
    source: &'static str,
    local_text: &str,
    target_text: &str,
) {
    if candidates.len() >= 128
        || is_visual_resource_link(ctx, url)
        || !is_untrusted_clickable_link(ctx, url)
        || is_counter_context_segment(local_text)
    {
        return;
    }
    let strip_source = |text: &str| {
        let prose_source = if source == "plain_text" {
            if let Some(span) = bare_url_source_span(text, url) {
                let mut prose = text.to_string();
                prose.replace_range(span, " ");
                Cow::Owned(prose)
            } else {
                Cow::Borrowed(text)
            }
        } else {
            Cow::Borrowed(text)
        };
        semantic_prose_without_transport_tokens(&prose_source)
    };
    let prose = strip_source(local_text);
    let target_prose = strip_source(target_text);
    // Local anti-action/report clauses may contain precisely the same brand,
    // action and destination as a lure. Remove only those attributed clauses;
    // a separate request in the window must survive the subtraction.
    let (prose, _) = crate::semantic::exclude_non_action_claims(
        &ctx.session,
        &prose,
        vigilyx_core::security::SemanticSourcePart::PlainText,
    );
    let (target_prose, _) = crate::semantic::exclude_non_action_claims(
        &ctx.session,
        &target_prose,
        vigilyx_core::security::SemanticSourcePart::PlainText,
    );
    if target_prose.trim().is_empty() {
        return;
    }
    if prose.trim().is_empty() || prose.chars().count() > 512 {
        return;
    }
    let effective_url = effective_structural_url(url);
    if url::Url::parse(&effective_url)
        .ok()
        .is_none_or(|url| !matches!(url.scheme(), "http" | "https"))
    {
        return;
    }
    if candidates.iter().any(|existing| {
        existing.effective_url == effective_url
            && existing.prose == prose
            && existing.target_prose == target_prose
    }) {
        return;
    }
    candidates.push(ScopedActionLink {
        original_url: url.to_string(),
        effective_url,
        extraction_source: source,
        prose,
        target_prose,
        stage_b_neighboring_link: false,
    });
}

/// Bind navigation to its visible local claim. HTML attributes and visual
/// resources never become prose; quoted blocks, neighboring paragraphs and
/// unrelated signature links never supply a claim's destination.
fn scoped_action_links(ctx: &SecurityContext, body: &str) -> Vec<ScopedActionLink> {
    let mut candidates = Vec::new();
    let retained = normalized_and_compact(body).0;
    let retained_prose = normalized_and_compact(&semantic_prose_without_transport_tokens(body)).0;
    if let Some(html) = ctx.session.content.body_html.as_deref()
        && html.len() <= 2 * 1024 * 1024
    {
        use scraper::{ElementRef, Html, Selector};
        let visible = visible_anchor_facts(html);
        let document = Html::parse_document(html);
        let selector = Selector::parse("a[href]").expect("valid action anchor selector");
        let positions = document
            .select(&selector)
            .take(128)
            .enumerate()
            .map(|(index, anchor)| (anchor.id(), format!("\u{e000}anchor:{index}\u{e001}")))
            .collect::<HashMap<_, _>>();
        let anchor_position = |element: ElementRef<'_>| positions.get(&element.id()).cloned();
        let mut block_windows = HashMap::new();
        for anchor in document.select(&selector).take(128) {
            let Some(href) = anchor.attr("href").map(str::to_string) else {
                continue;
            };
            if !visible
                .iter()
                .any(|fact| fact.href == decode_html_entities(&href))
                || anchor
                    .ancestors()
                    .filter_map(ElementRef::wrap)
                    .any(|ancestor| ancestor.value().name() == "blockquote")
            {
                continue;
            }
            let label = normalized_and_compact(&anchor.text().collect::<Vec<_>>().join(" ")).0;
            // A banner/footer removed by the canonical body pass must not be
            // recovered through the raw HTML fallback.
            if label.trim().is_empty() || !retained.contains(label.trim()) {
                continue;
            }
            let Some(position) = positions.get(&anchor.id()) else {
                continue;
            };
            let block = anchor
                .ancestors()
                .filter_map(ElementRef::wrap)
                .find(|ancestor| {
                    matches!(ancestor.value().name(), "p" | "li" | "td" | "div" | "body")
                });
            let windows = if let Some(block) = block {
                block_windows
                    .entry(block.id())
                    .or_insert_with(|| {
                        local_html_action_sections(block, &anchor_position)
                            .iter()
                            .filter(|section| RE_SCOPED_ANCHOR_POSITION.is_match(section))
                            .flat_map(|section| bounded_actionable_windows(section, 2, 320))
                            .map(|window| {
                                let source_segments = semantic_segments(&window)
                                    .map(|segment| segment.text)
                                    .collect::<Vec<_>>();
                                (window, source_segments)
                            })
                            .collect::<Vec<_>>()
                    })
                    .as_slice()
            } else {
                continue;
            };
            for (window, segments) in windows {
                if let Some(target) = segments.iter().find(|segment| segment.contains(position)) {
                    push_scoped_action_link(ctx, &mut candidates, &href, "href", window, target);
                }
            }
        }
    }

    if should_scan_projected_html_urls(ctx) {
        // Read the route from the immutable source. HTML-entity normalization
        // is a prose view and may remove literal `&url` query syntax.
        let source_body = ctx
            .session
            .content
            .body_text
            .as_deref()
            .map(bounded_detector_text)
            .unwrap_or_else(|| Cow::Borrowed(body));
        for paragraph in semantic_paragraphs(&source_body) {
            for window in bounded_actionable_windows(paragraph, 2, 320) {
                let segments = semantic_segments(&window)
                    .map(|segment| segment.text)
                    .collect::<Vec<_>>();
                for target in &segments {
                    let target_prose =
                        normalized_and_compact(&semantic_prose_without_transport_tokens(target)).0;
                    if target_prose.trim().is_empty()
                        || !retained_prose.contains(target_prose.trim())
                    {
                        continue;
                    }
                    for matched in RE_HTML_ALT_URL.find_iter(target) {
                        let url = trim_printed_url_punctuation(matched.as_str());
                        push_scoped_action_link(
                            ctx,
                            &mut candidates,
                            url,
                            "plain_text",
                            &window,
                            target,
                        );
                    }
                    // Bare links have no display label; their actual source
                    // spelling must occur in this exact target-bearing span.
                    if ctx.session.content.body_html.is_none() {
                        for link in ctx.session.content.links.iter().take(128) {
                            if let Some(span) = bare_url_source_span(target, &link.url) {
                                let route = format!("https://{}", &target[span]);
                                push_scoped_action_link(
                                    ctx,
                                    &mut candidates,
                                    &route,
                                    "plain_text",
                                    &window,
                                    target,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    candidates
}

/// Stage B may bind a bare plain-text URL to one adjacent semantic window when
/// the URL is the only destination in that short window. The caller still
/// requires a narrow account/credential request, an untrusted clickable URL,
/// and the matching same-window threat or secret field.
fn scoped_neighboring_action_links_stage_b(
    ctx: &SecurityContext,
    body: &str,
) -> Vec<ScopedActionLink> {
    let source_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .map(bounded_detector_text)
        .unwrap_or_else(|| Cow::Borrowed(body));
    let mut candidates = Vec::new();
    for paragraph in semantic_paragraphs(&source_body) {
        for window in bounded_actionable_windows(paragraph, 3, 512) {
            let urls = RE_HTML_ALT_URL
                .find_iter(&window)
                .map(|matched| trim_printed_url_punctuation(matched.as_str()).to_string())
                .filter(|url| {
                    url::Url::parse(url)
                        .ok()
                        .is_some_and(|parsed| matches!(parsed.scheme(), "http" | "https"))
                })
                .collect::<HashSet<_>>();
            if urls.len() != 1 {
                continue;
            }
            let Some(url) = urls.iter().next() else {
                continue;
            };
            let original_count = candidates.len();
            push_scoped_action_link(ctx, &mut candidates, url, "plain_text", &window, &window);
            if candidates.len() > original_count {
                candidates
                    .last_mut()
                    .expect("a newly pushed Stage-B action link")
                    .stage_b_neighboring_link = true;
            }
        }
    }
    candidates
}

fn compound_span_id(prose: &str) -> String {
    format!(
        "body:{}",
        hex::encode(Sha256::digest(
            normalize_text(&prose.to_lowercase()).as_bytes()
        ))
    )
}

fn qualified_link_compound(
    category: &str,
    link: &ScopedActionLink,
    score: f64,
) -> serde_json::Value {
    let span_id = compound_span_id(&link.prose);
    serde_json::json!({
        "category": category,
        "score": score,
        "confidence": 0.85,
        "source_span_id": span_id,
        "actor_role": "sender",
        "target_role": "recipient",
        "speech_act": "request",
        "polarity": "action",
        "quote_or_forward_status": "original",
        "link_extraction_source": link.extraction_source,
        "original_url": link.original_url,
        "effective_url": link.effective_url,
        "link_transport_status": "not_attempted",
        "link_content_status": "not_observed",
        "link_ownership_status": "unproven",
        "causal_keys": [span_id, format!("url:{}", hex::encode(Sha256::digest(link.effective_url.as_bytes())))],
        "counter_context_ids": [],
        "coverage_reason": "destination_not_fetched"
    })
}

fn collection_reply_target(ctx: &SecurityContext) -> Option<String> {
    // A reply uses Reply-To when present, then the visible From header and
    // finally the transport sender. The key identifies the actual route;
    // it does not assert ownership or authenticate that destination.
    let headers = &ctx.session.content.headers;
    let route = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("reply-to"))
        .or_else(|| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        })
        .map(|(_, value)| value.as_str())
        .or(ctx.session.mail_from.as_deref())?;
    let mailbox = RE_SEMANTIC_MAILBOX
        .find(route)?
        .as_str()
        .trim_end_matches('.');
    Some(mailbox.to_ascii_lowercase())
}

fn qualified_reply_compound(prose: &str, reply_target: &str) -> serde_json::Value {
    let span_id = compound_span_id(prose);
    let target_id = format!(
        "reply_target:{}",
        hex::encode(Sha256::digest(reply_target.as_bytes()))
    );
    serde_json::json!({
        "category": "pii_collection_lure", "source_span_id": span_id,
        "score": 0.58, "confidence": 0.85,
        "actor_role": "sender", "target_role": "recipient", "speech_act": "request",
        "polarity": "action", "quote_or_forward_status": "original",
        "link_extraction_source": "none", "original_url": null, "effective_url": null,
        "reply_target": target_id, "link_transport_status": "not_attempted",
        "link_content_status": "not_observed", "link_ownership_status": "unproven",
        "causal_keys": [span_id, target_id], "counter_context_ids": [],
        "coverage_reason": "reply_destination_not_verified"
    })
}

fn has_configured_phrase(text: &str, list_name: &str) -> bool {
    module_data()
        .get_list(list_name)
        .iter()
        .map(|phrase| normalize_text(&phrase.to_lowercase()))
        .any(|phrase| !phrase.is_empty() && text.contains(&phrase))
}

fn count_substantive_configured_benefits(text: &str, list_name: &str) -> usize {
    module_data()
        .get_list(list_name)
        .iter()
        .map(|phrase| normalize_text(&phrase.to_lowercase()))
        .filter(|phrase| {
            !phrase.is_empty() && is_substantive_subsidy_phrase(phrase) && text.contains(phrase)
        })
        .count()
}

/// A restricted government namespace is a verified destination only when the
/// parsed link is HTTPS, not marked suspicious, and the notice itself gives
/// multiple explicit anti-phishing safeguards plus relevant public-service
/// context. This avoids treating an arbitrary gov-looking substring or a
/// mixed message with a second attacker URL as a safe subsidy workflow.
fn is_routine_government_process_notice(ctx: &SecurityContext, raw_text: &str) -> bool {
    if ctx.session.content.links.is_empty() || !ctx.session.content.attachments.is_empty() {
        return false;
    }
    let md = module_data();
    let (normalized, compact) = normalized_and_compact(raw_text);
    let anti_phishing_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("external_action_link_anti_phishing_markers"),
    );
    let government_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("external_action_link_routine_official_context_terms"),
    );
    let verified_destinations = ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let effective_url = effective_structural_url(&link.url);
        let Ok(parsed) = url::Url::parse(&effective_url) else {
            return false;
        };
        matches!(parsed.scheme(), "https")
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>().is_err()
                    && crate::modules::link_scan::is_official_claimed_domain(host)
            })
    });
    verified_destinations && anti_phishing_hits >= 2 && government_context_hits >= 2
}

/// Named Stage-B compound scenario for benefit/subsidy portal lures.  A
/// domain is only promoted when the recipient is asked to perform a local
/// portal action in the same bounded body window.  A bare domain therefore
/// becomes useful evidence here without making every printed domain a threat.
fn detect_subsidy_external_portal_lure(
    ctx: &SecurityContext,
    body: &str,
) -> Option<(SubsidyExternalPortalPolicy, String)> {
    let policy = subsidy_external_portal_policy()?;
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let raw_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or_else(|| ctx.session.content.body_html.as_deref())
        .unwrap_or(body);
    if is_routine_government_process_notice(ctx, &format!("{subject}\n\n{raw_body}")) {
        return None;
    }
    // The gateway banner sanitizer intentionally removes trusted notice text,
    // but some real HTML templates flatten the banner and message into one
    // paragraph and can therefore lose the actionable tail.  Keep the
    // sanitized cross-detector text as the primary view and retry against the
    // same message's visible HTML text when it does not produce a match.
    let mut candidate_bodies = vec![body.to_string()];
    if let Some(body_html) = ctx.session.content.body_html.as_deref() {
        let visible_html = strip_html_tags(body_html);
        if !visible_html.trim().is_empty() && visible_html != body {
            candidate_bodies.push(visible_html);
        }
    }

    candidate_bodies.iter().find_map(|candidate_body| {
        let normalized_body = normalize_text(&candidate_body.to_lowercase());
        let mut destinations: Vec<(String, Option<String>)> = ctx
            .session
            .content
            .links
            .iter()
            .filter_map(|link| {
                extract_domain_from_url(&link.url).map(|domain| {
                    (
                        domain,
                        link.text
                            .as_deref()
                            .map(|text| normalize_text(&decode_html_entities(&text.to_lowercase())))
                            .filter(|text| !text.trim().is_empty()),
                    )
                })
            })
            .collect();

        // Plain-text notices frequently print a bare host instead of a
        // clickable URL.  Treat it as a destination only after strict host
        // parsing; the semantic policy below still requires benefit, action,
        // and portal context in the same bounded window.
        for token in candidate_body.split_whitespace() {
            let candidate = token.trim_matches(|ch: char| {
                !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '-' | '/' | '_')
            });
            if candidate.contains("@") || candidate.contains("://") || !candidate.contains('.') {
                continue;
            }
            let Ok(parsed) = url::Url::parse(&format!("https://{candidate}")) else {
                continue;
            };
            let Some(domain) = parsed.host_str().map(str::to_ascii_lowercase) else {
                continue;
            };
            if !destinations.iter().any(|(existing, _)| existing == &domain) {
                destinations.push((domain, None));
            }
        }
        destinations.into_iter().find_map(|(domain, anchor_text)| {
            let is_internal = ctx.is_internal_domain(&domain);
            let is_protected = module_data().contains("protected_domains", &domain);
            let is_trusted = crate::modules::link_scan::is_trusted_url_domain(&domain)
                || crate::modules::link_scan::is_well_known_safe_domain(&domain);
            if policy.require_external_destination && (is_internal || is_protected || is_trusted) {
                return None;
            }

            // HTML mail commonly keeps the destination only in `href`; the
            // stripped body therefore contains the anchor text but not the
            // domain.  Tie the link object to the same bounded body window via
            // its normalized anchor text when the URL is not visibly printed.
            let domain_position = normalized_body.find(&domain);
            let anchor_position = anchor_text
                .map(|text| {
                    text.trim_start_matches(|ch: char| !ch.is_alphanumeric())
                        .to_string()
                })
                .filter(|text| !text.is_empty())
                .and_then(|text| normalized_body.find(&text));
            let context_position = domain_position.or(anchor_position)?;
            let local_window = if policy.require_same_body_window {
                text_window_around(
                    &normalized_body,
                    context_position,
                    policy.max_local_window_chars,
                )
            } else {
                normalized_body.as_str()
            };
            let benefit_hits =
                count_substantive_configured_benefits(local_window, &policy.benefit_list);
            let has_action = has_configured_phrase(local_window, &policy.action_list);
            let has_portal_context = has_configured_phrase(local_window, &policy.portal_list);
            (benefit_hits >= policy.min_substantive_benefit_hits
                && has_action
                && has_portal_context)
                .then_some((policy.clone(), domain))
        })
    })
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

    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let actionable_body = strip_counter_context_segments(&body);
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let raw_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or_else(|| ctx.session.content.body_html.as_deref())
        .unwrap_or(&body);
    let routine_government_process =
        is_routine_government_process_notice(ctx, &format!("{subject}\n\n{raw_body}"));
    if routine_government_process
        || is_reported_benefit_scam_notice(ctx, subject, raw_body, &actionable_body)
    {
        return;
    }
    if let Some((policy, domain)) = detect_subsidy_external_portal_lure(ctx, &actionable_body) {
        *total_score += policy.score;
        categories.push(policy.result_category.clone());
        evidence.push(Evidence {
            description: format!(
                "Named scenario {}: substantive benefit phrase + recipient portal action + external destination {}",
                policy.scenario_id, domain
            ),
            location: Some("body + external domain".to_string()),
            snippet: None,
        });
        return;
    }

    // --- Part A: body-based detection (original step 5) ---
    // Government subsidy/tax fraud pattern (/ /)
    // Signature: benefit keywords + urgency/deadline + suspicious URL or fake authority
    if !actionable_body.trim().is_empty() {
        let body_lower = normalize_text(&actionable_body.to_lowercase());
        let (body_normalized, body_compact) = normalized_and_compact(&actionable_body);
        let verified_manual_benefit_process = count_config_terms(
            &body_normalized,
            &body_compact,
            module_data().get_list("routine_official_benefit_channel_markers"),
        ) >= 2;
        let has_untrusted_subsidy_destination =
            !routine_government_process && has_untrusted_body_destination(ctx, &actionable_body);
        // Two benefit concepts and urgency are common in real government
        // notices. Require a recipient-directed action in the same bounded
        // benefit/urgency compound. A no-link notice with multiple explicit
        // official manual-payment safeguards is treated as routine guidance;
        // direct collection of identity fields is handled by the PII compound.
        // Score 0.60: after BPA conversion (x0.85 confidence) and consensus gating
        // (x0.50 for 2-engine support), floor = 0.60x0.85x0.50 = 0.255 which,
        // combined with other keyword hits, comfortably reaches Medium (>= 0.40).
        if let Some((subsidy_hits, urgency_hits)) = local_subsidy_urgency_compound(&body_lower) {
            if !has_untrusted_subsidy_destination && verified_manual_benefit_process {
                return;
            }
            *total_score += 0.60;
            categories.push("subsidy_fraud".to_string());
            evidence.push(Evidence {
                description: format!(
                "Government subsidy fraud pattern: {} substantive benefit keywords + local urgency phrase ({}) with a recipient-directed action from external domain",
                    subsidy_hits.len(),
                    urgency_hits.join(", "),
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
        let risk_flagged_subject = subject.contains("[注意风险邮件]")
            || subject.contains("[垃圾邮件]")
            || subject.contains("[风险提示]");
        if subsidy_hits.len() >= 2
            && has_substantive_benefit
            && (has_untrusted_body_destination(ctx, &actionable_body) || risk_flagged_subject)
        {
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

/// A public-service notice may discuss a current subsidy and quote the false
/// deadline/payment claims used by a scam it is correcting. Suppress only the
/// subsidy compound when the message is framed as a correction, contains
/// multiple explicit report/correction cues, has no suspicious link or
/// attachment, and does not route recipients to a cross-domain portal.
/// Sensitive-field and other phishing detectors still run independently.
fn is_reported_benefit_scam_notice(
    ctx: &SecurityContext,
    subject: &str,
    raw_body: &str,
    actionable_body: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.iter().any(|link| link.suspicious)
    {
        return false;
    }
    let sender_domain = external_sender_domain(ctx);
    if has_cross_domain_untrusted_body_destination(ctx, actionable_body, sender_domain.as_deref()) {
        return false;
    }

    let (normalized, compact) = normalized_and_compact(&format!("{subject}\n{raw_body}"));
    count_config_terms(
        &normalized,
        &compact,
        module_data().get_list("subsidy_fraud_report_context_markers"),
    ) >= 2
}

fn has_social_engineering_negative_context(normalized: &str, _compact: &str) -> bool {
    let registry = module_data();
    let markers = registry.get_list("social_engineering_negative_context_markers");
    semantic_segments(normalized).any(|segment| {
        let segment_compact = compact_detection_view(&segment.text);
        first_config_term_hit(&segment.text, &segment_compact, markers).is_some()
    })
}

fn is_counter_context_list_intro(segment: &str) -> bool {
    let trimmed = segment.trim_end();
    if trimmed.chars().count() > 180 || !matches!(trimmed.chars().last(), Some(':' | '：')) {
        return false;
    }
    let normalized = normalize_text(&segment.to_lowercase());
    let compact = compact_detection_view(&normalized);
    first_config_term_hit(
        &normalized,
        &compact,
        module_data().get_list("counter_context_list_intro_markers"),
    )
    .is_some()
}

/// Split compact warning lists such as `we will never: - ask ... - request`
/// even when HTML-to-text conversion flattened their visual line breaks.
/// Only a short, configured negative heading may establish the list scope, so
/// an unrelated later request remains actionable.
fn split_inline_counter_context_list(line: &str) -> Option<(String, Vec<String>)> {
    let (colon_end, _) = line
        .char_indices()
        .find(|(_, character)| matches!(character, ':' | '：'))?;
    let intro_end = colon_end + line[colon_end..].chars().next()?.len_utf8();
    let intro = line[..intro_end].trim().to_string();
    if !is_counter_context_list_intro(&intro) {
        return None;
    }

    let remainder = line[intro_end..].trim_start();
    let first_marker = remainder.chars().next()?;
    if !matches!(first_marker, '-' | '*' | '+' | '•' | '·' | '▪' | '◦' | '‣') {
        return None;
    }

    let items = RE_INLINE_SEMANTIC_LIST_MARKER
        .split(remainder)
        .map(|item| {
            item.trim_start_matches(['-', '*', '+', '•', '·', '▪', '◦', '‣'])
                .trim()
        })
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    (!items.is_empty()).then_some((intro, items))
}

fn is_counter_context_segment(segment: &str) -> bool {
    let normalized = normalize_text(&segment.to_lowercase());
    let compact = compact_detection_view(&normalized);
    let md = module_data();
    let has_sentence_boundary = segment.chars().any(|character| {
        matches!(
            character,
            '\n' | '\r' | '。' | '！' | '？' | '!' | '?' | ';' | '；'
        )
    });
    let social_negative_context =
        if !has_sentence_boundary && split_inline_counter_context_list(segment).is_none() {
            first_config_term_hit(
                &normalized,
                &compact,
                md.get_list("social_engineering_negative_context_markers"),
            )
            .is_some()
        } else {
            has_social_engineering_negative_context(&normalized, &compact)
        };
    let configured_counter_context = social_negative_context
        || [
            "external_action_link_counter_context_markers",
            "external_action_link_anti_phishing_markers",
            "external_action_link_benign_markers",
            "external_action_link_benign_markers_v2",
        ]
        .iter()
        .any(|list_name| {
            first_config_term_hit(&normalized, &compact, md.get_list(list_name)).is_some()
        });
    is_reported_security_case_segment(&normalized)
        || is_quoted_or_forwarded_segment(segment)
        || configured_counter_context
}

fn has_possible_counter_context_marker(text: &str) -> bool {
    let md = module_data();
    let normalized_text = normalize_text(&text.to_lowercase());
    [
        "social_engineering_negative_context_markers",
        "external_action_link_counter_context_markers",
        "external_action_link_anti_phishing_markers",
        "external_action_link_benign_markers",
        "external_action_link_benign_markers_v2",
        "counter_context_list_intro_markers",
        "security_case_actor_markers",
        "security_case_narrative_markers",
    ]
    .iter()
    .any(|list_name| {
        md.get_list(list_name).iter().any(|marker| {
            let marker = normalize_text(&marker.to_lowercase());
            !marker.is_empty() && normalized_text.contains(&marker)
        })
    }) || normalized_text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with('>')
            || line.starts_with("fwd:")
            || line.starts_with("fw:")
            || line.starts_with("转发")
            || line.starts_with("转寄")
            || line.starts_with("原邮件")
    })
}

/// A counter-context heading immediately before a configured warning list is
/// part of that warning, even when it repeats the risky phrase being denied.
/// Keep removal local to short headings and preserve any heading that already
/// contains an explicit payment redirect or sensitive-data handoff.
fn is_counter_context_list_heading(segment: &str) -> bool {
    if segment.chars().count() > 180 {
        return false;
    }
    let (normalized, compact) = normalized_and_compact(segment);
    let md = module_data();
    if count_config_terms(
        &normalized,
        &compact,
        md.get_list("counter_context_list_heading_markers"),
    ) == 0
    {
        return false;
    }

    [
        "bec_local_action_terms",
        "payment_change_explicit_redirect_terms",
        "external_sensitive_exfiltration_action_terms",
    ]
    .iter()
    .all(|list_name| count_config_terms(&normalized, &compact, md.get_list(list_name)) == 0)
}

/// Remove only spans explicitly framed as reports, quotations, forwards, or
/// anti-action/training context.  This keeps a real request in another span
/// visible instead of applying a whole-message negative veto.
fn strip_counter_context_segments(text: &str) -> Cow<'_, str> {
    if !has_possible_counter_context_marker(text) {
        return Cow::Borrowed(text);
    }
    let segments = semantic_segments(text).collect::<Vec<_>>();
    let mut actionable_segments: Vec<String> = Vec::new();
    let mut removed_counter_context = false;
    let mut counter_list_intro = false;
    for (index, segment) in segments.iter().enumerate() {
        let is_counter_list_intro = is_counter_context_list_intro(&segment.text);
        if is_counter_list_intro
            && actionable_segments
                .last()
                .is_some_and(|previous| is_counter_context_list_heading(previous))
        {
            actionable_segments.pop();
            removed_counter_context = true;
        }
        // Scam-report headings such as “如遇可疑通知” often precede a list
        // of verification steps without spelling out “never” in the heading.
        // Scope removal to the immediately following bullet list and keep any
        // heading that contains a concrete redirect or secret handoff.
        let is_warning_heading_for_list = !segment.list_item
            && segments.get(index + 1).is_some_and(|next| next.list_item)
            && is_counter_context_list_heading(&segment.text);
        let is_counter_context = is_counter_context_segment(&segment.text);
        if segment.list_item {
            if counter_list_intro || is_counter_context {
                removed_counter_context = true;
            } else {
                actionable_segments.push(segment.text.clone());
            }
            continue;
        }

        counter_list_intro = (matches!(segment.text.trim_end().chars().last(), Some(':' | '：'))
            && (is_counter_context || is_counter_list_intro))
            || is_warning_heading_for_list;
        if is_counter_context || is_counter_list_intro || is_warning_heading_for_list {
            removed_counter_context = true;
        } else {
            actionable_segments.push(segment.text.clone());
        }
    }
    if removed_counter_context {
        Cow::Owned(actionable_segments.join("\n"))
    } else {
        Cow::Borrowed(text)
    }
}

fn has_recipient_directed_action(text: &str) -> bool {
    let prose = semantic_prose_without_transport_tokens(text);
    let normalized = normalize_text(&prose.to_lowercase());
    let compact = compact_detection_view(&normalized);
    first_config_term_hit(
        &normalized,
        &compact,
        module_data().get_list("recipient_directed_action_markers"),
    )
    .is_some()
}

/// Stage B is opt-in while additive semantic rules are being shadowed.
/// Stage A evidence-quality corrections remain active independently.
fn email_semantic_stage_b_enabled() -> bool {
    std::env::var("VIGILYX_EMAIL_SEMANTIC_STAGE_B").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "enabled"
        )
    })
}

fn external_credential_link_stage_b_enabled() -> bool {
    std::env::var("VIGILYX_EXTERNAL_CREDENTIAL_LINK_STAGE_B").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "enabled"
        )
    })
}

fn reply_to_handoff_stage_b_enabled() -> bool {
    std::env::var("VIGILYX_REPLY_TO_HANDOFF_STAGE_B").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "enabled"
        )
    })
}

/// Stage B recognizes a bounded reply-to handoff as the recipient-directed
/// action when the same short, non-counter-context window also names data to
/// be sent. A reply-to mismatch and an invoice mention in separate paragraphs
/// remain observations.
fn has_local_reply_handoff_sensitive_request(text: &str) -> bool {
    let md = module_data();
    bounded_actionable_windows(text, 3, 512)
        .into_iter()
        .any(|window| {
            let (normalized, compact) = normalized_and_compact(&window);
            let handoff = count_config_terms(
                &normalized,
                &compact,
                md.get_list("reply_to_handoff_action_terms"),
            ) > 0;
            let sensitive = count_config_terms(
                &normalized,
                &compact,
                md.get_list("pii_external_collection_terms"),
            ) + count_config_terms(
                &normalized,
                &compact,
                md.get_list("pii_external_collection_terms_extra"),
            ) + count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_sensitive_exfiltration_terms"),
            ) > 0;
            handoff && sensitive
        })
}

/// Named no-IOC gift-card BEC compound. Gift-card nouns, quantities, or a
/// reply request are individually ordinary business language; admission
/// requires an external sender and all four procurement/value/secret/delivery
/// dimensions in the same short message.
pub(super) fn detect_gift_card_bec(
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

    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    if normalized.trim().is_empty() {
        return;
    }

    let md = module_data();
    let procurement_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("gift_card_procurement_terms"),
    );
    let value_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("gift_card_quantity_value_terms"),
    );
    let secret_hits =
        count_config_terms(&normalized, &compact, md.get_list("gift_card_secret_terms"));
    let delivery_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("gift_card_delivery_terms"),
    );
    if procurement_hits < 2 || value_hits == 0 || secret_hits == 0 || delivery_hits == 0 {
        return;
    }

    *total_score += 0.78;
    categories.push("bec".to_string());
    if ctx.session.content.links.is_empty() && ctx.session.content.attachments.is_empty() {
        categories.push("bec_no_ioc_social".to_string());
    }
    evidence.push(Evidence {
        description: format!(
            "No-IOC gift-card BEC compound from external domain {}: procurement={}, value/quantity={}, card-secret={}, reply/photo delivery={}",
            sender_domain.as_deref().unwrap_or("unknown"),
            procurement_hits,
            value_hits,
            secret_hits,
            delivery_hits,
        ),
        location: Some("subject + body + envelope".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Named reply-style PII harvesting compound. DLP observations remain
/// informational by themselves; this scenario becomes phishing only when an
/// external sender asks for both identity-document media and biometric media
/// to be returned by email in an onboarding/recruitment context.
pub(super) fn detect_reply_pii_harvest(
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

    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    if normalized.trim().is_empty() {
        return;
    }

    let md = module_data();
    let reply = first_config_term_hit(
        &normalized,
        &compact,
        md.get_list("pii_reply_collection_terms"),
    );
    let document = first_config_term_hit(
        &normalized,
        &compact,
        md.get_list("pii_identity_document_terms"),
    );
    let biometric = first_config_term_hit(
        &normalized,
        &compact,
        md.get_list("pii_biometric_media_terms"),
    );
    let context = first_config_term_hit(
        &normalized,
        &compact,
        md.get_list("pii_collection_context_terms"),
    );
    let (Some(reply), Some(document), Some(biometric), Some(context)) =
        (reply, document, biometric, context)
    else {
        return;
    };

    *total_score += 0.75;
    // Keep a detector-specific admission anchor. The generic `phishing`
    // compatibility label is observation-only in verdict normalization, but
    // this qualified reply-style PII compound must remain actionable.
    categories.push("pii_reply_harvest_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "Reply-style PII harvesting compound from external domain {}: action '{}', document '{}', biometric '{}', context '{}'",
            sender_domain.as_deref().unwrap_or("unknown"),
            reply,
            document,
            biometric,
            context,
        ),
        location: Some("subject + body + envelope".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Detect external sensitive-field collection beyond the narrower
/// document-plus-biometric reply scenario. The compound still requires an
/// external sender, at least two distinct sensitive fields, a qualifying
/// service/context narrative, and an explicit collection action. A no-link
/// message must additionally ask for a reply.
pub(super) fn detect_external_pii_collection(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
    qualified_compounds: &mut Vec<serde_json::Value>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "pii_collection_lure")
    {
        return;
    }
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let md = module_data();
    let qualifies = |text: &str, target_text: &str, require_multiple: bool| {
        let prose = semantic_prose_without_transport_tokens(text);
        let (normalized, compact) = normalized_and_compact(&prose);
        let fields = count_config_terms(
            &normalized,
            &compact,
            md.get_list("pii_external_collection_terms"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("pii_external_collection_terms_extra"),
        );
        let high_risk_fields = count_config_terms(
            &normalized,
            &compact,
            md.get_list("pii_external_high_risk_field_terms"),
        );
        let context = count_config_terms(
            &normalized,
            &compact,
            md.get_list("pii_external_collection_context_terms"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("pii_external_collection_context_terms_extra"),
        );
        let (target_normalized, target_compact) = normalized_and_compact(target_text);
        let collection = count_config_terms(
            &target_normalized,
            &target_compact,
            md.get_list("pii_direct_collection_action_terms"),
        );
        // Names, company information, registration and ordinary phone contact
        // are not sensitive-data theft. Require an actual high-risk field and
        // a direct handoff in the same local claim as its collection route.
        high_risk_fields > 0
            && context > 0
            && collection > 0
            && count_config_terms(
                &target_normalized,
                &target_compact,
                md.get_list("pii_current_collection_request_markers"),
            ) > 0
            && count_config_terms(
                &target_normalized,
                &target_compact,
                md.get_list("pii_completed_collection_report_markers"),
            ) == 0
            && (!require_multiple || fields >= 2 || high_risk_fields >= 2)
            && !is_counter_context_segment(text)
    };
    let mut admitted = None;
    for link in scoped_action_links(ctx, &body) {
        let same_sender = extract_domain_from_url(&link.effective_url).is_some_and(|domain| {
            sender_domain
                .as_deref()
                .is_some_and(|sender| domains_share_organizational_domain(&domain, sender))
        });
        if qualifies(&link.prose, &link.target_prose, same_sender) {
            admitted = Some(qualified_link_compound("pii_collection_lure", &link, 0.58));
            break;
        }
    }
    if admitted.is_none() {
        for window in semantic_paragraphs(&body)
            .flat_map(|paragraph| bounded_actionable_windows(paragraph, 3, 512))
        {
            let prose = semantic_prose_without_transport_tokens(&window);
            let (normalized, compact) = normalized_and_compact(&prose);
            let reply = count_config_terms(
                &normalized,
                &compact,
                md.get_list("pii_reply_collection_terms"),
            ) + count_config_terms(
                &normalized,
                &compact,
                md.get_list("pii_reply_collection_terms_extra"),
            );
            let offplatform = count_config_terms(
                &normalized,
                &compact,
                md.get_list("pii_external_offplatform_action_terms"),
            );
            let target = if reply > 0 {
                collection_reply_target(ctx)
            } else if offplatform > 0 {
                // An explicit mailbox in the same request is a real handoff
                // route. An unspecified "agent" or WeChat mention has no
                // observed destination and cannot fabricate a reply target.
                RE_SEMANTIC_MAILBOX
                    .find(&window)
                    .map(|mailbox| mailbox.as_str().trim_end_matches('.').to_ascii_lowercase())
            } else {
                None
            };
            if let Some(target) = target
                && semantic_segments(&window)
                    .any(|segment| qualifies(&prose, &segment.text, reply > 0))
            {
                admitted = Some(qualified_reply_compound(&prose, &target));
                break;
            }
        }
    }
    let Some(record) = admitted else {
        return;
    };
    *total_score += 0.58;
    categories.push("pii_collection_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "Scoped sensitive-field collection request from {}; explicit field, handoff and destination share one claim; ownership unverified",
            sender_domain.as_deref().unwrap_or("unknown"),
        ),
        location: record.get("source_span_id").and_then(serde_json::Value::as_str).map(str::to_string),
        snippet: None,
    });
    qualified_compounds.push(record);
}

/// Routine vendor release notices and long-form business bulletins commonly
/// contain package/announcement wording, operational detail, and links to a
/// support portal. Those words are useful context for the generic action-link
/// detector only when paired with a credential, payment, or execution action.
/// Keep this veto narrow and structural so it cannot suppress a package-install
/// lure or a link with obvious URL-risk indicators.
fn has_direct_high_risk_action(text: &str) -> bool {
    let md = module_data();
    semantic_segments(text).any(|segment| {
        let (normalized, compact) = normalized_and_compact(&segment.text);
        let high_risk_hits = count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_high_risk_terms"),
        );
        let action_hits = count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_action_terms"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_extra_action_terms"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_extra_action_terms_v2"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_locale_action_terms"),
        );
        high_risk_hits > 0 && action_hits > 0 && has_recipient_directed_action(&segment.text)
    })
}

fn is_routine_official_notice(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty() || ctx.session.content.links.is_empty() {
        return false;
    }

    let (raw_normalized, raw_compact) = normalized_and_compact(raw_combined);
    let (normalized, compact) = normalized_and_compact(actionable_context);
    let md = module_data();
    let official_marker_hits = count_config_terms(
        &raw_normalized,
        &raw_compact,
        md.get_list("external_action_link_routine_official_markers"),
    );
    let official_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("external_action_link_routine_official_context_terms"),
    );
    // Anti-phishing disclaimers are deliberately removed from the actionable
    // view so that a real request elsewhere in the message remains visible.
    // They still need to participate in the routine-notice calibration: a
    // government notice that says the mail will not collect material, ask for
    // credentials, or use a non-government domain is materially different
    // from a lure containing the same workflow words.
    let anti_phishing_marker_hits = count_config_terms(
        &raw_normalized,
        &raw_compact,
        md.get_list("external_action_link_anti_phishing_markers"),
    );
    let raw_official_context_hits = count_config_terms(
        &raw_normalized,
        &raw_compact,
        md.get_list("external_action_link_routine_official_context_terms"),
    );
    let direct_high_risk_action = has_direct_high_risk_action(actionable_context);
    let safe_links = ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let effective_url = effective_structural_url(&link.url);
        let Ok(parsed) = url::Url::parse(&effective_url) else {
            return false;
        };
        matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>().is_err()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
            })
    });
    let official_notice_shape = official_marker_hits >= 3
        && official_context_hits >= 3
        && normalized.chars().count() >= 160;
    let anti_phishing_official_notice_shape = anti_phishing_marker_hits >= 2
        && raw_official_context_hits >= 3
        && raw_normalized.chars().count() >= 160;
    let manual_data_room_notice = is_routine_manual_data_room_notice(ctx, raw_combined);

    (official_notice_shape || anti_phishing_official_notice_shape || manual_data_room_notice)
        && (!direct_high_risk_action || manual_data_room_notice)
        && safe_links
        && !has_shortener_destination(ctx)
}

/// A business data-room notice is a routine workflow when it tells recipients
/// to type the named platform address themselves and says that the buyer's IT
/// team provisions the initial password out of band. Do not suppress normal
/// linked collection messages: this requires both safeguards, a platform name
/// in the message, and an HTTPS destination on a configured provider domain.
fn is_routine_manual_data_room_notice(ctx: &SecurityContext, raw_combined: &str) -> bool {
    let md = module_data();
    let (normalized, compact) = normalized_and_compact(raw_combined);
    let manual_navigation_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("routine_manual_data_room_navigation_markers"),
    );
    let out_of_band_credential_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("routine_manual_data_room_out_of_band_credential_markers"),
    );
    let data_room_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("routine_manual_data_room_context_markers"),
    );
    let has_suspicious_actionable_link = ctx
        .session
        .content
        .links
        .iter()
        .any(|link| link.suspicious && link_is_actionable_in_context(ctx, link, raw_combined));
    let mut actionable_urls = ctx
        .session
        .content
        .links
        .iter()
        .filter(|link| !link.suspicious && link_is_actionable_in_context(ctx, link, raw_combined))
        .map(|link| link.url.clone())
        .collect::<Vec<_>>();
    if actionable_urls.is_empty() {
        actionable_urls.extend(
            RE_HTML_ALT_URL
                .find_iter(raw_combined)
                .map(|matched| matched.as_str().to_string()),
        );
    }
    if manual_navigation_hits < 2
        || out_of_band_credential_hits < 2
        || data_room_context_hits < 2
        || normalized.chars().count() < 300
        || actionable_urls.is_empty()
        || has_suspicious_actionable_link
    {
        return false;
    }

    let platform_names = md.get_list("routine_manual_data_room_platform_names");
    let platform_domains = md.get_list("routine_manual_data_room_platform_domains");
    let links_match_named_platform = actionable_urls.iter().all(|url| {
        let effective = effective_structural_url(url);
        let Ok(parsed) = url::Url::parse(&effective) else {
            return false;
        };
        if parsed.scheme() != "https"
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return false;
        }
        let Some(host) = parsed.host_str() else {
            return false;
        };
        if host.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        let platform_domain_matches_host = platform_domains
            .iter()
            .any(|domain| host == domain || host.ends_with(&format!(".{domain}")));
        let message_names_platform = platform_names
            .iter()
            .any(|platform| normalized.contains(platform));
        platform_domain_matches_host && message_names_platform
    });

    links_match_named_platform && !has_shortener_destination(ctx)
}

/// A vendor maintenance bulletin may contain a real script/package
/// execution step. That is operational risk and must remain visible to the
/// attachment/coverage modules, but it is not a credential or navigation
/// lure by itself. Admit this narrow shape only when the attachment metadata
/// and the body independently describe a multi-dimensional business release.
/// The generic action-link detector still handles every other archive or
/// executable attachment.
fn is_routine_operational_attachment_notice(
    ctx: &SecurityContext,
    normalized: &str,
    compact: &str,
) -> bool {
    if ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.is_empty()
        || ctx.session.content.truncated
        || ctx.session.content.dropped_attachments > 0
        || ctx.session.content.links_truncated
    {
        return false;
    }

    let md = module_data();
    let attachment_names = ctx
        .session
        .content
        .attachments
        .iter()
        .map(|attachment| {
            format!(
                "{} {}",
                attachment.filename.to_lowercase(),
                attachment.content_type.to_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (attachment_normalized, attachment_compact) = normalized_and_compact(&attachment_names);
    let routine_attachment_count = ctx
        .session
        .content
        .attachments
        .iter()
        .filter(|attachment| {
            let filename: String = attachment
                .filename
                .nfkc()
                .collect::<String>()
                .to_lowercase();
            let extension = filename
                .rsplit('.')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or_default();
            md.contains(
                "external_action_link_routine_attachment_extensions",
                extension,
            )
        })
        .count();
    if routine_attachment_count != ctx.session.content.attachments.len() {
        return false;
    }

    let attachment_context_hits = count_config_terms(
        &attachment_normalized,
        &attachment_compact,
        md.get_list("external_action_link_routine_attachment_context_terms"),
    );
    let operational_step_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_operational_step_terms"),
    );
    let release_context_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_release_context_terms"),
    );
    let notice_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_notice_terms"),
    );
    let informational_context_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_informational_context_terms"),
    );
    let informational_detail_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_informational_detail_terms"),
    );
    if attachment_context_hits < 2
        || operational_step_hits < 2
        || release_context_hits == 0
        || notice_hits == 0
        || informational_context_hits < 3
        || informational_detail_hits < 2
    {
        return false;
    }

    let ambiguous_high_risk_terms =
        md.get_list("external_action_link_routine_ambiguous_high_risk_terms");
    let has_non_operational_high_risk = has_direct_high_risk_action(normalized)
        && md
            .get_list("external_action_link_high_risk_terms")
            .iter()
            .any(|term| {
                !ambiguous_high_risk_terms
                    .iter()
                    .any(|ambiguous| ambiguous == term)
                    && keyword_matches_text(normalized, compact, term)
            });
    if has_non_operational_high_risk {
        return false;
    }

    let safe_links = ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let effective_url = effective_structural_url(&link.url);
        let Ok(parsed) = url::Url::parse(&effective_url) else {
            return false;
        };
        matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>().is_err()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
            })
    });

    safe_links && !has_shortener_destination(ctx)
}

fn is_routine_business_notification(
    ctx: &SecurityContext,
    normalized: &str,
    compact: &str,
    high_risk_hits: usize,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if ctx.session.content.links.is_empty() {
        return false;
    }

    let md = module_data();
    let official_notice_shape = is_routine_official_notice(ctx, raw_combined, actionable_context);
    let routine_operational_attachment_notice =
        is_routine_operational_attachment_notice(ctx, normalized, compact);
    if !ctx.session.content.attachments.is_empty() && !routine_operational_attachment_notice {
        return false;
    }
    let ambiguous_business_high_risk_terms =
        md.get_list("external_action_link_routine_ambiguous_high_risk_terms");
    let has_disqualifying_high_risk = has_direct_high_risk_action(actionable_context)
        && md
            .get_list("external_action_link_high_risk_terms")
            .iter()
            .any(|term| {
                !ambiguous_business_high_risk_terms
                    .iter()
                    .any(|ambiguous| ambiguous == term)
                    && keyword_matches_text(normalized, compact, term)
            });
    if high_risk_hits > 0 && has_disqualifying_high_risk && !official_notice_shape {
        return false;
    }

    let release_context_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_release_context_terms"),
    );
    let notice_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_notice_terms"),
    );
    let risky_action_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_risky_action_terms"),
    );
    let informational_context_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_informational_context_terms"),
    );
    let informational_detail_hits = count_config_terms(
        normalized,
        compact,
        md.get_list("external_action_link_routine_informational_detail_terms"),
    );
    let release_notice_shape = release_context_hits >= 2 && notice_hits > 0;
    // A legitimate vendor bulletin can be compact after HTML/tag and footer
    // sanitization.  Keep the multi-dimension requirement, but do not make
    // the evidence depend on an arbitrary 400-character body boundary; the
    // observed 372-character bulletin is still structurally distinct from a
    // short click lure.
    let long_business_bulletin_shape = informational_context_hits >= 3
        && informational_detail_hits >= 3
        && notice_hits > 0
        && normalized.chars().count() >= 320;
    if (!release_notice_shape && !long_business_bulletin_shape && !official_notice_shape)
        || (risky_action_hits > 0
            && !official_notice_shape
            && !routine_operational_attachment_notice)
    {
        return false;
    }

    ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let effective_url = effective_structural_url(&link.url);
        let Ok(parsed) = url::Url::parse(&effective_url) else {
            return false;
        };
        matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>().is_err()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
            })
    }) && !has_shortener_destination(ctx)
}

/// A short CERT-style advisory may link to a password-protected malware
/// sample without requesting the recipient's password. Suppress only this
/// bounded publication shape on an HTTPS publisher-aligned destination, with
/// no attachment, shortener, suspicious link fact, or credential-entry ask.
fn is_routine_security_sample_advisory(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.is_empty()
        || ctx.session.content.links_truncated
        || has_shortener_destination(ctx)
    {
        return false;
    }
    let Some(sender_domain) = external_sender_domain(ctx) else {
        return false;
    };
    let links_are_publisher_aligned = ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let Ok(parsed) = effective_structural_url(&link.url).parse::<url::Url>() else {
            return false;
        };
        parsed.scheme() == "https"
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>().is_err()
                    && domains_share_organizational_domain(host, &sender_domain)
            })
    });
    let md = module_data();
    let publication_shape = bounded_actionable_windows(raw_combined, 2, 320)
        .iter()
        .any(|window| {
            let (normalized, compact) = normalized_and_compact(window);
            count_config_terms(
                &normalized,
                &compact,
                md.get_list("routine_sample_advisory_context_markers"),
            ) > 0
                && count_config_terms(
                    &normalized,
                    &compact,
                    md.get_list("routine_sample_archive_gating_markers"),
                ) > 0
        });
    let (actionable_normalized, actionable_compact) = normalized_and_compact(actionable_context);
    links_are_publisher_aligned
        && publication_shape
        && count_config_terms(
            &actionable_normalized,
            &actionable_compact,
            md.get_list("routine_sample_credential_request_markers"),
        ) == 0
}

/// Recover generic external action-link lures whose wording is not tied to a
/// single brand or product. The compound requires an untrusted destination,
/// an explicit recipient action, and either a high-risk credential/privacy
/// cue, multiple lure-context cues, or urgency. This keeps ordinary external
/// newsletters and business links below the admission bar while covering the
/// broad account/credential families when AI is disabled.
pub(super) fn detect_external_action_link_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
    qualified_compounds: &mut Vec<serde_json::Value>,
) {
    detect_external_action_link_lure_with_stage_b(
        ctx,
        body_for_cross,
        total_score,
        categories,
        evidence,
        qualified_compounds,
        external_credential_link_stage_b_enabled(),
    );
}

pub(super) fn detect_external_action_link_lure_with_stage_b(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
    qualified_compounds: &mut Vec<serde_json::Value>,
    stage_b_enabled: bool,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories.iter().any(|category| {
            category == "external_action_link_lure" || category == "external_identity_consent_lure"
        })
    {
        return;
    }
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    if looks_like_benign_account_notice(ctx, Some(&body)) {
        return;
    }
    let md = module_data();
    let mut scoped_links = scoped_action_links(ctx, &body);
    if stage_b_enabled {
        scoped_links.extend(scoped_neighboring_action_links_stage_b(ctx, &body));
    }
    for link in scoped_links {
        let (normalized, compact) = normalized_and_compact(&link.prose);
        let (target_normalized, target_compact) = normalized_and_compact(&link.target_prose);
        let context_hits = [
            "external_action_link_context_terms",
            "external_action_link_extra_context_terms",
            "external_action_link_extra_context_terms_v2",
            "external_action_link_locale_context_terms",
        ]
        .iter()
        .map(|name| count_config_terms(&normalized, &compact, md.get_list(name)))
        .sum::<usize>();
        let action_lists = [
            md.get_list("external_action_link_action_terms"),
            md.get_list("external_action_link_extra_action_terms"),
            md.get_list("external_action_link_extra_action_terms_v2"),
            md.get_list("external_action_link_locale_action_terms"),
            md.get_list("external_action_link_local_action_terms"),
        ];
        let stage_b_action = if stage_b_enabled {
            first_config_term_hit(
                &target_normalized,
                &target_compact,
                md.get_list("external_action_link_stage_b_action_markers"),
            )
        } else {
            None
        };
        let local_action = action_lists
            .iter()
            .find_map(|terms| first_config_term_hit(&target_normalized, &target_compact, terms))
            .or_else(|| stage_b_action.clone());
        let stage_b_sensitive_credential_request = stage_b_action.is_some()
            && count_config_terms(
                &target_normalized,
                &target_compact,
                md.get_list("external_action_link_stage_b_sensitive_secret_terms"),
            ) > 0;
        let high_risk_hits = count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_high_risk_terms"),
        );
        let observation_fields = md.get_list("external_action_link_observation_field_terms");
        let native_field_hits = md
            .get_list("external_action_link_high_risk_terms")
            .iter()
            .filter(|term| {
                !observation_fields.contains(term)
                    && keyword_matches_text(&normalized, &compact, term)
            })
            .count();
        let specific_action = first_config_term_hit(
            &normalized,
            &compact,
            md.get_list("external_action_link_local_action_terms"),
        );
        let account_threat = account_security_threats()
            .scan(&normalized)
            .distinct_count()
            > 0;
        let stage_b_account_threat = stage_b_enabled
            && count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_action_link_stage_b_account_threat_markers"),
            ) > 0;
        let stage_b_account_request = stage_b_action.is_some() && stage_b_account_threat;
        let stage_b_qualified = stage_b_account_request || stage_b_sensitive_credential_request;
        if link.stage_b_neighboring_link && !stage_b_qualified {
            continue;
        }
        let registration_context = count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_routine_registration_terms"),
        ) >= 2;
        // Registration and public business information are observations. A
        // real secret/identity handoff or account threat in this same claim
        // still defeats the calibration; unrelated disclaimers cannot do so.
        if registration_context
            && native_field_hits == 0
            && !account_threat
            && !stage_b_account_threat
            && specific_action.is_none()
        {
            continue;
        }
        let same_sender = extract_domain_from_url(&link.effective_url).is_some_and(|domain| {
            sender_domain
                .as_deref()
                .is_some_and(|sender| domains_share_organizational_domain(&domain, sender))
        });
        let same_sender_lure = count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_action_link_same_sender_lure_terms"),
        ) > 0
            || native_field_hits > 0;
        let semantic_qualification = native_field_hits > 0
            || context_hits >= 2
            || (specific_action.is_some() && context_hits > 0)
            || account_threat
            || stage_b_qualified;
        if local_action.is_none()
            || (!has_recipient_directed_action(&link.target_prose) && !stage_b_qualified)
            || !semantic_qualification
            || (same_sender && !same_sender_lure)
            || is_routine_security_sample_advisory(ctx, &link.prose, &link.prose)
            || is_routine_saml_signing_cert_notice(ctx, &link.prose, &link.prose)
            || is_routine_business_notification(
                ctx,
                &normalized,
                &compact,
                high_risk_hits,
                &link.prose,
                &link.prose,
            )
        {
            continue;
        }
        *total_score += 0.56;
        categories.push("external_action_link_lure".to_string());
        categories.push("phishing".to_string());
        qualified_compounds.push(qualified_link_compound(
            "external_action_link_lure",
            &link,
            0.56,
        ));
        evidence.push(Evidence {
            description: format!(
                "Scoped external action-link request from {}: context={}, local_action={}, high_risk={}; transport and ownership unverified",
                sender_domain.as_deref().unwrap_or("unknown"), context_hits,
                local_action.as_deref().unwrap_or("none"), high_risk_hits,
            ),
            location: Some(compound_span_id(&link.prose)),
            snippet: None,
        });
        return;
    }
}

/// Detect OAuth-style consent lures that describe a business or partner
/// identity handoff without using familiar password-phishing wording. The
/// explicit consent language must be in the same semantic span as a
/// third-party portal destination.
pub(super) fn detect_external_identity_consent_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "external_identity_consent_lure")
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    if !has_untrusted_body_destination(ctx, &actionable_context) {
        return;
    }

    let md = module_data();
    let qualifying_span = semantic_segments(&actionable_context).find(|segment| {
        let (normalized, compact) = normalized_and_compact(&segment.text);
        count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_identity_consent_action_terms"),
        ) > 0
            && count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_identity_consent_context_terms"),
            ) > 0
    });
    let Some(segment) = qualifying_span else {
        return;
    };

    *total_score += 0.64;
    categories.push("external_identity_consent_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External partner portal requests business-identity consent in the same span as an untrusted destination from {}",
            sender_domain.as_deref().unwrap_or("unknown")
        ),
        location: Some("subject + body + external portal destination".to_string()),
        snippet: Some(segment.text.chars().take(180).collect()),
    });
}

/// Detect an external non-standard-port URL that is presented as an internal
/// monitoring or diagnostics panel. The claim and resource reference must be
/// local to the URL-bearing semantic span, preventing ordinary `:8080`
/// documentation examples from becoming phishing evidence.
pub(super) fn detect_external_internal_service_link_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "external_internal_service_link")
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let md = module_data();

    for segment in semantic_segments(&actionable_context) {
        let (normalized, compact) = normalized_and_compact(&segment.text);
        if count_config_terms(
            &normalized,
            &compact,
            md.get_list("external_internal_service_claim_terms"),
        ) == 0
            || count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_internal_service_context_terms"),
            ) == 0
        {
            continue;
        }

        for matched in RE_HTML_ALT_URL.find_iter(&segment.text) {
            let normalized_raw = matched.as_str().replace('：', ":");
            let raw = normalized_raw.trim_end_matches([
                '.', ',', ';', ':', '!', '?', '，', '。', '；', '：', '）', ')', '】', ']',
            ]);
            let Ok(parsed) = url::Url::parse(raw) else {
                continue;
            };
            let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
                continue;
            };
            let Some(port) = parsed.port() else {
                continue;
            };
            let external_host = !ctx.is_internal_domain(&host)
                && !md.contains("protected_domains", &host)
                && !crate::modules::link_scan::is_trusted_url_domain(&host)
                && !crate::modules::link_scan::is_well_known_safe_domain(&host);
            if !external_host || port == 80 || port == 443 {
                continue;
            }

            *total_score += 0.60;
            categories.push("external_internal_service_link".to_string());
            categories.push("phishing".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Message calls a non-standard-port destination {host}:{port} an internal monitoring/diagnostics resource"
                ),
                location: Some("body internal-network claim + external URL".to_string()),
                snippet: Some(segment.text.chars().take(180).collect()),
            });
            return;
        }
    }
}

/// Detect dangerous inter-app protocol execution instructions that do not
/// contain an HTTP URL and therefore never reach the ordinary link detector.
/// The scheme and action vocabulary are JSON-backed; the compound still needs
/// an external sender and an explicit recipient execution step.
fn protocol_marker_needle(marker: &str) -> String {
    if marker.contains('\\') {
        // The seed represents UNC paths with escaped backslashes.  Match the
        // actual path prefix directly instead of sending it through the
        // compact keyword view, where punctuation-only terms lose meaning.
        "\\\\".to_string()
    } else {
        normalize_text(&marker.to_lowercase())
    }
}

fn protocol_marker_present(text: &str, marker: &str) -> bool {
    let needle = protocol_marker_needle(marker);
    !needle.is_empty() && text.to_lowercase().contains(&needle)
}

fn is_explicit_protocol_action(window: &str, action: &str) -> bool {
    let generic_action = matches!(action, "运行" | "run" | "保持在线" | "stay online");
    if !generic_action {
        return true;
    }

    // Standalone words such as “运行” occur in ordinary engineering reports.
    // They become execution evidence only with a recipient-directed command.
    [
        "请",
        "立即",
        "直接",
        "打开",
        "复制",
        "双击",
        "粘贴",
        "执行",
        "please",
        "immediately",
        "directly",
        "open",
        "copy",
        "paste",
        "double-click",
        "execute",
    ]
    .iter()
    .any(|marker| window.contains(marker))
}

fn is_protocol_implicit_action(action: &str) -> bool {
    let normalized = normalize_text(&action.to_lowercase());
    module_data()
        .get_list("protocol_implicit_action_terms")
        .iter()
        .map(|term| normalize_text(&term.to_lowercase()))
        .any(|term| !term.is_empty() && term == normalized)
}

/// Remove only the dangerous-protocol token from a local action window before
/// matching a configured multi-word execution phrase.  Mail commonly inserts
/// the URI between the two halves of an instruction, e.g. `复制
/// file://... 到运行窗口执行`; deleting the URI preserves the action relation
/// without turning a bare `复制` or `运行` into execution evidence.
fn protocol_action_search_view(text: &str, scheme_terms: &[String]) -> String {
    text.split_whitespace()
        .filter(|token| {
            !scheme_terms
                .iter()
                .any(|scheme| protocol_marker_present(token, scheme))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn find_protocol_execution_pair(
    text: &str,
    scheme_terms: &[String],
    action_terms: &[String],
) -> Option<(String, String)> {
    let normalized = normalize_text(&text.to_lowercase());
    for segment in semantic_segments(&normalized) {
        if is_counter_context_segment(&segment.text) {
            continue;
        }
        if let Some(scheme) = scheme_terms.iter().find(|scheme| {
            let needle = protocol_marker_needle(scheme);
            !needle.is_empty() && segment.text.contains(&needle)
        }) && let Some(action) = action_terms.iter().find(|action| {
            let normalized_action = normalize_text(&action.to_lowercase());
            let action_search_view = protocol_action_search_view(&segment.text, scheme_terms);
            let compact_action_search_view =
                compact_detection_view(&normalize_text(&action_search_view));
            let compact_action = compact_detection_view(&normalized_action);
            !normalized_action.is_empty()
                && (segment.text.contains(&normalized_action)
                    || normalize_text(&action_search_view).contains(&normalized_action)
                    || (!compact_action.is_empty()
                        && compact_action_search_view.contains(&compact_action)))
                && (has_recipient_directed_action(&segment.text)
                    || is_protocol_implicit_action(&normalized_action))
                && is_explicit_protocol_action(&segment.text, &normalized_action)
        }) {
            return Some((scheme.clone(), action.clone()));
        }
    }

    // Plain-text mail often puts the protocol on the next line after the
    // instruction.  Preserve that paragraph-level relation instead of
    // requiring both facts to occupy one punctuation segment.
    for scheme in scheme_terms {
        let needle = protocol_marker_needle(scheme);
        let Some(scheme_pos) = normalized.find(&needle) else {
            continue;
        };
        let window = text_window_around(&normalized, scheme_pos, 180);
        if is_counter_context_segment(window) {
            continue;
        }
        if let Some(action) = action_terms.iter().find(|action| {
            let normalized_action = normalize_text(&action.to_lowercase());
            let action_search_view = protocol_action_search_view(window, scheme_terms);
            let compact_action_search_view =
                compact_detection_view(&normalize_text(&action_search_view));
            let compact_action = compact_detection_view(&normalized_action);
            !normalized_action.is_empty()
                && (window.contains(&normalized_action)
                    || normalize_text(&action_search_view).contains(&normalized_action)
                    || (!compact_action.is_empty()
                        && compact_action_search_view.contains(&compact_action)))
                && (has_recipient_directed_action(window)
                    || is_protocol_implicit_action(&normalized_action))
                && is_explicit_protocol_action(window, &normalized_action)
        }) {
            return Some((scheme.clone(), action.clone()));
        }
    }
    None
}

fn find_explicit_protocol_action(text: &str, action_terms: &[String]) -> Option<String> {
    let normalized = normalize_text(&text.to_lowercase());
    semantic_segments(&normalized)
        .filter(|segment| !is_counter_context_segment(&segment.text))
        .find_map(|segment| {
            action_terms.iter().find_map(|action| {
                let normalized_action = normalize_text(&action.to_lowercase());
                (!normalized_action.is_empty()
                    && segment.text.contains(&normalized_action)
                    && (has_recipient_directed_action(&segment.text)
                        || is_protocol_implicit_action(&normalized_action))
                    && is_explicit_protocol_action(&segment.text, &normalized_action))
                .then(|| action.clone())
            })
        })
}

pub(super) fn detect_protocol_execution_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "protocol_execution_lure")
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let md = module_data();
    let scheme_terms = md.get_list("dangerous_url_schemes");
    let action_terms = md.get_list("protocol_execution_action_terms");
    let html = ctx.session.content.body_html.as_deref().unwrap_or_default();
    let action_text = format!("{combined}\n{html}");
    let scheme_sources = std::iter::once(combined.as_str())
        .chain(std::iter::once(html))
        .chain(
            ctx.session
                .content
                .links
                .iter()
                .map(|link| link.url.as_str()),
        );
    let scheme_hits = scheme_terms
        .iter()
        .filter(|scheme| {
            scheme_sources
                .clone()
                .any(|source| protocol_marker_present(source, scheme))
        })
        .count();
    let nearby_pair = find_protocol_execution_pair(&action_text, scheme_terms, action_terms);
    let linked_scheme_with_action = ctx.session.content.links.iter().any(|link| {
        scheme_terms
            .iter()
            .any(|scheme| protocol_marker_present(&link.url, scheme))
    }) && find_explicit_protocol_action(&action_text, action_terms)
        .is_some();
    if scheme_hits == 0 || (nearby_pair.is_none() && !linked_scheme_with_action) {
        return;
    }

    let action_hits = usize::from(nearby_pair.is_some() || linked_scheme_with_action);

    *total_score += 0.68;
    categories.push("protocol_execution_lure".to_string());
    categories.push("malware".to_string());
    evidence.push(Evidence {
        description: format!(
            "External sender {} combines a dangerous inter-app protocol ({scheme_hits} scheme cue(s)) with an execution instruction ({action_hits} action cue(s))",
            sender_domain.as_deref().unwrap_or("unknown")
        ),
        location: Some("subject + body + protocol".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

fn is_untrusted_hidden_anchor_destination(ctx: &SecurityContext, href: &str) -> bool {
    let effective = effective_structural_url(&decode_html_entities(href.trim()));
    let Ok(parsed) = url::Url::parse(&effective) else {
        return false;
    };
    let Some(domain) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };

    !ctx.is_internal_domain(&domain)
        && !module_data().contains("protected_domains", &domain)
        && !crate::modules::link_scan::is_trusted_url_domain(&domain)
        && !crate::modules::link_scan::is_well_known_safe_domain(&domain)
}

/// Recover low-visibility lures only when a hidden or collapsed local block
/// contains an untrusted destination, a relevant service/account context, and
/// an explicit recipient action. Ordinary footer styling and unrelated labels
/// do not establish this relation.
pub(super) fn detect_hidden_external_link_lure(
    ctx: &SecurityContext,
    _body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "hidden_external_action_lure")
    {
        return;
    }
    let md = module_data();

    let hidden_destination = hidden_external_destination_facts(html)
        .into_iter()
        .filter(|fact| is_untrusted_hidden_anchor_destination(ctx, &fact.href))
        .filter_map(|fact| {
            let local_context = strip_counter_context_segments(&fact.local_text);
            let (normalized, compact) = normalized_and_compact(&local_context);
            let context_hits = count_config_terms(
                &normalized,
                &compact,
                md.get_list("hidden_external_link_context_terms"),
            );
            if context_hits == 0 {
                return None;
            }

            let (anchor_normalized, anchor_compact) = normalized_and_compact(&fact.anchor_text);
            let action_term = first_config_term_hit(
                &anchor_normalized,
                &anchor_compact,
                md.get_list("hidden_external_link_action_terms"),
            )
            .or_else(|| {
                first_config_term_hit(
                    &anchor_normalized,
                    &anchor_compact,
                    md.get_list("hidden_external_link_implicit_action_terms"),
                )
            })
            .or_else(|| {
                first_config_term_hit(
                    &normalized,
                    &compact,
                    md.get_list("hidden_external_link_action_terms"),
                )
            });
            let local_recipient_action = has_recipient_directed_action(&local_context);
            action_term
                .or_else(|| local_recipient_action.then(|| "recipient-directed".to_string()))
                .map(|action_term| (fact, context_hits, action_term))
        })
        .next();

    if let Some((fact, context_hits, action_term)) = hidden_destination {
        *total_score += 0.56;
        categories.push("hidden_external_action_lure".to_string());
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "A hidden or collapsed external destination is bound to a local service/account context ({context_hits}) and an explicit action ({action_term})"
            ),
            location: Some("body_html hidden destination + nearest local block".to_string()),
            snippet: Some(
                format!("{} [{}]", fact.anchor_text, fact.local_text)
                    .chars()
                    .take(180)
                    .collect(),
            ),
        });
        return;
    }

    let visible_link_action = visible_anchor_facts(html)
        .into_iter()
        .filter(|anchor| is_untrusted_hidden_anchor_destination(ctx, &anchor.href))
        .find_map(|anchor| {
            let (normalized, compact) = normalized_and_compact(&anchor.anchor_text);
            first_config_term_hit(
                &normalized,
                &compact,
                md.get_list("hidden_external_link_action_terms"),
            )
            .or_else(|| {
                first_config_term_hit(
                    &normalized,
                    &compact,
                    md.get_list("external_action_link_local_action_terms"),
                )
            })
            .map(|action| (anchor, action))
        });
    let Some((anchor, visible_action)) = visible_link_action else {
        return;
    };
    let visible_destination_domain = extract_domain_from_url(&anchor.href);
    let hidden_instruction = hidden_text_region_facts(html)
        .into_iter()
        .find_map(|hidden_text| {
            let actionable_text = strip_counter_context_segments(&hidden_text);
            let (normalized, compact) = normalized_and_compact(&actionable_text);
            let context_hits = count_config_terms(
                &normalized,
                &compact,
                md.get_list("hidden_external_link_context_terms"),
            );
            let high_risk_hits = count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_action_link_high_risk_terms"),
            );
            let hidden_action = first_config_term_hit(
                &normalized,
                &compact,
                md.get_list("hidden_external_link_action_terms"),
            )
            .or_else(|| {
                first_config_term_hit(
                    &normalized,
                    &compact,
                    md.get_list("external_action_link_local_action_terms"),
                )
            });
            let explicit_destination_reference = first_config_term_hit(
                &normalized,
                &compact,
                md.get_list("hidden_external_link_visible_destination_markers"),
            );
            let hidden_text_names_visible_host = visible_destination_domain
                .as_deref()
                .is_some_and(|domain| normalized.contains(&domain.to_ascii_lowercase()));
            (context_hits > 0
                && high_risk_hits > 0
                && hidden_action.is_some()
                && (explicit_destination_reference.is_some() || hidden_text_names_visible_host))
                .then(|| (hidden_text, context_hits, hidden_action.unwrap()))
        });
    let Some((hidden_text, context_hits, hidden_action)) = hidden_instruction else {
        return;
    };

    *total_score += 0.60;
    categories.push("hidden_external_action_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "Hidden high-risk instruction ({hidden_action}, context={context_hits}) references a separate visible external action link ({visible_action}) in the same message"
        ),
        location: Some("body_html hidden instruction + visible anchor".to_string()),
        snippet: Some(
            format!("{} [{}]", anchor.anchor_text, hidden_text)
                .chars()
                .take(180)
                .collect(),
        ),
    });
}

/// Some mail gateways retain the text of an attachment instruction but omit
/// the attachment bytes. Keep that coverage gap actionable only when the
/// external message combines a narrow operational context with an explicit
/// extraction/active-content action.
pub(super) fn detect_missing_attachment_delivery_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || !ctx.session.content.attachments.is_empty()
        || categories
            .iter()
            .any(|category| category == "attachment_delivery_lure")
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    let md = module_data();
    let context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("missing_attachment_delivery_context_terms"),
    );
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("missing_attachment_delivery_action_terms"),
    );
    if context_hits == 0 || action_hits == 0 || !has_recipient_directed_action(&actionable_context)
    {
        return;
    }

    let active_content_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("missing_attachment_delivery_high_risk_terms"),
    );
    if active_content_hits == 0 {
        // A missing ordinary document can be a mail assembly problem. Keep it
        // visible to analysts, but reserve the threat compound for requests to
        // run, extract, or enable active content from the unavailable file.
        *total_score += 0.08;
        categories.push("attachment_delivery_observed".to_string());
        evidence.push(Evidence {
            description: format!(
                "External sender references an unavailable attachment ({context_hits} context cue(s), {action_hits} action cue(s)) without an active-content instruction"
            ),
            location: Some("subject + body + attachment metadata".to_string()),
            snippet: Some(combined.chars().take(180).collect()),
        });
        return;
    }

    *total_score += 0.56;
    categories.push("attachment_delivery_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External sender references an unavailable attachment delivery ({context_hits} context cue(s), {action_hits} action cue(s)); retained message has no attachment bytes"
        ),
        location: Some("subject + body + attachment metadata".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Detect external requests to export browser/session secrets or other
/// workstation credentials. Unlike the action-link compound this path does
/// not require a URL: a direct request to return a cookie database or token
/// is already an actionable exfiltration lure.
pub(super) fn detect_external_sensitive_exfiltration(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "credential_exfiltration_lure")
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    if actionable_context.trim().is_empty() {
        return;
    }
    if is_explicit_anti_phishing_security_advisory(ctx, &combined, &actionable_context) {
        return;
    }
    let md = module_data();
    let stage_b_enabled = email_semantic_stage_b_enabled();
    let local_request = bounded_actionable_windows(&actionable_context, 3, 512)
        .into_iter()
        .find_map(|window| {
            let (local_normalized, local_compact) = normalized_and_compact(&window);
            let high_risk_secret_hits = count_config_terms(
                &local_normalized,
                &local_compact,
                md.get_list("external_sensitive_exfiltration_high_risk_secret_terms"),
            ) + if stage_b_enabled {
                count_config_terms(
                    &local_normalized,
                    &local_compact,
                    md.get_list("external_sensitive_exfiltration_stage_b_high_risk_secret_terms"),
                )
            } else {
                0
            };
            let secret_hits = count_config_terms(
                &local_normalized,
                &local_compact,
                md.get_list("external_sensitive_exfiltration_terms"),
            ) + count_config_terms(
                &local_normalized,
                &local_compact,
                md.get_list("external_sensitive_exfiltration_terms_extra"),
            ) + if stage_b_enabled {
                count_config_terms(
                    &local_normalized,
                    &local_compact,
                    md.get_list("external_sensitive_exfiltration_stage_b_secret_terms"),
                )
            } else {
                0
            };
            let action_hits = count_config_terms(
                &local_normalized,
                &local_compact,
                md.get_list("external_sensitive_exfiltration_action_terms"),
            ) + if stage_b_enabled {
                count_config_terms(
                    &local_normalized,
                    &local_compact,
                    md.get_list("external_sensitive_exfiltration_stage_b_action_terms"),
                )
            } else {
                0
            };
            (high_risk_secret_hits > 0 && secret_hits > 0 && action_hits > 0)
                .then_some((high_risk_secret_hits, action_hits))
        });
    let Some((secret_hits, action_hits)) = local_request else {
        return;
    };

    *total_score += 0.65;
    categories.push("credential_exfiltration_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External high-risk secret exfiltration request from {} in a bounded recipient-directed span: secrets={}, actions={}",
            sender_domain.as_deref().unwrap_or("unknown"),
            secret_hits,
            action_hits,
        ),
        location: Some("subject + body + envelope".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Security advisories quote credential and token terms while telling users
/// not to submit them. Require multiple explicit warning markers, no
/// recipient-directed high-risk request, and only first-party or trusted
/// destinations before suppressing the direct-exfil compound.
fn is_explicit_anti_phishing_security_advisory(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty() {
        return false;
    }
    let sender_domain = external_sender_domain(ctx);
    let all_links_are_first_party_or_trusted = ctx.session.content.links.iter().all(|link| {
        if link.suspicious {
            return false;
        }
        let domain = effective_structural_url(&link.url)
            .parse::<url::Url>()
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase));
        domain.is_some_and(|domain| {
            sender_domain
                .as_deref()
                .is_some_and(|sender| domains_share_organizational_domain(&domain, sender))
                || crate::modules::link_scan::is_trusted_url_domain(&domain)
                || crate::modules::link_scan::is_well_known_safe_domain(&domain)
        })
    });
    let (normalized, compact) = normalized_and_compact(raw_combined);
    let explicitly_denies_quoted_token_handoff = semantic_segments(raw_combined).any(|segment| {
        count_config_terms(
            &segment.text,
            &compact_detection_view(&segment.text),
            module_data().get_list("external_action_link_specific_anti_phishing_markers"),
        ) >= 3
    });
    all_links_are_first_party_or_trusted
        && count_config_terms(
            &normalized,
            &compact,
            module_data().get_list("external_action_link_anti_phishing_markers"),
        ) >= 2
        && (!has_direct_high_risk_action(actionable_context)
            || explicitly_denies_quoted_token_handoff)
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
struct InvoiceKeywordMatcher {
    compact_patterns: Vec<String>,
    direct: Option<AhoCorasick>,
    compact: Option<AhoCorasick>,
    direct_owner: Vec<usize>,
    compact_owner: Vec<usize>,
}

impl InvoiceKeywordMatcher {
    fn new(keywords: &[String]) -> Self {
        let mut direct_patterns = Vec::new();
        let mut direct_owner = Vec::new();
        let mut compact_patterns = Vec::with_capacity(keywords.len());
        let mut compact_ac_patterns = Vec::new();
        let mut compact_owner = Vec::new();

        for (index, keyword) in keywords.iter().enumerate() {
            let normalized = normalize_text(&keyword.to_lowercase());
            let compact: String = normalized
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect();
            compact_patterns.push(compact.clone());

            // `contains` semantics for the normalized view are equivalent to
            // a byte-level Aho-Corasick search.  Build the automata once per
            // runtime keyword list instead of normalizing and rescanning the
            // entire list for every body window.
            if !normalized.is_empty() {
                direct_owner.push(index);
                direct_patterns.push(normalized);
            }
            if !compact.is_empty() {
                compact_owner.push(index);
                compact_ac_patterns.push(compact);
            }
        }

        Self {
            compact_patterns,
            direct: (!direct_patterns.is_empty())
                .then(|| AhoCorasick::new(direct_patterns).expect("valid invoice patterns")),
            compact: (!compact_ac_patterns.is_empty()).then(|| {
                AhoCorasick::new(compact_ac_patterns).expect("valid compact invoice patterns")
            }),
            direct_owner,
            compact_owner,
        }
    }

    fn matching_compact_patterns(&self, combined: &str, compact: &str) -> Vec<String> {
        let mut matched = vec![false; self.compact_patterns.len()];
        if let Some(automaton) = &self.direct {
            for mat in automaton.find_overlapping_iter(combined.as_bytes()) {
                matched[self.direct_owner[mat.pattern().as_usize()]] = true;
            }
        }
        if let Some(automaton) = &self.compact {
            for mat in automaton.find_overlapping_iter(compact.as_bytes()) {
                matched[self.compact_owner[mat.pattern().as_usize()]] = true;
            }
        }

        self.compact_patterns
            .iter()
            .zip(matched)
            .filter(|(pattern, matched)| *matched && !pattern.is_empty())
            .map(|(pattern, _)| pattern.clone())
            .collect()
    }
}

fn invoice_keyword_matcher(keywords: &[String]) -> Arc<InvoiceKeywordMatcher> {
    static CACHE: Mutex<Vec<(Vec<String>, Arc<InvoiceKeywordMatcher>)>> = Mutex::new(Vec::new());
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, matcher)) = guard.iter().find(|(cached, _)| cached == keywords) {
        return Arc::clone(matcher);
    }
    let matcher = Arc::new(InvoiceKeywordMatcher::new(keywords));
    if guard.len() >= 8 {
        guard.clear();
    }
    guard.push((keywords.to_vec(), Arc::clone(&matcher)));
    matcher
}

fn count_non_nested_keyword_hits(
    combined: &str,
    compact: &str,
    matcher: &InvoiceKeywordMatcher,
) -> usize {
    let mut hits = matcher.matching_compact_patterns(combined, compact);
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
    let matcher = invoice_contact_matcher();
    matcher
        .patterns
        .iter()
        .filter(|pattern| {
            combined.contains(pattern.normalized.as_str())
                || (pattern.contains_cjk
                    && !pattern.compact.is_empty()
                    && compact.contains(pattern.compact.as_str()))
        })
        .count()
}

#[derive(Debug, Clone)]
struct InvoiceContactPattern {
    normalized: String,
    compact: String,
    contains_cjk: bool,
}

#[derive(Debug)]
struct InvoiceContactMatcher {
    patterns: Vec<InvoiceContactPattern>,
}

type InvoiceContactMatcherCacheEntry = (Vec<String>, Vec<String>, Arc<InvoiceContactMatcher>);

/// Normalize the small contact-marker policy once per runtime list. The old
/// implementation rebuilt a HashSet and normalized every marker for every
/// invoice window, turning a long plain-text message into thousands of
/// repeated allocations even when it contained no contact marker.
fn invoice_contact_matcher() -> Arc<InvoiceContactMatcher> {
    static CACHE: Mutex<Vec<InvoiceContactMatcherCacheEntry>> = Mutex::new(Vec::new());

    let data = module_data();
    let direct = data
        .get_list("invoice_spam_direct_contact_markers")
        .to_vec();
    let contextual = data
        .get_list("invoice_spam_context_only_contact_markers")
        .to_vec();
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, _, matcher)) = guard.iter().find(|(cached_direct, cached_contextual, _)| {
        cached_direct == &direct && cached_contextual == &contextual
    }) {
        return Arc::clone(matcher);
    }

    let contextual_only: HashSet<String> = contextual
        .iter()
        .map(|marker| normalize_text(&marker.to_lowercase()))
        .collect();
    let mut seen = HashSet::new();
    let patterns = direct
        .iter()
        .filter_map(|marker| {
            let normalized = normalize_text(&marker.to_lowercase());
            if normalized.is_empty()
                || contextual_only.contains(&normalized)
                || !seen.insert(normalized.clone())
            {
                return None;
            }
            let compact: String = normalized
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect();
            Some(InvoiceContactPattern {
                contains_cjk: normalized
                    .chars()
                    .any(|ch| ('\u{4E00}'..='\u{9FFF}').contains(&ch)),
                normalized,
                compact,
            })
        })
        .collect();
    let matcher = Arc::new(InvoiceContactMatcher { patterns });
    if guard.len() >= 8 {
        guard.clear();
    }
    guard.push((direct, contextual, Arc::clone(&matcher)));
    matcher
}

#[derive(Debug, Clone, Deserialize)]
struct InvoiceContactIdWrapper {
    open: String,
    close: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct InvoiceContactIdPolicy {
    enabled: bool,
    marker_list: String,
    result_category: String,
    min_id_chars: usize,
    max_id_chars: usize,
    max_marker_gap_chars: usize,
    require_ascii_letter: bool,
    require_ascii_digit: bool,
    score: f64,
    wrappers: Vec<InvoiceContactIdWrapper>,
    #[serde(skip)]
    normalized_markers: Vec<String>,
    #[serde(skip)]
    normalized_wrappers: Vec<(String, String)>,
}

type InvoiceContactIdPolicyCacheEntry = (
    serde_json::Value,
    Vec<String>,
    Option<InvoiceContactIdPolicy>,
);

#[derive(Debug, Clone)]
struct InvoiceContactIdMatch {
    result_category: String,
    score: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ObfuscatedDomainLurePolicy {
    enabled: bool,
    lure_list: String,
    separator_list: String,
    tld_list: String,
    result_category: String,
    min_label_chars: usize,
    max_label_chars: usize,
    require_digit: bool,
    score: f64,
}

pub(super) fn parse_invoice_contact_id_policy(
    value: serde_json::Value,
) -> Option<InvoiceContactIdPolicy> {
    let policy = serde_json::from_value::<InvoiceContactIdPolicy>(value).ok()?;
    (policy.enabled
        && !policy.marker_list.trim().is_empty()
        && !policy.result_category.trim().is_empty()
        && policy.min_id_chars >= 4
        && policy.max_id_chars >= policy.min_id_chars
        && policy.max_id_chars <= 64
        && policy.max_marker_gap_chars <= 16
        && (0.40..=1.0).contains(&policy.score)
        && !policy.wrappers.is_empty()
        && policy
            .wrappers
            .iter()
            .all(|wrapper| !wrapper.open.is_empty() && !wrapper.close.is_empty()))
    .then_some(policy)
}

fn invoice_contact_id_policy() -> Option<InvoiceContactIdPolicy> {
    static CACHE: Mutex<Vec<InvoiceContactIdPolicyCacheEntry>> = Mutex::new(Vec::new());

    let data = module_data();
    let value = data
        .get_structured("invoice_spam_contact_id_policy_v1")?
        .clone();
    let marker_list = value
        .get("marker_list")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let markers = data.get_list(marker_list).to_vec();
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, _, policy)) = guard.iter().find(|(cached_value, cached_markers, _)| {
        cached_value == &value && cached_markers == &markers
    }) {
        return policy.clone();
    }

    let policy = parse_invoice_contact_id_policy(value.clone()).map(|mut policy| {
        policy.normalized_markers = markers
            .iter()
            .map(|marker| normalize_text(&marker.to_lowercase()))
            .filter(|marker| !marker.is_empty())
            .collect();
        policy.normalized_wrappers = policy
            .wrappers
            .iter()
            .map(|wrapper| {
                (
                    normalize_text(&wrapper.open.to_lowercase()),
                    normalize_text(&wrapper.close.to_lowercase()),
                )
            })
            .collect();
        policy
    });
    if guard.len() >= 8 {
        guard.clear();
    }
    guard.push((value, markers, policy.clone()));
    policy
}

pub(super) fn parse_obfuscated_domain_lure_policy(
    value: serde_json::Value,
) -> Option<ObfuscatedDomainLurePolicy> {
    let policy = serde_json::from_value::<ObfuscatedDomainLurePolicy>(value).ok()?;
    (policy.enabled
        && !policy.lure_list.trim().is_empty()
        && !policy.separator_list.trim().is_empty()
        && !policy.tld_list.trim().is_empty()
        && !policy.result_category.trim().is_empty()
        && policy.min_label_chars >= 3
        && policy.max_label_chars >= policy.min_label_chars
        && policy.max_label_chars <= 63
        && (0.40..=1.0).contains(&policy.score))
    .then_some(policy)
}

fn obfuscated_domain_lure_policy() -> Option<ObfuscatedDomainLurePolicy> {
    parse_obfuscated_domain_lure_policy(
        module_data()
            .get_structured("obfuscated_domain_lure_policy_v1")?
            .clone(),
    )
}

fn obfuscated_domain_marker(compact: &str, policy: &ObfuscatedDomainLurePolicy) -> Option<String> {
    let md = module_data();
    for separator in md.get_list(&policy.separator_list) {
        for (separator_start, _) in compact.match_indices(separator.as_str()) {
            let suffix = &compact[separator_start + separator.len()..];
            let Some(tld) = md.get_list(&policy.tld_list).iter().find(|tld| {
                suffix.starts_with(tld.as_str())
                    && !suffix[tld.len()..]
                        .chars()
                        .next()
                        .is_some_and(|ch| ch.is_ascii_alphanumeric())
            }) else {
                continue;
            };

            let prefix = &compact[..separator_start];
            let label: String = prefix
                .chars()
                .rev()
                .take_while(|ch| ch.is_ascii_alphanumeric())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let label_len = label.chars().count();
            if label_len < policy.min_label_chars || label_len > policy.max_label_chars {
                continue;
            }
            if policy.require_digit && !label.chars().any(|ch| ch.is_ascii_digit()) {
                continue;
            }
            return Some(format!("{label}{separator}{tld}"));
        }
    }
    None
}

fn is_structured_contact_id(candidate: &str, policy: &InvoiceContactIdPolicy) -> bool {
    let length = candidate.chars().count();
    length >= policy.min_id_chars
        && length <= policy.max_id_chars
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        && (!policy.require_ascii_letter || candidate.chars().any(|ch| ch.is_ascii_alphabetic()))
        && (!policy.require_ascii_digit || candidate.chars().any(|ch| ch.is_ascii_digit()))
}

fn bracketed_invoice_contact_id_match(window: &str) -> Option<InvoiceContactIdMatch> {
    let policy = invoice_contact_id_policy()?;
    let normalized = normalize_text(&decode_html_entities(&window.to_lowercase()));

    for marker in &policy.normalized_markers {
        if marker.is_empty() {
            continue;
        }
        for (marker_start, _) in normalized.match_indices(marker.as_str()) {
            let after_marker = &normalized[marker_start + marker.len()..];
            if after_marker
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric())
            {
                continue;
            }

            let prefix = &normalized[..marker_start];
            let prefix_trimmed = prefix.trim_end();
            let marker_gap = prefix[prefix_trimmed.len()..].chars().count();
            if marker_gap > policy.max_marker_gap_chars {
                continue;
            }

            for (open, close) in &policy.normalized_wrappers {
                let Some(before_close) = prefix_trimmed.strip_suffix(close.as_str()) else {
                    continue;
                };
                let before_close = before_close.trim_end();
                let Some(open_start) = before_close.rfind(open.as_str()) else {
                    continue;
                };
                let candidate = before_close[open_start + open.len()..].trim();
                if is_structured_contact_id(candidate, &policy) {
                    return Some(InvoiceContactIdMatch {
                        result_category: policy.result_category.clone(),
                        score: policy.score,
                    });
                }
            }
        }
    }
    None
}

fn invoice_detection_windows(subject: &str, body: &str) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    if !subject.trim().is_empty() {
        units.push(normalize_text(&subject.to_lowercase()));
    }
    units.extend(
        body.split(['\n', '\r', '。', '！', '？', '!', '?', '；', ';'])
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(|segment| normalize_text(&segment.to_lowercase())),
    );

    units
}

/// Keep an unnormalized view for the small set of contact markers whose
/// confusable characters must remain distinguishable from ordinary business
/// labels (for example `薇信` must not become the benign `微信` label).
fn invoice_detection_windows_raw(subject: &str, body: &str) -> Vec<String> {
    let mut units: Vec<String> = Vec::new();
    if !subject.trim().is_empty() {
        units.push(subject.trim().to_string());
    }
    units.extend(
        body.split(['\n', '\r', '。', '！', '？', '!', '?', '；', ';'])
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(str::to_string),
    );
    units
}

fn raw_obfuscated_invoice_contact_hits(window: &str) -> usize {
    module_data()
        .get_list("invoice_spam_obfuscated_contact_markers")
        .iter()
        .filter(|marker| !marker.is_empty() && window.contains(marker.as_str()))
        .count()
}

fn obfuscated_invoice_window_match(
    raw_window: &str,
    matcher: &InvoiceKeywordMatcher,
) -> Option<(usize, usize, usize, Option<InvoiceContactIdMatch>)> {
    // The obfuscated-invoice path cannot match without a raw confusable
    // contact marker. Check that necessary condition before normalizing and
    // running the invoice automaton; long routine mail often has thousands of
    // lines but no such marker.
    let obfuscated_contact_hits = raw_obfuscated_invoice_contact_hits(raw_window);
    if obfuscated_contact_hits == 0 {
        return None;
    }

    let normalized = normalize_text(&decode_html_entities(&raw_window.to_lowercase()));
    let compact = compact_detection_text(&normalized);
    let invoice_hits = count_non_nested_keyword_hits(&normalized, &compact, matcher);
    if invoice_hits == 0 {
        return None;
    }

    let phone_hits = RE_CHINESE_PHONE.captures_iter(&normalized).count();
    Some((
        invoice_hits,
        obfuscated_contact_hits,
        phone_hits,
        bracketed_invoice_contact_id_match(raw_window),
    ))
}

fn find_obfuscated_invoice_match(
    subject: &str,
    body: &str,
    matcher: &InvoiceKeywordMatcher,
) -> Option<(usize, usize, usize, Option<InvoiceContactIdMatch>)> {
    let windows = invoice_detection_windows_raw(subject, body);
    windows
        .iter()
        .find_map(|window| obfuscated_invoice_window_match(window, matcher))
        .or_else(|| {
            windows.windows(2).find_map(|pair| {
                let window = format!("{} {}", pair[0], pair[1]);
                obfuscated_invoice_window_match(&window, matcher)
            })
        })
}

fn invoice_window_match(
    window: &str,
    matcher: &InvoiceKeywordMatcher,
) -> Option<(usize, usize, usize, Option<InvoiceContactIdMatch>)> {
    let compact = compact_detection_text(window);
    let invoice_hits = count_non_nested_keyword_hits(window, &compact, matcher);
    let direct_contact_hits = explicit_invoice_contact_hits(window, &compact);
    let contact_id_match = bracketed_invoice_contact_id_match(window);
    (invoice_hits >= 1 && (direct_contact_hits >= 1 || contact_id_match.is_some())).then(|| {
        let phone_hits = RE_CHINESE_PHONE.captures_iter(window).count();
        (
            invoice_hits,
            direct_contact_hits,
            phone_hits,
            contact_id_match,
        )
    })
}

fn contextual_invoice_window_match(
    window: &str,
    matcher: &InvoiceKeywordMatcher,
) -> Option<(usize, usize, String, usize)> {
    let compact = compact_detection_text(window);
    let invoice_hits = count_non_nested_keyword_hits(window, &compact, matcher);
    let data = module_data();
    let solicitation_hits = count_config_terms(
        window,
        &compact,
        data.get_list("invoice_spam_contextual_solicitation_markers"),
    );
    let contextual_contact = first_config_term_hit(
        window,
        &compact,
        data.get_list("invoice_spam_context_only_contact_markers"),
    )?;
    let phone_hits = RE_CHINESE_PHONE.captures_iter(window).count();

    (invoice_hits >= 1 && solicitation_hits >= 2 && phone_hits >= 1).then_some((
        invoice_hits,
        solicitation_hits,
        contextual_contact,
        phone_hits,
    ))
}

fn find_contextual_invoice_match(
    subject: &str,
    body: &str,
    matcher: &InvoiceKeywordMatcher,
) -> Option<(usize, usize, String, usize)> {
    // A local window must contain an invoice cue, at least two solicitation
    // cues, a contextual contact label, and a phone number. Confirm those
    // necessary facts once across the full text before enumerating overlapping
    // 3–6 unit windows; this keeps long routine mail from paying for every
    // possible combination. The global check only gates work—the final match
    // still applies the original conjunction to one local window.
    let global_text = format!("{subject}\n{body}");
    let normalized = normalize_text(&global_text.to_lowercase());
    let compact = compact_detection_view(&normalized);
    let data = module_data();
    if count_non_nested_keyword_hits(&normalized, &compact, matcher) == 0
        || count_config_terms(
            &normalized,
            &compact,
            data.get_list("invoice_spam_contextual_solicitation_markers"),
        ) < 2
        || first_config_term_hit(
            &normalized,
            &compact,
            data.get_list("invoice_spam_context_only_contact_markers"),
        )
        .is_none()
        || !RE_CHINESE_PHONE.is_match(&normalized)
    {
        return None;
    }

    let windows = invoice_detection_windows(subject, body);
    (3..=windows.len().min(6)).find_map(|span| {
        windows
            .windows(span)
            .find_map(|units| contextual_invoice_window_match(&units.join(" "), matcher))
    })
}

fn raw_visible_body(ctx: &SecurityContext) -> Option<Cow<'_, str>> {
    ctx.session
        .content
        .body_text
        .as_deref()
        .map(Cow::Borrowed)
        .or_else(|| {
            ctx.session
                .content
                .body_html
                .as_deref()
                .map(strip_html_tags)
                .map(Cow::Owned)
        })
}

/// Detects Chinese invoice-spam / fake invoice solicitation patterns such as
/// "invoice solicitation + off-platform contact details". This targets off-platform contact lures rather
/// than legitimate invoice delivery notices.
pub(super) fn detect_invoice_spam(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
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

    let raw_subject = ctx.session.subject.as_deref().unwrap_or("");
    let subject =
        normalized_subject_for_scan(raw_subject, gateway_banner_patterns, notice_banner_patterns);
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let data = module_data();
    let invoice_keywords = data.get_list("invoice_spam_keywords");
    let invoice_matcher = invoice_keyword_matcher(invoice_keywords);
    let invoice_windows = invoice_detection_windows(&subject, &body);
    // Preserve the historical ordering: inspect every individual unit first,
    // then inspect adjacent units. Only allocate a joined pair while it is
    // actually being checked; the old implementation materialized all pairs
    // up front even for a body with no invoice/contact signal.
    let raw_body = raw_visible_body(ctx).unwrap_or_else(|| Cow::Borrowed(body.as_ref()));
    let local_match = invoice_windows
        .iter()
        .find_map(|window| invoice_window_match(window, &invoice_matcher))
        .or_else(|| {
            invoice_windows.windows(2).find_map(|pair| {
                let window = format!("{} {}", pair[0], pair[1]);
                invoice_window_match(&window, &invoice_matcher)
            })
        })
        .or_else(|| {
            find_obfuscated_invoice_match(raw_subject, raw_body.as_ref(), &invoice_matcher)
        });

    // A legitimate invoice notice commonly contains help-desk phone numbers,
    // contact labels and staff titles. Require an explicit off-platform CTA
    // (QQ/WeChat/Telegram/etc.); generic contact vocabulary plus a phone is
    // contextual business metadata, not an invoice-spam scenario.
    if let Some((invoice_hits, direct_contact_hits, phone_hits, contact_id_match)) = local_match {
        let structured_contact_id = contact_id_match.is_some();
        let combined_normalized = normalize_text(&format!("{subject}\n\n{body}").to_lowercase());
        let obfuscated_invoice_term = data
            .get_list("invoice_spam_obfuscated_invoice_markers")
            .iter()
            .any(|marker| combined_normalized.contains(marker));
        let specific_invoice_type = data
            .get_list("invoice_spam_fraud_invoice_type_markers")
            .iter()
            .any(|marker| combined_normalized.contains(marker));
        // A dialable mobile number makes an explicit off-platform contact
        // marker materially different from an ordinary invoice/help-desk
        // signature. Keep the named fraud compound bounded by all three
        // facts: invoice solicitation, direct contact CTA, and phone plus a
        // specific invoice type. The legacy obfuscated-invoice path remains
        // valid without a phone when it has a structured contact ID.
        let invoice_fraud_compound = structured_contact_id
            || (direct_contact_hits > 0
                && (obfuscated_invoice_term || (phone_hits >= 1 && specific_invoice_type)));
        let result_category = if invoice_fraud_compound {
            "invoice_fraud"
        } else {
            contact_id_match
                .as_ref()
                .map_or("invoice_spam", |matched| matched.result_category.as_str())
        };
        *total_score += if phone_hits >= 1 {
            0.62
        } else {
            contact_id_match
                .as_ref()
                .map_or(0.52, |matched| matched.score)
        };
        if invoice_fraud_compound {
            // Keep the legacy detector observation for audit/replay, while
            // adding the actionable fraud category used by fusion.
            categories.push("invoice_spam".to_string());
            categories.push("invoice_fraud".to_string());
        } else {
            categories.push(result_category.to_string());
        }
        evidence.push(Evidence {
            description: format!(
                "Detected invoice solicitation: {} invoice cues + {} explicit contact cues + structured contact ID={} + {} phone cue(s)",
                invoice_hits,
                direct_contact_hits,
                structured_contact_id,
                phone_hits
            ),
            location: Some("subject + body".to_string()),
            snippet: if raw_subject.is_empty() {
                Some(body.chars().take(120).collect())
            } else {
                Some(raw_subject.to_string())
            },
        });
        return;
    }

    // A bare `微信:` label is common in legitimate signatures and is not a CTA.
    // It becomes actionable only inside this named bounded compound:
    // invoice vocabulary + at least two solicitation/payment cues + a
    // contextual off-platform label + a dialable mobile number. The wider
    // window recovers intentionally fragmented lures without weakening the
    // established direct-contact path above.
    //
    // Banner cleanup is a useful primary view, but it is not authoritative for
    // this high-confidence conjunction. If cleanup removes or rewrites the
    // relevant units, inspect the original visible body as a bounded fallback.
    // The fallback keeps the exact same multi-signal gate and therefore does
    // not turn ordinary invoice notices or business signatures into findings.
    let contextual_match = find_contextual_invoice_match(&subject, &body, &invoice_matcher)
        .or_else(|| {
            raw_visible_body(ctx)
                .filter(|raw| raw.trim() != body.trim())
                .and_then(|raw| find_contextual_invoice_match(&subject, &raw, &invoice_matcher))
        });
    if let Some((invoice_hits, solicitation_hits, contact_marker, phone_hits)) = contextual_match {
        *total_score += 0.62;
        categories.push("invoice_spam".to_string());
        let combined_normalized = normalize_text(&format!("{subject}\n\n{body}").to_lowercase());
        if module_data()
            .get_list("invoice_spam_obfuscated_invoice_markers")
            .iter()
            .any(|marker| combined_normalized.contains(marker))
        {
            categories.push("invoice_fraud".to_string());
        }
        evidence.push(Evidence {
            description: format!(
                "Detected fragmented invoice solicitation: {} invoice cues + {} solicitation/payment cues + contextual contact '{}' + {} phone cue(s)",
                invoice_hits, solicitation_hits, contact_marker, phone_hits
            ),
            location: Some("subject + adjacent body units".to_string()),
            snippet: if raw_subject.is_empty() {
                Some(body.chars().take(120).collect())
            } else {
                Some(raw_subject.to_string())
            },
        });
    }
}

/// Detect an off-platform destination deliberately written with a Chinese
/// dot word inside an adult-content lure. Neither adult/video vocabulary nor
/// a dot-word identifier is actionable alone; their same-body conjunction is
/// a named bypass pattern intended to evade normal URL extraction.
pub(super) fn detect_obfuscated_domain_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(policy) = obfuscated_domain_lure_policy() else {
        return;
    };
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let normalized = normalize_text(&decode_html_entities(&body.to_lowercase()));
    let compact = compact_detection_view(&normalized);
    let lure_phrase = module_data()
        .get_list(&policy.lure_list)
        .iter()
        .find(|phrase| compact.contains(&compact_detection_text(phrase)))
        .cloned();
    let Some(lure_phrase) = lure_phrase else {
        return;
    };
    let Some(domain_marker) = obfuscated_domain_marker(&compact, &policy) else {
        return;
    };

    *total_score += policy.score;
    categories.push(policy.result_category.clone());
    evidence.push(Evidence {
        description: format!(
            "Detected adult-content lure '{}' combined with obfuscated destination '{}'",
            lure_phrase, domain_marker
        ),
        location: Some("body".to_string()),
        snippet: Some(body.chars().take(120).collect()),
    });
}

/// Surface adult-content phrases even when the message does not carry the
/// Chinese dot-word destination handled above.  A phrase alone is an analyst
/// observation; an external untrusted link or an explicit contact action is
/// the independent target needed for the additive low-weight lure signal.
pub(super) fn detect_adult_content_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if categories
        .iter()
        .any(|category| category == "obfuscated_domain_lure")
    {
        return;
    }

    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let normalized = normalize_text(&decode_html_entities(&actionable_context.to_lowercase()));
    let compact = compact_detection_view(&normalized);
    let data = module_data();
    let Some(adult_phrase) = first_config_term_hit(
        &normalized,
        &compact,
        data.get_list("adult_content_observation_phrases"),
    ) else {
        return;
    };
    if is_routine_password_awareness_notice(ctx) {
        return;
    }

    let sender_domain = external_sender_domain(ctx);
    let external_sender = is_external_sender_for_bec(ctx, sender_domain.as_deref());
    let has_untrusted_link = has_untrusted_clickable_link(ctx);
    let action_marker = first_config_term_hit(
        &normalized,
        &compact,
        data.get_list("adult_content_lure_action_markers"),
    );
    let contact_marker = explicit_invoice_contact_hits(&normalized, &compact) > 0;
    let has_phone = RE_CHINESE_PHONE.is_match(&normalized);
    let actionable = external_sender
        && (has_untrusted_link || (action_marker.is_some() && (contact_marker || has_phone)));

    if actionable {
        *total_score += 0.24;
        categories.push("adult_content_lure".to_string());
        evidence.push(Evidence {
            description: format!(
                "Adult-content phrase '{}' is paired with an external recipient-facing lure{}",
                adult_phrase,
                action_marker
                    .as_deref()
                    .map_or_else(|| "".to_string(), |marker| format!(" ({marker})"))
            ),
            location: Some("subject + body + links".to_string()),
            snippet: Some(combined.chars().take(160).collect()),
        });
    } else {
        categories.push("adult_content_observed".to_string());
        evidence.push(Evidence {
            description: format!(
                "Adult-content phrase '{}' observed without an independently actionable destination",
                adult_phrase
            ),
            location: Some("subject + body".to_string()),
            snippet: Some(combined.chars().take(160).collect()),
        });
    }
}

/// Keep generic urgency-plus-action language visible without treating common
/// calls to action as phishing on their own.  Strong detectors run before this
/// observation and suppress it when they already found an actionable category.
pub(super) fn detect_generic_lure_observation(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let normalized = normalize_text(&decode_html_entities(&actionable_context.to_lowercase()));
    let compact = compact_detection_view(&normalized);
    if normalized.trim().is_empty() {
        return;
    }

    let data = module_data();
    let Some(urgency_marker) = first_config_term_hit(
        &normalized,
        &compact,
        data.get_list("generic_lure_urgency_markers"),
    ) else {
        return;
    };
    let Some(action_marker) = first_config_term_hit(
        &normalized,
        &compact,
        data.get_list("generic_lure_action_markers"),
    ) else {
        return;
    };
    if is_routine_password_awareness_notice(ctx) {
        return;
    }

    let actionable_categories = [
        "account_security_phishing",
        "adult_content_lure",
        "bec",
        "bec_payment_change",
        "credential_link_lure",
        "external_impersonation",
        "invoice_spam",
        "invoice_fraud",
        "obfuscated_domain_lure",
        "phishing",
        "subsidy_fraud",
    ];
    if categories
        .iter()
        .any(|category| actionable_categories.contains(&category.as_str()))
    {
        return;
    }

    categories.push("generic_lure_observed".to_string());
    evidence.push(Evidence {
        description: format!(
            "Generic inducement language observed: urgency '{}' paired with action '{}' but no independent target",
            urgency_marker, action_marker
        ),
        location: Some("subject + body".to_string()),
        snippet: Some(actionable_context.chars().take(160).collect()),
    });
}

fn body_contains_bare_host(body: &str, host: &str) -> bool {
    let body_lower = body.to_lowercase();
    let host_lower = host.to_lowercase();
    body_lower.match_indices(&host_lower).any(|(start, _)| {
        let prefix = body_lower[..start].trim_end_matches(char::is_whitespace);
        !prefix.ends_with('@') && !prefix.ends_with("http://") && !prefix.ends_with("https://")
    })
}

fn reply_thread_headers_present(ctx: &SecurityContext) -> bool {
    ["in-reply-to", "references"].iter().all(|wanted| {
        ctx.session
            .content
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case(wanted) && !value.trim().is_empty())
    })
}

fn has_external_reply_to_domain_mismatch(ctx: &SecurityContext) -> bool {
    let from = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .map(|(_, value)| value.as_str());
    let reply_to = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("reply-to"))
        .map(|(_, value)| value.as_str());
    let (Some(from), Some(reply_to)) = (from, reply_to) else {
        return false;
    };
    let (Some(from_domain), Some(reply_to_domain)) = (
        extract_domain_from_email(from),
        extract_domain_from_email(reply_to),
    ) else {
        return false;
    };
    !domains_share_organizational_domain(&from_domain, &reply_to_domain)
        && !ctx.is_internal_domain(&reply_to_domain)
        && !module_data().contains("protected_domains", &reply_to_domain)
}

/// Legitimate customs-processing notices can contain financial authority,
/// payment, deadline, and logistics language that satisfies generic BEC
/// dimensions. Suppress only when every destination is a verified Single
/// Window host, the message has configured official-entry warnings and customs
/// context, and it does not redirect payment or provide a new account.
fn is_verified_routine_customs_notice(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.is_empty()
        || has_external_reply_to_domain_mismatch(ctx)
        || crate::modules::content_scan::has_explicit_payment_change_redirect(actionable_context)
        || RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(actionable_context)
        || RE_IBAN.is_match(actionable_context)
        || RE_GROUPED_BANK_ACCOUNT.is_match(actionable_context)
        || has_shortener_destination(ctx)
    {
        return false;
    }

    let md = module_data();
    let (raw_normalized, raw_compact) = normalized_and_compact(raw_combined);
    let (normalized, compact) = normalized_and_compact(actionable_context);
    count_config_terms(
        &raw_normalized,
        &raw_compact,
        md.get_list("external_action_link_routine_official_markers"),
    ) >= 3
        && count_config_terms(
            &normalized,
            &compact,
            md.get_list("routine_official_customs_context_terms"),
        ) >= 2
        && normalized.chars().count() >= 160
        && ctx.session.content.links.iter().all(|link| {
            if link.suspicious {
                return false;
            }
            let effective = effective_structural_url(&link.url);
            let Ok(parsed) = url::Url::parse(&effective) else {
                return false;
            };
            let Some(host) = parsed.host_str() else {
                return false;
            };
            parsed.scheme() == "https"
                && parsed.port().is_none()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && (host == "singlewindow.cn" || host.ends_with(".singlewindow.cn"))
                && crate::modules::link_scan::is_well_known_safe_domain(host)
        })
}

/// Detect a forged business reply that sends the recipient to an untrusted
/// cross-domain bare destination. Reply headers are attacker-controlled and
/// never score alone; admission requires all of: a reply subject, both thread
/// headers, sensitive business context, a local confirmation CTA, a hostname
/// action token, and sender/target domain separation.
pub(super) fn detect_reply_thread_destination_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || !reply_thread_headers_present(ctx)
    {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let subject_lower = normalize_text(&subject.to_lowercase());
    let data = module_data();
    let has_reply_prefix = data
        .get_list("thread_reply_prefixes")
        .iter()
        .any(|prefix| subject_lower.starts_with(&normalize_text(&prefix.to_lowercase())));
    if !has_reply_prefix {
        return;
    }

    // Bare-domain causality is defined against the retained plain text, not a
    // flattened HTML document whose href/action attributes could be mistaken
    // for user-visible prose.
    let Some(plain_body) = ctx.session.content.body_text.as_deref() else {
        return;
    };
    let body = body_for_cross.unwrap_or(plain_body);
    let combined = normalize_text(&format!("{subject}\n\n{body}").to_lowercase());
    let compact = compact_detection_view(&combined);
    let sensitive = first_config_term_hit(
        &combined,
        &compact,
        data.get_list("thread_reply_sensitive_terms"),
    );
    let action = first_config_term_hit(
        &combined,
        &compact,
        data.get_list("thread_reply_destination_actions"),
    );
    let (Some(sensitive), Some(action)) = (sensitive, action) else {
        return;
    };

    let sender_domain = sender_domain.as_deref().unwrap_or_default();
    let target = ctx
        .session
        .content
        .links
        .iter()
        .take(64)
        .filter_map(|link| url::Url::parse(&link.url).ok())
        .filter_map(|url| url.host_str().map(str::to_ascii_lowercase))
        .find(|host| {
            let sender_aligned =
                crate::modules::common::host_matches_domain_or_subdomain(host, sender_domain)
                    || crate::modules::common::host_matches_domain_or_subdomain(
                        sender_domain,
                        host,
                    );
            let untrusted = !crate::modules::link_scan::is_trusted_url_domain(host)
                && !crate::modules::link_scan::is_well_known_safe_domain(host);
            let risky_host_token = host
                .split(['.', '-'])
                .any(|token| data.contains("thread_reply_risky_host_tokens", token));
            !sender_aligned
                && untrusted
                && risky_host_token
                && body_contains_bare_host(plain_body, host)
        });
    let Some(target) = target else {
        return;
    };

    // The full conjunction is a high-confidence causal shape, not a loose
    // reply-thread heuristic. Its local strength must survive the BEC-family
    // DS discount without changing global thresholds.
    *total_score += 0.75;
    categories.push("bec".to_string());
    evidence.push(Evidence {
        description: format!(
            "External reply-thread lure combines business context '{sensitive}', confirmation action '{action}', and bare cross-domain destination {target}"
        ),
        location: Some("subject + thread headers + body bare domain".to_string()),
        snippet: Some(format!("{subject} | {target}")),
    });
}

/// Detect consequential requests routed through a Reply-To address that is
/// outside the visible sender's organization. The header mismatch is only a
/// routing observation; promotion also requires a recipient-directed handoff
/// plus sensitive-data/payment evidence and, for ordinary external senders,
/// independent pressure, secrecy, or authority language.
pub(super) fn detect_reply_to_social_engineering_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    detect_reply_to_social_engineering_lure_with_stage_b(
        ctx,
        body_for_cross,
        total_score,
        categories,
        evidence,
        reply_to_handoff_stage_b_enabled(),
    );
}

pub(super) fn detect_reply_to_social_engineering_lure_with_stage_b(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
    stage_b_enabled: bool,
) {
    let md = module_data();
    if !md.contains("content_detection_flags", "reply_to_social_engineering_v1")
        || categories
            .iter()
            .any(|category| category == "external_reply_to_social_engineering")
    {
        return;
    }

    let from_header = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .map(|(_, value)| value.as_str());
    let reply_to_header = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("reply-to"))
        .map(|(_, value)| value.as_str());
    let (Some(from_header), Some(reply_to_header)) = (from_header, reply_to_header) else {
        return;
    };
    let (Some(from_domain), Some(reply_to_domain)) = (
        extract_domain_from_email(from_header),
        extract_domain_from_email(reply_to_header),
    ) else {
        return;
    };
    if domains_share_organizational_domain(&from_domain, &reply_to_domain)
        || ctx.is_internal_domain(&reply_to_domain)
        || md.contains("protected_domains", &reply_to_domain)
    {
        return;
    }

    let envelope_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(extract_domain_from_email);
    if envelope_domain
        .as_deref()
        .is_some_and(|domain| domains_share_organizational_domain(domain, &reply_to_domain))
    {
        return;
    }
    let claims_internal_sender = ctx.is_internal_domain(&from_domain)
        || md.contains("protected_domains", &from_domain)
        || from_domain.ends_with(".internal")
        || from_domain.ends_with(".local");
    let sender_domain = external_sender_domain(ctx);
    if !claims_internal_sender && !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    if normalized.trim().is_empty() {
        return;
    }

    let sensitive_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("external_sensitive_exfiltration_terms"),
    ) + count_config_terms(
        &normalized,
        &compact,
        md.get_list("pii_external_collection_terms"),
    ) + count_config_terms(
        &normalized,
        &compact,
        md.get_list("pii_external_collection_terms_extra"),
    );
    let high_risk_field_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("pii_external_high_risk_field_terms"),
    ) + count_config_terms(
        &normalized,
        &compact,
        md.get_list("external_action_link_high_risk_terms"),
    );
    let payment_action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_payment_action_terms"),
    );
    let direct_payment_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_direct_payment_terms"),
    );
    let has_grouped_bank_account = RE_GROUPED_BANK_ACCOUNT.is_match(&actionable_context);
    let payment_destination = RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(&actionable_context)
        || has_iban_payment_destination(&actionable_context)
        || has_grouped_bank_account
        || direct_payment_hits > 0;
    let explicit_direct_payment_request = payment_action_hits > 0 && payment_destination;
    let pressure_hits =
        count_config_terms(
            &normalized,
            &compact,
            md.get_list("transaction_urgency_keywords"),
        ) + count_config_terms(
            &normalized,
            &compact,
            md.get_list("bec_confidentiality_terms"),
        ) + count_config_terms(&normalized, &compact, md.get_list("bec_authority_terms"))
            + count_config_terms(
                &normalized,
                &compact,
                md.get_list("reply_to_high_consequence_pressure_terms"),
            );
    let handoff_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("reply_to_handoff_action_terms"),
    );
    let has_stage_b_local_handoff_request =
        stage_b_enabled && has_local_reply_handoff_sensitive_request(&actionable_context);
    let action_hits =
        count_config_terms(&normalized, &compact, md.get_list("bec_local_action_terms"))
            + count_config_terms(
                &normalized,
                &compact,
                md.get_list("external_sensitive_exfiltration_action_terms"),
            );
    // The Reply-To mismatch was already required above. It is itself the
    // destination for reply-based collection, so a body URL is not required
    // for the recipient-facing action to be consequential.
    let has_untrusted_destination = has_untrusted_body_destination(ctx, &actionable_context)
        || (!domains_share_organizational_domain(&from_domain, &reply_to_domain)
            && !ctx.is_internal_domain(&reply_to_domain)
            && !md.contains("protected_domains", &reply_to_domain));
    let has_recipient_action = has_recipient_directed_action(&actionable_context)
        || has_stage_b_local_handoff_request
        || explicit_direct_payment_request;
    let has_consequential_request = has_recipient_action
        && (handoff_hits > 0
            || explicit_direct_payment_request
            || (sensitive_hits > 0 && action_hits > 0 && has_untrusted_destination));
    let has_sensitive_or_payment =
        sensitive_hits > 0 || high_risk_field_hits > 0 || explicit_direct_payment_request;
    let high_confidence_internal_handoff =
        claims_internal_sender && has_consequential_request && has_sensitive_or_payment;
    let high_confidence_external_lure =
        !claims_internal_sender && has_consequential_request && has_sensitive_or_payment;
    if !(high_confidence_internal_handoff || high_confidence_external_lure) {
        return;
    }

    *total_score += 0.72;
    categories.push("external_reply_to_social_engineering".to_string());
    categories.push("phishing".to_string());
    if payment_action_hits > 0 {
        categories.push("bec".to_string());
    }
    evidence.push(Evidence {
        description: format!(
            "Recipient-directed sensitive or payment request is routed to a Reply-To domain ({reply_to_domain}) unrelated to the visible sender ({from_domain}); pressure/secrecy/authority cues={pressure_hits}"
        ),
        location: Some("headers:From,Reply-To + actionable body".to_string()),
        snippet: Some(actionable_context.chars().take(180).collect()),
    });
}

fn has_hidden_payment_instruction_with_visible_destination(
    ctx: &SecurityContext,
    visible_body: &str,
) -> bool {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return false;
    };
    let hidden_text = hidden_text_region_facts(html).join("\n\n");
    let hidden_actionable = strip_counter_context_segments(&hidden_text);
    let (hidden_normalized, hidden_compact) = normalized_and_compact(&hidden_actionable);
    if hidden_normalized.trim().is_empty() {
        return false;
    }
    let md = module_data();
    let hidden_account_change_hits = count_config_terms(
        &hidden_normalized,
        &hidden_compact,
        md.get_list("payment_change_keywords"),
    );
    let hidden_payment_action_hits = count_config_terms(
        &hidden_normalized,
        &hidden_compact,
        md.get_list("bec_payment_action_terms"),
    );
    let hidden_urgency_hits = count_config_terms(
        &hidden_normalized,
        &hidden_compact,
        md.get_list("transaction_urgency_keywords"),
    );
    let visible_text = format!(
        "{}\n{}",
        ctx.session.subject.as_deref().unwrap_or_default(),
        visible_body
    );
    let (visible_normalized, visible_compact) = normalized_and_compact(&visible_text);
    let visible_invoice_or_payment = count_config_terms(
        &visible_normalized,
        &visible_compact,
        md.get_list("invoice_spam_keywords"),
    ) > 0
        || count_config_terms(
            &visible_normalized,
            &visible_compact,
            md.get_list("bec_payment_action_terms"),
        ) > 0;
    let visible_has_destination = RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(&visible_text)
        || has_iban_payment_destination(&visible_text)
        || RE_GROUPED_BANK_ACCOUNT.is_match(&visible_text);

    hidden_account_change_hits > 0
        && hidden_payment_action_hits > 0
        && hidden_urgency_hits > 0
        && visible_invoice_or_payment
        && visible_has_destination
}

/// Detect high-confidence external BEC/social-engineering compounds that do
/// not need a URL or attachment. The generic `bec` keyword category is not
/// sufficient by itself: promotion requires three independent configured
/// dimensions, or a forged reply thread that explicitly bypasses the normal
/// payment process. Internal senders are excluded from this named compound so
/// routine internal minutes cannot activate a verdict floor.
fn is_routine_in_app_api_migration_notice(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.iter().any(|link| link.suspicious)
    {
        return false;
    }
    let sender_domain = external_sender_domain(ctx);
    if has_cross_domain_untrusted_body_destination(
        ctx,
        actionable_context,
        sender_domain.as_deref(),
    ) || has_explicit_account_destination(actionable_context)
    {
        return false;
    }

    let (raw_normalized, raw_compact) = normalized_and_compact(raw_combined);
    let (normalized, _) = normalized_and_compact(actionable_context);
    count_config_terms(
        &raw_normalized,
        &raw_compact,
        module_data().get_list("routine_api_migration_notice_markers"),
    ) >= 2
        && count_config_terms(
            &raw_normalized,
            &raw_compact,
            module_data().get_list("external_action_link_anti_phishing_markers"),
        ) > 0
        && !has_direct_high_risk_action(&normalized)
        && !has_iban_payment_destination(actionable_context)
        && !RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(actionable_context)
}

/// A narrow exception for IdP signing-certificate lifecycle notices that
/// direct administrators to fetch metadata from their own tenant endpoint.
/// The full safe-rotation guidance, first-party tenant destination, and no
/// attachment requirement must all be present; a bare SAML/certificate
/// mention never suppresses a linked action lure.
fn is_routine_saml_signing_cert_notice(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.is_empty()
        || ctx.session.content.links.iter().any(|link| link.suspicious)
    {
        return false;
    }
    let sender_domain = external_sender_domain(ctx);
    let Some(sender_domain) = sender_domain.as_deref() else {
        return false;
    };
    let whitespace_free = raw_combined
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let destinations = RE_HTML_ALT_URL
        .find_iter(&whitespace_free)
        .filter_map(|matched| {
            url::Url::parse(&matched.as_str().replace('：', ":"))
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        })
        .collect::<Vec<_>>();
    let has_tenant_destination = destinations
        .iter()
        .any(|domain| domains_share_organizational_domain(domain, sender_domain));
    let destinations_are_first_party = destinations.iter().all(|domain| {
        domains_share_organizational_domain(domain, sender_domain)
            || crate::modules::link_scan::is_trusted_url_domain(domain)
            || crate::modules::link_scan::is_well_known_safe_domain(domain)
    });
    if !has_tenant_destination || !destinations_are_first_party {
        return false;
    }

    let (normalized, compact) = normalized_and_compact(raw_combined);
    count_config_terms(
        &normalized,
        &compact,
        module_data().get_list("routine_saml_signing_cert_notice_markers"),
    ) >= 4
        && count_config_terms(
            &normalized,
            &compact,
            module_data().get_list("external_action_link_anti_phishing_markers"),
        ) >= 2
        && !has_explicit_account_destination(actionable_context)
}

/// Association annual-review advisories can quote a fabricated service fee
/// and removal deadline while separately describing the next year's ordinary
/// dues. Suppress only the no-link BEC compound when multiple schedule and
/// correction facts are present and no concrete current payment destination
/// is supplied.
fn is_routine_association_annual_review_notice(
    ctx: &SecurityContext,
    raw_combined: &str,
    actionable_context: &str,
) -> bool {
    if !ctx.session.content.attachments.is_empty()
        || ctx.session.content.links.iter().any(|link| {
            effective_structural_url(&link.url)
                .parse::<url::Url>()
                .is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"))
        })
        || has_explicit_account_destination(actionable_context)
        || has_iban_payment_destination(actionable_context)
        || RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(actionable_context)
    {
        return false;
    }

    let (normalized, compact) = normalized_and_compact(raw_combined);
    count_config_terms(
        &normalized,
        &compact,
        module_data().get_list("routine_association_annual_review_markers"),
    ) >= 4
        && count_config_terms(
            &normalized,
            &compact,
            module_data().get_list("external_action_link_anti_phishing_markers"),
        ) >= 1
}

pub(super) fn detect_external_bec_compound(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || categories
            .iter()
            .any(|category| category == "bec_external_compound")
    {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&combined);
    if is_routine_in_app_api_migration_notice(ctx, &combined, &actionable_context) {
        return;
    }
    let routine_association_notice =
        is_routine_association_annual_review_notice(ctx, &combined, &actionable_context);
    if is_verified_routine_customs_notice(ctx, &combined, &actionable_context) {
        return;
    }
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    if normalized.trim().is_empty() {
        return;
    }

    let md = module_data();
    let stage_b_enabled = email_semantic_stage_b_enabled();
    let authority_hits =
        count_config_terms(&normalized, &compact, md.get_list("bec_authority_terms"));
    let payment_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_payment_action_terms"),
    );
    let confidentiality_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_confidentiality_terms"),
    );
    let urgency_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("transaction_urgency_keywords"),
    );
    let financial_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("payment_change_financial_context_terms"),
    );
    let local_action_hits =
        count_config_terms(&normalized, &compact, md.get_list("bec_local_action_terms"));
    let localpart = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(|address| address.split('@').next())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let local_authority_hit = !localpart.is_empty()
        && md
            .get_list("bec_authority_localpart_terms")
            .iter()
            .any(|term| localpart.split(['.', '-', '_']).any(|part| part == term));
    let has_reply_headers = reply_thread_headers_present(ctx);
    let business_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_business_context_terms"),
    );
    let high_risk_request_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_high_risk_request_terms"),
    );
    let direct_payment_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_direct_payment_terms"),
    );
    let direct_payment_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_direct_payment_context_terms"),
    );
    let direct_payment_action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_direct_payment_action_terms"),
    );
    let external_service_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_external_service_context_terms"),
    );
    let external_service_sensitive_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_external_service_sensitive_terms"),
    );
    let external_service_contact_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_external_service_contact_terms"),
    );
    let reconciliation_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_reconciliation_context_terms"),
    );
    let reconciliation_action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_reconciliation_action_terms"),
    );
    let settlement_account_change_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_settlement_account_change_terms"),
    );
    let crypto_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("crypto_payment_context_terms"),
    );
    let crypto_action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("crypto_payment_action_terms"),
    );
    let has_http_destination = ctx.session.content.links.iter().any(|link| {
        effective_structural_url(&link.url)
            .parse::<url::Url>()
            .is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"))
    });
    // Mail addresses are contact evidence, not web IOCs. Do not let an
    // auto-linked Reply-To or contact address disable the no-IOC BEC path.
    let no_ioc = !has_http_destination && ctx.session.content.attachments.is_empty();
    let no_ioc_solicitation_context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_context_terms"),
    );
    let no_ioc_solicitation_value_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_value_terms"),
    );
    let no_ioc_solicitation_action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_action_terms"),
    );
    let no_ioc_solicitation_pressure_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_pressure_terms"),
    );
    let no_ioc_solicitation_contact_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_contact_terms"),
    );
    let no_ioc_solicitation_secrecy_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_no_ioc_solicitation_secrecy_terms"),
    );
    let has_local_no_ioc_demand = has_local_no_ioc_solicitation_demand(&actionable_context);
    let has_scoped_no_ioc_solicitation =
        has_local_no_ioc_solicitation_compound(&actionable_context);
    let has_cross_domain_destination = has_cross_domain_untrusted_body_destination(
        ctx,
        &actionable_context,
        sender_domain.as_deref(),
    );
    let has_untrusted_payment_link = has_untrusted_body_destination(ctx, &actionable_context)
        && direct_payment_hits > 0
        && direct_payment_action_hits > 0;
    let has_payment_destination = RE_CARD_LIKE_PAYMENT_DESTINATION.is_match(&actionable_context)
        || (has_iban_payment_destination(&actionable_context) && direct_payment_action_hits > 0)
        || (RE_CRYPTO_WALLET_DESTINATION.is_match(&actionable_context) && crypto_action_hits > 0)
        || has_explicit_account_destination(&actionable_context)
        || has_untrusted_payment_link;
    // A direct-payment lure is a separate BEC path for external senders that
    // publish a concrete payment destination.  It requires independent
    // payment, business-context, and recipient-action evidence; a bare amount
    // or ordinary invoice language cannot activate it.
    let direct_payment_bec = has_payment_destination
        && direct_payment_hits > 0
        && direct_payment_context_hits > 0
        && direct_payment_action_hits > 0;
    let forged_reply_process_bypass = has_reply_headers
        && has_external_reply_to_domain_mismatch(ctx)
        && local_action_hits > 0
        && payment_hits > 0
        && has_cross_domain_destination;
    // A mismatched Reply-To is a strong route-change indicator even when the
    // first message contains no clickable destination. Combine it with a
    // concrete payment request or a confidential, urgent finance instruction
    // so ordinary alternate contact addresses remain below the BEC threshold.
    let reply_to_domain_mismatch = has_external_reply_to_domain_mismatch(ctx);
    let has_reply_routed_payment_request = payment_hits > 0
        && financial_hits > 0
        && has_payment_destination
        && has_recipient_directed_action(&actionable_context)
        && (urgency_hits > 0
            || direct_payment_action_hits > 0
            || settlement_account_change_hits > 0
            || high_risk_request_hits > 0);
    let reply_to_financial_process_bec = reply_to_domain_mismatch
        && ((payment_hits > 0
            && local_action_hits > 0
            && (high_risk_request_hits > 0 || has_payment_destination)
            && (urgency_hits > 0 || financial_hits > 0 || confidentiality_hits > 0))
            || (confidentiality_hits > 0
                && financial_hits > 0
                && urgency_hits > 0
                && authority_hits > 0
                && has_recipient_directed_action(&actionable_context))
            || has_reply_routed_payment_request);
    let named_payment_process_bec = has_payment_destination
        && high_risk_request_hits > 0
        && payment_hits > 0
        && (authority_hits > 0 || local_authority_hit)
        && local_action_hits >= 2
        && (confidentiality_hits > 0 || urgency_hits > 0 || financial_hits > 0);
    let high_confidence_payment_process_bec = payment_hits > 0
        && has_payment_destination
        && direct_payment_action_hits > 0
        && local_action_hits >= 2
        && high_risk_request_hits > 0
        && (urgency_hits > 0 || financial_hits > 0 || business_context_hits > 0);
    let linked_business_bec = has_cross_domain_destination
        && business_context_hits > 0
        && high_risk_request_hits > 0
        && local_action_hits > 0
        && (payment_hits > 0 || authority_hits > 0);
    let no_ioc_authority_social = local_authority_hit
        && confidentiality_hits > 0
        && local_action_hits > 0
        && (high_risk_request_hits > 0
            || (has_payment_destination && direct_payment_action_hits > 0));
    let external_service_request_bec = external_service_context_hits >= 2
        && external_service_sensitive_hits > 0
        && external_service_contact_hits > 0;
    let reconciliation_bec = reconciliation_context_hits >= 2
        && reconciliation_action_hits >= 2
        && payment_hits > 0
        && (has_payment_destination || high_risk_request_hits > 0);
    let settlement_account_change_bec = settlement_account_change_hits > 0 && payment_hits > 0;
    let crypto_payment_bec =
        crypto_context_hits >= 2 && crypto_action_hits > 0 && has_payment_destination;
    // A bank destination is often deliberately omitted from the first email
    // or sent in a separate thread. Keep that BEC path when the message still
    // states the account change or process bypass, payment context, and a
    // concrete recipient action under urgency or financial pressure.
    let no_destination_payment_process_bec = no_ioc
        && has_local_no_ioc_demand
        && payment_hits > 0
        && high_risk_request_hits > 0
        && local_action_hits >= 2
        && (urgency_hits > 0 || financial_hits > 0 || confidentiality_hits > 0);
    // Classic executive wire fraud often withholds account coordinates until
    // a follow-up message. The envelope authority, financial wording, urgency,
    // secrecy, and recipient-facing confirmation together are sufficient.
    let executive_wire_no_ioc_bec = no_ioc
        && local_authority_hit
        && authority_hits > 0
        && payment_hits > 0
        && urgency_hits > 0
        && financial_hits > 0
        && confidentiality_hits > 0
        && has_recipient_directed_action(&actionable_context);
    let hidden_payment_instruction_bec = has_hidden_payment_instruction_with_visible_destination(
        ctx,
        body_for_cross.unwrap_or_default(),
    );
    // Independent no-IOC social-engineering path: an external sender must
    // combine a consequential business/authority context, a non-routine fee
    // or illicit-value cue, an explicit recipient action, and either pressure
    // or secrecy plus a reply/account handoff.  This is deliberately not a
    // generic keyword score, so ordinary fee notices without coercion remain
    // below the admission bar.
    let no_ioc_solicitation_bec = no_ioc
        && !routine_association_notice
        && no_ioc_solicitation_context_hits > 0
        && no_ioc_solicitation_value_hits > 0
        && has_local_no_ioc_demand
        && has_scoped_no_ioc_solicitation
        && has_recipient_directed_action(&actionable_context)
        && (no_ioc_solicitation_pressure_hits > 0 || no_ioc_solicitation_secrecy_hits > 0);
    // Stage B recovers high-confidence no-link payment/social-engineering
    // solicitations whose domain-specific vocabulary is not in the general
    // BEC bank. Keep it shadowable and require a mismatched reply route plus
    // four co-scoped facts: process context, non-routine value, explicit
    // handoff action, and irreversible/deadline pressure.
    let stage_b_no_ioc_solicitation_bec = stage_b_enabled
        && no_ioc
        && !routine_association_notice
        && has_external_reply_to_domain_mismatch(ctx)
        // The additive no-IOC path is intended for ordinary-length prose.
        // Keep window enumeration out of multi-megabyte bodies, where the
        // content pipeline already has its own bounded sampling behavior.
        && actionable_context.len() <= 32 * 1024
        && bounded_actionable_windows(&actionable_context, 20, 1400)
            .iter()
            .any(|window| {
                let (window_normalized, window_compact) = normalized_and_compact(window);
                [
                    "bec_no_ioc_stage_b_context_terms",
                    "bec_no_ioc_stage_b_value_terms",
                    "bec_no_ioc_stage_b_action_terms",
                    "bec_no_ioc_stage_b_pressure_terms",
                ]
                .iter()
                .all(|list_name| {
                    count_config_terms(&window_normalized, &window_compact, md.get_list(list_name))
                        > 0
                })
            });
    // A no-link message that gives a concrete bank field and asks the
    // recipient to act is actionable even when it is a short margin-call or
    // fee lure rather than long-form BEC prose.
    let no_ioc_direct_payment_bec = no_ioc
        && !routine_association_notice
        && has_payment_destination
        && payment_hits > 0
        && has_recipient_directed_action(&actionable_context)
        && (urgency_hits > 0 || high_risk_request_hits > 0 || direct_payment_action_hits > 0);
    let illicit_invoice_offer_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("bec_illicit_invoice_offer_terms"),
    );
    // Cash-only invoice-broker solicitations may give an off-platform
    // contact route before a payment account. Several fabrication cues plus
    // a WeChat follow-up are required; “invoice” or “WeChat” alone is benign.
    let no_ioc_illicit_invoice_solicitation_bec = no_ioc
        && illicit_invoice_offer_hits >= 3
        && actionable_context.contains("微信")
        && actionable_context.contains("合作");

    if !(forged_reply_process_bypass
        || reply_to_financial_process_bec
        || named_payment_process_bec
        || high_confidence_payment_process_bec
        || linked_business_bec
        || external_service_request_bec
        || reconciliation_bec
        || settlement_account_change_bec
        || crypto_payment_bec
        || no_ioc_solicitation_bec
        || stage_b_no_ioc_solicitation_bec
        || no_ioc_direct_payment_bec
        || no_ioc_illicit_invoice_solicitation_bec
        || direct_payment_bec
        || no_ioc_authority_social
        || no_destination_payment_process_bec
        || executive_wire_no_ioc_bec
        || hidden_payment_instruction_bec)
    {
        return;
    }

    *total_score += if forged_reply_process_bypass
        || reply_to_financial_process_bec
        || named_payment_process_bec
        || high_confidence_payment_process_bec
        || linked_business_bec
        || external_service_request_bec
        || reconciliation_bec
        || settlement_account_change_bec
        || crypto_payment_bec
        || no_ioc_solicitation_bec
        || stage_b_no_ioc_solicitation_bec
        || no_ioc_direct_payment_bec
        || no_ioc_illicit_invoice_solicitation_bec
        || direct_payment_bec
        || no_ioc_authority_social
    {
        0.72
    } else {
        0.24
    };
    categories.push("bec".to_string());
    categories.push("bec_external_compound".to_string());
    if no_ioc {
        categories.push("bec_no_ioc_social".to_string());
    }
    evidence.push(Evidence {
        description: format!(
        "External BEC compound from {}: stage_b_no_ioc={}, authority={}, payment={}, business_context={}, high_risk_request={}, service_context={}, service_sensitive={}, service_contact={}, reconciliation_context={}, reconciliation_action={}, settlement_account_change={}, crypto_context={}, crypto_action={}, no_ioc_context={}, no_ioc_value={}, no_ioc_action={}, no_ioc_pressure={}, no_ioc_contact={}, no_ioc_secrecy={}, confidentiality={}, urgency={}, financial={}, local_action={}, reply_bypass={}, reply_to_financial_process={}, no_ioc_direct_payment={}, illicit_invoice_offer_hits={}, no_destination_payment_process={}, executive_wire={}, hidden_payment_instruction={}",
            sender_domain.as_deref().unwrap_or("unknown"),
            stage_b_no_ioc_solicitation_bec,
            authority_hits,
            payment_hits,
            business_context_hits,
            high_risk_request_hits,
            external_service_context_hits,
            external_service_sensitive_hits,
            external_service_contact_hits,
            reconciliation_context_hits,
            reconciliation_action_hits,
            settlement_account_change_hits,
            crypto_context_hits,
            crypto_action_hits,
            no_ioc_solicitation_context_hits,
            no_ioc_solicitation_value_hits,
            no_ioc_solicitation_action_hits,
            no_ioc_solicitation_pressure_hits,
            no_ioc_solicitation_contact_hits,
            no_ioc_solicitation_secrecy_hits,
            confidentiality_hits,
            urgency_hits,
            financial_hits,
            local_action_hits,
            forged_reply_process_bypass,
            reply_to_financial_process_bec,
            no_ioc_direct_payment_bec,
            illicit_invoice_offer_hits,
            no_destination_payment_process_bec,
            executive_wire_no_ioc_bec,
            hidden_payment_instruction_bec,
        ),
        location: Some("subject + body + envelope".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Text-only QR invoices are actionable only when the message explicitly
/// instructs scanning and contains multiple invoice/payment verification
/// cues. A bare `QR` mention remains ordinary business context.
pub(super) fn detect_text_qr_lure(
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
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let combined = format!("{subject}\n\n{body}");
    let (normalized, compact) = normalized_and_compact(&combined);
    let md = module_data();
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("qr_text_scan_action_terms"),
    );
    let context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("qr_text_business_context_terms"),
    );
    if action_hits == 0 || context_hits < 2 || !ctx.session.content.links.is_empty() {
        return;
    }

    *total_score += 0.60;
    categories.push("qr_text_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "External sender {} combines a text-only QR scan instruction with {} invoice/payment verification cues",
            sender_domain.as_deref().unwrap_or("unknown"),
            context_hits
        ),
        location: Some("subject + body".to_string()),
        snippet: Some(combined.chars().take(180).collect()),
    });
}

/// Detect ClickFix-style command-paste pages by requiring visible user
/// instructions, an active script operation, and a command/script payload.
/// Each vocabulary is runtime JSON; no lure wording is embedded here.
pub(super) fn detect_clickfix_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    let visible = body_for_cross
        .map(str::to_string)
        .unwrap_or_else(|| strip_html_tags(html));
    let (visible_normalized, visible_compact) = normalized_and_compact(&visible);
    let raw = normalize_text(&html.to_lowercase());
    let raw_compact = compact_detection_view(&raw);
    let md = module_data();
    let instruction_hits = count_config_terms(
        &visible_normalized,
        &visible_compact,
        md.get_list("clickfix_visible_instruction_terms"),
    );
    let active_hits = count_config_terms(&raw, &raw_compact, md.get_list("active_script_risk_ops"));
    let payload_hits =
        count_config_terms(&raw, &raw_compact, md.get_list("clickfix_payload_terms"));
    let command_operation_hits = count_config_terms(
        &raw,
        &raw_compact,
        md.get_list("clickfix_command_operation_terms"),
    );
    if instruction_hits < 2
        || payload_hits == 0
        || (active_hits == 0 && command_operation_hits == 0)
    {
        return;
    }

    *total_score += 0.82;
    categories.push("clickfix_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "HTML ClickFix compound: visible instructions={}, active script operations={}, command operations={}, payload markers={}",
            instruction_hits, active_hits, command_operation_hits, payload_hits
        ),
        location: Some("body_html + rendered text".to_string()),
        snippet: Some(visible.chars().take(180).collect()),
    });
}

/// Detect a trust-building social lure only when the external message also
/// asks for a fee/payment and supplies an untrusted destination.  The two
/// semantic dimensions are kept separate so ordinary adoption, donation, or
/// community notices remain observations.
pub(super) fn detect_social_trust_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || !has_untrusted_clickable_link(ctx)
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let (normalized, compact) = normalized_and_compact(&format!("{subject}\n\n{body}"));
    let md = module_data();
    let lure_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("social_trust_lure_terms"),
    );
    let payment_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("social_trust_payment_terms"),
    );
    if lure_hits < 2 || payment_hits < 2 {
        return;
    }

    *total_score += 0.58;
    categories.push("social_trust_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "External social-trust lure combines {} trust cues, {} fee/payment cues, and an untrusted destination",
            lure_hits, payment_hits
        ),
        location: Some("subject + body + links".to_string()),
        snippet: Some(format!("{subject}\n\n{body}").chars().take(180).collect()),
    });
}

/// Targeted recruitment spear-phishing needs both personalization and a
/// role-specific recruiting context.  A public careers message without a
/// personalized reference does not satisfy this compound.
pub(super) fn detect_targeted_recruitment_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref())
        || !has_untrusted_clickable_link(ctx)
    {
        return;
    }
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let (normalized, compact) = normalized_and_compact(&format!("{subject}\n\n{body}"));
    let md = module_data();
    let context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("targeted_recruitment_context_terms"),
    );
    let personalization_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("targeted_recruitment_personalization_terms"),
    );
    let benign_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("targeted_recruitment_benign_markers"),
    );
    if context_hits < 2 || personalization_hits == 0 || benign_hits >= 2 {
        return;
    }

    *total_score += 0.56;
    categories.push("targeted_recruitment_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "External targeted-recruitment lure combines {} role/context cues, {} personalized references, and an untrusted destination",
            context_hits, personalization_hits
        ),
        location: Some("subject + body + links".to_string()),
        snippet: Some(format!("{subject}\n\n{body}").chars().take(180).collect()),
    });
}

/// HTML base-href attacks turn a harmless-looking relative link into an
/// external action target.  Require an untrusted absolute base, a relative
/// href, and recipient action wording before scoring the pattern.
pub(super) fn detect_base_href_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    let has_relative_href = RE_HTML_HREF.captures_iter(html).any(|captures| {
        let Some(value) = captures.get(1).map(|value| value.as_str().trim()) else {
            return false;
        };
        !value.starts_with('/')
            && !value.starts_with("//")
            && !value.contains("://")
            && !value.contains(':')
    });
    if !has_relative_href {
        return;
    }
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let combined = format!("{subject}\n\n{body}\n\n{html}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        module_data().get_list("base_href_action_terms"),
    );
    if action_hits < 2 || !has_recipient_directed_action(&actionable_context) {
        return;
    }

    let base_domain = RE_HTML_BASE_HREF.captures_iter(html).find_map(|captures| {
        let raw = captures.get(1)?.as_str();
        let parsed = url::Url::parse(raw).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let trusted = ctx.is_internal_domain(&host)
            || module_data().contains("protected_domains", &host)
            || crate::modules::link_scan::is_trusted_url_domain(&host)
            || crate::modules::link_scan::is_well_known_safe_domain(&host);
        (!trusted && matches!(parsed.scheme(), "http" | "https")).then_some(host)
    });
    let Some(base_domain) = base_domain else {
        return;
    };

    *total_score += 0.52;
    categories.push("base_href_action_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "External HTML base-href redirect combines an untrusted base host {}, a relative action link, and {} action cues",
            base_domain, action_hits
        ),
        location: Some("body_html + base href".to_string()),
        snippet: Some(html.chars().take(180).collect()),
    });
}

/// Image-only mail can hide the entire lure in an alt attribute.  This path
/// requires a URL inside alt text plus an account threat/action pair and an
/// external sender; image layout alone remains non-threatening context.
pub(super) fn detect_image_alt_lure(
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }
    let md = module_data();
    let Some(alt_text) = RE_HTML_ALT_VALUE
        .captures_iter(html)
        .find_map(|captures| captures.get(1).map(|value| value.as_str()))
    else {
        return;
    };
    let Some(url_match) = RE_HTML_ALT_URL.find(alt_text) else {
        return;
    };
    let url = url_match.as_str().replace('：', ":");
    let Ok(parsed) = url::Url::parse(&url) else {
        return;
    };
    let Some(domain) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return;
    };
    if ctx.is_internal_domain(&domain)
        || module_data().contains("protected_domains", &domain)
        || crate::modules::link_scan::is_trusted_url_domain(&domain)
        || crate::modules::link_scan::is_well_known_safe_domain(&domain)
    {
        return;
    }
    let actionable_context = strip_counter_context_segments(alt_text);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    let threat_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("account_security_threat_phrases_body"),
    );
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("account_security_action_phrases_body"),
    );
    if threat_hits == 0 || action_hits == 0 || !has_recipient_directed_action(&actionable_context) {
        return;
    }

    *total_score += 0.60;
    categories.push("image_alt_phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External image alt text contains an account threat/action pair and an untrusted destination {}",
            domain
        ),
        location: Some("body_html img alt".to_string()),
        snippet: Some(alt_text.chars().take(180).collect()),
    });
}

/// An externally hosted QR image can be the only actionable element in an
/// otherwise harmless-looking HTML message. Require explicit connection/scan
/// wording and a matching access context; ordinary logos and QR images in
/// documentation remain observations.
pub(super) fn detect_embedded_image_qr_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }
    let Some(image_url) = first_untrusted_embedded_url(ctx, html, &RE_HTML_IMAGE_SRC) else {
        return;
    };
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let combined = format!("{subject}\n\n{body}\n\n{html}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    let md = module_data();
    let context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("embedded_image_qr_context_terms"),
    );
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("embedded_image_qr_action_terms"),
    );
    if context_hits == 0 || action_hits == 0 || !has_recipient_directed_action(&actionable_context)
    {
        return;
    }

    *total_score += 0.62;
    categories.push("embedded_image_qr_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External QR image destination combines {} access-context cue(s) and {} scan/connect action cue(s): {}",
            context_hits, action_hits, image_url
        ),
        location: Some("body_html img + rendered text".to_string()),
        snippet: Some(format!("{subject}\n\n{body}").chars().take(180).collect()),
    });
}

/// Iframes hide their destination from the ordinary anchor-link inventory.
/// Treat an external iframe as an authentication lure only when its path is
/// a configured auth segment and the visible message explains a session or
/// account action.
pub(super) fn detect_embedded_iframe_auth_lure(
    ctx: &SecurityContext,
    body_for_cross: Option<&str>,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(html) = ctx.session.content.body_html.as_deref() else {
        return;
    };
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }
    let Some(iframe_url) = first_untrusted_embedded_url(ctx, html, &RE_HTML_IFRAME_SRC) else {
        return;
    };
    let Ok(parsed) = url::Url::parse(&iframe_url) else {
        return;
    };
    let md = module_data();
    let auth_terms = md.get_list("credential_auth_path_segments");
    let auth_path = parsed.path_segments().is_some_and(|mut segments| {
        segments.any(|segment| {
            auth_terms
                .iter()
                .any(|term| segment.eq_ignore_ascii_case(term))
        })
    });
    if !auth_path {
        return;
    }

    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let subject = ctx.session.subject.as_deref().unwrap_or_default();
    let combined = format!("{subject}\n\n{body}\n\n{html}");
    let actionable_context = strip_counter_context_segments(&combined);
    let (normalized, compact) = normalized_and_compact(&actionable_context);
    let md = module_data();
    let context_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("embedded_iframe_auth_context_terms"),
    );
    let action_hits = count_config_terms(
        &normalized,
        &compact,
        md.get_list("embedded_iframe_auth_action_terms"),
    );
    if context_hits == 0 || action_hits == 0 || !has_recipient_directed_action(&actionable_context)
    {
        return;
    }

    *total_score += 0.62;
    categories.push("embedded_iframe_auth_lure".to_string());
    categories.push("phishing".to_string());
    evidence.push(Evidence {
        description: format!(
            "External iframe authentication target combines {} account/session context cue(s) and {} action cue(s): {}",
            context_hits, action_hits, iframe_url
        ),
        location: Some("body_html iframe + rendered text".to_string()),
        snippet: Some(format!("{subject}\n\n{body}").chars().take(180).collect()),
    });
}

/// Detect an explicit body action that points at a bare hostname whose public
/// suffix counterfeits a common ASCII suffix (for example `.cοm`). Neither a
/// mixed-script hostname nor generic confirmation prose scores alone.
pub(super) fn detect_confusable_suffix_action_lure(
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
    let Some(plain_body) = ctx.session.content.body_text.as_deref() else {
        return;
    };
    let body = body_for_cross.unwrap_or(plain_body);
    let normalized = normalize_text(&body.to_lowercase());
    let compact = compact_detection_view(&normalized);
    let Some(action) = first_config_term_hit(
        &normalized,
        &compact,
        module_data().get_list("thread_reply_destination_actions"),
    ) else {
        return;
    };

    let target = ctx
        .session
        .content
        .links
        .iter()
        .take(64)
        .filter_map(|link| url::Url::parse(&link.url).ok())
        .filter_map(|url| url.host_str().map(str::to_ascii_lowercase))
        .find_map(|ascii_host| {
            let unicode_host = idna::domain_to_unicode(&ascii_host).0.to_lowercase();
            let untrusted = !crate::modules::link_scan::is_trusted_url_domain(&ascii_host)
                && !crate::modules::link_scan::is_well_known_safe_domain(&ascii_host);
            (untrusted
                && crate::modules::link_content::has_confusable_common_public_suffix(&ascii_host)
                && body_contains_bare_host(plain_body, &unicode_host))
            .then_some(unicode_host)
        });
    let Some(target) = target else {
        return;
    };

    *total_score += 0.65;
    categories.push("obfuscated_domain_lure".to_string());
    evidence.push(Evidence {
        description: format!(
            "Confirmation action '{action}' points to bare hostname {target} with a confusable public suffix"
        ),
        location: Some("body bare domain".to_string()),
        snippet: Some(target),
    });
}

/// Distinguish a successfully parsed empty message from a parser/capture gap.
/// Incomplete content is handled by the coverage circuit elsewhere and must
/// not be relabeled as an empty-but-complete message here.
pub(super) fn detect_empty_body_observation(
    ctx: &SecurityContext,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let content = &ctx.session.content;
    if !content.is_complete
        || content.has_retained_message_entity()
        || !content.links.is_empty()
        || content.raw_size == 0 && content.headers.is_empty()
    {
        return;
    }

    categories.push("empty_body_observed".to_string());
    evidence.push(Evidence {
        description:
            "Message parsed successfully but contains no retained body, link, or attachment entity"
                .to_string(),
        location: Some("mime body".to_string()),
        snippet: None,
    });
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
    qualified_threat_actions: &mut Vec<serde_json::Value>,
) {
    let sender_domain = external_sender_domain(ctx);
    if !is_external_sender_for_bec(ctx, sender_domain.as_deref()) {
        return;
    }

    let subject = ctx.session.subject.as_deref().unwrap_or("");
    let body = detector_body_fallback_text(ctx, body_for_cross).unwrap_or_default();
    let raw_combined = format!("{subject}\n\n{body}");
    let actionable_context = strip_counter_context_segments(&raw_combined);
    let combined = normalize_text(&actionable_context.to_lowercase());
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

    // Account labels and update verbs are ordinary payment metadata in
    // statements, fee notices, and portal help text. They become actionable
    // only when the same local span tells the recipient to redirect payment
    // to a replacement destination. Keep strong, already-specific phrases
    // (for example `beneficiary account changed`) on the existing path.
    let context_only_hits = count_config_terms(
        &combined,
        &compact,
        md.get_list("payment_change_context_only_terms"),
    );
    let raw_body = ctx
        .session
        .content
        .body_text
        .as_deref()
        .or_else(|| ctx.session.content.body_html.as_deref())
        .unwrap_or(&body);
    let raw_combined = format!("{subject}\n\n{raw_body}");
    let (raw_normalized, raw_compact) = normalized_and_compact(&raw_combined);
    let no_redirect_counter_hits = count_config_terms(
        &raw_normalized,
        &raw_compact,
        md.get_list("payment_change_no_redirect_counter_markers"),
    );
    let has_explicit_redirect =
        crate::modules::content_scan::has_explicit_payment_change_redirect(&actionable_context);
    if no_redirect_counter_hits > 0 && !has_explicit_redirect {
        return;
    }
    if context_only_hits > 0 && !has_explicit_redirect {
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
    let business_context_hits = count_config_terms(
        &combined,
        &compact,
        md.get_list("bec_business_context_terms"),
    );

    let support_dimensions = usize::from(action_hits > 0)
        + usize::from(authority_hits > 0)
        + usize::from(urgency_hits > 0)
        + usize::from(confidentiality_hits > 0)
        + usize::from(business_context_hits > 0);
    let action_pair = action_hits >= 2;
    if support_dimensions < 2 && !action_pair {
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
    threat_actions::record_payment_actions(ctx, score.min(0.78), qualified_threat_actions);
    evidence.push(Evidence {
        description: format!(
            "Payment-account-change BEC pattern from external domain {}: change={}, action={} (pair={}), authority={}, urgency={}, confidentiality={}, business_context={}",
            sender_domain.as_deref().unwrap_or("unknown"),
            change_hits,
            action_hits,
            action_pair,
            authority_hits,
            urgency_hits,
            confidentiality_hits,
            business_context_hits,
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
            let normalized_subject = normalize_text(&subject.to_lowercase());
            let is_chat_forward = module_data()
                .get_list("benign_forwarded_message_subject_markers")
                .iter()
                .any(|marker| normalized_subject.contains(&normalize_text(&marker.to_lowercase())));
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
            let impersonation_hits = keyword_set(internal_authority_phrases).find_hits(&body_lower);
            // Authority phrases also occur in legitimate policies, reports,
            // industry newsletters, and event invitations. Unknown links are
            // not identity claims. Require both an explicit local claim and an
            // actionable credential/payment lure.
            if impersonation_hits.len() < 2 {
                return;
            }
            let has_claim = has_explicit_authority_claim(body, &impersonation_hits);
            let has_lure = has_external_impersonation_lure(body);
            if has_claim && has_lure {
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
    use super::{
        RE_GROUPED_BANK_ACCOUNT, has_explicit_authority_claim, has_external_impersonation_lure,
        has_local_reply_handoff_sensitive_request, parse_credential_content_lure_policy,
        strip_counter_context_segments,
    };

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

    #[test]
    fn malformed_json_policy_disables_content_credential_lure() {
        assert!(
            parse_credential_content_lure_policy(serde_json::json!({
                "enabled": true,
                "credential_link_category": "fixture_category"
            }))
            .is_none()
        );

        let mut invalid = crate::module_data::module_data()
            .get_structured("credential_brand_target_policy_v1")
            .expect("embedded policy")
            .clone();
        invalid["content_external_sender_score"] = serde_json::json!(1.5);
        assert!(parse_credential_content_lure_policy(invalid).is_none());
    }

    #[test]
    fn counter_context_is_scoped_and_does_not_erase_another_request() {
        let text = "安全培训：诈骗案例，请勿回复本邮件。\n请立即登录账户完成验证。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("安全培训"));
        assert!(actionable.contains("请立即登录账户完成验证"));
    }

    #[test]
    fn quoted_action_is_not_treated_as_current_request() {
        let text = "> 请立即登录账户完成验证\n请查看本周安全公告";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("请立即登录账户完成验证"));
        assert!(actionable.contains("请查看本周安全公告"));
    }

    #[test]
    fn soft_wrapped_counter_context_stays_with_its_object() {
        let text = "安全培训：请勿通过邮件发送\n银行卡密码或短信验证码。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("银行卡密码"));
        assert!(!actionable.contains("短信验证码"));
    }

    #[test]
    fn negative_list_intro_scopes_only_its_bullets() {
        let text = "研究生院永远不会：\n  - 以邮件链接收集身份证照片和短信验证码\n  - 要求向个人账户支付评审费\n\n请通过校园内官方系统提交进展报告。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("身份证照片"));
        assert!(!actionable.contains("短信验证码"));
        assert!(!actionable.contains("支付评审费"));
        assert!(actionable.contains("提交进展报告"));
    }

    #[test]
    fn inline_negative_list_intro_scopes_only_its_bullets() {
        let text = "环球仓配永远不会： - 以库存冻结威胁向陌生账户汇款 - 设立供应链金融账户收取附加费\n\n请将正常费用计入月结账单。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("库存冻结"));
        assert!(!actionable.contains("供应链金融账户"));
        assert!(actionable.contains("请将正常费用计入月结账单"));
    }

    #[test]
    fn negative_list_removes_its_risky_heading_but_keeps_following_request() {
        let text = "二、重要说明（关于库存冻结与结算账户变更）\n\n环球仓配永远不会：\n  - 威胁向陌生账户汇款\n  - 以库存冻结制造紧迫感\n\n请查看官方月结账单。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("结算账户变更"));
        assert!(!actionable.contains("陌生账户汇款"));
        assert!(actionable.contains("请查看官方月结账单"));
    }

    #[test]
    fn grouped_bank_account_detects_four_digit_groups_without_phone_numbers() {
        assert!(RE_GROUPED_BANK_ACCOUNT.is_match("账号：6228 4471 3392 8814 67"));
        assert!(RE_GROUPED_BANK_ACCOUNT.is_match("IBAN 收款账号：773 118 229 8846 4470"));
        assert!(!RE_GROUPED_BANK_ACCOUNT.is_match("联系电话：13800138000"));
    }

    #[test]
    fn official_anti_fraud_disclaimers_are_removed_without_erasing_real_notice_actions() {
        let text = "申报入口：请通过浙江企业码在线申报。\n不上传营业执照与法人身份证原件照片。\n\n没有只回邮件的通道。";
        let actionable = strip_counter_context_segments(text);

        assert!(actionable.contains("请通过浙江企业码在线申报"));
        assert!(!actionable.contains("营业执照与法人身份证"));
        assert!(!actionable.contains("没有只回邮件的通道"));
    }

    #[test]
    fn unbulleted_request_after_warning_list_remains_actionable() {
        let text = "研究生院永远不会：\n  - 以邮件链接收集身份证照片\n请今天将验证码回复给我。";
        let actionable = strip_counter_context_segments(text);

        assert!(!actionable.contains("身份证照片"));
        assert!(actionable.contains("验证码回复给我"));
    }

    #[test]
    fn reply_handoff_sensitive_request_requires_local_unquoted_evidence() {
        assert!(has_local_reply_handoff_sensitive_request(
            "她说缺一份发票原件照片，你直接回她邮箱就行，纸质的我这边补。"
        ));

        let quoted = strip_counter_context_segments(
            "> 她说缺一份发票原件照片，你直接回她邮箱就行。\n这是一起钓鱼邮件报告。",
        );
        assert!(!has_local_reply_handoff_sensitive_request(&quoted));

        let distant_request = format!(
            "发票和采购归档规则见附件。{}\n\n请直接回她邮箱。",
            "背景材料 ".repeat(130)
        );
        assert!(!has_local_reply_handoff_sensitive_request(&distant_request));
    }
}
