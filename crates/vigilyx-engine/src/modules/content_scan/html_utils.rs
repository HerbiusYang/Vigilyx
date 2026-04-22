//! HTML utility functions for content scanning.

use regex::Regex;
use std::sync::LazyLock;

use crate::context::SecurityContext;
use crate::modules::common::{extract_domain_from_url, percent_decode};

static RE_EMAIL_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("valid email regex")
});

/// Simple HTML tag stripper (does not need to be perfect; just for keyword matching)
pub(crate) fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                result.push(' ');
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    // HTML Decode: prevent &#x5BC6;&#x7801; (Password) Keywordsdetect
    decode_html_entities(&result)
}

/// Decode HTML,preventAttack Encode Keywordsmatch
pub(crate) fn decode_html_entities(text: &str) -> String {
    let mut result = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");

    // : &#; And &#x 6Base/Radix;
    // ofLoopDecode,Avoid regex Dependency
    while let Some(start) = result.find("&#") {
        let rest = &result[start + 2..];
        if let Some(end) = rest.find(';') {
            let entity = &rest[..end];
            let decoded = if let Some(hex) = entity
                .strip_prefix('x')
                .or_else(|| entity.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                entity.parse::<u32>().ok().and_then(char::from_u32)
            };
            if let Some(ch) = decoded {
                let before = &result[..start];
                let after = &result[start + 2 + end + 1..];
                result = format!("{}{}{}", before, ch, after);
            } else {
                break; // Decodeof, AvoidinfiniteLoop
            }
        } else {
            break;
        }
    }

    result
}

fn extract_normalized_email(text: &str) -> Option<String> {
    RE_EMAIL_TEXT
        .find(text)
        .map(|m| m.as_str().to_ascii_lowercase())
}

fn detect_contact_card_email(ctx: &SecurityContext) -> Option<String> {
    ctx.session
        .mail_from
        .as_deref()
        .and_then(extract_normalized_email)
        .or_else(|| {
            ctx.session
                .content
                .body_text
                .as_deref()
                .and_then(extract_normalized_email)
        })
        .or_else(|| {
            ctx.session
                .content
                .links
                .iter()
                .filter_map(|link| link.text.as_deref())
                .find_map(extract_normalized_email)
        })
}

fn is_business_card_profile_url(url: &str, contact_email: &str) -> bool {
    let decoded = percent_decode(url).to_ascii_lowercase();
    let Some(domain) = extract_domain_from_url(&decoded) else {
        return false;
    };

    matches!(domain.as_str(), "wx.mail.qq.com" | "mail.qq.com")
        && decoded.contains("readmail_businesscard_midpage")
        && decoded.contains(contact_email)
}

fn is_business_card_avatar_url(url: &str) -> bool {
    extract_domain_from_url(url).is_some_and(|domain| domain.ends_with("qlogo.cn"))
}

pub(super) fn is_embedded_contact_card_layout(ctx: &SecurityContext) -> bool {
    let Some(contact_email) = detect_contact_card_email(ctx) else {
        return false;
    };
    let Some(body_html) = ctx.session.content.body_html.as_deref() else {
        return false;
    };
    let html_lower = body_html.to_ascii_lowercase();
    let has_contact_card_markup = html_lower.contains("xm_write_card")
        || html_lower.contains("readmail_businesscard_midpage")
        || html_lower.contains("qlogo.cn");

    if !has_contact_card_markup {
        return false;
    }

    let mut business_card_links = 0usize;
    for link in &ctx.session.content.links {
        if is_business_card_profile_url(&link.url, &contact_email) {
            business_card_links += 1;
            continue;
        }
        if is_business_card_avatar_url(&link.url) {
            continue;
        }
        return false;
    }

    business_card_links > 0
}
