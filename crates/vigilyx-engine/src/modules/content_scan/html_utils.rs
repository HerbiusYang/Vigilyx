//! HTML utility functions for content scanning.

use regex::Regex;
use std::sync::LazyLock;

use crate::context::SecurityContext;
use crate::modules::common::{extract_domain_from_url, percent_decode};

static RE_EMAIL_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("valid email regex")
});

// `html-escape` ships the WHATWG/HTML5 named-entity table (including
// semicolon-less legacy forms).  Keep a second, bounded pass for residual
// entity-shaped tokens: an unknown `&attacker;` must not leave its letters
// between two CJK characters and thereby create a keyword-break primitive.
static RE_RESIDUAL_NAMED_ENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&[A-Za-z][A-Za-z0-9]{1,31};?").expect("valid residual HTML entity regex")
});

/// Simple HTML tag stripper (does not need to be perfect; just for keyword matching)
pub(crate) fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut chars = html.chars().peekable();
    let mut in_tag = false;
    while let Some(ch) = chars.next() {
        match ch {
            '<' => {
                // HTML5: '<' only opens markup when followed by an ASCII
                // letter, '/' or '!'. Otherwise it is literal text — an
                // attacker must not hide the rest of the body behind a bare
                // '<' that never closes.
                match chars.peek() {
                    Some(next)
                        if next.is_ascii_alphabetic() || *next == '/' || *next == '!' =>
                    {
                        in_tag = true;
                    }
                    _ => result.push('<'),
                }
            }
            '>' if in_tag => {
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
    // Decode the complete HTML5 entity set instead of a six-entry allowlist.
    // This is deliberately performed before numeric compatibility handling so
    // nested/double encoded references retain the historical behavior.
    let mut result = html_escape::decode_html_entities(text).into_owned();

    // : &#; And &#x 6Base/Radix;
    // ofLoopDecode,Avoid regex Dependency
    let mut search_from = 0usize;
    while let Some(rel) = result.get(search_from..).and_then(|s| s.find("&#")) {
        let start = search_from + rel;
        let rest = &result[start + 2..];

        // HTML spec: numeric character references do NOT require a trailing
        // semicolon — browsers decode "&#36134户" as "账户". Attackers use
        // the semicolon-less form to slip past keyword scans. Parse an
        // optional x/X marker plus digits first, then optionally consume ';'.
        let (hex, digits) = match rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            Some(hex_rest) => {
                let len = hex_rest
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .count();
                (true, len)
            }
            None => {
                let len = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                (false, len)
            }
        };

        if digits >= 1 {
            // Guard: at most 7 decimal / 6 hex digits can encode a Unicode
            // scalar. Longer digit runs (order numbers, IDs) are literal text.
            let marker_len = usize::from(hex);
            let within_bounds = digits <= if hex { 6 } else { 7 };
            let span_end = start + 2 + marker_len + digits;
            let digit_str = &result[start + 2 + marker_len..span_end];
            let value = if hex {
                u32::from_str_radix(digit_str, 16).ok()
            } else {
                digit_str.parse::<u32>().ok()
            };
            let decoded = within_bounds.then(|| value.and_then(char::from_u32)).flatten();
            // Consume a trailing semicolon when present.
            let consumed = span_end + usize::from(result[span_end..].starts_with(';'));
            if let Some(ch) = decoded {
                let before = &result[..start];
                let after = &result[consumed..];
                result = format!("{}{}{}", before, ch, after);
                // Re-scan from the replacement position: the decoded char may
                // complete a nested entity (e.g. "&#38;#60;" -> "<").
                search_from = start;
            } else if within_bounds && value.is_some() {
                // Out-of-range / surrogate scalar: drop the span so an
                // attacker cannot break keyword contiguity with it.
                let after = &result[consumed..];
                result = format!("{}{}", &result[..start], after);
                search_from = start;
            } else {
                // Too many digits to be a character reference: keep literal.
                search_from = start + 2;
            }
            continue;
        }

        if let Some(end) = rest.find(';') {
            let entity = &rest[..end];
            // Numeric entities are at most ~8 chars ("&#x10FFFF;"). Treat the
            // span as entity-like only when it is short and alphanumeric;
            // anything else is ordinary text that happens to contain "&#".
            let entity_like = !entity.is_empty()
                && entity.len() <= 10
                && !entity.contains("&#")
                && entity.chars().all(|c| c.is_ascii_alphanumeric());
            if entity_like {
                // Undecodable entity (e.g. "&#xZZ;"): drop the "&#...;" span
                // so an attacker cannot break keyword contiguity with it, and
                // keep decoding the rest instead of aborting the whole pass.
                let after = &result[start + 2 + end + 1..];
                result = format!("{}{}", &result[..start], after);
                search_from = start;
            } else {
                // Not entity-like: keep "&#" as literal text and continue.
                search_from = start + 2;
            }
        } else {
            // No digits and no terminating ';': keep "&#" as literal text.
            search_from = start + 2;
        }
    }

    // Browser-visible text cannot contain the literal spelling of an unknown
    // named entity.  Removing the whole residual token (rather than keeping
    // its alphabetic name) prevents `账&unknown;户` from becoming a stable
    // keyword separator.  Short ordinary ampersand text such as `R&D` is not
    // matched because the entity name requires at least two characters.
    RE_RESIDUAL_NAMED_ENTITY
        .replace_all(&result, "")
        .into_owned()
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


#[cfg(test)]
mod tests {
    use super::{decode_html_entities, strip_html_tags};

    #[test]
    fn decode_html_entities_skips_invalid_entity_and_continues() {
        // PoC: before the fix, a single undecodable entity aborted decoding
        // for the rest of the text, so "密&#xZZ;&#x7801;" never became "密码".
        assert_eq!(decode_html_entities("密&#xZZ;&#x7801;"), "密码");
        assert_eq!(decode_html_entities("&#x5BC6;&#x7801;"), "密码");
        // Nested double-encoding still resolves.
        assert_eq!(decode_html_entities("&#38;#60;"), "<");
        // Ordinary text that merely contains "&#" is left untouched.
        assert_eq!(decode_html_entities("fish &# chips"), "fish &# chips");
    }

    #[test]
    fn decode_html_entities_decodes_numeric_entity_without_semicolon() {
        // PoC: before the fix, only "&#36134;" (with semicolon) decoded;
        // browsers also decode the semicolon-less form, so attackers could
        // hide "账户" as "&#36134;户" -> "账&#36134户" and bypass keyword scans.
        // 36134 = U+8D26 账, 25143 = U+6237 户.
        assert_eq!(
            decode_html_entities("验证您的&#36134户"),
            "验证您的账户"
        );
        assert_eq!(
            decode_html_entities("您的&#36134;&#25143;存在异常"),
            "您的账户存在异常"
        );
        // Hex form without semicolon: 0x7801 = 码.
        assert_eq!(decode_html_entities("密&#x7801码?"), "密码码?");
        // Digits stop at the first non-digit, per HTML spec.
        assert_eq!(decode_html_entities("&#65B"), "AB");
        // Long digit runs are order numbers, not character references.
        assert_eq!(
            decode_html_entities("订单 &#12345678 号"),
            "订单 &#12345678 号"
        );
        // Plain "&#" text is still left untouched.
        assert_eq!(decode_html_entities("fish &# chips"), "fish &# chips");
    }

    #[test]
    fn strip_html_tags_treats_bare_angle_bracket_as_literal_text() {
        // PoC: before the fix, a bare '<' swallowed everything up to the next
        // '>' (possibly the rest of the body), hiding phishing prose.
        let stripped = strip_html_tags("成本 < 预算。您的账户异常，请立即登录处理。");
        assert!(
            stripped.contains("请立即登录处理"),
            "text after a bare '<' must survive stripping, got: {stripped:?}"
        );
        assert!(stripped.contains('<'));

        // HTML5: '<' only opens markup before [a-zA-Z/!]; '>' outside a tag
        // is literal text.
        let stripped = strip_html_tags("a < b > c");
        assert_eq!(stripped, "a < b > c");

        // Real tags are still stripped.
        assert_eq!(strip_html_tags("<div>Hello</div>World"), " Hello World");
    }

    #[test]
    fn decode_html_entities_covers_html5_named_whitespace_entities() {
        let decoded = decode_html_entities("您的账&hairsp;户&Tab;存在&NewLine;异常&thinsp;登录");
        assert_eq!(decoded, "您的账\u{200A}户\u{0009}存在\n异常\u{2009}登录");
    }

    #[test]
    fn unknown_named_entity_cannot_break_keyword_contiguity() {
        assert_eq!(decode_html_entities("您的账&unknownentity;户存在异常"), "您的账户存在异常");
    }
}
