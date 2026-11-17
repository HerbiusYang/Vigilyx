//! Plain-text body cleanup shared by the detectors.

use std::borrow::Cow;

/// Longest selector accepted in front of a leaked CSS rule block.
const MAX_SELECTOR_CHARS: usize = 200;

/// Remove CSS that HTML-to-text converters copy into a `text/plain`
/// alternative. Foxmail, for example, emits its `<style>` rules
/// (`div.fox_html_content { line-height: 1.5;} ol, ul { margin-Top: 0px; }`)
/// ahead of the message text, so keyword detectors read style code first.
///
/// Only `selector { property: value; … }` blocks and, when such a block is
/// present, `/* … */` comments are removed; all other text keeps its order.
/// Text without a CSS rule block is returned unchanged.
pub fn strip_leaked_css(text: &str) -> Cow<'_, str> {
    if !text.contains('{') {
        return Cow::Borrowed(text);
    }
    let chars: Vec<char> = text.chars().collect();
    if css_rule_spans(&chars).is_empty() {
        return Cow::Borrowed(text);
    }
    let chars = remove_css_comments(&chars);
    let mut out = String::with_capacity(text.len());
    let mut next = 0;
    for (start, end) in css_rule_spans(&chars) {
        out.extend(&chars[next..start]);
        out.push(' ');
        next = end + 1;
    }
    out.extend(&chars[next..]);
    Cow::Owned(out)
}

/// Inclusive `[selector start, closing brace]` spans, in order.
fn css_rule_spans(chars: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    // A selector never reaches back past the previous rule.
    let mut floor = 0;
    let mut open = 0;
    while open < chars.len() {
        if chars[open] != '{' {
            open += 1;
            continue;
        }
        let Some(close) = chars[open + 1..]
            .iter()
            .position(|&c| c == '{' || c == '}')
            .map(|offset| open + 1 + offset)
        else {
            break;
        };
        if chars[close] == '{' {
            open = close;
            continue;
        }
        if is_declaration_block(&chars[open + 1..close])
            && let Some(start) = selector_start(chars, floor, open)
        {
            spans.push((start, close));
            floor = close + 1;
        }
        open = close + 1;
    }
    spans
}

fn is_selector_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " \t\r\n.#*:,>+~[]=\"'()-_".contains(c)
}

fn selector_start(chars: &[char], floor: usize, brace: usize) -> Option<usize> {
    let mut start = brace;
    while start > floor && brace - start < MAX_SELECTOR_CHARS && is_selector_char(chars[start - 1])
    {
        start -= 1;
    }
    chars[start..brace]
        .iter()
        .any(|c| c.is_ascii_alphabetic() || *c == '*')
        .then_some(start)
}

/// `property: value; …` with ASCII property names and at least one declaration.
fn is_declaration_block(block: &[char]) -> bool {
    let block: String = block.iter().collect();
    let mut declarations = 0;
    for declaration in block.split(';') {
        let declaration = declaration.trim();
        if declaration.is_empty() {
            continue;
        }
        let Some((property, value)) = declaration.split_once(':') else {
            return false;
        };
        let property = property.trim();
        if property.is_empty()
            || !property
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '-')
            || value.trim().is_empty()
        {
            return false;
        }
        declarations += 1;
    }
    declarations > 0
}

fn remove_css_comments(chars: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/'
            && chars.get(i + 1) == Some(&'*')
            && let Some(end) = chars[i + 2..]
                .windows(2)
                .position(|pair| pair == ['*', '/'])
        {
            i += 2 + end + 2;
            out.push(' ');
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Excerpt of a Foxmail text/plain part observed in production
    /// (2026-11-12): gateway banner, Foxmail default styles, then the text.
    #[test]
    fn foxmail_default_styles_are_removed_and_text_is_kept() {
        let body = "检测结果：垃圾邮件。 div.fox_html_content { line-height: 1.5;} /* 一些默认样式 */ \
                    blockquote { margin-Top: 0px; margin-Bottom: 0px; margin-Left: 0.5em } \
                    ol, ul { margin-Top: 0px; margin-Bottom: 0px; list-style-position: inside; } \
                    p { margin-Top: 0px; margin-Bottom: 0px } \
                    .fox_html_content_dummy_textarea { position: absolute; overflow: hidden; width: 1px; height: 1px; opacity: 0; }\
                    2026年度课程安排";

        let cleaned = strip_leaked_css(body);

        assert!(cleaned.contains("检测结果：垃圾邮件。"), "{cleaned}");
        assert!(cleaned.contains("2026年度课程安排"), "{cleaned}");
        for leaked in [
            "line-height",
            "margin",
            "一些默认样式",
            "fox_html_content",
            "opacity",
        ] {
            assert!(!cleaned.contains(leaked), "{leaked} survived: {cleaned}");
        }
    }

    #[test]
    fn text_without_css_rules_is_borrowed_unchanged() {
        for body in [
            "价格{100元}，请于周五前确认。",
            "Meeting moved to 3pm {see calendar}.",
            "普通正文，没有花括号。",
        ] {
            assert!(matches!(strip_leaked_css(body), Cow::Borrowed(text) if text == body));
        }
    }

    #[test]
    fn comment_like_text_survives_when_no_rule_is_present() {
        let body = "路径 /* 不是样式 */ 保留";
        assert_eq!(strip_leaked_css(body), body);
    }
}
