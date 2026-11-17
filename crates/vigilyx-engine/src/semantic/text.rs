//! UTF-8 boundaries and semantic rule matching normalization.

use std::borrow::Cow;

use crate::modules::content_scan::html_utils::decode_html_entities;
use crate::modules::content_scan::normalize_text;

/// Borrow already-lowercase text without changing Unicode case semantics.
/// Titlecase and expanding mappings are checked through the actual mapping,
/// rather than assuming that `is_uppercase` covers every changing character.
pub(super) fn lowercase_view(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(text.to_ascii_lowercase())
        } else {
            Cow::Borrowed(text)
        }
    } else if text
        .chars()
        .all(|character| character.to_lowercase().eq(std::iter::once(character)))
    {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(text.to_lowercase())
    }
}

pub(super) fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Normalize the body for rule-based semantic keyword matching.
///
/// Most ordinary SMTP bodies are already ASCII and contain no HTML entity.
/// For that common path NFKD + NFC + the confusable/zero-width filters are
/// identity operations, so avoid allocating the intermediate decoded and
/// normalized strings. The guard is deliberately strict: `&` keeps the full
/// entity decoder enabled, and any non-ASCII byte keeps Unicode evasion
/// handling enabled.
pub(super) fn normalized_lowercase_body(body: &str) -> String {
    if body.is_ascii() && !body.as_bytes().contains(&b'&') {
        body.to_ascii_lowercase()
    } else {
        normalize_text(&decode_html_entities(body)).to_lowercase()
    }
}

pub(super) fn semantic_phrase_at(text: &str, phrase: &str, offset: usize) -> bool {
    if !phrase.is_ascii() || !phrase.chars().any(char::is_alphanumeric) {
        return true;
    }
    let before = text[..offset].chars().next_back();
    let after = text[offset + phrase.len()..].chars().next();
    // Chinese words can adjoin a Latin service label (e.g. 添加QQ). Keep
    // Latin/other alphabetic continuations bounded, without requiring spaces
    // between CJK text and an ASCII marker.
    let continuation = |c: char| c.is_alphanumeric() && !super::statistics::is_cjk_any(c);
    !before.is_some_and(continuation) && !after.is_some_and(continuation)
}
