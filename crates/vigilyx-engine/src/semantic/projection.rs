//! Production subject/body selection and source-preserving projections.

use serde::Deserialize;
use vigilyx_core::security::SemanticSourcePart;

use crate::modules::common::looks_like_raw_mime_container_text;
use crate::modules::content_scan::{
    normalize_text, normalized_subject_for_scan, sanitize_body_for_keyword_scan,
};
use crate::pipeline::verdict::runtime_scenario_patterns;

use super::budget::SEMANTIC_BODY_MAX_BYTES;
use super::compiled::{CompiledSemanticData, compiled_semantic_data};
use super::context::semantic_text_projection_with_data;
use super::text::floor_char_boundary;

pub(super) fn sanitize_semantic_inputs(
    subject: Option<&str>,
    raw_body: &str,
) -> (Option<String>, String) {
    let patterns = runtime_scenario_patterns();
    let cleaned_subject = subject
        .map(|value| {
            normalized_subject_for_scan(
                value,
                &patterns.gateway_banner_patterns,
                &patterns.notice_banner_patterns,
            )
        })
        .filter(|value| !value.trim().is_empty());
    let cleaned_body = sanitize_body_for_keyword_scan(
        raw_body,
        &patterns.gateway_banner_patterns,
        &patterns.notice_banner_patterns,
        &patterns.dsn_patterns,
        &patterns.auto_reply_patterns,
    );
    (cleaned_subject, cleaned_body)
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct SemanticBodySelectionPolicy {
    plain_stub_max_chars: usize,
    html_min_chars: usize,
    html_to_plain_ratio: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SemanticBodySource {
    PlainText,
    HtmlFallback,
    /// The message has no text body; the subject and attachment text are
    /// still analyzed.
    Empty,
}

impl SemanticBodySource {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::HtmlFallback => "html_fallback",
            Self::Empty => "empty",
        }
    }
}

const DEFAULT_BODY_SELECTION_POLICY: SemanticBodySelectionPolicy = SemanticBodySelectionPolicy {
    plain_stub_max_chars: 220,
    html_min_chars: 160,
    html_to_plain_ratio: 3.0,
};

/// The effective selection policy and an observation-only diagnostic. A
/// missing or invalid configured copy falls back to the built-in default so
/// HTML fallback keeps working; the fallback is reported, never silent.
fn semantic_body_selection_policy(
    data: &CompiledSemanticData,
) -> std::sync::Arc<(SemanticBodySelectionPolicy, Option<&'static str>)> {
    data.cached("semantic_body_selection_policy_v1", |registry| {
        let Some(value) = registry.get_structured("semantic_body_selection_policy_v1") else {
            return (
                DEFAULT_BODY_SELECTION_POLICY,
                Some("semantic body selection policy (semantic_body_selection_policy_v1) is missing; the built-in default selection is used"),
            );
        };
        let Ok(policy) = serde_json::from_value::<SemanticBodySelectionPolicy>(value.clone())
        else {
            return (
                DEFAULT_BODY_SELECTION_POLICY,
                Some("semantic body selection policy (semantic_body_selection_policy_v1) is malformed; the built-in default selection is used"),
            );
        };
        if policy.plain_stub_max_chars > 0
            && policy.html_min_chars > 0
            && policy.html_to_plain_ratio >= 1.0
            && policy.html_to_plain_ratio.is_finite()
        {
            (policy, None)
        } else {
            (
                DEFAULT_BODY_SELECTION_POLICY,
                Some("semantic body selection policy (semantic_body_selection_policy_v1) has invalid values; the built-in default selection is used"),
            )
        }
    })
}

pub(super) fn body_selection_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    semantic_body_selection_policy(data).1
}

fn raw_text_has_configured_banner(raw_text: &str) -> bool {
    let patterns = runtime_scenario_patterns();
    let normalized_raw = normalize_text(&raw_text.to_lowercase());
    patterns
        .gateway_banner_patterns
        .iter()
        .chain(patterns.notice_banner_patterns.iter())
        .any(|pattern| !pattern.is_empty() && normalized_raw.contains(pattern))
}

fn select_semantic_body_bounded(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
    data: &CompiledSemanticData,
) -> Option<(Option<String>, String, SemanticBodySource)> {
    let cleaned_subject = sanitize_semantic_inputs(subject, "").0;
    let plain_candidate = body_text
        .filter(|text| !looks_like_raw_mime_container_text(text))
        .map(|text| sanitize_semantic_inputs(None, text).1)
        .filter(|text| !text.trim().is_empty());
    let html_candidate = body_html
        .map(|html| semantic_text_projection_with_data(html, SemanticSourcePart::Html, data))
        .map(|text| sanitize_semantic_inputs(None, &text).1)
        .filter(|text| !text.trim().is_empty());

    match (plain_candidate, html_candidate) {
        (None, Some(html)) => Some((cleaned_subject, html, SemanticBodySource::HtmlFallback)),
        (Some(plain), Some(html)) => {
            let selection = semantic_body_selection_policy(data);
            let policy = &selection.0;
            let should_use_html = {
                let plain_chars = plain.chars().count();
                let html_chars = html.chars().count();
                body_text.is_some_and(raw_text_has_configured_banner)
                    && plain_chars <= policy.plain_stub_max_chars
                    && html_chars >= policy.html_min_chars
                    && (html_chars as f64)
                        >= (plain_chars.max(1) as f64 * policy.html_to_plain_ratio)
            };
            if should_use_html {
                Some((cleaned_subject, html, SemanticBodySource::HtmlFallback))
            } else {
                Some((cleaned_subject, plain, SemanticBodySource::PlainText))
            }
        }
        (Some(plain), None) => Some((cleaned_subject, plain, SemanticBodySource::PlainText)),
        (None, None) => None,
    }
}

/// The production body selector shared by audits and runtime analysis.
/// Offsets in semantic facts refer to this exact projection, including its
/// quote markers. Missing source bytes are returned as explicit coverage.
pub struct SemanticBodyProjection {
    pub subject: Option<String>,
    pub body: String,
    pub source_part: SemanticSourcePart,
    pub coverage_reasons: Vec<String>,
    pub original_body_bytes: usize,
    pub alternatives: Vec<SemanticAlternateProjection>,
    pub(super) source: SemanticBodySource,
}

impl SemanticBodyProjection {
    /// A message without a text body. Offsets refer to the empty plain-text
    /// body; the subject and attachment sources carry the analyzed text.
    pub(super) fn empty(subject: Option<String>) -> Self {
        Self {
            subject,
            body: String::new(),
            source_part: SemanticSourcePart::PlainText,
            coverage_reasons: Vec::new(),
            original_body_bytes: 0,
            alternatives: Vec::new(),
            source: SemanticBodySource::Empty,
        }
    }
}

pub struct SemanticAlternateProjection {
    pub body: String,
    pub source_part: SemanticSourcePart,
}

pub fn select_semantic_projection(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> Option<SemanticBodyProjection> {
    select_semantic_projection_with_data(subject, body_text, body_html, &compiled_semantic_data())
}

pub(super) fn select_semantic_projection_with_data(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
    data: &CompiledSemanticData,
) -> Option<SemanticBodyProjection> {
    let mut coverage_reasons = Vec::new();
    let mut bounded = |text: &str, limit: usize, source: &str| {
        if text.len() > limit {
            coverage_reasons.push(format!(
                "semantic {source} projection retained at most {limit} of {} source bytes",
                text.len()
            ));
        }
        floor_char_boundary(text, limit)
    };
    let subject = subject.map(|text| &text[..bounded(text, 8192, "subject")]);
    let body_text_bounded =
        body_text.map(|text| &text[..bounded(text, SEMANTIC_BODY_MAX_BYTES, "plain_text")]);
    let body_html_bounded =
        body_html.map(|text| &text[..bounded(text, SEMANTIC_BODY_MAX_BYTES, "html")]);
    let (subject, mut body, source) =
        select_semantic_body_bounded(subject, body_text_bounded, body_html_bounded, data)?;
    if body.len() > SEMANTIC_BODY_MAX_BYTES {
        let end = floor_char_boundary(&body, SEMANTIC_BODY_MAX_BYTES);
        body.truncate(end);
        coverage_reasons.push("semantic text projection exceeded its byte budget".to_string());
    }
    let (source_part, original_body_bytes) = match source {
        SemanticBodySource::PlainText => {
            (SemanticSourcePart::PlainText, body_text.map_or(0, str::len))
        }
        SemanticBodySource::HtmlFallback => {
            (SemanticSourcePart::Html, body_html.map_or(0, str::len))
        }
        SemanticBodySource::Empty => (SemanticSourcePart::PlainText, 0),
    };
    let alternate = match source {
        SemanticBodySource::PlainText => body_html_bounded.map(|html| {
            (
                sanitize_semantic_inputs(
                    None,
                    &semantic_text_projection_with_data(html, SemanticSourcePart::Html, data),
                )
                .1,
                SemanticSourcePart::Html,
            )
        }),
        SemanticBodySource::HtmlFallback => body_text_bounded
            .filter(|text| !looks_like_raw_mime_container_text(text))
            .map(|text| {
                (
                    sanitize_semantic_inputs(None, text).1,
                    SemanticSourcePart::PlainText,
                )
            }),
        SemanticBodySource::Empty => None,
    };
    let alternatives = alternate
        .filter(|(text, _)| !text.trim().is_empty() && text.trim() != body.trim())
        .map(|(mut text, source_part)| {
            if text.len() > SEMANTIC_BODY_MAX_BYTES {
                text.truncate(floor_char_boundary(&text, SEMANTIC_BODY_MAX_BYTES));
                coverage_reasons
                    .push("semantic alternate projection exceeded its byte budget".to_string());
            }
            SemanticAlternateProjection {
                body: text,
                source_part,
            }
        })
        .into_iter()
        .collect();
    Some(SemanticBodyProjection {
        subject,
        body,
        source_part,
        coverage_reasons,
        original_body_bytes,
        alternatives,
        source,
    })
}

#[cfg(test)]
pub(super) fn select_semantic_body(
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
) -> Option<(Option<String>, String, SemanticBodySource)> {
    select_semantic_projection(subject, body_text, body_html)
        .map(|projection| (projection.subject, projection.body, projection.source))
}
