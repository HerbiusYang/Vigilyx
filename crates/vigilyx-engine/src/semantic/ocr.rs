//! Bounded OCR request and response adaptation to local semantic facts.

use vigilyx_core::security::{SemanticCoverageStatus, SemanticSourcePart};

use crate::ai::remote::{VisualOcrRequest, VisualOcrResponse};

use super::budget::{SEMANTIC_BODY_MAX_BYTES, SemanticCpuBudget};
use super::compiled::CompiledSemanticData;
use super::context::extract_semantic_context_with_data;
use super::policy::evaluate_semantic_scenarios_with_data;
use super::text::floor_char_boundary;

pub(super) fn bounded_visual_ocr_request(
    session: &vigilyx_core::models::EmailSession,
) -> (Option<VisualOcrRequest>, bool) {
    if session
        .content
        .body_html
        .as_ref()
        .is_some_and(|html| html.len() > SEMANTIC_BODY_MAX_BYTES)
    {
        // The OCR builder scans source HTML for references. Do not give it a
        // complete oversized source after the semantic projection was bounded.
        return (None, true);
    }
    (
        crate::modules::visual_ocr::build_visual_ocr_request(session),
        false,
    )
}

#[cfg(test)]
pub(super) fn bounded_visual_ocr_semantics(
    session: &vigilyx_core::models::EmailSession,
    response: VisualOcrResponse,
    budget: &SemanticCpuBudget,
) -> (serde_json::Value, serde_json::Value, Vec<String>) {
    bounded_visual_ocr_semantics_with_data(
        session,
        response,
        budget,
        &super::compiled::compiled_semantic_data(),
    )
}

pub(super) fn bounded_visual_ocr_semantics_with_data(
    session: &vigilyx_core::models::EmailSession,
    mut response: VisualOcrResponse,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> (serde_json::Value, serde_json::Value, Vec<String>) {
    let mut coverage_reasons = Vec::new();
    if response.results.len() > crate::modules::visual_ocr::MAX_VISUAL_OCR_IMAGES {
        coverage_reasons
            .push("visual OCR response exceeded the three-source inspection budget".to_string());
        response
            .results
            .truncate(crate::modules::visual_ocr::MAX_VISUAL_OCR_IMAGES);
        response.coverage_limited = true;
    }
    if response.coverage_limited
        || response
            .results
            .iter()
            .any(|result| !matches!(result.status.as_str(), "ok" | "empty"))
    {
        coverage_reasons.push("visual OCR returned incomplete image coverage".to_string());
    }
    // Bound every retained source before any early budget exit or serialization.
    for result in &mut response.results {
        if result.text.len() > SEMANTIC_BODY_MAX_BYTES {
            result
                .text
                .truncate(floor_char_boundary(&result.text, SEMANTIC_BODY_MAX_BYTES));
            response.coverage_limited = true;
            coverage_reasons
                .push("visual OCR text exceeded the bounded 512 KiB inspection budget".to_string());
        }
    }
    let mut semantic_sources = Vec::new();
    for result in &response.results {
        if result.status != "ok" || result.text.trim().is_empty() {
            continue;
        }
        if budget.exhausted() {
            coverage_reasons
                .push("visual OCR semantic inspection exceeded its wall-clock budget".to_string());
            response.coverage_limited = true;
            break;
        }
        let context = extract_semantic_context_with_data(
            session,
            &result.text,
            SemanticSourcePart::Ocr,
            data,
        );
        if context.coverage != SemanticCoverageStatus::Complete {
            response.coverage_limited = true;
            coverage_reasons.push(context.coverage_reason.clone().unwrap_or_else(|| {
                "visual OCR semantic context inspection was incomplete".to_string()
            }));
        }
        let scenarios = evaluate_semantic_scenarios_with_data(&context, data);
        semantic_sources.push(serde_json::json!({
            "source_id": result.source_id,
            "confidence": result.confidence,
            "semantic_context": context,
            "semantic_scenarios": scenarios,
        }));
    }
    (
        serde_json::to_value(response).unwrap_or_default(),
        serde_json::json!(semantic_sources),
        coverage_reasons,
    )
}
