//! Rust semantic analysis algorithms and their engine integration.

mod attachments;
mod attribution;
mod budget;
mod classifier;
mod compiled;
mod constructions;
mod context;
mod guards;
mod intent_coercion;
mod intent_economic;
mod intent_model;
mod intent_phishing;
mod intent_text;
mod language;
mod ocr;
mod policy;
mod projection;
mod relations;
mod result;
mod risk;
mod scan;
mod solicitation;
mod source;
mod statistics;
mod style;
mod text;
mod workflow;

pub use classifier::{
    TEXT_CLASSIFIER_CATEGORY, TEXT_CLASSIFIER_FEATURE_SPEC, TEXT_CLASSIFIER_LEXICON_SOURCES,
    text_classifier_feature_index,
};
pub use context::{
    extract_semantic_context, is_current_recipient_action, semantic_counter_context_qualifies,
    semantic_phrase_present, semantic_text_projection,
};
pub use intent_model::{INTENT_MODEL_CATEGORY, IntentModel};
pub use policy::evaluate_semantic_scenarios;
pub use projection::{
    SemanticAlternateProjection, SemanticBodyProjection, select_semantic_projection,
};
pub use scan::SemanticScanModule;

pub(crate) use context::{exclude_non_action_claims, semantic_text_projection_with_coverage};

#[cfg(test)]
mod attribution_regression_tests;
#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod relation_regression_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod zh_optimization_tests;
