//! AI service integration, separate from deterministic local semantic analysis.

pub(crate) mod nlp;
pub mod remote;
mod service;

pub(crate) use service::build_ai_remote;

#[cfg(test)]
mod tests;
