//! Shared contracts for the non-additive relational V2 shadow path.
//!
//! These types intentionally contain no fusion score.  They preserve module
//! observations and describe whether a named, scoped relation has a complete
//! witness, a counter-witness, both, or neither.

use serde::{Deserialize, Serialize};

use super::ThreatLevel;

const MAX_CATEGORIES: usize = 256;
const MAX_CATEGORY_BYTES: usize = 256;

/// Bounded facts captured before a legacy module drops sub-threshold details.
/// The legacy score is deliberately not copied: it is not an input to the
/// relational decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservationSnapshot {
    pub schema_version: u8,
    pub categories: Vec<String>,
    pub category_count: usize,
    pub evidence_count: usize,
    pub truncated: bool,
}

impl ObservationSnapshot {
    pub fn capture(categories: &[String], evidence_count: usize) -> Self {
        let mut unique = categories.to_vec();
        unique.sort();
        unique.dedup();
        let category_count = unique.len();
        let mut truncated = category_count > MAX_CATEGORIES;
        unique.retain(|category| {
            let valid = !category.is_empty() && category.len() <= MAX_CATEGORY_BYTES;
            truncated |= !valid;
            valid
        });
        if unique.len() > MAX_CATEGORIES {
            unique.truncate(MAX_CATEGORIES);
            truncated = true;
        }
        Self {
            schema_version: 1,
            categories: unique,
            category_count,
            evidence_count,
            truncated,
        }
    }
}

/// JSON Pointer into a module result. Raw message bodies, URLs, and secrets
/// are kept in their owning module and are not copied into relation output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelationalEvidenceRef {
    pub module_id: String,
    pub pointer: String,
}

/// The complete evidence inventory for one module result. `original_level` is
/// an inherited legacy claim and is never treated as an independently proven
/// attack relation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetainedModuleEvidence {
    pub result_key: String,
    pub module_id: String,
    pub original_level: ThreatLevel,
    pub categories: Vec<String>,
    pub snapshot_categories: Vec<String>,
    pub evidence_count: usize,
    pub snapshot_evidence_count: Option<usize>,
    pub observations: Vec<RelationalEvidenceRef>,
    pub incomplete: bool,
}

/// A legacy alert that has not yet received a relational adapter. It remains
/// visible and traceable without being relabeled as a relation-supported
/// attack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LegacyAlertReference {
    pub result_key: String,
    pub module_id: String,
    pub original_level: ThreatLevel,
    pub categories: Vec<String>,
    pub evidence_refs: Vec<RelationalEvidenceRef>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationState {
    Supported,
    Refuted,
    Unresolved,
    Conflicted,
}

/// One local attack hypothesis. Severity is present only for a supported,
/// named relation; there is no probability, sum, or global confidence here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationDecision {
    pub relation_id: String,
    pub candidate_key: String,
    pub state: RelationState,
    pub candidate_severity: Option<ThreatLevel>,
    pub evidence_refs: Vec<RelationalEvidenceRef>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationalAssessment {
    pub model: String,
    pub model_version: u32,
    pub policy_version: Option<u32>,
    pub policy_sha256: Option<String>,
    /// False until an independent calibration and holdout process validates a
    /// probability interpretation. Relation severity is not a probability.
    pub calibrated: bool,
    pub modules: Vec<RetainedModuleEvidence>,
    pub legacy_alerts: Vec<LegacyAlertReference>,
    pub relations: Vec<RelationDecision>,
    /// Missing adapters, coverage gaps, and resource limits never imply
    /// safety.
    pub gaps: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_keeps_weak_categories_without_a_score() {
        let snapshot = ObservationSnapshot::capture(&["tiny".into(), "tiny".into()], 2);
        assert_eq!(snapshot.categories, ["tiny"]);
        assert_eq!(snapshot.evidence_count, 2);
        assert!(!snapshot.truncated);
    }

    #[test]
    fn snapshot_reports_invalid_and_over_budget_categories() {
        let categories = (0..300)
            .map(|index| format!("fact_{index}"))
            .collect::<Vec<_>>();
        let snapshot = ObservationSnapshot::capture(&categories, 300);
        assert_eq!(snapshot.categories.len(), MAX_CATEGORIES);
        assert_eq!(snapshot.category_count, 300);
        assert!(snapshot.truncated);
        assert!(serde_json::to_string(&snapshot).is_ok());
    }
}
