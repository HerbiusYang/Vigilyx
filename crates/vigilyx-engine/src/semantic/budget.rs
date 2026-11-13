//! Existing semantic input limits and cooperative CPU budget.

use std::time::{Duration, Instant};

/// Bounds apply before HTML parsing, normalization, or statistical allocation.
/// A prefix is kept rather than joining unrelated sampled spans into a claim.
pub(super) const SEMANTIC_BODY_MAX_BYTES: usize = 512 * 1024;
pub(super) const SEMANTIC_CPU_BUDGET: Duration = Duration::from_secs(2);
/// Local parsing of OCR text after its network response; kept short so the
/// module stays within its timeout after the shared budget has been spent.
pub(super) const SEMANTIC_OCR_CPU_BUDGET: Duration = Duration::from_secs(1);
pub(super) const SEMANTIC_INSPECTION_LIMITED: &str = "semantic_inspection_limited";

pub(super) struct SemanticCpuBudget {
    pub(super) deadline: Instant,
}

impl SemanticCpuBudget {
    pub(super) fn new() -> Self {
        Self {
            deadline: Instant::now() + SEMANTIC_CPU_BUDGET,
        }
    }

    pub(super) fn exhausted(&self) -> bool {
        Instant::now() >= self.deadline
    }
}
