//! A borrowed projection that owns the coordinate space used by local relations.

use vigilyx_core::security::{SemanticClaim, SemanticSourcePart, SemanticSpan};

#[derive(Clone, Copy)]
pub(super) struct SemanticSource<'a> {
    pub(super) text: &'a str,
    pub(super) part: SemanticSourcePart,
}

/// Position index with original claim ordinals retained for deterministic
/// first-match selection. No textual or semantic qualification is inferred.
pub(super) struct ClaimWindowIndex {
    entries: Vec<(usize, SemanticSpan)>,
    prefix_max_end: Vec<usize>,
}

impl ClaimWindowIndex {
    pub(super) fn new(claims: impl Iterator<Item = (usize, SemanticSpan)>) -> Self {
        let mut entries = claims.collect::<Vec<_>>();
        entries.sort_by_key(|(_, span)| span.start_byte);
        let mut maximum = 0;
        let prefix_max_end = entries
            .iter()
            .map(|(_, span)| {
                maximum = maximum.max(span.end_byte);
                maximum
            })
            .collect();
        Self {
            entries,
            prefix_max_end,
        }
    }

    pub(super) fn within_envelope(&self, span: SemanticSpan, limit: usize) -> Vec<usize> {
        if span.end_byte.saturating_sub(span.start_byte) > limit {
            return Vec::new();
        }
        let lower = span.end_byte.saturating_sub(limit);
        let upper = span.start_byte.saturating_add(limit);
        let first = self
            .entries
            .partition_point(|(_, other)| other.start_byte < lower);
        let last = self
            .entries
            .partition_point(|(_, other)| other.start_byte <= upper);
        let mut indices = self.entries[first..last]
            .iter()
            .filter(|(_, other)| other.end_byte <= upper)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }

    pub(super) fn within_gap(&self, span: SemanticSpan, limit: usize) -> Vec<usize> {
        let lower = span.start_byte.saturating_sub(limit);
        let upper = span.end_byte.saturating_add(limit);
        let last = self
            .entries
            .partition_point(|(_, other)| other.start_byte <= upper);
        let first = self.prefix_max_end[..last].partition_point(|end| *end < lower);
        let mut indices = self.entries[first..last]
            .iter()
            .filter(|(_, other)| other.end_byte >= lower)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }
}

impl<'a> SemanticSource<'a> {
    pub(super) fn new(text: &'a str, part: SemanticSourcePart) -> Self {
        Self { text, part }
    }

    /// Header facts may coexist with body facts in an observation context,
    /// but their offsets must never be interpreted as body coordinates.
    pub(super) fn claim_text(self, claim: &SemanticClaim) -> Option<&'a str> {
        if claim.source_part != self.part || claim.span.start_byte >= claim.span.end_byte {
            return None;
        }
        self.text.get(claim.span.start_byte..claim.span.end_byte)
    }
}

/// Check a qualified claim against its original source before accepting AI corroboration.
pub(super) fn sampled_claim_present(
    source: SemanticSource<'_>,
    sampled: &str,
    claim: &SemanticClaim,
) -> bool {
    source
        .claim_text(claim)
        .is_some_and(|span| !span.is_empty() && sampled.contains(span))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_candidates_preserve_original_order_and_final_relation_envelopes() {
        let index = ClaimWindowIndex::new(
            [
                (
                    8,
                    SemanticSpan {
                        start_byte: 70,
                        end_byte: 90,
                    },
                ),
                (
                    2,
                    SemanticSpan {
                        start_byte: 0,
                        end_byte: 20,
                    },
                ),
                (
                    5,
                    SemanticSpan {
                        start_byte: 40,
                        end_byte: 55,
                    },
                ),
                (
                    1,
                    SemanticSpan {
                        start_byte: 0,
                        end_byte: 200,
                    },
                ),
            ]
            .into_iter(),
        );
        let query = SemanticSpan {
            start_byte: 50,
            end_byte: 60,
        };
        assert_eq!(index.within_envelope(query, 50), vec![5, 8]);
        assert_eq!(index.within_gap(query, 5), vec![1, 5]);
    }
}
