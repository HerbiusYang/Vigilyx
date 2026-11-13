//! Registry-backed local lexical, attribution, and reply-header guards.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use vigilyx_core::security::SemanticActionDestination;

use super::compiled::CompiledSemanticData;
use super::text::semantic_phrase_at;
use crate::modules::content_scan::normalize_text;

#[derive(Deserialize)]
pub(super) struct ReplyHeaders {
    sender: Vec<String>,
    date: Vec<String>,
    subject: Vec<String>,
    auxiliary: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct ContextGuards {
    marker_exclusions: HashMap<String, Vec<String>>,
    reminders: Vec<String>,
    conditional_markers: Vec<String>,
    non_refuting_conditions: Vec<String>,
    sender_destinations: Vec<String>,
    other_destinations: Vec<String>,
    recipient_destinations: Vec<String>,
    completed_prefixes: Vec<String>,
    report_topics: Vec<String>,
    report_headings: Vec<String>,
    reply_headers: ReplyHeaders,
    reply_attribution_prefixes: Vec<String>,
    reply_attribution_suffixes: Vec<String>,
    reply_header_window_lines: usize,
    /// "Do not ignore/delay" urges the action instead of refuting it.
    #[serde(default)]
    urgency_negated_verbs: Vec<String>,
    /// A negation after "otherwise/否则" states a consequence, not a refusal.
    #[serde(default)]
    consequence_connectors: Vec<String>,
    /// Speech or example frames that may introduce an inline quotation.
    #[serde(default)]
    inline_quote_frames: Vec<String>,
    /// Subject tokens that client replies/forwards add ("re:", "转发:").
    #[serde(default)]
    thread_subject_prefixes: Vec<String>,
    #[serde(default)]
    list_request_headings: Vec<String>,
    #[serde(default)]
    pub(super) list_request_max_items: usize,
    #[serde(default)]
    pub(super) list_request_max_bytes: usize,
    #[serde(default)]
    nominalized_action_subjects: Vec<String>,
    #[serde(default)]
    nominalized_state_predicates: Vec<String>,
    #[serde(default)]
    explicit_report_predicates: Vec<String>,
    #[serde(default)]
    explicit_report_subjects: Vec<String>,
    #[serde(default)]
    explicit_report_temporal_modifiers: Vec<String>,
    #[serde(default)]
    explicit_report_verbs: Vec<String>,
    #[serde(default)]
    negated_coordination_connectors: Vec<String>,
    #[serde(default)]
    negated_coordination_predicates: Vec<String>,
    #[serde(default)]
    anchored_reminder_prefixes: Vec<String>,
    #[serde(default)]
    enumerated_command_prefixes: Vec<String>,
    #[serde(default)]
    enumerated_action_prefixes: Vec<String>,
    #[serde(default)]
    enumerated_command_exclusions: Vec<String>,
    #[serde(default)]
    coordinated_attribution_connectors: Vec<String>,
    #[serde(default)]
    sender_fulfillment_prefixes: Vec<String>,
    #[serde(default)]
    sender_fulfillment_future_markers: Vec<String>,
    #[serde(default)]
    sender_fulfillment_predicates: Vec<String>,
}

fn normalize(value: &str) -> String {
    normalize_text(&value.to_lowercase())
}

/// Matching view for an already separated action clause. Commas and
/// semicolons belong to the preceding grammatical boundary, not a command
/// prefix. Colons, quote glyphs, reply markers, and framing prose remain
/// intact: this helper never grants or removes quotation/report authority.
pub(super) fn clause_content(text: &str) -> &str {
    text.trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, ',' | '，' | ';' | '；')
    })
}

pub(super) fn contains(text: &str, marker: &str) -> bool {
    !marker.is_empty()
        && text
            .match_indices(marker)
            .any(|(offset, _)| semantic_phrase_at(text, marker, offset))
}

fn any(text: &str, markers: &[String]) -> bool {
    markers.iter().any(|marker| contains(text, marker))
}

/// Remove surrounding whitespace and leading client quote markers.
pub(super) fn strip_quote_prefix(line: &str) -> &str {
    line.trim()
        .trim_start_matches(|character: char| character == '>' || character.is_whitespace())
}

pub(super) fn context_guards(data: &CompiledSemanticData) -> Arc<Option<ContextGuards>> {
    data.cached("semantic_context_guard_policy_v1", |registry| {
        let mut value = registry
            .get_structured("semantic_context_guard_policy_v1")?
            .clone();
        fn normalize_values(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(text) => *text = normalize(text),
                serde_json::Value::Array(items) => items.iter_mut().for_each(normalize_values),
                serde_json::Value::Object(items) => items.values_mut().for_each(normalize_values),
                _ => {}
            }
        }
        normalize_values(&mut value);
        let policy: ContextGuards = serde_json::from_value(value).ok()?;
        if !(3..=16).contains(&policy.reply_header_window_lines)
            || policy.marker_exclusions.is_empty()
            || policy.reminders.is_empty()
            || policy.reply_headers.sender.is_empty()
            || policy.reply_headers.date.is_empty()
            || policy.reply_headers.subject.is_empty()
        {
            return None;
        }
        Some(policy)
    })
}

impl ContextGuards {
    pub(super) fn request_list_heading(&self, text: &str) -> bool {
        let text = normalize(text);
        self.list_request_max_items > 0
            && self.list_request_max_items <= 32
            && (256..=8192).contains(&self.list_request_max_bytes)
            && text.trim_end().ends_with([':', '：'])
            && any(&text, &self.list_request_headings)
    }

    pub(super) fn framed_report_heading(&self, text: &str) -> bool {
        let text = normalize(text);
        let text = text.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '【' | '['));
        self.report_headings.iter().any(|heading| {
            text.strip_prefix(heading.as_str()).is_some_and(|rest| {
                rest.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '】' | ']'))
                    .starts_with([':', '：'])
            })
        })
    }

    pub(super) fn marker_allowed(&self, text: &str, marker: &str, offset: usize) -> bool {
        self.marker_exclusions.get(marker).is_none_or(|exclusions| {
            !exclusions.iter().any(|word| {
                text.match_indices(word.as_str()).any(|(start, _)| {
                    start <= offset && offset + marker.len() <= start + word.len()
                })
            })
        })
    }

    pub(super) fn is_reminder(&self, text: &str) -> bool {
        let text = clause_content(text);
        any(text, &self.reminders)
            || self
                .anchored_reminder_prefixes
                .iter()
                .any(|prefix| text.starts_with(prefix.as_str()))
    }

    pub(super) fn enumerated_action(&self, text: &str, actions: &[String]) -> bool {
        self.enumerated_action_prefixes.iter().any(|prefix| {
            text.starts_with(prefix.as_str()) && actions.iter().any(|action| action == prefix)
        })
    }

    pub(super) fn enumerated_command(&self, text: &str) -> bool {
        self.enumerated_command_prefixes
            .iter()
            .any(|prefix| text.starts_with(prefix.as_str()))
            && !self
                .enumerated_command_exclusions
                .iter()
                .any(|prefix| text.starts_with(prefix.as_str()))
    }

    /// This view is only for grammatical scope across adjacent clauses of
    /// the same sentence. It cannot jump a comma, semicolon, quote, or line.
    pub(super) fn coordinated_complement<'a>(&self, text: &'a str) -> Option<&'a str> {
        let text = text.trim_start();
        self.coordinated_attribution_connectors
            .iter()
            .filter_map(|connector| {
                text.strip_prefix(connector.as_str())
                    .filter(|_| semantic_phrase_at(text, connector, 0))
            })
            .min_by_key(|rest| rest.len())
            .map(str::trim_start)
    }

    /// A local future fulfillment promise is the sender's own notice,
    /// not the recipient's next action. Require a configured prefix and a
    /// future marker before a specific fulfillment predicate; the caller
    /// excludes independently requested/instructed clauses.
    pub(super) fn sender_fulfillment(&self, text: &str) -> bool {
        let text = text.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '，' | ';' | '；')
        });
        self.sender_fulfillment_prefixes
            .iter()
            .any(|prefix| text.starts_with(prefix.as_str()))
            && self.sender_fulfillment_future_markers.iter().any(|future| {
                text.match_indices(future.as_str()).any(|(start, _)| {
                    semantic_phrase_at(text, future, start)
                        && self.sender_fulfillment_predicates.iter().any(|predicate| {
                            text[start + future.len()..]
                                .match_indices(predicate.as_str())
                                .any(|(gap, _)| {
                                    gap <= 96
                                        && semantic_phrase_at(
                                            text,
                                            predicate,
                                            start + future.len() + gap,
                                        )
                                })
                        })
                })
            })
    }

    /// An adjacent “or require” is a coordinated predicate of a local
    /// negation, rather than a fresh standalone recipient request. Explicit
    /// request openers such as 请/please are deliberately not in this list.
    pub(super) fn negated_coordination(&self, text: &str, request: usize, end: usize) -> bool {
        self.negated_coordination_predicates
            .iter()
            .any(|predicate| text.get(request..end) == Some(predicate.as_str()))
            && self
                .negated_coordination_connectors
                .iter()
                .any(|connector| {
                    let before = text[..request].trim_end();
                    before
                        .strip_suffix(connector.as_str())
                        .is_some_and(|prefix| {
                            let start = prefix.len();
                            semantic_phrase_at(before, connector, start)
                        })
                })
    }

    pub(super) fn is_conditional_marker(&self, marker: &str) -> bool {
        self.conditional_markers.iter().any(|value| value == marker)
    }

    pub(super) fn negates(&self, text: &str, marker: &str) -> bool {
        !self.is_conditional_marker(marker)
            && text.match_indices(marker).any(|(offset, _)| {
                semantic_phrase_at(text, marker, offset)
                    && !self.reminders.iter().any(|reminder| {
                        text.match_indices(reminder.as_str()).any(|(start, _)| {
                            start <= offset && offset + marker.len() <= start + reminder.len()
                        })
                    })
            })
    }

    /// The marker is immediately followed by a configured urgency verb
    /// ("请勿忽略", "do not delay"), so the clause urges rather than refuses.
    pub(super) fn urgency_negation(&self, text: &str, marker: &str) -> bool {
        text.match_indices(marker).any(|(offset, _)| {
            semantic_phrase_at(text, marker, offset)
                && text
                    .get(offset + marker.len()..)
                    .map(str::trim_start)
                    .is_some_and(|rest| {
                        self.urgency_negated_verbs.iter().any(|verb| {
                            rest.starts_with(verb.as_str()) && semantic_phrase_at(rest, verb, 0)
                        })
                    })
        })
    }

    /// Every occurrence of the marker follows a consequence connector in the
    /// same clause ("...否则您将无法登录", "...or you will never regain access").
    pub(super) fn consequence_negation(&self, text: &str, marker: &str) -> bool {
        let mut occurrences = text
            .match_indices(marker)
            .filter(|(offset, _)| semantic_phrase_at(text, marker, *offset))
            .peekable();
        occurrences.peek().is_some()
            && occurrences.all(|(offset, _)| {
                self.consequence_connectors.iter().any(|connector| {
                    text[..offset]
                        .match_indices(connector.as_str())
                        .any(|(start, _)| semantic_phrase_at(text, connector, start))
                })
            })
    }

    /// The text immediately before an inline quotation attributes or
    /// exemplifies it. Without a configured frame list, any visible framing
    /// text on the same line is required.
    pub(super) fn frames_inline_quote(&self, before: &str) -> bool {
        if self.inline_quote_frames.is_empty() {
            return before.chars().any(char::is_alphanumeric);
        }
        any(before, &self.inline_quote_frames)
    }

    /// The subject carries a client reply/forward token at a word start, for
    /// example "Re:", "[External] Fw:" or "回复：".
    pub(super) fn thread_subject(&self, subject: &str) -> bool {
        let subject = normalize(subject);
        subject
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '[' | ']' | '【' | '】')
            })
            .any(|token| {
                self.thread_subject_prefixes
                    .iter()
                    .any(|prefix| token.starts_with(prefix.as_str()))
            })
    }

    /// A normalized line (quote prefixes removed) starts with a reply sender header.
    pub(super) fn is_sender_header_line(&self, line: &str) -> bool {
        self.reply_headers
            .sender
            .iter()
            .any(|prefix| line.starts_with(prefix.as_str()))
    }

    pub(super) fn can_refute(&self, text: &str) -> bool {
        !self.is_reminder(text) && !any(text, &self.non_refuting_conditions)
    }

    pub(super) fn completed(&self, text: &str) -> bool {
        self.completed_prefixes
            .iter()
            .any(|prefix| text.starts_with(prefix.as_str()))
    }

    /// A verb phrase used as the subject of an explicit state description
    /// (“发送验证码给我的功能已经关闭”) is not a bare imperative. Require
    /// action → nominalized subject → state locally and in that order; the
    /// caller separately rejects this guard when a fresh request is present.
    pub(super) fn describes_nominalized_action_state(
        &self,
        text: &str,
        actions: &[(usize, usize)],
    ) -> bool {
        self.nominalized_action_subjects.iter().any(|subject| {
            text.match_indices(subject.as_str())
                .any(|(subject_start, _)| {
                    semantic_phrase_at(text, subject, subject_start)
                        && actions
                            .iter()
                            .any(|(_, end)| *end <= subject_start && subject_start - *end <= 96)
                        && self.nominalized_state_predicates.iter().any(|state| {
                            text[subject_start + subject.len()..]
                                .match_indices(state.as_str())
                                .any(|(gap, _)| {
                                    gap <= 48
                                        && semantic_phrase_at(
                                            text,
                                            state,
                                            subject_start + subject.len() + gap,
                                        )
                                        && !text[subject_start + subject.len()
                                            ..subject_start + subject.len() + gap]
                                            .contains([':', '：', ';', '；', '—', '–'])
                                })
                        })
                })
        })
    }

    pub(super) fn report(&self, text: &str, matched: &str) -> bool {
        if !self.report_topics.iter().any(|topic| topic == matched) {
            return true;
        }
        // A case/report heading requires a local structural delimiter.
        // A topic word inside an otherwise current request has no authority.
        let text = text.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '【' | '['));
        self.report_headings.iter().any(|heading| {
            text.strip_prefix(heading.as_str()).is_some_and(|rest| {
                rest.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '】' | ']'))
                    .starts_with([':', '：'])
            })
        })
    }

    /// A finished nominalized state statement can be followed immediately
    /// by a fresh imperative without punctuation. Only the local closing
    /// state qualifies; a state word elsewhere in the prefix cannot split it.
    pub(super) fn closes_nominalized_action_state(
        &self,
        text: &str,
        actions: &[(usize, usize)],
    ) -> bool {
        let text = text.trim_end();
        self.nominalized_state_predicates
            .iter()
            .any(|state| text.ends_with(state.as_str()))
            && self.describes_nominalized_action_state(text, actions)
    }

    /// A request word occurring only inside an explicit nominalized subject
    /// (e.g. “的要求”) is a noun in that state description. The caller must
    /// separately establish the action → subject → state relation and reject
    /// any fresh request/instruction elsewhere in the clause.
    pub(super) fn nominalized_subject_marker(&self, text: &str, marker: &str) -> bool {
        let mut occurrences = text
            .match_indices(marker)
            .filter(|(offset, _)| semantic_phrase_at(text, marker, *offset))
            .peekable();
        occurrences.peek().is_some()
            && occurrences.all(|(offset, _)| {
                self.nominalized_action_subjects.iter().any(|subject| {
                    text.match_indices(subject.as_str()).any(|(start, _)| {
                        start <= offset && offset + marker.len() <= start + subject.len()
                    })
                })
            })
    }

    /// A complete subject + reporting predicate owns its immediate action
    /// complement. An urgency adverb inside that complement does not turn
    /// “攻击者要求立即点击” into a request by the current sender.
    pub(super) fn explicit_report_prefix(&self, text: &str) -> Option<usize> {
        fn strip<'a>(text: &'a str, values: &[String]) -> Option<&'a str> {
            values
                .iter()
                .filter_map(|value| {
                    text.strip_prefix(value.as_str())
                        .filter(|_| semantic_phrase_at(text, value, 0))
                })
                .min_by_key(|rest| rest.len())
                .map(str::trim_start)
        }
        let mut rest = strip(text, &self.explicit_report_subjects)?;
        for _ in 0..2 {
            let Some(next) = strip(rest, &self.explicit_report_temporal_modifiers) else {
                break;
            };
            rest = next;
        }
        let rest = strip(rest, &self.explicit_report_verbs)?;
        Some(text.len() - rest.len())
    }

    pub(super) fn is_explicit_report_predicate(&self, marker: &str) -> bool {
        self.explicit_report_predicates
            .iter()
            .any(|predicate| predicate == marker)
            || self.explicit_report_prefix(marker) == Some(marker.len())
    }

    pub(super) fn destination(&self, text: &str) -> SemanticActionDestination {
        let mut matched = [
            (SemanticActionDestination::Sender, &self.sender_destinations),
            (SemanticActionDestination::Other, &self.other_destinations),
            (
                SemanticActionDestination::Recipient,
                &self.recipient_destinations,
            ),
        ]
        .into_iter()
        .filter_map(|(role, markers)| any(text, markers).then_some(role));
        let first = matched.next().unwrap_or_default();
        if matched.next().is_some() {
            SemanticActionDestination::Mixed
        } else {
            first
        }
    }

    /// A separator alone never opens quotation scope. Require either an
    /// attributed reply line or a contiguous sender/date/subject header block.
    pub(super) fn reply_headers(
        &self,
        body: &str,
        max_lines: usize,
        started: Instant,
        budget: Duration,
    ) -> (Vec<(usize, usize)>, bool) {
        let mut offset = 0;
        let mut lines = Vec::new();
        for raw in body.split_inclusive('\n').take(max_lines) {
            if started.elapsed() >= budget {
                return (Vec::new(), true);
            }
            // Client quote prefixes ("> On ... wrote:") do not hide the
            // attribution inside an HTML quote container or nested reply.
            lines.push((offset, raw.len(), normalize(strip_quote_prefix(raw))));
            offset += raw.len();
        }
        let mut boundaries = Vec::new();
        for (index, (start, size, line)) in lines.iter().enumerate() {
            if started.elapsed() >= budget {
                return (boundaries, true);
            }
            if self
                .reply_attribution_prefixes
                .iter()
                .any(|prefix| line.starts_with(prefix.as_str()))
                && self
                    .reply_attribution_suffixes
                    .iter()
                    .any(|suffix| line.ends_with(suffix.as_str()))
                && (line.contains('@') || line.chars().any(|c| c.is_ascii_digit()))
            {
                boundaries.push((*start, start + size));
                continue;
            }
            if !self
                .reply_headers
                .sender
                .iter()
                .any(|prefix| line.starts_with(prefix.as_str()))
            {
                continue;
            }
            let mut date = false;
            let mut subject = false;
            for (next, size, header) in lines
                .iter()
                .skip(index + 1)
                .take(self.reply_header_window_lines - 1)
            {
                if self
                    .reply_headers
                    .date
                    .iter()
                    .any(|prefix| header.starts_with(prefix.as_str()))
                {
                    date = true;
                } else if self
                    .reply_headers
                    .subject
                    .iter()
                    .any(|prefix| header.starts_with(prefix.as_str()))
                {
                    subject = true;
                } else if !header.is_empty()
                    && !self
                        .reply_headers
                        .auxiliary
                        .iter()
                        .any(|prefix| header.starts_with(prefix.as_str()))
                    && !header.chars().all(|c| matches!(c, '_' | '-' | '='))
                {
                    break;
                }
                if date && subject {
                    boundaries.push((*start, next + size));
                    break;
                }
            }
        }
        (boundaries, false)
    }
}
