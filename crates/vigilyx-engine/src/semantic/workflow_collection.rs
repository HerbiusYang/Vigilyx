//! A collection argument may span coordinated clauses or an explicit field
//! list. Sentence, actor and source boundaries still delimit its authority.

use vigilyx_core::security::{SemanticSourcePart, SemanticTargetRole};

use super::{
    Fact, FinancialPinPolicy, action_any, eligible, financial_pin_present, has, recipient_action,
};
use crate::semantic::source::SemanticSource;
use crate::semantic::text::semantic_phrase_at;

fn independent_nominal_state(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    policy
        .pin_terms
        .iter()
        .chain(&policy.identity_terms)
        .chain(&policy.otp_terms)
        .chain(&policy.form_terms)
        .chain(&policy.remote_channel_terms)
        .any(|noun| {
            fact.text.match_indices(noun.as_str()).any(|(at, _)| {
                if !semantic_phrase_at(&fact.text, noun, at) {
                    return false;
                }
                let after = fact.text[at + noun.len()..].trim_start();
                policy.nominal_state_predicates.iter().any(|state| {
                    after.starts_with(state.as_str()) && semantic_phrase_at(after, state, 0)
                })
            })
        })
}

fn argument_modifiers(mut text: &str, policy: &FinancialPinPolicy) -> bool {
    while !text.is_empty() {
        text = text.trim_start();
        if text.is_empty() {
            return true;
        }
        let Some(modifier) = policy
            .target_argument_modifiers
            .iter()
            .filter(|s| text.starts_with(s.as_str()) && semantic_phrase_at(text, s, 0))
            .max_by_key(|s| s.len())
        else {
            return false;
        };
        text = &text[modifier.len()..];
    }
    true
}

/// A target is an argument of an actual input predicate or an explicit
/// destination complement. Merely mentioning “the form” supplies no target.
pub(super) fn bound_target(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    policy
        .form_terms
        .iter()
        .chain(&policy.remote_channel_terms)
        .any(|noun| {
            fact.text.match_indices(noun.as_str()).any(|(at, _)| {
                if !semantic_phrase_at(&fact.text, noun, at) {
                    return false;
                }
                let before = fact.text[..at].trim_end();
                if policy.target_prepositions.iter().any(|prefix| {
                    before.ends_with(prefix.as_str())
                        && semantic_phrase_at(before, prefix, before.len() - prefix.len())
                }) {
                    return true;
                }
                // The risk layer may explicitly enable a preposed target:
                // "in [grant claim] form upload ...". The legacy policy has
                // an empty list and retains its existing admission grammar.
                let after = fact.text[at + noun.len()..].trim_start();
                let after_location = after
                    .strip_prefix(['中', '内', '內', '里', '裡', '上'])
                    .map(str::trim_start);
                if recipient_action(fact.claim)
                    && policy.input_actions.iter().any(|verb| {
                        std::iter::once(after)
                            .chain(after_location)
                            .any(|argument| {
                                argument.starts_with(verb.as_str())
                                    && semantic_phrase_at(argument, verb, 0)
                            })
                    })
                    && policy.preposed_target_prepositions.iter().any(|prep| {
                        before.match_indices(prep.as_str()).any(|(start, _)| {
                            semantic_phrase_at(before, prep, start)
                                && before.len().saturating_sub(start + prep.len()) <= 128
                                && argument_modifiers(&before[start + prep.len()..], policy)
                        })
                    })
                {
                    return true;
                }
                recipient_action(fact.claim)
                    && policy.input_actions.iter().any(|action| {
                        before.match_indices(action.as_str()).any(|(verb, _)| {
                            semantic_phrase_at(before, action, verb)
                                && at.saturating_sub(verb + action.len()) <= 128
                                && argument_modifiers(&before[verb + action.len()..], policy)
                        })
                    })
            })
        })
}

fn argument_fragment(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    !independent_nominal_state(fact, policy)
        && (!(has(&fact.text, &policy.form_terms) || has(&fact.text, &policy.remote_channel_terms))
            || bound_target(fact, policy))
}

fn strong_end(text: &str) -> bool {
    text.trim_end()
        .ends_with(['.', '。', '!', '！', '?', '？', ';', '；'])
}

fn separated(source: SemanticSource<'_>, left: &Fact<'_>, right: &Fact<'_>) -> bool {
    if strong_end(&left.text)
        || right
            .text
            .trim_start()
            .starts_with([';', '；', '。', '!', '！', '?', '？'])
    {
        return true;
    }
    let Some(gap) = source
        .text
        .get(left.claim.span.end_byte..right.claim.span.start_byte)
    else {
        return true;
    };
    let mut blank = false;
    for line in gap.lines() {
        let trimmed = line.trim();
        let divider = trimmed.chars().filter(|c| !c.is_whitespace()).count() >= 3
            && trimmed
                .chars()
                .all(|c| c.is_whitespace() || matches!(c, '-' | '*' | '_' | '='));
        if divider
            || trimmed.starts_with('#')
            || trimmed.starts_with("**")
            || trimmed.starts_with("__")
        {
            return true;
        }
        if line.trim().is_empty() {
            if blank {
                return true;
            }
            blank = true;
        } else {
            blank = false;
        }
    }
    gap.contains(['.', ';', '；', '。', '!', '！', '?', '？'])
}

pub(super) fn field_or_collection(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    if !eligible(fact.claim)
        || !argument_fragment(fact, policy)
        || matches!(
            fact.claim.target_role,
            SemanticTargetRole::SenderSelf | SemanticTargetRole::NamedThirdParty
        )
        || has(&fact.text, &policy.separate_collection_terms)
    {
        return false;
    }
    let field = financial_pin_present(&fact.text, policy)
        || has(&fact.text, &policy.identity_terms)
        || has(&fact.text, &policy.otp_terms);
    let target = has(&fact.text, &policy.form_terms);
    if fact.claim.actions.is_empty() {
        return field || target;
    }
    if recipient_action(fact.claim) {
        return fact.claim.actions.iter().all(|a| {
            policy.input_actions.contains(a) || policy.field_descriptor_actions.contains(a)
        });
    }
    // “the OTP you just received into this form” is a noun argument with
    // an attributive predicate. It cannot introduce an independently acting
    // customer, system or sender.
    (field || target)
        && fact.claim.actions.iter().all(|a| {
            policy.input_actions.contains(a) || policy.field_descriptor_actions.contains(a)
        })
}

/// Return the same-sentence coordination rooted at a real recipient input
/// request. The form target may be a later argument (“... into this form”).
pub(super) fn coordinated<'facts, 'context>(
    source: SemanticSource<'_>,
    facts: &'facts [Fact<'context>],
    anchor: usize,
    policy: &FinancialPinPolicy,
) -> Vec<&'facts Fact<'context>> {
    let first = &facts[anchor];
    let mut result = vec![first];
    for next in &facts[anchor + 1..] {
        let previous = *result.last().expect("collection has its anchor");
        if next
            .claim
            .span
            .end_byte
            .saturating_sub(first.claim.span.start_byte)
            > policy.max_form_bytes
            || next.claim.source_block_id.is_none()
            || (source.part != SemanticSourcePart::PlainText
                && next.claim.source_block_id != first.claim.source_block_id)
            || separated(source, previous, next)
            || !field_or_collection(next, policy)
        {
            break;
        }
        result.push(next);
    }
    result
}

fn physical_collection_parent(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    // Inspect only the actual parent request. “ATM PIN” in a field is not
    // a physical collection target. A location must have a local locative
    // preposition; the sender's “branch counter team” identity is not one.
    policy.physical_collection_targets.iter().any(|target| {
        fact.text.match_indices(target.as_str()).any(|(at, _)| {
            semantic_phrase_at(&fact.text, target, at)
                && ["到", "在", "至", "前往", "at", "to", "in", "visit"]
                    .iter()
                    .any(|preposition| {
                        fact.text[..at]
                            .match_indices(preposition)
                            .any(|(start, _)| {
                                let end = start + preposition.len();
                                semantic_phrase_at(&fact.text, preposition, start)
                                    && at.saturating_sub(end) <= 24
                                    && !fact.text[end..at].contains([
                                        ',', '，', ';', '；', ':', '：', '\n', '。', '.', '!',
                                        '！', '?', '？',
                                    ])
                            })
                    })
        })
    })
}

pub(super) fn implicit_remote_list_header(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    eligible(fact.claim)
        && recipient_action(fact.claim)
        && action_any(fact.claim, &policy.implicit_remote_list_actions)
        && fact.text.trim_end().ends_with([':', '：'])
        && !physical_collection_parent(fact, policy)
}

pub(super) fn can_start(fact: &Fact<'_>, policy: &FinancialPinPolicy) -> bool {
    recipient_action(fact.claim)
        && argument_fragment(fact, policy)
        && action_any(fact.claim, &policy.input_actions)
        && (has(&fact.text, &policy.form_terms)
            || financial_pin_present(&fact.text, policy)
            || has(&fact.text, &policy.identity_terms)
            || has(&fact.text, &policy.otp_terms))
}
