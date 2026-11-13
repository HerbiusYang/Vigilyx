//! Local prose-style observations, independent of Python model inference.

use serde::Deserialize;

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::semantic_phrase_present;

/// Lightweight heuristic for AI/LLM-generated phishing prose.
///
/// Modern phishing campaigns increasingly use ChatGPT-class LLMs to draft
/// extremely polished, grammatically perfect copy. A handful of stylistic
/// fingerprints distinguish that prose from authentic human business mail:
///
/// * an unusually high density of long, multi-clause sentences;
/// * boilerplate "AI assistant" phrases ("I hope this email finds you well",
///   "I am reaching out regarding…", "please do not hesitate to…");
/// * over-frequent transitional connectives (for example, "furthermore" and "moreover");
/// * conspicuously low contraction usage in English (LLMs prefer "do not"
///   over "don't"), combined with formal register that does not match a
///   short, urgent context.
///
/// These signals are individually weak — many legitimate writers also write
/// formally. We therefore (a) require multiple independent fingerprints to
/// fire and (b) cap the contribution at 0.30 so the module degrades to a
/// soft signal rather than a hard verdict. Detection runs on **already
/// HTML-stripped body text** so layout markup does not pollute scoring.
#[derive(Deserialize)]
struct SemanticLlmStylePolicy {
    boilerplate: Vec<String>,
    connectives: Vec<String>,
    zh_connectives: Vec<String>,
    expanded_forms: Vec<String>,
    contracted_forms: Vec<String>,
}

fn llm_style_policy(data: &CompiledSemanticData) -> std::sync::Arc<Option<SemanticLlmStylePolicy>> {
    data.cached("semantic_llm_style_policy_v1", |registry| {
        registry
            .get_structured("semantic_llm_style_policy_v1")
            .cloned()
            .and_then(|value| serde_json::from_value::<SemanticLlmStylePolicy>(value).ok())
    })
}

/// Style is observation-only; a missing or malformed policy is a diagnostic,
/// never an inspection coverage gap.
pub(super) fn llm_style_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    llm_style_policy(data).is_none().then_some(
        "semantic LLM style policy (semantic_llm_style_policy_v1) is missing or malformed; style observation is disabled",
    )
}

/// Count configured phrase occurrences so that each byte range is counted at
/// most once: longer phrases claim their range first, and a shorter phrase
/// contained in (or overlapping) an already counted occurrence is ignored.
fn count_unique_occurrences(text: &str, phrases: &[String]) -> usize {
    let mut ordered = phrases
        .iter()
        .filter(|phrase| !phrase.is_empty())
        .collect::<Vec<_>>();
    ordered.sort_by_key(|phrase| std::cmp::Reverse(phrase.len()));
    let mut counted: Vec<(usize, usize)> = Vec::new();
    for phrase in ordered {
        for (start, _) in text.match_indices(phrase.as_str()) {
            let end = start + phrase.len();
            if counted
                .iter()
                .all(|(other_start, other_end)| end <= *other_start || *other_end <= start)
            {
                counted.push((start, end));
            }
        }
    }
    counted.len()
}

#[cfg(test)]
pub(super) fn detect_llm_generated_text(text: &str) -> (f64, Vec<&'static str>) {
    detect_llm_generated_text_with_budget(
        text,
        &SemanticCpuBudget::new(),
        &super::compiled::compiled_semantic_data(),
    )
    .unwrap_or_default()
}

pub(super) fn detect_llm_generated_text_with_budget(
    text: &str,
    budget: &SemanticCpuBudget,
    data: &CompiledSemanticData,
) -> Option<(f64, Vec<&'static str>)> {
    let mut hits: Vec<&'static str> = Vec::new();
    let trimmed = text.trim();
    if trimmed.chars().count() < 80 {
        // Too short to draw a stylistic conclusion.
        return Some((0.0, hits));
    }

    let lower = trimmed.to_lowercase();

    if budget.exhausted() {
        return None;
    }
    let policy = llm_style_policy(data);
    let Some(policy) = policy.as_ref() else {
        return Some((0.0, hits));
    };

    // Style vocabulary is versioned policy data, never attack authority.
    let mut boilerplate_count = 0;
    for phrase in &policy.boilerplate {
        if semantic_phrase_present(&lower, phrase) {
            boilerplate_count += 1;
        }
    }
    if boilerplate_count >= 2 {
        hits.push("multiple LLM-style boilerplate phrases");
    } else if boilerplate_count == 1 {
        hits.push("single LLM-style boilerplate phrase");
    }

    // 2. Transitional connective density (Latin-script bodies). Genuine
    // business mail rarely chains 3+ formal connectives in a short message.
    let connective_hits = policy
        .connectives
        .iter()
        .filter(|phrase| semantic_phrase_present(&lower, phrase))
        .count();
    if connective_hits >= 3 {
        hits.push("dense formal connectives (LLM register)");
    }

    // 3. Mandarin equivalent — overly literary connectives are also a strong
    // signal in Chinese LLM-translated phishing.
    let zh_connective_hits = policy
        .zh_connectives
        .iter()
        .filter(|phrase| semantic_phrase_present(trimmed, phrase))
        .count();
    if zh_connective_hits >= 3 {
        hits.push("dense formal Chinese connectives");
    }

    // 4. Long-sentence dominance. Split on Latin and Chinese sentence enders.
    let mut sentence_lengths: Vec<usize> = Vec::new();
    let mut current_len = 0usize;
    for (index, ch) in trimmed.chars().enumerate() {
        if index % 1024 == 0 && budget.exhausted() {
            return None;
        }
        if matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '\n') {
            if current_len > 0 {
                sentence_lengths.push(current_len);
            }
            current_len = 0;
        } else if !ch.is_whitespace() {
            current_len += 1;
        }
    }
    if current_len > 0 {
        sentence_lengths.push(current_len);
    }
    if sentence_lengths.len() >= 4 {
        let long_sentences = sentence_lengths.iter().filter(|n| **n >= 80).count();
        let ratio = long_sentences as f64 / sentence_lengths.len() as f64;
        if ratio >= 0.5 {
            hits.push("majority of sentences are unusually long");
        }
    }

    // 5. Latin-script "no contractions" register: count "do not / will not /
    // cannot / I am" vs the contracted forms. LLMs systematically prefer the
    // expanded form; a real human under urgency uses contractions.
    let expanded = count_unique_occurrences(&lower, &policy.expanded_forms);
    let contracted = count_unique_occurrences(&lower, &policy.contracted_forms);
    if budget.exhausted() {
        return None;
    }
    if expanded >= 4 && contracted == 0 {
        hits.push("zero contractions despite formal English register");
    }

    // 6. Aggregate — only emit a positive score when *multiple independent*
    // fingerprints fire. Weak single-signal hits collapse to 0.0.
    let independent_signals = hits.len();
    let score = match independent_signals {
        0 | 1 => 0.0,
        2 => 0.15,
        3 => 0.22,
        _ => 0.30,
    };

    Some((score, hits))
}

#[cfg(test)]
mod tests {
    use super::count_unique_occurrences;

    #[test]
    fn nested_configured_phrases_count_each_byte_range_once() {
        let phrases = ["do not ".to_string(), "i do not ".to_string()];
        assert_eq!(
            count_unique_occurrences("i do not know. do not go.", &phrases),
            2
        );
        assert_eq!(count_unique_occurrences("no match here", &phrases), 0);
        let repeated = ["do not ".to_string()];
        assert_eq!(count_unique_occurrences("do not do not ", &repeated), 2);
    }
}
