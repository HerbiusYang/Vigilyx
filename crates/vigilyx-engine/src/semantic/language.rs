//! Language observations and existing sender/recipient context rules.

use crate::module::Evidence;
use crate::pipeline::context::SecurityContext;

use super::budget::SemanticCpuBudget;
use super::compiled::CompiledSemanticData;
use super::statistics::is_cjk_any;

/// (U+3040..U+309F)
fn is_hiragana(ch: char) -> bool {
    ('\u{3040}'..='\u{309F}').contains(&ch)
}

/// (U+30A0..U+30FF)
fn is_katakana(ch: char) -> bool {
    ('\u{30A0}'..='\u{30FF}').contains(&ch)
}

fn is_japanese_kana(ch: char) -> bool {
    is_hiragana(ch) || is_katakana(ch)
}

/// Retain language differences as context without adding threat score.
pub(super) fn observe_language(
    ctx: &SecurityContext,
    body: &str,
    cpu_budget: &SemanticCpuBudget,
    evidence: &mut Vec<Evidence>,
    semantic_coverage_reasons: &mut Vec<String>,
    data: &CompiledSemanticData,
) -> (bool, Vec<serde_json::Value>) {
    let mut language_observations = Vec::new();
    // Language anomaly detection
    let (total_chars, cjk_count) = if cpu_budget.exhausted() {
        semantic_coverage_reasons
            .push("semantic language observation exceeded its wall-clock budget".to_string());
        (0usize, 0usize)
    } else {
        body.chars().fold((0usize, 0usize), |(total, cjk), ch| {
            (
                total + usize::from(!ch.is_whitespace()),
                cjk + usize::from(is_cjk_any(ch)),
            )
        })
    };
    // CJK ratio < 2% counts as foreign-language. The previous
    // `cjk_count == 0` check let attackers disable this detector by
    // sprinkling a single CJK token (e.g. one "的") into an otherwise
    // pure foreign-language lure.
    let is_non_chinese = total_chars > 30 && cjk_count * 100 < total_chars * 2;

    if is_non_chinese {
        // Skip known financial sender domains (legitimate foreign-language emails)
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|m| m.rsplit('@').next())
            .unwrap_or("");
        let is_known_financial_sender =
            data.contains("known_financial_sender_domains", sender_domain);

        if !is_known_financial_sender {
            let rcpt_domains: Vec<String> = ctx
                .session
                .rcpt_to
                .iter()
                .filter_map(|r| r.rsplit('@').next().map(|d| d.to_lowercase()))
                .collect();
            let is_cn_corp = rcpt_domains.iter().any(|d| {
                d.ends_with(".cn")
                    || d.ends_with(".com.cn")
                    || ctx.is_internal_domain(d)
                    || data.contains("protected_domains", d)
            });

            if is_cn_corp {
                language_observations.push(serde_json::json!({
                    "kind": "foreign_to_cn_corp",
                    "character_count": total_chars,
                    "disposition": "context_only",
                }));
                evidence.push(Evidence {
                    description: format!(
                        "Foreign-language email ({} chars) sent to a Chinese corporate mailbox; recorded as context only",
                        total_chars,
                    ),
                    location: Some("body:language".to_string()),
                    snippet: Some(body.chars().take(100).collect::<String>()),
                });
            } else {
                language_observations.push(serde_json::json!({
                    "kind": "foreign_language",
                    "character_count": total_chars,
                    "disposition": "context_only",
                }));
                evidence.push(Evidence {
                    description: format!(
                        "Pure foreign-language email (no Chinese content, {} chars)",
                        total_chars,
                    ),
                    location: Some("body:language".to_string()),
                    snippet: Some(body.chars().take(100).collect::<String>()),
                });
            }
        }
        // Skip further anomaly detection for known senders
    }

    {
        let jp_kana_count = if cpu_budget.exhausted() {
            0
        } else {
            body.chars().filter(|c| is_japanese_kana(*c)).count()
        };
        if jp_kana_count >= 10 {
            let rcpt_domains: Vec<String> = ctx
                .session
                .rcpt_to
                .iter()
                .filter_map(|r| r.rsplit('@').next().map(|d| d.to_lowercase()))
                .collect();
            let is_cn_corp = rcpt_domains.iter().any(|d| {
                d.ends_with(".cn")
                    || d.ends_with(".com.cn")
                    || ctx.is_internal_domain(d)
                    || data.contains("protected_domains", d)
            });
            let is_jp_corp = rcpt_domains
                .iter()
                .any(|d| d.ends_with(".jp") || d.ends_with(".co.jp"));

            if is_cn_corp && !is_jp_corp {
                language_observations.push(serde_json::json!({
                    "kind": "japanese_to_cn_corp",
                    "kana_count": jp_kana_count,
                    "disposition": "context_only",
                }));
                evidence.push(Evidence {
                    description: format!(
                        "Japanese email ({} kana characters) sent to Chinese corporate mailbox; recorded as context only",
                        jp_kana_count,
                    ),
                    location: Some("body:language_mismatch".to_string()),
                    snippet: Some(body.chars().take(100).collect::<String>()),
                });
            } else if !is_jp_corp {
                language_observations.push(serde_json::json!({
                    "kind": "japanese_unexpected",
                    "kana_count": jp_kana_count,
                    "disposition": "context_only",
                }));
                evidence.push(Evidence {
                    description: format!(
                        "Japanese email ({} kana characters) sent to non-Japanese region enterprise",
                        jp_kana_count,
                    ),
                    location: Some("body:language_mismatch".to_string()),
                    snippet: Some(body.chars().take(100).collect::<String>()),
                });
            }
        }
    }

    (is_non_chinese, language_observations)
}
