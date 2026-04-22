//! ContentdetectModule - emailbodyMediumofPhishingKeywords, BEC modeAndSensitivedata

mod detectors;
mod html_utils;

use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

// KeywordsoverrideType (For API Andfirst Use)

/// KeywordsClassificationofoverrideConfiguration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeywordCategoryOverride {
    /// userAdd newofKeywords
    #[serde(default)]
    pub added: Vec<String>,
    /// FromSystem Medium ofKeywords
    #[serde(default)]
    pub removed: Vec<String>,
}

/// KeywordsClassificationofoverrideConfiguration (store DB config table, key = "keyword_overrides")
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeywordOverrides {
    #[serde(default)]
    pub phishing_keywords: KeywordCategoryOverride,
    #[serde(default)]
    pub weak_phishing_keywords: KeywordCategoryOverride,
    #[serde(default)]
    pub bec_phrases: KeywordCategoryOverride,
    #[serde(default)]
    pub internal_authority_phrases: KeywordCategoryOverride,
    #[serde(default)]
    pub gateway_banner_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub notice_banner_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub dsn_patterns: KeywordCategoryOverride,
    #[serde(default)]
    pub auto_reply_patterns: KeywordCategoryOverride,
}

#[derive(Debug, Clone, Default)]
pub struct EffectiveKeywordLists {
    pub phishing_keywords: Vec<String>,
    pub weak_phishing_keywords: Vec<String>,
    pub bec_phrases: Vec<String>,
    pub internal_authority_phrases: Vec<String>,
    pub gateway_banner_patterns: Vec<String>,
    pub notice_banner_patterns: Vec<String>,
    pub dsn_patterns: Vec<String>,
    pub auto_reply_patterns: Vec<String>,
}

/// Unicode NFKC + charactersCleanup + ->
/// preventAttack / characters/Same / characters Keywordsdetect
/// : "" -> "0", "" -> "password", " \u{200B}Code/Digit" -> " "
pub(crate) fn normalize_text(text: &str) -> String {
    text.nfkc()
        .filter(|c| {
            !matches!(
                c,
                '\u{200B}' | // Zero Width Space
            '\u{200C}' | // Zero Width Non-Joiner
            '\u{200D}' | // Zero Width Joiner
            '\u{200E}' | // Left-to-Right Mark
            '\u{200F}' | // Right-to-Left Mark
            '\u{2060}' | // Word Joiner
            '\u{FEFF}' | // BOM / Zero Width No-Break Space
            '\u{00AD}' | // Soft Hyphen
            '\u{034F}' | // Combining Grapheme Joiner
            '\u{061C}' | // Arabic Letter Mark
            '\u{2028}' | // Line Separator
            '\u{2029}' // Paragraph Separator
            )
        })
        .collect::<String>()
}

/// Minimum text length to trigger parallel keyword scanning.
const KEYWORD_PAR_THRESHOLD: usize = 50_000;

static RE_PARAGRAPH_BREAK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\r?\n\s*\r?\n+").expect("valid paragraph break regex"));

pub struct ContentScanModule {
    meta: ModuleMetadata,
    /// ofPhishingKeywordsList (builtin - removed + added)
    phishing_keywords: Vec<String>,
    /// of PhishingKeywordsList
    weak_phishing_keywords: Vec<String>,
    /// of BEC short List
    bec_phrases: Vec<String>,
    /// ofInternal short List
    internal_authority_phrases: Vec<String>,
    gateway_banner_patterns: Vec<String>,
    notice_banner_patterns: Vec<String>,
    dsn_patterns: Vec<String>,
    auto_reply_patterns: Vec<String>,
}

impl Default for ContentScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentScanModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "content_scan".to_string(),
                name: "Contentdetect".to_string(),
                description: "扫描emailbodyMediumofPhishingKeywords、BEC modeAndSensitivedata泄露"
                    .to_string(),
                pillar: Pillar::Content,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords: effective.phishing_keywords,
            weak_phishing_keywords: effective.weak_phishing_keywords,
            bec_phrases: effective.bec_phrases,
            internal_authority_phrases: effective.internal_authority_phrases,
            gateway_banner_patterns: effective.gateway_banner_patterns,
            notice_banner_patterns: effective.notice_banner_patterns,
            dsn_patterns: effective.dsn_patterns,
            auto_reply_patterns: effective.auto_reply_patterns,
        }
    }

    /// ReturnWhenfirst ofKeywordsList (For API Return)
    pub fn effective_keywords(&self) -> serde_json::Value {
        serde_json::json!({
            "phishing_keywords": self.phishing_keywords,
            "weak_phishing_keywords": self.weak_phishing_keywords,
            "bec_phrases": self.bec_phrases,
            "internal_authority_phrases": self.internal_authority_phrases,
            "gateway_banner_patterns": self.gateway_banner_patterns,
            "notice_banner_patterns": self.notice_banner_patterns,
            "dsn_patterns": self.dsn_patterns,
            "auto_reply_patterns": self.auto_reply_patterns,
        })
    }
}

/// Merge Keywords useroverride: (builtin - removed) + added
fn normalize_keyword_entry(value: &str) -> Option<String> {
    let normalized = normalize_text(&value.to_lowercase());
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

fn collect_normalized_keywords<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for value in values {
        let Some(normalized) = normalize_keyword_entry(value) else {
            continue;
        };
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }

    result
}

fn apply_overrides_to_builtin(
    builtin: &[String],
    overrides: &KeywordCategoryOverride,
) -> Vec<String> {
    let removed_set: HashSet<String> = overrides
        .removed
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .collect();

    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for builtin_kw in builtin {
        if removed_set.contains(builtin_kw) {
            continue;
        }
        if seen.insert(builtin_kw.clone()) {
            result.push(builtin_kw.clone());
        }
    }

    for added in &overrides.added {
        let Some(normalized) = normalize_keyword_entry(added) else {
            continue;
        };
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }
    result
}

fn normalize_system_category_seed(seed: &KeywordCategoryOverride) -> KeywordCategoryOverride {
    KeywordCategoryOverride {
        added: collect_normalized_keywords(seed.added.iter().map(|value| value.as_str())),
        removed: Vec::new(),
    }
}

pub fn normalize_system_keyword_seed(system_seed: &KeywordOverrides) -> KeywordOverrides {
    KeywordOverrides {
        phishing_keywords: normalize_system_category_seed(&system_seed.phishing_keywords),
        weak_phishing_keywords: normalize_system_category_seed(&system_seed.weak_phishing_keywords),
        bec_phrases: normalize_system_category_seed(&system_seed.bec_phrases),
        internal_authority_phrases: normalize_system_category_seed(
            &system_seed.internal_authority_phrases,
        ),
        gateway_banner_patterns: normalize_system_category_seed(
            &system_seed.gateway_banner_patterns,
        ),
        notice_banner_patterns: normalize_system_category_seed(&system_seed.notice_banner_patterns),
        dsn_patterns: normalize_system_category_seed(&system_seed.dsn_patterns),
        auto_reply_patterns: normalize_system_category_seed(&system_seed.auto_reply_patterns),
    }
}

fn build_system_keyword_lists(system_seed: &KeywordOverrides) -> EffectiveKeywordLists {
    let normalized_seed = normalize_system_keyword_seed(system_seed);
    EffectiveKeywordLists {
        phishing_keywords: normalized_seed.phishing_keywords.added,
        weak_phishing_keywords: normalized_seed.weak_phishing_keywords.added,
        bec_phrases: normalized_seed.bec_phrases.added,
        internal_authority_phrases: normalized_seed.internal_authority_phrases.added,
        gateway_banner_patterns: normalized_seed.gateway_banner_patterns.added,
        notice_banner_patterns: normalized_seed.notice_banner_patterns.added,
        dsn_patterns: normalized_seed.dsn_patterns.added,
        auto_reply_patterns: normalized_seed.auto_reply_patterns.added,
    }
}

fn normalize_user_category_overrides(
    overrides: &KeywordCategoryOverride,
    builtin: &[String],
) -> KeywordCategoryOverride {
    let builtin_set: HashSet<String> = builtin.iter().cloned().collect();

    let added = overrides
        .added
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .filter(|value| !builtin_set.contains(value))
        .collect::<Vec<_>>();

    let removed = overrides
        .removed
        .iter()
        .filter_map(|value| normalize_keyword_entry(value))
        .filter(|value| builtin_set.contains(value))
        .collect::<Vec<_>>();

    KeywordCategoryOverride {
        added: collect_normalized_keywords(added.iter().map(|value| value.as_str())),
        removed: collect_normalized_keywords(removed.iter().map(|value| value.as_str())),
    }
}

pub fn normalize_user_keyword_overrides(
    system_seed: &KeywordOverrides,
    overrides: &KeywordOverrides,
) -> KeywordOverrides {
    let builtin = build_system_keyword_lists(system_seed);

    KeywordOverrides {
        phishing_keywords: normalize_user_category_overrides(
            &overrides.phishing_keywords,
            &builtin.phishing_keywords,
        ),
        weak_phishing_keywords: normalize_user_category_overrides(
            &overrides.weak_phishing_keywords,
            &builtin.weak_phishing_keywords,
        ),
        bec_phrases: normalize_user_category_overrides(
            &overrides.bec_phrases,
            &builtin.bec_phrases,
        ),
        internal_authority_phrases: normalize_user_category_overrides(
            &overrides.internal_authority_phrases,
            &builtin.internal_authority_phrases,
        ),
        gateway_banner_patterns: normalize_user_category_overrides(
            &overrides.gateway_banner_patterns,
            &builtin.gateway_banner_patterns,
        ),
        notice_banner_patterns: normalize_user_category_overrides(
            &overrides.notice_banner_patterns,
            &builtin.notice_banner_patterns,
        ),
        dsn_patterns: normalize_user_category_overrides(
            &overrides.dsn_patterns,
            &builtin.dsn_patterns,
        ),
        auto_reply_patterns: normalize_user_category_overrides(
            &overrides.auto_reply_patterns,
            &builtin.auto_reply_patterns,
        ),
    }
}

pub fn build_effective_keyword_lists(
    system_seed: &KeywordOverrides,
    overrides: &KeywordOverrides,
) -> EffectiveKeywordLists {
    let builtin = build_system_keyword_lists(system_seed);

    EffectiveKeywordLists {
        phishing_keywords: apply_overrides_to_builtin(
            &builtin.phishing_keywords,
            &overrides.phishing_keywords,
        ),
        weak_phishing_keywords: apply_overrides_to_builtin(
            &builtin.weak_phishing_keywords,
            &overrides.weak_phishing_keywords,
        ),
        bec_phrases: apply_overrides_to_builtin(&builtin.bec_phrases, &overrides.bec_phrases),
        internal_authority_phrases: apply_overrides_to_builtin(
            &builtin.internal_authority_phrases,
            &overrides.internal_authority_phrases,
        ),
        gateway_banner_patterns: apply_overrides_to_builtin(
            &builtin.gateway_banner_patterns,
            &overrides.gateway_banner_patterns,
        ),
        notice_banner_patterns: apply_overrides_to_builtin(
            &builtin.notice_banner_patterns,
            &overrides.notice_banner_patterns,
        ),
        dsn_patterns: apply_overrides_to_builtin(&builtin.dsn_patterns, &overrides.dsn_patterns),
        auto_reply_patterns: apply_overrides_to_builtin(
            &builtin.auto_reply_patterns,
            &overrides.auto_reply_patterns,
        ),
    }
}

/// ReturnSystem KeywordsList (For API District builtin vs custom)
pub fn get_builtin_keyword_lists(system_seed: &KeywordOverrides) -> serde_json::Value {
    let builtin = build_system_keyword_lists(system_seed);

    serde_json::json!({
        "phishing_keywords": builtin.phishing_keywords,
        "weak_phishing_keywords": builtin.weak_phishing_keywords,
        "bec_phrases": builtin.bec_phrases,
        "internal_authority_phrases": builtin.internal_authority_phrases,
        "gateway_banner_patterns": builtin.gateway_banner_patterns,
        "notice_banner_patterns": builtin.notice_banner_patterns,
        "dsn_patterns": builtin.dsn_patterns,
        "auto_reply_patterns": builtin.auto_reply_patterns,
    })
}

/// Return detectRule (For API first)
pub fn get_builtin_rules(system_seed: &KeywordOverrides) -> serde_json::Value {
    let builtin = build_system_keyword_lists(system_seed);
    // Merge KeywordsUsed forfirst
    let mut all_phishing = builtin.phishing_keywords.clone();
    all_phishing.extend(builtin.weak_phishing_keywords.clone());
    all_phishing.sort();
    all_phishing.dedup();

    serde_json::json!({
        "phishing_keywords": all_phishing,
        "bec_phrases": builtin.bec_phrases,
        "dlp_patterns": [
            {
                "id": "credit_card",
                "name": "信用Card number",
                "description": "16 bit数字 (通 Luhn Verify)",
                "pattern": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
                "score_weight": 0.3
            },
            {
                "id": "chinese_id",
                "name": "ID cardNumber",
                "description": "18 bit数字 (末bit可  X)",
                "pattern": r"\b\d{17}[\dXx]\b",
                "score_weight": 0.25
            },
            {
                "id": "api_key",
                "name": "API Key",
                "description": "32+ contiguous字母数字 with surrounding API/secret/token context",
                "pattern": r"\b[A-Za-z0-9]{32,}\b",
                "score_weight": 0.2
            }
        ],
        "scoring": {
            "phishing_per_keyword": 0.08,
            "phishing_max": 0.5,
            "weak_phishing_per_keyword": 0.03,
            "weak_phishing_max": 0.15,
            "weak_phishing_threshold": 3,
            "bec_per_phrase": 0.15,
            "bec_max": 0.5
        }
    })
}

/// Medium large Mobile phoneNumberCode/Digit: 1[3-9] Headerof 11 bit
/// UseCapture + characters,AvoidFrom Time/CountNumber/Serial numberMedium Extract
pub(super) static RE_CHINESE_PHONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^0-9a-zA-Z])(1[3-9]\d{9})(?:[^0-9a-zA-Z]|$)").unwrap());

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());
static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{17}[\dXx]\b").unwrap());
static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9]{32,}\b").unwrap());

/// Check if a string looks like it could pass the Luhn algorithm (credit card)
fn contains_credit_card(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for m in RE_CREDIT_CARD.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 16 && luhn_check(&digits) {
            found.push(m.as_str().to_string());
        }
    }
    found
}

/// Luhn algorithm validation
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        if let Some(d) = ch.to_digit(10) {
            let val = if double {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d
            };
            sum += val;
            double = !double;
        } else {
            return false;
        }
    }
    sum.is_multiple_of(10)
}

/// Find Chinese national ID numbers (18 digits, last may be X)
fn find_chinese_ids(text: &str) -> Vec<String> {
    RE_CHINESE_ID
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Find potential API keys (32+ alphanumeric chars)
/// Exclude 6Base/RadixString (MD5/SHA Hash, ImageFileNamewait)
fn find_api_keys(text: &str) -> Vec<String> {
    RE_API_KEY
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            // 6Base/Radix (0-9, a-f) FileHash, API key
            let is_pure_hex = s
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c.to_ascii_lowercase()));
            if is_pure_hex
                || !looks_like_api_key_shape(s)
                || !has_api_key_context(text, m.start(), m.end())
            {
                None
            } else {
                Some(s.to_string())
            }
        })
        .collect()
}

fn looks_like_api_key_shape(candidate: &str) -> bool {
    let has_upper = candidate.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = candidate.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    let unique_chars = candidate.chars().collect::<HashSet<_>>().len();
    let class_count = [has_upper, has_lower, has_digit]
        .into_iter()
        .filter(|present| *present)
        .count();

    class_count >= 2 && unique_chars >= 10
}

fn has_api_key_context(text: &str, start: usize, end: usize) -> bool {
    let before: String = text[..start]
        .chars()
        .rev()
        .take(48)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let after: String = text[end..].chars().take(48).collect();
    let context = format!("{before}{}{after}", &text[start..end]).to_lowercase();

    module_data()
        .get_list("api_key_context_keywords")
        .iter()
        .any(|keyword| context.contains(keyword.as_str()))
}

pub(super) fn scan_text(
    text: &str,
    phishing_kw: &[String],
    weak_phishing_kw: &[String],
    bec_ph: &[String],
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score: f64 = 0.0;
    // NFKC: ->, -> Standard, prevent Unicode
    let text_lower = normalize_text(&text.to_lowercase());

    // --- PhishingKeywords (0.08/, 0.5) ---
    let phishing_hits: Vec<String> = if text_lower.len() >= KEYWORD_PAR_THRESHOLD {
        phishing_kw
            .par_iter()
            .filter(|kw| text_lower.contains(kw.as_str()))
            .cloned()
            .collect()
    } else {
        phishing_kw
            .iter()
            .filter(|kw| text_lower.contains(kw.as_str()))
            .cloned()
            .collect()
    };
    if !phishing_hits.is_empty() {
        let count = phishing_hits.len();
        score += (count as f64 * 0.08).min(0.5);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} PhishingKeywords: {}",
                count,
                phishing_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(phishing_hits.join(", ")),
        });
    }

    // --- PhishingKeywords (0.03/,>=3, 0.15) ---
    // NormalBusinessemailMedium found, stored
    let mut weak_hits = Vec::new();
    for kw in weak_phishing_kw {
        if text_lower.contains(kw.as_str()) {
            weak_hits.push(kw.clone());
        }
    }
    if weak_hits.len() >= 3 {
        score += (weak_hits.len() as f64 * 0.03).min(0.15);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} 弱PhishingIndicator: {}",
                weak_hits.len(),
                weak_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(weak_hits.join(", ")),
        });
    }

    // --- BEC impersonation ---
    // Single-token urgency words from the keyword manager (e.g. "immediately",
    // "asap") are too weak on their own. Treat them as weak BEC hints and only
    // score when multiple weak hits co-occur, while keeping multi-token phrases
    // as strong BEC evidence.
    let bec_hits: Vec<String> = if text_lower.len() >= KEYWORD_PAR_THRESHOLD {
        bec_ph
            .par_iter()
            .filter(|phrase| text_lower.contains(phrase.as_str()))
            .cloned()
            .collect()
    } else {
        bec_ph
            .iter()
            .filter(|phrase| text_lower.contains(phrase.as_str()))
            .cloned()
            .collect()
    };
    let (strong_bec_hits, weak_bec_hits): (Vec<String>, Vec<String>) = bec_hits
        .into_iter()
        .partition(|phrase| is_strong_bec_phrase(phrase));
    if !strong_bec_hits.is_empty() {
        let count = strong_bec_hits.len();
        score += (count as f64 * 0.15).min(0.5);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} strong BEC phrases: {}",
                count,
                strong_bec_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(strong_bec_hits.join(", ")),
        });
    } else if weak_bec_hits.len() >= 3 {
        score += (weak_bec_hits.len() as f64 * 0.05).min(0.15);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} weak BEC hints that co-occur: {}",
                weak_bec_hits.len(),
                weak_bec_hits.join(", ")
            ),
            location: Some("body".to_string()),
            snippet: Some(weak_bec_hits.join(", ")),
        });
    }

    // --- DLP: Credit cards ---
    let cc_matches = contains_credit_card(text);
    if !cc_matches.is_empty() {
        score += 0.3;
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} 疑似信用Card number（通 Luhn Verify）",
                cc_matches.len()
            ),
            location: Some("body".to_string()),
            snippet: Some(
                cc_matches
                    .iter()
                    .map(|c| {
                        // mask middle digits
                        let mut masked = c.clone();
                        if masked.len() >= 12 {
                            let len = masked.len();
                            masked.replace_range(4..len - 4, &"*".repeat(len - 8));
                        }
                        masked
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    // --- DLP: Chinese ID ---
    let id_matches = find_chinese_ids(text);
    if !id_matches.is_empty() {
        score += 0.25;
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!("Found {} 疑似ID cardNumber", id_matches.len()),
            location: Some("body".to_string()),
            snippet: Some(
                id_matches
                    .iter()
                    .map(|id| {
                        let mut masked = id.clone();
                        if masked.len() >= 10 {
                            masked.replace_range(4..14, "**********");
                        }
                        masked
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    // --- DLP: API keys ---
    let api_keys = find_api_keys(text);
    if !api_keys.is_empty() {
        score += 0.2;
        categories.push("dlp_api_key".to_string());
        evidence.push(Evidence {
            description: format!(
                "Found {} suspected API key(s) with nearby secret/token context",
                api_keys.len()
            ),
            location: Some("body".to_string()),
            snippet: Some(
                api_keys
                    .iter()
                    .map(|k| {
                        if k.len() > 8 {
                            format!("{}...{}", &k[..4], &k[k.len() - 4..])
                        } else {
                            k.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        });
    }

    score
}

fn is_strong_bec_phrase(phrase: &str) -> bool {
    let normalized = normalize_text(&phrase.to_lowercase());
    let word_count = normalized
        .split_whitespace()
        .filter(|segment| !segment.is_empty())
        .count();
    if word_count >= 2 {
        return true;
    }

    let cjk_count = normalized
        .chars()
        .filter(|ch| ('\u{4E00}'..='\u{9FFF}').contains(ch))
        .count();
    cjk_count >= 4
}

fn matches_any_pattern(text_lower: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let normalized = normalize_text(&pattern.to_lowercase());
        text_lower.contains(normalized.as_str())
    })
}

fn split_first_paragraph(text: &str) -> (&str, &str) {
    if let Some(m) = RE_PARAGRAPH_BREAK.find(text) {
        (&text[..m.start()], &text[m.end()..])
    } else {
        (text, "")
    }
}

fn strip_leading_notice_sections<'a>(text: &'a str, patterns: &[String]) -> (&'a str, bool) {
    let mut remaining = text.trim_start();
    let mut removed_any = false;

    for _ in 0..6 {
        if remaining.is_empty() {
            return (remaining, removed_any);
        }

        let (paragraph, rest) = split_first_paragraph(remaining);
        let paragraph_lower = normalize_text(&paragraph.to_lowercase());
        if matches_any_pattern(&paragraph_lower, patterns) {
            removed_any = true;
            remaining = rest.trim_start();
        } else {
            break;
        }
    }

    (remaining, removed_any)
}

fn separator_lead_len(line: &str) -> usize {
    line.trim_start()
        .chars()
        .take_while(|c| matches!(c, '_' | '-' | '=' | '*' | '·'))
        .count()
}

fn strip_trailing_footer_after_separator(text: &str) -> String {
    let mut offset = 0usize;
    let trimmed = text.trim();

    for line in trimmed.split_inclusive('\n') {
        let line_trimmed = line.trim();
        let separator_len = separator_lead_len(line_trimmed);
        let tail_start = offset;
        let tail = &trimmed[tail_start..];

        if separator_len >= 4 && tail.len() >= 160 && tail_start >= 48 {
            return trimmed[..tail_start].trim_end().to_string();
        }

        offset += line.len();
    }

    trimmed.to_string()
}

pub(crate) fn sanitize_body_for_keyword_scan(
    text: &str,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
    dsn_patterns: &[String],
    auto_reply_patterns: &[String],
) -> String {
    let mut notice_patterns = Vec::with_capacity(
        gateway_banner_patterns.len()
            + notice_banner_patterns.len()
            + dsn_patterns.len()
            + auto_reply_patterns.len(),
    );
    notice_patterns.extend(gateway_banner_patterns.iter().cloned());
    notice_patterns.extend(notice_banner_patterns.iter().cloned());
    notice_patterns.extend(dsn_patterns.iter().cloned());
    notice_patterns.extend(auto_reply_patterns.iter().cloned());

    let (without_notice, removed_notice) = strip_leading_notice_sections(text, &notice_patterns);
    let trimmed = without_notice.trim_start();
    if removed_notice && separator_lead_len(trimmed.lines().next().unwrap_or_default()) >= 4 {
        return String::new();
    }

    strip_trailing_footer_after_separator(without_notice)
}

pub(super) fn collect_gateway_prior_hits(
    prefix_text: &str,
    gateway_banner_patterns: &[String],
) -> Vec<String> {
    let prefix_lower = normalize_text(&prefix_text.to_lowercase());
    gateway_banner_patterns
        .iter()
        .filter(|pattern| {
            let normalized = normalize_text(&pattern.to_lowercase());
            prefix_lower.contains(normalized.as_str())
        })
        .cloned()
        .collect()
}

pub(crate) fn strip_subject_banner_prefixes(
    subject: &str,
    gateway_banner_patterns: &[String],
    notice_banner_patterns: &[String],
) -> String {
    let mut cleaned = subject.to_string();
    for pattern in gateway_banner_patterns
        .iter()
        .chain(notice_banner_patterns.iter())
    {
        cleaned = cleaned.replace(pattern, "");
    }
    cleaned.trim().to_string()
}

#[async_trait]
impl SecurityModule for ContentScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // Step 1: Gateway banner detection
        detectors::detect_gateway_banner(
            ctx,
            &self.gateway_banner_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 2: Subject phishing keywords + phone numbers
        detectors::detect_subject_phishing(
            ctx,
            &self.phishing_keywords,
            &self.gateway_banner_patterns,
            &self.notice_banner_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 3: Body text preparation + keyword/DLP scanning
        let body_for_cross = detectors::prepare_body_text(
            ctx,
            &self.phishing_keywords,
            &self.weak_phishing_keywords,
            &self.bec_phrases,
            &self.gateway_banner_patterns,
            &self.notice_banner_patterns,
            &self.dsn_patterns,
            &self.auto_reply_patterns,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 4: Image-only phishing detection
        detectors::detect_image_only_phishing(
            ctx,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 5: Account security phishing (body + subject fallback)
        detectors::detect_account_security_phishing(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 6: Subsidy/tax fraud (body + subject fallback)
        detectors::detect_subsidy_fraud(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 7: Invoice-spam / fake invoice solicitation detection
        detectors::detect_invoice_spam(
            ctx,
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 8: Body phone number detection
        detectors::detect_body_phone_numbers(
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 9: External impersonation detection
        detectors::detect_external_impersonation(
            ctx,
            body_for_cross.as_deref(),
            &self.internal_authority_phrases,
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Step 10: Language inconsistency detection
        detectors::detect_lang_inconsistency(
            body_for_cross.as_deref(),
            &mut total_score,
            &mut categories,
            &mut evidence,
        );

        // Cap the score at 1.0
        total_score = total_score.min(1.0);

        // Deduplicate categories
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "bodyContent未Found威胁",
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.85,
            categories,
            summary: format!(
                "bodyContentdetectFound {} Item证According to，综合评分 {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests;
