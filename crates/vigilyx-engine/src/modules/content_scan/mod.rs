//! ContentdetectModule - emailbodyMediumofPhishingKeywords, BEC modeAndSensitivedata

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
}

#[derive(Debug, Clone, Default)]
pub struct EffectiveKeywordLists {
    pub phishing_keywords: Vec<String>,
    pub weak_phishing_keywords: Vec<String>,
    pub bec_phrases: Vec<String>,
    pub internal_authority_phrases: Vec<String>,
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
        }
    }

   /// ReturnWhenfirst ofKeywordsList (For API Return)
    pub fn effective_keywords(&self) -> serde_json::Value {
        serde_json::json!({
            "phishing_keywords": self.phishing_keywords,
            "weak_phishing_keywords": self.weak_phishing_keywords,
            "bec_phrases": self.bec_phrases,
            "internal_authority_phrases": self.internal_authority_phrases,
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
    }
}

fn build_system_keyword_lists(system_seed: &KeywordOverrides) -> EffectiveKeywordLists {
    let normalized_seed = normalize_system_keyword_seed(system_seed);
    EffectiveKeywordLists {
        phishing_keywords: normalized_seed.phishing_keywords.added,
        weak_phishing_keywords: normalized_seed.weak_phishing_keywords.added,
        bec_phrases: normalized_seed.bec_phrases.added,
        internal_authority_phrases: normalized_seed.internal_authority_phrases.added,
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
    })
}

/// ProtectedofInternalDomain
const PROTECTED_DOMAINS: &[&str] = &["corp-internal.com"];

/// / bitSign - Used forMedium Sign 1 detect
const EN_DEPARTMENT_SIGNATURES: &[&str] = &[
    "financial department",
    "finance department",
    "hr department",
    "human resources",
    "admin department",
    "it department",
    "legal department",
    "compliance department",
    "marketing department",
    "general manager",
    "chief executive",
    "chief financial",
];

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
                "description": "32+ contiguous字母数字",
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
static RE_CHINESE_PHONE: LazyLock<Regex> =
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
            if is_pure_hex {
                None
            } else {
                Some(s.to_string())
            }
        })
        .collect()
}

fn scan_text(
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
    if !bec_hits.is_empty() {
        let count = bec_hits.len();
        score += (count as f64 * 0.15).min(0.5);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!("Found {}  BEC 冒充short语: {}", count, bec_hits.join(", ")),
            location: Some("body".to_string()),
            snippet: Some(bec_hits.join(", ")),
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
                "Found {} 疑似 API Key（32+ characterscontiguous字母数字）",
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


       // (Coremail/Exchange).

        {
            let body_for_gw = ctx
                .session
                .content
                .body_text
                .as_deref()
                .or(ctx.session.content.body_html.as_deref())
                .unwrap_or("");

            let gw_prefix: String = body_for_gw.chars().take(500).collect();
            let gw_lower = gw_prefix.to_lowercase();

            let gw_spam = gw_lower.contains("检测结果：垃圾邮件")
                || gw_lower.contains("检测结果:垃圾邮件");
            let gw_malicious = gw_lower.contains("该邮件可能存在恶意内容")
                || gw_lower.contains("此邮件可能存在恶意内容");

            if gw_spam || gw_malicious {
                let gw_score = if gw_malicious { 0.25 } else { 0.20 };
                total_score += gw_score;
                categories.push("gateway_pre_classified".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "上游邮件网关已标记: {}",
                        if gw_malicious {
                            "恶意内容"
                        } else {
                            "垃圾邮件"
                        }
                    ),
                    location: Some("body:gateway_tag".to_string()),
                    snippet: Some(gw_prefix.chars().take(120).collect()),
                });
            }
        }

       // line (PhishingKeywords + Mobile phoneNumber)
       // Attack Medium,if "Need/Require Add 13662542997"
       // Note: email first AddSecurity if "[]",
       // packetContains"Risk"waitKeywords, first, Internal email.
        if let Some(ref subject) = ctx.session.subject {
            let cleaned_subject = subject
                .replace("[注意风险邮件]", "")
                .replace("【注意风险邮件】", "")
                .replace("[外部邮件]", "")
                .replace("【外部邮件】", "");
            let sub_lower = normalize_text(&cleaned_subject.to_lowercase());

           // Mediumof PhishingKeywords
            let subject_hits: Vec<&str> = self
                .phishing_keywords
                .iter()
                .filter(|kw| sub_lower.contains(kw.as_str()))
                .map(|kw| kw.as_str())
                .collect();
            if !subject_hits.is_empty() {
                let count = subject_hits.len();
                total_score += (count as f64 * 0.10).min(0.5);
                categories.push("phishing_subject".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "主题lineFound {} PhishingKeywords: {}",
                        count,
                        subject_hits.join(", ")
                    ),
                    location: Some("subject".to_string()),
                    snippet: Some(subject.clone()),
                });
            }

           // /bodyMediumofMobile phoneNumberCode/Digit - Legitimate email Medium Mobile phoneNumber
            let phone_matches: Vec<String> = RE_CHINESE_PHONE
                .captures_iter(subject)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect();
            if !phone_matches.is_empty() {
                total_score += 0.15;
                categories.push("phone_in_subject".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "主题linepacketContainsMobile phoneNumberCode/Digit: {} (疑似微信/电话引Stream诈骗)",
                        phone_matches.join(", ")
                    ),
                    location: Some("subject".to_string()),
                    snippet: Some(subject.clone()),
                });
            }
        }

       // only 1bodyVersion,Avoid text + html Content
       // priorityUsePlain text (); Plain text HTML ofText
        let body_for_cross = if let Some(ref body_text) = ctx.session.content.body_text {
            total_score += scan_text(
                body_text,
                &self.phishing_keywords,
                &self.weak_phishing_keywords,
                &self.bec_phrases,
                &mut evidence,
                &mut categories,
            );
            Some(body_text.clone())
        } else if let Some(ref body_html) = ctx.session.content.body_html {
            let stripped = strip_html_tags(body_html);
            total_score += scan_text(
                &stripped,
                &self.phishing_keywords,
                &self.weak_phishing_keywords,
                &self.bec_phrases,
                &mut evidence,
                &mut categories,
            );
            Some(stripped)
        } else {
            None
        };

       // ImagePhishingdetect: body + HTML Image
       // Attack PhishingContent Image email, TextKeywordsdetectAnd NLP.
       // : body_text short,body_html not (only Image)
       // Note: email body_text=None But body_html complete Content(if),
       // Check HTML of Length,Avoid.
        {
            let body_text_len = ctx
                .session
                .content
                .body_text
                .as_ref()
                .map_or(0, |t| t.trim().len());
           // if body_text,Check body_html whether
            let effective_text_len = if body_text_len < 50 {
                ctx.session
                    .content
                    .body_html
                    .as_ref()
                    .map_or(0, |html| strip_html_tags(html).trim().len())
                    .max(body_text_len)
            } else {
                body_text_len
            };

            let has_html_images = ctx.session.content.body_html.as_ref().is_some_and(|html| {
                let html_lower = html.to_lowercase();
                html_lower.contains("<img") || html_lower.contains("background-image")
            });
            let has_links = !ctx.session.content.links.is_empty();

           // ofImagePhishing: Plain textAnd HTML allnot
            if effective_text_len < 50 && has_html_images && has_links {
                total_score += 0.15;
                categories.push("image_only_phishing".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "ImagePhishing嫌疑: body文字仅 {} charactersButpacketContainsImageAndlinkConnect (文字Content无法被 NLP Analyze)",
                        effective_text_len
                    ),
                    location: Some("body".to_string()),
                    snippet: None,
                });
            }
        }

       // AccountSecurity Phishing detect
       // mode: Sender + body "AbnormalLogin/Account number / immediatelyProcess"
       // of GetPhishingAttack,Need/Requireindependentdetect giving High.
        if let Some(ref body) = body_for_cross {
            let body_lower = normalize_text(&body.to_lowercase());
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|addr| addr.split('@').nth(1))
                .map(|d| d.to_lowercase());
            let is_external = match &sender_domain {
                Some(d) => {
                    !ctx.is_internal_domain(d) && !PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
                }
                None => true,
            };

            if is_external {
               // AccountSecurity Keywords (: Description + line)
                let threat_phrases = [
                    "异常登录",
                    "外地登录",
                    "异地登录",
                    "账号被盗",
                    "账户冻结",
                    "帐户冻结",
                    "账号封禁",
                    "暂时封禁",
                    "异常活动",
                    "账户关闭",
                    "帐户关闭",
                    "账户将于",
                    "帐户将于",
                    "非活动状态",
                    "邮箱权限",
                    "封禁危险",
                    "封号",

                    "お荷物",
                    "配達通知",
                    "不在通知",
                    "再配達",
                    "受取人",
                    "アカウント確認",
                    "利用停止",
                    "利用制限",
                    "不正アクセス",
                    "カード利用停止",
                    "本人認証",
                    "セキュリティ確認",
                    "パスワード変更",
                    "ログイン確認",

                    "unusual activity",
                    "suspicious login",
                    "account suspended",
                    "unauthorized access",
                    "security alert",
                    "account will be closed",
                    "account closure",
                ];
                let action_phrases = [

                    "立即采取行动",
                    "立即处理",
                    "立即验证",
                    "马上处理",
                    "限时处理",
                    "否则将",
                    "去处理",
                    "点击处理",
                    "立即认证",
                    "安全认证",
                    "完成认证",
                    "立即确认",
                   // (Microsoft/Google Phishing: And)
                    "请登录",
                    "保持开通",
                    "保持活动",
                    "将被关闭",
                    "将被停用",
                    "将被冻结",
                    "将无法使用",
                    "一旦你的",
                    "无法访问",

                    "確認はこちら",
                    "ご確認ください",
                    "ご本人確認",
                    "お手続き",
                    "お届け情報",
                    "受取情報",
                    "下記をご覧",
                    "至急ご対応",
                    "アクションが必要",
                    "手続きを完了",

                    "take action",
                    "verify immediately",
                    "confirm your",
                    "sign in",
                    "log in to",
                    "keep your account",
                    "will be closed",
                    "will be suspended",
                    "will be deactivated",
                ];
                let has_threat = threat_phrases.iter().any(|&p| body_lower.contains(p));
                let has_action = action_phrases.iter().any(|&p| body_lower.contains(p));
                if has_threat && has_action {
                   // DomainSendAccountSecurity email - according toDomainTrusted
                   // TrustedDomain (if microsoft.com) possibly ofSecurity, Low
                   // Unknown/randomDomain (if damuzhisofa.com) Phishing
                    let domain_str = sender_domain.as_deref().unwrap_or("");
                    let is_well_known =
                        crate::modules::link_scan::is_well_known_safe_domain(domain_str);
                    let phish_score = if is_well_known { 0.30 } else { 0.65 };
                    total_score += phish_score;
                    categories.push("account_security_phishing".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "外部Domain {} SendAccountSecurity威胁email: Same时packetContains威胁DescriptionAndline动催促，典型凭证窃GetPhishingmode{}",
                            domain_str,
                            if is_well_known { " (TrustedDomain, possibly NormalSecurity通知)" } else { "" },
                        ),
                        location: Some("body + envelope".to_string()),
                        snippet: None,
                    });
                }
            }

           // Government subsidy/tax fraud pattern (/ /)
           // Signature: benefit keywords + urgency/deadline + suspicious URL or fake authority
            if is_external {
                let subsidy_keywords = [
                    "补贴",
                    "退税",
                    "补偿金",
                    "社保",
                    "医保",
                    "生育",
                    "公积金",
                    "个税",
                    "劳动保障",
                    "申报领取",
                    "办理领取",
                ];
                let urgency_keywords = [
                    "逾期不予受理",
                    "不予受理",
                    "尽快办理",
                    "限期",
                    "请尽快",
                    "过期作废",
                    "逾期",
                ];
                let has_subsidy = subsidy_keywords
                    .iter()
                    .filter(|&&k| body_lower.contains(k))
                    .count();
                let has_urgency = urgency_keywords.iter().any(|&k| body_lower.contains(k));
               // 2+ subsidy keywords + urgency = strong fraud signal
               // Score 0.60: after BPA conversion (x0.85 confidence) and consensus gating
               // (x0.50 for 2-engine support), floor = 0.60x0.85x0.50 = 0.255 which,
               // combined with other keyword hits, comfortably reaches Medium (>= 0.40).
                if has_subsidy >= 2 && has_urgency {
                    total_score += 0.60;
                    categories.push("subsidy_fraud".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Government subsidy fraud pattern: {} benefit keywords + urgency phrase from external domain",
                            has_subsidy,
                        ),
                        location: Some("body + envelope".to_string()),
                        snippet: None,
                    });
                }
            }
        }

       // (body body)
       // body,.
       // body account_security_phishing,.
        if !categories.contains(&"account_security_phishing".to_string())
            && let Some(ref subject) = ctx.session.subject
        {
            let sub_lower = normalize_text(&subject.to_lowercase());
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|addr| addr.split('@').nth(1))
                .map(|d| d.to_lowercase());
            let is_external = match &sender_domain {
                Some(d) => {
                    !ctx.is_internal_domain(d) && !PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
                }
                None => true,
            };
            if is_external {
                let subject_threat_keywords = [

                    "异常登录",
                    "账户冻结",
                    "帐户冻结",
                    "账号封禁",
                    "封禁危险",
                    "账户关闭",
                    "帐户关闭",
                    "账号被盗",
                    "安全警告",
                    "安全风险",
                    "邮箱异常",
                    "异常活动",
                    "立即验证",
                    "账户警告",
                    "账号停用",
                    "面临封禁",
                    "面临封号",
                    "异常登录活动",
                    "安全提醒",
                    "更新密码",
                    "密码过期",
                    "密码到期",
                    "账号到期",
                    "账户到期",
                    "异常访问",
                    "登录异常",
                    "登录警告",
                    "可疑登录",

                    "アカウント確認",
                    "利用制限",
                    "認証手続き",
                    "不正アクセス",
                    "カード利用停止",
                    "使用確認",
                    "アクションが必要",
                    "お荷物に関する",
                    "配達通知",
                    "不在通知",
                    "再配達",
                    "お届け",
                    "パスワード変更",
                    "ログイン確認",
                    "セキュリティ確認",
                    "本人認証",
                    "利用停止",

                    "unusual activity",
                    "suspicious login",
                    "account suspended",
                    "security alert",
                    "verify your",
                    "password expired",
                    "account will be",
                    "unauthorized access",
                ];
                let has_subject_threat = subject_threat_keywords
                    .iter()
                    .any(|&kw| sub_lower.contains(kw));
                if has_subject_threat {
                    let domain_str = sender_domain.as_deref().unwrap_or("");
                    let is_well_known =
                        crate::modules::link_scan::is_well_known_safe_domain(domain_str);
                    let phish_score = if is_well_known { 0.20 } else { 0.50 };
                    total_score += phish_score;
                    categories.push("account_security_phishing".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "主题行含账户安全威胁关键词，外部域名 {} 发送",
                            domain_str,
                        ),
                        location: Some("subject".to_string()),
                        snippet: Some(subject.clone()),
                    });
                }
            }
        }

       // (body)
        if !categories.contains(&"subsidy_fraud".to_string())
            && let Some(ref subject) = ctx.session.subject
        {
            let sub_lower = normalize_text(&subject.to_lowercase());
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|addr| addr.split('@').nth(1))
                .map(|d| d.to_lowercase());
            let is_external = match &sender_domain {
                Some(d) => {
                    !ctx.is_internal_domain(d) && !PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
                }
                None => true,
            };
            if is_external {
                let subsidy_keywords = [
                    "补贴",
                    "退税",
                    "补偿金",
                    "个税",
                    "社保",
                    "公积金",
                    "补助津贴",
                    "补助金",
                    "申报领取",
                    "办理领取",
                ];
                let has_subsidy = subsidy_keywords
                    .iter()
                    .filter(|&&k| sub_lower.contains(k))
                    .count();
                if has_subsidy >= 2 {
                    total_score += 0.45;
                    categories.push("subsidy_fraud".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "主题行含 {} 个补贴/税务关键词，疑似补贴诈骗",
                            has_subsidy,
                        ),
                        location: Some("subject".to_string()),
                        snippet: ctx.session.subject.clone(),
                    });
                }
            }
        }

       // bodyMobile phoneNumberdetect
       // Note: Chinese emailbodypacketContainsMobile phoneNumber (Method, Signwait).
       // Same stored PhishingSignal Mobile phoneNumber Add,
       // >=2 NumberCode/Digit (NumberCode/Digit Normal Method).
        if let Some(ref body) = body_for_cross {
            let phone_matches: Vec<String> = RE_CHINESE_PHONE
                .captures_iter(body)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect();
            let has_other_signals = !categories.is_empty();
            if phone_matches.len() >= 2
                && has_other_signals
                && !categories.contains(&"phone_in_subject".to_string())
            {
                total_score += (phone_matches.len() as f64 * 0.04).min(0.12);
                categories.push("phone_in_body".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "bodypacketContains {} Mobile phoneNumberCode/Digit: {}",
                        phone_matches.len(),
                        phone_matches.join(", ")
                    ),
                    location: Some("body".to_string()),
                    snippet: Some(phone_matches.join(", ")),
                });
            }
        }

       // Signal 1: Sender Internal (+0.25)
        if let Some(ref body) = body_for_cross {
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|addr| addr.split('@').nth(1))
                .map(|d| d.to_lowercase());

            let is_external = match &sender_domain {
                Some(d) => {
                    !ctx.is_internal_domain(d) && !PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
                }
                None => true,
            };

            if is_external {
                let body_lower = body.to_lowercase();
                let mut impersonation_hits = Vec::new();
                for phrase in &self.internal_authority_phrases {
                    if body_lower.contains(phrase.as_str()) {
                        impersonation_hits.push(phrase.clone());
                    }
                }
               // Need/Require 2+ Internal short Medium: " "
                if impersonation_hits.len() >= 2 {
                    total_score += 0.30;
                    categories.push("external_impersonation".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "外部Domain {} 冒充Internal部门: {}",
                            sender_domain.as_deref().unwrap_or("unknown"),
                            impersonation_hits.join(", "),
                        ),
                        location: Some("body + envelope".to_string()),
                        snippet: Some(impersonation_hits.join(", ")),
                    });
                }
            }
        }

       // Signal 2: Medium Sign 1 (+0.08)
        if let Some(ref body) = body_for_cross {
            let body_lower = body.to_lowercase();
           // Checkbody whether Chinese
            let cjk_count = body
                .chars()
                .filter(|c| ('\u{4E00}'..='\u{9FFF}').contains(c))
                .count();
            let total_chars = body.chars().filter(|c| !c.is_whitespace()).count();
            let is_chinese_body = total_chars > 20 && cjk_count as f64 / total_chars as f64 > 0.3;

            if is_chinese_body {
                let mut en_sig_hits = Vec::new();
                for &sig in EN_DEPARTMENT_SIGNATURES {
                    if body_lower.contains(sig) {
                        en_sig_hits.push(sig.to_string());
                    }
                }
                if !en_sig_hits.is_empty() {
                    total_score += 0.08;
                    categories.push("lang_inconsistency".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "body以Chinese 主ButSignUse英文部门Name: {}",
                            en_sig_hits.join(", "),
                        ),
                        location: Some("signature".to_string()),
                        snippet: Some(en_sig_hits.join(", ")),
                    });
                }
            }
        }

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

/// Simple HTML tag stripper (does not need to be perfect; just for keyword matching)
fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                result.push(' ');
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
   // HTML Decode: prevent &#x5BC6;&#x7801; (Password) Keywordsdetect
    decode_html_entities(&result)
}

/// Decode HTML,preventAttack Encode Keywordsmatch
fn decode_html_entities(text: &str) -> String {
    let mut result = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");

   // : &#; And &#x 6Base/Radix;
   // ofLoopDecode,Avoid regex Dependency
    while let Some(start) = result.find("&#") {
        let rest = &result[start + 2..];
        if let Some(end) = rest.find(';') {
            let entity = &rest[..end];
            let decoded = if let Some(hex) = entity
                .strip_prefix('x')
                .or_else(|| entity.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                entity.parse::<u32>().ok().and_then(char::from_u32)
            };
            if let Some(ch) = decoded {
                let before = &result[..start];
                let after = &result[start + 2 + end + 1..];
                result = format!("{}{}{}", before, ch, after);
            } else {
                break; // Decodeof, AvoidinfiniteLoop
            }
        } else {
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests;
