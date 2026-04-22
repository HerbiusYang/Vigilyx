//! Detection module - Email content anomaly and phishing detection
//!
//! Engine analysis:
//!
//! Engine A - Rust CJK gibberish/nonsense detection (3 dimensions):
//! 1. CJK rare character ratio
//! 2. Shannon entropy analysis
//! 3. Bigram uniqueness anomaly
//!
//! Engine B - NLP phishing detection (remote Python HuggingFace model):
//! Calls Python AI service at /analyze/content,
//! uses Transformer classification model,
//! specialized for Chinese phishing/spam/BEC detection.
//! Falls back to Rust rule-based analysis when Python service is unavailable.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use rayon::prelude::*;
use tracing::{debug, warn};

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::common::looks_like_raw_mime_container_text;
use crate::modules::content_scan::{
    sanitize_body_for_keyword_scan, strip_subject_banner_prefixes,
};
use crate::pipeline::verdict::runtime_scenario_patterns;
use crate::remote::{ContentAnalysisRequest, RemoteError, RemoteModuleProxy};

/// Minimum CJK character count to trigger parallel bigram analysis.
const BIGRAM_PAR_THRESHOLD: usize = 10_000;

pub struct SemanticScanModule {
    meta: ModuleMetadata,
   /// Remote NLP Service (Python HuggingFace)
    remote: Option<RemoteModuleProxy>,
}

impl SemanticScanModule {
    pub fn new(remote: Option<RemoteModuleProxy>) -> Self {
        let has_nlp = remote.is_some();
        Self {
            meta: ModuleMetadata {
                id: "semantic_scan".to_string(),
                name: "Semantic Analysis".to_string(),
                description: if has_nlp {
                    "NLP phishing intent detection + CJK gibberish detection (HuggingFace Transformer)"
                        .to_string()
                } else {
                    "Detect nonsensical gibberish, rare character obfuscation, and entropy anomalies in email body".to_string()
                },
                pillar: Pillar::Semantic,
                depends_on: vec![],
                timeout_ms: if has_nlp { 12_000 } else { 3000 },
                is_remote: has_nlp,
                supports_ai: has_nlp,
                cpu_bound: !has_nlp,
                inline_priority: None,
            },
            remote,
        }
    }
}

/// Minimum CJK character count to begin analysis (short emails are skipped)
const MIN_CJK_CHARS: usize = 10;

/// Normal Chinese text Shannon entropy range (bits per character)
const ENTROPY_NORMAL_LOW: f64 = 4.0;
const ENTROPY_NORMAL_HIGH: f64 = 7.5;

/// Rare CJK character ratio threshold to trigger detection
const RARE_CJK_THRESHOLD: f64 = 0.05;

/// Bigram uniqueness threshold: normal text reuses bigrams; gibberish has near 100% unique bigrams
const BIGRAM_UNIQUE_THRESHOLD: f64 = 0.92;

/// NLP remote timeout. Semantic NLP is supplementary; a long wait should not
/// stall the whole verdict path when the AI side is overloaded.
/// Raised from 4s → 8s because the 55-core server under load regularly
/// exceeds 4s, causing unnecessary backoff escalation.
const NLP_TIMEOUT: Duration = Duration::from_secs(8);

// Unicode range detection

/// Check whether a character is in the CJK basic block (U+4E00..U+9FFF)
fn is_cjk_basic(ch: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&ch)
}

/// Check whether a character is in a CJK extended block (rare characters)
/// Includes Ext-A, Ext-B, Ext-C, Ext-D, Ext-E, Ext-F, Ext-G, and Compatibility Ideographs
fn is_cjk_rare(ch: char) -> bool {
    let c = ch as u32;
   // CJK Ext-A: U+3400..U+4DBF
    (0x3400..=0x4DBF).contains(&c)
   // CJK Ext-B: U+20000..U+2A6DF
    || (0x20000..=0x2A6DF).contains(&c)
   // CJK Ext-C: U+2A700..U+2B73F
    || (0x2A700..=0x2B73F).contains(&c)
   // CJK Ext-D: U+2B740..U+2B81F
    || (0x2B820..=0x2CEAF).contains(&c)
   // CJK Ext-F: U+2CEB0..U+2EBEF
    || (0x2CEB0..=0x2EBEF).contains(&c)
   // CJK Ext-G: U+30000..U+3134F
    || (0x30000..=0x3134F).contains(&c)
   // CJK Compatibility Ideographs: U+F900..U+FAFF
    || (0xF900..=0xFAFF).contains(&c)
   // CJK Compatibility Ideographs Supplement: U+2F800..U+2FA1F
    || (0x2F800..=0x2FA1F).contains(&c)
}

/// Check whether a character is any CJK ideograph (basic or extended)
fn is_cjk_any(ch: char) -> bool {
    is_cjk_basic(ch) || is_cjk_rare(ch)
}

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
// CJK gibberish analysis dimensions

/// Dimension 1: Rare CJK character ratio
fn analyze_rare_cjk(text: &str) -> (usize, usize, f64) {
    let mut rare_count = 0usize;
    let mut total_cjk = 0usize;

    for ch in text.chars() {
        if is_cjk_any(ch) {
            total_cjk += 1;
            if is_cjk_rare(ch) {
                rare_count += 1;
            }
        }
    }

    let ratio = if total_cjk > 0 {
        rare_count as f64 / total_cjk as f64
    } else {
        0.0
    };

    (rare_count, total_cjk, ratio)
}

/// Dimension 2: Shannon entropy of CJK characters
fn analyze_entropy(text: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;

    for ch in text.chars() {
        if is_cjk_any(ch) {
           *freq.entry(ch).or_insert(0) += 1;
            total += 1;
        }
    }

    if total == 0 {
        return 0.0;
    }

    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for &count in freq.values() {
        let p = count as f64 / total_f;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Dimension 3: Bigram uniqueness ratio
fn analyze_bigram(text: &str) -> (f64, usize) {
    let cjk_chars: Vec<char> = text.chars().filter(|ch| is_cjk_any(*ch)).collect();
    if cjk_chars.len() < 2 {
        return (0.0, 0);
    }

    let total_bigrams = cjk_chars.len() - 1;

    let unique_count = if cjk_chars.len() >= BIGRAM_PAR_THRESHOLD {
        (0..total_bigrams)
            .into_par_iter()
            .fold(HashSet::new, |mut set, i| {
                set.insert((cjk_chars[i], cjk_chars[i + 1]));
                set
            })
            .reduce(HashSet::new, |mut a, b| {
                a.extend(b);
                a
            })
            .len()
    } else {
        let mut bigram_counts: HashMap<(char, char), usize> = HashMap::new();
        for pair in cjk_chars.windows(2) {
           *bigram_counts.entry((pair[0], pair[1])).or_insert(0) += 1;
        }
        bigram_counts.len()
    };

    let unique_ratio = unique_count as f64 / total_bigrams as f64;
    (unique_ratio, total_bigrams)
}

/// Score CJK content across 3 anomaly dimensions
fn score_semantics(text: &str) -> (f64, Vec<Evidence>) {
    let mut evidence = Vec::new();
    let mut score = 0.0f64;

    let (rare_count, total_cjk, rare_ratio) = analyze_rare_cjk(text);

    if total_cjk < MIN_CJK_CHARS {
        return (0.0, evidence);
    }

   // Dimension 1: Rare character ratio (weight 0.4)
    if rare_ratio > RARE_CJK_THRESHOLD {
        let normalized = ((rare_ratio - RARE_CJK_THRESHOLD) / 0.25).min(1.0);
        let dim_score = (normalized * 0.4).min(0.4);
        score += dim_score;

        let rare_samples: Vec<char> = text
            .chars()
            .filter(|ch| is_cjk_rare(*ch))
            .take(10)
            .collect();

        evidence.push(Evidence {
            description: format!(
                "Rare CJK character ratio {:.1}% ({}/{} characters), exceeds {}% threshold",
                rare_ratio * 100.0,
                rare_count,
                total_cjk,
                (RARE_CJK_THRESHOLD * 100.0) as u32,
            ),
            location: Some("body".to_string()),
            snippet: Some(format!(
                "Rare character samples: {}",
                rare_samples.iter().collect::<String>()
            )),
        });
    }

   // Dimension 2: Entropy anomaly (weight 0.3)
    let entropy = analyze_entropy(text);
    let entropy_anomaly = if entropy < ENTROPY_NORMAL_LOW && entropy > 0.0 {
        ((ENTROPY_NORMAL_LOW - entropy) / ENTROPY_NORMAL_LOW).min(1.0)
    } else if entropy > ENTROPY_NORMAL_HIGH {
        ((entropy - ENTROPY_NORMAL_HIGH) / 3.0).min(1.0)
    } else {
        0.0
    };

    if entropy_anomaly > 0.1 {
        let dim_score = (entropy_anomaly * 0.3).min(0.3);
        score += dim_score;

        let anomaly_type = if entropy < ENTROPY_NORMAL_LOW {
            "low (excessive character repetition)"
        } else {
            "high (overly random characters)"
        };

        evidence.push(Evidence {
            description: format!(
                "CJK character entropy {:.2} bits {}, normal range {:.1}-{:.1} bits",
                entropy, anomaly_type, ENTROPY_NORMAL_LOW, ENTROPY_NORMAL_HIGH,
            ),
            location: Some("body".to_string()),
            snippet: None,
        });
    }

   // Dimension 3: Bigram uniqueness anomaly (weight 0.3)
    let (bigram_unique, bigram_total) = analyze_bigram(text);
    if bigram_total >= 50 {
        let bigram_anomaly = if bigram_unique > BIGRAM_UNIQUE_THRESHOLD {
            ((bigram_unique - BIGRAM_UNIQUE_THRESHOLD) / (1.0 - BIGRAM_UNIQUE_THRESHOLD)).min(1.0)
        } else if bigram_unique < 0.1 && bigram_total > 10 {
            1.0
        } else {
            0.0
        };

        if bigram_anomaly > 0.1 {
            let dim_score = (bigram_anomaly * 0.3).min(0.3);
            score += dim_score;

            evidence.push(Evidence {
                description: format!(
                    "Bigram uniqueness ratio {:.1}% ({} bigrams), {}",
                    bigram_unique * 100.0,
                    bigram_total,
                    if bigram_unique > BIGRAM_UNIQUE_THRESHOLD {
                        "anomalously high (character pairs almost never repeat)"
                    } else {
                        "anomalously low (excessive repeated character pairs)"
                    },
                ),
                location: Some("body".to_string()),
                snippet: None,
            });
        }
    }

    (score.min(1.0), evidence)
}

/// Lightweight heuristic for AI/LLM-generated phishing prose.
///
/// Modern phishing campaigns increasingly use ChatGPT-class LLMs to draft
/// extremely polished, grammatically perfect copy. A handful of stylistic
/// fingerprints distinguish that prose from authentic human business mail:
///
/// * an unusually high density of long, multi-clause sentences;
/// * boilerplate "AI assistant" phrases ("I hope this email finds you well",
///   "I am reaching out regarding…", "please do not hesitate to…",
///   "我希望这封邮件能在一切顺利时找到您");
/// * over-frequent transitional connectives (Furthermore / Moreover / 此外 / 然而);
/// * conspicuously low contraction usage in English (LLMs prefer "do not"
///   over "don't"), combined with formal register that does not match a
///   short, urgent context.
///
/// These signals are individually weak — many legitimate writers also write
/// formally. We therefore (a) require multiple independent fingerprints to
/// fire and (b) cap the contribution at 0.30 so the module degrades to a
/// soft signal rather than a hard verdict. Detection runs on **already
/// HTML-stripped body text** so layout markup does not pollute scoring.
pub(super) fn detect_llm_generated_text(text: &str) -> (f64, Vec<&'static str>) {
    let mut hits: Vec<&'static str> = Vec::new();
    let trimmed = text.trim();
    if trimmed.chars().count() < 80 {
        // Too short to draw a stylistic conclusion.
        return (0.0, hits);
    }

    let lower = trimmed.to_lowercase();

    // 1. Boilerplate openers / closers that LLMs default to.
    const LLM_BOILERPLATE: &[&str] = &[
        "i hope this email finds you well",
        "i hope this message finds you well",
        "i am reaching out regarding",
        "i am writing to inform you",
        "i am writing to let you know",
        "please do not hesitate to",
        "should you have any questions",
        "should you require any further",
        "thank you for your time and consideration",
        "looking forward to your prompt response",
        "we appreciate your understanding",
        "we kindly ask that you",
        "as previously mentioned",
        "in light of recent",
        "我希望这封邮件",
        "希望您一切顺利",
        "如有任何疑问，请随时",
        "如您有任何问题",
        "感谢您的理解与配合",
        "期待您的及时回复",
        "请您务必在",
        "为了确保您的账户",
    ];
    let mut boilerplate_count = 0;
    for phrase in LLM_BOILERPLATE {
        if lower.contains(phrase) {
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
    const CONNECTIVES: &[&str] = &[
        "furthermore", "moreover", "additionally", "consequently",
        "subsequently", "nevertheless", "nonetheless", "henceforth",
        "thereafter", "in conclusion", "to summarize",
    ];
    let connective_hits: usize = CONNECTIVES.iter().filter(|c| lower.contains(*c)).count();
    if connective_hits >= 3 {
        hits.push("dense formal connectives (LLM register)");
    }

    // 3. Mandarin equivalent — overly literary connectives are also a strong
    // signal in Chinese LLM-translated phishing.
    const ZH_CONNECTIVES: &[&str] = &[
        "此外", "然而", "尽管如此", "综上所述", "因此", "鉴于此", "与此同时",
    ];
    let zh_connective_hits: usize = ZH_CONNECTIVES.iter().filter(|c| trimmed.contains(*c)).count();
    if zh_connective_hits >= 3 {
        hits.push("dense formal Chinese connectives");
    }

    // 4. Long-sentence dominance. Split on Latin and Chinese sentence enders.
    let mut sentence_lengths: Vec<usize> = Vec::new();
    let mut current_len = 0usize;
    for ch in trimmed.chars() {
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
    let expanded = ["do not ", "will not ", "cannot ", "i am ", "we are ", "you are "]
        .iter()
        .map(|p| lower.matches(*p).count())
        .sum::<usize>();
    let contracted = ["don't ", "won't ", "can't ", "i'm ", "we're ", "you're "]
        .iter()
        .map(|p| lower.matches(*p).count())
        .sum::<usize>();
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

    (score, hits)
}

#[derive(Debug, Default, Clone)]
struct NlpSignalProfile {
    model_type: Option<String>,
    top_label: Option<String>,
    top_score: f64,
    malicious_probability: f64,
    legitimate_probability: f64,
}

fn summarize_nlp_signal(details: &serde_json::Value) -> NlpSignalProfile {
    let probabilities = details.get("probabilities");
    NlpSignalProfile {
        model_type: details
            .get("model_type")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        top_label: details
            .get("top_label")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        top_score: details
            .get("top_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        malicious_probability: details
            .get("malicious_probability")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        legitimate_probability: probabilities
            .and_then(|v| v.get("legitimate"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
    }
}

fn zero_shot_nlp_is_actionable(profile: &NlpSignalProfile, has_rule_corroboration: bool) -> bool {
    if profile.model_type.as_deref() != Some("zero-shot") {
        return true;
    }
    if !has_rule_corroboration {
        return false;
    }
    if profile.top_label.as_deref() == Some("legitimate") {
        return false;
    }
    if profile.top_score < 0.45 {
        return false;
    }
    if profile.malicious_probability < 0.80 {
        return false;
    }
    if profile.legitimate_probability > 0.0
        && profile.top_score <= profile.legitimate_probability + 0.10
    {
        return false;
    }
    true
}

/// Strip HTML tags from content
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
    result
}

fn sanitize_semantic_inputs(subject: Option<&str>, raw_body: &str) -> (Option<String>, String) {
    let patterns = runtime_scenario_patterns();
    let cleaned_subject = subject
        .map(|value| {
            strip_subject_banner_prefixes(
                value,
                &patterns.gateway_banner_patterns,
                &patterns.notice_banner_patterns,
            )
        })
        .filter(|value| !value.trim().is_empty());
    let cleaned_body = sanitize_body_for_keyword_scan(
        raw_body,
        &patterns.gateway_banner_patterns,
        &patterns.notice_banner_patterns,
        &patterns.dsn_patterns,
        &patterns.auto_reply_patterns,
    );
    (cleaned_subject, cleaned_body)
}

#[async_trait]
impl SecurityModule for SemanticScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

       // Get email body text
        let raw_body = match (
            ctx.session.content.body_text.as_ref(),
            ctx.session.content.body_html.as_ref(),
        ) {
            (Some(text), Some(html)) if looks_like_raw_mime_container_text(text) => strip_html_tags(html),
            (Some(text), None) if looks_like_raw_mime_container_text(text) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                return Ok(ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    "Body appears to be raw MIME container text, skipping semantic analysis",
                    duration_ms,
                ));
            }
            (Some(text), _) => text.clone(),
            (None, Some(html)) => strip_html_tags(html),
            (None, None) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                return Ok(ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    "No email body, skipping semantic analysis",
                    duration_ms,
                ));
            }
        };
        let (cleaned_subject, body) =
            sanitize_semantic_inputs(ctx.session.subject.as_deref(), &raw_body);

        if body.trim().is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "Body contains only gateway/notice banner noise, skipping semantic analysis",
                duration_ms,
            ));
        }

        
       // Engine B: NLP phishing detection - fire request immediately (async, non-blocking)
        
        let nlp_configured = self.remote.is_some();
        let mut nlp_skipped_temporarily = false;
        let mut nlp_status = if nlp_configured { "pending" } else { "disabled" };
        let mut nlp_retry_after_secs: Option<u64> = None;
        let mut nlp_status_message = if nlp_configured {
            None
        } else {
            Some("AI/NLP service is not configured; using rule-based analysis only".to_string())
        };
        let nlp_handle = if let Some(ref remote) = self.remote {
            if !remote.is_request_available() {
                nlp_skipped_temporarily = true;
                nlp_status = "cooldown";
                nlp_retry_after_secs = Some(remote.cooldown_remaining_secs());
                nlp_status_message = Some(format!(
                    "AI/NLP service is temporarily unavailable; retry after about {}s",
                    nlp_retry_after_secs.unwrap_or_default()
                ));
                debug!(
                    retry_after_secs = remote.cooldown_remaining_secs(),
                    "Skipping NLP request while AI remote is in cooldown"
                );
                None
            } else {
                let req = ContentAnalysisRequest {
                    session_id: ctx.session.id.to_string(),
                    subject: cleaned_subject.clone(),
                    body_text: Some(body.clone()),
                    body_html: None,
                    mail_from: ctx.session.mail_from.clone(),
                    rcpt_to: ctx.session.rcpt_to.clone(),
                };
                debug!("Firing NLP request first (most time-consuming)");
                let remote = remote.clone();
                Some(tokio::spawn(async move {
                    match tokio::time::timeout(NLP_TIMEOUT, remote.analyze_content(&req)).await {
                        Ok(result) => result,
                        Err(_) => {
                            remote.note_timeout();
                            Err(RemoteError::Timeout)
                        }
                    }
                }))
            }
        } else {
            None
        };

        
       // Engine A: Rust CJK gibberish detection (runs in parallel with NLP request)
        
        let (mut score, mut evidence) = score_semantics(&body);
        let gibberish_evidence_count = evidence.len(); // P2-4: track gibberish-specific evidence
        let mut categories: Vec<String> = Vec::new();

        // Engine A.5: AI/LLM-generated phishing prose detection.
        //
        // We only escalate the LLM-style signal when the message also carries
        // *some* other risk indicator — formal prose alone is not phishing.
        // The dependency check happens after the rest of the pipeline has
        // populated `categories`; we therefore stash the score and apply it
        // conditionally below.
        let (llm_raw_score, llm_hits) = detect_llm_generated_text(&body);
        if !llm_hits.is_empty() {
            evidence.push(Evidence {
                description: format!(
                    "AI/LLM-generated prose fingerprint: {}",
                    llm_hits.join("; ")
                ),
                location: Some("body:style".to_string()),
                snippet: Some(body.chars().take(120).collect::<String>()),
            });
        }

       // Language anomaly detection
        let total_chars: usize = body.chars().filter(|c| !c.is_whitespace()).count();
        let cjk_count: usize = body.chars().filter(|c| is_cjk_any(*c)).count();
        let is_non_chinese = total_chars > 30 && cjk_count == 0;

        if is_non_chinese {
           // Skip known financial sender domains (legitimate foreign-language emails)
            let sender_domain = ctx
                .session
                .mail_from
                .as_deref()
                .and_then(|m| m.rsplit('@').next())
                .unwrap_or("");
            let is_known_financial_sender = module_data().contains("known_financial_sender_domains", sender_domain);

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
                        || module_data().contains("protected_domains", d)
                });

                if is_cn_corp {
                    score += 0.30;
                    categories.push("foreign_to_cn_corp".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Pure foreign-language email (no Chinese content, {} chars) sent to Chinese corporate mailbox — highly suspicious",
                            total_chars,
                        ),
                        location: Some("body:language".to_string()),
                        snippet: Some(body.chars().take(100).collect::<String>()),
                    });
                } else {
                    score += 0.10;
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
            let jp_kana_count = body.chars().filter(|c| is_japanese_kana(*c)).count();
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
                        || module_data().contains("protected_domains", d)
                });
                let is_jp_corp = rcpt_domains.iter().any(|d| {
                    d.ends_with(".jp") || d.ends_with(".co.jp")
                });

                if is_cn_corp && !is_jp_corp {
                    
                    score += 0.35;
                    categories.push("japanese_to_cn_corp".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Japanese email ({} kana characters) sent to Chinese corporate mailbox — suspected Japanese delivery/account phishing",
                            jp_kana_count,
                        ),
                        location: Some("body:language_mismatch".to_string()),
                        snippet: Some(body.chars().take(100).collect::<String>()),
                    });
                } else if !is_jp_corp {
                    
                    score += 0.15;
                    categories.push("japanese_unexpected".to_string());
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

       // Rule-based sextortion detection (works even when NLP is unavailable)
       // Pattern: threat language + cryptocurrency payment demand
        let body_lower = body.to_lowercase();
        let (threat_signals, payment_signals): (Vec<String>, Vec<String>) = {
            let md = module_data();
            let threats = md
                .get_list("sextortion_threat_signals")
                .iter()
                .filter(|kw| body_lower.contains(kw.as_str()))
                .cloned()
                .collect();
            let payments = md
                .get_list("sextortion_payment_signals")
                .iter()
                .filter(|kw| body_lower.contains(kw.as_str()))
                .cloned()
                .collect();
            (threats, payments)
        };

        if !threat_signals.is_empty() && !payment_signals.is_empty() {
               // Threat language + payment demand = sextortion email
            score += 0.60;
            categories.push("sextortion".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Sextortion indicators: {} threatening phrases + {} cryptocurrency payment demands",
                    threat_signals.len(),
                    payment_signals.len()
                ),
                location: Some("body:semantic".to_string()),
                snippet: Some(format!(
                    "threats=[{}] payment=[{}]",
                    threat_signals.join(", "),
                    payment_signals.join(", ")
                )),
            });
        } else if threat_signals.len() >= 2 {
            score += 0.30;
            categories.push("extortion_threat".to_string());
            evidence.push(Evidence {
                description: format!("Detected {} threatening/intimidating phrases", threat_signals.len()),
                location: Some("body:semantic".to_string()),
                snippet: Some(threat_signals.join(", ")),
            });
        }

        // P2-4 fix: only push nonsensical_spam when gibberish detection (score_semantics)
        // actually produced evidence. Previously this checked ALL evidence including
        // language mismatch, sextortion etc., causing false positives on normal emails
        // like scanner-generated forwards.
        if gibberish_evidence_count > 0 {
            categories.push("nonsensical_spam".to_string());
        }

        
       // Await NLP result (Rust analysis already complete, NLP should be done or nearly done)
        
        let has_rule_corroboration =
            gibberish_evidence_count > 0 || !categories.is_empty() || score >= 0.20;

        let mut nlp_used = false;
        let mut nlp_contributed = false;
        let mut nlp_contribution_score = 0.0;
        let mut nlp_details = serde_json::Value::Null;

        if let Some(handle) = nlp_handle {
            match handle.await {
                Ok(Ok(ai_resp)) => {
                    nlp_used = true;
                    let nlp_threat = ai_resp.to_threat_level();
                    let nlp_confidence = ai_resp.confidence;
                    nlp_details = ai_resp.details.unwrap_or(serde_json::Value::Null);
                    let signal_profile = summarize_nlp_signal(&nlp_details);
                    let zero_shot_advisory_only =
                        signal_profile.model_type.as_deref() == Some("zero-shot")
                            && !zero_shot_nlp_is_actionable(
                                &signal_profile,
                                has_rule_corroboration,
                            );

                    let mut nlp_evidence_description = format!(
                        "NLP model verdict: {} (confidence {:.1}%) — {}",
                        ai_resp.threat_level,
                        nlp_confidence * 100.0,
                        ai_resp.summary,
                    );
                    if zero_shot_advisory_only {
                        nlp_evidence_description.push_str(
                            " (zero-shot advisory only; not used for scoring)",
                        );
                    }
                    evidence.push(Evidence {
                        description: nlp_evidence_description,
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });

                    let nlp_base = match (signal_profile.model_type.as_deref(), nlp_threat) {
                        (_, ThreatLevel::Safe | ThreatLevel::Low) => 0.0,
                        (Some("zero-shot"), ThreatLevel::Medium) => 0.05,
                        (Some("zero-shot"), ThreatLevel::High) => 0.08,
                        (Some("zero-shot"), ThreatLevel::Critical) => 0.10,
                        (_, ThreatLevel::Medium) => 0.10,
                        (_, ThreatLevel::High) => 0.15,
                        (_, ThreatLevel::Critical) => 0.20,
                    };

                    let nlp_score = if zero_shot_advisory_only {
                        0.0
                    } else if signal_profile.model_type.as_deref() == Some("zero-shot") {
                        if nlp_confidence >= 0.80 && nlp_threat >= ThreatLevel::High {
                            (nlp_base + nlp_confidence * 0.03).min(0.12)
                        } else {
                            nlp_base
                        }
                    } else if nlp_confidence >= 0.70 && nlp_threat >= ThreatLevel::High {
                        (nlp_base + nlp_confidence * 0.08).min(0.22)
                    } else {
                        nlp_base
                    };

                    if nlp_score > 0.0 {
                        nlp_contributed = true;
                        nlp_contribution_score = nlp_score;
                        score += nlp_score;
                        nlp_status = "ok";
                        nlp_status_message = Some(
                            "AI/NLP analysis completed and provided corroborating evidence"
                                .to_string(),
                        );
                        categories.extend(ai_resp.categories.clone());
                    } else {
                        nlp_status = "ok";
                        nlp_status_message = Some(
                            "AI/NLP analysis completed but remained advisory-only; rule engine stayed primary"
                                .to_string(),
                        );
                    }
                }
                Ok(Err(RemoteError::TemporarilyUnavailable { retry_after_secs })) => {
                    nlp_skipped_temporarily = true;
                    nlp_status = "cooldown";
                    nlp_retry_after_secs = Some(retry_after_secs);
                    nlp_status_message = Some(format!(
                        "AI/NLP service is temporarily unavailable; retry after about {}s",
                        retry_after_secs
                    ));
                    warn!(
                        retry_after_secs,
                        "NLP service temporarily unavailable, skipping semantic NLP"
                    );
                    evidence.push(Evidence {
                        description: format!(
                            "NLP service temporarily unavailable (retry after ~{}s); falling back to rule-based detection",
                            retry_after_secs
                        ),
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });
                }
                Ok(Err(RemoteError::Timeout)) => {
                    nlp_status = "timeout";
                    nlp_status_message = Some(format!(
                        "AI/NLP request timed out after {}s; using rule-based analysis only",
                        NLP_TIMEOUT.as_secs()
                    ));
                    warn!(
                        "NLP service timeout ({}s), falling back to rule-based",
                        NLP_TIMEOUT.as_secs()
                    );
                    evidence.push(Evidence {
                        description: format!(
                            "NLP service timeout ({}s) (falling back to rule-based detection)",
                            NLP_TIMEOUT.as_secs()
                        ),
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });
                }
                Ok(Err(e)) => {
                    nlp_status = "error";
                    nlp_status_message = Some(format!(
                        "AI/NLP request failed: {}; using rule-based analysis only",
                        e
                    ));
                    warn!("NLP service error: {}, falling back to rule-based", e);
                    evidence.push(Evidence {
                        description: format!(
                            "NLP service call failed: {} (falling back to rule-based detection)",
                            e
                        ),
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });
                }
                Err(e) => {
                    nlp_status = "error";
                    nlp_status_message = Some(format!(
                        "AI/NLP task terminated unexpectedly: {}; using rule-based analysis only",
                        e
                    ));
                    warn!("NLP task panicked: {}, falling back to rule-based", e);
                    evidence.push(Evidence {
                        description: format!("NLP task abnormal: {} (falling back to rule-based detection)", e),
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });
                }
            }
        }

        
       // Build final result
        
        // Apply LLM-style fingerprint contribution only when corroborated by
        // at least one other risk signal — formal prose alone must never push
        // a benign newsletter into Low. We treat the presence of any
        // category, any rule-based gibberish hit, or any sextortion match as
        // sufficient corroboration.
        if llm_raw_score > 0.0
            && (!categories.is_empty()
                || gibberish_evidence_count > 0
                || evidence.len() > gibberish_evidence_count + 1)
        {
            score += llm_raw_score;
            categories.push("llm_generated_prose".to_string());
        }

        score = score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(score);

        if threat_level == ThreatLevel::Safe {
            let summary = if nlp_contributed {
                "Rule engine + corroborated NLP analysis: email body semantics normal".to_string()
            } else if nlp_used {
                "Rule engine analysis completed; advisory NLP signal did not affect scoring"
                    .to_string()
            } else if nlp_status == "timeout" {
                format!(
                    "Rule engine analysis completed after NLP timeout ({}s)",
                    NLP_TIMEOUT.as_secs()
                )
            } else if nlp_skipped_temporarily {
                if let Some(retry_after_secs) = nlp_retry_after_secs {
                    format!(
                        "Rule engine analysis completed while NLP service cooldown was active (retry after ~{}s)",
                        retry_after_secs
                    )
                } else {
                    "Rule engine analysis completed while NLP service cooldown was active"
                        .to_string()
                }
            } else if nlp_status == "error" {
                "Rule engine analysis completed because AI/NLP request failed".to_string()
            } else if nlp_status == "disabled" {
                "Rule engine analysis completed (AI/NLP not configured)".to_string()
            } else if is_non_chinese {
                "Pure foreign-language email, below threat threshold (NLP service not enabled)".to_string()
            } else {
                "Email body semantics normal, no gibberish or rare character anomalies found".to_string()
            };

            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: if nlp_contributed { 0.62 } else { 0.70 },
                categories: vec![],
                summary,
                evidence,
                details: serde_json::json!({
                    "score": score,
                    "nlp_configured": nlp_configured,
                    "nlp_enabled": nlp_used,
                    "nlp_used": nlp_used,
                    "nlp_contributed": nlp_contributed,
                    "nlp_contribution_score": nlp_contribution_score,
                    "nlp_status": nlp_status,
                    "nlp_status_message": nlp_status_message,
                    "nlp_skipped_temporarily": nlp_skipped_temporarily,
                    "nlp_retry_after_secs": nlp_retry_after_secs,
                    "nlp_timeout_secs": NLP_TIMEOUT.as_secs(),
                    "nlp_details": nlp_details,
                    "analysis_type": if nlp_contributed {
                        "rules_plus_nlp_corroboration"
                    } else if nlp_used {
                        "rules_primary_nlp_observed"
                    } else {
                        "rules_only"
                    },
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: None,
                engine_id: None,
            });
        }

       // NLP confidence set lower (model misclassifies ~60% of the time)
       // Rule-based heuristics have more predictable behavior, so they get higher confidence
        let confidence = if nlp_contributed { 0.60 } else { 0.80 };

        let summary = if nlp_contributed {
            format!(
                "Rule engine + corroborated NLP detected threat (score {:.2}, {} evidence items)",
                score,
                evidence.len()
            )
        } else if nlp_used {
            format!(
                "Rule engine detected threat (score {:.2}); advisory NLP signal did not raise the score",
                score
            )
        } else if nlp_status == "timeout" {
            format!(
                "Semantic anomaly detected (score {:.2}); NLP timed out after {}s and rule-based detection continued",
                score,
                NLP_TIMEOUT.as_secs()
            )
        } else if nlp_status == "disabled" {
            format!(
                "Semantic anomaly detected (score {:.2}) using rule-based analysis only (AI/NLP not configured)",
                score
            )
        } else if nlp_status == "error" {
            format!(
                "Semantic anomaly detected (score {:.2}) after AI/NLP request failure; rule-based detection continued",
                score
            )
        } else if nlp_skipped_temporarily {
            if let Some(retry_after_secs) = nlp_retry_after_secs {
                format!(
                    "Semantic anomaly detected (score {:.2}) while AI/NLP service cooldown was active (~{}s retry)",
                    score,
                    retry_after_secs
                )
            } else {
                format!(
                    "Semantic anomaly detected (score {:.2}) while AI/NLP service cooldown was active",
                    score
                )
            }
        } else {
            format!(
                "Semantic anomaly detected (score {:.2}), found {} anomalous evidence items",
                score,
                evidence.len()
            )
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories,
            summary,
            evidence,
            details: serde_json::json!({
                "score": score,
                "nlp_configured": nlp_configured,
                "nlp_enabled": nlp_used,
                "nlp_used": nlp_used,
                "nlp_contributed": nlp_contributed,
                "nlp_contribution_score": nlp_contribution_score,
                "nlp_status": nlp_status,
                "nlp_status_message": nlp_status_message,
                "nlp_skipped_temporarily": nlp_skipped_temporarily,
                "nlp_retry_after_secs": nlp_retry_after_secs,
                "nlp_timeout_secs": NLP_TIMEOUT.as_secs(),
                "nlp_details": nlp_details,
                "analysis_type": if nlp_contributed {
                    "rules_plus_nlp_corroboration"
                } else if nlp_used {
                    "rules_primary_nlp_observed"
                } else {
                    "rules_only"
                },
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::context::SecurityContext;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    // ─── LLM-generated prose detection ───

    #[test]
    fn llm_detector_flags_multi_signal_text() {
        // Boilerplate opener + dense connectives + zero contractions
        let text = "I hope this email finds you well. I am writing to inform you that \
                    we have detected unusual activity on your account. Furthermore, \
                    you do not appear to have responded to our previous notice. \
                    Moreover, we cannot proceed without your verification. \
                    Additionally, you are required to confirm your identity. \
                    Should you have any questions, please do not hesitate to contact us.";
        let (score, hits) = detect_llm_generated_text(text);
        assert!(score > 0.0, "should fire on multi-signal LLM text, got hits={:?}", hits);
        assert!(hits.len() >= 2, "expected >=2 independent fingerprints, got {:?}", hits);
    }

    #[test]
    fn llm_detector_ignores_short_text() {
        let text = "Hi, your invoice is attached.";
        let (score, _) = detect_llm_generated_text(text);
        assert_eq!(score, 0.0, "short text must not fire LLM detector");
    }

    #[test]
    fn llm_detector_ignores_natural_human_writing() {
        // Plenty of contractions, no LLM boilerplate, varied sentence length
        let text = "Hey team — quick heads-up: I won't be able to join standup tomorrow. \
                    I've got a doctor's appointment that ran long. Can someone cover the \
                    deployment? Thanks!";
        let (score, hits) = detect_llm_generated_text(text);
        assert_eq!(score, 0.0, "natural human prose must not fire, got hits={:?}", hits);
    }

    #[test]
    fn llm_detector_single_signal_does_not_fire() {
        // Only one boilerplate phrase, nothing else suspicious
        let text = "Hello, I hope this email finds you well. Attached is the report \
                    you asked for last week. Let me know if anything looks off. \
                    Thanks, Bob.";
        let (score, _) = detect_llm_generated_text(text);
        assert_eq!(score, 0.0, "single weak signal must not fire LLM detector");
    }

    #[test]
    fn llm_detector_chinese_signals() {
        let text = "尊敬的用户，我希望这封邮件能在一切顺利时找到您。\
                    此外，您的账户存在异常登录记录。\
                    然而，我们尚未收到您的回复。\
                    与此同时，请您务必在24小时内完成身份验证，\
                    如有任何疑问，请随时联系我们。\
                    感谢您的理解与配合。";
        let (score, hits) = detect_llm_generated_text(text);
        assert!(score > 0.0, "Chinese LLM-style text should fire, got hits={:?}", hits);
    }

    #[test]
    fn zero_shot_nlp_requires_rule_corroboration() {
        let profile = NlpSignalProfile {
            model_type: Some("zero-shot".to_string()),
            top_label: Some("scam".to_string()),
            top_score: 0.91,
            malicious_probability: 0.96,
            legitimate_probability: 0.02,
        };

        assert!(!zero_shot_nlp_is_actionable(&profile, false));
    }

    #[test]
    fn zero_shot_legitimate_top_label_stays_advisory() {
        let profile = NlpSignalProfile {
            model_type: Some("zero-shot".to_string()),
            top_label: Some("legitimate".to_string()),
            top_score: 0.62,
            malicious_probability: 0.83,
            legitimate_probability: 0.58,
        };

        assert!(!zero_shot_nlp_is_actionable(&profile, true));
    }

    #[test]
    fn zero_shot_strong_corroborated_signal_is_actionable() {
        let profile = NlpSignalProfile {
            model_type: Some("zero-shot".to_string()),
            top_label: Some("phishing".to_string()),
            top_score: 0.72,
            malicious_probability: 0.91,
            legitimate_probability: 0.08,
        };

        assert!(zero_shot_nlp_is_actionable(&profile, true));
    }

    #[test]
    fn fine_tuned_nlp_can_contribute_without_zero_shot_gate() {
        let profile = NlpSignalProfile {
            model_type: Some("fine-tuned".to_string()),
            top_label: Some("phishing".to_string()),
            top_score: 0.34,
            malicious_probability: 0.62,
            legitimate_probability: 0.28,
        };

        assert!(zero_shot_nlp_is_actionable(&profile, false));
    }

    fn make_ctx(body_text: Option<&str>, body_html: Option<&str>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            body_html: body_html.map(str::to_string),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_raw_mime_container_text_is_skipped() {
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx(
            Some(
                "--=_NextPart_123\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\nU29tZSBiYXNlNjQgcGF5bG9hZA==\r\n",
            ),
            None,
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.summary.contains("raw MIME container text"));
        assert!(result.categories.is_empty());
    }

    #[tokio::test]
    async fn test_semantic_scan_reports_nlp_disabled_when_unconfigured() {
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx(Some("这是一封正常的中文业务邮件。"), None);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.details["nlp_configured"], serde_json::json!(false));
        assert_eq!(result.details["nlp_status"], serde_json::json!("disabled"));
        assert_eq!(result.details["analysis_type"], serde_json::json!("rules_only"));
        assert!(result.summary.contains("AI/NLP not configured"));
    }

    #[test]
    fn sanitize_semantic_inputs_strips_gateway_banner_noise() {
        crate::pipeline::verdict::set_runtime_scenario_patterns(
            crate::pipeline::verdict::ScenarioPatternLists {
                gateway_banner_patterns: vec![
                    "[注意风险邮件]".to_string(),
                    "该邮件可能存在恶意内容，请谨慎甄别邮件".to_string(),
                    "检测结果：垃圾邮件".to_string(),
                ],
                notice_banner_patterns: vec![],
                dsn_patterns: vec![],
                auto_reply_patterns: vec![],
            },
        );

        let (subject, body) = sanitize_semantic_inputs(
            Some("[注意风险邮件]工资清单"),
            "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n检测结果：垃圾邮件。\n\n请查收本月工资清单。",
        );

        assert_eq!(subject.as_deref(), Some("工资清单"));
        assert_eq!(body, "请查收本月工资清单。");
    }

    // ─── P2-2: foreign_to_cn_corp known sender domain tests ───

    fn make_ctx_with_sender(
        mail_from: &str,
        rcpt_to: &[&str],
        body_text: Option<&str>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(mail_from.to_string());
        for &r in rcpt_to {
            session.rcpt_to.push(r.to_string());
        }
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_foreign_to_cn_corp_skipped_for_163_sender() {
        // P2-2: 163.com is a Chinese domestic email provider.
        // An English-only email from 163.com to a .cn recipient should NOT
        // trigger foreign_to_cn_corp.
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx_with_sender(
            "user@163.com",
            &["recipient@company.cn"],
            Some("This is a pure English business email with enough characters to exceed the 30 char threshold for language detection."),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"foreign_to_cn_corp".to_string()),
            "163.com sender to .cn recipient should not trigger foreign_to_cn_corp, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_foreign_to_cn_corp_skipped_for_qq_sender() {
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx_with_sender(
            "user@qq.com",
            &["recipient@company.com.cn"],
            Some("This is another pure English email with sufficient length to trigger the non-Chinese content detection logic."),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"foreign_to_cn_corp".to_string()),
            "qq.com sender to .com.cn recipient should not trigger foreign_to_cn_corp, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_foreign_to_cn_corp_skipped_for_swift_sender() {
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx_with_sender(
            "noreply.cs.deployment@swift.com",
            &["recipient@company.com.cn"],
            Some("Dear customer, your invoice remains open. Please review the billing portal and settle within payment terms."),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"foreign_to_cn_corp".to_string()),
            "known transactional senders like swift.com should not trip foreign_to_cn_corp, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_foreign_to_cn_corp_still_triggers_for_unknown_foreign_sender() {
        // A truly foreign sender to a .cn recipient should still trigger
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx_with_sender(
            "attacker@evil-domain.xyz",
            &["victim@bank.com.cn"],
            Some("Dear valued customer, your account has been compromised. Please click here to verify your identity immediately."),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"foreign_to_cn_corp".to_string()),
            "Unknown foreign sender to .cn should trigger foreign_to_cn_corp, got categories={:?}",
            result.categories
        );
    }

    // ─── P2-4: nonsensical_spam only on gibberish evidence tests ───

    #[tokio::test]
    async fn test_nonsensical_spam_not_triggered_by_normal_chinese_text() {
        // Normal readable Chinese text should NOT produce nonsensical_spam
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx(
            Some("尊敬的客户，您好！感谢您对我们公司的支持。本月账单已经生成，请查收。如有疑问请联系客服。"),
            None,
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"nonsensical_spam".to_string()),
            "Normal Chinese text should not trigger nonsensical_spam, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_nonsensical_spam_not_triggered_by_english_only_email() {
        // English-only email — may trigger language mismatch but NOT nonsensical_spam
        let module = SemanticScanModule::new(None);
        let ctx = make_ctx(
            Some("Dear customer, please find attached your monthly invoice. If you have any questions, please contact our support team at support@example.com."),
            None,
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"nonsensical_spam".to_string()),
            "English email should not trigger nonsensical_spam, got categories={:?}",
            result.categories
        );
    }
}
