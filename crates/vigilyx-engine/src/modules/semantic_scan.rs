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
use crate::modules::common::looks_like_raw_mime_container_text;
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

/// Protected Chinese corporate domains
const PROTECTED_DOMAINS: &[&str] = &["corp-internal.com"];

/// Known legitimate financial sender domains
/// Emails from these domains skip the foreign-to-CN-corp check
const KNOWN_FINANCIAL_SENDER_DOMAINS: &[&str] = &[
   // "partner-securities.example.com",
   // "partner-fintech.example.com",
];

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

#[async_trait]
impl SecurityModule for SemanticScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

       // Get email body text
        let body = match (
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
                    subject: ctx.session.subject.clone(),
                    body_text: Some(body.clone()),
                    body_html: ctx.session.content.body_html.clone(),
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
        let mut categories: Vec<String> = Vec::new();

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
            let is_known_financial_sender = KNOWN_FINANCIAL_SENDER_DOMAINS
                .iter()
                .any(|&d| sender_domain.eq_ignore_ascii_case(d));

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
                        || PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
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
                        || PROTECTED_DOMAINS.iter().any(|&pd| d == pd)
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
        let threat_signals: Vec<&str> = [
            "recorded you",
            "your camera",
            "masturbat",
            "embarrassing",
            "i have your password",
            "i know your password",
            "infected by",
            "private malware",
            "hacked your",
            "compromised your",
            "share the video",
            "publish your",
            "expose you",
            "send to all",
        ]
        .iter()
        .filter(|&&kw| body_lower.contains(kw))
        .copied()
        .collect();
        let payment_signals: Vec<&str> = [
            "bitcoin",
            "btc",
            "ethereum",
            "eth",
            "cryptocurrency",
            "wallet address",
            "pay exactly",
            "send payment",
            "complete the payment",
            "days to pay",
        ]
        .iter()
        .filter(|&&kw| body_lower.contains(kw))
        .copied()
        .collect();

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

        if !evidence.is_empty() {
            categories.push("nonsensical_spam".to_string());
        }

        
       // Await NLP result (Rust analysis already complete, NLP should be done or nearly done)
        
        let mut nlp_used = false;
        let mut nlp_details = serde_json::Value::Null;

        if let Some(handle) = nlp_handle {
            match handle.await {
                Ok(Ok(ai_resp)) => {
                    nlp_used = true;
                    nlp_status = "ok";
                    nlp_status_message = Some(
                        "AI/NLP analysis completed and was fused with the rule engine"
                            .to_string(),
                    );
                    let nlp_threat = ai_resp.to_threat_level();
                    let nlp_confidence = ai_resp.confidence;

                   // Merge NLP categories
                    categories.extend(ai_resp.categories.clone());

                   // Merge NLP result into evidence
                    evidence.push(Evidence {
                        description: format!(
                            "NLP model verdict: {} (confidence {:.1}%) — {}",
                            ai_resp.threat_level,
                            nlp_confidence * 100.0,
                            ai_resp.summary,
                        ),
                        location: Some("body:nlp".to_string()),
                        snippet: None,
                    });

                   // Convert NLP threat level to score contribution
                   // Base: NLP provides a supplementary signal, adds to rule-based score.
                   // High-confidence boost: When NLP >= 70% confidence and verdict >= High,
                   // the model has strong malicious conviction, so boost the contribution.
                   // This avoids cases like 82% phishing yielding only 0.15 -> belief 0.09 -> missed.
                    let nlp_base = match nlp_threat {
                        ThreatLevel::Safe => 0.0,
                        ThreatLevel::Low => 0.05,
                        ThreatLevel::Medium => 0.10,
                        ThreatLevel::High => 0.15,
                        ThreatLevel::Critical => 0.20,
                    };
                    let nlp_score = if nlp_confidence >= 0.70 && nlp_threat >= ThreatLevel::High {
                       // High confidence: scale with confidence, capped at 0.30
                        (nlp_base + nlp_confidence * 0.15).min(0.30)
                    } else {
                        nlp_base
                    };

                    score += nlp_score;

                    nlp_details = ai_resp.details.unwrap_or(serde_json::Value::Null);
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
        
        score = score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(score);

        if threat_level == ThreatLevel::Safe {
            let summary = if nlp_used {
                "NLP + rule engine combined analysis: email body semantics normal".to_string()
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
                confidence: if nlp_used { 0.60 } else { 0.70 },
                categories: vec![],
                summary,
                evidence,
                details: serde_json::json!({
                    "score": score,
                    "nlp_configured": nlp_configured,
                    "nlp_enabled": nlp_used,
                    "nlp_status": nlp_status,
                    "nlp_status_message": nlp_status_message,
                    "nlp_skipped_temporarily": nlp_skipped_temporarily,
                    "nlp_retry_after_secs": nlp_retry_after_secs,
                    "nlp_timeout_secs": NLP_TIMEOUT.as_secs(),
                    "nlp_details": nlp_details,
                    "analysis_type": if nlp_used { "nlp+rules" } else { "rules_only" },
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: None,
                engine_id: None,
            });
        }

       // NLP confidence set lower (model misclassifies ~60% of the time)
       // Rule-based heuristics have more predictable behavior, so they get higher confidence
        let confidence = if nlp_used { 0.60 } else { 0.80 };

        let summary = if nlp_used {
            format!(
                "NLP + rule engine detected threat (score {:.2}, {} evidence items)",
                score,
                evidence.len()
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
                "nlp_status": nlp_status,
                "nlp_status_message": nlp_status_message,
                "nlp_skipped_temporarily": nlp_skipped_temporarily,
                "nlp_retry_after_secs": nlp_retry_after_secs,
                "nlp_timeout_secs": NLP_TIMEOUT.as_secs(),
                "nlp_details": nlp_details,
                "analysis_type": if nlp_used { "nlp+rules" } else { "rules_only" },
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
}
