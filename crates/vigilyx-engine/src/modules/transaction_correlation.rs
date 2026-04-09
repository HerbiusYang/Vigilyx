//! Engine H: Transaction Semantic Correlation

//! Extracts business entities from email content and detects anomalous patterns:
//! - Bank account / IBAN / SWIFT numbers
//! - Monetary amounts with currency markers
//! - Invoice/PO references
//! - Wire transfer instructions
//! - Payment urgency indicators combined with financial entities

//! When the email doesn't involve transaction intent, outputs u1 (vacuous),
//! effectively opting out of D-S fusion.

//! Output: BPA triple (b, d, u) with engine_id = "transaction_correlation"

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::LazyLock;

use crate::bpa::Bpa;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

/// Patterns for financial entity extraction
static RE_IBAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b")
        .unwrap()
});
static RE_SWIFT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:SWIFT|BIC)[:\s]*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b").unwrap()
});
static RE_AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[$€£¥₹]|USD|EUR|GBP|CNY|RMB)\s*[\d,]+(?:\.\d{1,2})?\b|\b[\d,]+(?:\.\d{1,2})?\s*(?:dollars?|euros?|pounds?|yuan|rmb)\b").unwrap()
});
static RE_BANK_ACCOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:account|acct|a/c|routing|sort[\s-]?code)[:\s#]*[\d\s-]{6,20}\b").unwrap()
});
static RE_INVOICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:invoice|inv|purchase[\s-]?order|po|receipt)[\s#:-]*[A-Z0-9]{3,20}\b")
        .unwrap()
});
static RE_WIRE_INSTRUCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:wire[\s-]?transfer|bank[\s-]?transfer|remittance|beneficiary|intermediary[\s-]?bank)\b").unwrap()
});
/// BTC Address: 1/3/bc1 Header, 25-62 characters Base58/Bech32
static RE_BTC_ADDR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b").unwrap()
});
/// ETH Address: 0x Header 40 bit 6Base/Radix
static RE_ETH_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0x[0-9a-fA-F]{40}\b").unwrap());

/// Valid IBAN country codes (ISO 13616). Used to filter false positives from
/// the broad IBAN regex. source: SWIFT IBAN Registry (2024 edition).
const IBAN_COUNTRY_CODES: &[&str] = &[
    "AD", "AE", "AL", "AT", "AZ", "BA", "BE", "BG", "BH", "BR", "BY", "CH", "CR", "CY", "CZ", "DE",
    "DK", "DO", "EE", "EG", "ES", "FI", "FO", "FR", "GB", "GE", "GI", "GL", "GR", "GT", "HR", "HU",
    "IE", "IL", "IQ", "IS", "IT", "JO", "KW", "KZ", "LB", "LC", "LI", "LT", "LU", "LV", "LY", "MC",
    "MD", "ME", "MK", "MR", "MT", "MU", "NL", "NO", "PK", "PL", "PS", "PT", "QA", "RO", "RS", "SA",
    "SC", "SE", "SI", "SK", "SM", "ST", "SV", "TL", "TN", "TR", "UA", "VA", "VG", "XK",
];

/// Check if a regex match has a valid IBAN country code prefix.
fn is_valid_iban_country(matched: &str) -> bool {
    if matched.len() < 2 {
        return false;
    }
    let prefix = &matched[..2].to_uppercase();
    IBAN_COUNTRY_CODES.contains(&prefix.as_str())
}

/// Urgency keywords that elevate risk when combined with financial entities
const URGENCY_KEYWORDS: &[&str] = &[
    "urgent",
    "immediately",
    "asap",
    "today",
    "deadline",
    "overdue",
    "final notice",
    "time sensitive",
    "act now",
    "紧急",
    "立即",
    "马上",
    "今天",
    "截止",
    "逾期",
];

/// Payment change keywords (BEC indicator)
const PAYMENT_CHANGE_KEYWORDS: &[&str] = &[
    "new account",
    "updated account",
    "change of bank",
    "revised payment",
    "new banking",
    "updated wire",
    "account has changed",
    "new beneficiary",
    "更换账户",
    "新账户",
    "变更银行",
    "修改收款",
];

/// Signal weights
const W_FINANCIAL_ENTITY: f64 = 0.15;
const W_WIRE_INSTRUCTION: f64 = 0.20;
const W_AMOUNT_PRESENT: f64 = 0.10;
const W_URGENCY_COMBO: f64 = 0.25;
const W_PAYMENT_CHANGE: f64 = 0.35;
const W_MULTI_FINANCIAL: f64 = 0.15;

pub struct TransactionCorrelationModule {
    meta: ModuleMetadata,
}

impl Default for TransactionCorrelationModule {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionCorrelationModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "transaction_correlation".to_string(),
                name: "Transaction Semantic Correlation".to_string(),
                description:
                    "Detect financial transaction signals in email: bank accounts, wire transfer instructions, payment changes"
                        .to_string(),
                pillar: Pillar::Semantic,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }

   /// Extract all text content from the email for analysis
    #[inline]
    fn get_text_content(ctx: &SecurityContext) -> String {
        let mut text = String::with_capacity(4096);

        if let Some(ref body) = ctx.session.content.body_text {
            text.push_str(body);
            text.push('\n');
        }

        if let Some(ref subject) = ctx.session.subject {
            text.push_str(subject);
            text.push('\n');
        }

       // Also check HTML body stripped of tags (rough extraction)
        if let Some(ref html) = ctx.session.content.body_html {
           // Very rough tag stripping - sufficient for regex matching
            let stripped: String = html
                .chars()
                .scan(false, |in_tag, c| {
                    if c == '<' {
                       *in_tag = true;
                        Some(' ')
                    } else if c == '>' {
                       *in_tag = false;
                        Some(' ')
                    } else if *in_tag {
                        Some(' ')
                    } else {
                        Some(c)
                    }
                })
                .collect();
            text.push_str(&stripped);
        }

        text
    }

   /// Check for payment change indicators (BEC attack signature)
    fn check_payment_change(text: &str) -> Option<(f64, Evidence)> {
        let text_lower = text.to_ascii_lowercase();
        for kw in PAYMENT_CHANGE_KEYWORDS {
            if text_lower.contains(kw) {
                return Some((
                    W_PAYMENT_CHANGE,
                    Evidence {
                        description: format!("Detected payment change instruction keyword: \"{}\"", kw),
                        location: Some("body".to_string()),
                        snippet: Self::find_context(text, kw),
                    },
                ));
            }
        }
        None
    }

   /// Check for urgency combined with financial entities
    fn check_urgency_combo(text: &str, has_financial: bool) -> Option<(f64, Evidence)> {
        if !has_financial {
            return None;
        }

        let text_lower = text.to_ascii_lowercase();
        for kw in URGENCY_KEYWORDS {
            if text_lower.contains(kw) {
                return Some((
                    W_URGENCY_COMBO,
                    Evidence {
                        description: format!(
                            "Urgency keyword \"{}\" co-occurs with financial entities (BEC risk signal)",
                            kw
                        ),
                        location: Some("body".to_string()),
                        snippet: Self::find_context(text, kw),
                    },
                ));
            }
        }
        None
    }

   /// Find a short context window around a keyword match
    fn find_context(text: &str, keyword: &str) -> Option<String> {
        let lower = text.to_ascii_lowercase();
        let pos = lower.find(&keyword.to_ascii_lowercase())?;
        let start = pos.saturating_sub(40);
        let end = (pos + keyword.len() + 40).min(text.len());
       // Find valid UTF-8 boundaries
        let start = text.floor_char_boundary(start);
        let end = text.ceil_char_boundary(end);
        Some(format!("...{}...", &text[start..end]))
    }
}

#[async_trait]
impl SecurityModule for TransactionCorrelationModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let text = Self::get_text_content(ctx);

       // Quick exit: no text content -> vacuous BPA
        if text.trim().is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.5,
                categories: vec![],
                summary: "No analyzable text content".to_string(),
                evidence: vec![],
                details: serde_json::json!({ "no_content": true }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(Bpa::vacuous()),
                engine_id: Some("transaction_correlation".to_string()),
            });
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut financial_entity_count: u32 = 0;

       // 1. IBAN detection (with country code validation to reduce false positives)
        let iban_matches: Vec<_> = RE_IBAN
            .find_iter(&text)
            .filter(|m| is_valid_iban_country(m.as_str()))
            .collect();
        if !iban_matches.is_empty() {
            financial_entity_count += iban_matches.len() as u32;
            total_score += W_FINANCIAL_ENTITY;
            categories.push("iban_detected".to_string());
            evidence.push(Evidence {
                description: format!("Detected {} IBAN account number(s)", iban_matches.len()),
                location: Some("body".to_string()),
                snippet: Some(iban_matches[0].as_str().to_string()),
            });
        }

       // 2. SWIFT/BIC code
        if RE_SWIFT.is_match(&text) {
            financial_entity_count += 1;
            total_score += W_FINANCIAL_ENTITY;
            categories.push("swift_code_detected".to_string());
            evidence.push(Evidence {
                description: "Detected SWIFT/BIC bank code".to_string(),
                location: Some("body".to_string()),
                snippet: RE_SWIFT.find(&text).map(|m| m.as_str().to_string()),
            });
        }

       // 3. Bank account numbers
        let acct_matches: Vec<_> = RE_BANK_ACCOUNT.find_iter(&text).collect();
        if !acct_matches.is_empty() {
            financial_entity_count += acct_matches.len() as u32;
            total_score += W_FINANCIAL_ENTITY;
            categories.push("bank_account_detected".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} bank account number reference(s)",
                    acct_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(acct_matches[0].as_str().to_string()),
            });
        }

       // 4. Monetary amounts
        let amount_matches: Vec<_> = RE_AMOUNT.find_iter(&text).collect();
        if !amount_matches.is_empty() {
            total_score += W_AMOUNT_PRESENT;
            evidence.push(Evidence {
                description: format!("Detected {} monetary amount reference(s)", amount_matches.len()),
                location: Some("body".to_string()),
                snippet: Some(amount_matches[0].as_str().to_string()),
            });
        }

       // 5. Invoice / PO references
        let invoice_matches: Vec<_> = RE_INVOICE.find_iter(&text).collect();
        if !invoice_matches.is_empty() {
            financial_entity_count += invoice_matches.len() as u32;
            total_score += W_FINANCIAL_ENTITY * 0.5;
            evidence.push(Evidence {
                description: format!(
                    "Detected {} invoice/order number reference(s)",
                    invoice_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(invoice_matches[0].as_str().to_string()),
            });
        }

       // 6. Wire transfer instructions
        if RE_WIRE_INSTRUCTION.is_match(&text) {
            total_score += W_WIRE_INSTRUCTION;
            categories.push("wire_transfer".to_string());
            evidence.push(Evidence {
                description: "Detected wire transfer instruction".to_string(),
                location: Some("body".to_string()),
                snippet: RE_WIRE_INSTRUCTION
                    .find(&text)
                    .map(|m| m.as_str().to_string()),
            });
        }

       // 6b. Cryptocurrency wallet addresses (sextortion/ransomware)
        let btc_matches: Vec<_> = RE_BTC_ADDR.find_iter(&text).collect();
        if !btc_matches.is_empty() {
            total_score += 0.40; // BTC wallet address in email is highly suspicious
            categories.push("crypto_wallet".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} Bitcoin wallet address(es) (extortion/scam high-risk indicator)",
                    btc_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(btc_matches[0].as_str().to_string()),
            });
        }
        let eth_matches: Vec<_> = RE_ETH_ADDR.find_iter(&text).collect();
        if !eth_matches.is_empty() {
            total_score += 0.35;
            categories.push("crypto_wallet".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} Ethereum wallet address(es) (extortion/scam high-risk indicator)",
                    eth_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(eth_matches[0].as_str().to_string()),
            });
        }

       // 7. Payment change (BEC signature)
        if let Some((score, ev)) = Self::check_payment_change(&text) {
            total_score += score;
            categories.push("payment_change".to_string());
            evidence.push(ev);
        }

        let has_financial = financial_entity_count > 0;

       // 8. Urgency + financial entity combo
        if let Some((score, ev)) = Self::check_urgency_combo(&text, has_financial) {
            total_score += score;
            categories.push("urgency_financial_combo".to_string());
            evidence.push(ev);
        }

       // 9. Multiple financial entities bonus
        if financial_entity_count >= 3 {
            total_score += W_MULTI_FINANCIAL;
            categories.push("multi_financial_entities".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} financial entities (accounts/codes/invoices) — multi-entity risk accumulation",
                    financial_entity_count
                ),
                location: Some("body".to_string()),
                snippet: None,
            });
        }

        total_score = total_score.min(1.0);
        let duration_ms = start.elapsed().as_millis() as u64;

       // If no financial signals found -> vacuous BPA (don't participate in fusion)
        if evidence.is_empty() {
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.5,
                categories: vec![],
                summary: "No transaction-related content detected".to_string(),
                evidence: vec![],
                details: serde_json::json!({ "score": 0.0, "financial_entities": 0 }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(Bpa::vacuous()),
                engine_id: Some("transaction_correlation".to_string()),
            });
        }

        let threat_level = ThreatLevel::from_score(total_score);
        categories.sort_unstable();
        categories.dedup();

       // Confidence: moderate-high (0.75) for regex-based extraction
        let confidence = 0.75;
        let bpa = Bpa::from_score_confidence(total_score, confidence);

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories,
            summary: format!(
                "Transaction semantic analysis found {} financial signal(s), composite score {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "financial_entities": financial_entity_count,
                "has_wire_instruction": RE_WIRE_INSTRUCTION.is_match(&text),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(bpa),
            engine_id: Some("transaction_correlation".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_iban_country_codes() {
        assert!(is_valid_iban_country("DE89370400440532013000"));
        assert!(is_valid_iban_country("GB29NWBK60161331926819"));
        assert!(is_valid_iban_country("FR7630006000011234567890189"));
        assert!(is_valid_iban_country("NL91ABNA0417164300"));
    }

    #[test]
    fn test_invalid_iban_country_codes() {
       // "XX" is not a valid IBAN country
        assert!(!is_valid_iban_country("XX12345678901234"));
       // "US" does not use IBAN
        assert!(!is_valid_iban_country("US12345678901234"));
       // Too short
        assert!(!is_valid_iban_country("D"));
        assert!(!is_valid_iban_country(""));
    }

    #[test]
    fn test_iban_regex_with_country_validation() {
       // Real IBAN: should match regex AND pass country validation
        let text = "Please pay to DE89370400440532013000";
        let matches: Vec<_> = RE_IBAN
            .find_iter(text)
            .filter(|m| is_valid_iban_country(m.as_str()))
            .collect();
        assert_eq!(matches.len(), 1);

       // Fake IBAN-like string with invalid country code: should be filtered out
        let text_fake = "Reference: XX99ABCD12345678";
        let matches_fake: Vec<_> = RE_IBAN
            .find_iter(text_fake)
            .filter(|m| is_valid_iban_country(m.as_str()))
            .collect();
        assert_eq!(matches_fake.len(), 0);
    }
}
