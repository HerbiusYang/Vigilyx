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
use crate::matcher::{payment_change_keywords, transaction_urgency_keywords};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;
use crate::modules::common::looks_like_raw_mime_container_text;
use crate::modules::content_scan::html_utils::strip_html_tags;
use crate::modules::content_scan::normalize_text;

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
    Regex::new(r"(?i)\b(?:invoice|inv|purchase[\s-]?order|po|receipt)\b[\s#:-]*[A-Z0-9]{3,20}\b")
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
/// Note: ETH and ERC-20 / BEP-20 (BSC) / Polygon all share this format. We treat
/// any 0x...40hex hit as a generic EVM wallet — context keywords disambiguate
/// (USDT/USDC/BNB/MATIC/etc).
static RE_ETH_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0x[0-9a-fA-F]{40}\b").unwrap());
/// TRON / TRC-20 address: T prefix, exactly 33 base58 chars after T = 34 total
/// Used by the most common USDT (TRC20) sextortion / pig-butchering scams.
static RE_TRON_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b").unwrap());
/// Solana address: base58, 32–44 chars, no 0/O/I/l. We anchor on a length
/// range that excludes BTC overlaps and require a crypto context to score.
static RE_SOL_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b").unwrap());
/// Monero (XMR): 4 prefix + 94 base58 chars (or 8 prefix for integrated). XMR
/// is the de-facto ransomware payout currency in 2024–2026.
static RE_XMR_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b").unwrap());
/// Litecoin: L/M prefix base58 (legacy), or ltc1 bech32.
static RE_LTC_ADDR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[LM][1-9A-HJ-NP-Za-km-z]{25,34}|ltc1[a-z0-9]{25,62})\b").unwrap()
});

/// Check if a regex match has a valid IBAN country code prefix.
fn is_valid_iban_country(matched: &str) -> bool {
    if matched.len() < 2 {
        return false;
    }
    let prefix = matched[..2].to_uppercase();
    module_data().contains("iban_country_codes", &prefix)
}

fn is_valid_iban_match(matched: &str) -> bool {
    is_valid_iban_country(matched) && crate::data_security::dlp::finders::is_valid_iban(matched)
}

/// Signal weights
const W_FINANCIAL_ENTITY: f64 = 0.15;
const W_WIRE_INSTRUCTION: f64 = 0.20;
const W_AMOUNT_PRESENT: f64 = 0.10;
const W_URGENCY_COMBO: f64 = 0.25;
const W_PAYMENT_CHANGE: f64 = 0.35;
const W_MULTI_FINANCIAL: f64 = 0.15;
const CRYPTO_CONTEXT_KEYWORDS: &[&str] = &[
    "bitcoin",
    "btc",
    "wallet",
    "crypto",
    "cryptocurrency",
    "ethereum",
    "blockchain",
    "usdt",
    "usdc",
    "tether",
    "trc20",
    "trc-20",
    "erc20",
    "erc-20",
    "bep20",
    "bep-20",
    "tron",
    "binance",
    "bnb",
    "polygon",
    "matic",
    "solana",
    "phantom",
    "metamask",
    "trustwallet",
    "trust wallet",
    "monero",
    "xmr",
    "litecoin",
    "ltc",
    "nft",
    "opensea",
    "rarible",
    "airdrop",
    "seed phrase",
    "mnemonic",
    "private key",
    "比特币",
    "以太坊",
    "钱包",
    "加密货币",
    "数字货币",
    "虚拟货币",
    "区块链",
    "泰达币",
    "波场",
    "门罗币",
    "莱特币",
    "助记词",
    "私钥",
    "空投",
];

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

        if let Some(ref body) = ctx.session.content.body_text
            && !looks_like_raw_mime_container_text(body)
        {
            text.push_str(body);
            text.push('\n');
        }

        if let Some(ref subject) = ctx.session.subject {
            text.push_str(subject);
            text.push('\n');
        }

        // Also check HTML body, stripped of tags by the shared stripper:
        // the old rough stripper left HTML entities undecoded (so "转&#36134;"
        // never matched "转账") and swallowed text after any bare '<'.
        if let Some(ref html) = ctx.session.content.body_html {
            let stripped = strip_html_tags(html);
            text.push_str(&stripped);
            // Tag stripping inserts a space at every tag boundary, so
            // keywords spliced by inline markup ("转<b>账</b>至新账户")
            // still evade the matchers. Append a whitespace-free view so
            // payment-change / urgency phrases survive splicing.
            let squashed: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
            if !squashed.is_empty() {
                text.push('\n');
                text.push_str(&squashed);
            }
        }

        text
    }

    /// Check for payment change indicators (BEC attack signature)
    fn check_payment_change(text: &str) -> Option<(f64, Evidence)> {
        let text_lower = text.to_ascii_lowercase();
        // Aho-Corasick scan: O(n + matches), independent of phrase count.
        let kw = payment_change_keywords()
            .scan(&text_lower)
            .first_pattern()?;

        // These phrases describe ordinary payment metadata and occur in bank
        // notices, payroll forms and invoices. They are not evidence that the
        // recipient is being asked to replace a previously trusted account.
        const CONTEXT_ONLY_TERMS: &[&str] = &[
            "direct deposit",
            "payroll bank",
            "payroll information",
            "routing number",
            "beneficiary account",
            "remittance details",
            "收款账户",
            "收款账号",
            "银行账户",
            "银行账号",
            "工资卡",
            "代发账户",
            "代发账号",
        ];
        if CONTEXT_ONLY_TERMS.contains(&kw.as_str()) {
            let window = Self::find_context(text, &kw)?;
            let window_lower = window.to_lowercase();
            const CHANGE_MARKERS: &[&str] = &[
                "change", "changed", "updated", "revised", "replace", "replacement",
                "new account", "old account", "instead", "变更", "更换", "更改", "修改",
                "更新", "新账户", "新账号", "旧账户", "原账户", "改为",
            ];
            if !CHANGE_MARKERS
                .iter()
                .any(|marker| window_lower.contains(marker))
            {
                return None;
            }
        }
        Some((
            W_PAYMENT_CHANGE,
            Evidence {
                description: format!("Detected payment change instruction keyword: \"{}\"", kw),
                location: Some("body".to_string()),
                snippet: Self::find_context(text, &kw),
            },
        ))
    }

    /// Check for urgency combined with financial entities
    fn check_urgency_combo(text: &str, has_financial: bool) -> Option<(f64, Evidence)> {
        if !has_financial {
            return None;
        }

        let text_lower = text.to_ascii_lowercase();
        let kw = transaction_urgency_keywords()
            .scan(&text_lower)
            .first_pattern()?;
        Some((
            W_URGENCY_COMBO,
            Evidence {
                description: format!(
                    "Urgency keyword \"{}\" co-occurs with financial entities (BEC risk signal)",
                    kw
                ),
                location: Some("body".to_string()),
                snippet: Self::find_context(text, &kw),
            },
        ))
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

    fn has_crypto_context(text: &str) -> bool {
        let lower = text.to_lowercase();
        CRYPTO_CONTEXT_KEYWORDS.iter().any(|keyword| {
            if keyword.is_ascii() {
                lower.match_indices(keyword).any(|(start, _)| {
                    let before = lower[..start].chars().next_back();
                    let end = start + keyword.len();
                    let after = lower[end..].chars().next();
                    !before.is_some_and(|ch| ch.is_ascii_alphanumeric())
                        && !after.is_some_and(|ch| ch.is_ascii_alphanumeric())
                })
            } else {
                lower.contains(keyword)
            }
        })
    }
}

#[async_trait]
impl SecurityModule for TransactionCorrelationModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        // Unicode normalization (NFKC + zero-width stripping) after the
        // rough HTML tag stripping in get_text_content: full-width
        // letters/digits and zero-width splices must not hide payment
        // change keywords, urgency phrases, or financial entities.
        let text = normalize_text(&Self::get_text_content(ctx));

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
        let mut actionable_signal_count: u32 = 0;
        let mut reference_entity_count: u32 = 0;
        let mut has_payment_change = false;
        let mut has_wire_instruction = false;
        let mut has_amount_reference = false;
        let has_crypto_context = Self::has_crypto_context(&text);

        // 1. IBAN detection (with country code validation to reduce false positives)
        let iban_matches: Vec<_> = RE_IBAN
            .find_iter(&text)
            .filter(|m| is_valid_iban_match(m.as_str()))
            .collect();
        if !iban_matches.is_empty() {
            financial_entity_count += iban_matches.len() as u32;
            actionable_signal_count += iban_matches.len() as u32;
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
            actionable_signal_count += 1;
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
            actionable_signal_count += acct_matches.len() as u32;
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
            has_amount_reference = true;
            total_score += W_AMOUNT_PRESENT;
            evidence.push(Evidence {
                description: format!(
                    "Detected {} monetary amount reference(s)",
                    amount_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(amount_matches[0].as_str().to_string()),
            });
        }

        // 5. Invoice / PO references
        let invoice_matches: Vec<_> = RE_INVOICE.find_iter(&text).collect();
        if !invoice_matches.is_empty() {
            financial_entity_count += invoice_matches.len() as u32;
            reference_entity_count += invoice_matches.len() as u32;
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
            has_wire_instruction = true;
            actionable_signal_count += 1;
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
        if !btc_matches.is_empty() && has_crypto_context {
            actionable_signal_count += btc_matches.len() as u32;
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
        if !eth_matches.is_empty() && has_crypto_context {
            actionable_signal_count += eth_matches.len() as u32;
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
        // TRON / TRC20 — by far the most common chain for USDT pig-butchering
        // and sextortion scams in CN/SEA targeted campaigns.
        let tron_matches: Vec<_> = RE_TRON_ADDR.find_iter(&text).collect();
        if !tron_matches.is_empty() && has_crypto_context {
            actionable_signal_count += tron_matches.len() as u32;
            total_score += 0.40;
            categories.push("crypto_wallet".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} TRON/TRC20 wallet address(es) (USDT pig-butchering / sextortion indicator)",
                    tron_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(tron_matches[0].as_str().to_string()),
            });
        }
        // Solana — increasingly popular in NFT-themed scams.
        let sol_matches: Vec<_> = RE_SOL_ADDR.find_iter(&text).collect();
        if !sol_matches.is_empty() && has_crypto_context {
            actionable_signal_count += sol_matches.len() as u32;
            total_score += 0.30;
            categories.push("crypto_wallet".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} Solana wallet address(es) (NFT/crypto scam indicator)",
                    sol_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(sol_matches[0].as_str().to_string()),
            });
        }
        // Monero — privacy-coin demand is a textbook ransomware/extortion fingerprint.
        let xmr_matches: Vec<_> = RE_XMR_ADDR.find_iter(&text).collect();
        if !xmr_matches.is_empty() && has_crypto_context {
            actionable_signal_count += xmr_matches.len() as u32;
            total_score += 0.45;
            categories.push("crypto_wallet".to_string());
            categories.push("ransomware_indicator".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} Monero (XMR) address(es) — strong ransomware/extortion signal",
                    xmr_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(xmr_matches[0].as_str().to_string()),
            });
        }
        // Litecoin — common fallback in extortion templates when victims push back on BTC fees.
        let ltc_matches: Vec<_> = RE_LTC_ADDR.find_iter(&text).collect();
        if !ltc_matches.is_empty() && has_crypto_context {
            actionable_signal_count += ltc_matches.len() as u32;
            total_score += 0.30;
            categories.push("crypto_wallet".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected {} Litecoin wallet address(es) (extortion/scam indicator)",
                    ltc_matches.len()
                ),
                location: Some("body".to_string()),
                snippet: Some(ltc_matches[0].as_str().to_string()),
            });
        }

        // 7. Payment change (BEC signature)
        if let Some((score, ev)) = Self::check_payment_change(&text) {
            has_payment_change = true;
            actionable_signal_count += 1;
            total_score += score;
            categories.push("payment_change".to_string());
            evidence.push(ev);
        }

        // Crypto vocabulary is context for validating wallet-shaped tokens,
        // not an actionable payment fact by itself. An account number or a
        // bare word such as "TRON" must not arm the urgency combination.
        let has_crypto_wallet = categories
            .iter()
            .any(|category| category == "crypto_wallet");
        let has_actionable_payment_signal =
            has_payment_change || has_wire_instruction || has_crypto_wallet;

        // 8. Urgency + financial entity combo
        if let Some((score, ev)) = Self::check_urgency_combo(&text, has_actionable_payment_signal) {
            total_score += score;
            categories.push("urgency_financial_combo".to_string());
            evidence.push(ev);
        }

        // 9. Multiple financial entities bonus
        let corroborating_reference_count =
            u32::from(reference_entity_count > 0) + u32::from(has_amount_reference);
        if actionable_signal_count >= 2
            || (actionable_signal_count >= 1 && corroborating_reference_count >= 2)
        {
            total_score += W_MULTI_FINANCIAL;
            categories.push("multi_financial_entities".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Detected corroborating payment signals (actionable={}, references={}, amount_ref={}) — multi-entity risk accumulation",
                    actionable_signal_count,
                    reference_entity_count,
                    has_amount_reference
                ),
                location: Some("body".to_string()),
                snippet: None,
            });
        }

        let routine_settlement_context = !has_payment_change
            && !has_crypto_wallet
            && has_wire_instruction
            && has_amount_reference
            && reference_entity_count > 0
            && actionable_signal_count <= 3;
        if routine_settlement_context {
            total_score = total_score.min(0.14);
            evidence.push(Evidence {
                description:
                    "Routine invoice / settlement reminder pattern detected without payment-change language; down-weighting transaction risk"
                        .to_string(),
                location: Some("body".to_string()),
                snippet: None,
            });
        }

        // Amounts and invoice/order references are common in receipts and
        // business notifications. Without an actionable payment signal they
        // should not independently create a low-risk threat finding.
        let passive_financial_context = !has_payment_change
            && !has_wire_instruction
            && !has_crypto_wallet
            && actionable_signal_count == 0
            && (reference_entity_count > 0 || has_amount_reference);
        if passive_financial_context {
            total_score = total_score.min(0.14);
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
                details: serde_json::json!({
                    "score": 0.0,
                    "financial_entities": 0,
                    "actionable_payment_signals": 0,
                    "reference_entities": 0,
                }),
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
                "actionable_payment_signals": actionable_signal_count,
                "reference_entities": reference_entity_count,
                "has_wire_instruction": has_wire_instruction,
                "has_payment_change": has_payment_change,
                "has_amount_reference": has_amount_reference,
                "has_crypto_context": has_crypto_context,
                "has_crypto_wallet": has_crypto_wallet,
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
    use crate::pipeline::context::SecurityContext;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    fn make_ctx(body_text: Option<&str>, subject: Option<&str>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = subject.map(str::to_string);
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_ctx_with_html(body_html: &str) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            body_html: Some(body_html.to_string()),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_html_spliced_payment_change_keyword_fires() {
        // Evasion PoC: the old rough HTML stripper left entities undecoded
        // ("转&#36134;" never became "转账") and split keywords across inline
        // tags ("新</b><b>账户"), so the payment-change BEC signature stayed
        // invisible. The shared stripper + whitespace-free view recovers it.
        let module = TransactionCorrelationModule::new();
        let html = "<p>财务部紧急通知：请将本月货款 <b>转&#36134;</b> 至 <b>新</b><b>账户</b> 收款，\
                    金额 ¥50000，请今天内完成。</p>";
        let ctx = make_ctx_with_html(html);

        let result = module.analyze(&ctx).await.expect("analyze ok");

        assert!(
            result.categories.contains(&"payment_change".to_string()),
            "entity/tag-spliced payment-change keyword must be detected, cats={:?}",
            result.categories
        );
        assert!(
            result.threat_level >= ThreatLevel::Low,
            "payment_change (0.35) + amount must reach Low+, got {:?}",
            result.threat_level
        );
    }

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

        // A gateway token beginning with the valid country code BE is not an
        // IBAN unless its country length and ISO 13616 checksum also match.
        let token = "be3287575130207014d70f5c0cf67f4faa1a2d32";
        assert!(!is_valid_iban_match(token));
    }

    #[tokio::test]
    async fn test_raw_mime_container_body_is_ignored() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "--=_NextPart_123\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\nMHgxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTA=\r\n",
            ),
            None,
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.is_empty());
        assert!(
            result.summary.contains("No analyzable text content")
                || result.summary.contains("No transaction-related content")
        );
    }

    #[tokio::test]
    async fn invoice_references_with_immediately_do_not_trigger_bec_combo() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Please review invoice INV-2026-1007 and purchase order PO-88421 immediately. Receipt REF-7781 is attached for reconciliation.",
            ),
            Some("Invoice notice"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result
                .categories
                .contains(&"urgency_financial_combo".to_string())
        );
        assert!(
            !result
                .categories
                .contains(&"multi_financial_entities".to_string())
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn urgent_wire_with_banking_details_still_triggers_multi_signal_risk() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Please process this wire transfer immediately to DE89370400440532013000. SWIFT: DEUTDEFF. Amount: USD 24,500.",
            ),
            Some("Urgent payment update"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result
                .categories
                .contains(&"urgency_financial_combo".to_string())
        );
        assert!(
            result
                .categories
                .contains(&"multi_financial_entities".to_string())
        );
        assert_ne!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn routine_invoice_reminder_without_payment_change_is_downgraded() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Dear customer, invoice INV-2026-7781 remains open. Amount Open: USD 50,084.70. \
                 Beneficiary: SWIFT SC. Bank Name: JPMorgan Chase Bank. \
                 S.W.I.F.T. BIC code: CHASUS33. ABA Routing Code: 021000021. \
                 Please proceed to pay the overdue amount without further delay within Swift's payment terms.",
            ),
            Some("Swift Invoice Reminder"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "routine settlement reminders without payment-change language should not be flagged on transaction semantics alone: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn wallet_like_token_without_crypto_context_does_not_trigger_crypto_wallet() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Please review invoice INV-2026-1007. Receipt REF-7781 is attached. Token: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            ),
            Some("Invoice notice"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(!result.categories.contains(&"crypto_wallet".to_string()));
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn crypto_context_requires_ascii_token_boundaries() {
        assert!(!TransactionCorrelationModule::has_crypto_context(
            "Electronic communications may contain computer viruses."
        ));
        assert!(!TransactionCorrelationModule::has_crypto_context(
            "The workflow is processed automatically."
        ));
        assert!(TransactionCorrelationModule::has_crypto_context(
            "Send the payment through the TRON network."
        ));
    }

    #[tokio::test]
    async fn electronic_disclaimer_urgency_is_not_a_financial_signal() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "If you are not the intended recipient, please immediately notify the sender and delete this message. Electronic communications may contain computer viruses. 请立即以电子邮件通知发件人并删除本邮件。",
            ),
            Some("OMS Push request received"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(result.categories.is_empty(), "{result:?}");
        assert_eq!(result.bpa, Some(Bpa::vacuous()));
    }

    #[tokio::test]
    async fn crypto_vocabulary_without_wallet_does_not_arm_urgency_combo() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some("Please immediately review the TRON blockchain integration architecture."),
            Some("Architecture review"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result
                .categories
                .contains(&"urgency_financial_combo".to_string()),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn receipt_amounts_and_references_are_passive_without_payment_action() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some("Apple receipt INV-2026-7781. Total: ¥25.00. Order number REF-1234."),
            Some("Apple receipt"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.is_empty());
    }

    #[tokio::test]
    async fn ordinary_bank_account_metadata_is_not_a_payment_change() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some("请于今日核对工资卡及代发账户信息，确认银行账号填写准确。"),
            Some("工资信息核对通知"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(!result.categories.contains(&"payment_change".to_string()));
        assert!(
            !result
                .categories
                .contains(&"urgency_financial_combo".to_string())
        );
    }

    #[tokio::test]
    async fn explicit_bank_account_change_remains_actionable() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some("重要通知：收款账户已变更，原账户停用，请从今日起使用新账户付款。"),
            Some("收款账户变更"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(result.categories.contains(&"payment_change".to_string()));
        assert_ne!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn crypto_wallet_with_context_still_triggers_detection() {
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Send the Bitcoin payment to wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT immediately to restore access.",
            ),
            Some("Urgent bitcoin payment"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(result.categories.contains(&"crypto_wallet".to_string()));
        assert_ne!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn zero_width_payment_change_keyword_fires() {
        // Evasion PoC: zero-width splice inside the Chinese payment-change
        // keyword "请用新账户付款" previously broke the substring scan.
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some("尊敬的合作伙伴，因银行系统升级，请用新\u{200B}账户付款，旧账户已停用。"),
            Some("付款信息更新"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"payment_change".to_string()),
            "zero-width-spliced payment-change keyword must fire, cats={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn fullwidth_wire_transfer_and_amount_fire() {
        // Evasion PoC: full-width "ＷＩＲＥ ＴＲＡＮＳＦＥＲ" and full-width
        // digits bypass the ASCII regexes until NFKC normalization.
        let module = TransactionCorrelationModule::new();
        let ctx = make_ctx(
            Some(
                "Please process this ｗｉｒｅ ｔｒａｎｓｆｅｒ immediately. Amount: USD ２４,５００.",
            ),
            Some("Urgent payment update"),
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"wire_transfer".to_string()),
            "full-width wire transfer keyword must fire, cats={:?}",
            result.categories
        );
        assert!(
            result
                .details
                .get("has_amount_reference")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            "full-width digit amount must be detected, details={:?}",
            result.details
        );
    }
}
