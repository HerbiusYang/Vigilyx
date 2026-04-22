//! Shared DLP (data) detect

//! ForSensitive Infomodematch: Card number, ID cardNumber, Mobile phoneNumber, BankCard number,,
//! email, Number, 1 Code/Digit,, SWIFT Code/Digit, CVV SecurityCode/Digit,
//! Number, IBAN BankAccount number, large Amount, BankAccount number(Context), / SameNumber.
//! mode content_scan ModuleMediumof1,Extract functionFordataSecurityModuleReuse.

//! Performance optimizations: Use `RegexSet` 1Time/Count, MediummodeExecutelineVerbosematch,
//! SensitivedataofText ~10x Add.

/// DLP matchfunction Verifyhandler.

/// PublicExport Test(property-based tests)Medium `luhn_check`,
/// `iban_mod97_check` wait functionofhintsTest.
pub mod finders;
mod normalize;
mod patterns;

use std::collections::HashSet;

use finders::*;
use normalize::normalize_for_dlp;
use patterns::*;

// DLP Result

/// DLP Result
#[derive(Debug, Clone, Default)]
pub struct DlpScanResult {
    /// match ofSensitivedataTypeList
    pub matches: Vec<String>,
    /// match (Type -> matchvalueList)
    pub details: Vec<(String, Vec<String>)>,
}

impl DlpScanResult {
    /// whether DLP Medium
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Statistics JR/T 0197-2020 level ofmatch total

    /// `details` Medium modeofmatchInstance, Deduplicate ofmode Class.
    /// if:1 FileContains 30 Mobile phoneNumber(C3) + 5 CVV(C4),
    /// `count_items_at_level(3)` Return 35,`count_items_at_level(4)` Return 5.
    pub fn count_items_at_level(&self, min_level: u8) -> usize {
        self.details
            .iter()
            .filter(|(name, _)| crate::data_security::jrt::jrt_level(name) >= min_level)
            .map(|(_, values)| values.len())
            .sum()
    }

    /// According to JR/T level match Count

    /// Return (level -> item_count) Mapping, packetContains matchoflevel.
    pub fn items_by_jrt_level(&self) -> std::collections::HashMap<u8, usize> {
        let mut counts = std::collections::HashMap::new();
        for (name, values) in &self.details {
            let level = crate::data_security::jrt::jrt_level(name);
            if level > 0 {
                *counts.entry(level).or_insert(0) += values.len();
            }
        }
        counts
    }
}

/// Maximum text length scanned by DLP.
///
/// Keep this bounded so a single oversized body cannot turn DLP into an
/// unbounded CPU/memory sink. Truncation is UTF-8 safe in `scan_text()`.
const DLP_MAX_SCAN_LEN: usize = 512 * 1024; // 512 KiB

// function (Use RegexSet Performance notes)

/// From HTTP SessionMediumExtractUsed for DLP ofText

/// Coremail compose.jsp of JSON body, Extract `attrs.content` + `attrs.subject`,
/// Avoid JSON Yuandata(id, CSS class name) match.
/// Coremail ConnectReturn body.
pub fn extract_dlp_text(body: &str, uri: &str) -> String {
    // Checkwhether Coremail compose URI
    if super::coremail::is_coremail_compose_uri(uri)
        && let Some(content) = super::coremail::extract_content_for_dlp(body)
    {
        return content;
    }
    // Coremail ExtractFailed,Return body
    body.to_string()
}

/// Extractuser: priority session.detected_user (Cookie),fallback Coremail JSON body of attrs.account
pub fn extract_user(session: &vigilyx_core::HttpSession) -> Option<String> {
    // priority Cookie Extractofuser
    if session.detected_user.is_some() {
        return session.detected_user.clone();
    }
    // Coremail compose URI -> From JSON body Extract attrs.account
    if super::coremail::is_coremail_compose_uri(&session.uri)
        && let Some(ref body) = session.request_body
    {
        return super::coremail::extract_user_from_body(body);
    }
    None
}

/// Text line DLP,ReturnmatchResult

/// Use RegexSet 1Time/Count, MediummodeExecutelineVerbosematch.
/// SensitivedataofText, 1Time/Count immediatelyReturn, mode ~10x Add.
/// 512 KB ofTextonly first 512 KB (SensitiveInfo Header).

/// 先截断再归一化再正则（anti-evasion）:
/// - 零宽/不可见字符清理 (U+200B/200C/200D/FEFF/00AD 等)
/// - 全角→半角转换 (Ａ -> A, ０ -> 0 等)
pub fn scan_text(text: &str) -> DlpScanResult {
    // 步骤 1: 先截断原始输入（UTF-8 安全），避免 normalize 处理超大文本浪费 CPU
    let text = if text.len() > DLP_MAX_SCAN_LEN {
        let mut end = DLP_MAX_SCAN_LEN;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };

    // 步骤 2: 归一化（仅处理截断后的文本）
    let normalized = normalize_for_dlp(text);
    let text = normalized.as_str();

    // RegexSet: 1Time/Count verdict modepossibly Medium
    let hits = DLP_REGEX_SET.matches(text);
    if !hits.matched_any() {
        return DlpScanResult::default();
    }

    let mut result = DlpScanResult::default();

    // Card number (idx 0) - Same Used forBank Deduplicate
    let cc_raw_digits = if hits.matched(0) {
        let (cc_matches, raw) = find_credit_cards(text);
        if !cc_matches.is_empty() {
            result.matches.push("credit_card".to_string());
            result.details.push(("credit_card".to_string(), cc_matches));
        }
        raw
    } else {
        HashSet::new()
    };

    // ID cardNumber (idx 1)
    if hits.matched(1) {
        let id_matches = find_chinese_ids(text);
        if !id_matches.is_empty() {
            result.matches.push("id_number".to_string());
            result.details.push(("id_number".to_string(), id_matches));
        }
    }

    // Mobile phoneNumber (idx 2) ->= 3 SameNumberCode/Digit Recording, Avoid Mobile phoneNumber
    if hits.matched(2) {
        let phone_matches = find_chinese_phones(text);
        if phone_matches.len() >= 3 {
            result.matches.push("phone_number".to_string());
            result
                .details
                .push(("phone_number".to_string(), phone_matches));
        }
    }

    // BankCard number (idx 3) - Excludealreadymatchof Card number (P1.1 Deduplicate)
    if hits.matched(3) {
        let bank_matches = find_bank_cards(text, &cc_raw_digits);
        if !bank_matches.is_empty() {
            result.matches.push("bank_card".to_string());
            result.details.push(("bank_card".to_string(), bank_matches));
        }
    }

    // (idx 4)
    if hits.matched(4) {
        let addr_matches = find_chinese_addresses(text);
        if !addr_matches.is_empty() {
            result.matches.push("customer_address".to_string());
            result
                .details
                .push(("customer_address".to_string(), addr_matches));
        }
    }

    // email (idx 5) ->= 3 Sameemail Recording
    if hits.matched(5) {
        let email_matches = find_emails(text);
        if email_matches.len() >= 3 {
            result.matches.push("email_address".to_string());
            result
                .details
                .push(("email_address".to_string(), email_matches));
        }
    }

    // Number (idx 6)
    if hits.matched(6) {
        let passport_matches = find_passports(text);
        if !passport_matches.is_empty() {
            result.matches.push("passport_number".to_string());
            result
                .details
                .push(("passport_number".to_string(), passport_matches));
        }
    }

    // 1 Code/Digit (idx 7)
    if hits.matched(7) {
        let scc_matches = find_social_credit_codes(text);
        if !scc_matches.is_empty() {
            result.matches.push("social_credit_code".to_string());
            result
                .details
                .push(("social_credit_code".to_string(), scc_matches));
        }
    }

    // Password/ (idx 8)
    if hits.matched(8) {
        let cred_matches = find_credentials(text);
        if !cred_matches.is_empty() {
            result.matches.push("credential_leak".to_string());
            result
                .details
                .push(("credential_leak".to_string(), cred_matches));
        }
    }

    // SWIFT Code/Digit (idx 9)
    if hits.matched(9) {
        let swift_matches = find_swift_codes(text);
        if !swift_matches.is_empty() {
            result.matches.push("swift_code".to_string());
            result
                .details
                .push(("swift_code".to_string(), swift_matches));
        }
    }

    // CVV/SecurityCode/Digit (idx 10)
    if hits.matched(10) {
        let cvv_matches = find_cvv_codes(text);
        if !cvv_matches.is_empty() {
            result.matches.push("cvv_code".to_string());
            result.details.push(("cvv_code".to_string(), cvv_matches));
        }
    }

    // line Add

    // Number (idx 11)
    if hits.matched(11) {
        let tax_matches = find_tax_ids(text);
        if !tax_matches.is_empty() {
            result.matches.push("tax_id".to_string());
            result.details.push(("tax_id".to_string(), tax_matches));
        }
    }

    // IBAN BankAccount number (idx 12)
    if hits.matched(12) {
        let iban_matches = find_ibans(text);
        if !iban_matches.is_empty() {
            result.matches.push("iban".to_string());
            result.details.push(("iban".to_string(), iban_matches));
        }
    }

    // large Amount (idx 13) ->= 2 Recording, AvoidbodyMedium Amount
    if hits.matched(13) {
        let amount_matches = find_large_amounts(text);
        if amount_matches.len() >= 2 {
            result.matches.push("large_amount".to_string());
            result
                .details
                .push(("large_amount".to_string(), amount_matches));
        }
    }

    // BankAccount number (Context) (idx 14)
    if hits.matched(14) {
        let acct_matches = find_bank_accounts(text);
        if !acct_matches.is_empty() {
            result.matches.push("bank_account".to_string());
            result
                .details
                .push(("bank_account".to_string(), acct_matches));
        }
    }

    // Policy number/ SameNumber (idx 15)
    if hits.matched(15) {
        let contract_matches = find_contract_numbers(text);
        if !contract_matches.is_empty() {
            result.matches.push("contract_number".to_string());
            result
                .details
                .push(("contract_number".to_string(), contract_matches));
        }
    }

    // JR/T 0197-2020 mode (idx 16-29)

    // (idx 16) - C4, At least 2 SameKeywords
    if hits.matched(16) {
        let matches = find_keyword_matches(&RE_BIOMETRIC, text, 2);
        if !matches.is_empty() {
            result.matches.push("biometric_data".to_string());
            result.details.push(("biometric_data".to_string(), matches));
        }
    }

    // (idx 17) - C4, At least 2 SameKeywords
    if hits.matched(17) {
        let matches = find_keyword_matches(&RE_MEDICAL, text, 2);
        if !matches.is_empty() {
            result.matches.push("medical_health".to_string());
            result.details.push(("medical_health".to_string(), matches));
        }
    }

    // Info (idx 18) - C3
    if hits.matched(18) {
        let matches = find_vehicle_info(text);
        if !matches.is_empty() {
            result.matches.push("vehicle_info".to_string());
            result.details.push(("vehicle_info".to_string(), matches));
        }
    }

    // Info (idx 19) - C3
    if hits.matched(19) {
        let matches = find_keyword_matches(&RE_PROPERTY, text, 1);
        if !matches.is_empty() {
            result.matches.push("property_info".to_string());
            result.details.push(("property_info".to_string(), matches));
        }
    }

    // / (idx 20) - C3
    if hits.matched(20) {
        let matches = find_context_matches(&RE_INCOME, text);
        if !matches.is_empty() {
            result.matches.push("income_info".to_string());
            result.details.push(("income_info".to_string(), matches));
        }
    }

    // bit / (idx 21) - C3
    if hits.matched(21) {
        let matches = find_context_matches(&RE_GEO, text);
        if !matches.is_empty() {
            result.matches.push("geo_location".to_string());
            result.details.push(("geo_location".to_string(), matches));
        }
    }

    // VerifyCode/Digit/OTP (idx 22) - C3
    if hits.matched(22) && !result.matches.contains(&"cvv_code".to_string()) {
        let matches = find_context_matches(&RE_OTP, text);
        if !matches.is_empty() {
            result.matches.push("otp_verification".to_string());
            result
                .details
                .push(("otp_verification".to_string(), matches));
        }
    }

    // / (idx 23) - C3
    if hits.matched(23) {
        let matches = find_context_matches(&RE_LOAN, text);
        if !matches.is_empty() {
            result.matches.push("loan_credit_info".to_string());
            result
                .details
                .push(("loan_credit_info".to_string(), matches));
        }
    }

    // (idx 24) - C3
    if hits.matched(24) {
        let matches = find_context_matches(&RE_INSURANCE, text);
        if !matches.is_empty() {
            result.matches.push("insurance_policy".to_string());
            result
                .details
                .push(("insurance_policy".to_string(), matches));
        }
    }

    // (idx 25) - C3
    if hits.matched(25) {
        let matches = find_context_matches(&RE_FAMILY, text);
        if !matches.is_empty() {
            result.matches.push("family_relation".to_string());
            result
                .details
                .push(("family_relation".to_string(), matches));
        }
    }

    // Info (idx 26) - C2
    if hits.matched(26) {
        let matches = find_context_matches(&RE_EMPLOYEE, text);
        if !matches.is_empty() {
            result.matches.push("employee_info".to_string());
            result.details.push(("employee_info".to_string(), matches));
        }
    }

    // Recording (idx 27) - C2, At least 2 SameKeywords
    if hits.matched(27) {
        let matches = find_keyword_matches(&RE_JUDICIAL, text, 2);
        if !matches.is_empty() {
            result.matches.push("judicial_record".to_string());
            result
                .details
                .push(("judicial_record".to_string(), matches));
        }
    }

    // Info (idx 28) - C2
    if hits.matched(28) {
        let matches = find_context_matches(&RE_EDUCATION, text);
        if !matches.is_empty() {
            result.matches.push("education_info".to_string());
            result.details.push(("education_info".to_string(), matches));
        }
    }

    // Execute Number (idx 29) - C2
    if hits.matched(29) {
        let matches = find_context_matches(&RE_BIZ_LICENSE, text);
        if !matches.is_empty() {
            result.matches.push("business_license".to_string());
            result
                .details
                .push(("business_license".to_string(), matches));
        }
    }

    result
}

#[cfg(test)]
mod tests;
