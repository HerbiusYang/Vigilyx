//! Data security detection module.
//!
//! Analyzes HTTP protocol traffic to detect webmail data exfiltration behaviors:
//! 1. Draft box abuse (DraftBoxAbuse)
//! 2. File transit risk (FileTransitAbuse)
//! 3. Self-sending (SelfSending)
//! 4. Volume anomaly (VolumeAnomaly) - short-term sensitive operation bursts
//!
//! Policies:
//! - Time policy (time_policy) - non-working-hours alerts

pub mod chunked_upload;
pub mod coremail;
pub mod dlp;
pub mod document_extract;
pub mod draft_detect;
pub mod engine;
pub mod file_transit_detect;
pub mod jrt;
pub mod jrt_compliance;
pub mod self_send_detect;
pub mod time_policy;
pub mod volume_anomaly;

use std::path::Path;

use vigilyx_core::{DataSecurityIncident, HttpSession};

use self::dlp::DlpScanResult;

/// SEC: validate that body_temp_file stays within the allowed temp directories to prevent path traversal reads (CWE-22).
/// Returns the normalized path if it is valid; otherwise returns None and logs a warning.
pub fn validate_temp_path(path: &str) -> Option<std::path::PathBuf> {
    // List of allowed base directories (/app/data/tmp/http in the container or relative data/tmp/http).
    const ALLOWED_BASES: &[&str] = &["data/tmp/http", "/app/data/tmp/http"];

    let real = match Path::new(path).canonicalize() {
        Ok(p) => p,
        Err(_) => return None, // File does not exist or is not accessible
    };

    for base in ALLOWED_BASES {
        if let Ok(allowed) = Path::new(base).canonicalize()
            && real.starts_with(&allowed)
        {
            return Some(real);
        }
    }

    tracing::warn!(
        path = %path,
        "SEC: body_temp_file path traversal blocked (not under allowed temp directory)"
    );
    None
}

/// Detector analysis result: incident + optional DLP result (for JR/T compliance tracking).
pub type DetectorResult = Option<(DataSecurityIncident, Option<DlpScanResult>)>;

/// Data security detector trait.
pub trait DataSecurityDetector: Send + Sync {
   /// Unique detector ID.
    fn id(&self) -> &str;
   /// Human-readable detector name.
    fn name(&self) -> &str;
   /// Analyze an HTTP session. Returns (incident, dlp_result) if a security issue is found.

   /// `dlp_result` is used by JR/T 0197-2020 compliance tracking to accumulate
   /// sensitive data counts by classification level.
   /// If the detector does not perform DLP internally, returns None for the second element.
    fn analyze(&self, session: &HttpSession) -> DetectorResult;
}

/// Map DLP match type to its display name.
pub fn dlp_type_cn(dtype: &str) -> &str {
    match dtype {
        "credit_card" => "Credit Card Number",
        "id_number" => "ID Card Number",
        "phone_number" => "Phone Number",
        "bank_card" => "Bank Card Number",
        "customer_address" => "Customer Address",
        "sensitive_extension" => "High-Risk File Type",
        "email_address" => "Email Address",
        "passport_number" => "Passport Number",
        "social_credit_code" => "Social Credit Code",
        "credential_leak" => "Credential Leak",
        "swift_code" => "SWIFT Code",
        "cvv_code" => "CVV Security Code",
        "executable_upload" => "Executable File",
        "file_type_mismatch" => "File Type Disguise",
        "encrypted_archive" => "Encrypted Archive",
        "encrypted_pdf" => "Encrypted PDF",
        "biometric_data" => "Biometric Data",
        "medical_health" => "Medical Health Data",
        "vehicle_info" => "Vehicle Information",
        "property_info" => "Real Estate Information",
        "income_info" => "Income/Salary Data",
        "geo_location" => "Geographic Location",
        "otp_verification" => "Verification Code/OTP",
        "loan_credit_info" => "Loan/Credit Information",
        "insurance_policy" => "Insurance Policy",
        "family_relation" => "Family Relations",
        "employee_info" => "Employee Information",
        "judicial_record" => "Judicial Record",
        "education_info" => "Education Information",
        "business_license" => "Business License",
        "bank_account_context" => "Bank Account",
        "tax_id" => "Tax ID",
        "iban" => "IBAN Account Number",
        "large_amount" => "Large Amount",
        "contract_number" => "Contract Number",
        other => other,
    }
}

/// Extract context snippets around DLP matched values from source text.
///
/// For each value in `matched_values`, extracts up to 40 characters of surrounding context,
/// highlighting the match with brackets. Returns at most 3 snippets.
pub fn extract_snippet(source_text: &str, matched_values: &[String]) -> Option<String> {
    const CONTEXT_CHARS: usize = 40;
    const MAX_SNIPPETS: usize = 3;

    let mut snippets: Vec<String> = Vec::new();

    for val in matched_values {
        if snippets.len() >= MAX_SNIPPETS {
            break;
        }
        if val.is_empty() {
            continue;
        }
        if let Some(pos) = source_text.find(val.as_str()) {
           // Get up to CONTEXT_CHARS characters before match (UTF-8 safe)
            let before_start = source_text[..pos]
                .char_indices()
                .rev()
                .nth(CONTEXT_CHARS)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let before = source_text[before_start..pos].trim();

           // Get up to CONTEXT_CHARS characters after match
            let after_end_byte = pos + val.len();
            let after_end = source_text[after_end_byte..]
                .char_indices()
                .nth(CONTEXT_CHARS)
                .map(|(i, _)| after_end_byte + i)
                .unwrap_or(source_text.len());
            let after = source_text[after_end_byte..after_end].trim();

            let mut s = String::with_capacity(before.len() + val.len() + after.len() + 10);
            if before_start > 0 {
                s.push('…');
            }
            s.push_str(before);
            s.push('【');
            s.push_str(val);
            s.push('】');
            s.push_str(after);
            if after_end < source_text.len() {
                s.push('…');
            }
            snippets.push(s);
        }
    }

    if snippets.is_empty() {
        None
    } else {
        Some(snippets.join("\n---\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_snippet_basic() {
        let text = "客户ID cardNumberCode/Digit是 110101199001011237 请妥善保管";
        let values = vec!["110101199001011237".to_string()];
        let result = extract_snippet(text, &values);
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(
            s.contains("【110101199001011237】"),
            "Value should be highlighted"
        );
    }

    #[test]
    fn test_extract_snippet_with_context() {
        let text = "first面of文字 110101199001011237 后面of文字";
        let values = vec!["110101199001011237".to_string()];
        let result = extract_snippet(text, &values).unwrap();
        assert!(
            result.contains("first面of文字"),
            "Should include before context"
        );
        assert!(
            result.contains("后面of文字"),
            "Should include after context"
        );
    }

    #[test]
    fn test_extract_snippet_no_match() {
        let text = "这里not有matchofvalue";
        let values = vec!["not_found".to_string()];
        assert!(extract_snippet(text, &values).is_none());
    }

    #[test]
    fn test_extract_snippet_empty_values() {
        let text = "some text";
        let values: Vec<String> = vec![];
        assert!(extract_snippet(text, &values).is_none());
    }

    #[test]
    fn test_extract_snippet_empty_string_value_skipped() {
        let text = "some text";
        let values = vec!["".to_string()];
        assert!(extract_snippet(text, &values).is_none());
    }

    #[test]
    fn test_extract_snippet_max_three() {
        let text = "AAA BBB CCC DDD EEE";
        let values = vec![
            "AAA".to_string(),
            "BBB".to_string(),
            "CCC".to_string(),
            "DDD".to_string(),
            "EEE".to_string(),
        ];
        let result = extract_snippet(text, &values).unwrap();
        let snippet_count = result.matches("---").count() + 1;
        assert!(
            snippet_count <= 3,
            "Should have at most 3 snippets, got {}",
            snippet_count
        );
    }

    #[test]
    fn test_extract_snippet_separator() {
        let text = "AAA BBB CCC";
        let values = vec!["AAA".to_string(), "CCC".to_string()];
        let result = extract_snippet(text, &values).unwrap();
        assert!(
            result.contains("---"),
            "Multiple snippets should be separated by ---"
        );
    }

    #[test]
    fn test_extract_snippet_value_at_start() {
        let text = "110101199001011237 是ID cardNumber";
        let values = vec!["110101199001011237".to_string()];
        let result = extract_snippet(text, &values).unwrap();
        assert!(
            result.starts_with("【"),
            "Value at start should not have leading ellipsis"
        );
    }

    #[test]
    fn test_extract_snippet_value_at_end() {
        let text = "ID cardNumber是 110101199001011237";
        let values = vec!["110101199001011237".to_string()];
        let result = extract_snippet(text, &values).unwrap();
        assert!(
            !result.ends_with("…"),
            "Value at end should not have trailing ellipsis"
        );
    }

    #[test]
    fn test_extract_snippet_long_context_has_ellipsis() {
        let prefix = "A".repeat(100);
        let suffix = "B".repeat(100);
        let text = format!("{}TARGET{}", prefix, suffix);
        let values = vec!["TARGET".to_string()];
        let result = extract_snippet(&text, &values).unwrap();
        assert!(
            result.starts_with('…'),
            "Long prefix should produce leading ellipsis"
        );
        assert!(
            result.ends_with('…'),
            "Long suffix should produce trailing ellipsis"
        );
    }

    #[test]
    fn test_extract_snippet_chinese_context() {
        let prefix = "这是first面ofChineseContent用来TestContext截GetFunctionwhether正确Process多Bytecharacters边界情况ofTextSegment落";
        let text = format!("{} 4532015112830366 后面ofContent", prefix);
        let values = vec!["4532015112830366".to_string()];
        let result = extract_snippet(&text, &values);
        assert!(
            result.is_some(),
            "Should handle Chinese text context correctly"
        );
    }
}
