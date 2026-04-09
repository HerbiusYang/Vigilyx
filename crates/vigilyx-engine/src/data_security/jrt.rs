//! JR/T 0197-2020 data security classification mapping.
//!
//! Maps DLP detection patterns to JR/T 0197-2020 data security classification levels:
//! - C1 Public: publicly available information
//! - C2 Internal: internal-use information
//! - C3 Sensitive: PII, account information, etc.
//! - C4 Highly Sensitive: authentication data, passwords, etc.
//! - C5 Extremely Sensitive: state-secret level data (not applicable here)

/// according to DLP modeNameReturn JR/T 0197-2020 Securitylevel (1-4)

/// Mapping According to:Standard A<data levelRule table>
/// MappingofmodeReturn 0(if executable_upload wait dataClassificationmode)
pub fn jrt_level(pattern_name: &str) -> u8 {
    match pattern_name {
       // C4 HighSensitivelevel - Info + +
        "credential_leak" | "cvv_code" | "credit_card" | "biometric_data" | "medical_health" => 4,

       // C3 Sensitivelevel - Info + AccountInfo + + + +
        "id_number"
        | "phone_number"
        | "bank_card"
        | "customer_address"
        | "email_address"
        | "passport_number"
        | "iban"
        | "large_amount"
        | "bank_account_context"
        | "contract_number"
        | "vehicle_info"
        | "property_info"
        | "income_info"
        | "geo_location"
        | "otp_verification"
        | "loan_credit_info"
        | "insurance_policy"
        | "family_relation" => 3,

       // C2 Internallevel - BusinessInfo + + + + Execute
        "swift_code" | "tax_id" | "employee_info" | "judicial_record" | "education_info"
        | "business_license" => 2,

       // C1 Publiclevel - PublicInfo
        "social_credit_code" => 1,

       // level: dataClass ofdetectmode (ifExecutable file, File)
        _ => 0,
    }
}

/// according to DLP Result Medium of High JR/T level Critical

/// JR/T 0197-2020:datalevel High, Critical High.
/// - C4 HighSensitivelevel -> High (Password/CVV/ - Connect)
/// - C3 Sensitivelevel -> Medium (ID card/Mobile phone/Bank -)
/// - C2 Internallevel -> Low (SWIFT/ ID - InternalInfo)
/// - C1 Publiclevel -> Low (Code/Digit - Public)

/// FiledetectMediumof dataClassificationmode(Executable file, File, EncryptCompresspacket)
/// Bydetecthandler lineProcess(Connect High), function.
pub fn severity_from_max_jrt_level(dlp_matches: &[String]) -> vigilyx_core::DataSecuritySeverity {
    let max_level = dlp_matches.iter().map(|m| jrt_level(m)).max().unwrap_or(0);

    match max_level {
        4 => vigilyx_core::DataSecuritySeverity::High,
        3 => vigilyx_core::DataSecuritySeverity::Medium,
        _ => vigilyx_core::DataSecuritySeverity::Low,
    }
}

/// Return JR/T level display label.
pub fn jrt_level_label(level: u8) -> &'static str {
    match level {
        1 => "C1-Public",
        2 => "C2-Internal",
        3 => "C3-Sensitive",
        4 => "C4-Highly Sensitive",
        5 => "C5-Extremely Sensitive",
        _ => "Unclassified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jrt_level_c4_patterns() {
        for p in [
            "credential_leak",
            "cvv_code",
            "credit_card",
            "biometric_data",
            "medical_health",
        ] {
            assert_eq!(jrt_level(p), 4, "pattern '{}' should be C4", p);
        }
    }

    #[test]
    fn test_jrt_level_c3_patterns() {
        let c3_patterns = [
            "id_number",
            "phone_number",
            "bank_card",
            "customer_address",
            "email_address",
            "passport_number",
            "iban",
            "large_amount",
            "bank_account_context",
            "contract_number",
            "vehicle_info",
            "property_info",
            "income_info",
            "geo_location",
            "otp_verification",
            "loan_credit_info",
            "insurance_policy",
            "family_relation",
        ];
        for p in c3_patterns {
            assert_eq!(jrt_level(p), 3, "pattern '{}' should be C3", p);
        }
    }

    #[test]
    fn test_jrt_level_c2_patterns() {
        for p in [
            "swift_code",
            "tax_id",
            "employee_info",
            "judicial_record",
            "education_info",
            "business_license",
        ] {
            assert_eq!(jrt_level(p), 2, "pattern '{}' should be C2", p);
        }
    }

    #[test]
    fn test_jrt_level_c1_patterns() {
        assert_eq!(jrt_level("social_credit_code"), 1);
    }

    #[test]
    fn test_jrt_level_unmapped() {
        assert_eq!(jrt_level("executable_upload"), 0);
        assert_eq!(jrt_level("file_type_mismatch"), 0);
        assert_eq!(jrt_level("volume_anomaly"), 0);
        assert_eq!(jrt_level("unknown_pattern"), 0);
    }

    #[test]
    fn test_jrt_level_label() {
        assert_eq!(jrt_level_label(1), "C1-Public");
        assert_eq!(jrt_level_label(2), "C2-Internal");
        assert_eq!(jrt_level_label(3), "C3-Sensitive");
        assert_eq!(jrt_level_label(4), "C4-Highly Sensitive");
        assert_eq!(jrt_level_label(5), "C5-Extremely Sensitive");
        assert_eq!(jrt_level_label(0), "Unclassified");
    }

    #[test]
    fn test_all_30_dlp_patterns_mapped() {
       // Ensure 30 DLP modeall Mapping(≥1)
        let all_patterns = [
           // 16
            "credit_card",
            "id_number",
            "phone_number",
            "bank_card",
            "customer_address",
            "email_address",
            "passport_number",
            "social_credit_code",
            "credential_leak",
            "swift_code",
            "cvv_code",
            "tax_id",
            "iban",
            "large_amount",
            "bank_account_context",
            "contract_number",
           // JR/T 14
            "biometric_data",
            "medical_health",
            "vehicle_info",
            "property_info",
            "income_info",
            "geo_location",
            "otp_verification",
            "loan_credit_info",
            "insurance_policy",
            "family_relation",
            "employee_info",
            "judicial_record",
            "education_info",
            "business_license",
        ];
        for p in all_patterns {
            assert!(
                jrt_level(p) >= 1,
                "pattern '{}' should have JR/T level >= 1",
                p
            );
        }
        assert_eq!(all_patterns.len(), 30);
    }
}
