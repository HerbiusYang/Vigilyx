//! Product risk policy informed by JR/T 0197 and JR/T 0171.
//!
//! These are candidate security levels (1-5), not an institution's approved
//! data catalogue, personal-financial C1-C3 categories, or a legal conclusion.
//! Single-transfer alerts and bulk escalation are separate controls.

use std::{collections::HashMap, sync::LazyLock};

use serde::Deserialize;
use vigilyx_core::{DataSecurityIncident, DataSecuritySeverity};

#[derive(Deserialize)]
pub struct FinancialPolicy {
    pub version: String,
    pub single_event_min_items: usize,
    pub bulk_window_hours: i64,
    pub bulk_sensitive_items: usize,
    pub bulk_high_sensitive_items: usize,
    pub bulk_cooldown_minutes: i64,
    pub field_levels: HashMap<String, u8>,
}

pub static POLICY: LazyLock<FinancialPolicy> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../../shared/schemas/data_security_policy.json"
    ))
    .expect("bundled financial data-security policy must be valid")
});

pub fn security_level(pattern: &str) -> u8 {
    let pattern = match pattern {
        "bank_account_context" => "bank_account",
        other => other,
    };
    POLICY.field_levels.get(pattern).copied().unwrap_or(0)
}

/// An OTP combined with an account can complete authentication. A card
/// number by itself is account information, not a CVV/password equivalent.
pub fn match_level(pattern: &str, matches: &[String]) -> u8 {
    if pattern == "otp_verification"
        && matches.iter().any(|name| {
            matches!(
                name.as_str(),
                "credit_card" | "bank_card" | "iban" | "bank_account" | "bank_account_context"
            )
        })
    {
        4
    } else {
        security_level(pattern)
    }
}

pub fn max_security_level(matches: &[String]) -> u8 {
    matches
        .iter()
        .map(|name| match_level(name, matches))
        .max()
        .unwrap_or(0)
}

pub fn observation_severity(matches: &[String]) -> DataSecuritySeverity {
    match max_security_level(matches) {
        4.. => DataSecuritySeverity::High,
        3 => DataSecuritySeverity::Medium,
        2 => DataSecuritySeverity::Low,
        _ => DataSecuritySeverity::Info,
    }
}

pub fn transfer_severity(matches: &[String]) -> DataSecuritySeverity {
    match max_security_level(matches) {
        4.. => DataSecuritySeverity::Critical,
        3 => DataSecuritySeverity::High,
        2 => DataSecuritySeverity::Medium,
        _ => DataSecuritySeverity::Info,
    }
}

/// Idempotency follows the observed session and event kind. Two different
/// transfers by the same user must never suppress each other's alerts.
pub fn assign_incident_id(incident: &mut DataSecurityIncident) {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!(
        "ds-policy-v1:{}:{}",
        incident.http_session_id, incident.incident_type
    ));
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    incident.id = uuid::Uuid::from_bytes(bytes);
}

pub fn transfer_details(matches: &[String], source: &str) -> serde_json::Value {
    serde_json::json!({
        "policy_version": POLICY.version,
        "security_level_candidate": max_security_level(matches),
        "authorization_status": "unverified",
        "observation": "transfer_submission",
        "delivery_confirmed": false,
        "source": source,
        "legal_assessment": "not_determined"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn single_account_and_authentication_secret_have_distinct_risks() {
        let password = super::super::dlp::scan_text("密码：a8Z!");
        assert!(password.matches.contains(&"credential_leak".to_string()));
        assert_eq!(
            transfer_severity(&password.matches),
            DataSecuritySeverity::Critical
        );
        assert_eq!(
            transfer_severity(&names(&["credit_card"])),
            DataSecuritySeverity::High
        );
        assert_eq!(
            transfer_severity(&names(&["cvv_code"])),
            DataSecuritySeverity::Critical
        );
        assert_eq!(
            transfer_severity(&names(&["phone_number"])),
            DataSecuritySeverity::High
        );
        assert_eq!(
            observation_severity(&names(&["id_number"])),
            DataSecuritySeverity::Medium
        );
    }

    #[test]
    fn otp_account_combination_escalates_without_quantity_threshold() {
        let account = super::super::dlp::scan_text("请转账到 账号：1234567890123");
        assert!(account.matches.contains(&"bank_account".to_string()));
        assert_eq!(
            transfer_severity(&account.matches),
            DataSecuritySeverity::High
        );
        let mut combined = account.matches;
        combined.push("otp_verification".into());
        assert_eq!(transfer_severity(&combined), DataSecuritySeverity::Critical);
        assert_eq!(security_level("bank_account_context"), 3);
        assert_eq!(max_security_level(&names(&["otp_verification"])), 3);
        assert_eq!(
            transfer_severity(&names(&["otp_verification", "bank_account_context"])),
            DataSecuritySeverity::Critical
        );
    }

    #[test]
    fn public_reference_and_business_budget_are_not_authentication_data() {
        assert_eq!(
            transfer_severity(&names(&["swift_code"])),
            DataSecuritySeverity::Info
        );
        assert_eq!(
            observation_severity(&names(&["large_amount"])),
            DataSecuritySeverity::Low
        );
        assert_eq!(POLICY.single_event_min_items, 1);
        assert!(
            POLICY
                .field_levels
                .values()
                .all(|level| (1..=4).contains(level))
        );
    }
}
