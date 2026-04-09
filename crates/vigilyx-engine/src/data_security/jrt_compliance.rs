//! JR/T 0197-2020 compliance threshold tracker.
//!
//! Tracks cumulative sensitive data counts per user/IP according to JR/T 0197-2020
//! data security classification, and triggers compliance alerts when thresholds are exceeded.
//!
//! # Thresholds
//!
//! - C3+ (sensitive level) cumulative >= 500 items -> severity = High
//! - C4+ (highly sensitive level) cumulative >= 50 items -> severity = Critical
//!
//! Design:
//! - In-memory state with sliding window tracking
//! - 24-hour window (compliance reset period)
//! - Separate L3+ and L4+ threshold tracking
//! - 1-hour alert cooldown (same user, same level)
//! - Implements DataSecurityDetector trait for engine loop integration

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tracing::info;
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity};

use super::dlp::DlpScanResult;

/// Window size (seconds) - 24 hours.
const WINDOW_SECS: i64 = 86400;
/// C3+ alert threshold: sensitive-level data cumulative count.
const LEVEL3_THRESHOLD: usize = 500;
/// C4+ alert threshold: highly-sensitive-level data cumulative count.
const LEVEL4_THRESHOLD: usize = 50;
/// Alert cooldown period (seconds) - same key cannot re-alert at the same level.
const ALERT_COOLDOWN_SECS: i64 = 3600; // 1 hour
/// Max tracked keys (prevent unbounded memory growth).
const MAX_TRACKED_KEYS: usize = 10_000;

/// A single DLP record with timestamp and counts.
struct DlpRecord {
   /// Record timestamp.
    timestamp: DateTime<Utc>,
   /// C3+ matches (includes C4).
    level3_plus_count: usize,
   /// C4+ matches only.
    level4_plus_count: usize,
}

/// Compliance tracking state for a single key.
struct ComplianceState {
   /// DLP records within the sliding window.
    records: Vec<DlpRecord>,
   /// Timestamp of last C3+ alert.
    last_alert_l3: Option<DateTime<Utc>>,
   /// Timestamp of last C4+ alert.
    last_alert_l4: Option<DateTime<Utc>>,
}

impl ComplianceState {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            last_alert_l3: None,
            last_alert_l4: None,
        }
    }

   /// Add a DLP record and clean up expired records.
    fn record(&mut self, now: DateTime<Utc>, l3_count: usize, l4_count: usize) {
        let cutoff = now - chrono::Duration::seconds(WINDOW_SECS);
        self.records.retain(|r| r.timestamp > cutoff);
        if l3_count > 0 || l4_count > 0 {
            self.records.push(DlpRecord {
                timestamp: now,
                level3_plus_count: l3_count,
                level4_plus_count: l4_count,
            });
        }
    }

   /// Total C3+ cumulative count.
    fn total_l3_plus(&self) -> usize {
        self.records.iter().map(|r| r.level3_plus_count).sum()
    }

   /// Total C4+ cumulative count.
    fn total_l4_plus(&self) -> usize {
        self.records.iter().map(|r| r.level4_plus_count).sum()
    }

   /// Whether C3+ alert is in cooldown period.
    fn l3_in_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.last_alert_l3
            .map(|t| (now - t).num_seconds() < ALERT_COOLDOWN_SECS)
            .unwrap_or(false)
    }

   /// Whether C4+ alert is in cooldown period.
    fn l4_in_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.last_alert_l4
            .map(|t| (now - t).num_seconds() < ALERT_COOLDOWN_SECS)
            .unwrap_or(false)
    }
}

/// JR/T 0197-2020 compliance tracker.
pub struct JrtComplianceTracker {
   /// key -> compliance tracking state (key = user email or client_ip).
    windows: HashMap<String, ComplianceState>,
   /// Cleanup counter.
    cleanup_counter: u64,
}

impl Default for JrtComplianceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl JrtComplianceTracker {
    pub fn new() -> Self {
        info!(
            "JrtComplianceTracker initialized: window={}h, C3+ threshold={}, C4+ threshold={}, cooldown={}min",
            WINDOW_SECS / 3600,
            LEVEL3_THRESHOLD,
            LEVEL4_THRESHOLD,
            ALERT_COOLDOWN_SECS / 60,
        );
        Self {
            windows: HashMap::with_capacity(256),
            cleanup_counter: 0,
        }
    }

   /// Record a DLP result and check whether JR/T compliance alerts should fire.
   ///
   /// `key`: tracking key (user email or client_ip)
   /// `dlp_result`: DLP scan result
   /// `client_ip`: source IP address
   /// `detected_user`: detected user identity
   /// `http_session_id`: associated HTTP session ID
   /// `uri`: request URI
   /// `host`: request host
   ///
   /// Returns 0-2 alerts (C3+ and C4+ are checked independently).
    #[allow(clippy::too_many_arguments)]
    pub fn record_dlp_result(
        &mut self,
        key: &str,
        dlp_result: &DlpScanResult,
        client_ip: &str,
        detected_user: Option<&str>,
        http_session_id: uuid::Uuid,
        uri: &str,
        host: Option<&str>,
    ) -> Vec<DataSecurityIncident> {
       // Count items at each classification level from this result
        let l3_count = dlp_result.count_items_at_level(3); // Contains C3 And C4
        let l4_count = dlp_result.count_items_at_level(4); // C4

       // No sensitive data at C3+ level, skip
        if l3_count == 0 {
            return Vec::new();
        }

        let now = Utc::now();

       // Periodically clean up expired keys
        self.cleanup_counter += 1;
        if self.cleanup_counter.is_multiple_of(200) || self.windows.len() > MAX_TRACKED_KEYS {
            self.cleanup(now);
        }

        let state = self
            .windows
            .entry(key.to_string())
            .or_insert_with(ComplianceState::new);

        state.record(now, l3_count, l4_count);

        let total_l3 = state.total_l3_plus();
        let total_l4 = state.total_l4_plus();

        let mut incidents = Vec::new();

       // Check C4+ threshold (higher priority, checked first)
        if total_l4 >= LEVEL4_THRESHOLD && !state.l4_in_cooldown(now) {
            state.last_alert_l4 = Some(now);
            let user_label = detected_user.unwrap_or(client_ip);
            let summary = format!(
                "JR/T compliance alert: {} exfiltrated {} C4-level (highly sensitive) data items within 24h, exceeding threshold {}",
                user_label, total_l4, LEVEL4_THRESHOLD
            );
            info!(
                key = key,
                total_l4 = total_l4,
                threshold = LEVEL4_THRESHOLD,
                "JR/T C4+ compliance alert triggered"
            );
            incidents.push(DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id,
                incident_type: DataSecurityIncidentType::JrtComplianceViolation,
                severity: DataSecuritySeverity::Critical,
                confidence: 0.90,
                summary,
                evidence: vec![
                    Evidence {
                        description: format!(
                            "JR/T 0197-2020 C4-level (highly sensitive) data: 24h cumulative {} items (threshold: {})",
                            total_l4, LEVEL4_THRESHOLD
                        ),
                        location: Some("jrt_compliance_c4".to_string()),
                        snippet: Some(format!(
                            "Contains: credentials/passwords/CVV/credit cards and other authentication info; key={}, ip={}",
                            key, client_ip
                        )),
                    },
                ],
                details: None,
                dlp_matches: vec!["jrt_compliance_c4".to_string()],
                client_ip: client_ip.to_string(),
                detected_user: detected_user.map(|s| s.to_string()),
                request_url: uri.to_string(),
                host: host.map(|s| s.to_string()),
                method: "AGGREGATE".to_string(),
                created_at: now,
            });
        }

       // Check C3+ Threshold
        if total_l3 >= LEVEL3_THRESHOLD && !state.l3_in_cooldown(now) {
            state.last_alert_l3 = Some(now);
            let user_label = detected_user.unwrap_or(client_ip);
            let summary = format!(
                "JR/T compliance alert: {} exfiltrated {} C3-level (sensitive) or higher data items within 24h, exceeding threshold {}",
                user_label, total_l3, LEVEL3_THRESHOLD
            );
            info!(
                key = key,
                total_l3 = total_l3,
                threshold = LEVEL3_THRESHOLD,
                "JR/T C3+ compliance alert triggered"
            );
            incidents.push(DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id,
                incident_type: DataSecurityIncidentType::JrtComplianceViolation,
                severity: DataSecuritySeverity::High,
                confidence: 0.90,
                summary,
                evidence: vec![
                    Evidence {
                        description: format!(
                            "JR/T 0197-2020 C3-level (sensitive) or higher data: 24h cumulative {} items (threshold: {})",
                            total_l3, LEVEL3_THRESHOLD
                        ),
                        location: Some("jrt_compliance_c3".to_string()),
                        snippet: Some(format!(
                            "Contains: ID cards/phone numbers/bank cards/addresses/emails/passports and other PII; key={}, ip={}",
                            key, client_ip
                        )),
                    },
                ],
                details: None,
                dlp_matches: vec!["jrt_compliance_c3".to_string()],
                client_ip: client_ip.to_string(),
                detected_user: detected_user.map(|s| s.to_string()),
                request_url: uri.to_string(),
                host: host.map(|s| s.to_string()),
                method: "AGGREGATE".to_string(),
                created_at: now,
            });
        }

        incidents
    }

   /// Clean up expired tracking state.
    fn cleanup(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(WINDOW_SECS);
        self.windows.retain(|_, state| {
            state.records.retain(|r| r.timestamp > cutoff);
            !state.records.is_empty() || state.l3_in_cooldown(now) || state.l4_in_cooldown(now)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_security::dlp::DlpScanResult;

   /// constructpacketContains Count ID Numberof DLP Result
    fn make_dlp_result_l3(count: usize) -> DlpScanResult {
        let values: Vec<String> = (0..count)
            .map(|i| format!("32010119900101{:04}", i))
            .collect();
        DlpScanResult {
            matches: vec!["id_number".to_string()],
            details: vec![("id_number".to_string(), values)],
        }
    }

   /// constructpacketContains Count CVV of DLP Result (C4 level)
    fn make_dlp_result_l4(count: usize) -> DlpScanResult {
        let values: Vec<String> = (0..count).map(|i| format!("cvv={:03}", i)).collect();
        DlpScanResult {
            matches: vec!["cvv_code".to_string()],
            details: vec![("cvv_code".to_string(), values)],
        }
    }

    #[test]
    fn test_below_l3_threshold_no_alert() {
        let mut tracker = JrtComplianceTracker::new();
       // 499 Item C3 data -
        let dlp = make_dlp_result_l3(499);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents.is_empty());
    }

    #[test]
    fn test_at_l3_threshold_alerts() {
        let mut tracker = JrtComplianceTracker::new();
       // 500 Item C3 data - High Alert
        let dlp = make_dlp_result_l3(500);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, DataSecuritySeverity::High);
        assert_eq!(
            incidents[0].incident_type,
            DataSecurityIncidentType::JrtComplianceViolation
        );
    }

    #[test]
    fn test_below_l4_threshold_no_alert() {
        let mut tracker = JrtComplianceTracker::new();
       // 49 Item C4 data -
        let dlp = make_dlp_result_l4(49);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents.is_empty());
    }

    #[test]
    fn test_at_l4_threshold_alerts() {
        let mut tracker = JrtComplianceTracker::new();
       // 50 Item C4 data - Critical Alert
        let dlp = make_dlp_result_l4(50);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_l4_counts_toward_l3() {
        let mut tracker = JrtComplianceTracker::new();
       // 450 Item C3 + 50 Item C4 = 500 Item C3+ -> C3 And C4 Alert
        let dlp_l3 = make_dlp_result_l3(450);
        let _ = tracker.record_dlp_result(
            "user@test.com",
            &dlp_l3,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        let dlp_l4 = make_dlp_result_l4(50);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp_l4,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
       // C4 Alert (50>= 50) + C3 Alert (500>= 500)
        assert_eq!(incidents.len(), 2);
    }

    #[test]
    fn test_accumulation_across_sessions() {
        let mut tracker = JrtComplianceTracker::new();
       // 5 Time/Count,every 100 Item C3 -> After 5 Time/Count
        for i in 0..5 {
            let dlp = make_dlp_result_l3(100);
            let incidents = tracker.record_dlp_result(
                "user@test.com",
                &dlp,
                "10.0.0.1",
                Some("user@test.com"),
                uuid::Uuid::new_v4(),
                "/test",
                None,
            );
            if i < 4 {
                assert!(
                    incidents.is_empty(),
                    "should not alert at {} items",
                    (i + 1) * 100
                );
            } else {
                assert_eq!(incidents.len(), 1, "should alert at 500 items");
            }
        }
    }

    #[test]
    fn test_different_users_independent() {
        let mut tracker = JrtComplianceTracker::new();
       // user A: 499 Item -> Alert
        let dlp = make_dlp_result_l3(499);
        let incidents_a = tracker.record_dlp_result(
            "userA@test.com",
            &dlp,
            "10.0.0.1",
            Some("userA@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents_a.is_empty());

       // user B: 500 Item -> Alert(A)
        let dlp = make_dlp_result_l3(500);
        let incidents_b = tracker.record_dlp_result(
            "userB@test.com",
            &dlp,
            "10.0.0.2",
            Some("userB@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents_b.len(), 1);
    }

    #[test]
    fn test_cooldown_prevents_duplicate_alert() {
        let mut tracker = JrtComplianceTracker::new();
       // After1Time/Count 500 Item -> Alert
        let dlp = make_dlp_result_l3(500);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 1);

       // Connect Time/Count -> Period Alert
        let dlp2 = make_dlp_result_l3(100);
        let incidents2 = tracker.record_dlp_result(
            "user@test.com",
            &dlp2,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents2.is_empty(), "should not alert during cooldown");
    }

    #[test]
    fn test_empty_dlp_result_no_effect() {
        let mut tracker = JrtComplianceTracker::new();
        let dlp = DlpScanResult::default();
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents.is_empty());
    }

    
   // Test: Threshold level
    

   /// constructpacketContains C3+C4 dataof DLP Result
    fn make_dlp_result_mixed(l3_count: usize, l4_count: usize) -> DlpScanResult {
        let mut matches = Vec::new();
        let mut details = Vec::new();
        if l3_count > 0 {
            let vals: Vec<String> = (0..l3_count).map(|i| format!("id_{}", i)).collect();
            matches.push("id_number".to_string());
            details.push(("id_number".to_string(), vals));
        }
        if l4_count > 0 {
            let vals: Vec<String> = (0..l4_count).map(|i| format!("cvv_{}", i)).collect();
            matches.push("cvv_code".to_string());
            details.push(("cvv_code".to_string(), vals));
        }
        DlpScanResult { matches, details }
    }

    #[test]
    fn test_l4_threshold_exact_boundary() {
        let mut tracker = JrtComplianceTracker::new();
       // 49 ItemDo not trigger
        let dlp = make_dlp_result_l4(49);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents.is_empty(), "49 C4 items should not alert");

       // Add 1 Item = 50,
        let dlp2 = make_dlp_result_l4(1);
        let incidents2 = tracker.record_dlp_result(
            "user@test.com",
            &dlp2,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents2.len(), 1, "50th C4 item should trigger alert");
        assert_eq!(incidents2[0].severity, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_l3_threshold_exact_boundary() {
        let mut tracker = JrtComplianceTracker::new();
       // 499 ItemDo not trigger
        let dlp = make_dlp_result_l3(499);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(incidents.is_empty(), "499 C3 items should not alert");

       // Add 1 Item = 500,
        let dlp2 = make_dlp_result_l3(1);
        let incidents2 = tracker.record_dlp_result(
            "user@test.com",
            &dlp2,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents2.len(), 1, "500th C3 item should trigger alert");
        assert_eq!(incidents2[0].severity, DataSecuritySeverity::High);
    }

    #[test]
    fn test_mixed_c3_c4_both_thresholds() {
        let mut tracker = JrtComplianceTracker::new();
       // 1Time/Count 450 C3 + 50 C4 = 500 C3+ total, 50 C4+ total
        let dlp = make_dlp_result_mixed(450, 50);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 2, "Should trigger both C3+ and C4+ alerts");
       // C4+ Critical Return (Code/Digit: Check C4+)
        assert!(
            incidents
                .iter()
                .any(|i| i.severity == DataSecuritySeverity::Critical)
        );
        assert!(
            incidents
                .iter()
                .any(|i| i.severity == DataSecuritySeverity::High)
        );
    }

    #[test]
    fn test_only_c4_also_triggers_c3_when_total_enough() {
        let mut tracker = JrtComplianceTracker::new();
       // 500 Item C4 data -> C4 C3+, C3+ = 500
        let dlp = make_dlp_result_l4(500);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(
            incidents.len(),
            2,
            "500 C4 items should trigger both C3+ and C4+ alerts"
        );
    }

    #[test]
    fn test_only_c4_below_c3_threshold() {
        let mut tracker = JrtComplianceTracker::new();
       // 50 Item C4 -> C4+, C3+ total = 50 <500 -> only C4+ Alert
        let dlp = make_dlp_result_l4(50);
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_many_small_batches_accumulate() {
        let mut tracker = JrtComplianceTracker::new();
       // every 10 Item C3,contiguous 50 Time/Count = 500 -> After 50 Time/Count
        for i in 0..50 {
            let dlp = make_dlp_result_l3(10);
            let incidents = tracker.record_dlp_result(
                "user@test.com",
                &dlp,
                "10.0.0.1",
                Some("user@test.com"),
                uuid::Uuid::new_v4(),
                "/test",
                None,
            );
            if i < 49 {
                assert!(
                    incidents.is_empty(),
                    "Should not alert at {} items",
                    (i + 1) * 10
                );
            } else {
                assert_eq!(incidents.len(), 1, "Should alert at 500 items");
            }
        }
    }

    #[test]
    fn test_multiple_users_parallel() {
        let mut tracker = JrtComplianceTracker::new();
       // 3 user SameCount
        let dlp_a = make_dlp_result_l3(500);
        let dlp_b = make_dlp_result_l3(300);
        let dlp_c = make_dlp_result_l3(500);

        let inc_a = tracker.record_dlp_result(
            "a@test.com",
            &dlp_a,
            "1.1.1.1",
            Some("a@test.com"),
            uuid::Uuid::new_v4(),
            "/",
            None,
        );
        let inc_b = tracker.record_dlp_result(
            "b@test.com",
            &dlp_b,
            "2.2.2.2",
            Some("b@test.com"),
            uuid::Uuid::new_v4(),
            "/",
            None,
        );
        let inc_c = tracker.record_dlp_result(
            "c@test.com",
            &dlp_c,
            "3.3.3.3",
            Some("c@test.com"),
            uuid::Uuid::new_v4(),
            "/",
            None,
        );

        assert_eq!(inc_a.len(), 1, "User A (500) should alert");
        assert!(inc_b.is_empty(), "User B (300) should NOT alert");
        assert_eq!(inc_c.len(), 1, "User C (500) should alert");
    }

    #[test]
    fn test_incident_fields_populated() {
        let mut tracker = JrtComplianceTracker::new();
        let dlp = make_dlp_result_l3(500);
        let session_id = uuid::Uuid::new_v4();
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "192.168.1.100",
            Some("user@test.com"),
            session_id,
            "/coremail/compose",
            Some("mail.example.com"),
        );
        assert_eq!(incidents.len(), 1);
        let inc = &incidents[0];
        assert_eq!(inc.client_ip, "192.168.1.100");
        assert_eq!(inc.detected_user, Some("user@test.com".to_string()));
        assert_eq!(inc.request_url, "/coremail/compose");
        assert_eq!(inc.host, Some("mail.example.com".to_string()));
        assert_eq!(inc.method, "AGGREGATE");
        assert_eq!(
            inc.incident_type,
            DataSecurityIncidentType::JrtComplianceViolation
        );
        assert!(!inc.evidence.is_empty());
        assert!(inc.summary.contains("500"));
    }

    #[test]
    fn test_no_detected_user_falls_back_to_ip() {
        let mut tracker = JrtComplianceTracker::new();
        let dlp = make_dlp_result_l3(500);
        let incidents = tracker.record_dlp_result(
            "10.0.0.99",
            &dlp,
            "10.0.0.99",
            None,
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert_eq!(incidents.len(), 1);
        assert!(
            incidents[0].summary.contains("10.0.0.99"),
            "Summary should use IP when no detected_user"
        );
        assert!(incidents[0].detected_user.is_none());
    }

    #[test]
    fn test_c2_only_data_no_alert() {
       // C2 leveldata (employee_info) C3+ C4+
        let dlp = DlpScanResult {
            matches: vec!["employee_info".to_string()],
            details: vec![(
                "employee_info".to_string(),
                (0..1000).map(|i| format!("emp_{}", i)).collect(),
            )],
        };
        let mut tracker = JrtComplianceTracker::new();
        let incidents = tracker.record_dlp_result(
            "user@test.com",
            &dlp,
            "10.0.0.1",
            Some("user@test.com"),
            uuid::Uuid::new_v4(),
            "/test",
            None,
        );
        assert!(
            incidents.is_empty(),
            "C2 data should NOT trigger C3+ or C4+ thresholds"
        );
    }
}
