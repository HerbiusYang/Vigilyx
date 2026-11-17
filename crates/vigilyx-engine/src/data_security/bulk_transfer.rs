//! Product bulk-transfer escalation. Single-transfer alerts are emitted independently.
//! The 50/500 defaults are operational thresholds, not regulatory allowances.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tracing::info;
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity};

use super::dlp::DlpScanResult;
use super::financial_policy::POLICY;

/// Max tracked keys (prevent unbounded memory growth).
const MAX_TRACKED_KEYS: usize = 10_000;

/// A single DLP record with timestamp and counts.
struct DlpRecord {
    /// Record timestamp.
    timestamp: DateTime<Utc>,
    /// level-3+ matches (includes level-4).
    level3_plus_count: usize,
    /// level-4+ matches only.
    level4_plus_count: usize,
}

/// Compliance tracking state for a single key.
struct ComplianceState {
    /// DLP records within the sliding window.
    records: Vec<DlpRecord>,
    /// Timestamp of last level-3+ alert.
    last_alert_l3: Option<DateTime<Utc>>,
    /// Timestamp of last level-4+ alert.
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
        let cutoff = now - chrono::Duration::seconds(POLICY.bulk_window_hours * 3600);
        self.records.retain(|r| r.timestamp > cutoff);
        if l3_count > 0 || l4_count > 0 {
            self.records.push(DlpRecord {
                timestamp: now,
                level3_plus_count: l3_count,
                level4_plus_count: l4_count,
            });
        }
    }

    /// Total level-3+ cumulative count.
    fn total_l3_plus(&self) -> usize {
        self.records.iter().map(|r| r.level3_plus_count).sum()
    }

    /// Total level-4+ cumulative count.
    fn total_l4_plus(&self) -> usize {
        self.records.iter().map(|r| r.level4_plus_count).sum()
    }

    /// Whether level-3+ alert is in cooldown period.
    fn l3_in_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.last_alert_l3
            .map(|t| (now - t).num_seconds() < (POLICY.bulk_cooldown_minutes * 60))
            .unwrap_or(false)
    }

    /// Whether level-4+ alert is in cooldown period.
    fn l4_in_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.last_alert_l4
            .map(|t| (now - t).num_seconds() < (POLICY.bulk_cooldown_minutes * 60))
            .unwrap_or(false)
    }
}

/// Product bulk-transfer escalation tracker.
pub struct BulkTransferTracker {
    /// key -> compliance tracking state (key = user email or client_ip).
    windows: HashMap<String, ComplianceState>,
    /// Cleanup counter.
    cleanup_counter: u64,
}

impl Default for BulkTransferTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkTransferTracker {
    pub fn new() -> Self {
        info!(
            "BulkTransferTracker initialized: window={}h, level-3+ threshold={}, level-4+ threshold={}, cooldown={}min",
            (POLICY.bulk_window_hours * 3600) / 3600,
            POLICY.bulk_sensitive_items,
            POLICY.bulk_high_sensitive_items,
            (POLICY.bulk_cooldown_minutes * 60) / 60,
        );
        Self {
            windows: HashMap::with_capacity(256),
            cleanup_counter: 0,
        }
    }

    /// Record one observed transfer and evaluate additional bulk escalation.
    ///
    /// `key`: tracking key (user email or client_ip)
    /// `dlp_result`: DLP scan result
    /// `client_ip`: source IP address
    /// `detected_user`: detected user identity
    /// `http_session_id`: associated HTTP session ID
    /// `uri`: request URI
    /// `host`: request host
    ///
    /// Returns 0-2 alerts (level-3+ and level-4+ are checked independently).
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
        let l3_count = dlp_result.count_items_at_level(3); // Contains level-3 And level-4
        let l4_count = dlp_result.count_items_at_level(4); // level-4

        // No sensitive data at level-3+ level, skip
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

        // Check level-4+ threshold (higher priority, checked first)
        if total_l4 >= POLICY.bulk_high_sensitive_items && !state.l4_in_cooldown(now) {
            state.last_alert_l4 = Some(now);
            let user_label = detected_user.unwrap_or(client_ip);
            let summary = format!(
                "Bulk transfer risk: {} submitted {} level-4 field matches within 24h (product threshold {}); authorization unverified",
                user_label, total_l4, POLICY.bulk_high_sensitive_items
            );
            info!(
                key = key,
                total_l4 = total_l4,
                threshold = POLICY.bulk_high_sensitive_items,
                "Level-4 bulk escalation triggered"
            );
            incidents.push(DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id,
                incident_type: DataSecurityIncidentType::BulkSensitiveTransfer,
                severity: DataSecuritySeverity::Critical,
                confidence: 0.90,
                summary,
                evidence: vec![
                    Evidence {
                        description: format!(
                            "Observed level-4 field matches: {} within 24h (product threshold: {}; not a statutory limit)",
                            total_l4, POLICY.bulk_high_sensitive_items
                        ),
                        location: Some("bulk_sensitive_level4".to_string()),
                        snippet: Some(format!(
                            "Observed high-sensitivity matches; key={}, ip={}",
                            key, client_ip
                        )),
                    },
                ],
                details: Some(serde_json::json!({"policy_version": POLICY.version, "authorization_status": "unverified", "legal_assessment": "not_determined", "counter_scope": "observed_http_transfers", "counter_durability": "process_lifetime"})),
                dlp_matches: vec!["bulk_sensitive_level4".to_string()],
                client_ip: client_ip.to_string(),
                detected_user: detected_user.map(|s| s.to_string()),
                request_url: uri.to_string(),
                host: host.map(|s| s.to_string()),
                method: "AGGREGATE".to_string(),
                created_at: now,
            });
        }

        // Check level-3+ Threshold
        if total_l3 >= POLICY.bulk_sensitive_items && !state.l3_in_cooldown(now) {
            state.last_alert_l3 = Some(now);
            let user_label = detected_user.unwrap_or(client_ip);
            let summary = format!(
                "Bulk transfer risk: {} submitted {} level-3+ field matches within 24h (product threshold {}); authorization unverified",
                user_label, total_l3, POLICY.bulk_sensitive_items
            );
            info!(
                key = key,
                total_l3 = total_l3,
                threshold = POLICY.bulk_sensitive_items,
                "Level-3+ bulk escalation triggered"
            );
            incidents.push(DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id,
                incident_type: DataSecurityIncidentType::BulkSensitiveTransfer,
                severity: DataSecuritySeverity::High,
                confidence: 0.90,
                summary,
                evidence: vec![
                    Evidence {
                        description: format!(
                            "Observed level-3+ field matches: {} within 24h (product threshold: {}; not a statutory limit)",
                            total_l3, POLICY.bulk_sensitive_items
                        ),
                        location: Some("bulk_sensitive_level3".to_string()),
                        snippet: Some(format!(
                            "Observed sensitive field matches; key={}, ip={}",
                            key, client_ip
                        )),
                    },
                ],
                details: Some(serde_json::json!({"policy_version": POLICY.version, "authorization_status": "unverified", "legal_assessment": "not_determined", "counter_scope": "observed_http_transfers", "counter_durability": "process_lifetime"})),
                dlp_matches: vec!["bulk_sensitive_level3".to_string()],
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
        let cutoff = now - chrono::Duration::seconds(POLICY.bulk_window_hours * 3600);
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
            ..Default::default()
        }
    }

    /// constructpacketContains Count CVV of DLP Result (level-4 level)
    fn make_dlp_result_l4(count: usize) -> DlpScanResult {
        let values: Vec<String> = (0..count).map(|i| format!("cvv={:03}", i)).collect();
        DlpScanResult {
            matches: vec!["cvv_code".to_string()],
            details: vec![("cvv_code".to_string(), values)],
            ..Default::default()
        }
    }

    #[test]
    fn test_below_l3_threshold_no_alert() {
        let mut tracker = BulkTransferTracker::new();
        // 499 Item level-3 data -
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
        let mut tracker = BulkTransferTracker::new();
        // 500 Item level-3 data - High Alert
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
            DataSecurityIncidentType::BulkSensitiveTransfer
        );
    }

    #[test]
    fn test_below_l4_threshold_no_alert() {
        let mut tracker = BulkTransferTracker::new();
        // 49 Item level-4 data -
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
        let mut tracker = BulkTransferTracker::new();
        // 50 Item level-4 data - Critical Alert
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
        let mut tracker = BulkTransferTracker::new();
        // 450 Item level-3 + 50 Item level-4 = 500 Item level-3+ -> level-3 And level-4 Alert
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
        // level-4 Alert (50>= 50) + level-3 Alert (500>= 500)
        assert_eq!(incidents.len(), 2);
    }

    #[test]
    fn test_accumulation_across_sessions() {
        let mut tracker = BulkTransferTracker::new();
        // 5 Time/Count,every 100 Item level-3 -> After 5 Time/Count
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
        let mut tracker = BulkTransferTracker::new();
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
        let mut tracker = BulkTransferTracker::new();
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
        let mut tracker = BulkTransferTracker::new();
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

    /// constructpacketContains level-3+level-4 dataof DLP Result
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
        DlpScanResult {
            matches,
            details,
            ..Default::default()
        }
    }

    #[test]
    fn test_l4_threshold_exact_boundary() {
        let mut tracker = BulkTransferTracker::new();
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
        assert!(incidents.is_empty(), "49 level-4 items should not alert");

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
        assert_eq!(
            incidents2.len(),
            1,
            "50th level-4 item should trigger alert"
        );
        assert_eq!(incidents2[0].severity, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_l3_threshold_exact_boundary() {
        let mut tracker = BulkTransferTracker::new();
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
        assert!(incidents.is_empty(), "499 level-3 items should not alert");

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
        assert_eq!(
            incidents2.len(),
            1,
            "500th level-3 item should trigger alert"
        );
        assert_eq!(incidents2[0].severity, DataSecuritySeverity::High);
    }

    #[test]
    fn test_mixed_c3_c4_both_thresholds() {
        let mut tracker = BulkTransferTracker::new();
        // 1Time/Count 450 level-3 + 50 level-4 = 500 level-3+ total, 50 level-4+ total
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
        assert_eq!(
            incidents.len(),
            2,
            "Should trigger both level-3+ and level-4+ alerts"
        );
        // level-4+ Critical Return (Code/Digit: Check level-4+)
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
        let mut tracker = BulkTransferTracker::new();
        // 500 Item level-4 data -> level-4 level-3+, level-3+ = 500
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
            "500 level-4 items should trigger both level-3+ and level-4+ alerts"
        );
    }

    #[test]
    fn test_only_c4_below_c3_threshold() {
        let mut tracker = BulkTransferTracker::new();
        // 50 Item level-4 -> level-4+, level-3+ total = 50 <500 -> only level-4+ Alert
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
        let mut tracker = BulkTransferTracker::new();
        // every 10 Item level-3,contiguous 50 Time/Count = 500 -> After 50 Time/Count
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
        let mut tracker = BulkTransferTracker::new();
        // 3 user SameCount
        let dlp_a = make_dlp_result_l3(500);
        let dlp_b = make_dlp_result_l3(300);
        let dlp_c = make_dlp_result_l3(500);

        let inc_a = tracker.record_dlp_result(
            "a@test.com",
            &dlp_a,
            "192.0.2.11",
            Some("a@test.com"),
            uuid::Uuid::new_v4(),
            "/",
            None,
        );
        let inc_b = tracker.record_dlp_result(
            "b@test.com",
            &dlp_b,
            "192.0.2.12",
            Some("b@test.com"),
            uuid::Uuid::new_v4(),
            "/",
            None,
        );
        let inc_c = tracker.record_dlp_result(
            "c@test.com",
            &dlp_c,
            "192.0.2.13",
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
        let mut tracker = BulkTransferTracker::new();
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
            DataSecurityIncidentType::BulkSensitiveTransfer
        );
        assert!(!inc.evidence.is_empty());
        assert!(inc.summary.contains("500"));
    }

    #[test]
    fn test_no_detected_user_falls_back_to_ip() {
        let mut tracker = BulkTransferTracker::new();
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
        // C2 leveldata (employee_info) level-3+ level-4+
        let dlp = DlpScanResult {
            matches: vec!["tax_id".to_string()],
            details: vec![(
                "tax_id".to_string(),
                (0..1000).map(|i| format!("emp_{}", i)).collect(),
            )],
            ..Default::default()
        };
        let mut tracker = BulkTransferTracker::new();
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
            "C2 data should NOT trigger level-3+ or level-4+ thresholds"
        );
    }
}
