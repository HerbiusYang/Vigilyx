//! Stream Abnormaldetect

//! detect user/IP shorttimestamp SensitiveOperations (Upload/SendContainsSensitivedataofRequest).
//! detecthandler Same, Need/Require SessionStatus (counter),
//! due to implementation DataSecurityDetector trait, EngineLoopMedium Connect.



//! - key (user IP) 1 counter
//! - size: 10 minute (Default)
//! - Threshold:>= N Time/CountSensitive Alert
//! - Deduplicate: Same1 key Alert Period Alert

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use vigilyx_core::security::Evidence;
use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity};

/// size ()
const WINDOW_SECS: i64 = 600; // 10 minute
/// AlertofThreshold ()
const ALERT_THRESHOLD: usize = 5;
/// Alert Period () - Same1 key timestamp Alert
const ALERT_COOLDOWN_SECS: i64 = 1800; // 30 minute
/// largetracing key (preventMemory)
const MAX_TRACKED_KEYS: usize = 10_000;

/// key of Status
struct WindowState {
   /// timestamp List
    timestamps: Vec<DateTime<Utc>>,
   /// recent1Time/CountAlerttimestamp
    last_alert: Option<DateTime<Utc>>,
}

impl WindowState {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            last_alert: None,
        }
    }

   /// Add1 CleanupExpiredtimestamp
    fn record(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(WINDOW_SECS);
        self.timestamps.retain(|ts| *ts > cutoff);
        self.timestamps.push(now);
    }

    
    fn count(&self) -> usize {
        self.timestamps.len()
    }

   /// whether Period
    fn in_cooldown(&self, now: DateTime<Utc>) -> bool {
        self.last_alert
            .map(|t| (now - t).num_seconds() < ALERT_COOLDOWN_SECS)
            .unwrap_or(false)
    }
}

/// Stream Abnormaltracinghandler

/// Engine process_loop Medium, WhendetecthandlerFound1 `record_incident()`,
/// if Same1user/IP Threshold,Return VolumeAnomaly.
#[derive(Default)]
pub struct VolumeAnomalyTracker {
   /// key -> Status (key = useremail client_ip)
    windows: HashMap<String, WindowState>,
   /// Cleanupcounter
    cleanup_counter: u64,
}

impl VolumeAnomalyTracker {
    pub fn new() -> Self {
        Self {
            windows: HashMap::with_capacity(256),
            cleanup_counter: 0,
        }
    }

   /// Recording1Time/CountSensitive,Checkwhether Stream AbnormalAlert
    
   /// `key`: user (email) client_ip
   /// `client_ip`: source IP
   /// `incident_summary`: of (Used for evidence)
    
   /// Return Some(incident) table Stream Abnormal,None table Normal
    pub fn record_incident(
        &mut self,
        key: &str,
        client_ip: &str,
        detected_user: Option<&str>,
        http_session_id: uuid::Uuid,
        uri: &str,
        host: Option<&str>,
    ) -> Option<DataSecurityIncident> {
        let now = Utc::now();

       // PeriodicCleanupExpired key (Get entry first)
        self.cleanup_counter += 1;
        if self.cleanup_counter.is_multiple_of(200) || self.windows.len() > MAX_TRACKED_KEYS {
            self.cleanup(now);
        }

        let state = self
            .windows
            .entry(key.to_string())
            .or_insert_with(WindowState::new);

        state.record(now);
        let count = state.count();

       // Checkwhether Threshold Period
        if count < ALERT_THRESHOLD || state.in_cooldown(now) {
            return None;
        }

       // MarkAlerttimestamp
        state.last_alert = Some(now);

        let severity = if count >= ALERT_THRESHOLD * 3 {
            DataSecuritySeverity::Critical
        } else if count >= ALERT_THRESHOLD * 2 {
            DataSecuritySeverity::High
        } else {
            DataSecuritySeverity::Medium
        };

        let summary = format!(
            "Stream量Abnormal: {} 在 {} minute内产生 {} Time/CountSensitiveOperations",
            detected_user.unwrap_or(client_ip),
            WINDOW_SECS / 60,
            count
        );

        let evidence = vec![Evidence {
            description: format!(
                "{} minute窗口内Detected {} countAccording toSecurity事件 (Threshold: {})",
                WINDOW_SECS / 60,
                count,
                ALERT_THRESHOLD
            ),
            location: Some("volume_anomaly".to_string()),
            snippet: Some(format!("key={}, ip={}", key, client_ip)),
        }];

        Some(DataSecurityIncident {
            id: vigilyx_core::fast_uuid(),
            http_session_id,
            incident_type: DataSecurityIncidentType::VolumeAnomaly,
            severity,
            confidence: 0.75,
            summary,
            evidence,
            details: None,
            dlp_matches: vec!["volume_anomaly".to_string()],
            client_ip: client_ip.to_string(),
            detected_user: detected_user.map(|s| s.to_string()),
            request_url: uri.to_string(),
            host: host.map(|s| s.to_string()),
            method: "AGGREGATE".to_string(),
            created_at: now,
        })
    }

   /// CleanupExpired Status
    fn cleanup(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(WINDOW_SECS);
        self.windows.retain(|_, state| {
           // keep timestamp Periodof key
            state.timestamps.retain(|ts| *ts > cutoff);
            !state.timestamps.is_empty() || state.in_cooldown(now)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_anomaly_below_threshold_no_alert() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // 4 Time/Count (<5 Threshold) -> Alert
        for _ in 0..4 {
            let result = tracker.record_incident(
                "user@corp.com",
                "192.168.1.100",
                Some("user@corp.com"),
                session_id,
                "/compose/send",
                Some("mail.corp.com"),
            );
            assert!(result.is_none(), "Below threshold should not alert");
        }
    }

    #[test]
    fn test_volume_anomaly_at_threshold_alerts() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // 5 Time/Count (= Threshold) -> After 5 Time/CountAlert
        for i in 0..5 {
            let result = tracker.record_incident(
                "user@corp.com",
                "192.168.1.100",
                Some("user@corp.com"),
                session_id,
                "/compose/send",
                Some("mail.corp.com"),
            );
            if i < 4 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some(), "At threshold should alert");
                let incident = result.unwrap();
                assert_eq!(
                    incident.incident_type,
                    DataSecurityIncidentType::VolumeAnomaly
                );
                assert_eq!(incident.severity, DataSecuritySeverity::Medium);
            }
        }
    }

    #[test]
    fn test_volume_anomaly_cooldown_prevents_duplicate() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // After1Time/CountAlert (5Time/Count)
        for _ in 0..5 {
            tracker.record_incident(
                "user@corp.com",
                "192.168.1.100",
                Some("user@corp.com"),
                session_id,
                "/compose/send",
                Some("mail.corp.com"),
            );
        }

       // After 6 Time/Count Period, Alert
        let result = tracker.record_incident(
            "user@corp.com",
            "192.168.1.100",
            Some("user@corp.com"),
            session_id,
            "/compose/send",
            Some("mail.corp.com"),
        );
        assert!(result.is_none(), "Should not alert during cooldown period");
    }

    #[test]
    fn test_volume_anomaly_different_users_independent() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // user_a 4 Time/Count, user_b 4 Time/Count -> all Alert
        for _ in 0..4 {
            let r1 = tracker.record_incident(
                "user_a@corp.com",
                "192.168.1.100",
                Some("user_a@corp.com"),
                session_id,
                "/compose/send",
                None,
            );
            let r2 = tracker.record_incident(
                "user_b@corp.com",
                "192.168.1.200",
                Some("user_b@corp.com"),
                session_id,
                "/compose/send",
                None,
            );
            assert!(r1.is_none());
            assert!(r2.is_none());
        }
    }

    #[test]
    fn test_volume_anomaly_first_alert_is_medium() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // After1Time/Count (count=5) -> Medium
        let mut first_alert = None;
        for _ in 0..5 {
            let r = tracker.record_incident(
                "attacker@evil.com",
                "10.0.0.99",
                Some("attacker@evil.com"),
                session_id,
                "/file/upload",
                None,
            );
            if r.is_some() {
                first_alert = r;
            }
        }
        let incident = first_alert.expect("Should have alerted at threshold");
        assert_eq!(incident.severity, DataSecuritySeverity::Medium);
    }

    #[test]
    fn test_volume_anomaly_severity_escalation_after_cooldown() {
        let mut tracker = VolumeAnomalyTracker::new();
        let session_id = uuid::Uuid::new_v4();

       // After1Time/CountAlert (count=5)
        for _ in 0..5 {
            tracker.record_incident(
                "attacker@evil.com",
                "10.0.0.99",
                Some("attacker@evil.com"),
                session_id,
                "/file/upload",
                None,
            );
        }

       // PeriodEnd: last_alert
        if let Some(state) = tracker.windows.get_mut("attacker@evil.com") {
            state.last_alert =
                Some(Utc::now() - chrono::Duration::seconds(ALERT_COOLDOWN_SECS + 10));
           // Add 10 ItemRecording count=15 (>= 3x Threshold)
            for _ in 0..10 {
                state.record(Utc::now());
            }
        }

       // 1Time/Count record Critical (count=16, Threshold)
        let result = tracker.record_incident(
            "attacker@evil.com",
            "10.0.0.99",
            Some("attacker@evil.com"),
            session_id,
            "/file/upload",
            None,
        );
        let incident = result.expect("Should alert after cooldown expired");
        assert_eq!(incident.severity, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_volume_anomaly_cleanup_removes_stale_keys() {
        let mut tracker = VolumeAnomalyTracker::new();

       // 1Expiredof
        tracker.windows.insert(
            "stale@corp.com".to_string(),
            WindowState {
                timestamps: vec![Utc::now() - chrono::Duration::seconds(WINDOW_SECS + 100)],
                last_alert: None,
            },
        );

        tracker.cleanup(Utc::now());
        assert!(
            !tracker.windows.contains_key("stale@corp.com"),
            "Stale key should be cleaned up"
        );
    }
}
