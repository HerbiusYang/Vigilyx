//! timestampstrategyModule

//! according to Occurtimestamp Critical:
//! - Non-workingtimestamp (18:00-08:00) ofSensitiveOperations 1levelCritical
//! - Weekday ofSensitiveOperations 1levelCritical

//! Bank/ ofdata line Non-workingtimestampOccur Risk High,
//! due to Monitor,Attack possibly 1.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use vigilyx_core::DataSecuritySeverity;

/// timestamp (Contains)
const WORK_HOUR_START: u32 = 8;
/// timestampEnd (Contains)
const WORK_HOUR_END: u32 = 18;

/// timestampstrategy ConfigurationParameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePolicyConfig {
   /// Whether to enableNon-workingtimestampCritical
    #[serde(default = "default_enabled")]
    pub enabled: bool,
   /// timestamp small (0-23, Contains), Default 8
    #[serde(default = "default_work_start")]
    pub work_hour_start: u32,
   /// timestampEndsmall (0-24, Contains), Default 18
    #[serde(default = "default_work_end")]
    pub work_hour_end: u32,
   /// UTC District, Default 8 (Medium)
    #[serde(default = "default_utc_offset")]
    pub utc_offset_hours: i64,
   /// Weekday whether Non-workingtimestamp, Default true
    #[serde(default = "default_weekend")]
    pub weekend_is_off_hours: bool,
}

fn default_enabled() -> bool {
    true
}
fn default_work_start() -> u32 {
    8
}
fn default_work_end() -> u32 {
    18
}
fn default_utc_offset() -> i64 {
    8
}
fn default_weekend() -> bool {
    true
}

impl Default for TimePolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            work_hour_start: 8,
            work_hour_end: 18,
            utc_offset_hours: 8,
            weekend_is_off_hours: true,
        }
    }
}

/// Checkgiving timestampwhether timestamp

/// timestamp: Monday Friday 08:00-18:00 (UTC+8)
/// Non-workingtimestamppacket: Sunday 18:00-08:00, Saturday, Sunday
pub fn is_off_hours(dt: DateTime<Utc>, utc_offset_hours: i64) -> bool {
   // Convert timestamp
    let local = dt + chrono::Duration::hours(utc_offset_hours);
    let hour = local.hour();
    let weekday = local.weekday();

   // Weekday
    if matches!(weekday, chrono::Weekday::Sat | chrono::Weekday::Sun) {
        return true;
    }

   // Non-working Segment
    !(WORK_HOUR_START..WORK_HOUR_END).contains(&hour)
}

/// Non-workingtimestampCritical

/// Critical 1level (Info -> Low -> Medium -> High -> Critical).
/// already Critical of.
pub fn boost_severity(severity: DataSecuritySeverity) -> DataSecuritySeverity {
    match severity {
        DataSecuritySeverity::Info => DataSecuritySeverity::Low,
        DataSecuritySeverity::Low => DataSecuritySeverity::Medium,
        DataSecuritySeverity::Medium => DataSecuritySeverity::High,
        DataSecuritySeverity::High => DataSecuritySeverity::Critical,
        DataSecuritySeverity::Critical => DataSecuritySeverity::Critical,
    }
}

/// according to timestamp Critical

/// Non-workingtimestampof Auto 1levelCritical.
/// `utc_offset_hours`: District (Medium large 8)
pub fn apply_time_policy(
    severity: DataSecuritySeverity,
    event_time: DateTime<Utc>,
    utc_offset_hours: i64,
) -> DataSecuritySeverity {
    if is_off_hours(event_time, utc_offset_hours) {
        boost_severity(severity)
    } else {
        severity
    }
}

/// Use ConfigurationParameterJudgewhether Non-workingtimestamp
pub fn is_off_hours_with_config(dt: DateTime<Utc>, config: &TimePolicyConfig) -> bool {
    let local = dt + chrono::Duration::hours(config.utc_offset_hours);
    let hour = local.hour();
    let weekday = local.weekday();

   // Weekday
    if config.weekend_is_off_hours && matches!(weekday, chrono::Weekday::Sat | chrono::Weekday::Sun)
    {
        return true;
    }

   // Non-working Segment
    !(config.work_hour_start..config.work_hour_end).contains(&hour)
}

/// Use ConfigurationParameter Critical

/// FunctionClose (`enabled=false`) ConnectReturn Critical.
pub fn apply_time_policy_with_config(
    severity: DataSecuritySeverity,
    event_time: DateTime<Utc>,
    config: &TimePolicyConfig,
) -> DataSecuritySeverity {
    if !config.enabled {
        return severity;
    }
    if is_off_hours_with_config(event_time, config) {
        boost_severity(severity)
    } else {
        severity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

   /// construct UTC timestampof DateTime
    fn utc(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    #[test]
    fn test_work_hours_monday_10am_cst() {
       // Monday 10:00 CST = 02:00 UTC
        let dt = utc(2026, 3, 9, 2, 0); // 2026-03-09 is Monday
        assert!(
            !is_off_hours(dt, 8),
            "Monday 10:00 CST should be work hours"
        );
    }

    #[test]
    fn test_off_hours_monday_20pm_cst() {
       // Monday 20:00 CST = 12:00 UTC
        let dt = utc(2026, 3, 9, 12, 0);
        assert!(is_off_hours(dt, 8), "Monday 20:00 CST should be off hours");
    }

    #[test]
    fn test_off_hours_monday_6am_cst() {
       // Monday 06:00 CST = 22:00 UTC (first1Day)
        let dt = utc(2026, 3, 8, 22, 0); // Sunday 22:00 UTC = Monday 06:00 CST
        assert!(is_off_hours(dt, 8), "Monday 06:00 CST should be off hours");
    }

    #[test]
    fn test_off_hours_saturday() {
       // Saturday 14:00 CST = 06:00 UTC
        let dt = utc(2026, 3, 14, 6, 0); // 2026-03-14 is Saturday
        assert!(is_off_hours(dt, 8), "Saturday should always be off hours");
    }

    #[test]
    fn test_off_hours_sunday() {
       // Sunday 10:00 CST = 02:00 UTC
        let dt = utc(2026, 3, 15, 2, 0); // 2026-03-15 is Sunday
        assert!(is_off_hours(dt, 8), "Sunday should always be off hours");
    }

    #[test]
    fn test_work_hours_boundary_start() {
       // Monday 08:00 CST = 00:00 UTC
        let dt = utc(2026, 3, 9, 0, 0);
        assert!(
            !is_off_hours(dt, 8),
            "Monday 08:00 CST should be work hours (boundary)"
        );
    }

    #[test]
    fn test_off_hours_boundary_end() {
       // Monday 18:00 CST = 10:00 UTC
        let dt = utc(2026, 3, 9, 10, 0);
        assert!(
            is_off_hours(dt, 8),
            "Monday 18:00 CST should be off hours (boundary)"
        );
    }

    #[test]
    fn test_boost_severity_info_to_low() {
        assert_eq!(
            boost_severity(DataSecuritySeverity::Info),
            DataSecuritySeverity::Low
        );
    }

    #[test]
    fn test_boost_severity_medium_to_high() {
        assert_eq!(
            boost_severity(DataSecuritySeverity::Medium),
            DataSecuritySeverity::High
        );
    }

    #[test]
    fn test_boost_severity_critical_stays_critical() {
        assert_eq!(
            boost_severity(DataSecuritySeverity::Critical),
            DataSecuritySeverity::Critical
        );
    }

    #[test]
    fn test_apply_time_policy_off_hours_boosts() {
       // Saturday 14:00 CST -> off hours -> Medium -> High
        let dt = utc(2026, 3, 14, 6, 0);
        let result = apply_time_policy(DataSecuritySeverity::Medium, dt, 8);
        assert_eq!(result, DataSecuritySeverity::High);
    }

    #[test]
    fn test_apply_time_policy_work_hours_no_change() {
       // Monday 10:00 CST -> work hours -> Medium stays Medium
        let dt = utc(2026, 3, 9, 2, 0);
        let result = apply_time_policy(DataSecuritySeverity::Medium, dt, 8);
        assert_eq!(result, DataSecuritySeverity::Medium);
    }

   // TimePolicyConfig ConfigurationVersionTest

    #[test]
    fn test_config_disabled_no_boost() {
        let cfg = TimePolicyConfig {
            enabled: false,
            ..Default::default()
        };
       // Saturday -> boost,But disabled
        let dt = utc(2026, 3, 14, 6, 0);
        let result = apply_time_policy_with_config(DataSecuritySeverity::Medium, dt, &cfg);
        assert_eq!(result, DataSecuritySeverity::Medium);
    }

    #[test]
    fn test_config_custom_hours_work_time() {
       // 09:00-21:00, Monday 15:00 CST = 07:00 UTC -> timestamp
        let cfg = TimePolicyConfig {
            work_hour_start: 9,
            work_hour_end: 21,
            ..Default::default()
        };
        let dt = utc(2026, 3, 9, 7, 0);
        assert!(!is_off_hours_with_config(dt, &cfg));
    }

    #[test]
    fn test_config_custom_hours_off_time() {
       // 09:00-21:00, Monday 08:30 CST = 00:30 UTC -> Non-workingtimestamp
        let cfg = TimePolicyConfig {
            work_hour_start: 9,
            work_hour_end: 21,
            ..Default::default()
        };
        let dt = utc(2026, 3, 9, 0, 30);
        assert!(is_off_hours_with_config(dt, &cfg));
    }

    #[test]
    fn test_config_weekend_disabled() {
       // CloseWeekday detect,Saturday -> Non-workingtimestamp(if Segment)
        let cfg = TimePolicyConfig {
            weekend_is_off_hours: false,
            ..Default::default()
        };
       // Saturday 10:00 CST = 02:00 UTC -> 8-18
        let dt = utc(2026, 3, 14, 2, 0);
        assert!(!is_off_hours_with_config(dt, &cfg));
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = TimePolicyConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: TimePolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.work_hour_start, 8);
        assert_eq!(parsed.work_hour_end, 18);
        assert_eq!(parsed.utc_offset_hours, 8);
        assert!(parsed.enabled);
        assert!(parsed.weekend_is_off_hours);
    }

    #[test]
    fn test_config_partial_json_uses_defaults() {
        let json = r#"{"work_hour_start": 7}"#;
        let cfg: TimePolicyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.work_hour_start, 7);
        assert_eq!(cfg.work_hour_end, 18); // default
        assert!(cfg.enabled); // default
    }

    
   // Test: Critical link
    

    #[test]
    fn test_boost_severity_full_chain() {
       // VerifyComplete levellink
        assert_eq!(
            boost_severity(DataSecuritySeverity::Info),
            DataSecuritySeverity::Low
        );
        assert_eq!(
            boost_severity(DataSecuritySeverity::Low),
            DataSecuritySeverity::Medium
        );
        assert_eq!(
            boost_severity(DataSecuritySeverity::Medium),
            DataSecuritySeverity::High
        );
        assert_eq!(
            boost_severity(DataSecuritySeverity::High),
            DataSecuritySeverity::Critical
        );
        assert_eq!(
            boost_severity(DataSecuritySeverity::Critical),
            DataSecuritySeverity::Critical
        );
    }

    #[test]
    fn test_apply_policy_off_hours_low_to_medium() {
       // Non-workingtimestamp Low -> Medium
        let dt = utc(2026, 3, 14, 6, 0); // Saturday
        let result = apply_time_policy(DataSecuritySeverity::Low, dt, 8);
        assert_eq!(result, DataSecuritySeverity::Medium);
    }

    #[test]
    fn test_apply_policy_off_hours_high_to_critical() {
        let dt = utc(2026, 3, 14, 6, 0); // Saturday
        let result = apply_time_policy(DataSecuritySeverity::High, dt, 8);
        assert_eq!(result, DataSecuritySeverity::Critical);
    }

    #[test]
    fn test_apply_policy_off_hours_critical_stays() {
        let dt = utc(2026, 3, 14, 6, 0); // Saturday
        let result = apply_time_policy(DataSecuritySeverity::Critical, dt, 8);
        assert_eq!(result, DataSecuritySeverity::Critical);
    }

   // Same DistrictTest

    #[test]
    fn test_off_hours_utc_plus_9_tokyo() {
       // Beijing UTC+9,Monday 19:00 JST = 10:00 UTC -> off hours (>= 18)
        let dt = utc(2026, 3, 9, 10, 0);
        assert!(is_off_hours(dt, 9), "Tokyo 19:00 should be off hours");
    }

    #[test]
    fn test_work_hours_utc_minus_5_new_york() {
       // UTC-5,Monday 10:00 EST = 15:00 UTC -> work hours
        let dt = utc(2026, 3, 9, 15, 0);
        assert!(!is_off_hours(dt, -5), "New York 10:00 should be work hours");
    }

   // ConfigurationVersion

    #[test]
    fn test_config_midnight_shift() {
       // : 22:00-06:00 timestamp
        let cfg = TimePolicyConfig {
            work_hour_start: 22,
            work_hour_end: 24, // Note:24 0..24 range Medium
            ..Default::default()
        };
       // Monday 23:00 CST = 15:00 UTC -> hour=23, 22..24 Range
        let dt = utc(2026, 3, 9, 15, 0);
        assert!(
            !is_off_hours_with_config(dt, &cfg),
            "23:00 should be in 22-24 work range"
        );
    }

    #[test]
    fn test_config_with_policy_off_hours_boosts() {
        let cfg = TimePolicyConfig::default();
       // Saturday -> off hours -> boost
        let dt = utc(2026, 3, 14, 6, 0);
        let result = apply_time_policy_with_config(DataSecuritySeverity::Medium, dt, &cfg);
        assert_eq!(result, DataSecuritySeverity::High);
    }

    #[test]
    fn test_config_disabled_never_boosts() {
        let cfg = TimePolicyConfig {
            enabled: false,
            ..Default::default()
        };
       // immediately 3
        let dt = utc(2026, 3, 8, 19, 0); // Monday 03:00 CST
        let result = apply_time_policy_with_config(DataSecuritySeverity::Low, dt, &cfg);
        assert_eq!(
            result,
            DataSecuritySeverity::Low,
            "Disabled policy should not boost"
        );
    }

   // Friday night edge case

    #[test]
    fn test_friday_17_59_still_work_hours() {
       // Friday 17:59 CST = 09:59 UTC -> timestamp
        let dt = utc(2026, 3, 13, 9, 59); // Friday
        assert!(
            !is_off_hours(dt, 8),
            "Friday 17:59 should still be work hours"
        );
    }

    #[test]
    fn test_friday_18_00_off_hours() {
       // Friday 18:00 CST = 10:00 UTC -> Non-workingtimestampStart
        let dt = utc(2026, 3, 13, 10, 0); // Friday
        assert!(is_off_hours(dt, 8), "Friday 18:00 should be off hours");
    }
}
