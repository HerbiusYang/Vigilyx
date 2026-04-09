//! Disposition rule engine

//! Features:
//! - Execute automated disposition based on Security verdict results
//! - itemsItem evaluation: Threat level threshold, category matching, module matching
//! - Action execution: Webhook notification, log recording
//! - Email alert: Send alert emails to admin and/or original recipients via SMTP

mod email_alert;
mod webhook;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::SecurityVerdict;
use vigilyx_db::VigilDb;

use email_alert::parse_threat_level;


// Types


/// Disposition rule item condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionCondition {
   /// Minimum threat level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_threat_level: Option<String>,
   /// Must contain category (any 1 match)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
   /// Must have specified module flag anomaly
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flagged_modules: Vec<String>,
}

/// Disposition rule action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionAction {
   /// Action type: webhook, log, alert
    pub action_type: String,
   /// Webhook URL (When action_type = webhook)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
   /// Webhook request headers
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub headers: std::collections::HashMap<String, String>,
   /// Additional message template
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_template: Option<String>,
}

/// Disposition rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i64,
    pub conditions: DispositionCondition,
    pub actions: Vec<DispositionAction>,
}


// Engine


/// Disposition engine
#[derive(Clone)]
pub struct DispositionEngine {
    db: VigilDb,
    http: reqwest::Client,
}

impl DispositionEngine {
    pub fn new(db: VigilDb) -> Self {
        Self {
            db,
           // SEC: Disable redirect following to prevent SSRF via 302 to internal network (CWE-918)
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }

   /// Disposition rules + Alert
    pub async fn evaluate(&self, verdict: &SecurityVerdict, session: &EmailSession) {
       // 1. Disposition rules
        let rules = match self.db.get_active_disposition_rules().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to load disposition rules: {}", e);
                Vec::new()
            }
        };

        for rule_row in &rules {
            let conditions: DispositionCondition = match serde_json::from_str(&rule_row.conditions)
            {
                Ok(c) => c,
                Err(e) => {
                    warn!(rule = rule_row.id, "Invalid rule conditions: {}", e);
                    continue;
                }
            };
            let actions: Vec<DispositionAction> = match serde_json::from_str(&rule_row.actions) {
                Ok(a) => a,
                Err(e) => {
                    warn!(rule = rule_row.id, "Invalid rule actions: {}", e);
                    continue;
                }
            };

            if self.check_conditions(&conditions, verdict) {
                info!(
                    rule = rule_row.name,
                    session_id = %verdict.session_id,
                    "Disposition rule matched"
                );
                for action in &actions {
                    self.execute_action(action, verdict).await;
                }
            }
        }

       // 2. Email alert check
        self.check_and_send_email_alert(verdict, session).await;
    }

    fn check_conditions(&self, cond: &DispositionCondition, verdict: &SecurityVerdict) -> bool {
        check_conditions_match(cond, verdict)
    }

    async fn execute_action(&self, action: &DispositionAction, verdict: &SecurityVerdict) {
        match action.action_type.as_str() {
            "webhook" => {
                if let Some(ref url) = action.webhook_url {
                    self.send_webhook(url, &action.headers, verdict).await;
                }
            }
            "log" => {
                info!(
                    session_id = %verdict.session_id,
                    threat_level = %verdict.threat_level,
                    summary = %verdict.summary,
                    "Disposition action: log"
                );
            }
            "alert" => {
                let msg = action
                    .message_template
                    .as_deref()
                    .unwrap_or("Security alert triggered");
                info!(
                    session_id = %verdict.session_id,
                    threat_level = %verdict.threat_level,
                    message = msg,
                    "Disposition action: alert"
                );
            }
            other => {
                warn!(action_type = other, "Unknown disposition action type");
            }
        }
    }
}


// Pure condition-matching logic (extracted for testability without DB)


fn check_conditions_match(cond: &DispositionCondition, verdict: &SecurityVerdict) -> bool {
   // Minimum threat level
    if let Some(ref min_level) = cond.min_threat_level {
        let required = parse_threat_level(min_level);
        if verdict.threat_level < required {
            return false;
        }
    }

   // Check category match (any 1 is sufficient)
    if !cond.categories.is_empty() {
        let has_match = cond
            .categories
            .iter()
            .any(|c| verdict.categories.contains(c));
        if !has_match {
            return false;
        }
    }

   // Check alert module match (any 1 is sufficient)
    if !cond.flagged_modules.is_empty() {
       // From fusion_details extract actual alert module ID list
        let flagged: Vec<&str> = verdict
            .fusion_details
            .as_ref()
            .map(|fd| {
                fd.engine_details
                    .iter()
                    .filter(|e| e.bpa.b > 0.05) // belief> 0.05 = has signal
                    .flat_map(|e| e.modules.iter().map(|s| s.as_str()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let has_module_match = cond
            .flagged_modules
            .iter()
            .any(|m| flagged.contains(&m.as_str()));
        if !has_module_match {
            return false;
        }
    }

    true
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;
    use vigilyx_core::security::ThreatLevel;

   /// Build a minimal SecurityVerdict for testing.
    fn make_verdict(threat_level: ThreatLevel, categories: Vec<String>) -> SecurityVerdict {
        SecurityVerdict {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            threat_level,
            confidence: 0.85,
            categories,
            summary: "test verdict".to_string(),
            pillar_scores: HashMap::new(),
            modules_run: 10,
            modules_flagged: 3,
            total_duration_ms: 120,
            created_at: Utc::now(),
            fusion_details: None,
        }
    }

    fn make_condition(
        min_threat_level: Option<&str>,
        categories: Vec<&str>,
    ) -> DispositionCondition {
        DispositionCondition {
            min_threat_level: min_threat_level.map(|s| s.to_string()),
            categories: categories.into_iter().map(|s| s.to_string()).collect(),
            flagged_modules: Vec::new(),
        }
    }

    
   // check_conditions_match - threat level filtering
    

    #[test]
    fn test_check_conditions_matches_threat_level_at_threshold() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = make_condition(Some("high"), vec![]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Verdict at exactly the threshold level should match"
        );
    }

    #[test]
    fn test_check_conditions_matches_threat_level_above_threshold() {
        let verdict = make_verdict(ThreatLevel::Critical, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Critical verdict should match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_no_match_below_threshold() {
        let verdict = make_verdict(ThreatLevel::Safe, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Safe verdict should NOT match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_low_below_medium_threshold() {
        let verdict = make_verdict(ThreatLevel::Low, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Low verdict should NOT match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_no_min_level_always_matches() {
        let verdict = make_verdict(ThreatLevel::Safe, vec![]);
        let cond = make_condition(None, vec![]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "No min_threat_level means any threat level should match"
        );
    }

    
   // check_conditions_match - category filtering
    

    #[test]
    fn test_check_conditions_matches_categories_single() {
        let verdict = make_verdict(
            ThreatLevel::High,
            vec!["phishing".to_string(), "spoofing".to_string()],
        );
        let cond = make_condition(None, vec!["phishing"]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Verdict with 'phishing' should match condition requiring 'phishing'"
        );
    }

    #[test]
    fn test_check_conditions_matches_categories_any_of_multiple() {
        let verdict = make_verdict(ThreatLevel::High, vec!["malware".to_string()]);
        let cond = make_condition(None, vec!["phishing", "malware"]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Condition requires any-of [phishing, malware]; verdict has 'malware' — should match"
        );
    }

    #[test]
    fn test_check_conditions_no_match_categories_disjoint() {
        let verdict = make_verdict(ThreatLevel::High, vec!["spam".to_string()]);
        let cond = make_condition(None, vec!["phishing", "malware"]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Verdict categories [spam] have no overlap with required [phishing, malware]"
        );
    }

    #[test]
    fn test_check_conditions_empty_categories_always_matches() {
        let verdict = make_verdict(ThreatLevel::High, vec!["anything".to_string()]);
        let cond = make_condition(None, vec![]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Empty category list means no category filtering — should match"
        );
    }

    #[test]
    fn test_check_conditions_categories_required_but_verdict_has_none() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = make_condition(None, vec!["phishing"]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Condition requires 'phishing' but verdict has no categories — should NOT match"
        );
    }

    
   // check_conditions_match - combined threat level + categories
    

    #[test]
    fn test_check_conditions_both_level_and_categories_must_match() {
        let verdict = make_verdict(ThreatLevel::Low, vec!["phishing".to_string()]);
        let cond = make_condition(Some("high"), vec!["phishing"]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Category matches but threat level is below threshold — should NOT match"
        );
    }

    #[test]
    fn test_check_conditions_level_matches_but_categories_do_not() {
        let verdict = make_verdict(ThreatLevel::Critical, vec!["spam".to_string()]);
        let cond = make_condition(Some("medium"), vec!["phishing"]);
        assert!(
            !check_conditions_match(&cond, &verdict),
            "Threat level matches but categories do not overlap — should NOT match"
        );
    }

    #[test]
    fn test_check_conditions_both_level_and_categories_pass() {
        let verdict = make_verdict(
            ThreatLevel::Critical,
            vec!["phishing".to_string(), "spoofing".to_string()],
        );
        let cond = make_condition(Some("high"), vec!["spoofing"]);
        assert!(
            check_conditions_match(&cond, &verdict),
            "Both threat level and category conditions satisfied — should match"
        );
    }

    
   // DispositionCondition / DispositionRule serde round-trip
    

    #[test]
    fn test_disposition_condition_serde_roundtrip() {
        let cond = DispositionCondition {
            min_threat_level: Some("high".to_string()),
            categories: vec!["phishing".to_string()],
            flagged_modules: vec!["content_scan".to_string()],
        };
        let json = serde_json::to_string(&cond).expect("serialize");
        let deserialized: DispositionCondition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            deserialized.min_threat_level.as_deref(),
            Some("high"),
            "min_threat_level should survive round-trip"
        );
        assert_eq!(deserialized.categories, vec!["phishing"]);
        assert_eq!(deserialized.flagged_modules, vec!["content_scan"]);
    }

    #[test]
    fn test_disposition_condition_deserialize_empty_defaults() {
        let json = r#"{"min_threat_level": null}"#;
        let cond: DispositionCondition = serde_json::from_str(json).expect("deserialize");
        assert!(
            cond.min_threat_level.is_none(),
            "null min_threat_level should deserialize as None"
        );
        assert!(
            cond.categories.is_empty(),
            "Missing categories should default to empty vec"
        );
        assert!(
            cond.flagged_modules.is_empty(),
            "Missing flagged_modules should default to empty vec"
        );
    }

    #[test]
    fn test_disposition_rule_serde_roundtrip() {
        let rule = DispositionRule {
            id: "rule-001".to_string(),
            name: "Block phishing".to_string(),
            description: Some("Auto-block phishing emails".to_string()),
            enabled: true,
            priority: 10,
            conditions: DispositionCondition {
                min_threat_level: Some("high".to_string()),
                categories: vec!["phishing".to_string()],
                flagged_modules: vec![],
            },
            actions: vec![DispositionAction {
                action_type: "webhook".to_string(),
                webhook_url: Some("https://example.com/hook".to_string()),
                headers: HashMap::new(),
                message_template: None,
            }],
        };
        let json = serde_json::to_string(&rule).expect("serialize");
        let deserialized: DispositionRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.id, "rule-001");
        assert_eq!(deserialized.name, "Block phishing");
        assert!(deserialized.enabled);
        assert_eq!(deserialized.actions.len(), 1);
        assert_eq!(deserialized.actions[0].action_type, "webhook");
    }
}
