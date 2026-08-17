//! Disposition rule engine

//! Features:
//! - Execute automated disposition based on Security verdict results
//! - itemsItem evaluation: Threat level threshold, category matching, module matching
//! - Action execution: Webhook notification, email/wechat alert, log recording

mod email_alert;
mod webhook;
mod wechat_alert;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;
use vigilyx_core::security::{AlertLevel, AlertRecord, SecurityVerdict};
use vigilyx_core::{
    is_sensitive_ip,
    models::{EmailSession, MailDirection},
};
use vigilyx_db::VigilDb;

use email_alert::parse_threat_level;

pub use wechat_alert::validate_wechat_webhook_url;

const SENSITIVE_HEADER_KEYWORDS: &[&str] = &[
    "authorization",
    "api-key",
    "api_key",
    "cookie",
    "secret",
    "token",
    "bearer",
];

// Types

/// Disposition rule item condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionCondition {
    /// Minimum threat level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_threat_level: Option<String>,
    /// Mail direction filter: inbound / outbound / internal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_direction: Option<String>,
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
    /// Action type: webhook, log, alert, email_alert, wechat_alert
    pub action_type: String,
    /// Webhook URL (when action_type = webhook / wechat_alert and using per-rule webhook)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Mentioned mobile numbers for WeChat text alerts
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentioned_mobile_list: Vec<String>,
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

/// Cooldown window per (session, rule): a release rescan and the periodic
/// catch-up rescan can evaluate the same session minutes apart; without a
/// cooldown both runs would re-fire every matched rule (duplicate SOAR email
/// / webhook / alert-row side effects).
const DISPOSITION_RULE_COOLDOWN: Duration = Duration::from_secs(300);

/// In-memory per-(session, rule) cooldown tracker for disposition actions.
#[derive(Debug, Default)]
struct DispositionCooldown {
    last_fired: HashMap<(Uuid, String), Instant>,
}

/// Hard size trigger for lazy eviction. Without eviction the map only ever
/// grew: every evaluated (session, rule) pair inserted an entry that was
/// never removed, so a broad-match rule leaked memory linearly forever.
/// When the map reaches this size, expired entries are swept on the spot.
const DISPOSITION_COOLDOWN_EVICTION_TRIGGER: usize = 10_000;

impl DispositionCooldown {
    /// Return `true` (and record the firing) when this (session, rule) pair
    /// has not fired within `window`; `false` while still cooling down.
    fn should_fire(&mut self, key: (Uuid, String), now: Instant, window: Duration) -> bool {
        // Lazy eviction: once the map grows past the trigger, drop entries
        // whose cooldown already expired. Steady-state size is then bounded
        // by the number of distinct (session, rule) firings per window.
        if self.last_fired.len() >= DISPOSITION_COOLDOWN_EVICTION_TRIGGER {
            self.last_fired
                .retain(|_, fired| now.duration_since(*fired) < window);
        }
        if let Some(last) = self.last_fired.get(&key)
            && now.duration_since(*last) < window
        {
            return false;
        }
        self.last_fired.insert(key, now);
        true
    }
}

/// Disposition engine
#[derive(Clone)]
pub struct DispositionEngine {
    db: VigilDb,
    http: reqwest::Client,
    cooldown: Arc<Mutex<DispositionCooldown>>,
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
            cooldown: Arc::new(Mutex::new(DispositionCooldown::default())),
        }
    }

    /// Evaluate disposition rules and execute matched actions.
    pub async fn evaluate(&self, verdict: &SecurityVerdict, session: &EmailSession) {
        // 1. Disposition rules
        let rules = match self.db.get_active_disposition_rules().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to load disposition rules: {}", e);
                Vec::new()
            }
        };
        let internal_domains = self.load_internal_domains().await;
        let inbound_mail_servers = load_inbound_mail_servers(&self.db).await;
        let effective_session = self
            .resolve_disposition_session(session, &inbound_mail_servers)
            .await;

        for rule_row in &rules {
            let conditions: DispositionCondition = match parse_rule_conditions(&rule_row.conditions)
            {
                Ok(c) => c,
                Err(e) => {
                    warn!(rule = rule_row.id, "Invalid rule conditions: {}", e);
                    continue;
                }
            };
            let actions: Vec<DispositionAction> = match parse_rule_actions(&rule_row.actions) {
                Ok(a) => a,
                Err(e) => {
                    warn!(rule = rule_row.id, "Invalid rule actions: {}", e);
                    continue;
                }
            };
            let mut actions = actions;
            decrypt_disposition_action_secrets(&mut actions);

            if self.check_conditions(
                &conditions,
                verdict,
                &effective_session,
                &internal_domains,
                &inbound_mail_servers,
            ) {
                // Idempotency: the same session can be evaluated more than
                // once (release rescan racing the periodic catch-up rescan).
                // Suppress re-firing a rule for a session inside the cooldown
                // window so SOAR emails/webhooks/alerts are not duplicated.
                let cooldown_key = (verdict.session_id, rule_row.id.clone());
                let allowed = self
                    .cooldown
                    .lock()
                    .expect("disposition cooldown lock poisoned")
                    .should_fire(cooldown_key, Instant::now(), DISPOSITION_RULE_COOLDOWN);
                if !allowed {
                    debug!(
                        rule = rule_row.name,
                        session_id = %verdict.session_id,
                        "Disposition rule suppressed by per-session cooldown"
                    );
                    continue;
                }
                info!(
                    rule = rule_row.name,
                    session_id = %verdict.session_id,
                    "Disposition rule matched"
                );
                for action in &actions {
                    self.execute_action(
                        action,
                        verdict,
                        &effective_session,
                        &internal_domains,
                        &inbound_mail_servers,
                    )
                    .await;
                }
            }
        }
    }

    pub(super) async fn load_internal_domains(&self) -> HashSet<String> {
        match self.db.get_internal_domains().await {
            Ok(Some(json)) => match serde_json::from_str::<Vec<String>>(&json) {
                Ok(domains) => domains
                    .into_iter()
                    .map(|domain| domain.trim().to_ascii_lowercase())
                    .filter(|domain| !domain.is_empty())
                    .collect(),
                Err(_) => HashSet::new(),
            },
            _ => HashSet::new(),
        }
    }

    async fn resolve_disposition_session(
        &self,
        session: &EmailSession,
        inbound_mail_servers: &HashSet<String>,
    ) -> EmailSession {
        if inbound_mail_servers.is_empty() {
            return session.clone();
        }

        let resolved = match self.trace_terminal_delivery_hop(session).await {
            Ok(resolved) => resolved,
            Err(err) => {
                warn!(
                    session_id = %session.id,
                    "Failed to resolve downstream delivery hop: {}", err
                );
                return session.clone();
            }
        };

        if resolved.server_ip != session.server_ip
            && inbound_mail_servers.contains(&resolved.server_ip)
        {
            resolved
        } else {
            session.clone()
        }
    }

    async fn trace_terminal_delivery_hop(
        &self,
        session: &EmailSession,
    ) -> Result<EmailSession, String> {
        const LOOKAHEAD_SECONDS: i64 = 180;

        let mut merged = session.clone();
        let mut cursor = session.clone();
        let mut visited: HashSet<Uuid> = HashSet::from([session.id]);

        loop {
            let candidates = self
                .db
                .find_downstream_sessions_by_envelope(&cursor, cursor.id, LOOKAHEAD_SECONDS)
                .await
                .map_err(|err| err.to_string())?;

            let Some(next_hop) = candidates
                .into_iter()
                .find(|candidate| !visited.contains(&candidate.id))
            else {
                break;
            };

            visited.insert(next_hop.id);
            merged = overlay_session_for_terminal_hop(&merged, &next_hop);
            cursor = next_hop;
        }

        Ok(merged)
    }

    fn check_conditions(
        &self,
        cond: &DispositionCondition,
        verdict: &SecurityVerdict,
        session: &EmailSession,
        internal_domains: &HashSet<String>,
        inbound_mail_servers: &HashSet<String>,
    ) -> bool {
        check_conditions_match(
            cond,
            verdict,
            session,
            internal_domains,
            inbound_mail_servers,
        )
    }

    async fn execute_action(
        &self,
        action: &DispositionAction,
        verdict: &SecurityVerdict,
        session: &EmailSession,
        internal_domains: &HashSet<String>,
        inbound_mail_servers: &HashSet<String>,
    ) {
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
                self.persist_disposition_alert(verdict, "log", &verdict.summary)
                    .await;
            }
            "email" | "email_alert" => {
                self.execute_email_action(
                    action,
                    verdict,
                    session,
                    internal_domains,
                    inbound_mail_servers,
                )
                .await;
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
                self.persist_disposition_alert(verdict, "alert", msg).await;
            }
            "wechat" | "wechat_alert" => {
                self.execute_wechat_action(
                    action,
                    verdict,
                    session,
                    internal_domains,
                    inbound_mail_servers,
                )
                .await;
            }
            other => {
                warn!(action_type = other, "Unknown disposition action type");
            }
        }
    }

    /// Persist a security_alerts record for disposition log/alert actions (P2 level).
    async fn persist_disposition_alert(
        &self,
        verdict: &SecurityVerdict,
        action_type: &str,
        message: &str,
    ) {
        let record = AlertRecord {
            id: Uuid::new_v4(),
            verdict_id: verdict.id,
            session_id: verdict.session_id,
            alert_level: AlertLevel::P2,
            expected_loss: 0.0,
            return_period: 0.0,
            cvar: 0.0,
            risk_final: verdict.confidence,
            k_conflict: 0.0,
            cusum_alarm: false,
            rationale: format!("Disposition rule action '{action_type}': {message}"),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            created_at: Utc::now(),
        };
        match self.db.insert_alert(&record).await {
            Ok(true) => {}
            Ok(false) => {
                debug!(
                    session_id = %verdict.session_id,
                    "Disposition alert suppressed as duplicate within dedup window"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %verdict.session_id,
                    "Failed to store disposition alert: {}",
                    e
                );
            }
        }
    }
}

// Pure condition-matching logic (extracted for testability without DB)

fn parse_rule_conditions(raw: &str) -> Result<DispositionCondition, serde_json::Error> {
    serde_json::from_str(raw).or_else(|_| {
        let inner: String = serde_json::from_str(raw)?;
        serde_json::from_str(&inner)
    })
}

fn parse_rule_actions(raw: &str) -> Result<Vec<DispositionAction>, serde_json::Error> {
    serde_json::from_str(raw).or_else(|_| {
        let inner: String = serde_json::from_str(raw)?;
        serde_json::from_str(&inner)
    })
}

fn is_sensitive_action_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADER_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}

fn decrypt_stored_action_secret(stored: &str) -> Option<String> {
    let encoded = stored.strip_prefix("ENC:")?;
    let jwt_secret = std::env::var("API_JWT_SECRET").ok()?;

    use sha2::{Digest, Sha256};
    let key_bytes: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"vigilyx-config-encryption-v1");
        hasher.update(jwt_secret.as_bytes());
        hasher.finalize().into()
    };

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if combined.len() < 13 {
        return None;
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::try_from(&combined[..12]).ok()?;
    let plaintext = cipher.decrypt(&nonce, &combined[12..]).ok()?;
    String::from_utf8(plaintext).ok()
}

fn decrypt_disposition_action_secrets(actions: &mut [DispositionAction]) {
    for action in actions {
        if let Some(webhook_url) = action.webhook_url.as_mut()
            && webhook_url.starts_with("ENC:")
        {
            match decrypt_stored_action_secret(webhook_url) {
                Some(plaintext) => *webhook_url = plaintext,
                None => {
                    warn!(action_type = %action.action_type, "Failed to decrypt disposition webhook URL");
                    webhook_url.clear();
                }
            }
        }

        for (key, value) in &mut action.headers {
            if !is_sensitive_action_header(key) || !value.starts_with("ENC:") {
                continue;
            }
            match decrypt_stored_action_secret(value) {
                Some(plaintext) => *value = plaintext,
                None => {
                    warn!(action_type = %action.action_type, header = %key, "Failed to decrypt disposition header");
                    value.clear();
                }
            }
        }
    }
}

pub(super) fn load_inbound_mail_servers_from_env() -> HashSet<String> {
    std::env::var("INBOUND_MAIL_SERVERS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

async fn load_inbound_mail_servers(db: &VigilDb) -> HashSet<String> {
    match db.get_capture_inbound_target_ips().await {
        Ok(servers) if !servers.is_empty() => servers,
        Ok(_) => load_inbound_mail_servers_from_env(),
        Err(err) => {
            warn!(
                "Failed to load inbound targets from ui_preferences: {}",
                err
            );
            load_inbound_mail_servers_from_env()
        }
    }
}

fn extract_email_domain(address: &str) -> Option<String> {
    address
        .rsplit('@')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn overlay_session_for_terminal_hop(base: &EmailSession, hop: &EmailSession) -> EmailSession {
    let mut merged = base.clone();
    merged.client_ip = hop.client_ip.clone();
    merged.client_port = hop.client_port;
    merged.server_ip = hop.server_ip.clone();
    merged.server_port = hop.server_port;
    merged.started_at = hop.started_at;
    merged.ended_at = hop.ended_at;
    merged.status = hop.status;
    merged.packet_count = hop.packet_count;
    merged.total_bytes = hop.total_bytes;

    if merged.mail_from.is_none() {
        merged.mail_from = hop.mail_from.clone();
    }
    if merged.rcpt_to.is_empty() {
        merged.rcpt_to = hop.rcpt_to.clone();
    }
    if merged.subject.as_deref().unwrap_or("").trim().is_empty() {
        merged.subject = hop.subject.clone();
    }
    if merged.message_id.as_deref().unwrap_or("").trim().is_empty() {
        merged.message_id = hop.message_id.clone();
    }
    if merged.content.headers.is_empty() && !hop.content.headers.is_empty() {
        merged.content = hop.content.clone();
    }
    if merged.email_count == 0 {
        merged.email_count = hop.email_count;
    }
    if merged.error_reason.is_none() {
        merged.error_reason = hop.error_reason.clone();
    }
    if merged.auth_info.is_none() {
        merged.auth_info = hop.auth_info.clone();
    }
    if merged.threat_level.is_none() {
        merged.threat_level = hop.threat_level.clone();
    }
    merged.source = hop.source;

    merged
}

fn extract_origin_external_ip(session: &EmailSession) -> Option<String> {
    for (name, value) in &session.content.headers {
        if !name.eq_ignore_ascii_case("received") {
            continue;
        }

        let mut remainder = value.as_str();
        while let Some(start) = remainder.find('[') {
            let bracketed = &remainder[start + 1..];
            let Some(end) = bracketed.find(']') else {
                break;
            };

            let candidate = bracketed[..end].trim();
            if let Ok(ip) = candidate.parse::<IpAddr>()
                && !is_sensitive_ip(ip)
            {
                return Some(candidate.to_string());
            }

            remainder = &bracketed[end + 1..];
        }
    }

    if let Ok(ip) = session.client_ip.parse::<IpAddr>()
        && !is_sensitive_ip(ip)
    {
        return Some(session.client_ip.clone());
    }

    None
}

fn normalize_mail_direction(value: &str) -> Option<MailDirection> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inbound" | "incoming" | "入站" => Some(MailDirection::Inbound),
        "outbound" | "outgoing" | "出站" => Some(MailDirection::Outbound),
        "internal" | "inside" | "内部" => Some(MailDirection::Internal),
        _ => None,
    }
}

pub(super) fn infer_mail_direction(
    session: &EmailSession,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> Option<MailDirection> {
    if internal_domains.is_empty() {
        return if inbound_mail_servers.is_empty() {
            None
        } else if inbound_mail_servers.contains(&session.server_ip) {
            Some(MailDirection::Inbound)
        } else {
            None
        };
    }

    let sender_domain = session
        .mail_from
        .as_deref()
        .and_then(extract_email_domain)?;
    let sender_local = internal_domains.contains(&sender_domain);

    if !sender_local {
        return if inbound_mail_servers.is_empty()
            || inbound_mail_servers.contains(&session.server_ip)
        {
            Some(MailDirection::Inbound)
        } else {
            None
        };
    }

    let rcpt_domains: Vec<String> = session
        .rcpt_to
        .iter()
        .filter_map(|address| extract_email_domain(address))
        .collect();

    if rcpt_domains.is_empty() {
        return Some(MailDirection::Internal);
    }

    if rcpt_domains
        .iter()
        .any(|domain| !internal_domains.contains(domain))
    {
        return Some(MailDirection::Outbound);
    }

    Some(MailDirection::Internal)
}

pub(super) fn infer_external_ip(
    session: &EmailSession,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> Option<String> {
    if let Some(origin_ip) = extract_origin_external_ip(session) {
        return Some(origin_ip);
    }

    match infer_mail_direction(session, internal_domains, inbound_mail_servers) {
        Some(MailDirection::Inbound) => Some(session.client_ip.clone()),
        Some(MailDirection::Outbound) => Some(session.server_ip.clone()),
        Some(MailDirection::Internal) => None,
        None => {
            if !session.client_ip.trim().is_empty() {
                Some(session.client_ip.clone())
            } else if !session.server_ip.trim().is_empty() {
                Some(session.server_ip.clone())
            } else {
                None
            }
        }
    }
}

pub(super) fn render_action_message_template(
    template: &str,
    verdict: &SecurityVerdict,
    session: &EmailSession,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> String {
    let sender = session.mail_from.as_deref().unwrap_or("(unknown)");
    let recipients = if session.rcpt_to.is_empty() {
        "(unknown)".to_string()
    } else {
        session.rcpt_to.join(", ")
    };
    let subject = session.subject.as_deref().unwrap_or("(no subject)");
    let categories = if verdict.categories.is_empty() {
        "-".to_string()
    } else {
        verdict.categories.join(", ")
    };
    let mail_direction = infer_mail_direction(session, internal_domains, inbound_mail_servers)
        .map(|direction| direction.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let external_ip = infer_external_ip(session, internal_domains, inbound_mail_servers)
        .unwrap_or_else(|| "-".to_string());
    let timestamp = verdict
        .created_at
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    let replacements = [
        ("{{threat_level}}", verdict.threat_level.to_string()),
        (
            "{{confidence_pct}}",
            ((verdict.confidence * 100.0) as u32).to_string(),
        ),
        ("{{summary}}", verdict.summary.clone()),
        ("{{categories}}", categories),
        ("{{mail_from}}", sender.to_string()),
        ("{{rcpt_to}}", recipients),
        ("{{subject}}", subject.to_string()),
        ("{{session_id}}", verdict.session_id.to_string()),
        ("{{client_ip}}", session.client_ip.clone()),
        ("{{server_ip}}", session.server_ip.clone()),
        ("{{external_ip}}", external_ip),
        ("{{mail_direction}}", mail_direction),
        ("{{modules_run}}", verdict.modules_run.to_string()),
        ("{{modules_flagged}}", verdict.modules_flagged.to_string()),
        ("{{timestamp}}", timestamp),
    ];

    let mut rendered = template.to_string();
    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, &value);
    }
    rendered
}

fn check_conditions_match(
    cond: &DispositionCondition,
    verdict: &SecurityVerdict,
    session: &EmailSession,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> bool {
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

    // Mail direction filter
    if let Some(ref required_direction) = cond.mail_direction {
        let Some(required_direction) = normalize_mail_direction(required_direction) else {
            return false;
        };
        let Some(actual_direction) =
            infer_mail_direction(session, internal_domains, inbound_mail_servers)
        else {
            return false;
        };

        if actual_direction != required_direction {
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
    use std::time::{Duration, Instant};
    use uuid::Uuid;
    use vigilyx_core::models::Protocol;
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
            mail_direction: None,
            categories: categories.into_iter().map(|s| s.to_string()).collect(),
            flagged_modules: Vec::new(),
        }
    }

    fn make_session(mail_from: Option<&str>, rcpt_to: Vec<&str>, server_ip: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "198.51.100.10".to_string(),
            2525,
            server_ip.to_string(),
            25,
        );
        session.mail_from = mail_from.map(|value| value.to_string());
        session.rcpt_to = rcpt_to.into_iter().map(|value| value.to_string()).collect();
        session.subject = Some("Quarterly report".to_string());
        session
    }

    fn rule_matches(cond: &DispositionCondition, verdict: &SecurityVerdict) -> bool {
        check_conditions_match(
            cond,
            verdict,
            &make_session(
                Some("sender@example.net"),
                vec!["user@example.com"],
                "10.0.0.20",
            ),
            &HashSet::new(),
            &HashSet::new(),
        )
    }

    // check_conditions_match - threat level filtering

    #[test]
    fn test_check_conditions_matches_threat_level_at_threshold() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = make_condition(Some("high"), vec![]);
        assert!(
            rule_matches(&cond, &verdict),
            "Verdict at exactly the threshold level should match"
        );
    }

    #[test]
    fn test_check_conditions_matches_threat_level_above_threshold() {
        let verdict = make_verdict(ThreatLevel::Critical, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            rule_matches(&cond, &verdict),
            "Critical verdict should match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_no_match_below_threshold() {
        let verdict = make_verdict(ThreatLevel::Safe, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            !rule_matches(&cond, &verdict),
            "Safe verdict should NOT match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_low_below_medium_threshold() {
        let verdict = make_verdict(ThreatLevel::Low, vec![]);
        let cond = make_condition(Some("medium"), vec![]);
        assert!(
            !rule_matches(&cond, &verdict),
            "Low verdict should NOT match a Medium threshold"
        );
    }

    #[test]
    fn test_check_conditions_no_min_level_always_matches() {
        let verdict = make_verdict(ThreatLevel::Safe, vec![]);
        let cond = make_condition(None, vec![]);
        assert!(
            rule_matches(&cond, &verdict),
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
            rule_matches(&cond, &verdict),
            "Verdict with 'phishing' should match condition requiring 'phishing'"
        );
    }

    #[test]
    fn test_check_conditions_matches_categories_any_of_multiple() {
        let verdict = make_verdict(ThreatLevel::High, vec!["malware".to_string()]);
        let cond = make_condition(None, vec!["phishing", "malware"]);
        assert!(
            rule_matches(&cond, &verdict),
            "Condition requires any-of [phishing, malware]; verdict has 'malware' — should match"
        );
    }

    #[test]
    fn test_check_conditions_no_match_categories_disjoint() {
        let verdict = make_verdict(ThreatLevel::High, vec!["spam".to_string()]);
        let cond = make_condition(None, vec!["phishing", "malware"]);
        assert!(
            !rule_matches(&cond, &verdict),
            "Verdict categories [spam] have no overlap with required [phishing, malware]"
        );
    }

    #[test]
    fn test_check_conditions_empty_categories_always_matches() {
        let verdict = make_verdict(ThreatLevel::High, vec!["anything".to_string()]);
        let cond = make_condition(None, vec![]);
        assert!(
            rule_matches(&cond, &verdict),
            "Empty category list means no category filtering — should match"
        );
    }

    #[test]
    fn test_check_conditions_categories_required_but_verdict_has_none() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = make_condition(None, vec!["phishing"]);
        assert!(
            !rule_matches(&cond, &verdict),
            "Condition requires 'phishing' but verdict has no categories — should NOT match"
        );
    }

    // check_conditions_match - combined threat level + categories

    #[test]
    fn test_check_conditions_both_level_and_categories_must_match() {
        let verdict = make_verdict(ThreatLevel::Low, vec!["phishing".to_string()]);
        let cond = make_condition(Some("high"), vec!["phishing"]);
        assert!(
            !rule_matches(&cond, &verdict),
            "Category matches but threat level is below threshold — should NOT match"
        );
    }

    #[test]
    fn test_check_conditions_level_matches_but_categories_do_not() {
        let verdict = make_verdict(ThreatLevel::Critical, vec!["spam".to_string()]);
        let cond = make_condition(Some("medium"), vec!["phishing"]);
        assert!(
            !rule_matches(&cond, &verdict),
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
            rule_matches(&cond, &verdict),
            "Both threat level and category conditions satisfied — should match"
        );
    }

    #[test]
    fn test_check_conditions_matches_inbound_direction_from_sender_domain() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = DispositionCondition {
            min_threat_level: None,
            mail_direction: Some("inbound".to_string()),
            categories: Vec::new(),
            flagged_modules: Vec::new(),
        };
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let session = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.0.0.20",
        );
        assert!(check_conditions_match(
            &cond,
            &verdict,
            &session,
            &internal_domains,
            &HashSet::new(),
        ));
    }

    #[test]
    fn test_check_conditions_matches_outbound_direction_from_recipient_domain() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = DispositionCondition {
            min_threat_level: None,
            mail_direction: Some("outbound".to_string()),
            categories: Vec::new(),
            flagged_modules: Vec::new(),
        };
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let session = make_session(
            Some("alice@corp.example"),
            vec!["bob@external.example"],
            "10.0.0.20",
        );
        assert!(check_conditions_match(
            &cond,
            &verdict,
            &session,
            &internal_domains,
            &HashSet::new(),
        ));
    }

    #[test]
    fn test_check_conditions_matches_internal_direction() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = DispositionCondition {
            min_threat_level: None,
            mail_direction: Some("internal".to_string()),
            categories: Vec::new(),
            flagged_modules: Vec::new(),
        };
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let session = make_session(
            Some("alice@corp.example"),
            vec!["bob@corp.example"],
            "10.0.0.20",
        );
        assert!(check_conditions_match(
            &cond,
            &verdict,
            &session,
            &internal_domains,
            &HashSet::new(),
        ));
    }

    #[test]
    fn test_check_conditions_accepts_chinese_inbound_direction_alias() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = DispositionCondition {
            min_threat_level: None,
            mail_direction: Some("入站".to_string()),
            categories: Vec::new(),
            flagged_modules: Vec::new(),
        };
        let inbound_servers = HashSet::from([String::from("10.0.0.20")]);
        let session = make_session(
            Some("ceo@corp.example"),
            vec!["ops@corp.example"],
            "10.0.0.20",
        );
        assert!(check_conditions_match(
            &cond,
            &verdict,
            &session,
            &HashSet::new(),
            &inbound_servers,
        ));
    }

    #[test]
    fn test_check_conditions_rejects_non_terminal_inbound_hop_when_filter_is_configured() {
        let verdict = make_verdict(ThreatLevel::High, vec![]);
        let cond = DispositionCondition {
            min_threat_level: None,
            mail_direction: Some("inbound".to_string()),
            categories: Vec::new(),
            flagged_modules: Vec::new(),
        };
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let inbound_servers = HashSet::from([String::from("10.7.126.68")]);
        let session = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.1.246.41",
        );

        assert!(!check_conditions_match(
            &cond,
            &verdict,
            &session,
            &internal_domains,
            &inbound_servers,
        ));
    }

    #[test]
    fn test_infer_external_ip_prefers_client_ip_for_inbound() {
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let session = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.0.0.20",
        );
        assert_eq!(
            infer_external_ip(&session, &internal_domains, &HashSet::new()),
            Some("198.51.100.10".to_string())
        );
    }

    #[test]
    fn test_infer_external_ip_prefers_public_received_header_ip_for_last_hop() {
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let mut session = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.7.126.68",
        );
        session.client_ip = "10.1.246.41".to_string();
        session.content.add_header(
            "Received".to_string(),
            "from mx.evil.example (mx.evil.example [124.196.27.22]) by relay.internal".to_string(),
        );

        assert_eq!(
            infer_external_ip(&session, &internal_domains, &HashSet::new()),
            Some("124.196.27.22".to_string())
        );
    }

    #[test]
    fn test_render_action_message_template_expands_ip_placeholders() {
        let verdict = make_verdict(ThreatLevel::High, vec!["phishing".to_string()]);
        let session = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.0.0.20",
        );
        let internal_domains = HashSet::from([String::from("corp.example")]);
        let rendered = render_action_message_template(
            "方向={{mail_direction}} 外网IP={{external_ip}} 发件人={{mail_from}}",
            &verdict,
            &session,
            &internal_domains,
            &HashSet::new(),
        );
        assert!(rendered.contains("方向=inbound"));
        assert!(rendered.contains("外网IP=198.51.100.10"));
        assert!(rendered.contains("发件人=attacker@evil.example"));
    }

    #[test]
    fn test_overlay_session_for_terminal_hop_keeps_message_content_and_uses_last_hop_network() {
        let mut base = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.1.246.41",
        );
        base.content.add_header(
            "Received".to_string(),
            "from mail.evil.example (unknown [192.252.179.28]) by relay.internal".to_string(),
        );
        base.message_id = Some("<msg@example>".to_string());

        let mut terminal = make_session(
            Some("attacker@evil.example"),
            vec!["user@corp.example"],
            "10.7.126.68",
        );
        terminal.client_ip = "10.1.246.41".to_string();
        terminal.subject = None;
        terminal.message_id = None;
        terminal.content.headers.clear();

        let merged = overlay_session_for_terminal_hop(&base, &terminal);
        let inbound_servers = HashSet::from([String::from("10.7.126.68")]);
        let internal_domains = HashSet::from([String::from("corp.example")]);

        assert_eq!(merged.client_ip, "10.1.246.41");
        assert_eq!(merged.server_ip, "10.7.126.68");
        assert_eq!(merged.message_id.as_deref(), Some("<msg@example>"));
        assert_eq!(merged.subject.as_deref(), Some("Quarterly report"));
        assert_eq!(
            infer_mail_direction(&merged, &internal_domains, &inbound_servers),
            Some(MailDirection::Inbound)
        );
        assert_eq!(
            infer_external_ip(&merged, &internal_domains, &inbound_servers),
            Some("192.252.179.28".to_string())
        );
    }

    // DispositionCondition / DispositionRule serde round-trip

    #[test]
    fn test_disposition_condition_serde_roundtrip() {
        let cond = DispositionCondition {
            min_threat_level: Some("high".to_string()),
            mail_direction: Some("inbound".to_string()),
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
        assert_eq!(deserialized.mail_direction.as_deref(), Some("inbound"));
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
            cond.mail_direction.is_none(),
            "Missing mail_direction should deserialize as None"
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
                mail_direction: Some("inbound".to_string()),
                categories: vec!["phishing".to_string()],
                flagged_modules: vec![],
            },
            actions: vec![DispositionAction {
                action_type: "webhook".to_string(),
                webhook_url: Some("https://example.com/hook".to_string()),
                mentioned_mobile_list: Vec::new(),
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

    #[test]
    fn test_parse_rule_conditions_accepts_double_encoded_json() {
        let raw = r#""{\"min_threat_level\":\"high\",\"categories\":[\"phishing\"]}""#;
        let parsed = parse_rule_conditions(raw).expect("double-encoded conditions should parse");
        assert_eq!(parsed.min_threat_level.as_deref(), Some("high"));
        assert_eq!(parsed.categories, vec!["phishing"]);
    }

    #[test]
    fn test_parse_rule_actions_accepts_double_encoded_json() {
        let raw = r#""[{\"action_type\":\"wechat_alert\"}]""#;
        let parsed = parse_rule_actions(raw).expect("double-encoded actions should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].action_type, "wechat_alert");
    }

    // ─── Round-4 PoC: per-(session, rule) disposition cooldown ────────────

    #[test]
    fn test_disposition_cooldown_blocks_second_fire_within_window() {
        // Attack/bug (round 4): a release rescan and the periodic catch-up
        // rescan both run post-verdict for the same session minutes apart.
        // Before the fix every matched rule fired twice (duplicate SOAR email).
        let mut cooldown = DispositionCooldown::default();
        let session_id = Uuid::new_v4();
        let key = (session_id, "rule-critical-alert".to_string());
        let now = Instant::now();

        assert!(
            cooldown.should_fire(key.clone(), now, DISPOSITION_RULE_COOLDOWN),
            "first evaluation must fire"
        );
        assert!(
            !cooldown.should_fire(
                key.clone(),
                now + Duration::from_secs(120),
                DISPOSITION_RULE_COOLDOWN,
            ),
            "rescan 2 minutes later must be suppressed"
        );
        assert!(
            cooldown.should_fire(
                key,
                now + DISPOSITION_RULE_COOLDOWN + Duration::from_secs(1),
                DISPOSITION_RULE_COOLDOWN,
            ),
            "firing after the cooldown window must be allowed again"
        );
    }

    #[test]
    fn test_disposition_cooldown_is_scoped_per_session_and_rule() {
        let mut cooldown = DispositionCooldown::default();
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();
        let now = Instant::now();

        assert!(cooldown.should_fire(
            (session_a, "rule-1".to_string()),
            now,
            DISPOSITION_RULE_COOLDOWN,
        ));
        // A different rule on the same session is independent.
        assert!(cooldown.should_fire(
            (session_a, "rule-2".to_string()),
            now,
            DISPOSITION_RULE_COOLDOWN,
        ));
        // The same rule on a different session is independent.
        assert!(cooldown.should_fire(
            (session_b, "rule-1".to_string()),
            now,
            DISPOSITION_RULE_COOLDOWN,
        ));
        // But the exact (session, rule) pair cools down.
        assert!(!cooldown.should_fire(
            (session_a, "rule-1".to_string()),
            now,
            DISPOSITION_RULE_COOLDOWN,
        ));
    }

    #[test]
    fn test_disposition_cooldown_evicts_expired_entries_lazily() {
        // PoC (round 5, D2): before the fix, `last_fired` only ever grew —
        // every (session, rule) pair inserted an entry that was never
        // removed, so a broad-match rule leaked memory linearly with traffic.
        // Now a size trigger sweeps expired entries in place.
        let mut cooldown = DispositionCooldown::default();
        let now = Instant::now();
        let stale_instant = now - DISPOSITION_RULE_COOLDOWN - Duration::from_secs(60);

        // Fill the map up to the eviction trigger with long-expired entries,
        // as a busy deployment would accumulate over time.
        for i in 0..DISPOSITION_COOLDOWN_EVICTION_TRIGGER {
            cooldown
                .last_fired
                .insert((Uuid::new_v4(), format!("rule-{}", i % 8)), stale_instant);
        }
        assert_eq!(cooldown.last_fired.len(), DISPOSITION_COOLDOWN_EVICTION_TRIGGER);

        // The next should_fire call sweeps the expired entries...
        let fresh_key = (Uuid::new_v4(), "rule-critical-alert".to_string());
        assert!(
            cooldown.should_fire(fresh_key.clone(), now, DISPOSITION_RULE_COOLDOWN),
            "a fresh (session, rule) pair must still fire"
        );

        // ...leaving only the freshly inserted entry.
        assert_eq!(
            cooldown.last_fired.len(),
            1,
            "expired cooldown entries must be evicted lazily, not kept forever"
        );

        // Entries still inside the window must survive eviction.
        let mut cooldown = DispositionCooldown::default();
        let fresh_pair = (Uuid::new_v4(), "rule-fresh".to_string());
        cooldown.last_fired.insert(fresh_pair.clone(), now);
        for i in 1..DISPOSITION_COOLDOWN_EVICTION_TRIGGER {
            cooldown
                .last_fired
                .insert((Uuid::new_v4(), format!("rule-stale-{i}")), stale_instant);
        }
        assert!(cooldown.should_fire(
            (Uuid::new_v4(), "trigger".to_string()),
            now,
            DISPOSITION_RULE_COOLDOWN
        ));
        assert!(
            cooldown.last_fired.contains_key(&fresh_pair),
            "in-window entries must survive the lazy sweep"
        );
    }
}
