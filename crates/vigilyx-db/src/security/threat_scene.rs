//! Threat scene (bulk mailing / bounce harvest) DB operations.

use anyhow::Result;
use chrono::{Duration, Utc};
use uuid::Uuid;

use vigilyx_core::security::{
    BounceHarvestConfig, BulkMailingConfig, InternalDomainImpersonationConfig, SceneTypeStats,
    ThreatScene, ThreatSceneRule, ThreatSceneStats, ThreatSceneStatus, ThreatSceneType,
};

use crate::VigilDb;

use super::verdict::parse_threat_level;

// ─── Aggregation query result (internal) ────────────────────────────────

/// Raw row from bulk-mailing aggregation query.
#[derive(Debug)]
pub struct BulkMailingRow {
    pub sender_domain: String,
    pub email_count: i64,
    pub unique_recipients: i64,
    pub window_start: String,
    pub window_end: String,
    pub sample_subjects: Vec<String>,
    pub sample_recipients: Vec<String>,
}

/// Raw row from bounce-harvest aggregation query.
#[derive(Debug)]
pub struct BounceHarvestRow {
    /// Original sender/source domain associated with the bounce pattern.
    /// For a network NDR this comes from the NDR recipient (the original
    /// sender), not from the MAILER-DAEMON envelope sender.
    pub sender: String,
    pub target_domain: String,
    pub bounce_count: i64,
    pub unique_targets: i64,
    pub window_start: String,
    pub window_end: String,
    pub sample_subjects: Vec<String>,
    pub sample_recipients: Vec<String>,
    /// Sender domains represented by a reported appliance alert. Network
    /// rows contain the single `sender` value here.
    pub sender_domains: Vec<String>,
    /// `network_bounce` for observed NDRs or `reported_alert` for a security
    /// appliance notification. Reported alerts are never auto-blocked solely
    /// from the notification.
    pub source: String,
    pub source_session_id: Option<Uuid>,
    pub source_session_ids: Vec<Uuid>,
    pub source_spans: Vec<serde_json::Value>,
    pub detection_basis: String,
}

/// Bounded security-appliance notification candidate. The engine owns marker
/// validation and report parsing; the DB layer only returns recent candidates.
#[derive(Debug)]
pub struct BounceHarvestAlertRow {
    pub session_id: Uuid,
    pub mail_from: Option<String>,
    pub client_ip: String,
    pub started_at: String,
    pub subject: Option<String>,
    pub body_text: String,
}

/// Additive, pre-extracted NDR metadata persisted with each session. The
/// marker is deliberately separate from `candidate`: `false` means the row
/// was classified and is not an NDR, while `NULL/old rows` are handled by the
/// bounded compatibility path.
#[derive(Debug, Clone, Default)]
pub(crate) struct BounceMetadata {
    pub ready: bool,
    pub candidate: bool,
    pub reported_alert: bool,
    pub target_addresses_json: Option<String>,
}

const BOUNCE_METADATA_MAX_BYTES: usize = 131_072;

/// Classify only bounded, already parsed session fields. This keeps the hot
/// detector query off the large JSONB body while preserving the legacy marker
/// semantics for existing deployments.
pub(crate) fn extract_bounce_metadata(
    mail_from: Option<&str>,
    subject: Option<&str>,
    body: Option<&str>,
) -> BounceMetadata {
    let body = body.map(|value| truncate_utf8(value, BOUNCE_METADATA_MAX_BYTES));
    let subject_lower = subject.unwrap_or_default().to_lowercase();
    let mail_lower = mail_from.unwrap_or_default().to_lowercase();
    let body_lower = body.unwrap_or_default().to_lowercase();

    let candidate = mail_lower.contains("mailer-daemon")
        || mail_lower.contains("postmaster")
        || [
            "undeliverable",
            "delivery failed",
            "returned mail",
            "delivery status",
            "退信",
            "退回",
            "投递失败",
            "failure notice",
        ]
        .iter()
        .any(|marker| subject_lower.contains(marker))
        || ((mail_from.is_none()
            || mail_from.is_some_and(|value| value.is_empty() || value == "<>"))
            && ([
                "mail system at host",
                "delivery status notification",
                "final-recipient:",
                "action: failed",
                "status: 5",
            ]
            .iter()
            .any(|marker| body_lower.contains(marker))
                || contains_ordered(&body_lower, "could not", "be delivered")));

    let reported_alert = subject_lower.contains("ddei")
        || subject_lower.contains("mta")
        || body_lower.contains("deep discovery");
    let target_addresses_json = if candidate {
        serde_json::to_string(&extract_email_addresses(body.unwrap_or_default())).ok()
    } else {
        None
    };

    BounceMetadata {
        ready: true,
        candidate,
        reported_alert,
        target_addresses_json,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn contains_ordered(value: &str, first: &str, second: &str) -> bool {
    value
        .find(first)
        .and_then(|start| value[start + first.len()..].find(second))
        .is_some()
}

/// Raw row from external sender aggregation (used by internal domain impersonation detection).
#[derive(Debug)]
pub struct ExternalSenderRow {
    pub sender_domain: String,
    pub email_count: i64,
    pub unique_recipients: i64,
    pub window_start: String,
    pub window_end: String,
    pub sample_subjects: Vec<String>,
    pub sample_recipients: Vec<String>,
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn domain_matches(domain: &str, configured: &str) -> bool {
    let domain = normalize_domain(domain);
    let configured = normalize_domain(configured);
    !configured.is_empty() && (domain == configured || domain.ends_with(&format!(".{configured}")))
}

fn address_matches_domain(address: &str, configured: &str) -> bool {
    address
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domain_matches(domain, configured))
}

fn record_bounce_event(
    event_keys: &mut std::collections::HashSet<(String, String)>,
    target_addresses: &mut std::collections::HashSet<String>,
    bounce_count: &mut i64,
    session_id: &str,
    target_address: &str,
) {
    let target_address = target_address.to_ascii_lowercase();
    if event_keys.insert((session_id.to_string(), target_address.clone())) {
        *bounce_count += 1;
    }
    target_addresses.insert(target_address);
}

impl VigilDb {
    // ─── Scene CRUD ─────────────────────────────────────────────────

    /// Insert or update a threat scene.
    pub async fn upsert_threat_scene(&self, scene: &ThreatScene) -> Result<()> {
        let scene_type = scene.scene_type.to_string();
        let threat_level = scene.threat_level.to_string();
        let status = scene.status.to_string();
        let subjects_json = serde_json::to_value(&scene.sample_subjects)?;
        let recipients_json = serde_json::to_value(&scene.sample_recipients)?;
        let details_json = scene.details.clone();

        sqlx::query(
            r#"
            INSERT INTO security_threat_scenes
                (id, scene_type, actor, actor_type, target_domain,
                 time_window_start, time_window_end,
                 email_count, unique_recipients, bounce_count,
                 sample_subjects, sample_recipients,
                 threat_level, status, auto_blocked, ioc_id, details,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17, $18, $19)
            ON CONFLICT (id) DO UPDATE SET
                actor = EXCLUDED.actor,
                actor_type = EXCLUDED.actor_type,
                target_domain = EXCLUDED.target_domain,
                time_window_end = EXCLUDED.time_window_end,
                email_count = EXCLUDED.email_count,
                unique_recipients = EXCLUDED.unique_recipients,
                bounce_count = EXCLUDED.bounce_count,
                sample_subjects = EXCLUDED.sample_subjects,
                sample_recipients = EXCLUDED.sample_recipients,
                threat_level = EXCLUDED.threat_level,
                status = EXCLUDED.status,
                auto_blocked = EXCLUDED.auto_blocked,
                ioc_id = EXCLUDED.ioc_id,
                details = EXCLUDED.details,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(scene.id.to_string())
        .bind(&scene_type)
        .bind(&scene.actor)
        .bind(&scene.actor_type)
        .bind(&scene.target_domain)
        .bind(scene.time_window_start.to_rfc3339())
        .bind(scene.time_window_end.to_rfc3339())
        .bind(scene.email_count)
        .bind(scene.unique_recipients)
        .bind(scene.bounce_count)
        .bind(&subjects_json)
        .bind(&recipients_json)
        .bind(&threat_level)
        .bind(&status)
        .bind(scene.auto_blocked)
        .bind(&scene.ioc_id)
        .bind(&details_json)
        .bind(scene.created_at.to_rfc3339())
        .bind(scene.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List threat scenes with filters.
    pub async fn list_threat_scenes(
        &self,
        scene_type: Option<&str>,
        status: Option<&str>,
        threat_level: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ThreatScene>, i64)> {
        // Use a simple approach: fetch all rows, filter in Rust for flexibility
        let rows = sqlx::query_as::<_, ThreatSceneRow>(
            "SELECT id, scene_type, actor, actor_type, target_domain,
                    time_window_start, time_window_end,
                    email_count, unique_recipients, bounce_count,
                    sample_subjects, sample_recipients,
                    threat_level, status, auto_blocked, ioc_id, details,
                    created_at, updated_at
             FROM security_threat_scenes
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit + 200) // fetch extra for filtering
        .bind(0i64)
        .fetch_all(&self.pool)
        .await?;

        let filtered: Vec<ThreatScene> = rows
            .into_iter()
            .filter(|r| {
                if let Some(st) = scene_type
                    && r.scene_type != st
                {
                    return false;
                }
                if let Some(s) = status
                    && r.status != s
                {
                    return false;
                }
                if let Some(tl) = threat_level
                    && r.threat_level != tl
                {
                    return false;
                }
                true
            })
            .map(|r| r.into_scene())
            .collect();

        let total = filtered.len() as i64;
        let page = filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        Ok((page, total))
    }

    /// Get a single scene by ID.
    pub async fn get_threat_scene(&self, id: &str) -> Result<Option<ThreatScene>> {
        let row = sqlx::query_as::<_, ThreatSceneRow>(
            "SELECT id, scene_type, actor, actor_type, target_domain,
                    time_window_start, time_window_end,
                    email_count, unique_recipients, bounce_count,
                    sample_subjects, sample_recipients,
                    threat_level, status, auto_blocked, ioc_id, details,
                    created_at, updated_at
             FROM security_threat_scenes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_scene()))
    }

    /// Find an active/acknowledged scene for the same actor + scene_type.
    pub async fn find_active_scene(
        &self,
        scene_type: &str,
        actor: &str,
    ) -> Result<Option<ThreatScene>> {
        let row = sqlx::query_as::<_, ThreatSceneRow>(
            "SELECT id, scene_type, actor, actor_type, target_domain,
                    time_window_start, time_window_end,
                    email_count, unique_recipients, bounce_count,
                    sample_subjects, sample_recipients,
                    threat_level, status, auto_blocked, ioc_id, details,
                    created_at, updated_at
             FROM security_threat_scenes
             WHERE scene_type = $1 AND actor = $2
               AND status IN ('active', 'acknowledged', 'auto_blocked')
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(scene_type)
        .bind(actor)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_scene()))
    }

    /// Find an active scene for the same actor and target domain.
    /// Bounce-harvest scenes may share one sender across multiple target
    /// domains, so actor-only lookup would overwrite an unrelated scene.
    pub async fn find_active_bounce_scene(
        &self,
        actor: &str,
        target_domain: &str,
        source: &str,
    ) -> Result<Option<ThreatScene>> {
        let row = sqlx::query_as::<_, ThreatSceneRow>(
            "SELECT id, scene_type, actor, actor_type, target_domain,
                    time_window_start, time_window_end,
                    email_count, unique_recipients, bounce_count,
                    sample_subjects, sample_recipients,
                    threat_level, status, auto_blocked, ioc_id, details,
                    created_at, updated_at
             FROM security_threat_scenes
             WHERE scene_type = 'bounce_harvest' AND actor = $1 AND target_domain = $2
               AND details->>'source' = $3
               AND status IN ('active', 'acknowledged', 'auto_blocked')
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(actor)
        .bind(target_domain)
        .bind(source)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_scene()))
    }

    /// Find a scene produced by the pre-sender-semantics implementation so a
    /// deployment can repair the bounded active row in place. This avoids
    /// leaving a misleading duplicate scene in the UI after the detector
    /// starts reporting the corrected sender -> target relationship.
    pub async fn find_legacy_bounce_scene(
        &self,
        source: &str,
        sender: &str,
        target_domain: &str,
    ) -> Result<Option<ThreatScene>> {
        let row = sqlx::query_as::<_, ThreatSceneRow>(
            "SELECT id, scene_type, actor, actor_type, target_domain,
                    time_window_start, time_window_end,
                    email_count, unique_recipients, bounce_count,
                    sample_subjects, sample_recipients,
                    threat_level, status, auto_blocked, ioc_id, details,
                    created_at, updated_at
             FROM security_threat_scenes
             WHERE scene_type = 'bounce_harvest'
               AND details->>'source' = $1
               AND (
                   (actor = $2 AND target_domain = $2)
                   OR (actor = $3 AND target_domain = $3)
               )
               AND status IN ('active', 'acknowledged', 'auto_blocked')
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(source)
        .bind(sender)
        .bind(target_domain)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_scene()))
    }

    /// Update scene status.
    pub async fn update_scene_status(&self, id: &str, status: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE security_threat_scenes SET status = $1, updated_at = $2 WHERE id = $3",
        )
        .bind(status)
        .bind(Utc::now().to_rfc3339())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete a scene.
    pub async fn delete_threat_scene(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM security_threat_scenes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Auto-resolve stale scenes (no activity for 24h past window_end).
    pub async fn auto_resolve_stale_scenes(&self) -> Result<u64> {
        let cutoff = (Utc::now() - Duration::hours(24)).to_rfc3339();
        let result = sqlx::query(
            "UPDATE security_threat_scenes
             SET status = 'resolved', updated_at = $1
             WHERE status IN ('active', 'acknowledged')
               AND time_window_end < $2",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(&cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ─── Stats ──────────────────────────────────────────────────────

    pub async fn threat_scene_stats(&self) -> Result<ThreatSceneStats> {
        let cutoff_24h = (Utc::now() - Duration::hours(24)).to_rfc3339();

        let rows = sqlx::query_as::<_, (String, String, i64)>(
            "SELECT scene_type, status, COUNT(*)::BIGINT as cnt
             FROM security_threat_scenes
             GROUP BY scene_type, status",
        )
        .fetch_all(&self.pool)
        .await?;

        let rows_24h = sqlx::query_as::<_, (String, i64)>(
            "SELECT scene_type, COUNT(*)::BIGINT as cnt
             FROM security_threat_scenes
             WHERE created_at > $1
             GROUP BY scene_type",
        )
        .bind(&cutoff_24h)
        .fetch_all(&self.pool)
        .await?;

        let mut bulk = SceneTypeStats::default();
        let mut bounce = SceneTypeStats::default();
        let mut impersonation = SceneTypeStats::default();

        for (scene_type, status, cnt) in &rows {
            let target = match scene_type.as_str() {
                "bulk_mailing" => &mut bulk,
                "bounce_harvest" => &mut bounce,
                "internal_domain_impersonation" => &mut impersonation,
                _ => continue,
            };
            match status.as_str() {
                "active" => target.active = *cnt,
                "acknowledged" => target.acknowledged = *cnt,
                "auto_blocked" => target.auto_blocked = *cnt,
                "resolved" => target.resolved = *cnt,
                _ => {}
            }
        }
        for (scene_type, cnt) in &rows_24h {
            match scene_type.as_str() {
                "bulk_mailing" => bulk.total_24h = *cnt,
                "bounce_harvest" => bounce.total_24h = *cnt,
                "internal_domain_impersonation" => impersonation.total_24h = *cnt,
                _ => {}
            }
        }

        Ok(ThreatSceneStats {
            bulk_mailing: bulk,
            bounce_harvest: bounce,
            internal_domain_impersonation: impersonation,
        })
    }

    // ─── Scene Rules ────────────────────────────────────────────────

    pub async fn get_scene_rules(&self) -> Result<Vec<ThreatSceneRule>> {
        let rows = sqlx::query_as::<_, SceneRuleRow>(
            "SELECT scene_type, enabled, config, updated_at FROM security_scene_rules",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_rule()).collect())
    }

    pub async fn upsert_scene_rule(&self, rule: &ThreatSceneRule) -> Result<()> {
        let scene_type = rule.scene_type.to_string();
        sqlx::query(
            "INSERT INTO security_scene_rules (scene_type, enabled, config, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (scene_type) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                config = EXCLUDED.config,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(&scene_type)
        .bind(rule.enabled)
        .bind(&rule.config)
        .bind(rule.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ─── Aggregation queries (called by engine scene detector) ──────

    /// Aggregate: find external domains bulk-mailing to internal recipients in time window.
    pub async fn detect_bulk_mailing(
        &self,
        internal_domains: &[String],
        config: &BulkMailingConfig,
    ) -> Result<Vec<BulkMailingRow>> {
        let internal_domains: Vec<String> = internal_domains
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect();
        if internal_domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = (Utc::now() - Duration::hours(config.time_window_hours)).to_rfc3339();

        // Exclude list: internal sender domains + user-configured excludes
        let mut exclude_list: Vec<String> = internal_domains.clone();
        exclude_list.extend(
            config
                .exclude_domains
                .iter()
                .map(|domain| normalize_domain(domain))
                .filter(|domain| !domain.is_empty()),
        );

        // Fetch candidate sessions (sender_domain NOT internal, after cutoff)
        // then aggregate in Rust (avoiding complex CTE with jsonb_array_elements)
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            "SELECT id::text, sender_domain, mail_from, rcpt_to, started_at, subject
             FROM sessions
             WHERE started_at > $1
               AND protocol = 'Smtp'
               AND status = 'Completed'
               AND sender_domain IS NOT NULL
             ORDER BY started_at DESC",
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        // Aggregate in Rust
        use std::collections::{HashMap, HashSet};
        struct Agg {
            sessions: HashSet<String>,
            internal_recipients: HashSet<String>,
            subjects: HashSet<String>,
            window_start: String,
            window_end: String,
        }

        let mut map: HashMap<String, Agg> = HashMap::new();

        for (session_id, sender_domain, _mail_from, rcpt_to_json, started_at, subject) in &rows {
            let sd_lower = normalize_domain(sender_domain);

            // Skip internal senders
            if config.exclude_internal_senders
                && exclude_list
                    .iter()
                    .any(|domain| domain_matches(&sd_lower, domain))
            {
                continue;
            }

            // Parse rcpt_to JSON array
            let recipients: Vec<String> = rcpt_to_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            // Filter to internal recipients only
            let internal_recips: Vec<String> = recipients
                .into_iter()
                .filter(|r| {
                    internal_domains
                        .iter()
                        .any(|domain| address_matches_domain(r, domain))
                })
                .collect();

            if internal_recips.is_empty() {
                continue;
            }

            let agg = map.entry(sd_lower).or_insert_with(|| Agg {
                sessions: HashSet::new(),
                internal_recipients: HashSet::new(),
                subjects: HashSet::new(),
                window_start: started_at.clone(),
                window_end: started_at.clone(),
            });

            agg.sessions.insert(session_id.clone());
            for r in internal_recips {
                agg.internal_recipients.insert(r.to_lowercase());
            }
            if let Some(subj) = subject
                && !subj.is_empty()
                && agg.subjects.len() < 5
            {
                agg.subjects.insert(subj.clone());
            }
            if started_at < &agg.window_start {
                agg.window_start = started_at.clone();
            }
            if started_at > &agg.window_end {
                agg.window_end = started_at.clone();
            }
        }

        // Filter by thresholds
        let results: Vec<BulkMailingRow> = map
            .into_iter()
            .filter(|(_, agg)| {
                agg.internal_recipients.len() as i64 >= config.min_unique_internal_recipients
                    && agg.sessions.len() as i64 >= config.min_emails
            })
            .map(|(domain, agg)| {
                let unique_count = agg.internal_recipients.len() as i64;
                let sample_recips: Vec<String> =
                    agg.internal_recipients.into_iter().take(10).collect();
                BulkMailingRow {
                    sender_domain: domain,
                    email_count: agg.sessions.len() as i64,
                    unique_recipients: unique_count,
                    window_start: agg.window_start,
                    window_end: agg.window_end,
                    sample_subjects: agg.subjects.into_iter().collect(),
                    sample_recipients: sample_recips,
                }
            })
            .collect();

        Ok(results)
    }

    /// Aggregate: find bounce/NDR patterns targeting internal domains.
    pub async fn detect_bounce_harvest(
        &self,
        internal_domains: &[String],
        config: &BounceHarvestConfig,
    ) -> Result<Vec<BounceHarvestRow>> {
        if internal_domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = (Utc::now() - Duration::hours(config.time_window_hours)).to_rfc3339();

        // Fetch bounce candidates: null/empty sender OR mailer-daemon/postmaster.
        // The original sender is in rcpt_to for an NDR; the failed internal
        // recipient is in the delivery-status body, so both are required to
        // keep sender and target semantics separate.
        let rows = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT id::text, mail_from, rcpt_to, started_at, subject,
                    CASE WHEN bounce_metadata_ready THEN bounce_target_addresses ELSE NULL END,
                    CASE WHEN NOT bounce_metadata_ready
                         THEN LEFT(COALESCE(content->>'body_text', content->>'body_html', ''), 131072)
                         ELSE NULL END
             FROM sessions
             WHERE started_at > $1
               AND LOWER(protocol) = 'smtp'
               AND LOWER(status) = 'completed'
               AND (
                   (bounce_metadata_ready AND bounce_candidate)
                   OR (NOT bounce_metadata_ready AND (
                       LOWER(mail_from) LIKE '%mailer-daemon%'
                       OR LOWER(mail_from) LIKE '%postmaster%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%undeliverable%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%delivery failed%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%returned mail%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%delivery status%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%退信%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%退回%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%投递失败%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%failure notice%'
                       OR (
                           (mail_from IS NULL OR mail_from = '' OR mail_from = '<>')
                           AND (
                               LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%mail system at host%'
                               OR LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%could not%be delivered%'
                               OR LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%delivery status notification%'
                               OR LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%final-recipient:%'
                               OR LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%action: failed%'
                               OR LOWER(COALESCE(content->>'body_text', content->>'body_html', '')) LIKE '%status: 5%'
                           )
                       )
                   ))
               )
             ORDER BY started_at DESC",
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        // Aggregate by original sender domain + failed internal target domain.
        use std::collections::{HashMap, HashSet};
        struct Agg {
            bounces: i64,
            target_addresses: HashSet<String>,
            sender_addresses: HashSet<String>,
            event_keys: HashSet<(String, String)>,
            subjects: HashSet<String>,
            window_start: String,
            window_end: String,
        }

        let mut map: HashMap<(String, String), Agg> = HashMap::new();

        for (
            session_id,
            _mail_from,
            rcpt_to_json,
            started_at,
            subject,
            target_addresses_json,
            body_text,
        ) in &rows
        {
            let original_senders: Vec<String> = rcpt_to_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let target_addresses = target_addresses_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
                .map(|addresses| filter_internal_addresses(addresses, internal_domains))
                .unwrap_or_else(|| {
                    extract_internal_addresses(
                        body_text.as_deref().unwrap_or_default(),
                        internal_domains,
                    )
                });
            if target_addresses.is_empty() {
                continue;
            }

            for sender_address in &original_senders {
                let sender_lower = sender_address.to_lowercase();
                let sender_domain = match sender_lower.rsplit_once('@') {
                    Some((_, domain)) => {
                        normalize_domain(domain.trim_matches(['<', '>', ',', ';']))
                    }
                    None => continue,
                };
                if sender_domain.is_empty() {
                    continue;
                }

                for (target_address, target_domain) in &target_addresses {
                    let key = (sender_domain.clone(), target_domain.clone());
                    let agg = map.entry(key).or_insert_with(|| Agg {
                        bounces: 0,
                        target_addresses: HashSet::new(),
                        sender_addresses: HashSet::new(),
                        event_keys: HashSet::new(),
                        subjects: HashSet::new(),
                        window_start: started_at.clone(),
                        window_end: started_at.clone(),
                    });

                    // Count one event per session and failed target address.
                    // A malformed NDR can list the same sender/target pair
                    // more than once; it must not inflate the campaign count.
                    record_bounce_event(
                        &mut agg.event_keys,
                        &mut agg.target_addresses,
                        &mut agg.bounces,
                        session_id,
                        target_address,
                    );
                    agg.sender_addresses.insert(sender_lower.clone());
                    if let Some(subj) = subject
                        && !subj.is_empty()
                        && agg.subjects.len() < 5
                    {
                        agg.subjects.insert(subj.clone());
                    }
                    if started_at < &agg.window_start {
                        agg.window_start = started_at.clone();
                    }
                    if started_at > &agg.window_end {
                        agg.window_end = started_at.clone();
                    }
                }
            }
        }

        // Filter by thresholds
        let results: Vec<BounceHarvestRow> = map
            .into_iter()
            .filter(|(_, agg)| agg.bounces >= config.min_bounces)
            .filter_map(|((sender, target_domain), agg)| {
                let association = select_bounce_association(
                    &agg.target_addresses,
                    &agg.sender_addresses,
                    config.min_unique_targets,
                )?;
                Some(BounceHarvestRow {
                    sender: sender.clone(),
                    target_domain,
                    bounce_count: agg.bounces,
                    unique_targets: association.unique_addresses,
                    window_start: agg.window_start,
                    window_end: agg.window_end,
                    sample_subjects: agg.subjects.into_iter().collect(),
                    sample_recipients: association.sample_addresses,
                    sender_domains: vec![sender],
                    source: association.source.to_string(),
                    source_session_id: None,
                    source_session_ids: Vec::new(),
                    source_spans: Vec::new(),
                    detection_basis: "volume_threshold".to_string(),
                })
            })
            .collect();

        Ok(results)
    }

    /// Return recent DDEI-like notification candidates for engine-side parsing.
    /// The subject predicate is intentionally broad enough to cover localized
    /// appliance subjects while keeping the result set bounded by the time
    /// window and SMTP completion state.
    pub async fn detect_bounce_harvest_alert_candidates(
        &self,
        cutoff: &str,
    ) -> Result<Vec<BounceHarvestAlertRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                String,
                String,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, mail_from, client_ip, started_at, subject,
                    LEFT(COALESCE(content->>'body_text', content->>'body_html', ''), 131072)
             FROM sessions
             WHERE started_at > $1
               AND LOWER(protocol) = 'smtp'
               AND LOWER(status) = 'completed'
               AND (
                   (bounce_metadata_ready AND bounce_reported_alert)
                   OR (NOT bounce_metadata_ready AND (
                       LOWER(COALESCE(subject, '')) LIKE '%ddei%'
                       OR LOWER(COALESCE(subject, '')) LIKE '%mta%'
                       OR LOWER(COALESCE(content->>'body_text', '')) LIKE '%deep discovery%'
                   ))
               )
             ORDER BY started_at DESC
             LIMIT 200",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(session_id, mail_from, client_ip, started_at, subject, body_text)| {
                    Uuid::parse_str(&session_id)
                        .ok()
                        .map(|session_id| BounceHarvestAlertRow {
                            session_id,
                            mail_from,
                            client_ip,
                            started_at,
                            subject,
                            body_text,
                        })
                },
            )
            .collect())
    }

    /// Bounded compatibility backfill for sessions written before the
    /// structured NDR fields existed. One batch is enough per scene cycle;
    /// subsequent cycles advance through the remaining recent rows.
    pub async fn backfill_recent_bounce_metadata(
        &self,
        lookback_hours: i64,
        limit: i64,
    ) -> Result<u64> {
        let cutoff = (Utc::now() - Duration::hours(lookback_hours.max(1))).to_rfc3339();
        let rows: Vec<(String, Option<String>, Option<String>, String)> = sqlx::query_as(
            "SELECT id, mail_from, subject,
                    LEFT(COALESCE(content->>'body_text', content->>'body_html', ''), 131072)
             FROM sessions
             WHERE started_at > $1
               AND NOT bounce_metadata_ready
               AND LOWER(protocol) = 'smtp'
               AND LOWER(status) = 'completed'
             ORDER BY started_at ASC
             LIMIT $2",
        )
        .bind(&cutoff)
        .bind(limit.clamp(1, 2_000))
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        for (id, mail_from, subject, body) in &rows {
            let metadata = extract_bounce_metadata(
                mail_from.as_deref(),
                subject.as_deref(),
                Some(body.as_str()),
            );
            sqlx::query(
                "UPDATE sessions
                 SET bounce_metadata_ready = TRUE,
                     bounce_candidate = $2,
                     bounce_reported_alert = $3,
                     bounce_target_addresses = $4
                 WHERE id = $1 AND NOT bounce_metadata_ready",
            )
            .bind(id)
            .bind(metadata.candidate)
            .bind(metadata.reported_alert)
            .bind(metadata.target_addresses_json)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    /// Aggregate: find external sender domains with stats (for internal domain impersonation detection).
    /// Returns ALL external sender domains that meet min_emails threshold.
    /// Engine-side does the similarity comparison against internal domains.
    ///
    /// Aggregation is fully pushed down to PostgreSQL — only grouped results are
    /// returned (typically <100 rows), avoiding the previous pattern of fetching
    /// all sessions (potentially 100 k+) into application memory.
    pub async fn query_external_sender_stats(
        &self,
        internal_domains: &[String],
        config: &InternalDomainImpersonationConfig,
    ) -> Result<Vec<ExternalSenderRow>> {
        if internal_domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = (Utc::now() - Duration::hours(config.time_window_hours)).to_rfc3339();

        let internal_domains: Vec<String> = internal_domains
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect();
        if internal_domains.is_empty() {
            return Ok(Vec::new());
        }

        // Build the exclude list: internal domains + user-configured excludes.
        // Passed as a single TEXT[] parameter to avoid dynamic SQL.
        let mut exclude_list: Vec<String> = internal_domains.clone();
        exclude_list.extend(
            config
                .exclude_domains
                .iter()
                .map(|domain| normalize_domain(domain))
                .filter(|domain| !domain.is_empty()),
        );

        // All aggregation happens in SQL:
        //  - CTE `base` filters sessions and excludes internal/configured domains
        //  - CTE `expanded` keeps only internal recipients and counts distinct sessions
        //  - Final SELECT groups by sender_domain, applies HAVING threshold, and
        //    collects sample subjects/recipients via array_agg slicing.
        //
        // rcpt_to is a TEXT column storing a JSON array (e.g. '["a@x.com","b@y.com"]').
        // We use rcpt_to::jsonb → jsonb_array_elements_text to unnest. Invalid
        // legacy JSON is still excluded by the query rather than becoming an
        // impersonation candidate.
        let rows = sqlx::query_as::<_, ExternalSenderAggRow>(
            r#"
            WITH base AS (
                SELECT
                    id                                                   AS session_id,
                    LOWER(sender_domain) AS sd,
                    started_at,
                    subject,
                    rcpt_to
                FROM sessions
                WHERE started_at > $1
                  AND protocol = 'Smtp'
                  AND status = 'Completed'
                  AND sender_domain IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM unnest($2::text[]) AS excluded(domain)
                      WHERE LOWER(sender_domain) = excluded.domain
                         OR LOWER(sender_domain) LIKE '%.' || excluded.domain
                  )
            ),
            expanded AS (
                SELECT
                    b.session_id,
                    b.sd,
                    b.started_at,
                    b.subject,
                    LOWER(r.addr) AS recipient
                FROM base b
                CROSS JOIN LATERAL
                    jsonb_array_elements_text(b.rcpt_to::jsonb) AS r(addr)
                WHERE split_part(LOWER(r.addr), '@', 2) = ANY($3)
                   OR EXISTS (
                       SELECT 1
                       FROM unnest($3::text[]) AS d(domain)
                       WHERE split_part(LOWER(r.addr), '@', 2) LIKE '%.' || d.domain
                   )
            )
            SELECT
                sd                                                   AS sender_domain,
                COUNT(DISTINCT session_id)::BIGINT                   AS email_count,
                COUNT(DISTINCT recipient)::BIGINT                    AS unique_recipients,
                MIN(started_at)                                      AS window_start,
                MAX(started_at)                                      AS window_end,
                (array_agg(DISTINCT subject) FILTER (WHERE subject IS NOT NULL AND subject != ''))[1:5]
                                                                     AS sample_subjects,
                (array_agg(DISTINCT recipient) FILTER (WHERE recipient IS NOT NULL))[1:10]
                                                                     AS sample_recipients
            FROM expanded
            GROUP BY sd
            HAVING COUNT(DISTINCT session_id) >= $4
            ORDER BY COUNT(DISTINCT session_id) DESC
            "#,
        )
        .bind(&cutoff)                          // $1: time window cutoff
        .bind(&exclude_list)                    // $2: TEXT[] of excluded domains
        .bind(&internal_domains)                // $3: normalized internal domains
        .bind(config.min_emails)                // $4: BIGINT min_emails threshold
        .fetch_all(&self.pool)
        .await?;

        // Map DB rows to ExternalSenderRow (field types already match).
        let results = rows
            .into_iter()
            .map(|r| ExternalSenderRow {
                sender_domain: r.sender_domain,
                email_count: r.email_count,
                unique_recipients: r.unique_recipients,
                window_start: r.window_start,
                window_end: r.window_end,
                sample_subjects: r.sample_subjects.unwrap_or_default(),
                sample_recipients: r.sample_recipients.unwrap_or_default(),
            })
            .collect();

        Ok(results)
    }

    /// Get emails related to a scene (same actor, within time window).
    pub async fn get_scene_emails(
        &self,
        scene: &ThreatScene,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>> {
        let window_start = scene.time_window_start.to_rfc3339();
        let window_end = scene.time_window_end.to_rfc3339();

        let rows = match scene.scene_type {
            ThreatSceneType::BulkMailing => {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        String,
                        Option<String>,
                        Option<String>,
                    ),
                >(
                    "SELECT s.id, s.mail_from, s.rcpt_to, s.subject, s.started_at, s.client_ip,
                            v.threat_level
                     FROM sessions s
                     LEFT JOIN security_verdicts v ON v.session_id = s.id
                     WHERE s.sender_domain = $1
                       AND s.started_at BETWEEN $2 AND $3
                       AND s.protocol = 'Smtp'
                     ORDER BY s.started_at DESC
                     LIMIT $4",
                )
                .bind(&scene.actor)
                .bind(&window_start)
                .bind(&window_end)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            ThreatSceneType::BounceHarvest if scene.details["source"] == "reported_alert" => {
                let mut session_ids: Vec<String> = scene.details["source_session_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str())
                    .filter_map(|value| Uuid::parse_str(value).ok())
                    .map(|id| id.to_string())
                    .collect();
                if let Some(id) = scene.details["source_session_id"]
                    .as_str()
                    .and_then(|value| Uuid::parse_str(value).ok())
                {
                    session_ids.push(id.to_string());
                }
                session_ids.sort();
                session_ids.dedup();
                sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        String,
                        Option<String>,
                        Option<String>,
                    ),
                >(
                    "SELECT s.id, s.mail_from, s.rcpt_to, s.subject, s.started_at, s.client_ip,
                            v.threat_level
                     FROM sessions s
                     LEFT JOIN LATERAL (
                         SELECT threat_level FROM security_verdicts
                         WHERE session_id = s.id ORDER BY created_at DESC LIMIT 1
                     ) v ON TRUE
                     WHERE s.id = ANY($1) AND LOWER(s.protocol) = 'smtp'
                     ORDER BY s.started_at DESC, s.id LIMIT $2",
                )
                .bind(session_ids)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            ThreatSceneType::BounceHarvest => {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        String,
                        Option<String>,
                        Option<String>,
                    ),
                >(
                    "SELECT s.id, s.mail_from, s.rcpt_to, s.subject, s.started_at, s.client_ip,
                            v.threat_level
                     FROM sessions s
                     LEFT JOIN security_verdicts v ON v.session_id = s.id
                     WHERE s.started_at BETWEEN $1 AND $2
                       AND s.protocol = 'Smtp'
                       AND (
                           s.mail_from IS NULL OR s.mail_from = '' OR s.mail_from = '<>'
                           OR LOWER(s.mail_from) LIKE '%mailer-daemon%'
                           OR LOWER(s.mail_from) LIKE '%postmaster%'
                       )
                     ORDER BY s.started_at DESC
                     LIMIT $3",
                )
                .bind(&window_start)
                .bind(&window_end)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            ThreatSceneType::InternalDomainImpersonation => {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<String>,
                        Option<String>,
                        String,
                        Option<String>,
                        Option<String>,
                    ),
                >(
                    "SELECT s.id, s.mail_from, s.rcpt_to, s.subject, s.started_at, s.client_ip,
                            v.threat_level
                     FROM sessions s
                     LEFT JOIN security_verdicts v ON v.session_id = s.id
                     WHERE s.sender_domain = $1
                       AND s.started_at BETWEEN $2 AND $3
                       AND s.protocol = 'Smtp'
                     ORDER BY s.started_at DESC
                     LIMIT $4",
                )
                .bind(&scene.actor)
                .bind(&window_start)
                .bind(&window_end)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        let emails: Vec<serde_json::Value> = rows
            .into_iter()
            .map(
                |(id, mail_from, rcpt_to, subject, started_at, client_ip, threat_level)| {
                    serde_json::json!({
                        "session_id": id,
                        "mail_from": mail_from,
                        "rcpt_to": rcpt_to,
                        "subject": subject,
                        "started_at": started_at,
                        "client_ip": client_ip,
                        "threat_level": threat_level,
                    })
                },
            )
            .collect();

        Ok(emails)
    }
}

struct BounceAssociation {
    source: &'static str,
    unique_addresses: i64,
    sample_addresses: Vec<String>,
}

fn select_bounce_association(
    target_addresses: &std::collections::HashSet<String>,
    sender_addresses: &std::collections::HashSet<String>,
    min_unique_addresses: i64,
) -> Option<BounceAssociation> {
    let target_count = target_addresses.len() as i64;
    if target_count >= min_unique_addresses {
        return Some(BounceAssociation {
            source: "network_bounce",
            unique_addresses: target_count,
            sample_addresses: target_addresses.iter().take(10).cloned().collect(),
        });
    }

    let sender_count = sender_addresses.len() as i64;
    (sender_count >= min_unique_addresses).then(|| BounceAssociation {
        source: "network_bounce_recipient_spray",
        unique_addresses: sender_count,
        sample_addresses: sender_addresses.iter().take(10).cloned().collect(),
    })
}

/// Extract failed internal recipient addresses from a bounded NDR body.
/// The SMTP envelope recipient is the original sender; delivery-status
/// content carries the internal address that was probed.
fn extract_email_addresses(body: &str) -> Vec<String> {
    use std::collections::HashSet;

    let mut addresses = HashSet::new();
    for token in body.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '<' | '>' | '(' | ')' | '[' | ']' | '"' | '\'' | ',' | ';'
            )
    }) {
        let token = token.trim_matches(['.', ':']);
        let Some((local, raw_domain)) = token.rsplit_once('@') else {
            continue;
        };
        let domain = raw_domain.trim_end_matches('.').to_ascii_lowercase();
        if local.is_empty() || domain.is_empty() {
            continue;
        }
        addresses.insert(format!("{}@{domain}", local.to_ascii_lowercase()));
    }

    addresses.into_iter().collect()
}

fn extract_internal_addresses(body: &str, internal_domains: &[String]) -> Vec<(String, String)> {
    filter_internal_addresses(extract_email_addresses(body), internal_domains)
}

fn filter_internal_addresses(
    addresses: Vec<String>,
    internal_domains: &[String],
) -> Vec<(String, String)> {
    addresses
        .into_iter()
        .filter_map(|address| {
            let (_, raw_domain) = address.rsplit_once('@')?;
            let domain = normalize_domain(raw_domain);
            let is_internal = internal_domains
                .iter()
                .any(|configured| domain_matches(&domain, configured));
            is_internal.then_some((address, domain))
        })
        .collect()
}

#[cfg(test)]
mod bounce_semantics_tests {
    use std::collections::HashSet;

    use uuid::Uuid;

    use super::{
        extract_bounce_metadata, extract_internal_addresses, record_bounce_event,
        select_bounce_association,
    };

    #[test]
    fn structured_ndr_metadata_separates_sender_and_target() {
        let metadata = extract_bounce_metadata(
            Some("mailer-daemon@mail.example"),
            Some("Delivery Status Notification"),
            Some("Final-Recipient: rfc822; victim@corp.example\r\nStatus: 550"),
        );
        assert!(metadata.ready);
        assert!(metadata.candidate);
        assert!(!metadata.reported_alert);
        assert_eq!(
            metadata.target_addresses_json.as_deref(),
            Some("[\"victim@corp.example\"]")
        );
    }

    #[test]
    fn appliance_notification_is_observation_not_network_bounce() {
        let metadata = extract_bounce_metadata(
            Some("alerts@security.example"),
            Some("DDEI relay warning"),
            Some("Deep Discovery Email Inspector cannot relay this message"),
        );
        assert!(metadata.ready);
        assert!(!metadata.candidate);
        assert!(metadata.reported_alert);
        assert!(metadata.target_addresses_json.is_none());
    }

    #[test]
    fn ndr_body_separates_original_sender_from_internal_target() {
        let targets = extract_internal_addresses(
            "<service@corp.example>: host 198.51.100.68 said: User not found",
            &["corp.example".to_string()],
        );
        assert_eq!(
            targets,
            vec![(
                "service@corp.example".to_string(),
                "corp.example".to_string()
            )]
        );
    }

    #[test]
    fn ndr_body_does_not_treat_external_addresses_as_internal_targets() {
        let targets = extract_internal_addresses(
            "To: recipient@sender.example; failed recipient: service@corp.example",
            &["corp.example".to_string()],
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1, "corp.example");
    }

    #[test]
    fn network_bounce_counts_distinct_failed_targets_not_sender_addresses() {
        let session_id = Uuid::new_v4();
        let mut event_keys = HashSet::new();
        let mut targets = HashSet::new();
        let mut bounce_count = 0;

        record_bounce_event(
            &mut event_keys,
            &mut targets,
            &mut bounce_count,
            &session_id.to_string(),
            "Alice@Corp.Example",
        );
        record_bounce_event(
            &mut event_keys,
            &mut targets,
            &mut bounce_count,
            &session_id.to_string(),
            "alice@corp.example",
        );
        record_bounce_event(
            &mut event_keys,
            &mut targets,
            &mut bounce_count,
            &Uuid::new_v4().to_string(),
            "bob@corp.example",
        );

        assert_eq!(bounce_count, 2);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains("alice@corp.example"));
        assert!(targets.contains("bob@corp.example"));
    }

    #[test]
    fn diversified_bounce_recipients_form_non_blocking_spray_association() {
        let targets = HashSet::from(["alias@corp.example".to_string()]);
        let senders = (0..6)
            .map(|index| format!("synthetic-{index}@provider.example"))
            .collect();

        let association = select_bounce_association(&targets, &senders, 5)
            .expect("recipient diversity should qualify the bounce spray");

        assert_eq!(association.source, "network_bounce_recipient_spray");
        assert_eq!(association.unique_addresses, 6);
    }

    #[test]
    fn low_diversity_bounces_do_not_form_an_association() {
        let targets = HashSet::from(["alias@corp.example".to_string()]);
        let senders = HashSet::from(["synthetic@provider.example".to_string()]);

        assert!(select_bounce_association(&targets, &senders, 5).is_none());
    }
}

// ─── Internal row types for sqlx ────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ThreatSceneRow {
    id: String,
    scene_type: String,
    actor: String,
    actor_type: String,
    target_domain: Option<String>,
    time_window_start: String,
    time_window_end: String,
    email_count: i32,
    unique_recipients: i32,
    bounce_count: i32,
    sample_subjects: serde_json::Value,
    sample_recipients: serde_json::Value,
    threat_level: String,
    status: String,
    auto_blocked: bool,
    ioc_id: Option<String>,
    details: serde_json::Value,
    created_at: String,
    updated_at: String,
}

impl ThreatSceneRow {
    fn into_scene(self) -> ThreatScene {
        ThreatScene {
            id: Uuid::parse_str(&self.id).unwrap_or_default(),
            scene_type: ThreatSceneType::from_str_loose(&self.scene_type)
                .unwrap_or(ThreatSceneType::BulkMailing),
            actor: self.actor,
            actor_type: self.actor_type,
            target_domain: self.target_domain,
            time_window_start: chrono::DateTime::parse_from_rfc3339(&self.time_window_start)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| Utc::now()),
            time_window_end: chrono::DateTime::parse_from_rfc3339(&self.time_window_end)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| Utc::now()),
            email_count: self.email_count,
            unique_recipients: self.unique_recipients,
            bounce_count: self.bounce_count,
            sample_subjects: serde_json::from_value(self.sample_subjects).unwrap_or_default(),
            sample_recipients: serde_json::from_value(self.sample_recipients).unwrap_or_default(),
            threat_level: parse_threat_level(&self.threat_level),
            status: ThreatSceneStatus::from_str_loose(&self.status)
                .unwrap_or(ThreatSceneStatus::Active),
            auto_blocked: self.auto_blocked,
            ioc_id: self.ioc_id,
            details: self.details,
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: chrono::DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SceneRuleRow {
    scene_type: String,
    enabled: bool,
    config: serde_json::Value,
    updated_at: String,
}

impl SceneRuleRow {
    fn into_rule(self) -> ThreatSceneRule {
        ThreatSceneRule {
            scene_type: ThreatSceneType::from_str_loose(&self.scene_type)
                .unwrap_or(ThreatSceneType::BulkMailing),
            enabled: self.enabled,
            config: self.config,
            updated_at: chrono::DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

/// Internal sqlx row for the SQL-aggregated external sender stats query.
#[derive(sqlx::FromRow)]
struct ExternalSenderAggRow {
    sender_domain: String,
    email_count: i64,
    unique_recipients: i64,
    window_start: String,
    window_end: String,
    /// PostgreSQL `array_agg(...)[1:5]` returns `NULL` when no qualifying rows exist.
    sample_subjects: Option<Vec<String>>,
    /// PostgreSQL `array_agg(...)[1:10]` returns `NULL` when no qualifying rows exist.
    sample_recipients: Option<Vec<String>>,
}
