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
    pub target_domain: String,
    pub bounce_count: i64,
    pub unique_targets: i64,
    pub window_start: String,
    pub window_end: String,
    pub sample_subjects: Vec<String>,
    pub sample_recipients: Vec<String>,
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
        if internal_domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = (Utc::now() - Duration::hours(config.time_window_hours)).to_rfc3339();

        // Exclude list: internal sender domains + user-configured excludes
        let mut exclude_list: Vec<String> = internal_domains.to_vec();
        exclude_list.extend(config.exclude_domains.iter().cloned());

        // Fetch candidate sessions (sender_domain NOT internal, after cutoff)
        // then aggregate in Rust (avoiding complex CTE with jsonb_array_elements)
        let rows = sqlx::query_as::<
            _,
            (
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            "SELECT sender_domain, mail_from, rcpt_to, started_at, subject
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

        for (sender_domain, _mail_from, rcpt_to_json, started_at, subject) in &rows {
            let sd_lower = sender_domain.to_lowercase();

            // Skip internal senders
            if config.exclude_internal_senders && exclude_list.iter().any(|d| d == &sd_lower) {
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
                    let r_lower = r.to_lowercase();
                    internal_domains
                        .iter()
                        .any(|d| r_lower.ends_with(&format!("@{d}")))
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

            agg.sessions.insert(started_at.clone());
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

        // Fetch bounce candidates: null/empty sender OR mailer-daemon/postmaster
        let rows = sqlx::query_as::<_, (Option<String>, Option<String>, String, Option<String>)>(
            "SELECT mail_from, rcpt_to, started_at, subject
             FROM sessions
             WHERE started_at > $1
               AND protocol = 'Smtp'
               AND status = 'Completed'
               AND (
                   mail_from IS NULL
                   OR mail_from = ''
                   OR mail_from = '<>'
                   OR LOWER(mail_from) LIKE '%mailer-daemon%'
                   OR LOWER(mail_from) LIKE '%postmaster%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%undeliverable%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%delivery failed%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%returned mail%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%delivery status%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%退信%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%退回%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%投递失败%'
                   OR LOWER(COALESCE(subject, '')) LIKE '%failure notice%'
               )
             ORDER BY started_at DESC",
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        // Aggregate by target domain
        use std::collections::{HashMap, HashSet};
        struct Agg {
            bounces: i64,
            targets: HashSet<String>,
            subjects: HashSet<String>,
            window_start: String,
            window_end: String,
        }

        let mut map: HashMap<String, Agg> = HashMap::new();

        for (_mail_from, rcpt_to_json, started_at, subject) in &rows {
            let recipients: Vec<String> = rcpt_to_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            for recip in &recipients {
                let recip_lower = recip.to_lowercase();
                // Extract domain from recipient
                let domain = match recip_lower.split('@').nth(1) {
                    Some(d) => d.to_string(),
                    None => continue,
                };

                // For directory harvest detection, we aggregate by the recipient domain
                // of the bounce (where the NDR goes). Many bounces originating from our
                // servers indicate the attacker probed internal addresses.

                let agg = map.entry(domain).or_insert_with(|| Agg {
                    bounces: 0,
                    targets: HashSet::new(),
                    subjects: HashSet::new(),
                    window_start: started_at.clone(),
                    window_end: started_at.clone(),
                });

                agg.bounces += 1;
                agg.targets.insert(recip_lower);
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

        // Filter by thresholds
        let results: Vec<BounceHarvestRow> = map
            .into_iter()
            .filter(|(_, agg)| agg.bounces >= config.min_bounces)
            .map(|(domain, agg)| {
                let targets: Vec<String> = agg.targets.into_iter().take(10).collect();
                let unique_targets = targets.len() as i64;
                BounceHarvestRow {
                    target_domain: domain,
                    bounce_count: agg.bounces,
                    unique_targets,
                    window_start: agg.window_start,
                    window_end: agg.window_end,
                    sample_subjects: agg.subjects.into_iter().collect(),
                    sample_recipients: targets,
                }
            })
            .collect();

        Ok(results)
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

        // Build the exclude list: internal domains + user-configured excludes.
        // Passed as a single TEXT[] parameter to avoid dynamic SQL.
        let mut exclude_list: Vec<String> = internal_domains.to_vec();
        exclude_list.extend(config.exclude_domains.iter().cloned());

        // All aggregation happens in SQL:
        //  - CTE `base` filters sessions and excludes internal/configured domains
        //  - CTE `expanded` unnests the rcpt_to JSON array for COUNT(DISTINCT recipient)
        //  - Final SELECT groups by sender_domain, applies HAVING threshold, and
        //    collects sample subjects/recipients via array_agg slicing.
        //
        // rcpt_to is a TEXT column storing a JSON array (e.g. '["a@x.com","b@y.com"]').
        // We use rcpt_to::jsonb → jsonb_array_elements_text to unnest.
        // Rows where rcpt_to is NULL or not valid JSON are handled with LEFT JOIN LATERAL
        // so they still count toward email_count but contribute 0 unique recipients.
        let rows = sqlx::query_as::<_, ExternalSenderAggRow>(
            r#"
            WITH base AS (
                SELECT
                    LOWER(sender_domain) AS sd,
                    started_at,
                    subject,
                    rcpt_to
                FROM sessions
                WHERE started_at > $1
                  AND protocol = 'Smtp'
                  AND status = 'Completed'
                  AND sender_domain IS NOT NULL
                  AND LOWER(sender_domain) != ALL($2)
            ),
            expanded AS (
                SELECT
                    b.sd,
                    b.started_at,
                    b.subject,
                    LOWER(r.addr) AS recipient
                FROM base b
                LEFT JOIN LATERAL
                    jsonb_array_elements_text(b.rcpt_to::jsonb) AS r(addr) ON true
            )
            SELECT
                sd                                                   AS sender_domain,
                COUNT(DISTINCT started_at)::BIGINT                   AS email_count,
                COUNT(DISTINCT recipient)::BIGINT                    AS unique_recipients,
                MIN(started_at)                                      AS window_start,
                MAX(started_at)                                      AS window_end,
                (array_agg(DISTINCT subject) FILTER (WHERE subject IS NOT NULL AND subject != ''))[1:5]
                                                                     AS sample_subjects,
                (array_agg(DISTINCT recipient) FILTER (WHERE recipient IS NOT NULL))[1:10]
                                                                     AS sample_recipients
            FROM expanded
            GROUP BY sd
            HAVING COUNT(DISTINCT started_at) >= $3
            ORDER BY COUNT(DISTINCT started_at) DESC
            "#,
        )
        .bind(&cutoff)                          // $1: time window cutoff
        .bind(&exclude_list)                    // $2: TEXT[] of excluded domains
        .bind(config.min_emails)                // $3: BIGINT min_emails threshold
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
