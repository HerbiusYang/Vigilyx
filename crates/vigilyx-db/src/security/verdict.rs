//! Security (Verdict) Module (ModuleResult) Data

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

use vigilyx_core::security::{
    Bpa, InspectionCoverage, ModuleResult, Pillar, SecurityVerdict, ThreatLevel, ThreatType,
    classify_email_classification,
};

use crate::VigilDb;

// Security overview aggregates delivery lineage and rolling threat counters.
// Keep one result for a short operational window so the dashboard and the
// security page do not serialize repeated multi-table scans every ten seconds.
// The API refresh loop runs every 30 seconds; 60 seconds prevents the next
// loop from immediately repeating the multi-table scan after the previous
// refresh and still keeps this rolling 24-hour view operationally fresh.
const SECURITY_STATS_CACHE_TTL: Duration = Duration::from_secs(60);

/// + metadata (Used for)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerdictWithMeta {
    #[serde(default)]
    pub inspection_coverage: InspectionCoverage,
    #[serde(default)]
    pub coverage_reasons: Vec<String>,
    pub verdict_id: String,
    pub session_id: String,
    pub threat_level: String,
    pub threat_type: Option<String>,
    pub classification: Option<String>,
    /// Fused composite risk after safety floors/caps. This is distinct from
    /// verdict confidence, which may be capped by inspection coverage.
    pub risk_score: Option<f64>,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub summary: String,
    pub modules_run: u32,
    pub modules_flagged: u32,
    pub total_duration_ms: u64,
    pub created_at: String,
    pub mail_from: Option<String>,
    pub rcpt_to: Option<String>,
    pub subject: Option<String>,
    pub protocol: Option<String>,
    pub client_ip: Option<String>,
    pub server_ip: Option<String>,
}

/// Single-statement UPSERT guarded by the `ux_security_verdicts_session`
/// unique index (created in the security migration after deduping).
///
/// Race rationale: the 180s rescan sweep and the live stream consumer may
/// analyze the same session concurrently. A DELETE + INSERT pair (the
/// previous implementation) serializes writers through row locks and
/// amplifies dead-row churn; one atomic UPSERT keeps exactly one current
/// verdict per session (newest wins) with no transaction window at all.
const UPSERT_VERDICT_SQL: &str = r#"
            INSERT INTO security_verdicts
                (id, session_id, threat_level, confidence, categories, summary,
                 pillar_scores, modules_run, modules_flagged, total_duration_ms,
                 created_at, fusion_details, verdict_origin, source_session_id,
                 threat_type, inspection_coverage, coverage_reasons)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'native', NULL, $13, $14, $15)
            ON CONFLICT(session_id) DO UPDATE SET
                id = EXCLUDED.id,
                threat_level = EXCLUDED.threat_level,
                confidence = EXCLUDED.confidence,
                categories = EXCLUDED.categories,
                summary = EXCLUDED.summary,
                pillar_scores = EXCLUDED.pillar_scores,
                modules_run = EXCLUDED.modules_run,
                modules_flagged = EXCLUDED.modules_flagged,
                total_duration_ms = EXCLUDED.total_duration_ms,
                created_at = EXCLUDED.created_at,
                fusion_details = EXCLUDED.fusion_details,
                verdict_origin = EXCLUDED.verdict_origin,
                source_session_id = EXCLUDED.source_session_id,
                threat_type = EXCLUDED.threat_type,
                inspection_coverage = EXCLUDED.inspection_coverage,
                coverage_reasons = EXCLUDED.coverage_reasons
            "#;

/// The verdict table intentionally keeps one current row per session. Since
/// a rescan publishes a new verdict id, any alert written for the previous
/// current row must follow that replacement or it becomes an orphaned UI
/// reference. This runs in the same transaction as the verdict UPSERT.
const REBIND_ALERTS_TO_CURRENT_VERDICT_SQL: &str = r#"
            UPDATE security_alerts
            SET verdict_id = $2
            WHERE session_id = $1 AND verdict_id <> $2
            "#;

/// UPSERT conflict clause for `security_module_results`, guarded by the
/// `ux_module_results_session_module` unique index on (session_id, module_id)
/// (created in the security migration after deduping historical double rows).
///
/// One current row per module per session: a rescan updates the row in place
/// (including `verdict_id`) instead of stacking a second copy next to the one
/// from the previous analysis.
const MODULE_RESULT_UPSERT_CLAUSE: &str = r#"
                ON CONFLICT (session_id, module_id) DO UPDATE SET
                    verdict_id = EXCLUDED.verdict_id,
                    module_name = EXCLUDED.module_name,
                    pillar = EXCLUDED.pillar,
                    threat_level = EXCLUDED.threat_level,
                    confidence = EXCLUDED.confidence,
                    categories = EXCLUDED.categories,
                    summary = EXCLUDED.summary,
                    evidence = EXCLUDED.evidence,
                    details = EXCLUDED.details,
                    duration_ms = EXCLUDED.duration_ms,
                    analyzed_at = EXCLUDED.analyzed_at,
                    bpa_b = EXCLUDED.bpa_b,
                    bpa_d = EXCLUDED.bpa_d,
                    bpa_u = EXCLUDED.bpa_u,
                    engine_id = EXCLUDED.engine_id
            "#;

/// Remove module rows from earlier analyses of the same session whose module
/// did not run in the current analysis (module set can shrink across engine
/// versions). Rows for modules that did run are covered by the UPSERT above.
const DELETE_STALE_MODULE_RESULTS_SQL: &str =
    "DELETE FROM security_module_results WHERE session_id = $1 AND NOT (module_id = ANY($2))";

impl VigilDb {
    /// Security (session 1, UPSERT)
    pub async fn insert_verdict(&self, verdict: &SecurityVerdict) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::upsert_verdict_tx(&mut tx, verdict).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Copy the first-hop verdict to a downstream session without re-running
    /// modules or post-verdict side effects. Module-result reads resolve back
    /// to the source session, while stats can exclude this synthetic row by
    /// `verdict_origin`.
    pub async fn insert_reused_first_hop_verdict(
        &self,
        session_id: Uuid,
        source_session_id: Uuid,
    ) -> Result<bool> {
        let reused_verdict_id = Uuid::new_v4().to_string();
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            r#"
            INSERT INTO security_verdicts
                (id, session_id, threat_level, confidence, categories, summary,
                 pillar_scores, modules_run, modules_flagged, total_duration_ms,
                 created_at, fusion_details, verdict_origin, source_session_id,
                 threat_type, inspection_coverage, coverage_reasons)
            SELECT $3, $1, threat_level, confidence, categories, summary,
                   pillar_scores, 0, 0, 0,
                   TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                   fusion_details,
                   'reused_first_hop', $2, threat_type, inspection_coverage, coverage_reasons
            FROM security_verdicts
            WHERE session_id = $2 AND verdict_origin = 'native'
            ON CONFLICT(session_id) DO NOTHING
            "#,
        )
        .bind(session_id.to_string())
        .bind(source_session_id.to_string())
        .bind(&reused_verdict_id)
        .execute(&mut *tx)
        .await?;
        let inserted = result.rows_affected() > 0;
        if inserted {
            sqlx::query(REBIND_ALERTS_TO_CURRENT_VERDICT_SQL)
                .bind(session_id.to_string())
                .bind(&reused_verdict_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(inserted)
    }

    /// Atomically store a verdict and its module results in ONE transaction.
    ///
    /// Race rationale: storing the verdict and the module rows in separate
    /// transactions (the previous implementation) let concurrent analyses
    /// (live stream, catch-up rescan, release rescan) interleave so a session
    /// could show the verdict from analysis A with module rows from analysis
    /// B — or keep double module rows. One transaction makes the pair
    /// all-or-nothing per analysis; combined with the UPSERTs, concurrent
    /// writers converge on the newest complete set.
    pub async fn insert_verdict_with_module_results(
        &self,
        verdict: &SecurityVerdict,
        results: &[&ModuleResult],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::upsert_verdict_tx(&mut tx, verdict).await?;
        Self::upsert_module_results_tx(&mut tx, verdict.id, verdict.session_id, results).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn upsert_verdict_tx(
        tx: &mut Transaction<'_, Postgres>,
        verdict: &SecurityVerdict,
    ) -> Result<()> {
        let categories_json = serde_json::to_string(&verdict.categories)?;
        let pillar_scores_json = serde_json::to_string(&verdict.pillar_scores)?;
        let fusion_details_json = verdict
            .fusion_details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(UPSERT_VERDICT_SQL)
            .bind(verdict.id.to_string())
            .bind(verdict.session_id.to_string())
            .bind(verdict.threat_level.to_string())
            .bind(verdict.confidence)
            .bind(&categories_json)
            .bind(&verdict.summary)
            .bind(&pillar_scores_json)
            .bind(verdict.modules_run as i64)
            .bind(verdict.modules_flagged as i64)
            .bind(verdict.total_duration_ms as i64)
            .bind(verdict.created_at.to_rfc3339())
            .bind(&fusion_details_json)
            .bind(verdict.threat_type.map(|value| value.to_string()))
            .bind(verdict.inspection_coverage.as_str())
            .bind(serde_json::to_string(&verdict.coverage_reasons)?)
            .execute(&mut **tx)
            .await?;

        sqlx::query(REBIND_ALERTS_TO_CURRENT_VERDICT_SQL)
            .bind(verdict.session_id.to_string())
            .bind(verdict.id.to_string())
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    /// Module (INSERT)
    ///
    /// VALUES INSERT, N DB ceil(N/CHUNK).
    /// 17 x 500 = 8500,Security.
    ///
    /// UPSERT on (session_id, module_id) + stale-row cleanup; prefer
    /// [`insert_verdict_with_module_results`](Self::insert_verdict_with_module_results)
    /// so the verdict and its module rows commit atomically.
    pub async fn insert_module_results(
        &self,
        verdict_id: Uuid,
        session_id: Uuid,
        results: &[&ModuleResult],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::upsert_module_results_tx(&mut tx, verdict_id, session_id, results).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn upsert_module_results_tx(
        tx: &mut Transaction<'_, Postgres>,
        verdict_id: Uuid,
        session_id: Uuid,
        results: &[&ModuleResult],
    ) -> Result<()> {
        let sid = session_id.to_string();

        if results.is_empty() {
            // No module ran in this analysis: drop every previous row so a
            // rescan cannot leave stale results behind.
            sqlx::query("DELETE FROM security_module_results WHERE session_id = $1")
                .bind(&sid)
                .execute(&mut **tx)
                .await?;
            return Ok(());
        }

        const COLS_PER_ROW: usize = 17;
        const BATCH_CHUNK_SIZE: usize = 500;

        // Process: JSON
        struct PreparedModuleResult {
            verdict_id: String,
            session_id: String,
            module_id: String,
            module_name: String,
            pillar: String,
            threat_level: String,
            confidence: f64,
            categories_json: String,
            summary: String,
            evidence_json: String,
            details_str: String,
            duration_ms: i64,
            analyzed_at: String,
            bpa_b: Option<f64>,
            bpa_d: Option<f64>,
            bpa_u: Option<f64>,
            engine_id: Option<String>,
        }

        let vid = verdict_id.to_string();

        let mut prepared: Vec<PreparedModuleResult> = Vec::with_capacity(results.len());
        for r in results {
            let (bpa_b, bpa_d, bpa_u) = match &r.bpa {
                Some(bpa) => (Some(bpa.b), Some(bpa.d), Some(bpa.u)),
                None => (None, None, None),
            };
            prepared.push(PreparedModuleResult {
                verdict_id: vid.clone(),
                session_id: sid.clone(),
                module_id: r.module_id.clone(),
                module_name: r.module_name.clone(),
                pillar: r.pillar.to_string(),
                threat_level: r.threat_level.to_string(),
                confidence: r.confidence,
                categories_json: serde_json::to_string(&r.categories)?,
                summary: r.summary.clone(),
                evidence_json: serde_json::to_string(&r.evidence)?,
                details_str: serde_json::to_string(&r.details)?,
                duration_ms: r.duration_ms as i64,
                analyzed_at: r.analyzed_at.to_rfc3339(),
                bpa_b,
                bpa_d,
                bpa_u,
                engine_id: r.engine_id.clone(),
            });
        }

        for chunk in prepared.chunks(BATCH_CHUNK_SIZE) {
            let mut sql = String::from(
                "INSERT INTO security_module_results \
                    (verdict_id, session_id, module_id, module_name, pillar, \
                     threat_level, confidence, categories, summary, evidence, \
                     details, duration_ms, analyzed_at, bpa_b, bpa_d, bpa_u, engine_id) \
                VALUES ",
            );

            let mut param_idx = 1u32;
            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    sql.push_str(", ");
                }
                sql.push('(');
                for col in 0..COLS_PER_ROW {
                    if col > 0 {
                        sql.push_str(", ");
                    }
                    sql.push('$');
                    sql.push_str(&(param_idx + col as u32).to_string());
                }
                sql.push(')');
                param_idx += COLS_PER_ROW as u32;
            }
            sql.push_str(MODULE_RESULT_UPSERT_CLAUSE);

            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
            for row in chunk {
                query = query
                    .bind(&row.verdict_id)
                    .bind(&row.session_id)
                    .bind(&row.module_id)
                    .bind(&row.module_name)
                    .bind(&row.pillar)
                    .bind(&row.threat_level)
                    .bind(row.confidence)
                    .bind(&row.categories_json)
                    .bind(&row.summary)
                    .bind(&row.evidence_json)
                    .bind(&row.details_str)
                    .bind(row.duration_ms)
                    .bind(&row.analyzed_at)
                    .bind(row.bpa_b)
                    .bind(row.bpa_d)
                    .bind(row.bpa_u)
                    .bind(&row.engine_id);
            }
            query.execute(&mut **tx).await?;
        }

        // Drop rows from earlier analyses whose module did not run this time.
        let current_module_ids: Vec<String> =
            prepared.iter().map(|p| p.module_id.clone()).collect();
        sqlx::query(DELETE_STALE_MODULE_RESULTS_SQL)
            .bind(&sid)
            .bind(&current_module_ids)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    /// session Security
    pub async fn get_verdict_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<SecurityVerdict>> {
        let row = sqlx::query_as::<_, VerdictRow>(
            r#"
            SELECT id, session_id, threat_level, threat_type, confidence, categories, summary,
                   pillar_scores, modules_run, modules_flagged, total_duration_ms, created_at,
                   fusion_details, inspection_coverage, coverage_reasons
            FROM security_verdicts
            WHERE session_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(r.into_verdict()?)),
            None => Ok(None),
        }
    }

    /// session Module (New1)
    ///
    /// CTE WHERE Query, PostgreSQL planner Index:
    /// - CTE `latest_verdict` Index New verdict id
    /// - Query id module_results(Query)
    pub async fn get_module_results_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ModuleResult>> {
        let sid = session_id.to_string();

        let rows = sqlx::query_as::<_, ModuleResultRow>(
            r#"
            WITH target_verdict AS (
                SELECT COALESCE(NULLIF(source_session_id, ''), session_id) AS source_session_id
                FROM security_verdicts
                WHERE session_id = $1
                ORDER BY created_at DESC
                LIMIT 1
            ), latest_verdict AS (
                SELECT id, session_id FROM security_verdicts
                WHERE session_id = (SELECT source_session_id FROM target_verdict)
                  AND verdict_origin = 'native'
                ORDER BY created_at DESC
                LIMIT 1
            )
            SELECT module_id, module_name, pillar, threat_level, confidence,
                   categories, summary, evidence, details, duration_ms, analyzed_at,
                   bpa_b, bpa_d, bpa_u, engine_id
            FROM security_module_results
            WHERE session_id = (SELECT session_id FROM latest_verdict)
              AND verdict_id = (SELECT id FROM latest_verdict)
            ORDER BY analyzed_at ASC
            "#,
        )
        .bind(&sid)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_module_result()).collect()
    }

    /// Security (metadata, Used for)
    pub async fn list_recent_verdicts(
        &self,
        threat_level: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<VerdictWithMeta>, u64)> {
        // (mail_from IS NOT NULL)
        let mut sql = String::from(
            r#"SELECT v.id, v.session_id, v.threat_level, v.confidence, v.fusion_details,
                      v.inspection_coverage, v.coverage_reasons, v.threat_type, v.categories, v.summary, v.modules_run, v.modules_flagged,
                      v.total_duration_ms, v.created_at,
                      s.mail_from, s.rcpt_to, s.subject, s.protocol,
                      s.client_ip, s.server_ip
               FROM security_verdicts v
               INNER JOIN sessions s ON v.session_id = s.id
               WHERE s.mail_from IS NOT NULL"#,
        );
        // Keep the user-controlled filter entirely in a bound PostgreSQL
        // array. The SQL text below is selected from two fixed fragments;
        // neither the raw query value nor a value-derived identifier is ever
        // concatenated into SQL. Empty input retains the default security
        // view (exclude safe), instead of producing an invalid `IN ()`.
        let levels: Vec<String> = threat_level
            .into_iter()
            .flat_map(|level| level.split(','))
            .map(str::trim)
            .filter(|level| !level.is_empty())
            .map(str::to_string)
            .collect();
        let threat_filter_clause = if levels.is_empty() {
            " AND v.threat_level != 'safe'"
        } else {
            " AND v.threat_level = ANY($1::text[])"
        };
        let threat_filter_values = (!levels.is_empty()).then_some(levels);
        sql.push_str(threat_filter_clause);

        // Get total count (same filter: only real emails)
        let mut count_sql = String::from(
            r#"SELECT COUNT(*) FROM security_verdicts v
               INNER JOIN sessions s ON v.session_id = s.id
               WHERE s.mail_from IS NOT NULL"#,
        );
        count_sql.push_str(threat_filter_clause);

        let total: (i64,) = {
            let mut q = sqlx::query_as(sqlx::AssertSqlSafe(count_sql.as_str()));
            if let Some(values) = &threat_filter_values {
                q = q.bind(values);
            }
            q.fetch_one(&self.pool).await?
        };

        sql.push_str(" ORDER BY v.created_at DESC");
        let limit_idx = if threat_filter_values.is_some() { 2 } else { 1 };
        let offset_idx = limit_idx + 1;
        sql.push_str(&format!(" LIMIT ${}", limit_idx));
        sql.push_str(&format!(" OFFSET ${}", offset_idx));

        let rows: Vec<VerdictMetaRow> = {
            let mut q = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()));
            if let Some(values) = &threat_filter_values {
                q = q.bind(values);
            }
            q = q.bind(limit as i64).bind(offset as i64);
            q.fetch_all(&self.pool).await?
        };

        let items: Vec<VerdictWithMeta> = rows.into_iter().map(|r| r.into_meta()).collect();
        Ok((items, total.0 as u64))
    }

    /// SecurityStatistics
    ///
    /// Statistics Session (/ mail_from)
    /// Exclude: 554, QUIT-only Session, Connection
    pub async fn get_security_stats(&self) -> Result<vigilyx_core::security::SecurityStats> {
        let mut cache = self.security_stats_cache.lock().await;
        if let Some((created_at, stats)) = cache.as_ref()
            && created_at.elapsed() < SECURITY_STATS_CACHE_TTL
        {
            return Ok(stats.clone());
        }

        let stats = self.compute_security_stats().await?;
        *cache = Some((std::time::Instant::now(), stats.clone()));
        Ok(stats)
    }

    async fn compute_security_stats(&self) -> Result<vigilyx_core::security::SecurityStats> {
        self.compute_security_stats_with_interquery_hook(|| async { Ok(()) })
            .await
    }

    async fn compute_security_stats_with_interquery_hook<F, Fut>(
        &self,
        interquery_hook: F,
    ) -> Result<vigilyx_core::security::SecurityStats>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        // The UI capture rule is the authoritative terminal identity for the
        // passive mirror. A terminal mail server is a delivery endpoint, not a
        // security vendor, so it must never enter the vendor comparison rows.
        // Keep an environment fallback for older installations without the UI
        // preference row.
        let mut terminal_mail_servers = self
            .get_capture_inbound_target_ips()
            .await
            .unwrap_or_default();
        if terminal_mail_servers.is_empty()
            && let Ok(raw) = std::env::var("INBOUND_MAIL_SERVERS")
        {
            terminal_mail_servers.extend(
                raw.split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(str::to_string),
            );
        }
        let mut terminal_mail_servers = terminal_mail_servers.iter().cloned().collect::<Vec<_>>();
        terminal_mail_servers.sort_unstable();

        self.compute_security_stats_with_terminal_mail_servers_and_hook(
            terminal_mail_servers,
            interquery_hook,
        )
        .await
    }

    async fn compute_security_stats_with_terminal_mail_servers_and_hook<F, Fut>(
        &self,
        mut terminal_mail_servers: Vec<String>,
        interquery_hook: F,
    ) -> Result<vigilyx_core::security::SecurityStats>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        terminal_mail_servers.sort_unstable();
        terminal_mail_servers.dedup();

        // The overall counters and per-node comparison are intentionally two
        // statements, but one API response must represent one database instant.
        // PostgreSQL READ COMMITTED would take a new snapshot for the second
        // statement and could mix a newly inserted hop into an older total.
        // REPEATABLE READ also keeps NOW() fixed at the transaction start, so
        // every rolling-window cutoff in this response has the same `as_of`.
        let mut snapshot = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *snapshot)
            .await?;
        // The rolling aggregate is mostly index/heap work; JIT generation for
        // its many FILTER/EXISTS expressions is more expensive than execution
        // on this result size. Keep the setting scoped to this snapshot.
        sqlx::query("SET LOCAL jit = off")
            .execute(&mut *snapshot)
            .await?;
        let delivery_stats_as_of: String = sqlx::query_scalar(
            r#"SELECT TO_CHAR(
                    CURRENT_TIMESTAMP AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                )"#,
        )
        .fetch_one(&mut *snapshot)
        .await?;

        // `ioc_count` remains library inventory only; actual email-to-IOC hit
        // events are not persisted by the current data model.
        let row: SecurityStatsRow = sqlx::query_as(
            r#"
            WITH eligible AS (
                SELECT v.threat_level, vigilyx_text_timestamptz(v.created_at) AS analyzed_at
                FROM security_verdicts v
                INNER JOIN sessions s ON v.session_id = s.id
                WHERE s.mail_from IS NOT NULL
                  AND v.verdict_origin = 'native'
            ), delivery_gateway_ips AS MATERIALIZED (
                -- A gateway is observed on both sides of the mirror: it is a
                -- destination on an inbound SMTP leg and a client on a later
                -- outbound leg.  The outbound leg itself is positive evidence
                -- that this gateway passed the message; it does not require the
                -- upstream message to carry the same Message-ID.
                SELECT DISTINCT output_hop.client_ip AS node_ip
                FROM email_delivery_hops output_hop
                WHERE vigilyx_text_timestamptz(output_hop.observed_at) <= NOW()
                  AND output_hop.client_ip <> output_hop.server_ip
                  AND EXISTS (
                      SELECT 1
                      FROM email_delivery_hops input_hop
                      WHERE input_hop.server_ip = output_hop.client_ip
                        AND vigilyx_text_timestamptz(input_hop.observed_at) <= NOW()
                  )
            )
            SELECT
                COUNT(*)::BIGINT AS total_scanned,
                COUNT(*) FILTER (WHERE threat_level = 'safe')::BIGINT AS safe_count,
                COUNT(*) FILTER (WHERE threat_level = 'low')::BIGINT AS low_count,
                COUNT(*) FILTER (WHERE threat_level = 'medium')::BIGINT AS medium_count,
                COUNT(*) FILTER (WHERE threat_level = 'high')::BIGINT AS high_count,
                COUNT(*) FILTER (WHERE threat_level = 'critical')::BIGINT AS critical_count,
                COUNT(*) FILTER (WHERE analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS analyzed_24h,
                COUNT(*) FILTER (WHERE analyzed_at > NOW() - INTERVAL '48 hours'
                                  AND analyzed_at <= NOW() - INTERVAL '24 hours')::BIGINT AS analyzed_previous_24h,
                COUNT(*) FILTER (WHERE threat_level = 'safe'
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS safe_24h,
                COUNT(*) FILTER (WHERE threat_level = 'low'
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS low_24h,
                COUNT(*) FILTER (WHERE threat_level = 'medium'
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS medium_24h,
                COUNT(*) FILTER (WHERE threat_level = 'high'
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS high_24h,
                COUNT(*) FILTER (WHERE threat_level = 'critical'
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS critical_24h,
                COUNT(*) FILTER (WHERE threat_level IN ('high', 'critical')
                                  AND analyzed_at > NOW() - INTERVAL '24 hours')::BIGINT AS high_threats_24h,
                COUNT(*) FILTER (WHERE threat_level IN ('high', 'critical')
                                  AND analyzed_at > NOW() - INTERVAL '48 hours'
                                  AND analyzed_at <= NOW() - INTERVAL '24 hours')::BIGINT AS high_threats_previous_24h,
                (SELECT COUNT(*)::BIGINT FROM security_ioc) AS ioc_count,
                (SELECT COUNT(*)::BIGINT FROM security_alerts
                 WHERE vigilyx_text_timestamptz(created_at) > NOW() - INTERVAL '24 hours') AS alerts_24h,
                (SELECT COUNT(*)::BIGINT FROM quarantine
                 WHERE vigilyx_text_timestamptz(created_at) > NOW() - INTERVAL '24 hours') AS quarantined_24h,
                (SELECT COUNT(*)::BIGINT FROM email_delivery_chains
                 WHERE vigilyx_text_timestamptz(first_seen_at) <= NOW()) AS first_hop_emails_total,
                (SELECT COUNT(*)::BIGINT FROM email_delivery_chains
                 WHERE vigilyx_text_timestamptz(first_seen_at) <= NOW()
                   AND first_verdict_id IS NOT NULL
                   AND first_threat_level IN ('low', 'medium', 'high', 'critical')) AS first_hop_dangerous_total,
                (SELECT COUNT(*)::BIGINT FROM email_delivery_hops
                 WHERE hop_index > 0
                   AND verdict_origin = 'reused_first_hop'
                   AND vigilyx_text_timestamptz(observed_at) <= NOW()) AS downstream_reused_hops_total,
                (SELECT COUNT(*)::BIGINT
                 FROM email_delivery_chains c
                 WHERE vigilyx_text_timestamptz(c.first_seen_at) <= NOW()
                   AND c.first_verdict_id IS NOT NULL
                   AND c.first_threat_level IN ('low', 'medium', 'high', 'critical')
                   AND EXISTS (
                       SELECT 1
                       FROM email_delivery_hops pass_hop
                       WHERE pass_hop.chain_id = c.chain_id
                         AND pass_hop.client_ip IN (
                             SELECT node_ip FROM delivery_gateway_ips
                         )
                         AND pass_hop.server_ip <> pass_hop.client_ip
                         AND vigilyx_text_timestamptz(pass_hop.observed_at) <= NOW()
                   )) AS dangerous_forwarded_total
            FROM eligible
            "#,
        )
        .fetch_one(&mut *snapshot)
        .await?;

        interquery_hook().await?;

        // A node comparison is only meaningful after the chain has settled.
        // Attribute a pass to the SMTP client gateway on an observed outbound
        // leg (`.40 -> .41` proves .40 passed; `.41 -> terminal` proves .41
        // passed). This remains valid when the gateway injects or rewrites a
        // Message-ID, and avoids fuzzy cross-message matching. Only a final
        // post-DATA/BDAT 550-554 with RFC 3463 5.7.x status is an explicit
        // node security-policy block. When a terminal mail-server policy is
        // configured, a settled non-terminal node with no observed outbound
        // edge is a path-termination block. A later outbound edge always wins
        // over an earlier rejection/termination observation; if no terminal
        // policy is configured, missing action evidence remains unconfirmed.
        let comparison_rows: Vec<DeliveryNodeComparisonRow> = sqlx::query_as(
            r#"
            WITH settled_chains AS (
                SELECT c.chain_id, c.first_threat_level
                FROM email_delivery_chains c
                WHERE vigilyx_text_timestamptz(c.first_seen_at) <= NOW()
                  AND COALESCE((
                      SELECT MAX(vigilyx_text_timestamptz(last_hop.observed_at))
                      FROM email_delivery_hops last_hop
                      WHERE last_hop.chain_id = c.chain_id
                        AND vigilyx_text_timestamptz(last_hop.observed_at) <= NOW()
                  ), vigilyx_text_timestamptz(c.first_seen_at)) <= NOW() - INTERVAL '30 seconds'
                  AND c.first_verdict_id IS NOT NULL
                  AND c.first_threat_level IN ('safe', 'low', 'medium', 'high', 'critical')
            ), gateway_ips AS MATERIALIZED (
                SELECT DISTINCT h.server_ip AS node_ip
                FROM settled_chains c
                INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                WHERE vigilyx_text_timestamptz(h.observed_at) <= NOW()
                  AND NOT (h.server_ip = ANY($1))
            ), node_keys AS MATERIALIZED (
                -- Receiving-side observation: needed for explicit rejection
                -- and for reporting action-coverage gaps.
                SELECT
                    h.chain_id,
                    h.server_ip AS node_ip,
                    MIN(h.hop_index * 2 + 1) AS action_order
                FROM settled_chains c
                INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                WHERE vigilyx_text_timestamptz(h.observed_at) <= NOW()
                  AND h.server_ip IN (SELECT node_ip FROM gateway_ips)
                GROUP BY h.chain_id, h.server_ip

                UNION

                -- Sending-side observation: the outbound SMTP connection is
                -- direct, one-hop proof that the client gateway passed mail.
                SELECT
                    h.chain_id,
                    h.client_ip AS node_ip,
                    MIN(h.hop_index * 2) AS action_order
                FROM settled_chains c
                INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                WHERE vigilyx_text_timestamptz(h.observed_at) <= NOW()
                  AND h.client_ip IN (SELECT node_ip FROM gateway_ips)
                  AND h.server_ip <> h.client_ip
                GROUP BY h.chain_id, h.client_ip
            ), node_actions AS MATERIALIZED (
                SELECT
                    k.chain_id,
                    k.node_ip AS server_ip,
                    MIN(k.action_order) AS action_order,
                    c.first_threat_level,
                    EXISTS (
                        SELECT 1
                        FROM email_delivery_hops pass_hop
                        WHERE pass_hop.chain_id = k.chain_id
                          AND pass_hop.client_ip = k.node_ip
                          AND pass_hop.server_ip <> k.node_ip
                          AND vigilyx_text_timestamptz(pass_hop.observed_at) <= NOW()
                    ) AS gateway_passed,
                    EXISTS (
                        SELECT 1
                        FROM email_delivery_hops terminal_hop
                        WHERE terminal_hop.chain_id = k.chain_id
                          AND terminal_hop.client_ip = k.node_ip
                          AND terminal_hop.server_ip = ANY($1)
                          AND vigilyx_text_timestamptz(terminal_hop.observed_at) <= NOW()
                    ) AS terminal_delivered,
                    EXISTS (
                        SELECT 1
                        FROM email_delivery_hops blocked_hop
                        WHERE blocked_hop.chain_id = k.chain_id
                          AND blocked_hop.server_ip = k.node_ip
                          AND vigilyx_text_timestamptz(blocked_hop.observed_at) <= NOW()
                          AND blocked_hop.smtp_security_rejection_metadata_ready
                          AND blocked_hop.smtp_security_rejected
                    ) AS vendor_blocked_explicit
                FROM node_keys k
                INNER JOIN settled_chains c ON c.chain_id = k.chain_id
                GROUP BY k.chain_id, k.node_ip, c.first_threat_level
            ), classified_actions AS (
                SELECT
                    node_actions.*,
                    (
                        vendor_blocked_explicit
                        OR (cardinality($1) > 0 AND NOT gateway_passed)
                    ) AS vendor_blocked
                FROM node_actions
            ), node_rollup AS (
                SELECT
                    server_ip,
                    MIN(action_order) AS first_action_order,
                    COUNT(*) FILTER (
                        WHERE vendor_blocked AND NOT gateway_passed
                    )::BIGINT AS vendor_blocked_total,
                    COUNT(*) FILTER (
                        WHERE gateway_passed
                    )::BIGINT AS vendor_passed_total,
                    COUNT(*) FILTER (
                        WHERE terminal_delivered
                    )::BIGINT AS terminal_delivered_total,
                    COUNT(*) FILTER (
                        WHERE NOT vendor_blocked
                          AND NOT gateway_passed
                    )::BIGINT AS vendor_unconfirmed_total,
                    COUNT(*) FILTER (
                        WHERE first_threat_level IN ('low', 'medium', 'high', 'critical')
                    )::BIGINT AS vigilyx_risky_total,
                    COUNT(*) FILTER (
                        WHERE vendor_blocked
                          AND NOT gateway_passed
                          AND first_threat_level IN ('low', 'medium', 'high', 'critical')
                    )::BIGINT AS both_threat_total,
                    COUNT(*) FILTER (
                        WHERE gateway_passed
                          AND first_threat_level IN ('low', 'medium', 'high', 'critical')
                    )::BIGINT AS vigilyx_only_threat_total,
                    COUNT(*) FILTER (
                        WHERE vendor_blocked
                          AND NOT gateway_passed
                          AND first_threat_level = 'safe'
                    )::BIGINT AS vendor_only_threat_total
                FROM classified_actions
                GROUP BY server_ip
            )
            SELECT
                ROW_NUMBER() OVER (
                    ORDER BY first_action_order, server_ip
                )::INT - 1 AS node_index,
                server_ip AS server_ips,
                (vendor_blocked_total + vendor_passed_total)::BIGINT AS comparable_total,
                vendor_blocked_total,
                vendor_passed_total,
                terminal_delivered_total,
                vendor_unconfirmed_total,
                vigilyx_risky_total,
                both_threat_total,
                vigilyx_only_threat_total,
                vendor_only_threat_total
            FROM node_rollup
            ORDER BY first_action_order, server_ip
            "#,
        )
        .bind(&terminal_mail_servers)
        .fetch_all(&mut *snapshot)
        .await?;

        snapshot.commit().await?;

        Ok(vigilyx_core::security::SecurityStats {
            total_scanned: row.total_scanned as u64,
            level_counts: level_counts_from_values(row.level_counts()),
            high_threats_24h: row.high_threats_24h as u64,
            ioc_count: row.ioc_count as u64,
            level_counts_24h: level_counts_from_values(row.level_counts_24h()),
            analyzed_24h: row.analyzed_24h as u64,
            analyzed_previous_24h: row.analyzed_previous_24h as u64,
            high_threats_previous_24h: row.high_threats_previous_24h as u64,
            alerts_24h: row.alerts_24h as u64,
            quarantined_24h: row.quarantined_24h as u64,
            first_hop_emails_total: row.first_hop_emails_total as u64,
            first_hop_dangerous_total: row.first_hop_dangerous_total as u64,
            downstream_reused_hops_total: row.downstream_reused_hops_total as u64,
            dangerous_forwarded_total: row.dangerous_forwarded_total as u64,
            dangerous_forwarded_rate: if row.first_hop_dangerous_total > 0 {
                (row.dangerous_forwarded_total as f64 / row.first_hop_dangerous_total as f64)
                    * 100.0
            } else {
                0.0
            },
            delivery_node_comparisons: comparison_rows
                .into_iter()
                .map(DeliveryNodeComparisonRow::into_stats)
                .collect(),
            terminal_mail_servers,
            delivery_stats_as_of,
            delivery_stats_scope: "all_history".to_string(),
        })
    }

    /// Test-only snapshot barrier used by the real PostgreSQL regression test.
    /// The hook commits a concurrent delivery row after the totals statement;
    /// the per-node statement must still read the original snapshot.
    #[cfg(feature = "infra-tests")]
    pub async fn get_security_stats_with_interquery_hook_for_test<F, Fut>(
        &self,
        interquery_hook: F,
    ) -> Result<vigilyx_core::security::SecurityStats>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        self.compute_security_stats_with_interquery_hook(interquery_hook)
            .await
    }

    /// Test-only terminal-identity injection. Production always resolves this
    /// list from the capture configuration before entering the snapshot.
    #[cfg(feature = "infra-tests")]
    pub async fn get_security_stats_with_terminal_mail_servers_for_test(
        &self,
        terminal_mail_servers: Vec<String>,
    ) -> Result<vigilyx_core::security::SecurityStats> {
        self.compute_security_stats_with_terminal_mail_servers_and_hook(
            terminal_mail_servers,
            || async { Ok(()) },
        )
        .await
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SecurityStatsRow {
    total_scanned: i64,
    safe_count: i64,
    low_count: i64,
    medium_count: i64,
    high_count: i64,
    critical_count: i64,
    analyzed_24h: i64,
    analyzed_previous_24h: i64,
    safe_24h: i64,
    low_24h: i64,
    medium_24h: i64,
    high_24h: i64,
    critical_24h: i64,
    high_threats_24h: i64,
    high_threats_previous_24h: i64,
    ioc_count: i64,
    alerts_24h: i64,
    quarantined_24h: i64,
    first_hop_emails_total: i64,
    first_hop_dangerous_total: i64,
    downstream_reused_hops_total: i64,
    dangerous_forwarded_total: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct DeliveryNodeComparisonRow {
    node_index: i32,
    server_ips: Option<String>,
    comparable_total: i64,
    vendor_blocked_total: i64,
    vendor_passed_total: i64,
    terminal_delivered_total: i64,
    vendor_unconfirmed_total: i64,
    vigilyx_risky_total: i64,
    both_threat_total: i64,
    vigilyx_only_threat_total: i64,
    vendor_only_threat_total: i64,
}

impl DeliveryNodeComparisonRow {
    fn into_stats(self) -> vigilyx_core::security::DeliveryNodeComparisonStats {
        fn ratio(numerator: i64, denominator: i64) -> f64 {
            if denominator > 0 {
                (numerator as f64 / denominator as f64) * 100.0
            } else {
                0.0
            }
        }

        vigilyx_core::security::DeliveryNodeComparisonStats {
            node_index: self.node_index.max(0) as u32,
            server_ips: self
                .server_ips
                .unwrap_or_default()
                .split(", ")
                .filter(|ip| !ip.is_empty())
                .map(str::to_string)
                .collect(),
            comparable_total: self.comparable_total.max(0) as u64,
            vendor_blocked_total: self.vendor_blocked_total.max(0) as u64,
            vendor_passed_total: self.vendor_passed_total.max(0) as u64,
            terminal_delivered_total: self.terminal_delivered_total.max(0) as u64,
            vendor_unconfirmed_total: self.vendor_unconfirmed_total.max(0) as u64,
            vigilyx_risky_total: self.vigilyx_risky_total.max(0) as u64,
            both_threat_total: self.both_threat_total.max(0) as u64,
            vigilyx_only_threat_total: self.vigilyx_only_threat_total.max(0) as u64,
            vendor_only_threat_total: self.vendor_only_threat_total.max(0) as u64,
            both_threat_rate: ratio(self.both_threat_total, self.vendor_blocked_total),
            vigilyx_only_threat_rate: ratio(
                self.vigilyx_only_threat_total,
                self.vendor_passed_total,
            ),
            vendor_only_threat_rate: ratio(
                self.vendor_only_threat_total,
                self.vendor_blocked_total,
            ),
            vendor_unconfirmed_rate: ratio(
                self.vendor_unconfirmed_total,
                self.comparable_total + self.vendor_unconfirmed_total,
            ),
        }
    }
}

impl SecurityStatsRow {
    fn level_counts(&self) -> [(&'static str, i64); 5] {
        [
            ("safe", self.safe_count),
            ("low", self.low_count),
            ("medium", self.medium_count),
            ("high", self.high_count),
            ("critical", self.critical_count),
        ]
    }

    fn level_counts_24h(&self) -> [(&'static str, i64); 5] {
        [
            ("safe", self.safe_24h),
            ("low", self.low_24h),
            ("medium", self.medium_24h),
            ("high", self.high_24h),
            ("critical", self.critical_24h),
        ]
    }
}

fn level_counts_from_values(
    values: impl IntoIterator<Item = (&'static str, i64)>,
) -> std::collections::HashMap<String, u64> {
    values
        .into_iter()
        .filter_map(|(level, count)| (count > 0).then_some((level.to_string(), count as u64)))
        .collect()
}

// Database row type (sqlx)

#[derive(Debug, sqlx::FromRow)]
struct VerdictRow {
    inspection_coverage: String,
    coverage_reasons: String,
    id: String,
    session_id: String,
    threat_level: String,
    #[sqlx(default)]
    threat_type: Option<String>,
    confidence: f64,
    categories: String,
    summary: String,
    pillar_scores: String,
    modules_run: i64,
    modules_flagged: i64,
    total_duration_ms: i64,
    created_at: String,
    #[sqlx(default)]
    fusion_details: Option<String>,
}

impl VerdictRow {
    fn into_verdict(self) -> Result<SecurityVerdict> {
        let fusion_details = self
            .fusion_details
            .as_deref()
            // Fusion metadata is optional. Older reused-hop rows can contain
            // a truncated/legacy value; that must not hide the authoritative
            // threat level or the module results from the detail page.
            .and_then(|raw| serde_json::from_str(raw).ok());

        Ok(SecurityVerdict {
            inspection_coverage: InspectionCoverage::parse(&self.inspection_coverage),
            coverage_reasons: serde_json::from_str(&self.coverage_reasons)?,
            id: Uuid::parse_str(&self.id)?,
            session_id: Uuid::parse_str(&self.session_id)?,
            threat_level: parse_threat_level(&self.threat_level),
            threat_type: self.threat_type.as_deref().and_then(parse_threat_type),
            classification: Some(classify_email_classification(&serde_json::from_str::<
                Vec<String>,
            >(
                &self.categories
            )?)),
            confidence: self.confidence,
            categories: serde_json::from_str(&self.categories)?,
            summary: self.summary,
            pillar_scores: serde_json::from_str(&self.pillar_scores)?,
            modules_run: self.modules_run as u32,
            modules_flagged: self.modules_flagged as u32,
            total_duration_ms: self.total_duration_ms as u64,
            created_at: parse_db_datetime(&self.created_at)?,
            fusion_details,
        })
    }
}

/// Parse timestamps written by both the current RFC3339 writers and older
/// PostgreSQL `NOW()::TEXT` writers (`YYYY-MM-DD HH:MM:SS.US+00`).
fn parse_db_datetime(raw: &str) -> Result<DateTime<Utc>> {
    if let Ok(value) = DateTime::parse_from_rfc3339(raw) {
        return Ok(value.with_timezone(&Utc));
    }

    let mut normalized = raw.replacen(' ', "T", 1);
    if normalized.ends_with("+00") || normalized.ends_with("-00") {
        normalized.push_str(":00");
    }
    DateTime::parse_from_rfc3339(&normalized)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| anyhow::anyhow!("invalid database timestamp {raw:?}: {error}"))
}

#[derive(Debug, sqlx::FromRow)]
struct ModuleResultRow {
    module_id: String,
    module_name: String,
    pillar: String,
    threat_level: String,
    confidence: f64,
    categories: String,
    summary: String,
    evidence: String,
    details: Option<String>,
    duration_ms: i64,
    analyzed_at: String,
    #[sqlx(default)]
    bpa_b: Option<f64>,
    #[sqlx(default)]
    bpa_d: Option<f64>,
    #[sqlx(default)]
    bpa_u: Option<f64>,
    #[sqlx(default)]
    engine_id: Option<String>,
}

impl ModuleResultRow {
    fn into_module_result(self) -> Result<ModuleResult> {
        let bpa = match (self.bpa_b, self.bpa_d, self.bpa_u) {
            (Some(b), Some(d), Some(u)) => Some(Bpa::new(b, d, u)),
            _ => None,
        };

        Ok(ModuleResult {
            module_id: self.module_id,
            module_name: self.module_name,
            pillar: parse_pillar(&self.pillar),
            threat_level: parse_threat_level(&self.threat_level),
            confidence: self.confidence,
            categories: serde_json::from_str(&self.categories)?,
            summary: self.summary,
            evidence: serde_json::from_str(&self.evidence)?,
            details: self
                .details
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
            duration_ms: self.duration_ms as u64,
            analyzed_at: DateTime::parse_from_rfc3339(&self.analyzed_at)?.with_timezone(&Utc),
            bpa,
            engine_id: self.engine_id,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VerdictMetaRow {
    inspection_coverage: String,
    coverage_reasons: String,
    id: String,
    session_id: String,
    threat_level: String,
    #[sqlx(default)]
    threat_type: Option<String>,
    confidence: f64,
    fusion_details: Option<String>,
    categories: String,
    summary: String,
    modules_run: i64,
    modules_flagged: i64,
    total_duration_ms: i64,
    created_at: String,
    mail_from: Option<String>,
    rcpt_to: Option<String>,
    subject: Option<String>,
    protocol: Option<String>,
    client_ip: Option<String>,
    server_ip: Option<String>,
}

impl VerdictMetaRow {
    fn into_meta(self) -> VerdictWithMeta {
        let risk_score = risk_score_from_fusion_details(self.fusion_details.as_deref());
        VerdictWithMeta {
            inspection_coverage: InspectionCoverage::parse(&self.inspection_coverage),
            coverage_reasons: serde_json::from_str(&self.coverage_reasons).unwrap_or_default(),
            verdict_id: self.id,
            session_id: self.session_id,
            threat_level: self.threat_level,
            threat_type: self.threat_type,
            classification: Some(
                classify_email_classification(
                    &serde_json::from_str::<Vec<String>>(&self.categories).unwrap_or_default(),
                )
                .to_string(),
            ),
            risk_score,
            confidence: self.confidence,
            categories: serde_json::from_str(&self.categories).unwrap_or_default(),
            summary: self.summary,
            modules_run: self.modules_run as u32,
            modules_flagged: self.modules_flagged as u32,
            total_duration_ms: self.total_duration_ms as u64,
            created_at: self.created_at,
            mail_from: self.mail_from,
            rcpt_to: self.rcpt_to,
            subject: self.subject,
            protocol: self.protocol,
            client_ip: self.client_ip,
            server_ip: self.server_ip,
        }
    }
}

fn risk_score_from_fusion_details(raw: Option<&str>) -> Option<f64> {
    serde_json::from_str::<serde_json::Value>(raw?)
        .ok()?
        .get("risk_single")?
        .as_f64()
        .filter(|risk| (0.0..=1.0).contains(risk))
}

pub(crate) fn parse_threat_level(s: &str) -> ThreatLevel {
    match s {
        "safe" => ThreatLevel::Safe,
        "low" => ThreatLevel::Low,
        "medium" => ThreatLevel::Medium,
        "high" => ThreatLevel::High,
        "critical" => ThreatLevel::Critical,
        _ => ThreatLevel::Safe,
    }
}

pub(crate) fn parse_threat_type(s: &str) -> Option<ThreatType> {
    match s {
        "phishing" => Some(ThreatType::Phishing),
        "bec_fraud" => Some(ThreatType::BecFraud),
        "malware_delivery" => Some(ThreatType::MalwareDelivery),
        "mailbox_enumeration" => Some(ThreatType::MailboxEnumeration),
        "social_engineering" => Some(ThreatType::SocialEngineering),
        "injection_abuse" => Some(ThreatType::InjectionAbuse),
        "malicious_other" => Some(ThreatType::MaliciousOther),
        _ => None,
    }
}

pub(crate) fn parse_pillar(s: &str) -> Pillar {
    match s {
        "content" => Pillar::Content,
        "attachment" => Pillar::Attachment,
        "package" => Pillar::Package,
        "link" => Pillar::Link,
        "semantic" => Pillar::Semantic,
        _ => Pillar::Content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_verdict_sql_is_atomic_upsert_on_session_conflict() {
        // Regression: the 180s rescan sweep and the live stream consumer can
        // submit a verdict for the same session concurrently. The insert must
        // rely on the ux_security_verdicts_session unique index via a single
        // atomic UPSERT — a bare INSERT would either duplicate rows or error,
        // and a DELETE + INSERT pair reopens a lock/visibility window.
        assert!(UPSERT_VERDICT_SQL.contains("ON CONFLICT(session_id) DO UPDATE"));
        assert!(!UPSERT_VERDICT_SQL.contains("DELETE FROM security_verdicts"));
        // Newest analysis wins so re-scans (Active->Completed, explicit
        // rescan, quarantine release gate) actually replace the stale row.
        assert!(UPSERT_VERDICT_SQL.contains("threat_level = EXCLUDED.threat_level"));
        assert!(REBIND_ALERTS_TO_CURRENT_VERDICT_SQL.contains("UPDATE security_alerts"));
        assert!(REBIND_ALERTS_TO_CURRENT_VERDICT_SQL.contains("session_id = $1"));
        assert!(REBIND_ALERTS_TO_CURRENT_VERDICT_SQL.contains("verdict_id = $2"));
    }

    #[test]
    fn module_results_upsert_conflicts_on_session_and_module() {
        // Regression (C4): without a uniqueness guard, concurrent analyses of
        // one session (live stream vs catch-up rescan vs release rescan)
        // stacked two rows per module. The UPSERT must conflict on the
        // (session_id, module_id) unique index and update in place — including
        // verdict_id, so the row always points at the newest verdict.
        assert!(
            MODULE_RESULT_UPSERT_CLAUSE.contains("ON CONFLICT (session_id, module_id) DO UPDATE")
        );
        assert!(MODULE_RESULT_UPSERT_CLAUSE.contains("verdict_id = EXCLUDED.verdict_id"));
        assert!(MODULE_RESULT_UPSERT_CLAUSE.contains("threat_level = EXCLUDED.threat_level"));
        // A bare DELETE+INSERT rewrite must not come back: it reopens the
        // cross-analysis visibility window this UPSERT closes.
        assert!(!MODULE_RESULT_UPSERT_CLAUSE.contains("DELETE"));
    }

    #[test]
    fn stale_module_cleanup_is_scoped_to_session_and_current_modules() {
        // The stale-row sweep must only drop rows of THIS session whose module
        // did not run in the current analysis — never a blanket delete.
        assert!(DELETE_STALE_MODULE_RESULTS_SQL.contains("session_id = $1"));
        assert!(DELETE_STALE_MODULE_RESULTS_SQL.contains("NOT (module_id = ANY($2))"));
    }

    #[test]
    fn parse_threat_level_orders_all_levels() {
        assert!(parse_threat_level("critical") > parse_threat_level("high"));
        assert!(parse_threat_level("high") > parse_threat_level("medium"));
        assert!(parse_threat_level("medium") > parse_threat_level("low"));
        assert!(parse_threat_level("low") > parse_threat_level("safe"));
    }

    #[test]
    fn verdict_list_risk_is_parsed_separately_from_confidence() {
        assert_eq!(
            risk_score_from_fusion_details(Some(r#"{"risk_single":0.718,"eta":0.3}"#)),
            Some(0.718)
        );
        assert_eq!(risk_score_from_fusion_details(Some("{}")), None);
        assert_eq!(
            risk_score_from_fusion_details(Some(r#"{"risk_single":1.2}"#)),
            None
        );
        assert_eq!(risk_score_from_fusion_details(None), None);
    }

    #[test]
    fn database_timestamp_parser_accepts_legacy_postgres_text() {
        assert!(parse_db_datetime("2026-08-21T11:20:34.159657Z").is_ok());
        assert!(parse_db_datetime("2026-08-21 11:20:34.159657+00").is_ok());
    }

    #[test]
    fn level_count_map_keeps_positive_counts_and_preserves_level_identity() {
        let counts = level_counts_from_values([
            ("safe", 18),
            ("low", 3),
            ("medium", 0),
            ("high", 1),
            ("critical", 0),
        ]);

        assert_eq!(counts.get("safe"), Some(&18));
        assert_eq!(counts.get("low"), Some(&3));
        assert_eq!(counts.get("high"), Some(&1));
        assert!(!counts.contains_key("medium"));
        assert!(!counts.contains_key("critical"));
    }
}
