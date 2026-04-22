//! Security (Verdict) Module (ModuleResult) Data

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::security::{Bpa, ModuleResult, Pillar, SecurityVerdict, ThreatLevel};

use crate::VigilDb;

/// + metadata (Used for)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerdictWithMeta {
    pub verdict_id: String,
    pub session_id: String,
    pub threat_level: String,
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

impl VigilDb {
    /// Security (DELETE + INSERT 1)
    pub async fn insert_verdict(&self, verdict: &SecurityVerdict) -> Result<()> {
        let categories_json = serde_json::to_string(&verdict.categories)?;
        let pillar_scores_json = serde_json::to_string(&verdict.pillar_scores)?;
        let fusion_details_json = verdict
            .fusion_details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let mut tx = self.pool.begin().await?;

        // session verdict,
        sqlx::query("DELETE FROM security_verdicts WHERE session_id = $1")
            .bind(verdict.session_id.to_string())
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO security_verdicts
                (id, session_id, threat_level, confidence, categories, summary,
                 pillar_scores, modules_run, modules_flagged, total_duration_ms,
                 created_at, fusion_details)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT(id) DO UPDATE SET
                session_id = EXCLUDED.session_id,
                threat_level = EXCLUDED.threat_level,
                confidence = EXCLUDED.confidence,
                categories = EXCLUDED.categories,
                summary = EXCLUDED.summary,
                pillar_scores = EXCLUDED.pillar_scores,
                modules_run = EXCLUDED.modules_run,
                modules_flagged = EXCLUDED.modules_flagged,
                total_duration_ms = EXCLUDED.total_duration_ms,
                created_at = EXCLUDED.created_at,
                fusion_details = EXCLUDED.fusion_details
            "#,
        )
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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Module (INSERT)
    ///
    /// VALUES INSERT, N DB ceil(N/CHUNK).
    /// 17 x 500 = 8500,Security.
    pub async fn insert_module_results(
        &self,
        verdict_id: Uuid,
        session_id: Uuid,
        results: &[&ModuleResult],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // session Module,
        sqlx::query("DELETE FROM security_module_results WHERE session_id = $1")
            .bind(session_id.to_string())
            .execute(&mut *tx)
            .await?;

        if results.is_empty() {
            tx.commit().await?;
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
        let sid = session_id.to_string();

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

            let mut query = sqlx::query(&sql);
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
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// session Security
    pub async fn get_verdict_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<SecurityVerdict>> {
        let row = sqlx::query_as::<_, VerdictRow>(
            r#"
            SELECT id, session_id, threat_level, confidence, categories, summary,
                   pillar_scores, modules_run, modules_flagged, total_duration_ms, created_at,
                   fusion_details
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
            WITH latest_verdict AS (
                SELECT id FROM security_verdicts
                WHERE session_id = $1
                ORDER BY created_at DESC
                LIMIT 1
            )
            SELECT module_id, module_name, pillar, threat_level, confidence,
                   categories, summary, evidence, details, duration_ms, analyzed_at,
                   bpa_b, bpa_d, bpa_u, engine_id
            FROM security_module_results
            WHERE session_id = $1
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
            r#"SELECT v.id, v.session_id, v.threat_level, v.confidence,
                      v.categories, v.summary, v.modules_run, v.modules_flagged,
                      v.total_duration_ms, v.created_at,
                      s.mail_from, s.rcpt_to, s.subject, s.protocol,
                      s.client_ip, s.server_ip
               FROM security_verdicts v
               INNER JOIN sessions s ON v.session_id = s.id
               WHERE s.mail_from IS NOT NULL"#,
        );
        let mut binds: Vec<String> = Vec::new();

        // Level: "medium,high,critical"
        let threat_filter_clause: String;
        if let Some(level) = threat_level {
            let levels: Vec<&str> = level
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if levels.len() == 1 {
                binds.push(levels[0].to_string());
                threat_filter_clause = format!(" AND v.threat_level = ${}", binds.len());
            } else {
                let placeholders: Vec<String> = levels
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        binds.push(levels[i].to_string());
                        format!("${}", binds.len())
                    })
                    .collect();
                threat_filter_clause =
                    format!(" AND v.threat_level IN ({})", placeholders.join(","));
            }
        } else {
            // Level: DefaultExclude safe (Security)
            threat_filter_clause = " AND v.threat_level != 'safe'".to_string();
        }
        sql.push_str(&threat_filter_clause);

        // Get total count (same filter: only real emails)
        let count_sql = format!(
            r#"SELECT COUNT(*) FROM security_verdicts v
               INNER JOIN sessions s ON v.session_id = s.id
               WHERE s.mail_from IS NOT NULL{}"#,
            &threat_filter_clause,
        );

        let total: (i64,) = {
            let mut q = sqlx::query_as(&count_sql);
            for b in &binds {
                q = q.bind(b);
            }
            q.fetch_one(&self.pool).await?
        };

        sql.push_str(" ORDER BY v.created_at DESC");
        let limit_idx = binds.len() + 1;
        let offset_idx = binds.len() + 2;
        sql.push_str(&format!(" LIMIT ${}", limit_idx));
        sql.push_str(&format!(" OFFSET ${}", offset_idx));

        let rows: Vec<VerdictMetaRow> = {
            let mut q = sqlx::query_as(&sql);
            for b in &binds {
                q = q.bind(b);
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
        // Query: Merge, According to Level, 24h, IOC (4 -> 1 DB)
        let row: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN v.threat_level = 'safe' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN v.threat_level = 'low' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN v.threat_level = 'medium' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN v.threat_level = 'high' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN v.threat_level = 'critical' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN v.threat_level IN ('high', 'critical')
                          AND v.created_at::timestamptz > NOW() - INTERVAL '24 hours' THEN 1 ELSE 0 END), 0)::BIGINT,
                (SELECT COUNT(*) FROM security_ioc)
            FROM security_verdicts v
            INNER JOIN sessions s ON v.session_id = s.id
            WHERE s.mail_from IS NOT NULL
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let mut level_counts = std::collections::HashMap::new();
        if row.1 > 0 {
            level_counts.insert("safe".to_string(), row.1 as u64);
        }
        if row.2 > 0 {
            level_counts.insert("low".to_string(), row.2 as u64);
        }
        if row.3 > 0 {
            level_counts.insert("medium".to_string(), row.3 as u64);
        }
        if row.4 > 0 {
            level_counts.insert("high".to_string(), row.4 as u64);
        }
        if row.5 > 0 {
            level_counts.insert("critical".to_string(), row.5 as u64);
        }

        Ok(vigilyx_core::security::SecurityStats {
            total_scanned: row.0 as u64,
            level_counts,
            high_threats_24h: row.6 as u64,
            ioc_count: row.7 as u64,
        })
    }
}

// Database row type (sqlx)

#[derive(Debug, sqlx::FromRow)]
struct VerdictRow {
    id: String,
    session_id: String,
    threat_level: String,
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
            .map(serde_json::from_str)
            .transpose()?;

        Ok(SecurityVerdict {
            id: Uuid::parse_str(&self.id)?,
            session_id: Uuid::parse_str(&self.session_id)?,
            threat_level: parse_threat_level(&self.threat_level),
            confidence: self.confidence,
            categories: serde_json::from_str(&self.categories)?,
            summary: self.summary,
            pillar_scores: serde_json::from_str(&self.pillar_scores)?,
            modules_run: self.modules_run as u32,
            modules_flagged: self.modules_flagged as u32,
            total_duration_ms: self.total_duration_ms as u64,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)?.with_timezone(&Utc),
            fusion_details,
        })
    }
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
    id: String,
    session_id: String,
    threat_level: String,
    confidence: f64,
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
        VerdictWithMeta {
            verdict_id: self.id,
            session_id: self.session_id,
            threat_level: self.threat_level,
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
