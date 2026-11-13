//! Cross-message IOC telemetry and the read-only Shadow scoring model.
//!
//! This module records facts and derives an explainable candidate score. It
//! never mutates `security_ioc.confidence` and never participates in the live
//! verdict or delivery disposition path.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;
use vigilyx_core::security::ioc_shadow::{IocShadowScore, score_from_counts};

use crate::VigilDb;

const DEFAULT_HALF_LIFE_HOURS: f64 = 720.0;
const DEFAULT_PRIOR_MALICIOUS_COUNT: u64 = 5;
const DEFAULT_PRIOR_MESSAGE_COUNT: u64 = 1_000;

/// One analyzed message in the local IOC denominator population.
#[derive(Debug, Clone)]
pub struct IocMessageObservation {
    pub session_id: Uuid,
    pub verdict_id: Uuid,
    pub direction: String,
    pub threat_level: String,
    pub engine_confidence: f64,
    pub observed_at: DateTime<Utc>,
    pub capture_coverage: String,
}

/// One normalized indicator observed in one message.
#[derive(Debug, Clone)]
pub struct IocIndicatorObservation {
    pub session_id: Uuid,
    pub verdict_id: Uuid,
    pub indicator: String,
    pub ioc_type: String,
    pub source_detector: String,
    pub detector_family: String,
    pub external_provider: String,
    pub evidence_cluster: String,
    pub activity_key: String,
    pub direction: String,
    pub threat_level: String,
    pub engine_confidence: f64,
    pub observed_at: DateTime<Utc>,
    pub capture_coverage: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocTrafficStats {
    pub observed_count: u64,
    pub outbound_count: u64,
    pub inbound_count: u64,
    pub unknown_direction_count: u64,
    pub provisional_threat_count: u64,
    pub distinct_session_count: u64,
    pub distinct_activity_count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocOutcomeCounts {
    pub malicious: u64,
    pub normal: u64,
    pub unresolved: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocEvidenceCluster {
    pub cluster: String,
    pub observations: u64,
    pub distinct_activities: u64,
    pub detector_families: u64,
    pub external_providers: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocShadowTelemetry {
    pub ioc_type: String,
    pub indicator: String,
    pub traffic: IocTrafficStats,
    pub outcomes: IocOutcomeCounts,
    pub score: IocShadowScore,
    pub prior_source: String,
    pub calibration_status: String,
    pub half_life_hours: f64,
    pub age_seconds: i64,
    pub clusters: Vec<IocEvidenceCluster>,
    pub actionability: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocReliabilityBin {
    pub lower: f64,
    pub upper: f64,
    pub sample_count: u64,
    pub predicted_mean: f64,
    pub observed_malicious_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocCalibrationSummary {
    pub status: String,
    pub labeled_observations: u64,
    pub malicious_observations: u64,
    pub normal_observations: u64,
    pub brier_score: Option<f64>,
    pub reliability: Vec<IocReliabilityBin>,
    pub note: String,
}

#[derive(Debug, sqlx::FromRow)]
struct TrafficRow {
    observed_count: i64,
    outbound_count: i64,
    inbound_count: i64,
    unknown_direction_count: i64,
    provisional_threat_count: i64,
    distinct_session_count: i64,
    distinct_activity_count: i64,
    first_seen: String,
    last_seen: String,
}

fn count(value: i64) -> u64 {
    value.max(0) as u64
}

fn parse_timestamp(value: &str, fallback: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or(fallback)
}

fn default_half_life(ioc_type: &str) -> f64 {
    match ioc_type.to_ascii_lowercase().as_str() {
        "hash" => 24.0 * 365.0,
        "ip" => 24.0 * 7.0,
        "url" => 24.0 * 30.0,
        "domain" => 24.0 * 90.0,
        "email" => 24.0 * 30.0,
        "helo" | "x_mailer" => 24.0 * 14.0,
        _ => DEFAULT_HALF_LIFE_HOURS,
    }
}

impl VigilDb {
    /// Persist one message denominator row and deduplicated indicator rows.
    /// Replaying/rescanning a session is idempotent because both tables have
    /// session-scoped uniqueness constraints.
    pub async fn record_ioc_telemetry(
        &self,
        message: &IocMessageObservation,
        indicators: &[IocIndicatorObservation],
    ) -> Result<usize> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO security_ioc_message_population
                (session_id, verdict_id, direction, threat_level, engine_confidence,
                 observed_at, capture_coverage)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (session_id) DO UPDATE SET
                verdict_id = EXCLUDED.verdict_id,
                direction = EXCLUDED.direction,
                threat_level = EXCLUDED.threat_level,
                engine_confidence = EXCLUDED.engine_confidence,
                observed_at = EXCLUDED.observed_at,
                capture_coverage = EXCLUDED.capture_coverage
            "#,
        )
        .bind(message.session_id.to_string())
        .bind(message.verdict_id.to_string())
        .bind(&message.direction)
        .bind(&message.threat_level)
        .bind(message.engine_confidence.clamp(0.0, 1.0))
        .bind(message.observed_at.to_rfc3339())
        .bind(&message.capture_coverage)
        .execute(&mut *tx)
        .await?;

        let mut inserted = 0usize;
        for indicator in indicators {
            let result = sqlx::query(
                r#"
                INSERT INTO security_ioc_observations
                    (id, session_id, verdict_id, indicator, ioc_type,
                     source_detector, detector_family, external_provider,
                     evidence_cluster, activity_key, direction, threat_level,
                     engine_confidence, observed_at, capture_coverage)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (session_id, ioc_type, indicator) DO NOTHING
                "#,
            )
            .bind(Uuid::new_v4().to_string())
            .bind(indicator.session_id.to_string())
            .bind(indicator.verdict_id.to_string())
            .bind(&indicator.indicator)
            .bind(&indicator.ioc_type)
            .bind(&indicator.source_detector)
            .bind(&indicator.detector_family)
            .bind(&indicator.external_provider)
            .bind(&indicator.evidence_cluster)
            .bind(&indicator.activity_key)
            .bind(&indicator.direction)
            .bind(&indicator.threat_level)
            .bind(indicator.engine_confidence.clamp(0.0, 1.0))
            .bind(indicator.observed_at.to_rfc3339())
            .bind(&indicator.capture_coverage)
            .execute(&mut *tx)
            .await?;

            if result.rows_affected() == 0 {
                continue;
            }
            inserted += 1;

            sqlx::query(
                r#"
                INSERT INTO security_ioc_traffic_stats
                    (ioc_type, indicator, observed_count, outbound_count,
                     inbound_count, unknown_direction_count, provisional_threat_count,
                     distinct_session_count, distinct_activity_count,
                     first_seen, last_seen)
                VALUES (
                    $1, $2, 1,
                    CASE WHEN $3 = 'outbound' THEN 1 ELSE 0 END,
                    CASE WHEN $3 = 'inbound' THEN 1 ELSE 0 END,
                    CASE WHEN $3 = 'unknown' THEN 1 ELSE 0 END,
                    CASE WHEN $4 IN ('low', 'medium', 'high', 'critical') THEN 1 ELSE 0 END,
                    1, 1, $5, $5
                )
                ON CONFLICT (ioc_type, indicator) DO UPDATE SET
                    observed_count = security_ioc_traffic_stats.observed_count + 1,
                    outbound_count = security_ioc_traffic_stats.outbound_count
                        + CASE WHEN $3 = 'outbound' THEN 1 ELSE 0 END,
                    inbound_count = security_ioc_traffic_stats.inbound_count
                        + CASE WHEN $3 = 'inbound' THEN 1 ELSE 0 END,
                    unknown_direction_count = security_ioc_traffic_stats.unknown_direction_count
                        + CASE WHEN $3 = 'unknown' THEN 1 ELSE 0 END,
                    provisional_threat_count = security_ioc_traffic_stats.provisional_threat_count
                        + CASE WHEN $4 IN ('low', 'medium', 'high', 'critical') THEN 1 ELSE 0 END,
                    distinct_session_count = (
                        SELECT COUNT(DISTINCT session_id)
                        FROM security_ioc_observations
                        WHERE ioc_type = $1 AND indicator = $2
                    ),
                    distinct_activity_count = (
                        SELECT COUNT(DISTINCT activity_key)
                        FROM security_ioc_observations
                        WHERE ioc_type = $1 AND indicator = $2
                    ),
                    first_seen = LEAST(security_ioc_traffic_stats.first_seen, $5),
                    last_seen = GREATEST(security_ioc_traffic_stats.last_seen, $5)
                "#,
            )
            .bind(&indicator.ioc_type)
            .bind(&indicator.indicator)
            .bind(&indicator.direction)
            .bind(indicator.threat_level.to_ascii_lowercase())
            .bind(indicator.observed_at.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(inserted)
    }

    /// Save a human or delivery outcome for the message and every IOC seen in
    /// it. Outcome history is append-only; Shadow queries select the latest
    /// outcome per session so a later adjudication can reverse an earlier weak
    /// label without deleting the audit trail.
    pub async fn record_ioc_outcome_for_session(
        &self,
        session_id: Uuid,
        verdict_id: Option<Uuid>,
        outcome: &str,
        source: &str,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<u64> {
        let normalized = outcome.trim().to_ascii_lowercase();
        if !matches!(normalized.as_str(), "normal" | "malicious") {
            anyhow::bail!("unsupported IOC outcome: {outcome}");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO security_ioc_message_outcomes
                (session_id, verdict_id, outcome, source, actor, reason, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW()::TEXT)
            "#,
        )
        .bind(session_id.to_string())
        .bind(verdict_id.map(|id| id.to_string()))
        .bind(&normalized)
        .bind(source)
        .bind(actor)
        .bind(reason)
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query(
            r#"
            INSERT INTO security_ioc_outcomes
                (session_id, verdict_id, ioc_type, indicator, outcome,
                 source, actor, reason, created_at)
            SELECT o.session_id, $2, o.ioc_type,
                   o.indicator, $3, $4, $5, $6, NOW()::TEXT
            FROM security_ioc_observations o
            WHERE o.session_id = $1
            "#,
        )
        .bind(session_id.to_string())
        .bind(verdict_id.map(|id| id.to_string()))
        .bind(&normalized)
        .bind(source)
        .bind(actor)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Calculate one indicator's current Shadow read model.
    pub async fn get_ioc_shadow_telemetry(
        &self,
        ioc_type: &str,
        indicator: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<IocShadowTelemetry>> {
        let stats = sqlx::query_as::<_, TrafficRow>(
            r#"SELECT observed_count, outbound_count, inbound_count,
                      unknown_direction_count, provisional_threat_count,
                      distinct_session_count, distinct_activity_count,
                      first_seen, last_seen
               FROM security_ioc_traffic_stats
               WHERE ioc_type = $1 AND indicator = $2"#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .fetch_optional(&self.pool)
        .await?;
        let Some(stats) = stats else {
            return Ok(None);
        };

        let outcome_counts: (i64, i64) = sqlx::query_as(
            r#"
            WITH latest AS (
                SELECT DISTINCT ON (session_id) session_id, outcome
                FROM security_ioc_outcomes
                WHERE ioc_type = $1 AND indicator = $2
                ORDER BY session_id, created_at DESC, id DESC
            )
            SELECT COUNT(*) FILTER (WHERE outcome = 'malicious'),
                   COUNT(*) FILTER (WHERE outcome = 'normal')
            FROM latest
            "#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .fetch_one(&self.pool)
        .await?;

        let global_labeled: (i64, i64) = sqlx::query_as(
            r#"
            WITH latest AS (
                SELECT DISTINCT ON (session_id) session_id, outcome
                FROM security_ioc_message_outcomes
                ORDER BY session_id, created_at DESC, id DESC
            )
            SELECT COUNT(*) FILTER (WHERE outcome = 'malicious'),
                   COUNT(*) FILTER (WHERE outcome = 'normal')
            FROM latest
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let feature_labeled: (i64, i64) = sqlx::query_as(
            r#"
            WITH latest AS (
                SELECT DISTINCT ON (session_id) session_id, outcome
                FROM security_ioc_message_outcomes
                ORDER BY session_id, created_at DESC, id DESC
            )
            SELECT COUNT(*) FILTER (WHERE latest.outcome = 'malicious'),
                   COUNT(*) FILTER (WHERE latest.outcome = 'normal')
            FROM security_ioc_observations observations
            JOIN latest ON latest.session_id = observations.session_id
            WHERE observations.ioc_type = $1 AND observations.indicator = $2
            "#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .fetch_one(&self.pool)
        .await?;

        let provisional_global: (i64, i64) = sqlx::query_as(
            r#"SELECT COUNT(*) FILTER (WHERE LOWER(threat_level) IN ('high', 'critical')),
                      COUNT(*) FILTER (WHERE LOWER(threat_level) IN ('safe', 'low'))
               FROM security_ioc_message_population"#,
        )
        .fetch_one(&self.pool)
        .await?;
        let provisional_feature: (i64, i64) = sqlx::query_as(
            r#"SELECT COUNT(*) FILTER (WHERE LOWER(threat_level) IN ('high', 'critical')),
                      COUNT(*) FILTER (WHERE LOWER(threat_level) IN ('safe', 'low'))
               FROM security_ioc_observations
               WHERE ioc_type = $1 AND indicator = $2"#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .fetch_one(&self.pool)
        .await?;

        let use_labels = global_labeled.0 > 0 && global_labeled.1 > 0;
        let (
            prior_malicious,
            prior_total,
            malicious_feature,
            normal_feature,
            malicious_messages,
            normal_messages,
            prior_source,
            calibration_status,
        ) = if use_labels {
            (
                count(global_labeled.0),
                count(global_labeled.0) + count(global_labeled.1),
                count(feature_labeled.0),
                count(feature_labeled.1),
                count(global_labeled.0),
                count(global_labeled.1),
                "outcome_labels".to_string(),
                "labeled".to_string(),
            )
        } else if provisional_global.0 > 0 && provisional_global.1 > 0 {
            (
                count(provisional_global.0),
                count(provisional_global.0) + count(provisional_global.1),
                count(provisional_feature.0),
                count(provisional_feature.1),
                count(provisional_global.0),
                count(provisional_global.1),
                "provisional_verdicts".to_string(),
                "provisional_only".to_string(),
            )
        } else {
            (
                DEFAULT_PRIOR_MALICIOUS_COUNT,
                DEFAULT_PRIOR_MESSAGE_COUNT,
                0,
                0,
                DEFAULT_PRIOR_MESSAGE_COUNT,
                DEFAULT_PRIOR_MESSAGE_COUNT.saturating_sub(DEFAULT_PRIOR_MALICIOUS_COUNT),
                "configured_default".to_string(),
                "hypothesis_only".to_string(),
            )
        };

        let configured_half_life = sqlx::query_scalar::<_, f64>(
            "SELECT half_life_hours FROM security_ioc_shadow_type_config WHERE ioc_type = $1",
        )
        .bind(ioc_type)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or_else(|| default_half_life(ioc_type));
        let last_seen = parse_timestamp(&stats.last_seen, now);
        let age_seconds = now.signed_duration_since(last_seen).num_seconds().max(0);
        let score = score_from_counts(
            prior_malicious,
            prior_total,
            malicious_feature,
            normal_feature,
            malicious_messages,
            normal_messages,
            age_seconds,
            configured_half_life,
        );

        let cluster_rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
            r#"SELECT evidence_cluster, COUNT(*), COUNT(DISTINCT activity_key),
                      COUNT(DISTINCT detector_family), COUNT(DISTINCT external_provider)
               FROM security_ioc_observations
               WHERE ioc_type = $1 AND indicator = $2
               GROUP BY evidence_cluster ORDER BY evidence_cluster"#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .fetch_all(&self.pool)
        .await?;

        let traffic = IocTrafficStats {
            observed_count: count(stats.observed_count),
            outbound_count: count(stats.outbound_count),
            inbound_count: count(stats.inbound_count),
            unknown_direction_count: count(stats.unknown_direction_count),
            provisional_threat_count: count(stats.provisional_threat_count),
            distinct_session_count: count(stats.distinct_session_count),
            distinct_activity_count: count(stats.distinct_activity_count),
            first_seen: stats.first_seen,
            last_seen: stats.last_seen,
        };
        Ok(Some(IocShadowTelemetry {
            ioc_type: ioc_type.to_string(),
            indicator: indicator.to_string(),
            traffic,
            outcomes: IocOutcomeCounts {
                malicious: count(outcome_counts.0),
                normal: count(outcome_counts.1),
                unresolved: count(stats.distinct_session_count)
                    .saturating_sub(count(outcome_counts.0) + count(outcome_counts.1)),
            },
            score,
            prior_source,
            calibration_status,
            half_life_hours: configured_half_life,
            age_seconds,
            clusters: cluster_rows
                .into_iter()
                .map(
                    |(cluster, observations, activities, detectors, providers)| {
                        IocEvidenceCluster {
                            cluster,
                            observations: count(observations),
                            distinct_activities: count(activities),
                            detector_families: count(detectors),
                            external_providers: count(providers),
                        }
                    },
                )
                .collect(),
            actionability: "shadow_only".to_string(),
        }))
    }

    /// Produce a bounded reliability/Brier summary from the latest labeled
    /// outcome per session/IOC. This is deliberately a diagnostic aggregate;
    /// it is not a release gate and does not claim an independent holdout.
    pub async fn get_ioc_calibration_summary(
        &self,
        limit: u32,
        now: DateTime<Utc>,
    ) -> Result<IocCalibrationSummary> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT ioc_type, indicator, outcome
            FROM (
                SELECT DISTINCT ON (session_id, ioc_type, indicator)
                       ioc_type, indicator, outcome, session_id, created_at, id
                FROM security_ioc_outcomes
                WHERE outcome IN ('malicious', 'normal')
                ORDER BY session_id, ioc_type, indicator, created_at DESC, id DESC
            ) latest
            ORDER BY created_at DESC, id DESC
            LIMIT $1
            "#,
        )
        .bind(i64::from(limit.clamp(1, 500)))
        .fetch_all(&self.pool)
        .await?;

        let mut score_cache = HashMap::<(String, String), f64>::new();
        let mut brier_sum = 0.0;
        let mut malicious = 0u64;
        let mut normal = 0u64;
        let mut bins = (0..10).map(|_| (0u64, 0.0f64, 0u64)).collect::<Vec<_>>();

        for (ioc_type, indicator, outcome) in rows {
            let key = (ioc_type.clone(), indicator.clone());
            let probability = if let Some(probability) = score_cache.get(&key) {
                *probability
            } else {
                let Some(telemetry) = self
                    .get_ioc_shadow_telemetry(&ioc_type, &indicator, now)
                    .await?
                else {
                    continue;
                };
                let probability = telemetry.score.probability;
                score_cache.insert(key, probability);
                probability
            };
            let observed = if outcome == "malicious" {
                malicious += 1;
                1.0
            } else {
                normal += 1;
                0.0
            };
            brier_sum += (probability - observed).powi(2);
            let bin_index = ((probability * 10.0).floor() as usize).min(9);
            bins[bin_index].0 += 1;
            bins[bin_index].1 += probability;
            bins[bin_index].2 += if observed > 0.5 { 1 } else { 0 };
        }

        let labeled_observations = malicious + normal;
        let reliability = bins
            .into_iter()
            .enumerate()
            .filter(|(_, (n, _, _))| *n > 0)
            .map(
                |(index, (n, predicted_sum, malicious_count))| IocReliabilityBin {
                    lower: index as f64 / 10.0,
                    upper: (index + 1) as f64 / 10.0,
                    sample_count: n,
                    predicted_mean: predicted_sum / n as f64,
                    observed_malicious_rate: malicious_count as f64 / n as f64,
                },
            )
            .collect();
        Ok(IocCalibrationSummary {
            status: "hypothesis_only".to_string(),
            labeled_observations,
            malicious_observations: malicious,
            normal_observations: normal,
            brier_score: (labeled_observations > 0).then(|| brier_sum / labeled_observations as f64),
            reliability,
            note: "Development aggregate only; independent validation, holdout, blind review, and capability preservation are still required before release.".to_string(),
        })
    }
}
