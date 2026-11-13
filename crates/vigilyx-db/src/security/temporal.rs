//! (CUSUM, EWMA, EntityRisk)

use anyhow::Result;
use chrono::Utc;

use vigilyx_core::security::{CusumState, DualEwmaState, EntityRiskState};

use crate::VigilDb;

const TEMPORAL_BATCH_SIZE: usize = 500;

impl VigilDb {
    /// CUSUM
    pub async fn save_cusum_states(&self, states: &[CusumState]) -> Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await?;
        upsert_cusum_batch(&mut tx, states, &now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Load CUSUM
    pub async fn load_cusum_states(&self) -> Result<Vec<CusumState>> {
        let rows: Vec<CusumRow> = sqlx::query_as(
            "SELECT entity_key, s_pos, s_neg, mu_0, sample_count, alarm_active, running_sum, running_sq_sum FROM security_temporal_cusum",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.into_state()).collect())
    }

    /// EWMA
    pub async fn save_ewma_states(&self, states: &[DualEwmaState]) -> Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await?;
        upsert_ewma_batch(&mut tx, states, &now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Load EWMA
    pub async fn load_ewma_states(&self) -> Result<Vec<DualEwmaState>> {
        let rows: Vec<EwmaRow> = sqlx::query_as(
            "SELECT entity_key, fast_value, slow_value, initialized, observation_count FROM security_temporal_ewma",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.into_state()).collect())
    }

    pub async fn save_entity_risk_states(&self, states: &[EntityRiskState]) -> Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await?;
        upsert_entity_batch(&mut tx, states, &now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Load
    pub async fn load_entity_risk_states(&self) -> Result<Vec<EntityRiskState>> {
        let rows: Vec<EntityRiskRow> = sqlx::query_as(
            "SELECT entity_key, risk_value, alpha, email_count FROM security_entity_risk",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.into_state()).collect())
    }

    pub async fn flush_temporal_states(
        &self,
        cusum: &[CusumState],
        ewma: &[DualEwmaState],
        entity: &[EntityRiskState],
    ) -> Result<()> {
        if cusum.is_empty() && ewma.is_empty() && entity.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await?;
        upsert_cusum_batch(&mut tx, cusum, &now).await?;
        upsert_ewma_batch(&mut tx, ewma, &now).await?;
        upsert_entity_batch(&mut tx, entity, &now).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn upsert_cusum_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    states: &[CusumState],
    now: &str,
) -> Result<()> {
    for chunk in states.chunks(TEMPORAL_BATCH_SIZE) {
        let mut sql = String::from(
            "INSERT INTO security_temporal_cusum (entity_key, s_pos, s_neg, mu_0, sample_count, alarm_active, running_sum, running_sq_sum, updated_at) VALUES ",
        );
        for (row_idx, _) in chunk.iter().enumerate() {
            if row_idx > 0 {
                sql.push_str(", ");
            }
            let first = row_idx * 9 + 1;
            sql.push_str(&format!(
                "(${0}, ${1}, ${2}, ${3}, ${4}, ${5}, ${6}, ${7}, ${8})",
                first,
                first + 1,
                first + 2,
                first + 3,
                first + 4,
                first + 5,
                first + 6,
                first + 7,
                first + 8
            ));
        }
        sql.push_str(
            " ON CONFLICT(entity_key) DO UPDATE SET s_pos = EXCLUDED.s_pos, s_neg = EXCLUDED.s_neg, mu_0 = EXCLUDED.mu_0, sample_count = EXCLUDED.sample_count, alarm_active = EXCLUDED.alarm_active, running_sum = EXCLUDED.running_sum, running_sq_sum = EXCLUDED.running_sq_sum, updated_at = EXCLUDED.updated_at",
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for state in chunk {
            query = query
                .bind(&state.entity_key)
                .bind(state.s_pos)
                .bind(state.s_neg)
                .bind(state.mu_0)
                .bind(state.sample_count as i64)
                .bind(state.alarm_active)
                .bind(state.running_sum)
                .bind(state.running_sq_sum)
                .bind(now);
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

async fn upsert_ewma_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    states: &[DualEwmaState],
    now: &str,
) -> Result<()> {
    for chunk in states.chunks(TEMPORAL_BATCH_SIZE) {
        let mut sql = String::from(
            "INSERT INTO security_temporal_ewma (entity_key, fast_value, slow_value, initialized, observation_count, updated_at) VALUES ",
        );
        for (row_idx, _) in chunk.iter().enumerate() {
            if row_idx > 0 {
                sql.push_str(", ");
            }
            let first = row_idx * 6 + 1;
            sql.push_str(&format!(
                "(${0}, ${1}, ${2}, ${3}, ${4}, ${5})",
                first,
                first + 1,
                first + 2,
                first + 3,
                first + 4,
                first + 5
            ));
        }
        sql.push_str(
            " ON CONFLICT(entity_key) DO UPDATE SET fast_value = EXCLUDED.fast_value, slow_value = EXCLUDED.slow_value, initialized = EXCLUDED.initialized, observation_count = EXCLUDED.observation_count, updated_at = EXCLUDED.updated_at",
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for state in chunk {
            query = query
                .bind(&state.entity_key)
                .bind(state.fast_value)
                .bind(state.slow_value)
                .bind(state.initialized)
                .bind(state.observation_count as i64)
                .bind(now);
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

async fn upsert_entity_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    states: &[EntityRiskState],
    now: &str,
) -> Result<()> {
    for chunk in states.chunks(TEMPORAL_BATCH_SIZE) {
        let mut sql = String::from(
            "INSERT INTO security_entity_risk (entity_key, risk_value, alpha, email_count, updated_at) VALUES ",
        );
        for (row_idx, _) in chunk.iter().enumerate() {
            if row_idx > 0 {
                sql.push_str(", ");
            }
            let first = row_idx * 5 + 1;
            sql.push_str(&format!(
                "(${0}, ${1}, ${2}, ${3}, ${4})",
                first,
                first + 1,
                first + 2,
                first + 3,
                first + 4
            ));
        }
        sql.push_str(
            " ON CONFLICT(entity_key) DO UPDATE SET risk_value = EXCLUDED.risk_value, alpha = EXCLUDED.alpha, email_count = EXCLUDED.email_count, updated_at = EXCLUDED.updated_at",
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for state in chunk {
            query = query
                .bind(&state.entity_key)
                .bind(state.risk_value)
                .bind(state.alpha)
                .bind(state.email_count as i64)
                .bind(now);
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

// Database row type

#[derive(Debug, sqlx::FromRow)]
struct CusumRow {
    entity_key: String,
    s_pos: f64,
    s_neg: f64,
    mu_0: f64,
    sample_count: i64,
    alarm_active: bool,
    running_sum: f64,
    running_sq_sum: f64,
}

impl CusumRow {
    fn into_state(self) -> CusumState {
        CusumState {
            entity_key: self.entity_key,
            s_pos: self.s_pos,
            s_neg: self.s_neg,
            mu_0: self.mu_0,
            sample_count: self.sample_count as u64,
            alarm_active: self.alarm_active,
            running_sum: self.running_sum,
            running_sq_sum: self.running_sq_sum,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct EwmaRow {
    entity_key: String,
    fast_value: f64,
    slow_value: f64,
    initialized: bool,
    observation_count: i64,
}

impl EwmaRow {
    fn into_state(self) -> DualEwmaState {
        DualEwmaState {
            entity_key: self.entity_key,
            fast_value: self.fast_value,
            slow_value: self.slow_value,
            initialized: self.initialized,
            observation_count: self.observation_count as u64,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct EntityRiskRow {
    entity_key: String,
    risk_value: f64,
    alpha: f64,
    email_count: i64,
}

impl EntityRiskRow {
    fn into_state(self) -> EntityRiskState {
        EntityRiskState {
            entity_key: self.entity_key,
            risk_value: self.risk_value,
            alpha: self.alpha,
            email_count: self.email_count as u64,
        }
    }
}
