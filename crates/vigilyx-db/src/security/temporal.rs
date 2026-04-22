//! (CUSUM, EWMA, EntityRisk)

use anyhow::Result;
use chrono::Utc;

use vigilyx_core::security::{CusumState, DualEwmaState, EntityRiskState};

use crate::VigilDb;

impl VigilDb {
    /// CUSUM
    pub async fn save_cusum_states(&self, states: &[CusumState]) -> Result<()> {
        if states.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut tx = self.pool.begin().await?;
        for s in states {
            sqlx::query(
                r#"
                INSERT INTO security_temporal_cusum
                    (entity_key, s_pos, s_neg, mu_0, sample_count,
                     alarm_active, running_sum, running_sq_sum, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT(entity_key) DO UPDATE SET
                    s_pos = EXCLUDED.s_pos,
                    s_neg = EXCLUDED.s_neg,
                    mu_0 = EXCLUDED.mu_0,
                    sample_count = EXCLUDED.sample_count,
                    alarm_active = EXCLUDED.alarm_active,
                    running_sum = EXCLUDED.running_sum,
                    running_sq_sum = EXCLUDED.running_sq_sum,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(&s.entity_key)
            .bind(s.s_pos)
            .bind(s.s_neg)
            .bind(s.mu_0)
            .bind(s.sample_count as i64)
            .bind(s.alarm_active)
            .bind(s.running_sum)
            .bind(s.running_sq_sum)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
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
        for s in states {
            sqlx::query(
                r#"
                INSERT INTO security_temporal_ewma
                    (entity_key, fast_value, slow_value, initialized,
                     observation_count, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT(entity_key) DO UPDATE SET
                    fast_value = EXCLUDED.fast_value,
                    slow_value = EXCLUDED.slow_value,
                    initialized = EXCLUDED.initialized,
                    observation_count = EXCLUDED.observation_count,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(&s.entity_key)
            .bind(s.fast_value)
            .bind(s.slow_value)
            .bind(s.initialized)
            .bind(s.observation_count as i64)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
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
        for s in states {
            sqlx::query(
                r#"
                INSERT INTO security_entity_risk
                    (entity_key, risk_value, alpha, email_count, updated_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT(entity_key) DO UPDATE SET
                    risk_value = EXCLUDED.risk_value,
                    alpha = EXCLUDED.alpha,
                    email_count = EXCLUDED.email_count,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(&s.entity_key)
            .bind(s.risk_value)
            .bind(s.alpha)
            .bind(s.email_count as i64)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
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
        self.save_cusum_states(cusum).await?;
        self.save_ewma_states(ewma).await?;
        self.save_entity_risk_states(entity).await?;
        Ok(())
    }
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
