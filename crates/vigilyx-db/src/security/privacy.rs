//! Persistence for the server-side privacy dual-control boundary.
//!
//! This module deliberately stores only verifier material, request metadata,
//! lease metadata, and structured audit events.  It never stores operator
//! factors, lease handles, plaintext, attachment bytes, or reconstructed EML.

use anyhow::{Result, anyhow};
use serde::Serialize;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::VigilDb;
use crate::infra::migrate::record_migration;

const PRIVACY_MIGRATION: &str = "122_privacy_dual_control";

#[derive(Debug, Clone, Serialize)]
pub struct PrivacyAccessRequest {
    #[serde(rename = "request_id")]
    pub id: String,
    #[serde(rename = "requester_id")]
    pub requester_user_id: String,
    #[serde(skip_serializing)]
    pub requester_session_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    pub status: String,
    pub expires_at: String,
    #[serde(rename = "approver_id")]
    pub approver_user_id: Option<String>,
    #[serde(skip_serializing)]
    pub approver_session_id: Option<String>,
    pub approved_at: Option<String>,
    pub rejected_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct PrivacyOperatorSecret {
    pub verifier: String,
    pub failed_attempts: i32,
    pub factor_version: i64,
    pub locked_until: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct PrivacyAccessRequestRow {
    id: String,
    requester_user_id: String,
    requester_session_id: String,
    resource_type: String,
    resource_id: String,
    scopes: String,
    purpose: String,
    status: String,
    expires_at: String,
    approver_user_id: Option<String>,
    approver_session_id: Option<String>,
    approved_at: Option<String>,
    rejected_at: Option<String>,
    created_at: String,
}

impl PrivacyAccessRequestRow {
    fn into_model(self) -> Result<PrivacyAccessRequest> {
        let scopes = serde_json::from_str(&self.scopes)
            .map_err(|error| anyhow!("invalid persisted privacy scope set: {error}"))?;
        Ok(PrivacyAccessRequest {
            id: self.id,
            requester_user_id: self.requester_user_id,
            requester_session_id: self.requester_session_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            scopes,
            purpose: self.purpose,
            status: self.status,
            expires_at: self.expires_at,
            approver_user_id: self.approver_user_id,
            approver_session_id: self.approver_session_id,
            approved_at: self.approved_at,
            rejected_at: self.rejected_at,
            created_at: self.created_at,
        })
    }
}

impl VigilDb {
    /// Create all privacy tables and indexes.  Every statement is additive and
    /// idempotent so API and engine startup can safely call this repeatedly.
    pub async fn init_privacy_tables(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS privacy_operator_secrets (
                user_id TEXT PRIMARY KEY REFERENCES platform_users(id) ON DELETE CASCADE,
                verifier TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMPTZ,
                factor_version BIGINT NOT NULL DEFAULT 1,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;

        // Existing installations may have created this table before factor
        // versioning was introduced.  CREATE TABLE IF NOT EXISTS does not
        // alter such tables, so keep the rollout explicitly additive.
        sqlx::query(
            "ALTER TABLE privacy_operator_secrets ADD COLUMN IF NOT EXISTS factor_version BIGINT NOT NULL DEFAULT 1",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS privacy_access_requests (
                id TEXT PRIMARY KEY,
                requester_user_id TEXT NOT NULL REFERENCES platform_users(id),
                requester_session_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('requested', 'approved', 'rejected', 'revoked', 'expired')),
                expires_at TIMESTAMPTZ NOT NULL,
                approver_user_id TEXT REFERENCES platform_users(id),
                approver_session_id TEXT,
                approved_at TIMESTAMPTZ,
                rejected_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS privacy_reveal_leases (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES privacy_access_requests(id) ON DELETE CASCADE,
                nonce_hash TEXT NOT NULL,
                requester_user_id TEXT NOT NULL REFERENCES platform_users(id),
                requester_session_id TEXT NOT NULL,
                approver_user_id TEXT NOT NULL REFERENCES platform_users(id),
                approver_session_id TEXT NOT NULL,
                approver_factor_version BIGINT NOT NULL DEFAULT 1,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                uses_remaining INTEGER NOT NULL CHECK (uses_remaining >= 0),
                status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'revoked', 'expired')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (request_id, scope)
            )"#,
        )
        .execute(&self.pool)
        .await?;

        // Existing installations predate the factor-version binding on
        // leases.  A default of 1 keeps the migration additive; the version
        // checks below intentionally invalidate old leases after an operator
        // factor has been rotated.
        sqlx::query(
            "ALTER TABLE privacy_reveal_leases ADD COLUMN IF NOT EXISTS approver_factor_version BIGINT NOT NULL DEFAULT 1",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS privacy_access_events (
                id BIGSERIAL PRIMARY KEY,
                event_type TEXT NOT NULL,
                request_id TEXT,
                actor_user_id TEXT,
                subject_user_id TEXT,
                resource_type TEXT,
                resource_id TEXT,
                scope TEXT,
                decision TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;

        // The privacy audit trail is append-only.  The application only ever
        // inserts events inside the same transaction as the decision or
        // delivery; a database trigger prevents accidental or privileged
        // UPDATE/DELETE mutations from rewriting the evidence.
        sqlx::query(
            r#"CREATE OR REPLACE FUNCTION vigilyx_reject_privacy_event_mutation()
               RETURNS trigger
               LANGUAGE plpgsql
               AS $$
               BEGIN
                   RAISE EXCEPTION 'privacy access events are append-only';
               END;
               $$"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DROP TRIGGER IF EXISTS trg_privacy_access_events_immutable ON privacy_access_events",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TRIGGER trg_privacy_access_events_immutable BEFORE UPDATE OR DELETE ON privacy_access_events FOR EACH ROW EXECUTE FUNCTION vigilyx_reject_privacy_event_mutation()",
        )
        .execute(&self.pool)
        .await?;

        for statement in [
            "CREATE INDEX IF NOT EXISTS idx_privacy_requests_requester ON privacy_access_requests(requester_user_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_privacy_requests_pending ON privacy_access_requests(status, expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_privacy_leases_lookup ON privacy_reveal_leases(request_id, resource_type, resource_id, scope, status)",
            "CREATE INDEX IF NOT EXISTS idx_privacy_events_created ON privacy_access_events(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_privacy_events_request ON privacy_access_events(request_id, created_at DESC)",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        record_migration(
            &self.pool,
            PRIVACY_MIGRATION,
            "server-side privacy dual-control requests, leases, factors and audit events",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_privacy_access_request(
        &self,
        id: &str,
        requester_user_id: &str,
        requester_session_id: &str,
        resource_type: &str,
        resource_id: &str,
        scopes: &[String],
        purpose: &str,
        expires_at: &str,
    ) -> Result<PrivacyAccessRequest> {
        let scopes_json = serde_json::to_string(scopes)?;
        sqlx::query(
            "INSERT INTO privacy_access_requests \
             (id, requester_user_id, requester_session_id, resource_type, resource_id, scopes, purpose, status, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'requested', $8::TIMESTAMPTZ)",
        )
        .bind(id)
        .bind(requester_user_id)
        .bind(requester_session_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(scopes_json)
        .bind(purpose)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        self.get_privacy_access_request(id)
            .await?
            .ok_or_else(|| anyhow!("privacy access request disappeared after insert"))
    }

    pub async fn get_privacy_access_request(
        &self,
        id: &str,
    ) -> Result<Option<PrivacyAccessRequest>> {
        let row: Option<PrivacyAccessRequestRow> = sqlx::query_as(
            "SELECT id, requester_user_id, requester_session_id, resource_type, resource_id, scopes, purpose, status, \
                    TO_CHAR(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                    approver_user_id, approver_session_id, \
                    TO_CHAR(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                    TO_CHAR(rejected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                    TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM privacy_access_requests WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(PrivacyAccessRequestRow::into_model).transpose()
    }

    pub async fn list_privacy_access_requests(
        &self,
        requester_user_id: &str,
        pending_only: bool,
    ) -> Result<Vec<PrivacyAccessRequest>> {
        let rows: Vec<PrivacyAccessRequestRow> = if pending_only {
            sqlx::query_as(
                "SELECT id, requester_user_id, requester_session_id, resource_type, resource_id, scopes, purpose, status, \
                        TO_CHAR(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        approver_user_id, approver_session_id, \
                        TO_CHAR(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        TO_CHAR(rejected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
                 FROM privacy_access_requests \
                 WHERE status = 'requested' AND expires_at > NOW() \
                 ORDER BY created_at ASC",
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, requester_user_id, requester_session_id, resource_type, resource_id, scopes, purpose, status, \
                        TO_CHAR(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        approver_user_id, approver_session_id, \
                        TO_CHAR(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        TO_CHAR(rejected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                        TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
                 FROM privacy_access_requests \
                 WHERE requester_user_id = $1 ORDER BY created_at DESC",
            )
            .bind(requester_user_id)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(PrivacyAccessRequestRow::into_model)
            .collect()
    }

    pub async fn get_privacy_operator_secret(
        &self,
        user_id: &str,
    ) -> Result<Option<PrivacyOperatorSecret>> {
        let row = sqlx::query_as::<_, (String, i32, i64, Option<String>)>(
            "SELECT verifier, failed_attempts, factor_version, TO_CHAR(locked_until AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM privacy_operator_secrets WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(verifier, failed_attempts, factor_version, locked_until)| PrivacyOperatorSecret {
                verifier,
                failed_attempts,
                factor_version,
                locked_until,
            },
        ))
    }

    /// Create a verifier only when the user has never configured one.  A
    /// concurrent creator loses the insert race instead of overwriting the
    /// established factor.
    pub async fn create_privacy_operator_secret(
        &self,
        user_id: &str,
        verifier: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO privacy_operator_secrets (user_id, verifier, factor_version) VALUES ($1, $2, 1) \
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(verifier)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Rotate a verifier only if the factor version observed during
    /// re-authentication is still current.  Lease revocation is part of the
    /// same transaction, so a successful rotation cannot leave an old
    /// approval lease usable.
    pub async fn rotate_privacy_operator_secret(
        &self,
        user_id: &str,
        verifier: &str,
        expected_factor_version: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE privacy_operator_secrets SET verifier = $2, failed_attempts = 0, locked_until = NULL, \
                 factor_version = factor_version + 1, updated_at = NOW() \
             WHERE user_id = $1 AND factor_version = $3",
        )
        .bind(user_id)
        .bind(verifier)
        .bind(expected_factor_version)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query(
            "UPDATE privacy_reveal_leases SET status = 'revoked', uses_remaining = 0 \
             WHERE status = 'active' AND (requester_user_id = $1 OR approver_user_id = $1)",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn record_privacy_factor_failure(
        &self,
        user_id: &str,
        max_attempts: i32,
        lock_seconds: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE privacy_operator_secrets SET \
                 failed_attempts = failed_attempts + 1, \
                 locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN NOW() + ($3 * INTERVAL '1 second') ELSE locked_until END, \
                 updated_at = NOW() WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(max_attempts)
        .bind(lock_seconds as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn clear_privacy_factor_failures(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE privacy_operator_secrets SET failed_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically transition a pending request and issue one lease per exact
    /// scope.  No lease handle is returned to the API client.
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_privacy_access_request(
        &self,
        request_id: &str,
        approver_user_id: &str,
        approver_session_id: &str,
        approver_factor_version: i64,
        nonce_hash: &str,
        now: &str,
        lease_expires_at: &str,
        actor_user_id: &str,
    ) -> Result<Option<PrivacyAccessRequest>> {
        let mut tx = self.pool.begin().await?;
        let current_factor: Option<(i64,)> = sqlx::query_as(
            "SELECT factor_version FROM privacy_operator_secrets WHERE user_id = $1 FOR SHARE",
        )
        .bind(approver_user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current_factor != Some((approver_factor_version,)) {
            tx.rollback().await?;
            return Ok(None);
        }

        let row: Option<PrivacyAccessRequestRow> = sqlx::query_as(
            "UPDATE privacy_access_requests SET status = 'approved', approver_user_id = $2, approver_session_id = $3, approved_at = $4::TIMESTAMPTZ \
             WHERE id = $1 AND status = 'requested' AND expires_at > $4::TIMESTAMPTZ AND requester_user_id <> $2 \
             RETURNING id, requester_user_id, requester_session_id, resource_type, resource_id, scopes, purpose, status, \
                       TO_CHAR(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                       approver_user_id, approver_session_id, \
                       TO_CHAR(approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                       TO_CHAR(rejected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
                       TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')",
        )
        .bind(request_id)
        .bind(approver_user_id)
        .bind(approver_session_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };

        let scopes: Vec<String> = serde_json::from_str(&row.scopes)?;
        for scope in &scopes {
            let lease_id = Uuid::new_v4().to_string();
            let uses = if matches!(scope.as_str(), "eml_download" | "attachment_download")
                || row.resource_type == "http_session"
            {
                1
            } else {
                8
            };
            sqlx::query(
                "INSERT INTO privacy_reveal_leases (id, request_id, nonce_hash, requester_user_id, requester_session_id, approver_user_id, approver_session_id, approver_factor_version, resource_type, resource_id, scope, expires_at, uses_remaining, status) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::TIMESTAMPTZ, $13, 'active')",
            )
            .bind(lease_id)
            .bind(request_id)
            .bind(nonce_hash)
            .bind(&row.requester_user_id)
            .bind(&row.requester_session_id)
            .bind(approver_user_id)
            .bind(approver_session_id)
            .bind(approver_factor_version)
            .bind(&row.resource_type)
            .bind(&row.resource_id)
            .bind(scope)
            .bind(lease_expires_at)
            .bind(uses)
            .execute(&mut *tx)
            .await?;
        }

        insert_privacy_event_tx(
            &mut tx,
            "approval",
            Some(request_id),
            Some(actor_user_id),
            Some(&row.requester_user_id),
            Some(&row.resource_type),
            Some(&row.resource_id),
            None,
            "approved",
            "dual-control approval accepted",
        )
        .await?;
        tx.commit().await?;
        Ok(Some(row.into_model()?))
    }

    pub async fn reject_privacy_access_request(
        &self,
        request_id: &str,
        approver_user_id: &str,
        approver_session_id: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, String, String)> = sqlx::query_as(
            "UPDATE privacy_access_requests SET status = 'rejected', approver_user_id = $2, approver_session_id = $3, rejected_at = NOW() \
             WHERE id = $1 AND status = 'requested' AND requester_user_id <> $2 \
             RETURNING requester_user_id, resource_type, resource_id",
        )
        .bind(request_id)
        .bind(approver_user_id)
        .bind(approver_session_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((requester_user_id, resource_type, resource_id)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        insert_privacy_event_tx(
            &mut tx,
            "rejection",
            Some(request_id),
            Some(approver_user_id),
            Some(&requester_user_id),
            Some(&resource_type),
            Some(&resource_id),
            None,
            "rejected",
            "dual-control approval rejected",
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn revoke_privacy_access_request(
        &self,
        request_id: &str,
        actor_user_id: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, String, String)> = sqlx::query_as(
            "UPDATE privacy_access_requests SET status = 'revoked' \
             WHERE id = $1 AND status IN ('requested', 'approved') \
             RETURNING requester_user_id, resource_type, resource_id",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((requester_user_id, resource_type, resource_id)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        sqlx::query(
            "UPDATE privacy_reveal_leases SET status = 'revoked', uses_remaining = 0 WHERE request_id = $1 AND status = 'active'",
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        insert_privacy_event_tx(
            &mut tx,
            "revocation",
            Some(request_id),
            Some(actor_user_id),
            Some(&requester_user_id),
            Some(&resource_type),
            Some(&resource_id),
            None,
            "revoked",
            "privacy access revoked",
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Return only active scopes for the exact authenticated user session.
    /// Expired/consumed/revoked leases never fall through to a safe-looking
    /// plaintext response.
    pub async fn active_privacy_scopes(
        &self,
        request_id: &str,
        user_id: &str,
        session_id: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT l.scope FROM privacy_reveal_leases AS l \
             WHERE l.request_id = $1 AND l.resource_type = $4 AND l.resource_id = $5 \
               AND l.status = 'active' AND l.expires_at > NOW() AND l.uses_remaining > 0 \
               AND ((l.requester_user_id = $2 AND l.requester_session_id = $3) \
                    OR (l.approver_user_id = $2 AND l.approver_session_id = $3 \
                        AND l.approver_factor_version = (SELECT factor_version FROM privacy_operator_secrets WHERE user_id = l.approver_user_id)))",
        )
        .bind(request_id)
        .bind(user_id)
        .bind(session_id)
        .bind(resource_type)
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(scope,)| scope).collect())
    }

    pub async fn privacy_lease_summary(
        &self,
        request_id: &str,
        user_id: &str,
        session_id: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<Option<(Vec<String>, String, i32)>> {
        let rows: Vec<(String, String, i32)> = sqlx::query_as(
            "SELECT l.scope, TO_CHAR(l.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), l.uses_remaining \
             FROM privacy_reveal_leases AS l \
             WHERE l.request_id = $1 AND l.resource_type = $4 AND l.resource_id = $5 \
               AND l.status = 'active' AND l.expires_at > NOW() AND l.uses_remaining > 0 \
               AND ((l.requester_user_id = $2 AND l.requester_session_id = $3) \
                    OR (l.approver_user_id = $2 AND l.approver_session_id = $3 \
                        AND l.approver_factor_version = (SELECT factor_version FROM privacy_operator_secrets WHERE user_id = l.approver_user_id)))",
        )
        .bind(request_id)
        .bind(user_id)
        .bind(session_id)
        .bind(resource_type)
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let expires_at = rows[0].1.clone();
        let uses_remaining = rows.iter().map(|row| row.2).min().unwrap_or(0);
        Ok(Some((
            rows.into_iter().map(|row| row.0).collect(),
            expires_at,
            uses_remaining,
        )))
    }

    pub async fn list_privacy_lease_summaries(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<Vec<(String, String, String, Vec<String>, String, i32)>> {
        let rows: Vec<(String, String, String, String, String, i32)> = sqlx::query_as(
            "SELECT l.request_id, l.resource_type, l.resource_id, l.scope, TO_CHAR(l.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), l.uses_remaining \
             FROM privacy_reveal_leases AS l \
             WHERE l.status = 'active' AND l.expires_at > NOW() AND l.uses_remaining > 0 \
               AND ((l.requester_user_id = $1 AND l.requester_session_id = $2) \
                    OR (l.approver_user_id = $1 AND l.approver_session_id = $2 \
                        AND l.approver_factor_version = (SELECT factor_version FROM privacy_operator_secrets WHERE user_id = l.approver_user_id))) \
             ORDER BY l.expires_at ASC, l.request_id ASC, l.scope ASC",
        )
        .bind(user_id)
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        let mut grouped: BTreeMap<String, (String, String, Vec<String>, String, i32)> =
            BTreeMap::new();
        for (request_id, resource_type, resource_id, scope, expires_at, uses_remaining) in rows {
            let entry = grouped.entry(request_id).or_insert_with(|| {
                (
                    resource_type,
                    resource_id,
                    Vec::new(),
                    expires_at.clone(),
                    uses_remaining,
                )
            });
            entry.2.push(scope);
            entry.4 = entry.4.min(uses_remaining);
        }
        Ok(grouped
            .into_iter()
            .map(
                |(request_id, (resource_type, resource_id, scopes, expires_at, uses_remaining))| {
                    (
                        request_id,
                        resource_type,
                        resource_id,
                        scopes,
                        expires_at,
                        uses_remaining,
                    )
                },
            )
            .collect())
    }

    /// Atomically consume a one-shot delivery lease.  This is used for EML and
    /// attachment downloads so concurrent requests cannot both succeed.
    pub async fn consume_privacy_scope(
        &self,
        request_id: &str,
        user_id: &str,
        session_id: &str,
        resource_type: &str,
        resource_id: &str,
        scope: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let lease_id: Option<(String,)> = sqlx::query_as(
            "SELECT l.id FROM privacy_reveal_leases AS l \
             WHERE l.request_id = $1 AND l.resource_type = $4 AND l.resource_id = $5 AND l.scope = $6 \
               AND l.status = 'active' AND l.expires_at > NOW() AND l.uses_remaining > 0 \
               AND ((l.requester_user_id = $2 AND l.requester_session_id = $3) \
                    OR (l.approver_user_id = $2 AND l.approver_session_id = $3 \
                        AND l.approver_factor_version = (SELECT factor_version FROM privacy_operator_secrets WHERE user_id = l.approver_user_id))) \
             FOR UPDATE",
        )
        .bind(request_id)
        .bind(user_id)
        .bind(session_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(scope)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((lease_id,)) = lease_id else {
            tx.rollback().await?;
            return Ok(false);
        };
        sqlx::query(
            "UPDATE privacy_reveal_leases SET uses_remaining = uses_remaining - 1, status = CASE WHEN uses_remaining <= 1 THEN 'consumed' ELSE status END WHERE id = $1",
        )
        .bind(lease_id)
        .execute(&mut *tx)
        .await?;
        insert_privacy_event_tx(
            &mut tx,
            "delivery",
            Some(request_id),
            Some(user_id),
            None,
            Some(resource_type),
            Some(resource_id),
            Some(scope),
            "allowed",
            "one-shot privacy delivery lease consumed",
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_privacy_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_type: &str,
    request_id: Option<&str>,
    actor_user_id: Option<&str>,
    subject_user_id: Option<&str>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    scope: Option<&str>,
    decision: &str,
    detail: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO privacy_access_events (event_type, request_id, actor_user_id, subject_user_id, resource_type, resource_id, scope, decision, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(event_type)
    .bind(request_id)
    .bind(actor_user_id)
    .bind(subject_user_id)
    .bind(resource_type)
    .bind(resource_id)
    .bind(scope)
    .bind(decision)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
