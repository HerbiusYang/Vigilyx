//! Persistent platform identity and RBAC storage.
//!
//! The API treats this module as the source of truth for user state and route
//! permissions.  The legacy `config`/`auth_credentials` rows remain in place
//! for backwards-compatible token-version and bootstrap-password handling.

use anyhow::{Result, anyhow};
use uuid::Uuid;

use crate::VigilDb;

/// Stable permission catalog.  New permissions must be added here and seeded
/// through a migration so role changes are reviewable and auditable.
pub const PLATFORM_PERMISSIONS: &[(&str, &str)] = &[
    ("sessions.read", "查看邮件会话"),
    ("sessions.rescan", "重新扫描邮件会话"),
    ("sessions.whitelist", "将会话加入白名单"),
    ("sessions.feedback", "提交检测反馈"),
    ("security.read", "查看安全分析"),
    ("security.manage", "管理安全检测配置"),
    ("security.ioc.manage", "管理 IOC"),
    ("security.quarantine.manage", "管理隔离区"),
    ("security.alerts.manage", "管理安全告警"),
    ("security.yara.manage", "管理 YARA 规则"),
    ("security.ai.manage", "管理 AI 服务配置"),
    ("security.threat.manage", "管理威胁场景"),
    ("data_security.read", "查看数据安全"),
    ("audit.read", "查看审计与登录记录"),
    ("config.manage", "管理平台配置"),
    ("ai.training", "管理 AI 训练"),
    ("platform.users.manage", "管理平台用户"),
    ("platform.roles.manage", "管理平台角色和权限"),
    ("platform.manage", "管理平台和高风险操作"),
];

const ADMIN_ROLE_ID: &str = "role-admin";
const ANALYST_ROLE_ID: &str = "role-analyst";
const VIEWER_ROLE_ID: &str = "role-viewer";

type PlatformAuthRow = (String, String, String, String, String, String, bool, bool, i64);
type PlatformUserRow = (
    String,
    String,
    String,
    String,
    String,
    bool,
    bool,
    Option<String>,
    String,
);

#[derive(Debug, Clone)]
pub struct PlatformAuthUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role_id: String,
    pub role: String,
    pub password_hash: String,
    pub is_active: bool,
    pub must_change_password: bool,
    /// Per-user JWT token version (SEC M-1): a token is rejected once its
    /// `tv` claim is lower than this value.
    pub token_version: u64,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role_id: String,
    pub role: String,
    pub is_active: bool,
    pub must_change_password: bool,
    pub last_login_at: Option<String>,
    pub created_at: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlatformPermission {
    pub key: String,
    pub description: String,
}

impl VigilDb {
    /// Create the RBAC tables and seed the fixed permission catalog and system
    /// roles.  Every statement is idempotent so normal and operational-clear
    /// startup paths can call this safely.
    pub async fn init_platform_auth(&self) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS platform_roles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                is_system BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS platform_permissions (
                key TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS platform_role_permissions (
                role_id TEXT NOT NULL REFERENCES platform_roles(id) ON DELETE CASCADE,
                permission_key TEXT NOT NULL REFERENCES platform_permissions(key) ON DELETE CASCADE,
                PRIMARY KEY (role_id, permission_key)
            )"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS platform_users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role_id TEXT NOT NULL REFERENCES platform_roles(id),
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
                last_login_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                token_version BIGINT NOT NULL DEFAULT 0
            )"#,
        )
        .execute(&self.pool)
        .await?;
        // SEC (M-1, 2026-08-15): session revocation is per user. Existing
        // installs get the column added idempotently, and a one-shot seed
        // (gated by a config marker so it never re-runs) initializes each
        // user's row to the current global counter — every live JWT carries
        // tv = global-at-issue-time, so validity across the upgrade is
        // preserved exactly, and the first per-user bump invalidates only
        // that user's older tokens.
        // Red-team hardening: the seed runs BEFORE the marker is written, so
        // a failed seed retries on the next boot instead of being skipped
        // (marker-first left users at tv=0 while their old tokens carried
        // higher values — those tokens then survived until a manual bump).
        sqlx::query(
            "ALTER TABLE platform_users ADD COLUMN IF NOT EXISTS token_version BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;
        let already_migrated: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM config WHERE key = 'platform_tv_migrated'",
        )
        .fetch_optional(&self.pool)
        .await?;
        if already_migrated.is_none() {
            let seeded = sqlx::query(
                r#"UPDATE platform_users
                   SET token_version = GREATEST(token_version,
                       COALESCE((SELECT NULLIF(value, '')::BIGINT FROM config WHERE key = 'auth_token_version'), 0))"#,
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO config (key, value) VALUES ('platform_tv_migrated', '1') ON CONFLICT (key) DO NOTHING",
            )
            .execute(&self.pool)
            .await?;
            tracing::info!(
                users = seeded.rows_affected(),
                "SEC M-1: seeded per-user token versions from the global counter (one-shot migration)"
            );
        }
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_platform_users_active ON platform_users(is_active)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_platform_users_role ON platform_users(role_id)",
        )
        .execute(&self.pool)
        .await?;

        for (key, description) in PLATFORM_PERMISSIONS {
            sqlx::query(
                "INSERT INTO platform_permissions (key, description) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description",
            )
            .bind(key)
            .bind(description)
            .execute(&self.pool)
            .await?;
        }

        for (id, name, description) in [
            (ADMIN_ROLE_ID, "admin", "平台管理员，拥有全部平台权限"),
            (
                ANALYST_ROLE_ID,
                "analyst",
                "安全分析员，可查看并处理邮件安全事件",
            ),
            (VIEWER_ROLE_ID, "viewer", "只读查看员"),
        ] {
            sqlx::query(
                "INSERT INTO platform_roles (id, name, description, is_system) VALUES ($1, $2, $3, TRUE) ON CONFLICT (id) DO NOTHING",
            )
            .bind(id)
            .bind(name)
            .bind(description)
            .execute(&self.pool)
            .await?;
        }

        // System role permission sets are deterministic.  Existing custom
        // changes on system roles are repaired on startup rather than leaving
        // an admin account without its invariant permissions.
        sqlx::query("DELETE FROM platform_role_permissions WHERE role_id = $1")
            .bind(ADMIN_ROLE_ID)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO platform_role_permissions (role_id, permission_key) SELECT $1, key FROM platform_permissions ON CONFLICT DO NOTHING",
        )
        .bind(ADMIN_ROLE_ID)
        .execute(&self.pool)
        .await?;

        let analyst_permissions = [
            "sessions.read",
            "sessions.rescan",
            "sessions.whitelist",
            "sessions.feedback",
            "security.read",
            "data_security.read",
        ];
        let viewer_permissions = ["sessions.read", "security.read", "data_security.read"];
        for (role_id, permissions) in [
            (ANALYST_ROLE_ID, &analyst_permissions[..]),
            (VIEWER_ROLE_ID, &viewer_permissions[..]),
        ] {
            sqlx::query("DELETE FROM platform_role_permissions WHERE role_id = $1")
                .bind(role_id)
                .execute(&self.pool)
                .await?;
            for permission in permissions {
                sqlx::query(
                    "INSERT INTO platform_role_permissions (role_id, permission_key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(role_id)
                .bind(permission)
                .execute(&self.pool)
                .await?;
            }
        }

        super::migrate::record_migration(
            &self.pool,
            "013_platform_rbac",
            "persistent platform users, roles and permissions",
        )
        .await
    }

    /// Idempotently bootstrap the legacy environment administrator.  Existing
    /// users are deliberately not overwritten, which prevents a restart from
    /// silently changing a real administrator's password or role.
    pub async fn ensure_platform_admin(
        &self,
        username: &str,
        password_hash: &str,
        must_change_password: bool,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let row: (String,) = sqlx::query_as(
            r#"
            INSERT INTO platform_users
                (id, username, display_name, password_hash, role_id, is_active, must_change_password)
            VALUES ($1, $2, $2, $3, $4, TRUE, $5)
            ON CONFLICT (username) DO UPDATE SET updated_at = platform_users.updated_at
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(username)
        .bind(password_hash)
        .bind(ADMIN_ROLE_ID)
        .bind(must_change_password)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Re-seed the configured administrator after a factory reset while
    /// preserving the other platform users and custom roles.
    pub async fn reset_platform_admin(&self, username: &str, password_hash: &str) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO platform_users
                    (id, username, display_name, password_hash, role_id, is_active, must_change_password)
               VALUES ($1, $2, $2, $3, $4, TRUE, TRUE)
               ON CONFLICT (username) DO UPDATE
               SET password_hash = EXCLUDED.password_hash,
                   role_id = EXCLUDED.role_id,
                   is_active = TRUE,
                   must_change_password = TRUE,
                   updated_at = NOW()"#,
        )
        .bind(id)
        .bind(username)
        .bind(password_hash)
        .bind(ADMIN_ROLE_ID)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn permissions_for_role(&self, role_id: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT permission_key FROM platform_role_permissions WHERE role_id = $1 ORDER BY permission_key",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(key,)| key).collect())
    }

    pub async fn get_platform_auth_user(&self, username: &str) -> Result<Option<PlatformAuthUser>> {
        let row: Option<PlatformAuthRow> = sqlx::query_as(
            r#"SELECT u.id, u.username, u.display_name, u.role_id, r.name,
                          u.password_hash, u.is_active, u.must_change_password, u.token_version
                   FROM platform_users u JOIN platform_roles r ON r.id = u.role_id
                   WHERE u.username = $1"#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((
                id,
                username,
                display_name,
                role_id,
                role,
                password_hash,
                is_active,
                must_change_password,
                token_version,
            )) => Ok(Some(PlatformAuthUser {
                permissions: self.permissions_for_role(&role_id).await?,
                id,
                username,
                display_name,
                role_id,
                role,
                password_hash,
                is_active,
                must_change_password,
                token_version: token_version.max(0) as u64,
            })),
            None => Ok(None),
        }
    }

    pub async fn get_platform_auth_user_by_id(&self, id: &str) -> Result<Option<PlatformAuthUser>> {
        let username: Option<(String,)> =
            sqlx::query_as("SELECT username FROM platform_users WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        match username {
            Some((username,)) => self.get_platform_auth_user(&username).await,
            None => Ok(None),
        }
    }

    pub async fn touch_platform_user_login(&self, id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE platform_users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_platform_user_password(
        &self,
        id: &str,
        password_hash: &str,
        must_change_password: bool,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE platform_users SET password_hash = $2, must_change_password = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(password_hash)
        .bind(must_change_password)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Update a platform password and revoke that user's prior JWT
    /// generations in one database transaction (SEC M-1: per-user token
    /// version, not a global counter).  The legacy admin hash is kept in sync
    /// for the compatibility login path during the migration window.
    pub async fn set_platform_user_password_and_bump_token(
        &self,
        id: &str,
        password_hash: &str,
        must_change_password: bool,
        sync_legacy_admin: bool,
    ) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let (token_version,): (i64,) = sqlx::query_as(
            "UPDATE platform_users SET password_hash = $2, must_change_password = $3,
                    token_version = token_version + 1, updated_at = NOW()
             WHERE id = $1 RETURNING token_version",
        )
        .bind(id)
        .bind(password_hash)
        .bind(must_change_password)
        .fetch_one(&mut *tx)
        .await?;
        if sync_legacy_admin {
            sqlx::query(
                "INSERT INTO config (key, value) VALUES ('auth_password_hash', $1) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(token_version.max(0) as u64)
    }

    /// Revoke one user's outstanding JWTs by bumping their token version
    /// (SEC M-1: logout / targeted session revocation).
    pub async fn bump_platform_user_token_version(&self, id: &str) -> Result<u64> {
        let (token_version,): (i64,) = sqlx::query_as(
            "UPDATE platform_users SET token_version = token_version + 1, updated_at = NOW()
             WHERE id = $1 RETURNING token_version",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("platform user not found"))?;
        Ok(token_version.max(0) as u64)
    }

    /// Revoke the outstanding JWTs of every user holding a role (SEC M-1:
    /// role permission changes affect only that role's sessions).
    pub async fn bump_platform_role_token_versions(&self, role_id: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE platform_users SET token_version = token_version + 1, updated_at = NOW() WHERE role_id = $1",
        )
        .bind(role_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every user's outstanding JWTs (SEC M-1: factory reset).
    ///
    /// Rows are pushed above the global `auth_token_version` counter so that
    /// even tokens issued in the old global-counter era (or rows recreated by
    /// the reset itself) end up below the new floor.
    pub async fn bump_all_platform_user_token_versions(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"UPDATE platform_users
               SET token_version = GREATEST(token_version,
                       COALESCE((SELECT NULLIF(value, '')::BIGINT FROM config WHERE key = 'auth_token_version'), 0)) + 1,
                   updated_at = NOW()"#,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn update_platform_user(
        &self,
        id: &str,
        display_name: &str,
        role_id: &str,
        is_active: bool,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE platform_users SET display_name = $2, role_id = $3, is_active = $4, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(display_name)
        .bind(role_id)
        .bind(is_active)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn create_platform_user(
        &self,
        username: &str,
        display_name: &str,
        password_hash: &str,
        role_id: &str,
        must_change_password: bool,
    ) -> Result<PlatformUser> {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO platform_users (id, username, display_name, password_hash, role_id, must_change_password) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&id)
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(role_id)
        .bind(must_change_password)
        .execute(&self.pool)
        .await?;
        self.get_platform_user_by_id(&id)
            .await?
            .ok_or_else(|| anyhow!("created platform user disappeared"))
    }

    pub async fn get_platform_user_by_id(&self, id: &str) -> Result<Option<PlatformUser>> {
        let row: Option<PlatformUserRow> = sqlx::query_as(
            r#"SELECT u.id, u.username, u.display_name, u.role_id, r.name, u.is_active,
                      u.must_change_password,
                      TO_CHAR(u.last_login_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                      TO_CHAR(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
               FROM platform_users u JOIN platform_roles r ON r.id = u.role_id WHERE u.id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((
                id,
                username,
                display_name,
                role_id,
                role,
                is_active,
                must_change_password,
                last_login_at,
                created_at,
            )) => Ok(Some(PlatformUser {
                permissions: self.permissions_for_role(&role_id).await?,
                id,
                username,
                display_name,
                role_id,
                role,
                is_active,
                must_change_password,
                last_login_at,
                created_at,
            })),
            None => Ok(None),
        }
    }

    pub async fn list_platform_users(&self) -> Result<Vec<PlatformUser>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM platform_users ORDER BY username")
                .fetch_all(&self.pool)
                .await?;
        let mut users = Vec::with_capacity(rows.len());
        for (id,) in rows {
            if let Some(user) = self.get_platform_user_by_id(&id).await? {
                users.push(user);
            }
        }
        Ok(users)
    }

    pub async fn list_platform_roles(&self) -> Result<Vec<PlatformRole>> {
        let rows: Vec<(String, String, String, bool)> = sqlx::query_as(
            "SELECT id, name, description, is_system FROM platform_roles ORDER BY is_system DESC, name",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut roles = Vec::with_capacity(rows.len());
        for (id, name, description, is_system) in rows {
            roles.push(PlatformRole {
                permissions: self.permissions_for_role(&id).await?,
                id,
                name,
                description,
                is_system,
            });
        }
        Ok(roles)
    }

    pub async fn list_platform_permissions(&self) -> Result<Vec<PlatformPermission>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, description FROM platform_permissions ORDER BY key")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|(key, description)| PlatformPermission { key, description })
            .collect())
    }

    pub async fn role_exists(&self, role_id: &str) -> Result<bool> {
        Ok(sqlx::query_as::<_, (bool,)>(
            "SELECT EXISTS(SELECT 1 FROM platform_roles WHERE id = $1)",
        )
        .bind(role_id)
        .fetch_one(&self.pool)
        .await?
        .0)
    }

    pub async fn role_is_system(&self, role_id: &str) -> Result<bool> {
        Ok(
            sqlx::query_as::<_, (bool,)>("SELECT is_system FROM platform_roles WHERE id = $1")
                .bind(role_id)
                .fetch_optional(&self.pool)
                .await?
                .map(|row| row.0)
                .unwrap_or(false),
        )
    }

    pub async fn create_platform_role(
        &self,
        name: &str,
        description: &str,
        permissions: &[String],
    ) -> Result<PlatformRole> {
        let role_id = format!("role-{}", Uuid::new_v4());
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO platform_roles (id, name, description, is_system) VALUES ($1, $2, $3, FALSE)")
            .bind(&role_id).bind(name).bind(description).execute(&mut *tx).await?;
        for permission in permissions {
            sqlx::query(
                "INSERT INTO platform_role_permissions (role_id, permission_key) VALUES ($1, $2)",
            )
            .bind(&role_id)
            .bind(permission)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.list_platform_roles()
            .await?
            .into_iter()
            .find(|r| r.id == role_id)
            .ok_or_else(|| anyhow!("created platform role disappeared"))
    }

    pub async fn update_platform_role(
        &self,
        role_id: &str,
        name: &str,
        description: &str,
        permissions: &[String],
    ) -> Result<bool> {
        if self.role_is_system(role_id).await? {
            return Err(anyhow!("system roles are immutable"));
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE platform_roles SET name = $2, description = $3, updated_at = NOW() WHERE id = $1")
            .bind(role_id).bind(name).bind(description).execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            sqlx::query("DELETE FROM platform_role_permissions WHERE role_id = $1")
                .bind(role_id)
                .execute(&mut *tx)
                .await?;
            for permission in permissions {
                sqlx::query("INSERT INTO platform_role_permissions (role_id, permission_key) VALUES ($1, $2)")
                    .bind(role_id).bind(permission).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_platform_role(&self, role_id: &str) -> Result<bool> {
        if self.role_is_system(role_id).await? {
            return Err(anyhow!("system roles are immutable"));
        }
        let assigned: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM platform_users WHERE role_id = $1")
                .bind(role_id)
                .fetch_one(&self.pool)
                .await?;
        if assigned.0 > 0 {
            return Err(anyhow!("role is assigned to active or inactive users"));
        }
        let result = sqlx::query("DELETE FROM platform_roles WHERE id = $1")
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn count_active_privileged_users(&self, exclude_id: Option<&str>) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(DISTINCT u.id)
               FROM platform_users u
               JOIN platform_role_permissions rp ON rp.role_id = u.role_id
               WHERE u.is_active AND rp.permission_key IN ('platform.users.manage', 'platform.manage')
                 AND ($1::TEXT IS NULL OR u.id <> $1)"#,
        )
        .bind(exclude_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn has_permission_key(&self, key: &str) -> Result<bool> {
        Ok(PLATFORM_PERMISSIONS.iter().any(|(known, _)| *known == key))
    }
}
