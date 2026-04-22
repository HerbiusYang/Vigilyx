//! JWT authentication module

//! Provides API and WebSocket authentication:
//! - JWT token generation and verification
//! - Password hashing and verification with Argon2
//! - Authentication middleware

//! Configuration:
//! - `API_JWT_SECRET`: JWT signing secret (at least 32 characters)
//! - `API_USERNAME`: admin username (default: admin)
//! - `API_PASSWORD`: admin password
//! - `API_TOKEN_EXPIRE_HOURS`: token lifetime in hours (default: 24)

mod handlers;
mod jwt;
mod middleware;
mod password;
pub mod rate_limit;
mod ws_ticket;

// Re-exports: keep the public API stable

pub(crate) use handlers::sanitize_login_username;
pub use handlers::{
    ChangePasswordRequest, ChangePasswordResponse, LoginRequest, build_clear_cookie,
    build_token_cookie, handle_change_password, handle_login, handle_logout, handle_me,
};
pub use middleware::{
    AuthenticatedUser, require_admin, require_auth, require_internal_origin, require_internal_token,
};
pub use password::hash_password;
pub use rate_limit::LoginRateLimiter;
pub use ws_ticket::WsTicketStore;

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Authentication configuration.

/// `password_hash` uses `RwLock` so password changes can be persisted to PostgreSQL at runtime.
/// `jwt_secret` uses `SecretString` so the secret is zeroized on drop (SEC-REMAINING-004, CWE-316).
pub struct AuthConfig {
    /// JWT secret (SecretString zeroizes on drop and masks Debug output)
    pub jwt_secret: SecretString,
    /// Username.
    pub username: String,
    /// Password hash (protected by `RwLock`)
    pub password_hash: RwLock<String>,
    /// Token lifetime in seconds
    pub token_expire_secs: u64,
    /// Whether the default password has been changed
    pub password_changed: RwLock<bool>,
    /// Token version - incremented on password change, old tokens rejected (SEC: CWE-613)
    pub token_version: AtomicU64,
}

impl Clone for AuthConfig {
    /// SEC-REMAINING-006: use `try_read` to avoid blocking in async contexts (CWE-667).

    /// NOTE: This `Clone` implementation is mainly used during startup (`AuthState` shares `Arc<AuthConfig>`).
    /// Regular `Arc::clone` does not invoke this impl. If `try_read` fails in an extreme race,
    /// it falls back to empty defaults and the values are reloaded from the database.
    fn clone(&self) -> Self {
        let hash = self
            .password_hash
            .try_read()
            .map(|g| g.clone())
            .unwrap_or_default();
        let changed = self
            .password_changed
            .try_read()
            .map(|g| *g)
            .unwrap_or(false);
        Self {
            jwt_secret: self.jwt_secret.clone(),
            username: self.username.clone(),
            password_hash: RwLock::new(hash),
            token_expire_secs: self.token_expire_secs,
            password_changed: RwLock::new(changed),
            token_version: AtomicU64::new(self.token_version.load(Ordering::Relaxed)),
        }
    }
}

impl AuthConfig {
    fn hash_runtime_password_from_env() -> Result<String, AuthError> {
        let password = std::env::var("API_PASSWORD").map_err(|_| {
            AuthError::ConfigError(
                "API_PASSWORD is not set; runtime auth reset requires an explicit admin password"
                    .into(),
            )
        })?;
        hash_password(&password)
    }

    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, AuthError> {
        let jwt_secret = std::env::var("API_JWT_SECRET")
            .map_err(|_| AuthError::ConfigError("API_JWT_SECRET is not set".into()))?;

        if jwt_secret.len() < 32 {
            return Err(AuthError::ConfigError(
                "API_JWT_SECRET must be at least 32 characters".into(),
            ));
        }

        let username = std::env::var("API_USERNAME").unwrap_or_else(|_| "admin".to_string());

        let password = std::env::var("API_PASSWORD")
            .map_err(|_| AuthError::ConfigError("API_PASSWORD is not set".into()))?;

        // Hash the configured password before storing it in memory.
        let password_hash = hash_password(&password)?;

        let token_expire_hours: u64 = std::env::var("API_TOKEN_EXPIRE_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(24);

        Ok(Self {
            jwt_secret: SecretString::from(jwt_secret),
            username,
            password_hash: RwLock::new(password_hash),
            token_expire_secs: token_expire_hours * 3600,
            password_changed: RwLock::new(false),
            token_version: AtomicU64::new(0),
        })
    }

    /// Validate that runtime auth reset has the required environment configuration.
    pub fn validate_factory_reset_prereqs() -> Result<(), AuthError> {
        Self::hash_runtime_password_from_env().map(|_| ())
    }

    /// Create a test-only configuration with a secure random JWT secret.
    #[cfg(test)]
    fn test_config(password: &str) -> Self {
        use std::fmt::Write;

        // Generate a 64-byte random JWT secret
        let mut secret = String::with_capacity(128);
        let random_bytes: [u8; 64] = {
            use argon2::password_hash::rand_core::RngCore;
            let mut buf = [0u8; 64];
            argon2::password_hash::rand_core::OsRng.fill_bytes(&mut buf);
            buf
        };
        for b in &random_bytes {
            let _ = write!(secret, "{:02x}", b);
        }
        let password_hash = hash_password(password).expect("Failed to hash test password");
        Self {
            jwt_secret: SecretString::from(secret),
            username: "admin".to_string(),
            password_hash: RwLock::new(password_hash),
            token_expire_secs: 24 * 3600,
            password_changed: RwLock::new(false),
            token_version: AtomicU64::new(0),
        }
    }

    /// Load the saved password hash from the database, overriding the default value when present
    pub async fn load_password_from_db(&self, db: &vigilyx_db::VigilDb) {
        match db.get_config("auth_password_hash").await {
            Ok(Some(hash)) => {
                info!("Loaded saved password hash from the database");
                *self.password_hash.write().await = hash;
                *self.password_changed.write().await = true;
            }
            Ok(None) => {
                info!(
                    "No saved password hash found in the database; first login will require a password change"
                );
                *self.password_changed.write().await = false;
            }
            Err(e) => {
                warn!(
                    "Failed to load password hash from the database: {}; using the environment default",
                    e
                );
            }
        }
        // SEC: Load token version from DB (CWE-613)
        match db.get_config("auth_token_version").await {
            Ok(Some(v)) => {
                if let Ok(tv) = v.parse::<u64>() {
                    self.token_version.store(tv, Ordering::Relaxed);
                    info!("Loaded token version from DB: {}", tv);
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Load token version failed: {}", e);
            }
        }
    }

    pub async fn reset_after_factory_reset(&self) -> Result<u64, AuthError> {
        let hash = Self::hash_runtime_password_from_env()?;
        *self.password_hash.write().await = hash;
        *self.password_changed.write().await = false;
        let next_tv = self.token_version.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(next_tv)
    }
}

/// Authentication error.
#[derive(Debug)]
pub enum AuthError {
    /// Configuration error.
    ConfigError(String),

    InvalidCredentials,
    /// Token has expired.
    TokenExpired,
    /// Token is invalid.
    InvalidToken,
    /// Token is missing.
    MissingToken,
    /// Authenticated user lacks the required role.
    Forbidden,
    /// Internal error.
    InternalError(String),
    /// Must change default password before accessing other endpoints (SEC: CWE-620)
    PasswordChangeRequired,
    /// Internal control-plane route accessed from a non-internal source.
    InternalSourceDenied,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::ConfigError(_) => write!(f, "服务配置错误"),
            AuthError::InvalidCredentials => write!(f, "用户名或密码错误"),
            AuthError::TokenExpired => write!(f, "登录已过期，请重新登录"),
            AuthError::InvalidToken => write!(f, "无效的登录凭证"),
            AuthError::MissingToken => write!(f, "请先登录"),
            AuthError::Forbidden => write!(f, "没有足够权限执行该操作"),
            AuthError::InternalError(_) => write!(f, "内部错误"),
            AuthError::PasswordChangeRequired => write!(f, "请先修改初始密码"),
            AuthError::InternalSourceDenied => write!(f, "内部接口仅允许内网来源访问"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        use crate::error_codes;

        // SEC-M07: errormessage, internal log (CWE-209)
        let (status, message, error_code) = match &self {
            AuthError::ConfigError(msg) => {
                warn!("Authentication configuration error: {}", msg);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    error_codes::INTERNAL_SERVICE_UNAVAILABLE,
                )
            }
            AuthError::InvalidCredentials => (
                axum::http::StatusCode::UNAUTHORIZED,
                self.to_string(),
                error_codes::AUTH_INVALID_CREDENTIALS,
            ),
            AuthError::TokenExpired => (
                axum::http::StatusCode::UNAUTHORIZED,
                self.to_string(),
                error_codes::AUTH_TOKEN_EXPIRED,
            ),
            AuthError::InvalidToken => (
                axum::http::StatusCode::UNAUTHORIZED,
                self.to_string(),
                error_codes::AUTH_INVALID_TOKEN,
            ),
            AuthError::MissingToken => (
                axum::http::StatusCode::UNAUTHORIZED,
                self.to_string(),
                error_codes::AUTH_MISSING_TOKEN,
            ),
            AuthError::Forbidden => (
                axum::http::StatusCode::FORBIDDEN,
                self.to_string(),
                error_codes::AUTH_FORBIDDEN,
            ),
            AuthError::InternalError(msg) => {
                warn!("Authentication internal error: {}", msg);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    error_codes::INTERNAL_SERVICE_UNAVAILABLE,
                )
            }
            AuthError::PasswordChangeRequired => (
                axum::http::StatusCode::FORBIDDEN,
                self.to_string(),
                error_codes::AUTH_PASSWORD_CHANGE_REQUIRED,
            ),
            AuthError::InternalSourceDenied => (
                axum::http::StatusCode::FORBIDDEN,
                self.to_string(),
                error_codes::AUTH_INTERNAL_SOURCE_DENIED,
            ),
        };

        let body = Json(serde_json::json!({
            "success": false,
            "error": message,
            "error_code": error_code,
        }));

        (status, body).into_response()
    }
}

/// Authenticationstatus (Used forSharedConfiguration)
#[derive(Clone)]
pub struct AuthState {
    pub config: std::sync::Arc<AuthConfig>,
    /// Per-IP login Stream (Arc Shared, lock-free DashMap)
    pub login_rate_limiter: std::sync::Arc<rate_limit::LoginRateLimiter>,
}

// NOTE: authentication handler AuthenticatedUser Extract

#[cfg(test)]
mod tests {
    use super::jwt::generate_token;
    use super::password::verify_password;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const TEST_ADMIN_PASSWORD: &str = "TestAdmin!2345";

    /// Test helper: a deterministic IP for unit tests.
    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Test helper: create a fresh rate limiter (10 failures / 60s window).
    fn test_limiter() -> LoginRateLimiter {
        LoginRateLimiter::new(10, 60)
    }

    #[test]
    fn test_password_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_token_generation_and_verification() {
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let token = generate_token(&config, "testuser", "admin").unwrap();
        let claims = jwt::verify_token(&config, &token).unwrap();
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.role, "admin");
    }

    #[tokio::test]
    async fn test_login() {
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = test_limiter();
        let ip = test_ip();

        // login (default password,)
        let request = LoginRequest {
            username: "admin".to_string(),
            password: TEST_ADMIN_PASSWORD.to_string(),
        };
        let response = handle_login(&config, &limiter, ip, &request).await;
        assert!(response.success);
        assert!(response.token.is_some());
        assert_eq!(response.must_change_password, Some(true));

        // errorPassword
        let request = LoginRequest {
            username: "admin".to_string(),
            password: "wrong".to_string(),
        };
        let response = handle_login(&config, &limiter, ip, &request).await;
        assert!(!response.success);
    }

    #[tokio::test]
    async fn test_login_after_password_change() {
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = test_limiter();
        let ip = test_ip();
        // Password
        *config.password_changed.write().await = true;

        let request = LoginRequest {
            username: "admin".to_string(),
            password: TEST_ADMIN_PASSWORD.to_string(),
        };
        let response = handle_login(&config, &limiter, ip, &request).await;
        assert!(response.success);
        assert!(response.must_change_password.is_none());
    }

    #[tokio::test]
    async fn test_login_rate_limit_per_ip() {
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = test_limiter();
        let attacker_ip: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let innocent_ip: IpAddr = "10.0.0.2".parse().expect("valid IP");

        // Attacker: 10 failed attempts
        for _ in 0..10 {
            let request = LoginRequest {
                username: "admin".to_string(),
                password: "wrong".to_string(),
            };
            let _ = handle_login(&config, &limiter, attacker_ip, &request).await;
        }

        // Attacker is now blocked (even with correct password)
        let request = LoginRequest {
            username: "admin".to_string(),
            password: TEST_ADMIN_PASSWORD.to_string(),
        };
        let response = handle_login(&config, &limiter, attacker_ip, &request).await;
        assert!(!response.success);
        assert!(response.error.as_deref().unwrap_or("").contains("过多"));

        // Innocent user from different IP is NOT affected
        let request = LoginRequest {
            username: "admin".to_string(),
            password: TEST_ADMIN_PASSWORD.to_string(),
        };
        let response = handle_login(&config, &limiter, innocent_ip, &request).await;
        assert!(
            response.success,
            "innocent IP should not be blocked by attacker's failures"
        );
    }

    #[tokio::test]
    async fn test_login_success_resets_failure_count() {
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = test_limiter();
        let ip = test_ip();

        // 5 failed attempts (under limit)
        for _ in 0..5 {
            let request = LoginRequest {
                username: "admin".to_string(),
                password: "wrong".to_string(),
            };
            let _ = handle_login(&config, &limiter, ip, &request).await;
        }

        // Successful login resets the counter
        let request = LoginRequest {
            username: "admin".to_string(),
            password: TEST_ADMIN_PASSWORD.to_string(),
        };
        let response = handle_login(&config, &limiter, ip, &request).await;
        assert!(response.success);

        // Another 9 failures should still be allowed (counter was reset)
        for _ in 0..9 {
            let request = LoginRequest {
                username: "admin".to_string(),
                password: "wrong".to_string(),
            };
            let response = handle_login(&config, &limiter, ip, &request).await;
            assert!(!response.success);
            // Should get "user Passworderror" not " "
            assert!(
                !response.error.as_deref().unwrap_or("").contains("过多"),
                "should not be rate-limited yet after reset"
            );
        }
    }
}
