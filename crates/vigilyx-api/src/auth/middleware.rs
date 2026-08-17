//! JWT and internal-token authentication middleware.

use axum::{
    extract::{FromRequestParts, State},
    http::HeaderMap,
    http::request::Parts,
};
use std::sync::Arc;
use tracing::warn;

use super::{AuthError, jwt::verify_token};
#[cfg(test)]
use super::AuthState;

/// Authenticated user extracted from a verified JWT.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub must_change_password: bool,
}

impl AuthenticatedUser {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|candidate| candidate == permission)
    }
}

/// Extract the JWT token from the request cookie or Authorization header.
/// Priority: Cookie `vigilyx_token` > `Authorization: Bearer` header.
pub(super) fn extract_jwt_token(headers: &HeaderMap) -> Option<&str> {
    // 1. Prefer reading from the HttpOnly cookie
    if let Some(token) = extract_token_from_cookie(headers) {
        return Some(token);
    }
    // 2. Fallback: Authorization header (backward compatibility + third-party clients)
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

/// Extract the `vigilyx_token` value from the Cookie header.
fn extract_token_from_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix("vigilyx_token="))
}

/// Extract `AuthenticatedUser` from request parts.
///
/// Only the value inserted by `require_auth` is accepted. The previous
/// fallback authenticated a bare `verify_token` success without the per-user
/// token-version check (RT-5, deep red-team round) — reachable only if a
/// handler were mounted outside the `require_auth` layer, but that is exactly
/// the misconfiguration a footgun should not silently absorb.
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or_else(|| {
                tracing::error!(
                    "SEC RT-5: AuthenticatedUser extractor used outside require_auth — refusing unverified identity"
                );
                AuthError::InternalError(
                    "authenticated identity missing; route must be wrapped by require_auth".into(),
                )
            })
    }
}

#[cfg(test)]
pub(crate) fn is_admin_role(role: &str) -> bool {
    role.eq_ignore_ascii_case("admin")
}

#[cfg(test)]
fn validate_admin_request(headers: &HeaderMap, auth_state: &AuthState) -> Result<(), AuthError> {
    let token = extract_jwt_token(headers).ok_or(AuthError::MissingToken)?;
    let claims = verify_token(&auth_state.config, token)?;
    if !is_admin_role(&claims.role) {
        return Err(AuthError::Forbidden);
    }

    Ok(())
}

/// Enforce JWT authentication for protected routes.
/// SEC: Reject sessions using default password except for the change-password endpoint (CWE-620).
pub async fn require_auth(
    State(state): State<Arc<crate::AppState>>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    // Expose `AuthState` to downstream extractors.
    req.extensions_mut().insert(state.auth.clone());

    // Extract the token from the cookie or Authorization header
    let token = extract_jwt_token(req.headers()).ok_or(AuthError::MissingToken)?;

    // Verify the token and then rehydrate the account from the database.  JWT
    // role claims are retained for compatibility but never decide access.
    let claims = verify_token(&state.auth.config, token)?;
    let platform_user = state
        .engine_db
        .get_platform_auth_user(&claims.sub)
        .await
        .map_err(|error| {
            AuthError::InternalError(format!("platform identity lookup failed: {error}"))
        })?
        .ok_or(AuthError::InvalidToken)?;
    if !platform_user.is_active {
        return Err(AuthError::InvalidToken);
    }
    // SEC M-1 (CWE-613): revoke per user. The token carries the issuing
    // user's row version; once the row advances (logout, password change,
    // targeted admin revocation, factory reset) older tokens die here — and
    // only for that user.
    if claims.tv < platform_user.token_version {
        warn!(
            user = %platform_user.username,
            token_tv = claims.tv,
            user_tv = platform_user.token_version,
            "SEC: token revoked by per-user token version bump"
        );
        return Err(AuthError::TokenExpired);
    }
    let user = AuthenticatedUser {
        id: platform_user.id,
        username: platform_user.username,
        display_name: platform_user.display_name,
        role: platform_user.role,
        permissions: platform_user.permissions,
        must_change_password: platform_user.must_change_password,
    };
    req.extensions_mut().insert(user.clone());

    // SEC: Enforce per-user password change.  The legacy global gate remains a
    // compatibility fallback for databases upgraded before the RBAC bootstrap.
    let password_changed = *state.auth.config.password_changed.read().await;
    if user.must_change_password
        || (!password_changed && user.username == state.auth.config.username)
    {
        let path = req.uri().path();
        let allowed = path.ends_with("/auth/change-password");
        if !allowed {
            warn!(
                path,
                "SEC: default-password session attempted restricted endpoint, blocked"
            );
            return Err(AuthError::PasswordChangeRequired);
        }
    }

    Ok(next.run(req).await)
}

/// Enforce administrator-only access for privileged routes.
///
/// Must be layered inside `require_auth` so the shared `AuthState` is already
/// attached to request extensions.
pub async fn require_admin(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    if !user.has_permission("platform.manage") {
        return Err(AuthError::Forbidden);
    }

    Ok(next.run(req).await)
}

/// Enforce the persisted permission for analyst feedback submissions.
///
/// Feedback is intentionally available to the analyst role, but it must not
/// be reachable by any authenticated account that merely has read access.
pub async fn require_session_feedback(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    if !user.has_permission("sessions.feedback") {
        return Err(AuthError::Forbidden);
    }

    Ok(next.run(req).await)
}

/// User-management routes are narrower than the legacy admin surface.
pub async fn require_platform_users_manage(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    if !user.has_permission("platform.users.manage") {
        return Err(AuthError::Forbidden);
    }
    Ok(next.run(req).await)
}

/// Role and permission catalog access middleware.
/// User managers may read the catalog so they can assign an existing role,
/// but only role managers may mutate role definitions.
pub async fn require_platform_roles_access(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    let read_only = req.method() == axum::http::Method::GET;
    if !user.has_permission("platform.roles.manage")
        && !(read_only && user.has_permission("platform.users.manage"))
    {
        return Err(AuthError::Forbidden);
    }
    Ok(next.run(req).await)
}

/// Enforce `X-Internal-Token` authentication for internal service routes.
pub async fn require_internal_token(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let expected = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        // Fail closed when the internal token is not configured.
        warn!("INTERNAL_API_TOKEN is not configured; rejecting internal API request");
        return Err(AuthError::MissingToken);
    }

    let provided = req
        .headers()
        .get("X-Internal-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // SEC-H03 + SEC-M01: hash both inputs first to reduce length-based timing leakage
    // before constant-time comparison of fixed-length digests.
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let provided_hash = Sha256::digest(provided.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    if provided_hash.ct_eq(&expected_hash).unwrap_u8() != 1 {
        return Err(AuthError::InvalidToken);
    }

    Ok(next.run(req).await)
}

/// Enforce that internal service routes are only reachable from internal source addresses.
pub async fn require_internal_origin(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let direct_addr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0)
        .ok_or_else(|| AuthError::InternalError("ConnectInfo not found".into()))?;

    if !crate::routes::request_originates_from_internal_network(req.headers(), direct_addr) {
        warn!(
            direct_addr = %direct_addr,
            "Internal API request rejected: non-internal source address"
        );
        return Err(AuthError::InternalSourceDenied);
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, AuthState, LoginRateLimiter, jwt::generate_token};
    use axum::http::{HeaderValue, header};

    const TEST_ADMIN_PASSWORD: &str = "TestAdmin!2345";

    fn test_auth_state() -> AuthState {
        AuthState {
            config: std::sync::Arc::new(AuthConfig::test_config(TEST_ADMIN_PASSWORD)),
            login_rate_limiter: std::sync::Arc::new(LoginRateLimiter::new(10, 60)),
        }
    }

    #[test]
    fn admin_role_match_is_case_insensitive() {
        assert!(is_admin_role("admin"));
        assert!(is_admin_role("ADMIN"));
        assert!(!is_admin_role("viewer"));
    }

    #[test]
    fn validate_admin_request_accepts_admin_token() {
        let auth_state = test_auth_state();
        let token = generate_token(&auth_state.config, "admin", "admin", 0).expect("admin token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
        );

        assert!(validate_admin_request(&headers, &auth_state).is_ok());
    }

    #[test]
    fn validate_admin_request_rejects_non_admin_token() {
        let auth_state = test_auth_state();
        let token = generate_token(&auth_state.config, "viewer", "viewer", 0).expect("viewer token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
        );

        assert!(matches!(
            validate_admin_request(&headers, &auth_state),
            Err(AuthError::Forbidden)
        ));
    }
}
