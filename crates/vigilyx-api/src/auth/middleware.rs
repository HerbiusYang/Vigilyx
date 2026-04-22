//! JWT and internal-token authentication middleware.

use axum::{
    extract::{FromRequestParts, State},
    http::HeaderMap,
    http::request::Parts,
};
use std::sync::Arc;
use tracing::warn;

use super::{AuthError, AuthState, jwt::verify_token};

/// Authenticated user extracted from a verified JWT.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub username: String,
    pub role: String,
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
        .find_map(|pair| {
            pair.strip_prefix("vigilyx_token=")
        })
}

/// Extract `AuthenticatedUser` from request parts.
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
       // Read `AuthState` from request extensions.
        let auth_state = parts
            .extensions
            .get::<AuthState>()
            .ok_or(AuthError::InternalError("AuthState not found".into()))?;

       // Extract the token from the cookie or Authorization header
        let token = extract_jwt_token(&parts.headers)
            .ok_or(AuthError::MissingToken)?;

       // Verify the token.
        let claims = verify_token(&auth_state.config, token)?;

        Ok(AuthenticatedUser {
            username: claims.sub,
            role: claims.role,
        })
    }
}

pub(crate) fn is_admin_role(role: &str) -> bool {
    role.eq_ignore_ascii_case("admin")
}

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
    let token = extract_jwt_token(req.headers())
        .ok_or(AuthError::MissingToken)?;

   // Verify the token.
    verify_token(&state.auth.config, token)?;

   // SEC: Enforce password change - default-password sessions can only access change-password
    let password_changed = *state.auth.config.password_changed.read().await;
    if !password_changed {
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
    let auth_state = req
        .extensions()
        .get::<AuthState>()
        .cloned()
        .ok_or(AuthError::InternalError("AuthState not found".into()))?;

    validate_admin_request(req.headers(), &auth_state)?;

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
    use crate::auth::{AuthConfig, LoginRateLimiter, jwt::generate_token};
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
        let token = generate_token(&auth_state.config, "admin", "admin").expect("admin token");
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
        let token = generate_token(&auth_state.config, "viewer", "viewer").expect("viewer token");
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
