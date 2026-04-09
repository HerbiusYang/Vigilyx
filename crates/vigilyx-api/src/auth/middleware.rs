//! JWT and internal-token authentication middleware.

use axum::{
    extract::{FromRequestParts, State},
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
fn extract_jwt_token(headers: &axum::http::HeaderMap) -> Option<&str> {
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
fn extract_token_from_cookie(headers: &axum::http::HeaderMap) -> Option<&str> {
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
