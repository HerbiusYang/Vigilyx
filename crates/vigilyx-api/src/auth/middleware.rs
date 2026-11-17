//! JWT and internal-token authentication middleware.

use axum::{
    extract::{FromRequestParts, State},
    http::HeaderMap,
    http::request::Parts,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;
use vigilyx_db::{ADMIN_ROLE_ID, AUDIT_ROLE_ID};

#[cfg(test)]
use super::AuthState;
use super::{AuthError, jwt::verify_token};

/// Authenticated user extracted from a verified JWT.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub id: String,
    /// Immutable RBAC role identifier. Authorization decisions must use this
    /// stable identity rather than the user-editable role display name.
    pub role_id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub must_change_password: bool,
    /// One-way fingerprint of the presented JWT.  It binds privacy leases to
    /// this authenticated session without exposing the token to handlers.
    pub session_id: String,
}

fn fingerprint_auth_session(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn audit_request_is_allowed(method: &axum::http::Method, path: &str) -> bool {
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return true;
    }

    // These are all registered as POST routes.  Checking the method here is
    // essential: a path-only exception would accidentally allow TRACE,
    // CONNECT, or another future write verb through the audit read-only wall.
    if method != axum::http::Method::POST {
        return false;
    }

    // The only non-lifecycle write available to audit is the exact privacy
    // approval/rejection route. The handler still checks the persisted role,
    // permission, factor, ownership, scope and request state.
    let privacy_segments: Vec<&str> = path.split('/').collect();
    if privacy_segments.len() == 6
        && privacy_segments[1] == "api"
        && privacy_segments[2] == "privacy"
        && privacy_segments[3] == "access-requests"
        && Uuid::parse_str(privacy_segments[4]).is_ok()
        && matches!(privacy_segments[5], "approve" | "reject")
    {
        return true;
    }

    // Self-service factor enrollment/rotation is the only other audit write;
    // the handler restricts it to the caller's own factor and never exposes
    // system configuration.
    if path == "/api/privacy/factor" {
        return true;
    }

    // Session lifecycle operations do not modify system configuration. An
    // audit user may log out, obtain a WebSocket ticket, or change their own
    // password while all other write methods remain denied.
    path.ends_with("/auth/logout")
        || path.ends_with("/auth/change-password")
        || path.ends_with("/auth/ws-ticket")
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
        role_id: platform_user.role_id,
        username: platform_user.username,
        display_name: platform_user.display_name,
        role: platform_user.role,
        permissions: platform_user.permissions,
        must_change_password: platform_user.must_change_password,
        session_id: fingerprint_auth_session(token),
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

    if user.role_id == AUDIT_ROLE_ID && !audit_request_is_allowed(req.method(), req.uri().path()) {
        warn!(
            user = %user.username,
            method = %req.method(),
            path = %req.uri().path(),
            "SEC: audit account attempted a write operation; request denied"
        );
        return Err(AuthError::Forbidden);
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
    if user.role_id != ADMIN_ROLE_ID || !user.has_permission("platform.manage") {
        return Err(AuthError::Forbidden);
    }

    Ok(next.run(req).await)
}

/// Enforce read-only access to audit and login history.
///
/// This is intentionally permission-based so the dedicated `audit` role can
/// review the audit surface without receiving the broader `platform.manage`
/// capability used by administrative routes.
pub async fn require_audit_read(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    if !user.has_permission("audit.read") {
        return Err(AuthError::Forbidden);
    }

    Ok(next.run(req).await)
}

async fn require_permission(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
    permission: &'static str,
) -> Result<axum::response::Response, AuthError> {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or(AuthError::InternalError(
            "AuthenticatedUser not found".into(),
        ))?;
    if !user.has_permission(permission) {
        return Err(AuthError::Forbidden);
    }
    Ok(next.run(req).await)
}

pub async fn require_sessions_read(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    require_permission(req, next, "sessions.read").await
}

pub async fn require_security_read(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    require_permission(req, next, "security.read").await
}

pub async fn require_data_security_read(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    require_permission(req, next, "data_security.read").await
}

pub async fn require_system_read(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    require_permission(req, next, "system.read").await
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
fn internal_token_env_for_path(path: &str) -> &'static str {
    match path {
        // Axum removes the outer `/api` prefix before running middleware on
        // a nested Router.  Keep the full forms as well so this helper remains
        // correct if the internal router is mounted without `nest()` in tests
        // or another binary.
        "/system/mta" | "/api/system/mta" => "MTA_API_TOKEN",
        "/system/sniffer"
        | "/api/system/sniffer"
        | "/import/sessions"
        | "/api/import/sessions"
        | "/import/stats"
        | "/api/import/stats"
        | "/data-security/import/http-sessions"
        | "/api/data-security/import/http-sessions"
        | "/internal/sniffer-config"
        | "/api/internal/sniffer-config" => "SNIFFER_API_TOKEN",
        _ => "INTERNAL_API_TOKEN",
    }
}

pub async fn require_internal_token(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AuthError> {
    let token_env = internal_token_env_for_path(req.uri().path());
    let expected = std::env::var(token_env).unwrap_or_default();
    if expected.is_empty() {
        // Fail closed when the internal token is not configured.
        warn!(
            token_env,
            "Internal API token is not configured; rejecting request"
        );
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
    use axum::{
        Extension, Router,
        body::Body,
        http::{HeaderValue, Request, StatusCode, header},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

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
    fn internal_service_tokens_are_endpoint_scoped() {
        for path in ["/system/mta", "/api/system/mta"] {
            assert_eq!(internal_token_env_for_path(path), "MTA_API_TOKEN");
        }
        for path in [
            "/system/sniffer",
            "/api/system/sniffer",
            "/import/sessions",
            "/api/import/sessions",
            "/import/stats",
            "/api/import/stats",
            "/data-security/import/http-sessions",
            "/api/data-security/import/http-sessions",
            "/internal/sniffer-config",
            "/api/internal/sniffer-config",
        ] {
            assert_eq!(internal_token_env_for_path(path), "SNIFFER_API_TOKEN");
        }
        assert_eq!(
            internal_token_env_for_path("/api/metrics"),
            "INTERNAL_API_TOKEN"
        );
        assert_eq!(
            internal_token_env_for_path("/api/system/mta/extra"),
            "INTERNAL_API_TOKEN"
        );
    }

    #[test]
    fn a_custom_role_named_admin_does_not_become_a_system_admin() {
        let user = AuthenticatedUser {
            id: "u".into(),
            role_id: "role-custom".into(),
            username: "operator".into(),
            display_name: "Operator".into(),
            role: "ADMIN".into(),
            permissions: vec!["sessions.read".into()],
            must_change_password: false,
            session_id: "session".into(),
        };
        assert_ne!(user.role_id, "role-admin");
        assert!(user.has_permission("sessions.read"));
        assert!(!user.has_permission("platform.manage"));
    }

    fn route_test_user(permissions: &[&str]) -> AuthenticatedUser {
        AuthenticatedUser {
            id: "u-route-test".into(),
            role_id: "role-custom".into(),
            username: "route-test".into(),
            display_name: "Route Test".into(),
            role: "viewer".into(),
            permissions: permissions
                .iter()
                .map(|permission| (*permission).into())
                .collect(),
            must_change_password: false,
            session_id: "route-test-session".into(),
        }
    }

    #[tokio::test]
    async fn sessions_read_route_rejects_authenticated_user_without_permission() {
        let app = Router::new()
            .route(
                "/",
                get(|| async { "ok" }).route_layer(middleware::from_fn(require_sessions_read)),
            )
            .layer(Extension(route_test_user(&["security.read"])));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sessions_read_route_allows_authenticated_user_with_permission() {
        let app = Router::new()
            .route(
                "/",
                get(|| async { "ok" }).route_layer(middleware::from_fn(require_sessions_read)),
            )
            .layer(Extension(route_test_user(&["sessions.read"])));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_route_rejects_non_admin_role_even_with_platform_permission() {
        let app = Router::new()
            .route(
                "/",
                get(|| async { "ok" }).route_layer(middleware::from_fn(require_admin)),
            )
            .layer(Extension(route_test_user(&["platform.manage"])));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_route_allows_exact_admin_role_with_platform_permission() {
        let mut user = route_test_user(&["platform.manage"]);
        user.role_id = ADMIN_ROLE_ID.to_string();
        let app = Router::new()
            .route(
                "/",
                get(|| async { "ok" }).route_layer(middleware::from_fn(require_admin)),
            )
            .layer(Extension(user));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    macro_rules! assert_read_guard_denies_missing_permission {
        ($test_name:ident, $guard:ident, $unrelated_permission:literal) => {
            #[tokio::test]
            async fn $test_name() {
                let app = Router::new()
                    .route(
                        "/",
                        get(|| async { "ok" }).route_layer(middleware::from_fn($guard)),
                    )
                    .layer(Extension(route_test_user(&[$unrelated_permission])));

                let response = app
                    .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                    .await
                    .unwrap();

                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            }
        };
    }

    assert_read_guard_denies_missing_permission!(
        security_read_route_rejects_without_permission,
        require_security_read,
        "sessions.read"
    );
    assert_read_guard_denies_missing_permission!(
        data_security_read_route_rejects_without_permission,
        require_data_security_read,
        "sessions.read"
    );
    assert_read_guard_denies_missing_permission!(
        system_read_route_rejects_without_permission,
        require_system_read,
        "sessions.read"
    );

    #[test]
    fn audit_accounts_are_read_only_except_for_session_lifecycle() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/security/config"
        ));
        assert!(!audit_request_is_allowed(
            &axum::http::Method::PUT,
            "/api/security/config"
        ));
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/change-password"
        ));
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/logout"
        ));
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
        let token =
            generate_token(&auth_state.config, "viewer", "viewer", 0).expect("viewer token");
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

    #[test]
    fn deep_audit_get_system_config_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/config"
        ));
    }

    #[test]
    fn deep_audit_head_system_config_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::HEAD,
            "/api/config"
        ));
    }

    #[test]
    fn deep_audit_options_system_config_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::OPTIONS,
            "/api/config"
        ));
    }

    #[test]
    fn deep_audit_get_audit_logs_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/audit/logs"
        ));
    }

    #[test]
    fn deep_audit_get_platform_users_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/platform/users"
        ));
    }

    #[test]
    fn deep_audit_get_data_security_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/security/data"
        ));
    }

    #[test]
    fn deep_audit_get_sessions_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/sessions"
        ));
    }

    #[test]
    fn deep_audit_get_unknown_read_path_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::GET,
            "/api/read-only-extension"
        ));
    }

    #[test]
    fn deep_audit_post_system_config_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/config"
        ));
    }

    #[test]
    fn deep_audit_put_security_config_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::PUT,
            "/api/security/config"
        ));
    }

    #[test]
    fn deep_audit_patch_platform_users_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::PATCH,
            "/api/platform/users/user-1"
        ));
    }

    #[test]
    fn deep_audit_delete_platform_role_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::DELETE,
            "/api/platform/roles/role-1"
        ));
    }

    #[test]
    fn deep_audit_post_audit_logs_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/audit/logs"
        ));
    }

    #[test]
    fn deep_audit_post_data_security_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/security/data/import"
        ));
    }

    #[test]
    fn deep_audit_post_sessions_feedback_is_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/sessions/session-1/feedback"
        ));
    }

    #[test]
    fn deep_audit_post_logout_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/logout"
        ));
    }

    #[test]
    fn deep_audit_post_change_password_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/change-password"
        ));
    }

    #[test]
    fn deep_audit_post_ws_ticket_is_allowed() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/ws-ticket"
        ));
    }

    #[test]
    fn deep_audit_nonstandard_methods_are_denied() {
        assert!(!audit_request_is_allowed(
            &axum::http::Method::TRACE,
            "/api/auth/logout"
        ));
        assert!(!audit_request_is_allowed(
            &axum::http::Method::CONNECT,
            "/api/auth/logout"
        ));
    }

    #[test]
    fn deep_audit_lifecycle_path_must_match_exact_suffix() {
        assert!(audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/logout"
        ));
        assert!(!audit_request_is_allowed(
            &axum::http::Method::POST,
            "/api/auth/logout/extra"
        ));
    }
}
