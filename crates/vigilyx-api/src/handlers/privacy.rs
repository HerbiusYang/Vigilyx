//! Global privacy dual-control API.
//!
//! The client receives request metadata only.  The approval factor and the
//! internal lease nonce never appear in a response, URL, or log.  Content
//! handlers use the request id as a non-secret server-side lookup handle and
//! must still satisfy the exact user/session/resource/scope checks in the DB.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

use super::ApiResponse;
use crate::{AppState, auth::AuthenticatedUser};
use vigilyx_db::{ADMIN_ROLE_ID, AUDIT_ROLE_ID};

pub(crate) const PRIVACY_REQUEST_ID_HEADER: &str = "x-vigilyx-privacy-lease";
pub(crate) const PRIVACY_POLICY_KEY: &str = "privacy_policy";
const PRIVACY_DISABLED_SCOPE: &str = "__privacy_disabled__";
const LEASE_TTL_SECONDS: i64 = 5 * 60;
const MAX_PURPOSE_CHARS: usize = 500;
const MAX_SCOPES: usize = 4;
const FACTOR_MAX_ATTEMPTS: i32 = 5;
const FACTOR_LOCK_SECONDS: i64 = 5 * 60;

const ALLOWED_SCOPES: &[&str] = &[
    "body",
    "html",
    "headers",
    "verdict",
    "attachment_download",
    "eml_download",
    "http_body",
];

fn parse_privacy_enabled(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };

    if let Ok(enabled) = serde_json::from_str::<bool>(value) {
        return enabled;
    }
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .and_then(|value| value.get("enabled").and_then(serde_json::Value::as_bool))
        .unwrap_or(true)
}

/// Missing, malformed, or unreadable configuration keeps redaction enabled.
pub(crate) async fn privacy_enabled(state: &AppState) -> bool {
    match state.engine_db.get_config(PRIVACY_POLICY_KEY).await {
        Ok(value) => parse_privacy_enabled(value.as_deref()),
        Err(error) => {
            tracing::warn!(error = %error, "Privacy policy lookup failed; keeping privacy mode enabled");
            true
        }
    }
}

fn unrestricted_scopes() -> HashSet<String> {
    ALLOWED_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .chain(std::iter::once(PRIVACY_DISABLED_SCOPE.to_string()))
        .collect()
}

pub(crate) async fn default_scopes(state: &AppState) -> HashSet<String> {
    if privacy_enabled(state).await {
        HashSet::new()
    } else {
        unrestricted_scopes()
    }
}

pub(crate) fn is_privacy_disabled(scopes: &HashSet<String>) -> bool {
    scopes.contains(PRIVACY_DISABLED_SCOPE)
}

/// Keep a small, useful identity hint in default responses without exposing
/// the mailbox local-part. Domains remain visible for routing/audit context,
/// while the full address is only returned under an approved header scope.
pub(crate) fn mask_email_address(value: &str) -> String {
    let value = value.trim();
    let Some((local, domain)) = value.rsplit_once('@') else {
        return mask_identifier(value);
    };
    let local = local.trim();
    let domain = domain.trim();
    let Some(first) = local.chars().next() else {
        return mask_identifier(value);
    };
    if domain.is_empty() || first.is_control() {
        return mask_identifier(value);
    }
    format!("{first}****@{}", domain.to_ascii_lowercase())
}

/// Mask non-email identifiers (for example an SMTP AUTH username) while
/// retaining enough context for an operator to correlate repeated events.
pub(crate) fn mask_identifier(value: &str) -> String {
    let value = value.trim();
    let Some(first) = value.chars().next() else {
        return "[REDACTED]".to_string();
    };
    if first.is_control() {
        return "[REDACTED]".to_string();
    }
    format!("{first}****")
}

/// Keep only a small correlation hint for subjects in default API responses.
/// The full subject remains available only under the explicit `headers` scope.
pub(crate) fn mask_subject(value: &str) -> String {
    const SUBJECT_MASK: &str = "******";

    let chars: Vec<char> = value.trim().chars().collect();
    match chars.as_slice() {
        [] => String::new(),
        [only] if !only.is_control() => SUBJECT_MASK.to_string(),
        [first, .., last] if !first.is_control() && !last.is_control() => {
            format!("{first}{SUBJECT_MASK}{last}")
        }
        _ => SUBJECT_MASK.to_string(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePrivacyAccessRequest {
    pub resource_type: String,
    pub resource_id: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    #[serde(default)]
    pub admin_key: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: i64,
}

fn default_ttl_seconds() -> i64 {
    300
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyFactorRequest {
    #[serde(alias = "factor", alias = "audit_key")]
    pub factor: String,
}

#[derive(Debug, Serialize)]
pub struct PrivacyLeaseResponse {
    pub request_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
    pub uses_remaining: i32,
    /// This is a non-secret request handle. Authorization still requires the
    /// current JWT session binding and the exact server-side lease row.
    pub lease_handle: String,
}

#[derive(Debug, Serialize)]
pub struct PrivacyContextResponse {
    pub current_user: PrivacyCurrentUser,
    pub active_leases: Vec<PrivacyLeaseResponse>,
}

#[derive(Debug, Serialize)]
pub struct PrivacyCurrentUser {
    pub id: String,
    pub role_id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub factor_configured: bool,
}

#[derive(Debug, Serialize)]
pub struct PrivacyPolicyResponse {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePrivacyPolicyRequest {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
struct PrivacyActionResponse {
    status: &'static str,
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        ApiResponse::<serde_json::Value>::err("Privacy approval required"),
    )
        .into_response()
}

fn conflict() -> Response {
    (
        StatusCode::CONFLICT,
        ApiResponse::<serde_json::Value>::err("Privacy request is no longer pending"),
    )
        .into_response()
}

fn is_exact_admin(user: &AuthenticatedUser) -> bool {
    // The persisted role ID is authoritative; `role` is display metadata.
    user.role_id == ADMIN_ROLE_ID && user.has_permission("privacy.request")
}

fn is_exact_audit(user: &AuthenticatedUser) -> bool {
    user.role_id == AUDIT_ROLE_ID && user.has_permission("privacy.approve")
}

fn is_control_free(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

pub(crate) fn normalize_scopes(scopes: &[String]) -> Result<Vec<String>, &'static str> {
    if scopes.is_empty() || scopes.len() > MAX_SCOPES {
        return Err("Invalid privacy scope");
    }
    let mut normalized = scopes.to_vec();
    normalized.sort();
    normalized.dedup();
    if normalized.len() != scopes.len()
        || normalized
            .iter()
            .any(|scope| !ALLOWED_SCOPES.contains(&scope.as_str()))
    {
        return Err("Invalid privacy scope");
    }
    Ok(normalized)
}

pub(crate) fn validate_create_request(
    request: &CreatePrivacyAccessRequest,
) -> Result<Vec<String>, &'static str> {
    let valid_resource = match request.resource_type.as_str() {
        "session" | "http_session" => Uuid::parse_str(&request.resource_id).is_ok(),
        "attachment" => request
            .resource_id
            .split_once(':')
            .is_some_and(|(session_id, index)| {
                Uuid::parse_str(session_id).is_ok() && index.parse::<usize>().is_ok()
            }),
        _ => false,
    };
    if !valid_resource
        || request.purpose.trim().is_empty()
        || request.purpose.chars().count() > MAX_PURPOSE_CHARS
        || !is_control_free(&request.purpose)
    {
        return Err("Invalid privacy request");
    }
    normalize_scopes(&request.scopes)
}

fn request_id_from_headers(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(PRIVACY_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())?;
    (value.len() <= 64 && Uuid::parse_str(value).is_ok()).then_some(value)
}

pub(crate) fn scope_permission(scope: &str) -> &'static str {
    match scope {
        "eml_download" | "attachment_download" => "privacy.eml.download",
        _ => "privacy.reveal",
    }
}

fn nonce_hash() -> String {
    let nonce = Uuid::new_v4().to_string();
    Sha256::digest(nonce.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn verify_operator_factor(
    state: &AppState,
    user: &AuthenticatedUser,
    factor: &str,
) -> Option<i64> {
    if factor.is_empty() || factor.chars().count() > 4096 {
        return None;
    }
    let secret = state
        .engine_db
        .get_privacy_operator_secret(&user.id)
        .await
        .ok()
        .flatten()?;

    if let Some(locked_until) = secret.locked_until.as_deref() {
        match chrono::DateTime::parse_from_rfc3339(locked_until) {
            Ok(deadline) if deadline > Utc::now() => return None,
            Err(_) => return None,
            _ => {}
        }
    }

    let valid = crate::auth::verify_password(factor, &secret.verifier).unwrap_or(false);
    if valid {
        let _ = state
            .engine_db
            .clear_privacy_factor_failures(&user.id)
            .await;
    } else {
        let _ = state
            .engine_db
            .record_privacy_factor_failure(&user.id, FACTOR_MAX_ATTEMPTS, FACTOR_LOCK_SECONDS)
            .await;
    }
    valid.then_some(secret.factor_version)
}

pub async fn create_access_request(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<CreatePrivacyAccessRequest>,
) -> Response {
    if !is_exact_admin(&user) {
        return forbidden();
    }
    if verify_operator_factor(&state, &user, &request.admin_key)
        .await
        .is_none()
    {
        return forbidden();
    }
    let scopes = match validate_create_request(&request) {
        Ok(scopes) => scopes,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
        }
    };

    let now = Utc::now();
    let ttl = request.ttl_seconds.clamp(60, LEASE_TTL_SECONDS);
    let expires_at = (now + Duration::seconds(ttl)).to_rfc3339();
    let id = Uuid::new_v4().to_string();
    match state
        .engine_db
        .create_privacy_access_request(
            &id,
            &user.id,
            &user.session_id,
            &request.resource_type,
            &request.resource_id,
            &scopes,
            request.purpose.trim(),
            &expires_at,
        )
        .await
    {
        Ok(created) => ApiResponse::ok(created).into_response(),
        Err(error) => ApiResponse::<serde_json::Value>::server_error(
            &error,
            "Privacy request creation failed",
        )
        .into_response(),
    }
}

pub async fn list_access_requests(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Response {
    let (subject, pending_only) = if is_exact_audit(&user) {
        (&user.id, true)
    } else if is_exact_admin(&user) {
        (&user.id, false)
    } else {
        return forbidden();
    };

    match state
        .engine_db
        .list_privacy_access_requests(subject, pending_only)
        .await
    {
        Ok(requests) => ApiResponse::ok(requests).into_response(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Privacy request listing failed")
                .into_response()
        }
    }
}

pub async fn approve_access_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    user: AuthenticatedUser,
    Json(request): Json<PrivacyFactorRequest>,
) -> Response {
    if !is_exact_audit(&user) || !Uuid::parse_str(&id).is_ok_and(|_| id.len() <= 64) {
        return forbidden();
    }
    let Some(approver_factor_version) =
        verify_operator_factor(&state, &user, &request.factor).await
    else {
        return forbidden();
    };

    let now = Utc::now();
    let expires_at = (now + Duration::seconds(LEASE_TTL_SECONDS)).to_rfc3339();
    match state
        .engine_db
        .approve_privacy_access_request(
            &id,
            &user.id,
            &user.session_id,
            approver_factor_version,
            &nonce_hash(),
            &now.to_rfc3339(),
            &expires_at,
            &user.id,
        )
        .await
    {
        Ok(Some(request)) => ApiResponse::ok(request).into_response(),
        Ok(None) => conflict(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Privacy approval failed")
                .into_response()
        }
    }
}

pub async fn reject_access_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    user: AuthenticatedUser,
) -> Response {
    if !is_exact_audit(&user) || Uuid::parse_str(&id).is_err() {
        return forbidden();
    }
    match state
        .engine_db
        .reject_privacy_access_request(&id, &user.id, &user.session_id)
        .await
    {
        Ok(true) => match state.engine_db.get_privacy_access_request(&id).await {
            Ok(Some(request)) => ApiResponse::ok(request).into_response(),
            Ok(None) => conflict(),
            Err(error) => ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy rejection lookup failed",
            )
            .into_response(),
        },
        Ok(false) => conflict(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Privacy rejection failed")
                .into_response()
        }
    }
}

pub async fn revoke_access_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    user: AuthenticatedUser,
) -> Response {
    if !is_exact_admin(&user) || Uuid::parse_str(&id).is_err() {
        return forbidden();
    }
    let Some(request) = state
        .engine_db
        .get_privacy_access_request(&id)
        .await
        .ok()
        .flatten()
    else {
        return ApiResponse::<serde_json::Value>::not_found("Privacy request not found")
            .into_response();
    };
    if request.requester_user_id != user.id {
        return forbidden();
    }
    match state
        .engine_db
        .revoke_privacy_access_request(&id, &user.id)
        .await
    {
        Ok(true) => ApiResponse::ok(PrivacyActionResponse { status: "revoked" }).into_response(),
        Ok(false) => conflict(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Privacy revocation failed")
                .into_response()
        }
    }
}

pub async fn get_privacy_policy(
    State(state): State<Arc<AppState>>,
    _user: AuthenticatedUser,
) -> Response {
    ApiResponse::ok(PrivacyPolicyResponse {
        enabled: privacy_enabled(&state).await,
    })
    .into_response()
}

pub async fn update_privacy_policy(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<UpdatePrivacyPolicyRequest>,
) -> Response {
    if !is_exact_admin(&user) {
        return forbidden();
    }

    let value = serde_json::json!({ "enabled": request.enabled }).to_string();
    if let Err(error) = state.engine_db.set_config(PRIVACY_POLICY_KEY, &value).await {
        return ApiResponse::<serde_json::Value>::server_error(
            &error,
            "Privacy policy update failed",
        )
        .into_response();
    }

    super::spawn_audit_log(
        state.engine_db.clone(),
        user.username,
        "update_privacy_policy",
        Some("config"),
        Some(PRIVACY_POLICY_KEY.to_string()),
        Some(format!("enabled={}", request.enabled)),
    );

    ApiResponse::ok(PrivacyPolicyResponse {
        enabled: request.enabled,
    })
    .into_response()
}

pub(crate) async fn active_scopes(
    state: &AppState,
    user: &AuthenticatedUser,
    request_id: Option<&str>,
    resource_type: &str,
    resource_id: &str,
) -> anyhow::Result<HashSet<String>> {
    if !privacy_enabled(state).await {
        return Ok(unrestricted_scopes());
    }
    let Some(request_id) = request_id else {
        return Ok(HashSet::new());
    };
    let scopes = state
        .engine_db
        .active_privacy_scopes(
            request_id,
            &user.id,
            &user.session_id,
            resource_type,
            resource_id,
        )
        .await?;
    Ok(scopes.into_iter().collect())
}

pub(crate) async fn consume_scope(
    state: &AppState,
    user: &AuthenticatedUser,
    request_id: Option<&str>,
    resource_type: &str,
    resource_id: &str,
    scope: &str,
) -> anyhow::Result<bool> {
    if !privacy_enabled(state).await {
        return Ok(true);
    }
    let Some(request_id) = request_id else {
        return Ok(false);
    };
    if !user.has_permission(scope_permission(scope)) {
        return Ok(false);
    }
    state
        .engine_db
        .consume_privacy_scope(
            request_id,
            &user.id,
            &user.session_id,
            resource_type,
            resource_id,
            scope,
        )
        .await
}

pub(crate) fn request_id_header(headers: &HeaderMap) -> Option<&str> {
    request_id_from_headers(headers)
}

pub(crate) fn can_reveal(user: &AuthenticatedUser, scopes: &HashSet<String>, scope: &str) -> bool {
    is_privacy_disabled(scopes)
        || (user.has_permission(scope_permission(scope)) && scopes.contains(scope))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPrivacyFactorRequest {
    pub factor: String,
    #[serde(default)]
    pub current_factor: Option<String>,
}

pub async fn set_operator_factor(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<SetPrivacyFactorRequest>,
) -> Response {
    let allowed = is_exact_admin(&user) || is_exact_audit(&user);
    if !allowed || request.factor.chars().count() < 12 || request.factor.chars().count() > 4096 {
        return forbidden();
    }
    let existing = match state.engine_db.get_privacy_operator_secret(&user.id).await {
        Ok(secret) => secret,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy factor setup failed",
            )
            .into_response();
        }
    };

    if let Some(secret) = existing {
        let Some(current_factor) = request
            .current_factor
            .as_deref()
            .filter(|factor| !factor.is_empty())
        else {
            return forbidden();
        };
        if verify_operator_factor(&state, &user, current_factor).await
            != Some(secret.factor_version)
        {
            return forbidden();
        }
        let verifier = match crate::auth::hash_password(&request.factor) {
            Ok(value) => value,
            Err(_) => {
                return ApiResponse::<serde_json::Value>::server_error(
                    &"factor hash failed",
                    "Privacy factor setup failed",
                )
                .into_response();
            }
        };
        match state
            .engine_db
            .rotate_privacy_operator_secret(&user.id, &verifier, secret.factor_version)
            .await
        {
            Ok(true) => {
                super::spawn_audit_log(
                    state.engine_db.clone(),
                    user.username,
                    "rotate_privacy_factor",
                    Some("privacy_operator_factor"),
                    Some(user.id),
                    Some("active privacy leases revoked".to_string()),
                );
                ApiResponse::ok(PrivacyActionResponse { status: "rotated" }).into_response()
            }
            Ok(false) => forbidden(),
            Err(error) => ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy factor setup failed",
            )
            .into_response(),
        }
    } else {
        let verifier = match crate::auth::hash_password(&request.factor) {
            Ok(value) => value,
            Err(_) => {
                return ApiResponse::<serde_json::Value>::server_error(
                    &"factor hash failed",
                    "Privacy factor setup failed",
                )
                .into_response();
            }
        };
        match state
            .engine_db
            .create_privacy_operator_secret(&user.id, &verifier)
            .await
        {
            Ok(true) => {
                super::spawn_audit_log(
                    state.engine_db.clone(),
                    user.username,
                    "enroll_privacy_factor",
                    Some("privacy_operator_factor"),
                    Some(user.id),
                    None,
                );
                ApiResponse::ok(PrivacyActionResponse {
                    status: "configured",
                })
                .into_response()
            }
            // Another request won the first-enrollment race.  Never fall back
            // to an overwrite; the caller must retry as a rotation with the
            // established factor.
            Ok(false) => forbidden(),
            Err(error) => ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy factor setup failed",
            )
            .into_response(),
        }
    }
}

pub async fn get_privacy_context(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Response {
    let factor_configured = match state.engine_db.get_privacy_operator_secret(&user.id).await {
        Ok(secret) => secret.is_some(),
        Err(error) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy context lookup failed",
            )
            .into_response();
        }
    };
    let leases = match state
        .engine_db
        .list_privacy_lease_summaries(&user.id, &user.session_id)
        .await
    {
        Ok(items) => items
            .into_iter()
            .map(
                |(request_id, resource_type, resource_id, scopes, expires_at, uses_remaining)| {
                    PrivacyLeaseResponse {
                        request_id: request_id.clone(),
                        resource_type,
                        resource_id,
                        scopes,
                        expires_at,
                        uses_remaining,
                        lease_handle: request_id,
                    }
                },
            )
            .collect(),
        Err(error) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy context lookup failed",
            )
            .into_response();
        }
    };
    ApiResponse::ok(PrivacyContextResponse {
        current_user: PrivacyCurrentUser {
            id: user.id,
            role_id: user.role_id,
            username: user.username,
            display_name: user.display_name,
            role: user.role,
            permissions: user.permissions,
            factor_configured,
        },
        active_leases: leases,
    })
    .into_response()
}

pub async fn acquire_privacy_lease(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    user: AuthenticatedUser,
) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return forbidden();
    }
    let Some(request) = state
        .engine_db
        .get_privacy_access_request(&id)
        .await
        .ok()
        .flatten()
    else {
        return ApiResponse::<serde_json::Value>::not_found("Privacy request not found")
            .into_response();
    };
    if request.status != "approved" {
        return conflict();
    }
    let summary = match state
        .engine_db
        .privacy_lease_summary(
            &id,
            &user.id,
            &user.session_id,
            &request.resource_type,
            &request.resource_id,
        )
        .await
    {
        Ok(Some(summary)) => summary,
        Ok(None) => return forbidden(),
        Err(error) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Privacy lease lookup failed",
            )
            .into_response();
        }
    };
    ApiResponse::ok(PrivacyLeaseResponse {
        request_id: id.clone(),
        resource_type: request.resource_type,
        resource_id: request.resource_id,
        scopes: summary.0,
        expires_at: summary.1,
        uses_remaining: summary.2,
        lease_handle: id,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticatedUser;
    use proptest::prelude::*;

    #[test]
    fn email_mask_keeps_first_character_and_domain_only() {
        assert_eq!(
            mask_email_address("analyst@CORP.EXAMPLE"),
            "a****@corp.example"
        );
        assert_eq!(mask_email_address("a@example.com"), "a****@example.com");
    }

    #[test]
    fn malformed_email_mask_does_not_return_the_original_value() {
        assert_eq!(mask_email_address("synthetic-id"), "s****");
        assert_eq!(mask_email_address(""), "[REDACTED]");
    }

    #[test]
    fn identifier_mask_keeps_only_a_correlation_hint() {
        assert_eq!(mask_identifier("alice"), "a****");
        assert_eq!(mask_identifier(""), "[REDACTED]");
    }

    #[test]
    fn subject_mask_keeps_first_and_last_character_only() {
        assert_eq!(mask_subject(" 关于123123的文件 "), "关******件");
        assert_eq!(mask_subject("Quarterly"), "Q******y");
        assert_eq!(mask_subject(""), "");
        assert_eq!(mask_subject("\u{1}"), "******");
    }

    #[test]
    fn privacy_role_checks_ignore_user_editable_role_names() {
        let mut custom_admin_name = user("admin", &["privacy.request"]);
        custom_admin_name.role_id = "role-custom".into();
        assert!(!is_exact_admin(&custom_admin_name));

        let mut custom_audit_name = user("audit", &["privacy.approve"]);
        custom_audit_name.role_id = "role-custom".into();
        assert!(!is_exact_audit(&custom_audit_name));
    }

    fn user(role: &str, permissions: &[&str]) -> AuthenticatedUser {
        AuthenticatedUser {
            id: "user".into(),
            role_id: match role {
                "admin" => "role-admin",
                "audit" => "role-audit",
                _ => "role-custom",
            }
            .into(),
            username: "user".into(),
            display_name: "User".into(),
            role: role.into(),
            permissions: permissions.iter().map(|value| (*value).into()).collect(),
            must_change_password: false,
            session_id: "session".into(),
        }
    }

    #[test]
    fn privacy_request_scopes_are_sorted_and_unique() {
        let scopes = vec!["html".into(), "body".into()];
        assert_eq!(normalize_scopes(&scopes).unwrap(), vec!["body", "html"]);
    }

    #[test]
    fn privacy_request_rejects_duplicate_scope() {
        let scopes = vec!["body".into(), "body".into()];
        assert!(normalize_scopes(&scopes).is_err());
    }

    #[test]
    fn privacy_request_rejects_unknown_scope() {
        assert!(normalize_scopes(&["all".into()]).is_err());
    }

    #[test]
    fn privacy_request_rejects_empty_scope_set() {
        assert!(normalize_scopes(&[]).is_err());
    }

    #[test]
    fn privacy_request_accepts_eml_scope() {
        assert_eq!(
            normalize_scopes(&["eml_download".into()]).unwrap(),
            vec!["eml_download"]
        );
    }

    #[test]
    fn privacy_request_requires_admin_role() {
        assert!(!is_exact_admin(&user("audit", &["privacy.request"])));
    }

    #[test]
    fn privacy_request_requires_admin_permission() {
        assert!(!is_exact_admin(&user("admin", &[])));
    }

    #[test]
    fn privacy_approval_requires_audit_role() {
        assert!(!is_exact_audit(&user("admin", &["privacy.approve"])));
    }

    #[test]
    fn privacy_approval_requires_audit_permission() {
        assert!(!is_exact_audit(&user("audit", &[])));
    }

    #[test]
    fn privacy_request_accepts_session_uuid() {
        let request = CreatePrivacyAccessRequest {
            resource_type: "session".into(),
            resource_id: Uuid::nil().to_string(),
            scopes: vec!["body".into()],
            purpose: "incident review".into(),
            admin_key: String::new(),
            ttl_seconds: 300,
        };
        assert!(validate_create_request(&request).is_ok());
    }

    #[test]
    fn privacy_request_rejects_non_session_resource() {
        let request = CreatePrivacyAccessRequest {
            resource_type: "user".into(),
            resource_id: Uuid::nil().to_string(),
            scopes: vec!["body".into()],
            purpose: "incident review".into(),
            admin_key: String::new(),
            ttl_seconds: 300,
        };
        assert!(validate_create_request(&request).is_err());
    }

    #[test]
    fn privacy_request_rejects_bad_resource_id() {
        let request = CreatePrivacyAccessRequest {
            resource_type: "session".into(),
            resource_id: "not-an-id".into(),
            scopes: vec!["body".into()],
            purpose: "incident review".into(),
            admin_key: String::new(),
            ttl_seconds: 300,
        };
        assert!(validate_create_request(&request).is_err());
    }

    #[test]
    fn privacy_request_rejects_blank_purpose() {
        let request = CreatePrivacyAccessRequest {
            resource_type: "session".into(),
            resource_id: Uuid::nil().to_string(),
            scopes: vec!["body".into()],
            purpose: "  ".into(),
            admin_key: String::new(),
            ttl_seconds: 300,
        };
        assert!(validate_create_request(&request).is_err());
    }

    #[test]
    fn privacy_request_rejects_control_character_purpose() {
        let request = CreatePrivacyAccessRequest {
            resource_type: "session".into(),
            resource_id: Uuid::nil().to_string(),
            scopes: vec!["body".into()],
            purpose: "review\nsecret".into(),
            admin_key: String::new(),
            ttl_seconds: 300,
        };
        assert!(validate_create_request(&request).is_err());
    }

    #[test]
    fn privacy_request_id_accepts_header_uuid() {
        let id = Uuid::new_v4().to_string();
        let mut headers = HeaderMap::new();
        headers.insert(PRIVACY_REQUEST_ID_HEADER, id.parse().unwrap());
        assert_eq!(request_id_from_headers(&headers), Some(id.as_str()));
    }

    #[test]
    fn privacy_request_id_rejects_missing_header() {
        assert!(request_id_from_headers(&HeaderMap::new()).is_none());
    }

    #[test]
    fn privacy_request_id_rejects_malformed_header() {
        let mut headers = HeaderMap::new();
        headers.insert(PRIVACY_REQUEST_ID_HEADER, "not-a-uuid".parse().unwrap());
        assert!(request_id_from_headers(&headers).is_none());
    }

    #[test]
    fn privacy_body_uses_reveal_permission() {
        assert_eq!(scope_permission("body"), "privacy.reveal");
    }

    #[test]
    fn privacy_html_uses_reveal_permission() {
        assert_eq!(scope_permission("html"), "privacy.reveal");
    }

    #[test]
    fn privacy_headers_use_reveal_permission() {
        assert_eq!(scope_permission("headers"), "privacy.reveal");
    }

    #[test]
    fn privacy_attachment_uses_download_permission() {
        assert_eq!(
            scope_permission("attachment_download"),
            "privacy.eml.download"
        );
    }

    #[test]
    fn privacy_eml_uses_download_permission() {
        assert_eq!(scope_permission("eml_download"), "privacy.eml.download");
    }

    #[test]
    fn privacy_scope_requires_exact_lease() {
        let mut scopes = HashSet::new();
        scopes.insert("body".to_string());
        assert!(!can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "html"
        ));
    }

    #[test]
    fn privacy_scope_requires_user_permission() {
        let mut scopes = HashSet::new();
        scopes.insert("body".to_string());
        assert!(!can_reveal(&user("admin", &[]), &scopes, "body"));
    }

    #[test]
    fn privacy_scope_allows_exact_permission_and_lease() {
        let mut scopes = HashSet::new();
        scopes.insert("body".to_string());
        assert!(can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "body"
        ));
    }

    #[test]
    fn privacy_download_does_not_use_reveal_permission() {
        let mut scopes = HashSet::new();
        scopes.insert("eml_download".to_string());
        assert!(!can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "eml_download"
        ));
    }

    #[test]
    fn privacy_download_scopes_require_download_permission_for_each_resource() {
        for scope in ["attachment_download", "eml_download"] {
            let mut scopes = HashSet::new();
            scopes.insert(scope.to_string());
            assert!(can_reveal(
                &user("admin", &["privacy.eml.download"]),
                &scopes,
                scope,
            ));
            assert!(!can_reveal(
                &user("admin", &["privacy.reveal"]),
                &scopes,
                scope,
            ));
        }
    }

    #[test]
    fn privacy_content_scopes_require_both_lease_and_reveal_permission() {
        for scope in ["body", "html", "headers", "verdict", "http_body"] {
            let mut scopes = HashSet::new();
            scopes.insert(scope.to_string());
            assert!(can_reveal(
                &user("admin", &["privacy.reveal"]),
                &scopes,
                scope,
            ));
            assert!(!can_reveal(&user("audit", &[]), &scopes, scope));
        }
    }

    #[test]
    fn privacy_scope_set_does_not_allow_unknown_or_unleased_scope() {
        let scopes = HashSet::from(["body".to_string()]);
        let privileged = user("admin", &["privacy.reveal", "privacy.eml.download"]);
        assert!(!can_reveal(&privileged, &scopes, "headers"));
        assert!(!can_reveal(&privileged, &scopes, "unknown"));
    }

    fn valid_request(
        resource_type: &str,
        resource_id: String,
        scopes: &[&str],
        purpose: &str,
    ) -> CreatePrivacyAccessRequest {
        CreatePrivacyAccessRequest {
            resource_type: resource_type.into(),
            resource_id,
            scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            purpose: purpose.into(),
            admin_key: "not-used-by-validation".into(),
            ttl_seconds: 300,
        }
    }

    #[test]
    fn privacy_request_accepts_http_session_uuid() {
        assert!(
            validate_create_request(&valid_request(
                "http_session",
                Uuid::new_v4().to_string(),
                &["http_body"],
                "http review"
            ))
            .is_ok()
        );
    }

    #[test]
    fn privacy_request_accepts_attachment_reference() {
        assert!(
            validate_create_request(&valid_request(
                "attachment",
                format!("{}:0", Uuid::new_v4()),
                &["attachment_download"],
                "attachment review"
            ))
            .is_ok()
        );
    }

    #[test]
    fn privacy_request_rejects_attachment_without_index() {
        assert!(
            validate_create_request(&valid_request(
                "attachment",
                Uuid::new_v4().to_string(),
                &["attachment_download"],
                "attachment review"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_rejects_attachment_with_bad_session() {
        assert!(
            validate_create_request(&valid_request(
                "attachment",
                "bad:0".into(),
                &["attachment_download"],
                "attachment review"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_rejects_attachment_with_bad_index() {
        assert!(
            validate_create_request(&valid_request(
                "attachment",
                format!("{}:x", Uuid::new_v4()),
                &["attachment_download"],
                "attachment review"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_rejects_unknown_resource_type() {
        assert!(
            validate_create_request(&valid_request(
                "incident",
                Uuid::new_v4().to_string(),
                &["body"],
                "incident review"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_accepts_verdict_scope() {
        assert_eq!(
            normalize_scopes(&["verdict".into()]).unwrap(),
            vec!["verdict"]
        );
    }

    #[test]
    fn privacy_verdict_uses_reveal_permission() {
        assert_eq!(scope_permission("verdict"), "privacy.reveal");
    }

    #[test]
    fn privacy_http_body_uses_reveal_permission() {
        assert_eq!(scope_permission("http_body"), "privacy.reveal");
    }

    #[test]
    fn privacy_request_rejects_more_than_max_scopes() {
        let scopes = vec![
            "body".into(),
            "html".into(),
            "headers".into(),
            "verdict".into(),
            "http_body".into(),
        ];
        assert!(normalize_scopes(&scopes).is_err());
    }

    #[test]
    fn privacy_request_accepts_exactly_max_scopes() {
        let scopes = vec![
            "body".into(),
            "html".into(),
            "headers".into(),
            "verdict".into(),
        ];
        assert!(normalize_scopes(&scopes).is_ok());
    }

    #[test]
    fn privacy_request_rejects_uppercase_scope() {
        assert!(normalize_scopes(&["BODY".into()]).is_err());
    }

    #[test]
    fn privacy_request_rejects_control_tab_in_purpose() {
        assert!(
            validate_create_request(&valid_request(
                "session",
                Uuid::new_v4().to_string(),
                &["body"],
                "review\tsecret"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_rejects_control_carriage_return_in_purpose() {
        assert!(
            validate_create_request(&valid_request(
                "session",
                Uuid::new_v4().to_string(),
                &["body"],
                "review\rsecret"
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_rejects_purpose_over_limit() {
        assert!(
            validate_create_request(&valid_request(
                "session",
                Uuid::new_v4().to_string(),
                &["body"],
                &"x".repeat(MAX_PURPOSE_CHARS + 1)
            ))
            .is_err()
        );
    }

    #[test]
    fn privacy_request_accepts_purpose_at_limit() {
        assert!(
            validate_create_request(&valid_request(
                "session",
                Uuid::new_v4().to_string(),
                &["body"],
                &"x".repeat(MAX_PURPOSE_CHARS)
            ))
            .is_ok()
        );
    }

    #[test]
    fn privacy_request_id_rejects_empty_header() {
        let mut headers = HeaderMap::new();
        headers.insert(PRIVACY_REQUEST_ID_HEADER, "".parse().unwrap());
        assert!(request_id_from_headers(&headers).is_none());
    }

    #[test]
    fn privacy_request_id_rejects_overlong_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            PRIVACY_REQUEST_ID_HEADER,
            format!("{}-extra", Uuid::new_v4()).parse().unwrap(),
        );
        assert!(request_id_from_headers(&headers).is_none());
    }

    #[test]
    fn privacy_admin_requires_exact_admin_role() {
        assert!(!is_exact_admin(&user(
            "ADMINISTRATOR",
            &["privacy.request"]
        )));
    }

    #[test]
    fn privacy_audit_requires_exact_audit_role() {
        assert!(!is_exact_audit(&user("AUDITOR", &["privacy.approve"])));
    }

    #[test]
    fn privacy_verdict_requires_exact_lease() {
        let mut scopes = HashSet::new();
        scopes.insert("body".to_string());
        assert!(!can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "verdict"
        ));
    }

    #[test]
    fn privacy_verdict_allows_exact_permission_and_lease() {
        let mut scopes = HashSet::new();
        scopes.insert("verdict".to_string());
        assert!(can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "verdict"
        ));
    }

    #[test]
    fn privacy_http_body_requires_exact_lease() {
        let mut scopes = HashSet::new();
        scopes.insert("body".to_string());
        assert!(!can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "http_body"
        ));
    }

    #[test]
    fn privacy_download_requires_download_permission() {
        let mut scopes = HashSet::new();
        scopes.insert("attachment_download".to_string());
        assert!(!can_reveal(
            &user("admin", &["privacy.reveal"]),
            &scopes,
            "attachment_download"
        ));
    }

    #[test]
    fn privacy_policy_defaults_to_enabled_and_fails_closed() {
        assert!(parse_privacy_enabled(None));
        assert!(parse_privacy_enabled(Some("not-json")));
        assert!(parse_privacy_enabled(Some(r#"{"enabled":"false"}"#)));
    }

    #[test]
    fn privacy_policy_accepts_json_object_or_boolean() {
        assert!(!parse_privacy_enabled(Some(r#"{"enabled":false}"#)));
        assert!(!parse_privacy_enabled(Some("false")));
        assert!(parse_privacy_enabled(Some(r#"{"enabled":true}"#)));
    }

    #[test]
    fn disabled_privacy_policy_bypasses_lease_and_permission_checks() {
        let scopes = unrestricted_scopes();
        assert!(is_privacy_disabled(&scopes));
        assert!(can_reveal(&user("custom", &[]), &scopes, "body"));
        assert!(can_reveal(
            &user("custom", &[]),
            &scopes,
            "attachment_download"
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 192, .. ProptestConfig::default() })]

        #[test]
        fn privacy_scope_normalization_is_total_and_canonical(
            scope_chars in prop::collection::vec(
                prop::collection::vec(any::<char>(), 0..=32),
                0..=16,
            ),
        ) {
            let scopes: Vec<String> = scope_chars
                .into_iter()
                .map(|chars| chars.into_iter().collect())
                .collect();
            let result = normalize_scopes(&scopes);

            if let Ok(normalized) = result {
                prop_assert!(normalized.len() <= MAX_SCOPES);
                prop_assert_eq!(normalized.len(), scopes.len());
                prop_assert!(normalized.windows(2).all(|pair| pair[0] < pair[1]));
                prop_assert!(normalized.iter().all(|scope| ALLOWED_SCOPES.contains(&scope.as_str())));
            }
        }

        #[test]
        fn privacy_request_purpose_boundary_is_enforced(
            purpose_chars in prop::collection::vec(any::<char>(), 0..=520),
        ) {
            let purpose: String = purpose_chars.into_iter().collect();
            let invalid = purpose.trim().is_empty()
                || purpose.chars().count() > MAX_PURPOSE_CHARS
                || purpose.chars().any(char::is_control);
            let request = valid_request(
                "session",
                Uuid::nil().to_string(),
                &["body"],
                &purpose,
            );

            prop_assert_eq!(validate_create_request(&request).is_ok(), !invalid);
        }

        #[test]
        fn privacy_lease_header_accepts_only_bounded_uuid_handles(
            header_chars in prop::collection::vec(prop::char::range(' ', '~'), 0..=160),
        ) {
            let header: String = header_chars.into_iter().collect();
            let mut headers = HeaderMap::new();
            if let Ok(value) = header.parse() {
                headers.insert(PRIVACY_REQUEST_ID_HEADER, value);
            }

            if let Some(request_id) = request_id_from_headers(&headers) {
                prop_assert!(request_id.len() <= 64);
                prop_assert!(Uuid::parse_str(request_id).is_ok());
            }
        }
    }
}
