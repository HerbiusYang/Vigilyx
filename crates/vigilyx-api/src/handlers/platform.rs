//! Platform identity and RBAC management endpoints.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    AppState,
    auth::{AuthenticatedUser, hash_password, validate_new_password},
    handlers::ApiResponse,
};
use vigilyx_db::{ADMIN_ROLE_ID, AUDIT_ROLE_ID, PLATFORM_PERMISSIONS};

const MAX_NAME_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    pub password: String,
    pub role_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub display_name: String,
    pub role_id: String,
    pub is_active: bool,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    (status, ApiResponse::<serde_json::Value>::err(message)).into_response()
}

fn validate_text(value: &str, max_chars: usize, field: &'static str) -> Result<(), &'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > max_chars
        || trimmed.chars().any(char::is_control)
    {
        return Err(field);
    }
    Ok(())
}

fn validate_username(value: &str) -> Result<(), &'static str> {
    validate_text(value, MAX_NAME_CHARS, "用户名无效")?;
    if value.chars().any(|ch| ch.is_whitespace()) {
        return Err("用户名不能包含空白字符");
    }
    Ok(())
}

fn validate_role_name(value: &str) -> Result<(), &'static str> {
    validate_text(value, MAX_NAME_CHARS, "角色名无效")?;
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err("角色名只能包含字母、数字、点、下划线或连字符");
    }
    if ["admin", "audit"]
        .iter()
        .any(|reserved| value.eq_ignore_ascii_case(reserved))
    {
        return Err("admin 和 audit 是系统保留角色名");
    }
    Ok(())
}

fn validate_permissions(permissions: &[String]) -> Result<Vec<String>, &'static str> {
    let mut normalized = permissions
        .iter()
        .map(|permission| permission.trim().to_string())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    if normalized.iter().any(|permission| {
        !PLATFORM_PERMISSIONS
            .iter()
            .any(|(key, _)| key == permission)
    }) {
        return Err("包含未知权限");
    }
    Ok(normalized)
}

/// Revoke one user's outstanding JWTs (SEC M-1: targeted revocation — a
/// global counter here would let any permission change log out every
/// operator).
async fn revoke_user_sessions(
    state: &Arc<AppState>,
    user_id: &str,
    username: &str,
) -> Result<(), &'static str> {
    // The profile/role mutation may already have committed. Invalidate live
    // sockets before a failing token-version write can leave cached access.
    crate::websocket::invalidate_websocket_sessions_for_user(state, username);
    state
        .engine_db
        .bump_platform_user_token_version(user_id)
        .await
        .map_err(|_| "会话撤销失败，请重试")?;
    Ok(())
}

/// Revoke the outstanding JWTs of every user holding a role whose permission
/// set just changed. `require_auth` rehydrates permissions per request, so
/// this is defense-in-depth for already-issued tokens, scoped to the role.
async fn revoke_role_sessions(state: &Arc<AppState>, role_id: &str) -> Result<(), &'static str> {
    state
        .engine_db
        .bump_platform_role_token_versions(role_id)
        .await
        .map_err(|_| "会话撤销失败，请重试")?;
    // The caller already invalidated the global WS epoch synchronously at
    // role commit, including concurrently added members. No member-list read
    // is needed to close sockets; this write revokes the role's REST tokens.
    Ok(())
}

fn audit(
    state: &Arc<AppState>,
    actor: &AuthenticatedUser,
    operation: &'static str,
    resource: &'static str,
    id: Option<String>,
    detail: String,
) {
    crate::handlers::spawn_audit_log(
        state.engine_db.clone(),
        actor.username.clone(),
        operation,
        Some(resource),
        id,
        Some(detail),
    );
}

fn is_platform_admin_role(role: &str) -> bool {
    role == ADMIN_ROLE_ID
}

/// Platform-management permissions are an authority boundary, not ordinary
/// delegated capabilities. Only the exact system admin role may grant, retain,
/// or modify them.
const PRIVILEGED_PLATFORM_PERMISSIONS: &[&str] = &[
    "platform.manage",
    "platform.users.manage",
    "platform.roles.manage",
];

fn has_privileged_platform_permission(permissions: &[String]) -> bool {
    permissions
        .iter()
        .any(|permission| PRIVILEGED_PLATFORM_PERMISSIONS.contains(&permission.as_str()))
}

fn privileged_platform_operation_allowed(
    actor_role: &str,
    current_permissions: &[String],
    requested_permissions: &[String],
) -> bool {
    is_platform_admin_role(actor_role)
        || (!has_privileged_platform_permission(current_permissions)
            && !has_privileged_platform_permission(requested_permissions))
}

fn audit_operation_allowed(
    _actor_role: &str,
    current_role_id: Option<&str>,
    requested_role_id: Option<&str>,
) -> bool {
    let touches_audit =
        current_role_id == Some(AUDIT_ROLE_ID) || requested_role_id == Some(AUDIT_ROLE_ID);
    // The audit approver must remain administratively independent. Provision,
    // promotion, editing, and disabling are therefore out-of-band operations;
    // no API role, including role-admin, may mutate role-audit membership.
    !touches_audit
}

fn deny_non_admin_audit_operation(
    state: &Arc<AppState>,
    actor: &AuthenticatedUser,
    operation: &'static str,
    target_id: Option<String>,
    detail: String,
) -> Response {
    audit(state, actor, operation, "platform_user", target_id, detail);
    error_response(StatusCode::FORBIDDEN, "只有 admin 可以管理 audit 账户")
}

fn deny_non_admin_privileged_operation(
    state: &Arc<AppState>,
    actor: &AuthenticatedUser,
    operation: &'static str,
    target_id: Option<String>,
    detail: String,
) -> Response {
    audit(state, actor, operation, "platform_rbac", target_id, detail);
    error_response(StatusCode::FORBIDDEN, "只有 admin 可以授予或修改平台高权限")
}

pub async fn list_users(State(state): State<Arc<AppState>>) -> Response {
    match state.engine_db.list_platform_users().await {
        Ok(users) => ApiResponse::ok(users).into_response(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to list platform users")
                .into_response()
        }
    }
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Json(request): Json<CreateUserRequest>,
) -> Response {
    if !audit_operation_allowed(&actor.role_id, None, Some(request.role_id.as_str())) {
        return deny_non_admin_audit_operation(
            &state,
            &actor,
            "platform_audit_user_create_denied",
            None,
            format!(
                "actor_role_id={},requested_role_id={}",
                actor.role_id, request.role_id
            ),
        );
    }
    if let Err(message) = validate_username(&request.username)
        .and_then(|_| {
            validate_text(&request.display_name, MAX_NAME_CHARS, "显示名无效").or_else(|_| {
                if request.display_name.trim().is_empty() {
                    Ok(())
                } else {
                    Err("显示名无效")
                }
            })
        })
        .and_then(|_| validate_new_password(&request.username, &request.password))
    {
        return error_response(StatusCode::BAD_REQUEST, message);
    }
    if !state
        .engine_db
        .role_exists(&request.role_id)
        .await
        .unwrap_or(false)
    {
        return error_response(StatusCode::BAD_REQUEST, "角色不存在");
    }
    let requested_role_permissions = match state.engine_db.list_platform_roles().await {
        Ok(roles) => roles
            .into_iter()
            .find(|role| role.id == request.role_id)
            .map(|role| role.permissions)
            .unwrap_or_default(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "角色读取失败"),
    };
    if !privileged_platform_operation_allowed(&actor.role_id, &[], &requested_role_permissions) {
        return deny_non_admin_privileged_operation(
            &state,
            &actor,
            "platform_privileged_user_create_denied",
            None,
            format!(
                "actor_role_id={},requested_role_id={}",
                actor.role_id, request.role_id
            ),
        );
    }
    let hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败"),
    };
    match state
        .engine_db
        .create_platform_user(
            &request.username,
            request.display_name.trim(),
            &hash,
            &request.role_id,
            true,
        )
        .await
    {
        Ok(user) => {
            // SEC M-1: a newly created user holds no sessions; nothing to
            // revoke (the old code bumped a global counter platform-wide).
            audit(
                &state,
                &actor,
                "platform_user_created",
                "platform_user",
                Some(user.id.clone()),
                format!("username={},role_id={}", user.username, user.role_id),
            );
            ApiResponse::ok(user).into_response()
        }
        Err(error) if error.to_string().contains("duplicate key") => {
            error_response(StatusCode::CONFLICT, "用户名已存在")
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to create platform user")
                .into_response()
        }
    }
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateUserRequest>,
) -> Response {
    if let Err(message) = validate_text(&request.display_name, MAX_NAME_CHARS, "显示名无效")
        .or_else(|_| {
            if request.display_name.trim().is_empty() {
                Ok(())
            } else {
                Err("显示名无效")
            }
        })
    {
        return error_response(StatusCode::BAD_REQUEST, message);
    }
    let target = match state.engine_db.get_platform_auth_user_by_id(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "用户不存在"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "用户读取失败"),
    };
    if !audit_operation_allowed(
        &actor.role_id,
        Some(target.role_id.as_str()),
        Some(request.role_id.as_str()),
    ) {
        return deny_non_admin_audit_operation(
            &state,
            &actor,
            "platform_audit_user_update_denied",
            Some(id.clone()),
            format!(
                "actor_role_id={},target_role_id={},requested_role_id={}",
                actor.role_id, target.role_id, request.role_id
            ),
        );
    }
    if !state
        .engine_db
        .role_exists(&request.role_id)
        .await
        .unwrap_or(false)
    {
        return error_response(StatusCode::BAD_REQUEST, "角色不存在");
    }
    let target_role_permissions = match state.engine_db.list_platform_roles().await {
        Ok(roles) => roles
            .into_iter()
            .find(|role| role.id == request.role_id)
            .map(|role| role.permissions)
            .unwrap_or_default(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "角色读取失败"),
    };
    if !privileged_platform_operation_allowed(
        &actor.role_id,
        &target.permissions,
        &target_role_permissions,
    ) {
        return deny_non_admin_privileged_operation(
            &state,
            &actor,
            "platform_privileged_user_update_denied",
            Some(id.clone()),
            format!(
                "actor_role_id={},target_role_id={},requested_role_id={}",
                actor.role_id, target.role_id, request.role_id
            ),
        );
    }
    // Validate and hash a replacement password before mutating the profile so
    // a rejected password cannot leave a partially applied role/display-name
    // update behind.
    let replacement_password_hash = if let Some(password) = request.password.as_deref() {
        if let Err(message) = validate_new_password(&target.username, password) {
            return error_response(StatusCode::BAD_REQUEST, message);
        }
        match hash_password(password) {
            Ok(hash) => Some(hash),
            Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败"),
        }
    } else {
        None
    };
    let was_privileged = has_privileged_platform_permission(&target.permissions);
    let remains_privileged = has_privileged_platform_permission(&target_role_permissions);
    if target.is_active && was_privileged && (!request.is_active || !remains_privileged) {
        match state
            .engine_db
            .count_active_privileged_users(Some(&id))
            .await
        {
            Ok(0) => return error_response(StatusCode::CONFLICT, "不能移除最后一个平台管理员"),
            Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "用户保护检查失败"),
            _ => {}
        }
    }
    if let Err(error) = state
        .engine_db
        .update_platform_user(
            &id,
            request.display_name.trim(),
            &request.role_id,
            request.is_active,
        )
        .await
    {
        return ApiResponse::<serde_json::Value>::server_error(
            &error,
            "Failed to update platform user",
        )
        .into_response();
    }
    // A replacement password write below can fail after the new role or
    // active state was committed. Do not retain that user's old WS grants.
    crate::websocket::invalidate_websocket_sessions_for_user(&state, &target.username);
    let mut token_bumped = false;
    if let Some(hash) = replacement_password_hash {
        if state
            .engine_db
            .set_platform_user_password_and_bump_token(
                &id,
                &hash,
                true,
                target.username == state.auth.config.username,
            )
            .await
            .is_err()
        {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "密码保存失败，请重试");
        }
        token_bumped = true;
    }
    if !token_bumped
        && revoke_user_sessions(&state, &id, &target.username)
            .await
            .is_err()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "会话撤销失败，请重试");
    }
    if token_bumped {
        crate::websocket::invalidate_websocket_sessions_for_user(&state, &target.username);
    }
    if let Ok(Some(updated)) = state.engine_db.get_platform_user_by_id(&id).await {
        audit(
            &state,
            &actor,
            "platform_user_updated",
            "platform_user",
            Some(id.clone()),
            format!("role_id={},active={}", updated.role_id, updated.is_active),
        );
        ApiResponse::ok(updated).into_response()
    } else {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "用户更新失败")
    }
}

pub async fn disable_user(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Path(id): Path<String>,
) -> Response {
    let target = match state.engine_db.get_platform_auth_user_by_id(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "用户不存在"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "用户读取失败"),
    };
    if !audit_operation_allowed(&actor.role_id, Some(target.role_id.as_str()), None) {
        return deny_non_admin_audit_operation(
            &state,
            &actor,
            "platform_audit_user_disable_denied",
            Some(id.clone()),
            format!(
                "actor_role_id={},target_role_id={}",
                actor.role_id, target.role_id
            ),
        );
    }
    let privileged = has_privileged_platform_permission(&target.permissions);
    if privileged && !is_platform_admin_role(&actor.role_id) {
        return deny_non_admin_privileged_operation(
            &state,
            &actor,
            "platform_privileged_user_disable_denied",
            Some(id.clone()),
            format!(
                "actor_role_id={},target_role_id={}",
                actor.role_id, target.role_id
            ),
        );
    }
    if target.is_active
        && privileged
        && state
            .engine_db
            .count_active_privileged_users(Some(&id))
            .await
            .unwrap_or(0)
            == 0
    {
        return error_response(StatusCode::CONFLICT, "不能禁用最后一个平台管理员");
    }
    if state
        .engine_db
        .update_platform_user(&id, &target.display_name, &target.role_id, false)
        .await
        .is_err()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "用户禁用失败");
    }
    // Inactive users are rejected by REST auth, and the token bump plus the
    // per-user WebSocket epoch closes already-upgraded dashboard sockets.
    if revoke_user_sessions(&state, &id, &target.username)
        .await
        .is_err()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "会话撤销失败，请重试");
    }
    audit(
        &state,
        &actor,
        "platform_user_disabled",
        "platform_user",
        Some(id.clone()),
        format!("username={}", target.username),
    );
    ApiResponse::ok(serde_json::json!({"id": id, "is_active": false})).into_response()
}

pub async fn list_roles(State(state): State<Arc<AppState>>) -> Response {
    match state.engine_db.list_platform_roles().await {
        Ok(roles) => ApiResponse::ok(roles).into_response(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to list platform roles")
                .into_response()
        }
    }
}

pub async fn list_permissions(State(state): State<Arc<AppState>>) -> Response {
    match state.engine_db.list_platform_permissions().await {
        Ok(permissions) => ApiResponse::ok(permissions).into_response(),
        Err(error) => ApiResponse::<serde_json::Value>::server_error(
            &error,
            "Failed to list platform permissions",
        )
        .into_response(),
    }
}

pub async fn create_role(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Json(request): Json<CreateRoleRequest>,
) -> Response {
    if let Err(message) = validate_role_name(&request.name).and_then(|_| {
        validate_text(&request.description, MAX_DESCRIPTION_CHARS, "角色描述无效").or_else(|_| {
            if request.description.trim().is_empty() {
                Ok(())
            } else {
                Err("角色描述无效")
            }
        })
    }) {
        return error_response(StatusCode::BAD_REQUEST, message);
    }
    let permissions = match validate_permissions(&request.permissions) {
        Ok(permissions) => permissions,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
    };
    if !privileged_platform_operation_allowed(&actor.role_id, &[], &permissions) {
        return deny_non_admin_privileged_operation(
            &state,
            &actor,
            "platform_privileged_role_create_denied",
            None,
            format!(
                "actor_role_id={},permissions={:?}",
                actor.role_id, permissions
            ),
        );
    }
    match state
        .engine_db
        .create_platform_role(
            request.name.trim(),
            request.description.trim(),
            &permissions,
        )
        .await
    {
        Ok(role) => {
            // SEC M-1: a new role has no holders; nothing to revoke.
            audit(
                &state,
                &actor,
                "platform_role_created",
                "platform_role",
                Some(role.id.clone()),
                format!("name={}", role.name),
            );
            ApiResponse::ok(role).into_response()
        }
        Err(error) if error.to_string().contains("duplicate key") => {
            error_response(StatusCode::CONFLICT, "角色名已存在")
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to create platform role")
                .into_response()
        }
    }
}

pub async fn update_role(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Path(id): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> Response {
    if let Err(message) = validate_role_name(&request.name) {
        return error_response(StatusCode::BAD_REQUEST, message);
    }
    let permissions = match validate_permissions(&request.permissions) {
        Ok(permissions) => permissions,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
    };
    let current_permissions = match state.engine_db.list_platform_roles().await {
        Ok(roles) => roles
            .into_iter()
            .find(|role| role.id == id)
            .map(|role| role.permissions)
            .unwrap_or_default(),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "角色读取失败"),
    };
    if !privileged_platform_operation_allowed(&actor.role_id, &current_permissions, &permissions) {
        return deny_non_admin_privileged_operation(
            &state,
            &actor,
            "platform_privileged_role_update_denied",
            Some(id.clone()),
            format!(
                "actor_role_id={},role_id={id},permissions={:?}",
                actor.role_id, permissions
            ),
        );
    }
    match state
        .engine_db
        .update_platform_role(
            &id,
            request.name.trim(),
            request.description.trim(),
            &permissions,
        )
        .await
    {
        Ok(true) => {
            // Role permission changes also affect members added concurrently
            // and must fail closed even if later token/member DB reads fail.
            // This rare administrative action forces all sockets to reconnect;
            // ordinary user logout/profile changes retain targeted revocation.
            crate::websocket::invalidate_websocket_sessions(&state);
            if revoke_role_sessions(&state, &id).await.is_err() {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "会话撤销失败，请重试");
            }
            audit(
                &state,
                &actor,
                "platform_role_updated",
                "platform_role",
                Some(id.clone()),
                format!("name={}", request.name),
            );
            match state
                .engine_db
                .list_platform_roles()
                .await
                .ok()
                .and_then(|roles| roles.into_iter().find(|role| role.id == id))
            {
                Some(role) => ApiResponse::ok(role).into_response(),
                None => error_response(StatusCode::NOT_FOUND, "角色不存在"),
            }
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "角色不存在"),
        Err(error) if error.to_string().contains("system roles") => {
            error_response(StatusCode::CONFLICT, "系统角色不可修改")
        }
        Err(error) if error.to_string().contains("duplicate key") => {
            error_response(StatusCode::CONFLICT, "角色名已存在")
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to update platform role")
                .into_response()
        }
    }
}

pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    actor: AuthenticatedUser,
    Path(id): Path<String>,
) -> Response {
    match state.engine_db.delete_platform_role(&id).await {
        Ok(true) => {
            // SEC M-1: the role FK prevents deletion while users hold it, so
            // no sessions need revocation here.
            audit(
                &state,
                &actor,
                "platform_role_deleted",
                "platform_role",
                Some(id.clone()),
                String::new(),
            );
            ApiResponse::ok(serde_json::json!({"id": id})).into_response()
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "角色不存在"),
        Err(error) if error.to_string().contains("system roles") => {
            error_response(StatusCode::CONFLICT, "系统角色不可删除")
        }
        Err(error) if error.to_string().contains("assigned") => {
            error_response(StatusCode::CONFLICT, "角色仍被用户使用")
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Failed to delete platform role")
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_db::AUDIT_ROLE_PERMISSIONS;

    #[test]
    fn audit_account_operations_require_exact_admin_role() {
        assert!(is_platform_admin_role(ADMIN_ROLE_ID));
        assert!(!is_platform_admin_role("admin"));
        assert!(!is_platform_admin_role("ADMIN"));
        assert!(!is_platform_admin_role("analyst"));
        assert!(!is_platform_admin_role("platform-admin"));
    }

    #[test]
    fn audit_role_is_a_dedicated_system_role() {
        assert_eq!(AUDIT_ROLE_ID, "role-audit");
        assert_ne!(AUDIT_ROLE_ID, "role-viewer");
    }

    #[test]
    fn deep_audit_admin_role_lowercase_is_admin() {
        assert!(is_platform_admin_role(ADMIN_ROLE_ID));
    }

    #[test]
    fn deep_audit_admin_display_name_is_not_system_admin() {
        assert!(!is_platform_admin_role("ADMIN"));
    }

    #[test]
    fn deep_audit_admin_mixed_case_display_name_is_not_system_admin() {
        assert!(!is_platform_admin_role("AdMiN"));
    }

    #[test]
    fn deep_audit_non_admin_and_lookalike_roles_are_rejected() {
        for role in [
            "",
            "viewer",
            "analyst",
            " admin",
            "admin ",
            "admin2",
            "platform-admin",
        ] {
            assert!(
                !is_platform_admin_role(role),
                "unexpected admin role: {role:?}"
            );
        }
    }

    #[test]
    fn deep_audit_create_audit_is_denied_for_admin() {
        assert!(!audit_operation_allowed(
            ADMIN_ROLE_ID,
            None,
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_create_audit_is_denied_for_analyst() {
        assert!(!audit_operation_allowed(
            "role-analyst",
            None,
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_create_audit_is_denied_for_viewer() {
        assert!(!audit_operation_allowed(
            "role-viewer",
            None,
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_create_audit_ignores_manage_permission_without_admin_role() {
        assert!(!audit_operation_allowed(
            "role-custom",
            None,
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_promote_to_audit_is_denied_for_admin() {
        assert!(!audit_operation_allowed(
            ADMIN_ROLE_ID,
            Some("role-viewer"),
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_promote_to_audit_is_denied_for_non_admin() {
        assert!(!audit_operation_allowed(
            "role-analyst",
            Some("role-viewer"),
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_edit_existing_audit_is_denied_for_admin() {
        assert!(!audit_operation_allowed(
            ADMIN_ROLE_ID,
            Some(AUDIT_ROLE_ID),
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_edit_existing_audit_is_denied_for_non_admin() {
        assert!(!audit_operation_allowed(
            "role-analyst",
            Some(AUDIT_ROLE_ID),
            Some(AUDIT_ROLE_ID)
        ));
    }

    #[test]
    fn deep_audit_disable_audit_is_denied_for_admin() {
        assert!(!audit_operation_allowed(
            ADMIN_ROLE_ID,
            Some(AUDIT_ROLE_ID),
            None
        ));
    }

    #[test]
    fn deep_audit_disable_audit_rejects_display_name_only_admin() {
        assert!(!audit_operation_allowed("ADMIN", Some(AUDIT_ROLE_ID), None));
    }

    #[test]
    fn deep_audit_disable_audit_is_denied_for_non_admin() {
        assert!(!audit_operation_allowed(
            "role-viewer",
            Some(AUDIT_ROLE_ID),
            None
        ));
    }

    #[test]
    fn deep_audit_normal_target_is_allowed_for_non_admin() {
        assert!(audit_operation_allowed(
            "role-analyst",
            Some("role-viewer"),
            Some("role-analyst")
        ));
    }

    #[test]
    fn deep_audit_audit_to_normal_change_is_denied_for_non_admin() {
        assert!(!audit_operation_allowed(
            "role-analyst",
            Some(AUDIT_ROLE_ID),
            Some("role-viewer")
        ));
    }

    #[test]
    fn deep_audit_normal_to_normal_change_is_allowed_for_non_admin() {
        assert!(audit_operation_allowed(
            "role-viewer",
            Some("role-analyst"),
            Some("role-viewer")
        ));
    }

    #[test]
    fn deep_audit_lookalike_role_id_is_not_audit() {
        assert!(audit_operation_allowed(
            "role-analyst",
            Some("role-audit-copy"),
            Some("role-viewer")
        ));
    }

    #[test]
    fn custom_roles_cannot_reuse_system_role_names() {
        for name in ["admin", "ADMIN", "audit", "AuDiT"] {
            assert!(
                validate_role_name(name).is_err(),
                "reserved role name: {name}"
            );
        }
        assert!(validate_role_name("security-operator").is_ok());
    }

    #[test]
    fn deep_audit_username_accepts_safe_value() {
        assert!(validate_username("audit.operator").is_ok());
    }

    #[test]
    fn deep_audit_username_rejects_whitespace() {
        assert!(validate_username("audit operator").is_err());
    }

    #[test]
    fn deep_audit_username_rejects_control_character() {
        assert!(validate_username("audit\noperator").is_err());
    }

    #[test]
    fn deep_audit_username_rejects_oversized_value() {
        let oversized = "a".repeat(MAX_NAME_CHARS + 1);
        assert!(validate_username(&oversized).is_err());
    }

    #[test]
    fn deep_audit_username_accepts_unicode_without_whitespace() {
        assert!(validate_username("审计员").is_ok());
    }

    #[test]
    fn deep_audit_role_name_accepts_safe_value() {
        assert!(validate_role_name("security-audit.v2").is_ok());
    }

    #[test]
    fn deep_audit_role_name_rejects_punctuation() {
        assert!(validate_role_name("audit/ops").is_err());
    }

    #[test]
    fn deep_audit_role_name_rejects_whitespace() {
        assert!(validate_role_name("audit ops").is_err());
    }

    #[test]
    fn deep_audit_role_name_rejects_empty_value() {
        assert!(validate_role_name("").is_err());
    }

    #[test]
    fn deep_audit_permissions_are_canonicalized_and_deduplicated() {
        let permissions = vec![
            "security.read".to_string(),
            " sessions.read ".to_string(),
            "security.read".to_string(),
        ];
        assert_eq!(
            validate_permissions(&permissions).expect("valid permissions"),
            vec!["security.read", "sessions.read"]
        );
    }

    #[test]
    fn deep_audit_unknown_permission_is_rejected() {
        let permissions = vec!["sessions.read".to_string(), "platform.root".to_string()];
        assert!(validate_permissions(&permissions).is_err());
    }

    #[test]
    fn deep_audit_role_permission_contract_is_exactly_read_only() {
        assert_eq!(
            AUDIT_ROLE_PERMISSIONS,
            [
                "sessions.read",
                "security.read",
                "data_security.read",
                "system.read",
                "audit.read",
                "privacy.approve",
                "privacy.reveal",
                "privacy.eml.download",
            ]
            .as_slice()
        );
    }

    #[test]
    fn only_exact_admin_role_can_grant_platform_management_permissions() {
        let privileged = vec!["platform.users.manage".to_string()];
        assert!(privileged_platform_operation_allowed(
            ADMIN_ROLE_ID,
            &[],
            &privileged
        ));
        assert!(!privileged_platform_operation_allowed(
            "role-operator",
            &[],
            &privileged
        ));
        assert!(!privileged_platform_operation_allowed(
            "role-operator",
            &privileged,
            &[]
        ));
    }

    #[test]
    fn non_admin_cannot_modify_a_role_that_already_has_platform_management() {
        let privileged = vec!["platform.roles.manage".to_string()];
        assert!(!privileged_platform_operation_allowed(
            "role-operator",
            &privileged,
            &privileged
        ));
    }
}
