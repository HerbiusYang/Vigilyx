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
use vigilyx_db::PLATFORM_PERMISSIONS;

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
async fn revoke_user_sessions(state: &Arc<AppState>, user_id: &str) -> Result<(), &'static str> {
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
    let was_privileged = target
        .permissions
        .iter()
        .any(|key| key == "platform.users.manage" || key == "platform.manage");
    let remains_privileged = target_role_permissions
        .iter()
        .any(|key| key == "platform.users.manage" || key == "platform.manage");
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
    if !token_bumped && revoke_user_sessions(&state, &id).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "会话撤销失败，请重试");
    }
    if let Ok(Some(updated)) = state.engine_db.get_platform_user_by_id(&id).await {
        audit(
            &state,
            &actor,
            "platform_user_updated",
            "platform_user",
            Some(id),
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
    let privileged = target
        .permissions
        .iter()
        .any(|key| key == "platform.users.manage" || key == "platform.manage");
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
    // SEC M-1: require_auth rejects inactive users on every request; no
    // token-version bump needed (the old code bumped a global counter).
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
