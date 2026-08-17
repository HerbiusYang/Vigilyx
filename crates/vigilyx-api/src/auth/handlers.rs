//! login Password handler

use std::net::IpAddr;

use axum::Json;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use std::sync::atomic::Ordering;

use super::AuthConfig;
use super::jwt::generate_token;
use super::middleware::AuthenticatedUser;
use super::password::{hash_password, verify_password, verify_password_dummy};
use super::rate_limit::LoginRateLimiter;
use vigilyx_db::PlatformAuthUser;

// -- Cookie constants --
const COOKIE_NAME: &str = "vigilyx_token";
const MAX_LOGIN_USERNAME_CHARS: usize = 256;
const MAX_LOGIN_PASSWORD_CHARS: usize = 4096;
const MAX_LOGIN_AUDIT_USERNAME_CHARS: usize = 128;

/// Build a Set-Cookie header value that sets the token.
pub fn build_token_cookie(token: &str, max_age_secs: u64, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age={max_age_secs}{secure_flag}"
    )
}

/// Build a Set-Cookie header value that clears the cookie.
pub fn build_clear_cookie(secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0{secure_flag}")
}

/// GET /api/auth/me - return the current session user info (cookie validation is handled by middleware).
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub must_change_password: bool,
}

pub async fn handle_me(user: AuthenticatedUser) -> Json<MeResponse> {
    Json(MeResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        role: user.role,
        permissions: user.permissions,
        must_change_password: user.must_change_password,
    })
}

/// POST /api/auth/logout - clear the HttpOnly cookie.
pub async fn handle_logout(secure_cookie: bool) -> (HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    if let Ok(val) = build_clear_cookie(secure_cookie).parse() {
        headers.insert(axum::http::header::SET_COOKIE, val);
    }
    (headers, Json(serde_json::json!({ "success": true })))
}

/// Loginrequest
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

/// Passwordrequest
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

impl std::fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest")
            .field("old_password", &"***")
            .field("new_password", &"***")
            .finish()
    }
}

/// Passwordresponse
#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Loginresponse
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    #[serde(skip_serializing)]
    pub token: Option<String>,
    pub expires_in: Option<u64>,
    pub error: Option<String>,
    /// First default passwordlogin true, Password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
}

/// Loginfailedresponse ()
fn login_fail(error: &str) -> LoginResponse {
    LoginResponse {
        success: false,
        token: None,
        expires_in: None,
        error: Some(error.to_string()),
        must_change_password: None,
    }
}

fn truncate_for_audit(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

pub(crate) fn sanitize_login_username(username: &str) -> String {
    let normalized = username
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_for_audit(&collapsed, MAX_LOGIN_AUDIT_USERNAME_CHARS)
}

fn validate_login_request(request: &LoginRequest) -> Result<(), &'static str> {
    let username_len = request.username.chars().count();
    if request.username.trim().is_empty() {
        return Err("登录请求无效");
    }
    if username_len > MAX_LOGIN_USERNAME_CHARS {
        return Err("登录请求无效");
    }
    if request.username.chars().any(char::is_control) {
        return Err("登录请求无效");
    }
    if request.password.chars().count() > MAX_LOGIN_PASSWORD_CHARS {
        return Err("登录请求无效");
    }

    Ok(())
}

const MIN_PASSWORD_LEN: usize = 12;
const PASSPHRASE_PASSWORD_LEN: usize = 16;
const COMMON_WEAK_PASSWORDS: &[&str] = &[
    "12345678",
    "123456789",
    "1234567890",
    "123456789012",
    "admin123",
    "adminadmin",
    "changeme123",
    "letmein123",
    "password",
    "password123",
    "qwerty123",
    "qwertyuiop",
    "welcome123",
];
const WEAK_SEQUENCES: &[&str] = &[
    "012345678901234567890123456789",
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm",
];

fn normalize_for_password_match(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn password_character_classes(password: &str) -> usize {
    let has_lower = password.chars().any(|ch| ch.is_lowercase());
    let has_upper = password.chars().any(|ch| ch.is_uppercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());
    let has_non_alphanumeric = password.chars().any(|ch| !ch.is_alphanumeric());

    usize::from(has_lower)
        + usize::from(has_upper)
        + usize::from(has_digit)
        + usize::from(has_non_alphanumeric)
}

fn is_obvious_sequence(normalized_password: &str) -> bool {
    if normalized_password.len() < 8 {
        return false;
    }

    WEAK_SEQUENCES.iter().any(|sequence| {
        let reversed: String = sequence.chars().rev().collect();
        sequence.contains(normalized_password) || reversed.contains(normalized_password)
    })
}

fn is_common_weak_password(normalized_password: &str) -> bool {
    if normalized_password.is_empty() {
        return false;
    }

    let repeated_char = normalized_password
        .chars()
        .next()
        .is_some_and(|first| normalized_password.chars().all(|ch| ch == first));

    repeated_char
        || is_obvious_sequence(normalized_password)
        || COMMON_WEAK_PASSWORDS.contains(&normalized_password)
}

pub(crate) fn validate_new_password(
    username: &str,
    new_password: &str,
) -> Result<(), &'static str> {
    if new_password.trim().is_empty() {
        return Err("新密码不能仅由空白字符组成");
    }

    if new_password.chars().any(char::is_control) {
        return Err("新密码不能包含控制字符");
    }

    let char_count = new_password.chars().count();
    if char_count < MIN_PASSWORD_LEN {
        return Err("新密码至少需要 12 位");
    }

    let normalized_password = normalize_for_password_match(new_password);
    if is_common_weak_password(&normalized_password) {
        return Err("新密码过于常见或模式过于简单，请使用更强的密码");
    }

    let normalized_username = normalize_for_password_match(username);
    if normalized_username.len() >= 3 && normalized_password.contains(&normalized_username) {
        return Err("新密码不能包含用户名或其明显变体");
    }

    let classes = password_character_classes(new_password);
    if classes < 2 {
        return Err("新密码至少需要包含 2 类字符");
    }

    if char_count < PASSPHRASE_PASSWORD_LEN && classes < 3 {
        return Err("12-15 位密码需至少包含大写字母、小写字母、数字、符号中的 3 类");
    }

    Ok(())
}

/// Processloginrequest (per-IP Rate limiting + default password)
#[allow(dead_code)]
pub async fn handle_login(
    config: &AuthConfig,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &LoginRequest,
) -> LoginResponse {
    let audit_username = sanitize_login_username(&request.username);

    if let Err(message) = validate_login_request(request) {
        warn!(
            ip = %client_ip,
            username = %audit_username,
            "Login rejected: malformed request"
        );
        return login_fail(message);
    }

    // ── Per-IP Rate limiting: pre-check ──
    // Peek without recording a failure. If already at/over the limit,
    // reject immediately to avoid expensive password verification.
    {
        if let Some((count, _)) = rate_limiter.peek(&client_ip)
            && count >= rate_limiter.max_failures
        {
            warn!(
                ip = %client_ip,
                failures = count,
                "Login rate-limited: IP {} exceeded max failures",
                client_ip
            );
            return login_fail("登录失败次数过多，请稍后再试");
        }
    }

    let username_matches = request.username == config.username;
    let hash = config.password_hash.read().await.clone();
    let password_result = if username_matches {
        verify_password(&request.password, &hash)
    } else {
        verify_password_dummy(&request.password).map(|_| false)
    };

    // verifyuser ; user, dummy hash,
    if !username_matches {
        if let Err(error) = &password_result {
            warn!(
                ip = %client_ip,
                error = %error,
                "dummy password verification failed while masking login timing"
            );
        }
        let blocked = rate_limiter.check_and_record_failure(client_ip);
        warn!(
            ip = %client_ip,
            username = %audit_username,
            "Login failed: invalid username"
        );
        if blocked {
            return login_fail("登录失败次数过多，请稍后再试");
        }
        return login_fail("用户名或密码错误");
    }

    // verifyPassword
    match password_result {
        Ok(true) => {
            // success: IP failed
            rate_limiter.reset(client_ip);

            // Token
            match generate_token(config, &config.username, "admin", config.token_version.load(std::sync::atomic::Ordering::Relaxed)) {
                Ok(token) => {
                    let changed = *config.password_changed.read().await;
                    if !changed {
                        warn!(
                            ip = %client_ip,
                            username = %audit_username,
                            "Security warning: user logged in with default password"
                        );
                    }
                    info!(
                        ip = %client_ip,
                        username = %audit_username,
                        password_changed = changed,
                        "Login success"
                    );
                    LoginResponse {
                        success: true,
                        token: Some(token),
                        expires_in: Some(config.token_expire_secs),
                        error: None,
                        must_change_password: if changed { None } else { Some(true) },
                    }
                }
                Err(e) => {
                    warn!("Token generation failed: {}", e);
                    login_fail("令牌生成失败，请重试")
                }
            }
        }
        Ok(false) => {
            let blocked = rate_limiter.check_and_record_failure(client_ip);
            warn!(
                ip = %client_ip,
                username = %audit_username,
                "Login failed: wrong password"
            );
            if blocked {
                return login_fail("登录失败次数过多，请稍后再试");
            }
            login_fail("用户名或密码错误")
        }
        Err(e) => {
            warn!("Password verification failed: {}", e);
            login_fail("认证失败，请重试")
        }
    }
}

/// RBAC-aware login.  The legacy `handle_login` above remains as a small
/// unit-test/compatibility helper; all HTTP login traffic uses this path.
pub async fn handle_platform_login(
    config: &AuthConfig,
    db: &vigilyx_db::VigilDb,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &LoginRequest,
) -> LoginResponse {
    let audit_username = sanitize_login_username(&request.username);
    if let Err(message) = validate_login_request(request) {
        warn!(ip = %client_ip, username = %audit_username, "Login rejected: malformed request");
        return login_fail(message);
    }

    if let Some((count, _)) = rate_limiter.peek(&client_ip)
        && count >= rate_limiter.max_failures
    {
        return login_fail("登录失败次数过多，请稍后再试");
    }

    let user = match db.get_platform_auth_user(&request.username).await {
        Ok(user) => user,
        Err(error) => {
            warn!(error = %error, "Platform user lookup failed during login");
            return login_fail("认证服务暂不可用，请稍后重试");
        }
    };

    // Keep unknown, inactive and malformed accounts on the same generic
    // response while still doing Argon2 work for timing resistance.
    let (password_hash, active) = user
        .as_ref()
        .map(|candidate| (candidate.password_hash.as_str(), candidate.is_active))
        .unwrap_or(("", false));
    let verified = if password_hash.is_empty() {
        verify_password_dummy(&request.password).map(|_| false)
    } else {
        verify_password(&request.password, password_hash)
    };

    match verified {
        Ok(true) if active => {
            let user = user.expect("active user is present after password verification");
            rate_limiter.reset(client_ip);
            if let Err(error) = db.touch_platform_user_login(&user.id).await {
                warn!(error = %error, username = %audit_username, "Failed to update platform last login timestamp");
            }
            match generate_token(config, &user.username, &user.role, user.token_version) {
                Ok(token) => LoginResponse {
                    success: true,
                    token: Some(token),
                    expires_in: Some(config.token_expire_secs),
                    error: None,
                    must_change_password: Some(user.must_change_password),
                },
                Err(error) => {
                    warn!(error = %error, "Token generation failed");
                    login_fail("令牌生成失败，请重试")
                }
            }
        }
        Ok(true) | Ok(false) => {
            let blocked = rate_limiter.check_and_record_failure(client_ip);
            if blocked {
                login_fail("登录失败次数过多，请稍后再试")
            } else {
                login_fail("用户名或密码错误")
            }
        }
        Err(error) => {
            warn!(error = %error, username = %audit_username, "Platform password verification failed");
            login_fail("认证失败，请重试")
        }
    }
}

/// Process Passwordrequest, verify Password New + PostgreSQL
///
/// SEC: wrong current-password attempts are counted per source IP with the
/// same limiter as login; without this an authenticated session (or a stolen
/// cookie) could brute-force the current password unbounded.
#[allow(dead_code)]
pub async fn handle_change_password(
    config: &AuthConfig,
    db: &vigilyx_db::VigilDb,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &ChangePasswordRequest,
) -> ChangePasswordResponse {
    if let Err(message) = validate_new_password(&config.username, &request.new_password) {
        return ChangePasswordResponse {
            success: false,
            error: Some(message.into()),
        };
    }

    // SEC: disallow reusing the old password to prevent bypassing the first-password-change gate by "changing" to the same password
    if request.new_password == request.old_password {
        return ChangePasswordResponse {
            success: false,
            error: Some("新密码不能与旧密码相同".into()),
        };
    }

    let current_hash =
        match precheck_change_password(config, rate_limiter, client_ip, request).await {
            Ok(hash) => hash,
            Err(response) => return response,
        };

    let new_hash = match hash_password(&request.new_password) {
        Ok(h) => h,
        Err(e) => {
            warn!("新密码哈希生成失败: {}", e);
            return ChangePasswordResponse {
                success: false,
                error: Some("密码处理失败".into()),
            };
        }
    };

    // SEC M-1: revocation is per user. The legacy admin maps to a seeded
    // platform row (RBAC bootstrap); bumping that row revokes only the
    // admin's outstanding JWTs. The pre-RBAC fallback (no platform row) keeps
    // the legacy global config counter — require_auth needs the row anyway,
    // so that state cannot serve authenticated traffic.
    // Red-team hardening: a transient lookup failure must FAIL the password
    // change. Treating it as "no row" silently bumped the legacy global
    // counter, leaving the admin's still-valid platform-row tokens alive
    // across a password change (fail-open revocation).
    let legacy_admin = match db.get_platform_auth_user(&config.username).await {
        Ok(admin) => admin,
        Err(error) => {
            warn!(
                %error,
                "legacy admin platform lookup failed; refusing password change (fail-closed)"
            );
            return ChangePasswordResponse {
                success: false,
                error: Some("密码保存失败，请重试".into()),
            };
        }
    };

    if let Err(e) = db.set_config("auth_password_hash", &new_hash).await {
        warn!("密码持久化失败: {}", e);
        return ChangePasswordResponse {
            success: false,
            error: Some("密码保存失败，请重试".into()),
        };
    }
    let revocation: Result<(), String> = match &legacy_admin {
        Some(admin) => db
            .bump_platform_user_token_version(&admin.id)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        None => {
            let new_tv = config.token_version.load(Ordering::Relaxed) + 1;
            db.set_config("auth_token_version", &new_tv.to_string())
                .await
                .map_err(|e| e.to_string())
        }
    };
    if let Err(e) = revocation {
        // If revocation persistence fails, roll back the password hash so old
        // JWTs cannot outlive a half-applied password change.
        warn!("Token version 持久化失败，回滚密码: {}", e);
        let _ = db.set_config("auth_password_hash", &current_hash).await;
        return ChangePasswordResponse {
            success: false,
            error: Some("密码保存失败（token version），请重试".into()),
        };
    }

    // Update in-memory state only after both DB writes succeed
    *config.password_hash.write().await = new_hash;
    *config.password_changed.write().await = true;
    if legacy_admin.is_none() {
        config
            .token_version
            .store(config.token_version.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }
    info!("Admin password changed and persisted; per-user token version bumped");

    ChangePasswordResponse {
        success: true,
        error: None,
    }
}

/// Change the password belonging to the authenticated platform user and
/// revoke all existing JWTs atomically with the database update.
pub async fn handle_platform_change_password(
    config: &AuthConfig,
    db: &vigilyx_db::VigilDb,
    user: &PlatformAuthUser,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &ChangePasswordRequest,
) -> ChangePasswordResponse {
    if let Err(message) = validate_new_password(&user.username, &request.new_password) {
        return ChangePasswordResponse {
            success: false,
            error: Some(message.into()),
        };
    }
    if request.new_password == request.old_password {
        return ChangePasswordResponse {
            success: false,
            error: Some("新密码不能与旧密码相同".into()),
        };
    }
    if let Some((count, _)) = rate_limiter.peek(&client_ip)
        && count >= rate_limiter.max_failures
    {
        return ChangePasswordResponse {
            success: false,
            error: Some("失败次数过多，请稍后再试".into()),
        };
    }
    match verify_password(&request.old_password, &user.password_hash) {
        Ok(true) => rate_limiter.reset(client_ip),
        Ok(false) => {
            let blocked = rate_limiter.check_and_record_failure(client_ip);
            return ChangePasswordResponse {
                success: false,
                error: Some(
                    if blocked {
                        "失败次数过多，请稍后再试"
                    } else {
                        "Current password is incorrect"
                    }
                    .into(),
                ),
            };
        }
        Err(error) => {
            warn!(error = %error, "Platform password verification failed");
            return ChangePasswordResponse {
                success: false,
                error: Some("Password verification failed".into()),
            };
        }
    }

    let new_hash = match hash_password(&request.new_password) {
        Ok(hash) => hash,
        Err(error) => {
            warn!(error = %error, "Platform password hash generation failed");
            return ChangePasswordResponse {
                success: false,
                error: Some("密码处理失败".into()),
            };
        }
    };
    let sync_legacy = user.username == config.username;
    match db
        .set_platform_user_password_and_bump_token(&user.id, &new_hash, false, sync_legacy)
        .await
    {
        Ok(_user_token_version) => {
            // SEC M-1: the row bump already revoked this user's older JWTs;
            // no in-memory global counter participates in enforcement.
            if sync_legacy {
                *config.password_hash.write().await = new_hash;
                *config.password_changed.write().await = true;
            }
            ChangePasswordResponse {
                success: true,
                error: None,
            }
        }
        Err(error) => {
            warn!(error = %error, "Platform password persistence failed");
            ChangePasswordResponse {
                success: false,
                error: Some("密码保存失败，请重试".into()),
            }
        }
    }
}

/// Verify the current password for a change request, with per-IP failure
/// counting on the same limiter as login. Without this an authenticated
/// session (or a stolen cookie) could brute-force the current password
/// unbounded. Returns the current hash on success (needed for the atomic
/// persistence rollback), or the rejection response to return to the caller.
#[allow(dead_code)]
async fn precheck_change_password(
    config: &AuthConfig,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &ChangePasswordRequest,
) -> Result<String, ChangePasswordResponse> {
    // ── Per-IP Rate limiting: pre-check (same limiter as login) ──
    // Peek without recording a failure. If already at/over the limit,
    // reject immediately to avoid expensive password verification.
    if let Some((count, _)) = rate_limiter.peek(&client_ip)
        && count >= rate_limiter.max_failures
    {
        warn!(
            ip = %client_ip,
            failures = count,
            "Password change rate-limited: IP exceeded max failures"
        );
        return Err(ChangePasswordResponse {
            success: false,
            error: Some("失败次数过多，请稍后再试".into()),
        });
    }

    let current_hash = config.password_hash.read().await.clone();
    match verify_password(&request.old_password, &current_hash) {
        Ok(true) => {
            // success: clear the IP failure counter
            rate_limiter.reset(client_ip);
            Ok(current_hash)
        }
        Ok(false) => {
            let blocked = rate_limiter.check_and_record_failure(client_ip);
            warn!(
                ip = %client_ip,
                "Password change failed: wrong current password"
            );
            if blocked {
                return Err(ChangePasswordResponse {
                    success: false,
                    error: Some("失败次数过多，请稍后再试".into()),
                });
            }
            Err(ChangePasswordResponse {
                success: false,
                error: Some("Current password is incorrect".into()),
            })
        }
        Err(e) => {
            warn!("Password verification failed: {}", e);
            Err(ChangePasswordResponse {
                success: false,
                error: Some("Password verification failed".into()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChangePasswordRequest, LoginRequest, LoginResponse, precheck_change_password,
        sanitize_login_username, validate_login_request, validate_new_password,
    };
    use crate::auth::AuthConfig;
    use crate::auth::rate_limit::LoginRateLimiter;
    use std::net::{IpAddr, Ipv4Addr};

    const TEST_ADMIN_PASSWORD: &str = "TestAdmin!2345";

    fn change_request(old: &str, new: &str) -> ChangePasswordRequest {
        ChangePasswordRequest {
            old_password: old.to_string(),
            new_password: new.to_string(),
        }
    }

    #[test]
    fn test_login_response_does_not_serialize_token() {
        let response = LoginResponse {
            success: true,
            token: Some("jwt-secret".to_string()),
            expires_in: Some(3600),
            error: None,
            must_change_password: Some(true),
        };

        let serialized = serde_json::to_value(response).unwrap();
        assert_eq!(serialized.get("token"), None);
        assert_eq!(serialized["success"], true);
        assert_eq!(serialized["expires_in"], 3600);
        assert_eq!(serialized["must_change_password"], true);
    }

    #[test]
    fn rejects_blank_passwords() {
        let error = validate_new_password("admin", "            ").unwrap_err();
        assert!(error.contains("空白字符"));
    }

    #[test]
    fn rejects_passwords_that_are_too_short() {
        let error = validate_new_password("admin", "Abc123!xyz").unwrap_err();
        assert!(error.contains("12 位"));
    }

    #[test]
    fn rejects_missing_complexity_for_shorter_passwords() {
        let error = validate_new_password("admin", "alllowercase12").unwrap_err();
        assert!(error.contains("3 类"));
    }

    #[test]
    fn rejects_common_password_patterns() {
        let error = validate_new_password("admin", "Password123!").unwrap_err();
        assert!(error.contains("常见"));
    }

    #[test]
    fn rejects_username_variants() {
        let error = validate_new_password("admin", "Admin-Team-2026!").unwrap_err();
        assert!(error.contains("用户名"));
    }

    #[test]
    fn allows_long_multi_word_passphrases() {
        assert!(validate_new_password("admin", "Blue Ocean Patrol 2026").is_ok());
    }

    #[test]
    fn sanitize_login_username_removes_controls_and_truncates() {
        let sanitized = sanitize_login_username(&format!(" admin\tname\r\n{}", "x".repeat(200)));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\t'));
        assert!(sanitized.starts_with("admin name"));
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn validate_login_request_rejects_control_chars_in_username() {
        let request = LoginRequest {
            username: "admin\nroot".to_string(),
            password: "test".to_string(),
        };

        assert_eq!(validate_login_request(&request), Err("登录请求无效"));
    }

    #[test]
    fn validate_login_request_rejects_oversized_password() {
        let request = LoginRequest {
            username: "admin".to_string(),
            password: "x".repeat(4097),
        };

        assert_eq!(validate_login_request(&request), Err("登录请求无效"));
    }

    #[tokio::test]
    async fn change_password_wrong_old_password_is_rate_limited_per_ip() {
        // PoC: before the fix, an authenticated session could brute-force the
        // current password unbounded — every wrong guess only got a generic
        // "incorrect" reply. Now failures are counted per IP like login.
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = LoginRateLimiter::new(5, 60);
        let attacker: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
        let bystander: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));

        // Under the limit: generic "incorrect" replies, no lockout.
        for _ in 0..4 {
            let err = precheck_change_password(
                &config,
                &limiter,
                attacker,
                &change_request("wrong-guess", "NewStrong!Pass1"),
            )
            .await
            .expect_err("wrong current password must be rejected");
            assert_eq!(err.error.as_deref(), Some("Current password is incorrect"));
        }

        // Hitting the limit locks the IP out...
        let err = precheck_change_password(
            &config,
            &limiter,
            attacker,
            &change_request("wrong-guess", "NewStrong!Pass1"),
        )
        .await
        .expect_err("fifth failure must trip the limiter");
        assert_eq!(err.error.as_deref(), Some("失败次数过多，请稍后再试"));

        // ...even for the correct current password.
        let err = precheck_change_password(
            &config,
            &limiter,
            attacker,
            &change_request(TEST_ADMIN_PASSWORD, "NewStrong!Pass1"),
        )
        .await
        .expect_err("locked-out IP must be rejected before verification");
        assert_eq!(err.error.as_deref(), Some("失败次数过多，请稍后再试"));

        // Other source IPs are unaffected.
        assert!(
            precheck_change_password(
                &config,
                &limiter,
                bystander,
                &change_request(TEST_ADMIN_PASSWORD, "NewStrong!Pass1"),
            )
            .await
            .is_ok(),
            "bystander IP must not inherit the attacker's failures"
        );
    }

    #[tokio::test]
    async fn change_password_correct_old_password_resets_failure_count() {
        // Regression: a legitimate change must clear the counter, mirroring
        // the login limiter's reset-on-success behavior.
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let limiter = LoginRateLimiter::new(5, 60);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 1, 1));

        for _ in 0..4 {
            let _ = precheck_change_password(
                &config,
                &limiter,
                ip,
                &change_request("wrong-guess", "NewStrong!Pass1"),
            )
            .await;
        }

        assert!(
            precheck_change_password(
                &config,
                &limiter,
                ip,
                &change_request(TEST_ADMIN_PASSWORD, "NewStrong!Pass1"),
            )
            .await
            .is_ok(),
            "correct current password must pass the precheck"
        );

        // Counter was reset: four more failures are tolerated again.
        for _ in 0..4 {
            let err = precheck_change_password(
                &config,
                &limiter,
                ip,
                &change_request("wrong-guess", "NewStrong!Pass1"),
            )
            .await
            .expect_err("wrong current password must be rejected");
            assert_eq!(
                err.error.as_deref(),
                Some("Current password is incorrect"),
                "counter must have been reset by the successful verification"
            );
        }
    }
}
