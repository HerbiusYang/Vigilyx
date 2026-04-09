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

// -- Cookie constants --
const COOKIE_NAME: &str = "vigilyx_token";

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
    format!(
        "{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0{secure_flag}"
    )
}

/// GET /api/auth/me - return the current session user info (cookie validation is handled by middleware).
#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub username: String,
    pub role: String,
}

pub async fn handle_me(user: AuthenticatedUser) -> Json<MeResponse> {
    Json(MeResponse {
        username: user.username,
        role: user.role,
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

fn validate_new_password(username: &str, new_password: &str) -> Result<(), &'static str> {
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
pub async fn handle_login(
    config: &AuthConfig,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
    request: &LoginRequest,
) -> LoginResponse {
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
        warn!(ip = %client_ip, "Login failed: invalid username - {}", request.username);
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
            match generate_token(config, &request.username, "admin") {
                Ok(token) => {
                    let changed = *config.password_changed.read().await;
                    if !changed {
                        warn!(
                            ip = %client_ip,
                            "Security warning: user {} logged in with default password",
                            request.username
                        );
                    }
                    info!(ip = %client_ip, "Login success: {} (password_changed: {})", request.username, changed);
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
            warn!(ip = %client_ip, "Login failed: wrong password - {}", request.username);
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

/// Process Passwordrequest, verify Password New + PostgreSQL
pub async fn handle_change_password(
    config: &AuthConfig,
    db: &vigilyx_db::VigilDb,
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

    let current_hash = config.password_hash.read().await.clone();
    match verify_password(&request.old_password, &current_hash) {
        Ok(true) => {
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

            // SEC: password hash and token version must be persisted atomically.
            // If either step fails, the whole password-change flow must fail to prevent old JWTs from reviving after a restart.
            let new_tv = config.token_version.load(Ordering::Relaxed) + 1;
            let tv_str = new_tv.to_string();

            if let Err(e) = db.set_config("auth_password_hash", &new_hash).await {
                warn!("密码持久化失败: {}", e);
                return ChangePasswordResponse {
                    success: false,
                    error: Some("密码保存失败，请重试".into()),
                };
            }
            if let Err(e) = db.set_config("auth_token_version", &tv_str).await {
                // If token version persistence fails, roll back the password hash
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
            config.token_version.store(new_tv, Ordering::Relaxed);
            info!("Admin password changed and persisted, token version -> {}", new_tv);

            ChangePasswordResponse {
                success: true,
                error: None,
            }
        }
        Ok(false) => {
            warn!("Password change failed: wrong current password");
            ChangePasswordResponse {
                success: false,
                error: Some("Current password is incorrect".into()),
            }
        }
        Err(e) => {
            warn!("Password verification failed: {}", e);
            ChangePasswordResponse {
                success: false,
                error: Some("Password verification failed".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LoginResponse, validate_new_password};

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
}
