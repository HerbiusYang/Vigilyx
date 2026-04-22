//! AlertConfigurationProcess: AI Service, Alert, Source,

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use vigilyx_core::{DEFAULT_INTERNAL_SERVICE_HOSTS, validate_internal_service_url};

use super::super::ApiResponse;
use super::mask_api_key;
use super::publish_engine_reload;
use crate::AppState;
use crate::auth::AuthenticatedUser;


// SEC-REMAINING-001: Configurationvalue (AES-256-GCM)

// Use HKDF-SHA256 to derive AES-256 key from API_JWT_SECRET,
// Encrypt sensitive values like smtp_password and API key before storing in DB.
// format: "ENC:" + base64(nonce || ciphertext || tag)


/// Derive AES-256 encryption key from JWT secret
fn derive_encryption_key(jwt_secret: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
   // HKDF-like: SHA256(salt || secret) - Simplified implementation,sufficient to defend against DB leaks
    let mut hasher = Sha256::new();
    hasher.update(b"vigilyx-config-encryption-v1");
    hasher.update(jwt_secret.as_bytes());
    hasher.finalize().into()
}

/// Configurationvalue (AES-256-GCM)
pub(super) fn encrypt_config_value(plaintext: &str, jwt_secret: &str) -> Result<String, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let key_bytes = derive_encryption_key(jwt_secret);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("cipher init: {e}"))?;

   // 96-bit random nonce
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("rng: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encrypt: {e}"))?;

   // nonce (12) || ciphertext+tag
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    use base64::Engine;
    Ok(format!(
        "ENC:{}",
        base64::engine::general_purpose::STANDARD.encode(&combined)
    ))
}

/// Decrypt config value (AES-256-GCM)
#[allow(dead_code)]
pub(super) fn decrypt_config_value(stored: &str, jwt_secret: &str) -> Result<String, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if stored.is_empty() {
        return Ok(String::new());
    }
   // : ENC: value ()
    let encoded = match stored.strip_prefix("ENC:") {
        Some(e) => e,
        None => return Ok(stored.to_string()), 
    };

    use base64::Engine;
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64: {e}"))?;
    if combined.len() < 13 {
        return Err("ciphertext too short".into());
    }

    let key_bytes = derive_encryption_key(jwt_secret);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(&combined[..12]);
    let plaintext = cipher
        .decrypt(nonce, &combined[12..])
        .map_err(|_| "decrypt failed (wrong key or tampered)".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
}


// AI Service configuration


/// Get AI Service configuration (API Key desensitize)
pub async fn get_ai_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_ai_service_config().await {
        Ok(Some(json)) => {
            let mut value: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            mask_api_key(&mut value);
            ApiResponse::ok(value)
        }
        Ok(None) => {
            let default_cfg = vigilyx_engine::config::AiServiceConfig::default();
            let mut value = serde_json::to_value(&default_cfg).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("api_key_set".to_string(), serde_json::json!(false));
            }
            ApiResponse::ok(value)
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// New AI Service configuration
pub async fn update_ai_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(mut body): Json<serde_json::Value>,
) -> axum::response::Response {
   // Missing or masked values keep the stored key; an explicit empty string clears it.
    if let Some(obj) = body.as_object_mut() {
        obj.remove("api_key_set"); // , Data
        if let Ok(Some(existing_json)) = state.engine_db.get_ai_service_config().await
            && let Ok(existing) = serde_json::from_str::<serde_json::Value>(&existing_json)
        {
            restore_existing_secret(obj, "api_key", &existing);
        }
    }

   // verifyformat
    let parsed: vigilyx_engine::config::AiServiceConfig = match serde_json::from_value(body.clone())
    {
        Ok(c) => c,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Invalid AI config: {}",
                e
            ))
            .into_response();
        }
    };

   // SEC: Validate URL allowlist on save, not just test - prevent SSRF/data exfil (CWE-918)
    if !is_allowed_internal_url(&parsed.service_url) {
        return ApiResponse::<serde_json::Value>::bad_request(
            "AI service URL must be an internal service (e.g. http://ai:8900)",
        )
        .into_response();
    }

   // SEC: Encrypt API key before storing in DB (CWE-312)
    if let Some(obj) = body.as_object_mut()
        && let Some(key) = obj
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        && !key.is_empty()
        && !key.starts_with("ENC:")
    {
        use secrecy::ExposeSecret;
        match encrypt_config_value(&key, state.auth.config.jwt_secret.expose_secret()) {
            Ok(encrypted) => {
                obj.insert("api_key".to_string(), serde_json::json!(encrypted));
            }
            Err(e) => {
                tracing::error!("AI API key encryption failed: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response();
            }
        }
    }

    let json_str = match serde_json::to_string(&body) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "AI config serialization failed: {}",
                e
            ))
            .into_response();
        }
    };
    match state.engine_db.set_ai_service_config(&json_str).await {
        Ok(()) => {
           // save AI Service
            let proxy = vigilyx_engine::remote::RemoteModuleProxy::new(parsed.service_url);
            let available = proxy.health_check().await;

           // Engine process New AI Configuration
            publish_engine_reload(&state, "ai_config").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_ai_config",
                Some("security"),
                Some("ai_service_config".to_string()),
                None,
            );

            ApiResponse::ok(serde_json::json!({
                "saved": true,
                "ai_service_available": available,
            }))
            .into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// AI ServiceConnection

/// SEC: SSRF protection - Connection Docker Address (CWE-918)
pub async fn test_ai_connection(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let ai_config: vigilyx_engine::config::AiServiceConfig = match serde_json::from_value(body) {
        Ok(c) => c,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("Invalid config: {}", e))
                .into_response();
        }
    };

   // SSRF protection: only allow internal service URLs such as `http://ai:8900`.
    if !is_allowed_internal_url(&ai_config.service_url) {
        return ApiResponse::<serde_json::Value>::bad_request(
            "Only internal service URLs are allowed (for example http://ai:8900).",
        )
        .into_response();
    }

    let proxy = vigilyx_engine::remote::RemoteModuleProxy::new(ai_config.service_url.clone());
    let available = proxy.health_check().await;

    ApiResponse::ok(serde_json::json!({
        "reachable": available,
        "service_url": ai_config.service_url,
    }))
    .into_response()
}

/// SSRF protection: Verify URL internalServiceAddress

/// SEC-NEW-001: URL ParseExtract host,
/// (`http://evil.com?x=://ai:`, CWE-918)
fn is_allowed_internal_url(url: &str) -> bool {
    validate_internal_service_url(url, DEFAULT_INTERNAL_SERVICE_HOSTS).is_ok()
}


// Email alert configuration


/// GetEmail alert configuration (Passworddesensitize)
pub async fn get_email_alert_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_email_alert_config().await {
        Ok(Some(json)) => {
            let mut value = match serde_json::from_str::<vigilyx_engine::config::EmailAlertConfig>(&json) {
                Ok(config) => serde_json::to_value(&config).unwrap_or(serde_json::Value::Null),
                Err(_) => serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
            };
            mask_smtp_password(&mut value);
            ApiResponse::ok(value)
        }
        Ok(None) => {
            let default_cfg = vigilyx_engine::config::EmailAlertConfig::default();
            let mut value = serde_json::to_value(&default_cfg).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("smtp_password_set".to_string(), serde_json::json!(false));
            }
            ApiResponse::ok(value)
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// NewEmail alert configuration
pub async fn update_email_alert_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(mut body): Json<serde_json::Value>,
) -> axum::response::Response {
   // Missing or masked values keep the stored password; an explicit empty string clears it.
    if let Some(obj) = body.as_object_mut() {
        obj.remove("smtp_password_set");

        if let Ok(Some(existing_json)) = state.engine_db.get_email_alert_config().await
            && let Ok(existing) = serde_json::from_str::<serde_json::Value>(&existing_json)
        {
            restore_existing_secret(obj, "smtp_password", &existing);
        }
    }

   // verifyformat
    let parsed: vigilyx_engine::config::EmailAlertConfig =
        match serde_json::from_value(body.clone()) {
            Ok(c) => c,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "Invalid email alert config: {}",
                    e
                ))
                .into_response();
            }
        };

   // SEC: Validate SMTP host on save, not just test - prevent SSRF (CWE-918)
    if crate::handlers::syslog_config::is_blocked_address(&parsed.smtp_host) {
        return ApiResponse::<serde_json::Value>::bad_request("Disallowed SMTP server address")
            .into_response();
    }

   // SEC-REMAINING-001: smtp_password DB
    if let Some(obj) = body.as_object_mut()
        && let Some(pwd) = obj
            .get("smtp_password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        && !pwd.is_empty()
        && !pwd.starts_with("ENC:")
    {
        use secrecy::ExposeSecret;
        match encrypt_config_value(&pwd, state.auth.config.jwt_secret.expose_secret()) {
            Ok(encrypted) => {
                obj.insert("smtp_password".to_string(), serde_json::json!(encrypted));
            }
            Err(e) => {
                tracing::error!("SMTP password encryption failed: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response();
            }
        }
    }

    let json_str = match serde_json::to_string(&body) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "序列化AlertConfigurationfailed: {}",
                e
            ))
            .into_response();
        }
    };
    match state.engine_db.set_email_alert_config(&json_str).await {
        Ok(()) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_email_alert_config",
                Some("security"),
                Some("email_alert_config".to_string()),
                None,
            );
            ApiResponse::ok(serde_json::json!({ "saved": true })).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// AlertConnection (send)

/// SEC: SSRF protection - SMTP Connection metadata/ Address (CWE-918)
pub async fn test_email_alert(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
   // ParseConfiguration (send Configuration)
    let mut config: vigilyx_engine::config::EmailAlertConfig =
        match serde_json::from_value(body.clone()) {
            Ok(c) => c,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "Invalid email alert config: {}",
                    e
                ))
                .into_response();
            }
        };

   // Masked UI placeholders keep the stored password; an explicit empty string does not.
    if is_masked_secret_placeholder(&config.smtp_password)
        && let Ok(Some(existing_json)) = state.engine_db.get_email_alert_config().await
        && let Ok(existing) =
            serde_json::from_str::<vigilyx_engine::config::EmailAlertConfig>(&existing_json)
    {
        config.smtp_password = existing.smtp_password;
    }

    if config.smtp_password.starts_with("ENC:") {
        use secrecy::ExposeSecret;

        match decrypt_config_value(&config.smtp_password, state.auth.config.jwt_secret.expose_secret())
        {
            Ok(password) => config.smtp_password = password,
            Err(e) => {
                tracing::error!("SMTP password decrypt failed during test email: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response();
            }
        }
    }

   // SSRF protection: Connection metadata internal Address
    if crate::handlers::syslog_config::is_blocked_address(&config.smtp_host) {
        return ApiResponse::<serde_json::Value>::bad_request("不允许Connection到该 SMTP Address")
            .into_response();
    }

    match state
        .managers
        .disposition_engine
        .test_email_connection(&config)
        .await
    {
        Ok(msg) => ApiResponse::ok(serde_json::json!({
            "success": true,
            "message": msg,
        }))
        .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::err(e).into_response(),
    }
}

/// SMTP Passworddesensitize
fn mask_smtp_password(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        let has_password = matches!(obj.get("smtp_password").and_then(|k| k.as_str()), Some(pwd) if !pwd.is_empty());
        obj.insert("smtp_password".to_string(), serde_json::json!(""));
        obj.insert(
            "smtp_password_set".to_string(),
            serde_json::json!(has_password),
        );
    }
}

/// Get WeChat alert configuration (webhook desensitized)
pub async fn get_wechat_alert_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_wechat_alert_config().await {
        Ok(Some(json)) => {
            let mut value =
                match serde_json::from_str::<vigilyx_engine::config::WechatAlertConfig>(&json) {
                    Ok(config) => serde_json::to_value(&config).unwrap_or(serde_json::Value::Null),
                    Err(_) => serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
                };
            mask_wechat_webhook_url(&mut value);
            ApiResponse::ok(value)
        }
        Ok(None) => {
            let default_cfg = vigilyx_engine::config::WechatAlertConfig::default();
            let mut value = serde_json::to_value(&default_cfg).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("webhook_url_set".to_string(), serde_json::json!(false));
            }
            ApiResponse::ok(value)
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

pub async fn update_wechat_alert_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(mut body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("webhook_url_set");

        if let Ok(Some(existing_json)) = state.engine_db.get_wechat_alert_config().await
            && let Ok(existing) = serde_json::from_str::<serde_json::Value>(&existing_json)
        {
            restore_existing_secret(obj, "webhook_url", &existing);
        }
    }

    let parsed: vigilyx_engine::config::WechatAlertConfig =
        match serde_json::from_value(body.clone()) {
            Ok(config) => config,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "Invalid WeChat alert config: {}",
                    e
                ))
                .into_response();
            }
        };

    if !parsed.webhook_url.is_empty()
        && let Err(reason) =
            vigilyx_soar::disposition::validate_wechat_webhook_url(&parsed.webhook_url)
    {
        return ApiResponse::<serde_json::Value>::bad_request(reason).into_response();
    }

    if let Some(obj) = body.as_object_mut()
        && let Some(webhook_url) = obj
            .get("webhook_url")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
        && !webhook_url.is_empty()
        && !webhook_url.starts_with("ENC:")
    {
        use secrecy::ExposeSecret;
        match encrypt_config_value(&webhook_url, state.auth.config.jwt_secret.expose_secret()) {
            Ok(encrypted) => {
                obj.insert("webhook_url".to_string(), serde_json::json!(encrypted));
            }
            Err(e) => {
                tracing::error!("WeChat webhook encryption failed: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response();
            }
        }
    }

    let json_str = match serde_json::to_string(&body) {
        Ok(json) => json,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "WeChat alert config serialization failed: {}",
                e
            ))
            .into_response();
        }
    };

    match state.engine_db.set_wechat_alert_config(&json_str).await {
        Ok(()) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_wechat_alert_config",
                Some("security"),
                Some("wechat_alert_config".to_string()),
                None,
            );
            ApiResponse::ok(serde_json::json!({ "saved": true })).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

pub async fn test_wechat_alert(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let mut config: vigilyx_engine::config::WechatAlertConfig =
        match serde_json::from_value(body.clone()) {
            Ok(config) => config,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "Invalid WeChat alert config: {}",
                    e
                ))
                .into_response();
            }
        };

    if is_masked_secret_placeholder(&config.webhook_url)
        && let Ok(Some(existing_json)) = state.engine_db.get_wechat_alert_config().await
        && let Ok(existing) =
            serde_json::from_str::<vigilyx_engine::config::WechatAlertConfig>(&existing_json)
    {
        config.webhook_url = existing.webhook_url;
    }

    if config.webhook_url.starts_with("ENC:") {
        use secrecy::ExposeSecret;

        match decrypt_config_value(
            &config.webhook_url,
            state.auth.config.jwt_secret.expose_secret(),
        ) {
            Ok(webhook_url) => config.webhook_url = webhook_url,
            Err(e) => {
                tracing::error!("WeChat webhook decrypt failed during test: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed")
                    .into_response();
            }
        }
    }

    if !config.webhook_url.is_empty()
        && let Err(reason) =
            vigilyx_soar::disposition::validate_wechat_webhook_url(&config.webhook_url)
    {
        return ApiResponse::<serde_json::Value>::bad_request(reason).into_response();
    }

    match state
        .managers
        .disposition_engine
        .test_wechat_alert(&config)
        .await
    {
        Ok(msg) => ApiResponse::ok(serde_json::json!({
            "success": true,
            "message": msg,
        }))
        .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::err(e).into_response(),
    }
}

fn mask_wechat_webhook_url(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        let has_webhook = matches!(obj.get("webhook_url").and_then(|value| value.as_str()), Some(url) if !url.is_empty());
        obj.insert("webhook_url".to_string(), serde_json::json!(""));
        obj.insert(
            "webhook_url_set".to_string(),
            serde_json::json!(has_webhook),
        );
    }
}

fn restore_existing_secret(
    body: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    existing: &serde_json::Value,
) {
    let should_restore = match body.get(field) {
        None => true,
        Some(value) => value
            .as_str()
            .is_some_and(is_masked_secret_placeholder),
    };

    if should_restore
        && let Some(real_value) = existing.get(field)
    {
        body.insert(field.to_string(), real_value.clone());
    }
}

fn normalize_empty_optional_secret_field(
    body: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
) {
    if body.get(field).and_then(|value| value.as_str()) == Some("") {
        body.insert(field.to_string(), serde_json::Value::Null);
    }
}

fn is_masked_secret_placeholder(value: &str) -> bool {
    value.contains("...") || value == "****"
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        is_masked_secret_placeholder, normalize_empty_optional_secret_field,
        restore_existing_secret,
    };

    #[test]
    fn restores_missing_ai_key_from_existing_config() {
        let mut incoming = serde_json::Map::new();
        let existing = json!({
            "api_key": "ENC:stored-secret"
        });

        restore_existing_secret(&mut incoming, "api_key", &existing);

        assert_eq!(incoming.get("api_key"), Some(&json!("ENC:stored-secret")));
    }

    #[test]
    fn restores_masked_ai_key_from_existing_config() {
        let mut incoming = serde_json::Map::from_iter([(
            "api_key".to_string(),
            json!("****...abcd"),
        )]);
        let existing = json!({
            "api_key": "ENC:stored-secret"
        });

        restore_existing_secret(&mut incoming, "api_key", &existing);

        assert_eq!(incoming.get("api_key"), Some(&json!("ENC:stored-secret")));
    }

    #[test]
    fn keeps_explicit_empty_ai_key_to_allow_clearing() {
        let mut incoming = serde_json::Map::from_iter([(
            "api_key".to_string(),
            json!(""),
        )]);
        let existing = json!({
            "api_key": "ENC:stored-secret"
        });

        restore_existing_secret(&mut incoming, "api_key", &existing);

        assert_eq!(incoming.get("api_key"), Some(&json!("")));
    }

    #[test]
    fn placeholder_detection_does_not_treat_empty_string_as_keep() {
        assert!(is_masked_secret_placeholder("****"));
        assert!(is_masked_secret_placeholder("****...abcd"));
        assert!(!is_masked_secret_placeholder(""));
        assert!(!is_masked_secret_placeholder("real-secret"));
    }

    #[test]
    fn normalizes_empty_optional_secret_to_null() {
        let mut incoming = serde_json::Map::from_iter([(
            "virustotal_api_key".to_string(),
            json!(""),
        )]);

        normalize_empty_optional_secret_field(&mut incoming, "virustotal_api_key");

        assert_eq!(
            incoming.get("virustotal_api_key"),
            Some(&serde_json::Value::Null)
        );
    }
}


// (IOC verdict=clean)


fn default_ioc_limit() -> u32 {
    50
}

fn normalize_intel_indicator(ioc_type: &str, indicator: &str) -> Result<String, String> {
    let normalized_type = ioc_type.trim().to_lowercase();
    let trimmed = indicator.trim();
    if trimmed.is_empty() {
        return Err("Indicator cannot be empty".to_string());
    }

    match normalized_type.as_str() {
        "domain" | "email" | "hash" => Ok(trimmed.to_lowercase()),
        "ip" | "url" => Ok(trimmed.to_string()),
        _ => Err("Unsupported IOC type".to_string()),
    }
}

/// Queryparameter
#[derive(Debug, Deserialize)]
pub struct IntelWhitelistParams {
    #[serde(default = "default_ioc_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub ioc_type: Option<String>,
    pub search: Option<String>,
}


pub async fn list_intel_whitelist(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<IntelWhitelistParams>,
) -> impl IntoResponse {
    params.limit = params.limit.clamp(1, 1000);
    match state
        .engine_db
        .list_intel_whitelist(
            params.ioc_type.as_deref(),
            params.search.as_deref(),
            params.limit,
            params.offset,
        )
        .await
    {
        Ok((items, total)) => ApiResponse::ok(serde_json::json!({
            "items": items,
            "total": total,
            "limit": params.limit,
            "offset": params.offset,
        })),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// request
#[derive(Debug, Deserialize)]
pub struct AddIntelCleanRequest {
    pub indicator: String,
    pub ioc_type: String,
    pub description: Option<String>,
}


pub async fn add_intel_clean(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<AddIntelCleanRequest>,
) -> axum::response::Response {
    let ioc_type = req.ioc_type.trim().to_lowercase();
    let indicator = match normalize_intel_indicator(&ioc_type, &req.indicator) {
        Ok(indicator) => indicator,
        Err(message) => {
            return ApiResponse::<serde_json::Value>::bad_request(&message).into_response();
        }
    };

    match state
        .engine_db
        .add_intel_clean(&indicator, &ioc_type, req.description.as_deref())
        .await
    {
        Ok(ioc) => {
            publish_engine_reload(&state, "ioc").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "add_intel_clean",
                Some("security"),
                Some(ioc.id.to_string()),
                None,
            );
            ApiResponse::ok(serde_json::to_value(ioc).unwrap_or_default()).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed").into_response()
        }
    }
}

/// Delete (Security)
pub async fn delete_intel_whitelist(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> axum::response::Response {
    let ioc_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid ID").into_response();
        }
    };

    match state.engine_db.delete_ioc(ioc_id).await {
        Ok(true) => {
            publish_engine_reload(&state, "ioc").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "delete_intel_clean",
                Some("security"),
                Some(id),
                None,
            );
            ApiResponse::ok(serde_json::json!({"deleted": true})).into_response()
        }
        Ok(false) => {
            ApiResponse::<serde_json::Value>::not_found("Whitelist entry not found").into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}


// SourceConfiguration (VT/AbuseIPDB API Key)


/// Get SourceConfiguration (API Key desensitize)
pub async fn get_intel_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_config("intel_sources").await {
        Ok(Some(json)) => {
            let mut value: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            mask_intel_api_keys(&mut value);
            ApiResponse::ok(value)
        }
        Ok(None) => {
            let default_cfg = vigilyx_engine::intel::IntelSourceConfig::default();
            let mut value = serde_json::to_value(&default_cfg).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("abuseipdb_api_key_set".to_string(), serde_json::json!(false));
                obj.insert("virustotal_api_key_set".to_string(), serde_json::json!(false));
            }
            ApiResponse::ok(value)
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// New SourceConfiguration
pub async fn update_intel_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(mut body): Json<serde_json::Value>,
) -> axum::response::Response {
   // Missing or masked values keep stored API keys; explicit null/empty clears them.
    if let Some(obj) = body.as_object_mut() {
        obj.remove("abuseipdb_api_key_set");
        obj.remove("virustotal_api_key_set");

        let existing: Option<serde_json::Value> =
            if let Ok(Some(json)) = state.engine_db.get_config("intel_sources").await {
                serde_json::from_str(&json).ok()
            } else {
                None
            };

        for key_field in &["abuseipdb_api_key", "virustotal_api_key"] {
            if let Some(ref existing) = existing {
                restore_existing_secret(obj, key_field, existing);
            }
            normalize_empty_optional_secret_field(obj, key_field);
        }
    }

   // Validate format
    let mut parsed: vigilyx_engine::intel::IntelSourceConfig = match serde_json::from_value(body.clone())
    {
        Ok(config) => config,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Invalid intel config: {}",
                e
            ))
            .into_response();
        }
    };

    if let Some(url) = parsed.vt_scrape_url.as_deref()
        && let Err(err) = validate_internal_service_url(url, DEFAULT_INTERNAL_SERVICE_HOSTS)
    {
        return ApiResponse::<serde_json::Value>::bad_request(format!(
            "VT scrape URL must point to an internal AI service: {err}"
        ))
        .into_response();
    }

   // SEC: Encrypt API keys before storing in DB (CWE-312)
    {
        use secrecy::ExposeSecret;
        let encrypt = |key: &Option<String>| -> Result<Option<String>, String> {
            match key.as_deref() {
                Some(k) if !k.is_empty() && !k.starts_with("ENC:") => {
                    encrypt_config_value(k, state.auth.config.jwt_secret.expose_secret())
                        .map(Some)
                        .map_err(|e| e.to_string())
                }
                other => Ok(other.map(|s| s.to_string())),
            }
        };
        match encrypt(&parsed.virustotal_api_key) {
            Ok(v) => parsed.virustotal_api_key = v,
            Err(e) => {
                tracing::error!("Intel API key encryption failed: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(
                    &e,
                    "Operation failed",
                )
                .into_response();
            }
        }
        match encrypt(&parsed.abuseipdb_api_key) {
            Ok(v) => parsed.abuseipdb_api_key = v,
            Err(e) => {
                tracing::error!("Intel API key encryption failed: {}", e);
                return ApiResponse::<serde_json::Value>::internal_err(
                    &e,
                    "Operation failed",
                )
                .into_response();
            }
        }
    }

   // Serialize the canonical struct (only known fields, no DB pollution)
    let json_str = match serde_json::to_string(&parsed) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Failed to serialize intel config: {}",
                e
            ))
            .into_response();
        }
    };
    match state.engine_db.set_config("intel_sources", &json_str).await {
        Ok(()) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_intel_config",
                Some("security"),
                Some("intel_sources".to_string()),
                None,
            );
            ApiResponse::ok(serde_json::json!({
                "saved": true,
                "note": "Intel configuration saved. Takes effect after engine restart.",
            }))
            .into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// desensitize Source API Key
fn mask_intel_api_keys(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        for key_field in &["abuseipdb_api_key", "virustotal_api_key"] {
            let (masked, has_key) = match obj.get(*key_field).and_then(|k| k.as_str()) {
                Some(key) if key.starts_with("ENC:") => (serde_json::json!("****"), true),
                Some(key) if key.len() > 4 => {
                    let masked = format!(
                        "{}...{}",
                        "*".repeat(key.len().min(8) - 4),
                        &key[key.len() - 4..]
                    );
                    (serde_json::json!(masked), true)
                }
                Some(key) if !key.is_empty() => (serde_json::json!("****"), true),
                _ => (serde_json::Value::Null, false),
            };
            obj.insert(key_field.to_string(), masked);
            obj.insert(
                key_field.replace("_api_key", "_api_key_set"),
                serde_json::json!(has_key),
            );
        }
    }
}
