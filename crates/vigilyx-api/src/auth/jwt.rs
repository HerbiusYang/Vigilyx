//! JWT Token verify

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{AuthConfig, AuthError};

/// JWT issuer
const JWT_ISSUER: &str = "vigilyx";
/// JWT audience
const JWT_AUDIENCE: &str = "vigilyx-api";

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
   /// user
    pub sub: String,
   /// time (Unix time)
    pub exp: usize,
   /// time
    pub iat: usize,
    
    pub role: String,
    
    #[serde(default)]
    pub iss: String,
    
    #[serde(default)]
    pub aud: String,
   /// Token version - incremented on password change, old tokens rejected (SEC: CWE-613)
    #[serde(default)]
    pub tv: u64,
}

/// JWT Token
pub fn generate_token(
    config: &AuthConfig,
    username: &str,
    role: &str,
) -> Result<String, AuthError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let exp = now + config.token_expire_secs as usize;

    let claims = Claims {
        sub: username.to_string(),
        exp,
        iat: now,
        role: role.to_string(),
        iss: JWT_ISSUER.to_string(),
        aud: JWT_AUDIENCE.to_string(),
        tv: config
            .token_version
            .load(std::sync::atomic::Ordering::Relaxed),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.expose_secret().as_bytes()),
    )
    .map_err(|e| AuthError::InternalError(format!("Token 生成failed: {}", e)))
}

/// Verify JWT Token

/// Verify, time, (iss) (aud).
/// iss/aud token - - Newlogin.
/// SEC: Validate token version (tv) - old tokens rejected after password change (CWE-613).
#[allow(dead_code)]
pub fn verify_token(config: &AuthConfig, token: &str) -> Result<Claims, AuthError> {
    let mut validation = Validation::default();
    validation.set_issuer(&[JWT_ISSUER]);
    validation.set_audience(&[JWT_AUDIENCE]);
   // SEC-C01: CVE-2026-25537 mitigation - require all time claims to be present
   // and correctly typed. Without this, a string-typed "exp" bypasses time validation.
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.expose_secret().as_bytes()),
        &validation,
    )
    .map_err(|e| {
        debug!("Token verifyfailed: {}", e);
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        }
    })?;

   // SEC: Validate token version - password change increments version, invalidating old tokens
    let current_tv = config
        .token_version
        .load(std::sync::atomic::Ordering::Relaxed);
    if token_data.claims.tv < current_tv {
        debug!(
            token_tv = token_data.claims.tv,
            current_tv, "Token version 过期 (密码已变更)"
        );
        return Err(AuthError::TokenExpired);
    }

    Ok(token_data.claims)
}
