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
    /// Token version of the issuing USER at sign time (SEC M-1: CWE-613).
    /// `require_auth` rejects the token once this value is lower than the
    /// user's current `platform_users.token_version`.
    #[serde(default)]
    pub tv: u64,
}

/// JWT Token
///
/// `token_version` is the issuing user's per-user version (SEC M-1); callers
/// read it from the freshly loaded platform-user row.
pub fn generate_token(
    config: &AuthConfig,
    username: &str,
    role: &str,
    token_version: u64,
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
        tv: token_version,
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
///
/// Cryptographic and temporal validation only.  Revocation (CWE-613, SEC M-1)
/// is enforced by `require_auth` against the per-user
/// `platform_users.token_version` after the identity lookup — a global
/// counter here would let one user's logout invalidate every operator.
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

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::{generate_token, verify_token};
    use crate::auth::AuthConfig;

    const TEST_ADMIN_PASSWORD: &str = "TestAdmin!2345";

    #[test]
    fn test_token_carries_per_user_version_and_verifies() {
        // SEC M-1: `tv` is the issuing user's row version; verify_token is
        // cryptographic only — revocation is enforced in require_auth
        // against the live platform row (see middleware tests).
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let token = generate_token(&config, "alice", "admin", 7).expect("token");
        let claims = verify_token(&config, &token).expect("valid token");
        assert_eq!(claims.tv, 7);
        assert_eq!(claims.sub, "alice");
    }

    #[test]
    fn per_user_versions_are_independent() {
        // PoC (M-1): one user's revocation must not invalidate another
        // user's token. Alice's row bumps to 8; Bob's token (tv unchanged)
        // still verifies, and a fresh Alice token at the new version
        // verifies while her pre-bump token fails the per-user comparison.
        let config = AuthConfig::test_config(TEST_ADMIN_PASSWORD);
        let alice_old = generate_token(&config, "alice", "admin", 7).expect("token");
        let bob = generate_token(&config, "bob", "viewer", 3).expect("token");

        let alice_row_tv: u64 = 8; // bumped by alice's logout
        let bob_row_tv: u64 = 3; // untouched

        let alice_old_claims = verify_token(&config, &alice_old).expect("crypto valid");
        let bob_claims = verify_token(&config, &bob).expect("crypto valid");

        assert!(alice_old_claims.tv < alice_row_tv, "alice's old token revoked");
        assert!(bob_claims.tv >= bob_row_tv, "bob unaffected by alice's logout");

        let alice_new = generate_token(&config, "alice", "admin", alice_row_tv).expect("token");
        let alice_new_claims = verify_token(&config, &alice_new).expect("crypto valid");
        assert!(alice_new_claims.tv >= alice_row_tv);
    }
}
