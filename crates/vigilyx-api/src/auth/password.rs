//! Argon2 Password verify

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use super::AuthError;

/// HashPassword
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::InternalError(format!("Password哈希failed: {}", e)))?;
    Ok(hash.to_string())
}

/// verifyPassword
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AuthError::InternalError(format!("无效Password哈希: {}", e)))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Run a fixed-cost verification against a dummy Argon2 hash to reduce
/// username-existence timing differences on failed logins.
pub(crate) fn verify_password_dummy(password: &str) -> Result<(), AuthError> {
    static DUMMY_PASSWORD_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let salt =
            SaltString::encode_b64(b"vigilyx-dummy-salt").expect("dummy salt should be valid");
        Argon2::default()
            .hash_password(b"vigilyx-dummy-password", &salt)
            .expect("dummy password hash should be valid")
            .to_string()
    });

    let _ = verify_password(password, DUMMY_PASSWORD_HASH.as_str())?;
    Ok(())
}
