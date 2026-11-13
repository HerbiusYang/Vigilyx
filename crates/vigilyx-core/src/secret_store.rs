//! Application configuration-secret envelope encryption.
//!
//! JWT signing and stored-secret encryption are separate trust domains. A JWT
//! rotation must not destroy SMTP, webhook, intelligence, or AI credentials,
//! and a worker that consumes those credentials must not receive the JWT key.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use sha2::{Digest, Sha256};

pub const CONFIG_ENCRYPTION_KEY_ENV: &str = "VIGILYX_CONFIG_ENCRYPTION_KEY";
pub const CONFIG_SECRET_PREFIX: &str = "ENC:v2:";
const LEGACY_CONFIG_SECRET_PREFIX: &str = "ENC:";
const CONFIG_SECRET_AAD: &[u8] = b"vigilyx-config-secret-v2";
const MIN_MASTER_KEY_BYTES: usize = 32;

fn configured_master_key() -> Result<String, String> {
    let key = std::env::var(CONFIG_ENCRYPTION_KEY_ENV)
        .map_err(|_| format!("{CONFIG_ENCRYPTION_KEY_ENV} is not set"))?;
    if key.len() < MIN_MASTER_KEY_BYTES {
        return Err(format!(
            "{CONFIG_ENCRYPTION_KEY_ENV} must contain at least {MIN_MASTER_KEY_BYTES} bytes"
        ));
    }
    if std::env::var("API_JWT_SECRET").as_deref() == Ok(key.as_str()) {
        return Err(format!(
            "{CONFIG_ENCRYPTION_KEY_ENV} must differ from API_JWT_SECRET"
        ));
    }
    Ok(key)
}

fn derive_key(domain: &[u8], master_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(master_key.as_bytes());
    hasher.finalize().into()
}

fn encrypt_with_master_key(plaintext: &str, master_key: &str) -> Result<String, String> {
    let key = derive_key(CONFIG_SECRET_AAD, master_key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher init failed".to_string())?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|_| "secure random generation failed".to_string())?;
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| "invalid nonce".to_string())?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: CONFIG_SECRET_AAD,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    let mut envelope = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!(
        "{CONFIG_SECRET_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(envelope)
    ))
}

fn decrypt_v2_with_master_key(stored: &str, master_key: &str) -> Result<String, String> {
    let encoded = stored
        .strip_prefix(CONFIG_SECRET_PREFIX)
        .ok_or_else(|| "unsupported encrypted configuration format".to_string())?;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid encrypted configuration encoding".to_string())?;
    if envelope.len() < 12 + 16 {
        return Err("encrypted configuration value is too short".to_string());
    }
    let key = derive_key(CONFIG_SECRET_AAD, master_key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher init failed".to_string())?;
    let nonce = Nonce::try_from(&envelope[..12]).map_err(|_| "invalid nonce".to_string())?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope[12..],
                aad: CONFIG_SECRET_AAD,
            },
        )
        .map_err(|_| "decryption failed (wrong key or tampered value)".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "decrypted configuration is not UTF-8".to_string())
}

fn decrypt_legacy_with_jwt(stored: &str, jwt_secret: &str) -> Result<String, String> {
    let encoded = stored
        .strip_prefix(LEGACY_CONFIG_SECRET_PREFIX)
        .ok_or_else(|| "not a legacy encrypted value".to_string())?;
    if stored.starts_with(CONFIG_SECRET_PREFIX) {
        return Err("not a legacy encrypted value".to_string());
    }
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid legacy encrypted configuration encoding".to_string())?;
    if envelope.len() < 12 + 16 {
        return Err("legacy encrypted configuration value is too short".to_string());
    }
    let key = derive_key(b"vigilyx-config-encryption-v1", jwt_secret);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher init failed".to_string())?;
    let nonce = Nonce::try_from(&envelope[..12]).map_err(|_| "invalid nonce".to_string())?;
    let plaintext = cipher
        .decrypt(&nonce, &envelope[12..])
        .map_err(|_| "legacy decryption failed (wrong key or tampered value)".to_string())?;
    String::from_utf8(plaintext)
        .map_err(|_| "legacy decrypted configuration is not UTF-8".to_string())
}

/// Fail startup early when a service may consume encrypted configuration.
pub fn validate_config_encryption_key() -> Result<(), String> {
    configured_master_key().map(|_| ())
}

/// Encrypt a plaintext configuration secret using the dedicated master key.
pub fn encrypt_config_secret(plaintext: &str) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    encrypt_with_master_key(plaintext, &configured_master_key()?)
}

/// Decrypt a v2 secret. Plaintext is returned unchanged for compatibility
/// with non-sensitive fields; legacy ENC values are rejected explicitly.
pub fn decrypt_config_secret(stored: &str) -> Result<String, String> {
    if stored.is_empty() || !stored.starts_with(LEGACY_CONFIG_SECRET_PREFIX) {
        return Ok(stored.to_string());
    }
    decrypt_v2_with_master_key(stored, &configured_master_key()?)
}

/// API-only rolling-upgrade reader. The JWT is accepted solely to read a v1
/// value so it can be re-encrypted as v2; workers must use
/// [`decrypt_config_secret`] and never receive the JWT signing key.
pub fn decrypt_config_secret_with_legacy(
    stored: &str,
    legacy_jwt_secret: &str,
) -> Result<String, String> {
    if stored.starts_with(CONFIG_SECRET_PREFIX) {
        decrypt_config_secret(stored)
    } else if stored.starts_with(LEGACY_CONFIG_SECRET_PREFIX) {
        decrypt_legacy_with_jwt(stored, legacy_jwt_secret)
    } else {
        Ok(stored.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MASTER_KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn v2_round_trip_is_randomized_and_authenticated() {
        let first = encrypt_with_master_key("smtp-password", TEST_MASTER_KEY).unwrap();
        let second = encrypt_with_master_key("smtp-password", TEST_MASTER_KEY).unwrap();
        assert!(first.starts_with(CONFIG_SECRET_PREFIX));
        assert_ne!(first, second);
        assert_eq!(
            decrypt_v2_with_master_key(&first, TEST_MASTER_KEY).unwrap(),
            "smtp-password"
        );

        let mut tampered = first.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(decrypt_v2_with_master_key(&tampered, TEST_MASTER_KEY).is_err());
    }

    #[test]
    fn wrong_master_key_cannot_decrypt() {
        let encrypted = encrypt_with_master_key("secret", TEST_MASTER_KEY).unwrap();
        assert!(
            decrypt_v2_with_master_key(&encrypted, "fedcba9876543210fedcba9876543210").is_err()
        );
    }
}
