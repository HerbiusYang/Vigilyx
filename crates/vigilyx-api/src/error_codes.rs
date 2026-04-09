//! API error
#![allow(dead_code)] // API, handler

//! client `error_code` field Processerror, errormessage.


//! - `AUTH_xxx`: authentication authorizationerror
//! - `VAL_xxx`: requestverifyerror (format, parameter, field)
//! - `RES_xxx`: Source error (,)
//! - `INT_xxx`: internal service errors (data, engine, external service)

// authentication authorization

/// user Passworderror
pub const AUTH_INVALID_CREDENTIALS: &str = "AUTH_001";

/// Token
pub const AUTH_TOKEN_EXPIRED: &str = "AUTH_002";

/// Login Stream (time failed)
pub const AUTH_RATE_LIMITED: &str = "AUTH_003";

/// Request authentication Token
pub const AUTH_MISSING_TOKEN: &str = "AUTH_004";

/// Token format Verifyfailed
pub const AUTH_INVALID_TOKEN: &str = "AUTH_005";

/// Must change default password first (SEC: CWE-620)
pub const AUTH_PASSWORD_CHANGE_REQUIRED: &str = "AUTH_006";

// requestverify

/// ID format (Such as UUID Parsefailed)
pub const VALIDATION_INVALID_ID: &str = "VAL_001";

/// Requestparameter (Type/ /format)
pub const VALIDATION_INVALID_PARAMS: &str = "VAL_002";

/// field
pub const VALIDATION_MISSING_FIELD: &str = "VAL_003";

// Source

/// target Source
pub const RESOURCE_NOT_FOUND: &str = "RES_001";

/// Source (Such as Create)
pub const RESOURCE_CONFLICT: &str = "RES_002";

// internalerror

/// Data Operation failed
pub const INTERNAL_DATABASE_ERROR: &str = "INT_001";

/// EngineProcessfailed
pub const INTERNAL_ENGINE_ERROR: &str = "INT_002";

/// Service
pub const INTERNAL_SERVICE_UNAVAILABLE: &str = "INT_003";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_are_unique() {
        let codes = [
            AUTH_INVALID_CREDENTIALS,
            AUTH_TOKEN_EXPIRED,
            AUTH_RATE_LIMITED,
            AUTH_MISSING_TOKEN,
            AUTH_INVALID_TOKEN,
            AUTH_PASSWORD_CHANGE_REQUIRED,
            VALIDATION_INVALID_ID,
            VALIDATION_INVALID_PARAMS,
            VALIDATION_MISSING_FIELD,
            RESOURCE_NOT_FOUND,
            RESOURCE_CONFLICT,
            INTERNAL_DATABASE_ERROR,
            INTERNAL_ENGINE_ERROR,
            INTERNAL_SERVICE_UNAVAILABLE,
        ];
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(*code), "Duplicate error code: {}", code);
        }
    }

    #[test]
    fn test_error_codes_follow_naming_convention() {
       // AUTH codes start with "AUTH_"
        assert!(AUTH_INVALID_CREDENTIALS.starts_with("AUTH_"));
        assert!(AUTH_TOKEN_EXPIRED.starts_with("AUTH_"));
        assert!(AUTH_RATE_LIMITED.starts_with("AUTH_"));
        assert!(AUTH_MISSING_TOKEN.starts_with("AUTH_"));
        assert!(AUTH_INVALID_TOKEN.starts_with("AUTH_"));
        assert!(AUTH_PASSWORD_CHANGE_REQUIRED.starts_with("AUTH_"));

       // VAL codes start with "VAL_"
        assert!(VALIDATION_INVALID_ID.starts_with("VAL_"));
        assert!(VALIDATION_INVALID_PARAMS.starts_with("VAL_"));
        assert!(VALIDATION_MISSING_FIELD.starts_with("VAL_"));

       // RES codes start with "RES_"
        assert!(RESOURCE_NOT_FOUND.starts_with("RES_"));
        assert!(RESOURCE_CONFLICT.starts_with("RES_"));

       // INT codes start with "INT_"
        assert!(INTERNAL_DATABASE_ERROR.starts_with("INT_"));
        assert!(INTERNAL_ENGINE_ERROR.starts_with("INT_"));
        assert!(INTERNAL_SERVICE_UNAVAILABLE.starts_with("INT_"));
    }
}
