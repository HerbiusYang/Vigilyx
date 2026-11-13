//! Additive carrier recovery remains independently switchable during evaluation.

pub(crate) fn stage_b_enabled() -> bool {
    std::env::var("VIGILYX_EMAIL_ATTACK_HARDENING_STAGE_B").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "enabled"
        )
    })
}
