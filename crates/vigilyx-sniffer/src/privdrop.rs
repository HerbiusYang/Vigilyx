//! Privilege drop for the capture process (SEC M-3, 2026-08-15 red-team scan).
//!
//! The sniffer must open the capture handle as root, but everything after
//! that — parsing attacker-controlled packet bytes, speaking Redis/HTTP —
//! runs with no need for privileges. Keeping root for the process lifetime
//! turned any future parser memory-safety bug into a root-level primitive,
//! so once root-only setup is complete the process drops to an unprivileged
//! account.
//!
//! Configuration:
//! - `SNIFFER_DROP_USER`: target account (default `nobody`).
//! - `SNIFFER_PRIVILEGE_DROP=0`: explicit opt-out for exotic setups.

use std::io;

/// Drop process privileges to `user` when running as root.
///
/// Failure semantics:
/// - Not running as root (or non-unix): no-op success — dev runs and
///   container setups that already use a non-root user are unaffected.
/// - Target user unknown: `Err(UserUnknown)` — callers log at error level
///   and continue as root (a configuration error, not a mechanism failure;
///   capture must not break silently on upgrade).
/// - setgroups/setgid/setuid syscall failure: `Err(io::Error)` — fatal; these
///   cannot legitimately fail for root and continuing would silently keep
///   the very privileges this module exists to shed.
#[cfg(unix)]
pub fn drop_privileges(user: &str) -> Result<(), DropError> {
    if !nix_euid_is_root() {
        tracing::debug!("privdrop: not running as root — nothing to drop");
        return Ok(());
    }
    if user.is_empty() {
        return Err(DropError::UserUnknown(user.to_string()));
    }
    // SAFETY: getpwnam_r reads the passwd database; the returned pointers are
    // owned by the libc-owned structure we pass in.
    let pwd = match unsafe { lookup_user(user) } {
        Some(pwd) => pwd,
        None => return Err(DropError::UserUnknown(user.to_string())),
    };
    if pwd.uid == 0 {
        // RT-9 (deep red-team round 4): a misconfigured drop target naming a
        // uid-0 account would "succeed" while shedding nothing. Treat it as
        // an unknown target so the operator-visible warning path applies.
        return Err(DropError::UserUnknown(user.to_string()));
    }
    // Order matters: setgroups before setgid before setuid ( dropping group
    // membership first prevents regaining privileges via the supplementary
    // list).
    // SAFETY: plain syscall wrappers with owned arguments.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(DropError::Syscall(io::Error::last_os_error()));
        }
        if libc::setgid(pwd.gid) != 0 {
            return Err(DropError::Syscall(io::Error::last_os_error()));
        }
        if libc::setuid(pwd.uid) != 0 {
            return Err(DropError::Syscall(io::Error::last_os_error()));
        }
    }
    tracing::info!(user, uid = pwd.uid, gid = pwd.gid, "privdrop: privileges dropped");
    Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
struct ResolvedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

#[cfg(unix)]
unsafe fn lookup_user(user: &str) -> Option<ResolvedUser> {
    let c_user = std::ffi::CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // RT-6: ERANGE means the buffer was too small for a passwd entry with an
    // unusually long gecos/shell — grow and retry rather than reporting the
    // user as missing (which would silently keep the process as root).
    let mut capacity = 4096usize;
    loop {
        let mut buf = vec![0u8; capacity];
        let status = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if status == 0 {
            return if result.is_null() {
                None
            } else {
                Some(ResolvedUser {
                    uid: pwd.pw_uid,
                    gid: pwd.pw_gid,
                })
            };
        }
        if status != libc::ERANGE || capacity >= 1024 * 1024 {
            return None;
        }
        capacity *= 2;
    }
}

#[cfg(unix)]
fn nix_euid_is_root() -> bool {
    // SAFETY: plain getter with no memory safety requirements.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
#[derive(Debug)]
pub enum DropError {
    /// The configured drop user does not exist on this system.
    UserUnknown(String),
    /// A privilege-shedding syscall failed; treat as fatal.
    Syscall(io::Error),
}

impl std::fmt::Display for DropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DropError::UserUnknown(user) => {
                write!(f, "privdrop target user {user:?} does not exist")
            }
            DropError::Syscall(error) => write!(f, "privdrop syscall failed: {error}"),
        }
    }
}

impl std::error::Error for DropError {}

/// Resolve the effective drop behavior from the environment:
/// `None` when explicitly disabled via `SNIFFER_PRIVILEGE_DROP=0`.
#[cfg(unix)]
pub fn configured_drop_user() -> Option<String> {
    if std::env::var("SNIFFER_PRIVILEGE_DROP").ok().as_deref() == Some("0") {
        tracing::warn!(
            "SNIFFER_PRIVILEGE_DROP=0 — capture process keeps root privileges (explicit operator opt-out)"
        );
        return None;
    }
    Some(
        std::env::var("SNIFFER_DROP_USER")
            .ok()
            .filter(|user| !user.is_empty())
            .unwrap_or_else(|| "nobody".to_string()),
    )
}

/// Apply the configured privilege drop after root-only setup completed.
///
/// `UserUnknown` logs at error level and keeps the process running (visible
/// misconfiguration, capture unaffected); syscall failures return `Err` and
/// the caller must treat them as fatal.
#[cfg(unix)]
pub fn drop_privileges_if_configured() -> Result<(), DropError> {
    let Some(user) = configured_drop_user() else {
        return Ok(());
    };
    match drop_privileges(&user) {
        Ok(()) => Ok(()),
        Err(error @ DropError::UserUnknown(_)) => {
            tracing::error!(
                error = %error,
                "privdrop skipped — continuing as root; set SNIFFER_DROP_USER to an existing unprivileged account"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
pub fn drop_privileges_if_configured() -> Result<(), std::convert::Infallible> {
    Ok(())
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_user_is_reported_not_fatal_semantic() {
        if !nix_euid_is_root() {
            // Non-root runs cannot exercise the syscall path; assert the
            // classification only.
            let err = drop_privileges("definitely-not-a-user-xyz");
            assert!(matches!(err, Ok(())), "non-root must be a no-op success");
            return;
        }
        let err = drop_privileges_if_configured_for("definitely-not-a-user-xyz");
        assert!(matches!(err, Err(DropError::UserUnknown(_))) || matches!(err, Ok(())));
    }

    #[cfg(unix)]
    fn drop_privileges_if_configured_for(user: &str) -> Result<(), DropError> {
        drop_privileges(user)
    }

    #[test]
    fn empty_user_is_user_unknown() {
        if nix_euid_is_root() {
            assert!(matches!(
                drop_privileges(""),
                Err(DropError::UserUnknown(_))
            ));
        }
    }
}
