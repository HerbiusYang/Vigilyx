//! Per-IP login rate limiter

//! Tracks failed login attempts per IP address using a lock-free `DashMap`.
//! Each IP has an independent failure counter and time window - one attacker
//! cannot lock out all users (the flaw in the old global `AtomicU32` design).

//! ## Design

//! - `DashMap<IpAddr, (u32, u64)>` - (failure_count, window_start_epoch_secs)
//! - Window auto-resets: if the entry's window has expired, the counter is reset
//! on the next access (no background timer needed for correctness).
//! - `cleanup()` sweeps stale entries to bound memory; call it periodically.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Per-IP login failure tracker.
pub struct LoginRateLimiter {
    /// IP -> (failure_count, window_start_epoch_secs)
    failures: DashMap<IpAddr, (u32, u64)>,
    /// Maximum allowed failures within one window before blocking.
    pub max_failures: u32,
    /// Window duration in seconds. After expiry the counter resets.
    pub window_secs: u64,
}

impl LoginRateLimiter {
    /// Create a new rate limiter.

    /// - `max_failures`: block the IP after this many failures within the window
    /// - `window_secs`: sliding window duration in seconds
    pub fn new(max_failures: u32, window_secs: u64) -> Self {
        Self {
            failures: DashMap::new(),
            max_failures,
            window_secs,
        }
    }

    /// Current epoch seconds (helper).
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Peek at the current failure state for an IP without modifying it.

    /// Returns `Some((count, window_start))` if the IP has recorded failures,
    /// `None` if the IP has no entry. Used to pre-check whether an IP is blocked
    /// before doing expensive credential verification.

    /// Note: does NOT reset expired windows (read-only peek). The caller should
    /// compare `window_start` with current time if staleness matters, but for a
    /// simple "are they over the limit?" pre-check this is sufficient because
    /// `check_and_record_failure` will handle the window reset on the next write.
    pub fn peek(&self, ip: &IpAddr) -> Option<(u32, u64)> {
        let now = Self::now_secs();
        self.failures.get(ip).and_then(|entry| {
            let (count, window_start) = *entry.value();
            // If the window has expired, report as if no entry exists.
            if now.saturating_sub(window_start) >= self.window_secs {
                None
            } else {
                Some((count, window_start))
            }
        })
    }

    /// Check whether `ip` is currently rate-limited, and record one more failure.

    /// Returns `true` if the IP is **blocked** (failure count>= max_failures).
    /// The caller should reject the request when this returns `true`.

    /// If the previous window has expired the counter is transparently reset
    /// before recording the new failure.
    pub fn check_and_record_failure(&self, ip: IpAddr) -> bool {
        let now = Self::now_secs();

        let mut entry = self.failures.entry(ip).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        // Reset if the window has expired.
        if now.saturating_sub(*window_start) >= self.window_secs {
            *count = 0;
            *window_start = now;
        }

        // Already at/over the limit - blocked.
        if *count >= self.max_failures {
            warn!(
                ip = %ip,
                failures = *count,
                window_secs = self.window_secs,
                "Per-IP login rate limit triggered"
            );
            return true;
        }

        // Record the failure.
        *count = count.saturating_add(1);

        // Return whether the IP is now blocked (just hit the limit).
        if *count >= self.max_failures {
            warn!(
                ip = %ip,
                failures = *count,
                window_secs = self.window_secs,
                "Per-IP login rate limit triggered"
            );
            true
        } else {
            false
        }
    }

    /// Reset the failure counter for `ip` (call on successful login).
    pub fn reset(&self, ip: IpAddr) {
        self.failures.remove(&ip);
    }

    pub fn clear_all(&self) {
        self.failures.clear();
    }

    /// Remove all entries whose window has expired.

    /// Call this periodically (e.g. every 5 minutes) to bound memory.
    /// Skipping cleanup is safe - expired entries are also lazily reset
    /// on next access - but stale keys would accumulate.
    pub fn cleanup(&self) {
        let now = Self::now_secs();
        self.failures
            .retain(|_ip, (_, window_start)| now.saturating_sub(*window_start) < self.window_secs);
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper: deterministic IP addresses for tests.
    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    #[test]
    fn test_allows_under_limit() {
        let limiter = LoginRateLimiter::new(5, 60);
        let addr = ip(1);

        // 4 failures - all should be allowed (not blocked).
        for _ in 0..4 {
            assert!(!limiter.check_and_record_failure(addr));
        }
    }

    #[test]
    fn test_blocks_at_limit() {
        let limiter = LoginRateLimiter::new(5, 60);
        let addr = ip(2);

        // First 4 failures: allowed.
        for _ in 0..4 {
            assert!(!limiter.check_and_record_failure(addr));
        }
        // 5th failure: now blocked.
        assert!(limiter.check_and_record_failure(addr));
        // Subsequent attempts: still blocked.
        assert!(limiter.check_and_record_failure(addr));
    }

    #[test]
    fn test_window_reset() {
        // Window of 0 seconds: every call is in a "new" window.
        let limiter = LoginRateLimiter::new(5, 0);
        let addr = ip(3);

        // Even though we record 10 failures, each one resets the window
        // because 0-second window has always expired by the next call.
        for _ in 0..10 {
            // The counter resets each time because window expired (0 secs).
            assert!(!limiter.check_and_record_failure(addr));
        }
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = LoginRateLimiter::new(3, 60);
        let attacker = ip(10);
        let innocent = ip(20);

        // Attacker hits the limit.
        for _ in 0..3 {
            limiter.check_and_record_failure(attacker);
        }
        assert!(limiter.check_and_record_failure(attacker));

        // Innocent user is completely unaffected.
        assert!(!limiter.check_and_record_failure(innocent));
    }

    #[test]
    fn test_reset_clears_ip() {
        let limiter = LoginRateLimiter::new(3, 60);
        let addr = ip(4);

        // Accumulate 2 failures.
        limiter.check_and_record_failure(addr);
        limiter.check_and_record_failure(addr);

        // Successful login resets.
        limiter.reset(addr);

        // Counter is back to 0 - 3 more failures before block.
        for _ in 0..2 {
            assert!(!limiter.check_and_record_failure(addr));
        }
        // 3rd failure: blocked.
        assert!(limiter.check_and_record_failure(addr));
    }

    #[test]
    fn test_cleanup_removes_expired() {
        // Window = 0 -> everything is immediately expired.
        let limiter = LoginRateLimiter::new(5, 0);
        let a = ip(50);
        let b = ip(51);
        limiter.check_and_record_failure(a);
        limiter.check_and_record_failure(b);

        // Both entries exist.
        assert_eq!(limiter.failures.len(), 2);

        // Cleanup should remove them (window=0 -> expired).
        limiter.cleanup();
        assert_eq!(limiter.failures.len(), 0);
    }

    #[test]
    fn test_cleanup_preserves_active() {
        // Window = 3600 seconds - entries will NOT be expired.
        let limiter = LoginRateLimiter::new(5, 3600);
        let addr = ip(60);
        limiter.check_and_record_failure(addr);

        limiter.cleanup();
        assert_eq!(limiter.failures.len(), 1);
    }

    #[test]
    fn test_ipv6_support() {
        let limiter = LoginRateLimiter::new(3, 60);
        let v6: IpAddr = "::1".parse().expect("valid IPv6");

        for _ in 0..2 {
            assert!(!limiter.check_and_record_failure(v6));
        }
        assert!(limiter.check_and_record_failure(v6));
    }
}
