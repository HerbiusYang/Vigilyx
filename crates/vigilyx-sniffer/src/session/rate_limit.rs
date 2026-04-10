//! IP rate limiter (lock-free design)

//! Each IP has an independent cache-line-aligned entry using CAS for lock-free window reset.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Max concurrent sessions per IP.
/// The sniffer is a passive packet analyzer - it must NOT reject legitimate traffic.
/// This limit only serves as memory protection against extreme anomalies
/// (e.g., port scan attacks generating millions of fake sessions).
/// Internal mail servers / load balancers can produce thousands of concurrent
/// connections from a single IP, so the threshold must be generous.
pub(super) const MAX_SESSIONS_PER_IP: usize = 50_000;

/// Rate limit window (seconds)
pub(super) const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Max new sessions per IP per minute.
/// Same rationale - only guards against extreme anomalies.
/// Normal mail servers can reach thousands of new connections per minute at peak.
pub(super) const MAX_NEW_SESSIONS_PER_IP_PER_MINUTE: u64 = 10_000;

/// IP rate limit entry (cache-line aligned)
#[repr(C, align(64))]
pub(crate) struct IpRateLimitEntry {
    /// New session count
    pub new_session_count: AtomicU64,
    /// Active session count
    pub active_session_count: AtomicU64,
    /// Window start time (stored in nanoseconds)
    pub(super) window_start_ns: AtomicU64,
    _pad: [u8; 40],
}

impl IpRateLimitEntry {
    pub fn new() -> Self {
        Self {
            new_session_count: AtomicU64::new(1),
            active_session_count: AtomicU64::new(1),
            window_start_ns: AtomicU64::new(Self::now_ns()),
            _pad: [0; 40],
        }
    }

    #[inline(always)]
    pub fn now_ns() -> u64 {
        // Use Instant converted to nanoseconds
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_nanos() as u64
    }

    /// Check if this IP should be rate limited (returns true to reject)
    #[inline(always)]
    pub fn should_limit(&self) -> bool {
        let active = self.active_session_count.load(Ordering::Relaxed);
        let new_count = self.new_session_count.load(Ordering::Relaxed);

        // Check active session count limit
        if active >= MAX_SESSIONS_PER_IP as u64 {
            return true;
        }

        // Check rate limit
        if new_count >= MAX_NEW_SESSIONS_PER_IP_PER_MINUTE {
            return true;
        }

        false
    }

    /// Check and reset window (if expired) - lock-free design
    #[inline(always)]
    pub fn check_and_maybe_reset(&self) -> bool {
        let now = Self::now_ns();
        let window_start = self.window_start_ns.load(Ordering::Relaxed);
        let elapsed_secs = (now.saturating_sub(window_start)) / 1_000_000_000;

        if elapsed_secs >= RATE_LIMIT_WINDOW_SECS {
            // CAS attempt to reset window - only one thread wins the race
            if self
                .window_start_ns
                .compare_exchange(window_start, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // NOTE: There is a tiny race window between CAS success and swap(0):
                // Concurrent threads may have executed fetch_add(1) during this window,
                // which will be zeroed by swap.
                // This is acceptable for rate limiting - at most 1-2 counts may be lost,
                // which won't affect security (only makes limit slightly looser momentarily).
                // Using swap(0) instead of store(0) ensures read and clear are atomic,
                // avoiding ABA problems (store could overwrite values just written by other threads).
                let _old_new = self.new_session_count.swap(0, Ordering::Relaxed);
                // SEC: Do NOT reset active_session_count here - it tracks long-lived sessions
                // and must only decrement when sessions actually close. Resetting it every 60s
                // allowed attackers to batch long-lived connections across windows to exhaust
                // MAX_SESSIONS. Active count is decremented in session_closed().

                return true;
            }
        }

        false
    }
}
