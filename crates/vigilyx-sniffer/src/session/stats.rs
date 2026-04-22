//! Cache-line-aligned session statistics structures.
//!
//! Avoids multi-thread false sharing by placing each independent counter in its
//! own 64-byte cache line.  When multiple worker threads increment different
//! counters in the same struct, each counter sitting in its own cache line
//! prevents costly MESI E→I invalidation storms across cores.

use std::sync::atomic::AtomicU64;

// ─── Cache-line-isolated atomic counter ────────────────────────────────────

/// Atomic counter occupying a full 64-byte cache line to prevent false sharing.
///
/// `Deref<Target = AtomicU64>` makes this a drop-in replacement for bare
/// `AtomicU64` — callers continue to use `.fetch_add()`, `.load()`, `.store()`
/// without any API change.
#[repr(C, align(64))]
pub struct CacheLineCounter {
    value: AtomicU64,
    _pad: [u8; 56],
}

impl CacheLineCounter {
    pub const fn new(val: u64) -> Self {
        Self {
            value: AtomicU64::new(val),
            _pad: [0; 56],
        }
    }
}

impl Default for CacheLineCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::ops::Deref for CacheLineCounter {
    type Target = AtomicU64;
    #[inline(always)]
    fn deref(&self) -> &AtomicU64 {
        &self.value
    }
}

// ─── Session-level statistics (unchanged, already cache-line-aligned) ──────

/// Session statistics (each counter occupies its own cache line)
#[repr(C, align(64))]
pub struct SessionStats {
    pub total_sessions: AtomicU64,
    _pad1: [u8; 56],
}

#[repr(C, align(64))]
pub struct SessionStatsActive {
    pub active_sessions: AtomicU64,
    _pad2: [u8; 56],
}

#[repr(C, align(64))]
pub struct SessionStatspackets {
    pub total_packets: AtomicU64,
    _pad3: [u8; 56],
}

#[repr(C, align(64))]
pub struct SessionStatsBytes {
    pub total_bytes: AtomicU64,
    _pad4: [u8; 56],
}

#[repr(C, align(64))]
pub struct SessionStatsProtocol {
    pub smtp_sessions: AtomicU64,
    pub pop3_sessions: AtomicU64,
    pub imap_sessions: AtomicU64,
    _pad5: [u8; 40],
}

// ─── HTTP pipeline statistics (cache-line-isolated per counter) ────────────

/// HTTP data security pipeline statistics (full-link packet loss tracking).
///
/// Used in 100% mirror traffic restoration scenarios, tracking HTTP sessions
/// from packet capture to engine ingestion.
///
/// Each counter occupies its own 64-byte cache line because multiple worker
/// threads increment different counters concurrently.
#[derive(Default)]
pub struct HttpPipelineStats {
    /// Total HTTP protocol packets (packets entering process_packet where protocol==Http)
    pub http_packets_total: CacheLineCounter,
    /// Outbound packets entering parse_http_data_security
    pub http_packets_outbound: CacheLineCounter,
    /// packets dropped due to TCP stream buffer overflow
    pub http_stream_overflow: CacheLineCounter,
    /// Complete requests successfully split by HTTP state machine (all methods included)
    pub http_requests_parsed: CacheLineCounter,
    /// Requests skipped due to non-POST/PUT methods
    pub http_requests_skipped_method: CacheLineCounter,
    /// HttpSessions successfully constructed and queued
    pub http_sessions_queued: CacheLineCounter,
    /// HttpSessions dropped due to full queue
    pub http_sessions_dropped_queue_full: CacheLineCounter,
    /// HttpSessions successfully published to MQ/HTTP
    pub http_sessions_published: CacheLineCounter,
    /// HTTP TCP connection (session) creation count
    pub http_connections_created: CacheLineCounter,
    /// HTTP packets rejected due to missing TCP SYN
    pub http_rejected_no_syn: CacheLineCounter,
}

// ─── SMTP pipeline statistics (cache-line-isolated per counter) ────────────

/// SMTP restoration pipeline statistics.
///
/// These counters make it easy to tell whether mirrored SMTP traffic is being
/// fully restored, partially restored, or lost due to gaps / parser failures.
///
/// Each counter occupies its own 64-byte cache line to prevent false sharing
/// between worker threads that update different counters concurrently.
#[derive(Default)]
pub struct SmtpPipelineStats {
    /// Fully restored non-encrypted SMTP emails.
    pub smtp_restored_ok: CacheLineCounter,
    /// Restored SMTP emails with TCP gaps (marked incomplete).
    pub smtp_restored_with_gaps: CacheLineCounter,
    /// MIME parsing failed after DATA termination.
    pub smtp_mime_parse_failed: CacheLineCounter,
    /// client->server TCP gap detections.
    pub smtp_client_gap_events: CacheLineCounter,
    /// Sum of client->server gap bytes.
    pub smtp_client_gap_bytes_total: CacheLineCounter,
    /// server->client TCP gap detections.
    pub smtp_server_gap_events: CacheLineCounter,
    /// Sum of server->client gap bytes.
    pub smtp_server_gap_bytes_total: CacheLineCounter,
    /// SMTP sessions that started without an observed SYN.
    pub smtp_sessions_created_without_syn: CacheLineCounter,
    /// Same SMTP session observed on multiple workers.
    pub smtp_worker_mismatch_events: CacheLineCounter,
    /// Late prepend events on client->server stream.
    pub smtp_client_late_prepend_events: CacheLineCounter,
    /// Sum of prepended bytes on client->server stream.
    pub smtp_client_late_prepend_bytes_total: CacheLineCounter,
    /// Late prepend events on server->client stream.
    pub smtp_server_late_prepend_events: CacheLineCounter,
    /// Sum of prepended bytes on server->client stream.
    pub smtp_server_late_prepend_bytes_total: CacheLineCounter,
    /// client stream overflow events.
    pub smtp_client_stream_overflow: CacheLineCounter,
    /// server stream overflow events.
    pub smtp_server_stream_overflow: CacheLineCounter,
    /// Total SMTP sessions that hit the session timeout path.
    pub smtp_timeout_sessions_total: CacheLineCounter,
    /// SMTP sessions forced through the shorter pending-DATA idle timeout.
    pub smtp_pending_idle_timeout_sessions: CacheLineCounter,
    /// Plaintext SMTP sessions closed by TCP without restored payload.
    pub smtp_plaintext_tcp_close_without_restore: CacheLineCounter,
    /// Plaintext SMTP sessions timed out without restored payload.
    pub smtp_plaintext_timeout_without_restore: CacheLineCounter,
    /// Plaintext SMTP sessions that reached DATA but closed before any payload arrived.
    pub smtp_plaintext_aborted_before_payload: CacheLineCounter,
    /// Plaintext SMTP sessions not restored because stream gaps made payload incomplete.
    pub smtp_plaintext_without_restore_stream_gap: CacheLineCounter,
    /// Plaintext SMTP sessions not restored because payload truncated before terminator.
    pub smtp_plaintext_without_restore_truncated: CacheLineCounter,
    /// Plaintext SMTP sessions not restored because DATA state stayed pending or 354 never aligned.
    pub smtp_plaintext_without_restore_missing_354: CacheLineCounter,
    /// Plaintext SMTP sessions not restored because MIME parse failed or payload stayed empty.
    pub smtp_plaintext_without_restore_mime_or_empty: CacheLineCounter,
    /// Close-path salvage restored only partial headers/body.
    pub smtp_close_salvage_partial: CacheLineCounter,
}

/// Complete cache-line-aligned statistics
pub struct AlignedSessionStats {
    pub total: SessionStats,
    pub active: SessionStatsActive,
    pub packets: SessionStatspackets,
    pub bytes: SessionStatsBytes,
    pub protocol: SessionStatsProtocol,
    pub smtp_pipeline: SmtpPipelineStats,
    pub http_pipeline: HttpPipelineStats,
}

impl Default for AlignedSessionStats {
    fn default() -> Self {
        Self {
            total: SessionStats {
                total_sessions: AtomicU64::new(0),
                _pad1: [0; 56],
            },
            active: SessionStatsActive {
                active_sessions: AtomicU64::new(0),
                _pad2: [0; 56],
            },
            packets: SessionStatspackets {
                total_packets: AtomicU64::new(0),
                _pad3: [0; 56],
            },
            bytes: SessionStatsBytes {
                total_bytes: AtomicU64::new(0),
                _pad4: [0; 56],
            },
            protocol: SessionStatsProtocol {
                smtp_sessions: AtomicU64::new(0),
                pop3_sessions: AtomicU64::new(0),
                imap_sessions: AtomicU64::new(0),
                _pad5: [0; 40],
            },
            smtp_pipeline: SmtpPipelineStats::default(),
            http_pipeline: HttpPipelineStats::default(),
        }
    }
}
