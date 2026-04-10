//! Cache-line-aligned session statistics structure

//! Avoids multi-thread false sharing by placing each independent counter in its own cache line.

use std::sync::atomic::AtomicU64;

// Cache-line-aligned statistics structure (avoid false sharing)

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

/// HTTP data security pipeline statistics (fulllink packet loss tracking)
///
/// Used in 100% mirror traffic restoration scenarios, tracking HTTP sessions from packet capture to engine ingestion.
pub struct HttpPipelineStats {
    /// Total HTTP protocol packets (packets entering process_packet where protocol==Http)
    pub http_packets_total: AtomicU64,
    /// Outbound packets entering parse_http_data_security
    pub http_packets_outbound: AtomicU64,
    /// packets dropped due to TCP stream buffer overflow
    pub http_stream_overflow: AtomicU64,
    /// Complete requests successfully split by HTTP state machine (all methods included)
    pub http_requests_parsed: AtomicU64,
    /// Requests skipped due to non-POST/PUT methods
    pub http_requests_skipped_method: AtomicU64,
    /// HttpSessions successfully constructed and queued
    pub http_sessions_queued: AtomicU64,
    /// HttpSessions dropped due to full queue
    pub http_sessions_dropped_queue_full: AtomicU64,
    /// HttpSessions successfully published to MQ/HTTP
    pub http_sessions_published: AtomicU64,
    /// HTTP TCP connection (session) creation count
    pub http_connections_created: AtomicU64,
    /// HTTP packets rejected due to missing TCP SYN
    pub http_rejected_no_syn: AtomicU64,
}

impl Default for HttpPipelineStats {
    fn default() -> Self {
        Self {
            http_packets_total: AtomicU64::new(0),
            http_packets_outbound: AtomicU64::new(0),
            http_stream_overflow: AtomicU64::new(0),
            http_requests_parsed: AtomicU64::new(0),
            http_requests_skipped_method: AtomicU64::new(0),
            http_sessions_queued: AtomicU64::new(0),
            http_sessions_dropped_queue_full: AtomicU64::new(0),
            http_sessions_published: AtomicU64::new(0),
            http_connections_created: AtomicU64::new(0),
            http_rejected_no_syn: AtomicU64::new(0),
        }
    }
}

/// SMTP restoration pipeline statistics.
///
/// These counters make it easy to tell whether mirrored SMTP traffic is being
/// fully restored, partially restored, or lost due to gaps / parser failures.
pub struct SmtpPipelineStats {
    /// Fully restored non-encrypted SMTP emails.
    pub smtp_restored_ok: AtomicU64,
    /// Restored SMTP emails with TCP gaps (marked incomplete).
    pub smtp_restored_with_gaps: AtomicU64,
    /// MIME parsing failed after DATA termination.
    pub smtp_mime_parse_failed: AtomicU64,
    /// client->server TCP gap detections.
    pub smtp_client_gap_events: AtomicU64,
    /// Sum of client->server gap bytes.
    pub smtp_client_gap_bytes_total: AtomicU64,
    /// server->client TCP gap detections.
    pub smtp_server_gap_events: AtomicU64,
    /// Sum of server->client gap bytes.
    pub smtp_server_gap_bytes_total: AtomicU64,
    /// SMTP sessions that started without an observed SYN.
    pub smtp_sessions_created_without_syn: AtomicU64,
    /// Same SMTP session observed on multiple workers.
    pub smtp_worker_mismatch_events: AtomicU64,
    /// Late prepend events on client->server stream.
    pub smtp_client_late_prepend_events: AtomicU64,
    /// Sum of prepended bytes on client->server stream.
    pub smtp_client_late_prepend_bytes_total: AtomicU64,
    /// Late prepend events on server->client stream.
    pub smtp_server_late_prepend_events: AtomicU64,
    /// Sum of prepended bytes on server->client stream.
    pub smtp_server_late_prepend_bytes_total: AtomicU64,
    /// client stream overflow events.
    pub smtp_client_stream_overflow: AtomicU64,
    /// server stream overflow events.
    pub smtp_server_stream_overflow: AtomicU64,
    /// Total SMTP sessions that hit the session timeout path.
    pub smtp_timeout_sessions_total: AtomicU64,
    /// SMTP sessions forced through the shorter pending-DATA idle timeout.
    pub smtp_pending_idle_timeout_sessions: AtomicU64,
    /// Plaintext SMTP sessions closed by TCP without restored payload.
    pub smtp_plaintext_tcp_close_without_restore: AtomicU64,
    /// Plaintext SMTP sessions timed out without restored payload.
    pub smtp_plaintext_timeout_without_restore: AtomicU64,
    /// Plaintext SMTP sessions that reached DATA but closed before any payload arrived.
    pub smtp_plaintext_aborted_before_payload: AtomicU64,
    /// Plaintext SMTP sessions not restored because stream gaps made payload incomplete.
    pub smtp_plaintext_without_restore_stream_gap: AtomicU64,
    /// Plaintext SMTP sessions not restored because payload truncated before terminator.
    pub smtp_plaintext_without_restore_truncated: AtomicU64,
    /// Plaintext SMTP sessions not restored because DATA state stayed pending or 354 never aligned.
    pub smtp_plaintext_without_restore_missing_354: AtomicU64,
    /// Plaintext SMTP sessions not restored because MIME parse failed or payload stayed empty.
    pub smtp_plaintext_without_restore_mime_or_empty: AtomicU64,
    /// Close-path salvage restored only partial headers/body.
    pub smtp_close_salvage_partial: AtomicU64,
}

impl Default for SmtpPipelineStats {
    fn default() -> Self {
        Self {
            smtp_restored_ok: AtomicU64::new(0),
            smtp_restored_with_gaps: AtomicU64::new(0),
            smtp_mime_parse_failed: AtomicU64::new(0),
            smtp_client_gap_events: AtomicU64::new(0),
            smtp_client_gap_bytes_total: AtomicU64::new(0),
            smtp_server_gap_events: AtomicU64::new(0),
            smtp_server_gap_bytes_total: AtomicU64::new(0),
            smtp_sessions_created_without_syn: AtomicU64::new(0),
            smtp_worker_mismatch_events: AtomicU64::new(0),
            smtp_client_late_prepend_events: AtomicU64::new(0),
            smtp_client_late_prepend_bytes_total: AtomicU64::new(0),
            smtp_server_late_prepend_events: AtomicU64::new(0),
            smtp_server_late_prepend_bytes_total: AtomicU64::new(0),
            smtp_client_stream_overflow: AtomicU64::new(0),
            smtp_server_stream_overflow: AtomicU64::new(0),
            smtp_timeout_sessions_total: AtomicU64::new(0),
            smtp_pending_idle_timeout_sessions: AtomicU64::new(0),
            smtp_plaintext_tcp_close_without_restore: AtomicU64::new(0),
            smtp_plaintext_timeout_without_restore: AtomicU64::new(0),
            smtp_plaintext_aborted_before_payload: AtomicU64::new(0),
            smtp_plaintext_without_restore_stream_gap: AtomicU64::new(0),
            smtp_plaintext_without_restore_truncated: AtomicU64::new(0),
            smtp_plaintext_without_restore_missing_354: AtomicU64::new(0),
            smtp_plaintext_without_restore_mime_or_empty: AtomicU64::new(0),
            smtp_close_salvage_partial: AtomicU64::new(0),
        }
    }
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
