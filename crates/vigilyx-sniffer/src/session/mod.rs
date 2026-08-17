//! High-performance session management module (v3.0 - Extreme performance optimized version)

//! Performance optimizations:
//! - FxHash replaces SipHash (2-4x faster)
//! - SIMD accelerated string search (memchr)
//! - Cache-line alignedavoid false sharing
//! - Arc Sharedsession avoid clone (critical optimization!)
//! - Fast UUID generation (WyRand)
//! - Zero-copy command passing

//!   Security features:
//! - SessionCountlimit (Prevent DoS)
//! - IP rate limiting (Prevent scan attacks)

mod cleanup;
mod http_helpers;
mod http_parse;
mod rate_limit;
mod sid_mapping;
mod smtp_diag;
mod smtp_process;
mod smtp_relay;
mod stats;
mod types;

use crate::capture::RawpacketInfo;
use crate::parser::http_state::HttpRequestStateMachine;
use crate::parser::mime::MimeParser;
use crate::parser::smtp_state::{SmtpCommand, SmtpResponse, SmtpStateMachine};
use crate::stream::{
    GLOBAL_REASSEMBLY_BUDGET, ReassemblyBudget, TcpHalfStream, TcpPendingSegmentsDiag, TcpSegment,
};
use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use memchr::memmem;
use rustc_hash::FxHasher;

use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};
use vigilyx_core::{
    Direction, EmailSession, HttpSession, MAX_SMTP_DIALOG_ENTRIES, Protocol, SessionStatus,
    SmtpDialogEntry, TrafficStats,
};

// Re-export sub-module items used by the rest of the crate
pub use stats::AlignedSessionStats;
pub use types::{CompactIp, SessionKey, Sessiondata};

// http_helpers functions are used by http_parse.rs (imported there directly)
use rate_limit::IpRateLimitEntry;
use smtp_relay::SmtpRelayCorrelationProbe;
use types::SidUserEntry;

// Processing result enum (Avoid unnecessary cloning)

/// packet processing result
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProcessResult {
    /// Existing session
    Existing,
    /// Newly created session (Requires full session data)
    New(EmailSession),
    /// Rejected (Security restrictions)
    Rejected,
}

// ============================================
// Performance constants
// ============================================

/// Maximum session count (Prevent memory exhaustion attacks)
const MAX_SESSIONS: usize = 25_000;
/// Bound rate-limiter metadata independently from active sessions. Entries are retained
/// briefly after the last session closes so the per-minute counter remains effective.
const MAX_IP_RATE_LIMIT_ENTRIES: usize = MAX_SESSIONS * 4;

/// HTTP session queue maximum capacity (Prevent OOM)
///
/// When the consumer (data security engine) processes slower than the producer (capture),
/// queue exceeds this limit, drop new HTTP Session, protect system memory.
pub(super) const HTTP_SESSION_QUEUE_CAPACITY: usize = 50_000;

/// SMTP pending DATA idle timeout.
/// If no new packet arrives for this long, salvage and flush instead of waiting the full
/// session timeout window.
const SMTP_PENDING_DATA_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================
// FxHash Type alias (faster than SipHash 2-4x)
// ============================================

/// FxHash builder - For DashMap
type FxBuildHasher = BuildHasherDefault<FxHasher>;

/// DashMap using FxHash
type FxDashMap<K, V> = DashMap<K, V, FxBuildHasher>;

// ============================================
// Sharded session manager (High-performance)
// ============================================

/// Sharded session manager (Lock-free concurrent, with safety limits)
pub struct ShardedSessionManager {
    /// session storage (FxHash DashMap)
    pub(super) sessions: FxDashMap<SessionKey, Sessiondata>,
    /// Exact admission counter. A slot is reserved atomically before a vacant
    /// DashMap entry is inserted, closing the len-check/insert TOCTOU window.
    pub(super) session_slots: AtomicUsize,
    /// IP rate limiter (FxHash DashMap)
    pub(super) ip_rate_limits: FxDashMap<CompactIp, IpRateLimitEntry>,
    /// Production-wide quota shared by every client/server TCP half-stream.
    pub(super) reassembly_budget: Arc<ReassemblyBudget>,
    /// Cache-line aligned statistics
    pub(super) stats: AlignedSessionStats,
    /// Rejectedof connectioncount (Security)
    pub(super) rejected_connections: AtomicU64,
    /// Session timeout duration
    pub(super) timeout: Duration,
    /// SMTP pending DATA idle timeout duration
    pub(super) smtp_pending_timeout: Duration,
    /// SIMD handler (precompiled mode)
    #[allow(dead_code)]
    pub(super) mail_from_finder: memmem::Finder<'static>,
    #[allow(dead_code)]
    pub(super) rcpt_to_finder: memmem::Finder<'static>,
    pub(super) subject_finder: memmem::Finder<'static>,
    /// Reuseof MIME Parsehandler (Avoid email SIMD Finder)
    pub(super) mime_parser: MimeParser,
    /// Dirty session queue (O(dirty_count))
    pub(super) dirty_queue: SegQueue<SessionKey>,
    /// Completed messages split from a pipelined SMTP connection. Each item
    /// has its own session id so no completed email is overwritten or lost.
    pub(super) completed_email_queue: SegQueue<EmailSession>,
    /// Post-restore relay-hop probes that are correlated outside the DashMap session lock.
    pub(super) smtp_relay_diag_queue: SegQueue<SmtpRelayCorrelationProbe>,
    /// HTTP SessionQueue (dataSecuritydetect, From HTTP Stream MediumExtract)
    pub(super) http_session_queue: SegQueue<HttpSession>,
    /// HTTP SessionQueueWhenfirstdepth (HTTP_SESSION_QUEUE_CAPACITY Capacitylimit)
    pub(super) http_queue_len: AtomicU64,
    /// Set when a TCP half-stream rejects data because the shared reassembly
    /// budget is exhausted; the worker loop evicts reclaimable buffers outside
    /// DashMap guards instead of dropping all new data globally.
    pub(super) budget_pressure: AtomicBool,
    /// Coremail sid -> useremailMapping (From compose body / socket.io auth learn)
    /// valuepacketContainslastaccesstimestamp Used for LRU eviction
    pub(super) sid_to_user: FxDashMap<String, SidUserEntry>,
    /// Add newof sid -> user MappingWaitwrite Redis ofbuffer (Avoidevery insert allwrite Redis)
    pub(super) sid_user_pending: std::sync::Mutex<Vec<(String, String)>>,
    /// Last user attributed to a client IP. A second, different user from the
    /// same IP is a webmail-attribution anomaly signal (F3).
    pub(super) client_ip_users: FxDashMap<CompactIp, SidUserEntry>,
}

impl ShardedSessionManager {
    /// CreateNew session manager
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(900)) // 15minute,givinglargeemailenoughtimestamp
    }

    /// CreatewithTimeout session manager
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::with_timeouts(timeout, SMTP_PENDING_DATA_IDLE_TIMEOUT)
    }

    /// Createwith independent session and SMTP pending DATA timeouts
    pub fn with_timeouts(timeout: Duration, smtp_pending_timeout: Duration) -> Self {
        Self {
            sessions: DashMap::with_hasher(FxBuildHasher::default()),
            session_slots: AtomicUsize::new(0),
            ip_rate_limits: DashMap::with_hasher(FxBuildHasher::default()),
            reassembly_budget: Arc::new(ReassemblyBudget::new(GLOBAL_REASSEMBLY_BUDGET)),
            stats: AlignedSessionStats::default(),
            rejected_connections: AtomicU64::new(0),
            timeout,
            smtp_pending_timeout,
            // Precompile SIMD search mode
            mail_from_finder: memmem::Finder::new(b"MAIL FROM:").into_owned(),
            rcpt_to_finder: memmem::Finder::new(b"RCPT TO:").into_owned(),
            subject_finder: memmem::Finder::new(b"Subject:").into_owned(),
            // Reuse MIME Parsehandler (Shared SIMD Finder)
            mime_parser: MimeParser::new(),
            // Dirty session queue
            dirty_queue: SegQueue::new(),
            completed_email_queue: SegQueue::new(),
            // SMTP relay-hop diagnostics queue
            smtp_relay_diag_queue: SegQueue::new(),
            // HTTP dataSecuritySessionQueue
            http_session_queue: SegQueue::new(),
            http_queue_len: AtomicU64::new(0),
            budget_pressure: AtomicBool::new(false),
            // Coremail sid -> user Mapping (LRU)
            sid_to_user: DashMap::with_hasher(FxBuildHasher::default()),
            sid_user_pending: std::sync::Mutex::new(Vec::new()),
            client_ip_users: DashMap::with_hasher(FxBuildHasher::default()),
        }
    }

    #[inline]
    fn refresh_packet_activity(
        session_data: &mut Sessiondata,
        packet: &RawpacketInfo,
        now: Instant,
    ) {
        session_data.last_activity = now;
        session_data.last_packet_at = chrono::Utc::now();
        session_data.last_packet_direction = packet.direction;
        session_data.last_packet_tcp_flags = packet.tcp_flags;
        session_data.last_packet_seq = packet.tcp_seq;
        session_data.last_packet_payload_len = packet.payload.len();
    }

    #[inline]
    pub(super) fn decrement_active_session_if_needed(&self, active_counter_open: &mut bool) {
        if !*active_counter_open {
            return;
        }

        let _ = self.stats.active.active_sessions.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| v.checked_sub(1),
        );
        *active_counter_open = false;
    }

    /// Merge an inspection-degradation tag into `error_reason`, preserving the
    /// `inspection:` prefix that `EmailSession::has_analyzable_content` and the
    /// engine's post-verdict P3 alerting rely on. Idempotent per tag; the
    /// stored reason is length-bounded and UTF-8 safe.
    pub(super) fn merge_inspection_reason(error_reason: &mut Option<String>, tag: &str) {
        const MAX_REASON_LEN: usize = 200;
        if let Some(existing) = error_reason.as_ref()
            && existing.contains(tag)
        {
            return;
        }
        let next = match error_reason.take() {
            None => format!("inspection:{tag}"),
            Some(existing) if existing.starts_with("inspection:") => {
                format!("{existing};{tag}")
            }
            Some(existing) => {
                let prior: String = existing.chars().take(120).collect();
                format!("inspection:{tag};prior:{prior}")
            }
        };
        *error_reason = Some(next.chars().take(MAX_REASON_LEN).collect());
    }

    /// Promote a TCP reassembly gap to an explicit inspection signal.
    ///
    /// Gap counters used to be emitted only in diagnostics.  That made an
    /// overloaded SPAN look like a normal envelope-only session to downstream
    /// consumers until a periodic log happened to be inspected.  The marker is
    /// carried with the dirty session, so the engine can generate its normal
    /// low-severity coverage alert and the event/byte counters remain visible
    /// in aggregate.
    pub(super) fn mark_smtp_stream_gap(
        &self,
        data: &mut Sessiondata,
        direction: &'static str,
        new_gap_bytes: usize,
        total_gap_bytes: usize,
    ) {
        Self::merge_inspection_reason(&mut data.session.error_reason, "smtp_stream_gap");
        self.stats
            .security
            .smtp_stream_gap_alert_total
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .security
            .smtp_stream_gap_alert_bytes_total
            .fetch_add(new_gap_bytes as u64, Ordering::Relaxed);
        let key = data.key.clone();
        self.mark_session_dirty(&mut data.dirty, &key);
        warn!(
            session_id = %data.session.id,
            direction,
            new_gap_bytes,
            total_gap_bytes,
            client_ip = %data.session.client_ip,
            server_ip = %data.session.server_ip,
            "SMTP stream gap detected; inspection coverage alert queued"
        );
    }

    /// F1: when a session reaches a terminal state with SMTP protocol
    /// anomalies counted by the parser state machine, fold a low-severity
    /// `protocol_anomaly` marker into the session so the engine surfaces it
    /// instead of treating the dialog as clean.
    pub(super) fn maybe_mark_protocol_anomaly(&self, data: &mut Sessiondata) {
        let anomalies = data
            .smtp_state
            .as_ref()
            .map(|s| s.anomaly_count())
            .unwrap_or(0);
        if anomalies == 0 || data.protocol_anomaly_marked {
            return;
        }
        data.protocol_anomaly_marked = true;
        Self::merge_inspection_reason(
            &mut data.session.error_reason,
            &format!("protocol_anomaly:{anomalies}"),
        );
        self.stats
            .security
            .protocol_anomaly_session_total
            .fetch_add(1, Ordering::Relaxed);
        self.mark_session_dirty(&mut data.dirty, &data.key);
        warn!(
            session_id = %data.session.id,
            anomaly_count = anomalies,
            client_ip = %data.session.client_ip,
            "SMTP protocol anomalies observed during session; marking inspection signal"
        );
    }

    #[inline]
    fn complete_session_if_needed(&self, data: &mut Sessiondata) -> bool {
        // Fold any SMTP protocol anomalies into the session before it leaves
        // the active pipeline (F1: anomalies must not vanish silently).
        self.maybe_mark_protocol_anomaly(data);

        let needs_terminal_refresh = data.session.status != SessionStatus::Completed
            || data.session.ended_at.is_none()
            || data.active_counter_open;
        if !needs_terminal_refresh {
            return false;
        }

        data.session.status = SessionStatus::Completed;
        data.session.ended_at = Some(chrono::Utc::now());
        self.decrement_active_session_if_needed(&mut data.active_counter_open);
        // A completed session no longer needs to hold an admission slot: under a
        // flood, 25k completed sessions would otherwise keep MAX_SESSIONS occupied
        // for the full idle timeout and blind the capture to new connections.
        // The map entry itself is dropped by the next cleanup pass after flush.
        if !data.slot_released {
            data.slot_released = true;
            let _ = self
                .session_slots
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(1))
                });
        }
        true
    }

    #[inline]
    fn mark_session_dirty(&self, dirty: &mut bool, key: &SessionKey) {
        if !*dirty {
            *dirty = true;
            self.dirty_queue.push(key.clone());
        }
    }

    /// Processdatapacket,ReturnProcessResult
    ///
    /// Performance optimizations:
    /// - Existing sessiononlyReturn ID,Avoid Session
    /// - Receive Option<&str> Reference,Avoid command
    #[cfg(test)]
    #[inline]
    pub fn process_packet(
        &self,
        packet: &RawpacketInfo,
        command: Option<&str>,
        now: Instant,
    ) -> ProcessResult {
        self.process_packet_with_worker(packet, command, now, None)
    }

    #[inline]
    pub fn process_packet_with_worker(
        &self,
        packet: &RawpacketInfo,
        command: Option<&str>,
        now: Instant,
        worker_id: Option<usize>,
    ) -> ProcessResult {
        let key = SessionKey::new(packet);

        // UpdateStatistics (Use Relaxed, High-performance)
        self.stats
            .packets
            .total_packets
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes
            .total_bytes
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);

        // HTTP pipeline Statistics: packet
        if packet.protocol == Protocol::Http {
            self.stats
                .http_pipeline
                .http_packets_total
                .fetch_add(1, Ordering::Relaxed);
        }

        // path: CheckSessionwhetherstored
        if let Some(mut session_ref) = self.sessions.get_mut(&key) {
            // Update found an existing session
            session_ref.session.packet_count += 1;
            session_ref.session.total_bytes += packet.payload.len();
            Self::refresh_packet_activity(&mut session_ref, packet, now);
            self.observe_session_worker(&mut session_ref, packet, worker_id);

            // Save session ID (FreeLock first)
            let session_id = session_ref.session.id;

            // packetlog: downgradelevel trace (pathPerformance notes)
            if packet.protocol == Protocol::Smtp {
                trace!(
                    "📦 Session {} Received {:?} packet #{} | {} Byte | in_data_mode={}, state={:?}",
                    session_id,
                    packet.direction,
                    session_ref.session.packet_count,
                    packet.payload.len(),
                    session_ref
                        .smtp_state
                        .as_ref()
                        .map(|s| s.is_in_data_mode())
                        .unwrap_or(false),
                    session_ref.smtp_state.as_ref().map(|s| s.state())
                );
            }

            // SMTP dataParse (UseState machineAnd SIMD)
            // SMTP Recording parse_smtp_data_simd Internalcomplete(Pipeline Command)
            if packet.protocol == Protocol::Smtp {
                self.parse_smtp_data_simd(&mut session_ref, packet, command, now);
            }

            // HTTP Login detection + dataSecuritydetect (Use TCP stream reassembly)
            if packet.protocol == Protocol::Http {
                self.parse_http_login(&mut session_ref, packet);
                self.parse_http_data_security(&mut session_ref, packet);
            }

            // F2: POP3/IMAP mail-retrieval coverage-gap signal
            if matches!(packet.protocol, Protocol::Pop3 | Protocol::Imap) {
                self.observe_mail_retrieval(&mut session_ref, packet);
            }

            // onlyReturn ID,Avoid Session!
            return ProcessResult::Existing;
        }

        // Mirror port tolerance: allow session creation without SYN.
        // Port mirroring commonly misses SYN packets (late start, dropped first packet,
        // one direction arriving first). Rejecting these loses entire SMTP connections.
        // Only skip pure ACKs with no payload (no useful data to start a session with).
        const TCP_SYN: u8 = 0x02;
        let has_syn = (packet.tcp_flags & TCP_SYN) != 0;
        if !has_syn && packet.payload.is_empty() {
            // Pure ACK with no data - not useful for starting a session
            if packet.protocol == Protocol::Http {
                self.stats
                    .http_pipeline
                    .http_rejected_no_syn
                    .fetch_add(1, Ordering::Relaxed);
            }
            return ProcessResult::Rejected;
        }

        // path: Need/RequireCreateNewSession
        self.create_new_session(packet, key, command, now, worker_id)
    }

    /// CreateNewSession (path,withSecurityCheck)
    #[cold]
    fn create_new_session(
        &self,
        packet: &RawpacketInfo,
        key: SessionKey,
        command: Option<&str>,
        now: Instant,
        worker_id: Option<usize>,
    ) -> ProcessResult {
        // Getclient IP
        let client_ip = SessionKey::client_ip_from_packet(packet);

        // A spoofed source address must not grow the per-IP metadata table without bound.
        // Existing addresses remain usable at capacity; new addresses are admitted only
        // after expired, inactive records have been evicted.
        if self.ip_rate_limits.len() >= MAX_IP_RATE_LIMIT_ENTRIES
            && !self.ip_rate_limits.contains_key(&client_ip)
        {
            self.cleanup_ip_rate_limits();
            if self.ip_rate_limits.len() >= MAX_IP_RATE_LIMIT_ENTRIES
                && !self.ip_rate_limits.contains_key(&client_ip)
            {
                self.rejected_connections.fetch_add(1, Ordering::Relaxed);
                warn!(
                    limit = MAX_IP_RATE_LIMIT_ENTRIES,
                    "rejecting new source IP: rate-limit metadata capacity reached"
                );
                return ProcessResult::Rejected;
            }
        }

        // SecurityCheck 2: IP rate limiting
        let should_reject = {
            let entry = self
                .ip_rate_limits
                .entry(client_ip)
                .or_insert_with(IpRateLimitEntry::new);
            let rate_entry = entry.value();

            // Check Expired
            rate_entry.check_and_maybe_reset();

            if rate_entry.should_limit() {
                true
            } else {
                // AddAddcount
                rate_entry.new_session_count.fetch_add(1, Ordering::Relaxed);
                rate_entry
                    .active_session_count
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        };

        if should_reject {
            self.rejected_connections.fetch_add(1, Ordering::Relaxed);
            debug!(
                "session rejected: IP {} rate limited (extreme traffic only)",
                client_ip.to_string()
            );
            return ProcessResult::Rejected;
        }

        if self
            .session_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_SESSIONS).then_some(current + 1)
            })
            .is_err()
        {
            if let Some(entry) = self.ip_rate_limits.get(&client_ip) {
                let _ = entry.new_session_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |value| value.checked_sub(1),
                );
                let _ = entry.active_session_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |value| value.checked_sub(1),
                );
            }
            self.rejected_connections.fetch_add(1, Ordering::Relaxed);
            warn!(
                limit = MAX_SESSIONS,
                "rejecting new session: capacity reached"
            );
            return ProcessResult::Rejected;
        }

        // CreateNewSessiondata (possibly drop,if 1Thread)
        let mut session_data = self.create_session_data(packet, now, key.clone());
        session_data.owner_worker_id = worker_id;
        session_data.last_worker_id = worker_id;

        // : Use Entry API get_mut -> insert of TOCTOU
        match self.sessions.entry(key) {
            Entry::Vacant(vacant) => {
                // ofNewSession - UpdateStatistics
                let mut session_entry = vacant.insert(session_data);

                self.stats
                    .total
                    .total_sessions
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .active
                    .active_sessions
                    .fetch_add(1, Ordering::Relaxed);

                match packet.protocol {
                    Protocol::Smtp => {
                        self.stats
                            .protocol
                            .smtp_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Protocol::Pop3 => {
                        self.stats
                            .protocol
                            .pop3_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Protocol::Imap => {
                        self.stats
                            .protocol
                            .imap_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Protocol::Http => {
                        self.stats
                            .http_pipeline
                            .http_connections_created
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }

                info!(
                    "NewSession: {} | {} -> {}:{} | {}{}",
                    session_entry.session.id,
                    session_entry.session.client_ip,
                    session_entry.session.server_ip,
                    session_entry.session.server_port,
                    session_entry.session.protocol,
                    if session_entry.session.content.is_encrypted {
                        " [Encrypt]"
                    } else {
                        ""
                    }
                );
                if packet.protocol == Protocol::Smtp && session_entry.created_without_syn {
                    self.stats
                        .smtp_pipeline
                        .smtp_sessions_created_without_syn
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        session_id = %session_entry.session.id,
                        owner_worker_id = ?session_entry.owner_worker_id,
                        client_ip = %session_entry.session.client_ip,
                        client_port = session_entry.session.client_port,
                        server_ip = %session_entry.session.server_ip,
                        server_port = session_entry.session.server_port,
                        direction = ?packet.direction,
                        first_seq = packet.tcp_seq,
                        first_payload_len = packet.payload.len(),
                        first_tcp_flags = packet.tcp_flags,
                        "SMTP session created without seeing SYN; capture may have started mid-stream"
                    );
                }

                // SMTP dataParse (UseState machineAnd SIMD)
                if packet.protocol == Protocol::Smtp {
                    // SMTP Command session content
                    if let Some(ref cmd) = command
                        && session_entry.session.content.smtp_dialog.len() < MAX_SMTP_DIALOG_ENTRIES
                    {
                        session_entry
                            .session
                            .content
                            .smtp_dialog
                            .push(SmtpDialogEntry {
                                direction: packet.direction,
                                command: cmd.to_string(),
                                size: packet.payload.len(),
                                timestamp: chrono::Utc::now(),
                            });
                    }
                    self.parse_smtp_data_simd(&mut session_entry, packet, command, now);
                }

                // HTTP Login detection
                if packet.protocol == Protocol::Http {
                    self.parse_http_login(&mut session_entry, packet);
                    // Symmetric with the existing-session path: the very first
                    // packet of a connection must also feed the data-security
                    // stream reassembly, otherwise its bytes are lost.
                    self.parse_http_data_security(&mut session_entry, packet);
                }

                // F2: POP3/IMAP mail-retrieval coverage-gap signal
                if matches!(packet.protocol, Protocol::Pop3 | Protocol::Imap) {
                    self.observe_mail_retrieval(&mut session_entry, packet);
                }

                // ReturnNewSession (Need/Require,Butonly NewSession Occur)
                ProcessResult::New(session_entry.session.clone())
            }
            Entry::Occupied(occupied) => {
                self.session_slots.fetch_sub(1, Ordering::AcqRel);
                // 1Threadalready Create Session - According toalready SessionProcess
                let mut session_ref = occupied.into_ref();
                session_ref.session.packet_count += 1;
                session_ref.session.total_bytes += packet.payload.len();
                Self::refresh_packet_activity(&mut session_ref, packet, now);

                // IP rate limitingof Add
                if let Some(entry) = self.ip_rate_limits.get(&client_ip) {
                    let _ = entry.value().new_session_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |value| value.checked_sub(1),
                    );
                    let _ = entry.value().active_session_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |value| value.checked_sub(1),
                    );
                }

                // SMTP dataParse (Recording parse_smtp_data_simd Internal)
                if packet.protocol == Protocol::Smtp {
                    self.parse_smtp_data_simd(&mut session_ref, packet, command, now);
                }

                // HTTP Login + dataSecuritydetect
                if packet.protocol == Protocol::Http {
                    self.parse_http_login(&mut session_ref, packet);
                    self.parse_http_data_security(&mut session_ref, packet);
                }

                // F2: POP3/IMAP mail-retrieval coverage-gap signal
                if matches!(packet.protocol, Protocol::Pop3 | Protocol::Imap) {
                    self.observe_mail_retrieval(&mut session_ref, packet);
                }

                ProcessResult::Existing
            }
        }
    }

    /// CreateNewSessiondata
    #[inline(always)]
    pub(super) fn create_session_data(
        &self,
        packet: &RawpacketInfo,
        now: Instant,
        key: SessionKey,
    ) -> Sessiondata {
        let (client_ip, client_port, server_ip, server_port) = match packet.direction {
            Direction::Outbound => (
                packet.src_ip.to_string(),
                packet.src_port,
                packet.dst_ip.to_string(),
                packet.dst_port,
            ),
            Direction::Inbound => (
                packet.dst_ip.to_string(),
                packet.dst_port,
                packet.src_ip.to_string(),
                packet.src_port,
            ),
        };

        let mut session = EmailSession::new(
            packet.protocol,
            client_ip,
            client_port,
            server_ip,
            server_port,
        );
        session.packet_count = 1;
        session.total_bytes = packet.payload.len();

        // Checkwhether EncryptPort
        if Protocol::is_encrypted_port(server_port) {
            session.content.is_encrypted = true;
        }

        // SMTP SessionCreateState machine
        const TCP_SYN: u8 = 0x02;
        let created_without_syn = (packet.tcp_flags & TCP_SYN) == 0;
        let smtp_state = if packet.protocol == Protocol::Smtp {
            let mut state = SmtpStateMachine::new();
            // Mid-stream captures missed the DATA command together with the SYN;
            // allow the first lone 354 so the in-flight body is still collected.
            state.set_midstream_capture(created_without_syn);
            Some(state)
        } else {
            None
        };

        // HTTP SessionCreateRequestState machine
        let http_state = if packet.protocol == Protocol::Http {
            Some(HttpRequestStateMachine::new())
        } else {
            None
        };

        let client_compact_ip = SessionKey::client_ip_from_packet(packet);

        Sessiondata {
            session,
            last_activity: now,
            last_packet_at: chrono::Utc::now(),
            last_packet_direction: packet.direction,
            last_packet_tcp_flags: packet.tcp_flags,
            last_packet_seq: packet.tcp_seq,
            last_packet_payload_len: packet.payload.len(),
            smtp_state,
            http_state,
            client_stream: TcpHalfStream::with_budget(Arc::clone(&self.reassembly_budget)),
            server_stream: TcpHalfStream::with_budget(Arc::clone(&self.reassembly_budget)),
            client_processed_offset: 0,
            server_processed_offset: 0,
            client_gap_logged_bytes: 0,
            server_gap_logged_bytes: 0,
            active_counter_open: true,
            client_tcp_closed: false,
            server_tcp_closed: false,
            created_without_syn,
            owner_worker_id: None,
            last_worker_id: None,
            worker_switch_count: 0,
            smtp_restore_issue_logged: false,
            smtp_pending_diag_logged: false,
            dirty: false,
            key,
            client_compact_ip,
            tls_magic_marked: false,
            slot_released: false,
            stream_buffers_evicted: false,
            http_desynced: false,
            mail_retrieval_seen: false,
            protocol_anomaly_marked: false,
        }
    }

    /// Extract Mark dirtyofSession (dirtyMark)
    /// Comment retained in English.
    /// O(dirty_count) : onlylookupdirtyQueueMediumofSession
    /// Performance optimizations: Batch key, AddLockProcess, Lock timestamp
    pub fn take_dirty_sessions(&self) -> Vec<EmailSession> {
        let mut dirty = Vec::with_capacity(64);
        while let Some(session) = self.completed_email_queue.pop() {
            dirty.push(session);
        }

        // 1. Batch pop key (LockOperations)
        let mut keys = Vec::with_capacity(64);
        while let Some(key) = self.dirty_queue.pop() {
            keys.push(key);
        }
        if keys.is_empty() {
            self.process_smtp_relay_diag_queue();
            return dirty;
        }

        // 2. short AddLockExtract dirtyMark
        dirty.reserve(keys.len());
        for key in keys {
            if let Some(mut entry) = self.sessions.get_mut(&key)
                && entry.dirty
            {
                entry.dirty = false;
                dirty.push(entry.session.clone());
            }
            // entry guard immediatelyFree, small Lock
        }
        self.process_smtp_relay_diag_queue();
        dirty
    }

    /// RecordingalreadyPublishof HTTP SessionCount (By worker_loop)
    pub fn record_http_sessions_published(&self, count: u64) {
        self.stats
            .http_pipeline
            .http_sessions_published
            .fetch_add(count, Ordering::Relaxed);
    }

    /// GetStatisticsInfo
    pub fn get_stats(&self) -> TrafficStats {
        TrafficStats {
            total_sessions: self.stats.total.total_sessions.load(Ordering::Relaxed),
            active_sessions: self.stats.active.active_sessions.load(Ordering::Relaxed),
            total_packets: self.stats.packets.total_packets.load(Ordering::Relaxed),
            total_bytes: self.stats.bytes.total_bytes.load(Ordering::Relaxed),
            smtp_sessions: self.stats.protocol.smtp_sessions.load(Ordering::Relaxed),
            pop3_sessions: self.stats.protocol.pop3_sessions.load(Ordering::Relaxed),
            imap_sessions: self.stats.protocol.imap_sessions.load(Ordering::Relaxed),
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        }
    }

    /// Get HTTP SessionQueueWhenfirstdepth
    pub fn http_queue_depth(&self) -> u64 {
        self.http_queue_len.load(Ordering::Relaxed)
    }

    /// F2: cleartext POP3 `RETR` / IMAP `FETCH BODY[]` transfer detection.
    ///
    /// The sniffer never reassembles or analyzes mail content for POP3/IMAP —
    /// without this marker the full message bytes crossing the sensor produced
    /// neither a verdict nor any signal. On first observation the session gets
    /// an `inspection:` coverage-gap reason (engine turns it into a verdict +
    /// P3 alert via the post-verdict incomplete-inspection path).
    pub(super) fn observe_mail_retrieval(
        &self,
        session_data: &mut Sessiondata,
        packet: &RawpacketInfo,
    ) {
        if session_data.mail_retrieval_seen
            || packet.direction != Direction::Outbound
            || packet.payload.is_empty()
            || session_data.session.content.is_encrypted
        {
            return;
        }
        // Commands are short; scanning the first 8KB of a client payload is
        // enough to catch RETR / FETCH even with pipelining.
        let scan_len = packet.payload.len().min(8192);
        let Some(head) = packet.payload.get(..scan_len) else {
            return;
        };
        let seen = match packet.protocol {
            Protocol::Pop3 => pop3_retr_observed(head),
            Protocol::Imap => imap_body_fetch_observed(head),
            _ => false,
        };
        if !seen {
            return;
        }
        session_data.mail_retrieval_seen = true;
        let tag = match packet.protocol {
            Protocol::Pop3 => {
                self.stats
                    .security
                    .pop3_content_gap_total
                    .fetch_add(1, Ordering::Relaxed);
                "pop3_retr_content_not_analyzed"
            }
            _ => {
                self.stats
                    .security
                    .imap_content_gap_total
                    .fetch_add(1, Ordering::Relaxed);
                "imap_fetch_body_content_not_analyzed"
            }
        };
        Self::merge_inspection_reason(&mut session_data.session.error_reason, tag);
        self.mark_session_dirty(&mut session_data.dirty, &session_data.key);
        warn!(
            session_id = %session_data.session.id,
            protocol = %session_data.session.protocol,
            client_ip = %session_data.session.client_ip,
            server_ip = %session_data.session.server_ip,
            "cleartext mail retrieval observed; message content is NOT analyzed (coverage gap)"
        );
    }

    /// Called from stream-buffer error paths (DashMap guard held): only record
    /// the pressure here; the actual eviction runs in the worker loop where no
    /// session locks are held.
    pub(super) fn note_budget_pressure(&self) {
        self.budget_pressure.store(true, Ordering::Relaxed);
    }

    /// Worker-loop hook: returns true once after budget pressure was observed.
    pub fn take_budget_pressure(&self) -> bool {
        self.budget_pressure.swap(false, Ordering::AcqRel)
    }
}

impl Default for ShardedSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// POP3: true when any command line in the client payload is a `RETR`
/// request (full-message retrieval). Case-insensitive per RFC 1939.
fn pop3_retr_observed(payload: &[u8]) -> bool {
    payload.split(|&b| b == b'\n').any(|line| {
        match line.get(..4) {
            Some(cmd) => {
                cmd.eq_ignore_ascii_case(b"RETR")
                    // Require a separator after the verb so that e.g. a line
                    // starting with "RETURN" is not misread.
                    && matches!(line.get(4), Some(b' ' | b'\t' | b'\r'))
            }
            None => false,
        }
    })
}

/// IMAP: true when any command line requests message body content:
/// `FETCH ... BODY[]` / `BODY.PEEK[]` / `BODY[TEXT]` / bare `RFC822` /
/// `RFC822.TEXT` (RFC 3501). `RFC822.SIZE` / `RFC822.HEADER` carry no body.
fn imap_body_fetch_observed(payload: &[u8]) -> bool {
    payload.split(|&b| b == b'\n').any(|line| {
        let line = if line.len() > 4096 {
            line.get(..4096).unwrap_or(line)
        } else {
            line
        };
        // Lossy-decode to a string so the substring checks below type-check;
        // IMAP command keywords are ASCII so the lossy replacement is inert.
        let upper = String::from_utf8_lossy(line).to_ascii_uppercase();
        if !upper.contains("FETCH") {
            return false;
        }
        if upper.contains("BODY[]")
            || upper.contains("BODY.PEEK[]")
            || upper.contains("BODY[TEXT]")
            || upper.contains("BODY.PEEK[TEXT]")
        {
            return true;
        }
        if let Some(idx) = upper.find("RFC822") {
            let after = upper.get(idx + 6..).unwrap_or("");
            if after.is_empty() || !after.starts_with('.') || after.starts_with(".TEXT") {
                return true;
            }
        }
        false
    })
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod redteam_capture_tests;
