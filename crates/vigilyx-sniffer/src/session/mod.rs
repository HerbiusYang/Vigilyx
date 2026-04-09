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

mod http_helpers;
mod http_parse;
mod rate_limit;
mod sid_mapping;
mod smtp_relay;
mod stats;
mod types;

use crate::capture::RawpacketInfo;
use crate::parser::http_state::HttpRequestStateMachine;
use crate::parser::mime::MimeParser;
use crate::parser::smtp_state::{SmtpCommand, SmtpResponse, SmtpStateMachine};
use crate::stream::{TcpHalfStream, TcpSegment};
use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use memchr::memmem;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};
use vigilyx_core::{
    Direction, EmailContent, EmailSession, HttpSession, MAX_SMTP_DIALOG_ENTRIES, Protocol,
    SessionStatus, SmtpAuthInfo, SmtpDialogEntry, TrafficStats,
};

// Re-export sub-module items used by the rest of the crate
pub use stats::AlignedSessionStats;
pub use types::{CompactIp, SessionKey, Sessiondata};

// http_helpers functions are used by http_parse.rs (imported there directly)
use rate_limit::{IpRateLimitEntry, RATE_LIMIT_WINDOW_SECS};
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
const MAX_SESSIONS: usize = 100_000;

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
   /// IP rate limiter (FxHash DashMap)
    pub(super) ip_rate_limits: FxDashMap<CompactIp, IpRateLimitEntry>,
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
   /// Post-restore relay-hop probes that are correlated outside the DashMap session lock.
    pub(super) smtp_relay_diag_queue: SegQueue<SmtpRelayCorrelationProbe>,
   /// HTTP SessionQueue (dataSecuritydetect, From HTTP Stream MediumExtract)
    pub(super) http_session_queue: SegQueue<HttpSession>,
   /// HTTP SessionQueueWhenfirstdepth (HTTP_SESSION_QUEUE_CAPACITY Capacitylimit)
    pub(super) http_queue_len: AtomicU64,
   /// Coremail sid -> useremailMapping (From compose body / socket.io auth learn)
   /// valuepacketContainslastaccesstimestamp Used for LRU eviction
    pub(super) sid_to_user: FxDashMap<String, SidUserEntry>,
   /// Add newof sid -> user MappingWaitwrite Redis ofbuffer (Avoidevery insert allwrite Redis)
    pub(super) sid_user_pending: std::sync::Mutex<Vec<(String, String)>>,
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
            ip_rate_limits: DashMap::with_hasher(FxBuildHasher::default()),
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
           // SMTP relay-hop diagnostics queue
            smtp_relay_diag_queue: SegQueue::new(),
           // HTTP dataSecuritySessionQueue
            http_session_queue: SegQueue::new(),
            http_queue_len: AtomicU64::new(0),
           // Coremail sid -> user Mapping (LRU)
            sid_to_user: DashMap::with_hasher(FxBuildHasher::default()),
            sid_user_pending: std::sync::Mutex::new(Vec::new()),
        }
    }

    #[inline]
    fn refresh_packet_activity(session_data: &mut Sessiondata, packet: &RawpacketInfo, now: Instant) {
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

    #[inline]
    fn complete_session_if_needed(
        &self,
        session: &mut EmailSession,
        active_counter_open: &mut bool,
    ) -> bool {
        let needs_terminal_refresh = session.status != SessionStatus::Completed
            || session.ended_at.is_none()
            || *active_counter_open;
        if !needs_terminal_refresh {
            return false;
        }

        session.status = SessionStatus::Completed;
        session.ended_at = Some(chrono::Utc::now());
        self.decrement_active_session_if_needed(active_counter_open);
        true
    }

    #[inline]
    pub(super) fn smtp_session_has_restored_payload(session: &EmailSession) -> bool {
        session.content.body_text.is_some()
            || session.content.body_html.is_some()
            || !session.content.attachments.is_empty()
            || !session.content.headers.is_empty()
    }

    #[inline]
    fn mark_session_dirty(&self, dirty: &mut bool, key: &SessionKey) {
        if !*dirty {
           *dirty = true;
            self.dirty_queue.push(key.clone());
        }
    }

    #[inline]
    fn populate_smtp_envelope_from_content(session: &mut EmailSession, content: &EmailContent) {
        if let Some(subject) = content
            .get_header("Subject")
            .map(crate::parser::mime::decode_rfc2047)
        {
            let subject = subject.trim();
            if !subject.is_empty() {
                session.subject = Some(subject.to_string());
            }
        }

        if session.mail_from.is_none()
            && let Some(from) = content.get_header("From")
        {
            let decoded = crate::parser::mime::decode_rfc2047(from);
            let addr = if let Some(start) = decoded.rfind('<') {
                decoded[start + 1..]
                    .trim_end_matches('>')
                    .trim()
                    .to_string()
            } else {
                decoded.trim().to_string()
            };
            if !addr.is_empty() && addr.contains('@') {
                session.mail_from = Some(addr);
            }
        }

        if session.rcpt_to.is_empty()
            && let Some(to) = content.get_header("To")
        {
            let decoded = crate::parser::mime::decode_rfc2047(to);
            for part in decoded.split(',') {
                let part = part.trim();
                let addr = if let Some(start) = part.rfind('<') {
                    part[start + 1..]
                        .trim_end_matches('>')
                        .trim()
                        .to_string()
                } else {
                    part.to_string()
                };
                if !addr.is_empty() && addr.contains('@') {
                    session.rcpt_to.push(addr);
                }
            }
        }

        if session.message_id.is_none()
            && let Some(message_id) = Self::extract_message_id(content)
        {
            session.message_id = Some(message_id);
        }
    }

    #[inline]
    fn extract_message_id(content: &EmailContent) -> Option<String> {
        content
            .get_header("Message-ID")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    }

    #[inline]
    pub(super) fn session_message_id(session: &EmailSession) -> Option<&str> {
        session
            .message_id
            .as_deref()
            .or_else(|| session.content.get_header("Message-ID"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_smtp_restore(
        &self,
        session: &mut EmailSession,
        dirty: &mut bool,
        key: &SessionKey,
        client_gap_bytes: usize,
        server_gap_bytes: usize,
        content: EmailContent,
        is_complete: bool,
        restore_origin: &str,
    ) -> Option<String> {
        let restored_message_id = Self::extract_message_id(&content);
        Self::populate_smtp_envelope_from_content(session, &content);

        let dialog = std::mem::take(&mut session.content.smtp_dialog);
        session.content = content;
        session.content.smtp_dialog = dialog;
        session.content.is_complete = is_complete;
        let body_bytes = session
            .content
            .body_text
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0)
            + session
                .content
                .body_html
                .as_ref()
                .map(|s| s.len())
                .unwrap_or(0);

        self.mark_session_dirty(dirty, key);

        if is_complete {
            self.stats
                .smtp_pipeline
                .smtp_restored_ok
                .fetch_add(1, Ordering::Relaxed);
            info!(
                "SMTP email restored: session={} subject={:?} is_complete=true body_bytes={} attachments={} links={} restore_origin={}",
                session.id,
                session.subject,
                body_bytes,
                session.content.attachments.len(),
                session.content.links.len(),
                restore_origin
            );
        } else {
            self.stats
                .smtp_pipeline
                .smtp_restored_with_gaps
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                "SMTP email restored with gaps: session={} subject={:?} is_complete=false body_bytes={} attachments={} links={} client_gap_bytes={} server_gap_bytes={} restore_origin={}",
                session.id,
                session.subject,
                body_bytes,
                session.content.attachments.len(),
                session.content.links.len(),
                client_gap_bytes,
                server_gap_bytes,
                restore_origin
            );
        }

        restored_message_id
    }

    fn finalize_completed_smtp_email(
        &self,
        session_data: &mut Sessiondata,
        restore_origin: &str,
        parse_context: &str,
    ) {
        session_data.session.email_count += 1;

        let email_data = {
            let Some(smtp_state) = session_data.smtp_state.as_mut() else {
                return;
            };
            let emails = smtp_state.take_completed_emails();
            smtp_state.clear_data_buffer();
            emails.into_iter().last()
        };

        let Some(email_data) = email_data else {
            return;
        };

        match self.mime_parser.parse(&email_data) {
            Ok(content) => {
                let is_complete = session_data.client_stream.gap_bytes_skipped == 0
                    && session_data.server_stream.gap_bytes_skipped == 0;
                if let Some(message_id) = self.record_smtp_restore(
                    &mut session_data.session,
                    &mut session_data.dirty,
                    &session_data.key,
                    session_data.client_stream.gap_bytes_skipped,
                    session_data.server_stream.gap_bytes_skipped,
                    content,
                    is_complete,
                    restore_origin,
                ) {
                    self.enqueue_smtp_relay_probe(session_data, message_id);
                }
            }
            Err(e) => {
                self.stats
                    .smtp_pipeline
                    .smtp_mime_parse_failed
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    session_id = %session_data.session.id,
                    payload_bytes = email_data.len(),
                    client_gap_bytes = session_data.client_stream.gap_bytes_skipped,
                    server_gap_bytes = session_data.server_stream.gap_bytes_skipped,
                    "SMTP MIME parse failed {}: {:?}",
                    parse_context,
                    e
                );
            }
        }
    }

    fn handle_smtp_client_commands(
        &self,
        session_data: &mut Sessiondata,
        commands: SmallVec<[SmtpCommand; 4]>,
        pending_restore_issue_trigger: &mut Option<&'static str>,
    ) {
        for cmd in commands {
            let dialog_text = match &cmd {
                SmtpCommand::Greeting(host) => Some(format!("EHLO {}", host)),
                SmtpCommand::MailFrom(email) => Some(format!("MAIL FROM:<{}>", email)),
                SmtpCommand::RcptTo(email) => Some(format!("RCPT TO:<{}>", email)),
                SmtpCommand::Data => Some("DATA".to_string()),
                SmtpCommand::DataEnd => Some(".(emaildataEnd)".to_string()),
                SmtpCommand::Quit => Some("QUIT".to_string()),
                SmtpCommand::Reset => Some("RSET".to_string()),
                SmtpCommand::StartTls => Some("STARTTLS".to_string()),
                SmtpCommand::Auth(arg) => {
                    let method = arg.split_whitespace().next().unwrap_or(arg);
                    if arg.len() > method.len() {
                        Some(format!("AUTH {} [REDACTED]", method))
                    } else {
                        Some(format!("AUTH {}", method))
                    }
                }
                SmtpCommand::AuthCredential {
                    method, username, ..
                } => Some(format!("AUTH {} (user: {})", method, username)),
                SmtpCommand::AuthResult(ok) => {
                    Some(format!("AUTH {}", if *ok { "Success" } else { "failed" }))
                }
                SmtpCommand::Other(_) => None,
            };

            if let Some(text) = dialog_text
                && session_data.session.content.smtp_dialog.len() < MAX_SMTP_DIALOG_ENTRIES
            {
                session_data.session.content.smtp_dialog.push(SmtpDialogEntry {
                    direction: Direction::Outbound,
                    command: text,
                    size: 0,
                    timestamp: chrono::Utc::now(),
                });
            }

            match cmd {
                SmtpCommand::MailFrom(email) => {
                    session_data.session.mail_from = Some(email);
                    if !session_data.dirty {
                        session_data.dirty = true;
                        self.dirty_queue.push(session_data.key.clone());
                    }
                    debug!("MAIL FROM: {:?}", session_data.session.mail_from);
                }
                SmtpCommand::RcptTo(email) => {
                    if !session_data.session.rcpt_to.contains(&email) {
                        session_data.session.rcpt_to.push(email);
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                    }
                    debug!("RCPT TO: {:?}", session_data.session.rcpt_to);
                }
                SmtpCommand::DataEnd => {
                    self.finalize_completed_smtp_email(
                        session_data,
                        "data_end",
                        "after DATA",
                    );
                }
                SmtpCommand::Quit => {
                    if session_data.session.status != SessionStatus::Timeout
                        && self.complete_session_if_needed(
                            &mut session_data.session,
                            &mut session_data.active_counter_open,
                        )
                    {
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                        info!("SessionEnd (QUIT): {}", session_data.session.id);
                        pending_restore_issue_trigger.get_or_insert("quit");
                    }
                }
                SmtpCommand::AuthCredential {
                    method,
                    username,
                    password,
                } => {
                    info!(
                        "🔑 Session {} SMTP AUTH credentials 原: method={} username={}",
                        session_data.session.id, method, username
                    );
                    session_data.session.auth_info = Some(SmtpAuthInfo {
                        auth_method: method,
                        username: Some(username),
                        password: Some(password),
                        auth_success: None,
                    });
                    if !session_data.dirty {
                        session_data.dirty = true;
                        self.dirty_queue.push(session_data.key.clone());
                    }
                }
                SmtpCommand::StartTls => {
                    debug!(
                        "🔒 Session {} STARTTLS CommandalreadySend，Waiting for server确认",
                        session_data.session.id
                    );
                }
                _ => {}
            }
        }
    }

    fn handle_smtp_server_progress(
        &self,
        session_data: &mut Sessiondata,
        responses: &[SmtpResponse],
        pending_restore_issue_trigger: &mut Option<&'static str>,
    ) {
        let pending_cmds = session_data
            .smtp_state
            .as_mut()
            .map(|s| s.take_pending_commands())
            .unwrap_or_default();

        for pending_cmd in pending_cmds {
            match pending_cmd {
                SmtpCommand::AuthResult(success) => {
                    if let Some(ref mut auth) = session_data.session.auth_info {
                        auth.auth_success = Some(success);
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                        info!(
                            "🔑 Session {} SMTP AUTH Result: {} (user: {:?})",
                            session_data.session.id,
                            if success { "Success" } else { "Failed" },
                            auth.username
                        );
                    }
                }
                SmtpCommand::DataEnd => {
                    self.finalize_completed_smtp_email(
                        session_data,
                        "server_pending_data_end",
                        "after pipelined DATA",
                    );
                }
                _ => {}
            }
        }

        for resp in responses {
            if session_data.session.content.smtp_dialog.len() < MAX_SMTP_DIALOG_ENTRIES {
                let desc = match resp.code {
                    220 => "Service就绪",
                    221 => "ServiceClose",
                    235 => "AuthenticationSuccess",
                    250 => "Operationscomplete",
                    334 => "RequestAuthenticationdata",
                    354 => "StartemailInput",
                    421 => "Service不可用",
                    450..=452 => "email不可用",
                    500..=503 => "CommandError",
                    535 => "Authenticationfailed",
                    550..=554 => "事务failed",
                    _ => "",
                };
                session_data.session.content.smtp_dialog.push(SmtpDialogEntry {
                    direction: Direction::Inbound,
                    command: if desc.is_empty() {
                        format!("{}", resp.code)
                    } else {
                        format!("{} {}", resp.code, desc)
                    },
                    size: 0,
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        for resp in responses {
            match resp.code {
                220 => {
                    let encrypted = session_data
                        .smtp_state
                        .as_ref()
                        .map(|s| s.is_encrypted())
                        .unwrap_or(false);
                    if encrypted {
                        session_data.session.content.is_encrypted = true;
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                        info!(
                            "🔒 Session {} STARTTLS already被ServiceDevice/Handler确认，Mark Encrypt",
                            session_data.session.id
                        );
                    }
                }
                221 => {
                    let pending_data = session_data
                        .smtp_state
                        .as_ref()
                        .map(|s| s.has_pending_data())
                        .unwrap_or(false);
                    let buffered_email_bytes = session_data
                        .smtp_state
                        .as_ref()
                        .map(|s| s.buffered_email_bytes())
                        .unwrap_or(0);
                    let saw_354 = Self::smtp_session_saw_354(&session_data.session);
                    let tcp_closed =
                        session_data.client_tcp_closed && session_data.server_tcp_closed;
                    if pending_data && !tcp_closed {
                        if saw_354 || buffered_email_bytes > 0 {
                            if session_data.session.status != SessionStatus::Timeout
                                && self.complete_session_if_needed(
                                    &mut session_data.session,
                                    &mut session_data.active_counter_open,
                                )
                            {
                                if !session_data.dirty {
                                    session_data.dirty = true;
                                    self.dirty_queue.push(session_data.key.clone());
                                }
                                info!(
                                    session_id = %session_data.session.id,
                                    packet_count = session_data.session.packet_count,
                                    total_bytes = session_data.session.total_bytes,
                                    buffered_email_bytes,
                                    saw_354,
                                    client_closed = session_data.client_tcp_closed,
                                    server_closed = session_data.server_tcp_closed,
                                    "Completing SMTP session on server 221 with pending DATA; salvaging without waiting for TCP close"
                                );
                                pending_restore_issue_trigger
                                    .get_or_insert("server_221_salvage");
                            }
                            continue;
                        }

                        self.maybe_log_smtp_pending_diagnostics(session_data, "server_221_deferred");
                        warn!(
                            session_id = %session_data.session.id,
                            packet_count = session_data.session.packet_count,
                            total_bytes = session_data.session.total_bytes,
                            buffered_email_bytes,
                            saw_354,
                            "Deferring SMTP 221 completion until TCP close/timeout"
                        );
                        continue;
                    }

                    if session_data.session.status != SessionStatus::Timeout
                        && self.complete_session_if_needed(
                            &mut session_data.session,
                            &mut session_data.active_counter_open,
                        )
                    {
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                        info!(
                            "SessionEnd (ServiceDevice/Handler 221): {}",
                            session_data.session.id
                        );
                        pending_restore_issue_trigger.get_or_insert("server_221");
                    }
                }
                _ => {}
            }
        }
    }

    fn try_restore_pending_smtp_payload_on_close(
        &self,
        session_data: &mut Sessiondata,
        trigger: &str,
    ) {
        if session_data.session.protocol != Protocol::Smtp
            || session_data.session.content.is_encrypted
            || Self::smtp_session_has_restored_payload(&session_data.session)
        {
            return;
        }

        self.try_lossy_fill_pending_smtp_client_bytes_on_close(session_data);
        if Self::smtp_session_has_restored_payload(&session_data.session) {
            return;
        }

        let pending_buffer_bytes = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.buffered_email_bytes())
            .unwrap_or(0);

        let pending_email = {
            let Some(smtp_state) = session_data.smtp_state.as_mut() else {
                return;
            };
            smtp_state.take_pending_email_for_close()
        };

        let Some((email_data, had_terminator)) = pending_email else {
            return;
        };

        match self.mime_parser.parse(&email_data) {
            Ok(content) => {
                session_data.session.email_count += 1;
                let is_complete = had_terminator
                    && session_data.client_stream.gap_bytes_skipped == 0
                    && session_data.server_stream.gap_bytes_skipped == 0;
                let headers_len = content.headers.len();
                let has_message_id = content.get_header("Message-ID").is_some();
                let has_subject = content.get_header("Subject").is_some();
                let body_text_len = content.body_text.as_ref().map_or(0, |body| body.len());
                let body_html_len = content.body_html.as_ref().map_or(0, |body| body.len());
                let header_names: Vec<String> = content
                    .headers
                    .iter()
                    .take(8)
                    .map(|(name, _)| name.clone())
                    .collect();
                if let Some(message_id) = self.record_smtp_restore(
                    &mut session_data.session,
                    &mut session_data.dirty,
                    &session_data.key,
                    session_data.client_stream.gap_bytes_skipped,
                    session_data.server_stream.gap_bytes_skipped,
                    content,
                    is_complete,
                    if had_terminator {
                        "close_salvage_terminated"
                    } else {
                        "close_salvage_truncated"
                    },
                ) {
                    self.enqueue_smtp_relay_probe(session_data, message_id);
                }
                if !has_message_id || !has_subject || (body_text_len == 0 && body_html_len == 0) {
                    self.stats
                        .smtp_pipeline
                        .smtp_close_salvage_partial
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        session_id = %session_data.session.id,
                        trigger,
                        had_terminator,
                        created_without_syn = session_data.created_without_syn,
                        pending_buffer_bytes,
                        headers_len,
                        has_message_id,
                        has_subject,
                        body_text_len,
                        body_html_len,
                        client_pending_segments = session_data.client_stream.pending_segments(),
                        server_pending_segments = session_data.server_stream.pending_segments(),
                        client_processed_offset = session_data.client_processed_offset,
                        server_processed_offset = session_data.server_processed_offset,
                        client_reassembled_len = session_data.client_stream.reassembled_len(),
                        server_reassembled_len = session_data.server_stream.reassembled_len(),
                        client_gap_bytes = session_data.client_stream.gap_bytes_skipped,
                        server_gap_bytes = session_data.server_stream.gap_bytes_skipped,
                        header_names = ?header_names,
                        "SMTP close salvage restored only partial headers/body"
                    );
                }
            }
            Err(e) => {
                self.stats
                    .smtp_pipeline
                    .smtp_mime_parse_failed
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    session_id = %session_data.session.id,
                    trigger,
                    payload_bytes = email_data.len(),
                    created_without_syn = session_data.created_without_syn,
                    pending_buffer_bytes,
                    had_terminator,
                    client_pending_segments = session_data.client_stream.pending_segments(),
                    server_pending_segments = session_data.server_stream.pending_segments(),
                    client_processed_offset = session_data.client_processed_offset,
                    server_processed_offset = session_data.server_processed_offset,
                    client_gap_bytes = session_data.client_stream.gap_bytes_skipped,
                    server_gap_bytes = session_data.server_stream.gap_bytes_skipped,
                    "SMTP MIME parse failed during close salvage: {:?}",
                    e
                );
            }
        }
    }

    fn try_lossy_fill_pending_smtp_client_bytes_on_close(&self, session_data: &mut Sessiondata) {
       // : has_pending_data() && buffered_email_bytes() == 0
       // : (buffered_email_bytes> 0)
       // TcpHalfStream pending segments, lossy reassembly,
       // MIME parse().
       // : pending segments SMTP, lossy fill.
        let smtp_has_pending = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.has_pending_data())
            .unwrap_or(false);
        let has_pending_segments = session_data.client_stream.pending_segments() > 0;
        if !smtp_has_pending && !has_pending_segments {
            return;
        }

        let prepend_shift = session_data.client_stream.prepend_shift;
        let (prepend_commands, commands, reassembled_len, total_gap_bytes) = {
            let (reassembled, total_gap_bytes) =
                session_data.client_stream.get_data_and_gap_bytes_lossy();
            let new_data_start = session_data
                .client_processed_offset
                .saturating_add(prepend_shift)
                .min(reassembled.len());

            let prepend_commands = if prepend_shift > 0 {
                let prepend_len = prepend_shift.min(reassembled.len());
                let already_processed_suffix = &reassembled[prepend_len..new_data_start];
                session_data
                    .smtp_state
                    .as_mut()
                    .expect("smtp state exists")
                    .process_late_client_prepend(&reassembled[..prepend_len], already_processed_suffix)
            } else {
                SmallVec::new()
            };

            let commands = if reassembled.len() > new_data_start {
                session_data
                    .smtp_state
                    .as_mut()
                    .expect("smtp state exists")
                    .process_client_data(&reassembled[new_data_start..])
            } else {
                SmallVec::new()
            };

            (prepend_commands, commands, reassembled.len(), total_gap_bytes)
        };

        if total_gap_bytes > session_data.client_gap_logged_bytes {
            self.stats
                .smtp_pipeline
                .smtp_client_gap_events
                .fetch_add(1, Ordering::Relaxed);
            let new_gap_bytes = total_gap_bytes - session_data.client_gap_logged_bytes;
            self.stats
                .smtp_pipeline
                .smtp_client_gap_bytes_total
                .fetch_add(new_gap_bytes as u64, Ordering::Relaxed);
            session_data.client_gap_logged_bytes = total_gap_bytes;
            warn!(
                session_id = %session_data.session.id,
                created_without_syn = session_data.created_without_syn,
                new_gap_bytes,
                total_gap_bytes,
                client_pending_segments = session_data.client_stream.pending_segments(),
                client_processed_offset = session_data.client_processed_offset,
                client_reassembled_len = session_data.client_stream.reassembled_len(),
                "SMTP close-path lossy gap skip: direction=client_to_server"
            );
        }

        let mut pending_restore_issue_trigger = None;
        self.handle_smtp_client_commands(
            session_data,
            prepend_commands,
            &mut pending_restore_issue_trigger,
        );
        self.handle_smtp_client_commands(session_data, commands, &mut pending_restore_issue_trigger);

        session_data.client_processed_offset = reassembled_len;
        session_data.client_stream.prepend_shift = 0;
    }

    #[inline]
    fn smtp_session_saw_354(session: &EmailSession) -> bool {
        session.content.smtp_dialog.iter().any(|entry| {
            entry.direction == Direction::Inbound && entry.command.as_bytes().starts_with(b"354")
        })
    }

    #[inline]
    fn smtp_pending_idle_timeout_applies(&self, session_data: &Sessiondata, idle: Duration) -> bool {
        if idle < self.smtp_pending_timeout
            || session_data.session.protocol != Protocol::Smtp
            || session_data.session.status != SessionStatus::Active
            || session_data.session.content.is_encrypted
        {
            return false;
        }

        session_data
            .smtp_state
            .as_ref()
            .map(|state| state.has_pending_data())
            .unwrap_or(false)
    }

    fn maybe_log_smtp_pending_diagnostics(&self, session_data: &mut Sessiondata, trigger: &str) {
        const SMTP_PENDING_DIAG_MIN_TOTAL_BYTES: usize = 16 * 1024;
        const SMTP_PENDING_DIAG_MIN_PACKETS: u32 = 16;

        if session_data.smtp_pending_diag_logged {
            return;
        }

        let Some(smtp_state) = session_data.smtp_state.as_ref() else {
            return;
        };

        if session_data.session.protocol != Protocol::Smtp
            || session_data.session.content.is_encrypted
            || Self::smtp_session_has_restored_payload(&session_data.session)
        {
            return;
        }

        let buffered_email_bytes = smtp_state.buffered_email_bytes();
        let data_pending = smtp_state.has_pending_data();
        let in_data_mode = smtp_state.is_in_data_mode();
        let saw_354 = Self::smtp_session_saw_354(&session_data.session);
        let looks_stuck_without_354 = !saw_354
            && (session_data.session.total_bytes >= SMTP_PENDING_DIAG_MIN_TOTAL_BYTES
                || session_data.session.packet_count >= SMTP_PENDING_DIAG_MIN_PACKETS
                || buffered_email_bytes > 0);
        let is_interesting = (data_pending || buffered_email_bytes > 0)
            && (looks_stuck_without_354
                || session_data.client_tcp_closed
                || session_data.server_tcp_closed);
        if !is_interesting {
            return;
        }

        let dialog_tail: Vec<String> = session_data
            .session
            .content
            .smtp_dialog
            .iter()
            .rev()
            .take(4)
            .map(|entry| entry.command.clone())
            .collect();

        session_data.smtp_pending_diag_logged = true;
        warn!(
            session_id = %session_data.session.id,
            trigger,
            created_without_syn = session_data.created_without_syn,
            client_ip = %session_data.session.client_ip,
            client_port = session_data.session.client_port,
            server_ip = %session_data.session.server_ip,
            server_port = session_data.session.server_port,
            status = ?session_data.session.status,
            packet_count = session_data.session.packet_count,
            total_bytes = session_data.session.total_bytes,
            email_count = session_data.session.email_count,
            idle_secs = session_data.last_activity.elapsed().as_secs_f32(),
            last_packet_at = %session_data.last_packet_at,
            last_packet_direction = ?session_data.last_packet_direction,
            last_packet_seq = session_data.last_packet_seq,
            last_packet_payload_len = session_data.last_packet_payload_len,
            last_packet_tcp_flags = session_data.last_packet_tcp_flags,
            last_packet_fin = (session_data.last_packet_tcp_flags & 0x01) != 0,
            last_packet_rst = (session_data.last_packet_tcp_flags & 0x04) != 0,
            buffered_email_bytes,
            in_data_mode,
            data_pending,
            saw_354,
            client_gap_bytes = session_data.client_stream.gap_bytes_skipped,
            server_gap_bytes = session_data.server_stream.gap_bytes_skipped,
            client_reassembled_len = session_data.client_stream.reassembled_len(),
            server_reassembled_len = session_data.server_stream.reassembled_len(),
            client_first_seq = ?session_data.client_stream.first_seq(),
            server_first_seq = ?session_data.server_stream.first_seq(),
            client_next_seq = ?session_data.client_stream.next_seq(),
            server_next_seq = ?session_data.server_stream.next_seq(),
            client_pending_segments = session_data.client_stream.pending_segments(),
            server_pending_segments = session_data.server_stream.pending_segments(),
            client_processed_offset = session_data.client_processed_offset,
            server_processed_offset = session_data.server_processed_offset,
            client_prepend_shift = session_data.client_stream.prepend_shift,
            server_prepend_shift = session_data.server_stream.prepend_shift,
            client_closed = session_data.client_tcp_closed,
            server_closed = session_data.server_tcp_closed,
            dialog_tail = ?dialog_tail,
            "SMTP session still has pending DATA state; waiting for close/timeout salvage"
        );
    }

    #[inline]
    fn maybe_log_plaintext_restore_issue(&self, session_data: &mut Sessiondata, trigger: &str) {
        if session_data.smtp_restore_issue_logged {
            return;
        }

        let Some(smtp_state) = session_data.smtp_state.as_ref() else {
            return;
        };

        if session_data.session.protocol != Protocol::Smtp
            || session_data.session.content.is_encrypted
        {
            return;
        }

        let restored_payload = Self::smtp_session_has_restored_payload(&session_data.session);
        let client_gap_bytes = session_data.client_stream.gap_bytes_skipped;
        let server_gap_bytes = session_data.server_stream.gap_bytes_skipped;
        let buffered_email_bytes = smtp_state.buffered_email_bytes();
        let in_data_mode = smtp_state.is_in_data_mode();
        let data_pending = smtp_state.has_pending_data();
        let email_count = session_data.session.email_count;
        let saw_354 = Self::smtp_session_saw_354(&session_data.session);

        let needs_attention = !restored_payload
            && (client_gap_bytes > 0
                || server_gap_bytes > 0
                || buffered_email_bytes > 0
                || in_data_mode
                || data_pending
                || email_count > 0);
        if !needs_attention {
            return;
        }

        let reason = if client_gap_bytes > 0 || server_gap_bytes > 0 {
            "stream_gap"
        } else if in_data_mode && buffered_email_bytes > 0 {
            "data_truncated_before_terminator"
        } else if data_pending && buffered_email_bytes == 0 && email_count == 0 && !saw_354 {
            "data_command_aborted_before_payload"
        } else if data_pending && buffered_email_bytes > 0 {
            "data_pending_or_missing_354"
        } else if data_pending {
            "data_pending_without_payload"
        } else if email_count > 0 {
            "mime_parse_failed_or_empty_payload"
        } else {
            "unknown"
        };

        let session_id = session_data.session.id;
        let mail_from = session_data.session.mail_from.clone();
        let rcpt_to_count = session_data.session.rcpt_to.len();
        let subject = session_data.session.subject.clone();
        let dialog_tail: Vec<String> = session_data
            .session
            .content
            .smtp_dialog
            .iter()
            .rev()
            .take(4)
            .map(|entry| entry.command.clone())
            .collect();
        let status = session_data.session.status;

        session_data.smtp_restore_issue_logged = true;
        if reason == "data_command_aborted_before_payload" {
            self.stats
                .smtp_pipeline
                .smtp_plaintext_aborted_before_payload
                .fetch_add(1, Ordering::Relaxed);
            info!(
                session_id = %session_id,
                trigger,
                reason,
                created_without_syn = session_data.created_without_syn,
                mail_from = ?mail_from,
                rcpt_to_count,
                subject = ?subject,
                email_count,
                client_gap_bytes,
                server_gap_bytes,
                buffered_email_bytes,
                in_data_mode,
                data_pending,
                client_pending_segments = session_data.client_stream.pending_segments(),
                server_pending_segments = session_data.server_stream.pending_segments(),
                client_processed_offset = session_data.client_processed_offset,
                server_processed_offset = session_data.server_processed_offset,
                client_reassembled_len = session_data.client_stream.reassembled_len(),
                server_reassembled_len = session_data.server_stream.reassembled_len(),
                idle_secs = session_data.last_activity.elapsed().as_secs_f32(),
                last_packet_at = %session_data.last_packet_at,
                last_packet_direction = ?session_data.last_packet_direction,
                last_packet_seq = session_data.last_packet_seq,
                last_packet_payload_len = session_data.last_packet_payload_len,
                last_packet_tcp_flags = session_data.last_packet_tcp_flags,
                status = ?status,
                client_closed = session_data.client_tcp_closed,
                server_closed = session_data.server_tcp_closed,
                dialog_tail = ?dialog_tail,
                "SMTP session closed before any DATA payload bytes arrived"
            );
            return;
        }

        match reason {
            "stream_gap" => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_without_restore_stream_gap
                    .fetch_add(1, Ordering::Relaxed);
            }
            "data_truncated_before_terminator" => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_without_restore_truncated
                    .fetch_add(1, Ordering::Relaxed);
            }
            "data_pending_or_missing_354" | "data_pending_without_payload" => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_without_restore_missing_354
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_without_restore_mime_or_empty
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        match trigger {
            "timeout" | "smtp_pending_idle_timeout" => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_timeout_without_restore
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.stats
                    .smtp_pipeline
                    .smtp_plaintext_tcp_close_without_restore
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        warn!(
            session_id = %session_id,
            trigger,
            reason,
            created_without_syn = session_data.created_without_syn,
            mail_from = ?mail_from,
            rcpt_to_count,
            subject = ?subject,
            email_count,
            client_gap_bytes,
            server_gap_bytes,
            buffered_email_bytes,
            in_data_mode,
            data_pending,
            client_pending_segments = session_data.client_stream.pending_segments(),
            server_pending_segments = session_data.server_stream.pending_segments(),
            client_processed_offset = session_data.client_processed_offset,
            server_processed_offset = session_data.server_processed_offset,
            client_reassembled_len = session_data.client_stream.reassembled_len(),
            server_reassembled_len = session_data.server_stream.reassembled_len(),
            idle_secs = session_data.last_activity.elapsed().as_secs_f32(),
            last_packet_at = %session_data.last_packet_at,
            last_packet_direction = ?session_data.last_packet_direction,
            last_packet_seq = session_data.last_packet_seq,
            last_packet_payload_len = session_data.last_packet_payload_len,
            last_packet_tcp_flags = session_data.last_packet_tcp_flags,
            status = ?status,
            client_closed = session_data.client_tcp_closed,
            server_closed = session_data.server_tcp_closed,
            dialog_tail = ?dialog_tail,
            "SMTP plaintext session ended without restored payload"
        );
    }

   /// Processdatapacket,ReturnProcessResult
   ///
   /// Performance optimizations:
   /// - Existing sessiononlyReturn ID,Avoid Session
   /// - Receive Option<&str> Reference,Avoid command
    #[inline]
    pub fn process_packet(
        &self,
        packet: &RawpacketInfo,
        command: Option<&str>,
        now: Instant,
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
        self.create_new_session(packet, key, command, now)
    }

   /// CreateNewSession (path,withSecurityCheck)
    #[cold]
    fn create_new_session(
        &self,
        packet: &RawpacketInfo,
        key: SessionKey,
        command: Option<&str>,
        now: Instant,
    ) -> ProcessResult {
       // SecurityCheck 1: SessionCountlimit
        if self.sessions.len() >= MAX_SESSIONS {
            self.rejected_connections.fetch_add(1, Ordering::Relaxed);
            warn!(
                "拒绝NewSession: already达到最largeSession数limit ({})",
                MAX_SESSIONS
            );
            return ProcessResult::Rejected;
        }

       // Getclient IP
        let client_ip = SessionKey::client_ip_from_packet(packet);

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

       // CreateNewSessiondata (possibly drop,if 1Thread)
        let session_data = self.create_session_data(packet, now, key.clone());

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
                    warn!(
                        session_id = %session_entry.session.id,
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
                }

               // ReturnNewSession (Need/Require,Butonly NewSession Occur)
                ProcessResult::New(session_entry.session.clone())
            }
            Entry::Occupied(occupied) => {
               // 1Threadalready Create Session - According toalready SessionProcess
                let mut session_ref = occupied.into_ref();
                session_ref.session.packet_count += 1;
                session_ref.session.total_bytes += packet.payload.len();
                Self::refresh_packet_activity(&mut session_ref, packet, now);

               // IP rate limitingof Add
                if let Some(entry) = self.ip_rate_limits.get(&client_ip) {
                    entry
                        .value()
                        .new_session_count
                        .fetch_sub(1, Ordering::Relaxed);
                    entry
                        .value()
                        .active_session_count
                        .fetch_sub(1, Ordering::Relaxed);
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
        let smtp_state = if packet.protocol == Protocol::Smtp {
            Some(SmtpStateMachine::new())
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
        const TCP_SYN: u8 = 0x02;

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
            client_stream: TcpHalfStream::new(),
            server_stream: TcpHalfStream::new(),
            client_processed_offset: 0,
            server_processed_offset: 0,
            client_gap_logged_bytes: 0,
            server_gap_logged_bytes: 0,
            active_counter_open: true,
            client_tcp_closed: false,
            server_tcp_closed: false,
            created_without_syn: (packet.tcp_flags & TCP_SYN) == 0,
            smtp_restore_issue_logged: false,
            smtp_pending_diag_logged: false,
            dirty: false,
            key,
            client_compact_ip,
        }
    }

   /// Use TCP stream reassemblyAnd SIMD Add Parse SMTP SessionInfo
   ///
   /// TCP stream reassemblyEnsuredatapacketAccording toSequenceNumber Process,immediately NetworkTransmissionMedium
    #[inline]
    fn parse_smtp_data_simd(
        &self,
        session_data: &mut Sessiondata,
        packet: &RawpacketInfo,
        _command: Option<&str>,
        now: Instant,
    ) {
       // packet: Markdirty dirtyQueue
        macro_rules! mark_dirty {
            ($sd:expr) => {
                if !$sd.dirty {
                    $sd.dirty = true;
                    self.dirty_queue.push($sd.key.clone());
                }
            };
        }
        let mut pending_restore_issue_trigger: Option<&'static str> = None;

       // packetlog: downgradelevel trace (pathPerformance notes)
        trace!(
            "📬 SMTP datapacket: {} | {:?} | seq={} | {} Byte",
            session_data.session.id,
            packet.direction,
            packet.tcp_seq,
            packet.payload.len(),
        );

       // TCP Constant
        const TCP_FIN: u8 = 0x01;
        const TCP_RST: u8 = 0x04;
        let saw_fin = (packet.tcp_flags & TCP_FIN) != 0;
        let saw_rst = (packet.tcp_flags & TCP_RST) != 0;
        if saw_fin || saw_rst {
            match packet.direction {
                Direction::Outbound => session_data.client_tcp_closed = true,
                Direction::Inbound => session_data.server_tcp_closed = true,
            }
        }

       // Midstream TLS detection: if payload starts with TLS record header (0x16 0x03 xx)
       // this is a session that entered STARTTLS before we started capturing.
       // Mark encrypted to avoid feeding TLS garbage into the SMTP parser.
        let packet_looks_like_tls = packet.payload.len() >= 3
            && packet.payload[0] == 0x16 // TLS Handshake
            && packet.payload[1] == 0x03 // TLS version major
            && packet.payload[2] <= 0x04; // TLS version minor (SSLv3..TLS1.3)
        if packet_looks_like_tls && !session_data.session.content.is_encrypted {
            session_data.session.content.is_encrypted = true;
            mark_dirty!(session_data);
        }

        let skip_smtp_payload_parse =
            session_data.session.content.is_encrypted || packet_looks_like_tls || saw_rst;
        if !skip_smtp_payload_parse {
            if session_data.smtp_state.is_none() {
                return;
            }

           // Create TCP Segment Add Streambuffer
            let segment = TcpSegment {
                seq: packet.tcp_seq,
                data: packet.payload.clone(), // Arc refcount +1, Avoid O(n) memcpy
                is_fin: saw_fin,
                is_rst: saw_rst,
                timestamp: now,
            };

           // according to Add ofStreambuffer
            match packet.direction {
                Direction::Outbound => {
                   // clientdata (Command emailContent)
                    if session_data.client_stream.add_segment(segment).is_err() {
                        self.stats
                            .smtp_pipeline
                            .smtp_client_stream_overflow
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            session_id = %session_data.session.id,
                            total_bytes = session_data.session.total_bytes,
                            in_data_mode = session_data
                                .smtp_state
                                .as_ref()
                                .map(|s| s.is_in_data_mode())
                                .unwrap_or(false),
                            buffered_email_bytes = session_data
                                .smtp_state
                                .as_ref()
                                .map(|s| s.buffered_email_bytes())
                                .unwrap_or(0),
                            "SMTP client stream buffer overflow"
                        );
                        mark_dirty!(session_data);
                        return;
                    }

                    let prepend_shift = session_data.client_stream.prepend_shift;
                    let (prepend_commands, commands, reassembled_len) = {
                        let (reassembled, total_gap_bytes) =
                            session_data.client_stream.get_data_and_gap_bytes();
                        if packet.protocol == Protocol::Smtp
                            && total_gap_bytes > session_data.client_gap_logged_bytes
                        {
                            self.stats
                                .smtp_pipeline
                                .smtp_client_gap_events
                                .fetch_add(1, Ordering::Relaxed);
                            let new_gap_bytes =
                                total_gap_bytes - session_data.client_gap_logged_bytes;
                            self.stats
                                .smtp_pipeline
                                .smtp_client_gap_bytes_total
                                .fetch_add(new_gap_bytes as u64, Ordering::Relaxed);
                            session_data.client_gap_logged_bytes = total_gap_bytes;
                            warn!(
                                "SMTP stream gap detected: session={} direction=client_to_server new_gap_bytes={} total_gap_bytes={} client={}:{} server={}:{}",
                                session_data.session.id,
                                new_gap_bytes,
                                total_gap_bytes,
                                session_data.session.client_ip,
                                session_data.session.client_port,
                                session_data.session.server_ip,
                                session_data.session.server_port
                            );
                        }

                        let new_data_start = session_data
                            .client_processed_offset
                            .saturating_add(prepend_shift)
                            .min(reassembled.len());

                        let prepend_commands = if prepend_shift > 0 {
                            let prepend_len = prepend_shift.min(reassembled.len());
                            let already_processed_suffix =
                                &reassembled[prepend_len..new_data_start];
                            session_data
                                .smtp_state
                                .as_mut()
                                .expect("smtp state exists")
                                .process_late_client_prepend(
                                    &reassembled[..prepend_len],
                                    already_processed_suffix,
                                )
                        } else {
                            SmallVec::new()
                        };

                        let commands = if reassembled.len() > new_data_start {
                            session_data
                                .smtp_state
                                .as_mut()
                                .expect("smtp state exists")
                                .process_client_data(&reassembled[new_data_start..])
                        } else {
                            SmallVec::new()
                        };

                        (prepend_commands, commands, reassembled.len())
                    };

                    self.handle_smtp_client_commands(
                        session_data,
                        prepend_commands,
                        &mut pending_restore_issue_trigger,
                    );
                    self.handle_smtp_client_commands(
                        session_data,
                        commands,
                        &mut pending_restore_issue_trigger,
                    );

                    session_data.client_processed_offset = reassembled_len;
                    session_data.client_stream.prepend_shift = 0;
                }
                Direction::Inbound => {
                   // ServicehandlerResponsedata (downgradelevel trace)
                    trace!(
                        "📥 SMTP ServiceDevice/HandlerResponse: {} | seq={} | {} Byte",
                        session_data.session.id,
                        packet.tcp_seq,
                        packet.payload.len(),
                    );

                    if session_data.server_stream.add_segment(segment).is_err() {
                        self.stats
                            .smtp_pipeline
                            .smtp_server_stream_overflow
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            session_id = %session_data.session.id,
                            total_bytes = session_data.session.total_bytes,
                            in_data_mode = session_data
                                .smtp_state
                                .as_ref()
                                .map(|s| s.is_in_data_mode())
                                .unwrap_or(false),
                            buffered_email_bytes = session_data
                                .smtp_state
                                .as_ref()
                                .map(|s| s.buffered_email_bytes())
                                .unwrap_or(0),
                            "SMTP server stream buffer overflow"
                        );
                        mark_dirty!(session_data);
                        return;
                    }

                    let prepend_shift = session_data.server_stream.prepend_shift;
                    let (prepend_responses, responses, reassembled_len) = {
                        let (reassembled, total_gap_bytes) =
                            session_data.server_stream.get_data_and_gap_bytes();
                        if packet.protocol == Protocol::Smtp
                            && total_gap_bytes > session_data.server_gap_logged_bytes
                        {
                            self.stats
                                .smtp_pipeline
                                .smtp_server_gap_events
                                .fetch_add(1, Ordering::Relaxed);
                            let new_gap_bytes =
                                total_gap_bytes - session_data.server_gap_logged_bytes;
                            self.stats
                                .smtp_pipeline
                                .smtp_server_gap_bytes_total
                                .fetch_add(new_gap_bytes as u64, Ordering::Relaxed);
                            session_data.server_gap_logged_bytes = total_gap_bytes;
                            warn!(
                                "SMTP stream gap detected: session={} direction=server_to_client new_gap_bytes={} total_gap_bytes={} client={}:{} server={}:{}",
                                session_data.session.id,
                                new_gap_bytes,
                                total_gap_bytes,
                                session_data.session.client_ip,
                                session_data.session.client_port,
                                session_data.session.server_ip,
                                session_data.session.server_port
                            );
                        }

                        let prepend_responses = if prepend_shift > 0
                            && session_data
                                .smtp_state
                                .as_ref()
                                .map(|s| s.has_pending_data())
                                .unwrap_or(false)
                        {
                            let prepend_len = prepend_shift.min(reassembled.len());
                            session_data
                                .smtp_state
                                .as_mut()
                                .expect("smtp state exists")
                                .process_server_response(&reassembled[..prepend_len])
                        } else {
                            SmallVec::new()
                        };

                        let new_data_start = session_data
                            .server_processed_offset
                            .saturating_add(prepend_shift)
                            .min(reassembled.len());

                        trace!(
                            "📥 ServiceDevice/Handlerstream reassembly: {} | alreadyreassemble={} | alreadyProcess={} | Newdata={}",
                            session_data.session.id,
                            reassembled.len(),
                            new_data_start,
                            reassembled.len().saturating_sub(new_data_start)
                        );

                        let responses = if reassembled.len() > new_data_start {
                            let new_data = &reassembled[new_data_start..];

                            trace!(
                                "📥 ProcessServiceDevice/HandlerResponse: {} | {} Byte",
                                session_data.session.id,
                                new_data.len(),
                            );

                            let responses = session_data
                                .smtp_state
                                .as_mut()
                                .expect("smtp state exists")
                                .process_server_response(new_data);

                            for resp in &responses {
                                trace!(
                                    "📥 SMTP ResponseCode/Digit: {} | code={} | is_data_mode={}",
                                    session_data.session.id,
                                    resp.code,
                                    session_data
                                        .smtp_state
                                        .as_ref()
                                        .expect("smtp state exists")
                                        .is_in_data_mode()
                                );
                            }

                            responses
                        } else {
                            SmallVec::new()
                        };

                        (prepend_responses, responses, reassembled.len())
                    };

                    self.handle_smtp_server_progress(
                        session_data,
                        &prepend_responses,
                        &mut pending_restore_issue_trigger,
                    );
                    self.handle_smtp_server_progress(
                        session_data,
                        &responses,
                        &mut pending_restore_issue_trigger,
                    );

                    session_data.server_processed_offset = reassembled_len;
                    session_data.server_stream.prepend_shift = 0;
                }
            }

           // : SIMD (Used for DATA Segmentof Parse)
            if !session_data
                .smtp_state
                .as_ref()
                .expect("smtp state exists")
                .is_in_data_mode()
            {
                let payload = &packet.payload[..];
               // SIMD Subject: (possibly emailHeaderMedium)
                if session_data.session.subject.is_none()
                    && let Some(subject) =
                        self.extract_subject_from_payload_fast(payload)
                {
                    session_data.session.subject = Some(subject);
                    mark_dirty!(session_data);
                    debug!(
                        "Subject (快速Parse): {:?}",
                        session_data.session.subject
                    );
                }
            }
        }

        self.maybe_log_smtp_pending_diagnostics(session_data, "post_packet_pending_data");

        let tcp_closed =
            saw_rst || (session_data.client_tcp_closed && session_data.server_tcp_closed);
        if tcp_closed
            && session_data.session.status != SessionStatus::Timeout
            && self.complete_session_if_needed(
                &mut session_data.session,
                &mut session_data.active_counter_open,
            )
        {
            mark_dirty!(session_data);
            info!(
                "SMTP session closed by TCP {}: session={} encrypted={} client_closed={} server_closed={}",
                if saw_rst { "RST" } else { "FIN" },
                session_data.session.id,
                session_data.session.content.is_encrypted,
                session_data.client_tcp_closed,
                session_data.server_tcp_closed
            );
            pending_restore_issue_trigger.get_or_insert(if saw_rst {
                "tcp_rst"
            } else {
                "tcp_fin"
            });
        }

        if let Some(trigger) = pending_restore_issue_trigger {
            self.try_restore_pending_smtp_payload_on_close(session_data, trigger);
            self.maybe_log_plaintext_restore_issue(session_data, trigger);
        }
    }

   /// ExtractemailAddress (Use memchr SIMD)
    #[inline(always)]
    #[allow(dead_code)]
    fn extract_email_fast(data: &[u8]) -> Option<String> {
        const MAX_EMAIL_LEN: usize = 256;

       // SIMD < And >
        let start = memchr::memchr(b'<', data)?;
        let end = memchr::memchr(b'>', &data[start + 1..])?;

        let email_bytes = &data[start + 1..start + 1 + end];

       // LengthCheck
        if email_bytes.len() > MAX_EMAIL_LEN {
            return None;
        }

       // ASCII Check
        if email_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"@.-_+".contains(&b))
        {
           // All bytes verified as ASCII subset -> valid UTF-8
            Some(
                String::from_utf8(email_bytes.to_vec())
                    .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
            )
        } else {
            None
        }
    }

    #[inline]
    pub(super) fn extract_subject_from_payload_fast(&self, payload: &[u8]) -> Option<String> {
       // Only scan the header section. This avoids false positives from MIME bodies
       // and DKIM h= parameter lists that happen to contain "Subject:".
        let header_end = memmem::find(payload, b"\r\n\r\n")
            .map(|pos| pos + 4)
            .or_else(|| memmem::find(payload, b"\n\n").map(|pos| pos + 2))
            .unwrap_or(payload.len());
        let scan_len = header_end.min(payload.len()).min(4096);
        let header_block = &payload[..scan_len];

        let mut search_offset = 0;
        while search_offset < header_block.len() {
            let rel = self.subject_finder.find(&header_block[search_offset..])?;
            let pos = search_offset + rel;

            if Self::is_header_line_start(header_block, pos)
                && let Some(subject) = Self::extract_subject_fast(&header_block[pos..])
            {
                return Some(subject);
            }

            search_offset = pos.saturating_add(b"Subject:".len());
        }

        None
    }

    #[inline(always)]
    fn is_header_line_start(data: &[u8], pos: usize) -> bool {
        pos == 0 || data.get(pos.wrapping_sub(1)) == Some(&b'\n')
    }

   /// Extract Subject
    #[inline(always)]
    fn extract_subject_fast(data: &[u8]) -> Option<String> {
       // hops "Subject:" (8 Byte)
        if data.len() < 9 {
            return None;
        }

        let rest = &data[8..];

       // SIMD line
        let end = memchr::memchr2(b'\r', b'\n', rest).unwrap_or(rest.len().min(200));

        let subject_bytes = &rest[..end];

       // UTF-8 Convert
        let subject = std::str::from_utf8(subject_bytes).ok()?.trim();

       // : DKIM h= ("Subject:"
       // DKIM-Signature h=From:To:Subject:Date;).
       // header.
        if subject.is_empty()
            || (subject.len() < 10 && subject.ends_with(';') && !subject.contains(' '))
        {
            return None;
        }

        Some(subject.to_string())
    }

   /// Extract Mark dirtyofSession (dirtyMark)
   /// Comment retained in English.
   /// O(dirty_count) : onlylookupdirtyQueueMediumofSession
   /// Performance optimizations: Batch key, AddLockProcess, Lock timestamp
    pub fn take_dirty_sessions(&self) -> Vec<EmailSession> {
       // 1. Batch pop key (LockOperations)
        let mut keys = Vec::with_capacity(64);
        while let Some(key) = self.dirty_queue.pop() {
            keys.push(key);
        }
        if keys.is_empty() {
            self.process_smtp_relay_diag_queue();
            return Vec::new();
        }

       // 2. short AddLockExtract dirtyMark
        let mut dirty = Vec::with_capacity(keys.len());
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

   /// Output SMTP restoration pipeline statistics log.
   /// Comment retained in English.
   /// This is the fast health signal for mirror-mode SMTP restoration:
   /// if complete mirrored packets are not reaching the restored-email path,
   /// the failure counters below should move immediately.
    pub fn log_smtp_pipeline_stats(&self) {
        let sp = &self.stats.smtp_pipeline;
        let restored_ok = sp.smtp_restored_ok.load(Ordering::Relaxed);
        let restored_with_gaps = sp.smtp_restored_with_gaps.load(Ordering::Relaxed);
        let mime_parse_failed = sp.smtp_mime_parse_failed.load(Ordering::Relaxed);
        let client_gap_events = sp.smtp_client_gap_events.load(Ordering::Relaxed);
        let client_gap_bytes_total = sp.smtp_client_gap_bytes_total.load(Ordering::Relaxed);
        let server_gap_events = sp.smtp_server_gap_events.load(Ordering::Relaxed);
        let server_gap_bytes_total = sp.smtp_server_gap_bytes_total.load(Ordering::Relaxed);
        let client_stream_overflow = sp.smtp_client_stream_overflow.load(Ordering::Relaxed);
        let server_stream_overflow = sp.smtp_server_stream_overflow.load(Ordering::Relaxed);
        let plaintext_tcp_close_without_restore = sp
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed);
        let plaintext_timeout_without_restore = sp
            .smtp_plaintext_timeout_without_restore
            .load(Ordering::Relaxed);
        let plaintext_aborted_before_payload = sp
            .smtp_plaintext_aborted_before_payload
            .load(Ordering::Relaxed);
        let unrestored_stream_gap = sp
            .smtp_plaintext_without_restore_stream_gap
            .load(Ordering::Relaxed);
        let unrestored_truncated = sp
            .smtp_plaintext_without_restore_truncated
            .load(Ordering::Relaxed);
        let unrestored_missing_354 = sp
            .smtp_plaintext_without_restore_missing_354
            .load(Ordering::Relaxed);
        let unrestored_mime_or_empty = sp
            .smtp_plaintext_without_restore_mime_or_empty
            .load(Ordering::Relaxed);
        let close_salvage_partial = sp.smtp_close_salvage_partial.load(Ordering::Relaxed);
        let unrestored_total =
            plaintext_tcp_close_without_restore + plaintext_timeout_without_restore;
        let total_observed = restored_ok
            + restored_with_gaps
            + mime_parse_failed
            + unrestored_total
            + plaintext_aborted_before_payload;
        let incomplete_or_failed =
            restored_with_gaps + mime_parse_failed + unrestored_total + close_salvage_partial;
        let incomplete_pct = if total_observed == 0 {
            0.0
        } else {
            incomplete_or_failed as f64 * 100.0 / total_observed as f64
        };

        if incomplete_or_failed > 0 {
            warn!(
                restored_ok = restored_ok,
                restored_with_gaps = restored_with_gaps,
                mime_parse_failed = mime_parse_failed,
                client_gap_events = client_gap_events,
                client_gap_bytes_total = client_gap_bytes_total,
                server_gap_events = server_gap_events,
                server_gap_bytes_total = server_gap_bytes_total,
                client_stream_overflow = client_stream_overflow,
                server_stream_overflow = server_stream_overflow,
                plaintext_tcp_close_without_restore = plaintext_tcp_close_without_restore,
                plaintext_timeout_without_restore = plaintext_timeout_without_restore,
                plaintext_aborted_before_payload = plaintext_aborted_before_payload,
                unrestored_stream_gap = unrestored_stream_gap,
                unrestored_truncated = unrestored_truncated,
                unrestored_missing_354 = unrestored_missing_354,
                unrestored_mime_or_empty = unrestored_mime_or_empty,
                close_salvage_partial = close_salvage_partial,
                incomplete_pct = incomplete_pct,
                total_observed = total_observed,
                "SMTP restore health degraded | restored_ok={} restored_with_gaps={} mime_parse_failed={} \
                 gap_events(client/server)={}/{} gap_bytes(client/server)={}/{} \
                 stream_overflow(client/server)={}/{} plaintext_without_restore(tcp_close/timeout)={}/{} \
                 reasons(stream_gap/truncated/missing_354/mime_or_empty)={}/{}/{}/{} \
                 partial_salvage={} aborted_before_payload={} incomplete_pct={:.2}%",
                restored_ok,
                restored_with_gaps,
                mime_parse_failed,
                client_gap_events,
                server_gap_events,
                client_gap_bytes_total,
                server_gap_bytes_total,
                client_stream_overflow,
                server_stream_overflow,
                plaintext_tcp_close_without_restore,
                plaintext_timeout_without_restore,
                unrestored_stream_gap,
                unrestored_truncated,
                unrestored_missing_354,
                unrestored_mime_or_empty,
                close_salvage_partial,
                plaintext_aborted_before_payload,
                incomplete_pct
            );
        } else {
            info!(
                restored_ok = restored_ok,
                restored_with_gaps = restored_with_gaps,
                mime_parse_failed = mime_parse_failed,
                client_gap_events = client_gap_events,
                client_gap_bytes_total = client_gap_bytes_total,
                server_gap_events = server_gap_events,
                server_gap_bytes_total = server_gap_bytes_total,
                client_stream_overflow = client_stream_overflow,
                server_stream_overflow = server_stream_overflow,
                total_observed = total_observed,
                "SMTP restore health clean | restored_ok={} restored_with_gaps={} mime_parse_failed={} \
                 gap_events(client/server)={}/{} gap_bytes(client/server)={}/{} \
                 stream_overflow(client/server)={}/{} total_observed={}",
                restored_ok,
                restored_with_gaps,
                mime_parse_failed,
                client_gap_events,
                server_gap_events,
                client_gap_bytes_total,
                server_gap_bytes_total,
                client_stream_overflow,
                server_stream_overflow,
                total_observed
            );
        }
    }

   /// Output HTTP dataSecurity pipeline Statisticslog
   /// Comment retained in English.
   /// linktracing: packet -> stream reassembly -> Requestsplit -> Sessionconstruct -> Queue -> Publish
   /// Any drop at any stage will be reflected here, used for troubleshooting.
    pub fn log_http_pipeline_stats(&self) {
        let hp = &self.stats.http_pipeline;
        let packets_total = hp.http_packets_total.load(Ordering::Relaxed);
        let packets_outbound = hp.http_packets_outbound.load(Ordering::Relaxed);
        let stream_overflow = hp.http_stream_overflow.load(Ordering::Relaxed);
        let requests_parsed = hp.http_requests_parsed.load(Ordering::Relaxed);
        let skipped_method = hp.http_requests_skipped_method.load(Ordering::Relaxed);
        let sessions_queued = hp.http_sessions_queued.load(Ordering::Relaxed);
        let dropped_queue = hp.http_sessions_dropped_queue_full.load(Ordering::Relaxed);
        let sessions_published = hp.http_sessions_published.load(Ordering::Relaxed);
        let connections_created = hp.http_connections_created.load(Ordering::Relaxed);
        let rejected_no_syn = hp.http_rejected_no_syn.load(Ordering::Relaxed);
        let queue_depth = self.http_queue_depth();

        info!(
            packets_total = packets_total,
            packets_outbound = packets_outbound,
            stream_overflow = stream_overflow,
            requests_parsed = requests_parsed,
            skipped_method = skipped_method,
            sessions_queued = sessions_queued,
            dropped_queue = dropped_queue,
            sessions_published = sessions_published,
            connections_created = connections_created,
            rejected_no_syn = rejected_no_syn,
            queue_depth = queue_depth,
            "HTTP dataSecurity Pipeline Statistics | \
             packet: 总={}(outbound={}) | StreamOverflow={} | \
             Request: Parse={} hops(非POST/PUT)={} | \
             Session: 入队={} Queuedrop={} alreadyPublish={} | \
             Connection: Create={} 拒绝(无SYN)={} | \
             Queuedepth={}",
            packets_total,
            packets_outbound,
            stream_overflow,
            requests_parsed,
            skipped_method,
            sessions_queued,
            dropped_queue,
            sessions_published,
            connections_created,
            rejected_no_syn,
            queue_depth,
        );

       // dropAlert: dropall Critical
        if dropped_queue > 0 {
            warn!(
                dropped = dropped_queue,
                queue_depth = queue_depth,
                "HTTP dataSecuritySessiondrop! QueueCapacity不足，possibly导致dataSecurity漏检"
            );
        }
        if stream_overflow > 0 {
            warn!(
                overflow = stream_overflow,
                "HTTP TCP StreambufferOverflow! possibly有超large HTTP Request或stream reassembly堆积"
            );
        }
    }

   /// CleanupTimeoutSession
   /// Comment retained in English.
   /// SegmentCleanup: Mark Timeout + flush dirty, Time/Count
   /// EnsureTimeoutSessionof Status Publish API, Avoiddata
   /// CleanupTimeoutSession (Periodic, Default 60)
   /// Comment retained in English.
   /// PerformanceAnalyze (O(n)):
   /// - DashMap::retain Traverse, Eachentry Instant (~5ns)
   /// - 50,000 sessions x 5ns = ~250μs Time/Count
   /// - 60, <5μs CPU,
   /// - 100,000 sessions (MAX_SESSIONS) ~500μs
   ///   Comment retained in English.
   ///   (timeout_candidates priorityQueue) Whenfirst value :
   /// - AddAddEach process_packet of (path writeQueue)
   /// - Need/RequireProcess / entry (Session Updatetimestamp)
   /// - When sessions 500K Performance notes
    pub fn cleanup_timeout_sessions(&self) {
        let now = Instant::now();
        let mut timed_out = 0;
        let mut removed = 0;

        self.sessions.retain(|_key, data| {
            let idle = now.duration_since(data.last_activity);
            let smtp_pending_idle_timeout = self.smtp_pending_idle_timeout_applies(data, idle);
            if idle <= self.timeout && !smtp_pending_idle_timeout {
                return true; // Period, keep
            }

            if data.session.status == SessionStatus::Active {
               // After1Time/CountTimeout: Mark Timeout, NewdirtyStatus
                data.session.status = SessionStatus::Timeout;
                data.session.ended_at = Some(chrono::Utc::now());

               // Markdirty, worker ThreadPublish Status
                if !data.dirty {
                    data.dirty = true;
                    self.dirty_queue.push(data.key.clone());
                }

                self.decrement_active_session_if_needed(&mut data.active_counter_open);

                let timeout_trigger = if smtp_pending_idle_timeout {
                    "smtp_pending_idle_timeout"
                } else {
                    "timeout"
                };
                let timeout_budget_secs = if smtp_pending_idle_timeout {
                    self.smtp_pending_timeout.as_secs_f32()
                } else {
                    self.timeout.as_secs_f32()
                };
                let smtp_in_data_mode = data.smtp_state.as_ref()
                    .map(|s| s.is_in_data_mode())
                    .unwrap_or(false);
                let smtp_data_pending = data
                    .smtp_state
                    .as_ref()
                    .map(|s| s.has_pending_data())
                    .unwrap_or(false);
                let buffered_email_bytes = data
                    .smtp_state
                    .as_ref()
                    .map(|s| s.buffered_email_bytes())
                    .unwrap_or(0);
                let has_content = data.session.content.body_text.is_some()
                    || data.session.content.body_html.is_some();

                warn!(
                    session_id = %data.session.id,
                    trigger = timeout_trigger,
                    protocol = %data.session.protocol,
                    created_without_syn = data.created_without_syn,
                    idle_secs = idle.as_secs_f32(),
                    timeout_budget_secs,
                    smtp_in_data_mode,
                    smtp_data_pending,
                    buffered_email_bytes,
                    has_content,
                    mail_from = ?data.session.mail_from,
                    rcpt_to = ?data.session.rcpt_to,
                    last_packet_at = %data.last_packet_at,
                    last_packet_direction = ?data.last_packet_direction,
                    last_packet_seq = data.last_packet_seq,
                    last_packet_payload_len = data.last_packet_payload_len,
                    last_packet_tcp_flags = data.last_packet_tcp_flags,
                    last_packet_fin = (data.last_packet_tcp_flags & 0x01) != 0,
                    last_packet_rst = (data.last_packet_tcp_flags & 0x04) != 0,
                    client_closed = data.client_tcp_closed,
                    server_closed = data.server_tcp_closed,
                    client_gap_bytes = data.client_stream.gap_bytes_skipped,
                    server_gap_bytes = data.server_stream.gap_bytes_skipped,
                    client_reassembled_len = data.client_stream.reassembled_len(),
                    server_reassembled_len = data.server_stream.reassembled_len(),
                    client_first_seq = ?data.client_stream.first_seq(),
                    server_first_seq = ?data.server_stream.first_seq(),
                    client_next_seq = ?data.client_stream.next_seq(),
                    server_next_seq = ?data.server_stream.next_seq(),
                    client_pending_segments = data.client_stream.pending_segments(),
                    server_pending_segments = data.server_stream.pending_segments(),
                    client_processed_offset = data.client_processed_offset,
                    server_processed_offset = data.server_processed_offset,
                    client_prepend_shift = data.client_stream.prepend_shift,
                    server_prepend_shift = data.server_stream.prepend_shift,
                    "⚠️ SessionTimeout fired"
                );

                if data.session.protocol == Protocol::Smtp {
                    self.try_restore_pending_smtp_payload_on_close(data, timeout_trigger);
                    self.maybe_log_plaintext_restore_issue(data, timeout_trigger);
                }

                timed_out += 1;
                return true; // keep, wait worker New
            }

           // Session (Timeout/Completed): only already New (dirty=false)
            if !data.dirty {
               // IP rate limitingcounter
                if let Some(entry) = self.ip_rate_limits.get(&data.client_compact_ip) {
                   // Saturating decrement to prevent underflow
                    let _ = entry.active_session_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |v| v.checked_sub(1),
                    );
                }
                removed += 1;
                return false; // Security
            }

            true // dirtydata, wait worker New
        });

        if timed_out > 0 {
            info!("TimeoutMark {} Session (waitWait刷New后移除)", timed_out);
        }
        if removed > 0 {
            info!("Cleanupalready刷Newof非活跃Session: {} ", removed);
        }

       // CleanupExpiredof IP rate limitingentry
        self.cleanup_ip_rate_limits();
    }

   /// CleanupExpiredof IP rate limitingentry
    fn cleanup_ip_rate_limits(&self) {
        let now_ns = IpRateLimitEntry::now_ns();
        let window_ns = RATE_LIMIT_WINDOW_SECS * 2 * 1_000_000_000;

        self.ip_rate_limits.retain(|_, entry| {
            let active = entry.active_session_count.load(Ordering::Relaxed);
            let window_start = entry.window_start_ns.load(Ordering::Relaxed);
            let window_expired = now_ns.saturating_sub(window_start) >= window_ns;
            !(active == 0 && window_expired)
        });
    }

}


impl Default for ShardedSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
