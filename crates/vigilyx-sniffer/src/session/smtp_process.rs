//! SMTP protocol processing: parsing, command handling, and email finalization.

use super::*;
use memchr::memmem;
use smallvec::SmallVec;
use std::time::Instant;
use tracing::{debug, info, trace, warn};
use vigilyx_core::{
    Direction, EmailContent, EmailSession, MAX_SMTP_DIALOG_ENTRIES, Protocol, SessionStatus,
    SmtpAuthInfo, SmtpDialogEntry,
};

/// Mask a username for safe logging (CWE-532).
/// - `"user@domain.com"` → `"u***@domain.com"`
/// - `"admin"` → `"a***"`
/// - `""` → `"(empty)"`
fn mask_username(username: &str) -> String {
    if username.is_empty() {
        return "(empty)".to_string();
    }
    if let Some((local, domain)) = username.split_once('@') {
        let first = local.chars().next().unwrap_or('_');
        format!("{first}***@{domain}")
    } else {
        let first = username.chars().next().unwrap_or('_');
        format!("{first}***")
    }
}

impl ShardedSessionManager {
    #[inline]
    pub(super) fn smtp_session_has_restored_payload(session: &EmailSession) -> bool {
        session.content.body_text.is_some()
            || session.content.body_html.is_some()
            || !session.content.attachments.is_empty()
            || !session.content.headers.is_empty()
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
                    part[start + 1..].trim_end_matches('>').trim().to_string()
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
    pub(super) fn record_smtp_restore(
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
        let diag_snapshot = Self::collect_smtp_restore_diag_snapshot(session_data);
        let should_log_resolution =
            Self::should_log_smtp_restore_resolution(session_data, &diag_snapshot, restore_origin);
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
                self.log_smtp_mime_parse_failure(
                    session_data,
                    &diag_snapshot,
                    email_data.len(),
                    parse_context,
                    Some(restore_origin),
                    None,
                    None,
                    diag_snapshot.buffered_email_bytes,
                    &e,
                );
            }
        }

        if should_log_resolution && Self::smtp_session_has_restored_payload(&session_data.session) {
            self.log_smtp_restore_resolution(
                session_data,
                &diag_snapshot,
                restore_origin,
                parse_context,
                None,
                None,
                diag_snapshot.buffered_email_bytes,
            );
        }
    }

    pub(super) fn handle_smtp_client_commands(
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
                SmtpCommand::Bdat { size, is_last } => {
                    Some(format!("BDAT {}{}", size, if *is_last { " LAST" } else { "" }))
                }
            };

            if let Some(text) = dialog_text
                && session_data.session.content.smtp_dialog.len() < MAX_SMTP_DIALOG_ENTRIES
            {
                session_data
                    .session
                    .content
                    .smtp_dialog
                    .push(SmtpDialogEntry {
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
                    self.finalize_completed_smtp_email(session_data, "data_end", "after DATA");
                }
                SmtpCommand::Quit
                    if session_data.session.status != SessionStatus::Timeout
                        && self.complete_session_if_needed(
                            &mut session_data.session,
                            &mut session_data.active_counter_open,
                        ) =>
                {
                    if !session_data.dirty {
                        session_data.dirty = true;
                        self.dirty_queue.push(session_data.key.clone());
                    }
                    info!("SessionEnd (QUIT): {}", session_data.session.id);
                    pending_restore_issue_trigger.get_or_insert("quit");
                }
                SmtpCommand::Quit => {}
                SmtpCommand::AuthCredential {
                    method,
                    username,
                    password,
                } => {
                    info!(
                        "🔑 Session {} SMTP AUTH credentials: method={} username={}",
                        session_data.session.id, method, mask_username(&username)
                    );
                    // Password intentionally not captured (CWE-316: cleartext storage
                    // in memory). The password is never written to DB, so there is no
                    // reason to keep it in the session's memory for its entire lifetime.
                    drop(password);
                    session_data.session.auth_info = Some(SmtpAuthInfo {
                        auth_method: method,
                        username: Some(username),
                        password: None,
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
                session_data
                    .session
                    .content
                    .smtp_dialog
                    .push(SmtpDialogEntry {
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
                        let client_pending_diag =
                            session_data.client_stream.pending_segments_diag();
                        let server_pending_diag =
                            session_data.server_stream.pending_segments_diag();
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
                                    restore_diag_hint = Self::smtp_restore_diag_hint(session_data),
                                    client_pending_segments = session_data.client_stream.pending_segments(),
                                    server_pending_segments = session_data.server_stream.pending_segments(),
                                    client_pending_bytes = client_pending_diag.pending_bytes,
                                    server_pending_bytes = server_pending_diag.pending_bytes,
                                    client_waiting_for_seq = ?client_pending_diag.waiting_for_seq,
                                    server_waiting_for_seq = ?server_pending_diag.waiting_for_seq,
                                    client_first_pending_seq = ?client_pending_diag.first_pending_seq,
                                    server_first_pending_seq = ?server_pending_diag.first_pending_seq,
                                    client_gap_before_first_pending_bytes = client_pending_diag.first_gap_bytes,
                                    server_gap_before_first_pending_bytes = server_pending_diag.first_gap_bytes,
                                    client_pending_explanation = Self::smtp_pending_explanation(&client_pending_diag),
                                    server_pending_explanation = Self::smtp_pending_explanation(&server_pending_diag),
                                    client_pending_summary = %client_pending_diag,
                                    server_pending_summary = %server_pending_diag,
                                    client_closed = session_data.client_tcp_closed,
                                    server_closed = session_data.server_tcp_closed,
                                    "Completing SMTP session on server 221 with pending DATA; salvaging without waiting for TCP close"
                                );
                                pending_restore_issue_trigger.get_or_insert("server_221_salvage");
                            }
                            continue;
                        }

                        self.maybe_log_smtp_pending_diagnostics(
                            session_data,
                            "server_221_deferred",
                        );
                        warn!(
                            session_id = %session_data.session.id,
                            packet_count = session_data.session.packet_count,
                            total_bytes = session_data.session.total_bytes,
                            buffered_email_bytes,
                            saw_354,
                            restore_diag_hint = Self::smtp_restore_diag_hint(session_data),
                            client_pending_segments = session_data.client_stream.pending_segments(),
                            server_pending_segments = session_data.server_stream.pending_segments(),
                            client_pending_bytes = client_pending_diag.pending_bytes,
                            server_pending_bytes = server_pending_diag.pending_bytes,
                            client_waiting_for_seq = ?client_pending_diag.waiting_for_seq,
                            server_waiting_for_seq = ?server_pending_diag.waiting_for_seq,
                            client_first_pending_seq = ?client_pending_diag.first_pending_seq,
                            server_first_pending_seq = ?server_pending_diag.first_pending_seq,
                            client_gap_before_first_pending_bytes = client_pending_diag.first_gap_bytes,
                            server_gap_before_first_pending_bytes = server_pending_diag.first_gap_bytes,
                            client_pending_explanation = Self::smtp_pending_explanation(&client_pending_diag),
                            server_pending_explanation = Self::smtp_pending_explanation(&server_pending_diag),
                            client_pending_summary = %client_pending_diag,
                            server_pending_summary = %server_pending_diag,
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

    #[inline]
    pub(super) fn smtp_session_saw_354(session: &EmailSession) -> bool {
        session.content.smtp_dialog.iter().any(|entry| {
            entry.direction == Direction::Inbound && entry.command.as_bytes().starts_with(b"354")
        })
    }

    /// Use TCP stream reassemblyAnd SIMD Add Parse SMTP SessionInfo
    ///
    /// TCP stream reassemblyEnsuredatapacketAccording toSequenceNumber Process,immediately NetworkTransmissionMedium
    #[inline]
    pub(super) fn parse_smtp_data_simd(
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
                        let reassembled_len = reassembled.len();
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

                        if prepend_shift > 0 {
                            self.stats
                                .smtp_pipeline
                                .smtp_client_late_prepend_events
                                .fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .smtp_pipeline
                                .smtp_client_late_prepend_bytes_total
                                .fetch_add(prepend_shift as u64, Ordering::Relaxed);
                            warn!(
                                session_id = %session_data.session.id,
                                prepend_bytes = prepend_shift,
                                total_gap_bytes,
                                client_processed_offset = session_data.client_processed_offset,
                                client_reassembled_len = reassembled_len,
                                created_without_syn = session_data.created_without_syn,
                                owner_worker_id = ?session_data.owner_worker_id,
                                last_worker_id = ?session_data.last_worker_id,
                                worker_switch_count = session_data.worker_switch_count,
                                "SMTP client stream prepended older bytes after newer bytes were already reassembled"
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
                        let reassembled_len = reassembled.len();
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

                        if prepend_shift > 0 {
                            self.stats
                                .smtp_pipeline
                                .smtp_server_late_prepend_events
                                .fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .smtp_pipeline
                                .smtp_server_late_prepend_bytes_total
                                .fetch_add(prepend_shift as u64, Ordering::Relaxed);
                            warn!(
                                session_id = %session_data.session.id,
                                prepend_bytes = prepend_shift,
                                total_gap_bytes,
                                server_processed_offset = session_data.server_processed_offset,
                                server_reassembled_len = reassembled_len,
                                created_without_syn = session_data.created_without_syn,
                                owner_worker_id = ?session_data.owner_worker_id,
                                last_worker_id = ?session_data.last_worker_id,
                                worker_switch_count = session_data.worker_switch_count,
                                "SMTP server stream prepended older bytes after newer bytes were already reassembled"
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
                    && let Some(subject) = self.extract_subject_from_payload_fast(payload)
                {
                    session_data.session.subject = Some(subject);
                    mark_dirty!(session_data);
                    debug!("Subject (快速Parse): {:?}", session_data.session.subject);
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

            if is_header_line_start(header_block, pos)
                && let Some(subject) = extract_subject_fast(&header_block[pos..])
            {
                return Some(subject);
            }

            search_offset = pos.saturating_add(b"Subject:".len());
        }

        None
    }
}

#[inline(always)]
pub(super) fn is_header_line_start(data: &[u8], pos: usize) -> bool {
    pos == 0 || data.get(pos.wrapping_sub(1)) == Some(&b'\n')
}

/// Extract Subject
#[inline(always)]
pub(super) fn extract_subject_fast(data: &[u8]) -> Option<String> {
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
