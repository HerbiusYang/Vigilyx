//! SMTP diagnostic snapshots, close-path salvage, and pending-state logging.

use super::*;
use smallvec::SmallVec;
use std::time::Duration;
use tracing::{info, warn};
use vigilyx_core::Protocol;

pub(super) struct SmtpRestoreDiagSnapshot {
    pub(super) restore_diag_hint: &'static str,
    pub(super) buffered_email_bytes: usize,
    pub(super) in_data_mode: bool,
    pub(super) data_pending: bool,
    pub(super) saw_354: bool,
    pub(super) client_pending_diag: TcpPendingSegmentsDiag,
    pub(super) server_pending_diag: TcpPendingSegmentsDiag,
    pub(super) client_gap_bytes: usize,
    pub(super) server_gap_bytes: usize,
    pub(super) client_pending_segments: usize,
    pub(super) server_pending_segments: usize,
    pub(super) client_prepend_shift: usize,
    pub(super) server_prepend_shift: usize,
    pub(super) client_reassembled_len: usize,
    pub(super) server_reassembled_len: usize,
    pub(super) client_first_seq: Option<u32>,
    pub(super) server_first_seq: Option<u32>,
    pub(super) client_next_seq: Option<u32>,
    pub(super) server_next_seq: Option<u32>,
    pub(super) dialog_tail: Vec<String>,
}

impl ShardedSessionManager {
    pub(super) fn try_restore_pending_smtp_payload_on_close(
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
        let diag_snapshot = Self::collect_smtp_restore_diag_snapshot(session_data);

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
                self.log_smtp_restore_resolution(
                    session_data,
                    &diag_snapshot,
                    if had_terminator {
                        "close_salvage_terminated"
                    } else {
                        "close_salvage_truncated"
                    },
                    "close salvage",
                    Some(trigger),
                    Some(had_terminator),
                    pending_buffer_bytes,
                );
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
                        restore_diag_hint = diag_snapshot.restore_diag_hint,
                        pending_buffer_bytes,
                        headers_len,
                        has_message_id,
                        has_subject,
                        body_text_len,
                        body_html_len,
                        client_pending_segments = session_data.client_stream.pending_segments(),
                        server_pending_segments = session_data.server_stream.pending_segments(),
                        client_pending_bytes = diag_snapshot.client_pending_diag.pending_bytes,
                        server_pending_bytes = diag_snapshot.server_pending_diag.pending_bytes,
                        client_waiting_for_seq = ?diag_snapshot.client_pending_diag.waiting_for_seq,
                        server_waiting_for_seq = ?diag_snapshot.server_pending_diag.waiting_for_seq,
                        client_first_pending_seq = ?diag_snapshot.client_pending_diag.first_pending_seq,
                        server_first_pending_seq = ?diag_snapshot.server_pending_diag.first_pending_seq,
                        client_gap_before_first_pending_bytes = diag_snapshot.client_pending_diag.first_gap_bytes,
                        server_gap_before_first_pending_bytes = diag_snapshot.server_pending_diag.first_gap_bytes,
                        client_pending_explanation = Self::smtp_pending_explanation(&diag_snapshot.client_pending_diag),
                        server_pending_explanation = Self::smtp_pending_explanation(&diag_snapshot.server_pending_diag),
                        client_pending_summary = %diag_snapshot.client_pending_diag,
                        server_pending_summary = %diag_snapshot.server_pending_diag,
                        client_processed_offset = session_data.client_processed_offset,
                        server_processed_offset = session_data.server_processed_offset,
                        client_reassembled_len = session_data.client_stream.reassembled_len(),
                        server_reassembled_len = session_data.server_stream.reassembled_len(),
                        client_gap_bytes = session_data.client_stream.gap_bytes_skipped,
                        server_gap_bytes = session_data.server_stream.gap_bytes_skipped,
                        owner_worker_id = ?session_data.owner_worker_id,
                        last_worker_id = ?session_data.last_worker_id,
                        worker_switch_count = session_data.worker_switch_count,
                        last_packet_at = %session_data.last_packet_at,
                        last_packet_direction = ?session_data.last_packet_direction,
                        last_packet_seq = session_data.last_packet_seq,
                        last_packet_payload_len = session_data.last_packet_payload_len,
                        last_packet_tcp_flags = session_data.last_packet_tcp_flags,
                        client_closed = session_data.client_tcp_closed,
                        server_closed = session_data.server_tcp_closed,
                        dialog_tail = ?diag_snapshot.dialog_tail,
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
                self.log_smtp_mime_parse_failure(
                    session_data,
                    &diag_snapshot,
                    email_data.len(),
                    "close salvage",
                    Some(if had_terminator {
                        "close_salvage_terminated"
                    } else {
                        "close_salvage_truncated"
                    }),
                    Some(trigger),
                    Some(had_terminator),
                    pending_buffer_bytes,
                    &e,
                );
            }
        }
    }

    pub(super) fn try_lossy_fill_pending_smtp_client_bytes_on_close(
        &self,
        session_data: &mut Sessiondata,
    ) {
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

            (
                prepend_commands,
                commands,
                reassembled.len(),
                total_gap_bytes,
            )
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
            let client_pending_diag = session_data.client_stream.pending_segments_diag();
            warn!(
                session_id = %session_data.session.id,
                created_without_syn = session_data.created_without_syn,
                new_gap_bytes,
                total_gap_bytes,
                client_pending_segments = session_data.client_stream.pending_segments(),
                client_pending_bytes = client_pending_diag.pending_bytes,
                client_waiting_for_seq = ?client_pending_diag.waiting_for_seq,
                client_first_pending_seq = ?client_pending_diag.first_pending_seq,
                client_gap_before_first_pending_bytes = client_pending_diag.first_gap_bytes,
                client_pending_explanation = Self::smtp_pending_explanation(&client_pending_diag),
                client_pending_summary = %client_pending_diag,
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
        self.handle_smtp_client_commands(
            session_data,
            commands,
            &mut pending_restore_issue_trigger,
        );

        session_data.client_processed_offset = reassembled_len;
        session_data.client_stream.prepend_shift = 0;
    }

    #[inline]
    pub(super) fn collect_smtp_restore_diag_snapshot(
        session_data: &Sessiondata,
    ) -> SmtpRestoreDiagSnapshot {
        let buffered_email_bytes = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.buffered_email_bytes())
            .unwrap_or(0);
        let in_data_mode = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.is_in_data_mode())
            .unwrap_or(false);
        let data_pending = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.has_pending_data())
            .unwrap_or(false);
        let client_pending_diag = session_data.client_stream.pending_segments_diag();
        let server_pending_diag = session_data.server_stream.pending_segments_diag();

        SmtpRestoreDiagSnapshot {
            restore_diag_hint: Self::smtp_restore_diag_hint(session_data),
            buffered_email_bytes,
            in_data_mode,
            data_pending,
            saw_354: Self::smtp_session_saw_354(&session_data.session),
            client_pending_segments: client_pending_diag.pending_segments,
            server_pending_segments: server_pending_diag.pending_segments,
            client_pending_diag,
            server_pending_diag,
            client_gap_bytes: session_data.client_stream.gap_bytes_skipped,
            server_gap_bytes: session_data.server_stream.gap_bytes_skipped,
            client_prepend_shift: session_data.client_stream.prepend_shift,
            server_prepend_shift: session_data.server_stream.prepend_shift,
            client_reassembled_len: session_data.client_stream.reassembled_len(),
            server_reassembled_len: session_data.server_stream.reassembled_len(),
            client_first_seq: session_data.client_stream.first_seq(),
            server_first_seq: session_data.server_stream.first_seq(),
            client_next_seq: session_data.client_stream.next_seq(),
            server_next_seq: session_data.server_stream.next_seq(),
            dialog_tail: Self::smtp_dialog_tail(session_data),
        }
    }

    #[inline]
    pub(super) fn should_log_smtp_restore_resolution(
        session_data: &Sessiondata,
        snapshot: &SmtpRestoreDiagSnapshot,
        restore_origin: &str,
    ) -> bool {
        restore_origin.starts_with("close_salvage")
            || restore_origin == "server_pending_data_end"
            || session_data.smtp_pending_diag_logged
            || session_data.worker_switch_count > 0
            || session_data.created_without_syn
            || snapshot.data_pending
            || snapshot.in_data_mode
            || snapshot.client_gap_bytes > 0
            || snapshot.server_gap_bytes > 0
            || snapshot.client_pending_segments > 0
            || snapshot.server_pending_segments > 0
            || snapshot.client_prepend_shift > 0
            || snapshot.server_prepend_shift > 0
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn log_smtp_restore_resolution(
        &self,
        session_data: &Sessiondata,
        snapshot: &SmtpRestoreDiagSnapshot,
        restore_origin: &str,
        parse_context: &str,
        trigger: Option<&str>,
        had_terminator: Option<bool>,
        pending_buffer_bytes: usize,
    ) {
        let body_text_len = session_data
            .session
            .content
            .body_text
            .as_ref()
            .map_or(0, |body| body.len());
        let body_html_len = session_data
            .session
            .content
            .body_html
            .as_ref()
            .map_or(0, |body| body.len());
        let should_warn = !session_data.session.content.is_complete
            || restore_origin.starts_with("close_salvage")
            || session_data.worker_switch_count > 0;

        macro_rules! emit_restore_resolution {
            ($log:path) => {
                $log!(
                    session_id = %session_data.session.id,
                    trigger,
                    restore_origin,
                    parse_context,
                    had_terminator = ?had_terminator,
                    pending_diag_logged = session_data.smtp_pending_diag_logged,
                    created_without_syn = session_data.created_without_syn,
                    restore_diag_hint = snapshot.restore_diag_hint,
                    mail_from = ?session_data.session.mail_from,
                    rcpt_to_count = session_data.session.rcpt_to.len(),
                    subject = ?session_data.session.subject,
                    email_count = session_data.session.email_count,
                    is_complete = session_data.session.content.is_complete,
                    body_text_len,
                    body_html_len,
                    attachments = session_data.session.content.attachments.len(),
                    links = session_data.session.content.links.len(),
                    pending_buffer_bytes,
                    buffered_email_bytes_before_parse = snapshot.buffered_email_bytes,
                    in_data_mode_before_parse = snapshot.in_data_mode,
                    data_pending_before_parse = snapshot.data_pending,
                    saw_354 = snapshot.saw_354,
                    client_gap_bytes = snapshot.client_gap_bytes,
                    server_gap_bytes = snapshot.server_gap_bytes,
                    client_pending_segments_before_parse = snapshot.client_pending_segments,
                    server_pending_segments_before_parse = snapshot.server_pending_segments,
                    client_pending_bytes_before_parse = snapshot.client_pending_diag.pending_bytes,
                    server_pending_bytes_before_parse = snapshot.server_pending_diag.pending_bytes,
                    client_waiting_for_seq_before_parse = ?snapshot.client_pending_diag.waiting_for_seq,
                    server_waiting_for_seq_before_parse = ?snapshot.server_pending_diag.waiting_for_seq,
                    client_first_pending_seq_before_parse = ?snapshot.client_pending_diag.first_pending_seq,
                    server_first_pending_seq_before_parse = ?snapshot.server_pending_diag.first_pending_seq,
                    client_gap_before_first_pending_bytes = snapshot.client_pending_diag.first_gap_bytes,
                    server_gap_before_first_pending_bytes = snapshot.server_pending_diag.first_gap_bytes,
                    client_pending_explanation = Self::smtp_pending_explanation(&snapshot.client_pending_diag),
                    server_pending_explanation = Self::smtp_pending_explanation(&snapshot.server_pending_diag),
                    client_pending_summary = %snapshot.client_pending_diag,
                    server_pending_summary = %snapshot.server_pending_diag,
                    client_prepend_shift_before_parse = snapshot.client_prepend_shift,
                    server_prepend_shift_before_parse = snapshot.server_prepend_shift,
                    client_processed_offset = session_data.client_processed_offset,
                    server_processed_offset = session_data.server_processed_offset,
                    client_reassembled_len = snapshot.client_reassembled_len,
                    server_reassembled_len = snapshot.server_reassembled_len,
                    client_first_seq = ?snapshot.client_first_seq,
                    server_first_seq = ?snapshot.server_first_seq,
                    client_next_seq = ?snapshot.client_next_seq,
                    server_next_seq = ?snapshot.server_next_seq,
                    owner_worker_id = ?session_data.owner_worker_id,
                    last_worker_id = ?session_data.last_worker_id,
                    worker_switch_count = session_data.worker_switch_count,
                    last_packet_at = %session_data.last_packet_at,
                    last_packet_direction = ?session_data.last_packet_direction,
                    last_packet_seq = session_data.last_packet_seq,
                    last_packet_payload_len = session_data.last_packet_payload_len,
                    last_packet_tcp_flags = session_data.last_packet_tcp_flags,
                    client_closed = session_data.client_tcp_closed,
                    server_closed = session_data.server_tcp_closed,
                    dialog_tail = ?snapshot.dialog_tail,
                    "SMTP restore path resolved with diagnostic context"
                );
            };
        }

        if should_warn {
            emit_restore_resolution!(warn);
        } else {
            emit_restore_resolution!(info);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn log_smtp_mime_parse_failure<E: std::fmt::Debug>(
        &self,
        session_data: &Sessiondata,
        snapshot: &SmtpRestoreDiagSnapshot,
        payload_bytes: usize,
        parse_context: &str,
        restore_origin: Option<&str>,
        trigger: Option<&str>,
        had_terminator: Option<bool>,
        pending_buffer_bytes: usize,
        error: &E,
    ) {
        warn!(
            session_id = %session_data.session.id,
            trigger,
            parse_context,
            restore_origin = restore_origin.unwrap_or("direct_parse"),
            had_terminator = ?had_terminator,
            pending_diag_logged = session_data.smtp_pending_diag_logged,
            created_without_syn = session_data.created_without_syn,
            restore_diag_hint = snapshot.restore_diag_hint,
            payload_bytes,
            pending_buffer_bytes,
            buffered_email_bytes_before_parse = snapshot.buffered_email_bytes,
            in_data_mode_before_parse = snapshot.in_data_mode,
            data_pending_before_parse = snapshot.data_pending,
            saw_354 = snapshot.saw_354,
            mail_from = ?session_data.session.mail_from,
            rcpt_to_count = session_data.session.rcpt_to.len(),
            subject = ?session_data.session.subject,
            email_count = session_data.session.email_count,
            client_gap_bytes = snapshot.client_gap_bytes,
            server_gap_bytes = snapshot.server_gap_bytes,
            client_pending_segments_before_parse = snapshot.client_pending_segments,
            server_pending_segments_before_parse = snapshot.server_pending_segments,
            client_pending_bytes_before_parse = snapshot.client_pending_diag.pending_bytes,
            server_pending_bytes_before_parse = snapshot.server_pending_diag.pending_bytes,
            client_waiting_for_seq_before_parse = ?snapshot.client_pending_diag.waiting_for_seq,
            server_waiting_for_seq_before_parse = ?snapshot.server_pending_diag.waiting_for_seq,
            client_first_pending_seq_before_parse = ?snapshot.client_pending_diag.first_pending_seq,
            server_first_pending_seq_before_parse = ?snapshot.server_pending_diag.first_pending_seq,
            client_gap_before_first_pending_bytes = snapshot.client_pending_diag.first_gap_bytes,
            server_gap_before_first_pending_bytes = snapshot.server_pending_diag.first_gap_bytes,
            client_pending_explanation = Self::smtp_pending_explanation(&snapshot.client_pending_diag),
            server_pending_explanation = Self::smtp_pending_explanation(&snapshot.server_pending_diag),
            client_pending_summary = %snapshot.client_pending_diag,
            server_pending_summary = %snapshot.server_pending_diag,
            client_prepend_shift_before_parse = snapshot.client_prepend_shift,
            server_prepend_shift_before_parse = snapshot.server_prepend_shift,
            client_processed_offset = session_data.client_processed_offset,
            server_processed_offset = session_data.server_processed_offset,
            client_reassembled_len = snapshot.client_reassembled_len,
            server_reassembled_len = snapshot.server_reassembled_len,
            client_first_seq = ?snapshot.client_first_seq,
            server_first_seq = ?snapshot.server_first_seq,
            client_next_seq = ?snapshot.client_next_seq,
            server_next_seq = ?snapshot.server_next_seq,
            owner_worker_id = ?session_data.owner_worker_id,
            last_worker_id = ?session_data.last_worker_id,
            worker_switch_count = session_data.worker_switch_count,
            last_packet_at = %session_data.last_packet_at,
            last_packet_direction = ?session_data.last_packet_direction,
            last_packet_seq = session_data.last_packet_seq,
            last_packet_payload_len = session_data.last_packet_payload_len,
            last_packet_tcp_flags = session_data.last_packet_tcp_flags,
            client_closed = session_data.client_tcp_closed,
            server_closed = session_data.server_tcp_closed,
            dialog_tail = ?snapshot.dialog_tail,
            "SMTP MIME parse failed: {:?}",
            error
        );
    }

    #[inline]
    pub(super) fn smtp_pending_explanation(diag: &TcpPendingSegmentsDiag) -> &'static str {
        if diag.pending_segments == 0 {
            "no_pending_segments_buffered_in_reassembly"
        } else if diag.first_gap_bytes > 0 {
            "waiting_for_missing_bytes_before_buffered_segments"
        } else if diag.waiting_for_seq.is_some() && diag.waiting_for_seq == diag.first_pending_seq {
            "buffered_segments_start_exactly_at_expected_seq"
        } else {
            "pending_segments_exist_but_head_gap_is_not_visible"
        }
    }

    #[inline]
    pub(super) fn smtp_dialog_tail(session_data: &Sessiondata) -> Vec<String> {
        session_data
            .session
            .content
            .smtp_dialog
            .iter()
            .rev()
            .take(4)
            .map(|entry| entry.command.clone())
            .collect()
    }

    #[inline]
    pub(super) fn smtp_restore_diag_hint(session_data: &Sessiondata) -> &'static str {
        let has_gap_signal = session_data.client_stream.gap_bytes_skipped > 0
            || session_data.server_stream.gap_bytes_skipped > 0;
        let has_pending_segments = session_data.client_stream.pending_segments() > 0
            || session_data.server_stream.pending_segments() > 0
            || session_data.client_stream.prepend_shift > 0
            || session_data.server_stream.prepend_shift > 0;
        let smtp_data_pending = session_data
            .smtp_state
            .as_ref()
            .map(|s| s.has_pending_data())
            .unwrap_or(false);

        if session_data.worker_switch_count > 0 {
            "cross_worker_processing_detected"
        } else if has_gap_signal {
            "tcp_gap_or_packet_loss_detected"
        } else if session_data.created_without_syn {
            "midstream_capture_or_missing_syn"
        } else if has_pending_segments {
            "out_of_order_or_missing_segment"
        } else if smtp_data_pending {
            "smtp_data_stalled_waiting_for_terminator_or_354"
        } else {
            "no_capture_side_signal"
        }
    }

    #[inline]
    pub(super) fn smtp_pending_idle_timeout_applies(
        &self,
        session_data: &Sessiondata,
        idle: Duration,
    ) -> bool {
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

    #[inline]
    pub(super) fn observe_session_worker(
        &self,
        session_data: &mut Sessiondata,
        packet: &RawpacketInfo,
        worker_id: Option<usize>,
    ) {
        let Some(worker_id) = worker_id else {
            return;
        };

        let owner_worker_id = *session_data.owner_worker_id.get_or_insert(worker_id);
        let last_worker_id = session_data.last_worker_id;
        session_data.last_worker_id = Some(worker_id);

        if owner_worker_id == worker_id {
            return;
        }

        session_data.worker_switch_count = session_data.worker_switch_count.saturating_add(1);
        if session_data.session.protocol == Protocol::Smtp {
            self.stats
                .smtp_pipeline
                .smtp_worker_mismatch_events
                .fetch_add(1, Ordering::Relaxed);
        }

        if session_data.worker_switch_count == 1 {
            warn!(
                session_id = %session_data.session.id,
                owner_worker_id,
                current_worker_id = worker_id,
                previous_worker_id = ?last_worker_id,
                packet_direction = ?packet.direction,
                packet_seq = packet.tcp_seq,
                packet_payload_len = packet.payload.len(),
                packet_tcp_flags = packet.tcp_flags,
                created_without_syn = session_data.created_without_syn,
                "Session packets observed on multiple workers; investigate worker routing / scheduling path"
            );
        }
    }

    pub(super) fn maybe_log_smtp_pending_diagnostics(
        &self,
        session_data: &mut Sessiondata,
        trigger: &str,
    ) {
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
        let client_pending_diag = session_data.client_stream.pending_segments_diag();
        let server_pending_diag = session_data.server_stream.pending_segments_diag();

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
            restore_diag_hint = Self::smtp_restore_diag_hint(session_data),
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
            client_processed_offset = session_data.client_processed_offset,
            server_processed_offset = session_data.server_processed_offset,
            client_prepend_shift = session_data.client_stream.prepend_shift,
            server_prepend_shift = session_data.server_stream.prepend_shift,
            owner_worker_id = ?session_data.owner_worker_id,
            last_worker_id = ?session_data.last_worker_id,
            worker_switch_count = session_data.worker_switch_count,
            client_closed = session_data.client_tcp_closed,
            server_closed = session_data.server_tcp_closed,
            dialog_tail = ?dialog_tail,
            "SMTP session still has pending DATA state; waiting for close/timeout salvage"
        );
    }

    #[inline]
    pub(super) fn maybe_log_plaintext_restore_issue(
        &self,
        session_data: &mut Sessiondata,
        trigger: &str,
    ) {
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
        let client_pending_diag = session_data.client_stream.pending_segments_diag();
        let server_pending_diag = session_data.server_stream.pending_segments_diag();

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
                restore_diag_hint = Self::smtp_restore_diag_hint(session_data),
                client_gap_bytes,
                server_gap_bytes,
                buffered_email_bytes,
                in_data_mode,
                data_pending,
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
                owner_worker_id = ?session_data.owner_worker_id,
                last_worker_id = ?session_data.last_worker_id,
                worker_switch_count = session_data.worker_switch_count,
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
            restore_diag_hint = Self::smtp_restore_diag_hint(session_data),
            client_gap_bytes,
            server_gap_bytes,
            buffered_email_bytes,
            in_data_mode,
            data_pending,
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
            owner_worker_id = ?session_data.owner_worker_id,
            last_worker_id = ?session_data.last_worker_id,
            worker_switch_count = session_data.worker_switch_count,
            status = ?status,
            client_closed = session_data.client_tcp_closed,
            server_closed = session_data.server_tcp_closed,
            dialog_tail = ?dialog_tail,
            "SMTP plaintext session ended without restored payload"
        );
    }
}
