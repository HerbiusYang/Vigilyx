//! Timeout cleanup and pipeline statistics logging.

use super::rate_limit::{IpRateLimitEntry, RATE_LIMIT_WINDOW_SECS};
use super::*;

impl ShardedSessionManager {
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
        let sessions_created_without_syn =
            sp.smtp_sessions_created_without_syn.load(Ordering::Relaxed);
        let worker_mismatch_events = sp.smtp_worker_mismatch_events.load(Ordering::Relaxed);
        let client_late_prepend_events = sp.smtp_client_late_prepend_events.load(Ordering::Relaxed);
        let client_late_prepend_bytes_total = sp
            .smtp_client_late_prepend_bytes_total
            .load(Ordering::Relaxed);
        let server_late_prepend_events = sp.smtp_server_late_prepend_events.load(Ordering::Relaxed);
        let server_late_prepend_bytes_total = sp
            .smtp_server_late_prepend_bytes_total
            .load(Ordering::Relaxed);
        let client_stream_overflow = sp.smtp_client_stream_overflow.load(Ordering::Relaxed);
        let server_stream_overflow = sp.smtp_server_stream_overflow.load(Ordering::Relaxed);
        let timeout_sessions_total = sp.smtp_timeout_sessions_total.load(Ordering::Relaxed);
        let pending_idle_timeout_sessions = sp
            .smtp_pending_idle_timeout_sessions
            .load(Ordering::Relaxed);
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
        let capture_side_anomalies = sessions_created_without_syn
            + client_gap_events
            + server_gap_events
            + client_late_prepend_events
            + server_late_prepend_events
            + client_stream_overflow
            + server_stream_overflow
            + pending_idle_timeout_sessions;
        let concurrency_side_anomalies = worker_mismatch_events;
        let restore_diag_hint = if worker_mismatch_events > 0 {
            "cross_worker_processing_detected"
        } else if capture_side_anomalies > 0 {
            "capture_gap_or_out_of_order_detected"
        } else {
            "no_concurrency_or_capture_signal"
        };
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
                sessions_created_without_syn = sessions_created_without_syn,
                worker_mismatch_events = worker_mismatch_events,
                client_late_prepend_events = client_late_prepend_events,
                client_late_prepend_bytes_total = client_late_prepend_bytes_total,
                server_late_prepend_events = server_late_prepend_events,
                server_late_prepend_bytes_total = server_late_prepend_bytes_total,
                client_stream_overflow = client_stream_overflow,
                server_stream_overflow = server_stream_overflow,
                timeout_sessions_total = timeout_sessions_total,
                pending_idle_timeout_sessions = pending_idle_timeout_sessions,
                plaintext_tcp_close_without_restore = plaintext_tcp_close_without_restore,
                plaintext_timeout_without_restore = plaintext_timeout_without_restore,
                plaintext_aborted_before_payload = plaintext_aborted_before_payload,
                unrestored_stream_gap = unrestored_stream_gap,
                unrestored_truncated = unrestored_truncated,
                unrestored_missing_354 = unrestored_missing_354,
                unrestored_mime_or_empty = unrestored_mime_or_empty,
                close_salvage_partial = close_salvage_partial,
                concurrency_side_anomalies = concurrency_side_anomalies,
                capture_side_anomalies = capture_side_anomalies,
                restore_diag_hint = restore_diag_hint,
                incomplete_pct = incomplete_pct,
                total_observed = total_observed,
                "SMTP restore health degraded | restored_ok={} restored_with_gaps={} mime_parse_failed={} \
                 gap_events(client/server)={}/{} gap_bytes(client/server)={}/{} \
                 created_without_syn={} worker_mismatch={} late_prepend(client/server)={}/{} bytes={}/{} \
                 stream_overflow(client/server)={}/{} timeout(total/pending_idle)={}/{} \
                 plaintext_without_restore(tcp_close/timeout)={}/{} \
                 reasons(stream_gap/truncated/missing_354/mime_or_empty)={}/{}/{}/{} \
                 partial_salvage={} aborted_before_payload={} diag_hint={} incomplete_pct={:.2}%",
                restored_ok,
                restored_with_gaps,
                mime_parse_failed,
                client_gap_events,
                server_gap_events,
                client_gap_bytes_total,
                server_gap_bytes_total,
                sessions_created_without_syn,
                worker_mismatch_events,
                client_late_prepend_events,
                server_late_prepend_events,
                client_late_prepend_bytes_total,
                server_late_prepend_bytes_total,
                client_stream_overflow,
                server_stream_overflow,
                timeout_sessions_total,
                pending_idle_timeout_sessions,
                plaintext_tcp_close_without_restore,
                plaintext_timeout_without_restore,
                unrestored_stream_gap,
                unrestored_truncated,
                unrestored_missing_354,
                unrestored_mime_or_empty,
                close_salvage_partial,
                plaintext_aborted_before_payload,
                restore_diag_hint,
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
                sessions_created_without_syn = sessions_created_without_syn,
                worker_mismatch_events = worker_mismatch_events,
                client_late_prepend_events = client_late_prepend_events,
                client_late_prepend_bytes_total = client_late_prepend_bytes_total,
                server_late_prepend_events = server_late_prepend_events,
                server_late_prepend_bytes_total = server_late_prepend_bytes_total,
                client_stream_overflow = client_stream_overflow,
                server_stream_overflow = server_stream_overflow,
                timeout_sessions_total = timeout_sessions_total,
                pending_idle_timeout_sessions = pending_idle_timeout_sessions,
                concurrency_side_anomalies = concurrency_side_anomalies,
                capture_side_anomalies = capture_side_anomalies,
                restore_diag_hint = restore_diag_hint,
                total_observed = total_observed,
                "SMTP restore health clean | restored_ok={} restored_with_gaps={} mime_parse_failed={} \
                 gap_events(client/server)={}/{} gap_bytes(client/server)={}/{} \
                 created_without_syn={} worker_mismatch={} late_prepend(client/server)={}/{} bytes={}/{} \
                 stream_overflow(client/server)={}/{} timeout(total/pending_idle)={}/{} diag_hint={} total_observed={}",
                restored_ok,
                restored_with_gaps,
                mime_parse_failed,
                client_gap_events,
                server_gap_events,
                client_gap_bytes_total,
                server_gap_bytes_total,
                sessions_created_without_syn,
                worker_mismatch_events,
                client_late_prepend_events,
                server_late_prepend_events,
                client_late_prepend_bytes_total,
                server_late_prepend_bytes_total,
                client_stream_overflow,
                server_stream_overflow,
                timeout_sessions_total,
                pending_idle_timeout_sessions,
                restore_diag_hint,
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
                if data.session.protocol == Protocol::Smtp {
                    self.stats
                        .smtp_pipeline
                        .smtp_timeout_sessions_total
                        .fetch_add(1, Ordering::Relaxed);
                    if smtp_pending_idle_timeout {
                        self.stats
                            .smtp_pipeline
                            .smtp_pending_idle_timeout_sessions
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
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
                let client_pending_diag = data.client_stream.pending_segments_diag();
                let server_pending_diag = data.server_stream.pending_segments_diag();
                let has_content = data.session.content.body_text.is_some()
                    || data.session.content.body_html.is_some();

                warn!(
                    session_id = %data.session.id,
                    trigger = timeout_trigger,
                    protocol = %data.session.protocol,
                    created_without_syn = data.created_without_syn,
                    restore_diag_hint = Self::smtp_restore_diag_hint(data),
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
                    client_processed_offset = data.client_processed_offset,
                    server_processed_offset = data.server_processed_offset,
                    client_prepend_shift = data.client_stream.prepend_shift,
                    server_prepend_shift = data.server_stream.prepend_shift,
                    owner_worker_id = ?data.owner_worker_id,
                    last_worker_id = ?data.last_worker_id,
                    worker_switch_count = data.worker_switch_count,
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
