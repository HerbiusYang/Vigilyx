use super::smtp_relay;
use super::*;
use crate::capture::{IpAddr, RawpacketInfo};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use vigilyx_core::{Direction, EmailSession, Protocol, SessionStatus};

fn smtp_packet(
    direction: Direction,
    client_port: u16,
    server_port: u16,
    tcp_seq: u32,
    tcp_flags: u8,
    payload: &'static [u8],
) -> RawpacketInfo {
    match direction {
        Direction::Outbound => RawpacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            payload: Bytes::from_static(payload),
            src_port: client_port,
            dst_port: server_port,
            protocol: Protocol::Smtp,
            direction,
            tcp_seq,
            tcp_ack: 0,
            tcp_flags,
        },
        Direction::Inbound => RawpacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            payload: Bytes::from_static(payload),
            src_port: server_port,
            dst_port: client_port,
            protocol: Protocol::Smtp,
            direction,
            tcp_seq,
            tcp_ack: 0,
            tcp_flags,
        },
    }
}

fn smtp_packet_between(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> RawpacketInfo {
    RawpacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(src_ip[0], src_ip[1], src_ip[2], src_ip[3])),
        dst_ip: IpAddr::V4(Ipv4Addr::new(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])),
        payload: Bytes::from_static(b""),
        src_port,
        dst_port,
        protocol: Protocol::Smtp,
        direction: Direction::Outbound,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_flags: 0x18,
    }
}

fn second_hop_probe(
    started_at: chrono::DateTime<chrono::Utc>,
    message_id: &str,
    mail_from: &str,
    rcpt_to: &[&str],
    subject: Option<&str>,
) -> smtp_relay::SmtpRelayCorrelationProbe {
    smtp_relay::SmtpRelayCorrelationProbe {
        session_id: "second-hop-session".to_string(),
        started_at,
        client_ip: smtp_relay::SMTP_SECOND_HOP_CLIENT_IP.to_string(),
        server_ip: smtp_relay::SMTP_SECOND_HOP_SERVER_IP.to_string(),
        message_id: message_id.to_string(),
        mail_from: Some(mail_from.to_string()),
        rcpt_to: rcpt_to.iter().map(|addr| (*addr).to_string()).collect(),
        subject: subject.map(|value| value.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_first_hop_session(
    manager: &ShardedSessionManager,
    _session_id: &str,
    started_at: chrono::DateTime<chrono::Utc>,
    last_packet_at: chrono::DateTime<chrono::Utc>,
    mail_from: Option<&str>,
    rcpt_to: &[&str],
    subject: Option<&str>,
    message_id: Option<&str>,
    has_restored_payload: bool,
    is_complete: bool,
) {
    let packet = smtp_packet_between([10, 1, 246, 40], [10, 1, 246, 41], 40000, 25);
    let key = SessionKey::new(&packet);
    let mut session_data = manager.create_session_data(&packet, Instant::now(), key.clone());

    session_data.session.started_at = started_at;
    session_data.last_packet_at = last_packet_at;
    session_data.session.status = SessionStatus::Completed;
    session_data.session.ended_at = Some(last_packet_at);
    session_data.session.mail_from = mail_from.map(|value| value.to_string());
    session_data.session.rcpt_to = rcpt_to.iter().map(|addr| (*addr).to_string()).collect();
    session_data.session.subject = subject.map(|value| value.to_string());
    session_data.session.message_id = message_id.map(|value| value.to_string());
    session_data.session.email_count = u32::from(has_restored_payload || message_id.is_some());
    session_data.session.content.is_complete = is_complete;
    if let Some(message_id) = message_id {
        session_data
            .session
            .content
            .headers
            .push(("Message-ID".to_string(), message_id.to_string()));
    }
    if let Some(subject) = subject {
        session_data
            .session
            .content
            .headers
            .push(("Subject".to_string(), subject.to_string()));
    }
    if has_restored_payload {
        session_data.session.content.body_text = Some("body".to_string());
    }
    session_data.active_counter_open = false;
    session_data.dirty = false;

    manager.sessions.insert(key, session_data);
}

#[test]
fn fast_subject_scan_ignores_dkim_h_tag_false_positive() {
    let manager = ShardedSessionManager::new();
    let payload = b"DKIM-Signature: v=1; h=From:To:Subject:Date; b=abc123\r\n\r\nbody";

    assert_eq!(manager.extract_subject_from_payload_fast(payload), None);
}

#[test]
fn fast_subject_scan_prefers_real_subject_header_line() {
    let manager = ShardedSessionManager::new();
    let payload = b"Received: from relay.example\r\nDKIM-Signature: v=1; h=From:To:Subject:Date; b=abc123\r\nSubject: Quarterly update\r\n\r\nbody";

    assert_eq!(
        manager
            .extract_subject_from_payload_fast(payload)
            .as_deref(),
        Some("Quarterly update")
    );
}

#[test]
fn take_dirty_sessions_keeps_terminal_empty_updates() {
    let manager = ShardedSessionManager::new();
    let packet = smtp_packet(Direction::Outbound, 35000, 25, 100, 0x18, b"EHLO test\r\n");
    let key = SessionKey::new(&packet);

    let _ = manager.process_packet(&packet, None, Instant::now());
    {
        let mut entry = manager.sessions.get_mut(&key).expect("session must exist");
        entry.session.status = SessionStatus::Completed;
        entry.session.ended_at = Some(chrono::Utc::now());
        entry.session.mail_from = None;
        entry.session.rcpt_to.clear();
        entry.session.subject = None;
        entry.session.content = Default::default();
        entry.dirty = true;
    }
    manager.dirty_queue.push(key.clone());

    let dirty = manager.take_dirty_sessions();
    assert_eq!(dirty.len(), 1);
    assert_eq!(dirty[0].status, SessionStatus::Completed);
}

#[test]
fn quit_completes_session_and_decrements_active_once() {
    let manager = ShardedSessionManager::new();

    let quit = smtp_packet(Direction::Outbound, 35001, 25, 200, 0x18, b"QUIT\r\n");
    let bye = smtp_packet(Direction::Inbound, 35001, 25, 300, 0x18, b"221 Bye\r\n");

    let _ = manager.process_packet(&quit, None, Instant::now());
    assert_eq!(manager.get_stats().active_sessions, 0);

    let dirty_after_quit = manager.take_dirty_sessions();
    assert_eq!(dirty_after_quit.len(), 1);
    assert_eq!(dirty_after_quit[0].status, SessionStatus::Completed);

    let _ = manager.process_packet(&bye, None, Instant::now());
    assert_eq!(manager.get_stats().active_sessions, 0);
}

#[test]
fn same_session_on_different_workers_records_diagnostic_signal() {
    let manager = ShardedSessionManager::new();
    let packet1 = smtp_packet(Direction::Outbound, 35011, 25, 100, 0x18, b"EHLO test\r\n");
    let packet2 = smtp_packet(
        Direction::Outbound,
        35011,
        25,
        120,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let key = SessionKey::new(&packet1);

    let _ = manager.process_packet_with_worker(&packet1, None, Instant::now(), Some(1));
    let _ = manager.process_packet_with_worker(&packet2, None, Instant::now(), Some(2));

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(entry.owner_worker_id, Some(1));
    assert_eq!(entry.last_worker_id, Some(2));
    assert_eq!(entry.worker_switch_count, 1);
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_worker_mismatch_events
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn relay_probe_reports_missing_first_hop_when_none_exists() {
    let manager = ShardedSessionManager::new();
    let probe = second_hop_probe(
        chrono::Utc::now(),
        "<missing@example.com>",
        "sender@example.com",
        &["recipient@example.com"],
        Some("missing first hop"),
    );

    let issue = manager
        .find_smtp_first_hop_correlation_issue(&probe)
        .expect("missing first hop should produce diagnostic");

    assert_eq!(
        issue.kind,
        smtp_relay::SmtpRelayCorrelationIssueKind::NoMatchingFirstHopSession
    );
    assert_eq!(issue.window_candidate_count, 0);
    assert_eq!(issue.same_envelope_candidate_count, 0);
}

#[test]
fn relay_probe_reports_same_envelope_first_hop_without_matching_message_id() {
    let manager = ShardedSessionManager::new();
    let probe_started_at = chrono::Utc::now();
    let probe = second_hop_probe(
        probe_started_at,
        "<second-hop@example.com>",
        "sender@example.com",
        &["recipient@example.com"],
        Some("same envelope"),
    );

    insert_first_hop_session(
        &manager,
        "first-hop-envelope-only",
        probe_started_at - chrono::Duration::seconds(5),
        probe_started_at - chrono::Duration::seconds(1),
        Some("sender@example.com"),
        &["recipient@example.com"],
        None,
        None,
        false,
        false,
    );

    let issue = manager
        .find_smtp_first_hop_correlation_issue(&probe)
        .expect("same-envelope gap should produce diagnostic");

    assert_eq!(
        issue.kind,
        smtp_relay::SmtpRelayCorrelationIssueKind::SameEnvelopeFirstHopWithoutMatchingMessageId
    );
    assert_eq!(issue.window_candidate_count, 1);
    assert_eq!(issue.same_envelope_candidate_count, 1);
    assert_eq!(issue.same_envelope_candidates.len(), 1);
}

#[test]
fn relay_probe_ignores_when_exact_first_hop_message_id_exists() {
    let manager = ShardedSessionManager::new();
    let probe_started_at = chrono::Utc::now();
    let probe = second_hop_probe(
        probe_started_at,
        "<exact-match@example.com>",
        "sender@example.com",
        &["recipient@example.com"],
        Some("exact match"),
    );

    insert_first_hop_session(
        &manager,
        "first-hop-exact",
        probe_started_at - chrono::Duration::seconds(4),
        probe_started_at - chrono::Duration::seconds(1),
        Some("sender@example.com"),
        &["recipient@example.com"],
        Some("exact match"),
        Some("<exact-match@example.com>"),
        true,
        true,
    );

    assert!(
        manager
            .find_smtp_first_hop_correlation_issue(&probe)
            .is_none(),
        "exact Message-ID match should suppress correlation warning"
    );
}

#[test]
fn attachments_count_as_restored_payload() {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.10".to_string(),
        35002,
        "10.0.0.20".to_string(),
        25,
    );
    session
        .content
        .attachments
        .push(vigilyx_core::EmailAttachment {
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 4,
            hash: "deadbeef".to_string(),
            content_base64: Some("dGVzdA==".to_string()),
        });

    assert!(ShardedSessionManager::smtp_session_has_restored_payload(
        &session
    ));
}

#[test]
fn headers_count_as_restored_payload() {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "10.0.0.10".to_string(),
        35002,
        "10.0.0.20".to_string(),
        25,
    );
    session
        .content
        .headers
        .push(("Subject".to_string(), "header-only".to_string()));

    assert!(ShardedSessionManager::smtp_session_has_restored_payload(
        &session
    ));
}

#[test]
fn plaintext_rst_with_pending_data_is_salvaged_as_incomplete_restore() {
    let manager = ShardedSessionManager::new();
    let data = smtp_packet(Direction::Outbound, 35003, 25, 100, 0x18, b"DATA\r\n");
    let key = SessionKey::new(&data);

    let ready = smtp_packet(
        Direction::Inbound,
        35003,
        25,
        200,
        0x18,
        b"354 go ahead\r\n",
    );
    let partial_body = smtp_packet(
        Direction::Outbound,
        35003,
        25,
        106,
        0x18,
        b"Subject: test\r\n\r\npartial body without terminator",
    );
    let rst = smtp_packet(Direction::Inbound, 35003, 25, 215, 0x04, b"");

    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&ready, None, Instant::now());
    let _ = manager.process_packet(&partial_body, None, Instant::now());
    let _ = manager.process_packet(&rst, None, Instant::now());

    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_restored_with_gaps
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed),
        0
    );

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.email_count, 1);
    assert!(!session.session.content.is_complete);
    assert!(
        session
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("partial body without terminator")
    );
}

#[test]
fn close_salvages_pipelined_data_without_354_as_complete_restore() {
    let manager = ShardedSessionManager::new();
    let data = smtp_packet(Direction::Outbound, 35004, 25, 100, 0x18, b"DATA\r\n");
    let key = SessionKey::new(&data);
    let pipelined_body = smtp_packet(
        Direction::Outbound,
        35004,
        25,
        106,
        0x18,
        b"Subject: pipelined\r\n\r\nhello from buffered data\r\n.\r\n",
    );
    let fin_client = smtp_packet(Direction::Outbound, 35004, 25, 160, 0x11, b"");
    let fin_server = smtp_packet(Direction::Inbound, 35004, 25, 200, 0x11, b"");

    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&pipelined_body, None, Instant::now());
    let _ = manager.process_packet(&fin_client, None, Instant::now());
    let _ = manager.process_packet(&fin_server, None, Instant::now());

    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_restored_ok
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed),
        0
    );

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.email_count, 1);
    assert!(session.session.content.is_complete);
    assert!(
        session
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("hello from buffered data")
    );
}

#[test]
fn server_221_with_pending_data_waits_for_real_close() {
    let manager = ShardedSessionManager::new();

    let mail_from = smtp_packet(
        Direction::Outbound,
        35005,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35005,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35005, 25, 165, 0x18, b"DATA\r\n");
    let bye = smtp_packet(Direction::Inbound, 35005, 25, 200, 0x18, b"221 Bye\r\n");
    let key = SessionKey::new(&data);

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&bye, None, Instant::now());

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.status, SessionStatus::Active);
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn smtp_pending_data_idle_timeout_salvages_before_global_timeout() {
    let manager =
        ShardedSessionManager::with_timeouts(Duration::from_secs(900), Duration::from_secs(60));

    let mail_from = smtp_packet(
        Direction::Outbound,
        35010,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35010,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35010, 25, 165, 0x18, b"DATA\r\n");
    let pipelined_body = smtp_packet(
        Direction::Outbound,
        35010,
        25,
        171,
        0x18,
        b"Subject: idle-timeout\r\n\r\nbody waiting for salvage",
    );
    let key = SessionKey::new(&data);

    let now = Instant::now();
    let _ = manager.process_packet(&mail_from, None, now);
    let _ = manager.process_packet(&rcpt_to, None, now);
    let _ = manager.process_packet(&data, None, now);
    let _ = manager.process_packet(&pipelined_body, None, now);

    {
        let mut session = manager.sessions.get_mut(&key).expect("session must exist");
        session.last_activity = Instant::now() - Duration::from_secs(61);
    }

    manager.cleanup_timeout_sessions();

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.status, SessionStatus::Timeout);
    assert_eq!(session.session.email_count, 1);
    assert_eq!(session.session.subject.as_deref(), Some("idle-timeout"));
    assert!(session.session.ended_at.is_some());
}

#[test]
fn late_prepended_354_replays_buffered_body() {
    let manager = ShardedSessionManager::new();
    let mail_from = smtp_packet(
        Direction::Outbound,
        35006,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35006,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35006, 25, 165, 0x18, b"DATA\r\n");
    let pipelined_body = smtp_packet(
        Direction::Outbound,
        35006,
        25,
        171,
        0x18,
        b"Subject: prepend\r\n\r\nhello from replay\r\n.\r\n",
    );
    let queued = smtp_packet(Direction::Inbound, 35006, 25, 214, 0x18, b"250 queued\r\n");
    let ready = smtp_packet(
        Direction::Inbound,
        35006,
        25,
        200,
        0x18,
        b"354 go ahead\r\n",
    );
    let key = SessionKey::new(&data);

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&pipelined_body, None, Instant::now());
    let _ = manager.process_packet(&queued, None, Instant::now());
    let _ = manager.process_packet(&ready, None, Instant::now());

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.email_count, 1);
    assert!(
        session
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("hello from replay")
    );
}

#[test]
fn late_prepended_data_replays_previously_processed_body() {
    let manager = ShardedSessionManager::new();
    let mail_from = smtp_packet(
        Direction::Outbound,
        35007,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35007,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let body_before_data = smtp_packet(
        Direction::Outbound,
        35007,
        25,
        171,
        0x18,
        b"Subject: replay late DATA\r\n\r\nhello from prepended DATA\r\n.\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35007, 25, 165, 0x18, b"DATA\r\n");
    let ready = smtp_packet(
        Direction::Inbound,
        35007,
        25,
        200,
        0x18,
        b"354 go ahead\r\n",
    );
    let key = SessionKey::new(&data);

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&body_before_data, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&ready, None, Instant::now());

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.email_count, 1);
    assert_eq!(session.session.subject.as_deref(), Some("replay late DATA"));
    assert!(
        session
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("hello from prepended DATA")
    );
}

#[test]
fn close_lossy_flush_salvages_body_behind_small_gap() {
    let manager = ShardedSessionManager::new();
    let mail_from = smtp_packet(
        Direction::Outbound,
        35008,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35008,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35008, 25, 165, 0x18, b"DATA\r\n");
    let body_after_gap = smtp_packet(
        Direction::Outbound,
        35008,
        25,
        181,
        0x18,
        b"Subject: lossy close\r\n\r\nhello after skipped gap\r\n.\r\n",
    );
    let fin_client = smtp_packet(Direction::Outbound, 35008, 25, 235, 0x11, b"");
    let fin_server = smtp_packet(Direction::Inbound, 35008, 25, 260, 0x11, b"");
    let key = SessionKey::new(&data);

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&body_after_gap, None, Instant::now());
    let _ = manager.process_packet(&fin_client, None, Instant::now());
    let _ = manager.process_packet(&fin_server, None, Instant::now());

    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_restored_with_gaps
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed),
        0
    );

    let session = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(session.session.email_count, 1);
    assert!(!session.session.content.is_complete);
    assert_eq!(session.client_stream.gap_bytes_skipped, 10);
    assert!(
        session
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("hello after skipped gap")
    );
}

#[test]
fn data_without_payload_before_354_counts_as_aborted_not_restore_failure() {
    let manager = ShardedSessionManager::new();
    let mail_from = smtp_packet(
        Direction::Outbound,
        35009,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        35009,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 35009, 25, 165, 0x18, b"DATA\r\n");
    let fin_client = smtp_packet(Direction::Outbound, 35009, 25, 171, 0x11, b"");
    let fin_server = smtp_packet(Direction::Inbound, 35009, 25, 200, 0x11, b"");

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&fin_client, None, Instant::now());
    let _ = manager.process_packet(&fin_server, None, Instant::now());

    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_tcp_close_without_restore
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        manager
            .stats
            .smtp_pipeline
            .smtp_plaintext_aborted_before_payload
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn encrypted_session_finishes_after_tcp_close() {
    let manager = ShardedSessionManager::new();

    let syn = smtp_packet(Direction::Outbound, 35002, 465, 1000, 0x02, b"");
    let fin_client = smtp_packet(Direction::Outbound, 35002, 465, 1001, 0x11, b"");
    let fin_server = smtp_packet(Direction::Inbound, 35002, 465, 2001, 0x11, b"");

    let _ = manager.process_packet(&syn, None, Instant::now());
    assert_eq!(manager.get_stats().active_sessions, 1);

    let _ = manager.process_packet(&fin_client, None, Instant::now());
    assert_eq!(manager.get_stats().active_sessions, 1);

    let _ = manager.process_packet(&fin_server, None, Instant::now());
    assert_eq!(manager.get_stats().active_sessions, 0);

    let dirty = manager.take_dirty_sessions();
    assert!(
        dirty
            .iter()
            .any(|s| s.status == SessionStatus::Completed && s.content.is_encrypted)
    );
}

#[test]
fn ip_rate_limit_active_count_returns_to_zero_after_session_removal() {
    let manager = ShardedSessionManager::with_timeout(Duration::from_millis(1));
    let syn = smtp_packet(Direction::Outbound, 35100, 465, 1000, 0x02, b"");
    let client_ip = SessionKey::client_ip_from_packet(&syn);
    let key = SessionKey::new(&syn);

    let _ = manager.process_packet(&syn, None, Instant::now());
    let entry = manager
        .ip_rate_limits
        .get(&client_ip)
        .expect("rate-limit entry created");
    assert_eq!(entry.active_session_count.load(Ordering::Relaxed), 1);
    drop(entry);

    {
        let mut session = manager.sessions.get_mut(&key).expect("session created");
        session.session.status = SessionStatus::Completed;
        session.dirty = false;
        session.last_activity = Instant::now() - Duration::from_secs(1);
    }
    manager.cleanup_timeout_sessions();

    assert!(!manager.sessions.contains_key(&key));
    assert_eq!(
        manager
            .ip_rate_limits
            .get(&client_ip)
            .expect("entry retained for rate window")
            .active_session_count
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn expired_inactive_ip_rate_limit_entry_is_evicted() {
    let manager = ShardedSessionManager::new();
    let ip = CompactIp::from_ip_addr(&crate::capture::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let entry = IpRateLimitEntry::new();
    entry.window_start_ns.store(1, Ordering::Relaxed);
    manager.ip_rate_limits.insert(ip, entry);

    let eviction_time = 2 * rate_limit::RATE_LIMIT_WINDOW_SECS * 1_000_000_000 + 2;
    manager.cleanup_ip_rate_limits_at(eviction_time);

    assert!(!manager.ip_rate_limits.contains_key(&ip));
}

#[test]
fn concurrent_first_packets_create_one_session_and_one_ip_count() {
    const WORKERS: usize = 64;
    let manager = Arc::new(ShardedSessionManager::new());
    let packet = smtp_packet(Direction::Outbound, 35101, 465, 1000, 0x02, b"");
    let client_ip = SessionKey::client_ip_from_packet(&packet);
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let manager = Arc::clone(&manager);
        let packet = packet.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            manager.process_packet(&packet, None, Instant::now())
        }));
    }

    let mut new_results = 0usize;
    for handle in handles {
        if matches!(
            handle.join().expect("session worker must not panic"),
            ProcessResult::New(_)
        ) {
            new_results += 1;
        }
    }

    assert_eq!(new_results, 1);
    assert_eq!(manager.sessions.len(), 1);
    let entry = manager
        .ip_rate_limits
        .get(&client_ip)
        .expect("one rate-limit entry must remain");
    assert_eq!(entry.new_session_count.load(Ordering::Relaxed), 1);
    assert_eq!(entry.active_session_count.load(Ordering::Relaxed), 1);
}

#[test]
fn unique_ip_churn_is_fully_reclaimable() {
    const SESSION_COUNT: usize = 1024;
    let manager = ShardedSessionManager::with_timeout(Duration::from_millis(1));

    for index in 0..SESSION_COUNT {
        let packet = RawpacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(
                198,
                18,
                (index / 256) as u8,
                (index % 256) as u8,
            )),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            payload: Bytes::new(),
            src_port: 20_000 + index as u16,
            dst_port: 465,
            protocol: Protocol::Smtp,
            direction: Direction::Outbound,
            tcp_seq: 1,
            tcp_ack: 0,
            tcp_flags: 0x02,
        };
        assert!(matches!(
            manager.process_packet(&packet, None, Instant::now()),
            ProcessResult::New(_)
        ));
    }
    assert_eq!(manager.sessions.len(), SESSION_COUNT);
    assert_eq!(manager.ip_rate_limits.len(), SESSION_COUNT);

    for mut session in manager.sessions.iter_mut() {
        session.session.status = SessionStatus::Completed;
        session.dirty = false;
        session.last_activity = Instant::now() - Duration::from_secs(1);
    }
    manager.cleanup_timeout_sessions();

    assert!(manager.sessions.is_empty());
    assert!(
        manager
            .ip_rate_limits
            .iter()
            .all(|entry| { entry.active_session_count.load(Ordering::Relaxed) == 0 })
    );
    for entry in manager.ip_rate_limits.iter() {
        entry.window_start_ns.store(1, Ordering::Relaxed);
    }
    let eviction_time = 2 * rate_limit::RATE_LIMIT_WINDOW_SECS * 1_000_000_000 + 2;
    manager.cleanup_ip_rate_limits_at(eviction_time);
    assert!(manager.ip_rate_limits.is_empty());
}

// ── R4A capture-layer regression tests ────────────────────────────────

#[test]
fn tls_magic_after_smtp_dialog_does_not_mark_encrypted() {
    // N1: an injected packet whose payload starts with TLS record magic must
    // not blind a session that already showed legitimate SMTP dialog.
    let manager = ShardedSessionManager::new();
    let probe = smtp_packet(Direction::Outbound, 36010, 25, 0, 0x18, b"");
    let key = SessionKey::new(&probe);

    // Midstream capture (no SYN): the attacker-injectable scenario.
    let mut client_seq = 100u32;
    let mut send_client = |manager: &ShardedSessionManager, payload: &'static [u8]| {
        let packet = smtp_packet(Direction::Outbound, 36010, 25, client_seq, 0x18, payload);
        client_seq += payload.len() as u32;
        let _ = manager.process_packet(&packet, None, Instant::now());
    };

    send_client(&manager, b"EHLO test\r\n");
    send_client(&manager, b"MAIL FROM:<alice@example.com>\r\n");
    send_client(&manager, b"RCPT TO:<bob@example.com>\r\n");
    // Injected TLS-looking bytes in the middle of the plaintext dialog.
    send_client(&manager, b"\x16\x03\x03X\r\n");
    send_client(&manager, b"DATA\r\n");
    let ready = smtp_packet(
        Direction::Inbound,
        36010,
        25,
        700,
        0x18,
        b"354 End data with <CR><LF>.<CR><LF>\r\n",
    );
    let _ = manager.process_packet(&ready, None, Instant::now());
    send_client(
        &manager,
        b"Subject: Q3 report\r\n\r\nquarterly numbers\r\n.\r\n",
    );

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert!(
        !entry.session.content.is_encrypted,
        "injected TLS magic must not mark a session with observed dialog"
    );
    assert!(!entry.tls_magic_marked);
    assert_eq!(entry.session.subject.as_deref(), Some("Q3 report"));
    assert!(
        entry
            .session
            .content
            .body_text
            .as_deref()
            .unwrap_or("")
            .contains("quarterly numbers")
    );
}

#[test]
fn tls_magic_midstream_marks_then_reverts_on_plaintext_dialog() {
    // N1: capture starting mid-stream on TLS-looking bytes marks the session,
    // but the mark must be revoked once plaintext SMTP dialog shows up.
    let manager = ShardedSessionManager::new();
    let probe = smtp_packet(Direction::Outbound, 36011, 25, 0, 0x18, b"");
    let key = SessionKey::new(&probe);

    let tls1 = smtp_packet(
        Direction::Outbound,
        36011,
        25,
        500,
        0x18,
        b"\x16\x03\x01\x00\x80GGGG",
    );
    let _ = manager.process_packet(&tls1, None, Instant::now());
    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert!(entry.session.content.is_encrypted);
        assert!(entry.tls_magic_marked);
    }

    let ok = smtp_packet(
        Direction::Inbound,
        36011,
        25,
        900,
        0x18,
        b"250 mail.example.com\r\n",
    );
    let _ = manager.process_packet(&ok, None, Instant::now());

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert!(
        !entry.session.content.is_encrypted,
        "plaintext dialog must revoke the heuristic TLS mark"
    );
    assert!(!entry.tls_magic_marked);
}

#[test]
fn tls_magic_midstream_without_dialog_stays_encrypted() {
    // N1: a genuinely mid-stream TLS session (no plaintext dialog at all)
    // keeps the encrypted mark.
    let manager = ShardedSessionManager::new();
    let probe = smtp_packet(Direction::Outbound, 36012, 25, 0, 0x18, b"");
    let key = SessionKey::new(&probe);

    let tls1 = smtp_packet(
        Direction::Outbound,
        36012,
        25,
        600,
        0x18,
        b"\x16\x03\x01\x00\x10AAAA",
    );
    let tls2_seq = 600 + tls1.payload.len() as u32;
    let tls2 = smtp_packet(
        Direction::Outbound,
        36012,
        25,
        tls2_seq,
        0x18,
        b"\x16\x03\x03\x00\x20BBBB",
    );
    let _ = manager.process_packet(&tls1, None, Instant::now());
    let _ = manager.process_packet(&tls2, None, Instant::now());

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert!(entry.session.content.is_encrypted);
    assert!(entry.tls_magic_marked);
}

#[test]
fn completed_session_releases_slot_immediately() {
    // 遗留2: a completed session must free its admission slot right away,
    // not only when cleanup eventually removes the map entry.
    let manager = ShardedSessionManager::new();
    let ehlo = smtp_packet(Direction::Outbound, 36013, 25, 100, 0x18, b"EHLO test\r\n");
    let key = SessionKey::new(&ehlo);

    assert!(matches!(
        manager.process_packet(&ehlo, None, Instant::now()),
        ProcessResult::New(_)
    ));
    assert_eq!(manager.session_slots.load(Ordering::Relaxed), 1);

    // "EHLO test\r\n" is 11 bytes: the next segment starts at seq 111.
    let quit = smtp_packet(Direction::Outbound, 36013, 25, 111, 0x18, b"QUIT\r\n");
    let _ = manager.process_packet(&quit, None, Instant::now());

    assert_eq!(manager.session_slots.load(Ordering::Relaxed), 0);
    assert!(
        manager.sessions.contains_key(&key),
        "map entry is kept for the relay-correlation grace window"
    );
}

#[test]
fn cleanup_removes_flushed_terminal_sessions_after_grace() {
    // 遗留2: after the final state is flushed (dirty=false) and the grace
    // window elapsed, cleanup removes the entry without double-decrementing
    // the already-released slot.
    let manager = ShardedSessionManager::new();
    let ehlo = smtp_packet(Direction::Outbound, 36014, 25, 100, 0x18, b"EHLO test\r\n");
    // "EHLO test\r\n" is 11 bytes: the next segment starts at seq 111.
    let quit = smtp_packet(Direction::Outbound, 36014, 25, 111, 0x18, b"QUIT\r\n");
    let key = SessionKey::new(&ehlo);

    let _ = manager.process_packet(&ehlo, None, Instant::now());
    let _ = manager.process_packet(&quit, None, Instant::now());
    assert_eq!(manager.session_slots.load(Ordering::Relaxed), 0);

    let dirty = manager.take_dirty_sessions();
    assert!(!dirty.is_empty());

    // Within the grace window the entry is kept for relay correlation.
    manager.cleanup_timeout_sessions();
    assert!(manager.sessions.contains_key(&key));

    {
        let mut entry = manager.sessions.get_mut(&key).expect("session must exist");
        entry.last_activity = Instant::now() - Duration::from_secs(31);
    }
    manager.cleanup_timeout_sessions();

    assert!(!manager.sessions.contains_key(&key));
    assert_eq!(
        manager.session_slots.load(Ordering::Relaxed),
        0,
        "slot released at completion must not be decremented again"
    );
}

#[test]
fn budget_pressure_evicts_completed_session_buffers() {
    // 遗留1: when the shared reassembly budget runs out, completed sessions
    // are evicted first; recently-active sessions keep their buffers.
    let manager = ShardedSessionManager::new();

    // Session A: complete SMTP flow, then QUIT -> terminal with buffered data.
    let a_ehlo = smtp_packet(Direction::Outbound, 36015, 25, 100, 0x18, b"EHLO a\r\n");
    let a_key = SessionKey::new(&a_ehlo);
    let _ = manager.process_packet(&a_ehlo, None, Instant::now());
    let a_quit = smtp_packet(Direction::Outbound, 36015, 25, 108, 0x18, b"QUIT\r\n");
    let _ = manager.process_packet(&a_quit, None, Instant::now());

    // Session B: active session with buffered data, not idle.
    let b_ehlo = smtp_packet(Direction::Outbound, 36016, 25, 100, 0x18, b"EHLO b\r\n");
    let b_key = SessionKey::new(&b_ehlo);
    let _ = manager.process_packet(&b_ehlo, None, Instant::now());

    let freed = manager.evict_reclaimable_stream_buffers(manager.reassembly_budget.limit());
    assert!(freed > 0, "completed session buffers must be reclaimable");

    let a = manager.sessions.get(&a_key).expect("session A must exist");
    assert_eq!(a.client_stream.total_bytes, 0);
    assert_eq!(a.server_stream.total_bytes, 0);
    drop(a);

    let b = manager.sessions.get(&b_key).expect("session B must exist");
    assert!(
        b.client_stream.total_bytes > 0,
        "recently-active session buffers must survive eviction"
    );
}

#[test]
fn first_http_packet_feeds_data_security() {
    // N5: the very first packet of a connection must also feed the
    // data-security HTTP pipeline; otherwise its bytes are lost.
    let manager = ShardedSessionManager::new();
    let packet = RawpacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
        payload: Bytes::from_static(
            b"POST /login HTTP/1.1\r\nHost: mail.example.com\r\nContent-Length: 14\r\n\r\nusername=admin",
        ),
        src_port: 41000,
        dst_port: 80,
        protocol: Protocol::Http,
        direction: Direction::Outbound,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_flags: 0x18,
    };

    assert!(matches!(
        manager.process_packet(&packet, None, Instant::now()),
        ProcessResult::New(_)
    ));

    let sessions = manager.take_http_sessions();
    assert_eq!(sessions.len(), 1, "first-packet POST must reach DLP");
    assert!(
        sessions[0]
            .request_body
            .as_deref()
            .unwrap_or("")
            .contains("username=admin")
    );
}

#[test]
fn http_body_between_16k_and_256k_spills_to_temp_file() {
    // N2: bodies above 16KB used to be truncated at 16KB in memory, creating
    // a DLP dead zone. They must now spill to a temp file so the full body
    // is scanned.
    let manager = ShardedSessionManager::new();

    let mut body = vec![b'x'; 100 * 1024];
    let marker = b"ID:110101199003077721";
    body[99_000..99_000 + marker.len()].copy_from_slice(marker);

    let mut payload = Vec::new();
    payload.extend_from_slice(
        b"POST /upload HTTP/1.1\r\nHost: mail.example.com\r\nContent-Length: 102400\r\n\r\n",
    );
    payload.extend_from_slice(&body);

    let packet = RawpacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
        payload: Bytes::from(payload),
        src_port: 41001,
        dst_port: 80,
        protocol: Protocol::Http,
        direction: Direction::Outbound,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_flags: 0x18,
    };

    let _ = manager.process_packet(&packet, None, Instant::now());

    let sessions = manager.take_http_sessions();
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.request_body_size, 100 * 1024);
    let temp_path = session
        .body_temp_file
        .as_ref()
        .expect("100KB body must spill to a temp file")
        .clone();
    // In-memory preview keeps only the head; the marker lives past 16KB.
    assert!(
        !session
            .request_body
            .as_deref()
            .unwrap_or("")
            .contains("ID:110101199003077721")
    );
    let on_disk = std::fs::read(&temp_path).expect("temp file readable");
    assert!(
        on_disk.windows(marker.len()).any(|window| window == &marker[..]),
        "temp file must contain the full body including content past 16KB"
    );
    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn chunked_post_reaches_data_security_decoded() {
    // 遗留3 (session level): a chunked POST body is decoded and delivered to
    // the data-security pipeline like a plain Content-Length body.
    let manager = ShardedSessionManager::new();
    let packet = RawpacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
        payload: Bytes::from_static(
            b"POST /upload HTTP/1.1\r\nHost: mail.example.com\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\nid_card=110101199003077721\r\n0\r\n\r\n",
        ),
        src_port: 41002,
        dst_port: 80,
        protocol: Protocol::Http,
        direction: Direction::Outbound,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_flags: 0x18,
    };

    let _ = manager.process_packet(&packet, None, Instant::now());

    let sessions = manager.take_http_sessions();
    assert_eq!(sessions.len(), 1, "chunked POST must reach DLP");
    assert!(
        sessions[0]
            .request_body
            .as_deref()
            .unwrap_or("")
            .contains("id_card=110101199003077721"),
        "chunked body must be decoded before DLP delivery"
    );
}

// ── R5 Slice-2 regression tests ─────────────────────────────────────────

/// Build a packet with an arbitrary protocol/direction for session tests.
fn proto_packet(
    protocol: Protocol,
    direction: Direction,
    client_port: u16,
    server_port: u16,
    tcp_seq: u32,
    tcp_flags: u8,
    payload: &'static [u8],
) -> RawpacketInfo {
    match direction {
        Direction::Outbound => RawpacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            payload: Bytes::from_static(payload),
            src_port: client_port,
            dst_port: server_port,
            protocol,
            direction,
            tcp_seq,
            tcp_ack: 0,
            tcp_flags,
        },
        Direction::Inbound => RawpacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            payload: Bytes::from_static(payload),
            src_port: server_port,
            dst_port: client_port,
            protocol,
            direction,
            tcp_seq,
            tcp_ack: 0,
            tcp_flags,
        },
    }
}

#[test]
fn eviction_resets_http_state_and_marks_active_session() {
    // A2: LRU eviction cleared the reassembly buffer and processed offsets but
    // left http_state.request_start_offset pointing into the old buffer —
    // afterwards offset >= stream.len() made every parse a silent no-op and
    // the connection was DLP-blind forever. Eviction must now reset the state
    // machine and mark the still-active session as inspection-limited.
    let manager = ShardedSessionManager::new();
    let first = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42000,
        80,
        1,
        0x18,
        // A complete request: the state machine has consumed bytes from the
        // buffer that eviction is about to drop.
        b"POST /save HTTP/1.1\r\nHost: mail.example.com\r\nContent-Length: 4\r\n\r\ndata",
    );
    let key = SessionKey::new(&first);
    let _ = manager.process_packet(&first, None, Instant::now());
    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert_eq!(entry.session.status, SessionStatus::Active);
        assert!(
            entry
                .http_state
                .as_ref()
                .map(|s| s.consumed_offset())
                .unwrap_or(0)
                > 0,
            "state machine must have consumed the first request pre-eviction"
        );
        assert!(entry.client_stream.total_bytes > 0);
    }
    // Drain the pre-eviction HTTP session so the post-eviction queue is clean.
    assert_eq!(manager.take_http_sessions().len(), 1);

    // Make the active session idle enough to be eviction-eligible.
    {
        let mut entry = manager.sessions.get_mut(&key).expect("session must exist");
        entry.last_activity = Instant::now() - Duration::from_secs(120);
    }
    let freed = manager.evict_reclaimable_stream_buffers(manager.reassembly_budget.limit());
    assert!(freed > 0, "idle active session buffers must be evicted");

    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert_eq!(
            entry
                .http_state
                .as_ref()
                .map(|s| s.consumed_offset())
                .unwrap_or(usize::MAX),
            0,
            "http state machine must be reset together with the buffer"
        );
        assert_eq!(entry.client_processed_offset, 0);
        assert!(entry.stream_buffers_evicted);
        assert_eq!(
            entry.session.error_reason.as_deref(),
            Some("inspection:stream_buffer_evicted"),
            "evicted active session must carry an inspection-limited signal"
        );
        assert!(entry.dirty, "signal must be published via the dirty queue");
    }
    assert_eq!(
        manager
            .stats
            .security
            .evicted_active_session_total
            .load(Ordering::Relaxed),
        1
    );

    // The connection keeps living (keep-alive): a fresh request must parse
    // again and must carry the gap flag downstream.
    let second = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42000,
        80,
        5000,
        0x18,
        b"POST /save HTTP/1.1\r\nHost: mail.example.com\r\nContent-Length: 26\r\n\r\nid_card=110101199003077721",
    );
    let _ = manager.process_packet(&second, None, Instant::now());
    let sessions = manager.take_http_sessions();
    assert_eq!(
        sessions.len(),
        1,
        "post-eviction request on the same connection must parse again"
    );
    assert!(
        sessions[0].has_gaps,
        "post-eviction content must be flagged as potentially incomplete"
    );
}

#[test]
fn eviction_clears_smtp_data_buffer_and_marks_signal() {
    // A2 (SMTP side): evicting an active session mid-DATA must not let the
    // partial buffered email stitch together with post-eviction bytes.
    let manager = ShardedSessionManager::new();
    let mail_from = smtp_packet(
        Direction::Outbound,
        42100,
        25,
        100,
        0x18,
        b"MAIL FROM:<sender@example.com>\r\n",
    );
    let rcpt_to = smtp_packet(
        Direction::Outbound,
        42100,
        25,
        132,
        0x18,
        b"RCPT TO:<recipient@example.com>\r\n",
    );
    let data = smtp_packet(Direction::Outbound, 42100, 25, 165, 0x18, b"DATA\r\n");
    let ready = smtp_packet(Direction::Inbound, 42100, 25, 200, 0x18, b"354 go ahead\r\n");
    let body = smtp_packet(
        Direction::Outbound,
        42100,
        25,
        171,
        0x18,
        b"Subject: partial\r\n\r\npartial body without terminator",
    );
    let key = SessionKey::new(&mail_from);

    let _ = manager.process_packet(&mail_from, None, Instant::now());
    let _ = manager.process_packet(&rcpt_to, None, Instant::now());
    let _ = manager.process_packet(&data, None, Instant::now());
    let _ = manager.process_packet(&ready, None, Instant::now());
    let _ = manager.process_packet(&body, None, Instant::now());
    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert!(
            entry
                .smtp_state
                .as_ref()
                .map(|s| s.buffered_email_bytes())
                .unwrap_or(0)
                > 0,
            "partial email must be buffered pre-eviction"
        );
    }

    {
        let mut entry = manager.sessions.get_mut(&key).expect("session must exist");
        entry.last_activity = Instant::now() - Duration::from_secs(120);
    }
    let freed = manager.evict_reclaimable_stream_buffers(manager.reassembly_budget.limit());
    assert!(freed > 0);

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(
        entry
            .smtp_state
            .as_ref()
            .map(|s| s.buffered_email_bytes())
            .unwrap_or(usize::MAX),
        0,
        "partial DATA buffer must be dropped on eviction (no cross-stitching)"
    );
    assert!(entry.stream_buffers_evicted);
    assert_eq!(
        entry.session.error_reason.as_deref(),
        Some("inspection:stream_buffer_evicted")
    );
}

#[test]
fn malformed_chunked_desync_stops_splitting_and_signals() {
    // A4 (session level): a malformed chunked body must desync the connection
    // (no more request splitting) and surface an inspection-limited signal,
    // instead of rescanning raw body bytes as requests.
    let manager = ShardedSessionManager::new();
    let bad = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42200,
        80,
        1,
        0x18,
        b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\nZZZnothex\r\nGET /fake HTTP/1.1\r\nHost: corp.com\r\n\r\n",
    );
    let key = SessionKey::new(&bad);
    let _ = manager.process_packet(&bad, None, Instant::now());

    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert!(entry.http_desynced, "desync flag must be set");
        assert!(
            entry
                .session
                .error_reason
                .as_deref()
                .unwrap_or("")
                .contains("inspection:http_stream_desynced"),
            "desync must be recorded as an inspection signal"
        );
        assert!(
            entry
                .http_state
                .as_ref()
                .map(|s| s.is_desynced())
                .unwrap_or(false)
        );
    }
    assert_eq!(
        manager
            .stats
            .security
            .http_desynced_connection_total
            .load(Ordering::Relaxed),
        1
    );
    assert!(
        manager.take_http_sessions().is_empty(),
        "bytes after the rejected chunk must not become fake requests"
    );

    // A later, well-formed request on the same connection is not split either
    // (framing is unrecoverable) — and the signal is not double-counted.
    let later = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42200,
        80,
        5000,
        0x18,
        b"POST /save HTTP/1.1\r\nHost: corp.com\r\nContent-Length: 4\r\n\r\ndata",
    );
    let _ = manager.process_packet(&later, None, Instant::now());
    assert!(manager.take_http_sessions().is_empty());
    assert_eq!(
        manager
            .stats
            .security
            .http_desynced_connection_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn pop3_retr_marks_coverage_gap() {
    // F2: a cleartext POP3 session retrieving a full message crosses the
    // sensor with zero analysis; it must carry an inspection coverage gap.
    let manager = ShardedSessionManager::new();
    let retr = proto_packet(
        Protocol::Pop3,
        Direction::Outbound,
        42300,
        110,
        100,
        0x18,
        b"RETR 1\r\n",
    );
    let key = SessionKey::new(&retr);
    let _ = manager.process_packet(&retr, None, Instant::now());

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(
        entry.session.error_reason.as_deref(),
        Some("inspection:pop3_retr_content_not_analyzed")
    );
    assert!(entry.mail_retrieval_seen);
    assert!(entry.dirty);
    assert_eq!(
        manager
            .stats
            .security
            .pop3_content_gap_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn pop3_non_retrieval_commands_stay_silent() {
    let manager = ShardedSessionManager::new();
    for (seq, payload) in [(100u32, &b"USER alice\r\n"[..]), (112, &b"LIST\r\n"[..])] {
        let packet = proto_packet(Protocol::Pop3, Direction::Outbound, 42301, 110, seq, 0x18, payload);
        let _ = manager.process_packet(&packet, None, Instant::now());
    }
    let sessions: Vec<_> = manager.sessions.iter().map(|e| e.key().clone()).collect();
    assert_eq!(sessions.len(), 1);
    let entry = manager.sessions.get(&sessions[0]).expect("session must exist");
    assert!(entry.session.error_reason.is_none());
    assert!(!entry.mail_retrieval_seen);
    assert_eq!(
        manager
            .stats
            .security
            .pop3_content_gap_total
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn pop3s_encrypted_port_produces_no_gap_signal() {
    // Port 995 is TLS-wrapped: the payload is ciphertext, RETR is invisible,
    // and no cleartext coverage gap applies.
    let manager = ShardedSessionManager::new();
    let retr = proto_packet(
        Protocol::Pop3,
        Direction::Outbound,
        42302,
        995,
        100,
        0x18,
        b"RETR 1\r\n",
    );
    let key = SessionKey::new(&retr);
    let _ = manager.process_packet(&retr, None, Instant::now());
    let entry = manager.sessions.get(&key).expect("session must exist");
    assert!(entry.session.content.is_encrypted);
    assert!(entry.session.error_reason.is_none());
}

#[test]
fn imap_fetch_body_marks_coverage_gap() {
    let manager = ShardedSessionManager::new();
    let fetch = proto_packet(
        Protocol::Imap,
        Direction::Outbound,
        42400,
        143,
        100,
        0x18,
        b"A1 LOGIN alice secret\r\nA2 FETCH 1 BODY[]\r\n",
    );
    let key = SessionKey::new(&fetch);
    let _ = manager.process_packet(&fetch, None, Instant::now());
    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(
        entry.session.error_reason.as_deref(),
        Some("inspection:imap_fetch_body_content_not_analyzed")
    );
    assert_eq!(
        manager
            .stats
            .security
            .imap_content_gap_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn imap_metadata_fetch_stays_silent() {
    let manager = ShardedSessionManager::new();
    for (seq, payload) in [
        (100u32, &b"A1 FETCH 1 (FLAGS)\r\n"[..]),
        (120, &b"A2 FETCH 1 RFC822.SIZE\r\n"[..]),
        (145, &b"A3 FETCH 1 BODY[HEADER]\r\n"[..]),
    ] {
        let packet = proto_packet(Protocol::Imap, Direction::Outbound, 42401, 143, seq, 0x18, payload);
        let _ = manager.process_packet(&packet, None, Instant::now());
    }
    let sessions: Vec<_> = manager.sessions.iter().map(|e| e.key().clone()).collect();
    assert_eq!(sessions.len(), 1);
    let entry = manager.sessions.get(&sessions[0]).expect("session must exist");
    assert!(entry.session.error_reason.is_none());
    assert_eq!(
        manager
            .stats
            .security
            .imap_content_gap_total
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn protocol_anomaly_marked_on_session_completion() {
    // F1: a forged 354 (response injection attempt) is counted by the parser
    // state machine; the completed session must carry a protocol_anomaly
    // marker instead of looking like a clean dialog.
    let manager = ShardedSessionManager::new();
    // A SYN-seen session is NOT a midstream capture, so a 354 without a
    // pending DATA command is counted as an anomaly.
    let syn = smtp_packet(Direction::Outbound, 42500, 25, 1, 0x02, b"");
    let key = SessionKey::new(&syn);
    let _ = manager.process_packet(&syn, None, Instant::now());

    // SYN consumes one sequence number: EHLO starts at seq 2 (11 bytes).
    let ehlo = smtp_packet(Direction::Outbound, 42500, 25, 2, 0x18, b"EHLO test\r\n");
    let _ = manager.process_packet(&ehlo, None, Instant::now());

    // Forged 354 with no pending DATA command -> anomaly_count += 1.
    let forged = smtp_packet(Direction::Inbound, 42500, 25, 200, 0x18, b"354 go ahead\r\n");
    let _ = manager.process_packet(&forged, None, Instant::now());

    // QUIT starts right after EHLO at seq 13.
    let quit = smtp_packet(Direction::Outbound, 42500, 25, 13, 0x18, b"QUIT\r\n");
    let _ = manager.process_packet(&quit, None, Instant::now());

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(entry.session.status, SessionStatus::Completed);
    assert_eq!(
        entry.session.error_reason.as_deref(),
        Some("inspection:protocol_anomaly:1"),
        "terminal session must carry the protocol_anomaly marker"
    );
    assert_eq!(
        manager
            .stats
            .security
            .protocol_anomaly_session_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn clean_smtp_session_has_no_anomaly_marker() {
    let manager = ShardedSessionManager::new();
    let ehlo = smtp_packet(Direction::Outbound, 42501, 25, 100, 0x18, b"EHLO test\r\n");
    let key = SessionKey::new(&ehlo);
    let _ = manager.process_packet(&ehlo, None, Instant::now());
    let quit = smtp_packet(Direction::Outbound, 42501, 25, 111, 0x18, b"QUIT\r\n");
    let _ = manager.process_packet(&quit, None, Instant::now());

    let entry = manager.sessions.get(&key).expect("session must exist");
    assert_eq!(entry.session.status, SessionStatus::Completed);
    assert!(entry.session.error_reason.is_none());
    assert_eq!(
        manager
            .stats
            .security
            .protocol_anomaly_session_total
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn sid_user_conflict_refuses_overwrite() {
    // F3①: sid->user mappings are learned from client-controlled bodies; a
    // conflicting rewrite must be refused, counted, and kept out of the
    // Redis write buffer.
    let manager = ShardedSessionManager::new();
    manager.sid_user_insert("sid-abc".to_string(), "alice@corp.com".to_string());
    manager.sid_user_insert("sid-abc".to_string(), "mallory@evil.com".to_string());

    assert_eq!(
        manager.sid_user_get("sid-abc").as_deref(),
        Some("alice@corp.com"),
        "existing mapping must survive a conflicting insert"
    );
    assert_eq!(
        manager
            .stats
            .security
            .sid_user_conflict_total
            .load(Ordering::Relaxed),
        1
    );
    let pending = manager.take_sid_user_pending();
    assert_eq!(
        pending,
        vec![("sid-abc".to_string(), "alice@corp.com".to_string())],
        "conflicting writes must not reach Redis"
    );

    // Same user (case variant) is a refresh, not a conflict: no conflict
    // counted, and the Redis write buffer carries the refresh (TTL renewal).
    manager.sid_user_insert("sid-abc".to_string(), "Alice@corp.com".to_string());
    assert_eq!(
        manager
            .stats
            .security
            .sid_user_conflict_total
            .load(Ordering::Relaxed),
        1
    );
    let pending = manager.take_sid_user_pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, "sid-abc");
}

#[test]
fn login_binding_wins_over_cookie_identity() {
    // F3②: a forged Cookie uid contradicting the observed login binding must
    // lose; the mismatch is counted and the binding is attributed.
    let manager = ShardedSessionManager::new();

    // 1) Login form POST binds username=alice to this connection.
    const LOGIN_PAYLOAD: &[u8] = b"POST /login HTTP/1.1\r\nHost: mail.example.com\r\nContent-Length: 27\r\n\r\nusername=alice&password=pw1";
    let login = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42600,
        80,
        1,
        0x18,
        LOGIN_PAYLOAD,
    );
    let key = SessionKey::new(&login);
    let _ = manager.process_packet(&login, None, Instant::now());
    // Server confirms the login (302 redirect).
    let login_resp = proto_packet(
        Protocol::Http,
        Direction::Inbound,
        42600,
        80,
        500,
        0x18,
        b"HTTP/1.1 302 Found\r\nLocation: /inbox\r\n\r\n",
    );
    let _ = manager.process_packet(&login_resp, None, Instant::now());
    {
        let entry = manager.sessions.get(&key).expect("session must exist");
        assert_eq!(
            entry
                .session
                .auth_info
                .as_ref()
                .and_then(|a| a.username.as_deref()),
            Some("alice")
        );
    }

    // 2) Keep-alive request with a forged Cookie identity.
    let forged_seq = 1 + LOGIN_PAYLOAD.len() as u32;
    let forged = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42600,
        80,
        forged_seq,
        0x18,
        b"POST /api/save HTTP/1.1\r\nHost: mail.example.com\r\nCookie: uid=mallory@evil.com\r\nContent-Length: 4\r\n\r\ndata",
    );
    let _ = manager.process_packet(&forged, None, Instant::now());

    let sessions = manager.take_http_sessions();
    assert_eq!(sessions.len(), 2);
    let forged_session = &sessions[1];
    assert_eq!(
        forged_session.detected_user.as_deref(),
        Some("alice"),
        "login binding must win over the forged cookie identity"
    );
    assert_eq!(
        manager
            .stats
            .security
            .attribution_mismatch_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn same_client_ip_reporting_two_users_is_anomalous() {
    // F3③: without a login binding, cookie identities are still recorded, but
    // a second distinct user from the same client IP is an anomaly signal.
    let manager = ShardedSessionManager::new();
    // Two separate connections from the same client IP (42700, 42701).
    let first = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42700,
        80,
        1,
        0x18,
        b"POST /api/save HTTP/1.1\r\nHost: mail.example.com\r\nCookie: uid=alice@corp.com\r\nContent-Length: 4\r\n\r\ndata",
    );
    let second = proto_packet(
        Protocol::Http,
        Direction::Outbound,
        42701,
        80,
        1,
        0x18,
        b"POST /api/save HTTP/1.1\r\nHost: mail.example.com\r\nCookie: uid=bob@corp.com\r\nContent-Length: 4\r\n\r\ndata",
    );
    let _ = manager.process_packet(&first, None, Instant::now());
    let _ = manager.process_packet(&second, None, Instant::now());

    let sessions = manager.take_http_sessions();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].detected_user.as_deref(), Some("alice@corp.com"));
    assert_eq!(
        sessions[1].detected_user.as_deref(),
        Some("bob@corp.com"),
        "without a login binding the extracted identity is kept as a hint"
    );
    assert_eq!(
        manager
            .stats
            .security
            .client_ip_multi_user_total
            .load(Ordering::Relaxed),
        1,
        "second distinct user from the same client IP must be counted"
    );
}
