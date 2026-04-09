use super::*;
use super::smtp_relay;
use crate::capture::{IpAddr, RawpacketInfo};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
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
    let payload =
        b"DKIM-Signature: v=1; h=From:To:Subject:Date; b=abc123\r\n\r\nbody";

    assert_eq!(manager.extract_subject_from_payload_fast(payload), None);
}

#[test]
fn fast_subject_scan_prefers_real_subject_header_line() {
    let manager = ShardedSessionManager::new();
    let payload = b"Received: from relay.example\r\nDKIM-Signature: v=1; h=From:To:Subject:Date; b=abc123\r\nSubject: Quarterly update\r\n\r\nbody";

    assert_eq!(
        manager.extract_subject_from_payload_fast(payload).as_deref(),
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
    assert_eq!(
        session.session.subject.as_deref(),
        Some("idle-timeout")
    );
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
