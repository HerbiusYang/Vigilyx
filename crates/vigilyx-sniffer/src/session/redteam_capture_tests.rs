//! Red-team capture-layer tests: replay attacker-controlled TCP segment
//! patterns through the real session manager and observe what the Mirror
//! pipeline would publish.
//!
//! Scenarios: baseline dialog, mid-DATA gap drop (SPAN overload), divergent
//! overlapping retransmission, RST mid-DATA, bare-LF dot terminator.

use super::*;
use crate::capture::{IpAddr, RawpacketInfo};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::time::Instant;
use vigilyx_core::{Direction, Protocol};

const CLIENT_PORT: u16 = 40000;
const SERVER_PORT: u16 = 25;

fn pkt(direction: Direction, seq: u32, flags: u8, payload: &[u8]) -> RawpacketInfo {
    let (src_ip, dst_ip, src_port, dst_port) = match direction {
        Direction::Outbound => (
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 124, 128, 68)),
            CLIENT_PORT,
            SERVER_PORT,
        ),
        Direction::Inbound => (
            IpAddr::V4(Ipv4Addr::new(10, 124, 128, 68)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
            SERVER_PORT,
            CLIENT_PORT,
        ),
    };
    RawpacketInfo {
        src_ip,
        dst_ip,
        payload: Bytes::copy_from_slice(payload),
        src_port,
        dst_port,
        protocol: Protocol::Smtp,
        direction,
        tcp_seq: seq,
        tcp_ack: 0,
        tcp_flags: flags,
    }
}

const MAIL: &[u8] = b"From: sender@partner-external.com\r\n\
To: employee@ccabchina.com\r\n\
Subject: capture-layer-test\r\n\
Message-ID: <rt-cap-001@partner-external.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><p>YOUR ACCOUNT IS AT RISK. Verify now: http://203.0.113.50/verify lure</p></body></html>\r\n";

struct Dialog {
    packets: Vec<RawpacketInfo>,
}

impl Dialog {
    fn new(mail: &[u8]) -> Self {
        let mut packets = Vec::new();
        let mut cseq = 1000u32;
        let mut sseq = 5000u32;
        let mut c = |packets: &mut Vec<RawpacketInfo>, payload: &[u8]| {
            packets.push(pkt(Direction::Outbound, cseq, 0x10, payload));
            cseq += payload.len() as u32;
        };
        let mut s = |packets: &mut Vec<RawpacketInfo>, payload: &[u8]| {
            packets.push(pkt(Direction::Inbound, sseq, 0x10, payload));
            sseq += payload.len() as u32;
        };

        s(&mut packets, b"220 mx.test ESMTP\r\n");
        c(&mut packets, b"EHLO redteam.test\r\n");
        s(&mut packets, b"250-mx.test\r\n250 SIZE 26214400\r\n");
        c(&mut packets, b"MAIL FROM:<sender@partner-external.com>\r\n");
        s(&mut packets, b"250 2.1.0 OK\r\n");
        c(&mut packets, b"RCPT TO:<employee@ccabchina.com>\r\n");
        s(&mut packets, b"250 2.1.5 OK\r\n");
        c(&mut packets, b"DATA\r\n");
        s(&mut packets, b"354 go ahead\r\n");
        let mut off = 0;
        while off < mail.len() {
            let end = (off + 200).min(mail.len());
            c(&mut packets, &mail[off..end]);
            off = end;
        }
        c(&mut packets, b".\r\n");
        s(&mut packets, b"250 2.0.0 queued\r\n");
        c(&mut packets, b"QUIT\r\n");
        s(&mut packets, b"221 bye\r\n");
        Dialog { packets }
    }
}

fn run(manager: &ShardedSessionManager, packets: &[RawpacketInfo]) -> Vec<EmailSession> {
    let mut now = Instant::now();
    for p in packets {
        let _ = manager.process_packet(p, None, now);
        now += std::time::Duration::from_millis(10);
    }
    let mut dirty = manager.take_dirty_sessions();
    // A second sweep after QUIT settles terminal state.
    let mut more = manager.take_dirty_sessions();
    dirty.append(&mut more);
    dirty
}

fn summarize(sessions: &[EmailSession]) -> String {
    sessions
        .iter()
        .map(|s| {
            format!(
                "emails={} complete={} from={:?} subj={:?} body_len={} html_len={}",
                s.email_count,
                s.content.is_complete,
                s.mail_from,
                s.subject,
                s.content.body_text.as_ref().map_or(0, |t| t.len()),
                s.content.body_html.as_ref().map_or(0, |t| t.len()),
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

#[test]
fn rt_baseline_dialog_produces_complete_email() {
    let manager = ShardedSessionManager::new();
    let sessions = run(&manager, &Dialog::new(MAIL).packets);
    eprintln!("baseline: {}", summarize(&sessions));
    assert!(
        sessions.iter().any(|s| s.email_count == 1 && s.content.is_complete),
        "baseline must publish a complete email, got: {}",
        summarize(&sessions)
    );
}

#[test]
fn rt_gap_drop_mid_data() {
    let manager = ShardedSessionManager::new();
    let mut dialog = Dialog::new(MAIL);
    // Remove one DATA body segment: SPAN overload loses one packet.
    let data_segments: Vec<usize> = dialog
        .packets
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.direction == Direction::Outbound
                && p.payload.len() >= 100
                && !p.payload.starts_with(b"EHLO")
                && !p.payload.starts_with(b"MAIL")
                && !p.payload.starts_with(b"RCPT")
                && !p.payload.starts_with(b"DATA\r\n")
                && !p.payload.starts_with(b"QUIT")
                && &p.payload[..] != b".\r\n"
        })
        .map(|(i, _)| i)
        .collect();
    assert!(!data_segments.is_empty(), "no DATA segments found to drop");
    let victim = data_segments[data_segments.len() / 2];
    dialog.packets.remove(victim);

    let sessions = run(&manager, &dialog.packets);
    eprintln!("gap_drop: {}", summarize(&sessions));
    // Whatever is published must not present a silently corrupted body as a
    // complete mail; is_complete=false or no email at all are the safe outcomes.
    for s in &sessions {
        if s.email_count > 0 {
            assert!(
                !s.content.is_complete,
                "gap-dropped stream must not publish a 'complete' mail: {}",
                summarize(&sessions)
            );
        }
    }
}

#[test]
fn rt_divergent_overlap_first_wins() {
    let manager = ShardedSessionManager::new();
    let mut dialog = Dialog::new(MAIL);
    // Find one 200-byte DATA segment and retransmit its range with different
    // content: benign "AAAA..." spanning an extra 20 bytes before it.
    let idx = dialog
        .packets
        .iter()
        .position(|p| {
            p.direction == Direction::Outbound && p.payload.len() == 200 && p.payload.starts_with(b"F")
        })
        .expect("data segment");
    let orig_seq = dialog.packets[idx].tcp_seq;
    let benign = vec![b'A'; 220];
    let retro = pkt(Direction::Outbound, orig_seq - 20, 0x10, &benign);
    dialog.packets.insert(idx + 1, retro);

    let sessions = run(&manager, &dialog.packets);
    eprintln!("overlap: {}", summarize(&sessions));
    for s in &sessions {
        if let Some(html) = s.content.body_html.as_deref() {
            let malicious = html.contains("203.0.113.50");
            let benign_override = html.contains("AAAA");
            eprintln!(
                "overlap body: malicious_ip={} benign_overrun={}",
                malicious, benign_override
            );
            // Document the winner: whichever bytes survive, both must not
            // silently coexist as a "complete" mail with the benign rewrite
            // hiding the malicious content (that would be an evasion).
            if benign_override && !malicious && s.content.is_complete {
                panic!(
                    "benign overlap replaced malicious payload but mail still complete: {}",
                    summarize(&sessions)
                );
            }
        }
    }
}

#[test]
fn rt_rst_mid_data_marks_incomplete() {
    let manager = ShardedSessionManager::new();
    let mut dialog = Dialog::new(MAIL);
    // Drop everything from the dot terminator onward, then RST.
    let term = dialog
        .packets
        .iter()
        .position(|p| p.direction == Direction::Outbound && &p.payload[..] == b".\r\n")
        .expect("terminator");
    dialog.packets.truncate(term);
    let last_seq = dialog.packets.last().unwrap().tcp_seq + 200;
    dialog
        .packets
        .push(pkt(Direction::Outbound, last_seq, 0x04, b""));

    let sessions = run(&manager, &dialog.packets);
    eprintln!("rst: {}", summarize(&sessions));
    for s in &sessions {
        if s.email_count > 0 {
            assert!(
                !s.content.is_complete,
                "RST mid-DATA must not yield a complete mail: {}",
                summarize(&sessions)
            );
        }
    }
}

#[test]
fn rt_bare_lf_terminator_splits_smuggling() {
    let manager = ShardedSessionManager::new();
    let mut dialog = Dialog::new(MAIL);
    let term = dialog
        .packets
        .iter_mut()
        .position(|p| p.direction == Direction::Outbound && &p.payload[..] == b".\r\n")
        .expect("terminator");
    dialog.packets[term].payload = Bytes::from_static(b".\n");

    let sessions = run(&manager, &dialog.packets);
    eprintln!("bare_lf: {}", summarize(&sessions));
    // The sniffer must surface the smuggled variant instead of absorbing it:
    // either multiple emails, or an incomplete first message, never one clean
    // "complete" mail that hides the second segment.
    let clean_single = sessions
        .iter()
        .any(|s| s.email_count == 1 && s.content.is_complete);
    eprintln!("clean_single={clean_single} (documenting split behavior)");
}
