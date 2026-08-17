//! SessionType

//! `SessionKey`, `CompactIp`, `Sessiondata`, `SidUserEntry` wait Type.

use crate::capture::{IpAddr, RawpacketInfo};
use crate::parser::http_state::HttpRequestStateMachine;
use crate::parser::smtp_state::SmtpStateMachine;
use crate::stream::TcpHalfStream;
use std::time::Instant;
use vigilyx_core::{Direction, EmailSession};

// Session (store + FxHash)

/// Session (store)
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct SessionKey {
    client_ip: CompactIp,
    server_ip: CompactIp,
    /// Port packet 1 u32
    port_pair: u32,
}

/// IP store (16 Byte, IPv4/IPv6)
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct CompactIp {
    bytes: [u8; 16],
    is_v6: bool,
}

impl CompactIp {
    #[inline(always)]
    pub fn from_ip_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let mut bytes = [0u8; 16];
                bytes[0..4].copy_from_slice(&octets);
                Self {
                    bytes,
                    is_v6: false,
                }
            }
            IpAddr::V6(v6) => Self {
                bytes: v6.octets(),
                is_v6: true,
            },
        }
    }
}

impl std::fmt::Display for CompactIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_v6 {
            write!(f, "{}", std::net::Ipv6Addr::from(self.bytes))
        } else {
            write!(
                f,
                "{}",
                std::net::Ipv4Addr::new(self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3])
            )
        }
    }
}

impl SessionKey {
    #[inline(always)]
    pub fn new(packet: &RawpacketInfo) -> Self {
        let (client_ip, client_port, server_ip, server_port) = match packet.direction {
            Direction::Outbound => (
                CompactIp::from_ip_addr(&packet.src_ip),
                packet.src_port,
                CompactIp::from_ip_addr(&packet.dst_ip),
                packet.dst_port,
            ),
            Direction::Inbound => (
                CompactIp::from_ip_addr(&packet.dst_ip),
                packet.dst_port,
                CompactIp::from_ip_addr(&packet.src_ip),
                packet.src_port,
            ),
        };

        let port_pair = ((client_port as u32) << 16) | (server_port as u32);

        Self {
            client_ip,
            server_ip,
            port_pair,
        }
    }

    /// Getclient IP (Used forrate limiting)
    #[inline(always)]
    pub fn client_ip_from_packet(packet: &RawpacketInfo) -> CompactIp {
        match packet.direction {
            Direction::Outbound => CompactIp::from_ip_addr(&packet.src_ip),
            Direction::Inbound => CompactIp::from_ip_addr(&packet.dst_ip),
        }
    }
}

/// Sessiondata (Internal)
pub struct Sessiondata {
    pub session: EmailSession,
    pub last_activity: Instant,
    /// 1 packet, timeout/
    pub last_packet_at: chrono::DateTime<chrono::Utc>,
    /// 1 packet
    pub last_packet_direction: Direction,
    /// 1 packet TCP flags
    pub last_packet_tcp_flags: u8,
    /// 1 packet sequence number
    pub last_packet_seq: u32,
    /// 1 packet payload
    pub last_packet_payload_len: usize,
    /// SMTP State machine (Used fortracing DATA SegmentAndParseemailContent)
    pub smtp_state: Option<SmtpStateMachine>,
    /// HTTP RequestState machine (Used forFrom TCP StreamMediumsplitcomplete HTTP Request)
    pub http_state: Option<HttpRequestStateMachine>,
    /// client Servicehandlerof TCP Streambuffer (Used forStreamreassemble)
    pub client_stream: TcpHalfStream,
    /// Servicehandler clientof TCP Streambuffer (Used forStreamreassemble)
    pub server_stream: TcpHalfStream,
    /// Time/CountProcessofclientdata
    pub client_processed_offset: usize,
    /// Time/CountProcessofServicehandlerdata
    pub server_processed_offset: usize,
    /// client->server gap,
    pub client_gap_logged_bytes: usize,
    /// server->client gap,
    pub server_gap_logged_bytes: usize,
    /// active_sessions,
    pub active_counter_open: bool,
    /// client TCP FIN/RST
    pub client_tcp_closed: bool,
    /// server TCP FIN/RST
    pub server_tcp_closed: bool,
    /// SYN ()
    pub created_without_syn: bool,
    /// First worker that handled this session.
    pub owner_worker_id: Option<usize>,
    /// Most recent worker that handled this session.
    pub last_worker_id: Option<usize>,
    /// Number of times packets for this session were seen on a non-owner worker.
    pub worker_switch_count: u32,
    /// " SMTP ",
    pub smtp_restore_issue_logged: bool,
    /// "SMTP DATA/ ",
    pub smtp_pending_diag_logged: bool,
    /// dirtyMark: SessiondataOccur ofUpdate, Need/Require NewPublish API
    pub dirty: bool,
    /// Session (Used fordirtyQueuelookup)
    pub key: SessionKey,
    /// client IP (Used forSession IP rate limitingcounter)
    pub client_compact_ip: CompactIp,
    /// `is_encrypted` was set by the mid-stream TLS-record magic heuristic (not
    /// by an encrypted port or a confirmed STARTTLS). Such sessions keep
    /// feeding the parser so a later legitimate SMTP line revokes the mark.
    pub tls_magic_marked: bool,
    /// The admission slot was already released when the session reached a
    /// terminal state; cleanup must not decrement `session_slots` again.
    pub slot_released: bool,
    /// Stream buffers were evicted under reassembly-budget pressure while the
    /// session was still Active. Content parsed after the eviction is
    /// incomplete by construction: HTTP sessions must carry the gap flag and
    /// email sessions an `inspection:` error reason.
    pub stream_buffers_evicted: bool,
    /// The HTTP request state machine permanently lost framing
    /// synchronization (malformed chunked body). Subsequent requests on this
    /// connection are no longer split; surfaced as inspection-limited.
    pub http_desynced: bool,
    /// A cleartext POP3 RETR / IMAP FETCH BODY[] transfer was observed. The
    /// sniffer does not reassemble mail content for these protocols, so the
    /// session carries an inspection coverage gap instead of a verdict.
    pub mail_retrieval_seen: bool,
    /// `protocol_anomaly` was already folded into `session.error_reason`;
    /// guards against repeated dirty marking on the terminal paths.
    pub protocol_anomaly_marked: bool,
}

/// sid -> user Mappingentry (Contains LRU timestamp)
#[derive(Clone)]
pub(crate) struct SidUserEntry {
    pub user: String,
    pub last_access: std::time::Instant,
}
