//! Data models

//! Performance notes:
//! - Fast UUID generation with WyRand
//! - Thread-local RNG to avoid locking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

use crate::magic_bytes::DetectedFileType;

// Fast UUID generation (about 10x faster than `Uuid::new_v4()`)

/// Global counter used to guarantee uniqueness
static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Fast UUID v4 generation with WyRand
///
/// Performance: about 10x faster than `Uuid::new_v4()`
/// Security: not suitable for security-sensitive use; intended for internal identifiers
#[inline]
pub fn fast_uuid() -> Uuid {
    // Use a fast thread-local random generator
    thread_local! {
        static RNG_STATE: std::cell::Cell<u64> = {
           // Seed with the current time and a stack address
            let time_seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
           // Use the address to diversify the per-thread seed
            let stack_addr = &time_seed as *const _ as u64;
            std::cell::Cell::new(time_seed ^ stack_addr.wrapping_mul(0x9e3779b97f4a7c15))
        };
    }

    // WyRand random number generator
    #[inline(always)]
    fn wyrand(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0xa0761d6478bd642f);
        let t = (*state as u128) * ((*state ^ 0xe7037ed1a0b428db) as u128);
        (t >> 64) as u64 ^ t as u64
    }

    let (rand1, rand2) = RNG_STATE.with(|cell| {
        let mut state = cell.get();
        let r1 = wyrand(&mut state);
        let r2 = wyrand(&mut state);
        cell.set(state);
        (r1, r2)
    });

    let counter = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let rand2 = rand2 ^ counter;

    // UUID v4 format
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&rand1.to_le_bytes());
    bytes[8..16].copy_from_slice(&rand2.to_le_bytes());

    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC4122

    Uuid::from_bytes(bytes)
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Smtp,
    Pop3,
    Imap,
    Http,
    Unknown,
}

impl Protocol {
    /// Determine the protocol from a port number
    pub fn from_port(port: u16) -> Self {
        match port {
            25 | 465 | 587 | 2525 | 2526 => Protocol::Smtp,
            110 | 995 => Protocol::Pop3,
            143 | 993 => Protocol::Imap,
            80 => Protocol::Http,
            _ => Protocol::Unknown,
        }
    }

    /// Check whether a port is encrypted
    pub fn is_encrypted_port(port: u16) -> bool {
        matches!(port, 465 | 995 | 993)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Smtp => write!(f, "SMTP"),
            Protocol::Pop3 => write!(f, "POP3"),
            Protocol::Imap => write!(f, "IMAP"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Inbound traffic
    Inbound,
    /// Outbound traffic
    Outbound,
}

// ============================================
// Session source (passive mirror vs. MTA proxy)
// ============================================

/// Source of an email session, used to distinguish capture modes
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSource {
    /// Passive mirror mode (Sniffer/libpcap capture)
    #[default]
    Sniffer,
    /// MTA proxy mode (received by the SMTP proxy)
    MtaProxy,
    /// Imported manually through the API
    Import,
}

/// Mail direction (in MTA proxy mode, determined from sender and recipient domains)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailDirection {
    /// External to internal (threat detection)
    #[default]
    Inbound,
    /// Internal to external (DLP / exfiltration detection)
    Outbound,
    /// Internal to internal (forward directly)
    Internal,
}

impl std::fmt::Display for MailDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailDirection::Inbound => write!(f, "inbound"),
            MailDirection::Outbound => write!(f, "outbound"),
            MailDirection::Internal => write!(f, "internal"),
        }
    }
}

impl std::fmt::Display for SessionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionSource::Sniffer => write!(f, "sniffer"),
            SessionSource::MtaProxy => write!(f, "mta_proxy"),
            SessionSource::Import => write!(f, "import"),
        }
    }
}

/// SMTP authentication information reconstructed from the AUTH exchange
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SmtpAuthInfo {
    /// Authentication method (PLAIN, LOGIN, CRAM-MD5, etc.)
    pub auth_method: String,
    /// Decoded username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Decoded password; skipped during serialization to avoid leakage
    #[serde(default, skip_serializing_if = "Option::is_none", skip_serializing)]
    pub password: Option<String>,
    /// Whether authentication succeeded
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_success: Option<bool>,
}

impl fmt::Debug for SmtpAuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpAuthInfo")
            .field("auth_method", &self.auth_method)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("auth_success", &self.auth_success)
            .finish()
    }
}

/// Email session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSession {
    /// Session ID.
    pub id: Uuid,
    /// Protocol type.
    pub protocol: Protocol,
    /// Client IP.
    pub client_ip: String,
    /// Client port.
    pub client_port: u16,
    /// Server IP.
    pub server_ip: String,
    /// Server port.
    pub server_port: u16,
    /// Session start time.
    pub started_at: DateTime<Utc>,
    /// Session end time.
    pub ended_at: Option<DateTime<Utc>>,
    /// Session status.
    pub status: SessionStatus,
    /// Packet count.
    pub packet_count: u32,

    pub total_bytes: usize,

    // Message metadata.
    /// Sender address (SMTP MAIL FROM).
    pub mail_from: Option<String>,
    /// Recipient list (SMTP RCPT TO).
    pub rcpt_to: Vec<String>,
    /// Parsed message subject.
    pub subject: Option<String>,

    // Extended metadata.
    #[serde(default)]
    pub content: EmailContent,
    /// Number of messages captured in this session.
    #[serde(default)]
    pub email_count: u32,
    /// Error reason for timeout or failure states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// Parsed `Message-ID`, used for session correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// SMTP authentication information extracted from the AUTH exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_info: Option<SmtpAuthInfo>,
    /// Threat level loaded from `security_verdicts` for list queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_level: Option<String>,
    /// Session source (`sniffer`, `mta_proxy`, or `import`).
    #[serde(default)]
    pub source: SessionSource,
}

/// WebSocket session signal payload.
///
/// Carries only routing / refresh metadata and intentionally excludes
/// message bodies, headers, and attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSessionSignal {
    pub id: Uuid,
    pub protocol: Protocol,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_level: Option<String>,
}

impl EmailSession {
    pub fn new(
        protocol: Protocol,
        client_ip: String,
        client_port: u16,
        server_ip: String,
        server_port: u16,
    ) -> Self {
        Self {
            id: fast_uuid(),
            protocol,
            client_ip,
            client_port,
            server_ip,
            server_port,
            started_at: Utc::now(),
            ended_at: None,
            status: SessionStatus::Active,
            packet_count: 0,
            total_bytes: 0,
            mail_from: None,
            rcpt_to: Vec::new(),
            subject: None,
            content: EmailContent::new(),
            email_count: 0,
            error_reason: None,
            message_id: None,
            auth_info: None,
            threat_level: None,
            source: SessionSource::default(),
        }
    }

    /// Build a stable key for a session.
    pub fn session_key(
        client_ip: &str,
        client_port: u16,
        server_ip: &str,
        server_port: u16,
    ) -> String {
        format!(
            "{}:{}-{}:{}",
            client_ip, client_port, server_ip, server_port
        )
    }

    pub fn is_email_complete(&self) -> bool {
        self.content.is_complete
    }

    /// Return whether the session has reached a terminal state that can be analyzed.
    pub fn is_terminal_for_analysis(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Completed | SessionStatus::Timeout
        )
    }

    /// Return whether the session contains enough content for downstream analysis.
    pub fn has_analyzable_content(&self) -> bool {
        self.mail_from.as_ref().is_some_and(|s| !s.is_empty())
            || !self.content.headers.is_empty()
            || self.content.body_text.is_some()
            || self.content.body_html.is_some()
            || !self.content.attachments.is_empty()
    }

    /// Return the number of attachments.
    pub fn attachment_count(&self) -> usize {
        self.content.attachments.len()
    }

    /// Return the number of suspicious links.
    pub fn suspicious_link_count(&self) -> usize {
        self.content.links.iter().filter(|l| l.suspicious).count()
    }

    pub fn ws_signal(&self) -> WsSessionSignal {
        WsSessionSignal::from(self)
    }

    /// Reconstruct a minimal EML byte stream from session data.
    ///
    /// The output is a best-effort RFC 2822 reconstruction:
    ///   - Original headers are written verbatim
    ///   - Body text/html is appended after the blank line separator
    ///   - Attachment binaries (decoded from base64) are appended as raw bytes
    ///
    /// Used by ClamAV scanning, YARA scanning, and EML file download.
    pub fn reconstruct_eml(&self) -> Vec<u8> {
        let estimated_size = self.content.raw_size.max(4096);
        let mut eml = Vec::with_capacity(estimated_size);

        // 1. Write headers
        for (name, value) in &self.content.headers {
            eml.extend_from_slice(name.as_bytes());
            eml.extend_from_slice(b": ");
            eml.extend_from_slice(value.as_bytes());
            eml.extend_from_slice(b"\r\n");
        }
        // Blank line separating headers from body
        eml.extend_from_slice(b"\r\n");

        // 2. Write body
        if let Some(ref text) = self.content.body_text {
            eml.extend_from_slice(text.as_bytes());
            eml.extend_from_slice(b"\r\n");
        }
        if let Some(ref html) = self.content.body_html {
            eml.extend_from_slice(html.as_bytes());
            eml.extend_from_slice(b"\r\n");
        }

        // 3. Append raw attachment bytes (decoded from base64)
        for att in &self.content.attachments {
            if let Some(ref b64) = att.content_base64
                && let Some(decoded) = decode_base64_bytes(b64)
            {
                eml.extend_from_slice(&decoded);
            }
        }

        eml
    }
}

impl From<&EmailSession> for WsSessionSignal {
    fn from(session: &EmailSession) -> Self {
        Self {
            id: session.id,
            protocol: session.protocol,
            status: session.status,
            threat_level: session.threat_level.clone(),
        }
    }
}

/// Minimal base64 decoder for attachment content.
/// Strips whitespace, tolerates padding, returns None on invalid input.
pub fn decode_base64_bytes(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &ch) in TABLE.iter().enumerate() {
        lookup[ch as usize] = i as u8;
    }

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        for (i, &b) in chunk.iter().enumerate() {
            let val = lookup[b as usize];
            if val == 255 {
                return None;
            }
            buf[i] = val;
        }

        if len >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Some(out)
}

/// Lifecycle state for a captured session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// Session is still receiving traffic.
    Active,
    /// Session ended normally.
    Completed,
    /// Session timed out before a clean shutdown.
    Timeout,
    /// Session ended because of an error.
    Error,
}

// Email content models.

/// Attachment metadata extracted from a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    /// Original file name.
    pub filename: String,
    /// MIME type such as `application/pdf`.
    pub content_type: String,
    /// Attachment size in bytes.
    pub size: usize,
    /// SHA-256 hash of the attachment payload.
    pub hash: String,
    /// Optional base64 payload when attachment content is retained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
}

/// Hyperlink extracted from message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailLink {
    /// Absolute URL.
    pub url: String,
    /// Optional anchor text associated with the link.
    pub text: Option<String>,
    /// Whether lightweight heuristics marked the link as suspicious.
    pub suspicious: bool,
}

/// One SMTP dialog entry recorded during message processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpDialogEntry {
    /// Direction of the SMTP exchange.
    pub direction: Direction,
    /// Command or response text.
    pub command: String,
    /// Raw line length in bytes.
    pub size: usize,
    /// Timestamp of the dialog entry.
    pub timestamp: DateTime<Utc>,
}

/// Maximum number of SMTP dialog entries retained per session.
pub const MAX_SMTP_DIALOG_ENTRIES: usize = 200;

/// Parsed content extracted from an email session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailContent {
    /// Message headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Plain-text body, if available.
    pub body_text: Option<String>,
    /// HTML body, if available.
    pub body_html: Option<String>,
    /// Parsed attachments.
    pub attachments: Vec<EmailAttachment>,
    /// Links extracted from the body.
    pub links: Vec<EmailLink>,
    /// Approximate raw message size in bytes.
    pub raw_size: usize,
    /// Whether the parser considers the message body complete.
    pub is_complete: bool,
    /// Whether the originating protocol session was encrypted.
    pub is_encrypted: bool,
    /// SMTP command/response transcript retained for analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub smtp_dialog: Vec<SmtpDialogEntry>,
}

impl EmailContent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    /// Look up a header value by case-insensitive header name.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn extract_attr_value_case_insensitive(tag: &str, attr_name: &str) -> Option<String> {
        for quote_char in ['"', '\''] {
            let prefix = format!("{attr_name}={quote_char}");
            if let Some(start) = tag
                .as_bytes()
                .windows(prefix.len())
                .position(|w| w.eq_ignore_ascii_case(prefix.as_bytes()))
            {
                let value_start = start + prefix.len();
                if let Some(value_end) = tag[value_start..].find(quote_char) {
                    return Some(tag[value_start..value_start + value_end].to_string());
                }
            }
        }
        None
    }

    fn normalize_anchor_text(raw: &str) -> Option<String> {
        let mut text = String::with_capacity(raw.len());
        let mut in_tag = false;
        for ch in raw.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => {
                    in_tag = false;
                    text.push(' ');
                }
                _ if !in_tag => text.push(ch),
                _ => {}
            }
        }

        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() {
            None
        } else {
            Some(collapsed)
        }
    }

    fn push_or_update_link(&mut self, url: &str, text: Option<String>) {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return;
        }

        let normalized_text = text.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        if let Some(existing) = self.links.iter_mut().find(|link| link.url == url) {
            if existing.text.is_none() && normalized_text.is_some() {
                existing.text = normalized_text;
            }
            return;
        }

        let suspicious = Self::is_suspicious_url(url);
        self.links.push(EmailLink {
            url: url.to_string(),
            text: normalized_text,
            suspicious,
        });
    }

    /// Extract HTTP and HTTPS links from the HTML body.
    pub fn extract_links_from_html(&mut self) {
        if let Some(html) = self.body_html.clone() {
            let html_lower = html.to_lowercase();
            let mut anchor_pos = 0usize;

            while let Some(start_rel) = html_lower[anchor_pos..].find("<a") {
                let start = anchor_pos + start_rel;
                let Some(tag_end_rel) = html[start..].find('>') else {
                    break;
                };
                let tag_end = start + tag_end_rel;
                let tag = &html[start..=tag_end];

                if let Some(url) = Self::extract_attr_value_case_insensitive(tag, "href") {
                    let close_start = html_lower[tag_end + 1..]
                        .find("</a>")
                        .map(|offset| tag_end + 1 + offset);
                    let anchor_text = close_start
                        .and_then(|close| Self::normalize_anchor_text(&html[tag_end + 1..close]));
                    self.push_or_update_link(&url, anchor_text);
                    anchor_pos = close_start.map(|close| close + 4).unwrap_or(tag_end + 1);
                } else {
                    anchor_pos = tag_end + 1;
                }
            }

            // Match remaining attribute-based links (including images and any hrefs we
            // didn't capture via anchor parsing above).
            let attr_prefixes: &[&str] = &["href=\"", "href='", "src=\"", "src='"];

            for prefix in attr_prefixes {
                let quote_char = prefix.as_bytes()[prefix.len() - 1]; // " or '
                let mut pos = 0;
                while pos < html.len() {
                    let search_slice = &html[pos..];
                    let found = search_slice
                        .as_bytes()
                        .windows(prefix.len())
                        .position(|w| w.eq_ignore_ascii_case(prefix.as_bytes()));

                    let start = match found {
                        Some(s) => s,
                        None => break,
                    };

                    let url_start = pos + start + prefix.len();
                    if url_start >= html.len() {
                        break;
                    }

                    // Stop at the closing quote and treat the enclosed text as the URL.
                    if let Some(quote_end) = html[url_start..].find(quote_char as char) {
                        let url = &html[url_start..url_start + quote_end];
                        self.push_or_update_link(url, None);
                        pos = url_start + quote_end + 1;
                    } else {
                        pos = url_start + 1;
                    }
                }
            }
        }
    }

    /// Apply lightweight heuristics to flag obviously suspicious URLs.
    pub fn is_suspicious_url(url: &str) -> bool {
        // Flag URLs that use a literal IPv4 address instead of a hostname.
        let after_protocol = if let Some(rest) = url.strip_prefix("http://") {
            Some(rest)
        } else {
            url.strip_prefix("https://")
        };
        if let Some(after_protocol) = after_protocol {
            let domain = after_protocol.split('/').next().unwrap_or("");
            let domain_part = domain.split(':').next().unwrap_or("");
            if domain_part.parse::<std::net::Ipv4Addr>().is_ok() {
                return true;
            }
        }

        // Flag login-like paths on domains that are not in a short allowlist.
        let suspicious_patterns = [
            "login",
            "signin",
            "account",
            "verify",
            "secure",
            "update",
            "confirm",
            "password",
            "credential",
            "authenticate",
        ];

        let url_lower = url.to_lowercase();
        for pattern in suspicious_patterns {
            if url_lower.contains(pattern) {
                // Skip common major domains that frequently appear in legitimate mail.
                let known_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com"];
                let is_known = known_domains.iter().any(|d| url_lower.contains(d));
                if !is_known {
                    return true;
                }
            }
        }

        false
    }
}

/// State machine for SMTP session parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpState {
    /// Connection established, no SMTP greeting observed yet.
    #[default]
    Connected,
    /// `EHLO` or `HELO` was seen.
    Greeted,
    /// Authentication succeeded.
    Authenticated,
    /// `MAIL FROM` was accepted.
    MailFrom,
    /// At least one `RCPT TO` was accepted.
    RcptTo,
    /// The session is receiving message body data (DATA command).
    Data,
    /// The session is receiving BDAT chunk data (RFC 3030 CHUNKING).
    BdatData,
    /// End of message data was observed.
    DataDone,
    /// `QUIT` was observed.
    Quit,
}

/// Aggregate traffic statistics shown in the UI and WebSocket updates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Total sessions seen since startup.
    pub total_sessions: u64,
    /// Sessions that are currently active.
    pub active_sessions: u64,
    /// Total packets processed.
    pub total_packets: u64,
    /// Total bytes processed.
    pub total_bytes: u64,
    /// SMTP session count.
    pub smtp_sessions: u64,
    /// POP3 session count.
    pub pop3_sessions: u64,
    /// IMAP session count.
    pub imap_sessions: u64,
    /// Packet throughput.
    pub packets_per_second: f64,
    /// Byte throughput.
    pub bytes_per_second: f64,
}

/// Compact security verdict payload sent over WebSocket updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerdictSummary {
    pub verdict_id: Uuid,
    pub session_id: Uuid,
    pub threat_level: String,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub summary: String,
    pub modules_run: u32,
    pub modules_flagged: u32,
    pub total_duration_ms: u64,
}

/// Login activity bucket for a single hour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HourlyLoginEntry {
    /// Hour bucket in ISO 8601 form such as `2026-03-02T14:00:00Z`.
    pub hour: String,
    /// SMTP authentication attempts.
    pub smtp: u64,
    /// POP3 login attempts.
    pub pop3: u64,
    /// IMAP login attempts.
    pub imap: u64,
    /// HTTP login attempts.
    pub http: u64,
    /// Total login attempts across all protocols.
    pub total: u64,
}

/// Aggregate external-login statistics for the last 24 hours.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalLoginStats {
    /// Hourly buckets in chronological order.
    pub hourly: Vec<HourlyLoginEntry>,
    /// Total logins in the last 24 hours.
    pub total_24h: u64,
    /// SMTP logins in the last 24 hours.
    pub smtp_24h: u64,
    /// POP3 logins in the last 24 hours.
    pub pop3_24h: u64,
    /// IMAP logins in the last 24 hours.
    pub imap_24h: u64,
    /// HTTP logins in the last 24 hours.
    pub http_24h: u64,
    /// Successful authentications in the last 24 hours.
    pub success_24h: u64,
    /// Failed authentications in the last 24 hours.
    pub failed_24h: u64,
    /// Unique source IPs seen in the last 24 hours.
    #[serde(default)]
    pub unique_ips_24h: u64,
}

// Data security model types for HTTP analysis.

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
    Other,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Other => write!(f, "OTHER"),
        }
    }
}

/// Data security event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSecurityIncidentType {
    /// Draft abuse risk
    DraftBoxAbuse,
    /// File transit risk
    FileTransitAbuse,
    /// Self-send
    SelfSending,
    /// Traffic anomaly (too many sensitive operations from one user/IP in a short time)
    VolumeAnomaly,
    /// JR/T 0197-2020 compliance threshold alert (sensitive data volume reached the regulatory threshold)
    JrtComplianceViolation,
}

impl std::fmt::Display for DataSecurityIncidentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSecurityIncidentType::DraftBoxAbuse => write!(f, "draft_box_abuse"),
            DataSecurityIncidentType::FileTransitAbuse => write!(f, "file_transit_abuse"),
            DataSecurityIncidentType::SelfSending => write!(f, "self_sending"),
            DataSecurityIncidentType::VolumeAnomaly => write!(f, "volume_anomaly"),
            DataSecurityIncidentType::JrtComplianceViolation => {
                write!(f, "jrt_compliance_violation")
            }
        }
    }
}

/// Severity level for a data security incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataSecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for DataSecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSecuritySeverity::Info => write!(f, "info"),
            DataSecuritySeverity::Low => write!(f, "low"),
            DataSecuritySeverity::Medium => write!(f, "medium"),
            DataSecuritySeverity::High => write!(f, "high"),
            DataSecuritySeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A single HTTP request/response pair used for data security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSession {
    /// Unique identifier.
    pub id: Uuid,
    /// Client IP address.
    pub client_ip: String,
    /// Client TCP port.
    pub client_port: u16,
    /// Server IP address.
    pub server_ip: String,
    /// Server TCP port.
    pub server_port: u16,
    /// HTTP method.
    pub method: HttpMethod,
    /// Request URI, including path and query string.
    pub uri: String,
    /// `Host` header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `Content-Type` header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Request body size in bytes.
    #[serde(default)]
    pub request_body_size: usize,
    /// Truncated request body retained for analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    /// HTTP response status code, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    /// Uploaded file name extracted from multipart form data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_filename: Option<String>,
    /// Uploaded file size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_file_size: Option<usize>,
    /// User identifier extracted from cookies or form fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_user: Option<String>,
    /// Recipients inferred in self-send scenarios.
    #[serde(default)]
    pub detected_recipients: Vec<String>,
    /// Sender inferred in self-send scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_sender: Option<String>,
    /// File type inferred from magic-byte inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_file_type: Option<DetectedFileType>,
    /// Whether the request body is binary; binary bodies skip text-oriented DLP scanning.
    #[serde(default)]
    pub body_is_binary: bool,
    /// Description of a mismatch between the file extension and detected file type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type_mismatch: Option<String>,
    /// Temporary file path for large bodies written to disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_temp_file: Option<String>,
    /// Whether TCP reassembly contained gaps, indicating potentially incomplete content.
    #[serde(default)]
    pub has_gaps: bool,
    /// Capture timestamp.
    pub timestamp: DateTime<Utc>,
    /// Associated network session ID, when correlated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_session_id: Option<Uuid>,
}

impl HttpSession {
    /// Create a new HTTP session record with default optional fields.
    pub fn new(
        client_ip: String,
        client_port: u16,
        server_ip: String,
        server_port: u16,
        method: HttpMethod,
        uri: String,
    ) -> Self {
        Self {
            id: fast_uuid(),
            client_ip,
            client_port,
            server_ip,
            server_port,
            method,
            uri,
            host: None,
            content_type: None,
            request_body_size: 0,
            request_body: None,
            response_status: None,
            uploaded_filename: None,
            uploaded_file_size: None,
            detected_user: None,
            detected_recipients: Vec::new(),
            detected_sender: None,
            detected_file_type: None,
            body_is_binary: false,
            file_type_mismatch: None,
            body_temp_file: None,
            has_gaps: false,
            timestamp: Utc::now(),
            network_session_id: None,
        }
    }
}

/// A data security incident derived from an HTTP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSecurityIncident {
    /// Unique identifier.
    pub id: Uuid,
    /// Associated HTTP session ID.
    pub http_session_id: Uuid,
    /// Incident type.
    pub incident_type: DataSecurityIncidentType,
    /// Severity level.
    pub severity: DataSecuritySeverity,
    /// Confidence score in the range `0.0..=1.0`.
    pub confidence: f64,
    /// Human-readable summary.
    pub summary: String,
    /// Evidence attached to the incident.
    pub evidence: Vec<crate::security::Evidence>,
    /// Optional structured detail payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// DLP match categories contributing to the finding.
    #[serde(default)]
    pub dlp_matches: Vec<String>,
    /// Source client IP.
    pub client_ip: String,
    /// Detected user identifier, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_user: Option<String>,
    /// Request URI.
    #[serde(default)]
    pub request_url: String,
    /// Target host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP method as a string.
    #[serde(default)]
    pub method: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Aggregate data security statistics used by dashboards and APIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataSecurityStats {
    /// Total incident count.
    pub total_incidents: u64,
    /// Draft-box abuse incident count.
    pub draft_abuse_count: u64,
    /// File-transit incident count.
    pub file_transit_count: u64,
    /// Self-send incident count.
    pub self_send_count: u64,
    /// Volume anomaly incident count.
    pub volume_anomaly_count: u64,
    /// JR/T 0197-2020 compliance incident count.
    #[serde(default)]
    pub jrt_compliance_count: u64,
    /// High-severity incidents observed in the last 24 hours.
    pub high_severity_24h: u64,
    /// Incident counts grouped by severity label.
    #[serde(default)]
    pub incidents_by_severity: std::collections::HashMap<String, u64>,
    /// Hourly HTTP session counts for the last 24 hours, oldest to newest.
    #[serde(default)]
    pub hourly_sessions: Vec<HourlyBucket>,
    /// Hourly incident counts for the last 24 hours.
    #[serde(default)]
    pub hourly_incidents: Vec<HourlyBucket>,
}

/// Per-hour statistics bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyBucket {
    /// Hour label such as `14:00`.
    pub hour: String,
    /// Count for that hour.
    pub count: u64,
}

/// WebSocket message variants emitted by the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsMessage {
    /// Newly created session.
    NewSession(WsSessionSignal),
    /// Session state update.
    SessionUpdate(WsSessionSignal),
    /// Traffic statistics update.
    StatsUpdate(TrafficStats),
    /// Completed security verdict.
    SecurityVerdict(SecurityVerdictSummary),
    /// Data security incident alert.
    DataSecurityAlert(DataSecurityIncident),
    /// Generic alert message, typically for P0-P3 notifications.
    Alert(String),
    /// Internal control message used to tear down authenticated WebSocket sessions.
    SessionInvalidated,
    /// Heartbeat ping.
    Ping,
    /// Heartbeat response.
    Pong,
}

#[cfg(test)]
mod tests {
    use super::{EmailContent, EmailSession, Protocol, SessionStatus};

    #[test]
    fn test_extract_links_from_html_captures_anchor_text() {
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<a href=\"https://evil.example/login\"><span>https://portal.example.com</span></a>"
                .to_string(),
        );

        content.extract_links_from_html();

        assert_eq!(content.links.len(), 1);
        assert_eq!(
            content.links[0].text.as_deref(),
            Some("https://portal.example.com")
        );
    }

    #[test]
    fn test_timeout_session_is_terminal_for_analysis() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );

        assert!(!session.is_terminal_for_analysis());

        session.status = SessionStatus::Timeout;
        assert!(session.is_terminal_for_analysis());

        session.status = SessionStatus::Completed;
        assert!(session.is_terminal_for_analysis());
    }
}
