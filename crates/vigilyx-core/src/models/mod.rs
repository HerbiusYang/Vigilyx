//! Data models

//! Performance notes:
//! - Fast UUID generation with WyRand
//! - Thread-local RNG to avoid locking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

/// Protocol port sets injected at startup (sniffer resolves env + DB overrides
/// before capture begins). When unset, `Protocol::from_port` falls back to the
/// hardcoded defaults below, so other binaries linking this crate see no change.
static PROTOCOL_PORTS: std::sync::RwLock<Option<ProtocolPorts>> = std::sync::RwLock::new(None);

#[derive(Debug, Clone, Default)]
struct ProtocolPorts {
    smtp: Vec<u16>,
    pop3: Vec<u16>,
    imap: Vec<u16>,
    http: Vec<u16>,
}

impl ProtocolPorts {
    fn lookup(&self, port: u16) -> Option<Protocol> {
        if self.smtp.contains(&port) {
            Some(Protocol::Smtp)
        } else if self.pop3.contains(&port) {
            Some(Protocol::Pop3)
        } else if self.imap.contains(&port) {
            Some(Protocol::Imap)
        } else if self.http.contains(&port) {
            Some(Protocol::Http)
        } else {
            None
        }
    }
}

impl Protocol {
    /// Inject the configured protocol port sets (env `SMTP_PORTS`/`POP3_PORTS`/
    /// `IMAP_PORTS`/`HTTP_PORTS`, possibly DB-overridden). Called once by the
    /// sniffer during startup; replaces any previously configured sets.
    pub fn configure_ports(smtp: &[u16], pop3: &[u16], imap: &[u16], http: &[u16]) {
        if let Ok(mut guard) = PROTOCOL_PORTS.write() {
            *guard = Some(ProtocolPorts {
                smtp: smtp.to_vec(),
                pop3: pop3.to_vec(),
                imap: imap.to_vec(),
                http: http.to_vec(),
            });
        }
    }

    /// Determine the protocol from a port number.
    ///
    /// Configured port sets take precedence; the hardcoded defaults remain as a
    /// fallback so well-known ports are still classified when configuration
    /// lists are partial or were never injected.
    pub fn from_port(port: u16) -> Self {
        if let Ok(guard) = PROTOCOL_PORTS.read()
            && let Some(ports) = guard.as_ref()
            && let Some(protocol) = ports.lookup(port)
        {
            return protocol;
        }
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
        !self.content.headers.is_empty()
            || self.content.body_text.is_some()
            || self.content.body_html.is_some()
            || !self.content.attachments.is_empty()
            || !self.content.links.is_empty()
            || self
                .error_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("inspection:"))
    }

    /// Return the number of attachments.
    pub fn attachment_count(&self) -> usize {
        self.content.attachments.len()
    }

    /// Return the number of suspicious links.
    pub fn suspicious_link_count(&self) -> usize {
        self.content.links.iter().filter(|l| l.suspicious).count()
    }

    /// Estimate the reconstructed EML byte size without decoding attachment payloads.
    pub fn estimated_reconstructed_eml_size(&self) -> usize {
        let mut reconstructed_estimate = 2usize; // header/body separator
        for (name, value) in &self.content.headers {
            reconstructed_estimate = reconstructed_estimate
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(4);
        }
        if let Some(text) = &self.content.body_text {
            reconstructed_estimate = reconstructed_estimate
                .saturating_add(text.len())
                .saturating_add(2);
        }
        if let Some(html) = &self.content.body_html {
            reconstructed_estimate = reconstructed_estimate
                .saturating_add(html.len())
                .saturating_add(2);
        }
        for attachment in &self.content.attachments {
            if let Some(content_base64) = &attachment.content_base64 {
                reconstructed_estimate = reconstructed_estimate
                    .saturating_add(content_base64.len().saturating_mul(3) / 4);
            }
        }

        self.content.raw_size.max(reconstructed_estimate)
    }

    /// Reconstruct EML only when the estimated and actual output fit the caller's cap.
    pub fn reconstruct_eml_limited(&self, max_bytes: usize) -> Option<Vec<u8>> {
        if self.estimated_reconstructed_eml_size() > max_bytes {
            return None;
        }
        let eml = self.reconstruct_eml();
        if eml.len() > max_bytes {
            None
        } else {
            Some(eml)
        }
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
    decode_base64_bytes_limited(input, usize::MAX)
}

/// Decode base64 while enforcing a hard decoded-size cap.
///
/// The cap is checked before allocation using the cleaned input length and again
/// while emitting bytes, so malformed or whitespace-heavy payloads cannot force
/// unbounded allocations in attachment scanners.
pub fn decode_base64_bytes_limited(input: &str, max_decoded_bytes: usize) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &ch) in TABLE.iter().enumerate() {
        lookup[ch as usize] = i as u8;
    }

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let estimated_decoded = bytes.len().saturating_mul(3) / 4;
    if estimated_decoded > max_decoded_bytes {
        return None;
    }

    let mut out = Vec::with_capacity(estimated_decoded);

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
            if out.len() >= max_decoded_bytes {
                return None;
            }
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            if out.len() >= max_decoded_bytes {
                return None;
            }
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            if out.len() >= max_decoded_bytes {
                return None;
            }
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

/// Maximum number of links retained per message. A hostile 25MB HTML body can
/// carry ~600k distinct hrefs; without a hard cap the dedup path alone is
/// quadratic in link count and link_scan / DB persistence amplify it further.
pub const MAX_EMAIL_LINKS: usize = 5000;

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
    /// Whether parsing degraded part of the message (multipart part/depth
    /// budget exceeded, or an oversized attachment body was not retained).
    /// Downstream attachment modules must treat this as an inspection
    /// coverage gap, never as "fully scanned".
    #[serde(default)]
    pub truncated: bool,
    /// Number of attachments dropped because the per-message attachment count
    /// budget was exceeded. Zero means every declared attachment is present.
    #[serde(default)]
    pub dropped_attachments: usize,
    /// Whether link extraction hit [`MAX_EMAIL_LINKS`] and dropped further
    /// links. Downstream modules must treat this as an inspection coverage
    /// gap, never as "all links scanned".
    #[serde(default)]
    pub links_truncated: bool,
    /// O(1) dedup index mirroring `links` (keyed by `EmailLink::url`).
    /// Rebuilt lazily when links were pushed externally; never serialized.
    #[serde(skip)]
    pub link_index: HashSet<String>,
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
        let bytes = tag.as_bytes();
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_whitespace()
                    || matches!(bytes[cursor], b'<' | b'/' | b'>'))
            {
                cursor += 1;
            }

            let name_start = cursor;
            while cursor < bytes.len()
                && !bytes[cursor].is_ascii_whitespace()
                && !matches!(bytes[cursor], b'=' | b'<' | b'/' | b'>')
            {
                cursor += 1;
            }
            if name_start == cursor {
                cursor += 1;
                continue;
            }

            let name = &bytes[name_start..cursor];
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b'=') {
                continue;
            }
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }

            let (value_start, value_end) = match bytes.get(cursor).copied() {
                Some(quote @ (b'"' | b'\'')) => {
                    cursor += 1;
                    let value_start = cursor;
                    while cursor < bytes.len() && bytes[cursor] != quote {
                        cursor += 1;
                    }
                    (value_start, cursor)
                }
                Some(_) => {
                    let value_start = cursor;
                    while cursor < bytes.len()
                        && !bytes[cursor].is_ascii_whitespace()
                        && bytes[cursor] != b'>'
                    {
                        cursor += 1;
                    }
                    (value_start, cursor)
                }
                None => return None,
            };

            if name.eq_ignore_ascii_case(attr_name.as_bytes()) {
                return Some(Self::decode_html_attribute_entities(
                    &tag[value_start..value_end],
                ));
            }
        }
        None
    }

    fn decode_html_attribute_entities(value: &str) -> String {
        let mut decoded = String::with_capacity(value.len());
        let mut cursor = 0usize;

        while let Some(relative_start) = value[cursor..].find('&') {
            let start = cursor + relative_start;
            decoded.push_str(&value[cursor..start]);

            let rest = &value[start + 1..];

            // Numeric character reference (`&#58` / `&#x3A`): browsers decode
            // these even without the terminating semicolon (HTML5 parse-error
            // recovery), so `href="https&#58//evil.com"` renders as a working
            // https:// link. The extractor must accept the optional ';' too,
            // otherwise the whole URL vanishes from the link layer.
            if let Some(after_hash) = rest.strip_prefix('#') {
                let (digits, radix) =
                    if let Some(hex) = after_hash.strip_prefix('x').or_else(|| after_hash.strip_prefix('X')) {
                        (hex, 16)
                    } else {
                        (after_hash, 10)
                    };
                let prefix_len = rest.len() - digits.len(); // 1 ("#") or 2 ("#x")
                let digit_len = digits
                    .bytes()
                    .take_while(|b| {
                        if radix == 16 {
                            b.is_ascii_hexdigit()
                        } else {
                            b.is_ascii_digit()
                        }
                    })
                    .count();
                let has_semi = digits[digit_len..].starts_with(';');
                if digit_len > 0
                    && digit_len <= 8
                    && let Some(ch) = u32::from_str_radix(&digits[..digit_len], radix)
                        .ok()
                        .and_then(char::from_u32)
                {
                    decoded.push(ch);
                    cursor = start + 1 + prefix_len + digit_len + usize::from(has_semi);
                } else {
                    decoded.push('&');
                    cursor = start + 1;
                }
                continue;
            }

            // Named references still require the semicolon. The length cap
            // (12, generous — the longest supported name is 5 chars) keeps a
            // distant ';' from turning plain text into an entity candidate.
            let Some(relative_end) = rest.find(';') else {
                decoded.push_str(&value[start..]);
                return decoded;
            };
            let entity = &rest[..relative_end];
            if entity.is_empty() || entity.len() > 12 {
                decoded.push('&');
                cursor = start + 1;
                continue;
            }

            let replacement = match entity.to_ascii_lowercase().as_str() {
                "amp" => Some('&'),
                "apos" => Some('\''),
                "colon" => Some(':'),
                "gt" => Some('>'),
                "lt" => Some('<'),
                "quot" => Some('"'),
                "sol" => Some('/'),
                _ => None,
            };

            if let Some(ch) = replacement {
                decoded.push(ch);
            } else {
                decoded.push_str(&value[start..=start + 1 + relative_end]);
            }
            cursor = start + 1 + relative_end + 1;
        }

        decoded.push_str(&value[cursor..]);
        decoded
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

    /// Rebuild the O(1) link dedup index when it fell out of sync with
    /// `links` (e.g. after deserialization, where the skipped field defaults
    /// to empty, or after external pushes that bypassed `push_or_update_link`).
    fn ensure_link_index(&mut self) {
        if self.link_index.len() != self.links.len() {
            self.link_index = self.links.iter().map(|link| link.url.clone()).collect();
        }
    }

    /// Push a link subject to the hard [`MAX_EMAIL_LINKS`] cap. Overflow sets
    /// `links_truncated` (an inspection-coverage signal) instead of growing
    /// the vector without bound.
    fn push_capped_link(&mut self, link: EmailLink) {
        if self.links.len() >= MAX_EMAIL_LINKS {
            self.links_truncated = true;
            return;
        }
        self.link_index.insert(link.url.clone());
        self.links.push(link);
    }

    /// Keep an href the URL parser rejected (or that uses an active-content
    /// scheme) as a suspicious raw link — bounded per entry, deduped through
    /// the index, and capped by [`MAX_EMAIL_LINKS`].
    fn push_raw_suspicious_link(&mut self, raw: String, text: Option<String>) {
        if raw.is_empty() {
            return;
        }
        self.ensure_link_index();
        if self.link_index.contains(&raw) {
            return;
        }
        self.push_capped_link(EmailLink {
            url: raw,
            text,
            suspicious: true,
        });
    }

    fn push_or_update_link(&mut self, url: &str, text: Option<String>) {
        let candidate = url.trim_matches(|ch: char| ch.is_ascii_whitespace() || ch.is_control());
        if candidate.is_empty() {
            return;
        }
        // Scheme-relative hrefs (`//evil.tk/login`) inherit the webmail's
        // https: origin in the browser; promote them so downstream analysis
        // sees the real destination instead of silently dropping the link.
        let promoted;
        let candidate = if candidate.starts_with("//") {
            promoted = format!("https:{candidate}");
            promoted.as_str()
        } else {
            candidate
        };
        let normalized_text = text.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let parsed = match url::Url::parse(candidate) {
            Ok(parsed) => parsed,
            Err(_) => {
                // Do not silently drop an href the URL parser rejects: the
                // browser/mail client may still resolve it (e.g. a `%40` in
                // the host), so the raw string is kept as a link and scored
                // by link_scan's `unparseable_url` weak signal. Bounded so a
                // hostile href cannot stuff unbounded bytes into the session.
                let raw: String = candidate.chars().take(512).collect();
                self.push_raw_suspicious_link(raw, normalized_text);
                return;
            }
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            // Active-content schemes (`javascript:`, `vbscript:`, `data:`,
            // `file:`) used to be dropped here, which made link_scan's
            // `javascript_uri` / `data_uri` checks unreachable dead code while
            // mail clients still execute them. Keep the raw href as a
            // suspicious link instead — same bounded treatment as the
            // unparseable branch above. Benign embedded resources (`img
            // src="data:image/..."`) are filtered out by the caller.
            let scheme = parsed.scheme();
            if matches!(scheme, "javascript" | "vbscript" | "data" | "file") {
                let raw: String = candidate.chars().take(512).collect();
                self.push_raw_suspicious_link(raw, normalized_text);
            }
            return;
        }
        let normalized_url = parsed.as_str();

        self.ensure_link_index();
        if self.link_index.contains(normalized_url) {
            // Existing entry: only backfill missing anchor text. The linear
            // find is bounded by MAX_EMAIL_LINKS and only runs on duplicates.
            if normalized_text.is_some()
                && let Some(existing) =
                    self.links.iter_mut().find(|link| link.url == normalized_url)
                && existing.text.is_none()
            {
                existing.text = normalized_text;
            }
            return;
        }

        let suspicious = Self::is_suspicious_url(normalized_url);
        self.push_capped_link(EmailLink {
            url: normalized_url.to_string(),
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

            // Scan every tag for browser-recognized URL-bearing attributes.
            // The attribute parser accepts quoted/unquoted values and whitespace
            // around '=', matching the HTML syntax that mail clients render.
            let mut tag_pos = 0usize;
            while let Some(tag_start_rel) = html[tag_pos..].find('<') {
                let tag_start = tag_pos + tag_start_rel;
                let Some(tag_end_rel) = html[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_end_rel;
                let tag = &html[tag_start..=tag_end];

                for attr_name in ["href", "src", "action", "formaction", "poster"] {
                    if let Some(url) = Self::extract_attr_value_case_insensitive(tag, attr_name) {
                        // `src`/`poster` data: URLs are inline images/fonts in
                        // legitimate mail — exempt them so the data: retention
                        // in push_or_update_link cannot turn every newsletter
                        // into a data_uri finding. `href`/`action` data:
                        // payloads remain reportable (credential-phish vector).
                        if matches!(attr_name, "src" | "poster")
                            && url
                                .trim_start()
                                .get(..5)
                                .is_some_and(|head| head.eq_ignore_ascii_case("data:"))
                        {
                            continue;
                        }
                        self.push_or_update_link(&url, None);
                    }
                }

                tag_pos = tag_end + 1;
            }
        }
    }

    /// Apply lightweight heuristics to flag obviously suspicious URLs.
    pub fn is_suspicious_url(url: &str) -> bool {
        let parsed = url::Url::parse(url).ok();
        let host = parsed.as_ref().and_then(url::Url::host_str);

        // Literal IP links are uncommon in legitimate mail and evade
        // domain-reputation controls.
        if host.is_some_and(|value| value.parse::<std::net::IpAddr>().is_ok()) {
            return true;
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
                let is_known = host.is_some_and(|host| {
                    known_domains.iter().any(|domain| {
                        host.eq_ignore_ascii_case(domain)
                            || host.to_ascii_lowercase().ends_with(&format!(".{domain}"))
                    })
                });
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
    use super::{
        EmailAttachment, EmailContent, EmailLink, EmailSession, MAX_EMAIL_LINKS, Protocol,
        SessionStatus,
        decode_base64_bytes_limited,
    };

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
    fn test_extract_links_from_html_matches_browser_attribute_syntax() {
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<a href = \"HTTPS&#58;//evil.example/login\">Review</a>\
             <img src=https://cdn.example/pixel.png>\
             <form action='https://forms.example/verify'></form>"
                .to_string(),
        );

        content.extract_links_from_html();

        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.example/login")
        );
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://cdn.example/pixel.png")
        );
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://forms.example/verify")
        );
    }

    #[test]
    fn test_extract_links_decodes_numeric_entities_without_semicolon() {
        // PoC: browsers decode `&#58` / `&#x3A` even without the terminating
        // semicolon, so href="https&#58//evil.com" is a working https:// link.
        // Before the fix the extractor required ';', left `&#58` as literal
        // text, and the whole URL vanished from the link layer (url_features /
        // link_content / link_scan all went blind).
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<a href=\"https&#58//evil.example/login\">点这里处理账户异常</a>\
             <a href=\"https&#x3A//evil2.example/verify\">立即验证</a>"
                .to_string(),
        );

        content.extract_links_from_html();

        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.example/login"),
            "no-semicolon decimal entity must decode into a real URL: {:?}",
            content.links
        );
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil2.example/verify"),
            "no-semicolon hex entity must decode into a real URL: {:?}",
            content.links
        );

        // Undecodable numeric spans stay literal and must not panic or swallow
        // the rest of the attribute value.
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<a href=\"https://ok.example/a?x=1&#zz&y=2\">plain</a>".to_string(),
        );
        content.extract_links_from_html();
        assert_eq!(content.links.len(), 1);
        assert!(content.links[0].url.starts_with("https://ok.example/"));
    }

    #[test]
    fn test_extract_links_promotes_scheme_relative_href() {
        // PoC (B1-3): `href="//evil.tk/login"` resolves against the webmail's
        // https: origin in the browser, but `Url::parse` rejected it as
        // RelativeUrlWithoutBase and the link was silently dropped — every
        // downstream module went blind. It is now promoted to https:.
        let mut content = EmailContent::new();
        content.body_html =
            Some("<a href=\"//evil.tk/login\">账户异常，请立即验证</a>".to_string());

        content.extract_links_from_html();

        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.tk/login"),
            "scheme-relative href must be promoted to https: {:?}",
            content.links
        );
    }

    #[test]
    fn test_extract_links_keeps_unparseable_href_as_raw_link() {
        // PoC (B1-3): `%40` inside the host is rejected by the WHATWG parser
        // but browsers may still resolve it; before the fix the href was
        // silently discarded. The raw string is now kept (marked suspicious)
        // so link_scan can score the `unparseable_url` weak signal.
        let mut content = EmailContent::new();
        content.body_html =
            Some("<a href=\"http://legit.com%40evil.com/\">点击登录</a>".to_string());

        content.extract_links_from_html();

        let link = content
            .links
            .iter()
            .find(|link| link.url == "http://legit.com%40evil.com/")
            .expect("unparseable href must be kept as a raw link");
        assert!(link.suspicious, "unparseable href must be marked suspicious");
        assert_eq!(link.text.as_deref(), Some("点击登录"));
    }

    #[test]
    fn test_extract_links_keeps_active_content_scheme_hrefs() {
        // PoC bypass (R4C): `<a href="javascript:...">` / `data:` / `file:` /
        // `vbscript:` hrefs used to hit the non-http(s) early return in
        // push_or_update_link and vanished — link_scan's javascript_uri /
        // data_uri checks were unreachable dead code while mail clients still
        // execute the href. They must be kept as suspicious raw links.
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<a href=\"javascript:alert(document.cookie)\">点击验证账户</a>\
             <a href=\"data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly9ldmlsLmV4YW1wbGUnKTwvc2NyaXB0Pg==\">查看账单</a>\
             <a href=\"file:///evil.example/share/loader.exe\">下载发票</a>\
             <a href=\"vbscript:msgbox(1)\">确认</a>"
                .to_string(),
        );

        content.extract_links_from_html();

        let urls: Vec<&str> = content.links.iter().map(|link| link.url.as_str()).collect();
        for expected in [
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly9ldmlsLmV4YW1wbGUnKTwvc2NyaXB0Pg==",
            "file:///evil.example/share/loader.exe",
            "vbscript:msgbox(1)",
        ] {
            let link = content
                .links
                .iter()
                .find(|link| link.url == expected)
                .unwrap_or_else(|| panic!("{expected} href must be kept: {urls:?}"));
            assert!(link.suspicious, "{expected} must be marked suspicious");
        }
    }

    #[test]
    fn test_extract_links_exempts_img_src_data_uri() {
        // Guard: inline images (`img src="data:image/..."`) are ubiquitous in
        // legitimate mail; the data: retention above must not surface them.
        let mut content = EmailContent::new();
        content.body_html = Some(
            "<p>hi</p><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==\">\
             <img src='DATA:image/gif;base64,R0lGODdhAQABAIAAAP///////ywAAAAAAQABAAACAkQBADs='>"
                .to_string(),
        );

        content.extract_links_from_html();

        assert!(
            content.links.is_empty(),
            "img-src data: URIs must stay out of the link layer: {:?}",
            content.links
        );
    }

    #[test]
    fn test_email_content_truncation_flags_default_off() {
        // Guard: the degraded-parse flags are opt-in and must not appear on a
        // normally parsed content struct.
        let content = EmailContent::new();
        assert!(!content.truncated);
        assert_eq!(content.dropped_attachments, 0);
        // Deserializing legacy JSON without the new fields must keep working.
        let legacy = serde_json::json!({
            "headers": [],
            "attachments": [],
            "links": [],
            "raw_size": 0,
            "is_complete": true,
            "is_encrypted": false
        });
        let parsed: EmailContent = serde_json::from_value(legacy).expect("legacy JSON");
        assert!(!parsed.truncated);
        assert_eq!(parsed.dropped_attachments, 0);
    }

    #[test]
    fn test_links_hard_cap_sets_truncated_flag() {
        // PoC (R5-B2): a hostile 25MB HTML body can carry ~600k distinct
        // hrefs; without a hard cap the dedup path alone is quadratic in link
        // count and link_scan / DB persistence amplify it further. The vector
        // must stop at MAX_EMAIL_LINKS and raise the coverage-gap flag.
        let mut content = EmailContent::new();
        for i in 0..(MAX_EMAIL_LINKS + 100) {
            content.push_or_update_link(&format!("https://evil.example/{i}"), None);
        }
        assert_eq!(content.links.len(), MAX_EMAIL_LINKS);
        assert!(content.links_truncated);
        assert_eq!(content.link_index.len(), MAX_EMAIL_LINKS);
    }

    #[test]
    fn test_link_dedup_index_backfills_anchor_text_on_duplicate() {
        let mut content = EmailContent::new();
        content.push_or_update_link("https://evil.example/login", None);
        content.push_or_update_link("https://evil.example/login", Some("点击验证".to_string()));
        content.push_or_update_link("https://evil.example/login", Some("ignored".to_string()));
        assert_eq!(content.links.len(), 1);
        assert_eq!(content.links[0].text.as_deref(), Some("点击验证"));
    }

    #[test]
    fn test_link_dedup_index_recovers_after_deserialization() {
        // #[serde(skip)] leaves the index empty after deserialization; the
        // lazy rebuild must restore dedup so a re-extraction cannot duplicate
        // links already present in the stored session.
        let mut content = EmailContent::new();
        content.links.push(EmailLink {
            url: "https://evil.example/login".to_string(),
            text: None,
            suspicious: false,
        });
        assert!(content.link_index.is_empty());
        content.push_or_update_link("https://evil.example/login", Some("click".to_string()));
        assert_eq!(content.links.len(), 1);
        assert_eq!(content.links[0].text.as_deref(), Some("click"));
    }

    #[test]
    fn test_unparseable_links_are_deduped() {
        let mut content = EmailContent::new();
        content.push_or_update_link("ht tp://broken link", None);
        content.push_or_update_link("ht tp://broken link", None);
        assert_eq!(content.links.len(), 1);
        assert!(content.links[0].suspicious);
    }

    #[test]
    fn suspicious_url_allowlist_requires_a_real_domain_boundary() {
        assert!(!EmailContent::is_suspicious_url(
            "https://accounts.google.com/login"
        ));
        assert!(EmailContent::is_suspicious_url(
            "https://accounts.google.com.attacker.example/login"
        ));
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

    #[test]
    fn mail_from_only_session_is_not_analyzable_content() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("sender@example.com".to_string());

        assert!(!session.has_analyzable_content());

        session
            .content
            .headers
            .push(("Subject".to_string(), "hello".to_string()));
        assert!(session.has_analyzable_content());
    }

    #[test]
    fn inspection_failure_session_remains_analyzable() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.error_reason = Some("inspection:mime_parse_failed:NoBoundary".to_string());

        assert!(session.has_analyzable_content());
    }

    #[test]
    fn reconstruct_eml_limited_rejects_oversized_raw_size() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.raw_size = 11;

        assert!(session.reconstruct_eml_limited(10).is_none());
    }

    #[test]
    fn estimated_reconstructed_eml_size_counts_attachment_payload() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.attachments = vec![EmailAttachment {
            filename: "a.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 9,
            hash: "abc".to_string(),
            content_base64: Some("QUJDREVGR0hJ".to_string()),
        }];

        assert!(session.estimated_reconstructed_eml_size() >= 11);
        assert!(session.reconstruct_eml_limited(10).is_none());
    }

    #[test]
    fn decode_base64_bytes_limited_rejects_oversized_payload() {
        assert_eq!(
            decode_base64_bytes_limited("QUJD", 3),
            Some(b"ABC".to_vec())
        );
        assert!(decode_base64_bytes_limited("QUJDRA==", 3).is_none());
    }

    #[test]
    fn from_port_uses_configured_ports_then_defaults() {
        // PoC (R4A legacy-8): DB-configured HTTP_PORTS must drive protocol
        // detection; hardcoded defaults stay as fallback for unlisted ports.
        Protocol::configure_ports(&[25, 2525], &[110], &[143], &[8080, 8443]);
        assert_eq!(Protocol::from_port(8080), Protocol::Http);
        assert_eq!(Protocol::from_port(8443), Protocol::Http);
        assert_eq!(Protocol::from_port(2525), Protocol::Smtp);
        // Fallback: port 80 remains HTTP even though not in the configured set.
        assert_eq!(Protocol::from_port(80), Protocol::Http);
        assert_eq!(Protocol::from_port(587), Protocol::Smtp);
        assert_eq!(Protocol::from_port(9999), Protocol::Unknown);

        // Reset so no other test in this process observes the configured sets.
        if let Ok(mut guard) = super::PROTOCOL_PORTS.write() {
            *guard = None;
        }
        assert_eq!(Protocol::from_port(8080), Protocol::Unknown);
        assert_eq!(Protocol::from_port(25), Protocol::Smtp);
    }
}
