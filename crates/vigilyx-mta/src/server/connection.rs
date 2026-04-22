//! SMTP

//! SMTP:
//! 1. banner -> EHLO -> STARTTLS
//! 2. MAIL FROM -> RCPT TO -> DATA
//! 3. DATA -> MIME -> EmailSession -> inline


use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};
use tracing::{debug, error, warn};

use vigilyx_core::models::{EmailSession, Protocol, SessionSource, SessionStatus};
use vigilyx_parser::mime::MimeParser;

use crate::config::MtaConfig;
use crate::envelope::{extract_domain, is_valid_envelope_address};

/// SMTP. RFC 5321,.
const MAX_COMMAND_LEN: usize = 1024;
/// DATA;,.
const MAX_DATA_LINE_LEN: usize = 16 * 1024;

/// SEC: Maximum total session lifetime (CWE-400).
/// Prevents NOOP-keepalive attacks from holding connection slots indefinitely.
const MAX_SESSION_SECS: u64 = 600; // 10 minutes

/// SEC: Maximum total time for a single DATA transaction (CWE-400).
/// Prevents slow-data attacks where one tiny line per ~300s holds the DATA phase open.
const MAX_DATA_TRANSACTION_SECS: u64 = 300; // 5 minutes

/// RFC 3030: Maximum size for a single BDAT chunk (64 MB).
const MAX_BDAT_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// SMTP
pub struct SmtpConnection {
   /// IP
    client_ip: String,

    client_port: u16,
    server_ip: String,
    server_port: u16,
   /// SMTP
    state: SmtpState,
   /// MAIL FROM
    mail_from: Option<String>,
   /// RCPT TO
    rcpt_to: Vec<String>,
   /// DATA / BDAT accumulated message buffer
    data_buffer: Vec<u8>,
    
    config: Arc<MtaConfig>,
   /// TLS
    tls_active: bool,
   /// SEC: connection start time for session lifetime enforcement
    session_started: Instant,
   /// SEC: DATA/BDAT phase start time for transaction timeout enforcement
    data_phase_started: Option<Instant>,
    /// RFC 3030 BDAT state: tracks remaining bytes in the current chunk.
    bdat_remaining: usize,
    /// RFC 3030 BDAT: whether the current chunk has the LAST flag.
    bdat_is_last: bool,
}

/// SMTP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpState {
   /// EHLO/HELO
    Connected,
   /// EHLO, MAIL FROM (STARTTLS)
    Ready,
   /// MAIL FROM, RCPT TO
    MailFrom,
   /// RCPT TO, DATA RCPT TO
    RcptTo,
   /// DATA
    Data,
    /// RFC 3030: BDAT chunk data collection (byte-counted, no terminator).
    BdatData,
}

/// SMTP
pub enum HandleResult {
   /// : EmailSession,
    Email(Box<EmailSession>, Vec<u8>),
   /// QUIT
    Closed,
    
    Error(String),
   /// TLS
    StartTls,
}

enum DataLineResult {
    Continue,
    Complete(Vec<u8>),
    TooLarge,
}

impl SmtpConnection {
    pub fn new(client_ip: String, client_port: u16, server_ip: String, server_port: u16, config: Arc<MtaConfig>, tls_active: bool) -> Self {
        Self {
            client_ip,
            client_port,
            server_ip,
            server_port,
            state: SmtpState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::new(),
            config,
            tls_active,
            session_started: Instant::now(),
            data_phase_started: None,
            bdat_remaining: 0,
            bdat_is_last: false,
        }
    }

    fn reset_transaction(&mut self) {
        self.state = SmtpState::Ready;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.data_phase_started = None;
        self.bdat_remaining = 0;
        self.bdat_is_last = false;
    }

    fn append_data_line(&mut self, line: &[u8]) -> DataLineResult {
        // SEC: RFC 5321 Section 4.1.1.4 — DATA terminator is strictly <CRLF>.<CRLF>.
        // Only accept ".\r\n" (the line already had its preceding CRLF consumed by the reader).
        // Bare LF (".\n") MUST NOT be accepted as a terminator — doing so creates a parsing
        // differential with the Sniffer (which matches \r\n.\r\n), enabling SMTP smuggling
        // attacks (CWE-444).
        if line == b".\r\n" {
            let raw_email = std::mem::take(&mut self.data_buffer);
            // Do not reset here - build_email_session still needs mail_from and rcpt_to
            // Reset after the Complete branch in handle()
            return DataLineResult::Complete(raw_email);
        }

       // RFC 5321 dot-stuffing: ".." on the wire means a single leading dot in message data.
        let payload = if line.starts_with(b"..") { &line[1..] } else { line };
        if self.data_buffer.len() + payload.len() > self.config.max_message_size {
            return DataLineResult::TooLarge;
        }

        self.data_buffer.extend_from_slice(payload);
        DataLineResult::Continue
    }

    fn is_local_recipient(&self, addr: &str) -> bool {
        let Some(domain) = extract_domain(addr) else {
            return false;
        };
        self.config
            .local_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
    }

    fn complete_message(&mut self, raw_email: Vec<u8>, event: &'static str) -> HandleResult {
        let session = self.build_email_session(&raw_email);
        let from_domain = session
            .mail_from
            .as_deref()
            .and_then(|a| a.rsplit('@').next())
            .unwrap_or("<>");
        tracing::info!(
            client_ip = %self.client_ip,
            from_domain = %from_domain,
            rcpt_count = session.rcpt_to.len(),
            data_size = raw_email.len(),
            "{event}"
        );
        self.reset_transaction();
        HandleResult::Email(Box::new(session), raw_email)
    }

   /// SMTP (-> ->)
    
    
   /// generic AsyncBufRead+AsyncWrite plain TCP TLS.
    pub async fn handle<S>(
        &mut self,
        stream: &mut S,
        skip_banner: bool,
    ) -> Vec<HandleResult>
    where
        S: AsyncBufRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut results = Vec::new();

        // SMTP banner (skip on TLS-upgraded connections to avoid double greeting)
        if !skip_banner {
            let banner = format!("220 {} ESMTP Vigilyx MTA\r\n", self.config.hostname);
            if let Err(e) = stream.write_all(banner.as_bytes()).await {
                error!(client_ip = %self.client_ip, "Failed to send banner: {e}");
                return results;
            }
            if let Err(e) = stream.flush().await {
                error!(client_ip = %self.client_ip, "Failed to flush banner: {e}");
                return results;
            }
        }

        loop {
            // SEC: enforce total session lifetime to prevent NOOP-keepalive attacks (CWE-400)
            if self.session_started.elapsed() > Duration::from_secs(MAX_SESSION_SECS) {
                warn!(client_ip = %self.client_ip, elapsed_secs = MAX_SESSION_SECS, "Session lifetime exceeded");
                let _ = stream.write_all(b"421 4.4.2 Session lifetime exceeded\r\n").await;
                let _ = stream.flush().await;
                break;
            }

            // SEC: enforce total DATA/BDAT transaction timeout to prevent slow-data attacks
            if let Some(data_start) = self.data_phase_started
                && data_start.elapsed() > Duration::from_secs(MAX_DATA_TRANSACTION_SECS)
            {
                warn!(client_ip = %self.client_ip, elapsed_secs = MAX_DATA_TRANSACTION_SECS, "DATA/BDAT transaction timeout");
                let _ = stream.write_all(b"451 4.4.2 DATA transaction timeout\r\n").await;
                let _ = stream.flush().await;
                self.reset_transaction();
                break;
            }

            // ── RFC 3030 BDAT: byte-counted data reading (no line terminator) ──
            if self.state == SmtpState::BdatData {
                let bdat_timeout = Duration::from_secs(300);
                let remaining = self.bdat_remaining;

                // Read exactly `remaining` bytes in chunks via the BufReader
                let mut bytes_left = remaining;
                let mut chunk_error = false;
                while bytes_left > 0 {
                    let read_result = tokio::time::timeout(bdat_timeout, stream.fill_buf()).await;
                    match read_result {
                        Ok(Ok([])) => {
                            warn!(client_ip = %self.client_ip, "Client disconnected during BDAT chunk");
                            chunk_error = true;
                            break;
                        }
                        Ok(Ok(buf)) => {
                            let take = buf.len().min(bytes_left);
                            self.data_buffer.extend_from_slice(&buf[..take]);
                            stream.consume(take);
                            bytes_left -= take;
                        }
                        Ok(Err(e)) => {
                            warn!(client_ip = %self.client_ip, "Read error during BDAT: {e}");
                            chunk_error = true;
                            break;
                        }
                        Err(_) => {
                            warn!(client_ip = %self.client_ip, "Client timeout during BDAT chunk");
                            let _ = stream.write_all(b"421 4.4.2 BDAT timeout\r\n").await;
                            let _ = stream.flush().await;
                            chunk_error = true;
                            break;
                        }
                    }
                }

                if chunk_error {
                    self.reset_transaction();
                    break;
                }

                self.bdat_remaining = 0;

                if self.bdat_is_last {
                    let raw_email = std::mem::take(&mut self.data_buffer);
                    results.push(self.complete_message(raw_email, "BDAT LAST complete"));
                    return results;
                } else {
                    // Non-last chunk: acknowledge and wait for next BDAT command
                    self.state = SmtpState::RcptTo; // Back to command state (BDAT allowed after RCPT TO)
                    let _ = stream.write_all(b"250 2.0.0 BDAT chunk accepted\r\n").await;
                    let _ = stream.flush().await;
                }
                continue;
            }

            // ── Line-based reading for DATA and command phases ──
            let line_limit = if self.state == SmtpState::Data {
                MAX_DATA_LINE_LEN
            } else {
                MAX_COMMAND_LEN
            };
            // SEC: 60s idle timeout during the command phase (prevents slowloris from exhausting connection slots)
            // 300s during the DATA phase (RFC 5321 allows large messages to take longer)
            let idle_timeout = if self.state == SmtpState::Data {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(60)
            };
            let read_result = tokio::time::timeout(
                idle_timeout,
                read_smtp_line(stream, line_limit),
            )
            .await;

            let line_buf = match read_result {
                Ok(Ok(None)) => {
                    debug!(client_ip = %self.client_ip, "Client disconnected");
                    break;
                }
                Ok(Ok(Some(line))) => line,
                Ok(Err(e)) if e.kind() == ErrorKind::InvalidData => {
                    let reply = if self.state == SmtpState::Data {
                        b"554 5.6.0 DATA line too long\r\n".as_slice()
                    } else {
                        b"500 5.5.1 Line too long\r\n".as_slice()
                    };
                    let _ = stream.write_all(reply).await;
                    let _ = stream.flush().await;
                    break;
                }
                Ok(Err(e)) if e.kind() == ErrorKind::InvalidInput => {
                    let reply = if self.state == SmtpState::Data {
                        b"554 5.6.0 Line terminator must be CRLF\r\n".as_slice()
                    } else {
                        b"500 5.5.2 Line terminator must be CRLF\r\n".as_slice()
                    };
                    let _ = stream.write_all(reply).await;
                    let _ = stream.flush().await;
                    break;
                }
                Ok(Err(e)) => {
                    warn!(client_ip = %self.client_ip, "Read error: {e}");
                    break;
                }
                Err(_) => {
                    warn!(client_ip = %self.client_ip, "Client timeout (300s)");
                    let _ = stream.write_all(b"421 4.4.2 Connection timeout\r\n").await;
                    break;
                }
            };

           // DATA,
            if self.state == SmtpState::Data {
                match self.append_data_line(&line_buf) {
                    DataLineResult::Continue => {}
                    DataLineResult::Complete(raw_email) => {
                        results.push(self.complete_message(raw_email, "DATA complete"));
                        return results;
                    }
                    DataLineResult::TooLarge => {
                        let _ = stream.write_all(b"552 5.3.4 Message too large\r\n").await;
                        let _ = stream.flush().await;
                        self.reset_transaction();
                    }
                }
                continue;
            }

            let cmd = trim_line_end(&line_buf);
            if cmd.is_empty() {
                continue;
            }
            let cmd = match std::str::from_utf8(cmd) {
                Ok(cmd) => cmd,
                Err(_) => {
                    let _ = stream.write_all(b"500 5.5.2 Invalid command encoding\r\n").await;
                    let _ = stream.flush().await;
                    continue;
                }
            };

            // SEC: full command at debug only to avoid leaking envelope addresses in production logs (CWE-532)
            tracing::debug!(client_ip = %self.client_ip, state = ?self.state, cmd = %cmd.trim(), "SMTP cmd");
           // SMTP
            let upper = cmd.to_ascii_uppercase();
            let response = self.process_command(&upper, cmd);

            // BDAT uses code 0 as sentinel: process_command returns Reply(0, _)
            // to signal "switch to BdatData state; handle() will send the real reply
            // after consuming the chunk bytes". Skip sending anything for code 0.
            match response {
                CmdResponse::Reply(code, msg) if code > 0 => {
                    let reply = format!("{code} {msg}\r\n");
                    if let Err(e) = stream.write_all(reply.as_bytes()).await {
                        error!("Write error: {e}");
                        break;
                    }
                    let _ = stream.flush().await;
                }
                CmdResponse::Reply(_, _) => {
                    // code == 0: BDAT sentinel, no reply to send now
                }
                CmdResponse::MultiLine(lines) => {
                    let mut buf = String::new();
                    for line in &lines {
                        buf.push_str(line);
                        buf.push_str("\r\n");
                    }
                    if let Err(e) = stream.write_all(buf.as_bytes()).await {
                        error!("Write error: {e}");
                        break;
                    }
                    let _ = stream.flush().await;
                }
                CmdResponse::Quit => {
                    let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
                    let _ = stream.flush().await;
                    results.push(HandleResult::Closed);
                    break;
                }
                CmdResponse::StartTls => {
                    let _ = stream.write_all(b"220 2.0.0 Ready to start TLS\r\n").await;
                    let _ = stream.flush().await;
                    results.push(HandleResult::StartTls);
                    return results;
                }
            }
        }

        results
    }

   /// SMTP,
    fn process_command(&mut self, upper: &str, original: &str) -> CmdResponse {
        if upper.starts_with("QUIT") {
            return CmdResponse::Quit;
        }

        if upper.starts_with("RSET") {
            self.reset_transaction();
            return CmdResponse::Reply(250, "2.1.5 OK".into());
        }

        if upper.starts_with("NOOP") {
            return CmdResponse::Reply(250, "2.0.0 OK".into());
        }

        match self.state {
            SmtpState::Connected => {
                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    self.state = SmtpState::Ready;
                    let mut lines = vec![
                        format!("250-{} Hello", self.config.hostname),
                        "250-PIPELINING".into(),
                        format!("250-SIZE {}", self.config.max_message_size),
                        "250-8BITMIME".into(),
                        "250-CHUNKING".into(),
                    ];
                    if self.config.tls.is_some() && !self.tls_active {
                        lines.push("250-STARTTLS".into());
                    }
                    lines.push("250 OK".into());
                    CmdResponse::MultiLine(lines)
                } else {
                    CmdResponse::Reply(503, "5.5.1 Send EHLO/HELO first".into())
                }
            }
            SmtpState::Ready | SmtpState::MailFrom | SmtpState::RcptTo => {
                if upper.starts_with("STARTTLS") && self.state == SmtpState::Ready {
                    if self.tls_active {
                        return CmdResponse::Reply(503, "5.5.1 TLS already active".into());
                    }
                    if self.config.tls.is_none() {
                        return CmdResponse::Reply(502, "5.5.1 TLS not available".into());
                    }
                    return CmdResponse::StartTls;
                }

                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                   // EHLO (TLS)
                    self.reset_transaction();
                    let mut lines = vec![
                        format!("250-{} Hello", self.config.hostname),
                        "250-PIPELINING".into(),
                        format!("250-SIZE {}", self.config.max_message_size),
                        "250-8BITMIME".into(),
                        "250-CHUNKING".into(),
                    ];
                    if self.config.tls.is_some() && !self.tls_active {
                        lines.push("250-STARTTLS".into());
                    }
                    lines.push("250 OK".into());
                    return CmdResponse::MultiLine(lines);
                }

                if upper.starts_with("MAIL FROM:") || upper.starts_with("MAIL FROM :") {
                    if self.state != SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Nested MAIL command".into());
                    }
                    let addr = match extract_envelope_address(original, true) {
                        Ok(addr) => addr,
                        Err(_) => {
                            return CmdResponse::Reply(501, "5.1.7 Bad sender address syntax".into());
                        }
                    };
                    let from_domain = addr.as_deref().and_then(|a| a.rsplit('@').next()).unwrap_or("<>");
                    tracing::info!(from_domain = %from_domain, "MAIL FROM accepted");
                    self.mail_from = addr;
                    self.state = SmtpState::MailFrom;
                    return CmdResponse::Reply(250, "2.1.0 OK".into());
                }

                if upper.starts_with("RCPT TO:") || upper.starts_with("RCPT TO :") {
                    if self.state == SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Need MAIL command first".into());
                    }
                    if self.rcpt_to.len() >= self.config.max_recipients {
                        return CmdResponse::Reply(452, "4.5.3 Too many recipients".into());
                    }
                    let addr = match extract_envelope_address(original, false) {
                        Ok(Some(addr)) => addr,
                        Ok(None) | Err(_) => {
                            return CmdResponse::Reply(501, "5.1.3 Bad recipient address syntax".into());
                        }
                    };
                    if !self.is_local_recipient(&addr) {
                        return CmdResponse::Reply(554, "5.7.1 Relay access denied".into());
                    }
                    let rcpt_domain = addr.rsplit('@').next().unwrap_or("<>");
                    tracing::info!(rcpt_domain = %rcpt_domain, rcpt_count = self.rcpt_to.len() + 1, "RCPT TO accepted");
                    self.rcpt_to.push(addr);
                    self.state = SmtpState::RcptTo;
                    return CmdResponse::Reply(250, "2.1.5 OK".into());
                }

                if upper.starts_with("DATA") {
                    if self.rcpt_to.is_empty() {
                        return CmdResponse::Reply(503, "5.5.1 Need RCPT command first".into());
                    }
                    self.state = SmtpState::Data;
                    self.data_phase_started = Some(Instant::now());
                    self.data_buffer.clear();
                    return CmdResponse::Reply(354, "Start mail input; end with <CRLF>.<CRLF>".into());
                }

                // RFC 3030: BDAT <size> [LAST]
                if upper.starts_with("BDAT") {
                    if self.rcpt_to.is_empty() {
                        return CmdResponse::Reply(503, "5.5.1 Need RCPT command first".into());
                    }
                    match parse_bdat_args(upper) {
                        Ok((size, is_last)) => {
                            if size > MAX_BDAT_CHUNK_SIZE {
                                return CmdResponse::Reply(552, "5.3.4 BDAT chunk too large".into());
                            }
                            if self.data_buffer.len() + size > self.config.max_message_size {
                                return CmdResponse::Reply(552, "5.3.4 Message too large".into());
                            }
                            self.bdat_remaining = size;
                            self.bdat_is_last = is_last;
                            self.state = SmtpState::BdatData;
                            if self.data_phase_started.is_none() {
                                self.data_phase_started = Some(Instant::now());
                            }
                            // Return a no-op response; the actual 250 is sent after
                            // the chunk data has been consumed in handle().
                            return CmdResponse::Reply(0, String::new());
                        }
                        Err(msg) => {
                            return CmdResponse::Reply(501, format!("5.5.4 {msg}"));
                        }
                    }
                }

                CmdResponse::Reply(502, "5.5.1 Command not recognized".into())
            }
            SmtpState::Data => {
               // (DATA handle)
                CmdResponse::Reply(503, "5.5.1 Unexpected command during DATA".into())
            }
            SmtpState::BdatData => {
                // Should not receive commands while reading BDAT chunk data
                CmdResponse::Reply(503, "5.5.1 Unexpected command during BDAT".into())
            }
        }
    }

   /// EmailSession
    fn build_email_session(&self, raw_email: &[u8]) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            self.client_ip.clone(),
            self.client_port,
            self.server_ip.clone(),
            self.server_port,
        );

        session.source = SessionSource::MtaProxy;
        session.status = SessionStatus::Completed;
        session.ended_at = Some(Utc::now());
        session.mail_from = self.mail_from.clone();
        session.rcpt_to = self.rcpt_to.clone();
        session.total_bytes = raw_email.len();
        session.email_count = 1;

       // MIME
        let parser = MimeParser::new();
        session.content = match parser.parse(raw_email) {
            Ok(content) => content,
            Err(e) => {
                warn!(client_ip = %self.client_ip, "MIME parse error: {e:?}");
                vigilyx_core::EmailContent::default()
            }
        };
        session.content.is_complete = true;

       // headers subject message_id
        for (key, value) in &session.content.headers {
            match key.to_ascii_lowercase().as_str() {
                "subject" if session.subject.is_none() => {
                    session.subject = Some(value.clone());
                }
                "message-id" if session.message_id.is_none() => {
                    session.message_id = Some(value.clone());
                }
                _ => {}
            }
        }

        session
    }
}

/// SMTP
enum CmdResponse {
    Reply(u16, String),
    MultiLine(Vec<String>),
    Quit,
    StartTls,
}

async fn read_smtp_line<R>(reader: &mut R, max_len: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(max_len.min(4096));

    'outer: loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SMTP line terminated without CRLF",
            ));
        }

        if line.last() == Some(&b'\r') {
            if buf[0] == b'\n' {
                if line.len() + 1 > max_len {
                    return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
                }
                line.push(b'\n');
                reader.consume(1);
                return Ok(Some(line));
            }

            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "SMTP line must end with CRLF",
            ));
        }

        for (idx, byte) in buf.iter().enumerate() {
            match byte {
                b'\n' => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "SMTP line must end with CRLF",
                    ));
                }
                b'\r' if idx + 1 < buf.len() => {
                    if buf[idx + 1] != b'\n' {
                        return Err(io::Error::new(
                            ErrorKind::InvalidInput,
                            "SMTP line must end with CRLF",
                        ));
                    }

                    let take = idx + 2;
                    if line.len() + take > max_len {
                        return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
                    }
                    line.extend_from_slice(&buf[..take]);
                    reader.consume(take);
                    return Ok(Some(line));
                }
                b'\r' => {
                    if line.len() + buf.len() > max_len {
                        return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
                    }
                    let take = buf.len();
                    line.extend_from_slice(&buf[..take]);
                    reader.consume(take);
                    continue 'outer;
                }
                _ => {}
            }
        }

        if line.len() + buf.len() > max_len {
            return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
        }

        let take = buf.len();
        line.extend_from_slice(&buf[..take]);
        reader.consume(take);
    }
}

/// SEC: RFC 5321 strict line terminator — only CRLF (\r\n) is a valid line ending.
/// Bare \r and bare \n MUST NOT be treated as line terminators; they are kept as
/// part of the line content. Accepting them would create parsing differentials
/// with the Sniffer, enabling SMTP smuggling attacks (CWE-444, P02).
fn trim_line_end(line: &[u8]) -> &[u8] {
    if let Some(stripped) = line.strip_suffix(b"\r\n") {
        stripped
    } else {
        line
    }
}

/// Parse BDAT command arguments: "BDAT <size>" or "BDAT <size> LAST".
/// Returns (chunk_size, is_last) on success.
fn parse_bdat_args(upper: &str) -> Result<(usize, bool), &'static str> {
    let args = upper.strip_prefix("BDAT").ok_or("not a BDAT command")?;
    let args = args.trim();
    if args.is_empty() {
        return Err("missing chunk size");
    }

    let (size_str, is_last) = if let Some(rest) = args.strip_suffix("LAST") {
        let rest = rest.trim_end();
        if rest.is_empty() {
            return Err("missing chunk size");
        }
        (rest, true)
    } else {
        (args, false)
    };

    let size: usize = size_str
        .trim()
        .parse()
        .map_err(|_| "invalid chunk size")?;

    if size == 0 && !is_last {
        return Err("chunk size must be positive");
    }

    Ok((size, is_last))
}

fn extract_envelope_address(cmd: &str, allow_empty: bool) -> Result<Option<String>, &'static str> {
    let (_, rest) = cmd.split_once(':').ok_or("missing colon")?;
    let rest = rest.trim();
    let addr = if let Some(stripped) = rest.strip_prefix('<') {
        let (addr, suffix) = stripped
            .split_once('>')
            .ok_or("missing closing angle bracket")?;
        if !suffix.is_empty() && !suffix.chars().next().is_some_and(char::is_whitespace) {
            return Err("invalid address parameters");
        }
        addr.trim()
    } else {
        rest.split_whitespace().next().ok_or("missing address")?
    };

    if addr.is_empty() {
        return if allow_empty {
            Ok(None)
        } else {
            Err("empty address")
        };
    }

    if !is_valid_envelope_address(addr) {
        return Err("invalid address");
    }

    Ok(Some(addr.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_address_with_brackets() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<user@example.com>", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_without_brackets() {
        assert_eq!(
            extract_envelope_address("MAIL FROM: user@example.com", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_with_params() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<user@example.com> SIZE=1024", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_empty_mail_from() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<>", true),
            Ok(None)
        );
    }

    #[test]
    fn test_extract_rcpt_to() {
        assert_eq!(
            extract_envelope_address("RCPT TO:<admin@corp.com>", false),
            Ok(Some("admin@corp.com".into()))
        );
    }

    #[test]
    fn test_extract_invalid_sender_domain_rejected() {
        assert!(
            extract_envelope_address("MAIL FROM:<user@bad_domain>", true).is_err(),
            "Underscore domain should be rejected"
        );
    }

    #[test]
    fn test_extract_invalid_sender_local_part_rejected() {
        assert!(
            extract_envelope_address("MAIL FROM:<a..b@example.com>", true).is_err(),
            "Invalid local-part should be rejected"
        );
    }

    #[test]
    fn test_extract_address_rejects_garbage_after_brackets() {
        assert!(
            extract_envelope_address("MAIL FROM:<user@example.com>X", true).is_err(),
            "Address parameters must be separated from the mailbox"
        );
    }

   /// MtaConfig
    fn test_config() -> Arc<MtaConfig> {
        Arc::new(MtaConfig {
            listen_smtp: "127.0.0.1:2525".parse().unwrap(),
            listen_submission: None,
            listen_smtps: None,
            max_connections: 10,
            tls: None,
            downstream: crate::config::DownstreamConfig {
                host: "127.0.0.1".into(),
                port: 25,
                starttls: false,
                timeout_secs: 5,
            },
            outbound: None,
            local_domains: vec!["test.com".into(), "corp.com".into()],
            inline_timeout_secs: 8,
            fail_open: true,
            quarantine_threshold: vigilyx_core::security::ThreatLevel::Medium,
            reject_threshold: vigilyx_core::security::ThreatLevel::Critical,
            max_message_size: 1024 * 1024,
            max_recipients: 10,
            database_url: String::new(),
            redis_url: None,
            hostname: "test-mta".into(),
            dlp: crate::dlp::DlpConfig::default(),
        })
    }

   /// : process_command (I/O,)
    fn cmd(conn: &mut SmtpConnection, cmd: &str) -> String {
        let upper = cmd.to_ascii_uppercase();
        match conn.process_command(&upper, cmd) {
            CmdResponse::Reply(code, msg) => format!("{code} {msg}"),
            CmdResponse::MultiLine(lines) => lines.join("\n"),
            CmdResponse::Quit => "QUIT".into(),
            CmdResponse::StartTls => "STARTTLS".into(),
        }
    }

    async fn read_available(client_stream: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match tokio::time::timeout(Duration::from_millis(25), client_stream.read(&mut chunk))
                .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(read)) => out.extend_from_slice(&chunk[..read]),
                Ok(Err(e)) => panic!("failed to read SMTP replies: {e}"),
            }
        }

        String::from_utf8(out).expect("SMTP replies should be UTF-8")
    }

    #[test]
    fn test_smtp_ehlo_returns_capabilities() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let resp = cmd(&mut conn, "EHLO client.test");
        assert!(resp.contains("250"), "Should get 250: {resp}");
        assert!(resp.contains("PIPELINING"));
        assert!(resp.contains("8BITMIME"));
        assert_eq!(conn.state, SmtpState::Ready);
    }

    #[test]
    fn test_smtp_mail_from_before_ehlo_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let resp = cmd(&mut conn, "MAIL FROM:<test@example.com>");
        assert!(resp.contains("503"), "Should fail: {resp}");
    }

    #[test]
    fn test_smtp_full_command_sequence() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);

        let r = cmd(&mut conn, "EHLO client.test");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::Ready);

        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::MailFrom);
        assert_eq!(conn.mail_from, Some("sender@test.com".into()));

        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::RcptTo);
        assert_eq!(conn.rcpt_to, vec!["rcpt@test.com"]);

        let r = cmd(&mut conn, "DATA");
        assert!(r.contains("354"));
        assert_eq!(conn.state, SmtpState::Data);
    }

    #[test]
    fn test_smtp_rcpt_to_before_mail_from_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("503"), "Should fail: {r}");
    }

    #[test]
    fn test_smtp_data_before_rcpt_to_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "DATA");
        assert!(r.contains("503"), "DATA without RCPT should fail: {r}");
    }

    #[test]
    fn test_smtp_rset_resets_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert_eq!(conn.state, SmtpState::MailFrom);

        let r = cmd(&mut conn, "RSET");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());

       // After RSET, RCPT should fail (no MAIL FROM)
        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("503"));
    }

    #[test]
    fn test_smtp_noop() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "NOOP");
        assert!(r.contains("250"));
    }

    #[test]
    fn test_smtp_quit() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let r = cmd(&mut conn, "QUIT");
        assert_eq!(r, "QUIT");
    }

    #[test]
    fn test_smtp_multiple_rcpt_to() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<a@test.com>");
        cmd(&mut conn, "RCPT TO:<b@test.com>");
        cmd(&mut conn, "RCPT TO:<c@test.com>");
        assert_eq!(conn.rcpt_to.len(), 3);
    }

    #[test]
    fn test_smtp_too_many_recipients() {
        let config = test_config(); // max_recipients = 10
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        for i in 0..10 {
            cmd(&mut conn, &format!("RCPT TO:<user{i}@test.com>"));
        }
        let r = cmd(&mut conn, "RCPT TO:<overflow@test.com>");
        assert!(r.contains("452"), "Should reject excess recipients: {r}");
    }

    #[test]
    fn test_smtp_starttls_without_tls_config() {
        let config = test_config(); // tls = None
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "STARTTLS");
        assert!(r.contains("502"), "No TLS config should return 502: {r}");
    }

    #[test]
    fn test_smtp_rejects_non_local_recipient_domain() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@external.net>");
        assert!(r.contains("554"), "Non-local relay should be denied: {r}");
    }

    #[test]
    fn test_smtp_accepts_empty_bounce_sender() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "MAIL FROM:<>");
        assert!(r.contains("250"), "Bounce sender should be allowed: {r}");
        assert!(conn.mail_from.is_none());
    }

    #[test]
    fn test_smtp_local_domain_match_is_case_insensitive() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@Corp.Com>");
        assert!(r.contains("250"), "Local domains should match case-insensitively: {r}");
    }

    #[test]
    fn test_data_line_unstuffs_leading_dot() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        conn.state = SmtpState::Data;

        assert!(matches!(
            conn.append_data_line(b"..leading dot\r\n"),
            DataLineResult::Continue
        ));
        assert_eq!(conn.data_buffer, b".leading dot\r\n");
    }

    #[test]
    fn test_session_started_is_set_on_construction() {
        let config = test_config();
        let before = Instant::now();
        let conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        assert!(conn.session_started >= before);
        assert!(conn.session_started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_data_phase_started_set_on_data_command() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(conn.data_phase_started.is_none());
        cmd(&mut conn, "DATA");
        assert!(conn.data_phase_started.is_some());
    }

    #[test]
    fn test_data_phase_started_cleared_on_reset() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        cmd(&mut conn, "DATA");
        assert!(conn.data_phase_started.is_some());
        conn.reset_transaction();
        assert!(conn.data_phase_started.is_none());
    }

    #[tokio::test]
    async fn test_build_email_session_from_raw() {
        let config = test_config();
        let mut conn = SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        let raw = b"From: test@example.com\r\nTo: admin@corp.com\r\nSubject: Hello\r\n\r\nBody text";
        let session = conn.build_email_session(raw);

        assert_eq!(session.client_ip, "10.0.0.1");
        assert_eq!(session.mail_from, Some("test@example.com".into()));
        assert_eq!(session.rcpt_to, vec!["admin@corp.com"]);
        assert_eq!(session.subject, Some("Hello".into()));
        assert!(session.content.body_text.is_some());
        assert_eq!(session.source, SessionSource::MtaProxy);
        assert_eq!(session.status, SessionStatus::Completed);
    }

    // ── SEC: SMTP Smuggling regression tests (P01 / P02) ──────────────────

    /// P01: DATA terminator MUST be strictly ".\r\n" (RFC 5321 §4.1.1.4).
    /// Bare LF ".\n" must NOT terminate the DATA phase — it should be treated
    /// as ordinary message content, matching the Sniffer's strict \r\n.\r\n parsing.
    #[test]
    fn test_p01_bare_lf_data_terminator_rejected() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        conn.state = SmtpState::Data;

        // ".\n" (bare LF) must NOT complete the DATA phase
        assert!(
            matches!(conn.append_data_line(b".\n"), DataLineResult::Continue),
            "Bare LF data terminator must be rejected — SMTP smuggling vector (CWE-444)"
        );
        // The ".\n" bytes should be accumulated as message body content
        assert_eq!(conn.data_buffer, b".\n");
    }

    /// P01: Proper CRLF DATA terminator ".\r\n" MUST still work.
    #[test]
    fn test_p01_crlf_data_terminator_accepted() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        conn.state = SmtpState::Data;

        // Feed some data first
        assert!(matches!(
            conn.append_data_line(b"Hello\r\n"),
            DataLineResult::Continue
        ));

        // ".\r\n" (proper CRLF) MUST complete the DATA phase
        assert!(
            matches!(conn.append_data_line(b".\r\n"), DataLineResult::Complete(_)),
            "Proper CRLF data terminator must be accepted"
        );
    }

    /// P02: trim_line_end MUST only strip \r\n — bare \r and bare \n are kept.
    #[test]
    fn test_p02_trim_line_end_strict_crlf_only() {
        // Proper CRLF is stripped
        assert_eq!(trim_line_end(b"EHLO test\r\n"), b"EHLO test");

        // Bare \n is NOT stripped — kept as part of the line
        assert_eq!(trim_line_end(b"EHLO test\n"), b"EHLO test\n");

        // Bare \r is NOT stripped — kept as part of the line
        assert_eq!(trim_line_end(b"EHLO test\r"), b"EHLO test\r");

        // No terminator — unchanged
        assert_eq!(trim_line_end(b"EHLO test"), b"EHLO test");

        // Only \r\n at end — stripped
        assert_eq!(trim_line_end(b"\r\n"), b"");

        // Embedded \r\n not at end — only trailing \r\n stripped
        assert_eq!(trim_line_end(b"A\r\nB\r\n"), b"A\r\nB");
    }

    /// P01 + P02 combined: An attacker sending ".\r" (bare CR dot) must NOT
    /// terminate DATA — it must be treated as regular message content.
    #[test]
    fn test_smuggling_bare_cr_dot_not_terminator() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        conn.state = SmtpState::Data;

        // ".\r" followed by something — must NOT complete DATA
        assert!(matches!(
            conn.append_data_line(b".\r"),
            DataLineResult::Continue
        ));
        assert_eq!(conn.data_buffer, b".\r");
    }

    #[tokio::test]
    async fn test_handle_rejects_lf_only_command_terminator() {
        use tokio::io::AsyncWriteExt;

        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        client_stream.write_all(b"EHLO client.test\n").await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        assert!(results.is_empty(), "Malformed LF-only command should not yield SMTP events");

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("500 5.5.2 Line terminator must be CRLF\r\n"));
    }

    // ── RFC 3030 BDAT / CHUNKING tests ────────────────────────────────────

    #[test]
    fn test_ehlo_advertises_chunking() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let resp = cmd(&mut conn, "EHLO client.test");
        assert!(resp.contains("CHUNKING"), "EHLO should advertise CHUNKING: {resp}");
    }

    #[test]
    fn test_parse_bdat_args_single_chunk() {
        let (size, is_last) = parse_bdat_args("BDAT 1024").unwrap();
        assert_eq!(size, 1024);
        assert!(!is_last);
    }

    #[test]
    fn test_parse_bdat_args_last_chunk() {
        let (size, is_last) = parse_bdat_args("BDAT 512 LAST").unwrap();
        assert_eq!(size, 512);
        assert!(is_last);
    }

    #[test]
    fn test_parse_bdat_args_zero_last() {
        // BDAT 0 LAST is valid (empty final chunk)
        let (size, is_last) = parse_bdat_args("BDAT 0 LAST").unwrap();
        assert_eq!(size, 0);
        assert!(is_last);
    }

    #[test]
    fn test_parse_bdat_args_zero_non_last_rejected() {
        assert!(parse_bdat_args("BDAT 0").is_err());
    }

    #[test]
    fn test_parse_bdat_args_missing_size() {
        assert!(parse_bdat_args("BDAT").is_err());
        assert!(parse_bdat_args("BDAT ").is_err());
    }

    #[test]
    fn test_parse_bdat_args_invalid_size() {
        assert!(parse_bdat_args("BDAT abc").is_err());
        assert!(parse_bdat_args("BDAT -1").is_err());
    }

    #[test]
    fn test_bdat_before_rcpt_to_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "BDAT 100");
        assert!(r.contains("503"), "BDAT without RCPT should fail: {r}");
    }

    #[test]
    fn test_bdat_chunk_too_large() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        let r = cmd(&mut conn, &format!("BDAT {}", MAX_BDAT_CHUNK_SIZE + 1));
        assert!(r.contains("552"), "Oversized BDAT chunk should be rejected: {r}");
    }

    #[test]
    fn test_bdat_transitions_to_bdat_data_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        cmd(&mut conn, "BDAT 100");
        assert_eq!(conn.state, SmtpState::BdatData);
        assert_eq!(conn.bdat_remaining, 100);
        assert!(!conn.bdat_is_last);
    }

    #[test]
    fn test_bdat_last_transitions_correctly() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        cmd(&mut conn, "BDAT 100 LAST");
        assert_eq!(conn.state, SmtpState::BdatData);
        assert_eq!(conn.bdat_remaining, 100);
        assert!(conn.bdat_is_last);
    }

    #[test]
    fn test_bdat_sets_data_phase_started() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(conn.data_phase_started.is_none());
        cmd(&mut conn, "BDAT 100");
        assert!(conn.data_phase_started.is_some());
    }

    #[test]
    fn test_bdat_reset_clears_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        cmd(&mut conn, "BDAT 100 LAST");
        assert_eq!(conn.bdat_remaining, 100);
        assert!(conn.bdat_is_last);
        conn.reset_transaction();
        assert_eq!(conn.bdat_remaining, 0);
        assert!(!conn.bdat_is_last);
        assert_eq!(conn.state, SmtpState::Ready);
    }

    #[test]
    fn test_bdat_message_too_large() {
        let config = test_config(); // max_message_size = 1MB
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        // Try a chunk larger than max_message_size (1MB)
        let r = cmd(&mut conn, &format!("BDAT {}", 1024 * 1024 + 1));
        assert!(r.contains("552"), "BDAT exceeding max_message_size should be rejected: {r}");
    }

    #[tokio::test]
    async fn test_data_session_stops_at_message_boundary() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: DATA Test\r\n\r\nHello\r\n.\r\n");
        input.extend_from_slice(b"QUIT\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(8192);
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        assert!(
            results.iter().any(|result| matches!(result, HandleResult::Email(_, _))),
            "DATA completion should yield one email transaction"
        );
        assert!(
            !results.iter().any(|result| matches!(result, HandleResult::Closed)),
            "handle() must stop at the message boundary before consuming QUIT"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("354 Start mail input; end with <CRLF>.<CRLF>\r\n"));
        assert!(
            !replies.contains("250 2.0.0 OK\r\n"),
            "Final DATA reply must not be emitted before the inline verdict path runs"
        );

        let quit_results = conn.handle(&mut server_stream, true).await;
        assert!(
            quit_results.iter().any(|result| matches!(result, HandleResult::Closed)),
            "QUIT should be processed on the next handle() call"
        );
    }

    /// Integration test: full BDAT session via the handle() async method.
    #[tokio::test]
    async fn test_bdat_full_session_via_handle() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let email_body = b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: BDAT Test\r\n\r\nBDAT body content";
        let body_len = email_body.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {body_len} LAST\r\n").as_bytes());
        input.extend_from_slice(email_body);
        input.extend_from_slice(b"QUIT\r\n");

        // DuplexStream has two independent 8192-byte channel buffers (one per direction).
        // Client input (~200B) and server responses (~230B) both fit without blocking.
        let (mut client_stream, server_stream) = tokio::io::duplex(8192);

        // Pre-load all client data into the channel buffer, then close write half.
        // client_stream stays alive (read half open) so server writes don't get broken-pipe.
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let results = conn.handle(&mut server_stream, false).await;

        let result_tags: Vec<&str> = results.iter().map(|r| match r {
            HandleResult::Email(_, _) => "Email",
            HandleResult::Closed => "Closed",
            HandleResult::Error(_) => "Error",
            HandleResult::StartTls => "StartTls",
        }).collect();
        let has_email = result_tags.contains(&"Email");
        assert!(has_email, "Should produce an Email result from BDAT session, got: {result_tags:?}");
        assert!(
            !result_tags.contains(&"Closed"),
            "handle() must stop at the BDAT message boundary before consuming QUIT"
        );

        if let Some(HandleResult::Email(session, raw)) = results.into_iter().find(|r| matches!(r, HandleResult::Email(_, _))) {
            assert_eq!(session.mail_from, Some("sender@test.com".into()));
            assert_eq!(session.rcpt_to, vec!["rcpt@test.com".to_string()]);
            assert_eq!(session.subject, Some("BDAT Test".into()));
            assert_eq!(raw.len(), body_len);
        }

        let replies = read_available(&mut client_stream).await;
        assert!(
            !replies.contains("250 2.0.0 BDAT chunk accepted, message complete\r\n"),
            "BDAT LAST must not acknowledge final delivery before verdict processing"
        );

        let quit_results = conn.handle(&mut server_stream, true).await;
        assert!(quit_results.iter().any(|result| matches!(result, HandleResult::Closed)));
    }

    /// Integration test: multi-chunk BDAT session (same sequential approach).
    #[tokio::test]
    async fn test_bdat_multi_chunk_via_handle() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let chunk1 = b"From: sender@test.com\r\nTo: rcpt@test.com\r\n";
        let chunk2 = b"Subject: Multi-Chunk\r\n\r\nBody here";
        let chunk1_len = chunk1.len();
        let chunk2_len = chunk2.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {chunk1_len}\r\n").as_bytes());
        input.extend_from_slice(chunk1);
        input.extend_from_slice(format!("BDAT {chunk2_len} LAST\r\n").as_bytes());
        input.extend_from_slice(chunk2);
        input.extend_from_slice(b"QUIT\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(8192);

        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let results = conn.handle(&mut server_stream, false).await;

        let result_tags: Vec<&str> = results.iter().map(|r| match r {
            HandleResult::Email(_, _) => "Email",
            HandleResult::Closed => "Closed",
            HandleResult::Error(_) => "Error",
            HandleResult::StartTls => "StartTls",
        }).collect();
        let has_email = result_tags.contains(&"Email");
        assert!(has_email, "Should produce an Email result from multi-chunk BDAT, got: {result_tags:?}");
        assert!(
            !result_tags.contains(&"Closed"),
            "handle() must stop once the multi-chunk message is assembled"
        );

        if let Some(HandleResult::Email(session, raw)) = results.into_iter().find(|r| matches!(r, HandleResult::Email(_, _))) {
            assert_eq!(raw.len(), chunk1_len + chunk2_len);
            assert_eq!(session.subject, Some("Multi-Chunk".into()));
        }

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("250 2.0.0 BDAT chunk accepted\r\n"));
        assert!(
            !replies.contains("250 2.0.0 BDAT chunk accepted, message complete\r\n"),
            "Final BDAT response must be deferred until the verdict path completes"
        );

        let quit_results = conn.handle(&mut server_stream, true).await;
        assert!(quit_results.iter().any(|result| matches!(result, HandleResult::Closed)));
    }
}
