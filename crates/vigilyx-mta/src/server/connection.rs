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
use vigilyx_parser::mime::{MimeParser, decode_rfc2047};

use crate::config::{MtaConfig, is_trusted_upstream_ip};
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
    /// SEC: BDAT CRLF validation state — true when the previous chunk ended
    /// with a `\r` whose `\n` must be the first byte of the next chunk.
    bdat_pending_cr: bool,
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
    /// Message could not be parsed safely enough for inline inspection.
    SecurityTempfail(String),
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
    pub fn new(
        client_ip: String,
        client_port: u16,
        server_ip: String,
        server_port: u16,
        config: Arc<MtaConfig>,
        tls_active: bool,
    ) -> Self {
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
            bdat_pending_cr: false,
        }
    }

    /// SEC: cumulative time-budget check shared by the outer command loop and
    /// the BDAT inner read loop (F-2). Returns the SMTP reply bytes to send
    /// when the session lifetime or the DATA/BDAT transaction budget has been
    /// exhausted, `None` while both budgets still have headroom.
    fn transaction_budget_reply(&self) -> Option<&'static [u8]> {
        if self.session_started.elapsed() > Duration::from_secs(MAX_SESSION_SECS) {
            return Some(b"421 4.4.2 Session lifetime exceeded\r\n");
        }
        if let Some(data_start) = self.data_phase_started
            && data_start.elapsed() > Duration::from_secs(MAX_DATA_TRANSACTION_SECS)
        {
            return Some(b"451 4.4.2 DATA transaction timeout\r\n");
        }
        None
    }

    fn reset_transaction(&mut self) {
        self.state = SmtpState::Ready;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.data_phase_started = None;
        self.bdat_remaining = 0;
        self.bdat_is_last = false;
        self.bdat_pending_cr = false;
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
        let payload = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line
        };
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

    fn may_relay_to_recipient(&self, addr: &str) -> bool {
        if self.is_local_recipient(addr) {
            return true;
        }

        let sender_is_local = self
            .mail_from
            .as_deref()
            .and_then(extract_domain)
            .is_some_and(|domain| {
                self.config
                    .local_domains
                    .iter()
                    .any(|local| local.eq_ignore_ascii_case(domain))
            });
        sender_is_local
            && is_trusted_upstream_ip(&self.client_ip, &self.config.trusted_upstream_cidrs)
    }

    fn complete_message(&mut self, raw_email: Vec<u8>, event: &'static str) -> HandleResult {
        let session = match self.build_email_session(&raw_email) {
            Ok(session) => session,
            Err(reason) => {
                warn!(
                    client_ip = %self.client_ip,
                    data_size = raw_email.len(),
                    "MIME parse failed in inline MTA path: {reason}"
                );
                self.reset_transaction();
                return HandleResult::SecurityTempfail(reason);
            }
        };
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
    pub async fn handle<S>(&mut self, stream: &mut S, skip_banner: bool) -> Vec<HandleResult>
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
                let _ = stream
                    .write_all(b"421 4.4.2 Session lifetime exceeded\r\n")
                    .await;
                let _ = stream.flush().await;
                break;
            }

            // SEC: enforce total DATA/BDAT transaction timeout to prevent slow-data attacks
            if let Some(data_start) = self.data_phase_started
                && data_start.elapsed() > Duration::from_secs(MAX_DATA_TRANSACTION_SECS)
            {
                warn!(client_ip = %self.client_ip, elapsed_secs = MAX_DATA_TRANSACTION_SECS, "DATA/BDAT transaction timeout");
                let _ = stream
                    .write_all(b"451 4.4.2 DATA transaction timeout\r\n")
                    .await;
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
                // SEC: set when the chunk violated the CRLF-only rule (F-1);
                // handled after the loop because the fill_buf borrow of the
                // stream must end before we can write the rejection reply.
                let mut invalid_line_endings = false;
                while bytes_left > 0 {
                    // SEC: cumulative budgets (F-2). A per-read timeout alone lets a
                    // slow-drip client hold the BDAT phase open indefinitely by
                    // sending one byte every ~300s (CWE-400).
                    if let Some(reply) = self.transaction_budget_reply() {
                        warn!(client_ip = %self.client_ip, "BDAT cumulative time budget exceeded");
                        let _ = stream.write_all(reply).await;
                        let _ = stream.flush().await;
                        chunk_error = true;
                        break;
                    }

                    let read_result = tokio::time::timeout(bdat_timeout, stream.fill_buf()).await;
                    match read_result {
                        Ok(Ok([])) => {
                            warn!(client_ip = %self.client_ip, "Client disconnected during BDAT chunk");
                            chunk_error = true;
                            break;
                        }
                        Ok(Ok(buf)) => {
                            let take = buf.len().min(bytes_left);
                            // SEC: RFC 5321 requires CRLF line endings. BDAT chunk
                            // bytes are relayed to the downstream MTA verbatim, where
                            // a bare `\n.\n` sequence can act as an end-of-DATA marker
                            // on lenient parsers and smuggle a second message past
                            // inline inspection (CWE-444). Enforce the same strictness
                            // as the DATA path.
                            if !bdat_chunk_has_only_crlf(&buf[..take], &mut self.bdat_pending_cr) {
                                invalid_line_endings = true;
                                chunk_error = true;
                                break;
                            }
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

                // A message whose final byte is a bare CR is rejected too: the CR
                // would reach the downstream MTA without its LF.
                if !chunk_error && self.bdat_is_last && self.bdat_pending_cr {
                    invalid_line_endings = true;
                    chunk_error = true;
                }

                if invalid_line_endings {
                    warn!(client_ip = %self.client_ip, "BDAT chunk rejected: bare CR/LF (possible SMTP smuggling)");
                    let _ = stream
                        .write_all(b"554 5.6.0 BDAT chunk must use CRLF line endings\r\n")
                        .await;
                    let _ = stream.flush().await;
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
            let read_result =
                tokio::time::timeout(idle_timeout, read_smtp_line(stream, line_limit)).await;

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
                    let _ = stream
                        .write_all(b"500 5.5.2 Invalid command encoding\r\n")
                        .await;
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
        if smtp_command_no_args(upper, "QUIT") {
            return CmdResponse::Quit;
        }

        if smtp_command_no_args(upper, "RSET") {
            self.reset_transaction();
            return CmdResponse::Reply(250, "2.1.5 OK".into());
        }

        if smtp_command_keyword(upper, "NOOP") {
            return CmdResponse::Reply(250, "2.0.0 OK".into());
        }

        match self.state {
            SmtpState::Connected => {
                if smtp_command_keyword(upper, "EHLO") || smtp_command_keyword(upper, "HELO") {
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
                if smtp_command_no_args(upper, "STARTTLS") && self.state == SmtpState::Ready {
                    if self.tls_active {
                        return CmdResponse::Reply(503, "5.5.1 TLS already active".into());
                    }
                    if self.config.tls.is_none() {
                        return CmdResponse::Reply(502, "5.5.1 TLS not available".into());
                    }
                    return CmdResponse::StartTls;
                }

                if smtp_command_keyword(upper, "EHLO") || smtp_command_keyword(upper, "HELO") {
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

                if smtp_path_command(upper, "MAIL FROM") {
                    if self.state != SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Nested MAIL command".into());
                    }
                    // SEC: MTA_REQUIRE_STARTTLS (F-4) — when enabled, a plaintext
                    // session may not start a mail transaction (RFC 3207, 530 reply).
                    if self.config.require_starttls && !self.tls_active {
                        return CmdResponse::Reply(
                            530,
                            "5.7.0 Must issue a STARTTLS command first".into(),
                        );
                    }
                    let addr = match extract_envelope_address(original, true) {
                        Ok(addr) => addr,
                        Err(_) => {
                            return CmdResponse::Reply(
                                501,
                                "5.1.7 Bad sender address syntax".into(),
                            );
                        }
                    };
                    let from_domain = addr
                        .as_deref()
                        .and_then(|a| a.rsplit('@').next())
                        .unwrap_or("<>");
                    tracing::info!(from_domain = %from_domain, "MAIL FROM accepted");
                    self.mail_from = addr;
                    self.state = SmtpState::MailFrom;
                    return CmdResponse::Reply(250, "2.1.0 OK".into());
                }

                if smtp_path_command(upper, "RCPT TO") {
                    if self.state == SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Need MAIL command first".into());
                    }
                    if self.rcpt_to.len() >= self.config.max_recipients {
                        return CmdResponse::Reply(452, "4.5.3 Too many recipients".into());
                    }
                    let addr = match extract_envelope_address(original, false) {
                        Ok(Some(addr)) => addr,
                        Ok(None) | Err(_) => {
                            return CmdResponse::Reply(
                                501,
                                "5.1.3 Bad recipient address syntax".into(),
                            );
                        }
                    };
                    // Port 25 remains closed to unauthenticated third-party
                    // relay. Explicitly trusted submission relays may target
                    // external recipients; this is the path that makes
                    // outbound routing and DLP enforcement reachable.
                    if !self.may_relay_to_recipient(&addr) {
                        return CmdResponse::Reply(554, "5.7.1 Relay access denied".into());
                    }
                    let rcpt_domain = addr.rsplit('@').next().unwrap_or("<>");
                    tracing::info!(rcpt_domain = %rcpt_domain, rcpt_count = self.rcpt_to.len() + 1, "RCPT TO accepted");
                    self.rcpt_to.push(addr);
                    self.state = SmtpState::RcptTo;
                    return CmdResponse::Reply(250, "2.1.5 OK".into());
                }

                if smtp_command_no_args(upper, "DATA") {
                    if self.rcpt_to.is_empty() {
                        return CmdResponse::Reply(503, "5.5.1 Need RCPT command first".into());
                    }
                    self.state = SmtpState::Data;
                    self.data_phase_started = Some(Instant::now());
                    self.data_buffer.clear();
                    return CmdResponse::Reply(
                        354,
                        "Start mail input; end with <CRLF>.<CRLF>".into(),
                    );
                }

                // RFC 3030: BDAT <size> [LAST]
                if smtp_command_keyword(upper, "BDAT") {
                    if self.rcpt_to.is_empty() {
                        return CmdResponse::Reply(503, "5.5.1 Need RCPT command first".into());
                    }
                    match parse_bdat_args(upper) {
                        Ok((size, is_last)) => {
                            if size > MAX_BDAT_CHUNK_SIZE {
                                return CmdResponse::Reply(
                                    552,
                                    "5.3.4 BDAT chunk too large".into(),
                                );
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
    fn build_email_session(&self, raw_email: &[u8]) -> Result<EmailSession, String> {
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
        session.content = parser
            .parse(raw_email)
            .map_err(|e| format!("MIME parse error: {e:?}"))?;
        session.content.is_complete = true;

        // headers subject message_id
        // Mirror the sniffer path (smtp_process.rs): RFC 2047 encoded-words
        // must be decoded so keyword detectors see the same text the MUA
        // renders. Without this an =?UTF-8?B?...?= phishing subject stayed
        // opaque base64 on the MTA path only.
        for (key, value) in &session.content.headers {
            match key.to_ascii_lowercase().as_str() {
                "subject" if session.subject.is_none() => {
                    let decoded = decode_rfc2047(value);
                    let trimmed = decoded.trim();
                    if !trimmed.is_empty() {
                        session.subject = Some(trimmed.to_string());
                    }
                }
                "from" if session.mail_from.is_none() => {
                    let decoded = decode_rfc2047(value);
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
                "to" if session.rcpt_to.is_empty() => {
                    let decoded = decode_rfc2047(value);
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
                "message-id" if session.message_id.is_none() => {
                    session.message_id = Some(value.clone());
                }
                _ => {}
            }
        }

        Ok(session)
    }
}

/// SEC: RFC 5321 strict line endings for BDAT chunk bytes (CWE-444).
/// This helper is shared by every BDAT read chunk so a CRLF split across
/// buffer boundaries is validated exactly once.
/// Returns false when the chunk contains a bare LF (`\n` not preceded by
/// `\r`) or a bare CR (`\r` not followed by `\n`). A CR at the very end of a
/// chunk is provisionally accepted via `pending_cr` and must be resolved by
/// the first byte of the next chunk (or rejected for a LAST chunk).
fn bdat_chunk_has_only_crlf(chunk: &[u8], pending_cr: &mut bool) -> bool {
    for &byte in chunk {
        if *pending_cr {
            *pending_cr = false;
            if byte != b'\n' {
                return false;
            }
            continue;
        }
        match byte {
            b'\r' => *pending_cr = true,
            b'\n' => return false,
            _ => {}
        }
    }
    true
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

fn smtp_command_keyword(upper: &str, keyword: &str) -> bool {
    upper == keyword
        || upper
            .strip_prefix(keyword)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn smtp_command_no_args(upper: &str, keyword: &str) -> bool {
    upper
        .strip_prefix(keyword)
        .is_some_and(|rest| rest.trim().is_empty())
}

fn smtp_path_command(upper: &str, keyword: &str) -> bool {
    upper
        .strip_prefix(keyword)
        .is_some_and(|rest| rest.trim_start().starts_with(':'))
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

    let size_str = size_str.trim();
    if size_str.is_empty() || !size_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid chunk size");
    }

    let size: usize = size_str.parse().map_err(|_| "invalid chunk size")?;

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
        assert_eq!(extract_envelope_address("MAIL FROM:<>", true), Ok(None));
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
            trusted_upstream_cidrs: Vec::new(),
            inline_timeout_secs: 8,
            fail_open: true,
            require_starttls: false,
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

    fn test_config_with_tls() -> Arc<MtaConfig> {
        Arc::new(MtaConfig {
            tls: Some(crate::config::TlsConfig {
                cert_path: std::path::PathBuf::from("/tmp/test.crt"),
                key_path: std::path::PathBuf::from("/tmp/test.key"),
            }),
            ..(*test_config()).clone()
        })
    }

    fn test_config_with_max_message_size(max_message_size: usize) -> Arc<MtaConfig> {
        Arc::new(MtaConfig {
            max_message_size,
            ..(*test_config()).clone()
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let resp = cmd(&mut conn, "EHLO client.test");
        assert!(resp.contains("250"), "Should get 250: {resp}");
        assert!(resp.contains("PIPELINING"));
        assert!(resp.contains("8BITMIME"));
        assert_eq!(conn.state, SmtpState::Ready);
    }

    #[test]
    fn test_smtp_mail_from_before_ehlo_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let resp = cmd(&mut conn, "MAIL FROM:<test@example.com>");
        assert!(resp.contains("503"), "Should fail: {resp}");
    }

    #[test]
    fn test_smtp_full_command_sequence() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );

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
    fn test_ehlo_resets_partial_mail_transaction() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO first");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        conn.data_buffer.extend_from_slice(b"partial");

        let r = cmd(&mut conn, "EHLO second");

        assert!(r.contains("250-test-mta Hello"));
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());
        assert!(conn.data_buffer.is_empty());
        assert!(conn.data_phase_started.is_none());
    }

    #[test]
    fn test_smtp_rcpt_to_before_mail_from_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("503"), "Should fail: {r}");
    }

    #[test]
    fn test_smtp_data_before_rcpt_to_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "DATA");
        assert!(r.contains("503"), "DATA without RCPT should fail: {r}");
    }

    #[test]
    fn test_smtp_rset_resets_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "NOOP");
        assert!(r.contains("250"));
    }

    #[test]
    fn test_smtp_quit() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let r = cmd(&mut conn, "QUIT");
        assert_eq!(r, "QUIT");
    }

    #[test]
    fn test_smtp_multiple_rcpt_to() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        for i in 0..10 {
            cmd(&mut conn, &format!("RCPT TO:<user{i}@test.com>"));
        }
        let r = cmd(&mut conn, "RCPT TO:<overflow@test.com>");
        assert!(r.contains("452"), "Should reject excess recipients: {r}");
        assert_eq!(conn.rcpt_to.len(), 10, "rejected recipient must not be retained");
    }

    #[test]
    fn test_smtp_starttls_without_tls_config() {
        let config = test_config(); // tls = None
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "STARTTLS");
        assert!(r.contains("502"), "No TLS config should return 502: {r}");
    }

    #[test]
    fn test_smtp_ehlo_advertises_starttls_when_tls_configured() {
        let config = test_config_with_tls();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let r = cmd(&mut conn, "EHLO test");
        assert!(
            r.contains("STARTTLS"),
            "TLS-capable EHLO should advertise STARTTLS: {r}"
        );
    }

    #[test]
    fn test_smtp_starttls_with_tls_config_returns_starttls() {
        let config = test_config_with_tls();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "STARTTLS");
        assert_eq!(r, "STARTTLS");
    }

    #[test]
    fn test_smtp_starttls_rejected_after_mail_transaction_started() {
        let config = test_config_with_tls();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");

        let r = cmd(&mut conn, "STARTTLS");

        assert!(r.contains("502"), "STARTTLS mid-transaction must fail: {r}");
        assert_eq!(conn.state, SmtpState::MailFrom);
        assert_eq!(conn.mail_from, Some("sender@test.com".into()));
    }

    #[test]
    fn test_smtp_rejects_command_keyword_prefix_smuggling() {
        let config = test_config_with_tls();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );

        let r = cmd(&mut conn, "EHLOX client.test");
        assert!(r.contains("503"), "EHLOX must not be accepted as EHLO: {r}");
        assert_eq!(conn.state, SmtpState::Connected);

        let r = cmd(&mut conn, "EHLO client.test");
        assert!(r.contains("250"));
        let r = cmd(&mut conn, "STARTTLSNOW");
        assert!(
            r.contains("502"),
            "STARTTLSNOW must not be accepted as STARTTLS: {r}"
        );
        assert_eq!(conn.state, SmtpState::Ready);

        let r = cmd(&mut conn, "QUITNOW");
        assert!(
            r.contains("502"),
            "QUITNOW must not be accepted as QUIT: {r}"
        );
        assert_eq!(conn.state, SmtpState::Ready);
    }

    #[test]
    fn test_smtp_rejects_transaction_command_prefix_smuggling_without_state_change() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");

        let r = cmd(&mut conn, "RSETNOW");
        assert!(
            r.contains("502"),
            "RSETNOW must not be accepted as RSET: {r}"
        );
        assert_eq!(conn.state, SmtpState::MailFrom);
        assert_eq!(conn.mail_from, Some("sender@test.com".into()));

        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        let r = cmd(&mut conn, "DATAFOO");
        assert!(
            r.contains("502"),
            "DATAFOO must not be accepted as DATA: {r}"
        );
        assert_eq!(conn.state, SmtpState::RcptTo);
        assert!(conn.data_phase_started.is_none());

        let r = cmd(&mut conn, "BDAT5 LAST");
        assert!(r.contains("502"), "BDAT5 must not be accepted as BDAT: {r}");
        assert_eq!(conn.state, SmtpState::RcptTo);
        assert_eq!(conn.bdat_remaining, 0);
    }

    #[test]
    fn test_smtp_rejects_mail_and_rcpt_keyword_prefix_smuggling() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO client.test");

        let r = cmd(&mut conn, "MAIL FROMX:<sender@test.com>");
        assert!(
            r.contains("502"),
            "MAIL FROMX must not be accepted as MAIL FROM: {r}"
        );
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());

        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(r.contains("250"));
        let r = cmd(&mut conn, "RCPT TOX:<rcpt@test.com>");
        assert!(
            r.contains("502"),
            "RCPT TOX must not be accepted as RCPT TO: {r}"
        );
        assert_eq!(conn.state, SmtpState::MailFrom);
        assert!(conn.rcpt_to.is_empty());
    }

    #[test]
    fn test_smtp_rejects_non_local_recipient_domain() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@external.net>");
        assert!(r.contains("554"), "Non-local relay should be denied: {r}");
    }

    #[test]
    fn test_trusted_submission_relay_accepts_external_recipient_for_outbound_dlp() {
        let mut config = (*test_config()).clone();
        config.trusted_upstream_cidrs = vec!["10.20.30.0/24".to_string()];
        let mut conn = SmtpConnection::new(
            "10.20.30.40".into(),
            9999,
            "0.0.0.0".into(),
            25,
            Arc::new(config),
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");

        let response = cmd(&mut conn, "RCPT TO:<user@external.net>");

        assert!(
            response.contains("250"),
            "Trusted submission relay must reach outbound DLP path: {response}"
        );
    }

    #[test]
    fn test_trusted_relay_cannot_forward_external_sender_to_external_recipient() {
        let mut config = (*test_config()).clone();
        config.trusted_upstream_cidrs = vec!["10.20.30.0/24".to_string()];
        let mut conn = SmtpConnection::new(
            "10.20.30.40".into(),
            9999,
            "0.0.0.0".into(),
            25,
            Arc::new(config),
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@external.example>");

        let response = cmd(&mut conn, "RCPT TO:<user@other.example>");

        assert!(response.contains("554"));
    }

    #[test]
    fn test_smtp_accepts_empty_bounce_sender() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "MAIL FROM:<>");
        assert!(r.contains("250"), "Bounce sender should be allowed: {r}");
        assert!(conn.mail_from.is_none());
    }

    #[test]
    fn test_smtp_local_domain_match_is_case_insensitive() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@Corp.Com>");
        assert!(
            r.contains("250"),
            "Local domains should match case-insensitively: {r}"
        );
    }

    #[test]
    fn test_data_line_unstuffs_leading_dot() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        assert!(conn.session_started >= before);
        assert!(conn.session_started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_data_phase_started_set_on_data_command() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn =
            SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        let raw = b"From: test@example.com\r\nTo: admin@corp.com\r\nSubject: Hello\r\nMessage-ID: <mta-test@example.com>\r\n\r\nBody text";
        let session = conn.build_email_session(raw).expect("valid raw email");
        assert_eq!(session.client_ip, "10.0.0.1");
        assert_eq!(session.mail_from, Some("test@example.com".into()));
        assert_eq!(session.rcpt_to, vec!["admin@corp.com"]);
        assert_eq!(session.subject, Some("Hello".into()));
        assert_eq!(session.message_id, Some("<mta-test@example.com>".into()));
        assert!(session.content.body_text.is_some());
        assert_eq!(session.source, SessionSource::MtaProxy);
        assert_eq!(session.status, SessionStatus::Completed);
    }

    #[tokio::test]
    async fn test_build_email_session_decodes_rfc2047_subject() {
        // PoC bypass: an RFC 2047 encoded-word subject previously stayed
        // opaque base64 on the MTA path while the sniffer path decoded it,
        // so MTA-mode keyword detection missed the phishing subject.
        let config = test_config();
        let mut conn =
            SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        // Subject: =?UTF-8?B?...?= encodes 您的账户存在异常登录
        let raw = b"From: test@example.com\r\nTo: admin@corp.com\r\nSubject: =?UTF-8?B?5oKo55qE6LSm5oi35a2Y5Zyo5byC5bi455m75b2V?=\r\n\r\nBody text";
        let session = conn.build_email_session(raw).expect("valid raw email");

        assert_eq!(
            session.subject.as_deref(),
            Some("您的账户存在异常登录"),
            "MTA session subject must be RFC 2047 decoded"
        );
    }

    #[tokio::test]
    async fn test_build_email_session_preserves_html_image_and_button_links() {
        // Regression for the image-only phishing drift found in the red-team
        // exercise: the inline MTA session must expose the same HTML body and
        // image/button URLs as the shared parser used by the offline pipeline.
        let config = test_config();
        let mut conn =
            SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        let raw = concat!(
            "From: test@example.com\r\n",
            "To: admin@corp.com\r\n",
            "Subject: image notice\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"IMG\"\r\n",
            "\r\n",
            "--IMG\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<a href=\"http://198.51.100.7/login\"><img src=\"http://198.51.100.7/banner.png\"></a>\r\n",
            "--IMG--\r\n",
        );
        let direct = MimeParser::new()
            .parse(raw.as_bytes())
            .expect("shared parser accepts html email");
        let session = conn
            .build_email_session(raw.as_bytes())
            .expect("valid raw email");

        assert_eq!(session.content.body_html, direct.body_html);
        let session_urls: Vec<&str> = session
            .content
            .links
            .iter()
            .map(|link| link.url.as_str())
            .collect();
        let direct_urls: Vec<&str> = direct
            .links
            .iter()
            .map(|link| link.url.as_str())
            .collect();
        assert_eq!(session_urls, direct_urls);
        assert!(session_urls.contains(&"http://198.51.100.7/login"));
        assert!(session_urls.contains(&"http://198.51.100.7/banner.png"));
    }

    #[tokio::test]
    async fn test_build_email_session_rfc2047_from_to_fallback() {
        // Bounce-style empty envelope: From/To headers (with RFC 2047
        // display names) must fill the session envelope, decoded.
        let config = test_config();
        let conn =
            SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);

        let raw = b"From: =?UTF-8?B?6LSm5oi35a6J5YWo?= <attacker@evil.example>\r\nTo: Victim <victim@corp.example>\r\nSubject: notice\r\n\r\nBody text";
        let session = conn.build_email_session(raw).expect("valid raw email");

        assert_eq!(session.mail_from.as_deref(), Some("attacker@evil.example"));
        assert_eq!(session.rcpt_to, vec!["victim@corp.example"]);
    }

    #[tokio::test]
    async fn test_malformed_mime_returns_security_tempfail() {
        let config = test_config();
        let mut conn =
            SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        let raw = b"From: test@example.com\r\nTo: admin@corp.com\r\nSubject: Bad MIME\r\nContent-Type: multipart/mixed\r\n\r\nbody";
        let result = conn.complete_message(raw.to_vec(), "malformed MIME test");

        assert!(
            matches!(result, HandleResult::SecurityTempfail(_)),
            "malformed MIME must not be treated as an empty safe message"
        );
    }

    // ── SEC: SMTP Smuggling regression tests (P01 / P02) ──────────────────

    /// P01: DATA terminator MUST be strictly ".\r\n" (RFC 5321 §4.1.1.4).
    /// Bare LF ".\n" must NOT terminate the DATA phase — it should be treated
    /// as ordinary message content, matching the Sniffer's strict \r\n.\r\n parsing.
    #[test]
    fn test_p01_bare_lf_data_terminator_rejected() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        conn.state = SmtpState::Data;

        // ".\r" followed by something — must NOT complete DATA
        assert!(matches!(
            conn.append_data_line(b".\r"),
            DataLineResult::Continue
        ));
        assert_eq!(conn.data_buffer, b".\r");
    }

    #[tokio::test]
    async fn test_read_smtp_line_accepts_crlf_split_across_reads() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"EHLO split.test\r").await.unwrap();
            tokio::task::yield_now().await;
            writer.write_all(b"\n").await.unwrap();
        });
        let mut reader = tokio::io::BufReader::new(reader);

        let line = read_smtp_line(&mut reader, MAX_COMMAND_LEN)
            .await
            .expect("split CRLF should be readable")
            .expect("line should be present");

        assert_eq!(line, b"EHLO split.test\r\n");
        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_smtp_line_rejects_cr_followed_by_non_lf_across_reads() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"EHLO bad\r").await.unwrap();
            tokio::task::yield_now().await;
            writer.write_all(b"X").await.unwrap();
        });
        let mut reader = tokio::io::BufReader::new(reader);

        let err = read_smtp_line(&mut reader, MAX_COMMAND_LEN)
            .await
            .expect_err("CR not followed by LF must be rejected");

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_enforces_session_lifetime_before_reading_commands() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        conn.session_started = Instant::now() - Duration::from_secs(MAX_SESSION_SECS + 1);

        let results = conn.handle(&mut server_stream, false).await;

        assert!(results.is_empty());
        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("220 test-mta ESMTP Vigilyx MTA\r\n"));
        assert!(replies.contains("421 4.4.2 Session lifetime exceeded\r\n"));
    }

    #[tokio::test]
    async fn test_handle_data_transaction_timeout_resets_partial_message() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        conn.state = SmtpState::Data;
        conn.mail_from = Some("sender@test.com".into());
        conn.rcpt_to = vec!["rcpt@test.com".into()];
        conn.data_buffer.extend_from_slice(b"partial body");
        conn.data_phase_started =
            Some(Instant::now() - Duration::from_secs(MAX_DATA_TRANSACTION_SECS + 1));

        let results = conn.handle(&mut server_stream, true).await;

        assert!(results.is_empty());
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());
        assert!(conn.data_buffer.is_empty());
        assert!(conn.data_phase_started.is_none());
        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("451 4.4.2 DATA transaction timeout\r\n"));
    }

    #[tokio::test]
    async fn test_handle_bdat_transaction_timeout_resets_partial_chunk() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        conn.state = SmtpState::BdatData;
        conn.mail_from = Some("sender@test.com".into());
        conn.rcpt_to = vec!["rcpt@test.com".into()];
        conn.data_buffer.extend_from_slice(b"partial bdat");
        conn.bdat_remaining = 16;
        conn.bdat_is_last = true;
        conn.data_phase_started =
            Some(Instant::now() - Duration::from_secs(MAX_DATA_TRANSACTION_SECS + 1));

        let results = conn.handle(&mut server_stream, true).await;

        assert!(results.is_empty());
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());
        assert!(conn.data_buffer.is_empty());
        assert_eq!(conn.bdat_remaining, 0);
        assert!(!conn.bdat_is_last);
        assert!(conn.data_phase_started.is_none());
        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("451 4.4.2 DATA transaction timeout\r\n"));
    }

    #[tokio::test]
    async fn test_handle_rejects_lf_only_command_terminator() {
        use tokio::io::AsyncWriteExt;

        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        client_stream
            .write_all(b"EHLO client.test\n")
            .await
            .unwrap();
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
            results.is_empty(),
            "Malformed LF-only command should not yield SMTP events"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("500 5.5.2 Line terminator must be CRLF\r\n"));
    }

    #[tokio::test]
    async fn test_handle_rejects_cr_only_command_terminator() {
        use tokio::io::AsyncWriteExt;

        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        client_stream
            .write_all(b"EHLO client.test\r")
            .await
            .unwrap();
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
            results.is_empty(),
            "Malformed CR-only command should not yield SMTP events"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("500 5.5.2 Line terminator must be CRLF\r\n"));
    }

    #[tokio::test]
    async fn test_handle_rejects_invalid_command_encoding() {
        use tokio::io::AsyncWriteExt;

        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        client_stream
            .write_all(&[0xff, 0xfe, b'\r', b'\n'])
            .await
            .unwrap();
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
            results.is_empty(),
            "Invalid-encoding command should not yield SMTP events"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("500 5.5.2 Invalid command encoding\r\n"));
    }

    #[tokio::test]
    async fn test_handle_rejects_overlong_command_line() {
        use tokio::io::AsyncWriteExt;

        let mut line = vec![b'A'; MAX_COMMAND_LEN + 1];
        line.extend_from_slice(b"\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(4096);
        client_stream.write_all(&line).await.unwrap();
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
            results.is_empty(),
            "Overlong command should terminate handling"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("500 5.5.1 Line too long\r\n"));
    }

    #[tokio::test]
    async fn test_handle_rejects_overlong_data_line() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(&vec![b'A'; MAX_DATA_LINE_LEN + 1]);
        input.extend_from_slice(b"\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(32768);
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
            results.is_empty(),
            "Overlong DATA line should abort the transaction"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("354 Start mail input; end with <CRLF>.<CRLF>\r\n"));
        assert!(replies.contains("554 5.6.0 DATA line too long\r\n"));
    }

    // ── RFC 3030 BDAT / CHUNKING tests ────────────────────────────────────

    #[test]
    fn test_ehlo_advertises_chunking() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let resp = cmd(&mut conn, "EHLO client.test");
        assert!(
            resp.contains("CHUNKING"),
            "EHLO should advertise CHUNKING: {resp}"
        );
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
        assert!(parse_bdat_args("BDAT +1").is_err());
        assert!(parse_bdat_args("BDAT 1.0").is_err());
        assert!(parse_bdat_args("BDAT 1 LAST EXTRA").is_err());
    }

    #[test]
    fn test_bdat_before_rcpt_to_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "BDAT 100");
        assert!(r.contains("503"), "BDAT without RCPT should fail: {r}");
    }

    #[test]
    fn test_bdat_chunk_too_large() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        let r = cmd(&mut conn, &format!("BDAT {}", MAX_BDAT_CHUNK_SIZE + 1));
        assert!(
            r.contains("552"),
            "Oversized BDAT chunk should be rejected: {r}"
        );
    }

    #[test]
    fn test_bdat_transitions_to_bdat_data_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        // Try a chunk larger than max_message_size (1MB)
        let r = cmd(&mut conn, &format!("BDAT {}", 1024 * 1024 + 1));
        assert!(
            r.contains("552"),
            "BDAT exceeding max_message_size should be rejected: {r}"
        );
    }

    #[test]
    fn test_bdat_cumulative_message_too_large_uses_existing_buffer_size() {
        let config = test_config_with_max_message_size(10);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        conn.data_buffer.extend_from_slice(b"123456");

        let r = cmd(&mut conn, "BDAT 5 LAST");

        assert!(
            r.contains("552"),
            "BDAT cumulative size should include already buffered chunks: {r}"
        );
        assert_eq!(conn.state, SmtpState::RcptTo);
        assert_eq!(conn.bdat_remaining, 0);
        assert!(!conn.bdat_is_last);
        assert_eq!(conn.data_buffer, b"123456");
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
            results
                .iter()
                .any(|result| matches!(result, HandleResult::Email(_, _))),
            "DATA completion should yield one email transaction"
        );
        assert!(
            !results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed)),
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
            quit_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed)),
            "QUIT should be processed on the next handle() call"
        );
    }

    #[tokio::test]
    async fn test_data_session_preserves_message_id_and_resets_transaction() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: DATA Test\r\nMessage-ID: <data@test.com>\r\n\r\nHello\r\n.\r\n",
        );

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
        let Some(HandleResult::Email(session, _raw)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected DATA flow to emit an email result");
        };

        assert_eq!(session.message_id, Some("<data@test.com>".into()));
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());
        assert!(conn.data_buffer.is_empty());
        assert!(conn.data_phase_started.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_data_sessions_are_isolated() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let mut handles = Vec::new();

        for idx in 0..64 {
            let config = Arc::clone(&config);
            handles.push(tokio::spawn(async move {
                let subject = format!("Concurrent {idx}");
                let message_id = format!("<concurrent-{idx}@test.com>");
                let input = format!(
                    concat!(
                        "EHLO client.test\r\n",
                        "MAIL FROM:<sender@test.com>\r\n",
                        "RCPT TO:<rcpt@test.com>\r\n",
                        "DATA\r\n",
                        "From: sender@test.com\r\n",
                        "To: rcpt@test.com\r\n",
                        "Subject: {}\r\n",
                        "Message-ID: {}\r\n",
                        "\r\n",
                        "Body {}\r\n",
                        ".\r\n"
                    ),
                    subject, message_id, idx
                );

                let (mut client_stream, server_stream) = tokio::io::duplex(8192);
                client_stream
                    .write_all(input.as_bytes())
                    .await
                    .expect("write concurrent SMTP input");
                client_stream.shutdown().await.expect("shutdown writer");

                let mut server_stream = tokio::io::BufStream::new(server_stream);
                let mut conn = SmtpConnection::new(
                    format!("127.0.0.{}", (idx % 250) + 1),
                    10000 + idx as u16,
                    "0.0.0.0".into(),
                    25,
                    config,
                    false,
                );

                let results = conn.handle(&mut server_stream, false).await;
                let Some(HandleResult::Email(session, raw)) = results
                    .into_iter()
                    .find(|result| matches!(result, HandleResult::Email(_, _)))
                else {
                    panic!("Expected concurrent DATA flow {idx} to emit an email result");
                };

                assert_eq!(session.subject, Some(subject.clone()));
                assert_eq!(session.message_id, Some(message_id.clone()));
                assert_eq!(session.mail_from, Some("sender@test.com".into()));
                assert_eq!(session.rcpt_to, vec!["rcpt@test.com"]);
                assert!(
                    raw.windows(subject.len())
                        .any(|window| window == subject.as_bytes())
                );
                assert_eq!(conn.state, SmtpState::Ready);
                assert!(conn.mail_from.is_none());
                assert!(conn.rcpt_to.is_empty());
                raw.len()
            }));
        }

        let mut total_bytes = 0usize;
        for handle in handles {
            total_bytes += handle.await.expect("concurrent SMTP task should not panic");
        }

        assert!(
            total_bytes > 64 * 64,
            "Concurrent sessions should all return non-empty raw messages"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_mixed_data_and_bdat_sessions_are_isolated() {
        use std::collections::HashSet;
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let mut handles = Vec::new();

        for idx in 0..48 {
            let config = Arc::clone(&config);
            handles.push(tokio::spawn(async move {
                let subject = format!("Mixed Concurrent {idx}");
                let message_id = format!("<mixed-concurrent-{idx}@test.com>");
                let mut input = Vec::new();
                input.extend_from_slice(b"EHLO client.test\r\n");
                input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
                input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");

                let is_bdat = idx % 2 == 1;
                if is_bdat {
                    let body = format!(
                        concat!(
                            "From: sender@test.com\r\n",
                            "To: rcpt@test.com\r\n",
                            "Subject: {}\r\n",
                            "Message-ID: {}\r\n",
                            "\r\n",
                            "BDAT body {}\r\n"
                        ),
                        &subject, &message_id, idx
                    );
                    input.extend_from_slice(format!("BDAT {} LAST\r\n", body.len()).as_bytes());
                    input.extend_from_slice(body.as_bytes());
                } else {
                    input.extend_from_slice(b"DATA\r\n");
                    input.extend_from_slice(
                        format!(
                            concat!(
                                "From: sender@test.com\r\n",
                                "To: rcpt@test.com\r\n",
                                "Subject: {}\r\n",
                                "Message-ID: {}\r\n",
                                "\r\n",
                                "DATA body {}\r\n",
                                ".\r\n"
                            ),
                            &subject, &message_id, idx
                        )
                        .as_bytes(),
                    );
                }

                let (mut client_stream, server_stream) =
                    tokio::io::duplex(input.len().max(8192) + 1024);
                client_stream
                    .write_all(&input)
                    .await
                    .expect("write mixed concurrent SMTP input");
                client_stream.shutdown().await.expect("shutdown writer");

                let mut server_stream = tokio::io::BufStream::new(server_stream);
                let mut conn = SmtpConnection::new(
                    format!("127.0.1.{}", (idx % 250) + 1),
                    11000 + idx as u16,
                    "0.0.0.0".into(),
                    25,
                    config,
                    false,
                );

                let results = conn.handle(&mut server_stream, false).await;
                let Some(HandleResult::Email(session, raw)) = results
                    .into_iter()
                    .find(|result| matches!(result, HandleResult::Email(_, _)))
                else {
                    panic!("Expected mixed concurrent flow {idx} to emit an email result");
                };

                assert_eq!(session.subject, Some(subject.clone()));
                assert_eq!(session.message_id, Some(message_id.clone()));
                assert_eq!(session.mail_from, Some("sender@test.com".into()));
                assert_eq!(session.rcpt_to, vec!["rcpt@test.com"]);
                assert_eq!(conn.state, SmtpState::Ready);
                assert!(conn.data_buffer.is_empty());
                assert_eq!(conn.bdat_remaining, 0);

                (session.id.to_string(), raw.len(), is_bdat)
            }));
        }

        let mut session_ids = HashSet::new();
        let mut bdat_count = 0usize;
        let mut data_count = 0usize;
        let mut total_bytes = 0usize;
        for handle in handles {
            let (session_id, raw_len, is_bdat) = handle
                .await
                .expect("mixed concurrent task should not panic");
            assert!(
                session_ids.insert(session_id),
                "Concurrent MTA sessions must receive unique session IDs"
            );
            total_bytes += raw_len;
            if is_bdat {
                bdat_count += 1;
            } else {
                data_count += 1;
            }
        }

        assert_eq!(data_count, 24);
        assert_eq!(bdat_count, 24);
        assert!(
            total_bytes > 48 * 64,
            "Mixed concurrent DATA/BDAT sessions should return non-empty raw messages"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_valid_and_malformed_sessions_do_not_cross_contaminate() {
        use tokio::io::AsyncWriteExt;

        let normal_config = test_config();
        let small_message_config = test_config_with_max_message_size(96);
        let mut handles = Vec::new();

        for idx in 0..40 {
            let config = if idx % 5 == 2 {
                Arc::clone(&small_message_config)
            } else {
                Arc::clone(&normal_config)
            };
            handles.push(tokio::spawn(async move {
                let valid_subject = format!("Valid Concurrent {idx}");
                let input = match idx % 5 {
                    0 => {
                        let mut input = Vec::new();
                        input.extend_from_slice(b"EHLO ");
                        input.extend_from_slice(&vec![b'A'; MAX_COMMAND_LEN + 8]);
                        input.extend_from_slice(b"\r\n");
                        input
                    }
                    1 => b"EHLO invalid-lf\n".to_vec(),
                    2 => {
                        let mut input = Vec::new();
                        input.extend_from_slice(b"EHLO client.test\r\n");
                        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
                        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
                        input.extend_from_slice(b"DATA\r\n");
                        input.extend_from_slice(b"Subject: Too Large\r\n\r\n");
                        input.extend_from_slice(&vec![b'X'; 256]);
                        input.extend_from_slice(b"\r\n.\r\n");
                        input
                    }
                    _ => format!(
                        concat!(
                            "EHLO client.test\r\n",
                            "MAIL FROM:<sender@test.com>\r\n",
                            "RCPT TO:<rcpt@test.com>\r\n",
                            "DATA\r\n",
                            "From: sender@test.com\r\n",
                            "To: rcpt@test.com\r\n",
                            "Subject: {}\r\n",
                            "Message-ID: <valid-concurrent-{}@test.com>\r\n",
                            "\r\n",
                            "Clean body {}\r\n",
                            ".\r\n"
                        ),
                        &valid_subject, idx, idx
                    )
                    .into_bytes(),
                };

                let (mut client_stream, server_stream) =
                    tokio::io::duplex(input.len().max(8192) + 1024);
                client_stream
                    .write_all(&input)
                    .await
                    .expect("write concurrent malformed SMTP input");
                client_stream.shutdown().await.expect("shutdown writer");

                let mut server_stream = tokio::io::BufStream::new(server_stream);
                let mut conn = SmtpConnection::new(
                    format!("127.0.2.{}", (idx % 250) + 1),
                    12000 + idx as u16,
                    "0.0.0.0".into(),
                    25,
                    config,
                    false,
                );

                let results = conn.handle(&mut server_stream, false).await;
                let replies = read_available(&mut client_stream).await;
                let email_result = results
                    .into_iter()
                    .find(|result| matches!(result, HandleResult::Email(_, _)));

                match idx % 5 {
                    0 => {
                        assert!(email_result.is_none());
                        assert!(
                            replies.contains("500 5.5.1 Line too long\r\n"),
                            "Overlong command should be rejected without affecting other sessions: {replies}"
                        );
                        false
                    }
                    1 => {
                        assert!(email_result.is_none());
                        assert!(
                            replies.contains("500 5.5.2 Line terminator must be CRLF\r\n"),
                            "Bare-LF command should be rejected without affecting other sessions: {replies}"
                        );
                        false
                    }
                    2 => {
                        assert!(email_result.is_none());
                        assert!(
                            replies.contains("552 5.3.4 Message too large\r\n"),
                            "Oversized DATA should be rejected without affecting other sessions: {replies}"
                        );
                        false
                    }
                    _ => {
                        let Some(HandleResult::Email(session, raw)) = email_result else {
                            panic!("Expected valid concurrent flow {idx} to emit an email result");
                        };
                        assert_eq!(session.subject, Some(valid_subject.clone()));
                        assert_eq!(
                            session.message_id,
                            Some(format!("<valid-concurrent-{idx}@test.com>"))
                        );
                        assert!(
                            raw.windows(valid_subject.len())
                                .any(|window| window == valid_subject.as_bytes())
                        );
                        true
                    }
                }
            }));
        }

        let mut valid_count = 0usize;
        let mut rejected_count = 0usize;
        for handle in handles {
            if handle
                .await
                .expect("valid/malformed concurrent task should not panic")
            {
                valid_count += 1;
            } else {
                rejected_count += 1;
            }
        }

        assert_eq!(valid_count, 16);
        assert_eq!(rejected_count, 24);
    }

    #[tokio::test]
    async fn test_data_session_unstuffs_dot_lines_without_terminating() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Dot Stuff\r\nMessage-ID: <dot@test.com>\r\n\r\n..leading dot\r\n...two leading dots\r\n.\r\n",
        );

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
        let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected DATA flow to emit an email result");
        };

        assert_eq!(session.subject, Some("Dot Stuff".into()));
        let raw_text = String::from_utf8(raw).expect("test raw email should be utf-8");
        assert!(raw_text.contains("\r\n.leading dot\r\n"));
        assert!(raw_text.contains("\r\n..two leading dots\r\n"));
        assert!(!raw_text.contains("\r\n..leading dot\r\n"));
        assert!(!raw_text.contains("\r\n...two leading dots\r\n"));

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("354 Start mail input; end with <CRLF>.<CRLF>\r\n"));
    }

    #[tokio::test]
    async fn test_data_message_too_large_resets_and_allows_fresh_transaction() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<oversize@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(b"Subject: Oversize\r\n\r\n");
        let oversized_line = [b'A'; 256];
        input.extend_from_slice(&oversized_line);
        input.extend_from_slice(b"\r\n");
        input.extend_from_slice(b"MAIL FROM:<fresh@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: fresh@test.com\r\nTo: rcpt@test.com\r\nSubject: Fresh After Oversize\r\nMessage-ID: <fresh-after-oversize@test.com>\r\n\r\nClean body\r\n.\r\n",
        );

        let (mut client_stream, server_stream) = tokio::io::duplex(16384);
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config_with_max_message_size(192),
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected fresh DATA flow to emit an email result after oversize reset");
        };

        assert_eq!(session.mail_from, Some("fresh@test.com".into()));
        assert_eq!(session.subject, Some("Fresh After Oversize".into()));
        assert_eq!(
            session.message_id,
            Some("<fresh-after-oversize@test.com>".into())
        );
        let raw_text = String::from_utf8(raw).expect("test raw email should be utf-8");
        assert!(raw_text.contains("Subject: Fresh After Oversize"));
        assert!(!raw_text.contains("Subject: Oversize"));

        let replies = read_available(&mut client_stream).await;
        assert!(
            replies.contains("552 5.3.4 Message too large\r\n"),
            "oversized DATA should be rejected before fresh transaction: {replies}"
        );
    }

    #[tokio::test]
    async fn test_data_session_supports_second_message_on_same_connection() {
        use tokio::io::AsyncWriteExt;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<first@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: first@test.com\r\nTo: rcpt@test.com\r\nSubject: First\r\nMessage-ID: <first@test.com>\r\n\r\nOne\r\n.\r\n",
        );
        input.extend_from_slice(b"MAIL FROM:<second@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: second@test.com\r\nTo: rcpt@test.com\r\nSubject: Second\r\nMessage-ID: <second@test.com>\r\n\r\nTwo\r\n.\r\n",
        );
        input.extend_from_slice(b"QUIT\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(16384);
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

        let first_results = conn.handle(&mut server_stream, false).await;
        let Some(HandleResult::Email(first_session, _)) = first_results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected first DATA flow to emit an email result");
        };
        assert_eq!(first_session.subject, Some("First".into()));
        assert_eq!(first_session.message_id, Some("<first@test.com>".into()));

        let first_replies = read_available(&mut client_stream).await;
        assert!(first_replies.contains("354 Start mail input; end with <CRLF>.<CRLF>\r\n"));

        let second_results = conn.handle(&mut server_stream, true).await;
        let Some(HandleResult::Email(second_session, _)) = second_results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected second DATA flow to emit an email result");
        };
        assert_eq!(second_session.subject, Some("Second".into()));
        assert_eq!(second_session.message_id, Some("<second@test.com>".into()));

        let third_results = conn.handle(&mut server_stream, true).await;
        assert!(
            third_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed)),
            "QUIT should still close the reused connection"
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let results = conn.handle(&mut server_stream, false).await;

        let result_tags: Vec<&str> = results
            .iter()
            .map(|r| match r {
                HandleResult::Email(_, _) => "Email",
                HandleResult::Closed => "Closed",
                HandleResult::Error(_) => "Error",
                HandleResult::SecurityTempfail(_) => "SecurityTempfail",
                HandleResult::StartTls => "StartTls",
            })
            .collect();
        let has_email = result_tags.contains(&"Email");
        assert!(
            has_email,
            "Should produce an Email result from BDAT session, got: {result_tags:?}"
        );
        assert!(
            !result_tags.contains(&"Closed"),
            "handle() must stop at the BDAT message boundary before consuming QUIT"
        );

        if let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|r| matches!(r, HandleResult::Email(_, _)))
        {
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
        assert!(
            quit_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed))
        );
    }

    #[tokio::test]
    async fn test_bdat_short_chunk_disconnect_resets_without_email() {
        use tokio::io::AsyncWriteExt;

        let partial_body =
            b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Short BDAT\r\n\r\npartial";
        let declared_len = partial_body.len() + 32;

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {declared_len} LAST\r\n").as_bytes());
        input.extend_from_slice(partial_body);

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
            !results
                .iter()
                .any(|result| matches!(result, HandleResult::Email(_, _))),
            "A short BDAT chunk must not synthesize a partial email"
        );
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());
        assert!(conn.data_buffer.is_empty());
        assert_eq!(conn.bdat_remaining, 0);
        assert!(!conn.bdat_is_last);

        let replies = read_available(&mut client_stream).await;
        assert!(
            !replies.contains("250 2.0.0 BDAT chunk accepted, message complete\r\n"),
            "A short BDAT chunk must not receive a final acceptance reply"
        );
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
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );
        let results = conn.handle(&mut server_stream, false).await;

        let result_tags: Vec<&str> = results
            .iter()
            .map(|r| match r {
                HandleResult::Email(_, _) => "Email",
                HandleResult::Closed => "Closed",
                HandleResult::Error(_) => "Error",
                HandleResult::SecurityTempfail(_) => "SecurityTempfail",
                HandleResult::StartTls => "StartTls",
            })
            .collect();
        let has_email = result_tags.contains(&"Email");
        assert!(
            has_email,
            "Should produce an Email result from multi-chunk BDAT, got: {result_tags:?}"
        );
        assert!(
            !result_tags.contains(&"Closed"),
            "handle() must stop once the multi-chunk message is assembled"
        );

        if let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|r| matches!(r, HandleResult::Email(_, _)))
        {
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
        assert!(
            quit_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed))
        );
    }

    #[tokio::test]
    async fn test_bdat_zero_last_final_chunk_completes_message_and_resets_transaction() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let chunk1 =
            b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Zero Last\r\nMessage-ID: <bdat-zero@test.com>\r\n\r\nBody here";
        let chunk1_len = chunk1.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {chunk1_len}\r\n").as_bytes());
        input.extend_from_slice(chunk1);
        input.extend_from_slice(b"BDAT 0 LAST\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(8192);
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected BDAT 0 LAST flow to emit an email result");
        };

        assert_eq!(session.subject, Some("Zero Last".into()));
        assert_eq!(session.message_id, Some("<bdat-zero@test.com>".into()));
        assert_eq!(raw, chunk1);
        assert_eq!(conn.state, SmtpState::Ready);
        assert_eq!(conn.bdat_remaining, 0);
        assert!(!conn.bdat_is_last);
        assert!(conn.data_buffer.is_empty());
        assert!(conn.data_phase_started.is_none());

        let replies = read_available(&mut client_stream).await;
        assert!(
            replies.contains("250 2.0.0 BDAT chunk accepted\r\n"),
            "Non-final BDAT chunk should be acknowledged before the empty LAST chunk"
        );
        assert!(
            !replies.contains("250 2.0.0 BDAT chunk accepted, message complete\r\n"),
            "Final delivery acknowledgement must still be deferred to the verdict path"
        );
    }

    #[tokio::test]
    async fn test_bdat_message_can_be_followed_by_data_message_on_same_connection() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let chunk =
            b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: BDAT First\r\nMessage-ID: <first-bdat@test.com>\r\n\r\nBody one";
        let chunk_len = chunk.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {chunk_len} LAST\r\n").as_bytes());
        input.extend_from_slice(chunk);
        input.extend_from_slice(b"MAIL FROM:<sender2@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: sender2@test.com\r\nTo: rcpt@test.com\r\nSubject: DATA Second\r\nMessage-ID: <second-data@test.com>\r\n\r\nBody two\r\n.\r\n",
        );
        input.extend_from_slice(b"QUIT\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(16384);
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );

        let first_results = conn.handle(&mut server_stream, false).await;
        let Some(HandleResult::Email(first_session, _)) = first_results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected BDAT flow to emit an email result");
        };
        assert_eq!(first_session.subject, Some("BDAT First".into()));
        assert_eq!(
            first_session.message_id,
            Some("<first-bdat@test.com>".into())
        );
        let first_replies = read_available(&mut client_stream).await;
        assert!(
            !first_replies.contains("250 2.0.0 BDAT chunk accepted, message complete\r\n"),
            "BDAT final delivery acknowledgement must still be deferred to the verdict path"
        );

        let second_results = conn.handle(&mut server_stream, true).await;
        let Some(HandleResult::Email(second_session, _)) = second_results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected follow-up DATA flow to emit an email result");
        };
        assert_eq!(second_session.subject, Some("DATA Second".into()));
        assert_eq!(
            second_session.message_id,
            Some("<second-data@test.com>".into())
        );

        let second_replies = read_available(&mut client_stream).await;
        assert!(
            second_replies.contains("354 Start mail input; end with <CRLF>.<CRLF>\r\n"),
            "Follow-up DATA transaction should still emit a DATA challenge"
        );

        let third_results = conn.handle(&mut server_stream, true).await;
        assert!(
            third_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed)),
            "QUIT should close the connection after BDAT -> DATA reuse"
        );
    }

    #[tokio::test]
    async fn test_bdat_partial_transaction_can_be_cleared_with_rset() {
        use tokio::io::AsyncWriteExt;

        let config = test_config();
        let partial_chunk =
            b"From: partial@test.com\r\nTo: rcpt@test.com\r\nSubject: Partial\r\n\r\nDiscard me";
        let partial_len = partial_chunk.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<partial@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {partial_len}\r\n").as_bytes());
        input.extend_from_slice(partial_chunk);
        input.extend_from_slice(b"RSET\r\n");
        input.extend_from_slice(b"MAIL FROM:<fresh@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(b"DATA\r\n");
        input.extend_from_slice(
            b"From: fresh@test.com\r\nTo: rcpt@test.com\r\nSubject: Fresh\r\nMessage-ID: <fresh@test.com>\r\n\r\nClean body\r\n.\r\n",
        );
        input.extend_from_slice(b"QUIT\r\n");

        let (mut client_stream, server_stream) = tokio::io::duplex(16384);
        client_stream.write_all(&input).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut server_stream = tokio::io::BufStream::new(server_stream);
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            config,
            false,
        );

        let results = conn.handle(&mut server_stream, false).await;
        let Some(HandleResult::Email(session, raw)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("Expected post-RSET DATA flow to emit an email result");
        };

        assert_eq!(session.subject, Some("Fresh".into()));
        assert_eq!(session.message_id, Some("<fresh@test.com>".into()));
        let raw_text = String::from_utf8(raw).expect("raw email should be utf-8 in test");
        assert!(raw_text.contains("Subject: Fresh"));
        assert!(!raw_text.contains("Subject: Partial"));

        let replies = read_available(&mut client_stream).await;
        assert!(replies.contains("250 2.0.0 BDAT chunk accepted\r\n"));
        assert!(
            replies.contains("250 2.1.5 OK\r\n"),
            "RSET should return 250"
        );

        let quit_results = conn.handle(&mut server_stream, true).await;
        assert!(
            quit_results
                .iter()
                .any(|result| matches!(result, HandleResult::Closed)),
            "QUIT should close the connection after RSET recovery"
        );
    }

    // ── F-1: BDAT chunk CRLF enforcement (SMTP smuggling guard) ─────────

    #[test]
    fn test_bdat_chunk_crlf_validation_rejects_smuggle_sequence() {
        // PoC (F-1): a BDAT chunk carrying `\n.\nMAIL FROM:...` previously
        // passed through to the downstream MTA verbatim, where a lenient
        // parser treats `\n.\n` as end-of-DATA — a second, uninspected
        // message is smuggled past inline verdict (CWE-444).
        let attack =
            b"From: sender@test.com\r\n\r\nbody\n.\nMAIL FROM:<evil@attacker.example>\r\n";
        let mut pending = false;
        assert!(
            !bdat_chunk_has_only_crlf(attack, &mut pending),
            "bare-LF smuggling sequence must be rejected"
        );
    }

    #[test]
    fn test_bdat_chunk_crlf_validation_rejects_bare_cr() {
        let mut pending = false;
        assert!(!bdat_chunk_has_only_crlf(b"line1\rX", &mut pending));

        // A CR at the very end of a chunk is provisionally pending; for a
        // LAST chunk the caller rejects it.
        let mut pending = false;
        assert!(bdat_chunk_has_only_crlf(b"line1\r", &mut pending));
        assert!(pending, "trailing CR must be flagged as pending");
    }

    #[test]
    fn test_bdat_chunk_crlf_validation_accepts_crlf_split_across_chunks() {
        let mut pending = false;
        assert!(bdat_chunk_has_only_crlf(b"Subject: hi\r", &mut pending));
        assert!(pending);
        assert!(bdat_chunk_has_only_crlf(b"\n\r\nbody\r\n", &mut pending));
        assert!(!pending, "resolved split CRLF must not stay pending");
    }

    #[test]
    fn test_bdat_chunk_crlf_validation_accepts_normal_message() {
        let mut pending = false;
        let msg = b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Hi\r\n\r\nBody\r\n";
        assert!(bdat_chunk_has_only_crlf(msg, &mut pending));
        assert!(!pending);
    }

    #[tokio::test]
    async fn test_bdat_chunk_with_bare_lf_smuggle_is_rejected() {
        use tokio::io::AsyncWriteExt;

        // PoC (F-1): end-to-end — the smuggling BDAT chunk must be rejected
        // with 554 and must not produce an email transaction.
        let chunk = b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: x\r\n\r\nbody\n.\nMAIL FROM:<evil@attacker.example>\r\n";
        let chunk_len = chunk.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {chunk_len} LAST\r\n").as_bytes());
        input.extend_from_slice(chunk);

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
            !results
                .iter()
                .any(|result| matches!(result, HandleResult::Email(_, _))),
            "smuggling BDAT chunk must not produce an email transaction"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(
            replies.contains("554 5.6.0 BDAT chunk must use CRLF line endings\r\n"),
            "bare-LF BDAT chunk must be rejected: {replies}"
        );
    }

    #[tokio::test]
    async fn test_bdat_last_chunk_ending_with_bare_cr_is_rejected() {
        use tokio::io::AsyncWriteExt;

        // PoC (F-1): a LAST chunk whose final byte is a bare CR would relay
        // a CR without its LF downstream — reject it.
        let chunk = b"Subject: dangling\r";
        let chunk_len = chunk.len();

        let mut input = Vec::new();
        input.extend_from_slice(b"EHLO client.test\r\n");
        input.extend_from_slice(b"MAIL FROM:<sender@test.com>\r\n");
        input.extend_from_slice(b"RCPT TO:<rcpt@test.com>\r\n");
        input.extend_from_slice(format!("BDAT {chunk_len} LAST\r\n").as_bytes());
        input.extend_from_slice(chunk);

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
            !results
                .iter()
                .any(|result| matches!(result, HandleResult::Email(_, _))),
            "LAST chunk ending in bare CR must not produce an email transaction"
        );

        let replies = read_available(&mut client_stream).await;
        assert!(
            replies.contains("554 5.6.0 BDAT chunk must use CRLF line endings\r\n"),
            "dangling-CR LAST chunk must be rejected: {replies}"
        );
    }

    #[tokio::test]
    async fn test_bdat_crlf_split_across_chunks_is_accepted() {
        use tokio::io::AsyncWriteExt;

        // Regression protection: a CRLF split across the BDAT chunk boundary
        // is legal RFC 3030 traffic and must not be rejected.
        let chunk1 = b"From: sender@test.com\r\nTo: rcpt@test.com\r\nSubject: Split CRLF\r";
        let chunk2 = b"\n\r\nBody after split\r\n";
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
        let Some(HandleResult::Email(session, _)) = results
            .into_iter()
            .find(|result| matches!(result, HandleResult::Email(_, _)))
        else {
            panic!("split-CRLF BDAT message must be accepted");
        };
        assert_eq!(session.subject, Some("Split CRLF".into()));
    }

    // ── F-2: BDAT cumulative time budget ─────────────────────────────────

    #[test]
    fn test_transaction_budget_reply_reflects_cumulative_budgets() {
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        assert!(conn.transaction_budget_reply().is_none());

        conn.data_phase_started =
            Some(Instant::now() - Duration::from_secs(MAX_DATA_TRANSACTION_SECS + 1));
        assert_eq!(
            conn.transaction_budget_reply(),
            Some(b"451 4.4.2 DATA transaction timeout\r\n".as_slice()),
            "expired DATA/BDAT transaction budget must yield the 451 reply"
        );

        let mut session_expired = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        session_expired.session_started =
            Instant::now() - Duration::from_secs(MAX_SESSION_SECS + 1);
        assert_eq!(
            session_expired.transaction_budget_reply(),
            Some(b"421 4.4.2 Session lifetime exceeded\r\n".as_slice()),
            "expired session lifetime must yield the 421 reply"
        );
    }

    // ── F-4: MTA_REQUIRE_STARTTLS ─────────────────────────────────────────

    fn test_config_with_require_starttls() -> Arc<MtaConfig> {
        Arc::new(MtaConfig {
            require_starttls: true,
            ..(*test_config_with_tls()).clone()
        })
    }

    #[test]
    fn test_require_starttls_rejects_plaintext_mail_from() {
        // PoC (F-4): with MTA_REQUIRE_STARTTLS=true a plaintext session must
        // not be able to start a mail transaction.
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config_with_require_starttls(),
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(
            r.contains("530"),
            "plaintext MAIL FROM must be refused when STARTTLS is required: {r}"
        );
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
    }

    #[test]
    fn test_require_starttls_allows_tls_session_mail_from() {
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config_with_require_starttls(),
            true, // tls_active
        );
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(
            r.contains("250"),
            "TLS session must be allowed to send MAIL FROM: {r}"
        );
        assert_eq!(conn.state, SmtpState::MailFrom);
    }

    #[test]
    fn test_require_starttls_explicitly_disabled_allows_plaintext() {
        // Compatibility coverage: plaintext is allowed only when the test
        // fixture explicitly sets require_starttls=false. Production config
        // defaults to true and must be opted out of explicitly.
        let mut conn = SmtpConnection::new(
            "127.0.0.1".into(),
            9999,
            "0.0.0.0".into(),
            25,
            test_config(),
            false,
        );
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(r.contains("250"), "explicit opt-out must allow plaintext: {r}");
    }
}
