//! SMTP TCP/TLS

//! SMTP,accept, connection handler.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::config::MtaConfig;
use crate::config::is_trusted_upstream_ip;
use crate::authentication::AuthenticationVerifier;
use crate::dlp::{DlpAction, detect_direction, format_dlp_reason, run_dlp_scan};
use crate::metrics::VerdictMetrics;
use crate::relay::downstream::{DownstreamRelay, RelayResult};
use crate::relay::quarantine::store_quarantine;
use crate::server::connection::{HandleResult, SmtpConnection};

use vigilyx_core::models::MailDirection;
use vigilyx_core::security::VerdictDisposition;
use vigilyx_db::VigilDb;
use vigilyx_engine::pipeline::engine::SecurityEngine;

enum ConnectionOutcome {
    Closed,
    StartTls,
}

struct SmtpRuntime<'a> {
    config: &'a MtaConfig,
    authentication: &'a AuthenticationVerifier,
    engine: &'a SecurityEngine,
    relay: &'a DownstreamRelay,
    outbound_relay: &'a DownstreamRelay,
    db: &'a VigilDb,
    metrics: &'a VerdictMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryPlan {
    Relay {
        relay_direction: MailDirection,
        enforce_outbound_dlp: bool,
    },
    TempfailReply,
    Quarantine,
    Reject,
}

const SECURITY_INSPECTION_TEMPFAIL_REPLY: &[u8] =
    b"451 4.7.1 Message could not be parsed for security inspection\r\n";

fn delivery_plan(
    disposition: &VerdictDisposition,
    direction: MailDirection,
    fail_open: bool,
    outbound_dlp_enabled: bool,
) -> DeliveryPlan {
    match disposition {
        VerdictDisposition::Accept => DeliveryPlan::Relay {
            relay_direction: direction,
            enforce_outbound_dlp: direction == MailDirection::Outbound && outbound_dlp_enabled,
        },
        VerdictDisposition::Tempfail if fail_open => DeliveryPlan::Relay {
            relay_direction: direction,
            enforce_outbound_dlp: direction == MailDirection::Outbound && outbound_dlp_enabled,
        },
        VerdictDisposition::Tempfail => DeliveryPlan::TempfailReply,
        VerdictDisposition::Quarantine => DeliveryPlan::Quarantine,
        VerdictDisposition::Reject { .. } => DeliveryPlan::Reject,
    }
}

fn session_trusted_submitter(
    session: &vigilyx_core::models::EmailSession,
    trusted_upstream_cidrs: &[String],
) -> bool {
    let auth_ok = session
        .auth_info
        .as_ref()
        .and_then(|auth| auth.auth_success)
        .unwrap_or(false);

    auth_ok || is_trusted_upstream_ip(&session.client_ip, trusted_upstream_cidrs)
}

async fn write_reply<S>(stream: &mut S, data: &[u8])
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let _ = stream.write_all(data).await;
    let _ = stream.flush().await;
}

fn relay_for_direction<'a>(
    runtime: &'a SmtpRuntime<'a>,
    direction: MailDirection,
) -> &'a DownstreamRelay {
    if direction == MailDirection::Outbound {
        runtime.outbound_relay
    } else {
        runtime.relay
    }
}

/// SEC-13: downstream error text is server-controlled and may contain CRLF
/// (SMTP reply injection). Strip CR/LF and cap the length before echoing it
/// in an SMTP reply.
fn sanitize_downstream_reply_text(msg: &str) -> String {
    msg.chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .take(200)
        .collect()
}

/// Relay the message downstream and write the SMTP reply.
/// Returns `true` when the downstream accepted the message (250 path).
async fn relay_and_reply<S, I>(
    stream: &mut S,
    relay: &DownstreamRelay,
    mail_from: Option<&str>,
    rcpt_to: &[String],
    raw_eml: &[u8],
    client_ip: Option<&str>,
    session_id: I,
) -> bool
where
    S: tokio::io::AsyncWrite + Unpin,
    I: Copy + std::fmt::Display,
{
    match relay.relay_from(mail_from, rcpt_to, raw_eml, client_ip).await {
        RelayResult::Accepted => {
            write_reply(stream, b"250 2.0.0 OK\r\n").await;
            true
        }
        RelayResult::TempFail(msg) => {
            let msg = sanitize_downstream_reply_text(&msg);
            let reply = format!("451 4.7.1 Downstream temporary failure: {msg}\r\n");
            write_reply(stream, reply.as_bytes()).await;
            false
        }
        RelayResult::PermFail(msg) => {
            let msg = sanitize_downstream_reply_text(&msg);
            let reply = format!("550 5.7.1 Downstream rejected: {msg}\r\n");
            write_reply(stream, reply.as_bytes()).await;
            false
        }
        RelayResult::ConnError(msg) => {
            warn!(session_id = %session_id, "Downstream unreachable: {msg}");
            write_reply(stream, b"421 4.7.0 Downstream unavailable, try later\r\n").await;
            false
        }
    }
}

async fn enforce_outbound_dlp<S>(
    stream: &mut S,
    runtime: &SmtpRuntime<'_>,
    session: &vigilyx_core::models::EmailSession,
    raw_eml: &[u8],
) -> bool
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if !runtime.config.dlp.enabled {
        return false;
    }

    let dlp_result = run_dlp_scan(session);
    let has_policy_match =
        !dlp_result.is_empty() && dlp_result.count_items_at_level(runtime.config.dlp.min_level) > 0;
    if !has_policy_match && dlp_result.complete {
        return false;
    }

    let reason = if dlp_result.complete {
        format_dlp_reason(&dlp_result)
    } else if has_policy_match {
        format!(
            "{}; attachment inspection incomplete",
            format_dlp_reason(&dlp_result)
        )
    } else {
        "DLP: attachment inspection incomplete — safe release prohibited".to_string()
    };
    info!(
        session_id = %session.id,
        matches = ?dlp_result.matches,
        inspection_complete = dlp_result.complete,
        attachments_scanned = dlp_result.attachments_scanned,
        "DLP hit on outbound email: {reason}"
    );

    match runtime.config.dlp.action {
        DlpAction::Block => {
            write_reply(
                stream,
                b"550 5.7.1 Message blocked: sensitive data detected\r\n",
            )
            .await;
            true
        }
        DlpAction::Quarantine => {
            let stored = store_quarantine(
                runtime.db,
                &session.id,
                session.mail_from.as_deref(),
                &session.rcpt_to,
                session.subject.as_deref(),
                raw_eml,
                "high",
                &reason,
                Some(session.client_ip.as_str()),
            )
            .await;
            if stored {
                write_reply(stream, b"250 2.0.0 OK\r\n").await;
            } else {
                warn!(session_id = %session.id, "DLP quarantine storage failed");
                write_reply(stream, b"451 4.7.1 Quarantine storage unavailable\r\n").await;
            }
            true
        }
        DlpAction::AllowAndAlert => {
            warn!(
                session_id = %session.id,
                "DLP alert (allow_and_alert): {reason}"
            );
            false
        }
    }
}

/// SEC: Maximum concurrent connections from a single IP address (CWE-400).
/// Prevents a single source from exhausting all connection slots.
const MAX_CONN_PER_IP: usize = 10;

/// SEC: TLS handshake hard deadline (F-3, CWE-400). An idle pre-handshake
/// client otherwise holds a connection slot (and its per-IP slot) forever.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// Accept a TLS handshake with a hard deadline. Returns `None` on handshake
/// failure or timeout; the caller drops the connection either way.
async fn accept_tls_with_timeout<S>(
    acceptor: &TlsAcceptor,
    stream: S,
    client_ip: &str,
) -> Option<tokio_rustls::server::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match tokio::time::timeout(
        std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
        acceptor.accept(stream),
    )
    .await
    {
        Ok(Ok(tls_stream)) => Some(tls_stream),
        Ok(Err(e)) => {
            warn!(client_ip = %client_ip, "TLS handshake failed: {e}");
            None
        }
        Err(_) => {
            warn!(
                client_ip = %client_ip,
                timeout_secs = TLS_HANDSHAKE_TIMEOUT_SECS,
                "TLS handshake timed out"
            );
            None
        }
    }
}

/// Per-IP concurrent connection limiter.
///
/// Shared between SMTP and SMTPS listeners to enforce a per-source-IP
/// cap on concurrent connections, preventing low-cost connection-slot DoS.
pub struct PerIpLimiter {
    counts: Mutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
}

impl PerIpLimiter {
    pub fn new(max_per_ip: usize) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            max_per_ip,
        }
    }

    /// Try to acquire a connection slot for the given IP.
    /// Returns `true` if within limit, `false` if the IP has reached its cap.
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        // SAFETY: critical section only performs integer arithmetic on HashMap, cannot panic
        let mut counts = self.counts.lock().expect("PerIpLimiter mutex poisoned");
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return false;
        }
        *count += 1;
        true
    }

    /// Release a connection slot for the given IP.
    pub fn release(&self, ip: IpAddr) {
        // SAFETY: critical section only performs integer arithmetic on HashMap, cannot panic
        let mut counts = self.counts.lock().expect("PerIpLimiter mutex poisoned");
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
}

fn try_acquire_global_connection_slot(
    active_connections: &AtomicUsize,
    max_connections: usize,
) -> Option<usize> {
    let previous = active_connections.fetch_add(1, Ordering::Relaxed);
    if previous >= max_connections {
        active_connections.fetch_sub(1, Ordering::Relaxed);
        None
    } else {
        Some(previous + 1)
    }
}

fn release_global_connection_slot(active_connections: &AtomicUsize) {
    active_connections.fetch_sub(1, Ordering::Relaxed);
}

/// SMTP (+ STARTTLS)
#[allow(clippy::too_many_arguments)]
pub async fn run_smtp_listener(
    config: Arc<MtaConfig>,
    engine: Arc<SecurityEngine>,
    relay: Arc<DownstreamRelay>,
    outbound_relay: Arc<DownstreamRelay>,
    db: Arc<VigilDb>,
    active_connections: Arc<AtomicUsize>,
    per_ip_limiter: Arc<PerIpLimiter>,
    tls_acceptor: Option<TlsAcceptor>,
    metrics: Arc<VerdictMetrics>,
    authentication: Arc<AuthenticationVerifier>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen_smtp).await?;
    info!(addr = %config.listen_smtp, "SMTP listener started");

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept error: {e}");
                continue;
            }
        };

        if try_acquire_global_connection_slot(&active_connections, config.max_connections).is_none()
        {
            let current = active_connections.load(Ordering::Relaxed);
            warn!(addr = %addr, current, "Max connections reached, rejecting");
            drop(stream);
            continue;
        }

        // SEC: per-IP connection limit (CWE-400)
        let client_ip_addr = addr.ip();
        if !per_ip_limiter.try_acquire(client_ip_addr) {
            release_global_connection_slot(&active_connections);
            warn!(addr = %addr, limit = MAX_CONN_PER_IP, "Per-IP connection limit reached, rejecting");
            drop(stream);
            continue;
        }

        let cfg = Arc::clone(&config);
        let eng = Arc::clone(&engine);
        let rl = Arc::clone(&relay);
        let orl = Arc::clone(&outbound_relay);
        let d = Arc::clone(&db);
        let tls = tls_acceptor.clone();
        let conn_counter = Arc::clone(&active_connections);
        let ip_limiter = Arc::clone(&per_ip_limiter);
        let met = Arc::clone(&metrics);
        let auth = Arc::clone(&authentication);

        tokio::spawn(async move {
            let client_ip = addr.ip().to_string();
            let client_port = addr.port();
            info!(client_ip = %client_ip, "New SMTP connection");

            let result = handle_smtp_connection(
                stream,
                client_ip,
                client_port,
                cfg,
                eng,
                rl,
                orl,
                d,
                tls,
                met,
                auth,
            )
            .await;

            if let Err(e) = result {
                error!(error = %e, "SMTP connection error");
            }

            release_global_connection_slot(&conn_counter);
            ip_limiter.release(client_ip_addr);
        });
    }
}

/// SMTPS (TLS, 465)
#[allow(clippy::too_many_arguments)]
pub async fn run_smtps_listener(
    config: Arc<MtaConfig>,
    engine: Arc<SecurityEngine>,
    relay: Arc<DownstreamRelay>,
    outbound_relay: Arc<DownstreamRelay>,
    db: Arc<VigilDb>,
    active_connections: Arc<AtomicUsize>,
    per_ip_limiter: Arc<PerIpLimiter>,
    tls_acceptor: TlsAcceptor,
    metrics: Arc<VerdictMetrics>,
    authentication: Arc<AuthenticationVerifier>,
) -> anyhow::Result<()> {
    let addr = config
        .listen_smtps
        .ok_or_else(|| anyhow::anyhow!("SMTPS listen address not configured"))?;
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "SMTPS (implicit TLS) listener started");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept error: {e}");
                continue;
            }
        };

        if try_acquire_global_connection_slot(&active_connections, config.max_connections).is_none()
        {
            warn!(addr = %peer_addr, "Max connections reached");
            drop(stream);
            continue;
        }

        // SEC: per-IP connection limit (CWE-400)
        let client_ip_addr = peer_addr.ip();
        if !per_ip_limiter.try_acquire(client_ip_addr) {
            release_global_connection_slot(&active_connections);
            warn!(addr = %peer_addr, limit = MAX_CONN_PER_IP, "Per-IP connection limit reached, rejecting");
            drop(stream);
            continue;
        }

        let cfg = Arc::clone(&config);
        let eng = Arc::clone(&engine);
        let rl = Arc::clone(&relay);
        let orl = Arc::clone(&outbound_relay);
        let d = Arc::clone(&db);
        let acceptor = tls_acceptor.clone();
        let conn_counter = Arc::clone(&active_connections);
        let ip_limiter = Arc::clone(&per_ip_limiter);
        let met = Arc::clone(&metrics);
        let auth = Arc::clone(&authentication);

        tokio::spawn(async move {
            let client_ip = peer_addr.ip().to_string();
            let client_port = peer_addr.port();

            // TLS:
            let server_ip = stream
                .local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "0.0.0.0".into());
            let server_port = stream.local_addr().map(|a| a.port()).unwrap_or(465);
            if let Some(tls_stream) = accept_tls_with_timeout(&acceptor, stream, &client_ip).await {
                let mut tls_stream = tokio::io::BufStream::new(tls_stream);
                let runtime = SmtpRuntime {
                    config: cfg.as_ref(),
                    authentication: auth.as_ref(),
                    engine: eng.as_ref(),
                    relay: rl.as_ref(),
                    outbound_relay: orl.as_ref(),
                    db: d.as_ref(),
                    metrics: met.as_ref(),
                };
                let mut conn = SmtpConnection::new(
                    client_ip,
                    client_port,
                    server_ip,
                    server_port,
                    cfg.clone(),
                    true,
                );
                let _ = drive_connection(&mut tls_stream, &mut conn, false, &runtime).await;
            }

            release_global_connection_slot(&conn_counter);
            ip_limiter.release(client_ip_addr);
        });
    }
}

/// SMTP (STARTTLS)
#[allow(clippy::too_many_arguments)]
async fn handle_smtp_connection(
    stream: tokio::net::TcpStream,
    client_ip: String,
    client_port: u16,
    config: Arc<MtaConfig>,
    engine: Arc<SecurityEngine>,
    relay: Arc<DownstreamRelay>,
    outbound_relay: Arc<DownstreamRelay>,
    db: Arc<VigilDb>,
    tls_acceptor: Option<TlsAcceptor>,
    metrics: Arc<VerdictMetrics>,
    authentication: Arc<AuthenticationVerifier>,
) -> anyhow::Result<()> {
    let mut stream = tokio::io::BufStream::new(stream);
    let server_ip = stream
        .get_ref()
        .local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".into());
    let server_port = stream
        .get_ref()
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(25);
    let runtime = SmtpRuntime {
        config: config.as_ref(),
        authentication: authentication.as_ref(),
        engine: engine.as_ref(),
        relay: relay.as_ref(),
        outbound_relay: outbound_relay.as_ref(),
        db: db.as_ref(),
        metrics: metrics.as_ref(),
    };

    let mut conn = SmtpConnection::new(
        client_ip.clone(),
        client_port,
        server_ip.clone(),
        server_port,
        config.clone(),
        false,
    );

    match drive_connection(&mut stream, &mut conn, false, &runtime).await {
        ConnectionOutcome::Closed => {}
        ConnectionOutcome::StartTls => {
            if let Some(acceptor) = tls_acceptor {
                let inner = stream.into_inner();
                if let Some(tls_stream) = accept_tls_with_timeout(&acceptor, inner, &client_ip).await
                {
                    let mut tls_stream = tokio::io::BufStream::new(tls_stream);
                    // After TLS upgrade: skip banner (client already saw 220 before STARTTLS)
                    let mut tls_conn = SmtpConnection::new(
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                        config.clone(),
                        true,
                    );
                    let _ =
                        drive_connection(&mut tls_stream, &mut tls_conn, true, &runtime).await;
                }
            } else {
                warn!(client_ip = %client_ip, "STARTTLS requested but no TLS acceptor is configured");
            }
        }
    }

    Ok(())
}

async fn drive_connection<S>(
    stream: &mut tokio::io::BufStream<S>,
    conn: &mut SmtpConnection,
    skip_banner: bool,
    runtime: &SmtpRuntime<'_>,
) -> ConnectionOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut skip_banner = skip_banner;
    loop {
        let results = conn.handle(stream, skip_banner).await;
        skip_banner = true;

        if results.is_empty() {
            return ConnectionOutcome::Closed;
        }

        let needs_starttls = results
            .iter()
            .any(|result| matches!(result, HandleResult::StartTls));
        let should_close = results
            .iter()
            .any(|result| matches!(result, HandleResult::Closed | HandleResult::Error(_)));

        process_results(results, stream, runtime).await;

        if needs_starttls {
            return ConnectionOutcome::StartTls;
        }

        if should_close {
            return ConnectionOutcome::Closed;
        }
    }
}

/// : inline SMTP
async fn process_results<S>(results: Vec<HandleResult>, stream: &mut S, runtime: &SmtpRuntime<'_>)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    for result in results {
        match result {
            HandleResult::Email(session, raw_eml) => {
                let mut session = *session; // unbox
                // Establish the identity boundary before any engine module or
                // relay sees the message. Incoming Authentication-Results,
                // ARC variants, and their folded continuations are removed;
                // the engine receives only this MTA-owned result.
                let raw_eml = runtime
                    .authentication
                    .stamp(&mut session, raw_eml, &runtime.config.hostname)
                    .await;
                let session_id = session.id;
                let mail_from = session.mail_from.clone();
                let rcpt_to = session.rcpt_to.clone();
                let subject = session.subject.clone();
                let client_ip = session.client_ip.clone();

                // Trusted submitter = authenticated submission (future AUTH path)
                // or an explicitly trusted upstream relay IP/CIDR.
                let trusted_submitter =
                    session_trusted_submitter(&session, &runtime.config.trusted_upstream_cidrs);
                let direction = detect_direction(
                    mail_from.as_deref(),
                    &rcpt_to,
                    &runtime.config.local_domains,
                    trusted_submitter,
                );

                // SEC: only log domain part to avoid leaking full addresses (CWE-532)
                let from_domain = mail_from
                    .as_deref()
                    .and_then(|a| a.rsplit('@').next())
                    .unwrap_or("<>");
                info!(
                    session_id = %session_id,
                    from_domain = %from_domain,
                    rcpt_count = rcpt_to.len(),
                    size = raw_eml.len(),
                    direction = %direction,
                    "Email received"
                );

                let outbound_dlp_session = (direction == MailDirection::Outbound
                    && runtime.config.dlp.enabled)
                    .then(|| session.clone());

                let timeout =
                    std::time::Duration::from_secs(runtime.config.inline_timeout_secs as u64);
                let response = runtime
                    .engine
                    .submit_inline(
                        session,
                        timeout,
                        runtime.config.quarantine_threshold,
                        runtime.config.reject_threshold,
                    )
                    .await;

                info!(
                    session_id = %session_id,
                    disposition = %response.disposition,
                    threat_level = %response.threat_level,
                    duration_ms = response.duration_ms,
                    "Inline verdict: {}", response.summary
                );

                match delivery_plan(
                    &response.disposition,
                    direction,
                    runtime.config.fail_open,
                    runtime.config.dlp.enabled,
                ) {
                    DeliveryPlan::Relay {
                        relay_direction,
                        enforce_outbound_dlp: should_enforce_outbound_dlp,
                    } => {
                        let fail_open_relay =
                            matches!(response.disposition, VerdictDisposition::Tempfail);
                        if fail_open_relay {
                            warn!(
                                session_id = %session_id,
                                "Inline verdict unavailable and MTA_FAIL_OPEN=true, relaying downstream"
                            );
                        }

                        if should_enforce_outbound_dlp
                            && let Some(ref dlp_session) = outbound_dlp_session
                            && enforce_outbound_dlp(stream, runtime, dlp_session, &raw_eml).await
                        {
                            continue;
                        }

                        let relayed = relay_and_reply(
                            stream,
                            relay_for_direction(runtime, relay_direction),
                            mail_from.as_deref(),
                            &rcpt_to,
                            &raw_eml,
                            Some(client_ip.as_str()),
                            session_id,
                        )
                        .await;
                        if fail_open_relay {
                            runtime.metrics.inc_timeout_failopen();
                        } else if relayed {
                            runtime.metrics.inc_accepted();
                        }
                    }
                    DeliveryPlan::TempfailReply => {
                        warn!(
                            session_id = %session_id,
                            "Inline verdict unavailable and MTA_FAIL_OPEN=false, deferring delivery"
                        );
                        write_reply(stream, b"451 4.7.1 Security engine temporary failure\r\n")
                            .await;
                        continue;
                    }
                    DeliveryPlan::Quarantine => {
                        // Quarantine -> 250,
                        let stored = store_quarantine(
                            runtime.db,
                            &session_id,
                            mail_from.as_deref(),
                            &rcpt_to,
                            subject.as_deref(),
                            &raw_eml,
                            &response.threat_level.to_string(),
                            &response.summary,
                            Some(client_ip.as_str()),
                        )
                        .await;
                        if stored {
                            runtime.metrics.inc_quarantined();
                            write_reply(stream, b"250 2.0.0 OK\r\n").await;
                        } else {
                            warn!(
                                session_id = %session_id,
                                "Quarantine storage failed, returning temporary failure to avoid silent loss"
                            );
                            write_reply(stream, b"451 4.7.1 Quarantine storage unavailable\r\n")
                                .await;
                        }
                    }
                    DeliveryPlan::Reject => {
                        // Reject -> 550
                        let reason = match &response.disposition {
                            VerdictDisposition::Reject { reason } => reason,
                            _ => unreachable!("delivery plan guaranteed reject disposition"),
                        };
                        runtime.metrics.inc_rejected();
                        let reply = format!("550 5.7.1 {reason}\r\n");
                        write_reply(stream, reply.as_bytes()).await;
                    }
                }
            }
            HandleResult::Closed => {}
            HandleResult::SecurityTempfail(reason) => {
                warn!("SMTP message could not be safely inspected: {reason}");
                write_reply(stream, SECURITY_INSPECTION_TEMPFAIL_REPLY).await;
            }
            HandleResult::Error(error) => {
                warn!("SMTP connection handler reported error: {error}");
            }
            HandleResult::StartTls => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_inspection_failure_is_a_retryable_smtp_reply() {
        let reply = std::str::from_utf8(SECURITY_INSPECTION_TEMPFAIL_REPLY).unwrap();

        assert!(reply.starts_with("451 4.7.1 "));
        assert!(reply.ends_with("\r\n"));
        assert!(
            !reply.starts_with("250"),
            "unsafe mail must not be accepted"
        );
        assert!(
            !reply.starts_with("550"),
            "parse failures should remain retryable"
        );
    }

    #[test]
    fn test_sanitize_downstream_reply_text_strips_crlf() {
        let malicious = "mailbox full\r\n250 2.0.0 OK injected\nnext line";
        let sanitized = sanitize_downstream_reply_text(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized, "mailbox full250 2.0.0 OK injectednext line");
    }

    #[test]
    fn test_sanitize_downstream_reply_text_caps_length() {
        let long = "x".repeat(500);
        let sanitized = sanitize_downstream_reply_text(&long);
        assert_eq!(sanitized.len(), 200);
    }

    #[test]
    fn test_sanitize_downstream_reply_text_keeps_normal_text() {
        let normal = "5.7.1 Mailbox unavailable";
        assert_eq!(sanitize_downstream_reply_text(normal), normal);
    }

    #[test]
    fn test_per_ip_limiter_allows_within_limit() {
        let limiter = PerIpLimiter::new(3);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
    }

    #[test]
    fn test_per_ip_limiter_blocks_at_limit() {
        let limiter = PerIpLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
        assert!(
            !limiter.try_acquire(ip),
            "Should reject 3rd connection when limit=2"
        );
    }

    #[test]
    fn test_per_ip_limiter_release_allows_new_connection() {
        let limiter = PerIpLimiter::new(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.try_acquire(ip));
        assert!(!limiter.try_acquire(ip));
        limiter.release(ip);
        assert!(limiter.try_acquire(ip), "Should allow after release");
    }

    #[test]
    fn test_per_ip_limiter_independent_ips() {
        let limiter = PerIpLimiter::new(1);
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.try_acquire(ip_a));
        assert!(
            limiter.try_acquire(ip_b),
            "Different IPs should have independent limits"
        );
        assert!(
            !limiter.try_acquire(ip_a),
            "Same IP should still be blocked"
        );
    }

    #[test]
    fn test_per_ip_limiter_release_cleans_up_zero_entries() {
        let limiter = PerIpLimiter::new(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.try_acquire(ip);
        limiter.release(ip);
        // SAFETY: same rationale as try_acquire/release — only integer ops
        let counts = limiter.counts.lock().expect("mutex poisoned");
        assert!(
            !counts.contains_key(&ip),
            "Zero-count entries should be cleaned up"
        );
    }

    #[test]
    fn test_per_ip_limiter_double_release_does_not_underflow() {
        let limiter = PerIpLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.try_acquire(ip);
        limiter.release(ip);
        limiter.release(ip); // extra release should not underflow
        assert!(
            limiter.try_acquire(ip),
            "Should still work after double release"
        );
    }

    #[test]
    fn test_global_connection_slot_rejects_zero_limit_without_leaking_count() {
        let active = AtomicUsize::new(0);

        assert!(try_acquire_global_connection_slot(&active, 0).is_none());
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "Rejected global connection must roll back active counter"
        );
    }

    #[test]
    fn test_global_connection_slot_concurrent_acquire_never_exceeds_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(65));
        let successes = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..64 {
            let active = Arc::clone(&active);
            let start = Arc::clone(&start);
            let successes = Arc::clone(&successes);
            let max_seen = Arc::clone(&max_seen);
            handles.push(std::thread::spawn(move || {
                start.wait();
                if let Some(current) = try_acquire_global_connection_slot(&active, 7) {
                    successes.fetch_add(1, Ordering::SeqCst);
                    max_seen.fetch_max(current, Ordering::SeqCst);
                }
            }));
        }

        start.wait();
        for handle in handles {
            handle
                .join()
                .expect("global limiter worker thread should not panic");
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            7,
            "Concurrent global acquire must grant exactly max_connections slots"
        );
        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            7,
            "Observed active count must not exceed max_connections"
        );
        assert_eq!(
            active.load(Ordering::SeqCst),
            7,
            "Rejected global acquisitions must not leak active counters"
        );

        for _ in 0..7 {
            release_global_connection_slot(&active);
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(try_acquire_global_connection_slot(&active, 7).is_some());
    }

    #[test]
    fn test_per_ip_limiter_concurrent_acquire_same_ip_never_exceeds_limit() {
        let limiter = Arc::new(PerIpLimiter::new(10));
        let start = Arc::new(std::sync::Barrier::new(65));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..64 {
            let limiter = Arc::clone(&limiter);
            let start = Arc::clone(&start);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                start.wait();
                if limiter.try_acquire(ip) {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        start.wait();
        for handle in handles {
            handle
                .join()
                .expect("limiter worker thread should not panic");
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            10,
            "Concurrent acquire must grant exactly max_per_ip slots"
        );
        assert!(
            !limiter.try_acquire(ip),
            "Limiter should remain saturated after concurrent acquisitions"
        );

        for _ in 0..10 {
            limiter.release(ip);
        }
        assert!(
            limiter.try_acquire(ip),
            "Limiter should recover after releasing all concurrent slots"
        );
    }

    #[test]
    fn test_per_ip_limiter_concurrent_acquire_many_ips_are_independent() {
        let limiter = Arc::new(PerIpLimiter::new(2));
        let start = Arc::new(std::sync::Barrier::new(33));
        let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();

        for idx in 0..32 {
            let limiter = Arc::clone(&limiter);
            let start = Arc::clone(&start);
            let successes = Arc::clone(&successes);
            handles.push(std::thread::spawn(move || {
                let ip: IpAddr = format!("10.0.0.{}", idx + 1)
                    .parse()
                    .expect("test ip should parse");
                start.wait();
                if limiter.try_acquire(ip) {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        start.wait();
        for handle in handles {
            handle
                .join()
                .expect("limiter worker thread should not panic");
        }

        assert_eq!(
            successes.load(Ordering::SeqCst),
            32,
            "Per-IP limit must not globally throttle independent client IPs"
        );
    }

    #[test]
    fn test_per_ip_limiter_concurrent_acquire_release_steady_state() {
        let limiter = Arc::new(PerIpLimiter::new(4));
        let start = Arc::new(std::sync::Barrier::new(17));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let limiter = Arc::clone(&limiter);
            let start = Arc::clone(&start);
            let in_flight = Arc::clone(&in_flight);
            let max_seen = Arc::clone(&max_seen);
            handles.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..100 {
                    while !limiter.try_acquire(ip) {
                        std::thread::yield_now();
                    }

                    let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(current, Ordering::SeqCst);
                    std::thread::yield_now();
                    let previous = in_flight.fetch_sub(1, Ordering::SeqCst);
                    assert!(
                        previous > 0,
                        "In-flight counter must not underflow during concurrent release"
                    );
                    limiter.release(ip);
                }
            }));
        }

        start.wait();
        for handle in handles {
            handle
                .join()
                .expect("limiter worker thread should not panic");
        }

        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "All concurrent acquisitions should have been released"
        );
        assert!(
            max_seen.load(Ordering::SeqCst) <= 4,
            "Concurrent acquire/release must never exceed max_per_ip"
        );
        assert!(
            limiter.try_acquire(ip),
            "Limiter should not retain stale counts after steady-state churn"
        );
    }

    #[test]
    fn test_delivery_plan_accept_inbound_relays_without_dlp() {
        let plan = delivery_plan(
            &VerdictDisposition::Accept,
            MailDirection::Inbound,
            false,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Inbound,
                enforce_outbound_dlp: false,
            }
        );
    }

    #[test]
    fn test_delivery_plan_accept_outbound_relays_with_dlp_when_enabled() {
        let plan = delivery_plan(
            &VerdictDisposition::Accept,
            MailDirection::Outbound,
            false,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Outbound,
                enforce_outbound_dlp: true,
            }
        );
    }

    #[test]
    fn test_delivery_plan_internal_never_requests_outbound_dlp() {
        let plan = delivery_plan(
            &VerdictDisposition::Accept,
            MailDirection::Internal,
            false,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Internal,
                enforce_outbound_dlp: false,
            }
        );
    }

    #[test]
    fn test_delivery_plan_tempfail_fail_closed_returns_451() {
        let plan = delivery_plan(
            &VerdictDisposition::Tempfail,
            MailDirection::Outbound,
            false,
            true,
        );
        assert_eq!(plan, DeliveryPlan::TempfailReply);
    }

    #[test]
    fn test_delivery_plan_tempfail_fail_open_reuses_outbound_path_and_dlp() {
        let plan = delivery_plan(
            &VerdictDisposition::Tempfail,
            MailDirection::Outbound,
            true,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Outbound,
                enforce_outbound_dlp: true,
            }
        );
    }

    #[test]
    fn test_delivery_plan_tempfail_fail_open_internal_relays_without_dlp() {
        let plan = delivery_plan(
            &VerdictDisposition::Tempfail,
            MailDirection::Internal,
            true,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Internal,
                enforce_outbound_dlp: false,
            }
        );
    }

    #[test]
    fn test_delivery_plan_tempfail_fail_open_inbound_relays_without_dlp() {
        let plan = delivery_plan(
            &VerdictDisposition::Tempfail,
            MailDirection::Inbound,
            true,
            true,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Inbound,
                enforce_outbound_dlp: false,
            }
        );
    }

    #[test]
    fn test_delivery_plan_outbound_skips_dlp_when_disabled() {
        let plan = delivery_plan(
            &VerdictDisposition::Accept,
            MailDirection::Outbound,
            false,
            false,
        );
        assert_eq!(
            plan,
            DeliveryPlan::Relay {
                relay_direction: MailDirection::Outbound,
                enforce_outbound_dlp: false,
            }
        );
    }

    #[test]
    fn test_delivery_plan_quarantine_short_circuits_delivery() {
        let plan = delivery_plan(
            &VerdictDisposition::Quarantine,
            MailDirection::Outbound,
            true,
            true,
        );
        assert_eq!(plan, DeliveryPlan::Quarantine);
    }

    #[test]
    fn test_delivery_plan_reject_short_circuits_delivery() {
        let plan = delivery_plan(
            &VerdictDisposition::Reject {
                reason: "blocked".into(),
            },
            MailDirection::Outbound,
            true,
            true,
        );
        assert_eq!(plan, DeliveryPlan::Reject);
    }

    fn make_trusted_session(client_ip: &str) -> vigilyx_core::models::EmailSession {
        use vigilyx_core::models::Protocol;

        let mut session = vigilyx_core::models::EmailSession::new(
            Protocol::Smtp,
            client_ip.to_string(),
            2525,
            "127.0.0.1".into(),
            25,
        );
        session.mail_from = Some("user@example.com".into());
        session.rcpt_to = vec!["dest@example.net".into()];
        session
    }

    #[test]
    fn test_session_trusted_submitter_matches_trusted_upstream_cidr() {
        let session = make_trusted_session("10.10.10.42");
        let trusted = vec!["10.10.10.0/24".to_string()];
        assert!(session_trusted_submitter(&session, &trusted));
    }

    #[test]
    fn test_session_trusted_submitter_matches_authenticated_session() {
        let mut session = make_trusted_session("203.0.113.10");
        session.auth_info = Some(vigilyx_core::models::SmtpAuthInfo {
            auth_method: "PLAIN".into(),
            username: Some("alice".into()),
            password: None,
            auth_success: Some(true),
        });
        assert!(session_trusted_submitter(&session, &[]));
    }

    #[test]
    fn test_session_trusted_submitter_rejects_unknown_auth_result() {
        let mut session = make_trusted_session("203.0.113.10");
        session.auth_info = Some(vigilyx_core::models::SmtpAuthInfo {
            auth_method: "PLAIN".into(),
            username: Some("alice".into()),
            password: None,
            auth_success: None,
        });
        assert!(!session_trusted_submitter(&session, &[]));
    }

    #[test]
    fn test_session_trusted_submitter_rejects_untrusted_sender_claim() {
        let session = make_trusted_session("203.0.113.10");
        assert!(!session_trusted_submitter(&session, &[]));
    }

    #[test]
    fn test_session_trusted_submitter_rejects_failed_auth_without_trusted_ip() {
        let mut session = make_trusted_session("203.0.113.10");
        session.auth_info = Some(vigilyx_core::models::SmtpAuthInfo {
            auth_method: "PLAIN".into(),
            username: Some("alice".into()),
            password: None,
            auth_success: Some(false),
        });
        assert!(!session_trusted_submitter(&session, &[]));
    }

    #[test]
    fn test_session_trusted_submitter_accepts_trusted_ip_even_with_failed_auth() {
        let mut session = make_trusted_session("10.10.10.42");
        session.auth_info = Some(vigilyx_core::models::SmtpAuthInfo {
            auth_method: "PLAIN".into(),
            username: Some("alice".into()),
            password: None,
            auth_success: Some(false),
        });
        let trusted = vec!["10.10.10.0/24".to_string()];
        assert!(session_trusted_submitter(&session, &trusted));
    }

    // ── F-3: TLS handshake timeout ────────────────────────────────────────

    // Test-only self-signed certificate for CN=vigilyx-mta-test (no SAN,
    // never used for real TLS termination, generated for these tests).
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDFzCCAf+gAwIBAgIUXN/LFLYWhMYNAbta+InDVJnKsp8wDQYJKoZIhvcNAQEL\n\
BQAwGzEZMBcGA1UEAwwQdmlnaWx5eC1tdGEtdGVzdDAeFw0yNjA4MTQwMTE5MDda\n\
Fw0zNjA4MTEwMTE5MDdaMBsxGTAXBgNVBAMMEHZpZ2lseXgtbXRhLXRlc3QwggEi\n\
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXawCL8gM+MBsOWfZ2p/XcrpIN\n\
+MQLHclk2SSzj5hUUDfZreHNtiyhZteleJEVh7yCoVYXz0h74spsl3QsfGgDu8zL\n\
gpKpSCgrk+AbgFbyF08ewT6BjBmEOfv5K4HzGt0m9SNSSDJyf8pA+ykluK85bNE/\n\
hJfs8NORKRNQM9I5g6iX2n2MCCP75Oh5BHrRpHlMES5kBAc+JZWAKJKJiC9dqgSa\n\
OtG8LZIeJCoOduEcA4YOKC0bOppEh5oVTbGXBbr6bzTQ9yvu6J2E2/w6r9+qn0fF\n\
ugq2ClYJ/DD0l1CejC1M+l9LYMB50w3XDFzlFCwX8wplm9yht7MK0i0mS+UTAgMB\n\
AAGjUzBRMB0GA1UdDgQWBBS2D7RjNQiCD4WSGLWaW1nQcia12zAfBgNVHSMEGDAW\n\
gBS2D7RjNQiCD4WSGLWaW1nQcia12zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n\
DQEBCwUAA4IBAQCC2gbo/HQS1b6j9QZAg69Hvqj8CPwj1nKAoZX1GOih0ZVCATmN\n\
T5uotAlrsFkL90Crbs2m9iTxZZi6isP+OupEifVyvOIawUNGfm+j5PFi0fDbxpO8\n\
8uSbYDLjCsJYlAicna/ZYAWn+9KnR5PYPpGZDfsB03DpK+wEv1ouLqWjDH05j0rQ\n\
OpzXs0gEGPodcTE7oDyJHoNZNkcILjfPb7csFL9MtWf5ZWYaJ47ouT0lokzbbUUY\n\
dFqFBhMf5TVSEpV5dDGw/F2Ake8osambLCB2XuO5d72WJDmlXY9Gz8kCi8BmVShC\n\
GhXcojlaCBZbOKgaS7E3BNijTzsYAHAGjO4U\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDXawCL8gM+MBsO\n\
WfZ2p/XcrpIN+MQLHclk2SSzj5hUUDfZreHNtiyhZteleJEVh7yCoVYXz0h74sps\n\
l3QsfGgDu8zLgpKpSCgrk+AbgFbyF08ewT6BjBmEOfv5K4HzGt0m9SNSSDJyf8pA\n\
+ykluK85bNE/hJfs8NORKRNQM9I5g6iX2n2MCCP75Oh5BHrRpHlMES5kBAc+JZWA\n\
KJKJiC9dqgSaOtG8LZIeJCoOduEcA4YOKC0bOppEh5oVTbGXBbr6bzTQ9yvu6J2E\n\
2/w6r9+qn0fFugq2ClYJ/DD0l1CejC1M+l9LYMB50w3XDFzlFCwX8wplm9yht7MK\n\
0i0mS+UTAgMBAAECggEAOCvFo7hCkje3BmH8+2nGmXnHye7hJ8jnl+1rPYsm/G1C\n\
cvd9Vse3EYsglhw/MK8JP8LUETdSvkMf53sCpwr1kGuq9jIhDhUrrFlN6b3obg4X\n\
6nwXUW53xNvd0VY/92U834iyYiVDSkn6MkGLtDNZNY8jbP2lI/qUIFjmmVY57hbl\n\
FNmoW50HIldL2WmPhIe7SMwaUzzAyCM8qp9VmP9QNvewU7IylS+vKah6vOJsYhCA\n\
mkrpP3JKlG2OhNTVRDc5rQVMc0oir4MTvdhCgHTgLND5eJRdqXIGszAdSwLdjsz3\n\
7dxP+5O1g79uQR0MI2kb3V/GhVAl3PCLIvFcp/zmgQKBgQDzqKw9zrr7rRfB7TJi\n\
93MwpvPC3YX8pzHeFhgSjbXIsis6GRhAJy+2f3/jXJ+p4PeulWiGkVJsMsGbz3U1\n\
voSrAdCTTSw1r/CW2SGU+QfvDyaDE7B5m/dzIqfPfKN47S1BWUbSmvnuuc7bNyO5\n\
/OAyn4Hd/n74cjapK6Y0rYoxQQKBgQDiVCcGevZhOlEUf8kH9O3FGB0Wr6/w1wmy\n\
FVmtBlbmRMqHCryyo1LpToB/PYAhdPJ8H9E6vAIgKCbupHi2bu4PtntI/KGC8nev\n\
aUKVvrEVW9zc8L9s2iRhmshWN2ZMmtjtE/sCJuqKZD9PdClVOhEzbCIyyHm1DlD+\n\
y0FeXPWtUwKBgQDVvbcqmPjp4hOfKIY0zsEbgrj+zfjFg515JoSDchBvN+w3kN/3\n\
FukB/KKhPhVJnnFnkuUYds6I35V7Kue096XFpVfkf6QyjF5O1bZhynstOGsePN1o\n\
MGtHcrUmjD2SzOwQEVLRWOW6hwBwyNPsSWoavlXb+W5EX1yX1hR8zWcWgQKBgQDR\n\
vebEjKNTCzYkZx+n7gWDB4u9gGbuLHnhvQNz41IY51tAtmSUr+KgL43JXPcnCjfF\n\
a778TUsy/cLGmUj81+RqT1QFGYmbzpO3zTZVi3iUMKOHZNwhRi88/LH3pDN7fmzV\n\
mBSfs+za/3fka+P6BWv3WZh/s2WGspPA7B/SERfj3QKBgHSOdCJJFH6gy0GkVq3y\n\
VKav/G7QcaAMAiSB7o7KigZYUWN3LzpejxNi887xuSb4WN7Mwxwb2sLlqTfqMfdK\n\
uI1z59S9RiHd0LMf//ma55dJ8kEKpsDIMqZ0ps9A9RHIM+pPB/thBtC4DjriC8Dm\n\
tXOsY15IIfKL93pMXxy6cYL+\n\
-----END PRIVATE KEY-----\n";

    fn test_tls_acceptor() -> TlsAcceptor {
        let certs: Vec<_> = rustls_pemfile::certs(&mut TEST_CERT_PEM.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("test cert PEM should parse");
        let key = rustls_pemfile::private_key(&mut TEST_KEY_PEM.as_bytes())
            .expect("test key PEM should parse")
            .expect("test key PEM should contain a private key");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("test cert/key should build a ServerConfig");
        TlsAcceptor::from(Arc::new(server_config))
    }

    /// PoC (F-3): a client that connects and never sends a ClientHello used
    /// to hold the acceptor (and its connection slot) forever; the handshake
    /// is now bounded by TLS_HANDSHAKE_TIMEOUT_SECS. `start_paused` lets the
    /// 15s deadline elapse instantly.
    #[tokio::test(start_paused = true)]
    async fn test_tls_handshake_times_out_when_client_never_speaks() {
        let acceptor = test_tls_acceptor();
        let (_silent_client, server_side) = tokio::io::duplex(1024);

        let result = accept_tls_with_timeout(&acceptor, server_side, "127.0.0.1").await;

        assert!(
            result.is_none(),
            "a silent client must fail the timed TLS handshake"
        );
    }

    /// Regression protection: a client that speaks garbage fails the
    /// handshake immediately (no timeout stall).
    #[tokio::test]
    async fn test_tls_handshake_garbage_client_fails_fast() {
        use tokio::io::AsyncWriteExt;

        let acceptor = test_tls_acceptor();
        let (mut client, server_side) = tokio::io::duplex(1024);
        client
            .write_all(b"NOT A TLS CLIENT HELLO\r\n")
            .await
            .expect("write garbage");
        drop(client);

        let result = accept_tls_with_timeout(&acceptor, server_side, "127.0.0.1").await;

        assert!(result.is_none(), "garbage bytes must fail the handshake");
    }
}
