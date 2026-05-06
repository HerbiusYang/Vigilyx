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
use crate::dlp::{DlpAction, detect_direction, format_dlp_reason, run_dlp_scan};
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
    engine: &'a SecurityEngine,
    relay: &'a DownstreamRelay,
    outbound_relay: &'a DownstreamRelay,
    db: &'a VigilDb,
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

async fn relay_and_reply<S, I>(
    stream: &mut S,
    relay: &DownstreamRelay,
    mail_from: Option<&str>,
    rcpt_to: &[String],
    raw_eml: &[u8],
    session_id: I,
) where
    S: tokio::io::AsyncWrite + Unpin,
    I: Copy + std::fmt::Display,
{
    match relay.relay(mail_from, rcpt_to, raw_eml).await {
        RelayResult::Accepted => {
            write_reply(stream, b"250 2.0.0 OK\r\n").await;
        }
        RelayResult::TempFail(msg) => {
            let reply = format!("451 4.7.1 Downstream temporary failure: {msg}\r\n");
            write_reply(stream, reply.as_bytes()).await;
        }
        RelayResult::PermFail(msg) => {
            let reply = format!("550 5.7.1 Downstream rejected: {msg}\r\n");
            write_reply(stream, reply.as_bytes()).await;
        }
        RelayResult::ConnError(msg) => {
            warn!(session_id = %session_id, "Downstream unreachable: {msg}");
            write_reply(stream, b"421 4.7.0 Downstream unavailable, try later\r\n").await;
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
    if dlp_result.is_empty() || dlp_result.count_items_at_level(runtime.config.dlp.min_level) == 0 {
        return false;
    }

    let reason = format_dlp_reason(&dlp_result);
    info!(
        session_id = %session.id,
        matches = ?dlp_result.matches,
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

        tokio::spawn(async move {
            let client_ip = addr.ip().to_string();
            let client_port = addr.port();
            info!(client_ip = %client_ip, "New SMTP connection");

            let result =
                handle_smtp_connection(stream, client_ip, client_port, cfg, eng, rl, orl, d, tls)
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

        tokio::spawn(async move {
            let client_ip = peer_addr.ip().to_string();
            let client_port = peer_addr.port();

            // TLS:
            let server_ip = stream
                .local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "0.0.0.0".into());
            let server_port = stream.local_addr().map(|a| a.port()).unwrap_or(465);
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let mut tls_stream = tokio::io::BufStream::new(tls_stream);
                    let runtime = SmtpRuntime {
                        config: cfg.as_ref(),
                        engine: eng.as_ref(),
                        relay: rl.as_ref(),
                        outbound_relay: orl.as_ref(),
                        db: d.as_ref(),
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
                Err(e) => {
                    warn!(client_ip = %client_ip, "TLS handshake failed: {e}");
                }
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
        engine: engine.as_ref(),
        relay: relay.as_ref(),
        outbound_relay: outbound_relay.as_ref(),
        db: db.as_ref(),
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
                match acceptor.accept(inner).await {
                    Ok(tls_stream) => {
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
                    Err(e) => {
                        warn!(client_ip = %client_ip, "STARTTLS handshake failed: {e}");
                    }
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
                let session = *session; // unbox
                let session_id = session.id;
                let mail_from = session.mail_from.clone();
                let rcpt_to = session.rcpt_to.clone();
                let subject = session.subject.clone();

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
                        if matches!(response.disposition, VerdictDisposition::Tempfail) {
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

                        relay_and_reply(
                            stream,
                            relay_for_direction(runtime, relay_direction),
                            mail_from.as_deref(),
                            &rcpt_to,
                            &raw_eml,
                            session_id,
                        )
                        .await;
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
                        )
                        .await;
                        if stored {
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
                        let reply = format!("550 5.7.1 {reason}\r\n");
                        write_reply(stream, reply.as_bytes()).await;
                    }
                }
            }
            HandleResult::Closed => {}
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
}
