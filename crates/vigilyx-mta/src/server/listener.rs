//! SMTP TCP/TLS

//! SMTP,accept, connection handler.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::config::MtaConfig;
use crate::dlp::{DlpAction, detect_direction, format_dlp_reason, run_dlp_scan};
use crate::relay::downstream::{DownstreamRelay, RelayResult};
use crate::relay::quarantine::store_quarantine;
use crate::server::connection::{HandleResult, SmtpConnection};

use vigilyx_core::models::MailDirection;
use vigilyx_core::security::VerdictDisposition;
use vigilyx_db::VigilDb;
use vigilyx_engine::pipeline::engine::SecurityEngine;

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

        let current = active_connections.fetch_add(1, Ordering::Relaxed);
        if current >= config.max_connections {
            active_connections.fetch_sub(1, Ordering::Relaxed);
            warn!(addr = %addr, current, "Max connections reached, rejecting");
            drop(stream);
            continue;
        }

        // SEC: per-IP connection limit (CWE-400)
        let client_ip_addr = addr.ip();
        if !per_ip_limiter.try_acquire(client_ip_addr) {
            active_connections.fetch_sub(1, Ordering::Relaxed);
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

            let result = handle_smtp_connection(
                stream, client_ip, client_port, cfg, eng, rl, orl, d, tls,
            )
            .await;

            if let Err(e) = result {
                error!(error = %e, "SMTP connection error");
            }

            conn_counter.fetch_sub(1, Ordering::Relaxed);
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

        let current = active_connections.fetch_add(1, Ordering::Relaxed);
        if current >= config.max_connections {
            active_connections.fetch_sub(1, Ordering::Relaxed);
            warn!(addr = %peer_addr, "Max connections reached");
            drop(stream);
            continue;
        }

        // SEC: per-IP connection limit (CWE-400)
        let client_ip_addr = peer_addr.ip();
        if !per_ip_limiter.try_acquire(client_ip_addr) {
            active_connections.fetch_sub(1, Ordering::Relaxed);
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
            let server_ip = stream.local_addr()
                .map(|a| a.ip().to_string()).unwrap_or_else(|_| "0.0.0.0".into());
            let server_port = stream.local_addr()
                .map(|a| a.port()).unwrap_or(465);
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let mut tls_stream = tokio::io::BufStream::new(tls_stream);
                    let mut conn = SmtpConnection::new(
                        client_ip, client_port, server_ip, server_port, cfg.clone(), true,
                    );

                    let results = conn.handle(&mut tls_stream, false).await;
                    process_results(results, &mut tls_stream, &cfg, &eng, &rl, &orl, &d).await;
                }
                Err(e) => {
                    warn!(client_ip = %client_ip, "TLS handshake failed: {e}");
                }
            }

            conn_counter.fetch_sub(1, Ordering::Relaxed);
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
    let server_ip = stream.get_ref().local_addr()
        .map(|a| a.ip().to_string()).unwrap_or_else(|_| "0.0.0.0".into());
    let server_port = stream.get_ref().local_addr()
        .map(|a| a.port()).unwrap_or(25);

    let mut conn = SmtpConnection::new(
        client_ip.clone(), client_port, server_ip.clone(), server_port, config.clone(), false,
    );

    // Phase 1: plain text SMTP (may include STARTTLS)
    let results = conn.handle(&mut stream, false).await;

    // Check if STARTTLS was requested
    let needs_tls = results.iter().any(|r| matches!(r, HandleResult::StartTls));

    if needs_tls {
        // Process any emails received before STARTTLS first
        process_results(
            results.into_iter().filter(|r| !matches!(r, HandleResult::StartTls)).collect(),
            &mut stream, &config, &engine, &relay, &outbound_relay, &db,
        ).await;

        if let Some(acceptor) = tls_acceptor {
            let inner = stream.into_inner();
            match acceptor.accept(inner).await {
                Ok(tls_stream) => {
                    let mut tls_stream = tokio::io::BufStream::new(tls_stream);
                    // After TLS upgrade: skip banner (client already saw 220 before STARTTLS)
                    let mut tls_conn = SmtpConnection::new(
                        client_ip, client_port, server_ip, server_port, config.clone(), true,
                    );
                    let tls_results = tls_conn.handle(&mut tls_stream, true).await;
                    process_results(tls_results, &mut tls_stream, &config, &engine, &relay, &outbound_relay, &db).await;
                }
                Err(e) => {
                    warn!(client_ip = %client_ip, "STARTTLS handshake failed: {e}");
                }
            }
        }
    } else {
        process_results(results, &mut stream, &config, &engine, &relay, &outbound_relay, &db).await;
    }

    Ok(())
}

/// : inline SMTP
async fn process_results<S>(
    results: Vec<HandleResult>,
    stream: &mut S,
    config: &MtaConfig,
    engine: &SecurityEngine,
    relay: &DownstreamRelay,
    outbound_relay: &DownstreamRelay,
    db: &VigilDb,
) where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Helper macro: write + flush (BufStream does not flush automatically)
    macro_rules! reply {
        ($stream:expr, $data:expr) => {{
            let _ = $stream.write_all($data).await;
            let _ = $stream.flush().await;
        }};
    }

    for result in results {
        match result {
            HandleResult::Email(session, raw_eml) => {
                let session = *session; // unbox
                let session_id = session.id;
                let mail_from = session.mail_from.clone();
                let rcpt_to = session.rcpt_to.clone();
                let subject = session.subject.clone();

                
                // SEC: port 25 has no SMTP AUTH, so all connections are treated as untrusted.
                // trusted_submitter=false ensures spoofed local-domain MAIL FROM values cannot bypass inline scanning.
                let trusted_submitter = false;
                let direction = detect_direction(
                    mail_from.as_deref(),
                    &rcpt_to,
                    &config.local_domains,
                    trusted_submitter,
                );

                // SEC: only log domain part to avoid leaking full addresses (CWE-532)
                let from_domain = mail_from.as_deref()
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

                
                if direction == MailDirection::Internal {
                    match relay.relay(mail_from.as_deref(), &rcpt_to, &raw_eml).await {
                        RelayResult::Accepted => {
                            reply!(stream, b"250 2.0.0 OK\r\n");
                        }
                        RelayResult::TempFail(msg) => {
                            let reply = format!("451 4.7.1 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                        RelayResult::PermFail(msg) => {
                            let reply = format!("550 5.7.1 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                        RelayResult::ConnError(msg) => {
                            let reply = format!("421 4.7.0 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                    }
                    continue;
                }

               // (->): DLP
                if direction == MailDirection::Outbound && config.dlp.enabled {
                    let dlp_result = run_dlp_scan(&session);
                    if !dlp_result.is_empty()
                        && dlp_result.count_items_at_level(config.dlp.min_level) > 0
                    {
                        let reason = format_dlp_reason(&dlp_result);
                        info!(
                            session_id = %session_id,
                            matches = ?dlp_result.matches,
                            "DLP hit on outbound email: {reason}"
                        );

                        match config.dlp.action {
                            DlpAction::Block => {
                                let _ = stream.write_all(
                                    b"550 5.7.1 Message blocked: sensitive data detected\r\n",
                                ).await;
                                continue;
                            }
                            DlpAction::Quarantine => {
                                let stored = store_quarantine(
                                    db, &session_id, mail_from.as_deref(), &rcpt_to,
                                    subject.as_deref(), &raw_eml, "high", &reason,
                                ).await;
                                if stored {
                                    reply!(stream, b"250 2.0.0 OK\r\n");
                                } else {
                                    warn!(session_id = %session_id, "DLP quarantine storage failed");
                                    reply!(stream, b"451 4.7.1 Quarantine storage unavailable\r\n");
                                }
                                continue;
                            }
                            DlpAction::AllowAndAlert => {
                               // (quarantine status=released)
                                warn!(
                                    session_id = %session_id,
                                    "DLP alert (allow_and_alert): {reason}"
                                );
                                
                            }
                        }
                    }
                   // DLP AllowAndAlert ->
                    match outbound_relay.relay(mail_from.as_deref(), &rcpt_to, &raw_eml).await {
                        RelayResult::Accepted => {
                            reply!(stream, b"250 2.0.0 OK\r\n");
                        }
                        RelayResult::TempFail(msg) => {
                            let reply = format!("451 4.7.1 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                        RelayResult::PermFail(msg) => {
                            let reply = format!("550 5.7.1 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                        RelayResult::ConnError(msg) => {
                            let reply = format!("421 4.7.0 {msg}\r\n");
                            reply!(stream, reply.as_bytes());
                        }
                    }
                    continue;
                }

               // (->) DLP:
                let timeout = std::time::Duration::from_secs(config.inline_timeout_secs as u64);
                let response = engine
                    .submit_inline(
                        session,
                        timeout,
                        config.quarantine_threshold,
                        config.reject_threshold,
                    )
                    .await;

                info!(
                    session_id = %session_id,
                    disposition = %response.disposition,
                    threat_level = %response.threat_level,
                    duration_ms = response.duration_ms,
                    "Inline verdict: {}", response.summary
                );

                
                match &response.disposition {
                    VerdictDisposition::Accept => {
                        match relay
                            .relay(mail_from.as_deref(), &rcpt_to, &raw_eml)
                            .await
                        {
                            RelayResult::Accepted => {
                                reply!(stream, b"250 2.0.0 OK\r\n");
                            }
                            RelayResult::TempFail(msg) => {
                                let reply = format!("451 4.7.1 Downstream temporary failure: {msg}\r\n");
                                reply!(stream, reply.as_bytes());
                            }
                            RelayResult::PermFail(msg) => {
                                let reply = format!("550 5.7.1 Downstream rejected: {msg}\r\n");
                                reply!(stream, reply.as_bytes());
                            }
                            RelayResult::ConnError(msg) => {
                                warn!(session_id = %session_id, "Downstream unreachable: {msg}");
                                reply!(stream, b"421 4.7.0 Downstream unavailable, try later\r\n");
                            }
                        }
                    }
                    VerdictDisposition::Tempfail => {
                        if !config.fail_open {
                            warn!(
                                session_id = %session_id,
                                "Inline verdict unavailable and MTA_FAIL_OPEN=false, deferring delivery"
                            );
                            reply!(stream, b"451 4.7.1 Security engine temporary failure\r\n");
                            continue;
                        }

                        warn!(
                            session_id = %session_id,
                            "Inline verdict unavailable and MTA_FAIL_OPEN=true, relaying downstream"
                        );
                        match relay
                            .relay(mail_from.as_deref(), &rcpt_to, &raw_eml)
                            .await
                        {
                            RelayResult::Accepted => {
                                reply!(stream, b"250 2.0.0 OK\r\n");
                            }
                            RelayResult::TempFail(msg) => {
                                let reply = format!("451 4.7.1 Downstream temporary failure: {msg}\r\n");
                                reply!(stream, reply.as_bytes());
                            }
                            RelayResult::PermFail(msg) => {
                                let reply = format!("550 5.7.1 Downstream rejected: {msg}\r\n");
                                reply!(stream, reply.as_bytes());
                            }
                            RelayResult::ConnError(msg) => {
                                
                                warn!(session_id = %session_id, "Downstream unreachable: {msg}");
                                reply!(stream, b"421 4.7.0 Downstream unavailable, try later\r\n");
                            }
                        }
                    }
                    VerdictDisposition::Quarantine => {
                       // Quarantine -> 250,
                        let stored = store_quarantine(
                            db,
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
                            reply!(stream, b"250 2.0.0 OK\r\n");
                        } else {
                            warn!(
                                session_id = %session_id,
                                "Quarantine storage failed, returning temporary failure to avoid silent loss"
                            );
                            reply!(stream, b"451 4.7.1 Quarantine storage unavailable\r\n");
                        }
                    }
                    VerdictDisposition::Reject { reason } => {
                       // Reject -> 550
                        let reply = format!("550 5.7.1 {reason}\r\n");
                        reply!(stream, reply.as_bytes());
                    }
                }
            }
            HandleResult::Closed | HandleResult::Error(_) => {}
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
        assert!(!limiter.try_acquire(ip), "Should reject 3rd connection when limit=2");
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
        assert!(limiter.try_acquire(ip_b), "Different IPs should have independent limits");
        assert!(!limiter.try_acquire(ip_a), "Same IP should still be blocked");
    }

    #[test]
    fn test_per_ip_limiter_release_cleans_up_zero_entries() {
        let limiter = PerIpLimiter::new(1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.try_acquire(ip);
        limiter.release(ip);
        // SAFETY: same rationale as try_acquire/release — only integer ops
        let counts = limiter.counts.lock().expect("mutex poisoned");
        assert!(!counts.contains_key(&ip), "Zero-count entries should be cleaned up");
    }

    #[test]
    fn test_per_ip_limiter_double_release_does_not_underflow() {
        let limiter = PerIpLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.try_acquire(ip);
        limiter.release(ip);
        limiter.release(ip); // extra release should not underflow
        assert!(limiter.try_acquire(ip), "Should still work after double release");
    }
}
