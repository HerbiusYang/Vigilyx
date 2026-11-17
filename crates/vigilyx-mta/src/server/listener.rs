//! SMTP TCP/TLS

//! SMTP,accept, connection handler.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::authentication::AuthenticationVerifier;
use crate::config::MtaConfig;
use crate::config::is_trusted_upstream_ip;
use crate::dlp::{DlpAction, DlpInspection, detect_direction, format_dlp_reason, run_dlp_scan};
use crate::metrics::VerdictMetrics;
use crate::relay::downstream::{DownstreamRelay, RelayResult};
use crate::relay::quarantine::store_quarantine_id;
use crate::server::connection::{HandleResult, SmtpConnection};

use vigilyx_core::models::{
    EmailAuditClass, EmailReviewAction, EmailReviewDirection, MailDirection,
    is_internal_to_external,
};
use vigilyx_core::security::VerdictDisposition;
use vigilyx_db::VigilDb;
use vigilyx_engine::data_security::email_review::build_email_review_with_class;
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

// SMTP and SMTPS share admission control. A timed-out caller cannot release
// its worker's permit while the blocking inspection is still running.
const MTA_DLP_MAX_WORKERS: usize = 2;
const MTA_DLP_TIMEOUT: Duration = Duration::from_secs(15);
static MTA_DLP_WORKERS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MTA_DLP_MAX_WORKERS)));

async fn run_dlp_scan_bounded(session: &vigilyx_core::models::EmailSession) -> DlpInspection {
    run_bounded_dlp_task(Arc::clone(&MTA_DLP_WORKERS), MTA_DLP_TIMEOUT, || {
        // Clone only after admission; queued connections do not multiply
        // retained attachment bodies before a worker slot becomes available.
        let session = session.clone();
        move || run_dlp_scan(&session)
    })
    .await
}

async fn run_bounded_dlp_task<F, J>(
    limiter: Arc<Semaphore>,
    timeout: Duration,
    make_scan: F,
) -> DlpInspection
where
    F: FnOnce() -> J + Send,
    J: FnOnce() -> DlpInspection + Send + 'static,
{
    let result = tokio::time::timeout(timeout, async {
        let permit = limiter
            .acquire_owned()
            .await
            .map_err(|error| error.to_string())?;
        let scan = make_scan();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            scan()
        })
        .await
        .map_err(|error| error.to_string())
    })
    .await;
    match result {
        Ok(Ok(inspection)) => inspection,
        Ok(Err(error)) => {
            warn!(%error, "MTA DLP worker unavailable; inspection coverage is incomplete");
            DlpInspection::default()
        }
        Err(_) => {
            warn!("MTA DLP admission or inspection timed out; inspection coverage is incomplete");
            DlpInspection::default()
        }
    }
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

#[derive(Debug)]
struct OutboundDlpDecision {
    action: EmailReviewAction,
    terminate: bool,
    delivery_status: &'static str,
    quarantine_id: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn persist_mta_email_review(
    runtime: &SmtpRuntime<'_>,
    session: &vigilyx_core::models::EmailSession,
    direction: EmailReviewDirection,
    audit_class: EmailAuditClass,
    inspection: Option<&DlpInspection>,
    action: EmailReviewAction,
    delivery_status: &str,
    quarantine_id: Option<String>,
) -> Result<(), String> {
    let review = build_email_review_with_class(
        session,
        direction,
        audit_class,
        &runtime.config.local_domains,
        inspection,
        action,
        Some(delivery_status.to_string()),
        quarantine_id,
    );
    if let Err(error) = runtime.db.upsert_email_data_security_review(&review).await {
        error!(session_id = %session.id, %error, "Failed to persist outbound email data-security review");
        return Err(error.to_string());
    }
    if let Some(incident) =
        vigilyx_engine::data_security::email_review::build_transfer_incident(&review, inspection)
    {
        runtime
            .db
            .insert_data_security_incident(&incident)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
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
    match relay
        .relay_from(mail_from, rcpt_to, raw_eml, client_ip)
        .await
    {
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
    dlp_result: &DlpInspection,
) -> Option<OutboundDlpDecision>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let has_policy_match =
        !dlp_result.is_empty() && dlp_result.count_items_at_level(runtime.config.dlp.min_level) > 0;
    if outbound_dlp_scan_is_clean(dlp_result, runtime.config.dlp.min_level) {
        return None;
    }

    let reason = if dlp_result.complete {
        format_dlp_reason(dlp_result)
    } else if has_policy_match {
        format!(
            "{}; attachment inspection incomplete",
            format_dlp_reason(dlp_result)
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
            Some(OutboundDlpDecision {
                action: EmailReviewAction::Block,
                terminate: true,
                delivery_status: "blocked",
                quarantine_id: None,
            })
        }
        DlpAction::Quarantine => {
            let quarantine_id = store_quarantine_id(
                runtime.db,
                &session.id,
                session.mail_from.as_deref(),
                &session.rcpt_to,
                session.subject.as_deref(),
                raw_eml,
                "high",
                "outbound",
                &reason,
                Some(session.client_ip.as_str()),
            )
            .await;
            if let Some(quarantine_id) = quarantine_id {
                write_reply(stream, b"250 2.0.0 OK\r\n").await;
                Some(OutboundDlpDecision {
                    action: EmailReviewAction::Quarantine,
                    terminate: true,
                    delivery_status: "quarantined",
                    quarantine_id: Some(quarantine_id),
                })
            } else {
                warn!(session_id = %session.id, "DLP quarantine storage failed");
                write_reply(stream, b"451 4.7.1 Quarantine storage unavailable\r\n").await;
                Some(OutboundDlpDecision {
                    action: EmailReviewAction::Tempfail,
                    terminate: true,
                    delivery_status: "quarantine_failed",
                    quarantine_id: None,
                })
            }
        }
        DlpAction::AllowAndAlert => {
            warn!(
                session_id = %session.id,
                "DLP alert (allow_and_alert): {reason}"
            );
            Some(OutboundDlpDecision {
                action: EmailReviewAction::Alert,
                terminate: false,
                delivery_status: "alerted",
                quarantine_id: None,
            })
        }
    }
}

fn outbound_dlp_scan_is_clean(inspection: &DlpInspection, min_level: u8) -> bool {
    inspection.complete
        && (inspection.is_empty() || inspection.count_items_at_level(min_level) == 0)
}

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

    pub fn max_per_ip(&self) -> usize {
        self.max_per_ip
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
            warn!(addr = %addr, limit = per_ip_limiter.max_per_ip(), "Per-IP connection limit reached, rejecting");
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
            warn!(addr = %peer_addr, limit = per_ip_limiter.max_per_ip(), "Per-IP connection limit reached, rejecting");
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
                if let Some(tls_stream) =
                    accept_tls_with_timeout(&acceptor, inner, &client_ip).await
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
                    let _ = drive_connection(&mut tls_stream, &mut tls_conn, true, &runtime).await;
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
                let audit_candidate = is_internal_to_external(
                    mail_from.as_deref(),
                    &rcpt_to,
                    &runtime.config.local_domains,
                );
                let audit_direction = if audit_candidate && trusted_submitter {
                    EmailReviewDirection::Outbound
                } else if audit_candidate {
                    EmailReviewDirection::Unknown
                } else {
                    EmailReviewDirection::from(direction)
                };
                let audit_class = if audit_candidate {
                    if trusted_submitter {
                        EmailAuditClass::ConfirmedOutbound
                    } else {
                        EmailAuditClass::OutboundCandidate
                    }
                } else {
                    EmailAuditClass::Legacy
                };

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

                let review_session = session.clone();

                // Establish one durable DATA-level audit row before inline
                // analysis or downstream delivery. The later upsert carries
                // the final DLP/relay disposition, while this initial row
                // guarantees that a crash cannot turn a DATA event into an
                // invisible message.
                if let Err(error) = persist_mta_email_review(
                    runtime,
                    &review_session,
                    audit_direction,
                    audit_class,
                    None,
                    EmailReviewAction::Audit,
                    "mta_audit_pending",
                    None,
                )
                .await
                {
                    error!(
                        session_id = %session_id,
                        %error,
                        "Failed to create MTA DATA audit row; returning temporary failure"
                    );
                    write_reply(stream, b"451 4.7.1 Audit storage unavailable\r\n").await;
                    continue;
                }

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

                // Run the shared outbound DLP pass once after the inline
                // verdict, regardless of whether the threat verdict itself
                // already quarantined/rejected the message. The review table
                // must distinguish "DLP clean" from "not scanned" for every
                // outbound message, and a threat verdict must not hide a
                // separate sensitive-data hit.
                let dlp_inspection = if runtime.config.dlp.enabled {
                    Some(run_dlp_scan_bounded(&review_session).await)
                } else {
                    None
                };

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

                        let dlp_decision = if should_enforce_outbound_dlp {
                            match dlp_inspection.as_ref() {
                                Some(inspection) => {
                                    enforce_outbound_dlp(
                                        stream,
                                        runtime,
                                        &review_session,
                                        &raw_eml,
                                        inspection,
                                    )
                                    .await
                                }
                                None => None,
                            }
                        } else {
                            None
                        };
                        if let Some(decision) = dlp_decision.as_ref().filter(|d| d.terminate) {
                            let _ = persist_mta_email_review(
                                runtime,
                                &review_session,
                                audit_direction,
                                audit_class,
                                dlp_inspection.as_ref(),
                                decision.action,
                                decision.delivery_status,
                                decision.quarantine_id.clone(),
                            )
                            .await;
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
                        {
                            let (action, status, quarantine_id) = match dlp_decision.as_ref() {
                                Some(decision) => (
                                    decision.action,
                                    if relayed {
                                        "relayed_after_alert"
                                    } else {
                                        "relay_failed_after_alert"
                                    },
                                    decision.quarantine_id.clone(),
                                ),
                                None if runtime.config.dlp.enabled => (
                                    EmailReviewAction::Allow,
                                    if relayed { "relayed" } else { "relay_failed" },
                                    None,
                                ),
                                None => (EmailReviewAction::Audit, "dlp_disabled", None),
                            };
                            let _ = persist_mta_email_review(
                                runtime,
                                &review_session,
                                audit_direction,
                                audit_class,
                                dlp_inspection.as_ref(),
                                action,
                                status,
                                quarantine_id,
                            )
                            .await;
                        }
                    }
                    DeliveryPlan::TempfailReply => {
                        warn!(
                            session_id = %session_id,
                            "Inline verdict unavailable and MTA_FAIL_OPEN=false, deferring delivery"
                        );
                        write_reply(stream, b"451 4.7.1 Security engine temporary failure\r\n")
                            .await;
                        {
                            let _ = persist_mta_email_review(
                                runtime,
                                &review_session,
                                audit_direction,
                                audit_class,
                                dlp_inspection.as_ref(),
                                EmailReviewAction::Tempfail,
                                "engine_tempfail",
                                None,
                            )
                            .await;
                        }
                        continue;
                    }
                    DeliveryPlan::Quarantine => {
                        // Quarantine -> 250,
                        let quarantine_id = store_quarantine_id(
                            runtime.db,
                            &session_id,
                            mail_from.as_deref(),
                            &rcpt_to,
                            subject.as_deref(),
                            &raw_eml,
                            &response.threat_level.to_string(),
                            &direction.to_string(),
                            &response.summary,
                            Some(client_ip.as_str()),
                        )
                        .await;
                        if let Some(quarantine_id) = quarantine_id {
                            runtime.metrics.inc_quarantined();
                            write_reply(stream, b"250 2.0.0 OK\r\n").await;
                            {
                                let _ = persist_mta_email_review(
                                    runtime,
                                    &review_session,
                                    audit_direction,
                                    audit_class,
                                    dlp_inspection.as_ref(),
                                    EmailReviewAction::Quarantine,
                                    "engine_quarantined",
                                    Some(quarantine_id),
                                )
                                .await;
                            }
                        } else {
                            warn!(
                                session_id = %session_id,
                                "Quarantine storage failed, returning temporary failure to avoid silent loss"
                            );
                            write_reply(stream, b"451 4.7.1 Quarantine storage unavailable\r\n")
                                .await;
                            {
                                let _ = persist_mta_email_review(
                                    runtime,
                                    &review_session,
                                    audit_direction,
                                    audit_class,
                                    dlp_inspection.as_ref(),
                                    EmailReviewAction::Tempfail,
                                    "quarantine_failed",
                                    None,
                                )
                                .await;
                            }
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
                        {
                            let _ = persist_mta_email_review(
                                runtime,
                                &review_session,
                                audit_direction,
                                audit_class,
                                dlp_inspection.as_ref(),
                                EmailReviewAction::Reject,
                                "engine_rejected",
                                None,
                            )
                            .await;
                        }
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

    fn clean_dlp_inspection() -> DlpInspection {
        DlpInspection {
            complete: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_pdf_extraction_gap_reaches_outbound_dlp_fail_safe_without_a_hit() {
        use vigilyx_core::models::{EmailAttachment, EmailSession, Protocol};
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        // The 27-byte prefix and 21-byte noise group are each aligned to a
        // base64 quantum, so concatenation retains a valid encoded fixture.
        let encoded_pdf = format!(
            "JVBERi0xLjcKKFJvdXRpbmUgbm90ZSkgVGoK{}",
            "c3RyZWFtIHN0cmVhbSBzdHJlYW0g".repeat(684)
        );
        session.content.attachments.push(EmailAttachment {
            filename: "routine.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: 27 + 21 * 684,
            hash: "synthetic".to_string(),
            content_base64: Some(encoded_pdf),
        });
        let inspection = run_dlp_scan(&session);
        assert!(
            inspection.is_empty(),
            "coverage is not a sensitive-data belief"
        );
        assert!(!inspection.complete);
        assert!(!outbound_dlp_scan_is_clean(&inspection, 3));
    }

    #[tokio::test]
    async fn test_bounded_dlp_success_preserves_complete_clean_result() {
        let limiter = Arc::new(Semaphore::new(1));
        let inspection = run_bounded_dlp_task(Arc::clone(&limiter), Duration::from_secs(1), || {
            clean_dlp_inspection
        })
        .await;
        assert!(outbound_dlp_scan_is_clean(&inspection, 3));
        assert_eq!(limiter.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_bounded_dlp_queue_timeout_is_incomplete_without_constructing_job() {
        use std::sync::atomic::AtomicBool;
        let limiter = Arc::new(Semaphore::new(1));
        let _occupied = Arc::clone(&limiter).acquire_owned().await.unwrap();
        let constructed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&constructed);
        let inspection = run_bounded_dlp_task(limiter, Duration::from_millis(20), move || {
            marker.store(true, Ordering::SeqCst);
            clean_dlp_inspection
        })
        .await;
        assert!(!constructed.load(Ordering::SeqCst));
        assert!(!inspection.complete);
        assert!(inspection.result.is_empty());
        assert!(!outbound_dlp_scan_is_clean(&inspection, 3));
    }

    #[tokio::test]
    async fn test_timed_out_dlp_worker_holds_permit_until_actual_exit() {
        use std::sync::atomic::AtomicBool;
        let limiter = Arc::new(Semaphore::new(1));
        let worker_limiter = Arc::clone(&limiter);
        let (release, wait_for_release) = std::sync::mpsc::channel::<()>();
        let (started, wait_for_start) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(async move {
            run_bounded_dlp_task(worker_limiter, Duration::from_millis(50), || {
                move || {
                    let _ = started.send(());
                    // Block without CPU load. Dropping release also unblocks the
                    // worker, including when this test exits unexpectedly.
                    let _ = wait_for_release.recv();
                    clean_dlp_inspection()
                }
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), wait_for_start)
            .await
            .unwrap()
            .unwrap();
        let timed_out = caller.await.unwrap();
        let available_before_exit = limiter.available_permits();
        let constructed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&constructed);
        let queued =
            run_bounded_dlp_task(Arc::clone(&limiter), Duration::from_millis(20), move || {
                marker.store(true, Ordering::SeqCst);
                clean_dlp_inspection
            })
            .await;
        let second_job_started = constructed.load(Ordering::SeqCst);
        release.send(()).unwrap();
        let returned_permit = tokio::time::timeout(Duration::from_secs(1), limiter.acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(returned_permit);

        assert!(!timed_out.complete);
        assert_eq!(available_before_exit, 0);
        assert!(!queued.complete);
        assert!(!second_job_started);
    }

    #[tokio::test]
    async fn test_panicking_dlp_worker_is_incomplete_and_releases_permit() {
        let limiter = Arc::new(Semaphore::new(1));
        let inspection = run_bounded_dlp_task(Arc::clone(&limiter), Duration::from_secs(1), || {
            || -> DlpInspection { panic!("synthetic worker failure") }
        })
        .await;
        assert!(!inspection.complete);
        assert!(!outbound_dlp_scan_is_clean(&inspection, 3));
        // A slow panic hook can outlive the caller's inspection timeout.
        // The worker must retain its permit until unwinding actually ends.
        let returned_permit =
            tokio::time::timeout(Duration::from_secs(5), Arc::clone(&limiter).acquire_owned())
                .await
                .expect("panicking DLP worker must eventually release its permit")
                .unwrap();
        drop(returned_permit);
        assert_eq!(limiter.available_permits(), 1);
    }

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

    fn test_tls_acceptor() -> TlsAcceptor {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["vigilyx-mta-test.example".to_string()])
                .expect("test certificate generation should succeed");
        let certs = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions should be available")
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
