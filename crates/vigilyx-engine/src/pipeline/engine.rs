use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

#[cfg(test)]
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, Semaphore, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use vigilyx_core::models::{
    EmailAuditClass, EmailReviewAction, EmailReviewDirection, EmailSession, HttpSession, Protocol,
    SessionSource, WsMessage, classify_mail_direction, email_domain, is_internal_to_external,
    is_ip_in_cidrs,
};
use vigilyx_core::security::{
    InlineVerdictResponse, SecurityVerdict, ThreatLevel, VerdictDisposition,
};
use vigilyx_db::VigilDb;

use crate::alert::AlertEngine;
use crate::config::PipelineConfig;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::ioc::IocManager;
use crate::metrics::EngineMetrics;
use crate::modules::registry::build_module_registry;
use crate::orchestrator::{
    MODULE_DEPENDENCY_UNAVAILABLE_CATEGORY, MODULE_EXECUTION_FAILED_CATEGORY,
    MODULE_EXECUTION_TIMEOUT_CATEGORY, PipelineOrchestrator,
};
use crate::temporal::temporal_analyzer::TemporalAnalyzer;
use crate::whitelist::WhitelistManager;
use vigilyx_soar::disposition::DispositionEngine;

use super::internal_domains::{load_internal_domains, refresh_internal_domains};
use super::post_verdict::{PostVerdictContext, run_post_verdict};
use crate::data_security::email_dlp::scan_email;
use crate::data_security::email_review::{
    build_email_review_with_class, build_webmail_email_review, classify_and_scan_webmail_email,
};

#[cfg(test)]
type MessageDedupKey = (String, [u8; 32]);

/// Synchronous MTA work is intentionally bounded to local detectors. Remote
/// NLP/intel/landing-page work is run by the full pipeline after SMTP has
/// received a provisional, evidence-based response.
const INLINE_MAX_PRIORITY: u8 = 90;
const DEFAULT_INLINE_WORKERS: usize = 4;
const MAX_INLINE_WORKERS: usize = 64;
const LARGE_YARA_PACK_RULES: usize = 10_000;
const MAX_EMAIL_PIPELINE_CONCURRENCY: usize = 1_024;

fn resolve_inline_workers(configured: Option<&str>) -> usize {
    configured
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| (1..=MAX_INLINE_WORKERS).contains(value))
        .unwrap_or(DEFAULT_INLINE_WORKERS)
}

fn configured_inline_workers() -> (usize, bool) {
    let configured = std::env::var("ENGINE_INLINE_WORKERS").ok();
    let workers = resolve_inline_workers(configured.as_deref());
    let configured_override = configured
        .as_deref()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|value| (1..=MAX_INLINE_WORKERS).contains(&value));
    (workers, configured_override)
}

fn resolve_email_pipeline_concurrency(
    cpu_count: usize,
    pack_rule_floor: usize,
    configured: Option<&str>,
) -> usize {
    let cpu_count = cpu_count.max(1);
    let default = if pack_rule_floor >= LARGE_YARA_PACK_RULES {
        // A large native signature pack makes every attachment pipeline
        // materially CPU/memory-bandwidth bound. Keep the default near the
        // physical CPU budget instead of the former 6x I/O oversubscription.
        cpu_count.clamp(2, 64)
    } else {
        cpu_count
            .saturating_mul(6)
            .clamp(8, MAX_EMAIL_PIPELINE_CONCURRENCY)
    };

    configured
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| (1..=MAX_EMAIL_PIPELINE_CONCURRENCY).contains(value))
        .unwrap_or(default)
}

fn configured_email_pipeline_concurrency() -> (usize, usize, usize, bool) {
    let cpu_count = num_cpus::get().max(1);
    let pack_rule_floor = std::env::var("YARA_PACK_MIN_RULES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let configured = std::env::var("ENGINE_MAX_CONCURRENT_EMAILS").ok();
    let max_concurrent =
        resolve_email_pipeline_concurrency(cpu_count, pack_rule_floor, configured.as_deref());
    let configured_override = configured
        .as_deref()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|value| (1..=MAX_EMAIL_PIPELINE_CONCURRENCY).contains(&value));
    (
        max_concurrent,
        cpu_count,
        pack_rule_floor,
        configured_override,
    )
}

fn inline_delivery_disposition(
    threat_level: ThreatLevel,
    inspection_incomplete: bool,
    quarantine_threshold: ThreatLevel,
    reject_threshold: ThreatLevel,
) -> VerdictDisposition {
    VerdictDisposition::from_threat_and_coverage(
        threat_level,
        inspection_incomplete,
        quarantine_threshold,
        reject_threshold,
    )
}

fn configured_mirror_trusted_sources() -> Vec<String> {
    let raw = std::env::var("OUTBOUND_SMTP_RELAY_IPS")
        .or_else(|_| std::env::var("MTA_TRUSTED_UPSTREAM_CIDRS"))
        .unwrap_or_default();
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// A database-backed historical rescan is marked as `Import` so it bypasses
/// the live-hop and recent-session filters. Its email review must still retain
/// the original mirror source; otherwise the rescan would never repair the
/// mirror review row that triggered it.
fn mirror_review_session(session: &EmailSession) -> Option<EmailSession> {
    if session.protocol != Protocol::Smtp {
        return None;
    }

    match session.source {
        SessionSource::Sniffer => Some(session.clone()),
        SessionSource::Import => {
            let mut review_session = session.clone();
            review_session.source = SessionSource::Sniffer;
            Some(review_session)
        }
        SessionSource::MtaProxy => None,
    }
}

/// Mirror mode has no SMTP AUTH trust boundary of its own. A local MAIL FROM
/// from a configured relay/client source is outbound; a local-looking sender
/// elsewhere is retained as unknown rather than silently treated as safe.
fn mirror_review_direction(
    session: &EmailSession,
    local_domains: &[String],
) -> Option<(EmailReviewDirection, EmailAuditClass)> {
    if session.protocol != Protocol::Smtp || session.source != SessionSource::Sniffer {
        return None;
    }

    let trusted_sources = configured_mirror_trusted_sources();
    let trusted_submitter =
        !trusted_sources.is_empty() && is_ip_in_cidrs(&session.client_ip, &trusted_sources);
    // STARTTLS/implicit TLS can expose a session before SMTP envelope fields
    // are visible. Preserve that observation as an attribution-pending audit
    // row so encrypted traffic is never silently counted as benign or lost
    // from the coverage view. It is deliberately not promoted to outbound.
    if session.content.is_encrypted && session.mail_from.is_none() {
        return Some((
            EmailReviewDirection::Unknown,
            EmailAuditClass::AttributionPending,
        ));
    }
    if !is_internal_to_external(
        session.mail_from.as_deref(),
        &session.rcpt_to,
        local_domains,
    ) {
        return None;
    }

    // Trust changes the attribution/enforcement label only. It must never
    // suppress the audit row for an envelope that is internal-to-external.
    let review_direction = if trusted_submitter {
        EmailReviewDirection::from(classify_mail_direction(
            session.mail_from.as_deref(),
            &session.rcpt_to,
            local_domains,
            true,
        ))
    } else {
        EmailReviewDirection::Unknown
    };
    let audit_class = if trusted_submitter {
        EmailAuditClass::ConfirmedOutbound
    } else {
        EmailAuditClass::OutboundCandidate
    };
    Some((review_direction, audit_class))
}

async fn persist_mirror_email_review(
    db: &VigilDb,
    session: &EmailSession,
    local_domains: &[String],
    inspect_content: bool,
) -> Result<bool, String> {
    let Some(review_session) = mirror_review_session(session) else {
        return Ok(false);
    };
    let Some((direction, audit_class)) = mirror_review_direction(&review_session, local_domains)
    else {
        return Ok(false);
    };
    let inspection = inspect_content.then(|| scan_email(&review_session));
    let review = build_email_review_with_class(
        &review_session,
        direction,
        audit_class,
        local_domains,
        inspection.as_ref(),
        EmailReviewAction::Audit,
        Some("mirror_audit".to_string()),
        None,
    );
    if let Err(error) = db.upsert_email_data_security_review(&review).await {
        error!(session_id = %session.id, %error, "Failed to persist mirror outbound email review");
        return Err(error.to_string());
    }
    if let Some(incident) =
        crate::data_security::email_review::build_transfer_incident(&review, inspection.as_ref())
    {
        db.insert_data_security_incident(&incident)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(true)
}

fn normalize_mailbox(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch| ch == '<' || ch == '>')
        .to_ascii_lowercase()
}

fn has_authenticated_sender_identity(session: &EmailSession) -> bool {
    let Some(mail_from) = session.mail_from.as_deref() else {
        return false;
    };
    let Some(auth) = session.auth_info.as_ref() else {
        return false;
    };
    if auth.auth_success != Some(true) {
        return false;
    }
    auth.username.as_deref().is_some_and(|username| {
        let username = normalize_mailbox(username);
        !username.is_empty() && username == normalize_mailbox(mail_from)
    })
}

async fn session_has_authenticated_whitelist_bypass(
    session: &EmailSession,
    whitelist_manager: &WhitelistManager,
) -> bool {
    // A sender domain and source IP are both attacker-influenceable when mail
    // arrives through a shared upstream gateway. Never let that pair bypass
    // content inspection. Whole-pipeline bypass requires a successfully
    // authenticated identity matching an explicitly trusted mailbox.
    if !has_authenticated_sender_identity(session) {
        return false;
    }
    let Some(mail_from) = session.mail_from.as_deref() else {
        return false;
    };

    let mailbox_ok = whitelist_manager
        .is_trusted_email(&normalize_mailbox(mail_from))
        .await;
    let ip_ok = whitelist_manager
        .is_trusted_ip(&session.client_ip.to_string())
        .await;

    mailbox_ok && ip_ok
}

#[cfg(test)]
fn message_dedup_key(session: &EmailSession) -> Option<MessageDedupKey> {
    let message_id = session
        .message_id
        .as_deref()
        .or_else(|| session.content.get_header("Message-ID"))?
        .trim()
        .trim_matches(|ch| ch == '<' || ch == '>')
        .to_ascii_lowercase();
    if message_id.is_empty() {
        return None;
    }

    fn hash_field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        session.mail_from.as_deref().unwrap_or_default().as_bytes(),
    );
    let mut recipients = session
        .rcpt_to
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    recipients.sort_unstable();
    for recipient in recipients {
        hash_field(&mut hasher, recipient.as_bytes());
    }
    hash_field(
        &mut hasher,
        session.subject.as_deref().unwrap_or_default().as_bytes(),
    );
    for (name, value) in &session.content.headers {
        // Relay-generated headers (Received, X-* stamps, Authentication-
        // Results, Delivered-To, DKIM/ARC) change at every gateway. Keep only
        // message-level headers that are useful as a content guard; the
        // Message-ID and body/attachment digest remain the primary identity.
        let stable_header = matches!(
            name.to_ascii_lowercase().as_str(),
            "date"
                | "from"
                | "to"
                | "cc"
                | "mime-version"
                | "content-type"
                | "content-transfer-encoding"
                | "in-reply-to"
                | "references"
        );
        if stable_header {
            hash_field(&mut hasher, name.to_ascii_lowercase().as_bytes());
            hash_field(&mut hasher, value.as_bytes());
        }
    }
    hash_field(
        &mut hasher,
        session
            .content
            .body_text
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        session
            .content
            .body_html
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    for attachment in &session.content.attachments {
        hash_field(&mut hasher, attachment.hash.as_bytes());
        hash_field(&mut hasher, attachment.filename.as_bytes());
        hash_field(&mut hasher, &(attachment.size as u64).to_be_bytes());
    }
    hash_field(&mut hasher, &[u8::from(session.content.is_complete)]);

    Some((message_id, hasher.finalize().into()))
}

fn delivery_fingerprint(session: &EmailSession) -> Option<String> {
    // Delivery correlation is intentionally less strict than security
    // de-duplication.  Gateways commonly rewrite the body, MIME boundaries,
    // Received/Auth headers, or attachment presentation while forwarding the
    // same message.  Those changes must not split one delivery chain into
    // unrelated messages.  Keep `message_dedup_key` content-bound for
    // security analysis; this identity is only for hop correlation.
    let message_id = session
        .message_id
        .as_deref()
        .or_else(|| session.content.get_header("Message-ID"))
        .filter(|value| !value.trim().is_empty());

    let sender = session
        .mail_from
        .as_deref()
        .or_else(|| session.content.get_header("From"));
    vigilyx_core::models::delivery_fingerprint_from_parts(message_id, sender)
}

fn is_mirror_inbound_session(session: &EmailSession, local_domains: &HashSet<String>) -> bool {
    if session.protocol != Protocol::Smtp || session.source != SessionSource::Sniffer {
        return false;
    }

    let has_local_recipient = session.rcpt_to.iter().any(|recipient| {
        email_domain(recipient).is_some_and(|domain| local_domains.contains(&domain))
    });
    if !has_local_recipient {
        return false;
    }

    // Keep the existing untrusted-mirror direction policy: a local-looking
    // MAIL FROM is still treated as inbound when it arrived over an
    // unauthenticated mirrored connection, so spoofing cannot escape review.
    let local_domains = local_domains.iter().cloned().collect::<Vec<_>>();
    classify_mail_direction(
        session.mail_from.as_deref(),
        &session.rcpt_to,
        &local_domains,
        false,
    ) == vigilyx_core::models::MailDirection::Inbound
}

struct InlineProcessorContext {
    inline_orchestrator: Arc<PipelineOrchestrator>,
    full_orchestrator: Arc<PipelineOrchestrator>,
    config: Arc<PipelineConfig>,
    engine_db: VigilDb,
    ioc_manager: IocManager,
    whitelist_manager: WhitelistManager,
    disposition_engine: DispositionEngine,
    metrics: EngineMetrics,
    temporal_analyzer: Arc<TemporalAnalyzer>,
    alert_engine: Arc<AlertEngine>,
    ws_tx: broadcast::Sender<WsMessage>,
    internal_domains: Arc<RwLock<HashSet<String>>>,
    temporal_semaphore: Arc<Semaphore>,
    verdict_count: Arc<AtomicU64>,
    full_semaphore: Arc<Semaphore>,
}

/// Process one MTA request independently from the dispatcher. A bounded
/// semaphore in `run_loop` limits the number of these tasks, so a slow inline
/// scan cannot stall passive sessions or later SMTP requests.
async fn process_inline_request(
    request: InlineVerdictRequest,
    ctx: InlineProcessorContext,
    inline_permit: tokio::sync::OwnedSemaphorePermit,
) {
    let InlineVerdictRequest {
        session: raw_session,
        respond_to,
        deadline,
        quarantine_threshold,
        reject_threshold,
    } = request;
    let start = Instant::now();
    let session = Arc::new(raw_session);
    let session_id = session.id;
    let remaining = deadline.saturating_duration_since(Instant::now());

    if remaining.is_zero() {
        warn!(session_id = %session_id, "Inline verdict deadline already expired");
        let _ = respond_to.send(InlineVerdictResponse {
            disposition: VerdictDisposition::Tempfail,
            threat_level: ThreatLevel::Safe,
            confidence: 0.0,
            summary: "Security analysis timed out — conservative verdict applied (deadline already expired)".into(),
            session_id,
            modules_run: 0,
            modules_flagged: 0,
            duration_ms: 0,
        });
        return;
    }

    if session_has_authenticated_whitelist_bypass(session.as_ref(), &ctx.whitelist_manager).await {
        info!(
            session_id = %session_id,
            mail_from = session.mail_from.as_deref().unwrap_or(""),
            client_ip = %session.client_ip,
            "Skipping whitelisted SMTP inline session"
        );
        let _ = respond_to.send(InlineVerdictResponse {
            disposition: VerdictDisposition::Accept,
            threat_level: ThreatLevel::Safe,
            confidence: 1.0,
            summary: "Session bypassed by whitelist".into(),
            session_id,
            modules_run: 0,
            modules_flagged: 0,
            duration_ms: start.elapsed().as_millis() as u64,
        });
        return;
    }

    let domains_snapshot = Arc::new(ctx.internal_domains.read().await.clone());
    let security_ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot);
    let inline_outcome = ctx
        .inline_orchestrator
        .execute_with_timeout(&security_ctx, remaining)
        .await;
    if inline_outcome.timed_out {
        warn!(
            session_id = %session_id,
            timeout_ms = remaining.as_millis() as u64,
            "Inline verdict hit deadline before full analysis completed"
        );
        let _ = respond_to.send(InlineVerdictResponse {
            disposition: VerdictDisposition::Tempfail,
            threat_level: ThreatLevel::Safe,
            confidence: 0.0,
            summary: format!(
                "Security analysis timed out — conservative verdict applied (full pipeline incomplete after {}ms)",
                remaining.as_millis()
            ),
            session_id,
            modules_run: 0,
            modules_flagged: 0,
            duration_ms: start.elapsed().as_millis() as u64,
        });
        return;
    }
    if let Some(reason) = inline_outcome.disposition_incomplete_summary() {
        let dependency_followup = inline_outcome.timed_out_modules.is_empty()
            && inline_outcome.results.values().any(|result| {
                result
                    .categories
                    .iter()
                    .any(|category| category == MODULE_DEPENDENCY_UNAVAILABLE_CATEGORY)
            });
        warn!(
            session_id = %session_id,
            reason = %reason,
            "Inline verdict pipeline did not complete successfully"
        );
        let _ = respond_to.send(InlineVerdictResponse {
            disposition: VerdictDisposition::Tempfail,
            threat_level: ThreatLevel::Safe,
            confidence: 0.0,
            summary: format!("Security analysis incomplete — temporary failure ({reason})"),
            session_id,
            modules_run: inline_outcome.results.len() as u32,
            modules_flagged: inline_outcome
                .results
                .values()
                .filter(|result| result.threat_level > ThreatLevel::Safe)
                .count() as u32,
            duration_ms: start.elapsed().as_millis() as u64,
        });
        drop(inline_permit);
        if dependency_followup {
            run_inline_full_followup(session, ctx).await;
        }
        return;
    }
    let results = inline_outcome.results;

    let verdict_result = crate::verdict::aggregate_verdict_with_session(
        Some(session.as_ref()),
        session_id,
        &results,
        &ctx.config.verdict_config,
    );
    let disposition = inline_delivery_disposition(
        verdict_result.threat_level,
        crate::verdict::has_incomplete_inspection(&verdict_result),
        quarantine_threshold,
        reject_threshold,
    );
    let response = InlineVerdictResponse {
        disposition,
        threat_level: verdict_result.threat_level,
        confidence: verdict_result.confidence,
        summary: verdict_result.summary.clone(),
        session_id,
        modules_run: verdict_result.modules_run,
        modules_flagged: verdict_result.modules_flagged,
        duration_ms: start.elapsed().as_millis() as u64,
    };

    info!(
        session_id = %session_id,
        threat_level = %verdict_result.threat_level,
        disposition = %response.disposition,
        duration_ms = response.duration_ms,
        "Inline verdict produced"
    );
    let _ = respond_to.send(response);

    // The SMTP client has its answer. Release the inline slot before waiting
    // for the durable full-pipeline follow-up, otherwise slow NLP/intel work
    // would consume the SMTP worker budget.
    drop(inline_permit);

    run_inline_full_followup(session, ctx).await;
}

/// Persist and analyze an MTA message after its inline result is handed to the
/// SMTP handler. Later analysis is for audit and UI visibility; it never
/// changes the delivery action selected from the inline result.
async fn run_inline_full_followup(session: Arc<EmailSession>, ctx: InlineProcessorContext) {
    let session_id = session.id;
    if let Err(e) = ctx.engine_db.insert_session(&session).await {
        error!(session_id = %session_id, "Failed to store MTA session: {e}");
    }

    let permit = match Arc::clone(&ctx.full_semaphore).acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            warn!(session_id = %session_id, "Full MTA follow-up skipped: pipeline semaphore closed");
            return;
        }
    };
    let pv = Arc::new(PostVerdictContext {
        db: ctx.engine_db,
        ioc: ctx.ioc_manager,
        disposition: ctx.disposition_engine,
        metrics: ctx.metrics,
        temporal: ctx.temporal_analyzer,
        alert: ctx.alert_engine,
        ws_tx: ctx.ws_tx,
        verdict_count: ctx.verdict_count,
        temporal_semaphore: ctx.temporal_semaphore,
        temporal_flush_interval: SecurityEngine::TEMPORAL_FLUSH_INTERVAL,
        internal_domains: ctx.internal_domains,
    });
    run_full_pipeline(ctx.full_orchestrator, ctx.config, session, pv).await;
    drop(permit);
}

/// Run the complete passive pipeline for a session. MTA inline requests call
/// this in the background after their bounded fast-tier response, ensuring
/// slow modules still contribute to the durable verdict and UI evidence.
async fn run_full_pipeline(
    orchestrator: Arc<PipelineOrchestrator>,
    config: Arc<PipelineConfig>,
    session: Arc<EmailSession>,
    pv_ctx: Arc<PostVerdictContext>,
) {
    let session_id = session.id;
    info!(session_id = %session_id, "Processing session through full security pipeline");
    pv_ctx.metrics.record_session_start();

    let domains_snapshot = Arc::new(pv_ctx.internal_domains.read().await.clone());
    let ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot.clone());
    let pipeline_outcome = orchestrator.execute_outcome(&ctx).await;
    let execution_incomplete = pipeline_outcome.disposition_incomplete_summary();
    let results = pipeline_outcome.results;

    for (module_id, result) in &results {
        let failed = result
            .categories
            .iter()
            .any(|category| category == MODULE_EXECUTION_FAILED_CATEGORY);
        let timed_out = result
            .categories
            .iter()
            .any(|category| category == MODULE_EXECUTION_TIMEOUT_CATEGORY);
        let dependency_unavailable = result
            .categories
            .iter()
            .any(|category| category == MODULE_DEPENDENCY_UNAVAILABLE_CATEGORY);
        pv_ctx
            .metrics
            .record_module_run(
                module_id,
                result.duration_ms,
                !failed && !timed_out && !dependency_unavailable,
                timed_out,
            )
            .await;
    }

    let mut verdict_result = crate::verdict::aggregate_verdict_with_session(
        Some(session.as_ref()),
        session_id,
        &results,
        &config.verdict_config,
    );
    if let Some(reason) = execution_incomplete.as_deref() {
        crate::verdict::apply_incomplete_inspection_policy(
            &mut verdict_result,
            session.source,
            "inspection_execution_incomplete",
            reason,
        );
    }

    info!(
        session_id = %session_id,
        threat_level = %verdict_result.threat_level,
        modules_run = verdict_result.modules_run,
        modules_flagged = verdict_result.modules_flagged,
        duration_ms = verdict_result.total_duration_ms,
        "Full security verdict produced"
    );

    if let Err(e) = pv_ctx.db.insert_session(&session).await {
        error!(session_id = %session_id, "Failed to persist session: {e}");
    }
    if session.protocol == Protocol::Smtp
        && matches!(
            session.source,
            SessionSource::Sniffer | SessionSource::Import
        )
    {
        let mut local_domains = domains_snapshot.iter().cloned().collect::<Vec<_>>();
        local_domains.sort_unstable();
        let _ = persist_mirror_email_review(&pv_ctx.db, &session, &local_domains, true).await;
    }
    run_post_verdict(&pv_ctx, &session, &verdict_result, &results).await;
}

async fn wait_for_first_hop_verdict(
    db: &VigilDb,
    first_session_id: Uuid,
) -> anyhow::Result<Option<SecurityVerdict>> {
    for attempt in 0..40 {
        if let Some(verdict) = db.get_verdict_by_session(first_session_id).await? {
            return Ok(Some(verdict));
        }
        if attempt < 39 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
    Ok(None)
}

/// A first hop captured incompletely must not hand its coverage gap to a
/// downstream hop that holds the complete message; that copy is analyzed.
fn downstream_hop_needs_own_analysis(
    first_verdict: &SecurityVerdict,
    session: &EmailSession,
) -> bool {
    first_verdict.has_incomplete_inspection()
        && session.content.is_complete
        && !session.content.truncated
}

async fn run_reused_or_fallback_delivery(
    orchestrator: Arc<PipelineOrchestrator>,
    config: Arc<PipelineConfig>,
    session: Arc<EmailSession>,
    pv_ctx: Arc<PostVerdictContext>,
    first_session_id: Uuid,
    semaphore: Arc<Semaphore>,
) {
    async fn native_fallback(
        orchestrator: Arc<PipelineOrchestrator>,
        config: Arc<PipelineConfig>,
        session: Arc<EmailSession>,
        pv_ctx: Arc<PostVerdictContext>,
        semaphore: Arc<Semaphore>,
    ) {
        let Ok(permit) = semaphore.acquire_owned().await else {
            warn!(session_id = %session.id, "Downstream fallback skipped: pipeline semaphore closed");
            return;
        };
        let _permit = permit;
        run_full_pipeline(orchestrator, config, session, pv_ctx).await;
    }

    match wait_for_first_hop_verdict(&pv_ctx.db, first_session_id).await {
        Ok(Some(first_verdict)) if downstream_hop_needs_own_analysis(&first_verdict, &session) => {
            info!(
                session_id = %session.id,
                first_session_id = %first_session_id,
                "First-hop verdict has limited coverage; analyzing complete downstream hop"
            );
            native_fallback(orchestrator, config, session, pv_ctx, semaphore).await;
        }
        Ok(Some(_first_verdict)) => {
            if let Err(error) = pv_ctx.db.insert_session(&session).await {
                error!(
                    session_id = %session.id,
                    %error,
                    "Failed to persist downstream delivery hop before verdict reuse"
                );
                native_fallback(orchestrator, config, session, pv_ctx, semaphore).await;
                return;
            }
            match pv_ctx
                .db
                .insert_reused_first_hop_verdict(session.id, first_session_id)
                .await
            {
                Ok(_) => {
                    if let Err(error) = pv_ctx
                        .db
                        .mark_email_delivery_hop_reused(session.id, first_session_id)
                        .await
                    {
                        error!(
                            session_id = %session.id,
                            %error,
                            "Failed to mark downstream delivery hop as verdict reuse"
                        );
                    }
                    info!(
                        session_id = %session.id,
                        first_session_id = %first_session_id,
                        "Reused first-hop verdict for downstream delivery hop"
                    );
                }
                Err(error) => {
                    warn!(
                        session_id = %session.id,
                        first_session_id = %first_session_id,
                        %error,
                        "First-hop verdict reuse failed; falling back to native analysis"
                    );
                    native_fallback(orchestrator, config, session, pv_ctx, semaphore).await;
                }
            }
        }
        Ok(None) => {
            warn!(
                session_id = %session.id,
                first_session_id = %first_session_id,
                "First-hop verdict unavailable after bounded wait; running downstream fallback analysis"
            );
            native_fallback(orchestrator, config, session, pv_ctx, semaphore).await;
        }
        Err(error) => {
            warn!(
                session_id = %session.id,
                first_session_id = %first_session_id,
                %error,
                "Failed to read first-hop verdict; running downstream fallback analysis"
            );
            native_fallback(orchestrator, config, session, pv_ctx, semaphore).await;
        }
    }
}

// MTA Inline Verdict - (oneshot, vigilyx-core)

/// MTA inline (, tokio oneshot channel)
pub struct InlineVerdictRequest {
    pub session: EmailSession,
    pub respond_to: oneshot::Sender<InlineVerdictResponse>,
    pub deadline: Instant,

    pub quarantine_threshold: ThreatLevel,

    pub reject_threshold: ThreatLevel,
}

/// The main security engine: receives email sessions, runs the pipeline, stores verdicts.
pub struct SecurityEngine {
    tx: mpsc::Sender<EmailSession>,
    inline_tx: mpsc::Sender<InlineVerdictRequest>,
    pub engine_db: VigilDb,
    pub ioc_manager: IocManager,
    pub whitelist_manager: WhitelistManager,
    pub disposition_engine: DispositionEngine,
    pub metrics: EngineMetrics,
    pub temporal_analyzer: Arc<TemporalAnalyzer>,
    pub alert_engine: Arc<AlertEngine>,
    /// Current internal-domain snapshot shared by threat analysis and the
    /// pre-ACK email audit adapters.
    internal_domains: Arc<RwLock<HashSet<String>>>,
    /// Safe-domain cache handle for runtime IOC reload (None if intel disabled).
    pub safe_domains_handle: Option<crate::modules::registry::SafeDomainsHandle>,
}

impl SecurityEngine {
    /// Create and start the security engine.
    /// Returns the engine handle (for sending sessions) and spawns the background processor.
    pub async fn start(
        db: VigilDb,
        pipeline_config: PipelineConfig,
        ws_tx: broadcast::Sender<WsMessage>,
    ) -> Result<Self, EngineError> {
        let (tx, rx) = mpsc::channel::<EmailSession>(10_000);
        let (inline_tx, inline_rx) = mpsc::channel::<InlineVerdictRequest>(500);

        // Schema ownership belongs to the one-shot postgres-migrate service.
        // Runtime API/engine/MTA roles are intentionally non-owners and must
        // never attempt DDL during startup.
        let engine_db = db;
        // Parameters are versioned independently of the immutable pipeline.
        // Polling also covers an MTA process and missed Pub/Sub reload notices.
        if let Err(error) = crate::ds_learning::reload_from_db(&engine_db).await {
            warn!(%error, "DS parameters rejected; retaining last valid model");
        }
        let ds_parameter_db = engine_db.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut ticks = 0_u64;
            loop {
                timer.tick().await;
                if ticks.is_multiple_of(5)
                    && let Err(error) =
                        crate::ds_learning::refresh_candidate(&ds_parameter_db).await
                {
                    warn!(%error, "DS candidate refresh failed; retrying on the next interval");
                }
                ticks = ticks.wrapping_add(1);
                if let Err(error) = crate::ds_learning::reload_from_db(&ds_parameter_db).await {
                    warn!(%error, "DS parameter reload rejected; retaining last valid model");
                }
            }
        });
        match engine_db.seed_system_whitelist().await {
            Ok(n) if n > 0 => info!(
                "System whitelist seed applied: {} rows inserted/refreshed",
                n
            ),
            Ok(_) => info!("System whitelist seed already up to date"),
            Err(e) => warn!("Failed to seed system whitelist: {}", e),
        }

        // Initialize subsystems
        let ioc_manager = IocManager::new(engine_db.clone());
        let whitelist_manager = WhitelistManager::new(engine_db.clone());
        let disposition_engine = DispositionEngine::new(engine_db.clone());
        let metrics = EngineMetrics::new();

        // Initialize temporal analyzer (Phase 3)
        let temporal_analyzer = Arc::new(TemporalAnalyzer::new());

        // Load temporal state from DB
        match (
            engine_db.load_cusum_states().await,
            engine_db.load_ewma_states().await,
            engine_db.load_entity_risk_states().await,
        ) {
            (Ok(cusum), Ok(ewma), Ok(entity)) => {
                let total = cusum.len() + ewma.len() + entity.len();
                if total > 0 {
                    temporal_analyzer.import_states(cusum, ewma, entity).await;
                    info!(total_states = total, "Loaded temporal state from DB");
                }
            }
            _ => {
                warn!("Failed to load some temporal states from DB, starting fresh");
            }
        }

        // Initialize alert engine (Phase 4)
        let alert_engine = Arc::new(AlertEngine::new());

        // Load whitelist cache
        if let Err(e) = whitelist_manager.load().await {
            warn!("Failed to load whitelist cache: {}", e);
        }

        // AutodetectInternalDomain(From DB ConfigurationLoad, Firstdetect)
        let internal_domains = Arc::new(RwLock::new(load_internal_domains(&engine_db).await));

        // Build module registry (async: loads source config from DB)
        let (modules, safe_domains_handle) = build_module_registry(&engine_db).await;

        // detectwhether AI Module (supports_ai && is_remote)
        let has_ai = modules
            .values()
            .any(|m| m.metadata().supports_ai && m.metadata().is_remote);
        metrics.set_ai_available(has_ai);
        if has_ai {
            info!("AI service detected (NLP modules ready)");
        }

        // Build orchestrator
        let orchestrator = PipelineOrchestrator::build(&modules, &pipeline_config)?;
        let inline_orchestrator =
            PipelineOrchestrator::build_inline(&modules, &pipeline_config, INLINE_MAX_PRIORITY)?;

        // Clone subsystems for background task
        let bg_engine_db = engine_db.clone();
        let bg_ioc = ioc_manager.clone();
        let bg_whitelist = whitelist_manager.clone();
        let bg_disposition = disposition_engine.clone();
        let bg_metrics = metrics.clone();
        let bg_temporal = Arc::clone(&temporal_analyzer);
        let bg_alert = Arc::clone(&alert_engine);
        let bg_internal_domains = Arc::clone(&internal_domains);

        // Spawn background processor
        tokio::spawn(async move {
            Self::run_loop(
                rx,
                inline_rx,
                orchestrator,
                inline_orchestrator,
                pipeline_config,
                bg_engine_db,
                bg_ioc,
                bg_whitelist,
                bg_disposition,
                bg_metrics,
                bg_temporal,
                bg_alert,
                ws_tx,
                bg_internal_domains,
            )
            .await;
        });

        info!("Security engine started");
        Ok(Self {
            tx,
            inline_tx,
            engine_db,
            ioc_manager,
            whitelist_manager,
            disposition_engine,
            metrics,
            temporal_analyzer,
            alert_engine,
            safe_domains_handle,
            internal_domains,
        })
    }

    /// Persist the mirror-mode outbound audit before the Redis Stream entry is
    /// acknowledged.  The predicate is envelope-based; source trust only
    /// chooses confirmed versus candidate classification.
    pub async fn audit_mirror_email(&self, session: &EmailSession) -> Result<bool, EngineError> {
        let domains = self.internal_domains.read().await.clone();
        let mut local_domains = domains.into_iter().collect::<Vec<_>>();
        local_domains.sort_unstable();
        persist_mirror_email_review(&self.engine_db, session, &local_domains, true)
            .await
            .map_err(EngineError::Other)
    }

    /// Persist a Webmail send request in the same review table and with the
    /// same DLP scanner used by SMTP. Non-send HTTP requests return `Ok(false)`
    /// and continue through the existing HTTP detector pipeline.
    pub async fn audit_webmail_email(&self, session: &HttpSession) -> Result<bool, EngineError> {
        let domains = self.internal_domains.read().await.clone();
        let mut local_domains = domains.into_iter().collect::<Vec<_>>();
        local_domains.sort_unstable();
        let Some((audit_class, inspection)) =
            classify_and_scan_webmail_email(session, &local_domains).await
        else {
            return Ok(false);
        };
        let review =
            build_webmail_email_review(session, audit_class, &local_domains, Some(&inspection));
        self.engine_db
            .upsert_email_data_security_review(&review)
            .await
            .map_err(|error| EngineError::Other(error.to_string()))?;
        Ok(true)
    }

    /// Submit a session for security analysis (awaits channel capacity).
    pub async fn submit(&self, session: EmailSession) -> Result<(), EngineError> {
        self.tx
            .send(session)
            .await
            .map_err(|_| EngineError::Other("Engine channel closed".into()))
    }

    /// Submit a session without blocking (returns error if channel is full).

    /// Use this in the import pipeline to avoid stalling the HTTP handler
    /// when the engine can't keep up with incoming session volume.
    pub fn try_submit(&self, session: EmailSession) -> Result<(), EngineError> {
        self.tx.try_send(session).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                EngineError::Other("Engine channel full, session dropped".into())
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                EngineError::Other("Engine channel closed".into())
            }
        })
    }

    /// Submit a session with a timeout - retries briefly instead of immediately dropping.

    /// Provides backpressure without permanently blocking the caller.
    pub async fn submit_with_backoff(&self, session: EmailSession) -> Result<(), EngineError> {
        // First try non-blocking
        match self.tx.try_send(session) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(EngineError::Other("Engine channel closed".into()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
                // Wait up to 2 seconds for capacity
                match tokio::time::timeout(std::time::Duration::from_secs(2), self.tx.send(session))
                    .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(EngineError::Other("Engine channel closed".into())),
                    Err(_) => Err(EngineError::Other(
                        "Engine channel full after 2s backoff, session dropped".into(),
                    )),
                }
            }
        }
    }

    /// Submit a session for synchronous inline verdict (MTA proxy mode).

    /// Blocks until the engine produces a verdict or the timeout expires.
    /// On timeout/error: returns Tempfail so the caller can choose fail-open or fail-closed.
    pub async fn submit_inline(
        &self,
        session: EmailSession,
        timeout: std::time::Duration,
        quarantine_threshold: ThreatLevel,
        reject_threshold: ThreatLevel,
    ) -> InlineVerdictResponse {
        let session_id = session.id;
        let (resp_tx, resp_rx) = oneshot::channel();

        let req = InlineVerdictRequest {
            session,
            respond_to: resp_tx,
            deadline: Instant::now() + timeout,
            quarantine_threshold,
            reject_threshold,
        };

        // Inspection failure is a coverage state, not threat evidence. Keep the
        // evidence-based threat at Safe with zero confidence and enforce the
        // configured fail-open/fail-closed behavior through Tempfail.

        // Try to send request to inline channel
        if self.inline_tx.try_send(req).is_err() {
            warn!(session_id = %session_id, "Inline channel full or closed — unscanned bypass");
            return InlineVerdictResponse {
                disposition: VerdictDisposition::Tempfail,
                threat_level: ThreatLevel::Safe,
                confidence: 0.0,
                summary: "Engine overloaded: inline channel full (unscanned)".into(),
                session_id,
                modules_run: 0,
                modules_flagged: 0,
                duration_ms: 0,
            };
        }

        // Wait for response with timeout
        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                warn!(session_id = %session_id, "Inline verdict channel dropped — unscanned bypass");
                InlineVerdictResponse {
                    disposition: VerdictDisposition::Tempfail,
                    threat_level: ThreatLevel::Safe,
                    confidence: 0.0,
                    summary: "Engine verdict channel dropped (unscanned)".into(),
                    session_id,
                    modules_run: 0,
                    modules_flagged: 0,
                    duration_ms: 0,
                }
            }
            Err(_) => {
                warn!(session_id = %session_id, timeout_secs = timeout.as_secs(), "Inline verdict timeout — unscanned bypass");
                InlineVerdictResponse {
                    disposition: VerdictDisposition::Tempfail,
                    threat_level: ThreatLevel::Safe,
                    confidence: 0.0,
                    summary: format!(
                        "Engine verdict timeout after {}s (unscanned)",
                        timeout.as_secs()
                    ),
                    session_id,
                    modules_run: 0,
                    modules_flagged: 0,
                    duration_ms: 0,
                }
            }
        }
    }

    /// Deduplicate: Same1 session timestamp may be Analyze
    const DEDUP_WINDOW_SECS: u64 = 30;

    /// Temporal state flush interval (every N verdicts).
    const TEMPORAL_FLUSH_INTERVAL: u64 = 50;

    #[allow(clippy::too_many_arguments)]
    async fn run_loop(
        mut rx: mpsc::Receiver<EmailSession>,
        mut inline_rx: mpsc::Receiver<InlineVerdictRequest>,
        orchestrator: PipelineOrchestrator,
        inline_orchestrator: PipelineOrchestrator,
        config: PipelineConfig,
        engine_db: VigilDb,
        ioc_manager: IocManager,
        whitelist_manager: crate::whitelist::WhitelistManager,
        disposition_engine: DispositionEngine,
        metrics: EngineMetrics,
        temporal_analyzer: Arc<TemporalAnalyzer>,
        alert_engine: Arc<AlertEngine>,
        ws_tx: broadcast::Sender<WsMessage>,
        internal_domains: Arc<RwLock<HashSet<String>>>,
    ) {
        // Shared state for concurrent processing
        let orchestrator = Arc::new(orchestrator);
        let inline_orchestrator = Arc::new(inline_orchestrator);
        let config = Arc::new(config);
        // Track (last_analyzed_time, was_completed) to allow re-analysis when
        // a session transitions from Active → Completed with full email content.
        let recent_analyzed: Arc<RwLock<HashMap<Uuid, (Instant, bool)>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let verdict_count = Arc::new(AtomicU64::new(0));

        // Semaphore: bound complete email pipelines. The default stays
        // I/O-oversubscribed without a large signature pack, but switches to
        // a CPU-sized budget once 10k+ governed YARA rules are activated.
        let (max_concurrent, cpu_count, yara_pack_rule_floor, configured_override) =
            configured_email_pipeline_concurrency();
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        info!(
            max_concurrent,
            cpu_count,
            yara_pack_rule_floor,
            configured_override,
            "Engine concurrent pipeline capacity"
        );

        // Limit temporal analysis background tasks (prevent unbounded spawning)
        let temporal_semaphore = Arc::new(Semaphore::new(max_concurrent));

        // InternalDomain New (6 small)
        {
            let domains = internal_domains.clone();
            let db = engine_db.clone();
            tokio::spawn(async move {
                // First New 10 minute(Engine Stable)
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
                loop {
                    interval.tick().await;
                    info!("Refreshing internal domains...");
                    let new_domains = refresh_internal_domains(&db).await;
                    *domains.write().await = new_domains;
                }
            });
        }

        // Threat scene detector (bulk mailing + bounce harvest, every 5 min)
        crate::threat_scene::spawn_scene_detector(
            engine_db.clone(),
            internal_domains.clone(),
            disposition_engine.clone(),
        );

        // JoinSet tracks in-flight per-email tasks for graceful shutdown
        let mut inflight = tokio::task::JoinSet::new();
        let mut dedup_cleanup_counter: u64 = 0;
        let (inline_workers, inline_workers_override) = configured_inline_workers();
        let inline_semaphore = Arc::new(Semaphore::new(inline_workers));
        info!(
            inline_workers,
            inline_workers_override, "Engine inline SMTP worker capacity"
        );

        loop {
            // Select: inline requests have priority (biased)
            let event = tokio::select! {
                biased;
                Some(inline_req) = inline_rx.recv() => Some(Ok(inline_req)),
                Some(session) = rx.recv() => Some(Err(session)),
                else => None,
            };

            let Some(event) = event else { break };
            let session = match event {
                Ok(inline_req) => {
                    let session_id = inline_req.session.id;
                    let deadline = inline_req.deadline;
                    let inline_ctx = InlineProcessorContext {
                        inline_orchestrator: Arc::clone(&inline_orchestrator),
                        full_orchestrator: Arc::clone(&orchestrator),
                        config: Arc::clone(&config),
                        engine_db: engine_db.clone(),
                        ioc_manager: ioc_manager.clone(),
                        whitelist_manager: whitelist_manager.clone(),
                        disposition_engine: disposition_engine.clone(),
                        metrics: metrics.clone(),
                        temporal_analyzer: Arc::clone(&temporal_analyzer),
                        alert_engine: Arc::clone(&alert_engine),
                        ws_tx: ws_tx.clone(),
                        internal_domains: Arc::clone(&internal_domains),
                        temporal_semaphore: Arc::clone(&temporal_semaphore),
                        verdict_count: Arc::clone(&verdict_count),
                        full_semaphore: Arc::clone(&semaphore),
                    };
                    let inline_semaphore = Arc::clone(&inline_semaphore);
                    inflight.spawn(async move {
                        // Queue within the caller's inline deadline instead of
                        // rejecting every burst above the worker count. The
                        // bounded inline channel still provides backpressure;
                        // once the deadline expires, fail closed through the
                        // normal Tempfail path.
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        let inline_permit =
                            match tokio::time::timeout(remaining, inline_semaphore.acquire_owned())
                                .await
                            {
                                Ok(Ok(permit)) => permit,
                                _ => {
                                    warn!(
                                        session_id = %session_id,
                                        "Inline worker queue deadline exceeded"
                                    );
                                    let _ = inline_req.respond_to.send(InlineVerdictResponse {
                                        disposition: VerdictDisposition::Tempfail,
                                        threat_level: ThreatLevel::Safe,
                                        confidence: 0.0,
                                        summary:
                                            "Security analysis temporarily overloaded — retry later"
                                                .into(),
                                        session_id,
                                        modules_run: 0,
                                        modules_flagged: 0,
                                        duration_ms: 0,
                                    });
                                    return;
                                }
                            };
                        process_inline_request(inline_req, inline_ctx, inline_permit).await;
                    });
                    continue;
                }
                Err(session) => session,
            };

            let session = Arc::new(session);
            let session_id = session.id;

            // Record mirror SMTP coverage independently of the inbound-hop
            // filter below. That filter selects which hop receives the full
            // threat pipeline; it must never suppress the outbound DLP audit.
            // Run the shared scan here so a non-target relay hop cannot leave
            // a permanent `content_scan_not_run` placeholder behind. The full
            // pipeline may upsert the same session later with richer context.
            if session.protocol == Protocol::Smtp
                && matches!(
                    session.source,
                    SessionSource::Sniffer | SessionSource::Import
                )
            {
                let db = engine_db.clone();
                let review_session = Arc::clone(&session);
                let domains = internal_domains.read().await.clone();
                let mut local_domains = domains.into_iter().collect::<Vec<_>>();
                local_domains.sort_unstable();
                tokio::spawn(async move {
                    let _ = persist_mirror_email_review(&db, &review_session, &local_domains, true)
                        .await;
                });
            }

            // 1. Skip non-email sessions (permanent filter)
            // emailHeaderofSession completeemail, Security
            // override: 554, QUIT-only, entering DATA Segmentof connection
            if !session.has_analyzable_content() {
                debug!(
                    session_id = %session_id,
                    mail_from = session.mail_from.as_deref().unwrap_or("<none>"),
                    "Skipping non-email session (no analyzable message content)"
                );
                continue;
            }

            let explicit_rescan = session.source == vigilyx_core::models::SessionSource::Import;
            let local_domains_snapshot = internal_domains.read().await.clone();
            let is_mirror_inbound = is_mirror_inbound_session(&session, &local_domains_snapshot);
            if !explicit_rescan && session.source == SessionSource::Sniffer && !is_mirror_inbound {
                debug!(
                    session_id = %session_id,
                    server_ip = %session.server_ip,
                    "Skipping non-inbound mirror session"
                );
                continue;
            }

            // Correlate every observed inbound mirror hop before the ordinary
            // session dedup. The first observed hop owns native analysis;
            // later hops wait briefly for that verdict and persist a
            // provenance row instead of running the detector graph again.
            let delivery_registration = if !explicit_rescan && is_mirror_inbound {
                match delivery_fingerprint(&session) {
                    Some(fingerprint) => match engine_db
                        .register_email_delivery_hop(
                            &fingerprint,
                            session_id,
                            &session.client_ip,
                            &session.server_ip,
                            session.started_at,
                        )
                        .await
                    {
                        Ok(registration) => Some(registration),
                        Err(error) => {
                            warn!(
                                session_id = %session_id,
                                %error,
                                "Failed to register mirror delivery hop; continuing with native analysis"
                            );
                            None
                        }
                    },
                    None => None,
                }
            } else {
                None
            };

            if let Some(registration) = delivery_registration
                && !registration.is_first_hop
            {
                let pv_ctx = Arc::new(PostVerdictContext {
                    db: engine_db.clone(),
                    ioc: ioc_manager.clone(),
                    disposition: disposition_engine.clone(),
                    metrics: metrics.clone(),
                    temporal: Arc::clone(&temporal_analyzer),
                    alert: Arc::clone(&alert_engine),
                    ws_tx: ws_tx.clone(),
                    verdict_count: Arc::clone(&verdict_count),
                    temporal_semaphore: Arc::clone(&temporal_semaphore),
                    temporal_flush_interval: Self::TEMPORAL_FLUSH_INTERVAL,
                    internal_domains: internal_domains.clone(),
                });
                let downstream_orchestrator = Arc::clone(&orchestrator);
                let downstream_config = Arc::clone(&config);
                let downstream_semaphore = Arc::clone(&semaphore);
                inflight.spawn(async move {
                    run_reused_or_fallback_delivery(
                        downstream_orchestrator,
                        downstream_config,
                        session,
                        pv_ctx,
                        registration.first_session_id,
                        downstream_semaphore,
                    )
                    .await;
                });
                continue;
            }

            // 2. Whitelist check (fast async)
            if session_has_authenticated_whitelist_bypass(session.as_ref(), &whitelist_manager)
                .await
            {
                debug!(
                    session_id = %session_id,
                    mail_from = session.mail_from.as_deref().unwrap_or(""),
                    client_ip = %session.client_ip,
                    "Skipping whitelisted session"
                );
                continue;
            }

            // 3. Dedup check (atomic: write lock -> check -> insert -> release)
            //
            // Key fix: when a session was previously analyzed while still Active
            // (e.g. on MAIL FROM dirty flush with empty links/body), allow
            // re-analysis once it reaches Completed status with full content.
            {
                let now_instant = Instant::now();
                let is_completed = session.status == vigilyx_core::models::SessionStatus::Completed
                    || session.status == vigilyx_core::models::SessionStatus::Timeout;
                let mut map = recent_analyzed.write().await;
                if !explicit_rescan
                    && let Some(&(last_time, prev_was_completed)) = map.get(&session_id)
                    && now_instant.duration_since(last_time).as_secs() < Self::DEDUP_WINDOW_SECS
                {
                    // Allow re-analysis: session is now Completed but was previously
                    // analyzed while still Active (incomplete content).
                    if is_completed && !prev_was_completed {
                        info!(
                            session_id = %session_id,
                            "Re-analyzing: session now Completed (previously analyzed while Active)"
                        );
                    } else {
                        debug!(
                            session_id = %session_id,
                            "Skipping duplicate submission (analyzed {}s ago, completed={})",
                            now_instant.duration_since(last_time).as_secs(),
                            prev_was_completed,
                        );
                        continue;
                    }
                }
                // PeriodicCleanupExpiredentry: 50 session map 100 Item Cleanup
                dedup_cleanup_counter += 1;
                if dedup_cleanup_counter.is_multiple_of(50) || map.len() > 100 {
                    map.retain(|_, &mut (t, _)| {
                        now_instant.duration_since(t).as_secs() < Self::DEDUP_WINDOW_SECS
                    });
                }
                map.insert(session_id, (now_instant, is_completed));
            } // write lock released

            // 4. Acquire semaphore permit (backpressure)
            let permit = match Arc::clone(&semaphore).acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    warn!("Semaphore closed, engine run_loop exiting");
                    break;
                }
            };

            // 5. Clone shared state for the per-email task
            let orch = Arc::clone(&orchestrator);
            let cfg = Arc::clone(&config);
            let int_domains = internal_domains.clone();

            let pv_ctx = Arc::new(PostVerdictContext {
                db: engine_db.clone(),
                ioc: ioc_manager.clone(),
                disposition: disposition_engine.clone(),
                metrics: metrics.clone(),
                temporal: Arc::clone(&temporal_analyzer),
                alert: Arc::clone(&alert_engine),
                ws_tx: ws_tx.clone(),
                verdict_count: Arc::clone(&verdict_count),
                temporal_semaphore: Arc::clone(&temporal_semaphore),
                temporal_flush_interval: Self::TEMPORAL_FLUSH_INTERVAL,
                internal_domains: int_domains.clone(),
            });

            // 6. Spawn per-email processing task
            inflight.spawn(async move {
                let _permit = permit; // held until task completes
                // Full pipeline execution is shared with the MTA follow-up path.
                // The permit remains held for the entire asynchronous analysis.
                run_full_pipeline(orch, cfg, session, pv_ctx).await;
            });

            // Reap completed tasks without blocking the receive loop
            while let Some(result) = inflight.try_join_next() {
                if let Err(e) = result {
                    error!("Email processing task panicked: {}", e);
                }
            }
        }

        // Graceful shutdown: wait for all in-flight tasks
        info!(
            inflight = inflight.len(),
            "Channel closed, waiting for in-flight tasks"
        );
        while let Some(result) = inflight.join_next().await {
            if let Err(e) = result {
                error!("Task panicked during shutdown: {}", e);
            }
        }

        // Final temporal flush
        let (cusum, ewma, entity) = temporal_analyzer.export_states().await;
        if let Err(e) = engine_db
            .flush_temporal_states(&cusum, &ewma, &entity)
            .await
        {
            error!("Failed to flush temporal states on shutdown: {}", e);
        }

        info!("Security engine stopped (channel closed)");
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use vigilyx_core::models::{EmailSession, Protocol, SmtpAuthInfo};

    #[test]
    fn large_yara_pack_uses_cpu_sized_pipeline_default() {
        assert_eq!(resolve_email_pipeline_concurrency(16, 0, None), 96);
        assert_eq!(
            resolve_email_pipeline_concurrency(16, LARGE_YARA_PACK_RULES, None),
            16
        );
        assert_eq!(
            resolve_email_pipeline_concurrency(128, LARGE_YARA_PACK_RULES, None),
            64
        );
    }

    #[test]
    fn explicit_pipeline_concurrency_is_bounded_and_invalid_values_fall_back() {
        assert_eq!(
            resolve_email_pipeline_concurrency(16, LARGE_YARA_PACK_RULES, Some("48")),
            48
        );
        assert_eq!(
            resolve_email_pipeline_concurrency(16, LARGE_YARA_PACK_RULES, Some("0")),
            16
        );
        assert_eq!(
            resolve_email_pipeline_concurrency(16, LARGE_YARA_PACK_RULES, Some("4096")),
            16
        );
    }

    #[test]
    fn inline_worker_capacity_is_bounded_and_configurable() {
        assert_eq!(resolve_inline_workers(None), DEFAULT_INLINE_WORKERS);
        assert_eq!(resolve_inline_workers(Some("12")), 12);
        assert_eq!(resolve_inline_workers(Some("0")), DEFAULT_INLINE_WORKERS);
        assert_eq!(resolve_inline_workers(Some("65")), DEFAULT_INLINE_WORKERS);
        assert_eq!(
            resolve_inline_workers(Some("not-a-number")),
            DEFAULT_INLINE_WORKERS
        );
    }

    /// Helper: create a minimal EmailSession with content headers for pipeline processing
    fn make_session_with_headers() -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.168.1.1".to_string(),
            12345,
            "10.0.0.1".to_string(),
            25,
        );
        session.mail_from = Some("test@example.com".to_string());
        session.rcpt_to = vec!["admin@example.com".to_string()];
        session
            .content
            .headers
            .push(("From".into(), "test@example.com".into()));
        session
            .content
            .headers
            .push(("To".into(), "admin@example.com".into()));
        session
            .content
            .headers
            .push(("Subject".into(), "Test email".into()));
        session.content.body_text = Some("Hello world".into());
        session.content.is_complete = true;
        session
    }

    /// Helper: create a session without headers (should be skipped by engine)
    fn make_empty_session() -> EmailSession {
        EmailSession::new(
            Protocol::Smtp,
            "192.168.1.1".to_string(),
            12345,
            "10.0.0.1".to_string(),
            25,
        )
    }

    #[test]
    fn whitelist_bypass_requires_matching_authenticated_sender() {
        let mut session = make_session_with_headers();
        assert!(!has_authenticated_sender_identity(&session));

        session.auth_info = Some(SmtpAuthInfo {
            auth_method: "PLAIN".to_string(),
            username: Some("other@example.com".to_string()),
            password: None,
            auth_success: Some(true),
        });
        assert!(!has_authenticated_sender_identity(&session));

        session.auth_info.as_mut().unwrap().username = Some("TEST@EXAMPLE.COM".to_string());
        assert!(has_authenticated_sender_identity(&session));
    }

    #[test]
    fn failed_authentication_cannot_enable_whitelist_bypass() {
        let mut session = make_session_with_headers();
        session.auth_info = Some(SmtpAuthInfo {
            auth_method: "LOGIN".to_string(),
            username: Some("test@example.com".to_string()),
            password: None,
            auth_success: Some(false),
        });

        assert!(!has_authenticated_sender_identity(&session));
    }

    #[tokio::test]
    async fn test_try_submit_returns_error_when_channel_full() {
        let (tx, _rx) = mpsc::channel::<EmailSession>(2);
        // Fill the channel
        tx.try_send(make_session_with_headers()).unwrap();
        tx.try_send(make_session_with_headers()).unwrap();

        // Third should fail
        let result = tx.try_send(make_session_with_headers());
        assert!(result.is_err(), "Expected channel full error");
    }

    #[tokio::test]
    async fn test_submit_with_backoff_succeeds_after_drain() {
        let (tx, mut rx) = mpsc::channel::<EmailSession>(2);
        // Fill the channel
        tx.try_send(make_session_with_headers()).unwrap();
        tx.try_send(make_session_with_headers()).unwrap();

        // Spawn a drainer that frees space after 100ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let _ = rx.recv().await;
        });

        // submit_with_backoff should succeed (waits up to 2s)
        let session = make_session_with_headers();
        match tx.try_send(session) {
            Ok(()) => panic!("Expected full channel"),
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
                let result =
                    tokio::time::timeout(std::time::Duration::from_secs(2), tx.send(session)).await;
                assert!(
                    result.is_ok(),
                    "submit_with_backoff should succeed after drain"
                );
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_submit_with_backoff_times_out_when_permanently_full() {
        let (tx, _rx) = mpsc::channel::<EmailSession>(1);
        tx.try_send(make_session_with_headers()).unwrap();

        // No drainer - should timeout after 200ms (using short timeout for test speed)
        let session = make_session_with_headers();
        let result = match tx.try_send(session) {
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
                tokio::time::timeout(std::time::Duration::from_millis(200), tx.send(session)).await
            }
            _ => panic!("Expected full channel"),
        };
        assert!(
            result.is_err(),
            "Should timeout when channel is permanently full"
        );
    }

    #[tokio::test]
    async fn test_channel_capacity_allows_burst() {
        // Verify the increased channel capacity (10,000) can handle burst imports
        let (tx, _rx) = mpsc::channel::<EmailSession>(10_000);
        let mut success_count = 0;

        for _ in 0..5_000 {
            if tx.try_send(make_session_with_headers()).is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(
            success_count, 5_000,
            "Should accept 5000 sessions without blocking"
        );
    }

    #[tokio::test]
    async fn test_empty_session_has_no_headers() {
        let session = make_empty_session();
        assert!(
            session.content.headers.is_empty(),
            "Empty session should have no headers (will be skipped by engine)"
        );
    }

    #[tokio::test]
    async fn test_session_with_headers_is_not_empty() {
        let session = make_session_with_headers();
        assert!(
            !session.content.headers.is_empty(),
            "Session with headers should not be skipped"
        );
    }

    #[test]
    fn message_id_dedup_requires_matching_security_content() {
        let mut benign = make_session_with_headers();
        benign.message_id = Some("<same@example.com>".to_string());
        let mut malicious = benign.clone();
        malicious.id = Uuid::new_v4();
        malicious.content.body_text = Some("Reset your password at the attached link".to_string());

        let benign_key = message_dedup_key(&benign).unwrap();
        let malicious_key = message_dedup_key(&malicious).unwrap();

        assert_eq!(benign_key.0, malicious_key.0);
        assert_ne!(benign_key.1, malicious_key.1);
    }

    #[test]
    fn message_id_dedup_ignores_only_relay_received_headers() {
        let mut first_hop = make_session_with_headers();
        first_hop.message_id = Some("<same@example.com>".to_string());
        first_hop
            .content
            .headers
            .push(("Received".to_string(), "from relay-a".to_string()));
        let mut final_hop = first_hop.clone();
        final_hop.id = Uuid::new_v4();
        final_hop.content.headers.last_mut().unwrap().1 = "from relay-b".to_string();

        assert_eq!(message_dedup_key(&first_hop), message_dedup_key(&final_hop));
    }

    #[test]
    fn delivery_identity_ignores_gateway_generated_headers() {
        let mut first_hop = make_session_with_headers();
        first_hop.message_id = Some("<stable@example.com>".to_string());
        let mut downstream = first_hop.clone();
        downstream.id = Uuid::new_v4();
        downstream.content.headers.extend([
            ("X-Gateway-Hop".to_string(), "gw-2".to_string()),
            (
                "Authentication-Results".to_string(),
                "relay.example".to_string(),
            ),
            ("Delivered-To".to_string(), "admin@example.com".to_string()),
        ]);

        assert_eq!(
            delivery_fingerprint(&first_hop),
            delivery_fingerprint(&downstream)
        );
    }

    #[test]
    fn delivery_identity_ignores_gateway_content_rewrites() {
        let mut first_hop = make_session_with_headers();
        first_hop.message_id = Some("<stable@example.com>".to_string());
        first_hop.subject = Some("Same subject".to_string());

        let mut downstream = first_hop.clone();
        downstream.id = Uuid::new_v4();
        downstream.content.body_text = Some("Rewritten by the next gateway".to_string());
        downstream.content.body_html = Some("<p>Rewritten by the next gateway</p>".to_string());
        downstream
            .content
            .headers
            .push(("X-Content-Rewritten".to_string(), "gateway-2".to_string()));

        assert_eq!(
            delivery_fingerprint(&first_hop),
            delivery_fingerprint(&downstream)
        );
    }

    #[test]
    fn mirror_inbound_requires_a_local_recipient() {
        let mut session = make_session_with_headers();
        session.mail_from = Some("sender@outside.example".to_string());
        session.rcpt_to = vec!["admin@example.com".to_string()];
        let local_domains = HashSet::from(["example.com".to_string()]);
        assert!(is_mirror_inbound_session(&session, &local_domains));

        session.rcpt_to = vec!["admin@outside.example".to_string()];
        assert!(!is_mirror_inbound_session(&session, &local_domains));
    }

    #[test]
    fn delivery_identity_requires_message_id() {
        let session = make_session_with_headers();
        assert!(delivery_fingerprint(&session).is_none());
    }

    #[tokio::test]
    async fn test_dedup_window_prevents_reprocessing() {
        let dedup: Arc<RwLock<HashMap<Uuid, Instant>>> = Arc::new(RwLock::new(HashMap::new()));
        let session_id = Uuid::new_v4();

        // First submission: insert into dedup map
        {
            let mut map = dedup.write().await;
            map.insert(session_id, Instant::now());
        }

        // Second submission within window: should be skipped
        {
            let now = Instant::now();
            let map = dedup.read().await;
            if let Some(&last_time) = map.get(&session_id) {
                let elapsed = now.duration_since(last_time).as_secs();
                assert!(elapsed < 30, "Should detect duplicate within 30s window");
            }
        }
    }

    #[tokio::test]
    async fn test_dedup_cleanup_at_threshold() {
        let dedup: Arc<RwLock<HashMap<Uuid, Instant>>> = Arc::new(RwLock::new(HashMap::new()));

        // Add 250 entries (above the 200 threshold)
        {
            let mut map = dedup.write().await;
            for _ in 0..250 {
                map.insert(Uuid::new_v4(), Instant::now());
            }
            assert_eq!(map.len(), 250);

            // Simulate cleanup (retain only entries within window)
            if map.len() > 200 {
                let now = Instant::now();
                map.retain(|_, t| now.duration_since(*t).as_secs() < 30);
            }
            // All entries are recent so all retained
            assert_eq!(map.len(), 250);
        }
    }

    #[tokio::test]
    async fn test_concurrent_semaphore_capacity() {
        // Verify semaphore allows sufficient concurrency for I/O-bound workloads
        let max_concurrent = (num_cpus::get() * 6).max(8);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        let mut permits = Vec::new();
        for _ in 0..max_concurrent {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            permits.push(permit);
        }

        // All permits acquired
        assert_eq!(semaphore.available_permits(), 0);

        // Next acquire should not immediately succeed
        let try_result = semaphore.try_acquire();
        assert!(try_result.is_err(), "No permits should be available");

        // Drop one permit
        drop(permits.pop());
        assert_eq!(semaphore.available_permits(), 1);
    }

    // MTA Inline Verdict Tests

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_safe_accepts() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Safe,
            ThreatLevel::Medium,   // quarantine threshold
            ThreatLevel::Critical, // reject threshold
        );
        assert!(matches!(d, VerdictDisposition::Accept));
        assert_eq!(d.smtp_code(), 250);
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_low_accepts() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Accept));
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_medium_quarantines() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Medium,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Quarantine));
        assert_eq!(d.smtp_code(), 250);
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_high_quarantines() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::High,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Quarantine));
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_critical_rejects() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Critical,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Reject { .. }));
        assert_eq!(d.smtp_code(), 550);
    }

    #[test]
    fn incomplete_inline_inspection_quarantines_without_inflating_threat() {
        let threat_level = ThreatLevel::Safe;
        let disposition = inline_delivery_disposition(
            threat_level,
            true,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );

        assert_eq!(threat_level, ThreatLevel::Safe);
        assert!(matches!(disposition, VerdictDisposition::Quarantine));
    }

    #[test]
    fn low_inline_inspection_gap_cannot_be_relabeled_as_accept() {
        let disposition = inline_delivery_disposition(
            ThreatLevel::Low,
            true,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );

        assert!(matches!(disposition, VerdictDisposition::Quarantine));
    }

    #[test]
    fn actual_inline_threat_still_controls_stronger_disposition() {
        let disposition = inline_delivery_disposition(
            ThreatLevel::Critical,
            true,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );

        assert!(matches!(disposition, VerdictDisposition::Reject { .. }));
    }

    #[tokio::test]
    async fn test_inline_channel_full_returns_tempfail() {
        // Create a tiny inline channel (capacity 1)
        let (inline_tx, _inline_rx) = mpsc::channel::<InlineVerdictRequest>(1);

        // Fill it with a dummy request
        let (dummy_tx, _dummy_rx) = oneshot::channel();
        inline_tx
            .try_send(InlineVerdictRequest {
                session: make_session_with_headers(),
                respond_to: dummy_tx,
                deadline: Instant::now() + std::time::Duration::from_secs(5),
                quarantine_threshold: ThreatLevel::Medium,
                reject_threshold: ThreatLevel::Critical,
            })
            .unwrap();

        // Second request should fail (channel full)
        let (resp_tx, _resp_rx) = oneshot::channel();
        let result = inline_tx.try_send(InlineVerdictRequest {
            session: make_session_with_headers(),
            respond_to: resp_tx,
            deadline: Instant::now() + std::time::Duration::from_secs(5),
            quarantine_threshold: ThreatLevel::Medium,
            reject_threshold: ThreatLevel::Critical,
        });
        assert!(result.is_err(), "Channel should be full");
    }

    #[tokio::test]
    async fn test_inline_verdict_response_serialization_roundtrip() {
        let response = InlineVerdictResponse {
            disposition: VerdictDisposition::Quarantine,
            threat_level: ThreatLevel::High,
            confidence: 0.85,
            summary: "Phishing detected".into(),
            session_id: uuid::Uuid::new_v4(),
            modules_run: 15,
            modules_flagged: 3,
            duration_ms: 4500,
        };
        let json = serde_json::to_string(&response).unwrap();
        let deser: InlineVerdictResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.threat_level, ThreatLevel::High);
        assert_eq!(deser.modules_run, 15);
        assert!(matches!(deser.disposition, VerdictDisposition::Quarantine));
    }

    #[test]
    fn test_inline_pipeline_matches_full_pipeline_config() {
        let config = PipelineConfig::default();
        let inline = config.clone();
        let inline_ids = inline
            .modules
            .iter()
            .map(|module| module.id.as_str())
            .collect::<Vec<_>>();

        assert!(
            inline.modules.len() == config.modules.len(),
            "inline and passive paths must use the same module count"
        );
        assert_eq!(
            inline_ids,
            config
                .modules
                .iter()
                .map(|module| module.id.as_str())
                .collect::<Vec<_>>(),
            "inline and passive paths must use the exact same module ordering"
        );
        for must_keep in [
            "attach_qr_scan",
            "aitm_detect",
            "link_content",
            "landing_page_scan",
            "semantic_scan",
            "transaction_correlation",
        ] {
            assert!(
                config
                    .modules
                    .iter()
                    .any(|module| module.id == must_keep && module.enabled),
                "default full pipeline contract should include enabled {must_keep}"
            );
            assert!(
                inline
                    .modules
                    .iter()
                    .any(|module| module.id == must_keep && module.enabled),
                "inline pipeline must not drop enabled {must_keep}"
            );
        }
    }

    #[test]
    fn historical_import_rescan_keeps_mirror_review_source() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.2".to_string(),
            25_000,
            "198.51.100.237".to_string(),
            25,
        );
        session.source = SessionSource::Import;

        let review_session = mirror_review_session(&session).expect("SMTP import is reviewable");

        assert_eq!(review_session.source, SessionSource::Sniffer);
        assert_eq!(review_session.server_ip, session.server_ip);
    }

    #[test]
    fn encrypted_mirror_session_without_envelope_is_attribution_pending() {
        let mut session = make_session_with_headers();
        session.mail_from = None;
        session.rcpt_to.clear();
        session.content.is_encrypted = true;
        session.content.is_complete = false;

        assert_eq!(
            mirror_review_direction(&session, &["example.com".into()]),
            Some((
                EmailReviewDirection::Unknown,
                EmailAuditClass::AttributionPending
            ))
        );
    }

    #[test]
    fn cleartext_mirror_session_without_envelope_is_not_promoted_to_review() {
        let mut session = make_session_with_headers();
        session.mail_from = None;
        session.rcpt_to.clear();

        assert_eq!(
            mirror_review_direction(&session, &["example.com".into()]),
            None
        );
    }

    #[test]
    fn test_tempfail_uses_smtp_451() {
        assert_eq!(VerdictDisposition::Tempfail.smtp_code(), 451);
        assert!(
            VerdictDisposition::Tempfail
                .smtp_message()
                .starts_with("4.7.1")
        );
    }

    fn first_hop_verdict(coverage: vigilyx_core::security::InspectionCoverage) -> SecurityVerdict {
        SecurityVerdict {
            inspection_coverage: coverage,
            coverage_reasons: vec![],
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            threat_level: ThreatLevel::Safe,
            threat_type: None,
            classification: None,
            confidence: 0.5,
            categories: vec![],
            summary: "first hop".to_string(),
            pillar_scores: HashMap::new(),
            modules_run: 25,
            modules_flagged: 0,
            total_duration_ms: 10,
            created_at: chrono::Utc::now(),
            fusion_details: None,
        }
    }

    #[test]
    fn complete_downstream_hop_is_analyzed_when_first_hop_coverage_is_limited() {
        use vigilyx_core::security::InspectionCoverage;
        // Field case: the gateway hop was captured incompletely, the relay hop
        // carried the whole message, and reuse copied "inspection incomplete".
        let mut downstream = make_session_with_headers();
        downstream.content.is_complete = true;
        downstream.content.truncated = false;
        assert!(downstream_hop_needs_own_analysis(
            &first_hop_verdict(InspectionCoverage::Limited),
            &downstream
        ));
        assert!(!downstream_hop_needs_own_analysis(
            &first_hop_verdict(InspectionCoverage::Complete),
            &downstream
        ));

        // An equally incomplete downstream copy keeps the reuse path.
        downstream.content.is_complete = false;
        assert!(!downstream_hop_needs_own_analysis(
            &first_hop_verdict(InspectionCoverage::Limited),
            &downstream
        ));
        downstream.content.is_complete = true;
        downstream.content.truncated = true;
        assert!(!downstream_hop_needs_own_analysis(
            &first_hop_verdict(InspectionCoverage::Limited),
            &downstream
        ));
    }
}
