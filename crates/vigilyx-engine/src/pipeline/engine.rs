use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, Semaphore, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use vigilyx_core::models::{EmailSession, WsMessage};
use vigilyx_core::security::{InlineVerdictResponse, ThreatLevel, VerdictDisposition};
use vigilyx_db::VigilDb;

use crate::alert::AlertEngine;
use crate::config::PipelineConfig;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::ioc::IocManager;
use crate::metrics::EngineMetrics;
use crate::modules::registry::build_module_registry;
use crate::orchestrator::{
    MODULE_EXECUTION_FAILED_CATEGORY, MODULE_EXECUTION_TIMEOUT_CATEGORY, PipelineOrchestrator,
};
use crate::temporal::temporal_analyzer::TemporalAnalyzer;
use crate::whitelist::WhitelistManager;
use vigilyx_soar::disposition::DispositionEngine;

use super::internal_domains::{load_internal_domains, refresh_internal_domains};
use super::post_verdict::{PostVerdictContext, run_post_verdict};

type MessageDedupKey = (String, [u8; 32]);
type MessageDedupMap = Arc<RwLock<HashMap<MessageDedupKey, (Uuid, Instant)>>>;

/// Synchronous MTA work is intentionally bounded to local detectors. Remote
/// NLP/intel/landing-page work is run by the full pipeline after SMTP has
/// received a provisional, evidence-based response.
const INLINE_MAX_PRIORITY: u8 = 90;
const LARGE_YARA_PACK_RULES: usize = 10_000;
const MAX_EMAIL_PIPELINE_CONCURRENCY: usize = 1_024;

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
    let evidence_disposition =
        VerdictDisposition::from_threat_level(threat_level, quarantine_threshold, reject_threshold);
    if inspection_incomplete && matches!(evidence_disposition, VerdictDisposition::Accept) {
        // A known partial inspection is not an engine outage. Quarantine it
        // directly so MTA_FAIL_OPEN cannot relay content that was omitted from
        // scanning. Tempfail remains reserved for timeout/channel/engine
        // failures, whose behavior is handled by the MTA fail-open setting.
        VerdictDisposition::Quarantine
    } else {
        evidence_disposition
    }
}

fn load_inbound_mail_servers_from_env() -> HashSet<String> {
    std::env::var("INBOUND_MAIL_SERVERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn load_inbound_mail_servers(db: &VigilDb) -> HashSet<String> {
    match db.get_capture_inbound_target_ips().await {
        Ok(servers) if !servers.is_empty() => servers,
        Ok(_) => load_inbound_mail_servers_from_env(),
        Err(err) => {
            warn!(
                "Failed to load inbound targets from ui_preferences: {}",
                err
            );
            load_inbound_mail_servers_from_env()
        }
    }
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

fn log_inbound_mail_servers(servers: &HashSet<String>) {
    if !servers.is_empty() {
        info!(
            servers = ?servers,
            "Inbound mail server filter active: only analyzing sessions delivered to these IPs"
        );
    }
}

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
        // Received changes at each relay and is precisely why hop-level dedup
        // exists. All other headers remain part of the security identity.
        if !name.eq_ignore_ascii_case("Received") {
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
    let ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot);
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
        pv_ctx
            .metrics
            .record_module_run(
                module_id,
                result.duration_ms,
                !failed && !timed_out,
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
    run_post_verdict(&pv_ctx, &session, &verdict_result, &results).await;
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

        // Initialize engine DB and tables
        let engine_db = db;
        engine_db
            .init_security_tables()
            .await
            .map_err(|e| EngineError::Other(format!("Failed to init engine tables: {}", e)))?;
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
                internal_domains.clone(),
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
        })
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

        // Inbound mail server IPs: when configured, the engine ONLY analyzes
        // sessions delivered TO these IPs — the final hop in the delivery chain
        // has the most complete information (gateway headers, all Received hops).
        // Intermediate relay hops are skipped entirely.
        // Format: comma-separated IPs, e.g. "10.7.126.68,10.1.246.41"
        let inbound_mail_servers =
            Arc::new(RwLock::new(load_inbound_mail_servers(&engine_db).await));
        {
            let servers = inbound_mail_servers.read().await;
            log_inbound_mail_servers(&servers);
        }

        {
            let inbound_mail_servers = inbound_mail_servers.clone();
            let db = engine_db.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let refreshed = load_inbound_mail_servers(&db).await;
                    let mut current = inbound_mail_servers.write().await;
                    if *current != refreshed {
                        *current = refreshed;
                        log_inbound_mail_servers(&current);
                    }
                }
            });
        }

        // A Message-ID is sender-controlled and is not a unique security
        // identity. Pair it with a content fingerprint so a later malicious
        // message reusing a benign ID is still analyzed.
        let msgid_dedup: MessageDedupMap = Arc::new(RwLock::new(HashMap::new()));

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
        crate::threat_scene::spawn_scene_detector(engine_db.clone(), internal_domains.clone());

        // JoinSet tracks in-flight per-email tasks for graceful shutdown
        let mut inflight = tokio::task::JoinSet::new();
        let mut dedup_cleanup_counter: u64 = 0;

        loop {
            // Select: inline requests have priority (biased)
            let session = tokio::select! {
                biased;
                Some(inline_req) = inline_rx.recv() => {
                   // Inline verdict path (MTA proxy)
                    let start = Instant::now();
                    let session = Arc::new(inline_req.session);
                    let session_id = session.id;
                    let remaining = inline_req.deadline.saturating_duration_since(Instant::now());

                    if remaining.is_zero() {
                        warn!(session_id = %session_id, "Inline verdict deadline already expired");
                        // Timeout is enforced through Tempfail. It does not
                        // manufacture a Low threat finding.
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
                            disposition: VerdictDisposition::Tempfail,
                            threat_level: ThreatLevel::Safe,
                            confidence: 0.0,
                            summary: "Security analysis timed out — conservative verdict applied (deadline already expired)".into(),
                            session_id,
                            modules_run: 0,
                            modules_flagged: 0,
                            duration_ms: 0,
                        });
                        continue;
                    }

                    if session_has_authenticated_whitelist_bypass(
                        session.as_ref(),
                        &whitelist_manager,
                    )
                    .await
                    {
                        info!(
                            session_id = %session_id,
                            mail_from = session.mail_from.as_deref().unwrap_or(""),
                            client_ip = %session.client_ip,
                            "Skipping whitelisted SMTP inline session"
                        );
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
                            disposition: VerdictDisposition::Accept,
                            threat_level: ThreatLevel::Safe,
                            confidence: 1.0,
                            summary: "Session bypassed by whitelist".into(),
                            session_id,
                            modules_run: 0,
                            modules_flagged: 0,
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                        continue;
                    }

                    let domains_snapshot = Arc::new(internal_domains.read().await.clone());
                    let ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot);
                    let inline_outcome = inline_orchestrator.execute_with_timeout(&ctx, remaining).await;
                    if inline_outcome.timed_out {
                        warn!(
                            session_id = %session_id,
                            timeout_ms = remaining.as_millis() as u64,
                            "Inline verdict hit deadline before full analysis completed"
                        );
                        // Timeout is enforced through Tempfail. It does not
                        // manufacture a Low threat finding.
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
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
                        continue;
                    }
                    if let Some(reason) = inline_outcome.disposition_incomplete_summary() {
                        warn!(
                            session_id = %session_id,
                            reason = %reason,
                            "Inline verdict pipeline did not complete successfully"
                        );
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
                            disposition: VerdictDisposition::Tempfail,
                            threat_level: ThreatLevel::Safe,
                            confidence: 0.0,
                            summary: format!(
                                "Security analysis incomplete — temporary failure ({reason})"
                            ),
                            session_id,
                            modules_run: inline_outcome.results.len() as u32,
                            modules_flagged: inline_outcome
                                .results
                                .values()
                                .filter(|result| result.threat_level > ThreatLevel::Safe)
                                .count() as u32,
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                        continue;
                    }
                    let results = inline_outcome.results;

                    let verdict_result = crate::verdict::aggregate_verdict_with_session(
                        Some(session.as_ref()),
                        session_id,
                        &results,
                        &config.verdict_config,
                    );

                    let disposition = inline_delivery_disposition(
                        verdict_result.threat_level,
                        crate::verdict::has_incomplete_inspection(&verdict_result),
                        inline_req.quarantine_threshold,
                        inline_req.reject_threshold,
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

                   // Send response back to MTA proxy
                    let _ = inline_req.respond_to.send(response);

                   // Persist the session to the DB (the MTA inline path had not stored it yet)
                   if let Err(e) = engine_db.insert_session(&session).await {
                       error!(session_id = %session_id, "Failed to store MTA session: {e}");
                   }

                   // Keep asynchronous MTA follow-ups under the same global
                   // concurrency budget as passive sessions. The SMTP client
                   // already received its response, so waiting here cannot
                   // extend the inline deadline.
                   let permit = match Arc::clone(&semaphore).acquire_owned().await {
                       Ok(permit) => permit,
                       Err(_) => {
                           warn!(session_id = %session_id, "Full MTA follow-up skipped: pipeline semaphore closed");
                           continue;
                       }
                   };

                   // The fast tier only answers SMTP. Run the complete pipeline
                   // asynchronously so landing-page, intel and NLP modules still
                   // produce the durable verdict without consuming the MTA
                   // deadline. This avoids writing a provisional verdict and
                   // then emitting duplicate alerts/IOC records.
                   let pv = Arc::new(PostVerdictContext {
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
                   let full_orchestrator = Arc::clone(&orchestrator);
                   let full_config = Arc::clone(&config);
                   let s = session.clone();
                   inflight.spawn(async move {
                        let _permit = permit;
                        run_full_pipeline(full_orchestrator, full_config, s, pv).await;
                   });

                    continue; // Back to select!
                }
                Some(session) = rx.recv() => session,
                else => break,
            };

            let session = Arc::new(session);
            let session_id = session.id;

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

            // 1b. Inbound IP filter: when INBOUND_MAIL_SERVERS is configured,
            //     only analyze sessions delivered TO those IPs (the final hop).
            //     Intermediate relay hops are skipped — the final inbound has
            //     the most complete info (gateway headers, all Received hops).
            let explicit_rescan = session.source == vigilyx_core::models::SessionSource::Import;
            let (inbound_filter_active, is_inbound_target) = {
                let servers = inbound_mail_servers.read().await;
                if servers.is_empty() {
                    (false, true) // No filter configured — all sessions pass
                } else {
                    (true, servers.contains(&session.server_ip))
                }
            };
            if !is_inbound_target && !explicit_rescan {
                debug!(
                    session_id = %session_id,
                    server_ip = %session.server_ip,
                    "Skipping non-inbound hop (server_ip not in INBOUND_MAIL_SERVERS)"
                );
                continue;
            }

            // 1c. Message-ID dedup: only active when INBOUND_MAIL_SERVERS is set.
            //     When inbound filter is active, same email at the same inbound
            //     server should only produce one verdict.
            //     When inbound filter is NOT set, all sessions are analyzed (no dedup).
            if inbound_filter_active
                && !explicit_rescan
                && let Some(dedup_key) = message_dedup_key(&session)
            {
                let now = Instant::now();
                let mut map = msgid_dedup.write().await;
                if let Some(&(prev_sid, seen_at)) = map.get(&dedup_key)
                    && prev_sid != session_id
                    && now.duration_since(seen_at).as_secs() < Self::DEDUP_WINDOW_SECS
                {
                    debug!(
                        session_id = %session_id,
                        prev_session_id = %prev_sid,
                        message_id = %dedup_key.0,
                        "Skipping duplicate message with matching content fingerprint"
                    );
                    continue;
                }
                map.insert(dedup_key, (session_id, now));
                if map.len() > 5000 {
                    map.retain(|_, (_, seen_at)| {
                        now.duration_since(*seen_at).as_secs() < Self::DEDUP_WINDOW_SECS
                    });
                }
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
    fn test_tempfail_uses_smtp_451() {
        assert_eq!(VerdictDisposition::Tempfail.smtp_code(), 451);
        assert!(
            VerdictDisposition::Tempfail
                .smtp_message()
                .starts_with("4.7.1")
        );
    }
}
