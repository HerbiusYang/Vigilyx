//! Post-verdict processing: IOC recording, disposition, temporal analysis, and alerting.

//! After a security verdict is produced, this module handles all the downstream
//! side effects: storing results, recording IOCs, evaluating disposition rules,
//! running temporal analysis, and generating alerts.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{debug, error};
use vigilyx_core::models::{EmailSession, SecurityVerdictSummary, WsMessage};
use vigilyx_db::VigilDb;

use crate::alert::AlertEngine;
use crate::ioc::IocManager;
use crate::metrics::EngineMetrics;
use crate::temporal::temporal_analyzer::TemporalAnalyzer;
use vigilyx_core::security::SecurityVerdict;
use vigilyx_soar::alert::AlertSignals;
use vigilyx_soar::disposition::DispositionEngine;

/// All the shared state needed by post-verdict processing.

/// Bundled into a struct to avoid passing 10+ arguments through the task boundary.
pub(crate) struct PostVerdictContext {
    pub db: VigilDb,
    pub ioc: IocManager,
    pub disposition: DispositionEngine,
    pub metrics: EngineMetrics,
    pub temporal: Arc<TemporalAnalyzer>,
    pub alert: Arc<AlertEngine>,
    pub ws_tx: broadcast::Sender<WsMessage>,
    pub verdict_count: Arc<AtomicU64>,
    pub temporal_semaphore: Arc<Semaphore>,
    pub temporal_flush_interval: u64,
    pub internal_domains: Arc<RwLock<HashSet<String>>>,
}

/// Run all post-verdict processing for a single email session.

/// This includes:
/// 1. Storing verdict and module results to DB
/// 2. Auto-recording IOCs from verdict
/// 3. Broadcasting verdict via WebSocket
/// 4. Evaluating disposition rules
/// 5. Temporal analysis + alert evaluation (spawned as background sub-task)
/// 6. Periodic temporal state flush
pub(crate) async fn run_post_verdict(
    ctx: &PostVerdictContext,
    session: &Arc<EmailSession>,
    verdict_result: &SecurityVerdict,
    results: &std::collections::HashMap<String, crate::module::ModuleResult>,
) {
    let session_id = session.id;

   // 1. Store verdict and results to DB
    if let Err(e) = ctx.db.insert_verdict(verdict_result).await {
        error!(session_id = %session_id, "Failed to store verdict: {}", e);
    }

    let results_refs: Vec<&_> = results.values().collect();
    if let Err(e) = ctx
        .db
        .insert_module_results(verdict_result.id, session_id, &results_refs)
        .await
    {
        error!(session_id = %session_id, "Failed to store module results: {}", e);
    }

   // 2. Auto-record IOC if threat_level>= High
   // Security: UPSERT Use Connect (MAX),confidence downgrade;
   // auto IOC 30 DayExpired;admin_clean Name override.
    ctx.ioc
        .auto_record_from_verdict(session, verdict_result)
        .await;
    {
        let domains = ctx.internal_domains.read().await;
        ctx.ioc
            .auto_record_internal_spoofing(session, verdict_result, &domains)
            .await;
    }

    // Auto-record domain impersonation IOC (self-learning loop):
    // When header_scan detects a domain impersonation hit, record the
    // spoofing domain as a malicious IOC so future emails from the same
    // domain get an automatic score boost in Step 5c of header_scan.
    if let Some(hs_result) = results.get("header_scan")
        && let Some(imp_hit) = hs_result.details.get("impersonation_hit")
        && let (Some(sender), Some(target), Some(sim_type), Some(score)) = (
            imp_hit.get("sender_domain").and_then(|v| v.as_str()),
            imp_hit.get("target_domain").and_then(|v| v.as_str()),
            imp_hit.get("similarity_type").and_then(|v| v.as_str()),
            imp_hit.get("score").and_then(|v| v.as_f64()),
        )
    {
        ctx.ioc
            .auto_record_impersonation_domain(
                session, sender, target, sim_type, score,
            )
            .await;
    }

    if let Some(sem_result) = results.get("semantic_scan")
        && sem_result.threat_level >= crate::module::ThreatLevel::Medium
    {
        ctx.ioc.auto_record_nonsensical(session, sem_result).await;
    }

   // 3. Broadcast verdict via WebSocket
    let summary = SecurityVerdictSummary {
        verdict_id: verdict_result.id,
        session_id: verdict_result.session_id,
        threat_level: verdict_result.threat_level.to_string(),
        confidence: verdict_result.confidence,
        categories: verdict_result.categories.clone(),
        summary: verdict_result.summary.clone(),
        modules_run: verdict_result.modules_run,
        modules_flagged: verdict_result.modules_flagged,
        total_duration_ms: verdict_result.total_duration_ms,
    };
    let _ = ctx.ws_tx.send(WsMessage::SecurityVerdict(summary));

   // 4. Evaluate disposition rules + email alerts
    ctx.disposition.evaluate(verdict_result, session).await;

   // 5. Temporal analysis (spawned as background sub-task)
    spawn_temporal_analysis(ctx, session, verdict_result);

   // 6. Periodic temporal state flush
    let count = ctx.verdict_count.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_multiple_of(ctx.temporal_flush_interval) {
        let temporal = Arc::clone(&ctx.temporal);
        let db = ctx.db.clone();
        tokio::spawn(async move {
            let (cusum, ewma, entity) = temporal.export_states().await;
            if let Err(e) = db.flush_temporal_states(&cusum, &ewma, &entity).await {
                error!("Failed to flush temporal states: {}", e);
            } else {
                debug!(
                    cusum = cusum.len(),
                    ewma = ewma.len(),
                    entity = entity.len(),
                    "Flushed temporal states to DB"
                );
            }
        });
    }

    ctx.metrics.record_verdict();
}

/// Spawn temporal analysis and alert evaluation as a background sub-task.
fn spawn_temporal_analysis(
    ctx: &PostVerdictContext,
    session: &Arc<EmailSession>,
    verdict_result: &SecurityVerdict,
) {
    let sender = session.mail_from.as_deref().unwrap_or("").to_string();
    let risk_single = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.risk_single)
        .unwrap_or_else(|| verdict_result.threat_level.as_numeric());

    if sender.is_empty() {
        return;
    }

    let temporal = Arc::clone(&ctx.temporal);
    let alert = Arc::clone(&ctx.alert);
    let db = ctx.db.clone();
    let verdict_id = verdict_result.id;
    let v_session_id = verdict_result.session_id;
    let session_for_temporal = Arc::clone(session);
    let ws = ctx.ws_tx.clone();
    let temporal_sem = Arc::clone(&ctx.temporal_semaphore);

    let u_final = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.fused_bpa.u)
        .unwrap_or(0.3);
    let k_conflict = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.k_conflict)
        .unwrap_or(0.0);
    let novelty = verdict_result
        .fusion_details
        .as_ref()
        .and_then(|fd| fd.novelty);
    let k_cross = verdict_result
        .fusion_details
        .as_ref()
        .and_then(|fd| fd.k_cross);

    tokio::spawn(async move {
       // Limit concurrent temporal tasks to prevent resource exhaustion
        let _temporal_permit = match temporal_sem.acquire().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed
        };
        let obs = crate::temporal::temporal_analyzer::TemporalObservation {
            sender: &sender,
            recipients: &session_for_temporal.rcpt_to,
            risk_single,
            u_final,
            k_conflict,
            content_similarity_delta: 0.0,
        };
        let temporal_result = temporal.analyze_full(&obs).await;

        let risk_final = if temporal_result.risk_upgraded {
            risk_single.max(temporal_result.temporal_risk)
        } else {
            risk_single
        };
        alert.observe(risk_final).await;

        let signals = temporal_to_signals(&temporal_result);
        if let Some(decision) = alert
            .evaluate(
                risk_final,
                k_conflict,
                u_final,
                novelty,
                k_cross,
                Some(&signals),
                &session_for_temporal.rcpt_to,
            )
            .await
        {
            let record = AlertEngine::to_record(&decision, verdict_id, v_session_id);
            if let Err(e) = db.insert_alert(&record).await {
                error!(verdict_id = %verdict_id, "Failed to store alert: {}", e);
            }
            let _ = ws.send(WsMessage::Alert(format!(
                "[{}] session={} EL={:.2} — {}",
                decision.level.as_str(),
                v_session_id,
                decision.expected_loss,
                decision.rationale.join("; ")
            )));
        }

        if temporal_result.risk_upgraded {
            debug!(
                sender = sender.as_str(),
                temporal_risk = temporal_result.temporal_risk,
                "Temporal analysis upgraded risk"
            );
        }
    });
}

/// Convert engine-internal `TemporalResult` to the decoupled `AlertSignals` for vigilyx-soar.
fn temporal_to_signals(t: &crate::temporal::temporal_analyzer::TemporalResult) -> AlertSignals {
    AlertSignals {
        cusum_alarm: t.cusum_alarm,
        hmm_trust_building: t
            .hmm_phase
            .as_ref()
            .map(|h| h.trust_building)
            .unwrap_or(0.0),
        hmm_attack_execution: t
            .hmm_phase
            .as_ref()
            .map(|h| h.attack_execution)
            .unwrap_or(0.0),
        sender_watchlisted: t.sender_watchlisted,
        sender_risk: t.sender_risk,
        ewma_drifting: t.ewma_drifting,
        ewma_drift_score: t.ewma_drift_score,
        graph_anomalous: t
            .graph_anomaly
            .as_ref()
            .map(|g| g.is_anomalous)
            .unwrap_or(false),
        graph_pattern_label: t
            .graph_anomaly
            .as_ref()
            .map(|g| g.pattern_label.clone())
            .unwrap_or_default(),
        hawkes_intensity_ratio: t.hawkes.as_ref().map(|h| h.intensity_ratio).unwrap_or(0.0),
    }
}
