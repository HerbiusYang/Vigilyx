//! Periodic threat scene detection: bulk mailing + bounce/NDR harvest.
//!
//! Runs as a background tokio task, scanning the DB every 5 minutes for
//! cross-session behavioral patterns that indicate email threat scenarios.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use uuid::Uuid;

use vigilyx_core::security::{
    BounceHarvestConfig, BulkMailingConfig, IocEntry, ThreatLevel, ThreatScene,
    ThreatSceneStatus, ThreatSceneType,
};
use vigilyx_db::VigilDb;

/// Scan interval: 5 minutes.
const SCAN_INTERVAL_SECS: u64 = 300;

/// Initial delay before first scan (let engine stabilize).
const INITIAL_DELAY_SECS: u64 = 120;

/// Spawn the background threat scene detector.
pub fn spawn_scene_detector(
    db: VigilDb,
    internal_domains: Arc<RwLock<HashSet<String>>>,
) {
    tokio::spawn(async move {
        // Wait for engine to stabilize
        tokio::time::sleep(std::time::Duration::from_secs(INITIAL_DELAY_SECS)).await;
        info!("Threat scene detector started, scan interval {}s", SCAN_INTERVAL_SECS);

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(SCAN_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let domains = internal_domains.read().await.clone();
            if domains.is_empty() {
                continue;
            }
            if let Err(e) = run_detection_cycle(&db, &domains).await {
                error!("Threat scene detection cycle failed: {e}");
            }
        }
    });
}

/// Run one full detection cycle (bulk mailing + bounce harvest).
async fn run_detection_cycle(
    db: &VigilDb,
    internal_domains: &HashSet<String>,
) -> anyhow::Result<()> {
    // Load scene rules
    let rules = db.get_scene_rules().await?;

    let domain_list: Vec<String> = internal_domains.iter().cloned().collect();

    // 1. Bulk mailing detection
    if let Some(rule) = rules.iter().find(|r| r.scene_type == ThreatSceneType::BulkMailing)
        && rule.enabled
    {
        let config: BulkMailingConfig =
            serde_json::from_value(rule.config.clone()).unwrap_or_default();
        detect_bulk_mailing(db, &domain_list, &config).await?;
    }

    // 2. Bounce harvest detection
    if let Some(rule) = rules.iter().find(|r| r.scene_type == ThreatSceneType::BounceHarvest)
        && rule.enabled
    {
        let config: BounceHarvestConfig =
            serde_json::from_value(rule.config.clone()).unwrap_or_default();
        detect_bounce_harvest(db, &domain_list, &config).await?;
    }

    // 3. Auto-resolve stale scenes
    let resolved = db.auto_resolve_stale_scenes().await?;
    if resolved > 0 {
        info!("Auto-resolved {resolved} stale threat scenes");
    }

    Ok(())
}

// ─── Bulk Mailing Detection ─────────────────────────────────────────────

async fn detect_bulk_mailing(
    db: &VigilDb,
    internal_domains: &[String],
    config: &BulkMailingConfig,
) -> anyhow::Result<()> {
    let hits = db.detect_bulk_mailing(internal_domains, config).await?;
    if hits.is_empty() {
        return Ok(());
    }

    for hit in &hits {
        let severity = bulk_mailing_severity(hit.unique_recipients, hit.email_count);

        // Check if an active scene already exists for this actor
        let existing = db
            .find_active_scene("bulk_mailing", &hit.sender_domain)
            .await?;

        let now = Utc::now();

        if let Some(mut scene) = existing {
            // Update existing scene
            scene.email_count = hit.email_count as i32;
            scene.unique_recipients = hit.unique_recipients as i32;
            scene.time_window_end = chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            scene.threat_level = severity;
            scene.sample_subjects = hit.sample_subjects.clone();
            scene.sample_recipients = hit.sample_recipients.clone();
            scene.updated_at = now;

            // Auto-block upgrade
            if config.auto_block_enabled
                && !scene.auto_blocked
                && hit.unique_recipients >= config.auto_block_recipient_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "bulk_mailing",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: sent {} emails to {} internal recipients within {}h",
                        hit.email_count, hit.unique_recipients, config.time_window_hours
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    recipients = hit.unique_recipients,
                    "Bulk mailing scene: auto-blocked domain"
                );
            }

            db.upsert_threat_scene(&scene).await?;
        } else {
            // Create new scene
            let mut scene = ThreatScene {
                id: Uuid::new_v4(),
                scene_type: ThreatSceneType::BulkMailing,
                actor: hit.sender_domain.clone(),
                actor_type: "domain".to_string(),
                target_domain: None,
                time_window_start: chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                time_window_end: chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                email_count: hit.email_count as i32,
                unique_recipients: hit.unique_recipients as i32,
                bounce_count: 0,
                sample_subjects: hit.sample_subjects.clone(),
                sample_recipients: hit.sample_recipients.clone(),
                threat_level: severity,
                status: ThreatSceneStatus::Active,
                auto_blocked: false,
                ioc_id: None,
                details: serde_json::json!({}),
                created_at: now,
                updated_at: now,
            };

            // Auto-block on creation if threshold exceeded
            if config.auto_block_enabled
                && hit.unique_recipients >= config.auto_block_recipient_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "bulk_mailing",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: sent {} emails to {} internal recipients within {}h",
                        hit.email_count, hit.unique_recipients, config.time_window_hours
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    recipients = hit.unique_recipients,
                    "New bulk mailing scene: auto-blocked domain"
                );
            }

            info!(
                domain = %hit.sender_domain,
                emails = hit.email_count,
                recipients = hit.unique_recipients,
                severity = %severity,
                "Detected bulk mailing scene"
            );
            db.upsert_threat_scene(&scene).await?;
        }
    }

    Ok(())
}

fn bulk_mailing_severity(unique_recipients: i64, email_count: i64) -> ThreatLevel {
    if unique_recipients >= 80 {
        ThreatLevel::Critical
    } else if unique_recipients >= 30 || email_count >= 30 {
        ThreatLevel::High
    } else if unique_recipients >= 15 || email_count >= 10 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    }
}

// ─── Bounce Harvest Detection ───────────────────────────────────────────

async fn detect_bounce_harvest(
    db: &VigilDb,
    internal_domains: &[String],
    config: &BounceHarvestConfig,
) -> anyhow::Result<()> {
    let hits = db.detect_bounce_harvest(internal_domains, config).await?;
    if hits.is_empty() {
        return Ok(());
    }

    for hit in &hits {
        let severity = bounce_harvest_severity(hit.bounce_count, hit.unique_targets);

        let existing = db
            .find_active_scene("bounce_harvest", &hit.target_domain)
            .await?;

        let now = Utc::now();

        if let Some(mut scene) = existing {
            scene.bounce_count = hit.bounce_count as i32;
            scene.unique_recipients = hit.unique_targets as i32;
            scene.time_window_end = chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            scene.threat_level = severity;
            scene.sample_subjects = hit.sample_subjects.clone();
            scene.sample_recipients = hit.sample_recipients.clone();
            scene.updated_at = now;

            if config.auto_block_enabled
                && !scene.auto_blocked
                && hit.bounce_count >= config.auto_block_bounce_threshold
            {
                // For bounce harvest, we block the target domain in a different way:
                // create an alert IOC for the probed domain pattern
                let ioc_id = auto_block_domain(
                    db,
                    &hit.target_domain,
                    "bounce_harvest",
                    config.auto_block_duration_hours,
                    &format!(
                        "Bounce harvest auto-block: {} bounces detected in {}h, {} addresses probed",
                        hit.bounce_count, config.time_window_hours, hit.unique_targets
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    target_domain = %hit.target_domain,
                    bounces = hit.bounce_count,
                    "Bounce harvest scene: auto-blocked"
                );
            }

            db.upsert_threat_scene(&scene).await?;
        } else {
            let mut scene = ThreatScene {
                id: Uuid::new_v4(),
                scene_type: ThreatSceneType::BounceHarvest,
                actor: hit.target_domain.clone(),
                actor_type: "domain".to_string(),
                target_domain: Some(hit.target_domain.clone()),
                time_window_start: chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                time_window_end: chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                email_count: 0,
                unique_recipients: hit.unique_targets as i32,
                bounce_count: hit.bounce_count as i32,
                sample_subjects: hit.sample_subjects.clone(),
                sample_recipients: hit.sample_recipients.clone(),
                threat_level: severity,
                status: ThreatSceneStatus::Active,
                auto_blocked: false,
                ioc_id: None,
                details: serde_json::json!({}),
                created_at: now,
                updated_at: now,
            };

            if config.auto_block_enabled
                && hit.bounce_count >= config.auto_block_bounce_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.target_domain,
                    "bounce_harvest",
                    config.auto_block_duration_hours,
                    &format!(
                        "Bounce harvest auto-block: {} bounces detected in {}h, {} addresses probed",
                        hit.bounce_count, config.time_window_hours, hit.unique_targets
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    target_domain = %hit.target_domain,
                    bounces = hit.bounce_count,
                    "New bounce harvest scene: auto-blocked"
                );
            }

            info!(
                target_domain = %hit.target_domain,
                bounces = hit.bounce_count,
                unique_targets = hit.unique_targets,
                severity = %severity,
                "Detected bounce harvest scene (Directory Harvest Attack)"
            );
            db.upsert_threat_scene(&scene).await?;
        }
    }

    Ok(())
}

fn bounce_harvest_severity(bounce_count: i64, unique_targets: i64) -> ThreatLevel {
    // Base level from bounce count
    let base = if bounce_count >= 150 {
        ThreatLevel::Critical
    } else if bounce_count >= 50 {
        ThreatLevel::High
    } else if bounce_count >= 15 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    };

    // Bonus escalation if many unique targets probed
    if unique_targets >= 50 && base < ThreatLevel::High {
        ThreatLevel::High
    } else if unique_targets >= 10 && base < ThreatLevel::Medium {
        ThreatLevel::Medium
    } else {
        base
    }
}

// ─── Auto-block via IOC ─────────────────────────────────────────────────

async fn auto_block_domain(
    db: &VigilDb,
    domain: &str,
    attack_type: &str,
    duration_hours: i64,
    context: &str,
) -> anyhow::Result<String> {
    let now = Utc::now();
    let expires = now + Duration::hours(duration_hours);
    let id = Uuid::new_v4();

    let ioc = IocEntry {
        id,
        indicator: domain.to_lowercase(),
        ioc_type: "domain".to_string(),
        source: "scene_auto".to_string(),
        verdict: "malicious".to_string(),
        confidence: 0.85,
        attack_type: attack_type.to_string(),
        first_seen: now,
        last_seen: now,
        hit_count: 0,
        context: Some(context.to_string()),
        expires_at: Some(expires),
        created_at: now,
        updated_at: now,
    };

    db.upsert_ioc(&ioc).await?;
    Ok(id.to_string())
}
