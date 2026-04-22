//! Internal domain auto-detection and periodic refresh.

//! Detects which email domains belong to the organization by analyzing
//! historical mail flow patterns (domains with many unique senders).

use std::collections::HashSet;

use tracing::{info, warn};
use vigilyx_db::VigilDb;

use crate::module_data::module_data;

/// InternalDomaindetectThreshold: DomainAt least Countof SameSendingDomain Internal
const INTERNAL_DOMAIN_MIN_SENDERS: i32 = 5;
/// detect:recent Dayofemaildata
const INTERNAL_DOMAIN_SCAN_DAYS: i32 = 30;
/// Check whether a domain is a well-known public email service domain.
/// Delegates to the runtime `module_data()` registry (key `public_mail_domains`).
/// Used to:
/// 1. Exclude from internal domain auto-detection
/// 2. Skip "first contact" checks in identity_anomaly (millions of users share these domains)
pub(crate) fn is_public_mail_domain(domain: &str) -> bool {
    module_data().contains("public_mail_domains", domain)
}

/// From DB LoadalreadydetectofInternalDomain,if not Firstdetect
pub(crate) async fn load_internal_domains(db: &VigilDb) -> HashSet<String> {
    // From config tableLoadalreadySaveofResult
    if let Ok(Some(json)) = db.get_internal_domains().await
        && let Ok(domains) = serde_json::from_str::<Vec<String>>(&json)
        && !domains.is_empty()
    {
        info!(
            count = domains.len(),
            "From DB LoadInternalDomain: {:?}", domains
        );
        return domains.into_iter().collect();
    }

    // not SaveofResult,Firstdetect
    info!("FirstdetectInternalDomain...");
    refresh_internal_domains(db).await
}

/// detect UpdateInternalDomain
pub(crate) async fn refresh_internal_domains(db: &VigilDb) -> HashSet<String> {
    let mut domains = HashSet::new();

    // InternalDomain ByAutodetect, Encode Domain.
    // if, INTERNAL_DOMAINS EnvironmentVariable (Numberdelimited).
    if let Ok(env_domains) = std::env::var("INTERNAL_DOMAINS") {
        for d in env_domains
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
        {
            domains.insert(d);
        }
    }

    match db
        .detect_internal_domains(INTERNAL_DOMAIN_SCAN_DAYS, INTERNAL_DOMAIN_MIN_SENDERS)
        .await
    {
        Ok(detected) => {
            for (domain, sender_count) in &detected {
                // Exclude emailServiceDomain
                if is_public_mail_domain(domain) {
                    continue;
                }
                info!(
                    domain = %domain,
                    unique_senders = sender_count,
                    "AutoDetectedInternalDomain"
                );
                domains.insert(domain.clone());
            }
        }
        Err(e) => {
            warn!("InternalDomaindetectFailed: {}", e);
        }
    }

    // Save config table
    let domain_list: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
    if let Ok(json) = serde_json::to_string(&domain_list)
        && let Err(e) = db.set_internal_domains(&json).await
    {
        warn!("SaveInternalDomainFailed: {}", e);
    }

    info!(count = domains.len(), "InternalDomainSet: {:?}", domains);
    domains
}
