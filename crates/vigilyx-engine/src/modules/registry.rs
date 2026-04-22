use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tracing::{info, warn};
use vigilyx_core::{DEFAULT_INTERNAL_SERVICE_HOSTS, validate_internal_service_url};
use vigilyx_db::VigilDb;

use crate::config::AiServiceConfig;
use crate::db_service::DbQueryService;
use crate::external::clamav::ClamAvClient;
use crate::intel::{IntelLayer, IntelSourceConfig, reload_safe_domains_into};
use crate::ioc::IocManager;
use crate::module::SecurityModule;
use crate::remote::RemoteModuleProxy;

use super::aitm_detect::AitmDetectModule;
use super::anomaly_detect::AnomalyDetectModule;
use super::attach_content::AttachContentModule;
use super::attach_hash::AttachHashModule;
use super::attach_qr_scan::AttachmentQrScanModule;
use super::attach_scan::AttachScanModule;
use super::av_attach_scan::AvAttachScanModule;
use super::av_eml_scan::AvEmlScanModule;
use super::content_scan::ContentScanModule;
use super::domain_verify::DomainVerifyModule;
use super::header_scan::HeaderScanModule;
use super::html_scan::HtmlScanModule;
use super::identity_anomaly::IdentityAnomalyModule;
use super::landing_page_scan::LandingPageScanModule;
use super::link_content::LinkContentModule;
use super::link_reputation::LinkReputationModule;
use super::link_scan::LinkScanModule;
use super::mime_scan::MimeScanModule;
use super::semantic_scan::SemanticScanModule;
use super::transaction_correlation::TransactionCorrelationModule;
use super::verdict_module::VerdictModule;
use super::yara_scan::YaraScanModule;

/// Safe-domain handle type returned alongside the module registry.
pub type SafeDomainsHandle = Arc<std::sync::RwLock<HashSet<String>>>;

#[derive(Default)]
struct BuiltinWhitelistSeed {
    well_known_safe: HashSet<String>,
    url_trusted: HashSet<String>,
}

fn extract_seed_domains(seed: &serde_json::Value, section: &str) -> HashSet<String> {
    seed.get(section)
        .and_then(|value| value.get("items"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn builtin_whitelist_seed() -> &'static BuiltinWhitelistSeed {
    static SEED: OnceLock<BuiltinWhitelistSeed> = OnceLock::new();

    SEED.get_or_init(|| {
        let seed_json = include_str!("../../../../shared/schemas/system_whitelist_seed.json");
        let seed: serde_json::Value = match serde_json::from_str(seed_json) {
            Ok(seed) => seed,
            Err(error) => {
                warn!(
                    "Failed to parse system whitelist seed for runtime merge: {}",
                    error
                );
                return BuiltinWhitelistSeed::default();
            }
        };

        let intel_safe = extract_seed_domains(&seed, "intel_safe");
        let url_trusted = extract_seed_domains(&seed, "url_trusted");
        let mut well_known_safe = intel_safe;
        well_known_safe.extend(url_trusted.iter().cloned());

        BuiltinWhitelistSeed {
            well_known_safe,
            url_trusted,
        }
    })
}

/// Build the full module registry with all available modules.
/// Also returns the safe-domains handle (if intel is enabled) for use by `reload_runtime_ioc_caches`.
pub async fn build_module_registry(
    db: &VigilDb,
) -> (
    HashMap<String, Arc<dyn SecurityModule>>,
    Option<SafeDomainsHandle>,
) {
    let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();

    // Initialize the global module data registry (replaces all hardcoded static lists)
    crate::module_data::init_module_data_from_db(db).await;

    let register = |modules: &mut HashMap<String, Arc<dyn SecurityModule>>,
                    m: Arc<dyn SecurityModule>| {
        modules.insert(m.metadata().id.clone(), m);
    };

    // Load URL-structure trusted domains separately from general clean/intel domains.
    let url_trusted_domains = load_trusted_url_domains(db).await;
    let url_trusted_arc = Arc::new(url_trusted_domains);
    let well_known_safe_domains = load_well_known_safe_domains(db).await;
    let well_known_safe_arc = Arc::new(well_known_safe_domains);

    // Set domain set for link_content / link_scan is_trusted_url_domain() access
    super::link_scan::set_trusted_url_domains(Arc::clone(&url_trusted_arc));
    super::link_scan::set_well_known_safe_domains(Arc::clone(&well_known_safe_arc));

    // Build IntelLayer (loads API keys + safe domain cache from DB)
    let (intel, safe_domains_handle) = {
        let result = build_intel_layer(db).await;
        match result {
            Some((layer, handle)) => (Some(layer), Some(handle)),
            None => (None, None),
        }
    };

    // Build AI remote proxy (NLP phishing detection)
    let nlp_remote = build_ai_remote(db).await;

    let keyword_system_seed = load_keyword_system_seed(db).await;
    let keyword_overrides = load_keyword_overrides(db, &keyword_system_seed).await;
    let effective_keyword_lists = super::content_scan::build_effective_keyword_lists(
        &keyword_system_seed,
        &keyword_overrides,
    );
    crate::pipeline::verdict::set_runtime_scenario_patterns(
        crate::pipeline::verdict::ScenarioPatternLists::from(&effective_keyword_lists),
    );
    register(
        &mut modules,
        Arc::new(ContentScanModule::new_with_keyword_lists(
            effective_keyword_lists.clone(),
        )),
    );
    register(&mut modules, Arc::new(HtmlScanModule::new()));
    register(
        &mut modules,
        Arc::new(super::html_pixel_art::HtmlPixelArtModule::new()),
    );
    register(&mut modules, Arc::new(AttachScanModule::new()));
    register(
        &mut modules,
        Arc::new(AttachContentModule::new_with_keyword_lists(
            effective_keyword_lists.clone(),
        )),
    );
    register(
        &mut modules,
        Arc::new(AttachmentQrScanModule::new_with_keyword_lists(
            effective_keyword_lists.clone(),
        )),
    );
    register(&mut modules, Arc::new(AttachHashModule::new(intel.clone())));
    register(&mut modules, Arc::new(MimeScanModule::new()));
    let db_service: Arc<dyn DbQueryService> = Arc::new(db.clone());
    register(
        &mut modules,
        Arc::new(HeaderScanModule::new(
            Arc::clone(&db_service),
            intel.clone(),
        )),
    );
    register(&mut modules, Arc::new(LinkScanModule::new()));
    register(&mut modules, Arc::new(LinkReputationModule::new(intel)));
    register(
        &mut modules,
        Arc::new(LinkContentModule::new_with_keyword_lists(
            effective_keyword_lists.clone(),
        )),
    );
    register(
        &mut modules,
        Arc::new(LandingPageScanModule::new_with_keyword_lists(
            effective_keyword_lists.clone(),
        )),
    );
    register(&mut modules, Arc::new(AnomalyDetectModule::new()));
    register(&mut modules, Arc::new(AitmDetectModule::new()));
    register(&mut modules, Arc::new(SemanticScanModule::new(nlp_remote)));
    register(&mut modules, Arc::new(DomainVerifyModule::new()));
    register(
        &mut modules,
        Arc::new(IdentityAnomalyModule::new(Some(Arc::clone(&db_service)))),
    );
    register(&mut modules, Arc::new(TransactionCorrelationModule::new()));

    // ClamAV module registration
    let clamav_client = build_clamav_client().await;
    if let Some(ref client) = clamav_client {
        register(
            &mut modules,
            Arc::new(AvEmlScanModule::new(Arc::clone(client))),
        );
        register(
            &mut modules,
            Arc::new(AvAttachScanModule::new(Arc::clone(client))),
        );
    }

    // CAPEv2 sandbox module registration
    if let Some(sandbox_client) = build_sandbox_client().await {
        register(
            &mut modules,
            Arc::new(super::sandbox_scan::SandboxScanModule::new(sandbox_client)),
        );
    }

    // YARA rule module (built-in + DB rules)
    {
        // Seed built-in rules into DB on first start
        seed_builtin_yara_rules(db).await;

        // Collect hardcoded rule names to avoid loading duplicates from DB
        let hardcoded_names: HashSet<String> = {
            let mut names = HashSet::new();
            for (_, source) in crate::yara::rules::ALL_RULE_SOURCES {
                let mut c = yara_x::Compiler::new();
                if c.add_source(*source).is_ok() {
                    let built = c.build();
                    for r in built.iter() {
                        names.insert(r.identifier().to_string());
                    }
                }
            }
            names
        };

        // Load extra rules from DB (excluding hardcoded ones, grouped by source)
        let extra_sources: Vec<String> = match db.list_yara_rules(Some(true)).await {
            Ok(rules) => rules
                .into_iter()
                .filter(|r| !hardcoded_names.contains(&r.rule_name))
                .map(|r| r.rule_source)
                .collect(),
            Err(e) => {
                warn!("Failed to load DB YARA rules: {}", e);
                Vec::new()
            }
        };

        match crate::yara::engine::YaraEngine::new_with_custom(&extra_sources) {
            Ok(yara_engine) => {
                let engine = Arc::new(yara_engine);
                info!(
                    "YARA rule engine ready: {} rules ({} custom)",
                    engine.rule_count(),
                    extra_sources.len()
                );
                register(&mut modules, Arc::new(YaraScanModule::new(engine)));
            }
            Err(e) => {
                warn!(
                    "YARA rule engine initialization failed: {}, YARA scanning disabled",
                    e
                );
            }
        }
    }

    register(&mut modules, Arc::new(VerdictModule::new()));

    (modules, safe_domains_handle)
}

/// MTA inline verdict Tier 1 ID.
/// MTA inline (SMTP).
/// (Tier 2).
pub const INLINE_TIER1_MODULES: &[&str] = &[
    "content_scan",     // keyword / pattern scan (~200ms)
    "header_scan",      // SPF/DKIM/header analysis (~100ms)
    "html_scan",        // HTML structure scan (~200ms)
    "mime_scan",        // MIME structure scan (~100ms)
    "link_scan",        // URL analysis (~300ms)
    "attach_scan",      // attachment metadata (~200ms)
    "attach_hash",      // attachment hash IOC lookup (~200ms)
    "domain_verify",    // DNS verification (~500ms)
    "anomaly_detect",   // anomaly detection (~200ms)
    "identity_anomaly", // identity anomaly (~200ms)
    "yara_scan",        // YARA rule scan (~500ms)
    "av_eml_scan",      // ClamAV EML scan (~1000ms)
    "av_attach_scan",   // ClamAV attachment scan (~1000ms)
    "html_pixel_art",   // pixel art detection (~100ms)
    "attach_content",   // attachment content scan (~500ms)
];

// Tier 2 (async only): semantic_scan, link_content, link_reputation,
// transaction_correlation, sandbox_scan, verdict_module

/// Check whether a module is in Tier 1 (eligible for MTA inline verdict).
pub fn is_inline_tier1(module_id: &str) -> bool {
    INLINE_TIER1_MODULES.contains(&module_id)
}

/// Reload IOC-derived runtime caches without rebuilding the whole module registry.
/// `safe_domains` is the handle returned by `build_module_registry` — pass `None` if intel is disabled.
pub async fn reload_runtime_ioc_caches(db: &VigilDb, safe_domains: Option<&SafeDomainsHandle>) {
    let url_trusted_domains = load_trusted_url_domains(db).await;
    super::link_scan::set_trusted_url_domains(Arc::new(url_trusted_domains));
    let well_known_safe_domains = load_well_known_safe_domains(db).await;
    super::link_scan::set_well_known_safe_domains(Arc::new(well_known_safe_domains));
    if let Some(handle) = safe_domains {
        reload_safe_domains_into(db, handle).await;
    }
}

/// Load trusted URL domains from DB (used by link_scan / link_content structural checks).
async fn load_trusted_url_domains(db: &VigilDb) -> HashSet<String> {
    let mut set = builtin_whitelist_seed().url_trusted.clone();
    match db.load_url_trusted_domains().await {
        Ok(domains) => {
            set.extend(domains);
            info!("Trusted URL domains loaded: {} entries", set.len());
            set
        }
        Err(e) => {
            warn!(
                "Failed to load trusted URL domains from DB: {}, using built-in seed only ({} entries)",
                e,
                set.len()
            );
            set
        }
    }
}

/// Load well-known built-in safe domains used by sender-domain heuristics.
async fn load_well_known_safe_domains(db: &VigilDb) -> HashSet<String> {
    let mut set = builtin_whitelist_seed().well_known_safe.clone();
    match db.load_system_clean_domains().await {
        Ok(domains) => {
            set.extend(domains);
            info!("Well-known safe domains loaded: {} entries", set.len());
            set
        }
        Err(e) => {
            warn!(
                "Failed to load well-known safe domains from DB: {}, using built-in seed only ({} entries)",
                e,
                set.len()
            );
            set
        }
    }
}

/// Load AI service configuration from DB and build the remote proxy.
async fn build_ai_remote(db: &VigilDb) -> Option<RemoteModuleProxy> {
    let ai_config: AiServiceConfig = match db.get_config("ai_service_config").await {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(e) => {
                warn!("AI service config parse failed: {}, using defaults", e);
                AiServiceConfig::default()
            }
        },
        _ => AiServiceConfig::default(),
    };

    // Check whether AI is enabled (frontend/wizard ai_enabled toggle + AI_ENABLED env var)
    if !ai_config.enabled {
        info!(
            "AI analysis service disabled (enabled=false), semantic detection will use rule-only mode"
        );
        return None;
    }

    // SEC: Validate URL allowlist at runtime, not just save-time (CWE-918)
    // Protects against DB poisoning / dirty backup restore leaking email content + token
    if let Err(err) =
        validate_internal_service_url(&ai_config.service_url, DEFAULT_INTERNAL_SERVICE_HOSTS)
    {
        warn!(
            url = %ai_config.service_url,
            error = %err,
            "SEC: AI service URL from DB failed allowlist check, refusing to connect"
        );
        return None;
    }

    let proxy = RemoteModuleProxy::new(ai_config.service_url.clone());

    // Health check (5s timeout): verify Python NLP service is reachable.
    // AI model loading can take 5-10 minutes, so a startup failure is normal.
    // The background health probe will clear the cooldown once the service
    // becomes available — we intentionally do NOT call note_probe_failure()
    // here to avoid entering cooldown before the service has finished loading.
    match tokio::time::timeout(std::time::Duration::from_millis(5000), proxy.health_check()).await {
        Ok(true) => {
            info!(
                "NLP phishing detection service connected: {}",
                ai_config.service_url
            );
        }
        _ => {
            info!(
                "NLP phishing detection service not ready ({}), background probe will auto-recover",
                ai_config.service_url,
            );
        }
    }

    // Always spawn background health probe — it will periodically check the
    // service during cooldown and clear backoff state on success.
    proxy.spawn_background_probe();

    Some(proxy)
}

/// Load intel source config from DB and build IntelLayer.
/// Returns the layer + safe-domains handle (for runtime reload).
async fn build_intel_layer(db: &VigilDb) -> Option<(IntelLayer, SafeDomainsHandle)> {
    let mut config: IntelSourceConfig = match db.get_config("intel_sources").await {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Intel source config parse failed: {}, using defaults (OTX + VT Scrape enabled)",
                    e
                );
                IntelSourceConfig::default()
            }
        },
        _ => IntelSourceConfig::default(),
    };

    // SEC: Decrypt API keys from encrypted DB storage (CWE-312)
    if let Some(ref key) = config.abuseipdb_api_key
        && let Some(decrypted) = decrypt_enc_value(key)
    {
        config.abuseipdb_api_key = Some(decrypted);
    }
    if let Some(ref key) = config.virustotal_api_key
        && let Some(decrypted) = decrypt_enc_value(key)
    {
        config.virustotal_api_key = Some(decrypted);
    }

    // VT Scrape and NLP share the same Python AI service (port 8900).
    // When vt_scrape_url is not configured, inherit the AI service address.
    // In Docker: VT Scrape auto-uses http://ai:8900
    // Default: http://127.0.0.1:8900 (handles localhost AI service).
    if config.vt_scrape_enabled
        && config.vt_scrape_url.is_none()
        && let Ok(Some(ai_json)) = db.get_config("ai_service_config").await
        && let Ok(ai_cfg) = serde_json::from_str::<AiServiceConfig>(&ai_json)
    {
        info!(
            "VT Scrape URL not configured, inheriting AI service address: {}",
            ai_cfg.service_url
        );
        config.vt_scrape_url = Some(ai_cfg.service_url);
    }

    if config.vt_scrape_enabled {
        let vt_base_url = config.vt_scrape_base_url();
        if let Err(err) =
            validate_internal_service_url(&vt_base_url, DEFAULT_INTERNAL_SERVICE_HOSTS)
        {
            warn!(
                url = %vt_base_url,
                error = %err,
                "SEC: VT scrape URL from DB failed internal allowlist check, disabling VT scrape"
            );
            config.vt_scrape_enabled = false;
        }
    }

    // At least one intel source must be enabled to create IntelLayer
    let has_otx = config.otx_enabled;
    let has_vt_api = config.virustotal_api_key.is_some();
    let has_vt_scrape = config.vt_scrape_enabled;
    let has_abuse = config.abuseipdb_enabled && config.abuseipdb_api_key.is_some();
    if !has_otx && !has_vt_api && !has_vt_scrape && !has_abuse {
        info!("All intel sources disabled, external intel queries not started");
        return None;
    }

    // Load safe domain cache from DB (verdict='clean')
    let safe_domains: HashSet<String> = match db.load_clean_domains().await {
        Ok(domains) => domains.into_iter().collect(),
        Err(e) => {
            warn!("Failed to load safe domain cache: {}", e);
            HashSet::new()
        }
    };

    let safe_domains_handle: SafeDomainsHandle = Arc::new(std::sync::RwLock::new(safe_domains));
    let ioc_manager = IocManager::new(db.clone());
    let layer = IntelLayer::new(ioc_manager, config, Arc::clone(&safe_domains_handle));
    info!(
        otx = has_otx,
        vt_api = has_vt_api,
        vt_scrape = has_vt_scrape,
        abuseipdb = has_abuse,
        "External intel query layer initialized"
    );
    Some((layer, safe_domains_handle))
}

/// Seed built-in YARA rules into DB (first start, deduplicated by rule_name).
async fn seed_builtin_yara_rules(db: &vigilyx_db::VigilDb) {
    use crate::yara::rules::{ALL_RULE_SOURCES, RULE_CATEGORIES};

    // Parse each rule's name, category, severity, description
    for (category, source) in ALL_RULE_SOURCES {
        // Compile with yara-x to extract rule metadata
        let mut compiler = yara_x::Compiler::new();
        if compiler.add_source(*source).is_err() {
            continue;
        }
        let rules = compiler.build();

        for rule in rules.iter() {
            let meta: Vec<(&str, yara_x::MetaValue<'_>)> = rule.metadata().collect();
            let description = meta
                .iter()
                .find(|(k, _)| *k == "description")
                .and_then(|(_, v)| match v {
                    yara_x::MetaValue::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .unwrap_or_default();
            let severity = meta
                .iter()
                .find(|(k, _)| *k == "severity")
                .and_then(|(_, v)| match v {
                    yara_x::MetaValue::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .unwrap_or_else(|| "high".to_string());
            let cat_name = RULE_CATEGORIES
                .iter()
                .find(|c| c.id == *category)
                .map(|c| c.id)
                .unwrap_or(category);

            // Extract a minimal YARA source for each individual rule
            // (category source contains multiple rules; we build per-rule source for DB storage)
            let single_rule_source = format!(
                "rule {} {{\n  meta:\n    description = \"{}\"\n    category = \"{}\"\n    severity = \"{}\"\n  condition:\n    true\n}}",
                rule.identifier(),
                description.replace('"', "\\\""),
                cat_name,
                severity
            );

            let now = chrono::Utc::now().to_rfc3339();
            let row = vigilyx_db::YaraRuleRow {
                id: uuid::Uuid::new_v4().to_string(),
                rule_name: rule.identifier().to_string(),
                category: cat_name.to_string(),
                severity,
                source: "builtin".to_string(),
                rule_source: single_rule_source,
                description,
                enabled: true,
                hit_count: 0,
                created_at: now.clone(),
                updated_at: now,
            };

            if let Err(e) = db.upsert_builtin_yara_rule(&row).await {
                warn!(
                    rule_name = rule.identifier(),
                    error = %e,
                    "Failed to write built-in YARA rule to DB"
                );
            }
        }
    }

    match db.count_builtin_yara_rules().await {
        Ok(count) => info!("Built-in YARA rules synced to DB: {} entries", count),
        Err(e) => warn!("Failed to count built-in YARA rules: {}", e),
    }
}

/// Build ClamAV client (reads address from environment, performs ping check).
async fn build_clamav_client() -> Option<Arc<ClamAvClient>> {
    let enabled = std::env::var("CLAMAV_ENABLED")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if !enabled {
        info!("ClamAV antivirus disabled (CLAMAV_ENABLED=false)");
        return None;
    }

    let client = ClamAvClient::from_env();
    let addr = client.address();

    // Health check (500ms timeout)
    match tokio::time::timeout(std::time::Duration::from_millis(500), client.ping()).await {
        Ok(true) => {
            info!("ClamAV antivirus service connected: {}", addr);
            Some(Arc::new(client))
        }
        Ok(false) => {
            warn!(
                "ClamAV service not ready ({}), antivirus module will retry at runtime",
                addr
            );
            // Return client anyway; module will retry at runtime (ClamAV may start later)
            Some(Arc::new(client))
        }
        Err(_) => {
            warn!(
                "ClamAV service connection timed out ({}), antivirus module will retry at runtime",
                addr
            );
            Some(Arc::new(client))
        }
    }
}

/// Load keyword system seed from DB configuration.
async fn load_keyword_system_seed(db: &VigilDb) -> super::content_scan::KeywordOverrides {
    match db.get_config("keyword_system_seed").await {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(seed) => {
                info!("Keyword system seed loaded from DB");
                super::content_scan::normalize_system_keyword_seed(&seed)
            }
            Err(e) => {
                warn!("Keyword system seed parse failed: {}, using empty set", e);
                super::content_scan::KeywordOverrides::default()
            }
        },
        Ok(None) => {
            warn!("Keyword system seed not found in DB, using empty set");
            super::content_scan::KeywordOverrides::default()
        }
        Err(e) => {
            warn!("Failed to load keyword system seed: {}, using empty set", e);
            super::content_scan::KeywordOverrides::default()
        }
    }
}

async fn load_keyword_overrides(
    db: &VigilDb,
    system_seed: &super::content_scan::KeywordOverrides,
) -> super::content_scan::KeywordOverrides {
    match db.get_config("keyword_overrides").await {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(o) => {
                info!("Keyword custom overrides loaded from DB");
                super::content_scan::normalize_user_keyword_overrides(system_seed, &o)
            }
            Err(e) => {
                warn!(
                    "Keyword override config parse failed: {}, using built-in defaults",
                    e
                );
                super::content_scan::KeywordOverrides::default()
            }
        },
        _ => super::content_scan::KeywordOverrides::default(),
    }
}

/// SEC: Decrypt ENC:-prefixed config values (AES-256-GCM, shared algorithm with vigilyx-api) (CWE-312)
fn decrypt_enc_value(stored: &str) -> Option<String> {
    let encoded = stored.strip_prefix("ENC:")?;
    let jwt_secret = std::env::var("API_JWT_SECRET").ok()?;

    use sha2::{Digest, Sha256};
    let key_bytes: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"vigilyx-config-encryption-v1");
        hasher.update(jwt_secret.as_bytes());
        hasher.finalize().into()
    };

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if combined.len() < 13 {
        return None;
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::from_slice(&combined[..12]);
    let plaintext = cipher.decrypt(nonce, &combined[12..]).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Build sandbox client (only when SANDBOX_URL environment variable is set).
async fn build_sandbox_client() -> Option<Arc<crate::external::sandbox::SandboxClient>> {
    let client = crate::external::sandbox::SandboxClient::from_env()?;

    match tokio::time::timeout(Duration::from_secs(5), client.ping()).await {
        Ok(Ok(status)) => {
            let pending = status.tasks.as_ref().and_then(|t| t.pending).unwrap_or(0);
            let running = status.tasks.as_ref().and_then(|t| t.running).unwrap_or(0);
            info!(
                version = status.version.as_deref().unwrap_or("unknown"),
                pending, running, "CAPEv2 sandbox service connected"
            );
            Some(Arc::new(client))
        }
        Ok(Err(e)) => {
            info!(
                "CAPEv2 sandbox service unavailable: {}, sandbox module disabled",
                e
            );
            None
        }
        Err(_) => {
            info!("CAPEv2 sandbox service connection timed out, sandbox module disabled");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_whitelist_seed_keeps_key_runtime_domains_available() {
        let seed = builtin_whitelist_seed();

        assert!(seed.url_trusted.contains("aliyuncs.com"));
        assert!(seed.url_trusted.contains("email.amazonaws.cn"));
        assert!(seed.well_known_safe.contains("aliyuncs.com"));
        assert!(seed.well_known_safe.contains("qichacha.com.cn"));
    }
}
