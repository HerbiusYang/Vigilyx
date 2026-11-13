//! AI service configuration, credential loading, and connection lifecycle.

use tracing::{info, warn};
use vigilyx_core::{DEFAULT_INTERNAL_SERVICE_HOSTS, validate_internal_service_url};
use vigilyx_db::VigilDb;

use crate::config::AiServiceConfig;

use super::remote::{LlmRequestConfig, RemoteModuleProxy};

/// Load AI service configuration from DB and build the remote proxy.
pub(crate) async fn build_ai_remote(db: &VigilDb) -> Option<RemoteModuleProxy> {
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

    if let Err(error) = ai_config.validate() {
        warn!(error = %error, "SEC: invalid AI service configuration, refusing to connect");
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

    let proxy = RemoteModuleProxy::new(ai_config.service_url.clone())
        .with_llm_config(llm_request_config(&ai_config));

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

/// Build the optional LLM second-opinion config from AiServiceConfig.
///
/// Only attached when a remote provider (claude/openai) and an API key are
/// both configured; the Python AI service only uses it to re-check emails
/// whose local NLP result is uncertain, and failures there are fail-open.
fn llm_request_config(ai_config: &AiServiceConfig) -> Option<LlmRequestConfig> {
    let provider = ai_config.provider.trim();
    if provider.is_empty() || provider == "local" {
        return None;
    }

    // api_key is stored AES-256-GCM encrypted ("ENC:" prefix); decrypt it the
    // same way the VirusTotal key is handled below.
    let api_key = if ai_config.api_key.starts_with("ENC:") {
        match vigilyx_core::decrypt_config_secret(&ai_config.api_key) {
            Ok(key) => key,
            Err(_) => {
                warn!("LLM api_key decryption failed, LLM second-opinion analysis disabled");
                return None;
            }
        }
    } else {
        ai_config.api_key.clone()
    };
    if api_key.is_empty() {
        return None;
    }

    info!(
        provider,
        model = %ai_config.model,
        "LLM second-opinion analysis enabled for uncertain NLP results"
    );
    Some(LlmRequestConfig {
        provider: provider.to_string(),
        api_key,
        model: ai_config.model.clone(),
        temperature: ai_config.temperature,
        max_tokens: ai_config.max_tokens,
    })
}
