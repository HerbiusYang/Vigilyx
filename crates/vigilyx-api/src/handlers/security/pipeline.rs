//! Stream Configuration, Modulemetadata, detect

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::super::ApiResponse;
use super::publish_engine_reload;
use crate::AppState;
use crate::auth::AuthenticatedUser;

async fn load_keyword_system_seed(
    state: &Arc<AppState>,
) -> Result<vigilyx_engine::modules::content_scan::KeywordOverrides, axum::response::Response> {
    use vigilyx_engine::modules::content_scan::{KeywordOverrides, normalize_system_keyword_seed};

    match state.engine_db.get_config("keyword_system_seed").await {
        Ok(Some(json)) => {
            let seed: KeywordOverrides = serde_json::from_str(&json).unwrap_or_default();
            Ok(normalize_system_keyword_seed(&seed))
        }
        Ok(None) => Ok(KeywordOverrides::default()),
        Err(e) => Err(ApiResponse::<serde_json::Value>::internal_err(
            &e,
            "读取系统关键词词库failed",
        )
        .into_response()),
    }
}

// Stream Configuration

/// GetStream Configuration
pub async fn get_pipeline_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_pipeline_config().await {
        Ok(Some(json)) => {
            let mut config = serde_json::from_str::<vigilyx_engine::config::PipelineConfig>(&json)
                .unwrap_or_default();
            config.merge_default_modules();
            ApiResponse::ok(config)
        }
        Ok(None) => {
            // DefaultConfiguration
            let default = vigilyx_engine::config::PipelineConfig::default();
            ApiResponse::ok(default)
        }
        Err(e) => ApiResponse::<vigilyx_engine::config::PipelineConfig>::internal_err(
            &e,
            "Operation failed",
        ),
    }
}

/// NewStream Configuration
pub async fn update_pipeline_config(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
    // verifyConfigurationformat
    let mut parsed: vigilyx_engine::config::PipelineConfig =
        match serde_json::from_value(config.clone()) {
            Ok(c) => c,
            Err(e) => {
                return ApiResponse::<serde_json::Value>::bad_request(format!(
                    "Invalid config: {}",
                    e
                ))
                .into_response();
            }
        };

    parsed.merge_default_modules();

    // Validate security-critical VerdictConfig ranges (A03 hardening)
    if let Err(violations) = parsed.verdict_config.validate() {
        tracing::warn!(
            violations = ?violations,
            "VerdictConfig API update rejected — potential security config tampering"
        );
        return ApiResponse::<serde_json::Value>::bad_request(format!(
            "VerdictConfig validation failed: {}",
            violations.join("; ")
        ))
        .into_response();
    }

    let json_str = match serde_json::to_string(&parsed) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "序列化Configurationfailed: {}",
                e
            ))
            .into_response();
        }
    };
    match state.engine_db.set_pipeline_config(&json_str).await {
        Ok(()) => {
            // Engine process NewConfiguration
            publish_engine_reload(&state, "config").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_pipeline_config",
                Some("security"),
                Some("security_pipeline".to_string()),
                None,
            );
            ApiResponse::ok(parsed).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ModuleMetadataResponse {
    id: String,
    name: String,
    pillar: String,
    description: String,
    supports_ai: bool,
    depends_on: Vec<String>,
    engine_id: Option<String>,
}

/// Get module metadata for every configured module.
///
/// Inclusion is derived from `PipelineConfig`, so adding a default module can no longer
/// silently hide it from the frontend. Display metadata has a safe generic fallback.
pub async fn get_modules_metadata(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut config = match state.engine_db.get_pipeline_config().await {
        Ok(Some(json)) => serde_json::from_str::<vigilyx_engine::config::PipelineConfig>(&json)
            .unwrap_or_default(),
        Ok(None) => vigilyx_engine::config::PipelineConfig::default(),
        Err(error) => {
            tracing::warn!(%error, "Failed to load pipeline config for module metadata");
            vigilyx_engine::config::PipelineConfig::default()
        }
    };
    config.merge_default_modules();

    ApiResponse::ok(build_modules_metadata(&config))
}

fn build_modules_metadata(
    config: &vigilyx_engine::config::PipelineConfig,
) -> Vec<ModuleMetadataResponse> {
    config
        .modules
        .iter()
        .map(|module| {
            let mut metadata = module_metadata(&module.id);
            metadata.depends_on = module
                .condition
                .as_ref()
                .and_then(|condition| condition.depends_module.clone())
                .into_iter()
                .collect();
            metadata
        })
        .collect()
}

fn module_metadata(id: &str) -> ModuleMetadataResponse {
    let (name, pillar, description, supports_ai, depends_on): (&str, &str, &str, bool, &[&str]) =
        match id {
            "content_scan" => (
                "Content scan",
                "content",
                "Phishing, BEC, and DLP content analysis",
                true,
                &[],
            ),
            "html_scan" => (
                "HTML scan",
                "content",
                "Malicious HTML and active-content analysis",
                false,
                &[],
            ),
            "html_pixel_art" => (
                "HTML pixel-art scan",
                "content",
                "Visual phishing and pixel-art text analysis",
                false,
                &[],
            ),
            "attach_scan" => (
                "Attachment type scan",
                "attachment",
                "Dangerous file type and MIME mismatch analysis",
                false,
                &[],
            ),
            "attach_content" => (
                "Attachment content scan",
                "attachment",
                "Extracted attachment content analysis",
                true,
                &["attach_scan"],
            ),
            "attach_qr_scan" => (
                "Attachment QR scan",
                "attachment",
                "QR-code extraction and target analysis",
                false,
                &["attach_scan"],
            ),
            "attach_hash" => (
                "Attachment hash reputation",
                "attachment",
                "Local and external hash reputation checks",
                false,
                &["attach_scan"],
            ),
            "mime_scan" => (
                "MIME structure scan",
                "package",
                "MIME boundary, nesting, and type validation",
                false,
                &[],
            ),
            "header_scan" => (
                "Mail header scan",
                "package",
                "Sender identity and transport-header validation",
                false,
                &[],
            ),
            "link_scan" => (
                "URL pattern scan",
                "link",
                "Suspicious URL pattern and homograph analysis",
                false,
                &[],
            ),
            "link_reputation" => (
                "URL reputation",
                "link",
                "Local and external URL reputation checks",
                false,
                &[],
            ),
            "link_content" => (
                "URL content scan",
                "link",
                "Remote landing-content analysis",
                true,
                &["link_scan"],
            ),
            "landing_page_scan" => (
                "Landing page scan",
                "link",
                "Phishing landing-page structure analysis",
                false,
                &["link_scan"],
            ),
            "aitm_detect" => (
                "Adversary-in-the-middle detection",
                "link",
                "AiTM proxy and authentication-flow analysis",
                false,
                &["link_scan"],
            ),
            "anomaly_detect" => (
                "Behavior anomaly detection",
                "package",
                "Sender baseline and delivery-pattern analysis",
                false,
                &[],
            ),
            "rmm_detect" => (
                "Remote-management lure detection",
                "content",
                "Remote management software lure analysis",
                false,
                &[],
            ),
            "prompt_injection_scan" => (
                "Prompt injection scan",
                "content",
                "Prompt-injection and model-manipulation analysis",
                false,
                &[],
            ),
            "toad_detect" => (
                "Telephone-oriented attack detection",
                "content",
                "Callback phishing and telephone lure analysis",
                false,
                &[],
            ),
            "semantic_scan" => (
                "Semantic scan",
                "semantic",
                "NLP phishing intent and semantic anomaly analysis",
                true,
                &[],
            ),
            "domain_verify" => (
                "Domain verification",
                "package",
                "SPF, DKIM, DMARC, and sender-domain validation",
                false,
                &[],
            ),
            "identity_anomaly" => (
                "Identity anomaly",
                "package",
                "Identity impersonation and first-contact analysis",
                false,
                &[],
            ),
            "transaction_correlation" => (
                "Transaction correlation",
                "package",
                "Cross-message transaction pattern correlation",
                false,
                &[],
            ),
            "av_eml_scan" => (
                "EML antivirus scan",
                "attachment",
                "Whole-message ClamAV analysis",
                false,
                &[],
            ),
            "av_attach_scan" => (
                "Attachment antivirus scan",
                "attachment",
                "Attachment-level ClamAV analysis",
                false,
                &["attach_scan"],
            ),
            "sandbox_scan" => (
                "Sandbox scan",
                "attachment",
                "Dynamic attachment behavior analysis",
                false,
                &["attach_scan"],
            ),
            "yara_scan" => (
                "YARA scan",
                "attachment",
                "YARA rule analysis for messages and attachments",
                false,
                &[],
            ),
            "verdict" => (
                "Final verdict",
                "verdict",
                "Aggregate module results into the final verdict",
                false,
                &["*"],
            ),
            _ => (id, "unknown", "Configured detection module", false, &[]),
        };

    ModuleMetadataResponse {
        id: id.to_string(),
        name: name.to_string(),
        pillar: pillar.to_string(),
        description: description.to_string(),
        supports_ai,
        depends_on: depends_on
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        engine_id: vigilyx_engine::engine_map::module_to_engine(id)
            .map(|engine| engine.label().to_string()),
    }
}

// detect

/// Get detect
pub async fn get_content_rules(State(state): State<Arc<AppState>>) -> axum::response::Response {
    let system_seed = match load_keyword_system_seed(&state).await {
        Ok(seed) => seed,
        Err(resp) => return resp,
    };
    let rules = vigilyx_engine::modules::content_scan::get_builtin_rules(&system_seed);
    ApiResponse::ok(rules).into_response()
}

// Configuration

/// Get Configuration (+ + Merge table)
pub async fn get_keyword_overrides(State(state): State<Arc<AppState>>) -> axum::response::Response {
    use vigilyx_engine::modules::content_scan::{
        KeywordOverrides, build_effective_keyword_lists, get_builtin_keyword_lists,
        normalize_user_keyword_overrides,
    };

    let system_seed = match load_keyword_system_seed(&state).await {
        Ok(seed) => seed,
        Err(resp) => return resp,
    };

    let stored_overrides: KeywordOverrides =
        match state.engine_db.get_config("keyword_overrides").await {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            Ok(None) => KeywordOverrides::default(),
            Err(e) => {
                return ApiResponse::<serde_json::Value>::internal_err(
                    &e,
                    "读取关键词Configurationfailed",
                )
                .into_response();
            }
        };
    let overrides = normalize_user_keyword_overrides(&system_seed, &stored_overrides);
    let effective =
        vigilyx_engine::modules::content_scan::ContentScanModule::new_with_keyword_lists(
            build_effective_keyword_lists(&system_seed, &overrides),
        )
        .effective_keywords();

    ApiResponse::ok(serde_json::json!({
        "builtin": get_builtin_keyword_lists(&system_seed),
        "overrides": overrides,
        "effective": effective,
    }))
    .into_response()
}

/// New Configuration
pub async fn update_keyword_overrides(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Response {
    use vigilyx_engine::modules::content_scan::{
        KeywordOverrides, normalize_user_keyword_overrides,
    };

    let system_seed = match load_keyword_system_seed(&state).await {
        Ok(seed) => seed,
        Err(resp) => return resp,
    };

    // verify JSON
    let overrides: KeywordOverrides = match serde_json::from_value(payload.clone()) {
        Ok(o) => o,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "关键词Configurationformaterror: {}",
                e
            ))
            .into_response();
        }
    };

    let normalized_overrides = normalize_user_keyword_overrides(&system_seed, &overrides);

    let json_str = match serde_json::to_string(&normalized_overrides) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("序列化failed: {}", e))
                .into_response();
        }
    };

    match state
        .engine_db
        .set_config("keyword_overrides", &json_str)
        .await
    {
        Ok(()) => {
            // Engine New (When)
            publish_engine_reload(&state, "keywords").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_keyword_overrides",
                Some("security"),
                Some("keyword_overrides".to_string()),
                None,
            );
            ApiResponse::ok(normalized_overrides).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "save关键词Configurationfailed")
                .into_response()
        }
    }
}

// ── Module Data Overrides ──────────────────────────────────────────

/// GET /api/security/module-data-overrides
/// Returns the current module data overrides stored in DB (empty object if none).
pub async fn get_module_data_overrides(
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    let overrides: serde_json::Value = match state
        .engine_db
        .get_config("engine_module_data_overrides")
        .await
    {
        Ok(Some(json)) => serde_json::from_str(&json).unwrap_or(serde_json::json!({})),
        Ok(None) => serde_json::json!({}),
        Err(e) => {
            return ApiResponse::<serde_json::Value>::internal_err(&e, "读取模块数据覆盖配置失败")
                .into_response();
        }
    };

    ApiResponse::ok(overrides).into_response()
}

/// PUT /api/security/module-data-overrides
/// Accepts a JSON object of overrides, persists to DB, and triggers engine reload.
pub async fn update_module_data_overrides(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Response {
    // Validate: must be a JSON object
    if !payload.is_object() {
        return ApiResponse::<serde_json::Value>::bad_request(
            "模块数据覆盖配置必须是 JSON 对象".to_string(),
        )
        .into_response();
    }

    let json_str = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("序列化失败: {}", e))
                .into_response();
        }
    };

    match state
        .engine_db
        .set_config("engine_module_data_overrides", &json_str)
        .await
    {
        Ok(()) => {
            publish_engine_reload(&state, "module_data").await;
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "update_module_data_overrides",
                Some("security"),
                Some("engine_module_data_overrides".to_string()),
                None,
            );
            ApiResponse::ok(payload).into_response()
        }
        Err(e) => ApiResponse::<serde_json::Value>::server_error(&e, "保存模块数据覆盖配置失败")
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::build_modules_metadata;

    #[test]
    fn module_metadata_covers_every_default_pipeline_module() {
        let config = vigilyx_engine::config::PipelineConfig::default();
        let expected: HashSet<_> = config
            .modules
            .iter()
            .map(|module| module.id.as_str())
            .collect();
        let metadata = build_modules_metadata(&config);
        let actual: HashSet<_> = metadata.iter().map(|module| module.id.as_str()).collect();

        assert_eq!(actual, expected);
        for (module, item) in config.modules.iter().zip(metadata.iter()) {
            let configured_dependency = module
                .condition
                .as_ref()
                .and_then(|condition| condition.depends_module.as_deref());
            assert_eq!(
                item.depends_on.first().map(String::as_str),
                configured_dependency
            );
        }
        assert!(
            metadata
                .iter()
                .filter(|module| module.id != "verdict")
                .all(|module| module.engine_id.is_some()),
            "every default detector must be assigned to a frontend engine"
        );
    }
}
