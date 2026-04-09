//! Stream Configuration, Modulemetadata, detect

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::super::ApiResponse;
use super::publish_engine_reload;
use crate::AppState;

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
            let value: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            ApiResponse::ok(value)
        }
        Ok(None) => {
           // DefaultConfiguration
            let default = vigilyx_engine::config::PipelineConfig::default();
            ApiResponse::ok(serde_json::to_value(default).unwrap_or_default())
        }
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// NewStream Configuration
pub async fn update_pipeline_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<serde_json::Value>,
) -> axum::response::Response {
   // verifyConfigurationformat
    let _: vigilyx_engine::config::PipelineConfig = match serde_json::from_value(config.clone()) {
        Ok(c) => c,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::bad_request(format!("Invalid config: {}", e))
                .into_response();
        }
    };

    let json_str = match serde_json::to_string(&config) {
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
            ApiResponse::ok(config).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Get Modulemetadata
pub async fn get_modules_metadata(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
   // Module metadata
    let modules = serde_json::json!([
        {
            "id": "content_scan", "name": "内容detect", "pillar": "content",
            "description": "Phishing关键词、BEC 话术、DLP Sensitive datadetect",
            "supports_ai": true, "depends_on": []
        },
        {
            "id": "html_scan", "name": "HTML detect", "pillar": "content",
            "description": "Malicious HTML Yuan素、脚本注入、事件Process器detect",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "attach_scan", "name": "AttachmentTypedetect", "pillar": "attachment",
            "description": "危险FileType、双extension、MIME 不匹配、宏文档detect",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "attach_content", "name": "Attachment内容detect", "pillar": "attachment",
            "description": "文档文本Extract + 关键词/AI 内容analyze",
            "supports_ai": true, "depends_on": ["attach_scan"]
        },
        {
            "id": "attach_hash", "name": "Attachment哈希信誉", "pillar": "attachment",
            "description": "SHA256 local黑名单 + external情报Source比对",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "mime_scan", "name": "MIME 结构detect", "pillar": "package",
            "description": "嵌套深度、边界冲突、Content-Type 不符detect",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "header_scan", "name": "邮件头detect", "pillar": "package",
            "description": "Received 链、From/Reply-To 不匹配、Header 注入detect",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "link_scan", "name": "URL Modedetect", "pillar": "link",
            "description": "IP Address链接、同形字/Punycode、短链、href/文本不匹配detect",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "link_reputation", "name": "URL 信誉Query", "pillar": "link",
            "description": "localDomain黑名单 + external情报SourceQuery",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "link_content", "name": "URL 内容detect", "pillar": "link",
            "description": "抓取页面 → table单detect + AI 页面analyze",
            "supports_ai": true, "depends_on": ["link_scan"]
        },
        {
            "id": "anomaly_detect", "name": "异常行为detect", "pillar": "package",
            "description": "Sender基线偏离、frequency/收件人/time/Attachment行为异常",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "semantic_scan", "name": "语义detect", "pillar": "semantic",
            "description": "无语义乱码/生僻字/熵异常detect，识别垃圾混淆邮件",
            "supports_ai": false, "depends_on": []
        },
        {
            "id": "verdict", "name": "综合判定", "pillar": "verdict",
            "description": "收集全部Module结果 → 加权聚合 → 最终判定",
            "supports_ai": false, "depends_on": ["*"]
        }
    ]);

    ApiResponse::ok(modules)
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
            ApiResponse::ok(normalized_overrides).into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "save关键词Configurationfailed")
                .into_response()
        }
    }
}
