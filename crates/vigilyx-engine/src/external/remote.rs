//! AI RemoteModule

//! Features:
//! - Rust -> Python AI Service of HTTP
//! - /analyze/content
//! - TimeoutAndErrorProcess

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::module::ThreatLevel;

/// Optional LLM second-opinion configuration forwarded to the AI service.
/// Only attached when both a remote provider and an API key are configured;
/// the Python side treats it as an advisory re-check for uncertain local results.
#[derive(Clone, Serialize)]
pub struct LlmRequestConfig {
    pub provider: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f64,
    pub max_tokens: u32,
}

impl std::fmt::Debug for LlmRequestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmRequestConfig")
            .field("provider", &self.provider)
            .field(
                "api_key",
                &if self.api_key.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .field("model", &self.model)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .finish()
    }
}

/// AI AnalyzeRequest - emailContent
#[derive(Debug, Clone, Serialize)]
pub struct ContentAnalysisRequest {
    pub session_id: String,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    /// Optional LLM second-opinion config; omitted from the payload unless set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmRequestConfig>,
}

/// AI AnalyzeResponse (1)
#[derive(Debug, Clone, Deserialize)]
pub struct AiAnalysisResponse {
    pub threat_level: String,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub summary: String,
    pub details: Option<serde_json::Value>,
}

impl AiAnalysisResponse {
    pub fn to_threat_level(&self) -> ThreatLevel {
        match self.threat_level.as_str() {
            "safe" | "clean" => ThreatLevel::Safe,
            "low" => ThreatLevel::Low,
            "medium" | "moderate" => ThreatLevel::Medium,
            "high" => ThreatLevel::High,
            "critical" | "severe" => ThreatLevel::Critical,
            other => {
                tracing::warn!(
                    value = other,
                    "Unknown threat level from remote AI, treating as Medium"
                );
                ThreatLevel::Medium
            }
        }
    }

    /// True when the Python LLM second opinion flagged a forged/injected
    /// verdict (`details.llm_analysis.injection_suspected`). Consumers should
    /// surface this as an engine signal instead of leaving it a silent
    /// Python-side log line.
    pub fn llm_injection_suspected(&self) -> bool {
        self.details
            .as_ref()
            .and_then(|d| d.get("llm_analysis"))
            .and_then(|l| l.get("injection_suspected"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }
}

const AI_BACKOFF_BASE: Duration = Duration::from_secs(30);
const AI_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Background health probe interval during cooldown.
const HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(30);

struct RemoteAvailabilityState {
    unavailable_until_epoch_secs: AtomicU64,
    consecutive_failures: AtomicU32,
}

impl Default for RemoteAvailabilityState {
    fn default() -> Self {
        Self {
            unavailable_until_epoch_secs: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn extract_retry_after_secs(body: &str) -> Option<u64> {
    fn extract(value: &Value) -> Option<u64> {
        match value {
            Value::Number(num) => num.as_u64(),
            Value::String(s) => s.parse().ok(),
            Value::Object(map) => map
                .get("retry_after_secs")
                .and_then(extract)
                .or_else(|| map.get("detail").and_then(extract))
                .or_else(|| map.get("model_status").and_then(extract)),
            _ => None,
        }
    }

    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| extract(&value))
}

/// Remote AI
#[derive(Clone)]
pub struct RemoteModuleProxy {
    base_url: String,
    client: reqwest::Client,
    /// SEC-H07: AI service-scoped internal authentication token
    internal_token: String,
    availability: Arc<RemoteAvailabilityState>,
    /// Controls the background health probe task lifetime.
    /// Set to `false` when the proxy is no longer needed.
    alive: Arc<AtomicBool>,
    /// Optional LLM second-opinion config attached to /analyze/content requests.
    llm_config: Option<LlmRequestConfig>,
}

impl RemoteModuleProxy {
    pub fn new(base_url: String) -> Self {
        let internal_token = std::env::var("AI_INTERNAL_TOKEN").unwrap_or_default();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("AI remote client should build");

        Self {
            base_url,
            client,
            internal_token,
            availability: Arc::new(RemoteAvailabilityState::default()),
            alive: Arc::new(AtomicBool::new(true)),
            llm_config: None,
        }
    }

    /// Attach the LLM second-opinion config (from AiServiceConfig) so every
    /// /analyze/content request carries it. `None` keeps requests LLM-free.
    pub fn with_llm_config(mut self, llm_config: Option<LlmRequestConfig>) -> Self {
        self.llm_config = llm_config;
        self
    }

    /// Spawn a background tokio task that periodically probes the AI service
    /// health during cooldown periods. When the service becomes reachable
    /// again the cooldown is cleared automatically, breaking the
    /// "fail → backoff → no requests → never recover" loop.
    ///
    /// The task runs until `alive` is set to `false` (i.e. the proxy is dropped).
    pub fn spawn_background_probe(&self) {
        let client = self.client.clone();
        let base_url = self.base_url.clone();
        let availability = Arc::clone(&self.availability);
        let alive = Arc::clone(&self.alive);
        let internal_token = self.internal_token.clone();

        tokio::spawn(async move {
            // Wait a short initial delay before starting periodic probes
            tokio::time::sleep(Duration::from_secs(10)).await;

            loop {
                if !alive.load(Ordering::Relaxed) {
                    debug!("AI background health probe stopped (proxy dropped)");
                    break;
                }

                tokio::time::sleep(HEALTH_PROBE_INTERVAL).await;

                if !alive.load(Ordering::Relaxed) {
                    break;
                }

                // Only probe when we are in cooldown — no need to waste
                // cycles when the service is already marked available.
                let until = availability
                    .unavailable_until_epoch_secs
                    .load(Ordering::Relaxed);
                if until == 0 || now_epoch_secs() >= until {
                    continue;
                }

                // Perform a lightweight health check with a short timeout
                let ready_url = format!("{}/health/ready", base_url);
                let probe_timeout = Duration::from_secs(5);

                let ok: bool = tokio::time::timeout(probe_timeout, async {
                    let mut req = client.get(&ready_url);
                    if !internal_token.is_empty() {
                        req = req.header("X-Internal-Token", &internal_token);
                    }
                    match req.send().await {
                        Ok(resp) if resp.status().is_success() => true,
                        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                            // /health/ready not implemented, try /health
                            let liveness_url = format!("{}/health", base_url);
                            let mut req2 = client.get(&liveness_url);
                            if !internal_token.is_empty() {
                                req2 = req2.header("X-Internal-Token", &internal_token);
                            }
                            matches!(req2.send().await, Ok(r) if r.status().is_success())
                        }
                        _ => false,
                    }
                })
                .await
                .unwrap_or_default();

                if ok {
                    availability
                        .consecutive_failures
                        .store(0, Ordering::Relaxed);
                    availability
                        .unavailable_until_epoch_secs
                        .store(0, Ordering::Relaxed);
                    info!(
                        base_url = %base_url,
                        "AI service recovered — background probe cleared cooldown"
                    );
                } else {
                    debug!(
                        base_url = %base_url,
                        "AI background probe: service still unavailable"
                    );
                }
            }
        });
    }

    pub fn is_request_available(&self) -> bool {
        self.cooldown_remaining_secs() == 0
    }

    pub fn cooldown_remaining_secs(&self) -> u64 {
        let until = self
            .availability
            .unavailable_until_epoch_secs
            .load(Ordering::Relaxed);
        until.saturating_sub(now_epoch_secs())
    }

    pub fn note_probe_failure(&self) {
        self.record_failure("startup_health_probe");
    }

    pub fn note_timeout(&self) {
        self.record_failure("request_timeout");
    }

    pub fn note_success(&self) {
        self.availability
            .consecutive_failures
            .store(0, Ordering::Relaxed);
        self.availability
            .unavailable_until_epoch_secs
            .store(0, Ordering::Relaxed);
    }

    fn record_failure(&self, reason: &str) {
        let failures = self
            .availability
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let shift = failures.saturating_sub(1).min(4);
        let backoff_secs = (AI_BACKOFF_BASE.as_secs() << shift).min(AI_BACKOFF_MAX.as_secs());
        let until = now_epoch_secs().saturating_add(backoff_secs);
        self.availability
            .unavailable_until_epoch_secs
            .store(until, Ordering::Relaxed);
        warn!(
            base_url = %self.base_url,
            reason,
            failures,
            backoff_secs,
            "AI remote unavailable, enabling temporary cooldown"
        );
    }

    /// Check AI Servicewhether
    pub async fn health_check(&self) -> bool {
        let ready_url = format!("{}/health/ready", self.base_url);
        match self.client.get(&ready_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                self.note_success();
                return true;
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {}
            Ok(_) => return false,
            Err(_) => return false,
        }

        let liveness_url = format!("{}/health", self.base_url);
        match self.client.get(&liveness_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                self.note_success();
                true
            }
            Ok(_) => false,
            Err(_) => false,
        }
    }

    /// AnalyzeemailContent
    pub async fn analyze_content(
        &self,
        req: &ContentAnalysisRequest,
    ) -> Result<AiAnalysisResponse, RemoteError> {
        let url = format!("{}/analyze/content", self.base_url);
        // Attach the configured LLM second-opinion config unless the caller
        // already supplied one explicitly.
        let mut req = req.clone();
        if req.llm.is_none() {
            req.llm = self.llm_config.clone();
        }
        self.post_analyze(&url, &req).await
    }

    async fn post_analyze<T: Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<AiAnalysisResponse, RemoteError> {
        if !self.is_request_available() {
            return Err(RemoteError::TemporarilyUnavailable {
                retry_after_secs: self.cooldown_remaining_secs(),
            });
        }

        let mut req = self.client.post(url).json(body);
        // SEC-H07: AddInternalServiceAuthentication
        if !self.internal_token.is_empty() {
            req = req.header("X-Internal-Token", &self.internal_token);
        }
        let response = req.send().await.map_err(|e| {
            error!(url, "AI service request failed: {}", e);
            self.record_failure("connection_failed");
            RemoteError::ConnectionFailed(e.to_string())
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(url, %status, "AI service returned error: {}", body);
            if status.is_server_error() || status.as_u16() == 429 {
                self.record_failure("service_error");
                if matches!(status.as_u16(), 429 | 503) {
                    return Err(RemoteError::TemporarilyUnavailable {
                        retry_after_secs: extract_retry_after_secs(&body)
                            .unwrap_or_else(|| self.cooldown_remaining_secs().max(1)),
                    });
                }
            }
            return Err(RemoteError::ServiceError {
                status: status.as_u16(),
                message: body,
            });
        }

        let parsed = response.json::<AiAnalysisResponse>().await.map_err(|e| {
            error!(url, "Failed to parse AI response: {}", e);
            self.record_failure("parse_error");
            RemoteError::ParseError(e.to_string())
        })?;
        self.note_success();
        Ok(parsed)
    }
}

impl Drop for RemoteModuleProxy {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
    }
}

/// Remote Error
#[derive(Debug)]
pub enum RemoteError {
    ConnectionFailed(String),
    ServiceError { status: u16, message: String },
    ParseError(String),
    Timeout,
    TemporarilyUnavailable { retry_after_secs: u64 },
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            RemoteError::ServiceError { status, message } => {
                write!(f, "Service error ({}): {}", status, message)
            }
            RemoteError::ParseError(e) => write!(f, "Parse error: {}", e),
            RemoteError::Timeout => write!(f, "Request timeout"),
            RemoteError::TemporarilyUnavailable { retry_after_secs } => {
                write!(
                    f,
                    "Temporarily unavailable, retry after {}s",
                    retry_after_secs
                )
            }
        }
    }
}

impl std::error::Error for RemoteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_retry_after_secs_reads_nested_payloads() {
        let body = r#"{"error":"MODEL_UNAVAILABLE","retry_after_secs":120,"detail":{"retry_after_secs":"45"}}"#;
        assert_eq!(extract_retry_after_secs(body), Some(120));

        let nested = r#"{"detail":{"model_status":{"retry_after_secs":33}}}"#;
        assert_eq!(extract_retry_after_secs(nested), Some(33));
    }

    #[test]
    fn extract_retry_after_secs_returns_none_for_invalid_payloads() {
        assert_eq!(extract_retry_after_secs("not-json"), None);
        assert_eq!(
            extract_retry_after_secs(r#"{"detail":{"retry_after_secs":"soon"}}"#),
            None
        );
    }

    #[test]
    fn timeout_marks_proxy_temporarily_unavailable() {
        let proxy = RemoteModuleProxy::new("http://127.0.0.1:8900".to_string());
        assert!(proxy.is_request_available());

        proxy.note_timeout();

        assert!(!proxy.is_request_available());
        assert!(proxy.cooldown_remaining_secs() > 0);
    }

    #[test]
    fn successful_health_probe_clears_cooldown_state() {
        let proxy = RemoteModuleProxy::new("http://127.0.0.1:8900".to_string());
        proxy.note_timeout();
        assert!(!proxy.is_request_available());

        proxy.note_success();

        assert!(proxy.is_request_available());
        assert_eq!(proxy.cooldown_remaining_secs(), 0);
    }

    fn sample_request() -> ContentAnalysisRequest {
        ContentAnalysisRequest {
            session_id: "s1".to_string(),
            subject: Some("hi".to_string()),
            body_text: Some("body".to_string()),
            body_html: None,
            mail_from: Some("a@b.com".to_string()),
            rcpt_to: vec!["c@d.com".to_string()],
            llm: None,
        }
    }

    fn sample_llm_config() -> LlmRequestConfig {
        LlmRequestConfig {
            provider: "claude".to_string(),
            api_key: "sk-secret".to_string(),
            model: "claude-3-5-sonnet-20241022".to_string(),
            temperature: 0.3,
            max_tokens: 1024,
        }
    }

    #[test]
    fn request_without_llm_omits_field_from_json() {
        let json = serde_json::to_value(sample_request()).unwrap();
        assert!(json.get("llm").is_none());
    }

    #[test]
    fn request_with_llm_serializes_config() {
        let mut req = sample_request();
        req.llm = Some(sample_llm_config());
        let json = serde_json::to_value(&req).unwrap();
        let llm = json.get("llm").expect("llm field should be present");
        assert_eq!(llm["provider"], "claude");
        assert_eq!(llm["api_key"], "sk-secret");
        assert_eq!(llm["model"], "claude-3-5-sonnet-20241022");
        assert_eq!(llm["max_tokens"], 1024);
    }

    #[test]
    fn llm_config_debug_masks_api_key() {
        let rendered = format!("{:?}", sample_llm_config());
        assert!(!rendered.contains("sk-secret"));
        assert!(rendered.contains("***"));
    }

    // ─── llm_injection_suspected consumption (R4 遗留5) ───

    fn response_with_details(details: serde_json::Value) -> AiAnalysisResponse {
        AiAnalysisResponse {
            threat_level: "medium".to_string(),
            confidence: 0.5,
            categories: vec![],
            summary: "test".to_string(),
            details: Some(details),
        }
    }

    #[test]
    fn llm_injection_suspected_true_when_python_flagged_forged_verdict() {
        // Python drops a forged verdict (e.g. an injected
        // "threat_level": "definitely_safe_green") and sets this flag.
        let resp = response_with_details(serde_json::json!({
            "malicious_probability": 0.5,
            "llm_analysis": {
                "provider": "claude",
                "verdict": null,
                "injection_suspected": true,
            }
        }));
        assert!(resp.llm_injection_suspected());
    }

    #[test]
    fn llm_injection_suspected_false_for_normal_llm_reply() {
        let resp = response_with_details(serde_json::json!({
            "llm_analysis": {
                "provider": "claude",
                "verdict": "high",
                "injection_suspected": false,
            }
        }));
        assert!(!resp.llm_injection_suspected());
    }

    #[test]
    fn llm_injection_suspected_false_when_llm_never_ran() {
        let mut resp = response_with_details(serde_json::json!({
            "malicious_probability": 0.9
        }));
        assert!(!resp.llm_injection_suspected());
        resp.details = None;
        assert!(!resp.llm_injection_suspected());
    }
}
