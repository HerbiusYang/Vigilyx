//! AI RemoteModule

//! Features:
//! - Rust -> Python AI Service of HTTP
//! - /analyze/content, /analyze/attachment, /analyze/link
//! - TimeoutAndErrorProcess

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::module::ThreatLevel;

/// AI AnalyzeRequest - emailContent
#[derive(Debug, Clone, Serialize)]
pub struct ContentAnalysisRequest {
    pub session_id: String,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
}

/// AI AnalyzeRequest - AttachmentContent
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentAnalysisRequest {
    pub session_id: String,
    pub filename: String,
    pub content_type: String,
    pub text_content: String,
}

/// AI AnalyzeRequest - linkConnect
#[derive(Debug, Clone, Serialize)]
pub struct LinkAnalysisRequest {
    pub session_id: String,
    pub url: String,
    pub page_text: String,
    pub page_title: Option<String>,
    pub has_login_form: bool,
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
        }
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
        let backoff_secs =
            (AI_BACKOFF_BASE.as_secs() << shift).min(AI_BACKOFF_MAX.as_secs());
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
        self.post_analyze(&url, req).await
    }

   /// AnalyzeAttachmentContent
    pub async fn analyze_attachment(
        &self,
        req: &AttachmentAnalysisRequest,
    ) -> Result<AiAnalysisResponse, RemoteError> {
        let url = format!("{}/analyze/attachment", self.base_url);
        self.post_analyze(&url, req).await
    }

   /// AnalyzelinkConnect
    pub async fn analyze_link(
        &self,
        req: &LinkAnalysisRequest,
    ) -> Result<AiAnalysisResponse, RemoteError> {
        let url = format!("{}/analyze/link", self.base_url);
        self.post_analyze(&url, req).await
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
                write!(f, "Temporarily unavailable, retry after {}s", retry_after_secs)
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
}
