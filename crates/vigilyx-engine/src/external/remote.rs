//! AI RemoteModule

//! Features:
//! - Rust -> Python AI Service of HTTP
//! - /analyze/content, /analyze/attachment, /analyze/link
//! - TimeoutAndErrorProcess

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

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

/// Remote AI
#[derive(Clone)]
pub struct RemoteModuleProxy {
    base_url: String,
    client: reqwest::Client,
   /// SEC-H07: AI service-scoped internal authentication token
    internal_token: String,
}

impl RemoteModuleProxy {
    pub fn new(base_url: String) -> Self {
        let internal_token = std::env::var("AI_INTERNAL_TOKEN").unwrap_or_default();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            base_url,
            client,
            internal_token,
        }
    }

   /// Check AI Servicewhether
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
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
        let mut req = self.client.post(url).json(body);
       // SEC-H07: AddInternalServiceAuthentication
        if !self.internal_token.is_empty() {
            req = req.header("X-Internal-Token", &self.internal_token);
        }
        let response = req.send().await.map_err(|e| {
            error!(url, "AI service request failed: {}", e);
            RemoteError::ConnectionFailed(e.to_string())
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(url, %status, "AI service returned error: {}", body);
            return Err(RemoteError::ServiceError {
                status: status.as_u16(),
                message: body,
            });
        }

        response.json::<AiAnalysisResponse>().await.map_err(|e| {
            error!(url, "Failed to parse AI response: {}", e);
            RemoteError::ParseError(e.to_string())
        })
    }
}

/// Remote Error
#[derive(Debug)]
pub enum RemoteError {
    ConnectionFailed(String),
    ServiceError { status: u16, message: String },
    ParseError(String),
    Timeout,
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
        }
    }
}

impl std::error::Error for RemoteError {}
