//! CAPEv2 Sandbox REST API Client

//! Communicates with CAPEv2 sandbox service for dynamic attachment analysis.
//! Supports: file submission, status polling, report retrieval, hash deduplication.

//! API Version: CAPEv2 /apiv2/
//! Authentication: token-based (`Authorization: Token <key>`)

use std::fmt;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use reqwest::multipart;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// SandboxAnalyzeTimeout(From Get of longwaitWaittimestamp)
const DEFAULT_ANALYSIS_TIMEOUT: Duration = Duration::from_secs(300);

/// Status
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// HTTP RequestTimeout
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// ErrorType

#[derive(Debug)]
pub enum SandboxError {
    /// ConnectionFailed
    ConnectionFailed(String),
    /// HTTP Error
    HttpError { status: u16, body: String },
    /// AnalyzeTimeout
    AnalysisTimeout { task_id: u64, elapsed_secs: u64 },
    /// ParseFailed
    ParseError(String),
    /// Service
    Unavailable(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "Sandbox connection failed: {}", msg),
            Self::HttpError { status, body } => write!(f, "Sandbox HTTP {}: {}", status, body),
            Self::AnalysisTimeout {
                task_id,
                elapsed_secs,
            } => {
                write!(
                    f,
                    "Sandbox analysis timeout: task={}, {}s",
                    task_id, elapsed_secs
                )
            }
            Self::ParseError(msg) => write!(f, "Sandbox response parse failed: {}", msg),
            Self::Unavailable(msg) => write!(f, "Sandbox service unavailable: {}", msg),
        }
    }
}

impl std::error::Error for SandboxError {}

// ── API Responsestructure ──

#[derive(Debug, Deserialize)]
pub struct SubmitResponse {
    pub task_id: Option<u64>,
    /// Version task_ids Array
    pub task_ids: Option<Vec<u64>>,
}

impl SubmitResponse {
    pub fn get_task_id(&self) -> Option<u64> {
        self.task_id
            .or_else(|| self.task_ids.as_ref().and_then(|ids| ids.first().copied()))
    }
}

#[derive(Debug, Deserialize)]
pub struct TaskStatus {
    pub task: Option<TaskInfo>,
    // Version Return
    pub id: Option<u64>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TaskInfo {
    pub id: u64,
    pub status: String,
    pub errors: Option<Vec<String>>,
}

/// SandboxAnalyze (, ExtractSecuritydetectNeed/Requireof Segment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Malicious (0-10)
    pub score: f64,
    /// ofline Sign
    pub signatures: Vec<SandboxSignature>,
    /// ofMalicious
    pub malfamily: Option<String>,
    /// Network IOC(C2 Domain/IP)
    pub network_iocs: Vec<String>,
    /// CAPE Extractof payload Count
    pub payload_count: usize,
    /// Analyze long()
    pub duration_secs: u64,
    /// TargetFileInfo
    pub target_sha256: Option<String>,
    pub target_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSignature {
    pub name: String,
    pub severity: u8,
    pub description: String,
}

/// SystemStatus
#[derive(Debug, Deserialize)]
pub struct SystemStatus {
    pub tasks: Option<SystemTasks>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SystemTasks {
    pub pending: Option<u64>,
    pub running: Option<u64>,
    pub completed: Option<u64>,
    pub reported: Option<u64>,
}

// ── client ──

#[derive(Clone)]
pub struct SandboxClient {
    base_url: String,
    api_token: Option<String>,
    http: reqwest::Client,
    analysis_timeout: Duration,
}

impl SandboxClient {
    pub fn new(base_url: &str, api_token: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .pool_max_idle_per_host(4)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token,
            http,
            analysis_timeout: DEFAULT_ANALYSIS_TIMEOUT,
        }
    }

    /// FromEnvironmentVariableBuildclient
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("SANDBOX_URL").ok()?;

        // SSRF :
        if let Err(reason) = validate_sandbox_base_url(&url) {
            tracing::error!(url = %url, reason = %reason, "Sandbox URL blocked by SSRF protection");
            return None;
        }

        let token = std::env::var("SANDBOX_API_TOKEN").ok();
        let timeout_secs = std::env::var("SANDBOX_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        let mut client = Self::new(&url, token);
        client.analysis_timeout = Duration::from_secs(timeout_secs);
        Some(client)
    }

    fn auth_header(&self) -> Option<String> {
        self.api_token.as_ref().map(|t| format!("Token {}", t))
    }

    /// Check
    pub async fn ping(&self) -> Result<SystemStatus, SandboxError> {
        let url = format!("{}/apiv2/cuckoo/status/", self.base_url);
        let mut req = self.http.get(&url);
        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SandboxError::ConnectionFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SandboxError::HttpError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        resp.json::<SystemStatus>()
            .await
            .map_err(|e| SandboxError::ParseError(e.to_string()))
    }

    /// According to SHA256 Queryalready Analyze(Hash Deduplicate)
    pub async fn search_by_hash(&self, sha256: &str) -> Result<Option<u64>, SandboxError> {
        let url = format!("{}/apiv2/tasks/search/sha256/{}/", self.base_url, sha256);
        let mut req = self.http.get(&url);
        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SandboxError::ConnectionFailed(e.to_string()))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(SandboxError::HttpError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        // Returnrecent1Time/CountAnalyzeof task_id
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SandboxError::ParseError(e.to_string()))?;

        // CAPEv2 Return {"data": [{"id": 42,...}]}
        let task_id = body
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.last())
            .and_then(|t| t.get("id"))
            .and_then(|id| id.as_u64());

        Ok(task_id)
    }

    /// File lineDynamicAnalyze
    pub async fn submit_file(
        &self,
        filename: &str,
        data: Vec<u8>,
        timeout_secs: Option<u32>,
    ) -> Result<u64, SandboxError> {
        let url = format!("{}/apiv2/tasks/create/file/", self.base_url);

        let part = multipart::Part::bytes(data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| SandboxError::ParseError(e.to_string()))?;

        let mut form = multipart::Form::new().part("file", part);
        if let Some(t) = timeout_secs {
            form = form.text("timeout", t.to_string());
        }
        form = form.text("priority", "2"); // Highprioritylevel

        let mut req = self.http.post(&url).multipart(form);
        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SandboxError::ConnectionFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SandboxError::HttpError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let submit: SubmitResponse = resp
            .json()
            .await
            .map_err(|e| SandboxError::ParseError(e.to_string()))?;

        submit
            .get_task_id()
            .ok_or_else(|| SandboxError::ParseError("No task_id in response".to_string()))
    }

    /// Status complete
    pub async fn wait_for_completion(&self, task_id: u64) -> Result<(), SandboxError> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > self.analysis_timeout {
                return Err(SandboxError::AnalysisTimeout {
                    task_id,
                    elapsed_secs: start.elapsed().as_secs(),
                });
            }

            tokio::time::sleep(POLL_INTERVAL).await;

            let url = format!("{}/apiv2/tasks/view/{}/", self.base_url, task_id);
            let mut req = self.http.get(&url);
            if let Some(ref auth) = self.auth_header() {
                req = req.header("Authorization", auth);
            }

            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let status: TaskStatus = resp
                        .json()
                        .await
                        .map_err(|e| SandboxError::ParseError(e.to_string()))?;

                    let task_status = status
                        .task
                        .as_ref()
                        .map(|t| t.status.as_str())
                        .or(status.status.as_deref())
                        .unwrap_or("unknown");

                    debug!(task_id, status = task_status, "Sandbox task status poll");

                    match task_status {
                        "reported" => return Ok(()),
                        "failed_analysis" | "failed_processing" | "failed_reporting" => {
                            return Err(SandboxError::Unavailable(format!(
                                "AnalyzeFailed: task={}, status={}",
                                task_id, task_status
                            )));
                        }
                        _ => continue, // pending, running, completed -> keep polling
                    }
                }
                Ok(resp) => {
                    warn!(
                        task_id,
                        status = resp.status().as_u16(),
                        "SandboxStatusQueryAbnormal"
                    );
                }
                Err(e) => {
                    warn!(task_id, error = %e, "SandboxStatusQueryConnectionFailed");
                }
            }
        }
    }

    /// GetAnalyze ()
    pub async fn get_report(&self, task_id: u64) -> Result<SandboxReport, SandboxError> {
        let url = format!("{}/apiv2/tasks/report/{}/", self.base_url, task_id);
        let mut req = self.http.get(&url);
        if let Some(ref auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SandboxError::ConnectionFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SandboxError::HttpError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SandboxError::ParseError(e.to_string()))?;

        parse_cape_report(&body)
    }

    /// waitWaitcomplete, Return
    pub async fn analyze_file(
        &self,
        filename: &str,
        data: Vec<u8>,
        sha256: &str,
    ) -> Result<SandboxReport, SandboxError> {
        // Hash Deduplicate: alreadyAnalyze ConnectGet
        if let Ok(Some(existing_task)) = self.search_by_hash(sha256).await {
            info!(
                task_id = existing_task,
                sha256, "Sandbox: existing analysis result found, skipping resubmission"
            );
            return self.get_report(existing_task).await;
        }

        // NewFile
        let task_id = self.submit_file(filename, data, Some(120)).await?;
        info!(
            task_id,
            sha256, filename, "Sandbox: attachment submitted for dynamic analysis"
        );

        // waitWaitcomplete
        self.wait_for_completion(task_id).await?;

        // Get
        self.get_report(task_id).await
    }
}

fn validate_sandbox_base_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("invalid sandbox URL: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "unsupported sandbox URL scheme: {other} (only http/https allowed)"
            ));
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("sandbox URL must not contain userinfo".to_string());
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("sandbox URL must not contain query parameters or fragments".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "sandbox URL must contain a host".to_string())?;
    validate_sandbox_host(host)
}

fn validate_sandbox_host(host: &str) -> Result<(), String> {
    let normalized = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();

    let blocked_host = matches!(
        normalized.as_str(),
        "localhost"
            | "host.docker.internal"
            | "gateway.docker.internal"
            | "metadata.google.internal"
    ) || normalized.ends_with(".internal");
    if blocked_host {
        return Err(format!("sandbox host is blocked: {normalized}"));
    }

    if let Ok(ip) = normalized.parse::<IpAddr>() {
        return validate_sandbox_ip(ip);
    }

    if let Ok(resolved) = (normalized.as_str(), 0).to_socket_addrs() {
        for addr in resolved {
            validate_sandbox_ip(addr.ip())?;
        }
    }

    Ok(())
}

fn validate_sandbox_ip(ip: IpAddr) -> Result<(), String> {
    if is_blocked_sandbox_ip(ip) {
        return Err(format!("sandbox address is blocked: {ip}"));
    }
    Ok(())
}

fn is_blocked_sandbox_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_loopback() || addr.is_unspecified() || addr.is_link_local(),
        IpAddr::V6(addr) => {
            if addr.is_loopback() || addr.is_unspecified() || addr.is_unicast_link_local() {
                return true;
            }

            addr.to_ipv4_mapped().is_some_and(|mapped| {
                mapped.is_loopback() || mapped.is_unspecified() || mapped.is_link_local()
            })
        }
    }
}

/// From CAPEv2 JSON MediumExtractSecuritydetectNeed/Requireof Segment
fn parse_cape_report(body: &serde_json::Value) -> Result<SandboxReport, SandboxError> {
    let info = body.get("info").unwrap_or(body);

    let score = info
        .get("score")
        .or_else(|| info.get("malscore"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let duration_secs = info.get("duration").and_then(|v| v.as_u64()).unwrap_or(0);

    // ExtractSign
    let signatures: Vec<SandboxSignature> = body
        .get("signatures")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|sig| {
                    Some(SandboxSignature {
                        name: sig.get("name")?.as_str()?.to_string(),
                        severity: sig.get("severity").and_then(|v| v.as_u64()).unwrap_or(1) as u8,
                        description: sig
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Malicious
    let malfamily = body
        .get("malfamily")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            body.get("malfamily_tag")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    // Network IOC
    let mut network_iocs = Vec::new();
    if let Some(network) = body.get("network") {
        // DNS QueryDomain
        if let Some(dns) = network.get("dns").and_then(|d| d.as_array()) {
            for entry in dns {
                if let Some(domain) = entry.get("request").and_then(|v| v.as_str()) {
                    network_iocs.push(domain.to_string());
                }
            }
        }
        // Connectionof IP
        if let Some(hosts) = network.get("hosts").and_then(|h| h.as_array()) {
            for host in hosts {
                if let Some(ip) = host.as_str() {
                    network_iocs.push(ip.to_string());
                }
            }
        }
    }
    network_iocs.sort();
    network_iocs.dedup();

    // CAPE payload Count
    let payload_count = body
        .get("CAPE")
        .and_then(|c| c.get("payloads"))
        .and_then(|p| p.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // TargetFileInfo
    let target_sha256 = body
        .get("target")
        .and_then(|t| t.get("file"))
        .and_then(|f| f.get("sha256"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let target_type = body
        .get("target")
        .and_then(|t| t.get("file"))
        .and_then(|f| f.get("type"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(SandboxReport {
        score,
        signatures,
        malfamily,
        network_iocs,
        payload_count,
        duration_secs,
        target_sha256,
        target_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cape_report_minimal() {
        let json = serde_json::json!({
            "info": {"score": 7.5, "duration": 120},
            "signatures": [
                {"name": "ransomware_file_modifications", "severity": 3, "description": "Modifies files"}
            ],
            "malfamily": "Emotet",
            "network": {
                "dns": [{"request": "evil.com"}],
                "hosts": ["1.2.3.4"]
            },
            "CAPE": {"payloads": [{"sha256": "abc"}]},
            "target": {"file": {"sha256": "deadbeef", "type": "PE32 executable"}}
        });

        let report = parse_cape_report(&json).expect("parse failed");
        assert!((report.score - 7.5).abs() < 0.01);
        assert_eq!(report.signatures.len(), 1);
        assert_eq!(report.signatures[0].name, "ransomware_file_modifications");
        assert_eq!(report.malfamily.as_deref(), Some("Emotet"));
        assert_eq!(report.network_iocs, vec!["1.2.3.4", "evil.com"]);
        assert_eq!(report.payload_count, 1);
        assert_eq!(report.target_sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_parse_cape_report_empty() {
        let json = serde_json::json!({});
        let report = parse_cape_report(&json).expect("parse failed");
        assert!((report.score - 0.0).abs() < 0.01);
        assert!(report.signatures.is_empty());
        assert!(report.malfamily.is_none());
    }

    #[test]
    fn test_submit_response_task_id() {
        let r1 = SubmitResponse {
            task_id: Some(42),
            task_ids: None,
        };
        assert_eq!(r1.get_task_id(), Some(42));

        let r2 = SubmitResponse {
            task_id: None,
            task_ids: Some(vec![10, 20]),
        };
        assert_eq!(r2.get_task_id(), Some(10));
    }

    #[test]
    fn test_validate_sandbox_rejects_loopback_ip() {
        let err = validate_sandbox_base_url("http://127.0.0.1:8090")
            .expect_err("loopback must be blocked");
        assert!(err.contains("blocked"));
    }

    #[test]
    fn test_validate_sandbox_rejects_metadata_host() {
        let err = validate_sandbox_base_url("http://metadata.google.internal:8090")
            .expect_err("metadata host must be blocked");
        assert!(err.contains("metadata.google.internal"));
    }

    #[test]
    fn test_validate_sandbox_rejects_userinfo() {
        let err = validate_sandbox_base_url("http://user:pass@10.0.0.8:8090")
            .expect_err("userinfo must be blocked");
        assert!(err.contains("userinfo"));
    }

    #[test]
    fn test_validate_sandbox_allows_private_lab_ip() {
        validate_sandbox_base_url("http://10.0.0.8:8090").expect("private sandbox lab should pass");
    }
}
