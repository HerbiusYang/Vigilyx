//! Webhook dispatch with SSRF protection.

use tracing::{error, info, warn};
use vigilyx_core::{DEFAULT_BLOCKED_HOSTNAMES, security::SecurityVerdict, validate_network_host};

use super::DispositionEngine;

/// Validate a webhook URL to prevent SSRF attacks (CWE-918).
///
/// Uses standard `url::Url` parsing to correctly handle userinfo, IPv6, port, etc.
/// Rejects: private/loopback/link-local IPs, non-http(s) schemes, internal hostnames,
/// userinfo in URL, Docker service names, cloud metadata endpoints.
pub(super) fn validate_webhook_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw).map_err(|e| format!("Invalid URL: {e}"))?;

   // Scheme check
    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("Disallowed scheme: {s}")),
    }

   // SEC: Reject userinfo (user:pass@host can bypass naive host extraction)
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL must not contain userinfo (user:pass@)".to_string());
    }

   // Require a non-empty host - url::Url may parse "http:///path" as valid with empty host
    let host = match parsed.host() {
        Some(url::Host::Domain(d)) if !d.is_empty() => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        _ => return Err("URL has no host".to_string()),
    };

    validate_network_host(&host, DEFAULT_BLOCKED_HOSTNAMES)?;

    Ok(())
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    
   // validate_webhook_url - valid URLs
    

    #[test]
    fn test_validate_webhook_url_valid_https() {
        assert!(
            validate_webhook_url("https://hooks.example.com/webhook").is_ok(),
            "Valid https URL should pass validation"
        );
    }

    #[test]
    fn test_validate_webhook_url_valid_http() {
        assert!(
            validate_webhook_url("http://hooks.example.com/webhook").is_ok(),
            "Valid http URL should pass validation"
        );
    }

    #[test]
    fn test_validate_webhook_url_valid_https_with_port() {
        assert!(
            validate_webhook_url("https://hooks.example.com:8443/webhook").is_ok(),
            "Valid https URL with port should pass validation"
        );
    }

    #[test]
    fn test_validate_webhook_url_valid_public_ip() {
        assert!(
            validate_webhook_url("https://203.0.113.50/webhook").is_ok(),
            "Valid public IP address should pass validation"
        );
    }

    
   // validate_webhook_url - blocked: localhost / loopback
    

    #[test]
    fn test_validate_webhook_url_rejects_localhost() {
        let result = validate_webhook_url("http://localhost/webhook");
        assert!(result.is_err(), "localhost should be blocked: {:?}", result);
    }

    #[test]
    fn test_validate_webhook_url_rejects_127_0_0_1() {
        let result = validate_webhook_url("http://127.0.0.1/webhook");
        assert!(
            result.is_err(),
            "127.0.0.1 (loopback) should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_ipv6_loopback() {
        let result = validate_webhook_url("http://[::1]/webhook");
        assert!(
            result.is_err(),
            "IPv6 loopback [::1] should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_ipv6_ula() {
        let result = validate_webhook_url("http://[fd00:ec2::254]/webhook");
        assert!(
            result.is_err(),
            "IPv6 ULA should be blocked: {:?}",
            result
        );
    }

    
   // validate_webhook_url - blocked: private IP ranges
    

    #[test]
    fn test_validate_webhook_url_rejects_10_x_private() {
        let result = validate_webhook_url("http://10.0.0.1/webhook");
        assert!(
            result.is_err(),
            "10.x.x.x (RFC 1918) should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_172_16_private() {
        let result = validate_webhook_url("http://172.16.0.1/webhook");
        assert!(
            result.is_err(),
            "172.16.x.x (RFC 1918) should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_192_168_private() {
        let result = validate_webhook_url("http://192.168.1.1/webhook");
        assert!(
            result.is_err(),
            "192.168.x.x (RFC 1918) should be blocked: {:?}",
            result
        );
    }

    
   // validate_webhook_url - blocked: link-local
    

    #[test]
    fn test_validate_webhook_url_rejects_link_local() {
        let result = validate_webhook_url("http://169.254.169.254/metadata");
        assert!(
            result.is_err(),
            "169.254.x.x (link-local / cloud metadata) should be blocked: {:?}",
            result
        );
    }

    
   // validate_webhook_url - blocked: non-http schemes
    

    #[test]
    fn test_validate_webhook_url_rejects_ftp_scheme() {
        let result = validate_webhook_url("ftp://example.com/file");
        assert!(
            result.is_err(),
            "ftp:// scheme should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_file_scheme() {
        let result = validate_webhook_url("file:///etc/passwd");
        assert!(
            result.is_err(),
            "file:// scheme should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_gopher_scheme() {
        let result = validate_webhook_url("gopher://evil.com/payload");
        assert!(
            result.is_err(),
            "gopher:// scheme should be blocked: {:?}",
            result
        );
    }

    
   // validate_webhook_url - blocked: internal domains
    

    #[test]
    fn test_validate_webhook_url_rejects_dot_internal() {
        let result = validate_webhook_url("http://service.internal/hook");
        assert!(
            result.is_err(),
            ".internal domain should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_dot_local() {
        let result = validate_webhook_url("http://printer.local/hook");
        assert!(
            result.is_err(),
            ".local domain should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_metadata_google_internal() {
        let result = validate_webhook_url("http://metadata.google.internal/computeMetadata");
        assert!(
            result.is_err(),
            "metadata.google.internal should be blocked: {:?}",
            result
        );
    }

    
   // validate_webhook_url - blocked: edge cases
    

    #[test]
    fn test_validate_webhook_url_rejects_empty_host() {
       // url::Url normalizes "http:///path" to "http://path/" (host=path).
       // Test truly empty/missing host via cannot-be-a-base URL instead.
        let result = validate_webhook_url("http://");
        assert!(
            result.is_err(),
            "URL with empty host should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_unspecified_ip() {
        let result = validate_webhook_url("http://0.0.0.0/webhook");
        assert!(
            result.is_err(),
            "0.0.0.0 (unspecified) should be blocked: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_webhook_url_rejects_broadcast() {
        let result = validate_webhook_url("http://255.255.255.255/webhook");
        assert!(
            result.is_err(),
            "255.255.255.255 (broadcast) should be blocked: {:?}",
            result
        );
    }
}

impl DispositionEngine {
    pub(super) async fn send_webhook(
        &self,
        url: &str,
        headers: &std::collections::HashMap<String, String>,
        verdict: &SecurityVerdict,
    ) {
       // SSRF protection: block internal/private URLs
        if let Err(reason) = validate_webhook_url(url) {
            warn!(url, "Webhook blocked (SSRF prevention): {}", reason);
            return;
        }

        let payload = serde_json::json!({
            "event": "security_verdict",
            "session_id": verdict.session_id.to_string(),
            "threat_level": verdict.threat_level.to_string(),
            "confidence": verdict.confidence,
            "categories": verdict.categories,
            "summary": verdict.summary,
            "modules_run": verdict.modules_run,
            "modules_flagged": verdict.modules_flagged,
            "created_at": verdict.created_at.to_rfc3339(),
        });

        let mut req = self.http.post(url).json(&payload);
        for (k, v) in headers {
            req = req.header(k, v);
        }

        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!(url, "Webhook sent successfully");
                } else {
                    warn!(url, status = %resp.status(), "Webhook returned non-success");
                }
            }
            Err(e) => {
                error!(url, "Webhook failed: {}", e);
            }
        }
    }
}
