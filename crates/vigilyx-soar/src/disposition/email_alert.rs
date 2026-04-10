//! Email alert pipeline: SMTP config, HTML builder, send logic, connection testing.

use std::collections::HashSet;

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, info, warn};
use vigilyx_core::{DEFAULT_BLOCKED_HOSTNAMES, models::EmailSession, validate_network_target};
use vigilyx_core::security::{SecurityVerdict, ThreatLevel};

use crate::config::EmailAlertConfig;

use super::{
    DispositionAction, DispositionEngine, infer_external_ip, infer_mail_direction,
    render_action_message_template,
};


// Helper functions


/// SEC-REMAINING-001: smtp_password (AES-256-GCM, vigilyx-api Shared)
fn decrypt_smtp_password(stored: &str) -> Option<String> {
    let encoded = stored.strip_prefix("ENC:")?;
    let jwt_secret = std::env::var("API_JWT_SECRET").ok()?;

   // Key (vigilyx-api/handlers/security/alerts.rs)
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

pub(super) fn parse_threat_level(s: &str) -> ThreatLevel {
    match s.to_ascii_lowercase().as_str() {
        "safe" => ThreatLevel::Safe,
        "low" => ThreatLevel::Low,
        "medium" => ThreatLevel::Medium,
        "high" => ThreatLevel::High,
        "critical" => ThreatLevel::Critical,
        other => {
            warn!(
                value = other,
                "Unknown threat level string, defaulting to Safe"
            );
            ThreatLevel::Safe
        }
    }
}

fn threat_level_label(level: &ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Safe => "Safe",
        ThreatLevel::Low => "Low",
        ThreatLevel::Medium => "Medium",
        ThreatLevel::High => "High",
        ThreatLevel::Critical => "Critical",
    }
}

fn threat_level_color(level: &ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Safe => "#22c55e",
        ThreatLevel::Low => "#3b82f6",
        ThreatLevel::Medium => "#f59e0b",
        ThreatLevel::High => "#ef4444",
        ThreatLevel::Critical => "#dc2626",
    }
}

/// Escape HTML special characters to prevent XSS in alert emails.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn html_escape_multiline(s: &str) -> String {
    html_escape(s).replace('\n', "<br/>")
}


// SMTP transport builder


fn build_smtp_transport(
    config: &EmailAlertConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    validate_network_target(&config.smtp_host, DEFAULT_BLOCKED_HOSTNAMES)
        .map_err(|reason| format!("SMTP host blocked (SSRF prevention): {reason}"))?;

    let auth = smtp_auth_fields(config)?;

    let transport = match config.smtp_tls.as_str() {
        "tls" => {
            let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| format!("SMTP relay error: {}", e))?
                .port(config.smtp_port);
            if let Some((username, password)) = &auth {
                builder
                    .credentials(Credentials::new(username.clone(), password.clone()))
                    .build()
            } else {
                builder.build()
            }
        }
        "starttls" => {
            let builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|e| format!("SMTP STARTTLS error: {}", e))?
                .port(config.smtp_port);
            if let Some((username, password)) = &auth {
                builder
                    .credentials(Credentials::new(username.clone(), password.clone()))
                    .build()
            } else {
                builder.build()
            }
        }
        "none" => {
           // Plaintext SMTP requires explicit admin opt-in in the persisted alert config.
           // Without this guard, a misconfiguration could leak credentials in cleartext.
            if !config.allow_plaintext_smtp {
                return Err(
                    "SMTP plaintext mode blocked: enable the admin plaintext SMTP switch to allow"
                        .to_string(),
                );
            }
            warn!("SMTP transport configured without TLS");
            let builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port);
            if let Some((username, password)) = &auth {
                warn!("SMTP credentials will be sent in plaintext!");
                builder
                    .credentials(Credentials::new(username.clone(), password.clone()))
                    .build()
            } else {
                builder.build()
            }
        }
        other => {
           // Unknown TLS mode -> default to STARTTLS rather than plaintext
            warn!(
                smtp_tls = other,
                "Unknown SMTP TLS mode, defaulting to STARTTLS"
            );
            let builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|e| format!("SMTP STARTTLS error: {}", e))?
                .port(config.smtp_port);
            if let Some((username, password)) = &auth {
                builder
                    .credentials(Credentials::new(username.clone(), password.clone()))
                    .build()
            } else {
                builder.build()
            }
        }
    };

    Ok(transport)
}

fn smtp_auth_fields(config: &EmailAlertConfig) -> Result<Option<(String, String)>, String> {
    let username = config.smtp_username.trim().to_string();
    let password = config.smtp_password.clone();
    let has_username = !username.is_empty();
    let has_password = !password.is_empty();

    match (has_username, has_password) {
        (false, false) => Ok(None),
        (true, true) => Ok(Some((username, password))),
        _ => Err(
            "SMTP username and password must either both be filled or both be left empty"
                .to_string(),
        ),
    }
}


// HTML email builder


/// BuildAlert HTML
fn build_alert_html(
    verdict: &SecurityVerdict,
    session: &EmailSession,
    custom_message: Option<&str>,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> String {
    let level = threat_level_label(&verdict.threat_level);
    let color = threat_level_color(&verdict.threat_level);
    let confidence_pct = (verdict.confidence * 100.0) as u32;
    let mail_direction = infer_mail_direction(session, internal_domains, inbound_mail_servers)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let external_ip = infer_external_ip(session, internal_domains, inbound_mail_servers)
        .unwrap_or_else(|| "-".to_string());
   // HTML-escape all user-controlled content to prevent XSS
    let mail_from = html_escape(session.mail_from.as_deref().unwrap_or("(unknown)"));
    let rcpt_to = if session.rcpt_to.is_empty() {
        "(unknown)".to_string()
    } else {
        html_escape(&session.rcpt_to.join(", "))
    };
    let subject = html_escape(session.subject.as_deref().unwrap_or("(no subject)"));
    let client_ip = html_escape(&session.client_ip);
    let server_ip = html_escape(&session.server_ip);
    let external_ip = html_escape(&external_ip);
    let mail_direction = html_escape(&mail_direction);
    let categories = if verdict.categories.is_empty() {
        "-".to_string()
    } else {
        html_escape(&verdict.categories.join(", "))
    };
    let timestamp = verdict
        .created_at
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let custom_message_block = custom_message
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|message| {
            format!(
                r#"<div style="margin:0 0 16px;padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
      <div style="font-size:12px;font-weight:600;color:#475569;margin-bottom:6px">自定义告警内容</div>
      <div style="font-size:14px;line-height:1.7;color:#1e293b">{}</div>
    </div>"#,
                html_escape_multiline(message)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">
<div style="max-width:600px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
  <!-- Header -->
  <div style="background:{color};padding:20px 24px;color:#fff">
    <h1 style="margin:0;font-size:20px">VIGILYX SecurityAlert</h1>
    <p style="margin:6px 0 0;font-size:14px;opacity:0.9">Threat level: {level} | Confidence: {confidence_pct}%</p>
  </div>
  <!-- Body -->
  <div style="padding:24px">
    {custom_message_block}
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr>
        <td style="padding:8px 0;color:#666;width:100px">Detection Time</td>
        <td style="padding:8px 0;font-weight:500">{timestamp}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Sender</td>
        <td style="padding:8px 0;font-weight:500">{mail_from}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Recipient</td>
        <td style="padding:8px 0;font-weight:500">{rcpt_to}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Email Subject</td>
        <td style="padding:8px 0;font-weight:500">{subject}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Threat Category</td>
        <td style="padding:8px 0"><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:13px">{categories}</code></td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Mail Direction</td>
        <td style="padding:8px 0;font-weight:500">{mail_direction}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Client IP</td>
        <td style="padding:8px 0;font-weight:500">{client_ip}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">Server IP</td>
        <td style="padding:8px 0;font-weight:500">{server_ip}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">External IP</td>
        <td style="padding:8px 0;font-weight:500">{external_ip}</td>
      </tr>
      <tr>
        <td style="padding:8px 0;color:#666">检测Module</td>
        <td style="padding:8px 0">{modules_run} 运行, {modules_flagged} Alert</td>
      </tr>
    </table>
    <div style="margin-top:16px;padding:12px;background:#f8f8f8;border-radius:6px;border-left:4px solid {color}">
      <p style="margin:0;font-size:14px;color:#333">{summary}</p>
    </div>
  </div>
  <!-- Footer -->
  <div style="padding:16px 24px;background:#fafafa;border-top:1px solid #eee;font-size:12px;color:#999">
    Session ID: {session_id} | VIGILYX Security Engine
  </div>
</div>
</body>
</html>"#,
        color = color,
        level = level,
        confidence_pct = confidence_pct,
        timestamp = timestamp,
        mail_from = mail_from,
        rcpt_to = rcpt_to,
        subject = subject,
        categories = categories,
        mail_direction = mail_direction,
        client_ip = client_ip,
        server_ip = server_ip,
        external_ip = external_ip,
        modules_run = verdict.modules_run,
        modules_flagged = verdict.modules_flagged,
        custom_message_block = custom_message_block,
        summary = html_escape(&verdict.summary),
        session_id = verdict.session_id,
    )
}


// DispositionEngine email methods


impl DispositionEngine {
   /// Execute an email alert action using the saved email channel config.
    pub(super) async fn execute_email_action(
        &self,
        action: &DispositionAction,
        verdict: &SecurityVerdict,
        session: &EmailSession,
        internal_domains: &HashSet<String>,
        inbound_mail_servers: &HashSet<String>,
    ) {
        let config = match self.load_email_alert_config().await {
            Some(c) => c,
            None => return,
        };

        if !config.enabled {
            return;
        }

       // Threat level Threshold
        let min_level = parse_threat_level(&config.min_threat_level);
        if verdict.threat_level < min_level {
            return;
        }

        let custom_message = action
            .message_template
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|template| {
                render_action_message_template(
                    template,
                    verdict,
                    session,
                    internal_domains,
                    inbound_mail_servers,
                )
            });

        self.send_email_alert_with_config(
            &config,
            verdict,
            session,
            custom_message.as_deref(),
            internal_domains,
            inbound_mail_servers,
        )
        .await;
    }

    async fn send_email_alert_with_config(
        &self,
        config: &EmailAlertConfig,
        verdict: &SecurityVerdict,
        session: &EmailSession,
        custom_message: Option<&str>,
        internal_domains: &HashSet<String>,
        inbound_mail_servers: &HashSet<String>,
    ) {

       // Recipient
        let mut recipients: Vec<String> = Vec::new();

        if config.notify_admin && !config.admin_email.is_empty() {
            recipients.push(config.admin_email.clone());
        }

        if config.notify_recipient {
            for rcpt in &session.rcpt_to {
                if !rcpt.is_empty() && !recipients.contains(rcpt) {
                    recipients.push(rcpt.clone());
                }
            }
        }

        if recipients.is_empty() {
            return;
        }

       // BuildAlert
        let subject_text = session.subject.as_deref().unwrap_or("(no subject)");
        let mail_subject = format!(
            "[VIGILYX] {} - {}",
            threat_level_label(&verdict.threat_level),
            subject_text
        );
        let html_body = build_alert_html(
            verdict,
            session,
            custom_message,
            internal_domains,
            inbound_mail_servers,
        );

       // Recipient
        for to_addr in &recipients {
            if let Err(e) = self
                .send_alert_email(config, to_addr, &mail_subject, &html_body)
                .await
            {
                error!(
                    to = to_addr,
                    session_id = %verdict.session_id,
                    "Failed to send alert email: {}", e
                );
            } else {
                info!(
                    to = to_addr,
                    session_id = %verdict.session_id,
                    threat_level = %verdict.threat_level,
                    "Alert email sent"
                );
            }
        }
    }

   /// FromData LoadEmail alert configuration (smtp_password)
    async fn load_email_alert_config(&self) -> Option<EmailAlertConfig> {
        match self.db.get_email_alert_config().await {
            Ok(Some(json)) => {
                let mut config: EmailAlertConfig = serde_json::from_str(&json).ok()?;
               // SEC-REMAINING-001: smtp_password (Such as "ENC:")
                if config.smtp_password.starts_with("ENC:") {
                    config.smtp_password =
                        decrypt_smtp_password(&config.smtp_password).unwrap_or_default();
                }
                if config.enabled
                    && let Err(reason) =
                        validate_network_target(&config.smtp_host, DEFAULT_BLOCKED_HOSTNAMES)
                {
                    warn!(
                        smtp_host = %config.smtp_host,
                        "SMTP alert config blocked at runtime (SSRF prevention): {}",
                        reason
                    );
                    return None;
                }
                Some(config)
            }
            _ => None,
        }
    }

   /// Alert
    async fn send_alert_email(
        &self,
        config: &EmailAlertConfig,
        to: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), String> {
        let from_mailbox: Mailbox = config
            .from_address
            .parse()
            .map_err(|e| format!("Invalid from address: {}", e))?;

        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| format!("Invalid to address '{}': {}", to, e))?;

        let email = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| format!("Failed to build email: {}", e))?;

        let transport = build_smtp_transport(config)?;

        transport
            .send(email)
            .await
            .map_err(|e| format!("SMTP send failed: {}", e))?;

        Ok(())
    }

   /// SMTP Connection (For API)
    pub async fn test_email_connection(&self, config: &EmailAlertConfig) -> Result<String, String> {
        if config.smtp_host.is_empty() {
            return Err("SMTP host is empty".to_string());
        }

        let from_mailbox: Mailbox = config
            .from_address
            .parse()
            .map_err(|e| format!("Invalid from address: {}", e))?;

        let to_mailbox: Mailbox = if !config.admin_email.is_empty() {
            config
                .admin_email
                .parse()
                .map_err(|e| format!("Invalid admin email: {}", e))?
        } else {
            return Err("Admin email is empty".to_string());
        };

        let email = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject("[VIGILYX] 邮件Alert测试")
            .header(ContentType::TEXT_HTML)
            .body(
                "<div style=\"font-family:sans-serif;padding:20px\">\
                 <h2>VIGILYX 邮件Alert测试</h2>\
                 <p>Such as果你Received了这封邮件，说明 SMTP Configuration正确。</p>\
                 <p style=\"color:#888;font-size:12px\">此邮件由 VIGILYX SecurityEngine自动发送。</p>\
                 </div>"
                    .to_string(),
            )
            .map_err(|e| format!("Failed to build test email: {}", e))?;

        let transport = build_smtp_transport(config)?;

        transport
            .send(email)
            .await
            .map_err(|e| format!("SMTP test failed: {}", e))?;

        Ok("Test email sent successfully".to_string())
    }
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;
    use vigilyx_core::models::Protocol;

   /// Build a minimal SecurityVerdict for testing.
    fn make_verdict(
        threat_level: ThreatLevel,
        categories: Vec<String>,
        summary: &str,
    ) -> SecurityVerdict {
        SecurityVerdict {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            threat_level,
            confidence: 0.92,
            categories,
            summary: summary.to_string(),
            pillar_scores: HashMap::new(),
            modules_run: 15,
            modules_flagged: 5,
            total_duration_ms: 250,
            created_at: Utc::now(),
            fusion_details: None,
        }
    }

   /// Build a minimal EmailSession for testing.
    fn make_session(
        mail_from: Option<&str>,
        rcpt_to: Vec<&str>,
        subject: Option<&str>,
    ) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = mail_from.map(|s| s.to_string());
        session.rcpt_to = rcpt_to.into_iter().map(|s| s.to_string()).collect();
        session.subject = subject.map(|s| s.to_string());
        session
    }

    fn build_html(verdict: &SecurityVerdict, session: &EmailSession) -> String {
        build_alert_html(verdict, session, None, &HashSet::new(), &HashSet::new())
    }

    fn make_smtp_config(tls_mode: &str) -> EmailAlertConfig {
        EmailAlertConfig {
            enabled: true,
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            smtp_tls: tls_mode.to_string(),
            allow_plaintext_smtp: false,
            from_address: "alert@example.com".to_string(),
            admin_email: "admin@example.com".to_string(),
            min_threat_level: "medium".to_string(),
            notify_recipient: false,
            notify_admin: true,
        }
    }

    #[test]
    fn test_smtp_auth_fields_allows_no_auth_when_both_empty() {
        let mut config = make_smtp_config("starttls");
        config.smtp_username.clear();
        config.smtp_password.clear();
        assert!(smtp_auth_fields(&config).unwrap().is_none());
    }

    #[test]
    fn test_smtp_auth_fields_rejects_partial_credentials() {
        let mut config = make_smtp_config("starttls");
        config.smtp_password.clear();
        let result = smtp_auth_fields(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must either both be filled or both be left empty")
        );
    }

    
   // parse_threat_level
    

    #[test]
    fn test_parse_threat_level_safe() {
        assert_eq!(
            parse_threat_level("safe"),
            ThreatLevel::Safe,
            "\"safe\" should parse to ThreatLevel::Safe"
        );
    }

    #[test]
    fn test_parse_threat_level_low() {
        assert_eq!(
            parse_threat_level("low"),
            ThreatLevel::Low,
            "\"low\" should parse to ThreatLevel::Low"
        );
    }

    #[test]
    fn test_parse_threat_level_medium() {
        assert_eq!(
            parse_threat_level("medium"),
            ThreatLevel::Medium,
            "\"medium\" should parse to ThreatLevel::Medium"
        );
    }

    #[test]
    fn test_parse_threat_level_high() {
        assert_eq!(
            parse_threat_level("high"),
            ThreatLevel::High,
            "\"high\" should parse to ThreatLevel::High"
        );
    }

    #[test]
    fn test_parse_threat_level_critical() {
        assert_eq!(
            parse_threat_level("critical"),
            ThreatLevel::Critical,
            "\"critical\" should parse to ThreatLevel::Critical"
        );
    }

    #[test]
    fn test_parse_threat_level_case_insensitive() {
        assert_eq!(
            parse_threat_level("HIGH"),
            ThreatLevel::High,
            "\"HIGH\" (uppercase) should parse to ThreatLevel::High"
        );
        assert_eq!(
            parse_threat_level("Medium"),
            ThreatLevel::Medium,
            "\"Medium\" (mixed case) should parse to ThreatLevel::Medium"
        );
    }

    #[test]
    fn test_parse_threat_level_unknown_defaults_to_safe() {
        assert_eq!(
            parse_threat_level("banana"),
            ThreatLevel::Safe,
            "Unknown string should default to ThreatLevel::Safe"
        );
    }

    #[test]
    fn test_parse_threat_level_empty_defaults_to_safe() {
        assert_eq!(
            parse_threat_level(""),
            ThreatLevel::Safe,
            "Empty string should default to ThreatLevel::Safe"
        );
    }

    
   // threat_level_label
    

    #[test]
    fn test_threat_level_label_safe() {
        assert_eq!(threat_level_label(&ThreatLevel::Safe), "Safe");
    }

    #[test]
    fn test_threat_level_label_low() {
        assert_eq!(threat_level_label(&ThreatLevel::Low), "Low");
    }

    #[test]
    fn test_threat_level_label_medium() {
        assert_eq!(threat_level_label(&ThreatLevel::Medium), "Medium");
    }

    #[test]
    fn test_threat_level_label_high() {
        assert_eq!(threat_level_label(&ThreatLevel::High), "High");
    }

    #[test]
    fn test_threat_level_label_critical() {
        assert_eq!(threat_level_label(&ThreatLevel::Critical), "Critical");
    }

    
   // threat_level_color
    

    #[test]
    fn test_threat_level_color_safe() {
        assert_eq!(
            threat_level_color(&ThreatLevel::Safe),
            "#22c55e",
            "Safe should be green"
        );
    }

    #[test]
    fn test_threat_level_color_low() {
        assert_eq!(
            threat_level_color(&ThreatLevel::Low),
            "#3b82f6",
            "Low should be blue"
        );
    }

    #[test]
    fn test_threat_level_color_medium() {
        assert_eq!(
            threat_level_color(&ThreatLevel::Medium),
            "#f59e0b",
            "Medium should be amber"
        );
    }

    #[test]
    fn test_threat_level_color_high() {
        assert_eq!(
            threat_level_color(&ThreatLevel::High),
            "#ef4444",
            "High should be red"
        );
    }

    #[test]
    fn test_threat_level_color_critical() {
        assert_eq!(
            threat_level_color(&ThreatLevel::Critical),
            "#dc2626",
            "Critical should be dark red"
        );
    }

    
   // html_escape
    

    #[test]
    fn test_html_escape_ampersand() {
        assert_eq!(
            html_escape("AT&T"),
            "AT&amp;T",
            "& should be escaped to &amp;"
        );
    }

    #[test]
    fn test_html_escape_angle_brackets() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
            "< and > and ' should all be escaped"
        );
    }

    #[test]
    fn test_html_escape_double_quotes() {
        assert_eq!(
            html_escape(r#"value="evil""#),
            "value=&quot;evil&quot;",
            "Double quotes should be escaped to &quot;"
        );
    }

    #[test]
    fn test_html_escape_single_quotes() {
        assert_eq!(
            html_escape("it's"),
            "it&#x27;s",
            "Single quote should be escaped to &#x27;"
        );
    }

    #[test]
    fn test_html_escape_all_special_chars() {
        assert_eq!(
            html_escape("<a href=\"url?a=1&b=2\">it's</a>"),
            "&lt;a href=&quot;url?a=1&amp;b=2&quot;&gt;it&#x27;s&lt;/a&gt;",
            "All 5 special chars should be escaped in a combined string"
        );
    }

    #[test]
    fn test_html_escape_plain_text_unchanged() {
        let input = "Hello World 2026";
        assert_eq!(
            html_escape(input),
            input,
            "Text without special chars should pass through unchanged"
        );
    }

    #[test]
    fn test_html_escape_empty_string() {
        assert_eq!(
            html_escape(""),
            "",
            "Empty string should produce empty string"
        );
    }

    
   // build_smtp_transport - plaintext rejection


    #[test]
    fn test_build_smtp_transport_rejects_plaintext_without_opt_in() {
        let config = make_smtp_config("none");
        let result = build_smtp_transport(&config);
        assert!(
            result.is_err(),
            "Plaintext SMTP should be blocked without allow_plaintext_smtp"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("plaintext mode blocked"),
            "Error message should mention plaintext blocking, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_build_smtp_transport_allows_plaintext_with_opt_in() {
        let mut config = make_smtp_config("none");
        config.allow_plaintext_smtp = true;
        let result = build_smtp_transport(&config);
        assert!(
            result.is_ok(),
            "Plaintext SMTP should build when allow_plaintext_smtp=true: {:?}",
            result.err()
        );
    }

   // These tests need a tokio runtime because lettre's AsyncSmtpTransport
   // connection pool spawns a task on Drop.
    #[tokio::test]
    async fn test_build_smtp_transport_tls_mode_succeeds() {
        let config = make_smtp_config("tls");
        let result = build_smtp_transport(&config);
        assert!(
            result.is_ok(),
            "TLS mode should build successfully: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_build_smtp_transport_starttls_mode_succeeds() {
        let config = make_smtp_config("starttls");
        let result = build_smtp_transport(&config);
        assert!(
            result.is_ok(),
            "STARTTLS mode should build successfully: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_build_smtp_transport_unknown_mode_falls_back_to_starttls() {
        let config = make_smtp_config("ssl3");
        let result = build_smtp_transport(&config);
        assert!(
            result.is_ok(),
            "Unknown TLS mode should fall back to STARTTLS and succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_smtp_transport_rejects_ipv6_ula_host() {
        let mut config = make_smtp_config("starttls");
        config.smtp_host = "fd00:ec2::254".to_string();
        let result = build_smtp_transport(&config);
        assert!(result.is_err(), "IPv6 ULA SMTP hosts must be blocked");
    }

    
   // build_alert_html
    

    #[test]
    fn test_build_alert_html_contains_threat_level_label() {
        let verdict = make_verdict(ThreatLevel::High, vec![], "Suspicious email detected");
        let session = make_session(
            Some("attacker@evil.com"),
            vec!["victim@company.com"],
            Some("Urgent: Account Verification"),
        );
        let html = build_html(&verdict, &session);

        assert!(
            html.contains("High"),
            "HTML should contain the threat level label 'High'"
        );
        assert!(
            html.contains("#ef4444"),
            "HTML should contain the High threat level color"
        );
    }

    #[test]
    fn test_build_alert_html_contains_session_fields() {
        let verdict = make_verdict(
            ThreatLevel::Critical,
            vec!["phishing".to_string()],
            "Known phishing campaign",
        );
        let session = make_session(
            Some("phisher@fake.com"),
            vec!["user@corp.com"],
            Some("Password Reset Required"),
        );
        let html = build_html(&verdict, &session);

        assert!(
            html.contains("phisher@fake.com"),
            "HTML should contain the sender address"
        );
        assert!(
            html.contains("user@corp.com"),
            "HTML should contain the recipient address"
        );
        assert!(
            html.contains("Password Reset Required"),
            "HTML should contain the email subject"
        );
        assert!(
            html.contains("phishing"),
            "HTML should contain the category"
        );
        assert!(
            html.contains("Known phishing campaign"),
            "HTML should contain the summary"
        );
    }

    #[test]
    fn test_build_alert_html_escapes_xss_in_subject() {
        let verdict = make_verdict(ThreatLevel::Medium, vec![], "test");
        let session = make_session(
            Some("sender@test.com"),
            vec!["rcpt@test.com"],
            Some("<script>alert('xss')</script>"),
        );
        let html = build_html(&verdict, &session);

        assert!(
            !html.contains("<script>"),
            "HTML should NOT contain unescaped <script> tag"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "HTML should contain escaped script tag"
        );
    }

    #[test]
    fn test_build_alert_html_escapes_xss_in_sender() {
        let verdict = make_verdict(ThreatLevel::Medium, vec![], "test");
        let session = make_session(
            Some("evil<img src=x onerror=alert(1)>@test.com"),
            vec!["rcpt@test.com"],
            Some("Normal subject"),
        );
        let html = build_html(&verdict, &session);

        assert!(
            !html.contains("<img"),
            "HTML should NOT contain unescaped <img> tag in sender"
        );
    }

    #[test]
    fn test_build_alert_html_handles_missing_fields() {
        let verdict = make_verdict(ThreatLevel::Safe, vec![], "Clean email");
       // mail_from = None, rcpt_to = empty, subject = None
        let session = make_session(None, vec![], None);
        let html = build_html(&verdict, &session);

        assert!(
            html.contains("(unknown)"),
            "Missing mail_from should show (unknown)"
        );
        assert!(
            html.contains("(no subject)"),
            "Missing subject should show (no subject)"
        );
    }

    #[test]
    fn test_build_alert_html_confidence_percentage() {
        let mut verdict = make_verdict(ThreatLevel::High, vec![], "test");
        verdict.confidence = 0.73;
        let session = make_session(Some("a@b.com"), vec!["c@d.com"], Some("test"));
        let html = build_html(&verdict, &session);

        assert!(html.contains("73%"), "Confidence 0.73 should appear as 73%");
    }

    #[test]
    fn test_build_alert_html_contains_session_id() {
        let verdict = make_verdict(ThreatLevel::Low, vec![], "test");
        let session_id_str = verdict.session_id.to_string();
        let session = make_session(Some("a@b.com"), vec!["c@d.com"], Some("test"));
        let html = build_html(&verdict, &session);

        assert!(
            html.contains(&session_id_str),
            "HTML should contain the session ID in the footer"
        );
    }

    #[test]
    fn test_build_alert_html_modules_count() {
        let verdict = make_verdict(ThreatLevel::Medium, vec![], "test");
        let session = make_session(Some("a@b.com"), vec!["c@d.com"], Some("test"));
        let html = build_html(&verdict, &session);

        assert!(
            html.contains("15"),
            "HTML should contain modules_run count (15)"
        );
        assert!(
            html.contains("5"),
            "HTML should contain modules_flagged count (5)"
        );
    }

    #[test]
    fn test_build_alert_html_empty_categories_shows_dash() {
        let verdict = make_verdict(ThreatLevel::Low, vec![], "test");
        let session = make_session(Some("a@b.com"), vec!["c@d.com"], Some("test"));
        let html = build_html(&verdict, &session);

       // The categories field should contain "-" when empty
        assert!(
            html.contains(">-</code>"),
            "Empty categories should show a dash"
        );
    }

    #[test]
    fn test_build_alert_html_multiple_recipients() {
        let verdict = make_verdict(ThreatLevel::High, vec![], "test");
        let session = make_session(
            Some("sender@test.com"),
            vec!["alice@corp.com", "bob@corp.com"],
            Some("test"),
        );
        let html = build_html(&verdict, &session);

        assert!(
            html.contains("alice@corp.com, bob@corp.com"),
            "Multiple recipients should be comma-separated"
        );
    }

    #[test]
    fn test_build_alert_html_contains_custom_message_and_ip_fields() {
        let verdict = make_verdict(ThreatLevel::High, vec!["phishing".to_string()], "test");
        let session = make_session(
            Some("attacker@evil.com"),
            vec!["user@corp.com"],
            Some("invoice"),
        );
        let internal_domains = HashSet::from([String::from("corp.com")]);
        let custom_message = render_action_message_template(
            "方向={{mail_direction}} 外网IP={{external_ip}}",
            &verdict,
            &session,
            &internal_domains,
            &HashSet::new(),
        );
        let html = build_alert_html(
            &verdict,
            &session,
            Some(&custom_message),
            &internal_domains,
            &HashSet::new(),
        );

        assert!(html.contains("自定义告警内容"));
        assert!(html.contains("方向=inbound"));
        assert!(html.contains("外网IP=10.0.0.1"));
        assert!(html.contains("Client IP"));
        assert!(html.contains("Server IP"));
        assert!(html.contains("External IP"));
    }
}
