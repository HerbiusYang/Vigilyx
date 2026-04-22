//! Enterprise WeChat alert pipeline: config validation, payload builder, send logic.

use std::collections::HashSet;

use serde::Deserialize;
use tracing::{error, info, warn};
use url::Url;
use vigilyx_core::{models::EmailSession, security::SecurityVerdict};

use crate::config::WechatAlertConfig;

use super::{
    DispositionAction, DispositionEngine, email_alert::parse_threat_level, infer_external_ip,
    infer_mail_direction, render_action_message_template,
};

#[derive(Deserialize)]
struct WechatResponse {
    errcode: i64,
    errmsg: String,
}

fn decrypt_webhook_url(stored: &str) -> Option<String> {
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

pub fn validate_wechat_webhook_url(raw: &str) -> Result<(), String> {
    let parsed = Url::parse(raw).map_err(|e| format!("Invalid WeChat webhook URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err("WeChat webhook must use https".to_string());
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("WeChat webhook must not contain userinfo".to_string());
    }

    if parsed.host_str() != Some("qyapi.weixin.qq.com") {
        return Err("WeChat webhook host must be qyapi.weixin.qq.com".to_string());
    }

    if parsed.path() != "/cgi-bin/webhook/send" {
        return Err("WeChat webhook path must be /cgi-bin/webhook/send".to_string());
    }

    let has_key = parsed
        .query_pairs()
        .any(|(key, value)| key == "key" && !value.trim().is_empty());
    if !has_key {
        return Err("WeChat webhook is missing the key query parameter".to_string());
    }

    Ok(())
}

fn normalize_mentioned_mobile_list(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !normalized.iter().any(|existing| existing == trimmed) {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

fn truncate_text(input: &str, max_chars: usize) -> String {
    let mut truncated = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_chars {
            truncated.push_str("...");
            break;
        }
        truncated.push(ch);
    }
    truncated
}

fn threat_level_label(level: &vigilyx_core::security::ThreatLevel) -> &'static str {
    match level {
        vigilyx_core::security::ThreatLevel::Safe => "Safe",
        vigilyx_core::security::ThreatLevel::Low => "Low",
        vigilyx_core::security::ThreatLevel::Medium => "Medium",
        vigilyx_core::security::ThreatLevel::High => "High",
        vigilyx_core::security::ThreatLevel::Critical => "Critical",
    }
}

fn build_wechat_alert_text(
    verdict: &SecurityVerdict,
    session: &EmailSession,
    internal_domains: &HashSet<String>,
    inbound_mail_servers: &HashSet<String>,
) -> String {
    let sender = session.mail_from.as_deref().unwrap_or("(unknown)");
    let recipients = if session.rcpt_to.is_empty() {
        "(unknown)".to_string()
    } else {
        session.rcpt_to.join(", ")
    };
    let subject = session.subject.as_deref().unwrap_or("(no subject)");
    let mail_direction = infer_mail_direction(session, internal_domains, inbound_mail_servers)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let external_ip = infer_external_ip(session, internal_domains, inbound_mail_servers)
        .unwrap_or_else(|| "-".to_string());
    let categories = if verdict.categories.is_empty() {
        "-".to_string()
    } else {
        verdict.categories.join(", ")
    };
    let summary = truncate_text(&verdict.summary, 280);

    format!(
        "VIGILYX 微信安全告警\n等级: {level}\n置信度: {confidence}%\n方向: {mail_direction}\n发件人: {sender}\n收件人: {recipients}\n主题: {subject}\nClient IP: {client_ip}\nServer IP: {server_ip}\n外网 IP: {external_ip}\n分类: {categories}\n模块: {modules_flagged}/{modules_run}\n摘要: {summary}\nSession: {session_id}",
        level = threat_level_label(&verdict.threat_level),
        confidence = (verdict.confidence * 100.0) as u32,
        mail_direction = truncate_text(&mail_direction, 40),
        sender = truncate_text(sender, 120),
        recipients = truncate_text(&recipients, 180),
        subject = truncate_text(subject, 140),
        client_ip = truncate_text(&session.client_ip, 80),
        server_ip = truncate_text(&session.server_ip, 80),
        external_ip = truncate_text(&external_ip, 80),
        categories = truncate_text(&categories, 140),
        modules_flagged = verdict.modules_flagged,
        modules_run = verdict.modules_run,
        summary = summary,
        session_id = verdict.session_id,
    )
}

impl DispositionEngine {
    pub(super) async fn execute_wechat_action(
        &self,
        action: &DispositionAction,
        verdict: &SecurityVerdict,
        session: &EmailSession,
        internal_domains: &HashSet<String>,
        inbound_mail_servers: &HashSet<String>,
    ) {
        let content = match action
            .message_template
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(prefix) => format!(
                "{}\n\n{}",
                truncate_text(
                    &render_action_message_template(
                        prefix,
                        verdict,
                        session,
                        internal_domains,
                        inbound_mail_servers,
                    ),
                    220,
                ),
                build_wechat_alert_text(verdict, session, internal_domains, inbound_mail_servers,)
            ),
            None => {
                build_wechat_alert_text(verdict, session, internal_domains, inbound_mail_servers)
            }
        };

        let config = if let Some(webhook_url) = action.webhook_url.as_deref() {
            WechatAlertConfig {
                enabled: true,
                webhook_url: webhook_url.to_string(),
                min_threat_level: "medium".to_string(),
                mentioned_mobile_list: normalize_mentioned_mobile_list(
                    &action.mentioned_mobile_list,
                ),
            }
        } else {
            let Some(mut config) = self.load_wechat_alert_config().await else {
                warn!("WeChat disposition action skipped: no saved WeChat alert config");
                return;
            };
            if !config.enabled || config.webhook_url.is_empty() {
                return;
            }
            let min_level = parse_threat_level(&config.min_threat_level);
            if verdict.threat_level < min_level {
                return;
            }
            if !action.mentioned_mobile_list.is_empty() {
                config.mentioned_mobile_list =
                    normalize_mentioned_mobile_list(&action.mentioned_mobile_list);
            }
            config
        };

        if let Err(e) = self.send_wechat_text(&config, &content).await {
            error!(
                session_id = %verdict.session_id,
                "Failed to execute WeChat disposition action: {}", e
            );
        } else {
            info!(
                session_id = %verdict.session_id,
                threat_level = %verdict.threat_level,
                "WeChat disposition action sent"
            );
        }
    }

    async fn load_wechat_alert_config(&self) -> Option<WechatAlertConfig> {
        match self.db.get_wechat_alert_config().await {
            Ok(Some(json)) => {
                let mut config: WechatAlertConfig = serde_json::from_str(&json).ok()?;
                if config.webhook_url.starts_with("ENC:") {
                    config.webhook_url =
                        decrypt_webhook_url(&config.webhook_url).unwrap_or_default();
                }
                config.mentioned_mobile_list =
                    normalize_mentioned_mobile_list(&config.mentioned_mobile_list);
                if config.enabled
                    && !config.webhook_url.is_empty()
                    && let Err(reason) = validate_wechat_webhook_url(&config.webhook_url)
                {
                    warn!(
                        "WeChat alert config blocked at runtime (validation failed): {}",
                        reason
                    );
                    return None;
                }
                Some(config)
            }
            _ => None,
        }
    }

    async fn send_wechat_text(
        &self,
        config: &WechatAlertConfig,
        content: &str,
    ) -> Result<(), String> {
        validate_wechat_webhook_url(&config.webhook_url)?;

        let mut text_obj = serde_json::json!({
            "content": content,
        });
        if !config.mentioned_mobile_list.is_empty()
            && let Some(map) = text_obj.as_object_mut()
        {
            map.insert(
                "mentioned_mobile_list".to_string(),
                serde_json::json!(config.mentioned_mobile_list.clone()),
            );
        }

        let body = serde_json::json!({
            "msgtype": "text",
            "text": text_obj,
        });

        let response = self
            .http
            .post(&config.webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WeChat request failed: {}", e))?;

        let status = response.status();
        let response_body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read WeChat response: {}", e))?;
        if !status.is_success() {
            return Err(format!(
                "WeChat request failed with HTTP {}: {}",
                status,
                truncate_text(&response_body, 200)
            ));
        }

        let result: WechatResponse = serde_json::from_str(&response_body)
            .map_err(|e| format!("Invalid WeChat response: {} ({})", e, response_body))?;
        if result.errcode != 0 {
            return Err(format!(
                "WeChat API error {}: {}",
                result.errcode, result.errmsg
            ));
        }

        Ok(())
    }

    pub async fn test_wechat_alert(&self, config: &WechatAlertConfig) -> Result<String, String> {
        if config.webhook_url.trim().is_empty() {
            return Err("WeChat webhook URL is empty".to_string());
        }

        let mut test_config = config.clone();
        test_config.mentioned_mobile_list =
            normalize_mentioned_mobile_list(&test_config.mentioned_mobile_list);

        let content = format!(
            "VIGILYX 微信告警测试\n时间: {}\nWebhook 配置验证成功\n此消息由 VIGILYX 自动发送。",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        self.send_wechat_text(&test_config, &content).await?;
        Ok("Test WeChat alert sent successfully".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_wechat_webhook_url;

    #[test]
    fn validate_wechat_webhook_url_accepts_official_webhook() {
        assert!(
            validate_wechat_webhook_url(
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_wechat_webhook_url_rejects_non_https() {
        assert!(
            validate_wechat_webhook_url(
                "http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key"
            )
            .is_err()
        );
    }

    #[test]
    fn validate_wechat_webhook_url_rejects_non_wechat_host() {
        assert!(
            validate_wechat_webhook_url("https://example.com/cgi-bin/webhook/send?key=test-key")
                .is_err()
        );
    }

    #[test]
    fn validate_wechat_webhook_url_rejects_missing_key() {
        assert!(
            validate_wechat_webhook_url("https://qyapi.weixin.qq.com/cgi-bin/webhook/send")
                .is_err()
        );
    }
}
