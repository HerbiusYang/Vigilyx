//! SOAR configuration types.
use serde::{Deserialize, Serialize};

/// Email alert configuration (stored in config table, key = 'email_alert_config')
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailAlertConfig {
   /// Whether to enable email alerts
    #[serde(default)]
    pub enabled: bool,
   /// SMTP server address
    #[serde(default)]
    pub smtp_host: String,
   /// SMTP port (25/465/587)
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
   /// SMTP login username
    #[serde(default)]
    pub smtp_username: String,
   /// SMTP login password
    #[serde(default)]
    pub smtp_password: String,
   /// Encryption method: "none" | "starttls" | "tls"
    #[serde(default = "default_smtp_tls")]
    pub smtp_tls: String,
   /// Sender address
    #[serde(default)]
    pub from_address: String,
   /// Admin email address
    #[serde(default)]
    pub admin_email: String,
   /// Minimum alert level: "medium" | "high" | "critical"
    #[serde(default = "default_min_alert_level")]
    pub min_threat_level: String,
   /// Notify original recipient
    #[serde(default)]
    pub notify_recipient: bool,
   /// Notify admin
    #[serde(default = "default_true_val")]
    pub notify_admin: bool,
}

impl std::fmt::Debug for EmailAlertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailAlertConfig")
            .field("enabled", &self.enabled)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_username", &self.smtp_username)
            .field(
                "smtp_password",
                &if self.smtp_password.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .field("smtp_tls", &self.smtp_tls)
            .field("from_address", &self.from_address)
            .finish()
    }
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_tls() -> String {
    "starttls".to_string()
}

fn default_min_alert_level() -> String {
    "medium".to_string()
}

fn default_true_val() -> bool {
    true
}

impl Default for EmailAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: default_smtp_port(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_tls: default_smtp_tls(),
            from_address: String::new(),
            admin_email: String::new(),
            min_threat_level: default_min_alert_level(),
            notify_recipient: false,
            notify_admin: true,
        }
    }
}
