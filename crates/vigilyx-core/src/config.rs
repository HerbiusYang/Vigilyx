//! Configuration management

use crate::error::{Error, Result};
use std::env;

/// Capture mode
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CaptureMode {
   /// Local network interface capture
    #[default]
    Local,
   /// Actively connect to remote server (suitable for local NAT environment)
    RemoteConnect,
   /// Listen on TCP port to receive remote traffic
    RemoteListen,
   /// Read pcap stream from stdin
    Stdin,
}

impl CaptureMode {
   /// Parse capture mode from string
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "remote_connect" | "remote-connect" | "remoteconnect" => Self::RemoteConnect,
            "remote_listen" | "remote-listen" | "remotelisten" => Self::RemoteListen,
            "stdin" => Self::Stdin,
            _ => Self::Local,
        }
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
   /// Capture mode
    pub capture_mode: CaptureMode,
   /// Remote server address (RemoteConnect Mode only)
    pub remote_address: Option<String>,
   /// Local listen port (RemoteListen Mode only)
    pub remote_listen_port: u16,
   /// Network interface name
    pub sniffer_interface: String,
   /// Whether to enable promiscuous mode
    pub sniffer_promiscuous: bool,
   /// SMTP port list
    pub smtp_ports: Vec<u16>,
   /// POP3 port list
    pub pop3_ports: Vec<u16>,
   /// IMAP port list
    pub imap_ports: Vec<u16>,
   /// HTTP port list (webmail login detection)
    pub http_ports: Vec<u16>,
   /// Webmail Service IP table (capture IP HTTP Stream, capture HTTP)
    pub webmail_servers: Vec<String>,
   /// API ListenAddress
    pub api_host: String,
   /// API listen port
    pub api_port: u16,
   /// Database URL
    pub database_url: String,
}

impl Config {
   /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
       // Try to load.env file
        let _ = dotenvy::dotenv();

       // Capture mode
        let capture_mode =
            CaptureMode::parse(&env::var("CAPTURE_MODE").unwrap_or_else(|_| "local".to_string()));

       // Remote address (verify format)
        let remote_address = env::var("REMOTE_ADDRESS").ok().filter(|s| !s.is_empty());
        if let Some(ref addr) = remote_address
            && !Self::validate_remote_address(addr)
        {
            return Err(Error::Config(format!(
                "Invalid remote address format: {}. Expected host:port",
                addr
            )));
        }

       // remoteListenport
        let remote_listen_port = env::var("REMOTE_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);

       // verifyinterfacename
        let sniffer_interface = env::var("SNIFFER_INTERFACE").unwrap_or_else(|_| "en0".to_string());
        if !Self::validate_interface(&sniffer_interface) {
            return Err(Error::Config(format!(
                "Invalid interface name: {}",
                sniffer_interface
            )));
        }

        Ok(Self {
            capture_mode,
            remote_address,
            remote_listen_port,
            sniffer_interface,
            sniffer_promiscuous: env::var("SNIFFER_PROMISCUOUS")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            smtp_ports: Self::parse_ports(
                &env::var("SMTP_PORTS").unwrap_or_else(|_| "25,465,587,2525,2526".to_string()),
            )?,
            pop3_ports: Self::parse_ports(
                &env::var("POP3_PORTS").unwrap_or_else(|_| "110,995".to_string()),
            )?,
            imap_ports: Self::parse_ports(
                &env::var("IMAP_PORTS").unwrap_or_else(|_| "143,993".to_string()),
            )?,
            http_ports: Self::parse_ports(
                &env::var("HTTP_PORTS").unwrap_or_else(|_| "80".to_string()),
            )?,
            webmail_servers: env::var("WEBMAIL_SERVERS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            api_host: env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            api_port: env::var("API_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL 环境变量必须set (例: postgres://user:pass@host:5432/db)"),
        })
    }

   /// verifyremoteAddressformat (host:port)
    pub fn validate_remote_address(addr: &str) -> bool {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
       // verifyport
        if parts[0].parse::<u16>().is_err() {
            return false;
        }
       // verify /IP ()
        let host = parts[1];
        !host.is_empty() && host.len() <= 255 && !host.contains(' ')
    }

   /// ParseremoteAddress (host, port)
    pub fn parse_remote_address(&self) -> Option<(String, u16)> {
        self.remote_address.as_ref().and_then(|addr| {
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                let port = parts[0].parse::<u16>().ok()?;
                let host = parts[1].to_string();
                Some((host, port))
            } else {
                None
            }
        })
    }

   /// Parseport table (Securityverify)
    fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
        let ports: Vec<u16> = ports_str
            .split(',')
            .map(|s| {
                let port = s
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| Error::Config(format!("Invalid port: {}", s)))?;
               // Security: port (1-65535)
                if port == 0 {
                    return Err(Error::Config("Port 0 is not allowed".to_string()));
                }
                Ok(port)
            })
            .collect::<Result<Vec<_>>>()?;

       // Security: port ConfigurationAttack
        if ports.len() > 100 {
            return Err(Error::Config(
                "Too many ports configured (max 100)".to_string(),
            ));
        }

        Ok(ports)
    }

   /// verifyinterfacename (Attack)
    pub fn validate_interface(name: &str) -> bool {
        
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    }

   /// get Listenport (HTTP - When webmail_servers)
    pub fn all_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        ports.extend(&self.smtp_ports);
        ports.extend(&self.pop3_ports);
        ports.extend(&self.imap_ports);
        if !self.webmail_servers.is_empty() {
            ports.extend(&self.http_ports);
        }
        ports
    }

   /// port protocolport
    pub fn is_email_port(&self, port: u16) -> bool {
        self.smtp_ports.contains(&port)
            || self.pop3_ports.contains(&port)
            || self.imap_ports.contains(&port)
    }

   /// port HTTP port
    pub fn is_http_port(&self, port: u16) -> bool {
        self.http_ports.contains(&port)
    }

   /// API Address
    pub fn api_addr(&self) -> String {
        format!("{}:{}", self.api_host, self.api_port)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            capture_mode: CaptureMode::Local,
            remote_address: None,
            remote_listen_port: 5000,
            sniffer_interface: "en0".to_string(),
            sniffer_promiscuous: true,
            smtp_ports: vec![25, 465, 587, 2525, 2526],
            pop3_ports: vec![110, 995],
            imap_ports: vec![143, 993],
            http_ports: vec![80],
            webmail_servers: vec![],
            api_host: "127.0.0.1".to_string(),
            api_port: 8080,
            database_url: String::new(), // DATABASE_URL For
        }
    }
}
