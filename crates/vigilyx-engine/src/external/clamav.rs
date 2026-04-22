//! ClamAV TCP client - clamd INSTREAM protocol implementation.

//! Communicates with a ClamAV daemon over TCP (default port 3310) using the
//! `zINSTREAM` command. data is sent in chunks with 4-byte big-endian length
//! prefixes, terminated by a zero-length chunk. The daemon responds with
//! `stream: OK\0` or `stream: <virus_name> FOUND\0`.

//! No temporary files are created - all scanning happens over the TCP stream.

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Maximum chunk size for INSTREAM data (2 KB).
const CHUNK_SIZE: usize = 2048;

/// Default connection timeout.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default scan timeout (large files may take a while).
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of a ClamAV scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    /// No virus detected.
    Clean,
    /// Virus detected with the given signature name.
    Infected { virus_name: String },
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanResult::Clean => write!(f, "Clean"),
            ScanResult::Infected { virus_name } => write!(f, "Infected: {}", virus_name),
        }
    }
}

/// Errors from ClamAV communication.
#[derive(Debug)]
pub enum ClamAvError {
    /// Cannot connect to the ClamAV daemon.
    ConnectionFailed(String),
    /// Scan timed out.
    Timeout,
    /// Unexpected response from the daemon.
    ProtocolError(String),
    /// I/O error during communication.
    IoError(std::io::Error),
}

impl fmt::Display for ClamAvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClamAvError::ConnectionFailed(msg) => write!(f, "ClamAV connection failed: {}", msg),
            ClamAvError::Timeout => write!(f, "ClamAV scan timeout"),
            ClamAvError::ProtocolError(msg) => write!(f, "ClamAV protocol error: {}", msg),
            ClamAvError::IoError(e) => write!(f, "ClamAV I/O Error: {}", e),
        }
    }
}

impl From<std::io::Error> for ClamAvError {
    fn from(e: std::io::Error) -> Self {
        ClamAvError::IoError(e)
    }
}

/// ClamAV TCP client for the clamd INSTREAM protocol.
pub struct ClamAvClient {
    host: String,
    port: u16,
    connect_timeout: Duration,
    scan_timeout: Duration,
}

impl ClamAvClient {
    /// Create a new client from explicit host and port.
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
        }
    }

    /// Create a client from environment variables.

    /// - `CLAMAV_HOST` (default: `clamav`)
    /// - `CLAMAV_PORT` (default: `3310`)
    /// - `CLAMAV_SCAN_TIMEOUT_SECS` (default: `30`)
    pub fn from_env() -> Self {
        let host = std::env::var("CLAMAV_HOST").unwrap_or_else(|_| "clamav".to_string());
        let port: u16 = std::env::var("CLAMAV_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3310);
        let scan_timeout_secs: u64 = std::env::var("CLAMAV_SCAN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Self {
            host,
            port,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            scan_timeout: Duration::from_secs(scan_timeout_secs),
        }
    }

    /// Address string for logging.
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Health check: send zPING, expect PONG.
    pub async fn ping(&self) -> bool {
        match self.ping_inner().await {
            Ok(true) => true,
            Ok(false) => {
                warn!("ClamAV ping response abnormal");
                false
            }
            Err(e) => {
                debug!("ClamAV ping Failed: {}", e);
                false
            }
        }
    }

    async fn ping_inner(&self) -> Result<bool, ClamAvError> {
        let mut stream = self.connect().await?;

        // Send zPING command (null-terminated)
        stream.write_all(b"zPING\0").await?;
        stream.flush().await?;

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(self.connect_timeout, stream.read(&mut buf))
            .await
            .map_err(|_| ClamAvError::Timeout)?
            .map_err(ClamAvError::IoError)?;

        let response = String::from_utf8_lossy(&buf[..n]);
        Ok(response.trim_matches('\0').trim() == "PONG")
    }

    /// Scan raw bytes via the INSTREAM protocol.

    /// Protocol:
    /// 1. Send `zINSTREAM\0`
    /// 2. Send data in chunks: `[4-byte big-endian length][chunk bytes]`
    /// 3. Send terminator: `[0x00 0x00 0x00 0x00]`
    /// 4. Read response until null byte
    /// 5. Parse `stream: OK\0` or `stream: <virus_name> FOUND\0`
    pub async fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult, ClamAvError> {
        tokio::time::timeout(self.scan_timeout, self.scan_bytes_inner(data))
            .await
            .map_err(|_| ClamAvError::Timeout)?
    }

    async fn scan_bytes_inner(&self, data: &[u8]) -> Result<ScanResult, ClamAvError> {
        let mut stream = self.connect().await?;

        // 1. Send INSTREAM command
        stream.write_all(b"zINSTREAM\0").await?;

        // 2. Send data in chunks with 4-byte big-endian length prefix
        for chunk in data.chunks(CHUNK_SIZE) {
            let len = chunk.len() as u32;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(chunk).await?;
        }

        // 3. Send zero-length terminator
        stream.write_all(&0u32.to_be_bytes()).await?;
        stream.flush().await?;

        // 4. Read response
        let mut response_buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 256];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            response_buf.extend_from_slice(&tmp[..n]);
            // Response is null-terminated
            if response_buf.contains(&0) {
                break;
            }
            if response_buf.len() > 4096 {
                return Err(ClamAvError::ProtocolError(
                    "Response exceeds 4KB limit".to_string(),
                ));
            }
        }

        // 5. Parse response
        let response = String::from_utf8_lossy(&response_buf);
        let response = response.trim_matches('\0').trim();
        parse_scan_response(response)
    }

    /// Establish a TCP connection to clamd.
    async fn connect(&self) -> Result<TcpStream, ClamAvError> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| ClamAvError::ConnectionFailed(format!("ConnectionTimeout: {}", addr)))?
            .map_err(|e| ClamAvError::ConnectionFailed(format!("{}: {}", addr, e)))?;
        Ok(stream)
    }
}

/// Parse a clamd scan response string.

/// Expected formats:
/// - `stream: OK` - no virus found
/// - `stream: <virus_name> FOUND` - virus detected
/// - `stream: <error> ERROR` - scan error
pub fn parse_scan_response(response: &str) -> Result<ScanResult, ClamAvError> {
    // Remove the "stream: " prefix
    let body = if let Some(stripped) = response.strip_prefix("stream: ") {
        stripped
    } else {
        // Some ClamAV versions omit "stream: " prefix
        response
    };

    if body == "OK" {
        return Ok(ScanResult::Clean);
    }

    if let Some(virus) = body.strip_suffix(" FOUND") {
        return Ok(ScanResult::Infected {
            virus_name: virus.to_string(),
        });
    }

    if body.ends_with("ERROR") {
        return Err(ClamAvError::ProtocolError(format!(
            "ClamAV scan error: {}",
            body
        )));
    }

    Err(ClamAvError::ProtocolError(format!(
        "Cannot parse ClamAV response: {}",
        response
    )))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_response() {
        let result = parse_scan_response("stream: OK");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ScanResult::Clean);
    }

    #[test]
    fn test_parse_clean_response_without_prefix() {
        let result = parse_scan_response("OK");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ScanResult::Clean);
    }

    #[test]
    fn test_parse_infected_response() {
        let result = parse_scan_response("stream: Eicar-Signature FOUND");
        assert!(result.is_ok());
        match result.unwrap() {
            ScanResult::Infected { virus_name } => {
                assert_eq!(virus_name, "Eicar-Signature");
            }
            ScanResult::Clean => panic!("expected Infected"),
        }
    }

    #[test]
    fn test_parse_infected_complex_name() {
        let result = parse_scan_response("stream: Win.Trojan.Agent-123456 FOUND");
        assert!(result.is_ok());
        match result.unwrap() {
            ScanResult::Infected { virus_name } => {
                assert_eq!(virus_name, "Win.Trojan.Agent-123456");
            }
            ScanResult::Clean => panic!("expected Infected"),
        }
    }

    #[test]
    fn test_parse_error_response() {
        let result = parse_scan_response("stream: INSTREAM size limit exceeded ERROR");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_response() {
        let result = parse_scan_response("something unexpected");
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_result_display() {
        assert_eq!(format!("{}", ScanResult::Clean), "Clean");
        assert_eq!(
            format!(
                "{}",
                ScanResult::Infected {
                    virus_name: "EICAR".to_string()
                }
            ),
            "Infected: EICAR"
        );
    }

    #[test]
    fn test_clamav_error_display() {
        let err = ClamAvError::ConnectionFailed("test".to_string());
        assert_eq!(format!("{}", err), "ClamAV connection failed: test");

        let err = ClamAvError::Timeout;
        assert_eq!(format!("{}", err), "ClamAV scan timeout");

        let err = ClamAvError::ProtocolError("bad".to_string());
        assert_eq!(format!("{}", err), "ClamAV protocol error: bad");
    }

    #[test]
    fn test_client_from_env_defaults() {
        // Clear env to test defaults
        // SAFETY: test-only, single-threaded test runner
        unsafe {
            std::env::remove_var("CLAMAV_HOST");
            std::env::remove_var("CLAMAV_PORT");
        }
        let client = ClamAvClient::from_env();
        assert_eq!(client.host, "clamav");
        assert_eq!(client.port, 3310);
        assert_eq!(client.address(), "clamav:3310");
    }

    #[test]
    fn test_chunk_encoding_size() {
        // Verify chunk size constant is reasonable
        assert_eq!(CHUNK_SIZE, 2048);
        // A 5000-byte payload should produce 3 chunks: 2048 + 2048 + 904
        let data = vec![0u8; 5000];
        let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 2048);
        assert_eq!(chunks[1].len(), 2048);
        assert_eq!(chunks[2].len(), 904);
    }
}
