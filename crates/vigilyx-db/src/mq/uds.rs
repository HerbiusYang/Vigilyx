//! Unix Domain Socket transport layer

//! Fallback communication when Redis unavailable. UdsServer runs on API side, UdsClient runs on Engine side.
//! Bidirectional communication using length-prefixed binary frame protocol.

//! Frame format:
//! ```text

//! 4 bytes LE payload
//! (length) topic\0json_payload



use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::error::{MqError, MqResult};

/// Max single message size: 16MB
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Reconnection interval
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// Channel capacity (backpressure)
const CHANNEL_CAPACITY: usize = 1000;

/// I/O buffer size
const BUF_SIZE: usize = 8 * 1024;

/// UDS Message
#[derive(Debug, Clone)]
pub struct UdsMessage {
    pub topic: String,
    pub payload: serde_json::Value,
}

impl UdsMessage {
   /// Serialize to frame: [4 bytes length LE][topic\0payload]
    fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload_str = serde_json::to_string(&self.payload)?;
       // topic + \0 + payload
        let body_len = self.topic.len() + 1 + payload_str.len();
        let mut buf = Vec::with_capacity(4 + body_len);
        buf.extend_from_slice(&(body_len as u32).to_le_bytes());
        buf.extend_from_slice(self.topic.as_bytes());
        buf.push(0); // null separator
        buf.extend_from_slice(payload_str.as_bytes());
        Ok(buf)
    }

   /// Parse from frame body (without length header)
    fn decode(body: &[u8]) -> MqResult<Self> {
       // Find null separator
        let sep_pos = body
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| MqError::Publish("UDS frame missing null separator".to_string()))?;

        let topic = std::str::from_utf8(&body[..sep_pos])
            .map_err(|e| MqError::Publish(format!("Invalid topic UTF-8: {}", e)))?
            .to_string();

        let payload: serde_json::Value = serde_json::from_slice(&body[sep_pos + 1..])?;

        Ok(UdsMessage { topic, payload })
    }
}


// UDS Server (API)


/// API-side UDS server
///
/// Listen on Unix socket and accept Engine process connections.
/// Support Engine reconnection (accept new connection after old one closes).
pub struct UdsServer;

impl UdsServer {
   /// Start UDS server
   ///
   /// Return (tx to Engine, rx from Engine).
   /// Spawn listener task in background, automatically handle connection/disconnection/reconnection.
    pub async fn start(
        socket_path: &Path,
    ) -> MqResult<(mpsc::Sender<UdsMessage>, mpsc::Receiver<UdsMessage>)> {
       // Delete leftover socket file
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path)
            .map_err(|e| MqError::Connection(format!("UDS bind failed: {}", e)))?;

       // SEC: Restrict socket permissions to owner only (CWE-732)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            {
                warn!("Failed to set UDS socket permissions: {}", e);
            }
        }

        info!("UDS server started: {}", socket_path.display());

       // API -> Engine direction
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<UdsMessage>(CHANNEL_CAPACITY);
       // Engine -> API direction
        let (incoming_tx, incoming_rx) = mpsc::channel::<UdsMessage>(CHANNEL_CAPACITY);

        let path_display = socket_path.display().to_string();

        tokio::spawn(async move {
            Self::accept_loop(listener, outgoing_rx, incoming_tx, &path_display).await;
        });

        Ok((outgoing_tx, incoming_rx))
    }

   /// Accept connection loop (supports Engine reconnection)
    async fn accept_loop(
        listener: UnixListener,
        mut outgoing_rx: mpsc::Receiver<UdsMessage>,
        incoming_tx: mpsc::Sender<UdsMessage>,
        path_display: &str,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("UDS Engine connected: {}", path_display);

                   // Split stream into read/write halves
                    let (reader, writer) = stream.into_split();
                    let buf_reader = BufReader::with_capacity(BUF_SIZE, reader);
                    let buf_writer = BufWriter::with_capacity(BUF_SIZE, writer);

                   // spawn read task
                    let incoming_tx_clone = incoming_tx.clone();
                    let read_handle = tokio::spawn(async move {
                        read_loop(buf_reader, incoming_tx_clone).await;
                    });

                   // Write loop (runs in current task until connection closes)
                    write_loop(buf_writer, &mut outgoing_rx).await;

                   // Write ended means connection closed, abort read task
                    read_handle.abort();
                    warn!("UDS Engine disconnected, waiting for reconnection...");
                }
                Err(e) => {
                    error!("UDS accept failed: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}


// UDS Client (Engine)


/// Engine-side UDS client
///
/// Connect to API Unix socket, supports automatic reconnection.
pub struct UdsClient;

impl UdsClient {
   /// Connect to UDS server
   ///
   /// Return (tx to API, rx from API).
   /// Spawn read/write tasks in background, automatic reconnection on disconnect.
    pub async fn connect(
        socket_path: &Path,
    ) -> MqResult<(mpsc::Sender<UdsMessage>, mpsc::Receiver<UdsMessage>)> {
       // Engine -> API direction
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<UdsMessage>(CHANNEL_CAPACITY);
       // API -> Engine direction
        let (incoming_tx, incoming_rx) = mpsc::channel::<UdsMessage>(CHANNEL_CAPACITY);

        let path = socket_path.to_path_buf();

        tokio::spawn(async move {
            Self::connect_loop(path, outgoing_rx, incoming_tx).await;
        });

        Ok((outgoing_tx, incoming_rx))
    }

   /// Connection loop (automatic reconnection on disconnect)
    async fn connect_loop(
        path: PathBuf,
        mut outgoing_rx: mpsc::Receiver<UdsMessage>,
        incoming_tx: mpsc::Sender<UdsMessage>,
    ) {
        loop {
            match UnixStream::connect(&path).await {
                Ok(stream) => {
                    info!("UDS connected to API: {}", path.display());

                    let (reader, writer) = stream.into_split();
                    let buf_reader = BufReader::with_capacity(BUF_SIZE, reader);
                    let buf_writer = BufWriter::with_capacity(BUF_SIZE, writer);

                    let incoming_tx_clone = incoming_tx.clone();
                    let read_handle = tokio::spawn(async move {
                        read_loop(buf_reader, incoming_tx_clone).await;
                    });

                    write_loop(buf_writer, &mut outgoing_rx).await;

                    read_handle.abort();
                    warn!(
                        "UDS connection disconnected, {}s seconds before reconnecting...",
                        RECONNECT_INTERVAL.as_secs()
                    );
                }
                Err(e) => {
                    warn!(
                        "UDS connection failed: {}, {}s seconds before retrying...",
                        e,
                        RECONNECT_INTERVAL.as_secs()
                    );
                }
            }

           // Drain backlog in outgoing channel before reconnecting (prevent sending stale data after reconnection)
            while outgoing_rx.try_recv().is_ok() {}

            tokio::time::sleep(RECONNECT_INTERVAL).await;
        }
    }
}


// Shared read/write loops


/// Read loop: read frames from socket and send to channel
async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    tx: mpsc::Sender<UdsMessage>,
) {
    let mut len_buf = [0u8; 4];

    loop {
       // read length header
        if let Err(e) = reader.read_exact(&mut len_buf).await {
            if e.kind() != std::io::ErrorKind::UnexpectedEof {
                warn!("UDS read length header失败: {}", e);
            }
            break;
        }

        let body_len = u32::from_le_bytes(len_buf);
        if body_len > MAX_MESSAGE_SIZE {
            error!(
                "UDS Message过大: {} bytes (limit {})",
                body_len, MAX_MESSAGE_SIZE
            );
            break;
        }

       // read message body
        let mut body = vec![0u8; body_len as usize];
        if let Err(e) = reader.read_exact(&mut body).await {
            warn!("UDS read message body失败: {}", e);
            break;
        }

       // parse message
        match UdsMessage::decode(&body) {
            Ok(msg) => {
                if tx.send(msg).await.is_err() {
                   // receiver closed
                    break;
                }
            }
            Err(e) => {
                warn!("UDS MessageParse失败: {}", e);
               // skip corrupted frame and continue reading
            }
        }
    }
}

/// Write loop: take messages from channel and write to socket
async fn write_loop<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: BufWriter<W>,
    rx: &mut mpsc::Receiver<UdsMessage>,
) {
    while let Some(msg) = rx.recv().await {
        let frame = match msg.encode() {
            Ok(f) => f,
            Err(e) => {
                warn!("UDS Message编码失败: {}", e);
                continue;
            }
        };

        if let Err(e) = writer.write_all(&frame).await {
            warn!("UDS write failed: {}", e);
            break;
        }

       // check for more pending messages, batch flush
        if rx.is_empty()
            && let Err(e) = writer.flush().await
        {
            warn!("UDS flush failed: {}", e);
            break;
        }
    }
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uds_message_encode_decode_roundtrip() {
        let msg = UdsMessage {
            topic: "vigilyx:engine:verdict".to_string(),
            payload: serde_json::json!({"score": 0.85, "verdict": "malicious"}),
        };

        let frame = msg.encode().expect("encode should succeed");
        
        let decoded = UdsMessage::decode(&frame[4..]).expect("decode should succeed");

        assert_eq!(decoded.topic, "vigilyx:engine:verdict");
        assert_eq!(decoded.payload["score"], 0.85);
        assert_eq!(decoded.payload["verdict"], "malicious");
    }

    #[test]
    fn test_uds_message_encode_decode_empty_payload() {
        let msg = UdsMessage {
            topic: "test:topic".to_string(),
            payload: serde_json::json!(null),
        };

        let frame = msg.encode().expect("encode should succeed");
        let decoded = UdsMessage::decode(&frame[4..]).expect("decode should succeed");

        assert_eq!(decoded.topic, "test:topic");
        assert!(decoded.payload.is_null());
    }

    #[test]
    fn test_uds_message_decode_missing_separator_returns_error() {
        let bad_body = b"no_separator_here";
        assert!(UdsMessage::decode(bad_body).is_err());
    }

    #[test]
    fn test_uds_message_frame_length_correct() {
        let msg = UdsMessage {
            topic: "t".to_string(),
            payload: serde_json::json!("v"),
        };

        let frame = msg.encode().expect("encode should succeed");
        let stored_len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(stored_len as usize, frame.len() - 4);
    }

    #[tokio::test]
    async fn test_uds_server_client_roundtrip() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("test.sock");

       // Start server
        let (server_tx, mut server_rx) = UdsServer::start(&sock_path).await.expect("server start");

       // briefly wait for server to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

       // connect client
        let (client_tx, mut client_rx) = UdsClient::connect(&sock_path)
            .await
            .expect("client connect");

       // wait for connection establishment
        tokio::time::sleep(Duration::from_millis(100)).await;

       // Client -> Server
        let msg = UdsMessage {
            topic: "test:c2s".to_string(),
            payload: serde_json::json!({"from": "client"}),
        };
        client_tx.send(msg).await.expect("client send");

        let received = tokio::time::timeout(Duration::from_secs(2), server_rx.recv())
            .await
            .expect("server recv timeout")
            .expect("server recv none");
        assert_eq!(received.topic, "test:c2s");
        assert_eq!(received.payload["from"], "client");

       // Server -> Client
        let msg = UdsMessage {
            topic: "test:s2c".to_string(),
            payload: serde_json::json!({"from": "server"}),
        };
        server_tx.send(msg).await.expect("server send");

        let received = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("client recv timeout")
            .expect("client recv none");
        assert_eq!(received.topic, "test:s2c");
        assert_eq!(received.payload["from"], "server");
    }
}
