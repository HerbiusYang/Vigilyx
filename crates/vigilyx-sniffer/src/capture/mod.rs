//! High-performance email traffic capture module (v2.0)

//! Designed to handle 10 Gbps+ email protocol traffic

//! Performance optimizations:
//! - Kernel BPF filtering reduces copies into userspace
//! - Port bitmap for O(1) matching (cache-line aligned)
//! - Cache-line aligned avoids false sharing
//! - Batch processing to reduce atomic operations
//! - Zero-copy `Bytes` reference counting
//! - Branch prediction hints (`#[cold]`) for slow paths
//! - Aggressively inline hot paths

mod bpf;
mod packet_parser;
mod port_bitmap;
mod publisher;

// Re-export the public API.
pub use packet_parser::{IpAddr, RawpacketInfo};
pub use port_bitmap::PortBitmap;
pub use publisher::{DataPublisher, PublishMode};

use crate::parser::ProtocolParser;
use crate::parser::file_protocol::{FileProtocolReader, Frame};
use crate::parser::pcapng::PcapngParser;
use crate::session::{ProcessResult, SessionKey, ShardedSessionManager};
use crate::zerocopy::{AdaptiveBatcher, BatchConfig};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, TrySendError, bounded};
use pcap::{Capture, Device};
use smallvec::SmallVec;
use socket2::{SockRef, TcpKeepalive};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufReader, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::TcpListener as TokioTcpListener;
use tracing::{debug, error, info, trace, warn};
use vigilyx_core::Config;
use vigilyx_db::mq::MqClient;


// Performance constants tuned for modern CPUs.


/// Capture timeout (100 ms, balancing latency and throughput)
const CAPTURE_TIMEOUT_MS: i32 = 100;
/// Worker queue capacity (100K, enough for burst traffic)
const WORKER_QUEUE_CAPACITY: usize = 100_000;
/// Batch size (512, tuned for L2 cache)
const BATCH_SIZE: usize = 512;
/// Batch timeout (microseconds)
const BATCH_TIMEOUT_US: u64 = 5000;
/// Default max worker thread count (overridable via `SNIFFER_WORKERS` env var).
/// Email protocol traffic is typically <10K pps - dozens of threads are unnecessary.
/// Excessive threads cause crossbeam channel contention + context switch overhead.
/// 16 threads can comfortably handle 100K+ pps with headroom for burst traffic.
const DEFAULT_MAX_WORKER_THREADS: usize = 16;
/// Default libpcap buffer size in MB.
const DEFAULT_CAPTURE_BUFFER_MB: usize = 256;
/// Keep the buffer within a sane range.
const MIN_CAPTURE_BUFFER_MB: usize = 64;
const MAX_CAPTURE_BUFFER_MB: usize = 1024;

/// Read worker thread count from `SNIFFER_WORKERS` env var, falling back to default.
fn max_worker_threads() -> usize {
    std::env::var("SNIFFER_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_WORKER_THREADS)
        .max(1)
}

fn capture_buffer_size_mb() -> usize {
    let requested = std::env::var("SNIFFER_CAPTURE_BUFFER_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let configured = requested.unwrap_or(DEFAULT_CAPTURE_BUFFER_MB);
    let clamped = configured.clamp(MIN_CAPTURE_BUFFER_MB, MAX_CAPTURE_BUFFER_MB);

    if let Some(raw) = requested
        && raw != clamped
    {
        warn!(
            requested_mb = raw,
            effective_mb = clamped,
            "SNIFFER_CAPTURE_BUFFER_MB 超出安全范围，已自动钳制"
        );
    }

    clamped
}


// Capture statistics


/// Capture statistics, cache-line aligned to avoid false sharing.
#[derive(Default)]
#[repr(C, align(64))]
pub struct CaptureStats {
    pub packets_received: AtomicU64,
    pub packets_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub worker_queue_full_drops: AtomicU64,
    pub packets_email: AtomicU64,
    pub bytes_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
struct InterfaceCounters {
    rx_packets: u64,
    rx_dropped: u64,
    rx_errors: u64,
    rx_missed_errors: u64,
}

impl InterfaceCounters {
    fn diff_since(self, previous: Self) -> Self {
        Self {
            rx_packets: self.rx_packets.saturating_sub(previous.rx_packets),
            rx_dropped: self.rx_dropped.saturating_sub(previous.rx_dropped),
            rx_errors: self.rx_errors.saturating_sub(previous.rx_errors),
            rx_missed_errors: self
                .rx_missed_errors
                .saturating_sub(previous.rx_missed_errors),
        }
    }
}

fn read_interface_counter(interface: &str, stat: &str) -> Option<u64> {
    let path = format!("/sys/class/net/{interface}/statistics/{stat}");
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn read_interface_counters(interface: &str) -> Option<InterfaceCounters> {
    Some(InterfaceCounters {
        rx_packets: read_interface_counter(interface, "rx_packets")?,
        rx_dropped: read_interface_counter(interface, "rx_dropped")?,
        rx_errors: read_interface_counter(interface, "rx_errors").unwrap_or(0),
        rx_missed_errors: read_interface_counter(interface, "rx_missed_errors").unwrap_or(0),
    })
}


// High-performance capture engine.


/// High-performance traffic capture engine
pub struct HighPerformanceCapturer {
    config: Arc<Config>,
    stats: Arc<CaptureStats>,
    stop_flag: Arc<AtomicBool>,
    session_manager: Arc<ShardedSessionManager>,
   /// Data publisher (MQ or HTTP)
    publisher: DataPublisher,
   /// Port bitmap for O(1) matching
    port_bitmap: Arc<PortBitmap>,
   /// Tokio runtime handle passed into worker threads from synchronous code
    runtime_handle: Option<tokio::runtime::Handle>,
}

impl HighPerformanceCapturer {
    fn start_worker_pool(
        &self,
        num_workers: usize,
        publisher_with_handle: DataPublisher,
    ) -> Result<Arc<Vec<Sender<RawpacketInfo>>>> {
        let mut worker_txs = Vec::with_capacity(num_workers);

        #[cfg(target_os = "linux")]
        let core_ids = core_affinity::get_core_ids().unwrap_or_default();

        for worker_id in 0..num_workers {
            let (tx, rx): (Sender<RawpacketInfo>, Receiver<RawpacketInfo>) =
                bounded(WORKER_QUEUE_CAPACITY);
            worker_txs.push(tx);

            let stats = self.stats.clone();
            let session_manager = self.session_manager.clone();
            let publisher = publisher_with_handle.clone();
            let stop_flag = self.stop_flag.clone();
            let config = self.config.clone();

            #[cfg(target_os = "linux")]
            let core_id = if core_ids.is_empty() {
                None
            } else {
                core_ids.get(worker_id % core_ids.len()).copied()
            };

            thread::Builder::new()
                .name(format!("worker-{}", worker_id))
                .spawn(move || {
                    #[cfg(target_os = "linux")]
                    if let Some(core) = core_id
                        && core_affinity::set_for_current(core)
                    {
                        info!("Worker thread {} 绑定到 CPU {}", worker_id, core.id);
                    }

                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        Self::worker_loop(
                            worker_id,
                            rx,
                            stats.clone(),
                            session_manager,
                            publisher,
                            stop_flag,
                            config,
                        );
                    }));

                    if let Err(e) = result {
                        error!(
                            "Worker thread {} Occur panic: {:?}",
                            worker_id,
                            e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                        );
                    }
                })?;
        }

        Ok(Arc::new(worker_txs))
    }

    #[inline]
    fn worker_index_for_packet(packet: &RawpacketInfo, num_workers: usize) -> usize {
        let key = SessionKey::new(packet);
        let mut hasher = rustc_hash::FxHasher::default();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % num_workers.max(1)
    }

    #[inline]
    fn dispatch_packet(
        worker_txs: &[Sender<RawpacketInfo>],
        packet_info: RawpacketInfo,
    ) -> Result<usize, (usize, TrySendError<RawpacketInfo>)> {
        let worker_idx = Self::worker_index_for_packet(&packet_info, worker_txs.len());
        worker_txs[worker_idx]
            .try_send(packet_info)
            .map(|_| worker_idx)
            .map_err(|err| (worker_idx, err))
    }

   /// Create a new high-performance capture engine.
    pub fn new(
        config: Config,
        session_manager: Arc<ShardedSessionManager>,
        mq: Option<MqClient>,
    ) -> Self {
       // Build the port bitmap.
        let mut all_ports = Vec::with_capacity(16);
        all_ports.extend(&config.smtp_ports);
        all_ports.extend(&config.pop3_ports);
        all_ports.extend(&config.imap_ports);
        if !config.webmail_servers.is_empty() {
            all_ports.extend(&config.http_ports);
        }
        let port_bitmap = Arc::new(PortBitmap::from_ports(&all_ports));

       // Create the data publisher.
        let publish_mode = if let Some(mq) = mq {
            info!("Using Redis Streams + Pub/Sub for data publishing");
            let stream = vigilyx_db::mq::StreamClient::with_auto_consumer(
                mq.clone(),
                vigilyx_db::mq::consumer_groups::ENGINE,
            );
            PublishMode::Mq {
                stream: Arc::new(stream),
            }
        } else {
            let api_url = format!("http://{}:{}", config.api_host, config.api_port);
            info!("Use HTTP 直ConnectSenddata到 API: {}", api_url);
           // Create an HTTP client that bypasses proxy inheritance from `sudo`.
            let client = crate::internal_api_client_builder()
                .build()
                .expect("internal publish HTTP client should build");
            PublishMode::Http {
                client: Arc::new(client),
                api_url,
            }
        };
        let publisher = DataPublisher::new(publish_mode);

       // Capture the current Tokio runtime handle, if available.
        let runtime_handle = tokio::runtime::Handle::try_current().ok();

        Self {
            config: Arc::new(config),
            stats: Arc::new(CaptureStats::default()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            session_manager,
            publisher,
            port_bitmap,
            runtime_handle,
        }
    }

   /// Return capture statistics.
    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

   /// Start packet capture.
    pub fn start(&self) -> Result<()> {
        let interface = &self.config.sniffer_interface;

       // Look up the configured network interface.
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == *interface)
            .ok_or_else(|| {
                let available: Vec<_> = Device::list()
                    .unwrap_or_default()
                    .iter()
                    .map(|d| d.name.clone())
                    .collect();
                anyhow!(
                    "未find到NetworkInterface: {}。可用: {:?}",
                    interface,
                    available
                )
            })?;

        info!("already选择NetworkInterface: {}", device.name);

       // Attach the runtime handle to the publisher when one is available.
        let publisher_with_handle = if let Some(ref handle) = self.runtime_handle {
            self.publisher.clone().with_runtime_handle(handle.clone())
        } else {
            self.publisher.clone()
        };

       // Start worker threads (CPU count minus one, with a minimum of one).
        let num_workers = (num_cpus::get().saturating_sub(1)).clamp(1, max_worker_threads());
        info!("Start {} Worker thread", num_workers);

        let worker_txs = self.start_worker_pool(num_workers, publisher_with_handle)?;

       // Start the capture thread with panic isolation.
        let stats = self.stats.clone();
        let config = self.config.clone();
        let port_bitmap = self.port_bitmap.clone();
        let stop_flag = self.stop_flag.clone();
        let worker_txs = worker_txs.clone();

        thread::Builder::new()
            .name("capture".to_string())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::capture_loop(
                        device,
                        worker_txs,
                        stats,
                        config,
                        port_bitmap,
                        stop_flag,
                    )
                }));

                match result {
                    Ok(Ok(())) => info!("Capture threadexited normally"),
                    Ok(Err(e)) => error!("Capture threadError: {}", e),
                    Err(e) => error!(
                        "Capture thread panic: {:?}",
                        e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                    ),
                }
            })?;

        info!("High-performanceCaptureDevice/HandleralreadyStart");
        Ok(())
    }

   /// Request a graceful stop for capture and worker threads.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

   /// Read a pcap byte stream from standard input.
   ///
   /// This mode is intended for remote piping, for example:
   /// ```bash
   /// ssh root@remote "tcpdump -i eth1 -U -s0 -w -" | vigilyx-sniffer --stdin
   /// ```
    pub fn start_from_stdin(&self) -> Result<()> {
        info!("Start stdin modeCapture...");

       // Reuse the Tokio runtime handle when available so workers can publish asynchronously.
        let publisher_with_handle = if let Some(ref handle) = self.runtime_handle {
            self.publisher.clone().with_runtime_handle(handle.clone())
        } else {
            self.publisher.clone()
        };

       // Start worker threads before reading from stdin so parsed packets can flow immediately.
        let num_workers = (num_cpus::get().saturating_sub(1)).clamp(1, max_worker_threads());
        info!("Start {} Worker thread", num_workers);

        let worker_txs = self.start_worker_pool(num_workers, publisher_with_handle)?;

       // Move stdin processing onto a dedicated blocking thread.
        let stats = self.stats.clone();
        let port_bitmap = self.port_bitmap.clone();
        let stop_flag = self.stop_flag.clone();
        let worker_txs = worker_txs.clone();

        thread::Builder::new()
            .name("stdin-capture".to_string())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::stdin_capture_loop(worker_txs, stats, port_bitmap, stop_flag)
                }));

                match result {
                    Ok(Ok(())) => info!("stdin Capture threadexited normally"),
                    Ok(Err(e)) => error!("stdin Capture threadError: {}", e),
                    Err(e) => error!(
                        "stdin Capture thread panic: {:?}",
                        e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                    ),
                }
            })?;

        info!("stdin modeCaptureDevice/HandleralreadyStart");
        Ok(())
    }

   /// Listen on a local TCP port and accept a remote pcap byte stream.
   ///
   /// This mode is designed to be exposed only through an SSH tunnel:
   /// ```bash
   /// vigilyx-sniffer --remote-listen 5000
   ///
   /// # SSH
   /// ssh -R 5000:127.0.0.1:5000 root@203.0.113.10
   ///
   /// # Remote
   /// tcpdump -i eth1 -U -s0 -w - | nc localhost 5000
   /// ```
    pub async fn start_remote_listen(&self, port: u16) -> Result<()> {
        info!("Start TCP ListenmodeCapture，Port: {}", port);

       // Workers may need a runtime handle for async publishing.
        let runtime_handle = tokio::runtime::Handle::current();

       // Attach the runtime handle to the publisher clone used by workers.
        let publisher_with_handle = self.publisher.clone().with_runtime_handle(runtime_handle);

       // Start packet-processing workers before accepting connections.
        let num_workers = (num_cpus::get().saturating_sub(1)).clamp(1, max_worker_threads());
        info!("Start {} Worker thread", num_workers);

        let worker_txs = self.start_worker_pool(num_workers, publisher_with_handle)?;

       // SEC: Bind 127.0.0.1 instead of 0.0.0.0 to prevent unauthenticated remote traffic injection (CWE-306)
       // For cross-host access, use SSH tunnel forwarding (see docs)
        let bind_addr = format!("127.0.0.1:{}", port);
        let listener = TokioTcpListener::bind(&bind_addr).await?;
        warn!(
            "SEC: remote-listen mode started on {} — no authentication, \
             use only via SSH tunnel, never expose to public network",
            bind_addr
        );
        info!("waitWaitRemoteConnection...");

       // Accept each incoming stream and forward it to a blocking capture thread.
        let stats = self.stats.clone();
        let port_bitmap = self.port_bitmap.clone();
        let stop_flag = self.stop_flag.clone();
        let worker_txs = worker_txs.clone();

        tokio::spawn(async move {
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                match listener.accept().await {
                    Ok((socket, addr)) => {
                        info!("Connect受RemoteConnection: {}", addr);

                        let stats = stats.clone();
                        let port_bitmap = port_bitmap.clone();
                        let stop_flag = stop_flag.clone();
                        let worker_txs = worker_txs.clone();

                       // Convert Tokio's socket into a blocking std stream for the parser loop.
                        let std_socket = match socket.into_std() {
                            Ok(s) => s,
                            Err(e) => {
                                error!("TcpStream ConvertFailed: {}", e);
                                continue;
                            }
                        };
                        std_socket.set_nonblocking(false).ok();

                        thread::Builder::new()
                            .name(format!("tcp-capture-{}", addr))
                            .spawn(move || {
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        Self::stream_capture_loop(
                                            std_socket,
                                            worker_txs,
                                            stats,
                                            port_bitmap,
                                            stop_flag,
                                        )
                                    }));

                                match result {
                                    Ok(Ok(())) => {
                                        info!("TCP Capture threadexited normally: {}", addr)
                                    }
                                    Ok(Err(e)) => error!("TCP Capture threadError {}: {}", addr, e),
                                    Err(e) => error!(
                                        "TCP Capture thread panic {}: {:?}",
                                        addr,
                                        e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                                    ),
                                }
                            })
                            .ok();
                    }
                    Err(e) => {
                        error!("Connect受ConnectionFailed: {}", e);
                    }
                }
            }
        });

        info!("TCP ListenmodeCaptureDevice/HandleralreadyStart");
        Ok(())
    }

   /// Connect to a remote TCP endpoint that streams pcap data.
   ///
   /// This v2 mode is useful when the sniffer must pull from a remote capture
   /// relay, for example behind NAT.
   ///
   /// Pipeline:
   /// dumpcap -> tee -> FIFO -> ncat/socat TCP:5000
   /// Each client connection writes a complete pcap stream with the global
   /// header followed by packet records.
   ///
   /// Example:
   /// ```bash
   /// # Remote relay managed by `email-capture.sh`
   /// # Local client
   /// vigilyx-sniffer --remote-connect 203.0.113.10:5000
   /// ```
    pub async fn start_remote_connect(&self, host: &str, port: u16) -> Result<()> {
        info!("StartRemoteConnectionmodeCapture: {}:{}", host, port);

        let sniffer_state = crate::get_sniffer_state();
        sniffer_state.set_connecting().await;

       // Workers publish through the current Tokio runtime.
        let runtime_handle = tokio::runtime::Handle::current();

       // Rebind the publisher with that runtime handle.
        let publisher_with_handle = self.publisher.clone().with_runtime_handle(runtime_handle);

       // Start worker threads before opening the remote stream.
        let num_workers = (num_cpus::get().saturating_sub(1)).clamp(1, max_worker_threads());
        info!("Start {} Worker thread", num_workers);

        let worker_txs = self.start_worker_pool(num_workers, publisher_with_handle)?;

       // Maintain a reconnecting background task for the remote capture stream.
        let stats = self.stats.clone();
        let port_bitmap = self.port_bitmap.clone();
        let stop_flag = self.stop_flag.clone();
        let host = host.to_string();
        let worker_txs = worker_txs.clone();

        tokio::spawn(async move {
            let addr = format!("{}:{}", host, port);
            let mut retry_count = 0u32;
            let max_retry_delay = Duration::from_secs(30);

           // Update the shared sniffer-status object so the UI can reflect connection health.
            let sniffer_state = crate::get_sniffer_state();

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                info!("正在ConnectionRemoteServiceDevice/Handler: {}", addr);
                sniffer_state.set_connecting().await;

               // Bound each connection attempt so retries remain responsive.
                let connect_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await;

                match connect_result {
                    Ok(Ok(socket)) => {
                        info!(
                            "✅ SuccessConnection到RemoteServiceDevice/Handler: {}",
                            addr
                        );
                        retry_count = 0;
                        sniffer_state.set_connected().await;

                        let stats = stats.clone();
                        let port_bitmap = port_bitmap.clone();
                        let thread_stop_flag = stop_flag.clone();
                        let worker_txs = worker_txs.clone();

                       // Switch to a blocking std socket for the packet reader thread.
                        let std_socket = match socket.into_std() {
                            Ok(s) => s,
                            Err(e) => {
                                error!("TcpStream ConvertFailed: {}", e);
                                continue;
                            }
                        };
                        std_socket.set_nonblocking(false).ok();

                       // Align keepalive settings with the remote relay scripts.
                        if let Err(e) = Self::configure_socket(&std_socket) {
                            warn!("Set socket ParameterFailed (不影响Function): {}", e);
                        }

                       // Process the remote pcap stream on a dedicated blocking thread.
                        let handle = thread::Builder::new()
                            .name(format!("remote-capture-{}", addr))
                            .spawn(move || {
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        Self::stream_capture_loop(
                                            std_socket,
                                            worker_txs,
                                            stats,
                                            port_bitmap,
                                            thread_stop_flag,
                                        )
                                    }));

                                match result {
                                    Ok(Ok(())) => info!("RemoteCapture threadexited normally"),
                                    Ok(Err(e)) => warn!("RemoteCapture threadError: {}", e),
                                    Err(e) => error!(
                                        "RemoteCapture thread panic: {:?}",
                                        e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                                    ),
                                }
                            });

                        if let Ok(handle) = handle {
                            let _ = handle.join();
                        }

                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }

                        warn!("⚠️ RemoteConnectionBreak/Judge开，3秒后重连...");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Ok(Err(e)) => {
                        retry_count = retry_count.saturating_add(1);
                        let delay = Duration::from_secs((2u64).pow(retry_count.min(5)))
                            .min(max_retry_delay);
                        let error_msg = format!("ConnectionFailed: {} (retry #{})", e, retry_count);
                        error!(
                            "❌ ConnectionRemoteServiceDevice/HandlerFailed (After {} Time/Count): {}，{}seconds retry",
                            retry_count,
                            e,
                            delay.as_secs()
                        );
                        sniffer_state.set_error(&error_msg).await;
                        tokio::time::sleep(delay).await;
                    }
                    Err(_) => {
                        retry_count = retry_count.saturating_add(1);
                        let delay = Duration::from_secs((2u64).pow(retry_count.min(5)))
                            .min(max_retry_delay);
                        let error_msg =
                            format!("ConnectionTimeout (10秒) (retry #{})", retry_count);
                        error!(
                            "❌ ConnectionRemoteServiceDevice/HandlerTimeout (After {} Time/Count)，{}seconds retry",
                            retry_count,
                            delay.as_secs()
                        );
                        sniffer_state.set_error(&error_msg).await;
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        });

        info!("✅ RemoteConnectionmodeCaptureDevice/HandleralreadyStart (withAuto重连)");
        Ok(())
    }

   /// Connect to the v3 file-protocol relay with resume support.
   ///
   /// The v3 protocol carries pcapng chunks, supports resume after disconnects,
   /// and exchanges heartbeat frames.
    pub async fn start_remote_connect_v3(&self, host: &str, port: u16) -> Result<()> {
        info!("Start v3 RemoteConnectionmodeCapture: {}:{}", host, port);

        let sniffer_state = crate::get_sniffer_state();
        sniffer_state.set_connecting().await;

        let runtime_handle = tokio::runtime::Handle::current();
        let publisher_with_handle = self.publisher.clone().with_runtime_handle(runtime_handle);

        let num_workers = (num_cpus::get().saturating_sub(1)).clamp(1, max_worker_threads());
        info!("Start {} Worker thread", num_workers);

        let worker_txs = self.start_worker_pool(num_workers, publisher_with_handle)?;

        let stats = self.stats.clone();
        let port_bitmap = self.port_bitmap.clone();
        let stop_flag = self.stop_flag.clone();
        let host = host.to_string();
        let worker_txs = worker_txs.clone();

        tokio::spawn(async move {
            let addr = format!("{}:{}", host, port);
            let mut retry_count = 0u32;
            let max_retry_delay = Duration::from_secs(30);
            let sniffer_state = crate::get_sniffer_state();

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                info!("v3: 正在ConnectionRemoteServiceDevice/Handler: {}", addr);
                sniffer_state.set_connecting().await;

                let connect_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await;

                match connect_result {
                    Ok(Ok(socket)) => {
                        info!(
                            "✅ v3: SuccessConnection到RemoteServiceDevice/Handler: {}",
                            addr
                        );
                        retry_count = 0;
                        sniffer_state.set_connected().await;

                        let stats = stats.clone();
                        let port_bitmap = port_bitmap.clone();
                        let thread_stop_flag = stop_flag.clone();
                        let worker_txs = worker_txs.clone();

                        let mut std_socket = match socket.into_std() {
                            Ok(s) => s,
                            Err(e) => {
                                error!("v3: TcpStream ConvertFailed: {}", e);
                                continue;
                            }
                        };
                        std_socket.set_nonblocking(false).ok();

                        if let Err(e) = Self::configure_socket(&std_socket) {
                            warn!("Set socket ParameterFailed: {}", e);
                        }

                       // Send SUBSCRIBE RESUME
                        use std::io::Write;
                        let resume_pos = Self::load_resume_position();
                        if let Some((ref file, offset)) = resume_pos {
                            info!("v3: Send RESUME {} {}", file, offset);
                            let _ = writeln!(std_socket, "RESUME {} {}", file, offset);
                        } else {
                            info!("v3: Send SUBSCRIBE");
                            let _ = writeln!(std_socket, "SUBSCRIBE");
                        }
                        let _ = std_socket.flush();

                       // v3 ProtocolCaptureLoop
                        let handle = thread::Builder::new()
                            .name(format!("v3-capture-{}", addr))
                            .spawn(move || {
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        Self::file_protocol_capture_loop(
                                            std_socket,
                                            worker_txs,
                                            stats,
                                            port_bitmap,
                                            thread_stop_flag,
                                        )
                                    }));

                                match result {
                                    Ok(Ok((file, offset))) => {
                                        Self::save_resume_position(file.as_deref(), offset);
                                        info!("v3 Capture threadexited normally");
                                    }
                                    Ok(Err(e)) => warn!("v3 Capture threadError: {}", e),
                                    Err(e) => error!(
                                        "v3 Capture thread panic: {:?}",
                                        e.downcast_ref::<&str>().unwrap_or(&"UnknownError")
                                    ),
                                }
                            });

                        if let Ok(handle) = handle {
                            let _ = handle.join();
                        }

                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }

                        warn!("⚠️ v3 RemoteConnectionBreak/Judge开，3秒后重连...");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Ok(Err(e)) => {
                        retry_count = retry_count.saturating_add(1);
                        let delay = Duration::from_secs((2u64).pow(retry_count.min(5)))
                            .min(max_retry_delay);
                        let error_msg =
                            format!("v3 ConnectionFailed: {} (retry #{})", e, retry_count);
                        error!(
                            "❌ v3 ConnectionFailed (After {} Time/Count): {}，{}seconds retry",
                            retry_count,
                            e,
                            delay.as_secs()
                        );
                        sniffer_state.set_error(&error_msg).await;
                        tokio::time::sleep(delay).await;
                    }
                    Err(_) => {
                        retry_count = retry_count.saturating_add(1);
                        let delay = Duration::from_secs((2u64).pow(retry_count.min(5)))
                            .min(max_retry_delay);
                        let error_msg = format!("v3 ConnectionTimeout (retry #{})", retry_count);
                        error!(
                            "❌ v3 ConnectionTimeout (After {} Time/Count)，{}seconds retry",
                            retry_count,
                            delay.as_secs()
                        );
                        sniffer_state.set_error(&error_msg).await;
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        });

        info!(
            "✅ v3 RemoteConnectionmodeCaptureDevice/HandleralreadyStart (支持Break/Judge点续传)"
        );
        Ok(())
    }

   /// Configure TCP keepalive and receive buffering for relay sockets.
   ///
   /// These values are aligned with the `email-capture.sh` relay script:
   /// idle=60s, interval=10s, retries=3
    fn configure_socket(socket: &std::net::TcpStream) -> Result<()> {
        let sock_ref = SockRef::from(socket);

       // Detect dead peers within roughly 90 seconds without being too aggressive.
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10))
            .with_retries(3);
        sock_ref.set_tcp_keepalive(&keepalive)?;

       // Match the sender's large socket buffers to reduce backpressure during bursts.
        sock_ref.set_recv_buffer_size(16 * 1024 * 1024)?;

        info!("Socket alreadyConfiguration: keepalive(idle=60s,intvl=10s,cnt=3), rcvbuf=16MB");
        Ok(())
    }

    
   // Capture-loop helpers.
    

   /// Run the generic stream capture loop over standard input.
    fn stdin_capture_loop(
        worker_txs: Arc<Vec<Sender<RawpacketInfo>>>,
        stats: Arc<CaptureStats>,
        port_bitmap: Arc<PortBitmap>,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<()> {
        let stdin = io::stdin();
        let handle = stdin.lock();
        Self::stream_capture_loop(handle, worker_txs, stats, port_bitmap, stop_flag)
    }

   /// Read a classic pcap stream from any blocking reader.
    fn stream_capture_loop<R: Read>(
        reader: R,
        worker_txs: Arc<Vec<Sender<RawpacketInfo>>>,
        stats: Arc<CaptureStats>,
        port_bitmap: Arc<PortBitmap>,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<()> {
       // Use pcap FromFileDescription readGet (savefile)
       // pcap Stream: Header(24Byte) + [packetHeader(16Byte) + packetdata]*
        let mut reader = BufReader::with_capacity(1024 * 1024, reader); // 1MB bufferDistrict

       // readGet pcap Header (24 Byte)
        let mut global_header = [0u8; 24];
        reader.read_exact(&mut global_header)?;

       // Verify magic number
        let magic = u32::from_le_bytes([
            global_header[0],
            global_header[1],
            global_header[2],
            global_header[3],
        ]);
        let is_swapped = match magic {
            0xa1b2c3d4 => false, // StandardByte
            0xd4c3b2a1 => true,  // Byte
            0xa1b23c4d => false, 
            0x4d3cb2a1 => true,  // , Byte
            _ => return Err(anyhow!("Invalidof pcap magic number: 0x{:08x}", magic)),
        };

        let read_u32 = |bytes: &[u8]| -> u32 {
            if is_swapped {
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
        };

       // readGetlinkType (20)
        let linktype = read_u32(&global_header[20..24]);
        info!("pcap linkType: {} (1=Ethernet)", linktype);

        if linktype != 1 {
            warn!("非以太网linkType，possibly无法正确Parse");
        }

        let mut last_stats_time = Instant::now();
        let stats_interval = Duration::from_secs(5);
        let mut packet_header = [0u8; 16];
        let mut packet_buffer = vec![0u8; 65536]; // largepacketsize

       // counter: Batch New Variable, per-packet Operations
        let mut local_received: u64 = 0;
        let mut local_bytes: u64 = 0;
        let mut local_email: u64 = 0;
        let mut local_dropped: u64 = 0;

        info!("StartFromStreamreadGet pcap data...");

        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

           // readGetpacketHeader (16 Byte)
            match reader.read_exact(&mut packet_header) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    info!("pcap StreamEnd");
                    break;
                }
                Err(e) => {
                    error!("readGetpacketHeaderFailed: {}", e);
                    break;
                }
            }

           // Parse the pcap record header. Timestamps are reserved for future use.
            let _ts_sec = read_u32(&packet_header[0..4]);
            let _ts_usec = read_u32(&packet_header[4..8]);
            let caplen = read_u32(&packet_header[8..12]) as usize;
            let _origlen = read_u32(&packet_header[12..16]);

           // Refuse implausibly large packet records before allocating or parsing them.
            if caplen > 65536 {
                warn!("packetLengthlarge: {}, hops", caplen);
               // Drain the oversized record from the stream so parsing can continue.
                let mut remaining = caplen;
                while remaining > 0 {
                    let to_read = remaining.min(packet_buffer.len());
                    if reader.read_exact(&mut packet_buffer[..to_read]).is_err() {
                        return Ok(());
                    }
                    remaining -= to_read;
                }
                continue;
            }

           // Read the full frame payload for this packet record.
            if reader.read_exact(&mut packet_buffer[..caplen]).is_err() {
                break;
            }

           // Track counters locally and flush them to atomics in batches.
            local_received += 1;

           // ONE copy of entire frame; parse_raw_packet uses O(1) slice() internally
            let frame = Bytes::copy_from_slice(&packet_buffer[..caplen]);
            if let Some(packet_info) = packet_parser::parse_raw_packet(frame, &port_bitmap) {
                local_bytes += packet_info.payload.len() as u64;
                local_email += 1;

                trace!(
                    "emailStream量: {:?}:{} -> {:?}:{} | {} | {:?} | seq={} | flags=0x{:02x} | {} Byte",
                    packet_info.src_ip,
                    packet_info.src_port,
                    packet_info.dst_ip,
                    packet_info.dst_port,
                    packet_info.protocol,
                    packet_info.direction,
                    packet_info.tcp_seq,
                    packet_info.tcp_flags,
                    packet_info.payload.len()
                );

                match Self::dispatch_packet(worker_txs.as_slice(), packet_info) {
                    Ok(_) => {}
                    Err((worker_idx, TrySendError::Full(packet_info))) => {
                        local_dropped += 1;
                        stats
                            .worker_queue_full_drops
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            worker_id = worker_idx,
                            src_ip = %packet_info.src_ip,
                            src_port = packet_info.src_port,
                            dst_ip = %packet_info.dst_ip,
                            dst_port = packet_info.dst_port,
                            protocol = %packet_info.protocol,
                            direction = ?packet_info.direction,
                            tcp_seq = packet_info.tcp_seq,
                            tcp_flags = packet_info.tcp_flags,
                            payload_len = packet_info.payload.len(),
                            "Worker queue full; dropping packet before session assembly"
                        );
                    }
                    Err((_worker_idx, TrySendError::Disconnected(_))) => {
                        break;
                    }
                }
            }

           // Flush batched counters periodically to reduce atomic contention.
            if last_stats_time.elapsed() >= stats_interval {
               // One atomic write per batch is cheaper than one per packet.
                stats
                    .packets_received
                    .fetch_add(local_received, Ordering::Relaxed);
                stats.bytes_total.fetch_add(local_bytes, Ordering::Relaxed);
                stats
                    .packets_email
                    .fetch_add(local_email, Ordering::Relaxed);
                if local_dropped > 0 {
                    stats
                        .packets_dropped
                        .fetch_add(local_dropped, Ordering::Relaxed);
                }

                let received = stats.packets_received.load(Ordering::Relaxed);
                let processed = stats.packets_processed.load(Ordering::Relaxed);
                let dropped = stats.packets_dropped.load(Ordering::Relaxed);
                let bytes = stats.bytes_total.load(Ordering::Relaxed);

                info!(
                    "CaptureStatistics: Receive={}, Process={}, drop={}, Stream量={:.2}MB/s",
                    received,
                    processed,
                    dropped,
                    bytes as f64 / 1024.0 / 1024.0 / 5.0
                );

                stats.bytes_total.store(0, Ordering::Relaxed);
                local_received = 0;
                local_bytes = 0;
                local_email = 0;
                local_dropped = 0;
                last_stats_time = Instant::now();
            }
        }

        Ok(())
    }

   /// Capture Loop (High-performance-optimized version)
    fn capture_loop(
        device: Device,
        worker_txs: Arc<Vec<Sender<RawpacketInfo>>>,
        stats: Arc<CaptureStats>,
        config: Arc<Config>,
        port_bitmap: Arc<PortBitmap>,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<()> {
        let capture_buffer_mb = capture_buffer_size_mb();
        // SECURITY: Defensive i32 conversion — current MAX_CAPTURE_BUFFER_MB (1024) is
        // well within i32::MAX, but guard against future constant changes (CWE-190).
        let capture_buffer_bytes = i32::try_from(capture_buffer_mb * 1024 * 1024)
            .expect("capture buffer exceeds i32::MAX; MAX_CAPTURE_BUFFER_MB must be ≤ 2047");

       // OpenCapture (Performance optimizationsConfiguration)
        let mut cap = Capture::from_device(device)?
            .buffer_size(capture_buffer_bytes)
            .timeout(CAPTURE_TIMEOUT_MS) // 100ms, And CPU
            .promisc(config.sniffer_promiscuous)
            .immediate_mode(true) // immediatelymode,
            .open()?;

       // Linux Performance notes
        #[cfg(target_os = "linux")]
        {
            info!("Linux: 启用 TPACKET_V3 MemoryMappingmode");
        }

       // macOS Performance notes
        #[cfg(target_os = "macos")]
        {
            info!("macOS: Use BPF 设备Capture");
        }

       // Set BPF handler (onlyCaptureemailProtocolPort)
        let filter = bpf::build_bpf_filter(&config);
        cap.filter(&filter, true)?;
        info!("BPF 滤Device/Handler: {}", filter);

       // PerformanceConfiguration
        info!(
            "CaptureConfiguration: bufferDistrict={}MB, Timeout={}ms, Queue={}",
            capture_buffer_mb,
            CAPTURE_TIMEOUT_MS,
            WORKER_QUEUE_CAPACITY
        );

        let mut last_stats_time = Instant::now();
        let stats_interval = Duration::from_secs(5);
        let mut last_interface_counters = read_interface_counters(&config.sniffer_interface);
        let mut last_worker_queue_full_total = 0u64;

        while !stop_flag.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    debug!("Receiveddatapacket: {} Byte", packet.data.len());

                   // ONE copy of entire frame here; all subsequent slicing is O(1)
                    let frame = Bytes::copy_from_slice(packet.data);
                    if let Some(packet_info) = packet_parser::parse_packet(frame, &port_bitmap) {
                        stats
                            .bytes_total
                            .fetch_add(packet_info.payload.len() as u64, Ordering::Relaxed);
                        stats.packets_email.fetch_add(1, Ordering::Relaxed);

                        trace!(
                            "emailStream量: {}:{} -> {}:{} | {} | {:?} | seq={} | flags=0x{:02x} | {} Byte",
                            packet_info.src_ip.to_string(),
                            packet_info.src_port,
                            packet_info.dst_ip.to_string(),
                            packet_info.dst_port,
                            packet_info.protocol,
                            packet_info.direction,
                            packet_info.tcp_seq,
                            packet_info.tcp_flags,
                            packet_info.payload.len()
                        );

                        match Self::dispatch_packet(worker_txs.as_slice(), packet_info) {
                            Ok(_) => {}
                            Err((worker_idx, TrySendError::Full(packet_info))) => {
                                stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                stats
                                    .worker_queue_full_drops
                                    .fetch_add(1, Ordering::Relaxed);
                                warn!(
                                    worker_id = worker_idx,
                                    src_ip = %packet_info.src_ip,
                                    src_port = packet_info.src_port,
                                    dst_ip = %packet_info.dst_ip,
                                    dst_port = packet_info.dst_port,
                                    protocol = %packet_info.protocol,
                                    direction = ?packet_info.direction,
                                    tcp_seq = packet_info.tcp_seq,
                                    tcp_flags = packet_info.tcp_flags,
                                    payload_len = packet_info.payload.len(),
                                    "Worker queue full; dropping live-capture packet before session assembly"
                                );
                            }
                            Err((_worker_idx, TrySendError::Disconnected(_))) => {
                                break;
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                   // Normal,
                }
                Err(e) => {
                    error!("CaptureError: {}", e);
                }
            }

           // Periodic Statistics
            if last_stats_time.elapsed() >= stats_interval {
                let received = stats.packets_received.load(Ordering::Relaxed);
                let processed = stats.packets_processed.load(Ordering::Relaxed);
                let dropped = stats.packets_dropped.load(Ordering::Relaxed);
                let worker_queue_full_total =
                    stats.worker_queue_full_drops.load(Ordering::Relaxed);
                let worker_queue_full_delta = worker_queue_full_total
                    .saturating_sub(last_worker_queue_full_total);
                let bytes = stats.bytes_total.load(Ordering::Relaxed);
                let throughput_mbps = bytes as f64 / 1024.0 / 1024.0 / 5.0;
                let current_interface_counters =
                    read_interface_counters(&config.sniffer_interface);
                let interface_delta = current_interface_counters
                    .zip(last_interface_counters)
                    .map(|(current, previous)| current.diff_since(previous));

                if let Some(delta) = interface_delta {
                    let total = current_interface_counters.unwrap_or_default();
                    info!(
                        interface = %config.sniffer_interface,
                        capture_packets_total = received,
                        processed_packets_total = processed,
                        capture_drop_total = dropped,
                        worker_queue_full_total = worker_queue_full_total,
                        worker_queue_full_interval = worker_queue_full_delta,
                        iface_rx_packets_total = total.rx_packets,
                        iface_rx_packets_interval = delta.rx_packets,
                        iface_rx_dropped_total = total.rx_dropped,
                        iface_rx_dropped_interval = delta.rx_dropped,
                        iface_rx_errors_total = total.rx_errors,
                        iface_rx_errors_interval = delta.rx_errors,
                        iface_rx_missed_errors_total = total.rx_missed_errors,
                        iface_rx_missed_errors_interval = delta.rx_missed_errors,
                        throughput_mbps = throughput_mbps,
                        "Capture health snapshot"
                    );

                    if delta.rx_dropped > 0 || worker_queue_full_delta > 0 {
                        warn!(
                            interface = %config.sniffer_interface,
                            iface_rx_dropped_interval = delta.rx_dropped,
                            iface_rx_errors_interval = delta.rx_errors,
                            iface_rx_missed_errors_interval = delta.rx_missed_errors,
                            worker_queue_full_interval = worker_queue_full_delta,
                            throughput_mbps = throughput_mbps,
                            "Capture loss detected in current interval"
                        );
                    }
                } else {
                    info!(
                        interface = %config.sniffer_interface,
                        capture_packets_total = received,
                        processed_packets_total = processed,
                        capture_drop_total = dropped,
                        worker_queue_full_total = worker_queue_full_total,
                        worker_queue_full_interval = worker_queue_full_delta,
                        throughput_mbps = throughput_mbps,
                        "Capture health snapshot (NIC counters unavailable)"
                    );
                }

               // Bytecount
                stats.bytes_total.store(0, Ordering::Relaxed);
                last_interface_counters = current_interface_counters;
                last_worker_queue_full_total = worker_queue_full_total;
                last_stats_time = Instant::now();
            }
        }

        Ok(())
    }

    
   // Worker thread
    

   /// Main worker loop for packet parsing and session assembly.
   ///
   /// Performance notes:
   /// - Avoids unnecessary `session.clone()` calls via `ProcessResult`
   /// - Keeps parsed commands borrowed where possible
   /// - Reuses batch buffers instead of allocating per packet
   /// - Flushes work in batches to amortize synchronization costs
    fn worker_loop(
        worker_id: usize,
        rx: Receiver<RawpacketInfo>,
        stats: Arc<CaptureStats>,
        session_manager: Arc<ShardedSessionManager>,
        publisher: DataPublisher,
        stop_flag: Arc<AtomicBool>,
        _config: Arc<Config>,
    ) {
        let parser = ProtocolParser::new();

       // Adaptive batching balances latency at low traffic and throughput at high traffic.
        let mut batcher = AdaptiveBatcher::new(BatchConfig {
            batch_size: BATCH_SIZE,
            timeout_us: BATCH_TIMEOUT_US,
            adaptive: true,
        });

        let mut batch: SmallVec<[RawpacketInfo; BATCH_SIZE]> = SmallVec::new();
        let mut last_flush = Instant::now();
        let batch_timeout = Duration::from_micros(batcher.recommended_batch_size() as u64 * 20);

       // Double-buffer session vectors so one can be filled while the other is published.
        let mut sessions_front: Vec<vigilyx_core::EmailSession> = Vec::with_capacity(BATCH_SIZE);
        let mut sessions_back: Vec<vigilyx_core::EmailSession> = Vec::with_capacity(BATCH_SIZE);

       // Maintain local counters and publish them periodically.
        let mut local_processed: u64 = 0;

       // Only worker 0 emits HTTP pipeline stats to avoid duplicated logs.
       // Log every three minutes to keep the signal useful without creating noise.
        let mut last_http_stats_time = Instant::now();
        let http_stats_interval = Duration::from_secs(180);

        loop {
           // Check the stop flag periodically without paying the cost on every packet.
            if local_processed.is_multiple_of(1000) && stop_flag.load(Ordering::Relaxed) {
                break;
            }

           // Try non-blocking receive first, then block with 10ms timeout.
           // 100s timeout causes 10K syscalls/sec per thread when idle;
           // 10ms keeps sub-millisecond latency at <1K pps while slashing idle CPU.
            let recv_result = rx
                .try_recv()
                .or_else(|_| rx.recv_timeout(Duration::from_millis(10)));

            match recv_result {
                Ok(packet_info) => {
                    batch.push(packet_info);
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }

           // Flush either when the batch is full or when it has been waiting too long.
            let should_flush = batch.len() >= BATCH_SIZE
                || (last_flush.elapsed() >= batch_timeout && !batch.is_empty());

            if should_flush {
                let batch_count = batch.len() as u64;

               // Reuse a single timestamp per flush to avoid repeated `Instant::now()` calls.
                let now = Instant::now();
                for packet_info in batch.drain(..) {
                    local_processed += 1;

                   // Parse the protocol payload before updating session state.
                    let command = parser.parse(&packet_info.payload, packet_info.protocol);

                   // Session updates are keyed by flow and performed inside the manager.
                    match session_manager.process_packet_with_worker(
                        &packet_info,
                        command.as_deref(),
                        now,
                        Some(worker_id),
                    ) {
                        ProcessResult::Existing => {}
                        ProcessResult::New(session) => {
                            sessions_front.push(session); // Connect,
                        }
                        ProcessResult::Rejected => continue,
                    }
                }

               // Publish processed-packet counters once per flush.
                stats
                    .packets_processed
                    .fetch_add(batch_count, Ordering::Relaxed);

               // Dirty sessions changed enough that the API/UI should be notified again.
                let dirty_sessions = session_manager.take_dirty_sessions();
                if !dirty_sessions.is_empty() {
                    for ds in &dirty_sessions {
                        info!(
                            "Worker thread {} PublishdirtySession: id={} mail_from={:?} subject={:?} status={:?} packets={} bytes={} is_complete={}",
                            worker_id,
                            ds.id,
                            ds.mail_from,
                            ds.subject,
                            ds.status,
                            ds.packet_count,
                            ds.total_bytes,
                            ds.content.is_complete
                        );
                    }
                    sessions_front.extend(dirty_sessions);
                }

               // HTTP dataSecuritySession (By parse_http_data_security)
                let http_sessions = session_manager.take_http_sessions();
                if !http_sessions.is_empty() {
                    let count = http_sessions.len() as u64;
                    info!(
                        worker_id = worker_id,
                        count = count,
                        "HTTP dataSecurity: Publish {} Session到Engine",
                        count
                    );
                   // HTTP pipeline: RecordingPublishCount
                    session_manager.record_http_sessions_published(count);
                    publisher.publish_http_sessions(http_sessions);
                }

               // bufferPublish (first bufferDistrict,Avoid to_vec())
                if !sessions_front.is_empty() {
                   // bufferDistrict (O(1) Operations)
                    std::mem::swap(&mut sessions_front, &mut sessions_back);

                   // AsynchronousPublish bufferDistrict (Ownership,)
                    publisher.publish(std::mem::take(&mut sessions_back));
                }

               // Update Batchhandler
                let elapsed_ns = last_flush.elapsed().as_nanos() as u64;
                batcher.update(batch_count as usize, elapsed_ns);

                last_flush = Instant::now();

               // Dynamic BatchTimeout
                let new_batch_size = batcher.recommended_batch_size();
                if new_batch_size != BATCH_SIZE {
                    debug!(
                        "Worker thread {} Batchlargesmall调整: {} -> {}",
                        worker_id, BATCH_SIZE, new_batch_size
                    );
                }

               // HTTP pipeline PeriodicStatistics (worker 0 Output)
                if worker_id == 0 && last_http_stats_time.elapsed() >= http_stats_interval {
                    session_manager.log_smtp_pipeline_stats();
                    session_manager.log_http_pipeline_stats();
                    last_http_stats_time = Instant::now();
                }
            }
        }

       // StatisticsUpdate
        let (final_batch_size, avg_time_ns) = batcher.stats();
        stats
            .packets_processed
            .fetch_add(local_processed % 1000, Ordering::Relaxed);
        info!(
            "Worker thread {} Exit | Process: {} packet | 最终Batch: {} | 平All: {:.2}μs/packet",
            worker_id,
            local_processed,
            final_batch_size,
            avg_time_ns as f64 / 1000.0
        );
    }

    
   // v3 file-protocol helpers.
    

   /// Consume frames from the v3 file protocol and push parsed packets to workers.
    fn file_protocol_capture_loop<R: Read>(
        reader: R,
        worker_txs: Arc<Vec<Sender<RawpacketInfo>>>,
        stats: Arc<CaptureStats>,
        port_bitmap: Arc<PortBitmap>,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<(Option<String>, u64)> {
        let mut protocol_reader = FileProtocolReader::new(reader);
        let mut pcapng_parser = PcapngParser::new();
        let mut last_stats_time = Instant::now();
        let stats_interval = Duration::from_secs(5);

        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            match protocol_reader.next_frame() {
                Ok(Frame::Filedata { data, offset, .. }) => {
                   // Decode any complete pcapng packets carried by this frame.
                    let packets = pcapng_parser.parse_blocks(&data);

                    for pkt in packets {
                        stats.packets_received.fetch_add(1, Ordering::Relaxed);

                       // Zero-copy: Vec<u8> -> Bytes takes ownership, no memcpy
                        let frame = Bytes::from(pkt.data);
                        if let Some(packet_info) =
                            packet_parser::parse_raw_packet(frame, &port_bitmap)
                        {
                            stats
                                .bytes_total
                                .fetch_add(packet_info.payload.len() as u64, Ordering::Relaxed);
                            stats.packets_email.fetch_add(1, Ordering::Relaxed);

                            match Self::dispatch_packet(worker_txs.as_slice(), packet_info) {
                                Ok(_) => {}
                                Err((worker_idx, TrySendError::Full(packet_info))) => {
                                    stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                    stats
                                        .worker_queue_full_drops
                                        .fetch_add(1, Ordering::Relaxed);
                                    warn!(
                                        worker_id = worker_idx,
                                        src_ip = %packet_info.src_ip,
                                        src_port = packet_info.src_port,
                                        dst_ip = %packet_info.dst_ip,
                                        dst_port = packet_info.dst_port,
                                        protocol = %packet_info.protocol,
                                        direction = ?packet_info.direction,
                                        tcp_seq = packet_info.tcp_seq,
                                        tcp_flags = packet_info.tcp_flags,
                                        payload_len = packet_info.payload.len(),
                                        "Worker queue full; dropping file-protocol packet before session assembly"
                                    );
                                }
                                Err((_worker_idx, TrySendError::Disconnected(_))) => {
                                    info!("工作QueuealreadyBreak/Judge开");
                                    let (file, off) = protocol_reader.resume_position();
                                    return Ok((file.map(|s| s.to_string()), off));
                                }
                            }
                        }
                    }

                    debug!("v3 FILE 帧: offset={}, data_len={}", offset, data.len());
                }
                Ok(Frame::Heartbeat) => {
                    debug!("v3 HEARTBEAT");
                }
                Err(e) => {
                    warn!("v3 ProtocolreadGetError: {}", e);
                    break;
                }
            }

           // Periodic Statistics
            if last_stats_time.elapsed() >= stats_interval {
                let received = stats.packets_received.load(Ordering::Relaxed);
                let processed = stats.packets_processed.load(Ordering::Relaxed);
                let dropped = stats.packets_dropped.load(Ordering::Relaxed);

                info!(
                    "v3 CaptureStatistics: Receive={}, Process={}, drop={}",
                    received, processed, dropped
                );

                last_stats_time = Instant::now();
            }
        }

        let (file, offset) = protocol_reader.resume_position();
        Ok((file.map(|s| s.to_string()), offset))
    }

   /// Save bit File
    fn save_resume_position(file: Option<&str>, offset: u64) {
        if let Some(f) = file {
            let _ = std::fs::create_dir_all("data");
            let _ = std::fs::write("data/resume_position.txt", format!("{} {}", f, offset));
            debug!("Save消费bit点: {} offset={}", f, offset);
        }
    }

   /// Load bit
    fn load_resume_position() -> Option<(String, u64)> {
        std::fs::read_to_string("data/resume_position.txt")
            .ok()
            .and_then(|s| {
                let parts: Vec<&str> = s.trim().splitn(2, ' ').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].parse().ok()?))
                } else {
                    None
                }
            })
    }
}
