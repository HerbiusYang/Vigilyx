//! Data publish handler (Redis MQ / HTTP mode)
//!
//! Email sessions and HTTP sessions are published with queue capacity limits
//! to prevent OOM when the consumer (Engine) is slower than the producer (Sniffer).
//!
//! Migration note (P0-3): Redis Streams are the primary durable transport.
//! Pub/Sub is kept as a shadow write during the migration period.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};
use vigilyx_core::{EmailSession, HttpSession};
use vigilyx_db::mq::{MqClient, StreamClient, streams};

/// emailSessionPublishQueue largeCapacity (Prevent OOM)
///
/// When Engine Processslower than Sniffer packet, WaitPublishofemailSession
/// tokio QueueMedium. hopsPublish Alert.
const MAX_EMAIL_PUBLISH_QUEUE: u64 = 50_000;

/// dataPublishhandler - MQ HTTP mode
#[derive(Clone)]
pub struct DataPublisher {
   /// PublishMode
    mode: PublishMode,
   /// Tokio Runtimehandle (Used for Tokio ThreadFound in)
    runtime_handle: Option<tokio::runtime::Handle>,
   /// emailSessionWaitPublishcount ()
    email_pending: Arc<AtomicU64>,
   /// due toQueuefull dropofemailSessioncount (Monitor)
    email_dropped: Arc<AtomicU64>,
}

#[derive(Clone)]
pub enum PublishMode {
    /// Redis Streams (primary) + Pub/Sub (shadow, migration period)
    Mq {
        mq: Arc<MqClient>,
        stream: Arc<StreamClient>,
    },
    /// HTTP API (legacy fallback when Redis unavailable)
    Http {
        client: Arc<reqwest::Client>,
        api_url: String,
    },
    /// No-op (disabled)
    #[allow(dead_code)]
    None,
}

impl DataPublisher {
   /// CreateNewofPublishhandler
    pub fn new(mode: PublishMode) -> Self {
       // GetWhenfirstRuntimehandle
        let runtime_handle = tokio::runtime::Handle::try_current().ok();
        Self {
            mode,
            runtime_handle,
            email_pending: Arc::new(AtomicU64::new(0)),
            email_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

   /// SetRuntimehandle (Used for Tokio ContextMediuminitialize givingWorker thread)
    pub fn with_runtime_handle(mut self, handle: tokio::runtime::Handle) -> Self {
        self.runtime_handle = Some(handle);
        self
    }

   /// Getdue toQueuefull dropofemailSessiontotal (Monitor, giving Prometheus)
    #[allow(dead_code)]
    pub fn email_sessions_dropped(&self) -> u64 {
        self.email_dropped.load(Ordering::Relaxed)
    }

   /// GetWhenfirstWaitPublishofemailSession (Monitor, giving Prometheus)
    #[allow(dead_code)]
    pub fn email_pending_count(&self) -> u64 {
        self.email_pending.load(Ordering::Relaxed)
    }

   /// BatchPublishSession
   /// Note: Methodpossibly Tokio ThreadMedium,UsestoreofRuntimehandle
    pub fn publish(&self, sessions: Vec<EmailSession>) {
        if sessions.is_empty() {
            return;
        }

        let session_count = sessions.len() as u64;

       // Check: preventconsumer (Engine) slower thanproducer tokio Queueinfinite growth
        let pending = self.email_pending.load(Ordering::Relaxed);
        if pending >= MAX_EMAIL_PUBLISH_QUEUE {
            self.email_dropped
                .fetch_add(session_count, Ordering::Relaxed);
            warn!(
                pending = pending,
                capacity = MAX_EMAIL_PUBLISH_QUEUE,
                dropped = session_count,
                total_dropped = self.email_dropped.load(Ordering::Relaxed),
                "emailSessionPublishdrop! WaitPublishQueuealreadyfull (Engine 载)"
            );
            return;
        }

       // UsestoreofRuntimehandle, GetWhenfirstof
        let handle = match &self.runtime_handle {
            Some(h) => h.clone(),
            None => match tokio::runtime::Handle::try_current() {
                Ok(h) => h,
                Err(_) => {
                    debug!("无法Get Tokio Runtime，hopsPublish");
                    return;
                }
            },
        };

       // AddWaitPublishcount
        self.email_pending
            .fetch_add(session_count, Ordering::Relaxed);
        let pending_counter = self.email_pending.clone();

        match &self.mode {
            PublishMode::Mq { mq, stream } => {
                let mq = mq.clone();
                let stream_client = stream.clone();
                handle.spawn(async move {
                    // Primary: Redis Streams (durable, at-least-once)
                    if let Err(e) = stream_client
                        .xadd_batch(streams::EMAIL_SESSIONS, &sessions)
                        .await
                    {
                        warn!(
                            count = sessions.len(),
                            "Stream XADD email sessions failed: {}", e
                        );
                    }
                    // Shadow: Pub/Sub (migration period, remove after Engine migrates)
                    if let Err(e) = mq.publish_sessions_batch(&sessions).await {
                        // Non-fatal: Stream write is the primary path
                        debug!(
                            count = sessions.len(),
                            "Pub/Sub shadow publish failed (non-fatal): {}", e
                        );
                    }
                    let _ =
                        pending_counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(session_count))
                        });
                });
            }
            PublishMode::Http { client, api_url } => {
                let client = client.clone();
                let api_url = api_url.clone();
                handle.spawn(async move {
                    let url = format!("{}/api/import/sessions", api_url);
                    if let Err(e) = client.post(&url).json(&sessions).send().await {
                        debug!("HTTP PublishSessionFailed: {}", e);
                    }
                   // Publishcomplete, WaitPublishcount
                    let _ =
                        pending_counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(session_count))
                        });
                });
            }
            PublishMode::None => {
               // Publish, Process - immediatelyFreeWaitPublishcount
                let _ =
                    self.email_pending
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(session_count))
                        });
            }
        }
    }

   /// Publish HTTP Session data security engine (HTTP mode)
    pub fn publish_http_sessions(&self, sessions: Vec<HttpSession>) {
        if sessions.is_empty() {
            return;
        }

        let session_count = sessions.len();

        let handle = match &self.runtime_handle {
            Some(h) => h.clone(),
            None => match tokio::runtime::Handle::try_current() {
                Ok(h) => h,
                Err(_) => {
                    warn!(
                        count = session_count,
                        "HTTP dataSecuritySessionPublishFailed: 无法Get Tokio Runtimehandle，{} Session丢失!",
                        session_count
                    );
                    return;
                }
            },
        };

        match &self.mode {
            PublishMode::Http { client, api_url } => {
                let client = client.clone();
                let api_url = api_url.clone();
                handle.spawn(async move {
                    let url = format!("{}/api/data-security/import/http-sessions", api_url);
                   // SEC: Chunk into batches of 50 to avoid hitting API body size limit (CWE-400)
                   // Without chunking, a large batch triggers 413 and entire payload is lost.
                    const CHUNK_SIZE: usize = 50;
                    for chunk in sessions.chunks(CHUNK_SIZE) {
                        let mut attempts = 0u32;
                        loop {
                            attempts += 1;
                            match client.post(&url).json(&chunk).send().await {
                                Ok(resp) if resp.status().is_success() => break,
                                Ok(resp) => {
                                    warn!(
                                        count = chunk.len(),
                                        status = %resp.status(),
                                        attempt = attempts,
                                        "HTTP data-security session publish failed"
                                    );
                                    if attempts >= 2 {
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                }
                                Err(e) => {
                                    warn!(
                                        count = chunk.len(),
                                        error = %e,
                                        attempt = attempts,
                                        "HTTP data-security session publish network error"
                                    );
                                    if attempts >= 2 {
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                }
                            }
                        }
                    }
                });
            }
            PublishMode::Mq { mq, stream } => {
                let mq = mq.clone();
                let stream_client = stream.clone();
                handle.spawn(async move {
                    // Primary: Redis Streams
                    if let Err(e) = stream_client
                        .xadd_batch(streams::HTTP_SESSIONS, &sessions)
                        .await
                    {
                        warn!(
                            count = session_count,
                            error = %e,
                            "Stream XADD HTTP sessions failed: {} sessions lost!",
                            session_count
                        );
                    }
                    // Shadow: Pub/Sub (migration period)
                    if let Err(e) = mq.publish("vigilyx:http_session:new", &sessions).await {
                        debug!(
                            count = session_count,
                            error = %e,
                            "Pub/Sub shadow HTTP session publish failed (non-fatal)"
                        );
                    }
                });
            }
            PublishMode::None => {}
        }
    }
}
