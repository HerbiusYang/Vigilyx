//! Vigilyx Web API Service

//! Features:
//! - REST API (sessions, statistics, security engine)
//! - WebSocket real-time push
//! - JWT authentication
//! - Receives engine analysis results via Redis (Engine process runs independently)

mod auth;
mod db;
mod error_codes;
mod handlers;
pub mod metrics;
mod routes;
mod state;
mod trace_id;
mod websocket;

// Re-export AppState at crate root for backward compatibility
pub use state::{AppState, CacheState, ManagerState, MessagingState, MonitoringState};

use anyhow::Result;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use futures::StreamExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, broadcast};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{Level, error, info, warn};
use vigilyx_core::{
    Config, DataSecurityIncident, SecurityVerdictSummary, TrafficStats, WsMessage,
};
use vigilyx_db::VigilDb;
use vigilyx_db::mq::{MqClient, MqConfig, topics};

use vigilyx_engine::ioc::IocManager;
use vigilyx_engine::whitelist::WhitelistManager;
use vigilyx_soar::disposition::DispositionEngine;

use crate::auth::{AuthConfig, AuthState};
use crate::db::Database;
use crate::handlers::{MtaStatus, SnifferStatus};

/// Dashboard cache background refresh task

/// Periodically calculates expensive statistics queries and caches results so API handlers can return cached data directly.
/// - External login statistics (original query ~29s) -> Refreshed every 60 seconds
/// - Traffic statistics (original query ~4.5s) -> Refreshed every 30 seconds
async fn refresh_dashboard_cache(state: Arc<AppState>) {
   // Refresh immediately on first startup (warm-up)
    info!("Dashboard cache warm-up starting...");

    loop {
       // Refresh traffic statistics (sessions COUNT)
        if let Ok(stats) = state.db.get_stats().await {
            let mut cache = state.cache.traffic_stats.write().await;
           *cache = Some((Instant::now(), stats));
        }

       // Refresh external login statistics (GROUP BY + COUNT DISTINCT + json_extract)
        if let Ok(stats) = state.db.get_external_login_stats().await {
            let mut cache = state.cache.login_stats.write().await;
           *cache = Some((Instant::now(), stats));
        }

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// SPA fallback: Requests that are not API / not static resources return index.html uniformly, handled by frontend routing
async fn spa_fallback() -> axum::response::Response {
    use axum::response::IntoResponse;
    match tokio::fs::read_to_string("frontend/dist/index.html").await {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "index.html not found",
        )
            .into_response(),
    }
}

fn validate_internal_token_scope_split() -> Result<()> {
    let internal_api_token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
    let ai_internal_token = std::env::var("AI_INTERNAL_TOKEN").unwrap_or_default();

    if !internal_api_token.is_empty()
        && !ai_internal_token.is_empty()
        && internal_api_token == ai_internal_token
    {
        anyhow::bail!(
            "AI_INTERNAL_TOKEN must differ from INTERNAL_API_TOKEN to preserve internal service boundaries"
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
   // Global panic hook: Records full stack trace before panic=abort terminates
   // eprintln is unbuffered, can write to log file even if process immediately aborts
    std::panic::set_hook(Box::new(|info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!("[PANIC] {}\n\nBacktrace:\n{}", info, backtrace);
    }));

   // Initialize logging (JSON format in production via LOG_FORMAT=json)
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_env_filter(env_filter)
            .init();
    }

    info!("Vigilyx API service starting...");
    validate_internal_token_scope_split()?;

   // Load configuration
    let config = Config::from_env()?;
    info!("Configuration loaded:");
    info!("  - API Address: {}:{}", config.api_host, config.api_port);
   // Security: Hide database password in logs
    let db_log = config.database_url.find('@').map_or_else(
        || config.database_url.clone(),
        |at| format!("postgres://***@{}", &config.database_url[at + 1..]),
    );
    info!("  - Database: {}", db_log);

   // Initialize database
    let db = Database::new(&config.database_url).await?;
    db.init().await?;
    info!("Database initialization complete");

   // Initialize security engine DB (shares same PostgreSQL database)
    let engine_db = VigilDb::new(&config.database_url).await?;
    engine_db.init_security_tables().await?;
    info!("Security engine DB initialization complete");

   // Initialize managers (lightweight DB wrappers for API CRUD)
    let ioc_manager = IocManager::new(engine_db.clone());
    let whitelist_manager = WhitelistManager::new(engine_db.clone());
    let disposition_engine = DispositionEngine::new(engine_db.clone());

   // Load whitelist cache
    if let Err(e) = whitelist_manager.load().await {
        warn!("Whitelist cache loading failed: {}", e);
    }

   // Use a bounded queue because lagged clients already fall back to a full refresh.
    let (ws_tx, _) = broadcast::channel::<WsMessage>(4_096);

   // Initialize message queue client
    let mq_config = MqConfig::from_env();
    let mq = MqClient::new(mq_config.clone());

   // Try to connect to Redis (3 second timeout)
    let mq_connected =
        match tokio::time::timeout(std::time::Duration::from_secs(3), mq.connect()).await {
            Ok(Ok(_)) => {
                info!("Redis message queue connected successfully");
                true
            }
            Ok(Err(e)) => {
                warn!("Redis connection failed: {}, will use local mode", e);
                false
            }
            Err(_) => {
                warn!("Redis connection timeout, will use local mode");
                false
            }
        };

   // Initialize authentication configuration
    let auth_config = match AuthConfig::from_env() {
        Ok(config) => {
            info!("Authentication configuration loaded successfully");
            config
        }
        Err(e) => {
            error!(
                "Auth config loading failed: {}. Set API_JWT_SECRET and API_PASSWORD in the environment. \
                 Default fallback credentials are disabled.",
                e
            );
            std::process::exit(1);
        }
    };
   // Load saved password from database (overrides env variable defaults if user changed it)
    auth_config.load_password_from_db(&engine_db).await;
    let auth_state = AuthState {
        config: Arc::new(auth_config),
       // Per-IP login rate limit: Max 10 failures within 60 second window
        login_rate_limiter: Arc::new(crate::auth::LoginRateLimiter::new(10, 60)),
    };

   // Initialize system info collector
    let mut sys = sysinfo::System::new_all();
    sys.refresh_cpu_usage();
    sys.refresh_memory();

   // Create application state
    let state = Arc::new(AppState {
        db,
        engine_db,
        config: config.clone(),
        auth: auth_state,
        messaging: MessagingState {
            ws_tx: ws_tx.clone(),
            mq: if mq_connected { Some(mq) } else { None },
        },
        managers: ManagerState {
            ioc_manager,
            whitelist_manager,
            disposition_engine,
        },
        monitoring: MonitoringState {
            sniffer_status: RwLock::new(SnifferStatus::default()),
            mta_status: RwLock::new(MtaStatus::default()),
            engine_status: RwLock::new(None),
            sys: Mutex::new(sys),
            latest_pps: std::sync::atomic::AtomicU64::new(0),
            latest_bps: std::sync::atomic::AtomicU64::new(0),
        },
        cache: CacheState {
            login_stats: RwLock::new(None),
            traffic_stats: RwLock::new(None),
        },
        ws_tickets: auth::WsTicketStore::new(),
        ws_auth_epoch: std::sync::atomic::AtomicU64::new(0),
       // SEC: add the Secure flag to cookies under HTTPS; omit it in dev HTTP mode
        secure_cookie: std::env::var("API_SECURE_COOKIE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or_else(|_| {
                // Auto-detect: default to secure when a TLS profile or reverse proxy is present
                std::env::var("CADDY_TLS_MODE").is_ok()
                    || std::env::var("API_TLS").is_ok()
            }),
       // SEC-H07: HTTP client includes AI-scoped auth token by default (for AI service proxy requests)
        http_client: {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Ok(token) = std::env::var("AI_INTERNAL_TOKEN")
                && let Ok(v) = token.parse()
            {
                headers.insert("X-Internal-Token", v);
            }
            reqwest::Client::builder()
                .default_headers(headers)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("AI internal HTTP client should build")
        },
    });

   // Start dashboard cache background refresh task
    {
        let state_bg = state.clone();
        tokio::spawn(async move {
            refresh_dashboard_cache(state_bg).await;
        });
    }

   // Per-IP login rate limiter: Clean expired entries every 5 minutes (prevents unbounded memory growth)
    {
        let limiter = state.auth.login_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                limiter.cleanup();
            }
        });
    }

   // Start Redis subscription task (with auto-reconnect)
    if mq_connected {
        let ws_tx_clone = ws_tx.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            loop {
                match subscribe_redis_messages(state_clone.clone(), ws_tx_clone.clone()).await {
                    Ok(()) => {
                        warn!("Redis subscription ended normally, reconnecting in 5 seconds...")
                    }
                    Err(e) => error!(
                        "Redis subscription failed: {}, reconnecting in 5 seconds...",
                        e
                    ),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

   // Configure CORS (read allowed origins from environment variable)
   // By default only same-origin requests allowed; set API_CORS_ORIGINS=* to allow all (not recommended)
    let cors = {
        use tower_http::cors::Any;
       // SEC-M08: Explicit allow-list for headers instead of Any (CWE-346 - Principle of least privilege)
        let base = CorsLayer::new()
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::ACCEPT,
                axum::http::HeaderName::from_static("x-internal-token"),
            ]);
        match std::env::var("API_CORS_ORIGINS") {
            Ok(origins) if origins.trim() == "*" => {
                warn!("CORS configured to allow all origins - for development environment only");
                base.allow_origin(Any)
            }
            Ok(origins) if !origins.is_empty() => {
                let allowed: Vec<_> = origins
                    .split(',')
                    .filter_map(|o| o.trim().parse().ok())
                    .collect();
                if allowed.is_empty() {
                    warn!("API_CORS_ORIGINS config invalid, rejecting all cross-origin requests");
                    base
                } else {
                    info!("CORS allowed origins: {:?}", allowed);
                    base.allow_origin(allowed)
                }
            }
            _ => {
               // Default: Reject cross-origin requests (front-end same-origin access not affected by CORS)
               // For cross-origin, please set API_CORS_ORIGINS environment variable
                info!("CORS: API_CORS_ORIGINS not configured, rejecting all cross-origin requests");
                base
            }
        }
    };

   // Security Response Headers Middleware
    use axum::http::HeaderValue;
    use tower_http::set_header::SetResponseHeaderLayer;

   // Portal mode: When PORTAL_MODE=true, accessing / redirects to /portal
    let portal_mode = std::env::var("PORTAL_MODE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

   // Build routes
   // SPA: /assets/* serves static files via ServeDir, other routes fallback to index.html (200)
    let mut app = Router::new()
        .nest("/api", routes::api_routes(state.clone()))
        .route("/ws", axum::routing::get(websocket::ws_handler))
        .nest_service("/assets", ServeDir::new("frontend/dist/assets"));

    if portal_mode {
        info!("Portal mode enabled: / -> /portal");
        app = app.route(
            "/",
            axum::routing::get(|| async { axum::response::Redirect::temporary("/portal") }),
        );
    }

    let app = app
        .fallback(spa_fallback)
       // Security response headers
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
       // SEC-H04: Content-Security-Policy (replaces deprecated X-XSS-Protection)
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; \
                 connect-src 'self' ws: wss:; \
                 font-src 'self'; \
                 object-src 'none'; \
                 base-uri 'self'; \
                 frame-ancestors 'none'; \
                 form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
       // HSTS: even if Caddy/Nginx adds this upstream, the API layer also sets it to prevent downgrade attacks
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(cors)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB
       // Prometheus metrics: Records request counts and latency per path (normalized to prevent high cardinality)
        .layer(axum::middleware::from_fn(metrics::metrics_middleware))
       // Trace ID: Outermost middleware - assigns unique trace_id per request, propagated through all log lines
       // In axum, the last.layer() added is outermost and executes first
        .layer(axum::middleware::from_fn(trace_id::trace_id_middleware))
        .with_state(state);

   // Start service
    let addr = config.api_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("API service started: http://{}", addr);
    info!("WebSocket endpoint: ws://{}/ws", addr);
    info!(
        "Note: Security analysis is performed by independent Engine process, ensure vigilyx-engine is running"
    );

   // Graceful shutdown signal: Ctrl+C (SIGINT) or SIGTERM (Docker stop)
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C (SIGINT), starting graceful shutdown...");
            }
            _ = terminate => {
                info!("Received SIGTERM, starting graceful shutdown...");
            }
        }

        info!(
            "Stop accepting new connections, waiting for in-flight requests and WebSocket connections to drain..."
        );
    };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await?;

   // Server stopped accepting new requests and drained in-flight connections
    info!("HTTP server shutdown, cleaning up resources...");

   // Notify all WebSocket subscribers: Drop original sender so receivers get closed signal
   // (Clones held by AppState and background tasks will be released when dropped)
    drop(ws_tx);
    info!("WebSocket broadcast channel closed");

    info!("Vigilyx API graceful shutdown complete");
    Ok(())
}

/// Subscribe to Redis messages and forward to WebSocket

/// Subscribe to Redis Pub/Sub channels and dispatch to WebSocket.
///
/// Subscription sources:
/// - Sniffer: real-time traffic stats (Pub/Sub, fire-and-forget)
/// - Engine: verdict/alert/ds_incident/status (Pub/Sub → WebSocket → Browser)
///
/// Note: Session data flows through Redis Streams (Sniffer → Engine),
/// not through Pub/Sub. The API receives session-related updates only
/// via Engine verdict/alert notifications after Engine processes them.
async fn subscribe_redis_messages(
    state: Arc<AppState>,
    ws_tx: broadcast::Sender<WsMessage>,
) -> Result<()> {
    let mq = state
        .messaging
        .mq
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MQ not connected"))?;

    let mut pubsub = mq
        .subscribe(&[
           // Sniffer real-time stats
            topics::STATS_UPDATE,
           // Engine analysis results
            topics::ENGINE_VERDICT,
            topics::ENGINE_ALERT,
            topics::ENGINE_DS_INCIDENT,
            topics::ENGINE_STATUS,
        ])
        .await?;

    info!("Starting Redis Pub/Sub subscription (Stats + Engine results)...");

   // Process message
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to get message content: {}", e);
                continue;
            }
        };

       // Parse message based on channel
       // DB writes are spawned asynchronously, not blocking subscription loop
        let ws_msg = match channel.as_str() {
            topics::STATS_UPDATE => {
                if let Ok(stats) = serde_json::from_str::<TrafficStats>(&payload) {
                   // Cache real-time rates pushed by sniffer for GET /api/stats
                    state.monitoring.latest_pps.store(
                        stats.packets_per_second.to_bits(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    state.monitoring.latest_bps.store(
                        stats.bytes_per_second.to_bits(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    Some(WsMessage::StatsUpdate(stats))
                } else {
                    None
                }
            }

           // Engine Analysis Results
            topics::ENGINE_VERDICT => {
                if let Ok(v) = serde_json::from_str::<SecurityVerdictSummary>(&payload) {
                   // Prometheus: Record verdict distribution
                    metrics::EMAILS_PROCESSED_TOTAL.inc();
                    metrics::VERDICTS_TOTAL
                        .with_label_values(&[&v.threat_level.to_lowercase()])
                        .inc();
                    Some(WsMessage::SecurityVerdict(v))
                } else {
                    None
                }
            }
            topics::ENGINE_ALERT => {
                if let Ok(a) = serde_json::from_str::<String>(&payload) {
                    Some(WsMessage::Alert(a))
                } else {
                    None
                }
            }
            topics::ENGINE_DS_INCIDENT => {
                if let Ok(i) = serde_json::from_str::<DataSecurityIncident>(&payload) {
                    Some(WsMessage::DataSecurityAlert(i))
                } else {
                    None
                }
            }
            topics::ENGINE_STATUS => {
               // Cache the full heartbeat envelope so readiness can inspect updated_at.
                if let Ok(status) = serde_json::from_str::<serde_json::Value>(&payload) {
                    let snapshot = if status.get("updated_at").is_some() && status.get("status").is_some() {
                        status
                    } else {
                        crate::handlers::security::wrap_engine_status_snapshot(status)
                    };
                   *state.monitoring.engine_status.write().await = Some(snapshot);
                }
                None
            }

            _ => None,
        };

       // Broadcast to WebSocket (silently skip if no subscribers)
        if let Some(msg) = ws_msg
            && ws_tx.receiver_count() > 0
        {
            let _ = ws_tx.send(msg);
        }
    }

    Ok(())
}
