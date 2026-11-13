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
mod training_redaction;
mod websocket;

// Re-export AppState at crate root for backward compatibility
pub use state::{AppState, CacheState, ManagerState, MessagingState, MonitoringState};

use anyhow::Result;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use futures::StreamExt;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, broadcast};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{Level, error, info, warn};
use uuid::Uuid;
use vigilyx_core::{Config, DataSecurityIncident, SecurityVerdictSummary, TrafficStats, WsMessage};
use vigilyx_db::VigilDb;
use vigilyx_db::cache::{CacheDataset, CacheEnvelope, CacheKey, ReadCacheClient, ReadCacheConfig};
use vigilyx_db::mq::{
    DataPayloadAuth, MqClient, MqConfig, require_data_plane_token, topics, verify_data_payload,
};

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
/// - Security overview/delivery statistics -> Warmed every 30 seconds
async fn refresh_dashboard_cache(state: Arc<AppState>) {
    // Refresh immediately on first startup (warm-up)
    info!("Dashboard cache warm-up starting...");
    let mut last_login_refresh: Option<Instant> = None;

    loop {
        // Refresh traffic statistics (sessions COUNT)
        let traffic_result = {
            let _guard = state.cache.traffic_stats_refresh_lock.lock().await;
            state.db.get_stats().await
        };
        if let Ok(stats) = traffic_result {
            let mut cache = state.cache.traffic_stats.write().await;
            *cache = Some((Instant::now(), stats.clone()));
            shadow_write_read_cache(
                &state,
                CacheDataset::SessionCounts,
                CacheKey::session_counts(),
                &stats,
            )
            .await;
        }

        // The security endpoint has its own process-local snapshot and an
        // optional distributed read cache. Warm both paths from the same
        // background task so the first dashboard visit does not pay the
        // delivery-chain aggregate cost.
        let security_result = state.engine_db.get_security_stats().await;
        match security_result {
            Ok(stats) => {
                shadow_write_read_cache(
                    &state,
                    CacheDataset::SecurityOverview24h,
                    CacheKey::security_overview(),
                    &stats,
                )
                .await;
            }
            Err(error) => warn!(%error, "Dashboard security statistics warm-up failed"),
        }

        // External login statistics scan a large, long-lived session table.
        // Keep the initial warm-up, then refresh at most once per minute;
        // otherwise the 30-second loop can continuously re-run the expensive
        // query and compete with every dashboard/list request.
        let login_due = last_login_refresh
            .is_none_or(|last_refresh| last_refresh.elapsed() >= Duration::from_secs(60));
        if login_due {
            let login_result = {
                let _guard = state.cache.login_stats_refresh_lock.lock().await;
                state.db.get_external_login_stats().await
            };
            last_login_refresh = Some(Instant::now());
            if let Ok(stats) = login_result {
                let mut cache = state.cache.login_stats.write().await;
                *cache = Some((Instant::now(), stats.clone()));
                shadow_write_read_cache(
                    &state,
                    CacheDataset::ExternalLogin24h,
                    CacheKey::external_login(),
                    &stats,
                )
                .await;
            }
        }

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Publish a background-computed aggregate to L2 when the dataset is enabled
/// for reads or shadow writes.  The distributed lease makes multiple API
/// instances share one refresh result instead of all writing the same key.
async fn shadow_write_read_cache<T: Serialize>(
    state: &AppState,
    dataset: CacheDataset,
    cache_key: CacheKey,
    data: &T,
) {
    let Some(read_cache) = state.cache.read_cache.as_ref() else {
        return;
    };
    let config = read_cache.config();
    if !(config.enabled(dataset) || config.shadow_write_enabled(dataset)) {
        return;
    }

    let token = Uuid::new_v4().to_string();
    let lease = match read_cache
        .try_acquire_refresh_lease(cache_key, &token)
        .await
    {
        Ok(true) => true,
        Ok(false) => {
            metrics::READ_CACHE_LOCK_CONTENTION_TOTAL
                .with_label_values(&[metrics::cache_dataset_label(dataset)])
                .inc();
            metrics::record_cache_request(dataset, "l2", "lease_contention");
            false
        }
        Err(error) => {
            metrics::record_cache_request(dataset, "l2", "lease_error");
            metrics::record_cache_refresh_failure(dataset, &error);
            false
        }
    };
    if !lease {
        return;
    }

    let envelope = CacheEnvelope::for_dataset(dataset, data, None);
    let refresh_started = Instant::now();
    match read_cache.set(cache_key, &envelope).await {
        Ok(payload_bytes) => {
            metrics::record_cache_request(dataset, "l2", "write");
            metrics::READ_CACHE_REFRESH_DURATION_SECONDS
                .with_label_values(&[metrics::cache_dataset_label(dataset)])
                .observe(refresh_started.elapsed().as_secs_f64());
            metrics::READ_CACHE_ENTRY_BYTES
                .with_label_values(&[metrics::cache_dataset_label(dataset)])
                .set(payload_bytes as f64);
            metrics::record_cache_observation(dataset, envelope.generated_at);
        }
        Err(error) => {
            metrics::record_cache_refresh_failure(dataset, &error);
            metrics::record_cache_fallback(dataset, metrics::cache_error_reason(&error));
            tracing::warn!(dataset = dataset.slug(), %error, "Read-cache background write failed");
        }
    }

    if let Err(error) = read_cache.release_refresh_lease(cache_key, &token).await {
        tracing::debug!(dataset = dataset.slug(), %error, "Read-cache background lease release failed");
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

/// API paths must never fall through to the SPA document.  Returning the
/// normal API envelope also keeps clients from treating an HTML success page
/// as a valid JSON response when a route is misspelled or removed.
async fn api_not_found() -> impl axum::response::IntoResponse {
    handlers::ApiResponse::<serde_json::Value>::not_found("API route not found")
}

fn validate_internal_token_scope_split() -> Result<()> {
    let internal_api_token = std::env::var("INTERNAL_API_TOKEN").unwrap_or_default();
    let sniffer_api_token = std::env::var("SNIFFER_API_TOKEN").unwrap_or_default();
    let mta_api_token = std::env::var("MTA_API_TOKEN").unwrap_or_default();
    let ai_internal_token = std::env::var("AI_INTERNAL_TOKEN").unwrap_or_default();
    let mq_auth_token = std::env::var("MQ_AUTH_TOKEN").unwrap_or_default();

    let tokens = [
        ("INTERNAL_API_TOKEN", internal_api_token),
        ("SNIFFER_API_TOKEN", sniffer_api_token),
        ("MTA_API_TOKEN", mta_api_token),
        ("AI_INTERNAL_TOKEN", ai_internal_token),
        ("MQ_AUTH_TOKEN", mq_auth_token),
    ];
    if let Some((name, _)) = tokens.iter().find(|(_, value)| value.len() < 32) {
        anyhow::bail!("{name} must contain at least 32 bytes");
    }
    let unique = tokens
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != tokens.len() {
        anyhow::bail!("Internal API, AI, and message-bus tokens must all differ");
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

    // jsonwebtoken 11: install the selected AWS-LC provider explicitly so
    // feature merging cannot leave provider selection ambiguous.
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();

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
    // Schema changes run in a short-lived one-shot container. The long-lived
    // API process never receives the PostgreSQL owner credential in its
    // environment, so an API compromise cannot recover migration authority.
    if std::env::var("VIGILYX_MIGRATE_ONLY").as_deref() == Ok("true") {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for migration mode"))?;
        let migration_db = Database::new(&database_url).await?;
        migration_db.init().await?;
        let migration_engine_db = VigilDb::new(&database_url).await?;
        migration_engine_db.init_security_tables().await?;
        info!("Database migrations completed");
        return Ok(());
    }

    // Provision the independent audit identity from a one-shot container.
    // Existing accounts are never overwritten, and the long-lived API
    // container is not given AUDIT_BOOTSTRAP_PASSWORD.
    if std::env::var("VIGILYX_PROVISION_AUDIT_ONLY").as_deref() == Ok("true") {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required for audit provisioning"))?;
        let username =
            std::env::var("AUDIT_USERNAME").unwrap_or_else(|_| "privacy-auditor".to_string());
        let password = std::env::var("AUDIT_BOOTSTRAP_PASSWORD")
            .map_err(|_| anyhow::anyhow!("AUDIT_BOOTSTRAP_PASSWORD is required"))?;
        if username.trim().is_empty()
            || username.chars().count() > 128
            || username.chars().any(char::is_control)
        {
            anyhow::bail!("AUDIT_USERNAME is invalid");
        }
        crate::auth::validate_new_password(&username, &password)
            .map_err(|error| anyhow::anyhow!("AUDIT_BOOTSTRAP_PASSWORD is invalid: {error}"))?;

        let audit_db = VigilDb::new(&database_url).await?;
        match audit_db.get_platform_auth_user(&username).await? {
            Some(existing) if existing.role_id == vigilyx_db::AUDIT_ROLE_ID => {
                info!("Independent audit identity already exists; leaving it unchanged");
            }
            Some(_) => anyhow::bail!(
                "AUDIT_USERNAME already belongs to a non-audit account; refusing role mutation"
            ),
            None => {
                let password_hash = crate::auth::hash_password(&password)
                    .map_err(|error| anyhow::anyhow!("failed to hash audit password: {error}"))?;
                audit_db
                    .create_platform_user(
                        &username,
                        "Privacy Auditor",
                        &password_hash,
                        vigilyx_db::AUDIT_ROLE_ID,
                        true,
                    )
                    .await?;
                info!("Independent audit identity provisioned; password change required");
            }
        }
        return Ok(());
    }

    vigilyx_core::validate_config_encryption_key()
        .map_err(|error| anyhow::anyhow!("configuration encryption is required: {error}"))?;

    info!("Vigilyx API service starting...");
    validate_internal_token_scope_split()?;
    require_data_plane_token()
        .map_err(|error| anyhow::anyhow!("data-plane authentication is required: {error}"))?;

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

    let db = Database::new(&config.database_url).await?;
    info!("Database initialization complete");

    // Runtime security DB uses the same least-privilege API role.
    let engine_db = VigilDb::new(&config.database_url).await?;
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

    // The read cache is an optional operational dependency. Invalid or
    // unavailable cache configuration must degrade to PostgreSQL and must not
    // prevent API startup or affect the message bus.
    let read_cache = match ReadCacheConfig::from_env() {
        Ok(cache_config) => {
            info!(config = ?cache_config, "Read-cache configuration loaded");
            if cache_config.should_initialize() {
                Some(ReadCacheClient::new(cache_config))
            } else {
                None
            }
        }
        Err(error) => {
            warn!(%error, "Read-cache configuration invalid; cache disabled, using PostgreSQL");
            None
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
    let bootstrap_hash = auth_config.password_hash.read().await.clone();
    let bootstrap_must_change = !*auth_config.password_changed.read().await;
    if let Err(error) = engine_db
        .ensure_platform_admin(
            &auth_config.username,
            &bootstrap_hash,
            bootstrap_must_change,
        )
        .await
    {
        error!(error = %error, "Platform RBAC bootstrap failed");
        std::process::exit(1);
    }
    info!("Platform RBAC bootstrap complete");
    let auth_state = AuthState {
        config: Arc::new(auth_config),
        // IP + account login rate limit: max 10 IP failures or 30 account
        // failures within the 60-second window.
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
            traffic_stats_refresh_lock: Mutex::new(()),
            login_stats_refresh_lock: Mutex::new(()),
            read_cache: read_cache.clone(),
        },
        ws_tickets: auth::WsTicketStore::new(),
        ws_auth_epoch: std::sync::atomic::AtomicU64::new(0),
        ws_user_epochs: dashmap::DashMap::new(),
        // SEC: add the Secure flag to cookies under HTTPS; omit it in dev HTTP mode
        secure_cookie: std::env::var("API_SECURE_COOKIE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or_else(|_| {
                // Auto-detect: default to secure when a TLS profile or reverse proxy is present
                std::env::var("CADDY_TLS_MODE").is_ok() || std::env::var("API_TLS").is_ok()
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

    // Warm the optional L2 cache connection without making it part of API
    // readiness. A stopped/slow cache is observable but harmless.
    if let Some(read_cache) = read_cache {
        tokio::spawn(async move {
            if let Err(error) = read_cache.warm_up().await {
                warn!(%error, "Read-cache warm-up failed; PostgreSQL fallback remains active");
            }
        });
    }

    // Start dashboard cache background refresh task
    {
        let state_bg = state.clone();
        tokio::spawn(async move {
            refresh_dashboard_cache(state_bg).await;
        });
    }

    // Login rate limiter: clean expired IP/account entries every 5 minutes.
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

    // Build routes.  The API has its own 404 fallback so an unknown /api/*
    // request cannot be mistaken for a frontend route and receive index.html.
    let api_app = routes::api_routes(state.clone()).fallback(api_not_found);

    // SPA: /assets/* serves static files via ServeDir, other non-API routes
    // fallback to index.html (200) for client-side routing.
    let mut app = Router::new()
        .nest("/api", api_app)
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
        // Prometheus metrics: Records request counts and latency per route template (SEC-03: MatchedPath labels keep cardinality bounded)
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

    // SEC (C1/M-2): data-plane payloads carry a v1 HMAC envelope. Startup
    // already fails without the shared token; keep the local copy stable for
    // the lifetime of this subscription loop.
    let data_token = require_data_plane_token()
        .map_err(|error| anyhow::anyhow!("data-plane authentication is required: {error}"))?;

    // Process message
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let raw_payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to get message content: {}", e);
                continue;
            }
        };

        // SEC (C1/M-2): verify and unwrap the data-plane auth envelope before
        // touching the payload; forged messages never reach WebSocket clients.
        let payload = match verify_data_payload(&raw_payload, &data_token) {
            DataPayloadAuth::Verified(json) => json,
            DataPayloadAuth::Rejected => {
                warn!(
                    channel,
                    "Rejected data-plane message with invalid auth token (possible forgery)"
                );
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
                    // Prometheus: Record verdict distribution. The threat level
                    // arrives over the message bus as an unconstrained string;
                    // map it through a fixed whitelist so a forged verdict
                    // cannot mint unbounded label combinations (C2, SEC-03
                    // class memory DoS).
                    metrics::EMAILS_PROCESSED_TOTAL.inc();
                    metrics::VERDICTS_TOTAL
                        .with_label_values(&[verdict_level_label(&v.threat_level)])
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
                    Some(WsMessage::DataSecurityAlert(redact_ws_incident(i)))
                } else {
                    None
                }
            }
            topics::ENGINE_STATUS => {
                // Cache the full heartbeat envelope so readiness can inspect updated_at.
                if let Ok(status) = serde_json::from_str::<serde_json::Value>(&payload) {
                    let snapshot =
                        if status.get("updated_at").is_some() && status.get("status").is_some() {
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

/// Map a verdict threat level to a fixed Prometheus label value.
///
/// `SecurityVerdictSummary.threat_level` is an unconstrained String arriving
/// over the message bus; using it directly as a label value would let every
/// forged verdict mint a new label combination (unbounded cardinality →
/// memory DoS, C2 / SEC-03 class). Unknown values collapse to `unknown`.
fn verdict_level_label(threat_level: &str) -> &'static str {
    match threat_level.to_ascii_lowercase().as_str() {
        "safe" => "safe",
        "low" => "low",
        "medium" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "unknown",
    }
}

fn redact_ws_incident(mut incident: DataSecurityIncident) -> DataSecurityIncident {
    incident.evidence.clear();
    incident.details = None;
    incident.detected_user = None;
    incident
}

#[cfg(test)]
mod tests {
    use super::{api_not_found, spa_fallback, verdict_level_label};

    #[test]
    fn verdict_level_label_accepts_known_levels_case_insensitively() {
        assert_eq!(verdict_level_label("safe"), "safe");
        assert_eq!(verdict_level_label("Low"), "low");
        assert_eq!(verdict_level_label("MEDIUM"), "medium");
        assert_eq!(verdict_level_label("High"), "high");
        assert_eq!(verdict_level_label("CRITICAL"), "critical");
    }

    #[test]
    fn verdict_level_label_collapses_forged_values_to_unknown() {
        // PoC (C2): each forged verdict with a random level used to create a
        // permanent new Prometheus label combination → unbounded memory DoS.
        for forged in [
            "critical-0x7f3a9b2c",
            "../../etc/passwd",
            "高危",
            "",
            "safe'; DROP TABLE--",
        ] {
            assert_eq!(verdict_level_label(forged), "unknown");
        }
    }

    #[tokio::test]
    async fn unknown_api_paths_return_404_instead_of_spa_html() {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        let api_app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .fallback(api_not_found);
        let app = Router::new().nest("/api", api_app).fallback(spa_fallback);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
    }
}
