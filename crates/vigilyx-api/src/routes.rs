//! API routes
//!
//! Routes organized by authentication requirement:
//!
//! Public routes (no authentication):
//! - /api/health — Health check (liveness)
//! - /api/health/live — K8s liveness probe
//! - /api/health/ready — K8s readiness probe (DB/Redis/Engine)
//! - /api/metrics — Prometheus metrics (INTERNAL_API_TOKEN)
//! - /api/auth/login — Login
//!
//! JWT-authenticated routes:
//! - /api/auth/* — Password change, WebSocket ticket
//! - /api/sessions/* — Session queries
//! - /api/stats/* — Statistics
//! - /api/system/* — System status
//! - /api/database/* — Database management
//! - /api/config/* — Configuration (sniffer, syslog, time policy, etc.)
//! - /api/config/setup-status — Initial setup status
//! - /api/audit/* — Audit logs, login history
//! - /api/security/* — Security engine (pipeline, IOC, whitelist, alerts, etc.)
//! - /api/admin/nlp/* — NLP model management
//! - /api/data-security/* — Data security (HTTP session analysis)
//!
//! Internal service routes (INTERNAL_API_TOKEN authentication):
//! - /api/system/sniffer — Sniffer status update
//! - /api/import/* — Data import
//! - /api/internal/* — Internal component queries

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware,
    response::IntoResponse,
    routing::{MethodRouter, delete, get, post, put},
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use crate::AppState;
use crate::auth::{
    ChangePasswordRequest, ChangePasswordResponse, LoginRequest, build_token_cookie,
    handle_change_password, handle_login, handle_logout, handle_me, require_admin, require_auth,
    require_internal_token, sanitize_login_username,
};
use crate::handlers;
use crate::handlers::data_security as data_security_handlers;
use crate::handlers::ioc_handlers;
use crate::handlers::security as security_handlers;
use crate::handlers::syslog_config as syslog_handlers;
use crate::handlers::training as training_handlers;
use crate::handlers::yara as yara_handlers;
use vigilyx_core::is_sensitive_ip;

/// Extract client IP from direct connection.

/// SEC-H02: X-Forwarded-For is NOT trusted unless the direct connection comes from
/// a known reverse proxy (configured via `TRUSTED_PROXY_IPS` / `TRUSTED_PROXY_HOSTS`).
/// Without a trusted proxy, XFF is trivially spoofable and would bypass per-IP
/// rate limiting (CWE-348).
const DEFAULT_TRUSTED_PROXY_HOSTS: &[&str] = &[
    "localhost",
    "host.docker.internal",
    "caddy",
    "vigilyx-caddy",
];

fn admin_only<S>(router: MethodRouter<S>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(middleware::from_fn(require_admin))
}

fn build_trusted_proxy_ips(
    configured_ips: Option<&str>,
    configured_hosts: Option<&str>,
) -> HashSet<IpAddr> {
    let mut trusted = HashSet::from([
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]);

    if let Some(raw_ips) = configured_ips
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        for entry in raw_ips
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            match entry.parse::<IpAddr>() {
                Ok(ip) => {
                    trusted.insert(ip);
                }
                Err(error) => {
                    tracing::warn!(
                        proxy_ip = entry,
                        error = %error,
                        "TRUSTED_PROXY_IPS: 无法解析条目"
                    );
                }
            }
        }
    }

    let configured_hosts = configured_hosts
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (hosts, defaults_only): (Vec<&str>, bool) = match configured_hosts {
        Some(raw_hosts) => (
            raw_hosts
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect(),
            false,
        ),
        None => (DEFAULT_TRUSTED_PROXY_HOSTS.to_vec(), true),
    };

    for host in hosts {
        match (host, 0).to_socket_addrs() {
            Ok(addresses) => {
                let mut resolved_any = false;
                for address in addresses {
                    resolved_any = true;
                    trusted.insert(address.ip());
                }
                if !resolved_any && !defaults_only {
                    tracing::warn!(
                        proxy_host = host,
                        "TRUSTED_PROXY_HOSTS: 条目未解析出任何 IP"
                    );
                }
            }
            Err(error) => {
                if defaults_only {
                    tracing::debug!(
                        proxy_host = host,
                        error = %error,
                        "默认可信代理主机未解析，已跳过"
                    );
                } else {
                    tracing::warn!(
                        proxy_host = host,
                        error = %error,
                        "TRUSTED_PROXY_HOSTS: 无法解析条目"
                    );
                }
            }
        }
    }

    trusted
}

fn trusted_proxy_ips() -> &'static HashSet<IpAddr> {
    static TRUSTED_PROXIES: std::sync::LazyLock<HashSet<IpAddr>> = std::sync::LazyLock::new(|| {
        let configured_ips = std::env::var("TRUSTED_PROXY_IPS").ok();
        let configured_hosts = std::env::var("TRUSTED_PROXY_HOSTS").ok();
        build_trusted_proxy_ips(configured_ips.as_deref(), configured_hosts.as_deref())
    });

    &TRUSTED_PROXIES
}

fn extract_client_ip_with_trusted(
    headers: &axum::http::HeaderMap,
    direct_addr: SocketAddr,
    trusted_proxies: &HashSet<IpAddr>,
) -> IpAddr {
    if trusted_proxies.contains(&direct_addr.ip())
        && let Some(client_ip) = extract_forwarded_client_ip(headers, trusted_proxies)
    {
        return client_ip;
    }

    direct_addr.ip()
}

fn extract_forwarded_client_ip(
    headers: &axum::http::HeaderMap,
    trusted_proxies: &HashSet<IpAddr>,
) -> Option<IpAddr> {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())?;

    let forwarded_ips: Vec<IpAddr> = xff
        .split(',')
        .map(str::trim)
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .collect();

    let mut non_trusted = forwarded_ips
        .into_iter()
        .filter(|ip| !trusted_proxies.contains(ip));
    let client_ip = non_trusted.next()?;

    if let Some(extra_hop) = non_trusted.next() {
        tracing::warn!(
            x_forwarded_for = xff,
            candidate_client_ip = %client_ip,
            extra_untrusted_hop = %extra_hop,
            "Ignoring ambiguous X-Forwarded-For chain from trusted proxy"
        );
        return None;
    }

    Some(client_ip)
}

pub(crate) fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    direct_addr: SocketAddr,
) -> IpAddr {
    extract_client_ip_with_trusted(headers, direct_addr, trusted_proxy_ips())
}

pub(crate) fn request_originates_from_internal_network(
    headers: &axum::http::HeaderMap,
    direct_addr: SocketAddr,
) -> bool {
    let trusted_proxies = trusted_proxy_ips();
    let client_ip = if trusted_proxies.contains(&direct_addr.ip()) {
        extract_forwarded_client_ip(headers, trusted_proxies)
    } else {
        Some(direct_addr.ip())
    };

    client_ip.is_some_and(is_sensitive_ip)
}

fn forwarded_proto(headers: &axum::http::HeaderMap) -> Option<&str> {
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(proto);
    }

    headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|entry| {
                entry.split(';').find_map(|part| {
                    let (key, value) = part.split_once('=')?;
                    if !key.trim().eq_ignore_ascii_case("proto") {
                        return None;
                    }
                    Some(value.trim().trim_matches('"'))
                })
            })
        })
        .filter(|value| !value.is_empty())
}

pub(crate) fn request_is_secure(
    headers: &axum::http::HeaderMap,
    direct_addr: SocketAddr,
    default_secure: bool,
) -> bool {
    if trusted_proxy_ips().contains(&direct_addr.ip())
        && let Some(proto) = forwarded_proto(headers)
    {
        return proto.eq_ignore_ascii_case("https");
    }

    default_secure
}

pub(crate) fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Login handler (per-IP rate limiting + audit logging)
/// SEC: set the HttpOnly JWT cookie via Set-Cookie when login succeeds.
async fn login(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<LoginRequest>,
) -> axum::response::Response {
    let client_ip = extract_client_ip(&headers, addr);
    let ip = client_ip.to_string();
    let secure_cookie = request_is_secure(&headers, addr, state.secure_cookie);
    let response = handle_login(
        &state.auth.config,
        &state.auth.login_rate_limiter,
        client_ip,
        &request,
    )
    .await;

    // Record login attempt (success or failure)
    let db = state.engine_db.clone();
    let username = sanitize_login_username(&request.username);
    let success = response.success;
    let reason = response.error.clone();
    let ip_clone = ip.clone();
    tokio::spawn(async move {
        if let Err(e) = db
            .record_login(&username, success, Some(&ip_clone), reason.as_deref())
            .await
        {
            tracing::error!(username = %username, error = %e, "审计: 登录记录写入失败");
        }
        if success
            && let Err(e) = db
                .write_audit_log(&username, "login", None, None, None, Some(&ip_clone))
                .await
        {
            tracing::error!(username = %username, error = %e, "审计: 登录审计日志写入失败");
        }
    });

    // Set the HttpOnly cookie on successful login; the JWT stays server-side and is not serialized into the JSON body.
    if let Some(ref token) = response.token {
        let cookie_val =
            build_token_cookie(token, state.auth.config.token_expire_secs, secure_cookie);
        let mut resp_headers = axum::http::HeaderMap::new();
        if let Ok(val) = cookie_val.parse() {
            resp_headers.insert(axum::http::header::SET_COOKIE, val);
        }
        (resp_headers, Json(response)).into_response()
    } else {
        Json(response).into_response()
    }
}

/// SEC-H02: Issue one-time WebSocket ticket (avoids JWT in URL)
async fn ws_ticket(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthenticatedUser,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let client_ip = extract_client_ip(&headers, addr);
    let user_agent = extract_user_agent(&headers);

    match state
        .ws_tickets
        .issue(&user.username, client_ip, user_agent.as_deref())
    {
        Some(ticket) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "ticket": ticket })),
        )
            .into_response(),
        None => {
            // SEC-M12: Rate limited, return 429
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "票据服务繁忙，请稍后重试"
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/auth/me - return the currently authenticated user (used for cookie-session validation).
async fn me(user: crate::auth::AuthenticatedUser) -> impl IntoResponse {
    handle_me(user).await
}

/// POST /api/auth/logout - revoke existing JWTs and clear the HttpOnly cookie.
async fn logout(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    user: crate::auth::AuthenticatedUser,
) -> axum::response::Response {
    // JWTs are also accepted via Authorization headers, so logout must revoke
    // the current token generation, not just clear the browser cookie.
    let new_token_version = match state.engine_db.bump_auth_token_version().await {
        Ok(version) => version,
        Err(e) => {
            return crate::handlers::ApiResponse::<serde_json::Value>::server_error(
                &e,
                "Failed to revoke auth tokens during logout",
            )
            .into_response();
        }
    };

    state
        .auth
        .config
        .token_version
        .store(new_token_version, std::sync::atomic::Ordering::Relaxed);
    state.ws_tickets.clear();
    crate::websocket::invalidate_websocket_sessions(&state);

    let db = state.engine_db.clone();
    let username = user.username;
    tokio::spawn(async move {
        if let Err(e) = db
            .write_audit_log(&username, "logout", Some("auth"), None, None, None)
            .await
        {
            tracing::error!(error = %e, "审计: 登出审计日志写入失败");
        }
    });

    let secure_cookie = request_is_secure(&headers, addr, state.secure_cookie);
    handle_logout(secure_cookie).await.into_response()
}

/// Change password (with audit logging)
/// SEC-M04: Extract username from JWT for audit trail (CWE-862)
async fn change_password(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthenticatedUser,
    Json(request): Json<ChangePasswordRequest>,
) -> Json<ChangePasswordResponse> {
    let response = handle_change_password(&state.auth.config, &state.engine_db, &request).await;

    if response.success {
        state.ws_tickets.clear();
        crate::websocket::invalidate_websocket_sessions(&state);

        let db = state.engine_db.clone();
        let username = user.username.clone();
        tokio::spawn(async move {
            if let Err(e) = db
                .write_audit_log(&username, "change_password", Some("auth"), None, None, None)
                .await
            {
                tracing::error!(error = %e, "审计: 密码修改审计日志写入失败");
            }
        });
    }

    Json(response)
}

/// Build API routes
pub fn api_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Public routes (no authentication)
    let public_routes = Router::new()
        // Health checks (K8s probes)
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::health::liveness))
        .route("/health/ready", get(handlers::health::public_readiness))
        // Login
        .route(
            "/auth/login",
            post(login).layer(DefaultBodyLimit::max(8 * 1024)),
        );

    // Protected routes (JWT authentication)
    let protected_routes = Router::new()
        // Session info (cookie-auth validation)
        .route("/auth/me", get(me))
        // Logout (clear the HttpOnly cookie)
        .route("/auth/logout", post(logout))
        // Password change (authenticated)
        .route("/auth/change-password", post(change_password))
        // SEC-H02: WebSocket ticket (authenticated)
        .route("/auth/ws-ticket", post(ws_ticket))
        // Sessions
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/{id}", get(handlers::get_session))
        .route("/sessions/{id}/eml", get(handlers::download_eml))
        .route(
            "/sessions/{id}/related",
            get(handlers::get_related_sessions),
        )
        // Session security verdict
        .route(
            "/sessions/{id}/verdict",
            get(security_handlers::get_session_verdict),
        )
        .route(
            "/sessions/{id}/security-results",
            get(security_handlers::get_session_security_results),
        )
        // Rescan session
        .route(
            "/sessions/{id}/rescan",
            admin_only(post(security_handlers::rescan_session)),
        )
        // Session feedback
        .route(
            "/sessions/{id}/feedback",
            post(security_handlers::submit_feedback),
        )
        // Statistics
        .route("/stats", get(handlers::get_stats))
        .route(
            "/stats/external-logins",
            get(handlers::get_external_login_stats),
        )
        // System status
        .route("/system/status", get(handlers::get_system_status))
        .route("/system/metrics", get(handlers::get_system_metrics))
        .route("/system/interfaces", get(handlers::get_host_interfaces))
        // Database management
        .route(
            "/database/rotate-config",
            admin_only(get(handlers::get_rotate_config).put(handlers::update_rotate_config)),
        )
        .route(
            "/database/clear",
            admin_only(delete(handlers::clear_database)),
        )
        .route(
            "/database/factory-reset",
            admin_only(post(handlers::factory_reset)),
        )
        .route(
            "/database/precise-clear",
            admin_only(post(handlers::precise_clear)),
        )
        // Audit logs and login history
        .route("/audit/logs", admin_only(get(handlers::list_audit_logs)))
        .route(
            "/audit/login-history",
            admin_only(get(handlers::list_login_history)),
        )
        // Syslog Configuration
        .route(
            "/config/syslog",
            admin_only(
                get(syslog_handlers::get_syslog_config).put(syslog_handlers::update_syslog_config),
            ),
        )
        .route(
            "/config/syslog/test",
            admin_only(post(syslog_handlers::test_syslog_connection)),
        )
        // Comment retained in English.
        .route(
            "/config/setup-status",
            admin_only(get(handlers::get_setup_status).put(handlers::update_setup_status)),
        )
        .route("/config/ui-preferences", get(handlers::get_ui_preferences))
        .route(
            "/config/ui-preferences",
            put(handlers::update_ui_preferences),
        )
        // Deployment mode (mirror / mta)
        .route(
            "/config/deployment-mode",
            admin_only(get(handlers::get_deployment_mode).put(handlers::update_deployment_mode)),
        )
        // Sniffer / data security configuration (webmail_servers, http_ports)
        .route(
            "/config/sniffer",
            admin_only(
                get(security_handlers::get_sniffer_config)
                    .put(security_handlers::update_sniffer_config),
            ),
        )
        // Time policy configuration
        .route(
            "/config/time-policy",
            admin_only(
                get(security_handlers::get_time_policy_config)
                    .put(security_handlers::update_time_policy_config),
            ),
        );

    // Security engine API
    let security_routes = Router::new()
        // Pipeline configuration
        .route(
            "/security/pipeline",
            admin_only(
                get(security_handlers::get_pipeline_config)
                    .put(security_handlers::update_pipeline_config),
            ),
        )
        // Module metadata
        .route(
            "/security/modules",
            get(security_handlers::get_modules_metadata),
        )
        // IOC
        .route(
            "/security/ioc",
            admin_only(get(ioc_handlers::list_ioc).post(ioc_handlers::add_ioc)),
        )
        .route(
            "/security/ioc/{id}",
            admin_only(delete(ioc_handlers::delete_ioc)),
        )
        .route(
            "/security/ioc/{id}/extend",
            admin_only(put(ioc_handlers::extend_ioc)),
        )
        .route(
            "/security/ioc/import",
            admin_only(post(ioc_handlers::import_ioc)),
        )
        .route(
            "/security/ioc/import-batch",
            admin_only(post(ioc_handlers::import_ioc_batch)),
        )
        .route(
            "/security/ioc/export",
            admin_only(get(ioc_handlers::export_ioc)),
        )
        // Comment retained in English.
        .route(
            "/security/whitelist",
            admin_only(
                get(security_handlers::get_whitelist)
                    .post(security_handlers::add_whitelist_entry)
                    .put(security_handlers::update_whitelist),
            ),
        )
        .route(
            "/security/whitelist/{id}",
            admin_only(delete(security_handlers::delete_whitelist_entry)),
        )
        // Comment retained in English.
        .route(
            "/security/rules",
            admin_only(
                get(security_handlers::list_disposition_rules)
                    .post(security_handlers::create_disposition_rule),
            ),
        )
        .route(
            "/security/rules/{id}",
            admin_only(put(security_handlers::update_disposition_rule)),
        )
        .route(
            "/security/rules/{id}",
            admin_only(delete(security_handlers::delete_disposition_rule)),
        )
        // Quarantine (MTA mode)
        .route(
            "/security/quarantine",
            admin_only(get(security_handlers::quarantine::list_quarantine)),
        )
        .route(
            "/security/quarantine/stats",
            admin_only(get(security_handlers::quarantine::quarantine_stats)),
        )
        .route(
            "/security/quarantine/{id}/release",
            admin_only(post(security_handlers::quarantine::release_quarantine)),
        )
        .route(
            "/security/quarantine/{id}",
            admin_only(delete(security_handlers::quarantine::delete_quarantine)),
        )
        // YARA
        .route(
            "/security/yara-rules",
            admin_only(get(yara_handlers::list_yara_rules).post(yara_handlers::create_yara_rule)),
        )
        .route(
            "/security/yara-rules/{id}",
            admin_only(put(yara_handlers::update_yara_rule)),
        )
        .route(
            "/security/yara-rules/{id}",
            admin_only(delete(yara_handlers::delete_yara_rule)),
        )
        .route(
            "/security/yara-rules/{id}/toggle",
            admin_only(put(yara_handlers::toggle_yara_rule)),
        )
        .route(
            "/security/yara-rules/validate",
            admin_only(post(yara_handlers::validate_yara_rule)),
        )
        // Recent verdicts (paginated)
        .route(
            "/security/verdicts",
            get(security_handlers::list_recent_verdicts),
        )
        // Security statistics and engine status
        .route(
            "/security/stats",
            get(security_handlers::get_security_stats),
        )
        .route(
            "/security/engine-status",
            get(security_handlers::get_engine_status),
        )
        // Rescan
        .route(
            "/security/rescan",
            admin_only(post(security_handlers::trigger_rescan)),
        )
        // Feedback statistics
        .route(
            "/security/feedback/stats",
            get(security_handlers::get_feedback_stats),
        )
        // AI service configuration
        .route(
            "/security/ai-config",
            admin_only(
                get(security_handlers::get_ai_config).put(security_handlers::update_ai_config),
            ),
        )
        .route(
            "/security/ai-config/test",
            admin_only(post(security_handlers::test_ai_connection)),
        )
        // Content detection rules
        .route(
            "/security/content-rules",
            get(security_handlers::get_content_rules),
        )
        // Keyword override configuration
        .route(
            "/security/keyword-overrides",
            admin_only(
                get(security_handlers::get_keyword_overrides)
                    .put(security_handlers::update_keyword_overrides),
            ),
        )
        // Module data override configuration
        .route(
            "/security/module-data-overrides",
            admin_only(
                get(security_handlers::get_module_data_overrides)
                    .put(security_handlers::update_module_data_overrides),
            ),
        )
        // Email alert configuration
        .route(
            "/security/email-alert",
            admin_only(
                get(security_handlers::get_email_alert_config)
                    .put(security_handlers::update_email_alert_config),
            ),
        )
        .route(
            "/security/email-alert/test",
            admin_only(post(security_handlers::test_email_alert)),
        )
        .route(
            "/security/wechat-alert",
            admin_only(
                get(security_handlers::get_wechat_alert_config)
                    .put(security_handlers::update_wechat_alert_config),
            ),
        )
        .route(
            "/security/wechat-alert/test",
            admin_only(post(security_handlers::test_wechat_alert)),
        )
        // Comment retained in English.
        .route(
            "/security/intel-whitelist",
            admin_only(
                get(security_handlers::list_intel_whitelist)
                    .post(security_handlers::add_intel_clean),
            ),
        )
        .route(
            "/security/intel-whitelist/{id}",
            admin_only(delete(security_handlers::delete_intel_whitelist)),
        )
        // Intel source configuration (VT / AbuseIPDB)
        .route(
            "/security/intel-config",
            admin_only(
                get(security_handlers::get_intel_config)
                    .put(security_handlers::update_intel_config),
            ),
        )
        // Threat scenes (bulk mailing + bounce harvest)
        .route(
            "/security/threat-scenes",
            get(security_handlers::list_threat_scenes),
        )
        .route(
            "/security/threat-scenes/stats",
            get(security_handlers::threat_scene_stats),
        )
        .route(
            "/security/threat-scenes/{id}",
            get(security_handlers::get_threat_scene),
        )
        .route(
            "/security/threat-scenes/{id}",
            admin_only(delete(security_handlers::delete_threat_scene)),
        )
        .route(
            "/security/threat-scenes/{id}/emails",
            get(security_handlers::get_scene_emails),
        )
        .route(
            "/security/threat-scenes/{id}/acknowledge",
            admin_only(post(security_handlers::acknowledge_scene)),
        )
        .route(
            "/security/threat-scenes/{id}/block",
            admin_only(post(security_handlers::block_scene)),
        )
        .route(
            "/security/threat-scenes/{id}/resolve",
            admin_only(post(security_handlers::resolve_scene)),
        )
        .route(
            "/security/scene-rules",
            admin_only(
                get(security_handlers::get_scene_rules).put(security_handlers::update_scene_rules),
            ),
        );

    // NLP model management API
    let admin_routes = Router::new()
        .route(
            "/admin/nlp/train",
            post(training_handlers::trigger_nlp_training),
        )
        .route(
            "/admin/nlp/status",
            get(training_handlers::get_nlp_training_status),
        )
        .route(
            "/admin/nlp/samples",
            get(training_handlers::get_training_samples),
        )
        .route(
            "/admin/nlp/samples/{id}",
            delete(training_handlers::delete_training_sample)
                .put(training_handlers::update_training_sample),
        )
        .route(
            "/admin/nlp/progress",
            get(training_handlers::get_training_progress),
        )
        .route(
            "/admin/nlp/stats",
            get(training_handlers::get_training_stats),
        )
        .layer(middleware::from_fn(require_admin));

    // Data security API (HTTP session analysis)
    let data_security_routes = Router::new()
        .route(
            "/data-security/stats",
            get(data_security_handlers::get_data_security_stats),
        )
        .route(
            "/data-security/incidents",
            get(data_security_handlers::list_data_security_incidents),
        )
        .route(
            "/data-security/incidents/{id}",
            get(data_security_handlers::get_data_security_incident),
        )
        .route(
            "/data-security/http-sessions",
            get(data_security_handlers::list_http_sessions),
        )
        .route(
            "/data-security/http-sessions/{id}",
            get(data_security_handlers::get_http_session),
        )
        .route(
            "/data-security/http-sessions/{id}/body",
            get(data_security_handlers::download_http_session_body),
        )
        .route(
            "/data-security/engine-status",
            get(data_security_handlers::get_data_security_engine_status),
        );

    // Internal service routes (sniffer/engine, INTERNAL_API_TOKEN auth)
    let internal_routes = Router::new()
        // SEC-M06: Prometheus metrics (internal route, token auth, CWE-306)
        .route("/metrics", get(crate::metrics::metrics_handler))
        .route("/internal/health/ready", get(handlers::health::readiness))
        // Sniffer status update
        .route("/system/sniffer", post(handlers::update_sniffer_status))
        // MTA proxy status update
        .route("/system/mta", post(handlers::update_mta_status))
        // Data import
        .route("/import/sessions", post(handlers::import_sessions))
        .route("/import/stats", post(handlers::update_stats))
        // Data security HTTP session import
        .route(
            "/data-security/import/http-sessions",
            post(data_security_handlers::import_http_sessions),
        )
        // Engine status query (internal component auth)
        .route(
            "/internal/engine-status",
            get(security_handlers::get_engine_status),
        )
        // Sniffer data security configuration (internal auth)
        .route(
            "/internal/sniffer-config",
            get(security_handlers::get_sniffer_config_internal),
        );

    // Merge protected routes and apply JWT auth middleware
    let authed = protected_routes
        .merge(security_routes)
        .merge(admin_routes)
        .merge(data_security_routes)
        .layer(middleware::from_fn_with_state(state, require_auth));

    // Internal routes with token auth middleware
    let internal_authed = internal_routes
        .layer(middleware::from_fn(crate::auth::require_internal_origin))
        .layer(middleware::from_fn(require_internal_token));

    // Final merge: public + internal (token) + JWT-authenticated
    public_routes.merge(internal_authed).merge(authed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn trusted_proxy_uses_forwarded_client_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.24, 127.0.0.1"),
        );

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        let trusted = HashSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        let client_ip = extract_client_ip_with_trusted(&headers, direct_addr, &trusted);
        assert_eq!(client_ip, "198.51.100.24".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_proxy_rejects_ambiguous_xff_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 198.51.100.24"),
        );

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        let trusted = HashSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        let client_ip = extract_client_ip_with_trusted(&headers, direct_addr, &trusted);
        assert_eq!(client_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn untrusted_proxy_ignores_forwarded_client_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.24"));

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 8088));
        let trusted = HashSet::new();

        let client_ip = extract_client_ip_with_trusted(&headers, direct_addr, &trusted);
        assert_eq!(client_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    }

    #[test]
    fn default_trusted_proxy_config_keeps_loopback_and_localhost() {
        let trusted = build_trusted_proxy_ips(None, Some("localhost"));

        assert!(trusted.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(trusted.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn request_is_secure_respects_https_forwarded_proto_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        assert!(request_is_secure(&headers, direct_addr, false));
    }

    #[test]
    fn request_is_secure_ignores_untrusted_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 8088));
        assert!(!request_is_secure(&headers, direct_addr, false));
    }

    #[test]
    fn internal_route_rejects_external_client_behind_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.24"));

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        assert!(!request_originates_from_internal_network(
            &headers,
            direct_addr
        ));
    }

    #[test]
    fn internal_route_accepts_direct_private_client() {
        let headers = HeaderMap::new();
        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 8088));

        assert!(request_originates_from_internal_network(
            &headers,
            direct_addr
        ));
    }

    #[test]
    fn internal_route_rejects_ambiguous_xff_chain_with_private_spoof() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.24, 10.0.0.9"),
        );

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        assert!(!request_originates_from_internal_network(
            &headers,
            direct_addr
        ));
    }
}
