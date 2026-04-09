//! API Road

//! Road (According toauthentication):

//! publicRoad (authentication):
//! - /api/health - (, liveness)
//! - /api/health/live - (K8s liveness probe,)
//! - /api/health/ready - (K8s readiness probe, DB/Redis/Engine)
//! - /api/metrics - Prometheus (INTERNAL_API_TOKEN)
//! - /api/auth/login - login

//! JWT authenticationRoad:
//! - /api/auth/* - Password, WebSocket
//! - /api/sessions/* - SessionQuery
//! - /api/stats/* - StatisticsData
//! - /api/system/* - systemstatus
//! - /api/database/* - Data
//! - /api/config/* - Configuration (Road, Syslog, Sniffer, time)
//! - /api/config/setup-status -
//! - /api/audit/* - log login
//! - /api/security/* - SecurityEngine (Stream, IOC,, Alert,)
//! - /api/admin/nlp/* - NLP Model
//! - /api/data-security/* - Data security (HTTP protocolanalyze)

//! internalServiceRoad (INTERNAL_API_TOKEN authentication):
//! - /api/system/sniffer - status
//! - /api/import/* - Data
//! - /api/internal/* - internalcomponentQuery

use axum::{
    Json, Router,
    extract::State,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use crate::AppState;
use crate::auth::{
    ChangePasswordRequest, ChangePasswordResponse, LoginRequest,
    build_token_cookie, handle_change_password, handle_login, handle_logout, handle_me,
    require_auth, require_internal_token,
};
use crate::handlers;
use crate::handlers::data_security as data_security_handlers;
use crate::handlers::ioc_handlers;
use crate::handlers::security as security_handlers;
use crate::handlers::syslog_config as syslog_handlers;
use crate::handlers::training as training_handlers;
use crate::handlers::yara as yara_handlers;

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

fn build_trusted_proxy_ips(
    configured_ips: Option<&str>,
    configured_hosts: Option<&str>,
) -> HashSet<IpAddr> {
    let mut trusted = HashSet::from([
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]);

    if let Some(raw_ips) = configured_ips.map(str::trim).filter(|value| !value.is_empty()) {
        for entry in raw_ips.split(',').map(str::trim).filter(|value| !value.is_empty()) {
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

    let configured_hosts = configured_hosts.map(str::trim).filter(|value| !value.is_empty());
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
                    tracing::warn!(proxy_host = host, "TRUSTED_PROXY_HOSTS: 条目未解析出任何 IP");
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
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|value| value.to_str().ok())
    {
        let forwarded_ips: Vec<IpAddr> = xff
            .split(',')
            .map(str::trim)
            .filter_map(|value| value.parse::<IpAddr>().ok())
            .collect();

        if let Some(client_ip) = forwarded_ips
            .into_iter()
            .rev()
            .find(|ip| !trusted_proxies.contains(ip))
        {
            return client_ip;
        }
    }

    direct_addr.ip()
}

pub(crate) fn extract_client_ip(headers: &axum::http::HeaderMap, direct_addr: SocketAddr) -> IpAddr {
    extract_client_ip_with_trusted(headers, direct_addr, trusted_proxy_ips())
}

pub(crate) fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// LoginProcess (per-IP Stream + recordlogin + log)
/// SEC: set the HttpOnly JWT cookie via Set-Cookie when login succeeds.
async fn login(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<LoginRequest>,
) -> axum::response::Response {
    let client_ip = extract_client_ip(&headers, addr);
    let ip = client_ip.to_string();
    let response = handle_login(
        &state.auth.config,
        &state.auth.login_rate_limiter,
        client_ip,
        &request,
    )
    .await;

   // recordlogin (response)
    let db = state.engine_db.clone();
    let username = request.username.clone();
    let success = response.success;
    let reason = response.error.clone();
    let ip_clone = ip.clone();
    tokio::spawn(async move {
        if let Err(e) = db
            .record_login(&username, success, Some(&ip_clone), reason.as_deref())
            .await
        {
            tracing::error!(username = %username, error = %e, "审计: loginrecord写入failed");
        }
        if success
            && let Err(e) = db
                .write_audit_log(&username, "login", None, None, None, Some(&ip_clone))
                .await
        {
            tracing::error!(username = %username, error = %e, "审计: login审计log写入failed");
        }
    });

    // Set the HttpOnly cookie on successful login; the JWT stays server-side and is not serialized into the JSON body.
    if let Some(ref token) = response.token {
        let cookie_val = build_token_cookie(
            token,
            state.auth.config.token_expire_secs,
            state.secure_cookie,
        );
        let mut resp_headers = axum::http::HeaderMap::new();
        if let Ok(val) = cookie_val.parse() {
            resp_headers.insert(axum::http::header::SET_COOKIE, val);
        }
        (resp_headers, Json(response)).into_response()
    } else {
        Json(response).into_response()
    }
}

/// SEC-H02: WebSocket 1 (JWT found URL)
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
           // SEC-M12:, 429
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "票据Service繁忙，请稍后重试"
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

/// POST /api/auth/logout - clear the HttpOnly cookie.
async fn logout(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    handle_logout(state.secure_cookie).await
}

/// Password (log)
/// SEC-M04: From JWT Extract Used for log (CWE-862)
async fn change_password(
    State(state): State<Arc<AppState>>,
    user: crate::auth::AuthenticatedUser,
    Json(request): Json<ChangePasswordRequest>,
) -> Json<ChangePasswordResponse> {
    let response = handle_change_password(&state.auth.config, &state.engine_db, &request).await;

    if response.success {
        let db = state.engine_db.clone();
        let username = user.username.clone();
        tokio::spawn(async move {
            if let Err(e) = db
                .write_audit_log(&username, "change_password", Some("auth"), None, None, None)
                .await
            {
                tracing::error!(error = %e, "审计: Password修改审计log写入failed");
            }
        });
    }

    Json(response)
}

/// API Road
pub fn api_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
   // publicRoad (authentication)
    let public_routes = Router::new()
       // (K8s)
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::health::liveness))
        .route("/health/ready", get(handlers::health::readiness))
       // login
        .route("/auth/login", post(login));

   // Road (JWT authentication)
    let protected_routes = Router::new()
       // Session info (cookie-auth validation)
        .route("/auth/me", get(me))
       // Logout (clear the HttpOnly cookie)
        .route("/auth/logout", post(logout))
       // Password (authentication)
        .route("/auth/change-password", post(change_password))
       // SEC-H02: WebSocket 1 (authentication)
        .route("/auth/ws-ticket", post(ws_ticket))
       // Session
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/{id}", get(handlers::get_session))
        .route("/sessions/{id}/eml", get(handlers::download_eml))
        .route(
            "/sessions/{id}/related",
            get(handlers::get_related_sessions),
        )
       // SessionSecurity
        .route(
            "/sessions/{id}/verdict",
            get(security_handlers::get_session_verdict),
        )
        .route(
            "/sessions/{id}/security-results",
            get(security_handlers::get_session_security_results),
        )
       // Session Newanalyze
        .route(
            "/sessions/{id}/rescan",
            post(security_handlers::rescan_session),
        )
       // Session
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
       // systemstatus
        .route("/system/status", get(handlers::get_system_status))
        .route("/system/metrics", get(handlers::get_system_metrics))
        .route("/system/interfaces", get(handlers::get_host_interfaces))
       // Data
        .route("/database/clear", delete(handlers::clear_database))
        .route("/database/factory-reset", post(handlers::factory_reset))
        .route("/database/precise-clear", post(handlers::precise_clear))
        .route("/database/rotate-config", get(handlers::get_rotate_config))
        .route(
            "/database/rotate-config",
            put(handlers::update_rotate_config),
        )
       // log login
        .route("/audit/logs", get(handlers::list_audit_logs))
        .route("/audit/login-history", get(handlers::list_login_history))
       // Syslog Configuration
        .route("/config/syslog", get(syslog_handlers::get_syslog_config))
        .route("/config/syslog", put(syslog_handlers::update_syslog_config))
        .route(
            "/config/syslog/test",
            post(syslog_handlers::test_syslog_connection),
        )
       // Comment retained in English.
        .route("/config/setup-status", get(handlers::get_setup_status))
        .route("/config/setup-status", put(handlers::update_setup_status))
        .route("/config/ui-preferences", get(handlers::get_ui_preferences))
        .route("/config/ui-preferences", put(handlers::update_ui_preferences))
       // (mirror / mta)
        .route("/config/deployment-mode", get(handlers::get_deployment_mode))
        .route("/config/deployment-mode", put(handlers::update_deployment_mode))
       // Sniffer Data securityConfiguration (webmail_servers, http_ports)
        .route(
            "/config/sniffer",
            get(security_handlers::get_sniffer_config),
        )
        .route(
            "/config/sniffer",
            put(security_handlers::update_sniffer_config),
        )
       // Data securitytime Configuration (time)
        .route(
            "/config/time-policy",
            get(security_handlers::get_time_policy_config),
        )
        .route(
            "/config/time-policy",
            put(security_handlers::update_time_policy_config),
        );

   // SecurityEngine API
    let security_routes = Router::new()
       // Stream Configuration
        .route(
            "/security/pipeline",
            get(security_handlers::get_pipeline_config),
        )
        .route(
            "/security/pipeline",
            put(security_handlers::update_pipeline_config),
        )
       // Modulemetadata
        .route(
            "/security/modules",
            get(security_handlers::get_modules_metadata),
        )
       // IOC
        .route("/security/ioc", get(ioc_handlers::list_ioc))
        .route("/security/ioc", post(ioc_handlers::add_ioc))
        .route("/security/ioc/{id}", delete(ioc_handlers::delete_ioc))
        .route("/security/ioc/{id}/extend", put(ioc_handlers::extend_ioc))
        .route("/security/ioc/import", post(ioc_handlers::import_ioc))
        .route(
            "/security/ioc/import-batch",
            post(ioc_handlers::import_ioc_batch),
        )
        .route("/security/ioc/export", get(ioc_handlers::export_ioc))
       // Comment retained in English.
        .route("/security/whitelist", get(security_handlers::get_whitelist))
        .route(
            "/security/whitelist",
            post(security_handlers::add_whitelist_entry),
        )
        .route(
            "/security/whitelist",
            put(security_handlers::update_whitelist),
        )
        .route(
            "/security/whitelist/{id}",
            delete(security_handlers::delete_whitelist_entry),
        )
       // Comment retained in English.
        .route(
            "/security/rules",
            get(security_handlers::list_disposition_rules),
        )
        .route(
            "/security/rules",
            post(security_handlers::create_disposition_rule),
        )
        .route(
            "/security/rules/{id}",
            put(security_handlers::update_disposition_rule),
        )
        .route(
            "/security/rules/{id}",
            delete(security_handlers::delete_disposition_rule),
        )
       // (MTA)
        .route("/security/quarantine", get(security_handlers::quarantine::list_quarantine))
        .route("/security/quarantine/stats", get(security_handlers::quarantine::quarantine_stats))
        .route("/security/quarantine/{id}/release", post(security_handlers::quarantine::release_quarantine))
        .route("/security/quarantine/{id}", delete(security_handlers::quarantine::delete_quarantine))
       // YARA
        .route("/security/yara-rules", get(yara_handlers::list_yara_rules))
        .route(
            "/security/yara-rules",
            post(yara_handlers::create_yara_rule),
        )
        .route(
            "/security/yara-rules/{id}",
            put(yara_handlers::update_yara_rule),
        )
        .route(
            "/security/yara-rules/{id}",
            delete(yara_handlers::delete_yara_rule),
        )
        .route(
            "/security/yara-rules/{id}/toggle",
            put(yara_handlers::toggle_yara_rule),
        )
        .route(
            "/security/yara-rules/validate",
            post(yara_handlers::validate_yara_rule),
        )
       // risk (table)
        .route(
            "/security/verdicts",
            get(security_handlers::list_recent_verdicts),
        )
       // Statistics monitor
        .route(
            "/security/stats",
            get(security_handlers::get_security_stats),
        )
        .route(
            "/security/engine-status",
            get(security_handlers::get_engine_status),
        )
       // scan
        .route("/security/rescan", post(security_handlers::trigger_rescan))
       // Statistics
        .route(
            "/security/feedback/stats",
            get(security_handlers::get_feedback_stats),
        )
       // AI Service configuration
        .route("/security/ai-config", get(security_handlers::get_ai_config))
        .route(
            "/security/ai-config",
            put(security_handlers::update_ai_config),
        )
        .route(
            "/security/ai-config/test",
            post(security_handlers::test_ai_connection),
        )
       // detect
        .route(
            "/security/content-rules",
            get(security_handlers::get_content_rules),
        )
       // Configuration (custom)
        .route(
            "/security/keyword-overrides",
            get(security_handlers::get_keyword_overrides),
        )
        .route(
            "/security/keyword-overrides",
            put(security_handlers::update_keyword_overrides),
        )
       // Email alert configuration
        .route(
            "/security/email-alert",
            get(security_handlers::get_email_alert_config),
        )
        .route(
            "/security/email-alert",
            put(security_handlers::update_email_alert_config),
        )
        .route(
            "/security/email-alert/test",
            post(security_handlers::test_email_alert),
        )
       // Comment retained in English.
        .route(
            "/security/intel-whitelist",
            get(security_handlers::list_intel_whitelist),
        )
        .route(
            "/security/intel-whitelist",
            post(security_handlers::add_intel_clean),
        )
        .route(
            "/security/intel-whitelist/{id}",
            delete(security_handlers::delete_intel_whitelist),
        )
       // SourceConfiguration (VT/AbuseIPDB)
        .route(
            "/security/intel-config",
            get(security_handlers::get_intel_config),
        )
        .route(
            "/security/intel-config",
            put(security_handlers::update_intel_config),
        )
       // Threat scenes (bulk mailing + bounce harvest)
        .route("/security/threat-scenes", get(security_handlers::list_threat_scenes))
        .route("/security/threat-scenes/stats", get(security_handlers::threat_scene_stats))
        .route("/security/threat-scenes/{id}", get(security_handlers::get_threat_scene))
        .route("/security/threat-scenes/{id}", delete(security_handlers::delete_threat_scene))
        .route("/security/threat-scenes/{id}/emails", get(security_handlers::get_scene_emails))
        .route("/security/threat-scenes/{id}/acknowledge", post(security_handlers::acknowledge_scene))
        .route("/security/threat-scenes/{id}/block", post(security_handlers::block_scene))
        .route("/security/threat-scenes/{id}/resolve", post(security_handlers::resolve_scene))
        .route("/security/scene-rules", get(security_handlers::get_scene_rules))
        .route("/security/scene-rules", put(security_handlers::update_scene_rules));

   // NLP Model API
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
        );

   // Data security API (HTTP protocolanalyze)
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

   // internalServiceRoad (/Engine, INTERNAL_API_TOKEN)
    let internal_routes = Router::new()
       // SEC-M06: Prometheus (internalRoad, Token authentication, CWE-306)
        .route("/metrics", get(crate::metrics::metrics_handler))
       // status
        .route("/system/sniffer", post(handlers::update_sniffer_status))
       // MTA proxy status
        .route("/system/mta", post(handlers::update_mta_status))
       // Data
        .route("/import/sessions", post(handlers::import_sessions))
        .route("/import/stats", post(handlers::update_stats))
       // Data security HTTP Session
        .route(
            "/data-security/import/http-sessions",
            post(data_security_handlers::import_http_sessions),
        )
       // EnginestatusQuery (Start + internalcomponent authentication)
        .route(
            "/internal/engine-status",
            get(security_handlers::get_engine_status),
        )
       // Sniffer Start Data securityConfiguration (authentication)
        .route(
            "/internal/sniffer-config",
            get(security_handlers::get_sniffer_config_internal),
        );

   // Road 1 JWT authentication
    let authed = protected_routes
        .merge(security_routes)
        .merge(admin_routes)
        .merge(data_security_routes)
        .layer(middleware::from_fn_with_state(state, require_auth));

   // internalRoad Token authentication
    let internal_authed = internal_routes.layer(middleware::from_fn(require_internal_token));

   // Merge: publicRoad + internalServiceRoad (Token) + JWT authentication Road
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
    fn trusted_proxy_ignores_spoofed_leftmost_xff_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 198.51.100.24"),
        );

        let direct_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088));
        let trusted = HashSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        let client_ip = extract_client_ip_with_trusted(&headers, direct_addr, &trusted);
        assert_eq!(client_ip, "198.51.100.24".parse::<IpAddr>().unwrap());
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
}
