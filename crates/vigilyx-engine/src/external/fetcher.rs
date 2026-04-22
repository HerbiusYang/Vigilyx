//! Sandbox URL Gethandler

//! Features:
//! - Securityof HTTP GET (Timeout 10s, large 3 Time/Count, Response <= 500KB)
//! - hopsPrivate/ IP
//! - HTML -> Plain textExtract
//! - formdetect (Login /Password Count)
//! - DomainKeywordsmatch

use std::time::Duration;

use reqwest::header::LOCATION;
use scraper::{Html, Selector};
use vigilyx_core::{DEFAULT_BLOCKED_HOSTNAMES, resolve_network_host, validate_network_host};

use crate::module_data::module_data;

/// GetConfiguration
pub struct FetchConfig {
    pub timeout_secs: u64,
    pub max_redirects: usize,
    pub max_response_bytes: u64,
    pub skip_private_ips: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_redirects: 3,
            max_response_bytes: 500 * 1024, // 500KB
            skip_private_ips: true,
        }
    }
}

/// GetResult
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    pub content_type: String,
    pub page_text: String,
    pub page_title: Option<String>,
    pub form_analysis: FormAnalysis,
    pub error: Option<String>,
}

/// formAnalyze
#[derive(Debug, Clone, Default)]
pub struct FormAnalysis {
    pub total_forms: usize,
    pub login_forms: usize,
    pub password_fields: usize,
    pub input_fields: usize,
    pub has_login_form: bool,
}

/// Sandbox URL Gethandler
pub struct UrlFetcher {
    config: FetchConfig,
}

impl UrlFetcher {
    pub fn new(config: FetchConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(FetchConfig::default())
    }

    /// Get URL Content
    pub async fn fetch(&self, url: &str) -> FetchResult {
        // 1. URL SecurityCheck + explicit DNS pinning per hop.
        //
        // SSRF protection must bind the validated DNS answers to the actual
        // connection attempt; otherwise a hostname can pass validation and then
        // re-resolve to a private IP at connect time (DNS rebinding / TOCTOU).
        let mut current_url = url.to_string();
        let mut redirect_hops = 0usize;

        let response = loop {
            if let Err(reason) = validate_fetch_url(&current_url, self.config.skip_private_ips) {
                return FetchResult {
                    url: url.to_string(),
                    final_url: current_url,
                    status_code: 0,
                    content_type: String::new(),
                    page_text: String::new(),
                    page_title: None,
                    form_analysis: FormAnalysis::default(),
                    error: Some(reason),
                };
            }

            let parsed = match url::Url::parse(&current_url) {
                Ok(url) => url,
                Err(e) => {
                    return FetchResult {
                        url: url.to_string(),
                        final_url: current_url,
                        status_code: 0,
                        content_type: String::new(),
                        page_text: String::new(),
                        page_title: None,
                        form_analysis: FormAnalysis::default(),
                        error: Some(format!("Invalid URL: {}", e)),
                    };
                }
            };

            let response = match self.send_with_pinned_resolution(&parsed).await {
                Ok(r) => r,
                Err(e) => {
                    return FetchResult {
                        url: url.to_string(),
                        final_url: current_url,
                        status_code: 0,
                        content_type: String::new(),
                        page_text: String::new(),
                        page_title: None,
                        form_analysis: FormAnalysis::default(),
                        error: Some(e),
                    };
                }
            };

            if !response.status().is_redirection() {
                break response;
            }

            if redirect_hops >= self.config.max_redirects {
                return FetchResult {
                    url: url.to_string(),
                    final_url: current_url,
                    status_code: response.status().as_u16(),
                    content_type: String::new(),
                    page_text: String::new(),
                    page_title: None,
                    form_analysis: FormAnalysis::default(),
                    error: Some(format!(
                        "Too many redirects (max {})",
                        self.config.max_redirects
                    )),
                };
            }

            let Some(location) = response.headers().get(LOCATION) else {
                return FetchResult {
                    url: url.to_string(),
                    final_url: current_url,
                    status_code: response.status().as_u16(),
                    content_type: String::new(),
                    page_text: String::new(),
                    page_title: None,
                    form_analysis: FormAnalysis::default(),
                    error: Some("Redirect response missing Location header".to_string()),
                };
            };

            let location = match location.to_str() {
                Ok(value) => value,
                Err(_) => {
                    return FetchResult {
                        url: url.to_string(),
                        final_url: current_url,
                        status_code: response.status().as_u16(),
                        content_type: String::new(),
                        page_text: String::new(),
                        page_title: None,
                        form_analysis: FormAnalysis::default(),
                        error: Some("Redirect Location header is not valid UTF-8".to_string()),
                    };
                }
            };

            current_url = match parsed.join(location) {
                Ok(next) => next.to_string(),
                Err(e) => {
                    return FetchResult {
                        url: url.to_string(),
                        final_url: current_url,
                        status_code: response.status().as_u16(),
                        content_type: String::new(),
                        page_text: String::new(),
                        page_title: None,
                        form_analysis: FormAnalysis::default(),
                        error: Some(format!("Invalid redirect target: {}", e)),
                    };
                }
            };
            redirect_hops += 1;
        };

        let final_url = current_url;
        let status_code = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // 3. CheckResponsesize
        let content_length = response.content_length().unwrap_or(0);
        if content_length > self.config.max_response_bytes {
            return FetchResult {
                url: url.to_string(),
                final_url,
                status_code,
                content_type,
                page_text: String::new(),
                page_title: None,
                form_analysis: FormAnalysis::default(),
                error: Some(format!(
                    "Response too large: {} bytes (max {})",
                    content_length, self.config.max_response_bytes
                )),
            };
        }

        // 4. readGet body (limitsize)
        let body = match response.bytes().await {
            Ok(b) => {
                if b.len() as u64 > self.config.max_response_bytes {
                    return FetchResult {
                        url: url.to_string(),
                        final_url,
                        status_code,
                        content_type,
                        page_text: String::new(),
                        page_title: None,
                        form_analysis: FormAnalysis::default(),
                        error: Some("Response body exceeded size limit".to_string()),
                    };
                }
                String::from_utf8_lossy(&b).to_string()
            }
            Err(e) => {
                return FetchResult {
                    url: url.to_string(),
                    final_url,
                    status_code,
                    content_type,
                    page_text: String::new(),
                    page_title: None,
                    form_analysis: FormAnalysis::default(),
                    error: Some(format!("Failed to read body: {}", e)),
                };
            }
        };

        // 5. HTML Parse
        let (page_text, page_title, form_analysis) = if content_type.contains("html") {
            self.analyze_html(&body)
        } else {
            (body.clone(), None, FormAnalysis::default())
        };

        FetchResult {
            url: url.to_string(),
            final_url,
            status_code,
            content_type,
            page_text,
            page_title,
            form_analysis,
            error: None,
        }
    }

    async fn send_with_pinned_resolution(
        &self,
        url: &url::Url,
    ) -> Result<reqwest::Response, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(false);

        if self.config.skip_private_ips {
            let host = url.host_str().ok_or_else(|| "No host in URL".to_string())?;
            if host.parse::<std::net::IpAddr>().is_err() {
                let port = url
                    .port_or_known_default()
                    .ok_or_else(|| "URL has no known default port".to_string())?;
                let addrs = resolve_network_host(host, port, DEFAULT_BLOCKED_HOSTNAMES)?;
                builder = builder.resolve_to_addrs(host, &addrs);
            }
        }

        let client = builder
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))
    }

    /// HTML Analyze: ExtractText + + formAnalyze
    fn analyze_html(&self, html: &str) -> (String, Option<String>, FormAnalysis) {
        let document = Html::parse_document(html);

        // Extract
        let title = Selector::parse("title")
            .ok()
            .and_then(|sel| document.select(&sel).next())
            .map(|el| el.text().collect::<String>().trim().to_string());

        // ExtractPlain text (Exclude script/style)
        let text = extract_visible_text(&document);

        // formAnalyze
        let form_analysis = analyze_forms(&document);

        (text, title, form_analysis)
    }
}

fn validate_fetch_url(url: &str, skip_private_ips: bool) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("Blocked scheme: {}", scheme)),
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL must not contain userinfo".to_string());
    }

    if !skip_private_ips {
        return Ok(());
    }

    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) if !domain.is_empty() => domain.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        _ => return Err("No host in URL".to_string()),
    };

    validate_network_host(&host, DEFAULT_BLOCKED_HOSTNAMES)
}

/// Extract HTML Text
fn extract_visible_text(doc: &Html) -> String {
    // SAFETY: "body" is a valid CSS selector literal; parse() only fails on malformed input.
    let body_sel = Selector::parse("body").expect("static CSS selector 'body' is always valid");
    let _script_sel = Selector::parse("script").ok();
    let _style_sel = Selector::parse("style").ok();

    let mut text = String::new();

    if let Some(body) = doc.select(&body_sel).next() {
        for node in body.text() {
            let trimmed = node.trim();
            if !trimmed.is_empty() {
                text.push_str(trimmed);
                text.push(' ');
            }
        }
    }

    // limitTextLength
    if text.len() > 50_000 {
        text.truncate(50_000);
    }

    text
}

/// Analyze HTML form
fn analyze_forms(doc: &Html) -> FormAnalysis {
    let form_sel = match Selector::parse("form") {
        Ok(s) => s,
        Err(_) => return FormAnalysis::default(),
    };
    // SAFETY: "input" is a valid CSS selector literal; parse() only fails on malformed input.
    let input_sel = Selector::parse("input").expect("static CSS selector 'input' is always valid");

    let mut analysis = FormAnalysis::default();
    let login_names = module_data().get_list("fetcher_login_input_names").to_vec();

    for form in doc.select(&form_sel) {
        analysis.total_forms += 1;

        let mut has_password = false;
        let mut has_text_or_email = false;

        for input in form.select(&input_sel) {
            analysis.input_fields += 1;

            let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
            let input_name = input.value().attr("name").unwrap_or("").to_lowercase();

            if input_type == "password" {
                analysis.password_fields += 1;
                has_password = true;
            }

            if input_type == "text" || input_type == "email" {
                has_text_or_email = true;
            }

            // name hintsdetectLogin
            if login_names.iter().any(|n| input_name.contains(n.as_str())) {
                has_text_or_email = true;
            }
        }

        if has_password && has_text_or_email {
            analysis.login_forms += 1;
        }
    }

    analysis.has_login_form = analysis.login_forms > 0;

    analysis
}

/// CheckDomainwhetherpacketContains Keywords
pub fn check_domain_keywords(domain: &str) -> Vec<String> {
    let domain_lower = domain.to_lowercase();
    module_data()
        .get_list("phishing_domain_keywords")
        .iter()
        .filter(|kw| domain_lower.contains(kw.as_str()))
        .map(|kw| kw.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::validate_fetch_url;

    #[test]
    fn blocks_localhost_hostname() {
        let result = validate_fetch_url("http://localhost/login", true);
        assert!(result.is_err(), "localhost should be blocked: {result:?}");
    }

    #[test]
    fn blocks_internal_service_hostname() {
        let result = validate_fetch_url("http://vigilyx-redis:6379/", true);
        assert!(
            result.is_err(),
            "Docker service hostnames should be blocked: {result:?}"
        );
    }

    #[test]
    fn blocks_ipv6_unique_local_address() {
        let result = validate_fetch_url("http://[fd00:ec2::254]/login", true);
        assert!(result.is_err(), "IPv6 ULA should be blocked: {result:?}");
    }

    #[test]
    fn blocks_url_userinfo() {
        let result = validate_fetch_url("https://user:pass@example.com/login", true);
        assert!(result.is_err(), "userinfo should be blocked: {result:?}");
    }

    #[test]
    fn allows_public_https_url() {
        let result = validate_fetch_url("https://203.0.113.10/login?next=%2Fmail", true);
        assert!(result.is_ok(), "public URL should be allowed: {result:?}");
    }
}
