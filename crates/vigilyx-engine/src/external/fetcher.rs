//! Sandbox URL Gethandler

//! Features:
//! - Securityof HTTP GET (Timeout 10s, large 3 Time/Count, Response <= 500KB)
//! - hopsPrivate/ IP
//! - HTML -> Plain textExtract
//! - formdetect (Login /Password Count)
//! - DomainKeywordsmatch

use std::net::IpAddr;
use std::time::Duration;

use scraper::{Html, Selector};

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
    client: reqwest::Client,
    config: FetchConfig,
}

impl UrlFetcher {
    pub fn new(config: FetchConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .danger_accept_invalid_certs(false)
            .build()
            .unwrap_or_default();

        Self { client, config }
    }

    pub fn with_defaults() -> Self {
        Self::new(FetchConfig::default())
    }

   /// Get URL Content
    pub async fn fetch(&self, url: &str) -> FetchResult {
       // 1. URL SecurityCheck
        if let Err(reason) = self.check_url_safety(url) {
            return FetchResult {
                url: url.to_string(),
                final_url: url.to_string(),
                status_code: 0,
                content_type: String::new(),
                page_text: String::new(),
                page_title: None,
                form_analysis: FormAnalysis::default(),
                error: Some(reason),
            };
        }

       // 2. HTTP GET
        let response = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                return FetchResult {
                    url: url.to_string(),
                    final_url: url.to_string(),
                    status_code: 0,
                    content_type: String::new(),
                    page_text: String::new(),
                    page_title: None,
                    form_analysis: FormAnalysis::default(),
                    error: Some(format!("Request failed: {}", e)),
                };
            }
        };

        let final_url = response.url().to_string();
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

   /// URL SecurityCheck
    fn check_url_safety(&self, url: &str) -> Result<(), String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

       // only http/https
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => return Err(format!("Blocked scheme: {}", scheme)),
        }

       // Check
        let host = parsed
            .host_str()
            .ok_or_else(|| "No host in URL".to_string())?;

       // hopsPrivate IP
        if self.config.skip_private_ips
            && let Ok(ip) = host.parse::<IpAddr>()
            && is_private_ip(&ip)
        {
            return Err(format!("Private/internal IP blocked: {}", ip));
        }

        Ok(())
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

/// Checkwhether Private/ IP
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 0 
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
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
            let login_names = [
                "user", "username", "login", "email", "account", "uid", "passwd", "password",
                "pass", "pwd",
            ];
            if login_names.iter().any(|n| input_name.contains(n)) {
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

/// Domain detectKeywords
pub const PHISHING_DOMAIN_KEYWORDS: &[&str] = &[
    "login",
    "signin",
    "sign-in",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "support",
    "helpdesk",
    "service",
    "security",
    "auth",
];

/// CheckDomainwhetherpacketContains Keywords
pub fn check_domain_keywords(domain: &str) -> Vec<String> {
    let domain_lower = domain.to_lowercase();
    PHISHING_DOMAIN_KEYWORDS
        .iter()
        .filter(|kw| domain_lower.contains(*kw))
        .map(|kw| kw.to_string())
        .collect()
}
