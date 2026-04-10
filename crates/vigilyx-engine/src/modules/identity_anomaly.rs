//! Engine G: Identity Behavior Anomaly Detection

//! MVP signals derivable from email metadata alone (no IAM integration needed):
//! - First-contact detection (sender-recipient pair never seen before)
//! - Communication pattern mutation (same sender, changed behavior)
//! - Reply-chain anomaly (reply to a thread the recipient never participated in)
//! - Client fingerprint change (User-Agent/X-Mailer sudden shift)

//! Output: BPA triple (b, d, u) with engine_id = "identity_anomaly"

use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;

use std::sync::Arc;

use crate::bpa::Bpa;
use crate::context::SecurityContext;
use crate::db_service::DbQueryService;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

/// Maximum score from all checks combined.
const MAX_RAW_SCORE: f64 = 1.0;
/// Individual signal weights.
/// First contact: sender domain has never emailed this organization before
const W_FIRST_CONTACT: f64 = 0.10; // Weak signal alone, but compounds with other signals
const W_DISPLAY_NAME_MISMATCH: f64 = 0.25;
const W_REPLY_CHAIN_ANOMALY: f64 = 0.30;
const W_CLIENT_FINGERPRINT: f64 = 0.15;
const W_ENVELOPE_MISMATCH: f64 = 0.20;

/// Pinyin syllable table (used to distinguish legitimate Chinese pinyin domains from random strings)
const PINYIN_SYLLABLES: &[&str] = &[
    "zhuang", "shuang", "chuang", "xiang", "jiang", "liang", "niang", "qiang", "guang", "huang",
    "kuang", "zhuai", "shuai", "zhang", "zheng", "zhong", "zhuai", "chang", "cheng", "chong",
    "chuai", "shang", "sheng", "shuai", "xiao", "xian", "xing", "xiong", "xuan", "zhan", "zhao",
    "zhen", "zhi", "zhou", "zhua", "zhui", "zhun", "zhuo", "chai", "chan", "chao", "chen", "chi",
    "chou", "chua", "chui", "chun", "chuo", "shan", "shao", "shen", "shi", "shou", "shua", "shui",
    "shun", "shuo", "bang", "beng", "bing", "biao", "bian", "cang", "ceng", "cong", "dang", "deng",
    "ding", "dong", "dian", "diao", "duan", "fang", "feng", "gang", "geng", "gong", "guan", "hang",
    "heng", "hong", "huan", "jian", "jiao", "jing", "jion", "juan", "kang", "keng", "kong", "kuan",
    "lang", "leng", "ling", "long", "lian", "liao", "luan", "mang", "meng", "ming", "mian", "miao",
    "nang", "neng", "ning", "nong", "nian", "niao", "nuan", "pang", "peng", "ping", "pian", "piao",
    "rang", "reng", "rong", "ruan", "sang", "seng", "song", "suan", "tang", "teng", "ting", "tong",
    "tian", "tiao", "tuan", "wang", "weng", "yang", "ying", "yong", "yuan", "zang", "zeng", "zong",
    "zuan", "bai", "ban", "bao", "bei", "ben", "bi", "bo", "bu", "cai", "can", "cao", "ce", "ci",
    "cu", "cuo", "dai", "dan", "dao", "de", "dei", "di", "diu", "du", "duo", "dui", "dun", "fan",
    "fei", "fen", "fo", "fu", "gai", "gan", "gao", "ge", "gei", "gu", "gua", "gui", "gun", "guo",
    "hai", "han", "hao", "he", "hei", "hen", "hu", "hua", "hui", "hun", "huo", "ji", "jia", "jie",
    "jin", "jiu", "ju", "jue", "jun", "ka", "kai", "kan", "kao", "ke", "ken", "ku", "kua", "kui",
    "kun", "kuo", "la", "lai", "lan", "lao", "le", "lei", "li", "lia", "lie", "lin", "liu", "lo",
    "lu", "lv", "luo", "lun", "ma", "mai", "man", "mao", "me", "mei", "men", "mi", "mie", "min",
    "miu", "mo", "mu", "na", "nai", "nan", "nao", "ne", "nei", "nen", "ni", "nie", "nin", "niu",
    "nu", "nv", "nuo", "nun", "ou", "pa", "pai", "pan", "pao", "pei", "pen", "pi", "pie", "pin",
    "po", "pu", "qi", "qia", "qie", "qin", "qiu", "qu", "que", "qun", "ran", "rao", "re", "ren",
    "ri", "rou", "ru", "rua", "rui", "run", "ruo", "sa", "sai", "san", "sao", "se", "si", "su",
    "sui", "sun", "suo", "ta", "tai", "tan", "tao", "te", "ti", "tie", "tou", "tu", "tui", "tun",
    "tuo", "wa", "wai", "wan", "wei", "wen", "wo", "wu", "xi", "xia", "xie", "xin", "xiu", "xu",
    "xue", "xun", "ya", "yan", "yao", "ye", "yi", "yin", "you", "yu", "yue", "yun", "za", "zai",
    "zan", "zao", "ze", "zei", "zi", "zu", "zui", "zun", "zuo", "a", "ai", "an", "ang", "ao", "e",
    "ei", "en", "er", "o",
];

/// Common short English words (used for username validation: helper, test, admin, notify, bot, mp, ...)
const COMMON_EN_WORDS: &[&str] = &[
    "helper", "admin", "test", "notify", "alert", "bot", "system", "service", "noreply", "support",
    "info", "news", "mail", "smtp", "auto", "mp", "pay", "shop", "store", "cloud", "dev", "api",
    "app", "web", "net", "push", "hub", "lab", "do", "no", "go", "hi", "my",
];

/// Legitimate vendor or product labels that can look consonant-heavy, but are not DGA domains.
const BENIGN_BRAND_DOMAIN_LABELS: &[&str] = &[
    "hundsun",
    "smartx",
    "aishu",
    "alipay",
    "wechat",
    "weixin",
    "foxmail",
    "qichacha",
    "cmbchina",
    "ccabchina",
    "nbcb",
];

/// Check whether a username can be decomposed into pinyin syllables + common English words.
/// If decomposable, it is a legitimate name (e.g., weixinmphelper = weixin + mp + helper), not random.
pub fn is_pinyin_english_name(name: &str) -> bool {
   // Dynamic programming: can_cover[i] = name[0..i] can be fully decomposed
    let n = name.len();
    if n == 0 {
        return true;
    }
    let mut can_cover = vec![false; n + 1];
    can_cover[0] = true;

    for i in 0..n {
        if !can_cover[i] {
            continue;
        }
       // Try pinyin syllables
        for &py in PINYIN_SYLLABLES {
            if name[i..].starts_with(py) {
                can_cover[i + py.len()] = true;
            }
        }
       // Try common English words
        for &ew in COMMON_EN_WORDS {
            if name[i..].starts_with(ew) {
                can_cover[i + ew.len()] = true;
            }
        }
    }
    can_cover[n]
}

pub fn is_human_readable_domain_label(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    is_pinyin_english_name(&normalized)
        || BENIGN_BRAND_DOMAIN_LABELS
            .iter()
            .any(|label| normalized == *label)
}

pub struct IdentityAnomalyModule {
    meta: ModuleMetadata,
    db: Option<Arc<dyn DbQueryService>>,
   /// Known suspicious User-Agent patterns (freemail providers, script-generated)
    suspicious_agents: Vec<&'static str>,
}

impl Default for IdentityAnomalyModule {
    fn default() -> Self {
        Self::new(None)
    }
}

impl IdentityAnomalyModule {
    pub fn new(db: Option<Arc<dyn DbQueryService>>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "identity_anomaly".to_string(),
                name: "Identity Behavior Anomaly".to_string(),
                description: "Detect sender identity anomalies: first contact, display name spoofing, reply chain anomaly, client fingerprint change"
                    .to_string(),
                pillar: Pillar::Semantic,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None, // First-contact detection requires DB query, not CPU-bound
            },
            db,
            suspicious_agents: vec![
                "python-requests",
                "curl/",
                "wget/",
                "go-http-client",
                "php/",
                "java/",
                "libwww-perl",
            ],
        }
    }

   /// Check if display name looks like it's impersonating a different domain
    #[inline]
    fn check_display_name_mismatch(&self, headers: &[(String, String)]) -> Option<(f64, Evidence)> {
        let from_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))?;
        let from_value = &from_header.1;

       // Extract display name and email address from "Display Name <email@domain>" format
        if let Some(angle_start) = from_value.rfind('<') {
            let display_name = from_value[..angle_start].trim().trim_matches('"');
            let email_part = from_value[angle_start..].trim_matches(|c| c == '<' || c == '>');

            if display_name.is_empty() {
                return None;
            }

            let email_domain = email_part.rsplit('@').next()?;
            let dn_lower = display_name.to_ascii_lowercase();

           // Check if display name contains an email-like pattern with a different domain
            static EMAIL_IN_DN: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap());

            if let Some(m) = EMAIL_IN_DN.find(&dn_lower) {
                let dn_email = m.as_str();
                if let Some(dn_domain) = dn_email.rsplit('@').next()
                    && dn_domain != email_domain.to_ascii_lowercase()
                {
                    return Some((
                        W_DISPLAY_NAME_MISMATCH,
                        Evidence {
                            description: format!(
                                "Display name contains email from different domain: display=\"{}\" actual sender domain={}",
                                display_name, email_domain
                            ),
                            location: Some("From header".to_string()),
                            snippet: Some(from_value.clone()),
                        },
                    ));
                }
            }

           // Check if display name mimics a well-known service
            let impersonation_targets = [
                "microsoft",
                "office365",
                "outlook",
                "google",
                "paypal",
                "apple",
                "amazon",
                "dhl",
                "fedex",
                "ups",
                "bank",
            ];
            for target in &impersonation_targets {
                if dn_lower.contains(target) && !email_domain.to_ascii_lowercase().contains(target)
                {
                    return Some((
                        W_DISPLAY_NAME_MISMATCH * 0.8,
                        Evidence {
                            description: format!(
                                "Display name impersonates known service: \"{}\" but sender domain is {}",
                                display_name, email_domain
                            ),
                            location: Some("From header".to_string()),
                            snippet: Some(from_value.clone()),
                        },
                    ));
                }
            }
        }

        None
    }

   /// Check for reply-chain anomalies (In-Reply-To / References mismatch)
    fn check_reply_chain_anomaly(
        &self,
        headers: &[(String, String)],
        rcpt_to: &[String],
        mail_from: Option<&str>,
    ) -> Option<(f64, Evidence)> {
        let in_reply_to = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("in-reply-to"));
        let references = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("references"));

       // If it claims to be a reply but there's no matching thread context
        if let Some((_, reply_id)) = in_reply_to
            && !reply_id.trim().is_empty()
        {
           // Check if Subject starts with Re: but we have no prior thread evidence
            let subject = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("subject"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");

            let is_reply_subject = subject.starts_with("Re:")
                || subject.starts_with("RE:")
                || subject.starts_with("re:")
                || subject.starts_with("Fwd:")
                || subject.starts_with("FW:");

           // Suspicious: has In-Reply-To but no References header
           // (legitimate mail clients usually include References)
            if references.is_none() && is_reply_subject {
                return Some((
                    W_REPLY_CHAIN_ANOMALY * 0.6,
                    Evidence {
                        description: "Reply email missing References header (possibly spoofed reply chain)"
                            .to_string(),
                        location: Some("In-Reply-To".to_string()),
                        snippet: Some(reply_id.clone()),
                    },
                ));
            }

           // Suspicious: reply claims to be from a thread but neither sender
           // nor recipient domain appears in References
            if let Some((_, refs)) = references {
                let rcpt_domains: HashSet<&str> = rcpt_to
                    .iter()
                    .filter_map(|r| r.rsplit('@').next())
                    .collect();

                let sender_domain = mail_from.and_then(|addr| addr.rsplit('@').next());

                let ref_domains: HashSet<&str> = refs
                    .split_whitespace()
                    .filter_map(|r| r.trim_matches(|c| c == '<' || c == '>').rsplit('@').next())
                    .collect();

               // Check if sender domain appears in References -> normal for legitimate replies
               // (e.g., internal email threads)
                let sender_in_refs =
                    sender_domain.is_some_and(|sd| ref_domains.iter().any(|rd| rd.contains(sd)));

               // Only flag if NEITHER sender nor recipient domain appears in refs
                if !ref_domains.is_empty()
                    && !rcpt_domains.is_empty()
                    && rcpt_domains.is_disjoint(&ref_domains)
                    && !sender_in_refs
                {
                    return Some((
                        W_REPLY_CHAIN_ANOMALY,
                        Evidence {
                            description: "Reply chain domains completely mismatch sender/recipient domains"
                                .to_string(),
                            location: Some("References".to_string()),
                            snippet: Some(refs.chars().take(200).collect()),
                        },
                    ));
                }
            }
        }

        None
    }

   /// Check for suspicious mail client fingerprints
    fn check_client_fingerprint(&self, headers: &[(String, String)]) -> Option<(f64, Evidence)> {
       // Check X-Mailer and User-Agent headers
        for (key, value) in headers {
            let k = key.to_ascii_lowercase();
            if k == "x-mailer" || k == "user-agent" {
                let v_lower = value.to_ascii_lowercase();
                for agent in &self.suspicious_agents {
                    if v_lower.contains(agent) {
                        return Some((
                            W_CLIENT_FINGERPRINT,
                            Evidence {
                                description: format!(
                                    "Suspicious email client fingerprint: {} = \"{}\"",
                                    key, value
                                ),
                                location: Some(key.clone()),
                                snippet: Some(value.clone()),
                            },
                        ));
                    }
                }
            }
        }

       // Check for missing standard headers (legitimate clients always include these)
        let has_mime_version = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("mime-version"));
        let has_content_type = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));

        if !has_mime_version && !has_content_type {
            return Some((
                W_CLIENT_FINGERPRINT * 0.5,
                Evidence {
                    description:
                        "Missing MIME-Version and Content-Type headers (non-standard email client)"
                            .to_string(),
                    location: Some("headers".to_string()),
                    snippet: None,
                },
            ));
        }

        None
    }

   /// Check envelope vs header mismatch (MAIL FROM vs From header)
    fn check_envelope_mismatch(
        &self,
        mail_from: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<(f64, Evidence)> {
        let envelope_from = mail_from?;
        let header_from = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))
            .map(|(_, v)| v.as_str())?;

       // Extract domain from envelope (handle "Name <user@domain>" format)
        let env_email = if let Some(start) = envelope_from.find('<') {
            if let Some(end) = envelope_from[start..].find('>') {
                &envelope_from[start + 1..start + end]
            } else {
                envelope_from.trim()
            }
        } else {
            envelope_from.trim()
        };
        let env_domain = env_email
            .rsplit('@')
            .next()
            .filter(|d| !d.is_empty())?
            .to_ascii_lowercase();

       // Extract domain from header (may have display name, quoted strings, encoded words)
        let header_email = if let Some(start) = header_from.rfind('<') {
            if let Some(end) = header_from[start..].find('>') {
                &header_from[start + 1..start + end]
            } else {
                header_from.trim()
            }
        } else {
            header_from.trim()
        };
        let hdr_domain = header_email
            .rsplit('@')
            .next()
            .filter(|d| !d.is_empty())?
            .to_ascii_lowercase();

        if env_domain != hdr_domain {
            return Some((
                W_ENVELOPE_MISMATCH,
                Evidence {
                    description: format!(
                        "Envelope sender domain mismatches email header: MAIL FROM=@{} vs From=@{}",
                        env_domain, hdr_domain
                    ),
                    location: Some("MAIL FROM / From header".to_string()),
                    snippet: Some(format!(
                        "envelope: {} | header: {}",
                        envelope_from, header_from
                    )),
                },
            ));
        }

        None
    }
}

#[async_trait]
impl SecurityModule for IdentityAnomalyModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let headers = &ctx.session.content.headers;

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

       // 1. Display name mismatch / impersonation
        if let Some((score, ev)) = self.check_display_name_mismatch(headers) {
            total_score += score;
            categories.push("display_name_spoof".to_string());
            evidence.push(ev);
        }

       // 2. Reply chain anomaly
       // Skip internal senders: internal users forwarding/replying is normal behavior
        let sender_is_internal = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|mf| mf.split('@').nth(1))
            .is_some_and(|d| ctx.is_internal_domain(&d.to_lowercase()));
        if !sender_is_internal
            && let Some((score, ev)) = self.check_reply_chain_anomaly(
                headers,
                &ctx.session.rcpt_to,
                ctx.session.mail_from.as_deref(),
            )
        {
            total_score += score;
            categories.push("reply_chain_anomaly".to_string());
            evidence.push(ev);
        }

       // 3. Client fingerprint
        if let Some((score, ev)) = self.check_client_fingerprint(headers) {
            total_score += score;
            categories.push("suspicious_client".to_string());
            evidence.push(ev);
        }

       // 4. Envelope mismatch
        if let Some((score, ev)) =
            self.check_envelope_mismatch(ctx.session.mail_from.as_deref(), headers)
        {
            total_score += score;
            categories.push("envelope_mismatch".to_string());
            evidence.push(ev);
        }

       // 5. First-contact detection (DB-backed)
       // Check if sender domain has ever appeared in session history -> first contact detection
       // Skip internal domains from this check
        if let Some(ref db) = self.db
            && let Some(ref mail_from) = ctx.session.mail_from
            && let Some(sender_domain) = mail_from.split('@').nth(1)
        {
            let sender_domain_lower = sender_domain.to_lowercase();
           // Skip internal domains (dynamic detection + hardcoded)
            let is_internal = ctx.is_internal_domain(&sender_domain_lower)
                || sender_domain_lower == "corp-internal.com";

            if !is_internal {
                let session_id = ctx.session.id.to_string();
                match db
                    .count_sender_domain_history(&sender_domain_lower, &session_id)
                    .await
                {
                    Ok(0) => {
                        total_score += W_FIRST_CONTACT;
                        categories.push("first_contact".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "First contact: domain {} has never sent email to this organization in history",
                                sender_domain_lower
                            ),
                            location: Some("envelope:MAIL_FROM".to_string()),
                            snippet: Some(mail_from.clone()),
                        });
                    }
                    Ok(_) => {} // Known sender domain, no additional risk
                    Err(e) => {
                        tracing::warn!("First-contact DB query failed: {}", e);
                    }
                }
            }
        }

       // 6. Sender domain randomness detection (DGA-like domains)
        if let Some(ref mail_from) = ctx.session.mail_from
            && let Some(sender_domain) = mail_from.split('@').nth(1)
        {
            let sender_domain_lower = sender_domain.to_ascii_lowercase();
            
            let is_internal = ctx.internal_domains.iter().any(|d| {
                sender_domain_lower == *d
                    || sender_domain_lower.ends_with(&format!(".{d}"))
            });

            let main_part = sender_domain.split('.').next().unwrap_or("");
            
            
           // (a) 3+ consecutive consonants -> likely random/DGA (snajgc, bncgjwl)
           // (b) Short mixed alphanumeric -> likely random (8t5om, ycgg4)
           // Excludes pinyin+English names (qingcloud = qing+cloud)
           // Excludes known domains (example.com, support.example.com)
            if main_part.len() >= 4 && !is_pinyin_english_name(main_part) && !is_internal {
                let mut is_random = false;
                let mut reason = String::new();

               // (a): Check for 3+ consecutive consonants
                let consecutive_consonants = {
                    let mut max_run = 0u32;
                    let mut run = 0u32;
                    for ch in main_part.chars() {
                        if "bcdfghjklmnpqrstvwxyz".contains(ch.to_ascii_lowercase()) {
                            run += 1;
                            if run > max_run {
                                max_run = run;
                            }
                        } else {
                            run = 0;
                        }
                    }
                    max_run
                };
                if consecutive_consonants >= 3 {
                    is_random = true;
                    reason = format!("{} consecutive consonants", consecutive_consonants);
                }

               // (b): Short mixed alphanumeric (8t5om, ycgg4, 2fkje0)
                if !is_random && main_part.len() <= 8 {
                    let has_digit = main_part.chars().any(|c| c.is_ascii_digit());
                    let has_alpha = main_part.chars().any(|c| c.is_ascii_alphabetic());
                    let alpha_count = main_part
                        .chars()
                        .filter(|c| c.is_ascii_alphabetic())
                        .count();
                    
                    if has_digit && has_alpha && alpha_count <= 5 {
                        is_random = true;
                        reason = "short mixed alphanumeric domain".to_string();
                    }
                }

                if is_random {
                    total_score += 0.25;
                    categories.push("random_domain".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Sender domain {} likely random/DGA-generated ({})",
                            sender_domain, reason
                        ),
                        location: Some("envelope:MAIL_FROM".to_string()),
                        snippet: Some(mail_from.clone()),
                    });
                }
            }
        }

       // --- Random username detection (e.g., pvzpfvq@hleg.com, ktipfnl@udcoraqhs.com) ---
       // Skips internal domains: Chinese pinyin usernames (yybdyy, wnssh) look random but aren't
       // Skips pinyin+English decomposable usernames (e.g., weixinmphelper, alipaynotify)
        if let Some(ref mail_from) = ctx.session.mail_from
            && let Some(username) = mail_from.split('@').next()
            && let Some(domain) = mail_from.split('@').nth(1)
            && !ctx.is_internal_domain(domain)
        {
           // Pure alpha username, 5+ chars, 4+ consecutive consonants -> likely randomly generated
            if username.len() >= 5
                && username.chars().all(|c| c.is_ascii_alphabetic())
                && !is_pinyin_english_name(&username.to_ascii_lowercase())
            {
                let max_consonant_run = {
                    let mut max_run = 0u32;
                    let mut run = 0u32;
                    for ch in username.chars() {
                        if "bcdfghjklmnpqrstvwxyz".contains(ch.to_ascii_lowercase()) {
                            run += 1;
                            if run > max_run {
                                max_run = run;
                            }
                        } else {
                            run = 0;
                        }
                    }
                    max_run
                };
                if max_consonant_run >= 4 {
                    total_score += 0.20;
                    categories.push("random_sender".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Sender username {} contains {} consecutive consonants, likely randomly generated address",
                            username, max_consonant_run
                        ),
                        location: Some("envelope:MAIL_FROM".to_string()),
                        snippet: Some(mail_from.clone()),
                    });
                }
            }
        }

       // Compound signal: Envelope forgery + random sender/domain + first contact
       // All 3 together form a classic spoofing attack pattern with elevated risk
        let has_envelope = categories.contains(&"envelope_mismatch".to_string());
        let has_random = categories.contains(&"random_sender".to_string())
            || categories.contains(&"random_domain".to_string());
        let has_first = categories.contains(&"first_contact".to_string());
        if has_envelope && has_random && has_first {
            total_score += 0.25;
            evidence.push(Evidence {
                description: "Compound identity spoofing: envelope forgery + random sender + first contact — classic attack pattern".to_string(),
                location: Some("compound_signal".to_string()),
                snippet: None,
            });
        } else if has_envelope && has_random {
           // Envelope forgery + random sender (without first contact) still noteworthy
            total_score += 0.15;
            evidence.push(Evidence {
                description: "Compound identity spoofing: envelope forgery + random sender".to_string(),
                location: Some("compound_signal".to_string()),
                snippet: None,
            });
        }

        total_score = total_score.min(MAX_RAW_SCORE);
        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No identity behavior anomalies found",
                duration_ms,
            ));
        }

        categories.dedup();

       // Confidence: moderate (0.70) since these are heuristic checks
        let confidence = 0.70;
        let bpa = Bpa::from_score_confidence(total_score, confidence);

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories,
            summary: format!(
                "Identity behavior anomaly detection found {} anomalies, composite score {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(bpa),
            engine_id: Some("identity_anomaly".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinyin_english_names_not_random() {
       // All legitimate pinyin + English word combinations, should not be flagged as random
        assert!(
            is_pinyin_english_name("weixinmphelper"),
            "weixinmphelper = weixin+mp+helper"
        );
        assert!(
            is_pinyin_english_name("alipaynotify"),
            "alipaynotify = ali+pay+notify"
        );
        assert!(
            is_pinyin_english_name("dingdingbot"),
            "dingdingbot = ding+ding+bot"
        );
        assert!(is_pinyin_english_name("wangyi"), "wangyi = wang+yi");
        assert!(is_pinyin_english_name("zhifubao"), "zhifubao = zhi+fu+bao");
        assert!(
            is_pinyin_english_name("huaweicloud"),
            "huaweicloud = hua+wei+cloud"
        );
        assert!(is_pinyin_english_name("xiaomi"), "xiaomi = xiao+mi");
        assert!(
            is_pinyin_english_name("systemadmin"),
            "systemadmin = system+admin"
        );
        assert!(
            is_pinyin_english_name("noreply"),
            "noreply = no+re+ply... hmm"
        );
        assert!(is_pinyin_english_name("testmail"), "testmail = test+mail");
    }

    #[test]
    fn test_random_names_detected() {
       // Random strings that cannot be decomposed into pinyin or English words
        assert!(!is_pinyin_english_name("pvzpfvq"), "pvzpfvq is random");
        assert!(!is_pinyin_english_name("ktipfnl"), "ktipfnl is random");
        assert!(!is_pinyin_english_name("xhjqwzk"), "xhjqwzk is random");
        assert!(!is_pinyin_english_name("bdfghjk"), "bdfghjk is random");
    }

    #[test]
    fn test_human_readable_brand_labels_not_treated_as_random() {
        assert!(is_human_readable_domain_label("hundsun"));
        assert!(is_human_readable_domain_label("smartx"));
        assert!(is_human_readable_domain_label("aishu"));
        assert!(!is_human_readable_domain_label("xvkrnbstq"));
    }
}
