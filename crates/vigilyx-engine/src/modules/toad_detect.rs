//! TOAD — Telephone-Oriented Attack Delivery detection.
//!
//! Background
//! ----------
//! TOAD attacks are pure-text phishing emails (no attachment, no link) that
//! lure the recipient into **calling a phone number** controlled by the
//! attacker. Once on the phone, the attacker performs voice-phishing /
//! social engineering, often instructing the victim to install a remote
//! monitoring tool (covered by the `rmm_detect` module — these chain
//! together as `toad_to_rmm_chain` at the temporal layer).
//!
//! Common pretexts: subscription auto-renewal "confirmation", IRS/tax
//! notice, fraud-alert from a brand (Geek Squad, Norton, McAfee, PayPal),
//! package delivery on hold, account suspension. The hallmark is:
//!
//!   1. A spoofed brand or authority context.
//!   2. An urgency / fear hook ("if you did not authorize this...").
//!   3. A prominent phone number — typically toll-free (1-800, 0800, 950/400)
//!      or a freshly registered international number.
//!   4. **Crucially, no link / no attachment**, so URL- and attachment-based
//!      detection layers see nothing.
//!
//! Detection strategy
//! ------------------
//! We score four orthogonal signals and emit a verdict only when at least
//! the callback-verb signal is present alongside a real phone number — that
//! combination is the irreducible TOAD core. Single-signal hits stay Safe
//! to avoid swamping legitimate billing emails.
//!
//!   - `toad_callback_verb`     +0.35 (data-driven phrase list)
//!   - `toad_urgency_phrase`    +0.20 (data-driven phrase list)
//!   - `toad_brand_impersonation` +0.15 (brand mentioned but sender domain
//!     does not match)
//!   - `toad_phone_present`     +0.15 (real callable number — toll-free /
//!     international / Chinese 400/950 /
//!     Chinese mobile 1[3-9]xxxxxxxxx)
//!
//! Combo escalation:
//!   - callback_verb + phone_present + (urgency OR brand_impersonation)
//!     → +0.15 boost (`toad_combo`), pushes typical TOAD email to High.
//!
//! False-positive guards:
//!   - If the email body contains a hyperlink or attachment, this module
//!     does NOT downgrade — TOAD lures sometimes pad with one harmless
//!     link to look legitimate — but it also does not require absence of
//!     them, so legitimate phone-bearing emails (signatures, support
//!     contact lines) are caught only when they also exhibit urgency or
//!     callback verbs, which legitimate sigs do not.
//!   - Single phone in body without callback verb → no signal (signature).
//!   - Chat-record forwards already filtered upstream by content_scan.

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::LazyLock;
use std::time::Instant;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::matcher::{toad_callback_verbs, toad_urgency_phrases};
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};
use crate::module_data::module_data;

pub struct ToadDetectModule {
    meta: ModuleMetadata,
}

impl Default for ToadDetectModule {
    fn default() -> Self {
        Self::new()
    }
}

impl ToadDetectModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "toad_detect".to_string(),
                name: "TOAD (Telephone-Oriented Attack) Detection".to_string(),
                description: "Detects callback-phishing emails that lure recipients into \
                              dialing attacker-controlled phone numbers. Pure-text TOAD \
                              attacks bypass URL/attachment scanners; this module looks \
                              for the irreducible core of callback verb + real phone \
                              number + urgency/brand context."
                    .to_string(),
                pillar: Pillar::Content,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Phone-number patterns
// ---------------------------------------------------------------------------

/// US/Canada toll-free: 1-800/833/844/855/866/877/888 plus 7 more digits.
/// Also matches with separators: spaces, dashes, dots, parentheses.
static RE_US_TOLLFREE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[^0-9])((?:\+?1[\s\-.]?)?\(?(?:800|833|844|855|866|877|888)\)?[\s\-.]?\d{3}[\s\-.]?\d{4})",
    )
    .expect("us toll-free regex")
});

/// Generic international format: +<country>(1-3 digits) <8-12 digits with
/// optional separators>. Catches +44 800 ..., +1 415 ..., +86 ...
static RE_INTL_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\+\d{1,3}[\s\-.]?\d{1,4}[\s\-.]?\d{1,4}[\s\-.]?\d{2,4})")
        .expect("intl phone regex")
});

/// Chinese 400 / 950 service hotlines: 400-XXX-XXXX, 950XXXX, 95XXX.
/// `\b` does not work on CJK boundaries (Chinese chars are not word
/// characters); instead require either start-of-string or a non-digit
/// before the number.
static RE_CN_HOTLINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9])(400[\s\-.]?\d{3}[\s\-.]?\d{4}|950\d{4,5}|95\d{3})")
        .expect("cn hotline regex")
});

/// Chinese mobile 11-digit (1[3-9]XXXXXXXXX) — strict 11-digit boundary.
/// Same CJK-boundary caveat as `RE_CN_HOTLINE`.
static RE_CN_MOBILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9])(1[3-9]\d{9})(?:[^0-9]|$)").expect("cn mobile regex")
});

/// Generic 10-15 digit run with separators ("call 800-555-1234"). Used as
/// a last-resort match; only fires when callback verb is also present.
static RE_GENERIC_DIALABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9])(\d{3}[\s\-.]\d{3}[\s\-.]\d{4})(?:[^0-9]|$)")
        .expect("generic dialable regex")
});

/// Build a `(numbers, kinds)` tuple from the body. Each number appears once.
fn extract_phone_numbers(body: &str) -> (Vec<String>, Vec<&'static str>) {
    let mut found: Vec<(String, &'static str)> = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();

    fn push(
        s: &str,
        kind: &'static str,
        found: &mut Vec<(String, &'static str)>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let normalized = s.trim().to_string();
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            found.push((normalized, kind));
        }
    }

    // Use captures_iter and read group 1 (the actual phone number, without
    // the boundary char captured by the alternation).
    for caps in RE_US_TOLLFREE.captures_iter(body) {
        if let Some(m) = caps.get(1) {
            push(m.as_str(), "us_tollfree", &mut found, &mut seen);
        }
    }
    for caps in RE_CN_HOTLINE.captures_iter(body) {
        if let Some(m) = caps.get(1) {
            push(m.as_str(), "cn_hotline", &mut found, &mut seen);
        }
    }
    for caps in RE_INTL_PHONE.captures_iter(body) {
        if let Some(m) = caps.get(1) {
            push(m.as_str(), "intl", &mut found, &mut seen);
        }
    }
    for caps in RE_CN_MOBILE.captures_iter(body) {
        if let Some(m) = caps.get(1) {
            push(m.as_str(), "cn_mobile", &mut found, &mut seen);
        }
    }
    for caps in RE_GENERIC_DIALABLE.captures_iter(body) {
        if let Some(m) = caps.get(1) {
            push(m.as_str(), "generic", &mut found, &mut seen);
        }
    }

    let numbers: Vec<String> = found.iter().map(|(n, _)| n.clone()).collect();
    let kinds: Vec<&'static str> = found.iter().map(|(_, k)| *k).collect();
    (numbers, kinds)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true if `brand` is mentioned in the body but the sender domain
/// does not look like it belongs to that brand. We extract the registrable
/// core label (the second-from-rightmost dot-segment, e.g. `paypal` in
/// `service.paypal.com`) and require it to equal the brand token exactly.
///
/// This rejects `totally-not-paypal.tld` (core = `totally-not-paypal`,
/// not equal to `paypal`) while still accepting `paypal.com` and
/// `service.paypal.com`.
fn brand_mismatched(brand: &str, sender_domain: Option<&str>) -> bool {
    let domain = match sender_domain {
        Some(d) => d.to_ascii_lowercase(),
        None => return true, // no sender domain → assume mismatch
    };
    let first_token: String = brand
        .split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    if first_token.len() < 4 {
        // Short brand tokens like "ups" / "irs" cause too many false
        // positives via substring matching, so any sender domain is
        // conservatively flagged as a mismatch.
        return true;
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return true;
    }
    // Registrable core label = label immediately to the left of the TLD.
    // (Crude: doesn't handle effective-TLD list like `.co.uk`, but for
    // brand impersonation detection we'd rather false-positive on a
    // multi-label TLD than miss a brand spoof.)
    let core = labels[labels.len() - 2];
    core != first_token
}

// ---------------------------------------------------------------------------
// SecurityModule impl
// ---------------------------------------------------------------------------

#[async_trait]
impl SecurityModule for ToadDetectModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        // Build the corpus: subject + plain body. We deliberately ignore
        // body_html here because TOAD lures are almost always plain text
        // (rendering HTML would also drag in CSS-hidden noise).
        let mut corpus = String::new();
        if let Some(s) = ctx.session.subject.as_deref() {
            corpus.push_str(s);
            corpus.push('\n');
        }
        if let Some(t) = ctx.session.content.body_text.as_deref() {
            corpus.push_str(t);
        }
        if corpus.trim().is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No textual content to scan",
                start.elapsed().as_millis() as u64,
            ));
        }
        let corpus_lower = corpus.to_ascii_lowercase();

        // Aho-Corasick matchers (built once, reused across calls).
        let callback_matcher = toad_callback_verbs();
        let urgency_matcher = toad_urgency_phrases();

        // brand_list still needs to flow through `brand_mismatched`, so keep
        // it as a snapshot Vec for the closure below.
        let md = module_data();
        let brand_list = md.get_list("toad_brand_impersonation").to_vec();
        let callback_empty = md.get_list("toad_callback_verbs").is_empty();
        drop(md);

        if callback_empty {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "TOAD pattern lists not configured",
                start.elapsed().as_millis() as u64,
            ));
        }

        // Scan signals.
        let callback_hit = callback_matcher.scan(&corpus_lower).first_pattern();
        let urgency_hit = urgency_matcher.scan(&corpus_lower).first_pattern();

        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|addr| addr.split('@').nth(1))
            .map(str::to_ascii_lowercase);

        // Brand impersonation: brand mentioned in body, sender domain
        // does not contain the brand token.
        let brand_hit = brand_list.iter().find(|b| {
            let b_lower = b.to_ascii_lowercase();
            corpus_lower.contains(&b_lower) && brand_mismatched(&b_lower, sender_domain.as_deref())
        });

        let (phone_numbers, phone_kinds) = extract_phone_numbers(&corpus);
        // Allow the noisy `generic` matcher only when an explicit callback
        // verb was found — signature phone numbers in legitimate emails
        // would otherwise create noise.
        let phone_present = if callback_hit.is_some() {
            !phone_numbers.is_empty()
        } else {
            phone_kinds
                .iter()
                .any(|k| *k != "generic" && *k != "cn_mobile")
        };

        // ── Score ─────────────────────────────────────────────────────────
        let mut score: f64 = 0.0;
        let mut categories: Vec<String> = Vec::new();
        let mut evidence: Vec<Evidence> = Vec::new();

        if let Some(ref kw) = callback_hit {
            score += 0.35;
            categories.push("toad_callback_verb".to_string());
            evidence.push(Evidence {
                description: format!("Callback instruction phrase detected: '{}'", kw),
                location: Some("body".to_string()),
                snippet: None,
            });
        }
        if let Some(ref kw) = urgency_hit {
            score += 0.20;
            categories.push("toad_urgency_phrase".to_string());
            evidence.push(Evidence {
                description: format!("Urgency / fear phrase detected: '{}'", kw),
                location: Some("body".to_string()),
                snippet: None,
            });
        }
        if let Some(brand) = brand_hit {
            score += 0.15;
            categories.push("toad_brand_impersonation".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Brand '{}' mentioned in body but sender domain '{}' does not match",
                    brand,
                    sender_domain.as_deref().unwrap_or("<unknown>")
                ),
                location: Some("body".to_string()),
                snippet: None,
            });
        }
        if phone_present {
            score += 0.15;
            categories.push("toad_phone_present".to_string());
            let preview: Vec<String> = phone_numbers.iter().take(3).cloned().collect();
            evidence.push(Evidence {
                description: format!(
                    "Dialable phone number(s) found: {} (kinds={:?})",
                    preview.join(", "),
                    phone_kinds
                ),
                location: Some("body".to_string()),
                snippet: Some(preview.join(", ")),
            });
        }

        // Core combo: callback verb + phone + (urgency OR brand_impersonation).
        let combo = callback_hit.is_some()
            && phone_present
            && (urgency_hit.is_some() || brand_hit.is_some());
        if combo {
            score += 0.15;
            categories.push("toad_combo".to_string());
        }

        // Without callback verb + phone present, this is not TOAD — clear
        // any score we accumulated from urgency/brand alone (those are
        // legitimate marketing signals on their own).
        if callback_hit.is_none() || !phone_present {
            score = 0.0;
            categories.clear();
            evidence.clear();
        }

        score = score.min(1.0);
        categories.sort();
        categories.dedup();

        let threat_level = ThreatLevel::from_score(score);
        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = if threat_level == ThreatLevel::Safe {
            "No TOAD callback-phishing pattern detected".to_string()
        } else {
            format!(
                "TOAD callback-phishing pattern: {} signals, score={:.2}",
                categories.len(),
                score
            )
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: if threat_level == ThreatLevel::Safe {
                0.85
            } else {
                0.80
            },
            categories,
            summary,
            evidence,
            details: serde_json::json!({
                "score": score,
                "phone_count": phone_numbers.len(),
                "phone_kinds": phone_kinds,
                "callback_hit": callback_hit,
                "urgency_hit": urgency_hit,
                "brand_hit": brand_hit,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(if threat_level == ThreatLevel::Safe {
                Bpa::safe_analyzed()
            } else {
                Bpa::from_score_confidence(score, 0.80)
            }),
            engine_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    fn ctx_with(from: &str, subject: Option<&str>, body: Option<&str>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.5".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(from.to_string());
        session.subject = subject.map(str::to_string);
        session.content = EmailContent {
            body_text: body.map(str::to_string),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn classic_geek_squad_subscription_renewal_fires_high() {
        let module = ToadDetectModule::new();
        let body = "Dear Customer,\n\
                    Your Geek Squad subscription has been renewed for $499.99. \
                    If you did not authorize this purchase, please call us at \
                    1-855-555-0142 immediately to dispute this charge.\n\
                    Regards,\nGeek Squad Billing";
        let ctx = ctx_with(
            "billing@random-cdn-host.tld",
            Some("Subscription renewal confirmation"),
            Some(body),
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert!(
            result.threat_level >= ThreatLevel::High,
            "classic Geek Squad TOAD must reach High, got {:?}, cats={:?}",
            result.threat_level,
            result.categories
        );
        assert!(result.categories.iter().any(|c| c == "toad_callback_verb"));
        assert!(result.categories.iter().any(|c| c == "toad_phone_present"));
        assert!(result.categories.iter().any(|c| c == "toad_combo"));
    }

    #[tokio::test]
    async fn chinese_400_hotline_fraud_fires_medium_or_high() {
        let module = ToadDetectModule::new();
        let body = "尊敬的客户，您的支付宝账户检测到可疑交易, \
                    如非本人操作,请立即拨打客服热线400-123-4567办理退款。";
        let ctx = ctx_with(
            "service@random-host.cn",
            Some("支付宝账户安全提醒"),
            Some(body),
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert!(
            result.threat_level >= ThreatLevel::Medium,
            "Chinese TOAD must reach Medium+, got {:?}, cats={:?}",
            result.threat_level,
            result.categories
        );
        assert!(result.categories.iter().any(|c| c == "toad_callback_verb"));
        assert!(result.categories.iter().any(|c| c == "toad_phone_present"));
    }

    #[tokio::test]
    async fn signature_phone_only_does_not_fire() {
        // Legitimate business email with a phone in the signature.
        // No callback verb → must stay Safe.
        let module = ToadDetectModule::new();
        let body = "Hi team,\nPlease review the attached Q3 deck.\n\n\
                    -- \nJane Doe\nVP Sales\nAcme Corp\n+1 415 555 0100";
        let ctx = ctx_with("jane@acme.com", Some("Q3 deck review"), Some(body));
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "signature-only phone must not fire, cats={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn callback_verb_without_phone_does_not_fire() {
        // Marketing email mentions "call us" but no number embedded — Safe.
        let module = ToadDetectModule::new();
        let body = "Need help? Please call our sales team — see contact details on our website.";
        let ctx = ctx_with("sales@acme.com", Some("Talk to sales"), Some(body));
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "callback verb without phone must not fire, cats={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn brand_match_on_legit_paypal_does_not_count_impersonation() {
        // Sender domain contains the brand token → not impersonation,
        // but we still expect callback+phone+urgency to fire as Medium+
        // (this scenario is a real PayPal email asking the user to call,
        // which legitimate transactional mail rarely does — keeping it at
        // Medium is acceptable defensive behavior; assert Safe→Medium
        // boundary is respected).
        let module = ToadDetectModule::new();
        let body = "Your PayPal subscription has been renewed. \
                    To dispute this charge please call us at 1-888-555-0199.";
        let ctx = ctx_with(
            "service@paypal.com",
            Some("Subscription renewal"),
            Some(body),
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        // Brand mention from a matching sender domain should NOT add
        // brand_impersonation. Combo (callback+phone+urgency) still fires.
        assert!(
            !result
                .categories
                .iter()
                .any(|c| c == "toad_brand_impersonation"),
            "brand match on owning domain must not impersonate, cats={:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Medium);
    }

    #[tokio::test]
    async fn empty_email_returns_not_applicable() {
        let module = ToadDetectModule::new();
        let ctx = ctx_with("a@b.com", None, None);
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn phone_extractor_us_tollfree() {
        let (nums, kinds) = extract_phone_numbers("Call 1-800-555-1234 today.");
        assert!(!nums.is_empty(), "should detect 1-800 number");
        assert!(kinds.contains(&"us_tollfree"));
    }

    #[test]
    fn phone_extractor_cn_400_hotline() {
        let (nums, kinds) = extract_phone_numbers("拨打400-123-4567");
        assert!(!nums.is_empty());
        assert!(kinds.contains(&"cn_hotline"));
    }

    #[test]
    fn brand_mismatch_short_token_treated_as_mismatch() {
        // "ups" is short; we conservatively treat as mismatch to avoid
        // false negatives where attackers exploit short brand names.
        assert!(brand_mismatched("ups", Some("legit-mailer.com")));
    }

    #[test]
    fn brand_match_long_token_recognized() {
        assert!(!brand_mismatched("paypal", Some("service.paypal.com")));
        assert!(brand_mismatched("paypal", Some("totally-not-paypal.tld")));
    }
}
