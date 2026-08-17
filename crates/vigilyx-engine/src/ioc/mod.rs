//! IOC (Indicators of Compromise) Manager

//! Features:
//! - Auto-extract IOCs from high-threat verdicts
//! - Auto-record IOCs for internal domain spoofing (internal -> internal)
//! - CRUD operations (with attack types)
//! - CSV/JSON batch import/export
//! - Expired cleanup

mod auto_record;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use vigilyx_core::security::IocEntry;
use vigilyx_db::VigilDb;
fn normalize_ioc_indicator(ioc_type: &str, indicator: &str) -> String {
    let trimmed = indicator.trim();
    match ioc_type {
        // Trailing-dot FQDNs (e.g. "evil.com.") must collapse to the same
        // indicator as "evil.com" or the exact-match IOC lookup misses.
        "domain" | "helo" => trimmed.trim_end_matches('.').to_lowercase(),
        "email" | "hash" | "x_mailer" => trimmed.to_lowercase(),
        _ => trimmed.to_string(),
    }
}

fn normalize_ioc_verdict(verdict: &str) -> String {
    match verdict.trim().to_ascii_lowercase().as_str() {
        // The UI used to submit "safe", while the engine treats whitelist hits
        // as "clean". Store one canonical value so export and lookup agree.
        "safe" => "clean".to_string(),
        "" => "suspicious".to_string(),
        normalized => normalized.to_string(),
    }
}

/// IOC Manager
#[derive(Clone)]
pub struct IocManager {
    pub(crate) db: VigilDb,
    /// Frequency gate state for auto-recorded IP IOCs: an IP harvested from
    /// Received headers becomes eligible only after appearing in >= 2 distinct
    /// Critical sessions within a 24h window (single-mail poisoning defense).
    ip_ioc_candidates:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, IpIocCandidate>>>,
}

/// Observation window for one candidate IP in the auto-record frequency gate.
#[derive(Debug, Clone, Copy)]
struct IpIocCandidate {
    count: u32,
    window_start: std::time::Instant,
    last_session: Option<Uuid>,
}

/// Pure gate logic behind [`IocManager::note_auto_ip_candidate`].
fn note_auto_ip_candidate_in(
    map: &mut std::collections::HashMap<String, IpIocCandidate>,
    ip: &str,
    session_id: Uuid,
) -> bool {
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
    const REQUIRED: u32 = 2;
    const MAX_TRACKED: usize = 50_000;

    // Bound memory: a flood of distinct candidate IPs must not grow the map forever.
    if map.len() >= MAX_TRACKED {
        map.clear();
    }
    let now = std::time::Instant::now();
    let entry = map.entry(ip.to_string()).or_insert(IpIocCandidate {
        count: 0,
        window_start: now,
        last_session: None,
    });
    if now.duration_since(entry.window_start) > WINDOW {
        entry.count = 0;
        entry.window_start = now;
        entry.last_session = None;
    }
    // Same session re-evaluated (e.g. rescan): never double-count.
    if entry.last_session == Some(session_id) {
        return false;
    }
    entry.count += 1;
    entry.last_session = Some(session_id);
    if entry.count >= REQUIRED {
        // Re-arm: eligibility is consumed so a burst does not re-write repeatedly.
        entry.count = 0;
        entry.window_start = now;
        true
    } else {
        false
    }
}

impl IocManager {
    pub fn new(db: VigilDb) -> Self {
        Self {
            db,
            ip_ioc_candidates: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Frequency gate for auto-recorded IP IOCs.
    ///
    /// IPs harvested from email headers are attacker-influenceable (forged
    /// Received chains), so a single Critical mail must not be enough to seed
    /// a malicious IP IOC. The IP becomes eligible only when observed in at
    /// least 2 distinct sessions within 24 hours. Returns true when this
    /// observation makes the IP eligible.
    pub(crate) fn note_auto_ip_candidate(&self, ip: &str, session_id: Uuid) -> bool {
        let mut guard = self
            .ip_ioc_candidates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        note_auto_ip_candidate_in(&mut guard, ip, session_id)
    }

    /// Check if indicator is whitelisted (verdict=clean)
    /// Pre-check before auto-recording to avoid overwriting manually added whitelist entries
    pub(crate) async fn is_whitelisted(&self, ioc_type: &str, indicator: &str) -> bool {
        let indicator = normalize_ioc_indicator(ioc_type, indicator);
        match self.db.find_ioc(ioc_type, &indicator).await {
            Ok(Some(ioc)) => matches!(ioc.verdict.to_ascii_lowercase().as_str(), "clean" | "safe"),
            _ => false,
        }
    }

    /// Lookup IOC matches (for module use)
    pub async fn check_indicator(&self, ioc_type: &str, indicator: &str) -> Option<IocEntry> {
        let indicator = normalize_ioc_indicator(ioc_type, indicator);
        match self.db.find_ioc(ioc_type, &indicator).await {
            Ok(entry) => entry,
            Err(e) => {
                warn!("IOC lookup failed for {}:{}: {}", ioc_type, indicator, e);
                None
            }
        }
    }

    /// Lookup IOC matches, excluding `source=auto` ofentry(For intel)

    /// source isolation: auto IOCs come from engine auto-recording, allowing them to be hit by intel queries
    /// Creates positive feedback loop: FP A -> auto IOC -> Email B hits IOC -> FP B -> more IOCs

    /// This method only returns IOCs from external intelligence sources (otx, vt_scrape, manual, import, admin_clean)
    /// Cutting off auto IOC self-reinforcement loops.
    pub async fn check_indicator_external_only(
        &self,
        ioc_type: &str,
        indicator: &str,
    ) -> Option<IocEntry> {
        let indicator = normalize_ioc_indicator(ioc_type, indicator);
        match self.db.find_ioc(ioc_type, &indicator).await {
            Ok(Some(ioc)) if ioc.source != "auto" => Some(ioc),
            Ok(Some(_)) => None, // auto source -
            Ok(None) => None,
            Err(e) => {
                warn!("IOC lookup failed for {}:{}: {}", ioc_type, indicator, e);
                None
            }
        }
    }

    /// Add IOC manually (with attack type)
    pub async fn add_manual(
        &self,
        indicator: String,
        ioc_type: String,
        verdict_label: String,
        confidence: f64,
        description: Option<String>,
    ) -> anyhow::Result<IocEntry> {
        self.add_manual_with_attack(
            indicator,
            ioc_type,
            verdict_label,
            confidence,
            description,
            String::new(),
        )
        .await
    }

    /// Add IOC manually (with attack type)
    pub async fn add_manual_with_attack(
        &self,
        indicator: String,
        ioc_type: String,
        verdict_label: String,
        confidence: f64,
        description: Option<String>,
        attack_type: String,
    ) -> anyhow::Result<IocEntry> {
        let now = Utc::now();
        let normalized_indicator = normalize_ioc_indicator(&ioc_type, &indicator);
        let normalized_verdict = normalize_ioc_verdict(&verdict_label);
        let ioc = IocEntry {
            id: Uuid::new_v4(),
            indicator: normalized_indicator,
            ioc_type,
            source: "manual".to_string(),
            verdict: normalized_verdict,
            confidence,
            attack_type,
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: description,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };
        self.db.upsert_ioc(&ioc).await?;
        Ok(ioc)
    }

    /// JSON batch import
    pub async fn import_batch(&self, entries: Vec<BatchIocInput>) -> anyhow::Result<ImportResult> {
        let mut imported = 0u64;
        let mut skipped = 0u64;
        let now = Utc::now();

        let mut iocs = Vec::new();
        for entry in entries {
            if entry.indicator.is_empty() || entry.ioc_type.is_empty() {
                skipped += 1;
                continue;
            }
            let normalized_indicator = normalize_ioc_indicator(&entry.ioc_type, &entry.indicator);
            let verdict = entry
                .verdict
                .as_deref()
                .map(normalize_ioc_verdict)
                .unwrap_or_else(|| "suspicious".to_string());
            iocs.push(IocEntry {
                id: Uuid::new_v4(),
                indicator: normalized_indicator,
                ioc_type: entry.ioc_type,
                source: "import".to_string(),
                verdict,
                confidence: entry.confidence.unwrap_or(0.7),
                attack_type: entry.attack_type.unwrap_or_default(),
                first_seen: now,
                last_seen: now,
                hit_count: 0,
                context: entry.context,
                expires_at: None,
                created_at: now,
                updated_at: now,
            });
        }

        match self.db.batch_upsert_iocs(&iocs).await {
            Ok(()) => imported = iocs.len() as u64,
            Err(e) => {
                warn!("Failed to batch import IOCs: {}", e);
                skipped = iocs.len() as u64;
            }
        }

        Ok(ImportResult { imported, skipped })
    }

    /// CSV Import
    pub async fn import_csv(&self, csv_content: &str) -> anyhow::Result<ImportResult> {
        let mut imported = 0u64;
        let mut skipped = 0u64;
        let now = Utc::now();

        for line in csv_content.lines().skip(1) {
            // hopstableHeader; Number of Number
            let parts = parse_csv_line(line);
            if parts.len() < 3 {
                skipped += 1;
                continue;
            }

            let indicator = parts[0].clone();
            let ioc_type = parts[1].clone();
            let verdict_label = parts
                .get(2)
                .map(|v| normalize_ioc_verdict(v))
                .unwrap_or_else(|| "suspicious".into());
            let confidence: f64 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0.7);
            let attack_type = parts.get(4).cloned().unwrap_or_default();
            let normalized_indicator = normalize_ioc_indicator(&ioc_type, &indicator);

            let ioc = IocEntry {
                id: Uuid::new_v4(),
                indicator: normalized_indicator,
                ioc_type,
                source: "import".to_string(),
                verdict: verdict_label,
                confidence,
                attack_type,
                first_seen: now,
                last_seen: now,
                hit_count: 0,
                context: Some("CSV import".to_string()),
                expires_at: None,
                created_at: now,
                updated_at: now,
            };

            match self.db.upsert_ioc(&ioc).await {
                Ok(_) => imported += 1,
                Err(e) => {
                    warn!("Failed to import IOC: {}", e);
                    skipped += 1;
                }
            }
        }

        Ok(ImportResult { imported, skipped })
    }

    /// CSV export (all)
    pub async fn export_csv(&self) -> anyhow::Result<String> {
        self.export_csv_filtered(None).await
    }

    /// CSV export (with verdict filter, paginated to avoid memory issues)
    pub async fn export_csv_filtered(&self, verdicts: Option<&[String]>) -> anyhow::Result<String> {
        // UTF-8 BOM - Excel needs BOM for correct UTF-8 encoding recognition
        let mut csv = String::from(
            "\u{FEFF}indicator,type,verdict,confidence,attack_type,source,first_seen,last_seen,hit_count,context\n",
        );

        // Paginated export: fetch in batches to avoid loading all IOCs into memory at once.
        // Verdict filtering is pushed down to DB layer for efficiency.
        const BATCH_SIZE: u32 = 10_000;
        let mut offset: u32 = 0;
        loop {
            let (items, _total) = self
                .db
                .list_ioc_filtered(None, None, None, verdicts, BATCH_SIZE, offset)
                .await?;
            if items.is_empty() {
                break;
            }
            let batch_len = items.len() as u32;
            for item in &items {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    csv_escape(&item.indicator),
                    csv_escape(&item.ioc_type),
                    csv_escape(&item.verdict),
                    item.confidence,
                    csv_escape(&item.attack_type),
                    csv_escape(&item.source),
                    item.first_seen.to_rfc3339(),
                    item.last_seen.to_rfc3339(),
                    item.hit_count,
                    csv_escape(item.context.as_deref().unwrap_or("")),
                ));
            }
            if batch_len < BATCH_SIZE {
                break;
            }
            offset += batch_len;
        }

        Ok(csv)
    }

    /// Cleanup expired IOCs
    pub async fn cleanup_expired(&self) -> anyhow::Result<u64> {
        let count = self.db.cleanup_expired_ioc().await?;
        if count > 0 {
            info!(count, "Cleaned up expired IOC entries");
        }
        Ok(count)
    }
}

/// CSV field escaping with formula injection protection (CWE-1236).

/// Prefixes cells that could be interpreted as formulas by Excel/WPS with a
/// single quote. Also handles commas, quotes, CR/LF per RFC 4180.
fn csv_escape(s: &str) -> String {
    let needs_quote = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');

    // SEC: Neutralize formula injection, including formulas hidden after leading whitespace.
    let formula_prefix = is_spreadsheet_formula_like(s);

    if formula_prefix {
        // Always quote, and prepend ' inside the quotes to defuse formulas
        format!("\"'{}\"", s.replace('"', "\"\""))
    } else if needs_quote {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn is_spreadsheet_formula_like(s: &str) -> bool {
    let Some(first) = s.as_bytes().first().copied() else {
        return false;
    };

    if matches!(first, b'\t' | b'\r' | b'\n') {
        return true;
    }

    let trimmed = s.trim_start_matches([' ', '\t', '\r', '\n']);
    matches!(
        trimmed.as_bytes().first().copied(),
        Some(b'=' | b'+' | b'-' | b'@')
    )
}

/// CSV line parsing: Supporting commas within double quotes and escaped quotes
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    // Escaped quote ""
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(c);
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// JSON batch importof Item IOC Input
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BatchIocInput {
    pub indicator: String,
    pub ioc_type: String,
    pub verdict: Option<String>,
    pub confidence: Option<f64>,
    pub attack_type: Option<String>,
    pub context: Option<String>,
}

/// CSV/JSON import result
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportResult {
    pub imported: u64,
    pub skipped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_defuses_direct_formula_cells() {
        assert_eq!(csv_escape("=cmd|'/C calc'!A0"), "\"'=cmd|'/C calc'!A0\"");
        assert_eq!(csv_escape("+SUM(1,2)"), "\"'+SUM(1,2)\"");
        assert_eq!(csv_escape("@malicious"), "\"'@malicious\"");
    }

    #[test]
    fn csv_escape_defuses_formula_cells_after_leading_whitespace() {
        assert_eq!(csv_escape(" =cmd"), "\"' =cmd\"");
        assert_eq!(csv_escape("\t=cmd"), "\"'\t=cmd\"");
        assert_eq!(csv_escape("\n=cmd"), "\"'\n=cmd\"");
    }

    #[test]
    fn csv_escape_quotes_rfc4180_special_chars() {
        assert_eq!(csv_escape("safe,value"), "\"safe,value\"");
        assert_eq!(csv_escape("safe\rvalue"), "\"safe\rvalue\"");
        assert_eq!(csv_escape("safe \"value\""), "\"safe \"\"value\"\"\"");
    }

    #[test]
    fn normalize_ioc_verdict_canonicalizes_safe_and_case() {
        assert_eq!(normalize_ioc_verdict(" Malicious "), "malicious");
        assert_eq!(normalize_ioc_verdict("SUSPICIOUS"), "suspicious");
        assert_eq!(normalize_ioc_verdict("safe"), "clean");
        assert_eq!(normalize_ioc_verdict(""), "suspicious");
    }

    #[test]
    fn normalize_ioc_indicator_trims_trailing_dot_fqdn() {
        // Trailing-dot FQDNs must collapse to the same indicator or the
        // exact-match IOC lookup misses (domain-splitting evasion).
        assert_eq!(normalize_ioc_indicator("domain", "Evil.COM."), "evil.com");
        assert_eq!(normalize_ioc_indicator("domain", "evil.com.."), "evil.com");
        assert_eq!(normalize_ioc_indicator("helo", "Mail.Evil.COM."), "mail.evil.com");
        // Non-domain types are untouched.
        assert_eq!(
            normalize_ioc_indicator("ip", "203.0.113.5"),
            "203.0.113.5"
        );
        assert_eq!(
            normalize_ioc_indicator("email", "User@Evil.COM"),
            "user@evil.com"
        );
    }

    #[test]
    fn auto_ip_candidate_requires_two_distinct_sessions() {
        let mut map = std::collections::HashMap::new();
        let first_mail = Uuid::new_v4();
        let second_mail = Uuid::new_v4();

        // Single Critical mail must not be enough to seed an IP IOC.
        assert!(!note_auto_ip_candidate_in(&mut map, "203.0.113.66", first_mail));
        // Re-evaluating the same session (rescan) must not double-count.
        assert!(!note_auto_ip_candidate_in(&mut map, "203.0.113.66", first_mail));
        // A second, distinct Critical session makes the IP eligible.
        assert!(note_auto_ip_candidate_in(&mut map, "203.0.113.66", second_mail));
        // Eligibility is consumed (re-armed) after firing.
        assert!(!note_auto_ip_candidate_in(
            &mut map,
            "203.0.113.66",
            Uuid::new_v4()
        ));
        // A different IP tracked independently.
        assert!(!note_auto_ip_candidate_in(&mut map, "198.51.100.9", first_mail));
    }
}
