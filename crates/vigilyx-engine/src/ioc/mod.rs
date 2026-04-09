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
        "domain" | "email" | "hash" | "helo" | "x_mailer" => trimmed.to_lowercase(),
        _ => trimmed.to_string(),
    }
}

/// IOC Manager
#[derive(Clone)]
pub struct IocManager {
    pub(crate) db: VigilDb,
}

impl IocManager {
    pub fn new(db: VigilDb) -> Self {
        Self { db }
    }

   /// Check if indicator is whitelisted (verdict=clean)
   /// Pre-check before auto-recording to avoid overwriting manually added whitelist entries
    pub(crate) async fn is_whitelisted(&self, ioc_type: &str, indicator: &str) -> bool {
        let indicator = normalize_ioc_indicator(ioc_type, indicator);
        match self.db.find_ioc(ioc_type, &indicator).await {
            Ok(Some(ioc)) => ioc.verdict == "clean",
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
        let ioc = IocEntry {
            id: Uuid::new_v4(),
            indicator: normalized_indicator,
            ioc_type,
            source: "manual".to_string(),
            verdict: verdict_label,
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
            iocs.push(IocEntry {
                id: Uuid::new_v4(),
                indicator: normalized_indicator,
                ioc_type: entry.ioc_type,
                source: "import".to_string(),
                verdict: entry.verdict.unwrap_or_else(|| "suspicious".to_string()),
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
            let verdict_label = parts.get(2).cloned().unwrap_or_else(|| "suspicious".into());
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

   /// CSV export (with verdict filter)
    pub async fn export_csv_filtered(&self, verdicts: Option<&[String]>) -> anyhow::Result<String> {
        let (items, _) = self.db.list_ioc(None, None, None, 100_000, 0).await?;
       // UTF-8 BOM - Excel needs BOM for correct UTF-8 encoding recognition
        let mut csv = String::from(
            "\u{FEFF}indicator,type,verdict,confidence,attack_type,source,first_seen,last_seen,hit_count,context\n",
        );

        for item in &items {
            if let Some(filter) = verdicts
                && !filter.iter().any(|v| v == &item.verdict)
            {
                continue;
            }
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

/// Prefixes cells starting with =, +, -, @, \t, \r with a single quote to prevent
/// Excel/WPS formula execution. Also handles commas, quotes, newlines per RFC 4180.
fn csv_escape(s: &str) -> String {
    let needs_quote = s.contains(',') || s.contains('"') || s.contains('\n');

   // SEC: Neutralize formula injection - prefix dangerous first-chars with single quote
    let first = s.as_bytes().first().copied().unwrap_or(0);
    let formula_prefix = matches!(first, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r');

    if formula_prefix {
       // Always quote, and prepend ' inside the quotes to defuse formulas
        format!("\"'{}\"", s.replace('"', "\"\""))
    } else if needs_quote {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
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
