//! Validated, immutable YARA rule-pack manifest loading.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::target::ScanTarget;

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const DEFAULT_MAX_SHARDS: usize = 256;
const DEFAULT_MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_RULES: usize = 1_000_000;
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct RulePackManifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub generation: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub min_engine_version: String,
    pub sources: Vec<RulePackSourceManifest>,
}

#[derive(Debug, Deserialize)]
pub struct RulePackSourceManifest {
    pub shard_id: String,
    pub path: String,
    pub sha256: String,
    pub target: ScanTarget,
    #[serde(default)]
    pub backend: RuleBackend,
    pub license: String,
    pub license_path: String,
    pub license_sha256: String,
    pub provenance: String,
    pub version: String,
    pub rule_count: usize,
    #[serde(default = "default_quality_tier")]
    pub quality_tier: String,
    #[serde(default = "default_pack_mode")]
    pub mode: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleBackend {
    #[default]
    #[serde(rename = "yara_x")]
    YaraX,
    #[serde(rename = "libyara")]
    LibYara,
}

impl RuleBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::YaraX => "yara_x",
            Self::LibYara => "libyara",
        }
    }
}

fn default_quality_tier() -> String {
    "legacy".to_string()
}

fn default_pack_mode() -> String {
    "shadow".to_string()
}

#[derive(Debug)]
pub struct LoadedRuleSource {
    pub shard_id: String,
    pub target: ScanTarget,
    pub backend: RuleBackend,
    pub source: String,
    pub expected_rule_count: usize,
    pub license: String,
    pub provenance: String,
    pub version: String,
    pub quality_tier: String,
    pub enforce: bool,
}

#[derive(Debug, Default)]
pub struct RulePackLoad {
    pub pack_id: Option<String>,
    pub generation: Option<String>,
    pub generated_at: Option<String>,
    pub min_engine_version: Option<String>,
    pub sources: Vec<LoadedRuleSource>,
    pub declared_rules: usize,
    pub rejected_sources: Vec<String>,
    pub manifest_path: Option<PathBuf>,
}

impl RulePackLoad {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load_configured() -> Self {
        let path = std::env::var("YARA_PACK_MANIFEST").unwrap_or_default();
        if path.trim().is_empty() {
            return Self::empty();
        }
        match Self::load(Path::new(path.trim())) {
            Ok(pack) => pack,
            Err(error) => Self {
                manifest_path: Some(PathBuf::from(path.trim())),
                rejected_sources: vec![format!("manifest: {error}")],
                ..Self::default()
            },
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let metadata = fs::metadata(path).map_err(|error| format!("manifest metadata: {error}"))?;
        if metadata.len() as usize > MAX_MANIFEST_BYTES {
            return Err("manifest exceeds size limit".to_string());
        }
        let canonical_manifest = path
            .canonicalize()
            .map_err(|error| format!("manifest canonicalize: {error}"))?;
        let root = canonical_manifest
            .parent()
            .ok_or_else(|| "manifest has no parent directory".to_string())?;
        let bytes =
            fs::read(&canonical_manifest).map_err(|error| format!("manifest read: {error}"))?;
        let manifest: RulePackManifest =
            serde_json::from_slice(&bytes).map_err(|error| format!("manifest JSON: {error}"))?;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(format!(
                "unsupported manifest schema {}",
                manifest.schema_version
            ));
        }
        if manifest.pack_id.trim().is_empty() || manifest.generation.trim().is_empty() {
            return Err("pack_id and generation are required".to_string());
        }
        if !manifest.min_engine_version.trim().is_empty()
            && !version_at_least(
                env!("CARGO_PKG_VERSION"),
                manifest.min_engine_version.trim(),
            )
        {
            return Err(format!(
                "pack requires engine {} but runtime is {}",
                manifest.min_engine_version,
                env!("CARGO_PKG_VERSION")
            ));
        }

        let max_shards = env_limit("YARA_PACK_MAX_SHARDS", DEFAULT_MAX_SHARDS);
        let max_source_bytes = env_limit("YARA_PACK_MAX_SOURCE_BYTES", DEFAULT_MAX_SOURCE_BYTES);
        let max_total_bytes = env_limit("YARA_PACK_MAX_TOTAL_BYTES", DEFAULT_MAX_TOTAL_BYTES);
        let max_rules = env_limit("YARA_PACK_MAX_RULES", DEFAULT_MAX_RULES);
        if manifest.sources.len() > max_shards {
            return Err(format!("manifest has more than {max_shards} shards"));
        }
        let declared_rules = manifest.sources.iter().try_fold(0usize, |total, source| {
            if source.rule_count == 0 {
                return Err(format!("{}: rule_count must be positive", source.shard_id));
            }
            total
                .checked_add(source.rule_count)
                .filter(|total| *total <= max_rules)
                .ok_or_else(|| format!("manifest exceeds the {max_rules} rule limit"))
        })?;
        let allowed_licenses = allowed_licenses();
        let mut seen_shards = HashSet::new();
        let mut seen_paths = HashSet::new();
        let mut total_bytes = 0usize;
        let mut load = Self {
            pack_id: Some(manifest.pack_id),
            generation: Some(manifest.generation),
            generated_at: Some(manifest.generated_at),
            min_engine_version: Some(manifest.min_engine_version),
            manifest_path: Some(canonical_manifest.clone()),
            declared_rules,
            ..Self::default()
        };

        for source in manifest.sources {
            let reject = |load: &mut RulePackLoad, reason: String| {
                load.rejected_sources
                    .push(format!("{}: {reason}", source.shard_id));
            };
            if !valid_token(&source.shard_id) || !seen_shards.insert(source.shard_id.clone()) {
                reject(&mut load, "invalid or duplicate shard id".to_string());
                continue;
            }
            if !allowed_licenses.contains(&source.license.to_ascii_lowercase()) {
                reject(
                    &mut load,
                    format!("license {} is not allowed", source.license),
                );
                continue;
            }
            if source.provenance.trim().is_empty()
                || source.version.trim().is_empty()
                || !matches!(
                    source.quality_tier.as_str(),
                    "exact" | "high" | "medium" | "hunting" | "legacy" | "high_cost"
                )
            {
                reject(
                    &mut load,
                    "provenance, version and valid quality_tier are required".to_string(),
                );
                continue;
            }
            if !matches!(source.mode.as_str(), "shadow" | "enforce") {
                reject(&mut load, "mode must be shadow or enforce".to_string());
                continue;
            }
            if source.backend == RuleBackend::LibYara && source.mode != "shadow" {
                reject(
                    &mut load,
                    "libyara community shards must remain in shadow mode".to_string(),
                );
                continue;
            }
            let relative = Path::new(&source.path);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
                || !seen_paths.insert(source.path.clone())
            {
                reject(&mut load, "unsafe or duplicate relative path".to_string());
                continue;
            }
            let source_path = match root.join(relative).canonicalize() {
                Ok(path) if path.starts_with(root) => path,
                _ => {
                    reject(
                        &mut load,
                        "source escapes pack root or is missing".to_string(),
                    );
                    continue;
                }
            };
            let license_relative = Path::new(&source.license_path);
            if license_relative.is_absolute()
                || license_relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                reject(&mut load, "unsafe license path".to_string());
                continue;
            }
            let license_path = match root.join(license_relative).canonicalize() {
                Ok(path) if path.starts_with(root) => path,
                _ => {
                    reject(
                        &mut load,
                        "license file escapes pack root or is missing".to_string(),
                    );
                    continue;
                }
            };
            let license_bytes = match fs::read(&license_path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    reject(&mut load, format!("license read: {error}"));
                    continue;
                }
            };
            let license_digest = hex::encode(Sha256::digest(&license_bytes));
            if !license_digest.eq_ignore_ascii_case(source.license_sha256.trim()) {
                reject(&mut load, "license SHA-256 mismatch".to_string());
                continue;
            }
            let source_bytes = match fs::read(&source_path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    reject(&mut load, format!("source read: {error}"));
                    continue;
                }
            };
            if source_bytes.len() > max_source_bytes
                || total_bytes.saturating_add(source_bytes.len()) > max_total_bytes
            {
                reject(&mut load, "source or aggregate byte limit".to_string());
                continue;
            }
            let digest = hex::encode(Sha256::digest(&source_bytes));
            if !digest.eq_ignore_ascii_case(source.sha256.trim()) {
                reject(&mut load, "SHA-256 mismatch".to_string());
                continue;
            }
            let source_text = match String::from_utf8(source_bytes) {
                Ok(source_text) => source_text,
                Err(_) => {
                    reject(&mut load, "source is not UTF-8".to_string());
                    continue;
                }
            };
            total_bytes += source_text.len();
            load.sources.push(LoadedRuleSource {
                shard_id: source.shard_id,
                target: source.target,
                backend: source.backend,
                source: source_text,
                expected_rule_count: source.rule_count,
                license: source.license,
                provenance: source.provenance,
                version: source.version,
                quality_tier: source.quality_tier,
                enforce: source.mode == "enforce",
            });
        }

        Ok(load)
    }
}

fn env_limit(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn allowed_licenses() -> HashSet<String> {
    std::env::var("YARA_PACK_ALLOWED_LICENSES")
        .unwrap_or_else(|_| {
            "MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,DRL-1.1,DRUL-1.0,GPL-2.0-only,GPL-3.0-only"
                .to_string()
        })
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn version_at_least(current: &str, minimum: &str) -> bool {
    fn components(value: &str) -> Option<[u64; 3]> {
        let core = value.split_once('-').map(|(core, _)| core).unwrap_or(value);
        let mut parts = core.split('.');
        Some([
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ])
    }
    match (components(current), components(minimum)) {
        (Some(current), Some(minimum)) => current >= minimum,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validates_hash_path_license_and_declared_counts() {
        let directory = tempfile::tempdir().unwrap();
        let source = b"rule pack_test { condition: true }";
        fs::write(directory.path().join("generic-000.yar"), source).unwrap();
        fs::write(directory.path().join("LICENSE"), b"test license").unwrap();
        let digest = hex::encode(Sha256::digest(source));
        let license_digest = hex::encode(Sha256::digest(b"test license"));
        let manifest = serde_json::json!({
            "schema_version": 1,
            "pack_id": "test-pack",
            "generation": "g1",
            "sources": [{
                "shard_id": "generic-000",
                "path": "generic-000.yar",
                "sha256": digest,
                "target": "generic",
                "backend": "libyara",
                "license": "MIT",
                "license_path": "LICENSE",
                "license_sha256": license_digest,
                "provenance": "https://example.invalid/rules",
                "version": "abc123",
                "rule_count": 1,
                "quality_tier": "high"
            }]
        });
        let mut file = fs::File::create(directory.path().join("manifest.json")).unwrap();
        file.write_all(serde_json::to_string(&manifest).unwrap().as_bytes())
            .unwrap();

        let pack = RulePackLoad::load(&directory.path().join("manifest.json")).unwrap();
        assert_eq!(pack.declared_rules, 1);
        assert_eq!(pack.sources.len(), 1);
        assert!(pack.rejected_sources.is_empty());
        assert_eq!(pack.sources[0].target, ScanTarget::Generic);
        assert_eq!(pack.sources[0].backend, RuleBackend::LibYara);
    }

    #[test]
    fn quarantines_bad_source_without_rejecting_manifest() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("bad.yar"),
            b"rule bad { condition: true }",
        )
        .unwrap();
        fs::write(directory.path().join("LICENSE"), b"test license").unwrap();
        let license_digest = hex::encode(Sha256::digest(b"test license"));
        let manifest = serde_json::json!({
            "schema_version": 1,
            "pack_id": "test-pack",
            "generation": "g2",
            "sources": [{
                "shard_id": "bad",
                "path": "bad.yar",
                "sha256": "00",
                "target": "generic",
                "license": "MIT",
                "license_path": "LICENSE",
                "license_sha256": license_digest,
                "provenance": "https://example.invalid/rules",
                "version": "abc123",
                "rule_count": 1
            }]
        });
        fs::write(
            directory.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let pack = RulePackLoad::load(&directory.path().join("manifest.json")).unwrap();
        assert!(pack.sources.is_empty());
        assert_eq!(pack.declared_rules, 1);
        assert_eq!(pack.rejected_sources.len(), 1);
    }

    #[test]
    fn version_comparison_is_numeric_and_bounded() {
        assert!(version_at_least("1.10.0", "1.9.9"));
        assert!(version_at_least("1.10.0-alpha", "1.10.0"));
        assert!(!version_at_least("1.9.9", "1.10.0"));
        assert!(!version_at_least("not-a-version", "1.0.0"));
    }

    #[test]
    fn native_community_shards_cannot_be_enforced_directly() {
        let directory = tempfile::tempdir().unwrap();
        let source = b"rule native_test { condition: true }";
        fs::write(directory.path().join("native.yar"), source).unwrap();
        fs::write(directory.path().join("LICENSE"), b"test license").unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "pack_id": "native-test",
            "generation": "g1",
            "sources": [{
                "shard_id": "native",
                "path": "native.yar",
                "sha256": hex::encode(Sha256::digest(source)),
                "target": "generic",
                "backend": "libyara",
                "license": "MIT",
                "license_path": "LICENSE",
                "license_sha256": hex::encode(Sha256::digest(b"test license")),
                "provenance": "https://example.invalid/rules",
                "version": "abc123",
                "rule_count": 1,
                "mode": "enforce"
            }]
        });
        fs::write(
            directory.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let pack = RulePackLoad::load(&directory.path().join("manifest.json")).unwrap();
        assert!(pack.sources.is_empty());
        assert_eq!(pack.rejected_sources.len(), 1);
    }
}
