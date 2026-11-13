use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::module::{RunMode, ThreatLevel};

/// Pipeline configuration (stored as JSON in PostgreSQL config table)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    pub modules: Vec<ModuleConfig>,
    #[serde(default)]
    pub verdict_config: VerdictConfig,
}

fn default_version() -> u32 {
    1
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            version: 1,
            modules: default_modules(),
            verdict_config: VerdictConfig::default(),
        }
    }
}

impl PipelineConfig {
    /// Backfill modules added in newer binaries into DB-stored pipeline configs.
    ///
    /// Existing module entries are preserved exactly as configured; only missing
    /// defaults are appended in the default configuration order.
    pub fn merge_default_modules(&mut self) -> Vec<String> {
        let mut existing_ids: HashSet<String> = self
            .modules
            .iter()
            .map(|module| module.id.clone())
            .collect();
        let mut added = Vec::new();

        for default_module in default_modules() {
            if existing_ids.insert(default_module.id.clone()) {
                added.push(default_module.id.clone());
                self.modules.push(default_module);
            }
        }

        added
    }

    /// Reset unsafe verdict settings to the compiled defaults.
    pub fn repair_unsafe_verdict_config(&mut self) -> Option<Vec<String>> {
        match self.verdict_config.validate() {
            Ok(()) => None,
            Err(violations) => {
                self.verdict_config = VerdictConfig::default();
                Some(violations)
            }
        }
    }

    /// Validate dependencies used by conditional module execution.
    ///
    /// A threat-level threshold must name the module whose result it examines;
    /// otherwise a concurrently running DAG could make the decision depend on
    /// which unrelated module happens to finish first.
    pub fn validate_conditions(&self) -> Result<(), Vec<String>> {
        let configured: HashMap<&str, &ModuleConfig> = self
            .modules
            .iter()
            .map(|module| (module.id.as_str(), module))
            .collect();
        let mut violations = Vec::new();

        for module in &self.modules {
            if !module.enabled {
                continue;
            }
            let Some(condition) = &module.condition else {
                continue;
            };

            if condition.min_threat_level.is_some() && condition.depends_module.is_none() {
                violations.push(format!(
                    "module '{}' sets min_threat_level without depends_module",
                    module.id
                ));
            }

            if let Some(dependency) = condition.depends_module.as_deref() {
                if dependency == module.id.as_str() {
                    violations.push(format!("module '{}' cannot depend on itself", module.id));
                } else if let Some(dependency_config) = configured.get(dependency) {
                    if !dependency_config.enabled {
                        violations.push(format!(
                            "module '{}' depends on disabled module '{}'",
                            module.id, dependency
                        ));
                    }
                } else {
                    violations.push(format!(
                        "module '{}' depends on unknown module '{}'",
                        module.id, dependency
                    ));
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Per-module configuration in the pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: RunMode,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionConfig>,
}

fn default_true() -> bool {
    true
}

/// Condition for conditional module execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionConfig {
    /// Only run if the configured dependency's threat level is at least this.
    /// Must be used together with `depends_module` for deterministic DAG behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_threat_level: Option<ThreatLevel>,
    /// Only run after this module completed; also selects the result inspected
    /// by `min_threat_level` when that threshold is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_module: Option<String>,
}

/// Verdict aggregation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictConfig {
    /// Authoritative D-S model. Retired stored selectors migrate to V2 on load.
    #[serde(
        default = "default_aggregation",
        deserialize_with = "deserialize_aggregation"
    )]
    pub aggregation: String,
    /// Module (Default 1.0)
    #[serde(default)]
    pub weights: HashMap<String, f64>,
    /// (Used for, Name: content/attachment/link/package/semantic)
    #[serde(default)]
    pub pillar_weights: HashMap<String, f64>,
    /// Risk in the range `\[0, 1\]`. Risk = `b + u`.
    /// 0.7 = " of 70% When Process" (priority)
    #[serde(default = "default_eta")]
    pub eta: f64,
    /// Engine override (8x8 flat row-major,)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_matrix: Option<Vec<f64>>,
    /// Engine override (Engine label,if "sender_reputation")
    #[serde(default)]
    pub engine_weights: HashMap<String, f64>,
    /// TBM v5.0: Default (Module For Useof open-world leakage)
    #[serde(default = "default_epsilon")]
    pub default_epsilon: f64,
    /// Read/write compatibility field for historical configurations; V2 does not use it.
    #[serde(default = "default_alert_belief_threshold")]
    pub alert_belief_threshold: f64,
    /// Multiplier for an eligible source's risk floor in `clustered_ds_v2`.
    /// The default is 1.0; validation prevents the factor from discounting the source score.
    #[serde(default = "default_alert_floor_factor")]
    pub alert_floor_factor: f64,
    /// Minimum number of distinct runtime causal keys for `clustered_ds_v2` convergence.
    /// The breaker also requires at least two evidence clusters and a native eligible anchor.
    /// Default: 2.
    #[serde(default = "default_convergence_min_modules")]
    pub convergence_min_modules: u32,
    /// Base risk floor when `clustered_ds_v2` convergence qualifies.
    /// A contextual-only cap can later reduce the result; default: 0.40.
    #[serde(default = "default_convergence_base_floor")]
    pub convergence_base_floor: f64,
    /// Minimum normalized source score counted by `clustered_ds_v2` convergence.
    /// The serialized field keeps its historical name `convergence_belief_threshold`.
    /// Default: 0.10.
    #[serde(default = "default_convergence_belief_threshold")]
    pub convergence_belief_threshold: f64,
}

fn default_aggregation() -> String {
    "clustered_ds_v2".to_string()
}

fn deserialize_aggregation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let name = String::deserialize(deserializer)?;
    Ok(match name.as_str() {
        "ds_murphy" | "clustered_ds_v1" | "legacy_ds_murphy" => default_aggregation(),
        _ => name,
    })
}

fn default_eta() -> f64 {
    0.30
}

fn default_epsilon() -> f64 {
    0.01
}

fn default_alert_belief_threshold() -> f64 {
    // Retained only for historical configuration compatibility.
    0.20
}

fn default_alert_floor_factor() -> f64 {
    // Preserve eligible source strength in clustered_ds_v2; never discount it.
    1.0
}

fn default_convergence_min_modules() -> u32 {
    // downgradeLow 2: independentModuleSame Mark enough ofConverge According to.
    // value 3 ModuledetectScenario.
    2
}

fn default_convergence_base_floor() -> f64 {
    // Base floor for qualified convergence, before any contextual-only cap.
    0.40
}

fn default_convergence_belief_threshold() -> f64 {
    // Historical field name; clustered_ds_v2 compares normalized source score.
    0.10
}

/// Default
pub const DEFAULT_PILLAR_WEIGHTS: &[(&str, f64)] = &[
    ("content", 1.0),
    ("attachment", 1.0),
    ("link", 1.0),
    ("package", 0.8),
    ("semantic", 0.7),
];

/// Noisy-OR modelConstant
pub const DIVERSITY_BETA: f64 = 0.20; // Signal large
pub const DIVERSITY_THRESHOLD: f64 = 0.05; // SignalValidThreshold
pub const COMBO_GAMMA: f64 = 0.25; // Danger headroom
pub const TRUST_DISCOUNT_FACTOR: f64 = 0.40; // large
pub const TOTAL_PILLARS: f64 = 5.0; // total

/// Allowed aggregation strategy names.
const ALLOWED_AGGREGATION_STRATEGIES: &[&str] =
    &["clustered_ds_v2", "noisy_or", "weighted_max", "tbm_v5"];

impl VerdictConfig {
    /// Get (priorityUseConfigurationvalue,downgradelevel Defaultvalue)
    pub fn pillar_weight(&self, pillar: &str) -> f64 {
        if let Some(&w) = self.pillar_weights.get(pillar) {
            return w;
        }
        DEFAULT_PILLAR_WEIGHTS
            .iter()
            .find(|(name, _)| *name == pillar)
            .map(|(_, w)| *w)
            .unwrap_or(1.0)
    }

    /// Validate all security-critical fields in VerdictConfig.
    ///
    /// Returns `Ok(())` if all fields are within safe operational ranges,
    /// or `Err(Vec<String>)` listing every violation found.
    ///
    /// # Safety invariants (from AGENTS.md project rules)
    /// - `alert_floor_factor` >= 1.0 — the default strategy cannot discount eligible source scores
    /// - `convergence_base_floor` >= 0.40 — base floor for qualified convergence; contextual caps may lower it
    /// - `convergence_belief_threshold` <= 0.10 — historical name; the default compares source score
    /// - Circuit breaker thresholds must not be set to values that disable detection
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // ── aggregation strategy ──
        if !ALLOWED_AGGREGATION_STRATEGIES.contains(&self.aggregation.as_str()) {
            errors.push(format!(
                "aggregation must be one of {:?}, got \"{}\"",
                ALLOWED_AGGREGATION_STRATEGIES, self.aggregation
            ));
        }

        // ── eta (uncertainty → risk conversion factor) ──
        // Must be in (0, 1]; 0 would discard all uncertainty signal.
        if self.eta <= 0.0 || self.eta > 1.0 {
            errors.push(format!("eta must be in (0.0, 1.0], got {}", self.eta));
        }

        // ── default_epsilon (open-world leakage mass) ──
        // Must be in (0, 0.5]; 0 breaks DS math, >0.5 floods uncertainty.
        if self.default_epsilon <= 0.0 || self.default_epsilon > 0.5 {
            errors.push(format!(
                "default_epsilon must be in (0.0, 0.5], got {}",
                self.default_epsilon
            ));
        }

        // ── alert_belief_threshold (legacy_ds_murphy only) ──
        // Keep the persisted compatibility field within its supported range.
        if self.alert_belief_threshold < 0.0 || self.alert_belief_threshold > 0.60 {
            errors.push(format!(
                "alert_belief_threshold must be in [0.0, 0.60], got {}",
                self.alert_belief_threshold
            ));
        }

        // ── alert_floor_factor (must be >= 1.0) ──
        // The default clustered path applies it to an eligible source score;
        // requiring >= 1.0 prevents discounting. The legacy path applies it to module belief.
        // Upper bound 3.0 limits amplification.
        if self.alert_floor_factor < 1.0 || self.alert_floor_factor > 3.0 {
            errors.push(format!(
                "alert_floor_factor must be in [1.0, 3.0], got {}",
                self.alert_floor_factor
            ));
        }

        // ── convergence_min_modules ──
        // 0 disables convergence breaker entirely (dangerous), max 10 is reasonable.
        // Must be >= 1 to keep convergence detection functional.
        if self.convergence_min_modules < 1 || self.convergence_min_modules > 10 {
            errors.push(format!(
                "convergence_min_modules must be in [1, 10], got {}",
                self.convergence_min_modules
            ));
        }

        // ── convergence_base_floor (must be >= 0.40) ──
        // This is the base for qualified convergence, subject to contextual-only caps.
        // Upper bound 0.85 prevents convergence alone from reaching Critical.
        if self.convergence_base_floor < 0.40 || self.convergence_base_floor > 0.85 {
            errors.push(format!(
                "convergence_base_floor must be in [0.40, 0.85], got {}",
                self.convergence_base_floor
            ));
        }

        // ── convergence_belief_threshold (serialized compatibility name) ──
        // clustered_ds_v2 compares normalized source score, and requires independent
        // causal keys, distinct evidence clusters, and an eligible native anchor.
        // Must be > 0 so no-signal sources cannot count.
        if self.convergence_belief_threshold <= 0.0 || self.convergence_belief_threshold > 0.10 {
            errors.push(format!(
                "convergence_belief_threshold must be in (0.0, 0.10], got {}",
                self.convergence_belief_threshold
            ));
        }

        // ── pillar_weights (per-pillar multipliers) ──
        // Each weight must be positive and ≤ 5.0 (prevent single-pillar domination).
        for (pillar, &weight) in &self.pillar_weights {
            if !(0.0..=5.0).contains(&weight) {
                errors.push(format!(
                    "pillar_weights[\"{}\"] must be in [0.0, 5.0], got {}",
                    pillar, weight
                ));
            }
        }

        // ── engine_weights (per-engine multipliers) ──
        // Same constraint: non-negative and bounded.
        for (engine, &weight) in &self.engine_weights {
            if !(0.0..=5.0).contains(&weight) {
                errors.push(format!(
                    "engine_weights[\"{}\"] must be in [0.0, 5.0], got {}",
                    engine, weight
                ));
            }
        }

        // ── module weights ──
        for (module, &weight) in &self.weights {
            if !(0.0..=5.0).contains(&weight) {
                errors.push(format!(
                    "weights[\"{}\"] must be in [0.0, 5.0], got {}",
                    module, weight
                ));
            }
        }

        // ── correlation_matrix (optional, 8×8 flat row-major) ──
        if let Some(ref matrix) = self.correlation_matrix {
            if matrix.len() != 64 {
                errors.push(format!(
                    "correlation_matrix must have exactly 64 elements (8×8), got {}",
                    matrix.len()
                ));
            }
            for (i, &val) in matrix.iter().enumerate() {
                if !val.is_finite() || !(-1.0..=1.0).contains(&val) {
                    errors.push(format!(
                        "correlation_matrix[{}] must be in [-1.0, 1.0] and finite, got {}",
                        i, val
                    ));
                    break; // one error is enough for the matrix
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Default for VerdictConfig {
    fn default() -> Self {
        Self {
            aggregation: default_aggregation(),
            weights: HashMap::new(),
            pillar_weights: HashMap::new(),
            eta: 0.30,
            correlation_matrix: None,
            engine_weights: HashMap::new(),
            default_epsilon: 0.01,
            alert_belief_threshold: 0.20,
            alert_floor_factor: 1.0,
            convergence_min_modules: 2,
            convergence_base_floor: 0.40,
            convergence_belief_threshold: 0.10,
        }
    }
}

/// AI Service Configuration (store config table, key = 'ai_service_config')
#[derive(Clone, Serialize, Deserialize)]
pub struct AiServiceConfig {
    /// Whether the AI analysis service is enabled (frontend/wizard ai_enabled toggle)
    #[serde(default = "default_ai_enabled")]
    pub enabled: bool,
    /// Python AI ServiceAddress
    #[serde(default = "default_ai_url")]
    pub service_url: String,
    /// LLM For: "claude" | "openai" | "local"
    #[serde(default = "default_ai_provider")]
    pub provider: String,
    /// LLM API Key
    #[serde(default)]
    pub api_key: String,
    /// modelName
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// Temperature (0.0 - 1.0)
    #[serde(default = "default_temperature")]
    pub temperature: f64,
    /// large Token
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// RequestTimeout ()
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
}

impl std::fmt::Debug for AiServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiServiceConfig")
            .field("enabled", &self.enabled)
            .field("service_url", &self.service_url)
            .field("provider", &self.provider)
            .field(
                "api_key",
                &if self.api_key.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .field("model", &self.model)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

fn default_ai_enabled() -> bool {
    std::env::var("AI_ENABLED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(false)
}
fn default_ai_url() -> String {
    std::env::var("AI_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:8900".to_string())
}
fn default_ai_provider() -> String {
    "claude".to_string()
}
fn default_ai_model() -> String {
    "claude-sonnet-4-20250514".to_string()
}
fn default_temperature() -> f64 {
    0.3
}
fn default_max_tokens() -> u32 {
    4096
}
fn default_timeout_secs() -> u32 {
    60
}

impl Default for AiServiceConfig {
    fn default() -> Self {
        Self {
            enabled: default_ai_enabled(),
            service_url: default_ai_url(),
            provider: default_ai_provider(),
            api_key: String::new(),
            model: default_ai_model(),
            temperature: default_temperature(),
            max_tokens: default_max_tokens(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

impl AiServiceConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.provider.trim(), "claude" | "openai" | "local") {
            return Err("AI provider must be claude, openai, or local".to_string());
        }
        if self.api_key.chars().count() > 4096 {
            return Err("AI API key is too long".to_string());
        }
        if self.model.chars().count() > 128 {
            return Err("AI model name is too long".to_string());
        }
        if !self.temperature.is_finite() || !(0.0..=1.0).contains(&self.temperature) {
            return Err("AI temperature must be finite and between 0 and 1".to_string());
        }
        if !(1..=8192).contains(&self.max_tokens) {
            return Err("AI max_tokens must be between 1 and 8192".to_string());
        }
        if !(1..=300).contains(&self.timeout_secs) {
            return Err("AI timeout_secs must be between 1 and 300".to_string());
        }
        Ok(())
    }
}

pub use vigilyx_soar::config::{EmailAlertConfig, WechatAlertConfig};

fn default_modules() -> Vec<ModuleConfig> {
    vec![
        ModuleConfig {
            id: "content_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "html_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "html_pixel_art".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "attach_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "attach_content".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "attach_qr_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "attach_hash".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "mime_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "header_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "link_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "link_reputation".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "link_content".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "landing_page_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "url_sandbox_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: Some(ConditionConfig {
                min_threat_level: None,
                depends_module: Some("landing_page_scan".into()),
            }),
        },
        ModuleConfig {
            id: "process_sandbox_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: Some(ConditionConfig {
                min_threat_level: None,
                depends_module: Some("landing_page_scan".into()),
            }),
        },
        ModuleConfig {
            id: "anomaly_detect".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "aitm_detect".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "rmm_detect".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "prompt_injection_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "toad_detect".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "semantic_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "domain_verify".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "identity_anomaly".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "transaction_correlation".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "av_eml_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "av_attach_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "sandbox_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: Some(ConditionConfig {
                min_threat_level: None,
                depends_module: Some("attach_scan".into()),
            }),
        },
        ModuleConfig {
            id: "yara_scan".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
        ModuleConfig {
            id: "verdict".into(),
            enabled: true,
            mode: RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODERN_PHISHING_MODULES: &[&str] = &[
        "attach_qr_scan",
        "landing_page_scan",
        "url_sandbox_scan",
        "aitm_detect",
        "rmm_detect",
        "prompt_injection_scan",
        "toad_detect",
    ];

    fn module_index(config: &PipelineConfig, id: &str) -> usize {
        config
            .modules
            .iter()
            .position(|module| module.id == id)
            .unwrap_or_else(|| panic!("missing default module {id}"))
    }

    #[test]
    fn test_default_pipeline_includes_modern_phishing_modules() {
        let config = PipelineConfig::default();

        for module_id in MODERN_PHISHING_MODULES {
            assert!(
                config
                    .modules
                    .iter()
                    .any(|module| module.id == *module_id && module.enabled),
                "default pipeline must enable {module_id}"
            );
        }
    }

    #[test]
    fn test_default_pipeline_module_ids_are_unique() {
        let config = PipelineConfig::default();
        let mut seen = HashSet::new();

        for module in &config.modules {
            assert!(
                seen.insert(module.id.as_str()),
                "duplicate default module id {}",
                module.id
            );
        }
    }

    #[test]
    fn test_default_pipeline_preserves_dependency_order() {
        let config = PipelineConfig::default();

        assert!(module_index(&config, "attach_scan") < module_index(&config, "attach_qr_scan"));
        assert!(module_index(&config, "link_scan") < module_index(&config, "landing_page_scan"));
        assert!(module_index(&config, "link_content") < module_index(&config, "landing_page_scan"));
        assert!(module_index(&config, "verdict") > module_index(&config, "aitm_detect"));
    }

    #[test]
    fn test_merge_default_modules_backfills_modern_phishing_modules() {
        let mut config = PipelineConfig::default();
        config
            .modules
            .retain(|module| !MODERN_PHISHING_MODULES.contains(&module.id.as_str()));

        let added = config.merge_default_modules();

        for module_id in MODERN_PHISHING_MODULES {
            assert!(
                added.iter().any(|added_id| added_id == module_id),
                "merge_default_modules should report added {module_id}"
            );
            assert!(
                config.modules.iter().any(|module| module.id == *module_id),
                "merge_default_modules should restore {module_id}"
            );
        }
    }

    #[test]
    fn test_repair_unsafe_verdict_config_resets_to_default() {
        let mut config = PipelineConfig {
            verdict_config: VerdictConfig {
                alert_floor_factor: 0.5,
                ..VerdictConfig::default()
            },
            ..PipelineConfig::default()
        };

        let violations = config.repair_unsafe_verdict_config();

        assert!(violations.is_some());
        assert_eq!(
            config.verdict_config.alert_floor_factor,
            VerdictConfig::default().alert_floor_factor
        );
    }

    #[test]
    fn test_default_verdict_config_passes_validation() {
        let config = VerdictConfig::default();
        assert!(
            config.validate().is_ok(),
            "Default VerdictConfig must pass validation"
        );
    }

    #[test]
    fn retired_saved_selectors_migrate_to_authoritative_v2() {
        for name in [
            "ds_murphy",
            "clustered_ds_v1",
            "legacy_ds_murphy",
            "clustered_ds_v2",
        ] {
            let config: VerdictConfig =
                serde_json::from_value(serde_json::json!({"aggregation": name})).unwrap();
            assert_eq!(config.aggregation, "clustered_ds_v2");
            assert!(config.validate().is_ok());
        }
        assert_eq!(VerdictConfig::default().aggregation, "clustered_ds_v2");
    }

    #[test]
    fn test_alert_floor_factor_below_minimum_rejected() {
        let config = VerdictConfig {
            alert_floor_factor: 0.80,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("alert_floor_factor")));
    }

    #[test]
    fn test_alert_floor_factor_above_maximum_rejected() {
        let config = VerdictConfig {
            alert_floor_factor: 5.0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("alert_floor_factor")));
    }

    #[test]
    fn test_convergence_base_floor_below_minimum_rejected() {
        let config = VerdictConfig {
            convergence_base_floor: 0.25,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("convergence_base_floor")));
    }

    #[test]
    fn test_convergence_belief_threshold_above_maximum_rejected() {
        let config = VerdictConfig {
            convergence_belief_threshold: 0.20,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.iter()
                .any(|e| e.contains("convergence_belief_threshold"))
        );
    }

    #[test]
    fn test_convergence_belief_threshold_zero_rejected() {
        let config = VerdictConfig {
            convergence_belief_threshold: 0.0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.iter()
                .any(|e| e.contains("convergence_belief_threshold"))
        );
    }

    #[test]
    fn test_convergence_min_modules_zero_rejected() {
        let config = VerdictConfig {
            convergence_min_modules: 0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("convergence_min_modules")));
    }

    #[test]
    fn test_eta_zero_rejected() {
        let config = VerdictConfig {
            eta: 0.0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("eta")));
    }

    #[test]
    fn test_epsilon_zero_rejected() {
        let config = VerdictConfig {
            default_epsilon: 0.0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("default_epsilon")));
    }

    #[test]
    fn test_invalid_aggregation_rejected() {
        let config = VerdictConfig {
            aggregation: "max_all".to_string(),
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("aggregation")));
    }

    #[test]
    fn test_alert_belief_threshold_too_high_rejected() {
        let config = VerdictConfig {
            alert_belief_threshold: 0.80,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("alert_belief_threshold")));
    }

    #[test]
    fn test_negative_pillar_weight_rejected() {
        let mut config = VerdictConfig::default();
        config.pillar_weights.insert("content".into(), -0.5);
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("pillar_weights")));
    }

    #[test]
    fn test_excessive_engine_weight_rejected() {
        let mut config = VerdictConfig::default();
        config.engine_weights.insert("test".into(), 10.0);
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("engine_weights")));
    }

    #[test]
    fn test_wrong_size_correlation_matrix_rejected() {
        let config = VerdictConfig {
            correlation_matrix: Some(vec![0.0; 10]),
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.iter().any(|e| e.contains("correlation_matrix")));
    }

    #[test]
    fn test_multiple_violations_all_reported() {
        let config = VerdictConfig {
            alert_floor_factor: 0.5,
            convergence_base_floor: 0.10,
            convergence_belief_threshold: 0.50,
            eta: 0.0,
            ..VerdictConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.len() >= 4,
            "Expected at least 4 violations, got {}: {:?}",
            err.len(),
            err
        );
    }

    #[test]
    fn test_valid_non_default_config_passes() {
        let config = VerdictConfig {
            aggregation: "noisy_or".to_string(),
            eta: 0.50,
            default_epsilon: 0.05,
            alert_belief_threshold: 0.30,
            alert_floor_factor: 1.5,
            convergence_min_modules: 3,
            convergence_base_floor: 0.50,
            convergence_belief_threshold: 0.08,
            ..VerdictConfig::default()
        };
        assert!(
            config.validate().is_ok(),
            "Valid non-default config should pass validation"
        );
    }

    #[test]
    fn test_boundary_values_accepted() {
        // All values at exact boundary (minimum/maximum allowed)
        let config = VerdictConfig {
            eta: 1.0,                           // upper bound
            default_epsilon: 0.5,               // upper bound
            alert_belief_threshold: 0.0,        // lower bound (0.0 is valid, means always trigger)
            alert_floor_factor: 1.0,            // lower bound
            convergence_min_modules: 1,         // lower bound
            convergence_base_floor: 0.40,       // lower bound
            convergence_belief_threshold: 0.10, // upper bound
            ..VerdictConfig::default()
        };
        // Note: alert_belief_threshold=0.0 triggers the > 0.60 check, but 0.0 is within [0.0, 0.60]
        assert!(
            config.validate().is_ok(),
            "Boundary values should be accepted"
        );
    }
}
