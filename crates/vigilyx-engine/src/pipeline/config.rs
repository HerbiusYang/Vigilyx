use std::collections::HashMap;

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
    /// Only run if max threat level from prior modules>= this
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_threat_level: Option<ThreatLevel>,
    /// Only run if this specific module has completed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_module: Option<String>,
}

/// Verdict aggregation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictConfig {
    /// strategy: "ds_murphy" (D-S Murphy, Default) | "noisy_or" | "weighted_max"
    #[serde(default = "default_aggregation")]
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
    /// SecurityBreak/JudgeRoadhandler: Modulelevel Alert Threshold.
    /// When 1Moduleof BPA b>= value, Security,
    /// prevent D-S of Signal.
    /// 0.0 Break/JudgeRoadhandler.Default 0.20 (Mediumwait PhishingSignal).
    #[serde(default = "default_alert_belief_threshold")]
    pub alert_belief_threshold: f64,
    /// SecurityBreak/JudgeRoadhandler: due to.floor = max_module_belief * alert_floor_factor.
    /// When Result risk <floor, risk level floor.
    /// Default 0.80 (0.21 ofModule -> floor = 0.168, immediately Low level).
    #[serde(default = "default_alert_floor_factor")]
    pub alert_floor_factor: f64,
    /// SignalConvergeBreak/JudgeRoadhandler: MarkModule.
    /// When N independentModuleSame Mark Converge.
    /// Safe Module confidence=1.0 Engine Dempster CompositionMediumof Yuan.
    /// 0.Default 2.
    #[serde(default = "default_convergence_min_modules")]
    pub convergence_min_modules: u32,
    /// SignalConvergeBreak/JudgeRoadhandler: Risk.
    /// WhenConverge, risk At least value.Default 0.40 (Medium level).
    #[serde(default = "default_convergence_base_floor")]
    pub convergence_base_floor: f64,
    /// SignalConvergeBreak/JudgeRoadhandler: Module belief.
    /// only BPA belief>= valueofModule Convergecount.
    /// Default 0.10: But1 of ModuleSignal(if phishing+suspicious_params+NLP,
    /// belief 0.06~0.11) Converge. value 0.20 ClassPhishingemail.
    #[serde(default = "default_convergence_belief_threshold")]
    pub convergence_belief_threshold: f64,
}

fn default_aggregation() -> String {
    "ds_murphy".to_string()
}

fn default_eta() -> f64 {
    0.30
}

fn default_epsilon() -> f64 {
    0.01
}

fn default_alert_belief_threshold() -> f64 {
    // downgradeLow 0.20: content_scan waitModuleofMediumwait Signal(b0.21) Break/JudgeRoadhandler.
    // value 0.60 Module score>= 0.71,, Critical.
    // : Phishingemail content_scan score0.25, conf=0.85 -> b=0.21
    0.20
}

fn default_alert_floor_factor() -> f64 {
    // High 1.0: Break/JudgeRoadhandler Risk belief.
    // : b=0.47 -> floor=0.47 -> ThreatLevel::Medium (Ensure)
    // value 0.80 b=0.47 -> floor=0.374 -> Low,
    // Phishingemail(randomDomain+NLP 72%Malicious+5Module) Low.
    1.0
}

fn default_convergence_min_modules() -> u32 {
    // downgradeLow 2: independentModuleSame Mark enough ofConverge According to.
    // value 3 ModuledetectScenario.
    2
}

fn default_convergence_base_floor() -> f64 {
    // High 0.40: 2+ independentHigh ModuleConverge Medium (>= 0.40).
    // value 0.25 -> Low, Module found.
    0.40
}

fn default_convergence_belief_threshold() -> f64 {
    // downgradeLow 0.10: SignalModule(belief 0.06~0.11) ConvergeBreak/JudgeRoadhandler.
    // Scenario: xiaomi@randomDomain Phishingemail,url_analysis b=0.11 + semantic b=0.09,
    // value 0.20 Moduleall Converge -> Break/JudgeRoadhandlerDo not trigger -> Safe().
    // downgrade 0.10,url_analysis (0.11), content_scan/transaction_correlation
    // convergence_min_modules=2 Converge -> floor=0.40 -> Medium.
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
const ALLOWED_AGGREGATION_STRATEGIES: &[&str] = &[
    "ds_murphy",
    "clustered_ds_v1",
    "noisy_or",
    "weighted_max",
    "legacy_ds_murphy",
    "tbm_v5",
];

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
    /// - `alert_floor_factor` >= 1.0 — prevents high-belief modules from being discounted
    /// - `convergence_base_floor` >= 0.40 — ensures multi-module convergence reaches Medium
    /// - `convergence_belief_threshold` <= 0.10 — prevents weak multi-signal phishing misses
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

        // ── alert_belief_threshold (circuit breaker trigger) ──
        // Must be in [0, 1]. Value 0 means always trigger (aggressive), 1 means never trigger.
        // Reasonable operational range: [0.0, 0.60].
        // Values > 0.60 effectively disable the circuit breaker for all but extreme signals.
        if self.alert_belief_threshold < 0.0 || self.alert_belief_threshold > 0.60 {
            errors.push(format!(
                "alert_belief_threshold must be in [0.0, 0.60], got {}",
                self.alert_belief_threshold
            ));
        }

        // ── alert_floor_factor (AGENTS.md rule: MUST be >= 1.0) ──
        // Floor = max_module_belief * factor. Below 1.0 discounts module belief,
        // causing high-confidence detections to drop a threat level.
        // Upper bound 3.0 prevents unreasonable amplification.
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

        // ── convergence_base_floor (AGENTS.md rule: MUST be >= 0.40) ──
        // When convergence triggers, risk is at least this value.
        // Below 0.40 means convergence only guarantees Low, not Medium.
        // Upper bound 0.85 prevents convergence alone from reaching Critical.
        if self.convergence_base_floor < 0.40 || self.convergence_base_floor > 0.85 {
            errors.push(format!(
                "convergence_base_floor must be in [0.40, 0.85], got {}",
                self.convergence_base_floor
            ));
        }

        // ── convergence_belief_threshold (AGENTS.md rule: MUST be <= 0.10) ──
        // Only modules with belief >= this threshold count toward convergence.
        // Above 0.10 causes weak but consistent multi-module signals to be ignored,
        // leading to phishing false negatives.
        // Must be > 0 (otherwise every module counts, even no-signal ones).
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
            aggregation: "ds_murphy".to_string(),
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
            id: "anomaly_detect".into(),
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

    #[test]
    fn test_default_verdict_config_passes_validation() {
        let config = VerdictConfig::default();
        assert!(
            config.validate().is_ok(),
            "Default VerdictConfig must pass validation"
        );
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
