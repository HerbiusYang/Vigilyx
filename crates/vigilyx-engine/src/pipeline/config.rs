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
   /// Risk [0,1].Risk = b + u.
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

pub use vigilyx_soar::config::EmailAlertConfig;

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
