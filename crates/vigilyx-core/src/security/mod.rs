//! Security engine shared type definitions

//! These types are defined in vigilyx-core to allow both vigilyx-db and
//! vigilyx-engine to use them without circular dependencies.

//! - Type
//! - (Engine,) vigilyx-engine

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Pillar - Securityanalyze

/// Security analysis pillar
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pillar {
    Content,
    Attachment,
    Package,
    Link,
    Semantic,
}

/// Total number of pillars.
pub const PILLAR_COUNT: usize = 5;

/// All pillar variants in declaration order.
pub const ALL_PILLARS: [Pillar; PILLAR_COUNT] = [
    Pillar::Content,
    Pillar::Attachment,
    Pillar::Package,
    Pillar::Link,
    Pillar::Semantic,
];

impl Pillar {
    /// Convert to array index (0-4).
    #[inline(always)]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

impl std::fmt::Display for Pillar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pillar::Content => write!(f, "content"),
            Pillar::Attachment => write!(f, "attachment"),
            Pillar::Package => write!(f, "package"),
            Pillar::Link => write!(f, "link"),
            Pillar::Semantic => write!(f, "semantic"),
        }
    }
}

// ============================================================================
// ThreatLevel - Threat level
// ============================================================================

/// Threat severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn as_numeric(&self) -> f64 {
        match self {
            ThreatLevel::Safe => 0.0,
            ThreatLevel::Low => 0.25,
            ThreatLevel::Medium => 0.50,
            ThreatLevel::High => 0.75,
            ThreatLevel::Critical => 1.0,
        }
    }

    pub fn from_score(score: f64) -> Self {
        if score >= 0.85 {
            ThreatLevel::Critical
        } else if score >= 0.65 {
            ThreatLevel::High
        } else if score >= 0.40 {
            ThreatLevel::Medium
        } else if score >= 0.15 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Safe
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Safe => write!(f, "safe"),
            ThreatLevel::Low => write!(f, "low"),
            ThreatLevel::Medium => write!(f, "medium"),
            ThreatLevel::High => write!(f, "high"),
            ThreatLevel::Critical => write!(f, "critical"),
        }
    }
}

// BPA - Dempster-Shafer Basic Probability Assignment

/// BPA four-tuple: mass function over {Threat, Normal,, }.
///
/// Invariant: `b + d + u + epsilon 1.0` (within f64 tolerance).
/// - `b` (belief) = m({Threat}) - evidence for malicious
/// - `d` (disbelief) = m({Normal}) - evidence for benign
/// - `u` (uncertainty) = m() - uncommitted mass
/// - `epsilon` = m() - open-world leakage (TBM)
///
/// When `epsilon = 0.0` (default), this is equivalent to closed-world D-S.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct Bpa {
    pub b: f64,
    pub d: f64,
    pub u: f64,
    /// Open-world leakage rate (TBM): m().
    /// Default 0.0 = closed-world (backward compatible).
    #[serde(default)]
    pub epsilon: f64,
}

impl Bpa {
    /// Create a closed-world BPA (epsilon = 0), normalizing to ensure sum = 1.0.
    #[inline]
    pub fn new(b: f64, d: f64, u: f64) -> Self {
        let b = b.max(0.0);
        let d = d.max(0.0);
        let u = u.max(0.0);
        let sum = b + d + u;
        if sum < 1e-15 {
            return Self::vacuous();
        }
        let inv = 1.0 / sum;
        Self {
            b: b * inv,
            d: d * inv,
            u: u * inv,
            epsilon: 0.0,
        }
    }

    /// Create a TBM open-world BPA with epsilon (m()).
    /// Normalizes so that b + d + u + epsilon = 1.0.
    #[inline]
    pub fn new_tbm(b: f64, d: f64, u: f64, epsilon: f64) -> Self {
        let b = b.max(0.0);
        let d = d.max(0.0);
        let u = u.max(0.0);
        let epsilon = epsilon.max(0.0);
        let sum = b + d + u + epsilon;
        if sum < 1e-15 {
            return Self::vacuous();
        }
        let inv = 1.0 / sum;
        Self {
            b: b * inv,
            d: d * inv,
            u: u * inv,
            epsilon: epsilon * inv,
        }
    }

    /// Vacuous BPA: total uncertainty, zero information.
    #[inline(always)]
    pub const fn vacuous() -> Self {
        Self {
            b: 0.0,
            d: 0.0,
            u: 1.0,
            epsilon: 0.0,
        }
    }

    /// Fully certain malicious.
    #[inline(always)]
    pub const fn certain_threat() -> Self {
        Self {
            b: 1.0,
            d: 0.0,
            u: 0.0,
            epsilon: 0.0,
        }
    }

    /// Fully certain benign.
    #[inline(always)]
    pub const fn certain_benign() -> Self {
        Self {
            b: 0.0,
            d: 1.0,
            u: 0.0,
            epsilon: 0.0,
        }
    }

    /// Weak safe signal for modules that analyzed content and found nothing.
    ///
    /// BPA = {b=0, d=0.15, u=0.85}: "I looked and found nothing bad, but I'm
    /// 85% uncertain." Crucially, this is **not** an absorbing element in
    /// Dempster combination - threat signals from other modules pass through
    /// because u> 0.
    #[inline(always)]
    pub const fn safe_analyzed() -> Self {
        Self {
            b: 0.0,
            d: 0.15,
            u: 0.85,
            epsilon: 0.0,
        }
    }

    /// Convert legacy (score, confidence) pair to BPA (closed-world).
    #[inline]
    pub fn from_score_confidence(score: f64, confidence: f64) -> Self {
        let s = score.clamp(0.0, 1.0);
        let c = confidence.clamp(0.0, 1.0);
        Self {
            b: s * c,
            d: (1.0 - s) * c,
            u: 1.0 - c,
            epsilon: 0.0,
        }
    }

    /// Risk score: `b + u` where controls uncertainty -> threat conversion.
    /// Note: contributes through the Novelty signal, not directly in risk.
    #[inline(always)]
    pub fn risk_score(self, eta: f64) -> f64 {
        self.b + eta * self.u
    }

    /// Pignistic probability (closed-world): `b + u/2`.
    #[inline(always)]
    pub fn pignistic_threat(self) -> f64 {
        self.b + self.u * 0.5
    }

    /// TBM Pignistic probability: `b/(1-) + u/(2 (1-))`.
    /// When -> 1.0, returns 0.5 as fallback.
    #[inline]
    pub fn pignistic_tbm(self) -> f64 {
        let denom = 1.0 - self.epsilon;
        if denom < 1e-12 {
            return 0.5;
        }
        self.b / denom + self.u / (2.0 * denom)
    }

    /// Check BPA validity (sum 1.0, non-negative components).
    #[inline]
    pub fn is_valid(self) -> bool {
        self.b >= 0.0
            && self.d >= 0.0
            && self.u >= 0.0
            && self.epsilon >= 0.0
            && (self.b + self.d + self.u + self.epsilon - 1.0).abs() < 1e-6
    }

    /// Whether this BPA carries no information (vacuous).
    #[inline(always)]
    pub fn is_vacuous(self) -> bool {
        self.u > 1.0 - 1e-9
    }

    /// Discount this BPA by factor `alpha` in the range `\[0, 1\]`.
    /// Moves committed mass (b, d) into uncertainty; preserves epsilon.
    #[inline]
    pub fn discount(self, alpha: f64) -> Self {
        let a = alpha.clamp(0.0, 1.0);
        let b = self.b * a;
        let d = self.d * a;
        Self {
            b,
            d,
            u: 1.0 - b - d - self.epsilon,
            epsilon: self.epsilon,
        }
    }
}

impl Default for Bpa {
    #[inline(always)]
    fn default() -> Self {
        Self::vacuous()
    }
}

// Dempster Combination Rule

/// Result of combining two BPAs via Dempster's rule.
#[derive(Debug, Clone, Copy)]
pub struct DempsterResult {
    pub combined: Bpa,
    pub conflict: f64,
}

/// Standard Dempster combination rule for two BPAs on = {Threat, Normal}.
/// This is the closed-world version: conflict is normalized away via 1/(1-K).
/// Ignores epsilon (treats input as closed-world even if epsilon> 0).
#[inline]
pub fn dempster_combine(m1: Bpa, m2: Bpa) -> DempsterResult {
    let k = m1.b * m2.d + m1.d * m2.b;

    if k >= 1.0 - 1e-12 {
        return DempsterResult {
            combined: Bpa::vacuous(),
            conflict: 1.0,
        };
    }

    let inv_k = 1.0 / (1.0 - k);
    let b = (m1.b * m2.b + m1.b * m2.u + m1.u * m2.b) * inv_k;
    let d = (m1.d * m2.d + m1.d * m2.u + m1.u * m2.d) * inv_k;
    let u = (m1.u * m2.u) * inv_k;

    DempsterResult {
        combined: Bpa {
            b,
            d,
            u,
            epsilon: 0.0,
        },
        conflict: k,
    }
}

/// Combine N BPAs sequentially via Dempster's rule.
#[inline]
pub fn dempster_combine_n(bpas: &[Bpa]) -> DempsterResult {
    match bpas.len() {
        0 => DempsterResult {
            combined: Bpa::vacuous(),
            conflict: 0.0,
        },
        1 => DempsterResult {
            combined: bpas[0],
            conflict: 0.0,
        },
        _ => {
            let mut acc = bpas[0];
            let mut total_k = 0.0_f64;
            for &bpa in &bpas[1..] {
                let r = dempster_combine(acc, bpa);
                total_k = 1.0 - (1.0 - total_k) * (1.0 - r.conflict);
                acc = r.combined;
            }
            DempsterResult {
                combined: acc,
                conflict: total_k,
            }
        }
    }
}

// Evidence -

/// Evidence supporting a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

// ModuleResult - Moduledetect

/// Result from a single security module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub module_id: String,
    pub module_name: String,
    pub pillar: Pillar,
    pub threat_level: ThreatLevel,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub details: serde_json::Value,
    pub duration_ms: u64,
    pub analyzed_at: DateTime<Utc>,
    /// D-S BPA triple. `None` for legacy modules (auto-converted in fusion layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpa: Option<Bpa>,
    /// Parent engine ID (A-H). `None` for legacy modules (auto-mapped via engine_map).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
}

impl ModuleResult {
    /// Create a safe result for a module that actually analyzed content and
    /// found nothing suspicious.
    ///
    /// Produces `Bpa::safe_analyzed()` = {b=0, d=0.15, u=0.85}.
    /// This is NOT an absorbing element in Dempster combination.
    pub fn safe_analyzed(
        module_id: &str,
        module_name: &str,
        pillar: Pillar,
        summary: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            module_id: module_id.to_string(),
            module_name: module_name.to_string(),
            pillar,
            threat_level: ThreatLevel::Safe,
            confidence: 0.85,
            categories: vec![],
            summary: summary.to_string(),
            evidence: vec![],
            details: serde_json::Value::Null,
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(Bpa::safe_analyzed()),
            engine_id: None,
        }
    }

    /// Create a safe result for a module that had nothing to analyze
    /// (e.g., no attachments for attach_scan, no links for link_scan).
    ///
    /// Produces `Bpa::vacuous()` = {b=0, d=0, u=1.0} - the identity element
    /// in Dempster combination, contributing zero information to the fusion.
    pub fn not_applicable(
        module_id: &str,
        module_name: &str,
        pillar: Pillar,
        summary: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            module_id: module_id.to_string(),
            module_name: module_name.to_string(),
            pillar,
            threat_level: ThreatLevel::Safe,
            confidence: 0.0,
            categories: vec![],
            summary: summary.to_string(),
            evidence: vec![],
            details: serde_json::Value::Null,
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(Bpa::vacuous()),
            engine_id: None,
        }
    }

    /// Create a safe (no threat) result.
    #[deprecated(note = "use safe_analyzed() or not_applicable() instead")]
    pub fn safe(
        module_id: &str,
        module_name: &str,
        pillar: Pillar,
        summary: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            module_id: module_id.to_string(),
            module_name: module_name.to_string(),
            pillar,
            threat_level: ThreatLevel::Safe,
            confidence: 1.0,
            categories: vec![],
            summary: summary.to_string(),
            evidence: vec![],
            details: serde_json::Value::Null,
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        }
    }

    /// Extract continuous raw score from details.score or fallback to threat_level numeric.
    #[inline]
    pub fn raw_score(&self) -> f64 {
        self.details
            .get("score")
            .and_then(|v| v.as_f64())
            .unwrap_or_else(|| self.threat_level.as_numeric())
    }

    /// Get or compute BPA triple. If `bpa` is None, auto-converts from (score, confidence).
    #[inline]
    pub fn effective_bpa(&self) -> Bpa {
        self.bpa
            .unwrap_or_else(|| Bpa::from_score_confidence(self.raw_score(), self.confidence))
    }
}

// SecurityVerdict - Security

/// Per-engine BPA detail for the verdict output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineBpaDetail {
    pub engine_id: String,
    pub engine_name: String,
    pub bpa: Bpa,
    pub modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_factors: Vec<String>,
}

/// Post-fusion safety circuit breaker activation record.
///
/// When a single module's raw BPA belief exceeds the alert threshold but D-S
/// Murphy fusion suppresses it (treating the module as an outlier), the circuit
/// breaker applies a minimum risk floor to prevent complete suppression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerInfo {
    /// The module that triggered the circuit breaker.
    pub trigger_module_id: String,
    /// The raw belief value of the triggering module's BPA.
    pub trigger_belief: f64,
    /// The computed floor value: `trigger_belief * alert_floor_factor`.
    pub floor_value: f64,
    /// The original `risk_single` before floor application.
    pub original_risk: f64,
}

/// Multi-signal convergence breaker activation record.
///
/// When 3+ independent modules flag threats (even at Low level), their
/// convergence is treated as strong evidence that D-S fusion should not
/// suppress. This addresses the "intra-engine dilution" problem where
/// Safe modules with confidence=1.0 act as absorbing elements in Dempster
/// combination, zeroing out threat signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceBreakerInfo {
    /// Number of modules that flagged threats.
    pub modules_flagged: u32,
    /// The applied floor value.
    pub floor_value: f64,
    /// The original `risk_single` before floor application.
    pub original_risk: f64,
    /// IDs of modules that flagged threats.
    pub flagged_modules: Vec<String>,
}

/// Full D-S fusion diagnostics attached to the verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionDetails {
    pub fused_bpa: Bpa,
    pub k_conflict: f64,
    pub risk_single: f64,
    pub eta: f64,
    pub engine_details: Vec<EngineBpaDetail>,
    pub credibility_weights: HashMap<String, f64>,
    /// v5.0 TBM: Novelty = 1 - (1-). None for closed-world paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub novelty: Option<f64>,
    /// v5.0 TBM: Cross-layer conflict between tech and blind-spot layers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_cross: Option<f64>,
    /// v5.0 TBM: Pignistic probability BetP(Threat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub betp: Option<f64>,
    /// Fusion method used: "ds_murphy" | "tbm_v5" | "noisy_or" | "weighted_max".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fusion_method: Option<String>,
    /// Post-fusion safety circuit breaker: activated when D-S fusion suppresses
    /// a strong minority signal. None = no activation needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerInfo>,
    /// Multi-signal convergence breaker: activated when 3+ modules flag threats
    /// but D-S fusion dilutes them all. None = no activation needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub convergence_breaker: Option<ConvergenceBreakerInfo>,
}

/// Aggregated security verdict for an email session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerdict {
    pub id: Uuid,
    pub session_id: Uuid,
    pub threat_level: ThreatLevel,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub summary: String,
    pub pillar_scores: HashMap<String, f64>,
    pub modules_run: u32,
    pub modules_flagged: u32,
    pub total_duration_ms: u64,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fusion_details: Option<FusionDetails>,
}

// AlertLevel / AlertRecord - Alert Level record

/// P0-P3 alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertLevel {
    P3 = 3,
    P2 = 2,
    P1 = 1,
    P0 = 0,
}

impl AlertLevel {
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }

    #[inline]
    pub fn parse(s: &str) -> Self {
        match s {
            "P0" => Self::P0,
            "P1" => Self::P1,
            "P2" => Self::P2,
            _ => Self::P3,
        }
    }
}

/// Persistent alert record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: Uuid,
    pub verdict_id: Uuid,
    pub session_id: Uuid,
    pub alert_level: AlertLevel,
    pub expected_loss: f64,
    pub return_period: f64,
    pub cvar: f64,
    pub risk_final: f64,
    pub k_conflict: f64,
    pub cusum_alarm: bool,
    pub rationale: String,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Temporal state types - CUSUM / EWMA / EntityRisk
// ============================================================================

/// CUSUM change-point detection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CusumState {
    pub entity_key: String,
    pub s_pos: f64,
    pub s_neg: f64,
    pub mu_0: f64,
    pub sample_count: u64,
    pub alarm_active: bool,
    pub running_sum: f64,
    pub running_sq_sum: f64,
}

impl CusumState {
    /// Create a new CUSUM tracker for an entity.
    #[inline]
    pub fn new(entity_key: String) -> Self {
        Self {
            entity_key,
            s_pos: 0.0,
            s_neg: 0.0,
            mu_0: 0.0,
            sample_count: 0,
            alarm_active: false,
            running_sum: 0.0,
            running_sq_sum: 0.0,
        }
    }

    /// Reset CUSUM statistics (e.g., after acknowledged alarm).
    pub fn reset(&mut self) {
        self.s_pos = 0.0;
        self.s_neg = 0.0;
        self.alarm_active = false;
    }
}

/// Dual EWMA drift detection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualEwmaState {
    pub entity_key: String,
    pub fast_value: f64,
    pub slow_value: f64,
    pub initialized: bool,
    pub observation_count: u64,
}

impl DualEwmaState {
    /// Create a new dual EWMA tracker.
    #[inline]
    pub fn new(entity_key: String) -> Self {
        Self {
            entity_key,
            fast_value: 0.0,
            slow_value: 0.0,
            initialized: false,
            observation_count: 0,
        }
    }
}

/// Entity risk accumulation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRiskState {
    pub entity_key: String,
    pub risk_value: f64,
    pub alpha: f64,
    pub email_count: u64,
}

impl EntityRiskState {
    /// Create a new entity risk tracker.
    #[inline]
    pub fn new(entity_key: String, alpha: f64) -> Self {
        Self {
            entity_key,
            risk_value: 0.0,
            alpha: alpha.clamp(0.0, 1.0),
            email_count: 0,
        }
    }

    /// Create with default alpha (0.92).
    #[inline]
    pub fn with_defaults(entity_key: String) -> Self {
        Self::new(entity_key, 0.92)
    }
}

// ============================================================================
// SecurityStats - SecurityStatistics
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    pub total_scanned: u64,
    pub level_counts: HashMap<String, u64>,
    pub high_threats_24h: u64,
    pub ioc_count: u64,
}

// ============================================================================
// IocEntry - IOC items
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub id: Uuid,
    pub indicator: String,
    pub ioc_type: String,
    pub source: String,
    pub verdict: String,
    pub confidence: f64,
    /// AttackType: phishing, spoofing, malware, bec, spam, unknown
    #[serde(default)]
    pub attack_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub context: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IocEntry {
    /// FromSecurity Create IOC
    pub fn auto_from_indicator(
        indicator: String,
        ioc_type: String,
        confidence: f64,
        context: String,
    ) -> Self {
        Self::auto_from_indicator_with_attack(
            indicator,
            ioc_type,
            confidence,
            context,
            String::new(),
        )
    }

    /// FromSecurity Create IOC (AttackType)
    pub fn auto_from_indicator_with_attack(
        indicator: String,
        ioc_type: String,
        confidence: f64,
        context: String,
        attack_type: String,
    ) -> Self {
        Self::auto_from_indicator_full(
            indicator,
            ioc_type,
            confidence,
            context,
            attack_type,
            "malicious".to_string(),
        )
    }

    /// FromSecurity Create IOC (AttackType + verdict)
    pub fn auto_from_indicator_full(
        indicator: String,
        ioc_type: String,
        confidence: f64,
        context: String,
        attack_type: String,
        verdict: String,
    ) -> Self {
        let now = Utc::now();
        let expires = now + chrono::Duration::days(30);
        Self {
            id: Uuid::new_v4(),
            indicator,
            ioc_type,
            source: "auto".to_string(),
            verdict,
            confidence,
            attack_type,
            first_seen: now,
            last_seen: now,
            hit_count: 1,
            context: Some(context),
            expires_at: Some(expires),
            created_at: now,
            updated_at: now,
        }
    }
}

// ============================================================================
// WhitelistEntry - items
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: Uuid,
    pub entry_type: String,
    pub value: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

// ============================================================================
// TrainingSample - NLP (5Classification)
// ============================================================================

/// 5Classification
pub const TRAINING_NUM_LABELS: usize = 5;

/// 5Classification :
pub const LABEL_LEGITIMATE: i32 = 0;
/// 5Classification : Phishing
pub const LABEL_PHISHING: i32 = 1;
/// 5Classification :
pub const LABEL_SPOOFING: i32 = 2;
/// 5Classification :
pub const LABEL_SOCIAL_ENGINEERING: i32 = 3;
/// 5Classification : threat
pub const LABEL_OTHER_THREAT: i32 = 4;

/// name
pub const LABEL_NAMES: [&str; TRAINING_NUM_LABELS] = [
    "legitimate",
    "phishing",
    "spoofing",
    "social_engineering",
    "other_threat",
];

/// Type
pub fn feedback_type_to_label(feedback_type: &str) -> Option<(i32, &'static str)> {
    match feedback_type {
        "legitimate" => Some((LABEL_LEGITIMATE, "legitimate")),
        "phishing" => Some((LABEL_PHISHING, "phishing")),
        "spoofing" => Some((LABEL_SPOOFING, "spoofing")),
        "social_engineering" => Some((LABEL_SOCIAL_ENGINEERING, "social_engineering")),
        "other_threat" => Some((LABEL_OTHER_THREAT, "other_threat")),
        _ => None,
    }
}

/// NLP Model fine-tuning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSample {
    pub id: Uuid,
    pub session_id: Uuid,
    /// 5Classification (0-4)
    pub label: i32,
    /// : legitimate / phishing / spoofing / social_engineering / other_threat
    pub label_name: String,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    pub analyst_comment: Option<String>,
    pub original_threat_level: String,
    pub verdict_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

// FeedbackEntry - items

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub id: Uuid,
    pub session_id: Uuid,
    pub verdict_id: Option<Uuid>,
    pub feedback_type: String,
    pub module_id: Option<String>,
    pub original_threat_level: String,
    pub user_comment: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// FeedbackStat - Statistics

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackStat {
    pub module_id: String,
    pub total_feedback: u64,
    pub false_positives: u64,
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpa_normalization() {
        let bpa = Bpa::new(2.0, 3.0, 5.0);
        assert!((bpa.b - 0.2).abs() < 1e-10);
        assert!((bpa.d - 0.3).abs() < 1e-10);
        assert!((bpa.u - 0.5).abs() < 1e-10);
        assert!(bpa.is_valid());
    }

    #[test]
    fn test_bpa_zero_input() {
        let bpa = Bpa::new(0.0, 0.0, 0.0);
        assert!(bpa.is_vacuous());
    }

    #[test]
    fn test_from_score_confidence() {
        let bpa = Bpa::from_score_confidence(0.8, 1.0);
        assert!((bpa.b - 0.8).abs() < 1e-10);
        assert!((bpa.d - 0.2).abs() < 1e-10);
        assert!((bpa.u).abs() < 1e-10);
    }

    #[test]
    fn test_dempster_combine_vacuous() {
        let m1 = Bpa {
            b: 0.6,
            d: 0.3,
            u: 0.1,
            epsilon: 0.0,
        };
        let r = dempster_combine(m1, Bpa::vacuous());
        assert!((r.combined.b - m1.b).abs() < 1e-10);
        assert!((r.combined.d - m1.d).abs() < 1e-10);
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Safe < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn test_alert_level_ordering() {
        assert!(AlertLevel::P0 < AlertLevel::P1);
        assert!(AlertLevel::P1 < AlertLevel::P2);
        assert!(AlertLevel::P2 < AlertLevel::P3);
    }

    #[test]
    fn test_bpa_safe_analyzed_is_not_absorbing() {
        let safe = Bpa::safe_analyzed();
        assert!(safe.is_valid());
        assert!(!safe.is_vacuous());
        // Must have positive uncertainty - NOT an absorbing element
        assert!(safe.u > 0.5, "safe_analyzed must retain high uncertainty");
        assert!(
            (safe.b).abs() < 1e-10,
            "safe_analyzed must have zero belief"
        );
        assert!(safe.d > 0.0, "safe_analyzed must have some disbelief");
    }

    #[test]
    fn test_safe_analyzed_does_not_absorb_threat() {
        // This is the critical test: a threat BPA combined with safe_analyzed
        // must NOT zero out the threat signal.
        let threat = Bpa {
            b: 0.6,
            d: 0.1,
            u: 0.3,
            epsilon: 0.0,
        };
        let safe = Bpa::safe_analyzed();

        let result = dempster_combine(threat, safe);
        // The combined belief must remain significantly positive
        assert!(
            result.combined.b > 0.1,
            "threat signal must survive combination with safe_analyzed, got b={}",
            result.combined.b
        );
    }

    #[test]
    fn test_old_safe_was_absorbing_element() {
        // Verify the old behavior: from_score_confidence(0.0, 1.0) = certain_benign
        // IS an absorbing element - combining with it zeroes all threat.
        let old_safe = Bpa::from_score_confidence(0.0, 1.0);
        assert!((old_safe.d - 1.0).abs() < 1e-10);
        assert!((old_safe.u).abs() < 1e-10);

        let threat = Bpa {
            b: 0.6,
            d: 0.1,
            u: 0.3,
            epsilon: 0.0,
        };
        let result = dempster_combine(threat, old_safe);
        // Old behavior: threat completely absorbed -> b 0
        assert!(
            result.combined.b < 0.01,
            "old safe BPA should absorb threat (demonstrating the bug)"
        );
    }

    #[test]
    fn test_vacuous_is_identity_in_combination() {
        let threat = Bpa {
            b: 0.5,
            d: 0.2,
            u: 0.3,
            epsilon: 0.0,
        };
        let result = dempster_combine(threat, Bpa::vacuous());
        assert!((result.combined.b - threat.b).abs() < 1e-10);
        assert!((result.combined.d - threat.d).abs() < 1e-10);
        assert!((result.combined.u - threat.u).abs() < 1e-10);
    }

    #[test]
    fn test_module_result_safe_analyzed_has_explicit_bpa() {
        let r = ModuleResult::safe_analyzed("test", "Test", Pillar::Content, "ok", 10);
        assert!(r.bpa.is_some(), "safe_analyzed must set explicit BPA");
        let bpa = r.effective_bpa();
        assert!(!bpa.is_vacuous());
        assert!(bpa.u > 0.5);
    }

    #[test]
    fn test_module_result_not_applicable_has_vacuous_bpa() {
        let r = ModuleResult::not_applicable("test", "Test", Pillar::Content, "N/A", 0);
        assert!(r.bpa.is_some(), "not_applicable must set explicit BPA");
        let bpa = r.effective_bpa();
        assert!(bpa.is_vacuous(), "not_applicable must produce vacuous BPA");
    }

    #[test]
    fn test_feedback_type_to_label_valid_types() {
        assert_eq!(
            feedback_type_to_label("legitimate"),
            Some((0, "legitimate"))
        );
        assert_eq!(feedback_type_to_label("phishing"), Some((1, "phishing")));
        assert_eq!(feedback_type_to_label("spoofing"), Some((2, "spoofing")));
        assert_eq!(
            feedback_type_to_label("social_engineering"),
            Some((3, "social_engineering"))
        );
        assert_eq!(
            feedback_type_to_label("other_threat"),
            Some((4, "other_threat"))
        );
    }

    #[test]
    fn test_feedback_type_to_label_invalid_returns_none() {
        assert_eq!(feedback_type_to_label("unknown"), None);
        assert_eq!(feedback_type_to_label("false_positive"), None);
        assert_eq!(feedback_type_to_label(""), None);
    }

    #[test]
    fn test_label_names_consistency() {
        for (i, name) in LABEL_NAMES.iter().enumerate() {
            let result = feedback_type_to_label(name);
            assert!(
                result.is_some(),
                "LABEL_NAMES[{}] = '{}' should be valid",
                i,
                name
            );
            let (label, label_name) = result.unwrap();
            assert_eq!(label, i as i32);
            assert_eq!(label_name, *name);
        }
    }

    #[test]
    fn test_training_sample_serde_roundtrip() {
        let sample = TrainingSample {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            label: LABEL_PHISHING,
            label_name: "phishing".to_string(),
            subject: Some("Urgent: verify your account".to_string()),
            body_text: Some("Click here to verify".to_string()),
            body_html: None,
            mail_from: Some("attacker@evil.com".to_string()),
            rcpt_to: vec!["victim@company.com".to_string()],
            analyst_comment: Some("Clear phishing attempt".to_string()),
            original_threat_level: "high".to_string(),
            verdict_id: Some(Uuid::new_v4()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&sample).expect("serialize");
        let deser: TrainingSample = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.id, sample.id);
        assert_eq!(deser.label, LABEL_PHISHING);
        assert_eq!(deser.label_name, "phishing");
        assert_eq!(deser.rcpt_to, vec!["victim@company.com"]);
    }
}

// MTA Proxy - Inline Verdict Types

/// MTA
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum VerdictDisposition {
    /// - MTA
    Accept,
    /// - SMTP 550
    Reject {
        /// (SMTP)
        reason: String,
    },

    Quarantine,
    /// - / 451, fail-open
    Tempfail,
}

impl VerdictDisposition {
    pub fn from_threat_level(
        level: ThreatLevel,
        quarantine_threshold: ThreatLevel,
        reject_threshold: ThreatLevel,
    ) -> Self {
        if level >= reject_threshold {
            VerdictDisposition::Reject {
                reason: format!("Message rejected: {} threat detected", level),
            }
        } else if level >= quarantine_threshold {
            VerdictDisposition::Quarantine
        } else {
            VerdictDisposition::Accept
        }
    }

    /// SMTP
    pub fn smtp_code(&self) -> u16 {
        match self {
            VerdictDisposition::Accept => 250,
            VerdictDisposition::Reject { .. } => 550,
            VerdictDisposition::Quarantine => 250,
            VerdictDisposition::Tempfail => 451,
        }
    }

    /// SMTP
    pub fn smtp_message(&self) -> String {
        match self {
            VerdictDisposition::Accept => "2.0.0 OK".to_string(),
            VerdictDisposition::Reject { reason } => format!("5.7.1 {reason}"),
            VerdictDisposition::Quarantine => "2.0.0 OK".to_string(),
            VerdictDisposition::Tempfail => "4.7.1 Temporary failure".to_string(),
        }
    }
}

impl std::fmt::Display for VerdictDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictDisposition::Accept => write!(f, "accept"),
            VerdictDisposition::Reject { reason } => write!(f, "reject: {reason}"),
            VerdictDisposition::Quarantine => write!(f, "quarantine"),
            VerdictDisposition::Tempfail => write!(f, "tempfail"),
        }
    }
}

/// MTA inline verdict (MTA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineVerdictResponse {
    /// Comment retained in English.
    pub disposition: VerdictDisposition,
    /// Comment retained in English.
    pub threat_level: ThreatLevel,
    /// Comment retained in English.
    pub confidence: f64,
    /// Summary
    pub summary: String,
    /// Session ID
    pub session_id: Uuid,
    /// Comment retained in English.
    pub modules_run: u32,
    /// Comment retained in English.
    pub modules_flagged: u32,
    /// ()
    pub duration_ms: u64,
}

// ============================================================================
// ThreatScene - 邮件威胁场景 (群发检测 / 退信扫描)
// ============================================================================

/// 威胁场景类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSceneType {
    /// 群发邮件: 外部域名在时间窗口内向多个内部收件人发送邮件
    BulkMailing,
    /// 退信扫描: 大量退信涌入, 表明攻击者在枚举内部邮箱地址 (Directory Harvest Attack)
    BounceHarvest,
    /// 内部域名仿冒: 外部发件人使用与内部域名相似的域名 (TLD变种/子域前缀/同形攻击)
    InternalDomainImpersonation,
}

impl std::fmt::Display for ThreatSceneType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BulkMailing => write!(f, "bulk_mailing"),
            Self::BounceHarvest => write!(f, "bounce_harvest"),
            Self::InternalDomainImpersonation => write!(f, "internal_domain_impersonation"),
        }
    }
}

impl ThreatSceneType {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "bulk_mailing" => Some(Self::BulkMailing),
            "bounce_harvest" => Some(Self::BounceHarvest),
            "internal_domain_impersonation" => Some(Self::InternalDomainImpersonation),
            _ => None,
        }
    }
}

/// 威胁场景状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSceneStatus {
    Active,
    Acknowledged,
    AutoBlocked,
    Resolved,
}

impl std::fmt::Display for ThreatSceneStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Acknowledged => write!(f, "acknowledged"),
            Self::AutoBlocked => write!(f, "auto_blocked"),
            Self::Resolved => write!(f, "resolved"),
        }
    }
}

impl ThreatSceneStatus {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "acknowledged" => Some(Self::Acknowledged),
            "auto_blocked" => Some(Self::AutoBlocked),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// 威胁场景事件记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScene {
    pub id: Uuid,
    pub scene_type: ThreatSceneType,
    pub actor: String,
    pub actor_type: String,
    pub target_domain: Option<String>,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub email_count: i32,
    pub unique_recipients: i32,
    pub bounce_count: i32,
    pub sample_subjects: Vec<String>,
    pub sample_recipients: Vec<String>,
    pub threat_level: ThreatLevel,
    pub status: ThreatSceneStatus,
    pub auto_blocked: bool,
    pub ioc_id: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 场景检测规则配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSceneRule {
    pub scene_type: ThreatSceneType,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// 场景统计摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSceneStats {
    pub bulk_mailing: SceneTypeStats,
    pub bounce_harvest: SceneTypeStats,
    pub internal_domain_impersonation: SceneTypeStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SceneTypeStats {
    pub active: i64,
    pub acknowledged: i64,
    pub auto_blocked: i64,
    pub resolved: i64,
    pub total_24h: i64,
}

/// 群发邮件检测配置 (从 JSON 反序列化)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkMailingConfig {
    #[serde(default = "default_24")]
    pub time_window_hours: i64,
    #[serde(default = "default_5")]
    pub min_emails: i64,
    #[serde(default = "default_3")]
    pub min_unique_internal_recipients: i64,
    #[serde(default = "default_true")]
    pub exclude_internal_senders: bool,
    #[serde(default)]
    pub auto_block_enabled: bool,
    #[serde(default = "default_10")]
    pub auto_block_recipient_threshold: i64,
    #[serde(default = "default_48")]
    pub auto_block_duration_hours: i64,
    #[serde(default)]
    pub exclude_domains: Vec<String>,
}

impl Default for BulkMailingConfig {
    fn default() -> Self {
        Self {
            time_window_hours: 24,
            min_emails: 5,
            min_unique_internal_recipients: 3,
            exclude_internal_senders: true,
            auto_block_enabled: false,
            auto_block_recipient_threshold: 10,
            auto_block_duration_hours: 48,
            exclude_domains: Vec::new(),
        }
    }
}

/// 退信扫描检测配置 (从 JSON 反序列化)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceHarvestConfig {
    #[serde(default = "default_24")]
    pub time_window_hours: i64,
    #[serde(default = "default_10")]
    pub min_bounces: i64,
    #[serde(default = "default_5")]
    pub min_unique_targets: i64,
    #[serde(default)]
    pub auto_block_enabled: bool,
    #[serde(default = "default_20")]
    pub auto_block_bounce_threshold: i64,
    #[serde(default = "default_72")]
    pub auto_block_duration_hours: i64,
}

impl Default for BounceHarvestConfig {
    fn default() -> Self {
        Self {
            time_window_hours: 24,
            min_bounces: 10,
            min_unique_targets: 5,
            auto_block_enabled: false,
            auto_block_bounce_threshold: 20,
            auto_block_duration_hours: 72,
        }
    }
}

/// 内部域名仿冒检测配置 (从 JSON 反序列化)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalDomainImpersonationConfig {
    /// 检测时间窗口 (小时)
    #[serde(default = "default_24")]
    pub time_window_hours: i64,
    /// 触发场景的最少邮件数
    #[serde(default = "default_3")]
    pub min_emails: i64,
    /// 是否启用自动封禁
    #[serde(default)]
    pub auto_block_enabled: bool,
    /// 自动封禁持续时间 (小时)
    #[serde(default = "default_48")]
    pub auto_block_duration_hours: i64,
    /// 自动封禁最少邮件数门控 (达到此数量才允许自动封禁)
    #[serde(default = "default_10")]
    pub auto_block_min_emails: i64,
    /// 排除的域名列表 (不做仿冒检测)
    #[serde(default)]
    pub exclude_domains: Vec<String>,
}

impl Default for InternalDomainImpersonationConfig {
    fn default() -> Self {
        Self {
            time_window_hours: 24,
            min_emails: 3,
            auto_block_enabled: false,
            auto_block_duration_hours: 48,
            auto_block_min_emails: 10,
            exclude_domains: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_3() -> i64 {
    3
}
fn default_5() -> i64 {
    5
}
fn default_10() -> i64 {
    10
}
fn default_20() -> i64 {
    20
}
fn default_24() -> i64 {
    24
}
fn default_48() -> i64 {
    48
}
fn default_72() -> i64 {
    72
}
