//! Module-to-Engine mapping for the 8-engine architecture.

//! Maps 14 existing security modules to 8 conceptual analysis engines (A-H).
//! Engines group modules that analyze the same security dimension, allowing
//! within-engine pre-fusion before cross-engine D-S combination.

//! Engine architecture:
//! - A: Sender Reputation (HMM-based dynamic trust)
//! - B: Content Analysis (5-dimensional composite)
//! - C: Behavior Baseline (GMM + Isolation Forest)
//! - D: URL/Link Analysis (+ QR code + LOTS)
//! - E: Protocol Compliance (headers + MIME)
//! - F: Semantic Intent Analysis (LLM-based)
//! - G: Identity Behavior Anomaly (IAM correlation)
//! - H: Transaction Semantic Correlation (business logic)

use serde::{Deserialize, Serialize};

/// Engine identifiers A-H.
/// `#[repr(u8)]` for compact storage and fast array indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EngineId {
    A = 0, // Sender Reputation
    B = 1, // Content Analysis
    C = 2, // Behavior Baseline
    D = 3, // URL/Link Analysis
    E = 4, // Protocol Compliance
    F = 5, // Semantic Intent
    G = 6, // Identity Anomaly
    H = 7, // Transaction Correlation
}

/// Total number of engines.
pub const ENGINE_COUNT: usize = 8;

impl EngineId {
    /// Convert to array index (0-7).
    #[inline(always)]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// All engine IDs in order.
    pub const ALL: [EngineId; ENGINE_COUNT] = [
        EngineId::A,
        EngineId::B,
        EngineId::C,
        EngineId::D,
        EngineId::E,
        EngineId::F,
        EngineId::G,
        EngineId::H,
    ];

    /// Human-readable engine name.
    pub const fn name_cn(self) -> &'static str {
        match self {
            EngineId::A => "Sender Reputation",
            EngineId::B => "Content Analysis",
            EngineId::C => "Behavior Baseline",
            EngineId::D => "URL Analysis",
            EngineId::E => "Protocol Compliance",
            EngineId::F => "Semantic Intent",
            EngineId::G => "Identity Anomaly",
            EngineId::H => "Transaction Correlation",
        }
    }

    /// Short engine label (for JSON keys, logs).
    pub const fn label(self) -> &'static str {
        match self {
            EngineId::A => "sender_reputation",
            EngineId::B => "content_analysis",
            EngineId::C => "behavior_baseline",
            EngineId::D => "url_analysis",
            EngineId::E => "protocol_compliance",
            EngineId::F => "semantic_intent",
            EngineId::G => "identity_anomaly",
            EngineId::H => "transaction_correlation",
        }
    }

    /// Parse from label string.
    #[inline]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "sender_reputation" | "A" => Some(EngineId::A),
            "content_analysis" | "B" => Some(EngineId::B),
            "behavior_baseline" | "C" => Some(EngineId::C),
            "url_analysis" | "D" => Some(EngineId::D),
            "protocol_compliance" | "E" => Some(EngineId::E),
            "semantic_intent" | "F" => Some(EngineId::F),
            "identity_anomaly" | "G" => Some(EngineId::G),
            "transaction_correlation" | "H" => Some(EngineId::H),
            _ => None,
        }
    }
}

impl std::fmt::Display for EngineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Module-to-Engine Mapping ───────────────────────────────────────────────

/// Map a module_id to its parent engine.
///
/// Multiple modules may belong to the same engine. Their BPAs are
/// pre-fused (within-engine Dempster combination) before cross-engine fusion.
///
/// Returns `None` for modules that don't map to any engine (e.g., "verdict").
#[inline]
pub fn module_to_engine(module_id: &str) -> Option<EngineId> {
    // Static dispatch via match - zero allocation, branch-predicted
    match module_id {
        // Engine A: Sender Reputation
        "domain_verify" => Some(EngineId::A),

        // Engine B: Content Analysis (9 modules, incl. ClamAV + YARA)
        "content_scan" | "html_scan" | "html_pixel_art" | "attach_scan" | "attach_content"
        | "attach_hash" | "av_eml_scan" | "av_attach_scan" | "yara_scan" => Some(EngineId::B),

        // Engine C: Behavior Baseline
        "anomaly_detect" => Some(EngineId::C),

        // Engine D: URL/Link Analysis (3 modules)
        "link_scan" | "link_reputation" | "link_content" => Some(EngineId::D),

        // Engine E: Protocol Compliance (2 modules)
        "header_scan" | "mime_scan" => Some(EngineId::E),

        // Engine F: Semantic Intent
        "semantic_scan" => Some(EngineId::F),

        // Engine G & H: new engines, direct mapping
        "identity_anomaly" => Some(EngineId::G),
        "transaction_correlation" => Some(EngineId::H),

        // DAG sink or unknown
        _ => None,
    }
}

// Default Correlation Matrix

/// Default inter-engine correlation matrix (8x8, row-major flat array).

/// Based on expected statistical dependency between engine outputs:
/// - BF (0.30): both analyze email text content
/// - DB (0.20): URLs embedded in content body
/// - AE (0.15): both use SPF/DKIM signals
/// - CG (0.15): both model sender behavior patterns
/// - Others <= 0.10: largely independent

/// Diagonal = 0 (self-correlation not used).

/// Layout: `corr[i * ENGINE_COUNT + j]` where i,j [0, ENGINE_COUNT).
#[rustfmt::skip]
pub const DEFAULT_CORRELATION_MATRIX: [f64; ENGINE_COUNT * ENGINE_COUNT] = [
   // A B C D E F G H
    0.00, 0.10, 0.05, 0.05, 0.15, 0.05, 0.10, 0.05, // A
    0.10, 0.00, 0.10, 0.20, 0.05, 0.30, 0.05, 0.10, // B
    0.05, 0.10, 0.00, 0.05, 0.05, 0.05, 0.15, 0.10, // C
    0.05, 0.20, 0.05, 0.00, 0.05, 0.10, 0.05, 0.05, // D
    0.15, 0.05, 0.05, 0.05, 0.00, 0.05, 0.05, 0.05, // E
    0.05, 0.30, 0.05, 0.10, 0.05, 0.00, 0.05, 0.15, // F
    0.10, 0.05, 0.15, 0.05, 0.05, 0.05, 0.00, 0.10, // G
    0.05, 0.10, 0.10, 0.05, 0.05, 0.15, 0.10, 0.00, // H
];

/// Get correlation between two engines from the flat matrix.
#[inline(always)]
pub fn engine_correlation(a: EngineId, b: EngineId) -> f64 {
    DEFAULT_CORRELATION_MATRIX[a.as_index() * ENGINE_COUNT + b.as_index()]
}

/// Build a sub-correlation matrix for only the active engines.
/// Returns a flat row-major array for the active engines only.
pub fn active_correlation_matrix(active_engines: &[EngineId]) -> Vec<f64> {
    let n = active_engines.len();
    let mut matrix = vec![0.0_f64; n * n];
    for (i, &ei) in active_engines.iter().enumerate() {
        for (j, &ej) in active_engines.iter().enumerate() {
            matrix[i * n + j] = engine_correlation(ei, ej);
        }
    }
    matrix
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_mapping() {
        assert_eq!(module_to_engine("content_scan"), Some(EngineId::B));
        assert_eq!(module_to_engine("html_scan"), Some(EngineId::B));
        assert_eq!(module_to_engine("link_scan"), Some(EngineId::D));
        assert_eq!(module_to_engine("header_scan"), Some(EngineId::E));
        assert_eq!(module_to_engine("domain_verify"), Some(EngineId::A));
        assert_eq!(module_to_engine("verdict"), None);
        assert_eq!(module_to_engine("unknown_module"), None);
    }

    #[test]
    fn test_av_modules_map_to_engine_b() {
        assert_eq!(module_to_engine("av_eml_scan"), Some(EngineId::B));
        assert_eq!(module_to_engine("av_attach_scan"), Some(EngineId::B));
    }

    #[test]
    fn test_yara_module_maps_to_engine_b() {
        assert_eq!(module_to_engine("yara_scan"), Some(EngineId::B));
    }

    #[test]
    fn test_correlation_matrix_symmetric() {
        for i in 0..ENGINE_COUNT {
            for j in 0..ENGINE_COUNT {
                let a = DEFAULT_CORRELATION_MATRIX[i * ENGINE_COUNT + j];
                let b = DEFAULT_CORRELATION_MATRIX[j * ENGINE_COUNT + i];
                assert!(
                    (a - b).abs() < 1e-10,
                    "Matrix not symmetric at ({}, {}): {} vs {}",
                    i,
                    j,
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_correlation_matrix_diagonal_zero() {
        for i in 0..ENGINE_COUNT {
            assert_eq!(DEFAULT_CORRELATION_MATRIX[i * ENGINE_COUNT + i], 0.0);
        }
    }

    #[test]
    fn test_engine_id_roundtrip() {
        for id in EngineId::ALL {
            assert_eq!(EngineId::from_label(id.label()), Some(id));
        }
    }

    #[test]
    fn test_active_correlation_submatrix() {
        let active = vec![EngineId::A, EngineId::B, EngineId::E];
        let sub = active_correlation_matrix(&active);
        assert_eq!(sub.len(), 9); // 3x3
        // A-B correlation
        assert!((sub[1] - 0.10).abs() < 1e-10);
        // A-E correlation
        assert!((sub[2] - 0.15).abs() < 1e-10);
    }
}
