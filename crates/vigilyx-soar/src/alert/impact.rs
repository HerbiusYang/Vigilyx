//! Target impact weight configuration for expected loss calculation.

//! In production, weights would come from an LDAP/HR directory.
//! For prototype: default weight = 1.0, can be overridden per-recipient.

/// Target impact weight (for expected loss calculation).
/// In production, this would come from an LDAP/HR directory.
/// For prototype: default weight = 1.0, can be overridden per-recipient.
#[derive(Debug, Clone)]
pub struct ImpactConfig {
    /// Default impact weight for unknown recipients.
    pub default_weight: f64,
    /// Override weights by recipient email pattern.
    pub overrides: Vec<(String, f64)>,
}

impl Default for ImpactConfig {
    fn default() -> Self {
        Self {
            default_weight: 1.0,
            overrides: vec![
                // Example high-value targets
                ("ceo@".to_string(), 5.0),
                ("cfo@".to_string(), 4.5),
                ("finance@".to_string(), 4.5),
                ("it-admin@".to_string(), 4.0),
                ("admin@".to_string(), 3.5),
            ],
        }
    }
}

impl ImpactConfig {
    /// Look up impact weight for a recipient.
    #[inline]
    pub fn weight_for(&self, recipient: &str) -> f64 {
        let lower = recipient.to_ascii_lowercase();
        for (pattern, weight) in &self.overrides {
            if lower.starts_with(pattern) || lower.contains(pattern) {
                return *weight;
            }
        }
        self.default_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impact_config_lookup() {
        let config = ImpactConfig::default();
        assert_eq!(config.weight_for("ceo@company.com"), 5.0);
        assert_eq!(config.weight_for("cfo@company.com"), 4.5);
        assert_eq!(config.weight_for("random@company.com"), 1.0);
    }
}
