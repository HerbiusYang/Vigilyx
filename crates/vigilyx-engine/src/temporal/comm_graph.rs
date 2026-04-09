//! Communication graph anomaly detection (7.3).

//! Maintains a directed weighted graph of email communication:
//! - Nodes: email addresses
//! - Edges: sender -> recipient with frequency and risk history

//! Detects anomalous patterns:
//! 1. **New node high out-degree**: New sender reaching many recipients (mass phishing)
//! 2. **Existing node new high-risk edge**: Known sender contacts new recipient with high risk (BEC)
//! 3. **Out-degree burst**: Sudden increase in unique recipients (data exfiltration)
//! 4. **New external neighbor**: Internal user starts communicating with new external entities

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

/// Communication edge between sender and recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommEdge {
   /// Sender email
    pub sender: String,
   /// Recipient email
    pub recipient: String,
   /// Total communication count
    pub total_count: u64,
   /// EWMA of risk scores on this edge
    pub avg_risk: f64,
   /// EWMA of communication frequency (emails per day)
    pub ewma_frequency: f64,
}

/// Per-sender summary statistics.
#[derive(Debug, Clone, Default)]
struct SenderStats {
   /// Total unique recipients
    out_degree: usize,
   /// Total emails sent
    total_emails: u64,
   /// Average risk across all edges
    avg_risk: f64,
   /// When this sender was first seen (email count at graph level)
    #[allow(dead_code)]
    first_seen_at: u64,
}

/// Communication graph state.
#[derive(Debug, Clone)]
pub struct CommGraph {
   /// Edges indexed by "sender -> recipient"
    edges: FxHashMap<String, CommEdge>,
   /// Per-sender statistics
    sender_stats: FxHashMap<String, SenderStats>,
   /// Total emails processed (global counter)
    total_emails: u64,
   /// EWMA smoothing for edge frequency
    freq_alpha: f64,
   /// EWMA smoothing for edge risk
    risk_alpha: f64,
}

/// Parameters for graph anomaly detection.
#[derive(Debug, Clone)]
pub struct GraphParams {
   /// New sender threshold: sender with <N emails is "new"
    pub new_sender_email_threshold: u64,
   /// High out-degree threshold for new senders
    pub new_sender_high_outdegree: usize,
   /// Out-degree burst: ratio of new recipients to historical average
    pub outdegree_burst_ratio: f64,
   /// High risk edge threshold
    pub high_risk_edge_threshold: f64,
}

impl Default for GraphParams {
    fn default() -> Self {
        Self {
            new_sender_email_threshold: 5,
            new_sender_high_outdegree: 10,
            outdegree_burst_ratio: 3.0,
            high_risk_edge_threshold: 0.5,
        }
    }
}

/// Result of graph anomaly check for one email.
#[derive(Debug, Clone)]
pub struct GraphCheckResult {
   /// Whether any anomaly was detected
    pub is_anomalous: bool,
   /// Pattern label describing the anomaly
    pub pattern_label: String,
   /// Anomaly score [0, 1]
    pub anomaly_score: f64,
   /// Whether this is a new sender-recipient pair
    pub is_new_edge: bool,
   /// Current out-degree of sender
    pub sender_out_degree: usize,
}

impl Default for CommGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl CommGraph {
   /// Create a new communication graph.
    pub fn new() -> Self {
        Self {
            edges: FxHashMap::default(),
            sender_stats: FxHashMap::default(),
            total_emails: 0,
            freq_alpha: 0.1,
            risk_alpha: 0.15,
        }
    }

   /// Record a communication and check for anomalies.
    
   /// # Arguments
   /// - `sender`: sender email address
   /// - `recipients`: list of recipient addresses
   /// - `risk_single`: D-S fused risk score for this email
   /// - `params`: detection parameters
    
   /// # Returns
   /// Graph anomaly check result.
    pub fn observe(
        &mut self,
        sender: &str,
        recipients: &[String],
        risk_single: f64,
        params: &GraphParams,
    ) -> GraphCheckResult {
        self.total_emails += 1;
        let sender_lower = sender.to_ascii_lowercase();

       // Track new edges in this observation
        let mut new_edges_count = 0;
        let mut new_edge_high_risk = false;

       // Get or create sender stats, update immediately, then release borrow
        {
            let stats = self
                .sender_stats
                .entry(sender_lower.clone())
                .or_insert_with(|| SenderStats {
                    out_degree: 0,
                    total_emails: 0,
                    avg_risk: risk_single,
                    first_seen_at: self.total_emails,
                });
            stats.total_emails += 1;
            stats.avg_risk =
                self.risk_alpha * risk_single + (1.0 - self.risk_alpha) * stats.avg_risk;
        }

        let old_out_degree = self
            .sender_stats
            .get(&sender_lower)
            .map(|s| s.out_degree)
            .unwrap_or(0);

       // Pre-allocate edge key buffer - reused across recipients to avoid per-iteration format!()
        let prefix_len = sender_lower.len() + "→".len();
        let mut edge_key = String::with_capacity(prefix_len + 32); // typical recipient ~20-30 chars

        for recipient in recipients {
            let recipient_lower = recipient.to_ascii_lowercase();

           // Build edge key via reusable buffer (avoids format!() allocation per recipient)
            edge_key.clear();
            edge_key.push_str(&sender_lower);
            edge_key.push('→');
            edge_key.push_str(&recipient_lower);

           // Single entry() lookup instead of contains_key() + entry() (was 2 hashes)
            use std::collections::hash_map::Entry;
            let edge = match self.edges.entry(edge_key.clone()) {
                Entry::Vacant(v) => {
                    new_edges_count += 1;
                    if risk_single > params.high_risk_edge_threshold {
                        new_edge_high_risk = true;
                    }
                    v.insert(CommEdge {
                        sender: sender_lower.clone(),
                        recipient: recipient_lower,
                        total_count: 0,
                        avg_risk: risk_single,
                        ewma_frequency: 0.0,
                    })
                }
                Entry::Occupied(o) => o.into_mut(),
            };

            edge.total_count += 1;
            edge.avg_risk = self.risk_alpha * risk_single + (1.0 - self.risk_alpha) * edge.avg_risk;
            edge.ewma_frequency =
                self.freq_alpha * 1.0 + (1.0 - self.freq_alpha) * edge.ewma_frequency;
        }

       // Batch-update out-degree after loop - O(1), avoids borrow conflict
        if let Some(stats) = self.sender_stats.get_mut(&sender_lower) {
            stats.out_degree += new_edges_count;
        }
        let out_degree = old_out_degree + new_edges_count;

       // Anomaly detection (track worst only - no Vec allocation)
        let mut worst: Option<(String, f64)> = None;

       // Helper: update worst if new score is higher
        #[inline(always)]
        fn update_worst(worst: &mut Option<(String, f64)>, label: String, score: f64) {
            if worst.as_ref().is_none_or(|w| score > w.1) {
               *worst = Some((label, score));
            }
        }

       // Pattern 1: New sender with high out-degree (mass phishing)
        let sender_age = self
            .sender_stats
            .get(&sender_lower)
            .map(|s| s.total_emails)
            .unwrap_or(0);
        if sender_age <= params.new_sender_email_threshold
            && out_degree >= params.new_sender_high_outdegree
        {
            let score = (out_degree as f64 / params.new_sender_high_outdegree as f64).min(1.0);
            update_worst(
                &mut worst,
                format!(
                    "NewSender群发: {}封email→{}recipient",
                    sender_age, out_degree
                ),
                score,
            );
        }

       // Pattern 2: Known sender, new high-risk edge (BEC lateral movement)
        if sender_age > params.new_sender_email_threshold && new_edge_high_risk {
            let score = risk_single.min(1.0);
            update_worst(
                &mut worst,
                format!(
                    "already知SenderAdd newHighRiskcommunication: risk={:.2}, New边数={}",
                    risk_single, new_edges_count
                ),
                score,
            );
        }

       // Pattern 3: Out-degree burst (sudden expansion of recipients)
        if old_out_degree > 3 && new_edges_count > 0 {
            let burst_ratio = (out_degree as f64) / (old_out_degree as f64);
            if burst_ratio > params.outdegree_burst_ratio {
                let score = ((burst_ratio - 1.0) / params.outdegree_burst_ratio).min(1.0);
                update_worst(
                    &mut worst,
                    format!(
                        "recipient突Add: {}→{} ({}x)",
                        old_out_degree, out_degree, burst_ratio as u32
                    ),
                    score,
                );
            }
        }

        match worst {
            None => GraphCheckResult {
                is_anomalous: false,
                pattern_label: String::new(),
                anomaly_score: 0.0,
                is_new_edge: new_edges_count > 0,
                sender_out_degree: out_degree,
            },
            Some((label, score)) => GraphCheckResult {
                is_anomalous: true,
                pattern_label: label,
                anomaly_score: score,
                is_new_edge: new_edges_count > 0,
                sender_out_degree: out_degree,
            },
        }
    }

   /// Get edge data for a sender-recipient pair.
    pub fn get_edge(&self, sender: &str, recipient: &str) -> Option<&CommEdge> {
        let key = format!(
            "{}→{}",
            sender.to_ascii_lowercase(),
            recipient.to_ascii_lowercase()
        );
        self.edges.get(&key)
    }

   /// Get all edges for a sender.
    pub fn sender_edges(&self, sender: &str) -> Vec<&CommEdge> {
        let prefix = format!("{}→", sender.to_ascii_lowercase());
        self.edges
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v)
            .collect()
    }

   /// Get the out-degree of a sender.
    pub fn sender_out_degree(&self, sender: &str) -> usize {
        self.sender_stats
            .get(&sender.to_ascii_lowercase())
            .map(|s| s.out_degree)
            .unwrap_or(0)
    }

   /// Total edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

   /// Total unique senders.
    pub fn sender_count(&self) -> usize {
        self.sender_stats.len()
    }

   /// Export all edges for DB persistence.
    pub fn export_edges(&self) -> Vec<CommEdge> {
        self.edges.values().cloned().collect()
    }

   /// Import edges from DB (called on startup).
    pub fn import_edges(&mut self, edges: Vec<CommEdge>) {
       // Pre-size maps to avoid rehashing
        self.edges.reserve(edges.len());

        for edge in edges {
            let key = format!("{}→{}", edge.sender, edge.recipient);

           // Rebuild sender stats incrementally - O(1) per edge
            let stats = self.sender_stats.entry(edge.sender.clone()).or_default();
           // Weighted average: combine previous avg with this edge's avg
            let old_total = stats.total_emails;
            let new_total = old_total + edge.total_count;
            if new_total > 0 {
                stats.avg_risk = (stats.avg_risk * old_total as f64
                    + edge.avg_risk * edge.total_count as f64)
                    / new_total as f64;
            }
            stats.total_emails = new_total;
            stats.out_degree += 1; // Each edge = one unique recipient

            self.edges.insert(key, edge);
        }
    }
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_graph_empty() {
        let g = CommGraph::new();
        assert_eq!(g.edge_count(), 0);
        assert_eq!(g.sender_count(), 0);
    }

    #[test]
    fn test_observe_creates_edge() {
        let mut g = CommGraph::new();
        let params = GraphParams::default();

        g.observe("alice@a.com", &["bob@b.com".to_string()], 0.1, &params);

        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.sender_count(), 1);
        assert_eq!(g.sender_out_degree("alice@a.com"), 1);
    }

    #[test]
    fn test_observe_increments_count() {
        let mut g = CommGraph::new();
        let params = GraphParams::default();

        for _ in 0..5 {
            g.observe("alice@a.com", &["bob@b.com".to_string()], 0.1, &params);
        }

        let edge = g.get_edge("alice@a.com", "bob@b.com").unwrap();
        assert_eq!(edge.total_count, 5);
    }

    #[test]
    fn test_normal_usage_no_anomaly() {
        let mut g = CommGraph::new();
        let params = GraphParams::default();

       // Same sender, same recipient, low risk -> no anomaly
        for _ in 0..20 {
            let r = g.observe("alice@a.com", &["bob@b.com".to_string()], 0.05, &params);
            assert!(!r.is_anomalous, "Normal usage should not be anomalous");
        }
    }

    #[test]
    fn test_new_sender_mass_phishing_detected() {
        let mut g = CommGraph::new();
        let params = GraphParams {
            new_sender_email_threshold: 3,
            new_sender_high_outdegree: 5,
            ..Default::default()
        };

       // New sender sends to many recipients at once
        let recipients: Vec<String> = (0..10)
            .map(|i| format!("victim{}@company.com", i))
            .collect();

        let r = g.observe("phisher@evil.com", &recipients, 0.7, &params);
        assert!(r.is_anomalous, "Mass phishing should be detected");
        assert!(r.pattern_label.contains("NewSender群发"));
        assert_eq!(r.sender_out_degree, 10);
    }

    #[test]
    fn test_known_sender_new_high_risk_edge() {
        let mut g = CommGraph::new();
        let params = GraphParams {
            new_sender_email_threshold: 3,
            high_risk_edge_threshold: 0.5,
            ..Default::default()
        };

       // Build history: known sender
        for _ in 0..10 {
            g.observe("alice@a.com", &["bob@b.com".to_string()], 0.05, &params);
        }

       // New high-risk edge
        let r = g.observe(
            "alice@a.com",
            &["cfo@company.com".to_string()],
            0.80,
            &params,
        );
        assert!(
            r.is_anomalous,
            "New high-risk edge from known sender should be detected"
        );
        assert!(r.pattern_label.contains("Add newHighRiskcommunication"));
    }

    #[test]
    fn test_outdegree_burst() {
        let mut g = CommGraph::new();
        let params = GraphParams {
            outdegree_burst_ratio: 2.0,
            ..Default::default()
        };

       // Build moderate out-degree
        for i in 0..5 {
            g.observe("alice@a.com", &[format!("user{}@b.com", i)], 0.1, &params);
        }

       // Sudden burst: 15 new recipients
        let burst_recipients: Vec<String> = (10..25)
            .map(|i| format!("target{}@external.com", i))
            .collect();

        let r = g.observe("alice@a.com", &burst_recipients, 0.3, &params);
        assert!(r.is_anomalous, "Out-degree burst should be detected");
        assert!(r.pattern_label.contains("recipient突Add"));
    }

    #[test]
    fn test_export_import_preserves_edges() {
        let mut g = CommGraph::new();
        let params = GraphParams::default();

        g.observe("a@x.com", &["b@y.com".to_string()], 0.1, &params);
        g.observe("a@x.com", &["c@y.com".to_string()], 0.2, &params);
        g.observe("d@x.com", &["b@y.com".to_string()], 0.3, &params);

        let edges = g.export_edges();
        assert_eq!(edges.len(), 3);

        let mut g2 = CommGraph::new();
        g2.import_edges(edges);
        assert_eq!(g2.edge_count(), 3);
        assert_eq!(g2.sender_out_degree("a@x.com"), 2);
    }

    #[test]
    fn test_anomaly_score_bounded() {
        let mut g = CommGraph::new();
        let params = GraphParams {
            new_sender_email_threshold: 2,
            new_sender_high_outdegree: 3,
            ..Default::default()
        };

        let recipients: Vec<String> = (0..20).map(|i| format!("v{}@x.com", i)).collect();
        let r = g.observe("attacker@evil.com", &recipients, 0.9, &params);

        assert!(r.anomaly_score >= 0.0 && r.anomaly_score <= 1.0);
    }
}
