//! Training Sample Database Operations (NLP fine-tuning)

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Result;
use serde::Deserialize;
use uuid::Uuid;

use vigilyx_core::security::{
    LABEL_LEGITIMATE, LABEL_OTHER_THREAT, LABEL_PHISHING, LABEL_SOCIAL_ENGINEERING, LABEL_SPOOFING,
    TrainingSample,
};
use vigilyx_parser::MimeParser;
use vigilyx_parser::mime::decode_rfc2047;

use crate::VigilDb;

const TRAINING_EXPORT_MAX_SUBJECT_CHARS: i32 = 500;
const TRAINING_EXPORT_MAX_BODY_CHARS: i32 = 20_000;
const TRAINING_EXPORT_MAX_ADDRESS_CHARS: i32 = 320;
const TRAINING_EXPORT_MAX_COMMENT_CHARS: i32 = 2_000;
const TRAINING_EXPORT_MAX_RCPT_JSON_CHARS: i32 = 64 * 1024;
const REDTEAM_RUNTIME_CORPUS_DIR: &str = "/app/test-corpus/redteam_cases";
const REDTEAM_CREATED_AT: &str = "2026-08-24T00:00:00+00:00";

#[derive(Debug, Deserialize)]
struct RedteamLabelRecord {
    file: String,
    label: String,
    family: String,
    #[serde(default)]
    expected: String,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Deserialize)]
struct RedteamLabelDocument {
    cases: Vec<RedteamLabelRecord>,
}

static REDTEAM_TRAINING_SAMPLES: OnceLock<Vec<TrainingSample>> = OnceLock::new();

/// Database row type (clippy::type_complexity)
type TrainingSampleRow = (
    String,         // id
    String,         // session_id
    i32,            // label
    String,         // label_name
    Option<String>, // subject
    Option<String>, // body_text
    Option<String>, // body_html
    Option<String>, // mail_from
    Option<String>, // rcpt_to (JSON)
    Option<String>, // analyst_comment
    Option<String>, // original_threat_level
    Option<String>, // verdict_id
    String,         // created_at
);

/// Classification fields and bounded session content used to derive a sample
/// from an existing engine verdict. These rows are intentionally kept separate
/// from analyst feedback rows so the label provenance is explicit.
type AutomaticTrainingSampleRow = (
    String,         // verdict id
    String,         // session id
    Option<String>, // threat_type
    String,         // threat_level
    Option<String>, // subject
    Option<String>, // body_text
    Option<String>, // body_html
    Option<String>, // mail_from
    Option<String>, // rcpt_to (JSON)
    String,         // created_at
);

impl VigilDb {
    /// Insert a training sample
    pub async fn insert_training_sample(&self, sample: &TrainingSample) -> Result<()> {
        let rcpt_to_json = serde_json::to_string(&sample.rcpt_to)?;
        sqlx::query(
            r#"
            INSERT INTO training_samples
                (id, session_id, label, label_name, subject, body_text, body_html,
                 mail_from, rcpt_to, analyst_comment, original_threat_level,
                 verdict_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(sample.id.to_string())
        .bind(sample.session_id.to_string())
        .bind(sample.label)
        .bind(&sample.label_name)
        .bind(&sample.subject)
        .bind(&sample.body_text)
        .bind(&sample.body_html)
        .bind(&sample.mail_from)
        .bind(&rcpt_to_json)
        .bind(&sample.analyst_comment)
        .bind(&sample.original_threat_level)
        .bind(sample.verdict_id.as_ref().map(|v| v.to_string()))
        .bind(sample.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query the combined training dataset (pagination, newest first).
    ///
    /// Analyst feedback wins for a session; otherwise an eligible existing
    /// engine verdict supplies the automatic label.
    pub async fn list_training_samples(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<TrainingSample>> {
        let fetch_limit = limit.saturating_add(offset);
        let mut samples = self
            .get_feedback_training_samples(Some(fetch_limit), false)
            .await?;
        samples.extend(
            self.get_automatic_training_samples(Some(fetch_limit), false)
                .await?,
        );
        samples.extend(
            curated_redteam_training_samples()
                .iter()
                .take(fetch_limit as usize)
                .cloned(),
        );
        sort_training_samples(&mut samples, false);
        Ok(samples
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    /// Get all samples in the combined dataset (oldest first for training).
    pub async fn get_all_training_samples(&self) -> Result<Vec<TrainingSample>> {
        self.get_all_training_samples_for_export().await
    }

    /// Get the oldest bounded training samples for an NLP training request.
    ///
    /// Each source is bounded before merging, so a large historical dataset is
    /// not loaded twice just to enforce the request cap.
    pub async fn get_training_samples_for_export(&self, limit: u32) -> Result<Vec<TrainingSample>> {
        let mut samples = self
            .get_feedback_training_samples(Some(limit), true)
            .await?;
        samples.extend(
            self.get_automatic_training_samples(Some(limit), true)
                .await?,
        );
        samples.extend(
            curated_redteam_training_samples()
                .iter()
                .take(limit as usize)
                .cloned(),
        );
        sort_training_samples(&mut samples, true);
        samples.truncate(limit as usize);
        Ok(samples)
    }

    /// Get the complete bounded training dataset for an administrator export.
    ///
    /// This includes both explicit analyst feedback and existing classified
    /// verdicts. A feedback row takes precedence over the automatically derived
    /// row for the same session. The automatic row retains its source family and
    /// is marked in `label_source` for auditability.
    pub async fn get_all_training_samples_for_export(&self) -> Result<Vec<TrainingSample>> {
        let mut samples = self.get_feedback_training_samples(None, true).await?;
        samples.extend(self.get_automatic_training_samples(None, true).await?);
        samples.extend(curated_redteam_training_samples().iter().cloned());
        sort_training_samples(&mut samples, true);
        Ok(samples)
    }

    async fn get_feedback_training_samples(
        &self,
        limit: Option<u32>,
        ascending: bool,
    ) -> Result<Vec<TrainingSample>> {
        let order = if ascending {
            "ORDER BY created_at ASC, id ASC"
        } else {
            "ORDER BY created_at DESC, id DESC"
        };
        let query = format!(
            r#"
            SELECT id, session_id, label, label_name,
                   LEFT(subject, $2),
                   LEFT(body_text, $3),
                   LEFT(body_html, $3),
                   LEFT(mail_from, $4),
                   CASE
                     WHEN rcpt_to IS NULL THEN rcpt_to
                     WHEN length(rcpt_to) > $6 THEN '[]'
                     ELSE rcpt_to
                   END,
                   LEFT(analyst_comment, $5),
                   original_threat_level,
                   verdict_id, created_at
            FROM training_samples
            {order}
            LIMIT $1
            "#
        );
        let rows: Vec<TrainingSampleRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(limit.map(i64::from))
            .bind(TRAINING_EXPORT_MAX_SUBJECT_CHARS)
            .bind(TRAINING_EXPORT_MAX_BODY_CHARS)
            .bind(TRAINING_EXPORT_MAX_ADDRESS_CHARS)
            .bind(TRAINING_EXPORT_MAX_COMMENT_CHARS)
            .bind(TRAINING_EXPORT_MAX_RCPT_JSON_CHARS)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(row_to_training_sample).collect()
    }

    async fn get_automatic_training_samples(
        &self,
        limit: Option<u32>,
        ascending: bool,
    ) -> Result<Vec<TrainingSample>> {
        let order = if ascending {
            "ORDER BY v.created_at ASC, v.id ASC"
        } else {
            "ORDER BY v.created_at DESC, v.id DESC"
        };
        let query = format!(
            r#"
            SELECT v.id, v.session_id, NULLIF(v.threat_type, ''), v.threat_level,
                   LEFT(s.subject, $2),
                   LEFT(s.content->>'body_text', $3),
                   LEFT(s.content->>'body_html', $3),
                   LEFT(s.mail_from, $4),
                   CASE
                     WHEN s.rcpt_to IS NULL THEN s.rcpt_to
                     WHEN length(s.rcpt_to) > $5 THEN '[]'
                     ELSE s.rcpt_to
                   END,
                   v.created_at
            FROM security_verdicts v
            INNER JOIN sessions s ON s.id = v.session_id
            WHERE v.verdict_origin = 'native'
              AND (
                    NULLIF(v.threat_type, '') IN (
                        'phishing', 'social_engineering', 'bec_fraud',
                        'malware_delivery', 'mailbox_enumeration',
                        'injection_abuse', 'malicious_other'
                    )
                    OR (
                        NULLIF(v.threat_type, '') IS NULL
                        AND v.threat_level IN ('safe', 'low')
                    )
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM training_samples feedback
                    WHERE feedback.session_id = v.session_id
                  )
            {order}
            LIMIT $1
            "#
        );
        let rows: Vec<AutomaticTrainingSampleRow> =
            sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
                .bind(limit.map(i64::from))
                .bind(TRAINING_EXPORT_MAX_SUBJECT_CHARS)
                .bind(TRAINING_EXPORT_MAX_BODY_CHARS)
                .bind(TRAINING_EXPORT_MAX_ADDRESS_CHARS)
                .bind(TRAINING_EXPORT_MAX_RCPT_JSON_CHARS)
                .fetch_all(&self.pool)
                .await?;

        Ok(rows
            .into_iter()
            .filter_map(row_to_automatic_training_sample)
            .collect())
    }

    async fn get_automatic_training_sample_counts(&self) -> Result<Vec<(String, String, i64)>> {
        let rows = sqlx::query_as(
            r#"
            SELECT COALESCE(NULLIF(v.threat_type, ''), ''), v.threat_level, COUNT(*)
            FROM security_verdicts v
            INNER JOIN sessions s ON s.id = v.session_id
            WHERE v.verdict_origin = 'native'
              AND (
                    NULLIF(v.threat_type, '') IN (
                        'phishing', 'social_engineering', 'bec_fraud',
                        'malware_delivery', 'mailbox_enumeration',
                        'injection_abuse', 'malicious_other'
                    )
                    OR (
                        NULLIF(v.threat_type, '') IS NULL
                        AND v.threat_level IN ('safe', 'low')
                    )
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM training_samples feedback
                    WHERE feedback.session_id = v.session_id
                  )
            GROUP BY COALESCE(NULLIF(v.threat_type, ''), ''), v.threat_level
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Delete training sample
    pub async fn delete_training_sample(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM training_samples WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Statistics: count both feedback and automatically classified samples.
    pub async fn get_training_sample_counts(&self) -> Result<HashMap<String, u64>> {
        let feedback_rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT label_name, COUNT(*) as cnt
            FROM training_samples
            GROUP BY label_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let automatic_rows = self.get_automatic_training_sample_counts().await?;

        let mut counts = HashMap::new();
        for (label_name, cnt) in feedback_rows {
            *counts.entry(label_name).or_insert(0) += cnt.max(0) as u64;
        }
        for (threat_type, threat_level, cnt) in automatic_rows {
            if let Some((_, label_name)) = automatic_label(&threat_type, &threat_level) {
                *counts.entry(label_name.to_string()).or_insert(0) += cnt.max(0) as u64;
            }
        }
        for sample in curated_redteam_training_samples() {
            *counts.entry(sample.label_name.clone()).or_insert(0) += 1;
        }
        Ok(counts)
    }

    /// Total count in the combined training dataset.
    pub async fn count_training_samples(&self) -> Result<u64> {
        Ok(self.get_training_sample_counts().await?.values().sum())
    }

    /// Modify analyst-feedback sample label. Automatically derived rows are
    /// read-only and can be overridden by submitting feedback for the session.
    pub async fn update_training_sample_label(
        &self,
        id: &str,
        label: i32,
        label_name: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE training_samples SET label = $1, label_name = $2 WHERE id = $3")
                .bind(label)
                .bind(label_name)
                .bind(id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Check if an explicit training sample exists by session_id.
    pub async fn training_sample_exists(&self, session_id: &str) -> Result<bool> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM training_samples WHERE session_id = $1")
                .bind(session_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }
}

fn sort_training_samples(samples: &mut [TrainingSample], ascending: bool) {
    samples.sort_by(|left, right| {
        let ordering = left.created_at.cmp(&right.created_at);
        let ordering = if ascending {
            ordering
        } else {
            ordering.reverse()
        };
        ordering.then_with(|| {
            let ordering = left.id.cmp(&right.id);
            if ascending {
                ordering
            } else {
                ordering.reverse()
            }
        })
    });
}

fn automatic_label(threat_type: &str, threat_level: &str) -> Option<(i32, &'static str)> {
    match threat_type.trim() {
        "phishing" => Some((LABEL_PHISHING, "phishing")),
        "social_engineering" => Some((LABEL_SOCIAL_ENGINEERING, "social_engineering")),
        "bec_fraud"
        | "malware_delivery"
        | "mailbox_enumeration"
        | "injection_abuse"
        | "malicious_other" => Some((LABEL_OTHER_THREAT, "other_threat")),
        "" if matches!(threat_level, "safe" | "low") => Some((LABEL_LEGITIMATE, "legitimate")),
        _ => None,
    }
}

/// Map the curated corpus family taxonomy to the model's five-class labels.
/// The source family remains in `source_threat_type` so this reduction is
/// auditable in exported JSONL and can be revised without losing provenance.
fn curated_redteam_label(label: &str, family: &str) -> Option<(i32, &'static str)> {
    if label == "benign" {
        return Some((LABEL_LEGITIMATE, "legitimate"));
    }
    if label != "malicious" {
        return None;
    }

    if family == "identity_spoof" {
        return Some((LABEL_SPOOFING, "spoofing"));
    }
    if matches!(
        family,
        "bec" | "pii_harvest" | "social_trust" | "subsidy_fraud" | "toad"
    ) {
        return Some((LABEL_SOCIAL_ENGINEERING, "social_engineering"));
    }
    if matches!(
        family,
        "account_phishing"
            | "credential_harvest"
            | "encoding_evasion"
            | "language_coverage"
            | "link_obfuscation"
            | "quishing"
            | "redirect_attachment"
            | "sanitizer_evasion"
            | "structure_evasion"
            | "visual_lure"
    ) {
        return Some((LABEL_PHISHING, "phishing"));
    }

    // Malware and other explicitly malicious families have no dedicated
    // five-class head, so retain them under the model's catch-all class.
    Some((LABEL_OTHER_THREAT, "other_threat"))
}

fn curated_redteam_corpus_dir() -> Option<PathBuf> {
    [
        PathBuf::from(REDTEAM_RUNTIME_CORPUS_DIR),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vigilyx-engine/tests/redteam_cases"),
    ]
    .into_iter()
    .find(|path| path.is_dir())
}

fn read_redteam_labels(root: &Path) -> Vec<RedteamLabelRecord> {
    let mut records = Vec::new();
    if let Ok(raw) = std::fs::read_to_string(root.join("labels.json"))
        && let Ok(document) = serde_json::from_str::<RedteamLabelDocument>(&raw)
    {
        records.extend(document.cases);
    }
    if let Ok(raw) = std::fs::read_to_string(root.join("synth/labels.jsonl")) {
        for line in raw.lines().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<RedteamLabelRecord>(line) {
                Ok(record) => records.push(record),
                Err(error) => tracing::warn!(%error, "Skipping malformed redteam label record"),
            }
        }
    }
    records
}

fn safe_redteam_file(root: &Path, relative: &str) -> Option<PathBuf> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || !relative_path
            .extension()
            .is_some_and(|extension| extension == "eml")
    {
        return None;
    }
    let path = root.join(relative_path);
    path.is_file().then_some(path)
}

fn redteam_header(content: &vigilyx_core::EmailContent, name: &str) -> Option<String> {
    content
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| decode_rfc2047(value).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn load_curated_redteam_training_samples() -> Vec<TrainingSample> {
    let Some(root) = curated_redteam_corpus_dir() else {
        tracing::debug!("Curated redteam corpus is not present in this runtime image");
        return Vec::new();
    };

    let parser = MimeParser::new();
    let created_at = chrono::DateTime::parse_from_rfc3339(REDTEAM_CREATED_AT)
        .expect("valid redteam corpus timestamp")
        .with_timezone(&chrono::Utc);
    let mut seen_files = HashSet::new();
    let mut samples = Vec::new();

    for record in read_redteam_labels(&root) {
        // This fixture is explicitly a parser coverage contract, not a
        // malicious/benign ground-truth label. Never use it for fine-tuning.
        if record.family == "coverage_gap_contract" || record.expected == "regression_contract" {
            continue;
        }
        if !seen_files.insert(record.file.clone()) {
            continue;
        }
        let Some(path) = safe_redteam_file(&root, &record.file) else {
            tracing::warn!(file = %record.file, "Skipping missing or unsafe redteam training file");
            continue;
        };
        let Some((label, label_name)) = curated_redteam_label(&record.label, &record.family) else {
            tracing::warn!(file = %record.file, label = %record.label, "Skipping unknown redteam label");
            continue;
        };
        let Ok(raw) = std::fs::read(&path) else {
            tracing::warn!(file = %record.file, "Skipping unreadable redteam training file");
            continue;
        };
        let content = parser.parse(&raw).unwrap_or_else(|_| {
            let mut fallback = vigilyx_core::EmailContent::new();
            fallback.body_text = Some(String::from_utf8_lossy(&raw).into_owned());
            fallback
        });
        let id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("vigilyx:redteam:{relative}", relative = record.file).as_bytes(),
        );
        let subject = redteam_header(&content, "Subject");
        let mail_from = redteam_header(&content, "From");
        let rcpt_to = redteam_header(&content, "To").into_iter().collect();
        let note = if record.note.trim().is_empty() {
            None
        } else {
            Some(format!("Curated redteam corpus: {}", record.note.trim()))
        };

        samples.push(TrainingSample {
            id,
            session_id: id,
            label,
            label_name: label_name.to_string(),
            subject,
            body_text: content.body_text,
            body_html: content.body_html,
            mail_from,
            rcpt_to,
            analyst_comment: note,
            original_threat_level: String::new(),
            verdict_id: None,
            created_at,
            label_source: "curated_redteam".to_string(),
            source_threat_type: Some(record.family),
        });
    }

    samples.sort_by_key(|sample| sample.id);
    tracing::info!(
        count = samples.len(),
        "Loaded curated redteam training samples"
    );
    samples
}

fn curated_redteam_training_samples() -> &'static [TrainingSample] {
    REDTEAM_TRAINING_SAMPLES
        .get_or_init(load_curated_redteam_training_samples)
        .as_slice()
}

fn row_to_automatic_training_sample(row: AutomaticTrainingSampleRow) -> Option<TrainingSample> {
    let (
        id,
        session_id,
        threat_type,
        threat_level,
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to_json,
        created_at,
    ) = row;
    let threat_type_for_label = threat_type.as_deref().unwrap_or("");
    let (label, label_name) = automatic_label(threat_type_for_label, &threat_level)?;
    let id = Uuid::parse_str(&id).ok()?;
    let session_id = Uuid::parse_str(&session_id).ok()?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .ok()?
        .with_timezone(&chrono::Utc);
    let rcpt_to = rcpt_to_json
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default();

    Some(TrainingSample {
        id,
        session_id,
        label,
        label_name: label_name.to_string(),
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to,
        analyst_comment: None,
        original_threat_level: threat_level,
        verdict_id: Some(id),
        created_at,
        label_source: "security_verdict".to_string(),
        source_threat_type: threat_type,
    })
}

/// Convert database row to TrainingSample
fn row_to_training_sample(row: TrainingSampleRow) -> Result<TrainingSample> {
    let (
        id,
        session_id,
        label,
        label_name,
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to_json,
        analyst_comment,
        original_threat_level,
        verdict_id,
        created_at,
    ) = row;

    let rcpt_to: Vec<String> = rcpt_to_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let verdict_id = verdict_id.and_then(|v| Uuid::parse_str(&v).ok());

    Ok(TrainingSample {
        id: Uuid::parse_str(&id)?,
        session_id: Uuid::parse_str(&session_id)?,
        label,
        label_name,
        subject,
        body_text,
        body_html,
        mail_from,
        rcpt_to,
        analyst_comment,
        original_threat_level: original_threat_level.unwrap_or_default(),
        verdict_id,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&chrono::Utc),
        label_source: "analyst_feedback".to_string(),
        source_threat_type: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_labels_reuse_existing_verdict_classification() {
        assert_eq!(
            automatic_label("phishing", "high"),
            Some((LABEL_PHISHING, "phishing"))
        );
        assert_eq!(
            automatic_label("social_engineering", "medium"),
            Some((LABEL_SOCIAL_ENGINEERING, "social_engineering"))
        );
        assert_eq!(
            automatic_label("bec_fraud", "high"),
            Some((LABEL_OTHER_THREAT, "other_threat"))
        );
        assert_eq!(
            automatic_label("", "safe"),
            Some((LABEL_LEGITIMATE, "legitimate"))
        );
        assert_eq!(automatic_label("", "medium"), None);
    }

    #[test]
    fn curated_redteam_labels_map_to_model_classes() {
        assert_eq!(
            curated_redteam_label("benign", "ham_business"),
            Some((LABEL_LEGITIMATE, "legitimate"))
        );
        assert_eq!(
            curated_redteam_label("malicious", "identity_spoof"),
            Some((LABEL_SPOOFING, "spoofing"))
        );
        assert_eq!(
            curated_redteam_label("malicious", "bec"),
            Some((LABEL_SOCIAL_ENGINEERING, "social_engineering"))
        );
        assert_eq!(
            curated_redteam_label("malicious", "account_phishing"),
            Some((LABEL_PHISHING, "phishing"))
        );
    }

    #[test]
    fn curated_redteam_corpus_has_stable_labeled_samples() {
        let root = curated_redteam_corpus_dir().expect("redteam corpus");
        let samples = load_curated_redteam_training_samples();
        // Keep this invariant aligned with the loader: label manifests may
        // intentionally contain records for fixtures that are not present in
        // a runtime image, and duplicate/unknown records are not training
        // samples. Counting the raw manifest made this test fail whenever
        // the corpus was split between source and runtime artifacts.
        let expected = read_redteam_labels(&root)
            .into_iter()
            .filter(|record| {
                record.family != "coverage_gap_contract" && record.expected != "regression_contract"
            })
            .filter(|record| safe_redteam_file(&root, &record.file).is_some())
            .filter(|record| curated_redteam_label(&record.label, &record.family).is_some())
            .map(|record| record.file)
            .collect::<HashSet<_>>()
            .len();
        assert_eq!(samples.len(), expected);
        assert!(
            samples
                .iter()
                .all(|sample| sample.label_source == "curated_redteam")
        );
        assert!(samples.iter().all(|sample| sample.verdict_id.is_none()));
        assert!(samples
            .iter()
            .all(|sample| sample.source_threat_type.as_deref() != Some("coverage_gap_contract")));
    }
}
