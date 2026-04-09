

use tracing::{error, info};
use uuid::Uuid;
use vigilyx_db::VigilDb;
use vigilyx_db::security::quarantine::QuarantineStoreRequest;


#[allow(clippy::too_many_arguments)]
pub async fn store_quarantine(
    db: &VigilDb,
    session_id: &Uuid,
    mail_from: Option<&str>,
    rcpt_to: &[String],
    subject: Option<&str>,
    raw_eml: &[u8],
    threat_level: &str,
    reason: &str,
) -> bool {
    let req = QuarantineStoreRequest {
        session_id,
        verdict_id: None,
        mail_from,
        rcpt_to,
        subject,
        raw_eml,
        threat_level,
        reason: Some(reason),
    };

    match db.quarantine_store(&req).await {
        Ok(id) => {
            info!(
                quarantine_id = %id,
                session_id = %session_id,
                threat_level,
                "Email quarantined"
            );
            true
        }
        Err(e) => {
            error!(
                session_id = %session_id,
                error = %e,
                "Failed to quarantine email"
            );
            false
        }
    }
}
