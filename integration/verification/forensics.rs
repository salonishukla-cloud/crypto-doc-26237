use serde::{Deserialize, Serialize};
use shared::models::DecryptionEvent;

/// Comprehensive Forensic Evidence Report produced during leak investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicEvidenceReport {
    /// Unique report tracking identifier.
    pub report_id: String,

    /// RFC 3339 timestamp of forensic report generation.
    pub generated_at: String,

    /// Investigator ID / workstation fingerprint conducting analysis.
    pub investigator_id: String,

    /// Leaked document hash and properties.
    pub leaked_document_sha256: String,

    /// Extracted watermark identification details.
    pub watermark_id: String,
    pub watermark_hash: String,
    pub extraction_confidence: f64,

    /// Ledger event matched to the watermark.
    pub matched_event: DecryptionEvent,

    /// Cryptographic verification statuses.
    pub recipient_signature_valid: bool,
    pub ledger_integrity_valid: bool,

    /// Attributed recipient identity.
    pub attributed_recipient_id: String,

    /// Legal non-repudiation executive summary.
    pub executive_summary: String,
}
