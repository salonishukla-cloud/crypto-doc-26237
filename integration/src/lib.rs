//! # Member 5 — Integration Module
//!
//! Owns:
//! - End-to-end Decryption & Provenance Workflow orchestration
//! - Offline forensic verification workstation
//! - Forensic evidence report generation
//! - UI shell and final demonstration
//!
//! Required API Contract:
//! - `run_decryption_workflow()`
//! - `verify_leaked_document()`
//! - `generate_report()`

pub mod backend;
pub mod verification;

pub use backend::{DecryptionWorkflowRequest, DecryptionWorkflowResult, IntegrationError};
pub use verification::ForensicEvidenceReport;

/// Primary API contract for Member 5 (Integration).
pub trait ForensicOrchestrator {
    /// Executes the complete recipient decryption pipeline:
    ///
    /// 1. Calls Member 1 to decrypt AES-256-GCM document payload via ML-KEM.
    /// 2. Calls Member 2 to generate and invisibly embed forensic watermark.
    /// 3. Calls Member 3 to construct unsigned DecryptionEvent and sign with ML-DSA.
    /// 4. Calls Member 4 to submit signed DecryptionEvent to offline DLT.
    /// 5. Returns watermarked PDF to recipient and logs audit record.
    fn run_decryption_workflow(
        &self,
        request: DecryptionWorkflowRequest,
    ) -> Result<DecryptionWorkflowResult, IntegrationError>;

    /// Forensic verification workstation entrypoint:
    ///
    /// 1. Calls Member 2 to extract watermark from a suspected leaked PDF.
    /// 2. Calls Member 4 to find recorded DecryptionEvent on the offline ledger.
    /// 3. Calls Member 3 to verify ML-DSA signature over event canonical bytes.
    /// 4. Calls Member 4 to verify ledger Merkle root and block chain integrity.
    /// 5. Correlates recipient identity with non-repudiation proof.
    fn verify_leaked_document(
        &self,
        leaked_document_bytes: &[u8],
    ) -> Result<ForensicEvidenceReport, IntegrationError>;

    /// Formats verified forensic findings into a structured legal/audit evidence report.
    fn generate_report(
        &self,
        report: &ForensicEvidenceReport,
    ) -> Result<String, IntegrationError>;
}
