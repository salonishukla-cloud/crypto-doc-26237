//! # Member 5 — Integration & Verification Module (`integration`)
//!
//! Owns:
//! - End-to-end Decryption & Provenance Workflow orchestration
//! - Offline forensic verification workstation
//! - Forensic evidence report generation (Human-readable Markdown + Canonical JSON)
//! - Simple Rust + HTML UI
//!
//! ## Required APIs:
//! - `run_decryption_workflow(request, ledger_client)`
//! - `verify_leaked_document(leaked_document_bytes, recipient_public_key, ledger_client)`
//! - `generate_report(report)`

#[path = "../backend/mod.rs"]
pub mod backend;

#[path = "../report.rs"]
pub mod report;

#[path = "../verification.rs"]
pub mod verification;

#[path = "../workflow.rs"]
pub mod workflow;

pub use backend::IntegrationError;
pub use report::{generate_report, ForensicEvidenceReport, ForensicVerdict};
pub use verification::verify_leaked_document;
pub use workflow::{
    run_decryption_workflow, DecryptionWorkflowRequest, DecryptionWorkflowResult,
};

use ledger::PermissionedLedgerClient;

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
        ledger_client: &PermissionedLedgerClient,
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
        recipient_dsa_public_key: &[u8],
        ledger_client: &PermissionedLedgerClient,
    ) -> Result<ForensicEvidenceReport, IntegrationError>;

    /// Formats verified forensic findings into a structured legal/audit evidence report.
    fn generate_report(
        &self,
        report: &ForensicEvidenceReport,
    ) -> Result<String, IntegrationError>;
}

/// Default implementation of [`ForensicOrchestrator`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultForensicOrchestrator;

impl ForensicOrchestrator for DefaultForensicOrchestrator {
    fn run_decryption_workflow(
        &self,
        request: DecryptionWorkflowRequest,
        ledger_client: &PermissionedLedgerClient,
    ) -> Result<DecryptionWorkflowResult, IntegrationError> {
        run_decryption_workflow(request, ledger_client)
    }

    fn verify_leaked_document(
        &self,
        leaked_document_bytes: &[u8],
        recipient_dsa_public_key: &[u8],
        ledger_client: &PermissionedLedgerClient,
    ) -> Result<ForensicEvidenceReport, IntegrationError> {
        verify_leaked_document(leaked_document_bytes, recipient_dsa_public_key, ledger_client)
    }

    fn generate_report(
        &self,
        report: &ForensicEvidenceReport,
    ) -> Result<String, IntegrationError> {
        generate_report(report)
    }
}
