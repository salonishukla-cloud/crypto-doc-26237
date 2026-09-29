use thiserror::Error;

#[derive(Error, Debug)]
pub enum IntegrationError {
    #[error("Document decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Forensic watermark generation failed: {0}")]
    WatermarkGenerationFailed(String),

    #[error("Watermark embedding failed: {0}")]
    WatermarkEmbeddingFailed(String),

    #[error("Watermark extraction failed: {0}")]
    WatermarkExtractionFailed(String),

    #[error("ML-DSA signature or event creation failed: {0}")]
    EventSigningFailed(String),

    #[error("Offline ledger submission or query failed: {0}")]
    LedgerSubmissionFailed(String),

    #[error("Forensic report generation failed: {0}")]
    ReportGenerationFailed(String),
}

pub use crate::report::{ForensicEvidenceReport, ForensicVerdict};
pub use crate::workflow::{DecryptionWorkflowRequest, DecryptionWorkflowResult};
