use thiserror::Error;

#[derive(Error, Debug)]
pub enum IntegrationError {
    #[error("Encryption module error during workflow: {0}")]
    EncryptionModuleError(String),

    #[error("Watermark module error during workflow: {0}")]
    WatermarkModuleError(String),

    #[error("Post-Quantum Crypto module error during workflow: {0}")]
    PqCryptoModuleError(String),

    #[error("Ledger module error during workflow: {0}")]
    LedgerModuleError(String),

    #[error("Forensic analysis failed to identify or match watermark: {0}")]
    ForensicAttributionFailed(String),

    #[error("Verification failure: signature or ledger record corrupted: {0}")]
    VerificationMismatch(String),
}

/// Request parameters for initiating the recipient decryption workflow.
#[derive(Debug, Clone)]
pub struct DecryptionWorkflowRequest {
    pub package_bytes: Vec<u8>,
    pub recipient_id: String,
    pub recipient_kem_secret_key: Vec<u8>,
    pub recipient_dsa_private_key: Vec<u8>,
}

/// Result of complete decryption, watermarking, signing, and ledger committing workflow.
#[derive(Debug, Clone)]
pub struct DecryptionWorkflowResult {
    pub document_id: String,
    pub session_id: String,
    pub watermarked_pdf_bytes: Vec<u8>,
    pub event_id: String,
    pub watermark_id: String,
    pub ledger_receipt_hash: String,
}
