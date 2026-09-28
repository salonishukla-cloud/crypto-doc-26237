use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Ledger storage error: {0}")]
    StorageError(String),

    #[error("Event already committed or duplicate event ID: {0}")]
    DuplicateEvent(String),

    #[error("Event not found on ledger: {0}")]
    EventNotFound(String),

    #[error("Watermark hash not associated with any recorded decryption event: {0}")]
    WatermarkNotFound(String),

    #[error("Cryptographic ledger verification failed (corrupted block or broken chain): {0}")]
    IntegrityCheckFailed(String),

    #[error("Consensus or synchronization error in offline partition: {0}")]
    ConsensusError(String),
}

/// Verification result certifying ledger record immutability.
#[derive(Debug, Clone)]
pub struct LedgerVerificationResult {
    pub is_valid: bool,
    pub block_height: u64,
    pub block_hash: String,
    pub merkle_valid: bool,
    pub audit_timestamp: String,
}
