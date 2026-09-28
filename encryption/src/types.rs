use shared::models::{EncryptedDocumentPackage, RecipientKEMEnvelope};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("AES-256-GCM symmetric encryption failed: {0}")]
    SymmetricEncryptionFailed(String),

    #[error("AES-256-GCM symmetric decryption failed or authentication tag mismatch: {0}")]
    DecryptionAuthenticationFailed(String),

    #[error("ML-KEM key encapsulation failed for recipient '{0}': {1}")]
    KemEncapsulationFailed(String, String),

    #[error("ML-KEM decapsulation failed: {0}")]
    KemDecapsulationFailed(String),

    #[error("Key management error: {0}")]
    KeyManagementError(String),

    #[error("Invalid package format or corrupted envelope: {0}")]
    InvalidPackage(String),

    #[error("Recipient '{0}' not authorized in this document package")]
    RecipientNotAuthorized(String),
}

/// Request parameters for packaging and encrypting a confidential document.
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub document_id: String,
    pub title: String,
    pub plaintext_bytes: Vec<u8>,
    pub recipient_kem_public_keys: Vec<RecipientKeyDescriptor>,
}

/// Description of an authorized recipient's Post-Quantum KEM public key.
#[derive(Debug, Clone)]
pub struct RecipientKeyDescriptor {
    pub recipient_id: String,
    pub kem_public_key_bytes: Vec<u8>,
}

/// Request parameters for decrypting a document package.
#[derive(Debug, Clone)]
pub struct DecryptionRequest {
    pub package: EncryptedDocumentPackage,
    pub recipient_id: String,
    pub kem_secret_key_bytes: Vec<u8>,
}

/// Result of successful document decryption.
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    pub document_id: String,
    pub plaintext_bytes: Vec<u8>,
    pub session_id: String,
}
