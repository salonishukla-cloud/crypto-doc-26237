//! Error definitions for the Encryption and Key Management module.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("AES-256-GCM symmetric encryption failed: {0}")]
    SymmetricEncryptionFailed(String),

    #[error("Decryption failed: authentication tag mismatch or corrupted ciphertext")]
    DecryptionAuthenticationFailed,

    #[error("Post-Quantum ML-KEM encapsulation failed for recipient '{0}': {1}")]
    KemEncapsulationFailed(String, String),

    #[error("Post-Quantum ML-KEM decapsulation failed: {0}")]
    KemDecapsulationFailed(String),

    #[error("Recipient '{0}' is not authorized in this document package")]
    RecipientNotAuthorized(String),

    #[error("Invalid document package format: {0}")]
    InvalidPackage(String),

    #[error("Invalid magic header: expected 'CRPTDOC1', found '{0}'")]
    InvalidMagicHeader(String),

    #[error("Unsupported package format version: {0}")]
    UnsupportedVersion(u16),

    #[error("Key management error: {0}")]
    KeyManagerError(String),

    #[error("Key pair not found for recipient '{0}'")]
    KeyNotFound(String),

    #[error("Key version mismatch: expected {expected}, found {found}")]
    KeyVersionMismatch { expected: u32, found: u32 },

    #[error("Key serialization / deserialization error: {0}")]
    KeySerializationError(String),

    #[error("I/O error during offline key or document storage: {0}")]
    IoError(#[from] std::io::Error),
}
