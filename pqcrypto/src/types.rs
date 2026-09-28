use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqCryptoError {
    #[error("ML-DSA keypair generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("ML-DSA signature generation failed: {0}")]
    SigningFailed(String),

    #[error("ML-DSA signature verification failed: invalid signature or tampered data: {0}")]
    VerificationFailed(String),

    #[error("Canonical event serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Malformed identity public key bytes: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid event schema or missing mandatory fields: {0}")]
    InvalidEventSchema(String),
}

/// Request parameters to construct an unsigned DecryptionEvent.
#[derive(Debug, Clone)]
pub struct CreateEventParams {
    pub document_id: String,
    pub recipient_id: String,
    pub session_id: String,
    pub watermark_id: String,
    pub watermark_hash: String,
}

/// Keypair container for ML-DSA Post-Quantum Digital Signature identity.
#[derive(Debug, Clone)]
pub struct PqIdentityKeypair {
    pub recipient_id: String,
    pub public_key_bytes: Vec<u8>,
    pub secret_key_bytes: Vec<u8>,
}
