use serde::{Deserialize, Serialize};

/// Canonical Decryption Event representing an immutable record of document access.
///
/// Every module must strictly adhere to these exact field names and types.
/// In accordance with the project contract, field names are fixed:
/// - event_id
/// - document_id
/// - recipient_id
/// - session_id
/// - watermark_id
/// - timestamp
/// - watermark_hash
/// - signature_algorithm
/// - signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionEvent {
    /// Unique identifier for this decryption occurrence (UUIDv4 string).
    pub event_id: String,

    /// Unique identifier or cryptographic digest of the source confidential document.
    pub document_id: String,

    /// Public identifier or fingerprint of the authorized recipient.
    pub recipient_id: String,

    /// Ephemeral decryption session identifier tied to local recipient authentication.
    pub session_id: String,

    /// Unique identifier of the invisible forensic watermark generated for this recipient.
    pub watermark_id: String,

    /// RFC 3339 formatted UTC timestamp marking the exact instant of decryption.
    pub timestamp: String,

    /// Hex-encoded SHA-256 hash of the generated watermark payload bytes.
    pub watermark_hash: String,

    /// Fixed signature algorithm name ("ML-DSA").
    pub signature_algorithm: String,

    /// Post-Quantum ML-DSA signature over the canonical byte representation of the unsigned event fields.
    pub signature: String,
}

/// Unsigned portion of the DecryptionEvent used for deterministic hashing and signature generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedDecryptionEvent {
    pub event_id: String,
    pub document_id: String,
    pub recipient_id: String,
    pub session_id: String,
    pub watermark_id: String,
    pub timestamp: String,
    pub watermark_hash: String,
    pub signature_algorithm: String,
}

impl DecryptionEvent {
    /// Extracts the unsigned fields in a canonical layout suitable for signature verification.
    pub fn to_unsigned(&self) -> UnsignedDecryptionEvent {
        UnsignedDecryptionEvent {
            event_id: self.event_id.clone(),
            document_id: self.document_id.clone(),
            recipient_id: self.recipient_id.clone(),
            session_id: self.session_id.clone(),
            watermark_id: self.watermark_id.clone(),
            timestamp: self.timestamp.clone(),
            watermark_hash: self.watermark_hash.clone(),
            signature_algorithm: self.signature_algorithm.clone(),
        }
    }
}
