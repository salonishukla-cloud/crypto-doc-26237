use serde::{Deserialize, Serialize};

/// Key Encapsulation Envelope protecting the symmetric Document Encryption Key (DEK)
/// for a single authorized recipient using ML-KEM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientKEMEnvelope {
    /// Recipient's public identifier / identity key fingerprint.
    pub recipient_id: String,

    /// Encapsulated cipher key bytes produced by ML-KEM encapsulation (hex or base64 encoded).
    pub encapsulated_key: String,

    /// Encrypted document encryption key (DEK) wrapped with the derived shared secret.
    pub wrapped_dek: String,
}

/// Metadata and payload container for the encrypted document distribution package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDocumentPackage {
    /// Format identifier and version.
    pub magic: String,
    pub version: u16,

    /// Canonical identifier of the document.
    pub document_id: String,

    /// Document title or display name (unencrypted or pseudonymous).
    pub title: String,

    /// Nonce/IV used for AES-256-GCM symmetric document encryption (hex encoded).
    pub nonce: String,

    /// Authentication tag for AES-256-GCM (hex encoded).
    pub auth_tag: String,

    /// Encrypted document ciphertext payload (base64 encoded or byte path).
    pub ciphertext: String,

    /// List of authorized recipient KEM envelopes for multi-recipient broadcast.
    pub recipient_envelopes: Vec<RecipientKEMEnvelope>,

    /// Creation timestamp of the package (RFC 3339).
    pub created_at: String,
}

/// Metadata describing a generated invisible forensic watermark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkMetadata {
    /// Watermark unique identifier.
    pub watermark_id: String,

    /// Bound recipient identifier.
    pub recipient_id: String,

    /// Associated document identifier.
    pub document_id: String,

    /// SHA-256 digest of the watermark bit payload.
    pub watermark_hash: String,

    /// Timestamp of watermark generation.
    pub generated_at: String,

    /// Length in bits or payload format version.
    pub payload_length_bits: usize,
}
