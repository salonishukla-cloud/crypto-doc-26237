//! Document packaging container and serialization routines.
//!
//! Enforces the canonical sealed package format with magic header 'CRPTDOC1',
//! authentication tags, symmetric ciphertext, and multi-recipient ML-KEM envelopes.

use crate::errors::EncryptionError;
pub use shared::models::{EncryptedDocumentPackage, RecipientKEMEnvelope};
use shared::constants::{PACKAGE_FORMAT_VERSION, PACKAGE_MAGIC_HEADER};
use std::fs;
use std::path::Path;

/// Builder for constructing an `EncryptedDocumentPackage`.
pub struct PackageBuilder {
    document_id: String,
    title: String,
    nonce: String,
    auth_tag: String,
    ciphertext: String,
    recipient_envelopes: Vec<RecipientKEMEnvelope>,
    created_at: String,
}

impl PackageBuilder {
    pub fn new(document_id: &str, title: &str) -> Self {
        Self {
            document_id: document_id.to_string(),
            title: title.to_string(),
            nonce: String::new(),
            auth_tag: String::new(),
            ciphertext: String::new(),
            recipient_envelopes: Vec::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn with_cipher_payload(mut self, nonce_hex: &str, auth_tag_hex: &str, ciphertext_hex: &str) -> Self {
        self.nonce = nonce_hex.to_string();
        self.auth_tag = auth_tag_hex.to_string();
        self.ciphertext = ciphertext_hex.to_string();
        self
    }

    pub fn with_recipient_envelopes(mut self, envelopes: Vec<RecipientKEMEnvelope>) -> Self {
        self.recipient_envelopes = envelopes;
        self
    }

    pub fn build(self) -> Result<EncryptedDocumentPackage, EncryptionError> {
        if self.ciphertext.is_empty() {
            return Err(EncryptionError::InvalidPackage("Ciphertext cannot be empty".to_string()));
        }
        if self.recipient_envelopes.is_empty() {
            return Err(EncryptionError::InvalidPackage("Package must contain at least one recipient envelope".to_string()));
        }

        let magic = String::from_utf8_lossy(PACKAGE_MAGIC_HEADER).to_string();

        Ok(EncryptedDocumentPackage {
            magic,
            version: PACKAGE_FORMAT_VERSION,
            document_id: self.document_id,
            title: self.title,
            nonce: self.nonce,
            auth_tag: self.auth_tag,
            ciphertext: self.ciphertext,
            recipient_envelopes: self.recipient_envelopes,
            created_at: self.created_at,
        })
    }
}

/// Serializes an `EncryptedDocumentPackage` to a JSON string or bytes.
pub fn serialize_package(package: &EncryptedDocumentPackage) -> Result<Vec<u8>, EncryptionError> {
    serde_json::to_vec_pretty(package)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Package serialization failed: {}", e)))
}

/// Deserializes raw bytes into a verified `EncryptedDocumentPackage`.
pub fn deserialize_package(raw_bytes: &[u8]) -> Result<EncryptedDocumentPackage, EncryptionError> {
    let package: EncryptedDocumentPackage = serde_json::from_slice(raw_bytes)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Package JSON deserialization failed: {}", e)))?;

    validate_package(&package)?;
    Ok(package)
}

/// Validates package integrity, magic header, and version constraints.
pub fn validate_package(package: &EncryptedDocumentPackage) -> Result<(), EncryptionError> {
    let expected_magic = String::from_utf8_lossy(PACKAGE_MAGIC_HEADER);
    if package.magic != expected_magic {
        return Err(EncryptionError::InvalidMagicHeader(package.magic.clone()));
    }

    if package.version != PACKAGE_FORMAT_VERSION {
        return Err(EncryptionError::UnsupportedVersion(package.version));
    }

    if package.recipient_envelopes.is_empty() {
        return Err(EncryptionError::InvalidPackage("Zero recipient envelopes found".to_string()));
    }

    Ok(())
}

/// Saves a document package to an air-gapped file path.
pub fn save_package_to_file<P: AsRef<Path>>(package: &EncryptedDocumentPackage, path: P) -> Result<(), EncryptionError> {
    let bytes = serialize_package(package)?;
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

/// Loads a document package from an air-gapped file path.
pub fn load_package_from_file<P: AsRef<Path>>(path: P) -> Result<EncryptedDocumentPackage, EncryptionError> {
    let bytes = fs::read(path.as_ref())?;
    deserialize_package(&bytes)
}
