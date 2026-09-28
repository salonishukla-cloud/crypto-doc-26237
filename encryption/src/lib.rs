//! # Member 1 — Encryption Module
//!
//! Owns:
//! - AES-256-GCM symmetric authenticated encryption
//! - ML-KEM post-quantum key establishment
//! - Key Management
//! - Document Packaging
//!
//! Required API Contract:
//! - `encrypt_document()`
//! - `decrypt_document()`
//! - `protect_document_key()`

pub mod cipher;
pub mod kem;
pub mod package;
pub mod types;

pub use cipher::SymmetricCipher;
pub use kem::KemEngine;
pub use package::DocumentPackager;
pub use types::*;

use shared::models::{EncryptedDocumentPackage, RecipientKEMEnvelope};

/// Primary API contract for Member 1 (Encryption).
pub trait EncryptionService {
    /// Encrypts a confidential document for one or more authorized recipients.
    ///
    /// 1. Generates a random 256-bit symmetric Document Encryption Key (DEK).
    /// 2. Encrypts the plaintext PDF using AES-256-GCM.
    /// 3. Protects the DEK for each recipient using `protect_document_key()` via ML-KEM.
    /// 4. Assembles and returns the sealed `EncryptedDocumentPackage`.
    fn encrypt_document(
        &self,
        request: EncryptionRequest,
    ) -> Result<EncryptedDocumentPackage, EncryptionError>;

    /// Decrypts an encrypted document package for an authenticated recipient.
    ///
    /// 1. Locates the recipient's KEM envelope inside the package.
    /// 2. Decapsulates the shared secret using the recipient's ML-KEM secret key.
    /// 3. Unwraps the symmetric DEK.
    /// 4. Decrypts and authenticates the document ciphertext using AES-256-GCM.
    /// 5. Returns the raw plaintext PDF and established session identifier.
    fn decrypt_document(
        &self,
        request: DecryptionRequest,
    ) -> Result<DecryptionResult, EncryptionError>;

    /// Protects a symmetric Document Encryption Key (DEK) for a specific recipient
    /// using ML-KEM post-quantum key encapsulation.
    ///
    /// Produces a `RecipientKEMEnvelope` containing the encapsulated key and wrapped DEK.
    fn protect_document_key(
        &self,
        recipient_id: &str,
        recipient_kem_public_key: &[u8],
        dek: &[u8; 32],
    ) -> Result<RecipientKEMEnvelope, EncryptionError>;
}
