//! # Secure Document Encryption & Post-Quantum Key Management
//!
//! **Module Owner**: Member 1 (Encryption)
//!
//! Provides production-grade authenticated document encryption with AES-256-GCM,
//! multi-recipient Post-Quantum key establishment with ML-KEM-768 (FIPS 203),
//! recipient key management with automatic memory zeroization, and canonical packaging.

pub mod decryption;
pub mod encryption;
pub mod errors;
pub mod key_manager;
pub mod package;

pub use decryption::{decrypt_document, DecryptionRequest, DecryptionResult};
pub use encryption::{encrypt_document, protect_document_key, EncryptionRequest, RecipientKeyInput};
pub use errors::EncryptionError;
pub use key_manager::{
    generate_recipient_keys, generate_recipient_keys_with_version, load_key_pair,
    RecipientKeyDescriptor, RecipientKeyPair, ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE,
};
pub use package::{
    deserialize_package, load_package_from_file, save_package_to_file, serialize_package,
    validate_package, EncryptedDocumentPackage, PackageBuilder, RecipientKEMEnvelope,
};

/// Trait implementation providing object-oriented access to Encryption services.
pub trait EncryptionService {
    fn encrypt_document(
        &self,
        request: EncryptionRequest,
    ) -> Result<EncryptedDocumentPackage, EncryptionError>;

    fn decrypt_document(
        &self,
        request: DecryptionRequest,
    ) -> Result<DecryptionResult, EncryptionError>;

    fn protect_document_key(
        &self,
        recipient_id: &str,
        recipient_kem_public_key: &[u8],
        dek: &[u8; 32],
    ) -> Result<RecipientKEMEnvelope, EncryptionError>;
}

/// Default implementation of the `EncryptionService` trait.
#[derive(Debug, Default, Clone)]
pub struct StandardEncryptionService;

impl StandardEncryptionService {
    pub fn new() -> Self {
        Self
    }
}

impl EncryptionService for StandardEncryptionService {
    fn encrypt_document(
        &self,
        request: EncryptionRequest,
    ) -> Result<EncryptedDocumentPackage, EncryptionError> {
        encryption::encrypt_document(request)
    }

    fn decrypt_document(
        &self,
        request: DecryptionRequest,
    ) -> Result<DecryptionResult, EncryptionError> {
        decryption::decrypt_document(request)
    }

    fn protect_document_key(
        &self,
        recipient_id: &str,
        recipient_kem_public_key: &[u8],
        dek: &[u8; 32],
    ) -> Result<RecipientKEMEnvelope, EncryptionError> {
        encryption::protect_document_key(recipient_id, recipient_kem_public_key, dek)
    }
}
