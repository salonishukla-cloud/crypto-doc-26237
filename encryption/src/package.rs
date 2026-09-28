use crate::types::EncryptionError;
use shared::models::{EncryptedDocumentPackage, RecipientKEMEnvelope};

/// Trait stub for packaging and serialization of encrypted document containers.
pub trait DocumentPackager {
    /// Serializes an EncryptedDocumentPackage into binary/JSON envelope format.
    fn serialize_package(package: &EncryptedDocumentPackage) -> Result<Vec<u8>, EncryptionError>;

    /// Deserializes a raw binary package into an EncryptedDocumentPackage.
    fn deserialize_package(raw_bytes: &[u8]) -> Result<EncryptedDocumentPackage, EncryptionError>;
}
