use crate::types::EncryptionError;

/// Trait stub for ML-KEM (FIPS 203) key encapsulation mechanism operations.
pub trait KemEngine {
    /// Generates an ephemeral ML-KEM-768 keypair (public_key, secret_key).
    fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), EncryptionError>;

    /// Encapsulates a shared secret against a recipient's ML-KEM public key.
    /// Returns (shared_secret_bytes, encapsulated_ciphertext_bytes).
    fn encapsulate(recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptionError>;

    /// Decapsulates ciphertext using the recipient's ML-KEM secret key.
    /// Recovers the shared secret bytes.
    fn decapsulate(
        recipient_secret_key: &[u8],
        encapsulated_ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;
}
