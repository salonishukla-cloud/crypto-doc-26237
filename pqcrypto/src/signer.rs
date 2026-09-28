use crate::types::PqCryptoError;

/// Trait stub for ML-DSA (FIPS 204) digital signature signing.
pub trait PqSigner {
    /// Generates an ML-DSA digital signature over canonical input bytes using the recipient's private key.
    fn sign(secret_key: &[u8], message_bytes: &[u8]) -> Result<Vec<u8>, PqCryptoError>;
}
