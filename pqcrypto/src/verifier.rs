use crate::types::PqCryptoError;

/// Trait stub for ML-DSA (FIPS 204) digital signature verification.
pub trait PqVerifier {
    /// Verifies an ML-DSA digital signature against canonical message bytes and recipient public key.
    fn verify(
        public_key: &[u8],
        message_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, PqCryptoError>;
}
