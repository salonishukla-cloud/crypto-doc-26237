use crate::types::WatermarkError;

/// Trait stub for verifying watermark integrity against an expected hash or identity.
pub trait WatermarkVerifier {
    /// Compares extracted watermark hash against an expected hash, returning true if verified.
    fn verify(extracted_hash: &str, expected_hash: &str) -> Result<bool, WatermarkError>;
}
