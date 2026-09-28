use crate::types::{CreateWatermarkParams, WatermarkError, WatermarkPayload};

/// Trait stub for generating cryptographic forensic watermark bitstreams.
pub trait WatermarkGenerator {
    /// Generates a spread-spectrum or pseudo-random frequency bitstream bound to recipient and session.
    fn generate(params: CreateWatermarkParams) -> Result<WatermarkPayload, WatermarkError>;
}
