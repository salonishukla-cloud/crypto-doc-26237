use crate::types::{EmbedWatermarkParams, WatermarkError};

/// Trait stub for embedding invisible forensic watermarks into PDF documents.
pub trait WatermarkEmbedder {
    /// Injects imperceptible forensic watermarks into PDF content streams, text glyph shifts, or raster layers.
    /// Returns the watermarked PDF bytes.
    fn embed(params: EmbedWatermarkParams) -> Result<Vec<u8>, WatermarkError>;
}
