use crate::types::{WatermarkError, WatermarkExtractionResult};

/// Trait stub for extracting watermark signals from candidate leaked documents.
pub trait WatermarkExtractor {
    /// Inspects PDF bytes, rasterized pages, or scanned images to extract forensic watermark signals.
    fn extract(leaked_document_bytes: &[u8]) -> Result<WatermarkExtractionResult, WatermarkError>;
}
