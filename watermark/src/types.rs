use shared::models::WatermarkMetadata;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WatermarkError {
    #[error("Failed to generate forensic watermark payload: {0}")]
    GenerationFailed(String),

    #[error("Failed to embed watermark into document structure/rendering: {0}")]
    EmbeddingFailed(String),

    #[error("No watermark detected or payload corrupted beyond recovery threshold: {0}")]
    ExtractionFailed(String),

    #[error("Watermark verification failed: hash mismatch or integrity failure: {0}")]
    VerificationFailed(String),

    #[error("Unsupported document format or invalid PDF stream: {0}")]
    UnsupportedFormat(String),
}

/// Parameters for creating a recipient-specific forensic watermark.
#[derive(Debug, Clone)]
pub struct CreateWatermarkParams {
    pub document_id: String,
    pub recipient_id: String,
    pub session_id: String,
    pub strength_factor: f32,
}

/// Generated watermark payload representation.
#[derive(Debug, Clone)]
pub struct WatermarkPayload {
    pub metadata: WatermarkMetadata,
    pub bitstream: Vec<u8>,
}

/// Parameters for embedding a watermark into a decrypted document.
#[derive(Debug, Clone)]
pub struct EmbedWatermarkParams {
    pub original_pdf_bytes: Vec<u8>,
    pub watermark: WatermarkPayload,
}

/// Result of watermark extraction from a candidate leaked document.
#[derive(Debug, Clone)]
pub struct WatermarkExtractionResult {
    pub watermark_id: String,
    pub watermark_hash: String,
    pub confidence_score: f64,
    pub recovered_bitstream: Vec<u8>,
}
