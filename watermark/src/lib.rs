//! # Member 2 — Watermark Module
//!
//! Owns:
//! - Watermark Generation
//! - Embedding (invisible forensic watermarking)
//! - Extraction (from leaked documents / scans)
//! - Robustness Testing (resistance to cropping, recompression, blurring)
//!
//! Required API Contract:
//! - `create_watermark()`
//! - `embed_watermark()`
//! - `extract_watermark()`
//! - `verify_watermark()`

pub mod embedder;
pub mod extractor;
pub mod generator;
pub mod types;
pub mod verifier;

pub use embedder::WatermarkEmbedder;
pub use extractor::WatermarkExtractor;
pub use generator::WatermarkGenerator;
pub use types::*;
pub use verifier::WatermarkVerifier;

/// Primary API contract for Member 2 (Watermark).
pub trait WatermarkEngine {
    /// Generates a unique, cryptographically random, recipient-bound forensic watermark.
    ///
    /// The watermark ID and SHA-256 watermark hash will be bound to the DecryptionEvent.
    fn create_watermark(
        &self,
        params: CreateWatermarkParams,
    ) -> Result<WatermarkPayload, WatermarkError>;

    /// Embeds an invisible forensic watermark into the decrypted document bytes.
    ///
    /// Must remain imperceptible to the human eye while surviving basic transformations.
    fn embed_watermark(
        &self,
        params: EmbedWatermarkParams,
    ) -> Result<Vec<u8>, WatermarkError>;

    /// Extracts forensic watermark signals and metadata from a candidate leaked document.
    ///
    /// Supports native PDF streams and reconstructed raster scans.
    fn extract_watermark(
        &self,
        leaked_document_bytes: &[u8],
    ) -> Result<WatermarkExtractionResult, WatermarkError>;

    /// Verifies that an extracted watermark hash matches an expected hash recorded on the ledger.
    fn verify_watermark(
        &self,
        extracted_hash: &str,
        expected_hash: &str,
    ) -> Result<bool, WatermarkError>;
}
