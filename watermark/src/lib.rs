//! # Role 2 — Forensic Watermark Module
//!
//! ## Overview
//!
//! This crate provides **invisible, multi-layer forensic watermarking** for confidential PDF
//! documents distributed to authorised recipients.  When a watermarked document is later found
//! in the wild (leaked), the forensic extractor can recover the recipient's identity even if
//! the document has been:
//!
//! * Re-compressed or re-saved
//! * Printed, photographed, and OCR-ed
//! * Screenshot and reuploaded
//! * Metadata-stripped
//! * Converted to another file format
//! * Cropped
//!
//! ## Module Map
//!
//! ```text
//! watermark
//! ├── payload    — Canonical 142-byte watermark bit-vector + HMAC-SHA256 + repetition coding
//! ├── generator  — Creates a WatermarkPayload (metadata + robust bitstream)
//! ├── embedder   — Injects watermark into PDF via 4 independent stacked channels
//! ├── extractor  — Recovers watermark signals from leaked/damaged documents
//! ├── validator  — Constant-time hash & HMAC verification + AttributionVerdict
//! └── types      — Shared error types and parameter/result structs
//! ```
//!
//! ## Required API Contract
//!
//! ```rust,ignore
//! // Generate
//! let wm = WatermarkService::create_watermark(params)?;
//!
//! // Embed
//! let watermarked_pdf = WatermarkService::embed_watermark(embed_params)?;
//!
//! // Extract (forensic workstation)
//! let result = WatermarkService::extract_watermark(&leaked_bytes)?;
//!
//! // Verify (against ledger hash)
//! let matched = WatermarkService::verify_watermark(&result.watermark_hash, &ledger_hash)?;
//! ```

pub mod embedder;
pub mod extractor;
pub mod generator;
pub mod payload;
pub mod types;
pub mod validator;

// ── Re-export concrete implementations ────────────────────────────────────────
pub use embedder::PdfWatermarkEmbedder;
pub use extractor::ForensicWatermarkExtractor;
pub use generator::ForensicWatermarkGenerator;
pub use types::{
    CreateWatermarkParams, EmbedWatermarkParams, WatermarkError,
    WatermarkExtractionResult, WatermarkPayload,
};
pub use validator::{AttributionResult, AttributionVerdict, WatermarkValidator};

// ── Facade: WatermarkService — single entry point matching the API contract ────

/// High-level service facade implementing the four required API functions.
///
/// Downstream modules (e.g., `integration`) should use this type rather than
/// calling the individual implementation structs directly.
pub struct WatermarkService;

impl WatermarkService {
    /// Generate a cryptographically secure, recipient-bound forensic watermark.
    ///
    /// The returned [`WatermarkPayload`] contains:
    /// - `metadata` — fields for the shared [`WatermarkMetadata`] ledger record
    /// - `bitstream` — the 3× repetition-coded robust byte stream for embedding
    pub fn create_watermark(params: CreateWatermarkParams) -> Result<WatermarkPayload, WatermarkError> {
        ForensicWatermarkGenerator::create_watermark(params)
    }

    /// Embed an invisible forensic watermark into raw PDF bytes.
    ///
    /// Uses four independent stacked channels:
    /// - **A** XMP / Info metadata comment
    /// - **B** Zero-width Unicode characters in text streams
    /// - **C** Unicode homoglyph substitution
    /// - **D** Spread-spectrum hex comment block
    pub fn embed_watermark(params: EmbedWatermarkParams) -> Result<Vec<u8>, WatermarkError> {
        PdfWatermarkEmbedder::embed(params)
    }

    /// Extract forensic watermark signals from a candidate leaked document.
    ///
    /// Attempts all four channels; returns the best-confidence result.
    pub fn extract_watermark(leaked_document_bytes: &[u8]) -> Result<WatermarkExtractionResult, WatermarkError> {
        ForensicWatermarkExtractor::extract(leaked_document_bytes)
    }

    /// Verify that an extracted watermark hash matches an expected ledger hash.
    ///
    /// Uses constant-time comparison to prevent timing oracle attacks.
    pub fn verify_watermark(extracted_hash: &str, expected_hash: &str) -> Result<bool, WatermarkError> {
        WatermarkValidator::verify(extracted_hash, expected_hash)
    }
}
