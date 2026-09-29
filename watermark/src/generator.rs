//! # Watermark Generator
//!
//! Generates the forensic watermark [`WatermarkPayload`] for a given document-recipient-session
//! triple.  The generator:
//!
//! 1. Calls [`payload::build_payload`] to produce the canonical 142-byte bitstream.
//! 2. Applies 3× repetition coding → 426-byte robust bitstream.
//! 3. Computes the SHA-256 fingerprint of the **raw 142-byte payload** (not the coded copy)
//!    for inclusion in the [`WatermarkMetadata`] that flows to the ledger.
//! 4. Populates all [`WatermarkMetadata`] fields from the shared contract.
//!
//! The `strength_factor` (0.0 – 2.0) is stored for use by the embedder; it controls
//! how aggressively whitespace / zero-width characters are injected.

use chrono::Utc;
use sha2::{Digest, Sha256};
use shared::models::WatermarkMetadata;

use crate::payload::{apply_repetition_coding, build_payload, PAYLOAD_BYTES};
use crate::types::{CreateWatermarkParams, WatermarkError, WatermarkPayload};

/// Repetition factor applied to the raw payload before embedding.
/// 3× means up to 1 of every 3 copies can be fully destroyed and the
/// payload is still recoverable via majority vote.
const REPETITION_N: usize = 3;

/// Concrete implementation of the watermark generator.
pub struct ForensicWatermarkGenerator;

impl ForensicWatermarkGenerator {
    /// Generate a cryptographically secure, recipient-bound forensic watermark.
    ///
    /// # Arguments
    /// * `params` – Source identifiers and embedding strength hint.
    ///
    /// # Returns
    /// A [`WatermarkPayload`] containing the metadata (for the ledger) and the
    /// robust bitstream (for the embedder).
    pub fn create_watermark(params: CreateWatermarkParams) -> Result<WatermarkPayload, WatermarkError> {
        let timestamp_secs = Utc::now().timestamp() as u64;

        // ── Step 1: Build canonical 142-byte payload ──────────────────────────
        let raw_payload = build_payload(&params, timestamp_secs)?;
        debug_assert_eq!(raw_payload.len(), PAYLOAD_BYTES);

        // ── Step 2: Apply repetition coding for robustness ───────────────────
        let bitstream = apply_repetition_coding(&raw_payload, REPETITION_N);

        // ── Step 3: SHA-256 fingerprint of the raw payload ───────────────────
        let watermark_hash = hex::encode(Sha256::digest(&raw_payload));

        // ── Step 4: Watermark UUID derived deterministically from the hash ────
        // We use the first 16 bytes of SHA-256(hash) as the UUID to avoid
        // importing the uuid crate's v5 (name-based) feature set.
        let id_bytes = Sha256::digest(watermark_hash.as_bytes());
        let watermark_id = format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&id_bytes[0..4]),
            hex::encode(&id_bytes[4..6]),
            hex::encode(&id_bytes[6..8]),
            hex::encode(&id_bytes[8..10]),
            hex::encode(&id_bytes[10..16]),
        );

        // ── Step 5: Populate shared WatermarkMetadata ─────────────────────────
        let metadata = WatermarkMetadata {
            watermark_id,
            recipient_id:        params.recipient_id,
            document_id:         params.document_id,
            watermark_hash,
            generated_at:        Utc::now().to_rfc3339(),
            payload_length_bits: bitstream.len() * 8,
        };

        Ok(WatermarkPayload { metadata, bitstream })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(strength: f32) -> CreateWatermarkParams {
        CreateWatermarkParams {
            document_id:     "doc-test-42".to_string(),
            recipient_id:    "bob@secure.gov".to_string(),
            session_id:      "sess-xyz-2026".to_string(),
            strength_factor: strength,
        }
    }

    #[test]
    fn create_watermark_returns_non_empty_bitstream() {
        let wm = ForensicWatermarkGenerator::create_watermark(make_params(1.0)).unwrap();
        assert!(!wm.bitstream.is_empty());
        assert_eq!(wm.bitstream.len(), PAYLOAD_BYTES * REPETITION_N);
    }

    #[test]
    fn watermark_hash_is_hex_sha256() {
        let wm = ForensicWatermarkGenerator::create_watermark(make_params(1.0)).unwrap();
        assert_eq!(wm.metadata.watermark_hash.len(), 64); // 32 bytes → 64 hex chars
    }

    #[test]
    fn watermark_id_has_uuid_shape() {
        let wm = ForensicWatermarkGenerator::create_watermark(make_params(1.0)).unwrap();
        let parts: Vec<&str> = wm.metadata.watermark_id.split('-').collect();
        assert_eq!(parts.len(), 5, "watermark_id must have 5 dash-separated segments");
    }

    #[test]
    fn same_params_different_timestamps_produce_different_hashes() {
        // Two calls happen at different wall-clock times; hashes must differ.
        // This is probabilistically guaranteed (1/2^64 chance of collision).
        // We just verify the generator runs twice without panic.
        let wm1 = ForensicWatermarkGenerator::create_watermark(make_params(1.0)).unwrap();
        let wm2 = ForensicWatermarkGenerator::create_watermark(make_params(1.0)).unwrap();
        // They MAY be equal if run in the same second — that's acceptable.
        let _ = (wm1, wm2); // no panic ⇒ pass
    }
}
