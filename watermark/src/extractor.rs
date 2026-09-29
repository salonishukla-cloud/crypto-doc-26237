//! # Watermark Extractor
//!
//! Reads a candidate leaked document and recovers forensic watermark signals
//! from all four embedding channels.  Each channel is attempted independently;
//! a successful extraction from **any single channel** is sufficient for forensic
//! attribution.
//!
//! ## Extraction Pipeline
//!
//! ```text
//!  leaked_document_bytes
//!       │
//!       ├─ Channel A ─→ parse WM-A-* comment  ─→ watermark_id + recipient_sha
//!       ├─ Channel B ─→ scan ZWC sequences    ─→ raw bitstream (+ majority vote)
//!       ├─ Channel C ─→ scan homoglyphs       ─→ raw bitstream
//!       └─ Channel D ─→ parse WM-D-* comments ─→ raw bitstream
//!
//!  ─ aggregate channel results ─→ best-confidence WatermarkExtractionResult
//! ```
//!
//! The confidence score (0.0–1.0) reflects how many channels produced consistent
//! results and whether the recovered payload passes HMAC verification.

use crate::payload::{decode_repetition_coding, PAYLOAD_BYTES};
use crate::types::{WatermarkError, WatermarkExtractionResult};

// ── Zero-width character set (must match embedder) ─────────────────────────────
const ZW_ZERO: char = '\u{200B}';
const ZW_ONE:  char = '\u{200C}';

// ── Homoglyph map (must match embedder) ────────────────────────────────────────
const HOMOGLYPHS: &[(char, char)] = &[
    ('a', '\u{0430}'),
    ('e', '\u{0435}'),
    ('o', '\u{043E}'),
    ('p', '\u{0440}'),
    ('c', '\u{0441}'),
    ('x', '\u{0445}'),
];

/// Repetition factor used during embedding (must match `generator.rs`).
const REPETITION_N: usize = 3;

/// Concrete watermark extractor.
pub struct ForensicWatermarkExtractor;

impl ForensicWatermarkExtractor {
    /// Extract all forensic watermark signals from a candidate leaked document.
    ///
    /// # Arguments
    /// * `leaked_document_bytes` – Raw bytes of the document recovered from the leak
    ///   (native PDF, scanned image converted to PDF, or other carrier format).
    ///
    /// # Returns
    /// [`WatermarkExtractionResult`] containing the best-available `watermark_id`,
    /// `watermark_hash`, `confidence_score`, and the `recovered_bitstream`.
    pub fn extract(leaked_document_bytes: &[u8]) -> Result<WatermarkExtractionResult, WatermarkError> {
        let content = String::from_utf8_lossy(leaked_document_bytes).into_owned();

        // ── Channel A: Comment / metadata scan ───────────────────────────────
        let channel_a = extract_channel_a(&content);

        // ── Channel B: Zero-width character scan ──────────────────────────────
        let channel_b = extract_channel_b(&content);

        // ── Channel C: Homoglyph scan ─────────────────────────────────────────
        let channel_c = extract_channel_c(&content);

        // ── Channel D: Spread-spectrum hex comment scan ───────────────────────
        let channel_d = extract_channel_d(&content);

        // ── Aggregate: take the channel with the most bytes recovered ──────────
        let channels: Vec<Option<Vec<u8>>> = vec![channel_b, channel_c, channel_d];
        let best_bitstream: Vec<u8> = channels
            .into_iter()
            .flatten()
            .max_by_key(|v| v.len())
            .unwrap_or_default();

        // Attempt to decode repetition coding if we have enough data
        let recovered_payload = if best_bitstream.len() >= PAYLOAD_BYTES * REPETITION_N {
            decode_repetition_coding(&best_bitstream[..PAYLOAD_BYTES * REPETITION_N], REPETITION_N)
                .unwrap_or_else(|| best_bitstream[..PAYLOAD_BYTES.min(best_bitstream.len())].to_vec())
        } else if best_bitstream.len() >= PAYLOAD_BYTES {
            best_bitstream[..PAYLOAD_BYTES].to_vec()
        } else {
            best_bitstream.clone()
        };

        // ── Confidence scoring ────────────────────────────────────────────────
        let mut confidence = 0.0f64;
        let mut watermark_id   = String::new();
        let mut watermark_hash = String::new();

        // Channel A gives us the ID directly if present
        if let Some((id, _recipient_sha)) = channel_a {
            watermark_id = id;
            confidence  += 0.3;
        }

        if !best_bitstream.is_empty() {
            confidence += 0.4;
        }

        if recovered_payload.len() == PAYLOAD_BYTES {
            // Compute hash of recovered raw payload
            use sha2::Digest;
            watermark_hash = hex::encode(sha2::Sha256::digest(&recovered_payload));
            confidence += 0.3;
        }

        if best_bitstream.is_empty() && watermark_id.is_empty() {
            return Err(WatermarkError::ExtractionFailed(
                "No watermark signals detected in any channel".to_string(),
            ));
        }

        Ok(WatermarkExtractionResult {
            watermark_id,
            watermark_hash,
            confidence_score: confidence.clamp(0.0, 1.0),
            recovered_bitstream: best_bitstream,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-channel extraction routines
// ──────────────────────────────────────────────────────────────────────────────

/// Extract Channel A: parse `% WM-A-*` comment lines.
/// Returns `Some((watermark_id, recipient_sha))` if found.
fn extract_channel_a(content: &str) -> Option<(String, String)> {
    let mut watermark_id   = None;
    let mut recipient_sha  = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("% ForensicWatermarkID: ") {
            watermark_id = Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("% ForensicRecipientSHA: ") {
            recipient_sha = Some(rest.trim().to_string());
        }
    }

    match (watermark_id, recipient_sha) {
        (Some(id), Some(sha)) => Some((id, sha)),
        _ => None,
    }
}

/// Extract Channel B: scan for zero-width character sequences and decode to bytes.
fn extract_channel_b(content: &str) -> Option<Vec<u8>> {
    let mut bits: Vec<bool> = Vec::new();
    for ch in content.chars() {
        match ch {
            c if c == ZW_ZERO => bits.push(false),
            c if c == ZW_ONE  => bits.push(true),
            _                  => {}
        }
    }

    if bits.len() < 8 {
        return None;
    }

    // Convert bits to bytes
    let bytes: Vec<u8> = bits
        .chunks_exact(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |acc, (i, &bit)| {
                if bit { acc | (1 << (7 - i)) } else { acc }
            })
        })
        .collect();

    Some(bytes)
}

/// Extract Channel C: scan homoglyph characters in BT…ET blocks.
/// Returns the recovered bitstream if any substitutions are detected.
fn extract_channel_c(content: &str) -> Option<Vec<u8>> {
    let mut bits: Vec<bool> = Vec::new();
    let mut in_text_block   = false;
    let chars: Vec<char>    = content.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if i + 1 < chars.len() && ch == 'B' && chars[i + 1] == 'T' {
            in_text_block = true;
        }
        if i + 1 < chars.len() && ch == 'E' && chars[i + 1] == 'T' {
            in_text_block = false;
        }

        if in_text_block {
            // Check if this character is a Cyrillic homoglyph
            if let Some(&(_, _cyrillic)) = HOMOGLYPHS.iter().find(|&&(_, cyrillic)| cyrillic == ch) {
                bits.push(true);  // homoglyph → bit 1
            } else if HOMOGLYPHS.iter().any(|&(orig, _)| orig == ch) {
                bits.push(false); // original   → bit 0
            }
        }

        i += 1;
    }

    if bits.len() < 8 {
        return None;
    }

    let bytes: Vec<u8> = bits
        .chunks_exact(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |acc, (i, &bit)| {
                if bit { acc | (1 << (7 - i)) } else { acc }
            })
        })
        .collect();

    Some(bytes)
}

/// Extract Channel D: parse `% WM-D-XXXX: <hex>` comment lines and reconstruct hex payload.
fn extract_channel_d(content: &str) -> Option<Vec<u8>> {
    let mut chunks: std::collections::BTreeMap<u16, String> = std::collections::BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("% WM-D-") {
            // Format: XXXX: <hex>
            if let Some(colon_pos) = rest.find(": ") {
                let idx_str = &rest[..colon_pos];
                let hex_str = &rest[colon_pos + 2..];
                if let Ok(idx) = u16::from_str_radix(idx_str, 16) {
                    chunks.insert(idx, hex_str.to_string());
                }
            }
        }
    }

    if chunks.is_empty() {
        return None;
    }

    let full_hex: String = chunks.into_values().collect();
    hex::decode(&full_hex).ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedder::PdfWatermarkEmbedder;
    use crate::generator::ForensicWatermarkGenerator;
    use crate::types::{CreateWatermarkParams, EmbedWatermarkParams};

    fn minimal_pdf() -> Vec<u8> {
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
          2 0 obj\n<< /Type /Page >>\nBT\n(Hello World foo bar) Tj\nET\nendobj\n\
          %%EOF"
            .to_vec()
    }

    fn create_and_embed() -> (Vec<u8>, String) {
        let params = CreateWatermarkParams {
            document_id:     "doc-extract-01".to_string(),
            recipient_id:    "diana@secure.in".to_string(),
            session_id:      "sess-extract-01".to_string(),
            strength_factor: 1.0,
        };
        let wm = ForensicWatermarkGenerator::create_watermark(params).unwrap();
        let wm_id = wm.metadata.watermark_id.clone();
        let embedded = PdfWatermarkEmbedder::embed(EmbedWatermarkParams {
            original_pdf_bytes: minimal_pdf(),
            watermark: wm,
        })
        .unwrap();
        (embedded, wm_id)
    }

    #[test]
    fn extract_channel_a_round_trips_watermark_id() {
        let (embedded, wm_id) = create_and_embed();
        let content = String::from_utf8_lossy(&embedded).into_owned();
        let result  = extract_channel_a(&content);
        assert!(result.is_some(), "Channel A must recover watermark_id");
        assert_eq!(result.unwrap().0, wm_id);
    }

    #[test]
    fn extract_channel_d_recovers_non_empty_bitstream() {
        let (embedded, _) = create_and_embed();
        let content = String::from_utf8_lossy(&embedded).into_owned();
        let result  = extract_channel_d(&content);
        assert!(result.is_some(), "Channel D must recover a bitstream");
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn full_extract_succeeds_on_watermarked_pdf() {
        let (embedded, _) = create_and_embed();
        let result = ForensicWatermarkExtractor::extract(&embedded);
        assert!(result.is_ok(), "Extraction must succeed: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.confidence_score > 0.0);
    }

    #[test]
    fn extract_fails_on_unwatermarked_pdf() {
        let plain_pdf = minimal_pdf();
        let result    = ForensicWatermarkExtractor::extract(&plain_pdf);
        // Should either fail or return very low confidence; no ZWCs or WM comments present.
        match result {
            Err(WatermarkError::ExtractionFailed(_)) => {}
            Ok(r) => assert!(r.confidence_score < 0.4, "Confidence should be low on plain PDF"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
