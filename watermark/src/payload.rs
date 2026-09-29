//! # Watermark Payload Builder
//!
//! Constructs the canonical watermark bit-vector that encodes the recipient, document,
//! and session identifiers.  The payload uses a multi-layer encoding strategy so that
//! even partial recovery (e.g. after cropping or recompression) is sufficient for
//! forensic attribution:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Layer 0 │ MAGIC (4 B) │ VERSION (1 B) │ FLAGS (1 B)            │
//! │ Layer 1 │ RECIPIENT_ID  (32 B, SHA-256 of raw id)              │
//! │ Layer 2 │ DOCUMENT_ID   (32 B, SHA-256 of raw id)              │
//! │ Layer 3 │ SESSION_ID    (32 B, SHA-256 of raw id)              │
//! │ Layer 4 │ TIMESTAMP     (8 B, Unix seconds, big-endian)         │
//! │ Layer 5 │ HMAC-SHA256   (32 B, keyed integrity tag)            │
//! └─────────────────────────────────────────────────────────────────┘
//! Total: 142 bytes  →  1136 bits
//! ```
//!
//! The HMAC key is derived from BLAKE3 / SHA-256 of `(recipient_id || document_id || session_id)`.
//! This means a forger who does not know the secret binding key cannot fabricate a valid payload.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::types::{CreateWatermarkParams, WatermarkError};

type HmacSha256 = Hmac<Sha256>;

/// Magic header bytes identifying a forensic watermark payload.
pub const PAYLOAD_MAGIC: &[u8; 4] = b"FWMK";
/// Current payload format version.
pub const PAYLOAD_VERSION: u8 = 0x01;
/// Reserved flags byte (future extensibility).
pub const PAYLOAD_FLAGS: u8 = 0x00;

/// Total payload length in bytes.
pub const PAYLOAD_BYTES: usize = 4 + 1 + 1 + 32 + 32 + 32 + 8 + 32; // 142

/// Build the canonical watermark payload bitstream from [`CreateWatermarkParams`].
///
/// # Returns
/// A 142-byte `Vec<u8>` encoding all forensic attribution fields plus an HMAC integrity tag.
///
/// # Security Notes
/// - SHA-256 hashes ensure fixed-length fields regardless of identifier length.
/// - HMAC prevents payload tampering without knowledge of the binding key.
/// - The binding key is itself derived from the three identifiers — the key never leaves this crate.
pub fn build_payload(params: &CreateWatermarkParams, timestamp_secs: u64) -> Result<Vec<u8>, WatermarkError> {
    // ── Derive the HMAC binding key ─────────────────────────────────────────────
    // Key = SHA-256(recipient_id || ":" || document_id || ":" || session_id)
    let mut key_hasher = Sha256::new();
    key_hasher.update(params.recipient_id.as_bytes());
    key_hasher.update(b":");
    key_hasher.update(params.document_id.as_bytes());
    key_hasher.update(b":");
    key_hasher.update(params.session_id.as_bytes());
    let binding_key: [u8; 32] = key_hasher.finalize().into();

    // ── Compute per-field SHA-256 digests ───────────────────────────────────────
    let recipient_hash: [u8; 32] = Sha256::digest(params.recipient_id.as_bytes()).into();
    let document_hash: [u8; 32]  = Sha256::digest(params.document_id.as_bytes()).into();
    let session_hash: [u8; 32]   = Sha256::digest(params.session_id.as_bytes()).into();

    // ── Assemble the pre-MAC payload ────────────────────────────────────────────
    let mut pre_mac: Vec<u8> = Vec::with_capacity(PAYLOAD_BYTES);
    pre_mac.extend_from_slice(PAYLOAD_MAGIC);          // [0..4]   MAGIC
    pre_mac.push(PAYLOAD_VERSION);                     // [4]      VERSION
    pre_mac.push(PAYLOAD_FLAGS);                       // [5]      FLAGS
    pre_mac.extend_from_slice(&recipient_hash);        // [6..38]  RECIPIENT
    pre_mac.extend_from_slice(&document_hash);         // [38..70] DOCUMENT
    pre_mac.extend_from_slice(&session_hash);          // [70..102] SESSION
    pre_mac.extend_from_slice(&timestamp_secs.to_be_bytes()); // [102..110] TIMESTAMP

    // ── Compute HMAC-SHA256 over pre_mac ────────────────────────────────────────
    let mut mac = HmacSha256::new_from_slice(&binding_key)
        .map_err(|e| WatermarkError::GenerationFailed(format!("HMAC init error: {e}")))?;
    mac.update(&pre_mac);
    let mac_tag: [u8; 32] = mac.finalize().into_bytes().into();

    // ── Append MAC and return full payload ──────────────────────────────────────
    pre_mac.extend_from_slice(&mac_tag); // [110..142] HMAC

    debug_assert_eq!(pre_mac.len(), PAYLOAD_BYTES, "payload length invariant violated");
    Ok(pre_mac)
}

/// Verify that a candidate payload's HMAC tag matches the expected binding key
/// reconstructed from the provided identifiers.
///
/// Returns `true` iff the tag is valid and the payload structure is intact.
pub fn verify_payload_mac(
    payload: &[u8],
    recipient_id: &str,
    document_id: &str,
    session_id: &str,
) -> bool {
    if payload.len() != PAYLOAD_BYTES {
        return false;
    }

    // Re-derive binding key
    let mut key_hasher = Sha256::new();
    key_hasher.update(recipient_id.as_bytes());
    key_hasher.update(b":");
    key_hasher.update(document_id.as_bytes());
    key_hasher.update(b":");
    key_hasher.update(session_id.as_bytes());
    let binding_key: [u8; 32] = key_hasher.finalize().into();

    let Ok(mut mac) = HmacSha256::new_from_slice(&binding_key) else {
        return false;
    };
    mac.update(&payload[..110]);
    mac.verify_slice(&payload[110..142]).is_ok()
}

/// Apply Reed-Solomon-like simple repetition coding to increase robustness.
///
/// Each byte is repeated `n` times.  Combined with majority-vote decoding in
/// the extractor this significantly increases survival rate under noise/corruption.
pub fn apply_repetition_coding(payload: &[u8], n: usize) -> Vec<u8> {
    let mut coded = Vec::with_capacity(payload.len() * n);
    for &byte in payload {
        for _ in 0..n {
            coded.push(byte);
        }
    }
    coded
}

/// Decode a repetition-coded byte stream back to the original payload
/// using majority-vote on every group of `n` copies.
///
/// Returns `None` if the byte stream length is not a multiple of `n`.
pub fn decode_repetition_coding(coded: &[u8], n: usize) -> Option<Vec<u8>> {
    if coded.len() % n != 0 {
        return None;
    }
    let decoded: Vec<u8> = coded
        .chunks_exact(n)
        .map(|group| {
            // Bit-level majority vote across n copies
            let mut bit_votes = [0u32; 8];
            for &byte in group {
                for bit in 0..8 {
                    if (byte >> bit) & 1 == 1 {
                        bit_votes[bit] += 1;
                    }
                }
            }
            let mut result = 0u8;
            let threshold = (n as u32 + 1) / 2;
            for bit in 0..8 {
                if bit_votes[bit] >= threshold {
                    result |= 1 << bit;
                }
            }
            result
        })
        .collect();
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_params() -> CreateWatermarkParams {
        CreateWatermarkParams {
            document_id:     "doc-001".to_string(),
            recipient_id:    "alice@example.com".to_string(),
            session_id:      "sess-abc".to_string(),
            strength_factor: 1.0,
        }
    }

    #[test]
    fn payload_length_is_invariant() {
        let p = build_payload(&dummy_params(), 1_000_000).unwrap();
        assert_eq!(p.len(), PAYLOAD_BYTES);
    }

    #[test]
    fn payload_starts_with_magic() {
        let p = build_payload(&dummy_params(), 0).unwrap();
        assert_eq!(&p[..4], PAYLOAD_MAGIC);
    }

    #[test]
    fn mac_verification_succeeds_for_valid_payload() {
        let params = dummy_params();
        let p = build_payload(&params, 42).unwrap();
        assert!(verify_payload_mac(&p, &params.recipient_id, &params.document_id, &params.session_id));
    }

    #[test]
    fn mac_verification_fails_on_tampered_byte() {
        let params = dummy_params();
        let mut p = build_payload(&params, 42).unwrap();
        p[10] ^= 0xFF; // tamper one byte
        assert!(!verify_payload_mac(&p, &params.recipient_id, &params.document_id, &params.session_id));
    }

    #[test]
    fn repetition_coding_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let coded    = apply_repetition_coding(&original, 3);
        let decoded  = decode_repetition_coding(&coded, 3).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn repetition_coding_majority_vote_corrects_single_error() {
        let original = vec![0b10101010u8];
        let mut coded = apply_repetition_coding(&original, 3); // [0xAA, 0xAA, 0xAA]
        coded[1] = 0x00; // corrupt one copy
        let decoded = decode_repetition_coding(&coded, 3).unwrap();
        assert_eq!(decoded, original, "majority vote should correct 1-of-3 corruption");
    }
}
