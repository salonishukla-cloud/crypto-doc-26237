//! # serialization.rs — Canonical Deterministic Event Serialization
//!
//! Implements two serialization formats for [`UnsignedDecryptionEvent`]:
//!
//! ## Format 1: Canonical JSON (RFC 8785)
//!
//! RFC 8785 specifies the JSON Canonicalization Scheme (JCS):
//! - Object keys sorted lexicographically (Unicode code-point order)
//! - No insignificant whitespace
//! - Numbers in a specific floating-point representation (we only have strings — trivially compliant)
//! - UTF-8 without BOM
//!
//! Our implementation sorts keys by constructing an ordered `BTreeMap` from
//! the event's fields and serializing that — no extra JCS library required.
//!
//! ## Format 2: Deterministic CBOR (RFC 8949 §4.2)
//!
//! - Map keys sorted by byte length then lexicographically (RFC 8949 "Canonical CBOR")
//! - Definite-length encoding for all arrays and maps
//! - Smallest possible encoding for each value
//!
//! The canonical JSON format is the **primary signing format** used in `sign_event()`.
//! CBOR is provided for offline ledger storage efficiency.
//!
//! ## Why determinism matters
//!
//! If two different parties independently serialize the same event and get different
//! bytes, signature verification will fail even though the event is authentic.
//! RFC 8785 eliminates this by specifying a unique byte sequence for any given
//! JSON value.

use std::collections::BTreeMap;

use serde_json::Value;
use shared::models::UnsignedDecryptionEvent;

use crate::types::PqCryptoError;

/// Concrete canonical serializer for [`UnsignedDecryptionEvent`].
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Serialize `event` to RFC 8785 canonical JSON bytes.
    ///
    /// Field ordering (lexicographic by key name):
    /// ```text
    /// document_id, event_id, recipient_id, session_id,
    /// signature_algorithm, timestamp, watermark_hash, watermark_id
    /// ```
    ///
    /// This is the **signing payload** — the bytes that go into SHA-256 then ML-DSA.
    pub fn to_canonical_json(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError> {
        // ── Build a BTreeMap (auto-sorted by key) ─────────────────────────────
        let mut map = BTreeMap::new();
        map.insert("document_id",        event.document_id.clone());
        map.insert("event_id",           event.event_id.clone());
        map.insert("recipient_id",       event.recipient_id.clone());
        map.insert("session_id",         event.session_id.clone());
        map.insert("signature_algorithm",event.signature_algorithm.clone());
        map.insert("timestamp",          event.timestamp.clone());
        map.insert("watermark_hash",     event.watermark_hash.clone());
        map.insert("watermark_id",       event.watermark_id.clone());

        // ── Serialize with serde_json (compact, no whitespace) ────────────────
        // BTreeMap guarantees key order → produces RFC 8785-compliant output
        // for string-valued maps (which is all we have here).
        serde_json::to_vec(&map).map_err(|e| {
            PqCryptoError::SerializationFailed(format!("canonical JSON serialize: {e}"))
        })
    }

    /// Serialize `event` to deterministic CBOR bytes (RFC 8949 §4.2).
    ///
    /// Uses `ciborium` (the workspace CBOR library).  The struct derives Serialize,
    /// so ciborium emits a map with fields in declaration order.  For strict RFC 8949
    /// canonical CBOR the keys would need additional sort post-processing; for our
    /// system this is used only for ledger storage, NOT for signature computation.
    pub fn to_canonical_cbor(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError> {
        // Build a sorted BTreeMap<String, String> for deterministic key ordering
        let mut map: BTreeMap<&str, &str> = BTreeMap::new();
        map.insert("document_id",         &event.document_id);
        map.insert("event_id",            &event.event_id);
        map.insert("recipient_id",        &event.recipient_id);
        map.insert("session_id",          &event.session_id);
        map.insert("signature_algorithm", &event.signature_algorithm);
        map.insert("timestamp",           &event.timestamp);
        map.insert("watermark_hash",      &event.watermark_hash);
        map.insert("watermark_id",        &event.watermark_id);

        // Serialize the BTreeMap as a CBOR map — ciborium produces definite-length encoding
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf)
            .map_err(|e| PqCryptoError::SerializationFailed(format!("CBOR serialize: {e}")))?;
        Ok(buf)
    }

    /// Deserialize a CBOR byte slice back into a field map for inspection.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<BTreeMap<String, String>, PqCryptoError> {
        ciborium::de::from_reader(bytes)
            .map_err(|e| PqCryptoError::SerializationFailed(format!("CBOR deserialize: {e}")))
    }

    /// Deserialize a canonical JSON byte slice back into a field map for inspection.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<BTreeMap<String, Value>, PqCryptoError> {
        serde_json::from_slice(bytes)
            .map_err(|e| PqCryptoError::SerializationFailed(format!("JSON deserialize: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::models::UnsignedDecryptionEvent;

    fn sample_event() -> UnsignedDecryptionEvent {
        UnsignedDecryptionEvent {
            event_id:            "evt-001".into(),
            document_id:         "doc-001".into(),
            recipient_id:        "alice@secure.gov".into(),
            session_id:          "sess-001".into(),
            watermark_id:        "wm-001".into(),
            timestamp:           "2026-09-28T18:00:00Z".into(),
            watermark_hash:      "aabbccdd".into(),
            signature_algorithm: "ML-DSA".into(),
        }
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let event = sample_event();
        let bytes1 = CanonicalSerializer::to_canonical_json(&event).unwrap();
        let bytes2 = CanonicalSerializer::to_canonical_json(&event).unwrap();
        assert_eq!(bytes1, bytes2, "canonical JSON must be byte-for-byte identical across calls");
    }

    #[test]
    fn canonical_json_keys_are_sorted() {
        let event  = sample_event();
        let bytes  = CanonicalSerializer::to_canonical_json(&event).unwrap();
        let text   = String::from_utf8(bytes).unwrap();
        // Find positions of keys in the output to confirm lexicographic ordering
        let doc_pos  = text.find("\"document_id\"").unwrap();
        let evt_pos  = text.find("\"event_id\"").unwrap();
        let recv_pos = text.find("\"recipient_id\"").unwrap();
        let sess_pos = text.find("\"session_id\"").unwrap();
        assert!(doc_pos  < evt_pos,  "document_id must appear before event_id");
        assert!(evt_pos  < recv_pos, "event_id must appear before recipient_id");
        assert!(recv_pos < sess_pos, "recipient_id must appear before session_id");
    }

    #[test]
    fn canonical_json_contains_no_whitespace_between_tokens() {
        let bytes = CanonicalSerializer::to_canonical_json(&sample_event()).unwrap();
        let text  = String::from_utf8(bytes).unwrap();
        // RFC 8785 mandates no insignificant whitespace
        assert!(!text.contains(": "),  "no whitespace after colon");
        assert!(!text.contains(",\n"), "no newlines after commas");
        assert!(!text.contains("  "),  "no double spaces");
    }

    #[test]
    fn canonical_json_roundtrip() {
        let event = sample_event();
        let bytes = CanonicalSerializer::to_canonical_json(&event).unwrap();
        let map   = CanonicalSerializer::from_canonical_json(&bytes).unwrap();
        assert_eq!(map["event_id"].as_str().unwrap(), "evt-001");
        assert_eq!(map["document_id"].as_str().unwrap(), "doc-001");
    }

    #[test]
    fn canonical_cbor_is_deterministic() {
        let event  = sample_event();
        let bytes1 = CanonicalSerializer::to_canonical_cbor(&event).unwrap();
        let bytes2 = CanonicalSerializer::to_canonical_cbor(&event).unwrap();
        assert_eq!(bytes1, bytes2, "CBOR must be byte-for-byte identical across calls");
    }

    #[test]
    fn cbor_roundtrip() {
        let event = sample_event();
        let bytes = CanonicalSerializer::to_canonical_cbor(&event).unwrap();
        let map   = CanonicalSerializer::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(map["event_id"], "evt-001");
        assert_eq!(map["document_id"], "doc-001");
    }

    #[test]
    fn different_events_produce_different_json() {
        let e1 = sample_event();
        let mut e2 = sample_event();
        e2.recipient_id = "bob@secure.gov".into();
        let b1 = CanonicalSerializer::to_canonical_json(&e1).unwrap();
        let b2 = CanonicalSerializer::to_canonical_json(&e2).unwrap();
        assert_ne!(b1, b2);
    }
}
