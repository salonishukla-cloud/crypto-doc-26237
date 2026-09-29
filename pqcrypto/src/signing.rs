//! # signing.rs — ML-DSA-65 Event Signing
//!
//! Implements `sign_event()` using the **HashML-DSA** construction:
//!
//! ```text
//! UnsignedDecryptionEvent
//!   └─ canonical JSON (RFC 8785) bytes
//!         └─ SHA-256 digest  (32 bytes)
//!               └─ ML-DSA-65::sign(sk, digest, ctx=b"decryption-event-v1")
//!                     └─ 3293-byte raw signature
//!                           └─ hex::encode → signature field in DecryptionEvent
//! ```
//!
//! ## Context String
//! The FIPS 204 context byte string is fixed to `b"decryption-event-v1"`.
//! This binds signatures to this specific application and version, preventing
//! cross-protocol signature reuse attacks.
//!
//! ## Why pre-hash?
//! ML-DSA is designed for arbitrary-length messages but for our use case:
//! 1. The 32-byte SHA-256 digest is a commitment to the entire event body
//! 2. Signing the hash is faster and memory-bounded (critical on air-gapped hardware)
//! 3. The hash independently serves as an integrity check in the ledger record

use fips204::traits::Signer;

use shared::models::{DecryptionEvent, UnsignedDecryptionEvent};

use crate::hash::sha256_bytes;
use crate::identity::IdentityManager;
use crate::serialization::CanonicalSerializer;
use crate::types::PqCryptoError;

/// Application-specific context string for ML-DSA signing.
/// Prevents cross-protocol signature reuse (FIPS 204 §3.3).
pub const SIGNING_CONTEXT: &[u8] = b"decryption-event-v1";

/// ML-DSA-65 signer for [`UnsignedDecryptionEvent`].
pub struct MlDsaSigner;

impl MlDsaSigner {
    /// Sign an unsigned decryption event with the recipient's ML-DSA-65 secret key.
    ///
    /// # Arguments
    /// * `unsigned_event` — The event to sign; must have all required fields populated.
    /// * `secret_key_bytes` — Raw 4032-byte ML-DSA-65 secret key bytes.
    ///
    /// # Returns
    /// A fully assembled [`DecryptionEvent`] with the `signature` field populated
    /// as a lowercase hex-encoded string of the 3293-byte ML-DSA-65 signature.
    ///
    /// # Errors
    /// - [`PqCryptoError::SerializationFailed`] if canonical serialization fails
    /// - [`PqCryptoError::SigningFailed`] if the key is malformed or signing fails
    pub fn sign_event(
        unsigned_event: UnsignedDecryptionEvent,
        secret_key_bytes: &[u8],
    ) -> Result<DecryptionEvent, PqCryptoError> {
        // ── Step 1: Canonical JSON serialization ──────────────────────────────
        let canonical_bytes = CanonicalSerializer::to_canonical_json(&unsigned_event)?;

        // ── Step 2: SHA-256 pre-hash ──────────────────────────────────────────
        let digest = sha256_bytes(&canonical_bytes);

        // ── Step 3: Load the secret key ───────────────────────────────────────
        let sk = IdentityManager::load_secret_key(secret_key_bytes)?;

        // ── Step 4: ML-DSA-65 sign over the digest with context ───────────────
        let signature_bytes = sk
            .try_sign(&digest, SIGNING_CONTEXT)
            .map_err(|e| PqCryptoError::SigningFailed(format!("ML-DSA-65 sign failed: {e:?}")))?;

        // ── Step 5: Hex-encode the signature for the event field ──────────────
        let signature_hex = hex::encode(signature_bytes);

        // ── Step 6: Assemble the signed DecryptionEvent ───────────────────────
        Ok(DecryptionEvent {
            event_id:            unsigned_event.event_id,
            document_id:         unsigned_event.document_id,
            recipient_id:        unsigned_event.recipient_id,
            session_id:          unsigned_event.session_id,
            watermark_id:        unsigned_event.watermark_id,
            timestamp:           unsigned_event.timestamp,
            watermark_hash:      unsigned_event.watermark_hash,
            signature_algorithm: unsigned_event.signature_algorithm,
            signature:           signature_hex,
        })
    }

    /// Sign raw bytes directly with an ML-DSA-65 secret key.
    ///
    /// Lower-level API for use by other modules (e.g., integration tests).
    /// The caller is responsible for pre-hashing if desired.
    pub fn sign_bytes(
        secret_key_bytes: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, PqCryptoError> {
        let sk = IdentityManager::load_secret_key(secret_key_bytes)?;
        let sig = sk
            .try_sign(message, SIGNING_CONTEXT)
            .map_err(|e| PqCryptoError::SigningFailed(format!("{e:?}")))?;
        Ok(sig.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventBuilder;
    use crate::identity::IdentityManager;
    use crate::types::CreateEventParams;

    fn make_keypair_and_unsigned_event() -> (Vec<u8>, Vec<u8>, UnsignedDecryptionEvent) {
        let kp = IdentityManager::generate_signing_keys("test@secure.gov").unwrap();
        let event = EventBuilder::create_event(CreateEventParams {
            document_id:    "doc-sign-001".into(),
            recipient_id:   "test@secure.gov".into(),
            session_id:     "sess-sign-001".into(),
            watermark_id:   "wm-sign-001".into(),
            watermark_hash: "cafebabe".into(),
        }).unwrap();
        (kp.public_key_bytes, kp.secret_key_bytes, event)
    }

    #[test]
    fn sign_event_returns_non_empty_signature() {
        let (_, sk, event) = make_keypair_and_unsigned_event();
        let signed = MlDsaSigner::sign_event(event, &sk).unwrap();
        assert!(!signed.signature.is_empty(), "signature must not be empty");
    }

    #[test]
    fn signature_is_hex_encoded() {
        let (_, sk, event) = make_keypair_and_unsigned_event();
        let signed = MlDsaSigner::sign_event(event, &sk).unwrap();
        // Must be valid hex
        assert!(hex::decode(&signed.signature).is_ok(), "signature must be valid hex");
    }

    #[test]
    fn signature_length_is_ml_dsa_65() {
        use crate::identity::ML_DSA_65_SIG_BYTES;
        let (_, sk, event) = make_keypair_and_unsigned_event();
        let signed = MlDsaSigner::sign_event(event, &sk).unwrap();
        let sig_bytes = hex::decode(&signed.signature).unwrap();
        assert_eq!(
            sig_bytes.len(), ML_DSA_65_SIG_BYTES,
            "ML-DSA-65 signature must be exactly 3293 bytes"
        );
    }

    #[test]
    fn all_unsigned_fields_preserved_in_signed_event() {
        let (_, sk, event) = make_keypair_and_unsigned_event();
        let event_id_copy = event.event_id.clone();
        let doc_id_copy   = event.document_id.clone();
        let signed = MlDsaSigner::sign_event(event, &sk).unwrap();
        assert_eq!(signed.event_id,   event_id_copy);
        assert_eq!(signed.document_id, doc_id_copy);
        assert_eq!(signed.signature_algorithm, "ML-DSA-65");
    }

    #[test]
    fn signing_with_wrong_key_length_fails() {
        let (_, _, event) = make_keypair_and_unsigned_event();
        let bad_sk = vec![0u8; 64]; // wrong length
        let err = MlDsaSigner::sign_event(event, &bad_sk);
        assert!(err.is_err(), "signing with wrong-length key must fail");
    }
}
