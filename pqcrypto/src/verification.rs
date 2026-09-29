//! # verification.rs — ML-DSA-65 Signature Verification
//!
//! Implements `verify_event()` using the **HashML-DSA** verification scheme:
//!
//! ```text
//! DecryptionEvent
//!   ├─ extract fields (excluding signature) → UnsignedDecryptionEvent
//!   ├─ canonical JSON (RFC 8785) serialization
//!   ├─ SHA-256 digest (32 bytes)
//!   └─ ML-DSA-65::verify(pk, digest, sig, ctx=b"decryption-event-v1")
//!         ├─ true  → Signature is VALID (document decryption proven)
//!         └─ false → Signature is INVALID (tampering or wrong key detected)
//! ```
//!
//! ## Security Properties
//! 1. **Authenticity**: Proves the event was signed by the holder of the recipient's ML-DSA private key.
//! 2. **Integrity**: Any single-bit alteration in `event_id`, `document_id`, `recipient_id`,
//!    `session_id`, `watermark_id`, `timestamp`, or `watermark_hash` invalidates the signature.
//! 3. **Non-Repudiation**: The recipient cannot deny having decrypted the document once their
//!    ML-DSA-65 signature is verified.
//! 4. **Post-Quantum Security**: Unforgeable against quantum computers (Category 3 NIST / FIPS 204).

use fips204::traits::Verifier;

use shared::models::{DecryptionEvent, UnsignedDecryptionEvent};

use crate::hash::sha256_bytes;
use crate::identity::{IdentityManager, ML_DSA_65_SIG_BYTES};
use crate::serialization::CanonicalSerializer;
use crate::signing::SIGNING_CONTEXT;
use crate::types::PqCryptoError;

/// ML-DSA-65 verifier for [`DecryptionEvent`].
pub struct MlDsaVerifier;

impl MlDsaVerifier {
    /// Verify the ML-DSA-65 digital signature on a [`DecryptionEvent`].
    ///
    /// # Process
    /// 1. Decodes and validates the hex-encoded signature from `event.signature`.
    /// 2. Extracts all non-signature fields into an [`UnsignedDecryptionEvent`].
    /// 3. Computes the canonical JSON bytes (RFC 8785).
    /// 4. Computes the SHA-256 pre-hash of the canonical JSON bytes.
    /// 5. Loads the recipient's public key from raw bytes.
    /// 6. Verifies the ML-DSA-65 signature against the digest with the fixed domain-separation context.
    ///
    /// # Returns
    /// - `Ok(true)` if the signature is cryptographically valid and matches the event content and public key.
    /// - `Ok(false)` if the signature is invalid (tampered content, wrong key, or modified signature).
    /// - `Err(PqCryptoError)` if public key bytes are malformed or signature hex decoding fails.
    pub fn verify_event(
        event: &DecryptionEvent,
        public_key_bytes: &[u8],
    ) -> Result<bool, PqCryptoError> {
        // ── Step 1: Decode hex signature ──────────────────────────────────────
        let sig_bytes = hex::decode(&event.signature).map_err(|e| {
            PqCryptoError::VerificationFailed(format!("signature is not valid hex: {e}"))
        })?;

        if sig_bytes.len() != ML_DSA_65_SIG_BYTES {
            return Err(PqCryptoError::VerificationFailed(format!(
                "invalid signature length: expected {ML_DSA_65_SIG_BYTES} bytes, got {}",
                sig_bytes.len()
            )));
        }

        let sig_arr: [u8; ML_DSA_65_SIG_BYTES] = sig_bytes
            .try_into()
            .map_err(|_| PqCryptoError::VerificationFailed("signature slice conversion failed".into()))?;

        // ── Step 2: Reconstruct unsigned event fields ─────────────────────────
        let unsigned = UnsignedDecryptionEvent {
            event_id:            event.event_id.clone(),
            document_id:         event.document_id.clone(),
            recipient_id:        event.recipient_id.clone(),
            session_id:          event.session_id.clone(),
            watermark_id:        event.watermark_id.clone(),
            timestamp:           event.timestamp.clone(),
            watermark_hash:      event.watermark_hash.clone(),
            signature_algorithm: event.signature_algorithm.clone(),
        };

        // ── Step 3: Compute canonical JSON serialization ──────────────────────
        let canonical_bytes = CanonicalSerializer::to_canonical_json(&unsigned)?;

        // ── Step 4: Compute SHA-256 pre-hash ──────────────────────────────────
        let digest = sha256_bytes(&canonical_bytes);

        // ── Step 5: Load recipient's public key ────────────────────────────────
        let pk = IdentityManager::load_public_key(public_key_bytes)?;

        // ── Step 6: Verify ML-DSA-65 signature ────────────────────────────────
        let is_valid = pk.verify(&digest, &sig_arr, SIGNING_CONTEXT);

        Ok(is_valid)
    }

    /// Verify raw signature bytes against arbitrary message bytes and public key.
    ///
    /// Lower-level API for modular verification pipelines.
    pub fn verify_bytes(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, PqCryptoError> {
        if signature_bytes.len() != ML_DSA_65_SIG_BYTES {
            return Ok(false);
        }

        let sig_arr: [u8; ML_DSA_65_SIG_BYTES] = signature_bytes
            .try_into()
            .map_err(|_| PqCryptoError::VerificationFailed("signature slice conversion failed".into()))?;

        let pk = IdentityManager::load_public_key(public_key_bytes)?;
        let is_valid = pk.verify(message, &sig_arr, SIGNING_CONTEXT);
        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventBuilder;
    use crate::identity::IdentityManager;
    use crate::signing::MlDsaSigner;
    use crate::types::CreateEventParams;

    fn make_test_setup() -> (Vec<u8>, Vec<u8>, DecryptionEvent) {
        let kp = IdentityManager::generate_signing_keys("alice@secure.gov").unwrap();
        let unsigned = EventBuilder::create_event(CreateEventParams {
            document_id:    "doc-classified-001".into(),
            recipient_id:   "alice@secure.gov".into(),
            session_id:     "sess-auth-8812".into(),
            watermark_id:   "wm-forensic-09".into(),
            watermark_hash: "3f79a90c12879a6d".into(),
        }).unwrap();
        let signed = MlDsaSigner::sign_event(unsigned, &kp.secret_key_bytes).unwrap();
        (kp.public_key_bytes, kp.secret_key_bytes, signed)
    }

    // ── VALID VERIFICATION SCENARIO ──────────────────────────────────────────
    #[test]
    fn test_valid_event_verification_succeeds() {
        let (pk, _, event) = make_test_setup();
        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(is_valid, "unmodified event with legitimate key must verify as valid");
    }

    // ── INVALID VERIFICATION SCENARIOS ───────────────────────────────────────
    #[test]
    fn test_invalid_verification_tampered_document_id() {
        let (pk, _, mut event) = make_test_setup();
        // Attacker alters document ID from doc-classified-001 to doc-classified-002
        event.document_id = "doc-classified-002".into();
        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(!is_valid, "tampered document_id must fail verification");
    }

    #[test]
    fn test_invalid_verification_tampered_recipient_id() {
        let (pk, _, mut event) = make_test_setup();
        // Attacker frames another recipient
        event.recipient_id = "bob@secure.gov".into();
        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(!is_valid, "tampered recipient_id must fail verification");
    }

    #[test]
    fn test_invalid_verification_tampered_watermark_hash() {
        let (pk, _, mut event) = make_test_setup();
        // Watermark hash altered
        event.watermark_hash = "deadbeef00000000".into();
        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(!is_valid, "tampered watermark_hash must fail verification");
    }

    #[test]
    fn test_invalid_verification_tampered_timestamp() {
        let (pk, _, mut event) = make_test_setup();
        // Timestamp changed
        event.timestamp = "2026-01-01T00:00:00Z".into();
        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(!is_valid, "tampered timestamp must fail verification");
    }

    #[test]
    fn test_invalid_verification_wrong_public_key() {
        let (_, _, event) = make_test_setup();
        // Eve generates her own keypair and tries to verify Alice's signed event
        let eve_kp = IdentityManager::generate_signing_keys("eve@malicious.org").unwrap();
        let is_valid = MlDsaVerifier::verify_event(&event, &eve_kp.public_key_bytes).unwrap();
        assert!(!is_valid, "verification with wrong recipient public key must fail");
    }

    #[test]
    fn test_invalid_verification_corrupted_signature_bytes() {
        let (pk, _, mut event) = make_test_setup();
        // Corrupt first byte of signature hex
        let mut sig_chars: Vec<char> = event.signature.chars().collect();
        sig_chars[0] = if sig_chars[0] == '0' { '1' } else { '0' };
        event.signature = sig_chars.into_iter().collect();

        let is_valid = MlDsaVerifier::verify_event(&event, &pk).unwrap();
        assert!(!is_valid, "corrupted signature bytes must fail verification");
    }

    #[test]
    fn test_invalid_verification_malformed_hex_signature() {
        let (pk, _, mut event) = make_test_setup();
        event.signature = "NOT_HEX_STRING!!".into();
        let result = MlDsaVerifier::verify_event(&event, &pk);
        assert!(matches!(result, Err(PqCryptoError::VerificationFailed(_))));
    }
}
