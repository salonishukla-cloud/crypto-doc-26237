//! # Member 3 — Post-Quantum Cryptography Module
//!
//! Owns:
//! - ML-DSA (FIPS 204 / Dilithium) post-quantum digital signatures
//! - Event canonical serialization (CBOR + RFC 8785 JSON)
//! - Identity management (Post-quantum public key identity verification)
//! - Signature verification for non-repudiation
//!
//! ## Required APIs:
//! - `generate_signing_keys(recipient_id)`
//! - `create_event(params)`
//! - `serialize_event(event)`
//! - `sign_event(unsigned_event, recipient_private_key)`
//! - `verify_event(event, recipient_public_key)`

pub mod event;
pub mod hash;
pub mod identity;
pub mod serialization;
pub mod signer;
pub mod signing;
pub mod types;
pub mod verification;
pub mod verifier;

pub use event::EventBuilder;
pub use hash::{sha256_bytes, sha256_hex, sha256_vec};
pub use identity::{
    IdentityManager, ALGORITHM_ID, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES, ML_DSA_65_SK_BYTES,
};
pub use serialization::CanonicalSerializer;
pub use signer::PqSigner;
pub use signing::{MlDsaSigner, SIGNING_CONTEXT};
pub use types::*;
pub use verification::MlDsaVerifier;
pub use verifier::PqVerifier;

use shared::models::{DecryptionEvent, UnsignedDecryptionEvent};

// ── Top-Level Direct Functional APIs (Role 3 Contract) ──────────────────────

/// Generate an ML-DSA-65 post-quantum signing keypair for a recipient identity.
pub fn generate_signing_keys(recipient_id: &str) -> Result<PqIdentityKeypair, PqCryptoError> {
    IdentityManager::generate_signing_keys(recipient_id)
}

/// Create an unsigned `DecryptionEvent` with standard fields, generated UUID, and RFC 3339 timestamp.
pub fn create_event(params: CreateEventParams) -> Result<UnsignedDecryptionEvent, PqCryptoError> {
    EventBuilder::create_event(params)
}

/// Deterministically serialize an unsigned decryption event into canonical byte form (RFC 8785 JSON).
pub fn serialize_event(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError> {
    CanonicalSerializer::to_canonical_json(event)
}

/// Deterministically serialize an unsigned decryption event into canonical CBOR byte form (RFC 8949).
pub fn serialize_event_cbor(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError> {
    CanonicalSerializer::to_canonical_cbor(event)
}

/// Sign the canonical byte representation of an unsigned decryption event using the recipient's ML-DSA-65 private key.
pub fn sign_event(
    unsigned_event: UnsignedDecryptionEvent,
    recipient_private_key: &[u8],
) -> Result<DecryptionEvent, PqCryptoError> {
    MlDsaSigner::sign_event(unsigned_event, recipient_private_key)
}

/// Verify the ML-DSA-65 signature on a `DecryptionEvent` against the recipient's public key.
pub fn verify_event(
    event: &DecryptionEvent,
    recipient_public_key: &[u8],
) -> Result<bool, PqCryptoError> {
    MlDsaVerifier::verify_event(event, recipient_public_key)
}

// ── Trait Definition & Implementation for Pluggable Providers ────────────────

/// Primary API contract for Member 3 (PQ Crypto).
pub trait PqCryptoProvider {
    /// Constructs a new `DecryptionEvent` instance populated with standard fields and timestamp.
    fn create_event(
        &self,
        params: CreateEventParams,
    ) -> Result<UnsignedDecryptionEvent, PqCryptoError>;

    /// Deterministically serializes an unsigned decryption event into canonical byte form
    /// for hashing and signing. Supports Canonical JSON (RFC 8785).
    fn serialize_event(&self, event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError>;

    /// Signs the canonical byte representation of an unsigned decryption event using
    /// the recipient's ML-DSA private key. Returns the fully assembled, signed `DecryptionEvent`.
    fn sign_event(
        &self,
        unsigned_event: UnsignedDecryptionEvent,
        recipient_private_key: &[u8],
    ) -> Result<DecryptionEvent, PqCryptoError>;

    /// Verifies the ML-DSA signature on a `DecryptionEvent` using the recipient's public key.
    fn verify_event(
        &self,
        event: &DecryptionEvent,
        recipient_public_key: &[u8],
    ) -> Result<bool, PqCryptoError>;
}

/// Default implementation of [`PqCryptoProvider`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultPqCryptoProvider;

impl PqCryptoProvider for DefaultPqCryptoProvider {
    fn create_event(
        &self,
        params: CreateEventParams,
    ) -> Result<UnsignedDecryptionEvent, PqCryptoError> {
        create_event(params)
    }

    fn serialize_event(&self, event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError> {
        serialize_event(event)
    }

    fn sign_event(
        &self,
        unsigned_event: UnsignedDecryptionEvent,
        recipient_private_key: &[u8],
    ) -> Result<DecryptionEvent, PqCryptoError> {
        sign_event(unsigned_event, recipient_private_key)
    }

    fn verify_event(
        &self,
        event: &DecryptionEvent,
        recipient_public_key: &[u8],
    ) -> Result<bool, PqCryptoError> {
        verify_event(event, recipient_public_key)
    }
}
