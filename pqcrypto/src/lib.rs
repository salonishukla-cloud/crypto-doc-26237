//! # Member 3 — Post-Quantum Cryptography Module
//!
//! Owns:
//! - ML-DSA (FIPS 204 / Dilithium) digital signatures
//! - Event canonical serialization (CBOR + RFC 8785 JSON)
//! - Identity management (Post-quantum public key identity verification)
//! - Signature verification for non-repudiation
//!
//! Required API Contract:
//! - `create_event()`
//! - `serialize_event()`
//! - `sign_event()`
//! - `verify_event()`

pub mod event;
pub mod signer;
pub mod types;
pub mod verifier;

pub use event::EventSerializer;
pub use signer::PqSigner;
pub use types::*;
pub use verifier::PqVerifier;

use shared::models::{DecryptionEvent, UnsignedDecryptionEvent};

/// Primary API contract for Member 3 (PQ Crypto).
pub trait PqCryptoProvider {
    /// Constructs a new `DecryptionEvent` instance populated with standard fields and timestamp.
    /// Signature field is initially empty or prepared for signing.
    fn create_event(
        &self,
        params: CreateEventParams,
    ) -> Result<UnsignedDecryptionEvent, PqCryptoError>;

    /// Deterministically serializes an unsigned decryption event into canonical byte form
    /// for hashing and signing. Supports both Canonical JSON (RFC 8785) and deterministic CBOR.
    fn serialize_event(
        &self,
        event: &UnsignedDecryptionEvent,
    ) -> Result<Vec<u8>, PqCryptoError>;

    /// Signs the canonical byte representation of an unsigned decryption event using
    /// the recipient's ML-DSA private key. Returns the fully assembled, signed `DecryptionEvent`.
    fn sign_event(
        &self,
        unsigned_event: UnsignedDecryptionEvent,
        recipient_private_key: &[u8],
    ) -> Result<DecryptionEvent, PqCryptoError>;

    /// Verifies the ML-DSA signature on a `DecryptionEvent` using the recipient's public key.
    ///
    /// Returns `true` if and only if the signature is cryptographically valid over
    /// the canonical serialization of the event's data fields.
    fn verify_event(
        &self,
        event: &DecryptionEvent,
        recipient_public_key: &[u8],
    ) -> Result<bool, PqCryptoError>;
}
