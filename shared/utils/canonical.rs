//! Deterministic and Canonical Serialization Interfaces.
//! Adheres strictly to RFC 8785 (JSON Canonicalization Scheme) and deterministic CBOR.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CanonicalizationError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Hash calculation failure: {0}")]
    HashError(String),
}

/// Trait defining canonical deterministic byte representation for cryptographic signing.
pub trait CanonicalSerialize {
    /// Produces a deterministic canonical JSON byte sequence (RFC 8785).
    fn to_canonical_json(&self) -> Result<Vec<u8>, CanonicalizationError>;

    /// Produces a deterministic CBOR byte sequence.
    fn to_canonical_cbor(&self) -> Result<Vec<u8>, CanonicalizationError>;
}

/// Interface for generating cryptographic digests over payloads.
pub trait DigestProvider {
    /// Computes a standard SHA-256 digest returning a 64-character lowercase hex string.
    fn sha256_hex(data: &[u8]) -> String;
}
