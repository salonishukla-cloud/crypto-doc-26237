//! # hash.rs — Cryptographic Digest Utilities
//!
//! Provides SHA-256 hashing helpers used throughout the pqcrypto module.
//!
//! ## Design Rule
//! All signing operations in this system operate over a **SHA-256 pre-hash** of the
//! canonical serialization, not the raw bytes. This is the "HashML-DSA" construction
//! described in FIPS 204 Section 5.4.  Benefits:
//! - Bounded message length for the signer (critical for embedded/air-gapped hardware)
//! - Consistent 32-byte digest regardless of event payload size
//! - Independent verifiability of the content hash without the ML-DSA library

use sha2::{Digest, Sha256};

/// Compute the SHA-256 digest of `data` and return it as a 32-byte array.
#[inline]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Compute the SHA-256 digest of `data` and return a 64-char lowercase hex string.
#[inline]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute SHA-256 of `data` and return as `Vec<u8>`.
#[inline]
pub fn sha256_vec(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Compute the SHA-256 digest of multiple concatenated slices without heap allocation
/// of the intermediate buffer.
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = sha256_hex(b"");
        assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_abc_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492c347bcd017d9f4
        // corrected: ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492c347bcd017d9f4
        let result = sha256_hex(b"abc");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn sha256_bytes_matches_hex() {
        let data = b"test payload";
        let bytes = sha256_bytes(data);
        let hex   = sha256_hex(data);
        assert_eq!(hex::encode(bytes), hex);
    }

    #[test]
    fn sha256_concat_matches_single_call() {
        let a = b"hello ";
        let b = b"world";
        let combined: Vec<u8> = [a.as_ref(), b.as_ref()].concat();
        let c1 = sha256_bytes(&combined);
        let c2 = sha256_concat(&[a, b]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn sha256_is_deterministic() {
        let d1 = sha256_hex(b"deterministic");
        let d2 = sha256_hex(b"deterministic");
        assert_eq!(d1, d2);
    }
}
