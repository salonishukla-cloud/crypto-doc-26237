//! Common cryptographic, protocol, and format constants.
//! Note: No business logic resides in this shared crate.

/// Cryptographic algorithm identifier for symmetric authenticated encryption.
pub const ALGORITHM_AES_256_GCM: &str = "AES-256-GCM";

/// Cryptographic algorithm identifier for Post-Quantum Key Encapsulation (FIPS 203).
pub const ALGORITHM_ML_KEM_768: &str = "ML-KEM-768";

/// Cryptographic algorithm identifier for Post-Quantum Digital Signatures (FIPS 204).
pub const ALGORITHM_ML_DSA: &str = "ML-DSA";

/// Specific ML-DSA parameter set (ML-DSA-65 / Dilithium3 equivalent).
pub const ALGORITHM_ML_DSA_65: &str = "ML-DSA-65";

/// Magic bytes header for encrypted document packages.
pub const PACKAGE_MAGIC_HEADER: &[u8; 8] = b"CRPTDOC1";

/// Current package format version.
pub const PACKAGE_FORMAT_VERSION: u16 = 1;

/// Event schema version identifier.
pub const EVENT_SCHEMA_VERSION: &str = "1.0.0";

/// Nonce length for AES-256-GCM (96 bits / 12 bytes).
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Authentication tag length for AES-256-GCM (128 bits / 16 bytes).
pub const AES_GCM_TAG_LEN: usize = 16;

/// Standard SHA-256 digest length in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;
