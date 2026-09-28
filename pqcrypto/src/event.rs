use crate::types::PqCryptoError;
use shared::models::{DecryptionEvent, UnsignedDecryptionEvent};

/// Trait stub for deterministic canonical serialization of DecryptionEvent structures.
pub trait EventSerializer {
    /// Serializes an UnsignedDecryptionEvent into canonical JSON (RFC 8785) byte sequence.
    fn to_canonical_json(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError>;

    /// Serializes an UnsignedDecryptionEvent into deterministic CBOR byte sequence.
    fn to_canonical_cbor(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError>;
}
