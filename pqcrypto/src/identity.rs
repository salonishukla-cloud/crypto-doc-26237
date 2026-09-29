//! # identity.rs — ML-DSA Post-Quantum Identity Management
//!
//! Manages the generation, storage, and loading of ML-DSA-65 keypairs for recipients.
//!
//! ## Parameter Set: ML-DSA-65
//!
//! | Property | Value |
//! |----------|-------|
//! | NIST Security Category | 3 (≥ 192-bit classical equiv.) |
//! | Public key size | 1952 bytes |
//! | Secret key size | 4032 bytes |
//! | Signature size | 3293 bytes |
//! | Standard | FIPS 204 |
//!
//! ML-DSA-65 is the recommended parameter set for government/classified document
//! distribution where long-term unforgeability must survive quantum adversaries.
//!
//! ## Key Lifecycle
//! ```text
//! generate_signing_keys(recipient_id)
//!       │
//!       ├─ MlDsa65::try_keygen()   →  (PublicKey, SecretKey)
//!       ├─ pk.into_bytes()          →  public_key_bytes  (1952 B)
//!       ├─ sk.into_bytes()          →  secret_key_bytes  (4032 B)
//!       └─ PqIdentityKeypair { recipient_id, public_key_bytes, secret_key_bytes }
//! ```
//!
//! The secret key bytes must be stored in a secure key store (air-gapped HSM or
//! encrypted key file) and NEVER logged or transmitted over any network.

use fips204::ml_dsa_65::{self, KG};
use fips204::traits::{KeyGen, SerDes};

use crate::types::{PqCryptoError, PqIdentityKeypair};

/// ML-DSA-65 public key size in bytes (FIPS 204 Table 2).
pub const ML_DSA_65_PK_BYTES: usize = 1952;
/// ML-DSA-65 secret key size in bytes (FIPS 204 Table 2).
pub const ML_DSA_65_SK_BYTES: usize = 4032;
/// ML-DSA-65 signature size in bytes (FIPS 204 Table 2).
pub const ML_DSA_65_SIG_BYTES: usize = 3309;

/// Algorithm identifier embedded in every `DecryptionEvent.signature_algorithm`.
pub const ALGORITHM_ID: &str = "ML-DSA-65";

/// Identity manager for ML-DSA-65 keypair operations.
pub struct IdentityManager;

impl IdentityManager {
    /// Generate a fresh ML-DSA-65 keypair for `recipient_id`.
    ///
    /// Uses the OS CSPRNG internally (via `fips204`'s `try_keygen`).
    ///
    /// # Returns
    /// [`PqIdentityKeypair`] containing:
    /// - `recipient_id` — the identity string bound to this keypair
    /// - `public_key_bytes` — 1952-byte raw public key (safe to distribute)
    /// - `secret_key_bytes` — 4032-byte raw secret key (must be kept secret)
    ///
    /// # Errors
    /// Returns [`PqCryptoError::KeyGenerationFailed`] if the RNG fails.
    pub fn generate_signing_keys(recipient_id: &str) -> Result<PqIdentityKeypair, PqCryptoError> {
        let (pk, sk) = KG::try_keygen()
            .map_err(|e| PqCryptoError::KeyGenerationFailed(format!("{e:?}")))?;

        let public_key_bytes  = pk.into_bytes().to_vec();
        let secret_key_bytes  = sk.into_bytes().to_vec();

        debug_assert_eq!(public_key_bytes.len(),  ML_DSA_65_PK_BYTES);
        debug_assert_eq!(secret_key_bytes.len(),  ML_DSA_65_SK_BYTES);

        Ok(PqIdentityKeypair {
            recipient_id:    recipient_id.to_string(),
            public_key_bytes,
            secret_key_bytes,
        })
    }

    /// Reconstruct a public key object from raw bytes for verification.
    ///
    /// # Errors
    /// Returns [`PqCryptoError::InvalidPublicKey`] if the bytes are malformed.
    pub fn load_public_key(
        bytes: &[u8],
    ) -> Result<ml_dsa_65::PublicKey, PqCryptoError> {
        let arr: [u8; ML_DSA_65_PK_BYTES] = bytes.try_into().map_err(|_| {
            PqCryptoError::InvalidPublicKey(format!(
                "expected {ML_DSA_65_PK_BYTES} bytes, got {}",
                bytes.len()
            ))
        })?;
        ml_dsa_65::PublicKey::try_from_bytes(arr).map_err(|e| {
            PqCryptoError::InvalidPublicKey(format!("malformed ML-DSA-65 public key: {e:?}"))
        })
    }

    /// Reconstruct a secret key object from raw bytes for signing.
    ///
    /// # Errors
    /// Returns [`PqCryptoError::KeyGenerationFailed`] if the bytes are malformed.
    pub fn load_secret_key(
        bytes: &[u8],
    ) -> Result<ml_dsa_65::PrivateKey, PqCryptoError> {
        let arr: [u8; ML_DSA_65_SK_BYTES] = bytes.try_into().map_err(|_| {
            PqCryptoError::KeyGenerationFailed(format!(
                "expected {ML_DSA_65_SK_BYTES} bytes, got {}",
                bytes.len()
            ))
        })?;
        ml_dsa_65::PrivateKey::try_from_bytes(arr).map_err(|e| {
            PqCryptoError::KeyGenerationFailed(format!("malformed ML-DSA-65 secret key: {e:?}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_correct_sizes() {
        let kp = IdentityManager::generate_signing_keys("test@example.com").unwrap();
        assert_eq!(kp.public_key_bytes.len(),  ML_DSA_65_PK_BYTES, "public key must be 1952 bytes");
        assert_eq!(kp.secret_key_bytes.len(),  ML_DSA_65_SK_BYTES, "secret key must be 4032 bytes");
    }

    #[test]
    fn keygen_produces_unique_keys() {
        let kp1 = IdentityManager::generate_signing_keys("alice@secure.gov").unwrap();
        let kp2 = IdentityManager::generate_signing_keys("alice@secure.gov").unwrap();
        // Two calls must produce different keys (CSPRNG guarantee)
        assert_ne!(kp1.public_key_bytes, kp2.public_key_bytes, "keys must be unique per call");
        assert_ne!(kp1.secret_key_bytes, kp2.secret_key_bytes);
    }

    #[test]
    fn recipient_id_is_preserved() {
        let id = "bob@defence.in";
        let kp = IdentityManager::generate_signing_keys(id).unwrap();
        assert_eq!(kp.recipient_id, id);
    }

    #[test]
    fn load_public_key_roundtrip() {
        let kp = IdentityManager::generate_signing_keys("carol@gov.in").unwrap();
        let _pk = IdentityManager::load_public_key(&kp.public_key_bytes)
            .expect("loading freshly-generated public key must succeed");
    }

    #[test]
    fn load_public_key_rejects_wrong_length() {
        let bad_bytes = vec![0u8; 100];
        let err = IdentityManager::load_public_key(&bad_bytes);
        assert!(matches!(err, Err(PqCryptoError::InvalidPublicKey(_))));
    }

    #[test]
    fn load_secret_key_roundtrip() {
        let kp = IdentityManager::generate_signing_keys("dave@gov.in").unwrap();
        let _sk = IdentityManager::load_secret_key(&kp.secret_key_bytes)
            .expect("loading freshly-generated secret key must succeed");
    }
}
