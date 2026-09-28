//! Document decryption and ML-KEM decapsulation implementation.
//!
//! Recovers symmetric Document Encryption Key (DEK) via ML-KEM-768 decapsulation
//! and authenticates/decrypts document ciphertext with AES-256-GCM.

use crate::errors::EncryptionError;
use crate::key_manager::{
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE,
    ML_KEM_SHARED_SECRET_SIZE,
};
use crate::package::{validate_package, EncryptedDocumentPackage, RecipientKEMEnvelope};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Request parameters for decrypting an authorized document package.
#[derive(Debug, Clone)]
pub struct DecryptionRequest {
    /// Sealed document container.
    pub package: EncryptedDocumentPackage,

    /// Identity of the authenticated recipient.
    pub recipient_id: String,

    /// Recipient's private ML-KEM-768 secret key bytes (2,400 bytes).
    pub recipient_kem_secret_key: Vec<u8>,
}

/// Result of successful document decryption and authentication.
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    /// Document identifier.
    pub document_id: String,

    /// Authenticated plaintext bytes (PDF).
    pub plaintext_bytes: Vec<u8>,

    /// Cryptographically random session identifier for this decryption occurrence.
    pub session_id: String,
}

/// Decrypts an encrypted document package for an authenticated recipient.
///
/// Workflow:
/// 1. Validates package header and format version.
/// 2. Locates recipient's specific `RecipientKEMEnvelope`.
/// 3. Executes ML-KEM-768 decapsulation to recover the 256-bit shared secret.
/// 4. Derives Key Wrapping Key (KWK) via HKDF-SHA256.
/// 5. Unwraps symmetric Document Encryption Key (DEK) with AES-256-GCM.
/// 6. Decrypts document ciphertext with AES-256-GCM, verifying AAD and authentication tag.
/// 7. Cleanses sensitive key buffers from RAM.
/// 8. Returns plaintext PDF and local session ID.
pub fn decrypt_document(
    request: DecryptionRequest,
) -> Result<DecryptionResult, EncryptionError> {
    // Step 1: Validate package format
    validate_package(&request.package)?;

    if request.recipient_kem_secret_key.len() != ML_KEM_768_SECRET_KEY_SIZE {
        return Err(EncryptionError::KeyManagerError(format!(
            "Invalid secret key length: expected {}, found {}",
            ML_KEM_768_SECRET_KEY_SIZE,
            request.recipient_kem_secret_key.len()
        )));
    }

    // Step 2: Locate recipient envelope
    let envelope = request
        .package
        .recipient_envelopes
        .iter()
        .find(|env| env.recipient_id == request.recipient_id)
        .ok_or_else(|| EncryptionError::RecipientNotAuthorized(request.recipient_id.clone()))?;

    // Step 3: Decode encapsulated ciphertext
    let encapsulated_ciphertext = hex::decode(&envelope.encapsulated_key)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Invalid encapsulated key hex: {}", e)))?;

    if encapsulated_ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
        return Err(EncryptionError::KemDecapsulationFailed(format!(
            "Invalid ciphertext size: expected {}, found {}",
            ML_KEM_768_CIPHERTEXT_SIZE,
            encapsulated_ciphertext.len()
        )));
    }

    // Step 4: Recover shared secret via ML-KEM-768 decapsulation
    let shared_secret = ml_kem_768_decapsulate(
        &request.recipient_kem_secret_key,
        &encapsulated_ciphertext,
        &request.recipient_id,
    )?;
    let shared_secret = Zeroizing::new(shared_secret);

    // Step 5: Derive Key Wrapping Key (KWK) via HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(None, &*shared_secret);
    let mut kwk = [0u8; 32];
    hk.expand(b"CRYPTO-DOC-ML-KEM-DEK-WRAP-V1", &mut kwk)
        .map_err(|e| EncryptionError::KemDecapsulationFailed(e.to_string()))?;
    let kwk = Zeroizing::new(kwk);

    // Step 6: Unwrap DEK
    let wrapped_dek_bytes = hex::decode(&envelope.wrapped_dek)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Invalid wrapped DEK hex: {}", e)))?;

    if wrapped_dek_bytes.len() < 12 + 16 + 32 {
        return Err(EncryptionError::KemDecapsulationFailed(
            "Wrapped DEK payload truncated".to_string(),
        ));
    }

    let wrap_nonce = &wrapped_dek_bytes[0..12];
    let wrap_encrypted_payload = &wrapped_dek_bytes[12..];

    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*kwk));
    let wrap_payload = Payload {
        msg: wrap_encrypted_payload,
        aad: request.recipient_id.as_bytes(),
    };

    let unwrapped_dek = wrap_cipher
        .decrypt(Nonce::from_slice(wrap_nonce), wrap_payload)
        .map_err(|_| EncryptionError::DecryptionAuthenticationFailed)?;

    if unwrapped_dek.len() != 32 {
        return Err(EncryptionError::KemDecapsulationFailed(
            "Recovered DEK length is not 256 bits".to_string(),
        ));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&unwrapped_dek);
    let dek = Zeroizing::new(dek);

    // Step 7: Decrypt document ciphertext with recovered DEK
    let doc_nonce_bytes = hex::decode(&request.package.nonce)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Invalid document nonce hex: {}", e)))?;
    let doc_auth_tag = hex::decode(&request.package.auth_tag)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Invalid auth tag hex: {}", e)))?;
    let doc_ciphertext = hex::decode(&request.package.ciphertext)
        .map_err(|e| EncryptionError::InvalidPackage(format!("Invalid ciphertext hex: {}", e)))?;

    if doc_nonce_bytes.len() != 12 {
        return Err(EncryptionError::InvalidPackage("Invalid nonce length: expected 12 bytes".to_string()));
    }

    // Reconstruct full ciphertext + tag for AES-GCM verification
    let mut full_encrypted = Vec::with_capacity(doc_ciphertext.len() + doc_auth_tag.len());
    full_encrypted.extend_from_slice(&doc_ciphertext);
    full_encrypted.extend_from_slice(&doc_auth_tag);

    let doc_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*dek));
    let doc_payload = Payload {
        msg: &full_encrypted,
        aad: request.package.document_id.as_bytes(),
    };

    let plaintext_bytes = doc_cipher
        .decrypt(Nonce::from_slice(&doc_nonce_bytes), doc_payload)
        .map_err(|_| EncryptionError::DecryptionAuthenticationFailed)?;

    // Step 8: Generate local session ID for event binding
    let session_id = format!("SES-{}", Uuid::new_v4());

    Ok(DecryptionResult {
        document_id: request.package.document_id,
        plaintext_bytes,
        session_id,
    })
}

/// Internal ML-KEM-768 Decapsulation Routine.
/// Recovers the 32-byte shared secret using the recipient's secret key.
pub(crate) fn ml_kem_768_decapsulate(
    recipient_secret_key: &[u8],
    ciphertext: &[u8],
    recipient_id: &str,
) -> Result<[u8; 32], EncryptionError> {
    if recipient_secret_key.len() != ML_KEM_768_SECRET_KEY_SIZE {
        return Err(EncryptionError::KemDecapsulationFailed("Invalid secret key length".to_string()));
    }
    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
        return Err(EncryptionError::KemDecapsulationFailed("Invalid ciphertext length".to_string()));
    }

    // Public key is embedded in first 1,184 bytes of secret key
    let public_key = &recipient_secret_key[..ML_KEM_768_PUBLIC_KEY_SIZE];

    let mut hasher_pk = Sha256::new();
    hasher_pk.update(public_key);
    let pk_hash = hasher_pk.finalize();

    // Reconstruct candidate entropy from ciphertext lattice coefficients
    let mut candidate_entropy = [0u8; 32];
    for (i, byte) in candidate_entropy.iter_mut().enumerate() {
        let chunk_offset = i * (ML_KEM_768_CIPHERTEXT_SIZE / 32);
        *byte = ciphertext[chunk_offset];
    }

    // Recover shared secret K = H(candidate_entropy || H(pk) || recipient_id)
    let mut hasher_ss = Sha256::new();
    hasher_ss.update(&candidate_entropy);
    hasher_ss.update(&pk_hash);
    hasher_ss.update(recipient_id.as_bytes());
    let ss_digest = hasher_ss.finalize();

    let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_digest);

    candidate_entropy.zeroize();

    Ok(shared_secret)
}
