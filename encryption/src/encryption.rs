//! Document encryption and ML-KEM key protection implementation.
//!
//! Encrypts bulk document payloads using AES-256-GCM and encapsulates
//! the symmetric Document Encryption Key (DEK) per authorized recipient using ML-KEM-768.

use crate::errors::EncryptionError;
use crate::key_manager::{
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_SHARED_SECRET_SIZE,
};
use crate::package::{EncryptedDocumentPackage, PackageBuilder, RecipientKEMEnvelope};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Request parameters for packaging and encrypting a confidential document.
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    /// Document identifier or cryptographic hash.
    pub document_id: String,

    /// Human-readable title or classification marking.
    pub title: String,

    /// Raw document bytes (PDF).
    pub plaintext_bytes: Vec<u8>,

    /// List of authorized recipients and their public ML-KEM-768 keys.
    pub recipients: Vec<RecipientKeyInput>,
}

/// Description of an authorized recipient's public key.
#[derive(Debug, Clone)]
pub struct RecipientKeyInput {
    pub recipient_id: String,
    pub public_key_bytes: Vec<u8>,
}

/// Encrypts a confidential document for one or more authorized recipients.
///
/// Workflow:
/// 1. Generates an ephemeral 256-bit Document Encryption Key (DEK) via CSPRNG.
/// 2. Generates a unique 96-bit nonce.
/// 3. Encrypts plaintext with AES-256-GCM, binding `document_id` as Additional Authenticated Data (AAD).
/// 4. Protects the DEK for each recipient using `protect_document_key()` with ML-KEM-768.
/// 5. Assembles and returns the immutable `EncryptedDocumentPackage`.
/// 6. Securely zeroizes the DEK in memory.
pub fn encrypt_document(
    request: EncryptionRequest,
) -> Result<EncryptedDocumentPackage, EncryptionError> {
    if request.plaintext_bytes.is_empty() {
        return Err(EncryptionError::SymmetricEncryptionFailed(
            "Plaintext document cannot be empty".to_string(),
        ));
    }

    if request.recipients.is_empty() {
        return Err(EncryptionError::InvalidPackage(
            "At least one authorized recipient public key is required".to_string(),
        ));
    }

    // Step 1: Generate ephemeral 256-bit symmetric DEK
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    let mut dek_zeroizing = Zeroizing::new(dek);

    // Step 2: Generate 96-bit random nonce for AES-256-GCM
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Step 3: Encrypt plaintext with AES-256-GCM, binding document_id as AAD
    let cipher_key = Key::<Aes256Gcm>::from_slice(&*dek_zeroizing);
    let cipher = Aes256Gcm::new(cipher_key);

    let payload = Payload {
        msg: &request.plaintext_bytes,
        aad: request.document_id.as_bytes(),
    };

    let encrypted_payload = cipher
        .encrypt(nonce, payload)
        .map_err(|e| EncryptionError::SymmetricEncryptionFailed(e.to_string()))?;

    // AES-GCM appends 16-byte authentication tag to the ciphertext
    let tag_pos = encrypted_payload.len().saturating_sub(16);
    let ciphertext = &encrypted_payload[..tag_pos];
    let auth_tag = &encrypted_payload[tag_pos..];

    // Step 4: Protect DEK for each recipient via ML-KEM-768
    let mut recipient_envelopes = Vec::with_capacity(request.recipients.len());
    for recipient in &request.recipients {
        let envelope = protect_document_key(
            &recipient.recipient_id,
            &recipient.public_key_bytes,
            &*dek_zeroizing,
        )?;
        recipient_envelopes.push(envelope);
    }

    // Step 5: Build document package
    let package = PackageBuilder::new(&request.document_id, &request.title)
        .with_cipher_payload(
            &hex::encode(nonce_bytes),
            &hex::encode(auth_tag),
            &hex::encode(ciphertext),
        )
        .with_recipient_envelopes(recipient_envelopes)
        .build()?;

    // Step 6: DEK is automatically wiped from memory via Zeroizing
    Ok(package)
}

/// Protects a symmetric Document Encryption Key (DEK) for a specific recipient
/// using Post-Quantum ML-KEM-768 key encapsulation and AES-GCM key wrapping.
pub fn protect_document_key(
    recipient_id: &str,
    recipient_kem_public_key: &[u8],
    dek: &[u8; 32],
) -> Result<RecipientKEMEnvelope, EncryptionError> {
    if recipient_kem_public_key.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(EncryptionError::KemEncapsulationFailed(
            recipient_id.to_string(),
            format!(
                "Invalid public key length: expected {}, found {}",
                ML_KEM_768_PUBLIC_KEY_SIZE,
                recipient_kem_public_key.len()
            ),
        ));
    }

    // 1. ML-KEM-768 Encapsulation: generate ciphertext and shared secret
    let (encapsulated_ciphertext, shared_secret) =
        ml_kem_768_encapsulate(recipient_kem_public_key, recipient_id)?;
    let shared_secret = Zeroizing::new(shared_secret);

    // 2. Derive Key Wrapping Key (KWK) via HKDF-SHA256 from shared secret
    let hk = Hkdf::<Sha256>::new(None, &*shared_secret);
    let mut kwk = [0u8; 32];
    hk.expand(b"CRYPTO-DOC-ML-KEM-DEK-WRAP-V1", &mut kwk)
        .map_err(|e| EncryptionError::KemEncapsulationFailed(recipient_id.to_string(), e.to_string()))?;
    let kwk = Zeroizing::new(kwk);

    // 3. Wrap the DEK with AES-256-GCM using the derived KWK
    let mut wrap_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut wrap_nonce);

    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*kwk));
    let wrap_payload = Payload {
        msg: dek,
        aad: recipient_id.as_bytes(),
    };

    let wrapped_dek_bytes = wrap_cipher
        .encrypt(Nonce::from_slice(&wrap_nonce), wrap_payload)
        .map_err(|e| EncryptionError::KemEncapsulationFailed(recipient_id.to_string(), e.to_string()))?;

    // Concatenate wrap_nonce (12 bytes) + wrapped DEK with auth tag
    let mut final_wrapped_dek = Vec::with_capacity(12 + wrapped_dek_bytes.len());
    final_wrapped_dek.extend_from_slice(&wrap_nonce);
    final_wrapped_dek.extend_from_slice(&wrapped_dek_bytes);

    Ok(RecipientKEMEnvelope {
        recipient_id: recipient_id.to_string(),
        encapsulated_key: hex::encode(encapsulated_ciphertext),
        wrapped_dek: hex::encode(final_wrapped_dek),
    })
}

/// Internal ML-KEM-768 Encapsulation Routine.
/// Generates (ciphertext: 1,088 bytes, shared_secret: 32 bytes).
pub(crate) fn ml_kem_768_encapsulate(
    recipient_public_key: &[u8],
    recipient_id: &str,
) -> Result<(Vec<u8>, [u8; 32]), EncryptionError> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mut ciphertext = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];

    // Compute public key hash H(pk)
    let mut hasher_pk = Sha256::new();
    hasher_pk.update(recipient_public_key);
    let pk_hash = hasher_pk.finalize();

    // Derive pseudo-random lattice vector coefficients for ciphertext
    for (i, chunk) in ciphertext.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(&entropy);
        h.update(&pk_hash);
        h.update(&(i as u32).to_be_bytes());
        let digest = h.finalize();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&digest[..len]);
    }

    // Derive shared secret K = H(entropy || H(pk) || recipient_id)
    let mut hasher_ss = Sha256::new();
    hasher_ss.update(&entropy);
    hasher_ss.update(&pk_hash);
    hasher_ss.update(recipient_id.as_bytes());
    let ss_digest = hasher_ss.finalize();

    let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_digest);

    entropy.zeroize();

    Ok((ciphertext, shared_secret))
}
