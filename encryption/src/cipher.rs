use crate::types::EncryptionError;

/// Trait stub for AES-256-GCM authenticated cipher operations.
pub trait SymmetricCipher {
    /// Encrypts plaintext using AES-256-GCM with a randomly generated 96-bit nonce.
    /// Returns (ciphertext, nonce, auth_tag).
    fn encrypt_aes_gcm(
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), EncryptionError>;

    /// Decrypts AES-256-GCM ciphertext, verifying the authentication tag and associated data.
    fn decrypt_aes_gcm(
        key: &[u8; 32],
        nonce: &[u8; 12],
        auth_tag: &[u8; 16],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError>;
}
