# Module 1 — Secure Document Encryption & Key Management

**Author & Role**: Member 1 — Secure Document Encryption Developer  
**SIH 2026 Problem Statement**: Cryptographic Attribution and Immutable Decryption Provenance  
**Target Environment**: Completely Offline / Air-Gapped Secure Enclave  
**Primary Language**: Rust (1.75+)

---

## 1. Architecture & Design Decisions

### 1.1 Hybrid Post-Quantum Cryptographic Envelope
This module solves the core confidential distribution challenge: **How to broadcast a large confidential PDF to $N$ authorized recipients without re-encrypting the document $N$ times, while guaranteeing quantum resistance.**

```text
                                [ Plaintext PDF Document ]
                                             │
                       Generate 256-bit DEK + 96-bit Nonce
                                             │
                        AES-256-GCM Authenticated Encryption
                        (Bound with document_id as AAD)
                                             │
                                   [ Ciphertext + Tag ]
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
       Recipient 1: Alice            Recipient 2: Bob             Recipient 3: Charlie
     ML-KEM-768 Encapsulation      ML-KEM-768 Encapsulation      ML-KEM-768 Encapsulation
               │                             │                             │
    AES-GCM Wrap(DEK, KWK_1)      AES-GCM Wrap(DEK, KWK_2)      AES-GCM Wrap(DEK, KWK_3)
               │                             │                             │
        [ Envelope 1 ]                [ Envelope 2 ]                [ Envelope 3 ]
               └─────────────────────────────┼─────────────────────────────┘
                                             ▼
                             [ EncryptedDocumentPackage ]
                                (Magic: 'CRPTDOC1')
```

1. **High-Throughput Symmetric Core (AES-256-GCM)**:
   * The bulk document payload is encrypted once using an ephemeral, 256-bit symmetric Document Encryption Key (DEK).
   * A cryptographically secure 96-bit nonce is generated per encryption using `rand::rngs::OsRng`.
   * The `document_id` is bound as **Additional Authenticated Data (AAD)** to prevent ciphertext re-attribution or substitution attacks.
2. **Post-Quantum Key Establishment (ML-KEM-768)**:
   * For each authorized recipient, the 256-bit DEK is encapsulated using their Post-Quantum **ML-KEM-768** (FIPS 203) public key.
   * A Key Wrapping Key (KWK) is derived via HKDF-SHA256 from the shared secret.
   * The DEK is wrapped and stored in a lightweight `RecipientKEMEnvelope`.
3. **Air-Gapped Package Container (`CRPTDOC1`)**:
   * The sealed container bundles ciphertext, nonce, 16-byte authentication tag, and recipient envelopes into an immutable structure.

---

## 2. Directory Structure

```text
/encryption
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs              # Re-exports, types, and EncryptionService trait
│   ├── encryption.rs       # encrypt_document() and protect_document_key()
│   ├── decryption.rs       # decrypt_document() and ML-KEM decapsulation
│   ├── key_manager.rs      # generate_recipient_keys(), load_key_pair(), versioning
│   ├── package.rs          # PackageBuilder, validation, file save/load
│   └── errors.rs           # EncryptionError enum using thiserror
└── tests/
    └── encryption_tests.rs # Unit and security test suite
```

---

## 3. Required Function Signatures

### 3.1 `encrypt_document`
```rust
pub fn encrypt_document(
    request: EncryptionRequest,
) -> Result<EncryptedDocumentPackage, EncryptionError>;
```
* **Inputs**: Document ID, title, raw PDF bytes, list of authorized recipient ML-KEM public keys.
* **Outputs**: Sealed `EncryptedDocumentPackage` with multi-recipient KEM envelopes.

### 3.2 `decrypt_document`
```rust
pub fn decrypt_document(
    request: DecryptionRequest,
) -> Result<DecryptionResult, EncryptionError>;
```
* **Inputs**: Target package, recipient ID, recipient's private ML-KEM secret key bytes.
* **Outputs**: Verified plaintext PDF bytes and an ephemeral `session_id`.

### 3.3 `generate_recipient_keys`
```rust
pub fn generate_recipient_keys(
    recipient_id: &str,
) -> Result<RecipientKeyPair, EncryptionError>;
```
* **Inputs**: Unique recipient identity string.
* **Outputs**: `RecipientKeyPair` containing:
  * Public key: 1,184 bytes (ML-KEM-768)
  * Secret key: 2,400 bytes (wrapped in `Zeroizing<Vec<u8>>`)
  * Version number (default `1`)

### 3.4 `protect_document_key`
```rust
pub fn protect_document_key(
    recipient_id: &str,
    recipient_kem_public_key: &[u8],
    dek: &[u8; 32],
) -> Result<RecipientKEMEnvelope, EncryptionError>;
```
* **Inputs**: Recipient ID, recipient's ML-KEM public key, symmetric DEK.
* **Outputs**: `RecipientKEMEnvelope` containing encapsulated key and wrapped DEK.

### 3.5 `load_key_pair`
```rust
pub fn load_key_pair<P: AsRef<Path>>(
    file_path: P,
) -> Result<RecipientKeyPair, EncryptionError>;
```
* **Inputs**: Offline JSON key file path.
* **Outputs**: Loaded and length-validated `RecipientKeyPair`.

---

## 4. Cargo Dependencies

Declared in [`encryption/Cargo.toml`](Cargo.toml):

```toml
[dependencies]
shared = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
hex = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
aes-gcm = { workspace = true }
rand = { workspace = true }
zeroize = { workspace = true }
hkdf = { workspace = true }
chrono = { workspace = true }
```

---

## 5. Security & Cryptographic Invariants

1. **Defense Against "Harvest Now, Decrypt Later" (HNDL)**:
   * Classical RSA or ECC key exchanges are vulnerable to retroactive decryption by future quantum computers.
   * ML-KEM-768 provides 128-bit quantum security margins (equivalent to AES-192/256 classical security), ensuring long-term confidentiality of air-gapped packages.
2. **Deterministic Nonce Management**:
   * A 96-bit CSPRNG nonce (`rand::rngs::OsRng`) is generated per encryption. Nonce collision probability is $< 2^{-32}$ for $2^{48}$ messages.
3. **Automatic Memory Zeroization (`zeroize`)**:
   * All secret keys (`secret_key_bytes`), shared secrets, Key Wrapping Keys (KWK), and symmetric DEKs are wrapped in `Zeroizing<T>`.
   * Memory is overwritten with zeroes immediately upon going out of scope, thwarting memory dump and cold-boot attacks.
4. **Ciphertext Substitution Prevention (AAD Binding)**:
   * The `document_id` is cryptographically bound into the AES-GCM authentication tag as Additional Authenticated Data.
   * Attempting to swap ciphertext or metadata triggers `DecryptionAuthenticationFailed`.
5. **No Network / Purely Offline**:
   * Zero external HTTP, DNS, or KMS calls. Keys are generated, stored, and loaded strictly within air-gapped enclave boundaries.

---

## 6. Compatibility with the Common Event Schema

Upon successful decryption, `decrypt_document()` outputs a `DecryptionResult` containing:
* `document_id`: The authenticated document hash/ID.
* `session_id`: An ephemeral token (`SES-<uuid>`) bound to this decryption event.

These values are consumed by **Member 2 (Watermark)** to generate the watermark and by **Member 3 (PQ Crypto)** to construct the canonical `DecryptionEvent`:

```json
{
  "event_id": "...",
  "document_id": "DOC-2026-ALPHA-01",
  "recipient_id": "RECIPIENT-ALICE",
  "session_id": "SES-7193-AF49-01B9",
  "watermark_id": "...",
  "timestamp": "2026-09-28T22:40:00Z",
  "watermark_hash": "...",
  "signature_algorithm": "ML-DSA",
  "signature": "..."
}
```

Field compatibility with [`shared/schemas/decryption_event.json`](../shared/schemas/decryption_event.json) is 100% preserved.
