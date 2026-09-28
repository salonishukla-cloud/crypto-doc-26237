# Member 1 — Encryption Module

## Ownership Scope

* **Owner**: Member 1 (Principal Cryptographer & Packaging Engineer)
* **Assigned Git Branch**: `feature/member1-encryption`
* **Core Responsibilities**:
  * AES-256-GCM Authenticated Encryption for high-throughput confidential document payloads.
  * ML-KEM (FIPS 203 / Kyber) Post-Quantum Key Encapsulation Mechanism.
  * Ephemeral Document Encryption Key (DEK) lifecycle and secure key derivation.
  * Document Packaging (`EncryptedDocumentPackage`) with multi-recipient KEM envelopes.

## Implemented API Contract

Every implementation of Member 1 must fulfill the trait defined in [`src/lib.rs`](src/lib.rs):

```rust
pub trait EncryptionService {
    fn encrypt_document(&self, request: EncryptionRequest) -> Result<EncryptedDocumentPackage, EncryptionError>;
    fn decrypt_document(&self, request: DecryptionRequest) -> Result<DecryptionResult, EncryptionError>;
    fn protect_document_key(&self, recipient_id: &str, recipient_kem_public_key: &[u8], dek: &[u8; 32]) -> Result<RecipientKEMEnvelope, EncryptionError>;
}
```

## Directory Structure

```text
encryption/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs        # Primary EncryptionService trait stubs
│   ├── types.rs      # Encryption requests, results, and error definitions
│   ├── cipher.rs     # AES-256-GCM symmetric cipher trait stub
│   ├── kem.rs        # ML-KEM post-quantum key encapsulation trait stub
│   └── package.rs    # Document packaging serialization trait stub
└── tests/
    └── encryption_tests.rs  # Test suite stubs
```

## Security Invariants

1. **Never reuse a nonce**: AES-256-GCM nonces must be 96-bit cryptographically secure random values generated per encryption.
2. **Post-Quantum Forward Secrecy**: The DEK is never stored on disk in unencrypted form; it is wrapped exclusively within recipient ML-KEM envelopes.
3. **Multi-Recipient Broadcast**: A single document ciphertext is broadcast to $N$ authorized parties without re-encrypting the payload—only the 256-bit DEK is encapsulated per recipient.
4. **Air-Gapped Operation**: No remote KMS, cloud HSM, or network calls are permitted. All keys are derived or loaded locally.

## Git Workflow for Member 1

1. Checkout assigned feature branch:
   ```bash
   git checkout feature/member1-encryption
   ```
2. Develop unit tests and implementations within `encryption/src/` and `encryption/tests/`.
3. Do not modify files in other domain directories (`watermark/`, `pqcrypto/`, `ledger/`, `integration/`).
4. Commit using semantic conventions:
   ```bash
   git commit -m "feat(encryption): implement AES-256-GCM cipher wrapper"
   ```
5. Submit Pull Request targeting `develop`.
