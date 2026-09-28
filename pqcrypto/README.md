# Member 3 — Post-Quantum Cryptography Module

## Ownership Scope

* **Owner**: Member 3 (Post-Quantum Digital Signatures & Identity Engineer)
* **Assigned Git Branch**: `feature/member3-pqcrypto`
* **Core Responsibilities**:
  * ML-DSA (FIPS 204 / Dilithium) post-quantum digital signature generation and verification.
  * Deterministic serialization using Canonical JSON (RFC 8785) and CBOR.
  * Local recipient identity binding and non-repudiation.
  * Cryptographic signature audit trail creation for every decryption occurrence.

## Implemented API Contract

Every implementation of Member 3 must fulfill the trait defined in [`src/lib.rs`](src/lib.rs):

```rust
pub trait PqCryptoProvider {
    fn create_event(&self, params: CreateEventParams) -> Result<UnsignedDecryptionEvent, PqCryptoError>;
    fn serialize_event(&self, event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError>;
    fn sign_event(&self, unsigned_event: UnsignedDecryptionEvent, recipient_private_key: &[u8]) -> Result<DecryptionEvent, PqCryptoError>;
    fn verify_event(&self, event: &DecryptionEvent, recipient_public_key: &[u8]) -> Result<bool, PqCryptoError>;
}
```

## Directory Structure

```text
pqcrypto/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs        # Primary PqCryptoProvider trait stubs
│   ├── types.rs      # Identity keys, event params, and error models
│   ├── signer.rs     # ML-DSA signing trait stub
│   ├── verifier.rs   # ML-DSA signature verification trait stub
│   └── event.rs      # Canonical serialization (JSON RFC 8785 / CBOR) stub
└── tests/
    └── pqcrypto_tests.rs  # Test suite stubs
```

## Cryptographic Guarantees

1. **Post-Quantum Non-Repudiation**: Even against future cryptanalytically relevant quantum computers (CRQC), ML-DSA signatures cannot be forged.
2. **Deterministic Serialization**: Signatures are computed strictly over canonical serialized bytes; key reordering or whitespace variance is strictly prevented.
3. **Immutability Contract**: All fields in `DecryptionEvent` match the schema defined in [`shared/schemas/decryption_event.json`](../shared/schemas/decryption_event.json).

## Git Workflow for Member 3

1. Checkout assigned feature branch:
   ```bash
   git checkout feature/member3-pqcrypto
   ```
2. Implement ML-DSA routines and serialization stubs in `pqcrypto/src/` and tests in `pqcrypto/tests/`.
3. Never touch `encryption/`, `watermark/`, `ledger/`, or `integration/`.
4. Commit with semantic messages:
   ```bash
   git commit -m "feat(pqcrypto): add ML-DSA signing stub and canonical serialization"
   ```
5. Submit Pull Request targeting `develop`.
