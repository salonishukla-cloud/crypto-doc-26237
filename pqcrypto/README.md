# Module: Post-Quantum Cryptography & Identity (`pqcrypto`)

## 1. Role Scope & Ownership (Role 3)

* **Owner**: Role 3 — Principal Post-Quantum Security Architect
* **Branch**: `feature/member3-pqcrypto`
* **Core Responsibilities**:
  * **ML-DSA Key Generation** (FIPS 204 / ML-DSA-65)
  * **Recipient Identity Management** (Post-quantum public key binding)
  * **Canonical Event Serialization** (RFC 8785 Canonical JSON & RFC 8949 CBOR)
  * **Event Signing** (Deterministic pre-hash ML-DSA signing)
  * **Signature Verification & Non-Repudiation**
* **Explicit Non-Goals (Never Implemented Here)**:
  * ❌ AES-256-GCM document encryption (Owned by Member 1)
  * ❌ Watermark generation & embedding (Owned by Member 2)
  * ❌ Ledger & consensus storage (Owned by Member 4)
  * ❌ UI / Web application (Owned by Member 5)

---

## 2. Cryptographic Specifications

### Parameter Set: ML-DSA-65 (FIPS 204 / Dilithium)

| Parameter | Value | Standard |
| :--- | :--- | :--- |
| **NIST Security Category** | Category 3 (≥ 192-bit classical security) | FIPS 204 |
| **Public Key Size** | 1,952 bytes | FIPS 204 Table 2 |
| **Secret Key Size** | 4,032 bytes | FIPS 204 Table 2 |
| **Signature Size** | 3,293 bytes | FIPS 204 Table 2 |
| **Pre-hash Algorithm** | SHA-256 (32-byte digest) | FIPS 180-4 |
| **Domain Separation Context** | `b"decryption-event-v1"` | FIPS 204 §3.3 |

---

## 3. Directory Layout

```text
pqcrypto/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs            # Top-level public APIs & PqCryptoProvider trait
│   ├── identity.rs       # Keypair generation (1952B PK / 4032B SK) & loading
│   ├── signing.rs        # ML-DSA-65 signing over canonical SHA-256 digest
│   ├── verification.rs   # ML-DSA-65 signature verification & tamper detection
│   ├── serialization.rs  # Deterministic RFC 8785 JSON & RFC 8949 CBOR
│   ├── event.rs          # EventBuilder & field validation
│   ├── hash.rs           # SHA-256 digest utilities
│   ├── types.rs          # PqCryptoError, CreateEventParams, PqIdentityKeypair
│   ├── signer.rs         # Trait definition
│   └── verifier.rs       # Trait definition
└── tests/
    └── pqcrypto_tests.rs # Comprehensive unit & integration tests
```

---

## 4. Required API Specifications

### `generate_signing_keys(recipient_id: &str) -> Result<PqIdentityKeypair, PqCryptoError>`
Generates a fresh FIPS 204 ML-DSA-65 keypair using the OS CSPRNG.

### `create_event(params: CreateEventParams) -> Result<UnsignedDecryptionEvent, PqCryptoError>`
Constructs an `UnsignedDecryptionEvent` with UUIDv4 `event_id`, RFC 3339 UTC `timestamp`, and algorithm tag `"ML-DSA-65"`. Validates that all required fields are non-empty.

### `serialize_event(event: &UnsignedDecryptionEvent) -> Result<Vec<u8>, PqCryptoError>`
Performs deterministic RFC 8785 Canonical JSON serialization (lexicographically ordered keys, zero extraneous whitespace).

### `sign_event(unsigned_event: UnsignedDecryptionEvent, recipient_private_key: &[u8]) -> Result<DecryptionEvent, PqCryptoError>`
Computes the canonical serialization, digests with SHA-256, signs using the ML-DSA-65 private key with context `b"decryption-event-v1"`, and attaches the hex-encoded 3,293-byte signature.

### `verify_event(event: &DecryptionEvent, recipient_public_key: &[u8]) -> Result<bool, PqCryptoError>`
Extracts the event fields, computes the canonical JSON digest, loads the 1,952-byte public key, and verifies the ML-DSA-65 signature.

---

## 5. Verification Scenarios & Examples

### ✅ Valid Verification Scenario
When a legitimate recipient signs their decryption event, verification returns `Ok(true)`:

```rust
use pqcrypto::{generate_signing_keys, create_event, sign_event, verify_event, CreateEventParams};

// 1. Recipient generates post-quantum keys
let keypair = generate_signing_keys("officer.shukla@hq.defence.gov")?;

// 2. Recipient creates an event upon document decryption
let unsigned = create_event(CreateEventParams {
    document_id:    "doc-classified-900".into(),
    recipient_id:   "officer.shukla@hq.defence.gov".into(),
    session_id:     "sess-airgap-001".into(),
    watermark_id:   "wm-forensic-7".into(),
    watermark_hash: "a3f890b...".into(),
})?;

// 3. Recipient signs the event locally
let signed_event = sign_event(unsigned, &keypair.secret_key_bytes)?;

// 4. Forensic workstation verifies provenance
let is_valid = verify_event(&signed_event, &keypair.public_key_bytes)?;
assert!(is_valid); // Provenance verified!
```

### ❌ Invalid Verification Scenarios (Tamper Detection)

#### 1. Altered Payload / Framing Another Recipient
If an adversary modifies any field (e.g., `document_id`, `recipient_id`, `watermark_hash`, `timestamp`), the canonical hash changes and verification returns `Ok(false)`:

```rust
let mut tampered_event = signed_event.clone();
tampered_event.recipient_id = "innocent.thirdparty@defence.gov".into();

let is_valid = verify_event(&tampered_event, &keypair.public_key_bytes)?;
assert!(!is_valid); // Verification fails: Tampering detected!
```

#### 2. Key Substitution / Impersonation
If an event is verified with the wrong recipient's public key:

```rust
let eve_keys = generate_signing_keys("eve@malicious.org")?;
let is_valid = verify_event(&signed_event, &eve_keys.public_key_bytes)?;
assert!(!is_valid); // Verification fails: Signature was not produced by Eve's key!
```

#### 3. Modified Signature
If any bit in the hex signature payload is flipped:

```rust
let mut corrupted_event = signed_event.clone();
corrupted_event.signature.replace_range(10..12, "ff");

let is_valid = verify_event(&corrupted_event, &keypair.public_key_bytes)?;
assert!(!is_valid); // Verification fails: Invalid signature!
```

---

## 6. Running Tests

To run the test suite for the PQ Crypto module:

```bash
cargo test -p pqcrypto
```
