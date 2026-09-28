# Member 4 — Permissioned Offline Ledger Module

## Ownership Scope

* **Owner**: Member 4 (Distributed Ledger & Consensus Architect)
* **Assigned Git Branch**: `feature/member4-ledger`
* **Core Responsibilities**:
  * Permissioned, air-gapped Distributed Ledger Technology (DLT) storage engine.
  * Append-only cryptographic block structure with Merkle trees for event inclusion proofs.
  * Fast reverse-index lookup by `watermark_id` and `watermark_hash`.
  * Offline partition consensus and batch export/import synchronization over secure physical air-gap media.

## Implemented API Contract

Every implementation of Member 4 must fulfill the trait defined in [`src/lib.rs`](src/lib.rs):

```rust
pub trait LedgerClient {
    fn submit_event(&self, event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError>;
    fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError>;
    fn find_by_watermark(&self, watermark_identifier: &str) -> Result<DecryptionEvent, LedgerError>;
    fn verify_ledger_record(&self, event_id: &str) -> Result<LedgerVerificationResult, LedgerError>;
}
```

## Directory Structure

```text
ledger/
├── Cargo.toml
├── README.md
├── src/
│   └── lib.rs        # Primary LedgerClient trait stubs
├── client/
│   ├── mod.rs        # Client exports
│   └── dlt_client.rs # Error types and verification result models
├── schema/
│   ├── mod.rs        # Schema exports
│   └── block.rs      # BlockHeader, LedgerBlock, and LedgerReceipt models
└── tests/
    └── ledger_tests.rs  # Test suite stubs
```

## Ledger Security Invariants

1. **Air-Gapped Operation**: No tokenomics, mining, gas, or public network gossip. The ledger is designed for high-assurance confidential operations.
2. **Cryptographic Immutability**: All blocks are cryptographically linked using SHA-256 block hashes and Merkle root trees. Tampering with any historical event breaks downstream block hashes.
3. **Partition Resilience**: Supports offline node operations where records are generated locally and synced asynchronously across security enclaves via signed migration manifests.

## Git Workflow for Member 4

1. Checkout assigned feature branch:
   ```bash
   git checkout feature/member4-ledger
   ```
2. Develop block storage, indexing, and lookup functions in `ledger/src/`, `ledger/client/`, `ledger/schema/`, and tests in `ledger/tests/`.
3. Do not modify files in `encryption/`, `watermark/`, `pqcrypto/`, or `integration/`.
4. Commit with semantic messages:
   ```bash
   git commit -m "feat(ledger): implement block header hashing and Merkle tree generation"
   ```
5. Submit Pull Request targeting `develop`.
