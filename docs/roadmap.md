# 4-Week Development Roadmap

## Sprint Schedule Overview

```text
Week 1: Foundations, Schemas & API Contracts (Scaffold Complete)
Week 2: Isolated Module Implementation & Unit Test Suites
Week 3: Cross-Module Integration, Pipeline Assembly & Sneakernet DLT
Week 4: Forensic Hardening, Adversarial Watermark Attacks & UI Demo
```

---

## Week 1: Contracts, Architecture & Scaffolding
* **Objectives**: Establish repository layout, lock `shared/schemas/decryption_event.json`, initialize traits and git feature branches.
* **Member Deliverables**:
  * **All Members**: Review and sign off on `docs/api-contract.md` and `docs/event-schema.md`.
  * **Member 1**: Scaffold `encryption` crate, define AES-256-GCM and ML-KEM interfaces.
  * **Member 2**: Scaffold `watermark` crate, define embedding and extraction traits.
  * **Member 3**: Scaffold `pqcrypto` crate, establish canonical RFC 8785 JSON serialization stubs.
  * **Member 4**: Scaffold `ledger` crate, design block structure and Merkle proof schemas.
  * **Member 5**: Scaffold `integration` crate, build central Fluent UI theme and dark/light tokens.

---

## Week 2: Core Domain Implementations
* **Objectives**: Each member implements their domain logic in their respective feature branch without modifying other modules.
* **Member Deliverables**:
  * **Member 1 (`feature/member1-encryption`)**:
    * Implement AES-256-GCM authenticated cipher wrapping.
    * Implement ML-KEM-768 key encapsulation and decapsulation routines.
    * Build `EncryptedDocumentPackage` builder with multi-recipient envelope serialization.
  * **Member 2 (`feature/member2-watermark`)**:
    * Implement pseudo-random spread-spectrum watermark bitstream generator.
    * Implement PDF content stream imperceptible glyph displacement embedder.
    * Implement extraction engine for native PDF and scanned image inputs.
  * **Member 3 (`feature/member3-pqcrypto`)**:
    * Implement ML-DSA-65 post-quantum signing and verification algorithms.
    * Implement RFC 8785 Canonical JSON and deterministic CBOR serializers.
    * Write property-based test harness validating 100% deterministic event digests.
  * **Member 4 (`feature/member4-ledger`)**:
    * Implement append-only disk block storage with SHA-256 chain links.
    * Implement Merkle tree calculation for block transaction receipts.
    * Implement high-speed in-memory reverse lookup indexing (`find_by_watermark`).
  * **Member 5 (`feature/member5-integration`)**:
    * Expand Fluent UI workstation interface (acrylic cards, theme toggle, forms).
    * Build mock harness for end-to-end event execution.

---

## Week 3: Pipeline Integration & DLT Sync
* **Objectives**: Merge individual feature branches into `develop` via Pull Requests. Connect the full decryption and watermarking workflow.
* **Member Deliverables**:
  * **Sprint Milestone**: First automated end-to-end run: Document Encrypted -> Decrypted -> Watermarked -> Event Signed -> Ingested to DLT.
  * **Integration Work**:
    * Wire `run_decryption_workflow()` in `integration::orchestrator`.
    * Implement air-gapped sneakernet batch export/import protocol for offline ledger synchronization.
    * Execute cross-module integration tests in `tests/integration/decryption_pipeline_test.rs`.

---

## Week 4: Security Hardening, Robustness & Final Demo
* **Objectives**: Subject the watermarking engine to adversarial attacks, audit cryptographic signatures, and polish the Fluent UI workstation for executive demonstration.
* **Member Deliverables**:
  * **Forensic Robustness Testing**:
    * Test watermark extraction against cropped (up to 50%), blurred, noise-injected, and re-rasterized PDFs.
  * **Security Audit**:
    * Verify tamper-detection on modified ledger blocks and altered events.
    * Validate that unsigned or wrongly signed events are rejected by the DLT.
  * **UI/UX Polish**:
    * Finalize Fluent UI workstation with seamless dark/light mode transitions.
    * Add interactive forensic evidence report preview and PDF download.
  * **Release**: Merge `develop` -> `main` with full test suite passing.
