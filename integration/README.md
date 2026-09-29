# Member 5 — Integration & Verification Workstation (`integration`)

## 1. Role Scope & Ownership (Role 5)

* **Owner**: Role 5 — Principal Software Architect (System Integration)
* **Branch**: `feature/member5-integration`
* **Core Responsibilities**:
  * **End-to-End Orchestration**: Connect Modules 1 (Encryption), 2 (Watermark), 3 (PQ Crypto), and 4 (Ledger).
  * **Authentication & Decryption Pipeline**: De-encapsulate ML-KEM keys, decrypt AES-256-GCM payload, embed invisible forensic watermarks, sign with ML-DSA-65, and commit to the 4-node ledger.
  * **Forensic Attribution Workstation**: Extract watermark fingerprints from leaked documents, query DLT reverse indices, verify post-quantum signatures, audit Merkle trees, and establish non-repudiation.
  * **Legally Admissible Dossier**: Generate dual-format forensic evidence reports (Human-readable Markdown + Canonical JSON).
  * **Simple Rust + HTML UI**: Clean, responsive, and beautiful interface styled in warm beige and rich shades of brown.
* **Non-Goals (Zero Rewriting of Other Modules)**:
  * ❌ Does NOT reimplement core cryptography; orchestrates existing modules through clean API traits.

---

## 2. Decryption & Provenance Pipeline

```text
Recipient Authenticates
        ↓
ML-KEM De-encapsulate & AES-256-GCM Decrypt (Module 1)
        ↓
Generate Invisible Multi-Layer Watermark (Module 2)
        ↓
Embed Watermark into Plaintext PDF (Module 2)
        ↓
Create RFC 8785 Canonical JSON Event (Module 3)
        ↓
ML-DSA-65 Post-Quantum Sign Event (Module 3)
        ↓
Submit Signed Event to 4-Node Offline Ledger (Module 4)
        ↓
Return Watermarked PDF + Immutable Audit Receipt
```

---

## 3. Forensic Leak Attribution Pipeline

```text
Candidate Leaked Document PDF
        ↓
Extract Watermark via 4 Stacked Channels (Module 2)
        ↓
Reverse Lookup Decryption Event on 4-Node DLT (Module 4)
        ↓
Verify ML-DSA-65 Digital Signature (Module 3)
        ↓
Verify Blockchain Merkle Tree & Hash Continuity (Module 4)
        ↓
Generate Formal Forensic Attribution Dossier (Markdown + JSON)
```

---

## 4. Directory Layout

```text
integration/
├── Cargo.toml
├── README.md
├── workflow.rs       # run_decryption_workflow() orchestration
├── verification.rs   # verify_leaked_document() workstation
├── report.rs         # generate_report() Markdown & JSON dossiers
├── backend/
│   └── mod.rs        # Integration error models & type re-exports
├── ui/               # Simple, vibrant, beige & brown UI
│   ├── index.html    # Single-page interface (Sender, Recipient, Forensics, Explorer)
│   ├── styles.css    # Custom warm beige & rich brown palette
│   └── app.js        # Interactivity, simulation, and report exporter
├── src/
│   └── lib.rs        # ForensicOrchestrator trait & top-level APIs
└── tests/
    └── integration_tests.rs  # Full 5-stage end-to-end integration tests
```

---

## 5. Required APIs & Code Examples

### `run_decryption_workflow()`
```rust
use integration::{run_decryption_workflow, DecryptionWorkflowRequest};
use ledger::PermissionedLedgerClient;

let ledger_client = PermissionedLedgerClient::new("node-1");
let result = run_decryption_workflow(request, &ledger_client)?;
// Returns watermarked_pdf_bytes, signed decryption_event, and ledger_receipt
```

### `verify_leaked_document()`
```rust
use integration::verify_leaked_document;

let report = verify_leaked_document(&leaked_pdf_bytes, &recipient_dsa_public_key, &ledger_client)?;
assert_eq!(report.verdict, ForensicVerdict::ConfirmedAttribution);
```

### `generate_report()`
```rust
use integration::generate_report;

let dossier_text = generate_report(&report)?;
println!("{}", dossier_text);
```

---

## 6. Running Tests

To run the full end-to-end integration suite across all 4 modules:

```bash
cargo test -p integration
```
