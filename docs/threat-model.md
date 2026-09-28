# Threat Model & Security Architecture

## 1. Threat Modeling Scope & Methodology

This analysis follows the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with **DREAD** risk scoring.

The core goal of the system is: **Guaranteed attribution of leaked confidential documents under post-quantum threat environments without relying on real-time internet connectivity.**

---

## 2. Threat Scenarios & Mitigations

### 2.1 Threat Scenario 1: Malicious Recipient (Document Leaker)
* **Threat**: An authorized recipient decrypts a classified PDF, leaks it to an external entity, and claims they never accessed or decrypted it (Repudiation).
* **Attack Vectors**:
  * Attempting to claim someone else forged their access.
  * Claiming the system fabricated the ledger record.
* **Mitigations**:
  * **ML-DSA Post-Quantum Digital Signature**: Decryption cannot occur without the recipient's local workstation invoking their private ML-DSA signing key.
  * **Cryptographic Event Binding**: The signature binds the recipient ID to the specific document ID and unique watermark hash.
  * **Non-Repudiation**: Even with quantum computing access, the signature cannot be forged.

### 2.2 Threat Scenario 2: Malicious Administrator
* **Threat**: A rogue IT or security administrator attempts to frame an innocent user or distribute documents with backdoored keys.
* **Attack Vectors**:
  * Injecting fabricated `DecryptionEvent` records into the offline ledger.
  * Tampering with the recipient public key registry.
* **Mitigations**:
  * **Private Key Isolation**: Private keys ($SK_{KEM}$, $SK_{DSA}$) are generated locally on the recipient's secure enclave and never exposed to administrators.
  * **Ledger Multi-Signature Consensus**: Block insertion requires multi-stakeholder validator signatures from independent workstations.
  * The administrator cannot forge the recipient's ML-DSA signature over fabricated events.

### 2.3 Threat Scenario 3: Watermark Removal & Adversarial Distortion
* **Threat**: The leaker attempts to destroy the forensic watermark before publishing the leaked PDF.
* **Attack Vectors**:
  * Cropping margins, re-rasterizing, changing resolution.
  * High-compression JPEG artifacts, geometric warping, print-and-scan attacks.
  * Text extraction / OCR reformatting.
* **Mitigations**:
  * **Multi-Domain Watermarking**: Signals are embedded across both spatial glyph positioning (kerning micro-shifts) and high-frequency Fourier/wavelet transform coefficients.
  * **Spread-Spectrum Redundancy**: The watermark signal is redundantly dispersed across all pages and content layers, surviving aggressive cropping (up to 60% loss).
  * **Statistical Confidence Scoring**: The extraction engine calculates cross-correlation metrics yielding probabilistic confidence bounds admissible in forensic analysis.

### 2.4 Threat Scenario 4: Compromised Endpoint & Memory Dumps
* **Threat**: Malware or an adversary with local administrative privileges attempts to dump plaintext from RAM before watermarking is applied.
* **Attack Vectors**:
  * Attaching a debugger to the decryption process.
  * Extracting symmetric AES key from process memory.
* **Mitigations**:
  * **Atomic Pipeline Execution**: Decryption, watermarking, and signing are executed inside a unified secure memory enclave using zeroizing memory allocators (`zeroize`).
  * The plaintext PDF is never written to disk without watermarks; disk output is strictly watermarked.
  * Ephemeral session keys are wiped immediately after cryptographic operations.

### 2.5 Threat Scenario 5: Ledger Tampering & History Rewriting
* **Threat**: An adversary attempts to delete or alter a past `DecryptionEvent` to conceal a collaborator's leak.
* **Attack Vectors**:
  * Overwriting local ledger block files.
  * Forking an offline partition.
* **Mitigations**:
  * **Merkle Block Chaining**: Each block contains the SHA-256 hash of the preceding block header and the Merkle root of all block events.
  * Any alteration to a historical event invalidates all subsequent block hashes and cryptographic proofs.
  * Periodic sneakernet cross-synchronization ensures distributed parity across air-gapped nodes.

---

## 3. STRIDE Threat Matrix

| Threat Category | Target Component | Threat Description | Architectural Mitigation | Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Identity / Auth | Impersonating an authorized recipient | Post-quantum ML-DSA identity keys protected by local hardware/passphrase | High (Mitigated) |
| **Tampering** | Ledger Blocks | Retroactive deletion of decryption record | Append-only Merkle-linked DLT block structure | Critical (Mitigated) |
| **Repudiation** | Decryption Event | Denying document access after leak | Signed `DecryptionEvent` with canonical serialization & RFC 3339 timestamp | Critical (Mitigated) |
| **Information Disclosure** | Distribution Package | Interception of sealed package in transit | AES-256-GCM + recipient ML-KEM-768 multi-envelope protection | Critical (Mitigated) |
| **Denial of Service** | Offline Ledger | Corrupting ledger sync files | Cryptographic validation of all block headers and receipts before merge | Medium (Mitigated) |
| **Elevation of Privilege** | Local Decryption Engine | Bypassing watermark embedding | Atomic in-memory execution pipeline; watermark hash required in signed event | High (Mitigated) |
