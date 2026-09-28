# Unified API Contract Specification

This document details the interface definitions for all five engineering roles. Every module author must maintain strict API compatibility.

---

## Member 1 — Encryption (`encryption::EncryptionService`)

### 1.1 `encrypt_document`
* **Signature**:
  ```rust
  fn encrypt_document(
      &self,
      request: EncryptionRequest,
  ) -> Result<EncryptedDocumentPackage, EncryptionError>;
  ```
* **Inputs**:
  * `request.document_id`: Unique identifier/digest of the document.
  * `request.title`: Display metadata.
  * `request.plaintext_bytes`: Raw PDF payload.
  * `request.recipient_kem_public_keys`: Array of authorized recipient IDs and their ML-KEM-768 public keys.
* **Outputs**: `EncryptedDocumentPackage` containing ciphertext, IV/nonce, authentication tag, and recipient envelopes.
* **Errors**: `EncryptionError::SymmetricEncryptionFailed`, `EncryptionError::KemEncapsulationFailed`.

### 1.2 `decrypt_document`
* **Signature**:
  ```rust
  fn decrypt_document(
      &self,
      request: DecryptionRequest,
  ) -> Result<DecryptionResult, EncryptionError>;
  ```
* **Inputs**:
  * `request.package`: Target `EncryptedDocumentPackage`.
  * `request.recipient_id`: Authenticated recipient ID.
  * `request.kem_secret_key_bytes`: Recipient's ML-KEM private key.
* **Outputs**: `DecryptionResult` containing recovered plaintext bytes, document ID, and active session ID.
* **Errors**: `EncryptionError::RecipientNotAuthorized`, `EncryptionError::DecryptionAuthenticationFailed`.

### 1.3 `protect_document_key`
* **Signature**:
  ```rust
  fn protect_document_key(
      &self,
      recipient_id: &str,
      recipient_kem_public_key: &[u8],
      dek: &[u8; 32],
  ) -> Result<RecipientKEMEnvelope, EncryptionError>;
  ```
* **Inputs**: Recipient ID, recipient's ML-KEM public key bytes, symmetric 256-bit DEK.
* **Outputs**: `RecipientKEMEnvelope` with encapsulated key and wrapped DEK.

---

## Member 2 — Watermark (`watermark::WatermarkEngine`)

### 2.1 `create_watermark`
* **Signature**:
  ```rust
  fn create_watermark(
      &self,
      params: CreateWatermarkParams,
  ) -> Result<WatermarkPayload, WatermarkError>;
  ```
* **Inputs**: `document_id`, `recipient_id`, `session_id`, `strength_factor`.
* **Outputs**: `WatermarkPayload` containing metadata (`watermark_id`, `watermark_hash`) and bitstream.

### 2.2 `embed_watermark`
* **Signature**:
  ```rust
  fn embed_watermark(
      &self,
      params: EmbedWatermarkParams,
  ) -> Result<Vec<u8>, WatermarkError>;
  ```
* **Inputs**: Original decrypted PDF bytes, `WatermarkPayload`.
* **Outputs**: Watermarked PDF bytes visually indistinguishable from source.

### 2.3 `extract_watermark`
* **Signature**:
  ```rust
  fn extract_watermark(
      &self,
      leaked_document_bytes: &[u8],
  ) -> Result<WatermarkExtractionResult, WatermarkError>;
  ```
* **Inputs**: Candidate PDF bytes or raster image bytes.
* **Outputs**: `WatermarkExtractionResult` containing recovered `watermark_id`, `watermark_hash`, and statistical confidence score.

### 2.4 `verify_watermark`
* **Signature**:
  ```rust
  fn verify_watermark(
      &self,
      extracted_hash: &str,
      expected_hash: &str,
  ) -> Result<bool, WatermarkError>;
  ```
* **Inputs**: Hex string of extracted watermark hash vs expected hash recorded on ledger.
* **Outputs**: Boolean confirmation.

---

## Member 3 — PQ Crypto (`pqcrypto::PqCryptoProvider`)

### 3.1 `create_event`
* **Signature**:
  ```rust
  fn create_event(
      &self,
      params: CreateEventParams,
  ) -> Result<UnsignedDecryptionEvent, PqCryptoError>;
  ```
* **Inputs**: `document_id`, `recipient_id`, `session_id`, `watermark_id`, `watermark_hash`.
* **Outputs**: `UnsignedDecryptionEvent` with formatted UTC timestamp (RFC 3339) and UUIDv4 event ID.

### 3.2 `serialize_event`
* **Signature**:
  ```rust
  fn serialize_event(
      &self,
      event: &UnsignedDecryptionEvent,
  ) -> Result<Vec<u8>, PqCryptoError>;
  ```
* **Inputs**: `UnsignedDecryptionEvent`.
* **Outputs**: Deterministic canonical bytes (RFC 8785 JSON or canonical CBOR).

### 3.3 `sign_event`
* **Signature**:
  ```rust
  fn sign_event(
      &self,
      unsigned_event: UnsignedDecryptionEvent,
      recipient_private_key: &[u8],
  ) -> Result<DecryptionEvent, PqCryptoError>;
  ```
* **Inputs**: `UnsignedDecryptionEvent`, recipient's ML-DSA private key.
* **Outputs**: Fully signed `DecryptionEvent` adhering to `shared/schemas/decryption_event.json`.

### 3.4 `verify_event`
* **Signature**:
  ```rust
  fn verify_event(
      &self,
      event: &DecryptionEvent,
      recipient_public_key: &[u8],
  ) -> Result<bool, PqCryptoError>;
  ```
* **Inputs**: Signed `DecryptionEvent`, recipient ML-DSA public key.
* **Outputs**: Boolean indicating cryptographic signature validity.

---

## Member 4 — Ledger (`ledger::LedgerClient`)

### 4.1 `submit_event`
* **Signature**:
  ```rust
  fn submit_event(
      &self,
      event: DecryptionEvent,
  ) -> Result<LedgerReceipt, LedgerError>;
  ```
* **Inputs**: Signed `DecryptionEvent`.
* **Outputs**: `LedgerReceipt` containing block height, block hash, and Merkle inclusion proof.

### 4.2 `get_event`
* **Signature**:
  ```rust
  fn get_event(
      &self,
      event_id: &str,
  ) -> Result<DecryptionEvent, LedgerError>;
  ```
* **Inputs**: `event_id` UUID string.
* **Outputs**: Stored `DecryptionEvent`.

### 4.3 `find_by_watermark`
* **Signature**:
  ```rust
  fn find_by_watermark(
      &self,
      watermark_identifier: &str,
  ) -> Result<DecryptionEvent, LedgerError>;
  ```
* **Inputs**: `watermark_id` or 64-char hex `watermark_hash`.
* **Outputs**: Associated `DecryptionEvent`.

### 4.4 `verify_ledger_record`
* **Signature**:
  ```rust
  fn verify_ledger_record(
      &self,
      event_id: &str,
  ) -> Result<LedgerVerificationResult, LedgerError>;
  ```
* **Inputs**: `event_id`.
* **Outputs**: `LedgerVerificationResult` verifying Merkle proof and chain continuity.

---

## Member 5 — Integration (`integration::ForensicOrchestrator`)

### 5.1 `run_decryption_workflow`
* **Signature**:
  ```rust
  fn run_decryption_workflow(
      &self,
      request: DecryptionWorkflowRequest,
  ) -> Result<DecryptionWorkflowResult, IntegrationError>;
  ```
* **Inputs**: `DecryptionWorkflowRequest` (package bytes, recipient credentials).
* **Outputs**: `DecryptionWorkflowResult` (watermarked PDF bytes, event ID, ledger receipt).

### 5.2 `verify_leaked_document`
* **Signature**:
  ```rust
  fn verify_leaked_document(
      &self,
      leaked_document_bytes: &[u8],
  ) -> Result<ForensicEvidenceReport, IntegrationError>;
  ```
* **Inputs**: Raw bytes of suspect leaked file.
* **Outputs**: `ForensicEvidenceReport` detailing watermark match, attributed recipient, and signature verification.

### 5.3 `generate_report`
* **Signature**:
  ```rust
  fn generate_report(
      &self,
      report: &ForensicEvidenceReport,
  ) -> Result<String, IntegrationError>;
  ```
* **Inputs**: `ForensicEvidenceReport`.
* **Outputs**: Formatted legal/audit markdown or text certificate.
