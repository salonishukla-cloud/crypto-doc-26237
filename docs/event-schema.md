# Common Decryption Event Schema Specification

## 1. Overview & Invariant Rule

The `DecryptionEvent` is the cryptographic core of the attribution platform. It serves as an immutable, non-repudiable legal and forensic record proving that a specific authorized recipient accessed, decrypted, and received a uniquely watermarked instance of a confidential document.

> [!CRITICAL]
> **Strict Field Contract Rule**:
> No module, library, or branch may alter, rename, omit, or add fields to this contract. All five developers must consume and produce this exact schema.

---

## 2. Canonical JSON Schema

Defined centrally in [`shared/schemas/decryption_event.json`](../shared/schemas/decryption_event.json):

```json
{
  "event_id": "a98c7602-5e43-46fc-86cf-90f757f495b2",
  "document_id": "DOC-2026-CONFIDENTIAL-4019",
  "recipient_id": "RECIPIENT-OPERATIVE-07",
  "session_id": "SES-7193-AF49-01B9",
  "watermark_id": "WM-94F0-18D2",
  "timestamp": "2026-09-28T22:40:00Z",
  "watermark_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature_algorithm": "ML-DSA",
  "signature": "3045022100a3...[ML-DSA-65 Signature Bytes]"
}
```

---

## 3. Field-by-Field Specification

| Field Name | Type | Format / Constraints | Description | Produced By | Verified By |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | String | UUIDv4 | Universally unique event identifier. Prevents replay attacks across sessions. | Member 3 | Member 4, 5 |
| `document_id` | String | UTF-8 String / SHA-256 | Identifier or cryptographic digest of the source confidential document. | Member 1, 5 | Member 4, 5 |
| `recipient_id` | String | UTF-8 String / Key Fingerprint | Unique public identity string of authorized recipient executing decryption. | Member 3, 5 | Member 4, 5 |
| `session_id` | String | UTF-8 String | Ephemeral session token bound to the recipient's local authentication state. | Member 1, 5 | Member 5 |
| `watermark_id` | String | UTF-8 String | Unique identifier of the generated forensic watermark instance. | Member 2 | Member 4, 5 |
| `timestamp` | String | RFC 3339 / ISO 8601 UTC | Exact UTC timestamp marking the decryption and embedding operation. | Member 3 | Member 4, 5 |
| `watermark_hash` | String | 64-char Hex (SHA-256) | Cryptographic digest of the raw forensic watermark bitstream. | Member 2 | Member 3, 4, 5 |
| `signature_algorithm` | String | Fixed: `"ML-DSA"` | Algorithm name designating post-quantum digital signature scheme. | Member 3 | Member 5 |
| `signature` | String | Hex or Base64 | Post-Quantum ML-DSA signature computed over canonical serialization. | Member 3 | Member 3, 5 |

---

## 4. Canonical Serialization & Signing Rules

To ensure non-repudiation, the recipient's signature is computed over the unsigned canonical byte representation:

1. **Unsigned Extraction**:
   The `signature` field is excluded. The unsigned tuple is:
   $$\{ \text{event\_id}, \text{document\_id}, \text{recipient\_id}, \text{session\_id}, \text{watermark\_id}, \text{timestamp}, \text{watermark\_hash}, \text{signature\_algorithm} \}$$

2. **JSON Canonicalization Scheme (RFC 8785)**:
   * Keys are sorted lexicographically by UTF-16 code units.
   * Whitespace outside strings is completely stripped.
   * Number formatting and character escapes adhere to strict RFC 8785 rules.

3. **Deterministic CBOR**:
   * Map keys are sorted by byte length, then lexicographical order.
   * Definite-length strings and arrays only.

4. **Signing Computation**:
   $$\text{signature} = \text{ML-DSA-Sign}_{SK_{recipient}}(\text{CanonicalBytes})$$
