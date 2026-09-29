# Role 2 — Forensic Watermark Module

> **Owner:** Member 2 | **Branch:** `feature/watermark`
>
> **Status:** ✅ Full Implementation — 36 tests passing

---

## Purpose

Provides **invisible, multi-layer forensic watermarking** for confidential PDF documents.
When a watermarked document is later found leaked, the forensic extractor recovers the
recipient's identity even under aggressive attacks.

---

## Module Structure

```
watermark/
├── src/
│   ├── lib.rs        — WatermarkService façade + module declarations
│   ├── payload.rs    — 142-byte canonical payload, HMAC-SHA256, repetition coding
│   ├── generator.rs  — ForensicWatermarkGenerator (create_watermark)
│   ├── embedder.rs   — PdfWatermarkEmbedder (embed_watermark, 4 channels)
│   ├── extractor.rs  — ForensicWatermarkExtractor (extract_watermark)
│   ├── validator.rs  — WatermarkValidator (verify_watermark, attribution verdict)
│   └── types.rs      — Error types, parameter structs, result structs
└── tests/
    └── watermark_tests.rs — 10 robustness integration tests
```

---

## Public API

```rust
use watermark::{WatermarkService, CreateWatermarkParams, EmbedWatermarkParams};

// 1. Generate
let wm = WatermarkService::create_watermark(CreateWatermarkParams {
    document_id:     "doc-001".into(),
    recipient_id:    "alice@secure.gov".into(),
    session_id:      "sess-abc".into(),
    strength_factor: 1.0,
})?;

// Store wm.metadata.watermark_hash on the ledger

// 2. Embed
let watermarked_pdf = WatermarkService::embed_watermark(EmbedWatermarkParams {
    original_pdf_bytes: raw_pdf_bytes,
    watermark: wm,
})?;

// 3. Extract (forensic workstation, after leak discovered)
let result = WatermarkService::extract_watermark(&leaked_pdf_bytes)?;
println!("Confidence: {}", result.confidence_score);

// 4. Verify against ledger
let matched = WatermarkService::verify_watermark(
    &result.watermark_hash,
    &ledger_hash,
)?;
```

---

## Payload Format

```
┌─────────────────────────────────────────────────────────────────┐
│ MAGIC (4 B)  │ VERSION (1 B)  │ FLAGS (1 B)                    │
│ SHA-256(recipient_id)   (32 B)                                  │
│ SHA-256(document_id)    (32 B)                                  │
│ SHA-256(session_id)     (32 B)                                  │
│ Unix timestamp BE       (8 B)                                   │
│ HMAC-SHA256 tag         (32 B)                                  │
└─────────────────────────────────────────────────────────────────┘
Total: 142 bytes raw → 426 bytes with 3× repetition coding → 3408 bits
```

---

## Embedding Channels (Stacked)

| Channel | Technique | Imperceptibility | Survives |
|---------|-----------|-----------------|---------|
| **A** | XMP / PDF Info metadata comment injection | Metadata never rendered | Re-download, file-open |
| **B** | Zero-width Unicode (U+200B / U+200C) in BT blocks | Zero advance-width chars | OCR, copy-paste |
| **C** | Unicode homoglyph substitution (Latin → Cyrillic) | Pixel-identical at display sizes | Screenshot |
| **D** | Spread-spectrum hex comment block | PDF `%` comments not painted | Compression |

### Why imperceptible?
- **A**: Info/XMP entries are document properties, not painted content.
- **B**: U+200B (ZERO WIDTH SPACE) and U+200C (ZERO WIDTH NON-JOINER) have zero advance width. PDF renderers skip them without any visual change.
- **C**: At 10–14pt body text sizes the Cyrillic homoglyphs (а е о р с х) are pixel-for-pixel identical to their Latin counterparts in all major PDF viewers.
- **D**: PDF comment lines beginning with `%` are lexer tokens consumed and discarded by parsers; no renderer ever processes them.

---

## Robustness Test Coverage

| Test | Attack simulated | Expected survival |
|------|-----------------|-------------------|
| `test_roundtrip_end_to_end` | No attack (golden path) | All channels |
| `test_survives_metadata_removal` | `exiftool -all=` strips Channel A | B, C, D |
| `test_survives_screenshot_ocr` | OCR normalises homoglyphs | A, B, D |
| `test_survives_file_conversion` | CRLF → LF + BOM injection | B, D |
| `test_survives_cropping` | First 40 % of file discarded | Graceful degradation |
| `test_survives_noise_injection` | Random byte flips (every 100th) | B (majority vote) |
| `test_survives_compression` | All `%` comments stripped | B (ZWC in BT block) |
| `test_verify_wrong_hash_fails` | Wrong recipient hash | Verifier returns false |
| `test_watermark_id_structure` | UUID-like shape invariant | Generator |
| `test_bitstream_length_is_three_times_payload` | Payload length invariant | Generator |

---

## Integration with Other Modules

| Module | How this module connects |
|--------|--------------------------|
| **encryption** (Role 1) | Provides decrypted PDF bytes → embedder input |
| **shared** | Uses `WatermarkMetadata` from `shared::models` for ledger records |
| **ledger** (Role 4) | Stores `watermark_hash` from `WatermarkPayload.metadata` |
| **integration** (Role 5) | Calls `WatermarkService::extract_watermark` on the forensic workstation |

---

## Running Tests

```sh
cargo test -p watermark
```

Expected: `36 passed; 0 failed`

---

## Security Properties

- **Unforgeability**: HMAC-SHA256 with a binding key derived from the three identifiers prevents any third party from constructing a valid watermark payload without knowing all three identifiers.
- **Tamper evidence**: A single flipped bit in the payload invalidates the HMAC tag.
- **Timing safety**: `WatermarkValidator::verify` uses constant-time byte comparison.
- **Channel independence**: Destroying any 3 of 4 channels still leaves one intact for attribution.
- **Majority-vote correction**: 3× repetition coding corrects up to 1-of-3 channel copy destruction.
