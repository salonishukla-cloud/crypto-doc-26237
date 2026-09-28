# Member 2 — Watermark Module

## Ownership Scope

* **Owner**: Member 2 (Forensic Steganography & Watermarking Engineer)
* **Assigned Git Branch**: `feature/member2-watermark`
* **Core Responsibilities**:
  * Invisible forensic watermark generation bound uniquely to recipient identity, document ID, and session ID.
  * PDF embedding engine ensuring zero visible degradation to document typography, layouts, or graphics.
  * Forensic extraction algorithm capable of recovering signals from digital PDFs, print scans, or re-encoded files.
  * Robustness testing against adversarial attacks (cropping, downsampling, JPEG recompression, noise injection).

## Implemented API Contract

Every implementation of Member 2 must fulfill the trait defined in [`src/lib.rs`](src/lib.rs):

```rust
pub trait WatermarkEngine {
    fn create_watermark(&self, params: CreateWatermarkParams) -> Result<WatermarkPayload, WatermarkError>;
    fn embed_watermark(&self, params: EmbedWatermarkParams) -> Result<Vec<u8>, WatermarkError>;
    fn extract_watermark(&self, leaked_document_bytes: &[u8]) -> Result<WatermarkExtractionResult, WatermarkError>;
    fn verify_watermark(&self, extracted_hash: &str, expected_hash: &str) -> Result<bool, WatermarkError>;
}
```

## Directory Structure

```text
watermark/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs          # Primary WatermarkEngine trait stubs
│   ├── types.rs        # Watermark parameters, payloads, extraction structs, and errors
│   ├── generator.rs    # Forensic watermark bitstream generation stub
│   ├── embedder.rs     # Imperceptible PDF embedding stub
│   ├── extractor.rs    # Signal extraction and recovery stub
│   └── verifier.rs     # Hash verification and confidence scoring stub
└── tests/
    └── watermark_tests.rs  # Robustness and extraction test suite stubs
```

## Forensic Guarantees

1. **Imperceptibility**: The embedded watermark must not alter visual appearance or font kerning to the naked eye (PSNR > 45 dB).
2. **Deterministic Attribution**: The 64-character hex `watermark_hash` stored in the decryption event must match the SHA-256 digest of the watermark payload.
3. **Extraction Confidence**: Extraction results must include a statistical confidence score $[0.0, 1.0]$ to withstand forensic scrutiny in legal/provenance proceedings.

## Git Workflow for Member 2

1. Checkout assigned feature branch:
   ```bash
   git checkout feature/member2-watermark
   ```
2. Build generator and embedder modules within `watermark/src/` and tests in `watermark/tests/`.
3. Never edit files in `encryption/`, `pqcrypto/`, `ledger/`, or `integration/`.
4. Commit with semantic messages:
   ```bash
   git commit -m "feat(watermark): create spread-spectrum watermark payload generator"
   ```
5. Submit Pull Request targeting `develop`.
