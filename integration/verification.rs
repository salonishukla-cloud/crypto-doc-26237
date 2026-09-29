//! # verification.rs — Leaked Document Forensic Verification Workstation
//!
//! Orchestrates the full attribution analysis of candidate leaked documents:
//! 1. Module 2: Watermark Signal Extraction across 4 stacked channels
//! 2. Module 4: Reverse DLT Index Lookup
//! 3. Module 3: ML-DSA-65 Post-Quantum Signature Verification
//! 4. Module 4: Merkle Proof & Blockchain Cryptographic Continuity Audit
//! 5. Module 5: Evidence Correlation & Attribution Dossier Compilation

use chrono::Utc;
use ledger::PermissionedLedgerClient;
use pqcrypto::verify_event;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use watermark::WatermarkService;

use crate::backend::IntegrationError;
use crate::report::{ForensicEvidenceReport, ForensicVerdict};

/// Executes the full forensic verification pipeline on a candidate leaked document.
pub fn verify_leaked_document(
    leaked_document_bytes: &[u8],
    recipient_dsa_public_key: &[u8],
    ledger_client: &PermissionedLedgerClient,
) -> Result<ForensicEvidenceReport, IntegrationError> {
    let report_id = format!("FOR-DOSSIER-{}", &Uuid::new_v4().to_string()[..8].to_uppercase());
    let generated_at = Utc::now().to_rfc3339();

    // ── STEP 1: Extract Watermark Signals from Leaked PDF (Module 2) ────────
    let wm_extraction = match WatermarkService::extract_watermark(leaked_document_bytes) {
        Ok(ext) => ext,
        Err(_) => {
            // Document without recognizable watermark
            return Ok(ForensicEvidenceReport {
                report_id,
                generated_at,
                verdict: ForensicVerdict::UnattributedDocument,
                document_id: "UNKNOWN_DOCUMENT".into(),
                suspected_recipient_id: "UNATTRIBUTED".into(),
                session_id: "N/A".into(),
                watermark_extracted: false,
                watermark_id: "".into(),
                watermark_hash: "".into(),
                watermark_match: false,
                watermark_channel: "NONE".into(),
                watermark_confidence: 0.0,
                signature_algorithm: "ML-DSA-65".into(),
                signature_valid: false,
                public_key_fingerprint: "".into(),
                non_repudiation_confirmed: false,
                ledger_event_found: false,
                ledger_block_height: 0,
                ledger_block_hash: "".into(),
                merkle_proof_valid: false,
                chain_continuity_valid: false,
                captured_event: None,
            });
        }
    };

    let extracted_wm_id = wm_extraction.watermark_id.clone();
    let extracted_wm_hash = wm_extraction.watermark_hash.clone();
    let detected_channel = "MultiChannelExtraction".to_string();
    let confidence = wm_extraction.confidence_score;

    // ── STEP 2: Query Offline Ledger for Decryption Event (Module 4) ────────
    let ledger_event = ledger_client.find_by_watermark(&extracted_wm_hash)
        .or_else(|_| ledger_client.find_by_watermark(&extracted_wm_id));

    let event = match ledger_event {
        Ok(e) => e,
        Err(_) => {
            // Watermark found but not recorded in ledger
            return Ok(ForensicEvidenceReport {
                report_id,
                generated_at,
                verdict: ForensicVerdict::SuspiciousTamperingDetected,
                document_id: "UNKNOWN_UNINDEXED_DOC".into(),
                suspected_recipient_id: "UNKNOWN_RECIPIENT".into(),
                session_id: "UNKNOWN_SESSION".into(),
                watermark_extracted: true,
                watermark_id: extracted_wm_id,
                watermark_hash: extracted_wm_hash,
                watermark_match: false,
                watermark_channel: detected_channel,
                watermark_confidence: confidence,
                signature_algorithm: "ML-DSA-65".into(),
                signature_valid: false,
                public_key_fingerprint: "".into(),
                non_repudiation_confirmed: false,
                ledger_event_found: false,
                ledger_block_height: 0,
                ledger_block_hash: "".into(),
                merkle_proof_valid: false,
                chain_continuity_valid: false,
                captured_event: None,
            });
        }
    };

    let watermark_match = WatermarkService::verify_watermark(&extracted_wm_hash, &event.watermark_hash)
        .unwrap_or(false);

    // ── STEP 3: Cryptographically Verify ML-DSA-65 Signature (Module 3) ────
    let signature_valid = verify_event(&event, recipient_dsa_public_key).unwrap_or(false);
    let pk_fingerprint = hex::encode(Sha256::digest(recipient_dsa_public_key));

    // ── STEP 4: Cryptographically Audit Ledger & Merkle Proof (Module 4) ───
    let ledger_audit = ledger_client.verify_ledger_record(&event.event_id);
    let (ledger_valid, block_height, block_hash, merkle_valid) = match ledger_audit {
        Ok(res) => (res.is_valid, res.block_height, res.block_hash, res.merkle_valid),
        Err(_) => (false, 0, "".into(), false),
    };

    // ── STEP 5: Synthesize Final Attribution Verdict ─────────────────────────
    let is_confirmed = watermark_match && signature_valid && ledger_valid && merkle_valid;
    let verdict = if is_confirmed {
        ForensicVerdict::ConfirmedAttribution
    } else {
        ForensicVerdict::SuspiciousTamperingDetected
    };

    Ok(ForensicEvidenceReport {
        report_id,
        generated_at,
        verdict,
        document_id: event.document_id.clone(),
        suspected_recipient_id: event.recipient_id.clone(),
        session_id: event.session_id.clone(),
        watermark_extracted: true,
        watermark_id: extracted_wm_id,
        watermark_hash: extracted_wm_hash,
        watermark_match,
        watermark_channel: detected_channel,
        watermark_confidence: confidence,
        signature_algorithm: event.signature_algorithm.clone(),
        signature_valid,
        public_key_fingerprint: pk_fingerprint,
        non_repudiation_confirmed: signature_valid,
        ledger_event_found: true,
        ledger_block_height: block_height,
        ledger_block_hash: block_hash,
        merkle_proof_valid: merkle_valid,
        chain_continuity_valid: ledger_valid,
        captured_event: Some(event),
    })
}
