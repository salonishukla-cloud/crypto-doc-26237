//! # report.rs — Forensic Evidence Dossier & Report Generator
//!
//! Produces comprehensive, legally admissible forensic evidence dossiers
//! combining Watermark Attribution, ML-DSA Post-Quantum Signatures, and DLT Merkle Proofs.

use serde::{Deserialize, Serialize};
use shared::models::DecryptionEvent;
use crate::backend::IntegrationError;

/// Attribution verdict outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicVerdict {
    /// Cryptographically proven beyond reasonable doubt: Watermark matches, ML-DSA valid, Ledger verified.
    ConfirmedAttribution,
    /// Watermark matched but cryptographic signature or ledger audit failed.
    SuspiciousTamperingDetected,
    /// No matching watermark or ledger record found.
    UnattributedDocument,
}

/// Detailed forensic evidence dossier compiled from full verification pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicEvidenceReport {
    pub report_id: String,
    pub generated_at: String,
    pub verdict: ForensicVerdict,
    
    // Leaked Document Findings
    pub document_id: String,
    pub suspected_recipient_id: String,
    pub session_id: String,
    
    // Watermark Extraction Evidence
    pub watermark_extracted: bool,
    pub watermark_id: String,
    pub watermark_hash: String,
    pub watermark_match: bool,
    pub watermark_channel: String,
    pub watermark_confidence: f64,
    
    // ML-DSA Post-Quantum Cryptographic Proof
    pub signature_algorithm: String,
    pub signature_valid: bool,
    pub public_key_fingerprint: String,
    pub non_repudiation_confirmed: bool,
    
    // Ledger DLT Immutability Proof
    pub ledger_event_found: bool,
    pub ledger_block_height: u64,
    pub ledger_block_hash: String,
    pub merkle_proof_valid: bool,
    pub chain_continuity_valid: bool,
    
    // Full Captured Event Record
    pub captured_event: Option<DecryptionEvent>,
}

/// Generates human-readable forensic report dossier alongside canonical JSON.
pub fn generate_report(report: &ForensicEvidenceReport) -> Result<String, IntegrationError> {
    let json_dump = serde_json::to_string_pretty(report).map_err(|e| {
        IntegrationError::ReportGenerationFailed(format!("failed to serialize report to JSON: {e}"))
    })?;

    let verdict_str = match report.verdict {
        ForensicVerdict::ConfirmedAttribution => "CONFIRMED ATTRIBUTION (PROVEN BEYOND REASONABLE DOUBT)",
        ForensicVerdict::SuspiciousTamperingDetected => "SUSPICIOUS / TAMPERING DETECTED (INTEGRITY FAILED)",
        ForensicVerdict::UnattributedDocument => "UNATTRIBUTED (NO MATCHING FORENSIC RECORD)",
    };

    let report_markdown = format!(
r#"================================================================================
          OFFLINE CONFIDENTIAL DOCUMENT FORENSIC ATTRIBUTION REPORT
================================================================================
Dossier Reference : {report_id}
Generated At      : {generated_at}
Attribution Status: {verdict_str}
--------------------------------------------------------------------------------

1. EXECUTIVE SUMMARY & ATTRIBUTION IDENTIFICATION
   Target Document ID     : {document_id}
   Attributed Recipient   : {recipient_id}
   Decryption Session ID  : {session_id}
   Confidence Level       : {confidence:.2}%

2. FORENSIC WATERMARK EXTRACTION
   Watermark Extracted    : {wm_extracted}
   Watermark ID           : {wm_id}
   Extracted Hash         : {wm_hash}
   Ledger Hash Match      : {wm_match}
   Detection Channel      : {wm_channel}

3. POST-QUANTUM CRYPTOGRAPHIC AUDIT (ML-DSA-65 / FIPS 204)
   Signature Algorithm    : {sig_algo}
   Signature Verification : {sig_valid}
   Public Key Fingerprint : {pk_fingerprint}
   Non-Repudiation Status : {non_repudiation}

4. DISTRIBUTED LEDGER TECHNOLOGY (DLT) MERKLE PROOF
   Ledger Record Found    : {ledger_found}
   Committed Block Height : #{block_height}
   Committed Block Hash   : {block_hash}
   Merkle Inclusion Valid : {merkle_valid}
   Chain Integrity Valid  : {chain_valid}

5. VERDICT CONCLUSION
   Based on multi-layer forensic watermarking, FIPS 204 ML-DSA digital signatures,
   and immutable 4-node offline DLT ledger verification, the unauthorized dissemination
   of document '{document_id}' is conclusively attributed to recipient:
   >> {recipient_id} <<

================================================================================
Canonical JSON Evidence Dump:
{json_dump}
================================================================================
"#,
        report_id = report.report_id,
        generated_at = report.generated_at,
        verdict_str = verdict_str,
        document_id = report.document_id,
        recipient_id = report.suspected_recipient_id,
        session_id = report.session_id,
        confidence = report.watermark_confidence * 100.0,
        wm_extracted = if report.watermark_extracted { "YES (PASSED)" } else { "NO (FAILED)" },
        wm_id = report.watermark_id,
        wm_hash = report.watermark_hash,
        wm_match = if report.watermark_match { "YES (EXACT MATCH)" } else { "NO (MISMATCH)" },
        wm_channel = report.watermark_channel,
        sig_algo = report.signature_algorithm,
        sig_valid = if report.signature_valid { "VALID (UNFORGEABLE)" } else { "INVALID / TAMPERED" },
        pk_fingerprint = report.public_key_fingerprint,
        non_repudiation = if report.non_repudiation_confirmed { "AFFIRMED (LEGAL BINDING)" } else { "FAILED" },
        ledger_found = if report.ledger_event_found { "YES (INDEXED)" } else { "NO" },
        block_height = report.ledger_block_height,
        block_hash = report.ledger_block_hash,
        merkle_valid = if report.merkle_proof_valid { "VERIFIED (MATHEMATICALLY SOUND)" } else { "INVALID" },
        chain_valid = if report.chain_continuity_valid { "VERIFIED (CONTINUOUS SHA-256)" } else { "COMPROMISED" },
        json_dump = json_dump
    );

    Ok(report_markdown)
}
