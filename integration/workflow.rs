//! # workflow.rs — Decryption & Provenance Pipeline Orchestrator
//!
//! Connects:
//! 1. Module 1: ML-KEM Post-Quantum Key Encapsulation + AES-256-GCM Decryption
//! 2. Module 2: Multi-Layer Invisible Forensic Watermarking
//! 3. Module 3: ML-DSA-65 Post-Quantum Event Signing
//! 4. Module 4: 4-Node Permissioned Offline Ledger Ingestion

use encryption::{decrypt_document, DecryptionRequest, EncryptedDocumentPackage};
use ledger::{LedgerReceipt, PermissionedLedgerClient};
use pqcrypto::{create_event, sign_event, CreateEventParams};
use serde::{Deserialize, Serialize};
use shared::models::DecryptionEvent;
use watermark::{CreateWatermarkParams, EmbedWatermarkParams, WatermarkService};

use crate::backend::IntegrationError;

/// Input parameters for recipient document decryption workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionWorkflowRequest {
    pub encrypted_package: EncryptedDocumentPackage,
    pub recipient_id: String,
    pub recipient_kem_secret_key: Vec<u8>,
    pub recipient_dsa_secret_key: Vec<u8>,
    pub recipient_session_id: String,
}

/// Output payload from recipient document decryption workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionWorkflowResult {
    pub document_id: String,
    pub recipient_id: String,
    pub watermarked_pdf_bytes: Vec<u8>,
    pub decryption_event: DecryptionEvent,
    pub ledger_receipt: LedgerReceipt,
    pub watermark_hash: String,
}

/// Orchestrates the full recipient document decryption pipeline.
pub fn run_decryption_workflow(
    request: DecryptionWorkflowRequest,
    ledger_client: &PermissionedLedgerClient,
) -> Result<DecryptionWorkflowResult, IntegrationError> {
    let document_id = request.encrypted_package.document_id.clone();
    let recipient_id = request.recipient_id.clone();
    let session_id = request.recipient_session_id.clone();

    // ── STEP 1: Decrypt Document Payload (AES-256-GCM + ML-KEM) ─────────────
    let decrypt_req = DecryptionRequest {
        package: request.encrypted_package,
        recipient_id: recipient_id.clone(),
        recipient_kem_secret_key: request.recipient_kem_secret_key,
    };

    let decrypt_res = decrypt_document(decrypt_req).map_err(|e| {
        IntegrationError::DecryptionFailed(format!("Module 1 Decryption error: {e:?}"))
    })?;

    let plaintext_pdf_bytes = decrypt_res.plaintext_bytes;

    // ── STEP 2: Generate Forensic Watermark (Module 2) ──────────────────────
    let wm_params = CreateWatermarkParams {
        document_id: document_id.clone(),
        recipient_id: recipient_id.clone(),
        session_id: session_id.clone(),
        strength_factor: 1.0,
    };

    let wm_payload = WatermarkService::create_watermark(wm_params).map_err(|e| {
        IntegrationError::WatermarkGenerationFailed(format!("Module 2 Watermark error: {e:?}"))
    })?;

    let watermark_id = wm_payload.metadata.watermark_id.clone();
    let watermark_hash = wm_payload.metadata.watermark_hash.clone();

    // ── STEP 3: Embed Multi-Layer Watermark into PDF (Module 2) ─────────────
    let embed_params = EmbedWatermarkParams {
        original_pdf_bytes: plaintext_pdf_bytes,
        watermark: wm_payload,
    };

    let watermarked_pdf = WatermarkService::embed_watermark(embed_params).map_err(|e| {
        IntegrationError::WatermarkEmbeddingFailed(format!("Module 2 Embedding error: {e:?}"))
    })?;

    // ── STEP 4: Construct Unsigned Decryption Event (Module 3) ──────────────
    let event_params = CreateEventParams {
        document_id: document_id.clone(),
        recipient_id: recipient_id.clone(),
        session_id: session_id.clone(),
        watermark_id: watermark_id.clone(),
        watermark_hash: watermark_hash.clone(),
    };

    let unsigned_event = create_event(event_params).map_err(|e| {
        IntegrationError::EventSigningFailed(format!("Module 3 Event creation error: {e:?}"))
    })?;

    // ── STEP 5: Sign Event with ML-DSA-65 (Module 3) ────────────────────────
    let signed_event = sign_event(unsigned_event, &request.recipient_dsa_secret_key).map_err(|e| {
        IntegrationError::EventSigningFailed(format!("Module 3 Signing error: {e:?}"))
    })?;

    // ── STEP 6: Submit to Offline DLT Ledger (Module 4) ──────────────────────
    let receipt = ledger_client.submit_event(signed_event.clone()).map_err(|e| {
        IntegrationError::LedgerSubmissionFailed(format!("Module 4 Ledger ingestion error: {e:?}"))
    })?;

    // ── STEP 7: Return Provenance-Tracked Watermarked Document ───────────────
    Ok(DecryptionWorkflowResult {
        document_id,
        recipient_id,
        watermarked_pdf_bytes: watermarked_pdf,
        decryption_event: signed_event,
        ledger_receipt: receipt,
        watermark_hash,
    })
}
