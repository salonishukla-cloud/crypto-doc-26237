//! # End-to-End System Integration Test Suite
//!
//! Validates the complete 5-stage platform lifecycle:
//! 1. Module 1: Document Packaging with ML-KEM-768 + AES-256-GCM
//! 2. Module 2: Invisible Multi-Layer Forensic Watermark Embedding
//! 3. Module 3: ML-DSA-65 Post-Quantum Event Signing
//! 4. Module 4: 4-Node Permissioned Offline Ledger Ingestion & Merkle Tree
//! 5. Module 5: Leaked Document Forensic Attribution & Evidence Dossier Generation

use encryption::{
    encrypt_document, generate_recipient_keys, EncryptionRequest, RecipientKeyInput,
};
use integration::{
    generate_report, run_decryption_workflow, verify_leaked_document, DecryptionWorkflowRequest,
    ForensicVerdict,
};
use ledger::PermissionedLedgerClient;
use pqcrypto::generate_signing_keys;

#[test]
fn test_full_system_e2e_lifecycle() {
    let recipient_id = "officer.shukla@hq.defence.gov";

    // ── STAGE 1: Key Generation (KEM for encryption, DSA for signatures) ──
    let kem_keys = generate_recipient_keys(recipient_id).expect("KEM key generation failed");
    let dsa_keys = generate_signing_keys(recipient_id).expect("DSA key generation failed");

    // ── STAGE 2: Sender Packaging (Module 1) ────────────────────────────────
    let sample_pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF".to_vec();

    let enc_req = EncryptionRequest {
        document_id: "DOC-CONFIDENTIAL-DEFENCE-001".into(),
        title: "Top Secret Strategy Briefing".into(),
        plaintext_bytes: sample_pdf_content,
        recipients: vec![RecipientKeyInput {
            recipient_id: recipient_id.into(),
            public_key_bytes: kem_keys.public_key_bytes,
        }],
    };

    let encrypted_package = encrypt_document(enc_req).expect("Document encryption failed");
    assert_eq!(encrypted_package.document_id, "DOC-CONFIDENTIAL-DEFENCE-001");

    // ── STAGE 3: Recipient Decryption & Provenance Workflow (Integration) ───
    let ledger_client = PermissionedLedgerClient::new("node-1");

    let decrypt_workflow_req = DecryptionWorkflowRequest {
        encrypted_package,
        recipient_id: recipient_id.into(),
        recipient_kem_secret_key: kem_keys.secret_key_bytes.to_vec(),
        recipient_dsa_secret_key: dsa_keys.secret_key_bytes,
        recipient_session_id: "SESS-AIRGAP-8891".into(),
    };

    let workflow_res = run_decryption_workflow(decrypt_workflow_req, &ledger_client)
        .expect("Decryption workflow failed");

    assert!(!workflow_res.watermarked_pdf_bytes.is_empty());
    assert_eq!(workflow_res.decryption_event.recipient_id, recipient_id);
    assert_eq!(workflow_res.ledger_receipt.block_height, 1);

    // ── STAGE 4: Leak Simulation & Forensic Attribution (Verification) ──────
    let leaked_pdf_bytes = workflow_res.watermarked_pdf_bytes;

    let forensic_report = verify_leaked_document(
        &leaked_pdf_bytes,
        &dsa_keys.public_key_bytes,
        &ledger_client,
    ).expect("Forensic verification failed");

    // ── STAGE 5: Assert Forensic Attribution Truth ──────────────────────────
    assert_eq!(forensic_report.verdict, ForensicVerdict::ConfirmedAttribution);
    assert_eq!(forensic_report.suspected_recipient_id, recipient_id);
    assert!(forensic_report.watermark_extracted);
    assert!(forensic_report.watermark_match);
    assert!(forensic_report.signature_valid);
    assert!(forensic_report.merkle_proof_valid);
    assert!(forensic_report.chain_continuity_valid);

    // ── STAGE 6: Generate Legal Dossier ─────────────────────────────────────
    let report_markdown = generate_report(&forensic_report).expect("Report generation failed");
    assert!(report_markdown.contains("CONFIRMED ATTRIBUTION"));
    assert!(report_markdown.contains(recipient_id));
    assert!(report_markdown.contains("ML-DSA-65"));
}

#[test]
fn test_unwatermarked_document_attribution_failure() {
    let unwatermarked_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF".to_vec();
    let ledger_client = PermissionedLedgerClient::new("node-1");
    let dsa_keys = generate_signing_keys("alice@gov.in").unwrap();

    let report = verify_leaked_document(
        &unwatermarked_pdf,
        &dsa_keys.public_key_bytes,
        &ledger_client,
    ).unwrap();

    assert_eq!(report.verdict, ForensicVerdict::UnattributedDocument);
    assert!(!report.watermark_extracted);
}
