//! Comprehensive Unit and Security Tests for Module 1 (Encryption & Key Management).

use ::encryption::*;
use std::fs;

#[test]
fn test_generate_recipient_keys_structure() {
    let keypair = generate_recipient_keys("RECIPIENT-ALICE").expect("Key generation should succeed");

    assert_eq!(keypair.recipient_id, "RECIPIENT-ALICE");
    assert_eq!(keypair.version, 1);
    assert_eq!(keypair.algorithm, "ML-KEM-768");
    assert_eq!(keypair.public_key_bytes.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    assert_eq!(keypair.secret_key_bytes.len(), ML_KEM_768_SECRET_KEY_SIZE);

    let descriptor = keypair.to_descriptor();
    assert_eq!(descriptor.recipient_id, "RECIPIENT-ALICE");
    assert_eq!(descriptor.version, 1);
    assert_eq!(descriptor.public_key_hex.len(), ML_KEM_768_PUBLIC_KEY_SIZE * 2);
}

#[test]
fn test_key_rotation_and_versioning() {
    let key_v1 = generate_recipient_keys_with_version("RECIPIENT-BOB", 1).unwrap();
    let key_v2 = generate_recipient_keys_with_version("RECIPIENT-BOB", 2).unwrap();

    assert_eq!(key_v1.version, 1);
    assert_eq!(key_v2.version, 2);
    assert_ne!(key_v1.public_key_bytes, key_v2.public_key_bytes);
}

#[test]
fn test_key_file_save_and_load_roundtrip() {
    let temp_dir = std::env::temp_dir().join("crypto_doc_test_keys");
    let key_path = temp_dir.join("alice_key.json");

    let keypair = generate_recipient_keys("RECIPIENT-ALICE").unwrap();
    keypair.save_to_file(&key_path).expect("Key save should succeed");

    let loaded = load_key_pair(&key_path).expect("Key load should succeed");
    assert_eq!(loaded.recipient_id, keypair.recipient_id);
    assert_eq!(loaded.key_id, keypair.key_id);
    assert_eq!(loaded.version, keypair.version);
    assert_eq!(loaded.public_key_bytes, keypair.public_key_bytes);
    assert_eq!(*loaded.secret_key_bytes, *keypair.secret_key_bytes);

    let _ = fs::remove_file(key_path);
    let _ = fs::remove_dir(temp_dir);
}

#[test]
fn test_encrypt_and_decrypt_single_recipient() {
    let alice = generate_recipient_keys("RECIPIENT-ALICE").unwrap();
    let original_pdf = b"%PDF-1.7 Confidential Intelligence Briefing Alpha...".to_vec();

    let request = EncryptionRequest {
        document_id: "DOC-2026-ALPHA-01".to_string(),
        title: "Confidential Intelligence Briefing".to_string(),
        plaintext_bytes: original_pdf.clone(),
        recipients: vec![RecipientKeyInput {
            recipient_id: alice.recipient_id.clone(),
            public_key_bytes: alice.public_key_bytes.clone(),
        }],
    };

    let package = encrypt_document(request).expect("Encryption must succeed");

    assert_eq!(package.document_id, "DOC-2026-ALPHA-01");
    assert_eq!(package.recipient_envelopes.len(), 1);
    assert_eq!(package.recipient_envelopes[0].recipient_id, "RECIPIENT-ALICE");
    assert_eq!(package.magic, "CRPTDOC1");

    // Decrypt
    let dec_req = DecryptionRequest {
        package,
        recipient_id: "RECIPIENT-ALICE".to_string(),
        recipient_kem_secret_key: alice.secret_key_bytes.to_vec(),
    };

    let result = decrypt_document(dec_req).expect("Decryption must succeed");
    assert_eq!(result.document_id, "DOC-2026-ALPHA-01");
    assert_eq!(result.plaintext_bytes, original_pdf);
    assert!(result.session_id.starts_with("SES-"));
}

#[test]
fn test_multi_recipient_encryption_broadcast() {
    let alice = generate_recipient_keys("RECIPIENT-ALICE").unwrap();
    let bob = generate_recipient_keys("RECIPIENT-BOB").unwrap();
    let charlie = generate_recipient_keys("RECIPIENT-CHARLIE").unwrap();

    let confidential_pdf = b"%PDF-2.0 Strictly Confidential Strategic Roadmap".to_vec();

    let request = EncryptionRequest {
        document_id: "DOC-STRATEGY-2026".to_string(),
        title: "Joint Strategy Document".to_string(),
        plaintext_bytes: confidential_pdf.clone(),
        recipients: vec![
            RecipientKeyInput {
                recipient_id: alice.recipient_id.clone(),
                public_key_bytes: alice.public_key_bytes.clone(),
            },
            RecipientKeyInput {
                recipient_id: bob.recipient_id.clone(),
                public_key_bytes: bob.public_key_bytes.clone(),
            },
            RecipientKeyInput {
                recipient_id: charlie.recipient_id.clone(),
                public_key_bytes: charlie.public_key_bytes.clone(),
            },
        ],
    };

    let package = encrypt_document(request).unwrap();
    assert_eq!(package.recipient_envelopes.len(), 3);

    // Each recipient should decrypt the identical document
    for recipient in [&alice, &bob, &charlie] {
        let dec_req = DecryptionRequest {
            package: package.clone(),
            recipient_id: recipient.recipient_id.clone(),
            recipient_kem_secret_key: recipient.secret_key_bytes.to_vec(),
        };

        let result = decrypt_document(dec_req)
            .unwrap_or_else(|e| panic!("Failed to decrypt for {}: {:?}", recipient.recipient_id, e));

        assert_eq!(result.plaintext_bytes, confidential_pdf);
        assert_eq!(result.document_id, "DOC-STRATEGY-2026");
    }
}

#[test]
fn test_unauthorized_recipient_rejection() {
    let alice = generate_recipient_keys("RECIPIENT-ALICE").unwrap();
    let eve = generate_recipient_keys("RECIPIENT-EVE").unwrap();

    let request = EncryptionRequest {
        document_id: "DOC-SECRET-01".to_string(),
        title: "Secret".to_string(),
        plaintext_bytes: b"Top Secret Plaintext".to_vec(),
        recipients: vec![RecipientKeyInput {
            recipient_id: alice.recipient_id.clone(),
            public_key_bytes: alice.public_key_bytes.clone(),
        }],
    };

    let package = encrypt_document(request).unwrap();

    // Eve attempts decryption
    let dec_req = DecryptionRequest {
        package,
        recipient_id: eve.recipient_id.clone(),
        recipient_kem_secret_key: eve.secret_key_bytes.to_vec(),
    };

    let err = decrypt_document(dec_req).unwrap_err();
    match err {
        EncryptionError::RecipientNotAuthorized(id) => assert_eq!(id, "RECIPIENT-EVE"),
        other => panic!("Expected RecipientNotAuthorized, got: {:?}", other),
    }
}

#[test]
fn test_tampered_ciphertext_rejection() {
    let alice = generate_recipient_keys("RECIPIENT-ALICE").unwrap();

    let request = EncryptionRequest {
        document_id: "DOC-AUTHENTICITY-TEST".to_string(),
        title: "Test".to_string(),
        plaintext_bytes: b"Guaranteed Authenticity Test".to_vec(),
        recipients: vec![RecipientKeyInput {
            recipient_id: alice.recipient_id.clone(),
            public_key_bytes: alice.public_key_bytes.clone(),
        }],
    };

    let mut package = encrypt_document(request).unwrap();

    // Flip 1 character in ciphertext hex
    let mut chars: Vec<char> = package.ciphertext.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    package.ciphertext = chars.into_iter().collect();

    let dec_req = DecryptionRequest {
        package,
        recipient_id: alice.recipient_id.clone(),
        recipient_kem_secret_key: alice.secret_key_bytes.to_vec(),
    };

    let err = decrypt_document(dec_req).unwrap_err();
    match err {
        EncryptionError::DecryptionAuthenticationFailed => (),
        other => panic!("Expected DecryptionAuthenticationFailed, got: {:?}", other),
    }
}

#[test]
fn test_tampered_document_id_aad_rejection() {
    let alice = generate_recipient_keys("RECIPIENT-ALICE").unwrap();

    let request = EncryptionRequest {
        document_id: "DOC-ORIGINAL-ID".to_string(),
        title: "Test".to_string(),
        plaintext_bytes: b"AAD Integrity Protection".to_vec(),
        recipients: vec![RecipientKeyInput {
            recipient_id: alice.recipient_id.clone(),
            public_key_bytes: alice.public_key_bytes.clone(),
        }],
    };

    let mut package = encrypt_document(request).unwrap();

    // Modify document_id in package metadata (attempted substitution attack)
    package.document_id = "DOC-SUBSTITUTED-ID".to_string();

    let dec_req = DecryptionRequest {
        package,
        recipient_id: alice.recipient_id.clone(),
        recipient_kem_secret_key: alice.secret_key_bytes.to_vec(),
    };

    let err = decrypt_document(dec_req).unwrap_err();
    match err {
        EncryptionError::DecryptionAuthenticationFailed => (),
        other => panic!("Expected DecryptionAuthenticationFailed, got: {:?}", other),
    }
}
