//! # Comprehensive Integration & Unit Tests for Member 3 (PQ Crypto)
//!
//! Covers:
//! - ML-DSA-65 key generation and identity binding
//! - Canonical JSON (RFC 8785) deterministic serialization
//! - Deterministic CBOR (RFC 8949) serialization
//! - Event creation with validation
//! - Event signing and signature verification
//! - Scenarios of VALID vs INVALID verification (tampering, wrong keys, corrupted signatures)

use pqcrypto::{
    create_event, generate_signing_keys, serialize_event, serialize_event_cbor, sign_event,
    verify_event, CreateEventParams, DefaultPqCryptoProvider, PqCryptoError, PqCryptoProvider,
    ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES, ML_DSA_65_SK_BYTES,
};

fn sample_params() -> CreateEventParams {
    CreateEventParams {
        document_id:    "doc-classified-quantum-v1".into(),
        recipient_id:   "officer.shukla@hq.defence.gov".into(),
        session_id:     "sess-airgap-99120".into(),
        watermark_id:   "wm-forensic-alpha-77".into(),
        watermark_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Key Generation & Identity Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_signing_keys_properties() {
    let recipient = "analyst.rao@secure.org";
    let keypair = generate_signing_keys(recipient).expect("keygen should succeed");

    assert_eq!(keypair.recipient_id, recipient);
    assert_eq!(keypair.public_key_bytes.len(), ML_DSA_65_PK_BYTES, "PK must be 1952 bytes");
    assert_eq!(keypair.secret_key_bytes.len(), ML_DSA_65_SK_BYTES, "SK must be 4032 bytes");
}

#[test]
fn test_keygen_randomness_and_uniqueness() {
    let kp1 = generate_signing_keys("agent@secure.gov").unwrap();
    let kp2 = generate_signing_keys("agent@secure.gov").unwrap();

    assert_ne!(kp1.public_key_bytes, kp2.public_key_bytes, "consecutive keys must be distinct");
    assert_ne!(kp1.secret_key_bytes, kp2.secret_key_bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Canonical Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_canonical_json_determinism() {
    let event = create_event(sample_params()).unwrap();
    let bytes1 = serialize_event(&event).unwrap();
    let bytes2 = serialize_event(&event).unwrap();

    assert_eq!(bytes1, bytes2, "serialization must be strictly deterministic across calls");
    
    // Check that keys are alphabetically sorted per RFC 8785
    let json_str = String::from_utf8(bytes1).unwrap();
    assert!(json_str.find("\"document_id\"").unwrap() < json_str.find("\"event_id\"").unwrap());
    assert!(json_str.find("\"event_id\"").unwrap() < json_str.find("\"recipient_id\"").unwrap());
}

#[test]
fn test_canonical_cbor_determinism() {
    let event = create_event(sample_params()).unwrap();
    let cbor1 = serialize_event_cbor(&event).unwrap();
    let cbor2 = serialize_event_cbor(&event).unwrap();

    assert_eq!(cbor1, cbor2, "CBOR serialization must be deterministic");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Full Lifecycle: Create -> Serialize -> Sign -> Verify (VALID SCENARIO)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_lifecycle_valid_event_verification() {
    let keypair = generate_signing_keys("officer.shukla@hq.defence.gov").unwrap();
    
    // Step 1: Create event
    let unsigned_event = create_event(sample_params()).unwrap();
    
    // Step 2: Sign event
    let signed_event = sign_event(unsigned_event, &keypair.secret_key_bytes).unwrap();
    
    // Validate signature format
    let decoded_sig = hex::decode(&signed_event.signature).expect("signature must be valid hex");
    assert_eq!(decoded_sig.len(), ML_DSA_65_SIG_BYTES, "signature must be 3293 bytes");
    
    // Step 3: Verify event
    let is_valid = verify_event(&signed_event, &keypair.public_key_bytes).unwrap();
    assert!(is_valid, "VALID SCENARIO: authentic signature must verify as true");
}

#[test]
fn test_provider_trait_lifecycle() {
    let provider = DefaultPqCryptoProvider;
    let keypair = generate_signing_keys("officer.shukla@hq.defence.gov").unwrap();

    let unsigned = provider.create_event(sample_params()).unwrap();
    let _canonical_bytes = provider.serialize_event(&unsigned).unwrap();
    let signed = provider.sign_event(unsigned, &keypair.secret_key_bytes).unwrap();
    let is_valid = provider.verify_event(&signed, &keypair.public_key_bytes).unwrap();

    assert!(is_valid, "Trait implementation must verify authentic event");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. INVALID VERIFICATION SCENARIOS (Tamper Detection & Non-Repudiation)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invalid_verification_tampered_document_id() {
    let keypair = generate_signing_keys("recipient@test.gov").unwrap();
    let unsigned = create_event(sample_params()).unwrap();
    let mut signed = sign_event(unsigned, &keypair.secret_key_bytes).unwrap();

    // Adversary changes the target document ID
    signed.document_id = "doc-tampered-leak-999".into();

    let is_valid = verify_event(&signed, &keypair.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: tampered document_id must fail verification");
}

#[test]
fn test_invalid_verification_tampered_recipient_id() {
    let keypair = generate_signing_keys("recipient@test.gov").unwrap();
    let unsigned = create_event(sample_params()).unwrap();
    let mut signed = sign_event(unsigned, &keypair.secret_key_bytes).unwrap();

    // Adversary attempts to attribute decryption to an innocent third party
    signed.recipient_id = "innocent.user@defence.gov".into();

    let is_valid = verify_event(&signed, &keypair.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: tampered recipient_id must fail verification");
}

#[test]
fn test_invalid_verification_tampered_watermark_hash() {
    let keypair = generate_signing_keys("recipient@test.gov").unwrap();
    let unsigned = create_event(sample_params()).unwrap();
    let mut signed = sign_event(unsigned, &keypair.secret_key_bytes).unwrap();

    // Watermark fingerprint altered
    signed.watermark_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();

    let is_valid = verify_event(&signed, &keypair.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: tampered watermark_hash must fail verification");
}

#[test]
fn test_invalid_verification_tampered_timestamp() {
    let keypair = generate_signing_keys("recipient@test.gov").unwrap();
    let unsigned = create_event(sample_params()).unwrap();
    let mut signed = sign_event(unsigned, &keypair.secret_key_bytes).unwrap();

    // Alter event timestamp to forge timeline
    signed.timestamp = "1970-01-01T00:00:00Z".into();

    let is_valid = verify_event(&signed, &keypair.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: altered timestamp must fail verification");
}

#[test]
fn test_invalid_verification_wrong_recipient_public_key() {
    let keypair_alice = generate_signing_keys("alice@secure.gov").unwrap();
    let keypair_bob = generate_signing_keys("bob@secure.gov").unwrap();

    let unsigned = create_event(sample_params()).unwrap();
    // Signed by Alice
    let signed_by_alice = sign_event(unsigned, &keypair_alice.secret_key_bytes).unwrap();

    // Verification attempted with Bob's public key
    let is_valid = verify_event(&signed_by_alice, &keypair_bob.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: verifying Alice's signature with Bob's PK must fail");
}

#[test]
fn test_invalid_verification_corrupted_signature_payload() {
    let keypair = generate_signing_keys("recipient@test.gov").unwrap();
    let unsigned = create_event(sample_params()).unwrap();
    let mut signed = sign_event(unsigned, &keypair.secret_key_bytes).unwrap();

    // Bit-flip inside hex signature
    let mut hex_chars: Vec<char> = signed.signature.chars().collect();
    hex_chars[100] = if hex_chars[100] == 'a' { 'b' } else { 'a' };
    signed.signature = hex_chars.into_iter().collect();

    let is_valid = verify_event(&signed, &keypair.public_key_bytes).unwrap();
    assert!(!is_valid, "INVALID SCENARIO: modified signature payload must fail verification");
}

#[test]
fn test_invalid_schema_validation_errors() {
    let mut bad_params = sample_params();
    bad_params.document_id = "   ".into(); // blank field

    let err = create_event(bad_params);
    assert!(matches!(err, Err(PqCryptoError::InvalidEventSchema(_))));
}
