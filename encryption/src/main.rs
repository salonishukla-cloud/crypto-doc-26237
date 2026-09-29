//! Command-Line Demonstration Runner for Member 1 (Encryption & Key Management).
//!
//! Run with: `cargo run` (inside encryption/) or `cargo run -p encryption` (from workspace root)

use ::encryption::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("🔐 SIH 2026: Cryptographic Attribution & Immutable Decryption Provenance");
    println!("   Module 1: Secure Document Encryption & Key Management (Member 1)");
    println!("================================================================================\n");

    // 1. Generate Post-Quantum ML-KEM-768 keypairs for authorized recipients
    println!("[1/5] Generating Post-Quantum ML-KEM-768 keypairs for authorized recipients...");
    let alice_keys = generate_recipient_keys("RECIPIENT-ALICE-DELTA")?;
    let bob_keys = generate_recipient_keys("RECIPIENT-BOB-SIGMA")?;

    println!("      ✓ Alice Public Key Fingerprint: {}", alice_keys.public_key_fingerprint());
    println!("      ✓ Alice Public Key Size:        {} bytes (FIPS 203)", alice_keys.public_key_bytes.len());
    println!("      ✓ Alice Secret Key Size:        {} bytes (Zeroized in RAM)", alice_keys.secret_key_bytes.len());
    println!("      ✓ Bob Public Key Fingerprint:   {}", bob_keys.public_key_fingerprint());

    // 2. Prepare sample confidential PDF document
    let sample_document_id = "DOC-CONFIDENTIAL-2026-X409";
    let sample_title = "Joint Defense Post-Quantum Operational Protocol";
    let sample_pdf_content = b"%PDF-1.7\n% Confidential Briefing for SIH 2026.\nClassified Document Payload...";

    println!("\n[2/5] Encrypting Document via AES-256-GCM and Encapsulating DEK via ML-KEM-768...");
    let encryption_req = EncryptionRequest {
        document_id: sample_document_id.to_string(),
        title: sample_title.to_string(),
        plaintext_bytes: sample_pdf_content.to_vec(),
        recipients: vec![
            RecipientKeyInput {
                recipient_id: alice_keys.recipient_id.clone(),
                public_key_bytes: alice_keys.public_key_bytes.clone(),
            },
            RecipientKeyInput {
                recipient_id: bob_keys.recipient_id.clone(),
                public_key_bytes: bob_keys.public_key_bytes.clone(),
            },
        ],
    };

    let package = encrypt_document(encryption_req)?;

    println!("      ✓ Document Package Magic:       {}", package.magic);
    println!("      ✓ Format Version:               v{}", package.version);
    println!("      ✓ Document ID (AAD Bound):      {}", package.document_id);
    println!("      ✓ AES-256-GCM Nonce (96-bit):   {}", package.nonce);
    println!("      ✓ Auth Tag (128-bit):           {}", package.auth_tag);
    println!("      ✓ Ciphertext Byte Length:       {} bytes", hex::decode(&package.ciphertext)?.len());
    println!("      ✓ Authorized Envelopes Count:   {}", package.recipient_envelopes.len());

    for (i, env) in package.recipient_envelopes.iter().enumerate() {
        println!("        - Envelope [{}]: Recipient '{}'", i + 1, env.recipient_id);
        println!("          Encapsulated Ciphertext: {} bytes", hex::decode(&env.encapsulated_key)?.len());
        println!("          Wrapped DEK Length:      {} bytes", hex::decode(&env.wrapped_dek)?.len());
    }

    // 3. Decrypt for Alice
    println!("\n[3/5] Testing Recipient Decryption for Alice...");
    let alice_dec_req = DecryptionRequest {
        package: package.clone(),
        recipient_id: alice_keys.recipient_id.clone(),
        recipient_kem_secret_key: alice_keys.secret_key_bytes.to_vec(),
    };

    let alice_result = decrypt_document(alice_dec_req)?;
    println!("      ✓ Decryption & Authentication:  SUCCESS");
    println!("      ✓ Recovered Document ID:        {}", alice_result.document_id);
    println!("      ✓ Established Session ID:       {}", alice_result.session_id);
    println!("      ✓ Decrypted Payload Match:      {}", alice_result.plaintext_bytes == sample_pdf_content);

    // 4. Test unauthorized decryption rejection (Eve)
    println!("\n[4/5] Testing Security Invariant: Unauthorized Recipient (Eve)...");
    let eve_keys = generate_recipient_keys("RECIPIENT-EVE-ATTACKER")?;
    let eve_dec_req = DecryptionRequest {
        package: package.clone(),
        recipient_id: eve_keys.recipient_id.clone(),
        recipient_kem_secret_key: eve_keys.secret_key_bytes.to_vec(),
    };

    match decrypt_document(eve_dec_req) {
        Err(EncryptionError::RecipientNotAuthorized(id)) => {
            println!("      ✓ Correctly Rejected: Recipient '{}' not authorized in package envelopes.", id);
        }
        Ok(_) => panic!("SECURITY VIOLATION: Unauthorized recipient decrypted the document!"),
        Err(e) => println!("      ✓ Rejected with expected error: {:?}", e),
    }

    // 5. Test ciphertext tampering detection
    println!("\n[5/5] Testing Security Invariant: Ciphertext Tamper Detection...");
    let mut tampered_package = package.clone();
    let mut chars: Vec<char> = tampered_package.ciphertext.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    tampered_package.ciphertext = chars.into_iter().collect();

    let tamper_req = DecryptionRequest {
        package: tampered_package,
        recipient_id: alice_keys.recipient_id.clone(),
        recipient_kem_secret_key: alice_keys.secret_key_bytes.to_vec(),
    };

    match decrypt_document(tamper_req) {
        Err(EncryptionError::DecryptionAuthenticationFailed) => {
            println!("      ✓ Correctly Rejected: 1-bit tampering caught by AES-256-GCM authentication tag.");
        }
        Ok(_) => panic!("SECURITY VIOLATION: Tampered document decrypted without authentication!"),
        Err(e) => println!("      ✓ Rejected with expected error: {:?}", e),
    }

    println!("\n================================================================================");
    println!("🎉 All Encryption, ML-KEM Key Encapsulation, & Decryption Checks PASSED!");
    println!("================================================================================\n");

    Ok(())
}
