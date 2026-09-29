//! # Comprehensive Test Suite for Member 4 (Distributed Ledger)
//!
//! Covers:
//! - Cryptographic Block Chaining (Genesis -> Block 1 -> Block 2)
//! - Merkle Tree construction & inclusion proof verification
//! - Event submission & duplicate rejection
//! - Fast reverse lookup by watermark_id and watermark_hash
//! - 4-node local permissioned cluster replication and quorum consensus
//! - Offline sneakernet sync package export and import
//! - Cryptographic audit and tamper detection

use ledger::{
    hash_event, LedgerError, LocalFourNodeCluster, MerkleTree, PermissionedLedgerClient,
};
use shared::models::DecryptionEvent;

fn sample_event(id: &str, watermark_id: &str, watermark_hash: &str) -> DecryptionEvent {
    DecryptionEvent {
        event_id: id.to_string(),
        document_id: "doc-classified-dlt-01".to_string(),
        recipient_id: "officer.shukla@hq.defence.gov".to_string(),
        session_id: "sess-airgap-991".to_string(),
        watermark_id: watermark_id.to_string(),
        timestamp: "2026-09-29T12:00:00Z".to_string(),
        watermark_hash: watermark_hash.to_string(),
        signature_algorithm: "ML-DSA-65".to_string(),
        signature: "deadbeefcafebabe".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Single Node Block Chaining & Merkle Verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_genesis_block_and_chaining() {
    let client = PermissionedLedgerClient::new("node-1");
    assert_eq!(client.store().current_height(), 0, "initial height is 0 (genesis)");

    let event1 = sample_event("evt-001", "wm-001", "hash-001");
    let receipt1 = client.submit_event(event1).expect("event 1 should submit");
    assert_eq!(receipt1.block_height, 1);
    assert_eq!(client.store().current_height(), 1);

    let event2 = sample_event("evt-002", "wm-002", "hash-002");
    let receipt2 = client.submit_event(event2).expect("event 2 should submit");
    assert_eq!(receipt2.block_height, 2);
    assert_eq!(client.store().current_height(), 2);

    let blocks = client.store().get_all_blocks();
    assert_eq!(blocks.len(), 3); // Genesis + Block 1 + Block 2
    assert_eq!(blocks[1].header.previous_hash, blocks[0].current_hash);
    assert_eq!(blocks[2].header.previous_hash, blocks[1].current_hash);
}

#[test]
fn test_merkle_tree_proof_verification() {
    let e1 = sample_event("e-1", "wm-1", "h-1");
    let e2 = sample_event("e-2", "wm-2", "h-2");
    let e3 = sample_event("e-3", "wm-3", "h-3");
    let events = vec![e1.clone(), e2.clone(), e3.clone()];

    let tree = MerkleTree::from_events(&events);
    assert!(!tree.root.is_empty());

    // Verify inclusion proof for event 1 (index 1)
    let proof = tree.generate_proof(1);
    let leaf_hash = hash_event(&e2);
    let is_valid = MerkleTree::verify_proof(&leaf_hash, &proof, 1, &tree.root);
    assert!(is_valid, "Merkle inclusion proof must verify correctly");
}

#[test]
fn test_get_event_and_reverse_watermark_lookup() {
    let client = PermissionedLedgerClient::new("node-1");
    let event = sample_event("evt-lookup-100", "wm-watermark-100", "hash-fingerprint-100");

    client.submit_event(event.clone()).unwrap();

    // 1. Get by event ID
    let fetched = client.get_event("evt-lookup-100").unwrap();
    assert_eq!(fetched.event_id, "evt-lookup-100");

    // 2. Find by watermark ID
    let by_wm_id = client.find_by_watermark("wm-watermark-100").unwrap();
    assert_eq!(by_wm_id.event_id, "evt-lookup-100");

    // 3. Find by watermark hash
    let by_wm_hash = client.find_by_watermark("hash-fingerprint-100").unwrap();
    assert_eq!(by_wm_hash.event_id, "evt-lookup-100");
}

#[test]
fn test_duplicate_event_rejection() {
    let client = PermissionedLedgerClient::new("node-1");
    let event = sample_event("evt-duplicate", "wm-dup", "hash-dup");

    client.submit_event(event.clone()).unwrap();
    let duplicate_result = client.submit_event(event);

    assert!(matches!(duplicate_result, Err(LedgerError::DuplicateEvent(_))));
}

#[test]
fn test_cryptographic_audit_verification() {
    let client = PermissionedLedgerClient::new("node-1");
    let event = sample_event("evt-audit-1", "wm-audit-1", "hash-audit-1");

    let receipt = client.submit_event(event).unwrap();
    let verification = client.verify_ledger_record(&receipt.event_id).unwrap();

    assert!(verification.is_valid, "ledger record must pass cryptographic audit");
    assert!(verification.merkle_valid, "Merkle root must be valid");
    assert_eq!(verification.block_height, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. 4-Node Cluster, Replication & Sneakernet Synchronization
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_four_node_cluster_replication_and_consensus() {
    let cluster = LocalFourNodeCluster::new();
    assert_eq!(cluster.nodes.len(), 4, "cluster must have exactly 4 nodes");

    let event = sample_event("evt-cluster-1", "wm-cluster-1", "hash-cluster-1");
    let receipt = cluster.submit_and_replicate(event.clone()).unwrap();
    assert_eq!(receipt.block_height, 1);

    // Verify all 4 nodes have replicated the event
    for (id, node) in &cluster.nodes {
        assert_eq!(node.height(), 1, "node {} must be at height 1", id);
        let fetched = node.get_event("evt-cluster-1").unwrap();
        assert_eq!(fetched.watermark_id, "wm-cluster-1");
    }

    // Verify cluster consensus verification
    let consensus_ok = cluster.verify_cluster_consensus("evt-cluster-1").unwrap();
    assert!(consensus_ok, "quorum consensus across 4 nodes must succeed");
}

#[test]
fn test_four_node_cluster_reverse_watermark_lookup() {
    let cluster = LocalFourNodeCluster::new();
    let event = sample_event("evt-forensic-99", "wm-leaked-alpha", "hash-leaked-9999");

    cluster.submit_and_replicate(event).unwrap();

    let found = cluster.find_by_watermark_cluster("wm-leaked-alpha").unwrap();
    assert_eq!(found.event_id, "evt-forensic-99");

    let found_hash = cluster.find_by_watermark_cluster("hash-leaked-9999").unwrap();
    assert_eq!(found_hash.event_id, "evt-forensic-99");
}

#[test]
fn test_airgap_sneakernet_sync_package() {
    let cluster = LocalFourNodeCluster::new();

    // Submit events to primary cluster
    cluster
        .submit_and_replicate(sample_event("e-sync-1", "wm-s1", "h-s1"))
        .unwrap();
    cluster
        .submit_and_replicate(sample_event("e-sync-2", "wm-s2", "h-s2"))
        .unwrap();

    // Export sync package from node-1
    let package = cluster.export_sync_package("node-1").unwrap();
    assert_eq!(package.exported_height, 2);
    assert_eq!(package.blocks.len(), 3); // genesis + 2 blocks

    // Create a new offline air-gapped node (e.g., node-5 in isolated zone)
    let isolated_node = ledger::LedgerNode::new("node-isolated", "http://127.0.0.1:8005");
    assert_eq!(isolated_node.height(), 0);

    // Import package onto isolated node
    let _imported = isolated_node.receive_block(package.blocks[1].clone()).unwrap();
    let _imported2 = isolated_node.receive_block(package.blocks[2].clone()).unwrap();
    assert_eq!(isolated_node.height(), 2);

    let fetched = isolated_node.get_event("e-sync-2").unwrap();
    assert_eq!(fetched.watermark_id, "wm-s2");
}
