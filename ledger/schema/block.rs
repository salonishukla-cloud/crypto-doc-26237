use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::models::DecryptionEvent;

use super::merkle::MerkleTree;

/// Offline DLT Block Header encapsulating cryptographic state and consensus metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Height / index of block in local offline chain (0 = Genesis).
    pub block_height: u64,

    /// Hex-encoded SHA-256 hash of previous block.
    pub previous_hash: String,

    /// Merkle root hash of all DecryptionEvents in this block.
    pub merkle_root: String,

    /// RFC 3339 timestamp of block creation.
    pub timestamp: String,

    /// Identifier of the node / validator generating the block (e.g., "node-1").
    pub validator_id: String,

    /// Proof / digital signature over block header.
    pub block_signature: String,
}

impl BlockHeader {
    /// Computes the SHA-256 header hash.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.block_height.to_le_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.merkle_root.as_bytes());
        hasher.update(self.timestamp.as_bytes());
        hasher.update(self.validator_id.as_bytes());
        hasher.update(self.block_signature.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// A block within the permissioned offline ledger containing verified DecryptionEvents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub header: BlockHeader,
    pub events: Vec<DecryptionEvent>,
    pub current_hash: String,
}

impl LedgerBlock {
    /// Constructs a new block with computed Merkle root and block hash.
    pub fn new(
        block_height: u64,
        previous_hash: String,
        events: Vec<DecryptionEvent>,
        validator_id: String,
    ) -> Self {
        let merkle_tree = MerkleTree::from_events(&events);
        let timestamp = Utc::now().to_rfc3339();
        
        let header = BlockHeader {
            block_height,
            previous_hash,
            merkle_root: merkle_tree.root,
            timestamp,
            validator_id: validator_id.clone(),
            block_signature: format!("sig-validator-{}", validator_id),
        };

        let current_hash = header.compute_hash();

        Self {
            header,
            events,
            current_hash,
        }
    }

    /// Creates the standardized genesis block for the offline ledger network.
    pub fn genesis() -> Self {
        let header = BlockHeader {
            block_height: 0,
            previous_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            merkle_root: MerkleTree::from_events(&[]).root,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            validator_id: "network-genesis".to_string(),
            block_signature: "genesis-signature-standard".to_string(),
        };
        let current_hash = header.compute_hash();

        Self {
            header,
            events: Vec::new(),
            current_hash,
        }
    }

    /// Validates the internal cryptographic integrity of this block.
    pub fn validate_integrity(&self) -> bool {
        // 1. Recompute Merkle root
        let computed_tree = MerkleTree::from_events(&self.events);
        if computed_tree.root != self.header.merkle_root {
            return false;
        }

        // 2. Recompute header hash
        let recomputed_hash = self.header.compute_hash();
        if recomputed_hash != self.current_hash {
            return false;
        }

        true
    }

    /// Generates a Merkle inclusion receipt for a specific event in this block.
    pub fn generate_receipt(&self, target_event_id: &str) -> Option<LedgerReceipt> {
        let event_idx = self.events.iter().position(|e| e.event_id == target_event_id)?;
        let tree = MerkleTree::from_events(&self.events);
        let proof = tree.generate_proof(event_idx);

        Some(LedgerReceipt {
            event_id: target_event_id.to_string(),
            block_height: self.header.block_height,
            block_hash: self.current_hash.clone(),
            merkle_proof: proof,
            committed_at: self.header.timestamp.clone(),
        })
    }
}

/// Cryptographic audit receipt returned upon successful ledger ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReceipt {
    pub event_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub merkle_proof: Vec<String>,
    pub committed_at: String,
}
