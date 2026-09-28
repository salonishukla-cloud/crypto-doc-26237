use serde::{Deserialize, Serialize};
use shared::models::DecryptionEvent;

/// Offline DLT Block Header encapsulating cryptographic state and consensus metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Height / index of block in local offline chain.
    pub block_height: u64,

    /// Hex-encoded SHA-256 hash of previous block.
    pub previous_hash: String,

    /// Merkle root hash of all DecryptionEvents in this block.
    pub merkle_root: String,

    /// RFC 3339 timestamp of block creation.
    pub timestamp: String,

    /// Public key identifier of the validator / workstation generating the block.
    pub validator_id: String,

    /// Proof / signature over block header.
    pub block_signature: String,
}

/// A block within the permissioned offline ledger containing verified DecryptionEvents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub header: BlockHeader,
    pub events: Vec<DecryptionEvent>,
    pub current_hash: String,
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
