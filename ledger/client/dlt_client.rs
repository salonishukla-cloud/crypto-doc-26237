use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use shared::models::DecryptionEvent;

use crate::client::storage::AppendOnlyStore;
use crate::schema::{hash_event, MerkleTree};

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Ledger storage error: {0}")]
    StorageError(String),

    #[error("Event already committed or duplicate event ID: {0}")]
    DuplicateEvent(String),

    #[error("Event not found on ledger: {0}")]
    EventNotFound(String),

    #[error("Watermark hash not associated with any recorded decryption event: {0}")]
    WatermarkNotFound(String),

    #[error("Cryptographic ledger verification failed (corrupted block or broken chain): {0}")]
    IntegrityCheckFailed(String),

    #[error("Consensus or synchronization error in offline partition: {0}")]
    ConsensusError(String),
}

/// Verification result certifying ledger record immutability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerVerificationResult {
    pub is_valid: bool,
    pub block_height: u64,
    pub block_hash: String,
    pub merkle_valid: bool,
    pub audit_timestamp: String,
}

/// Concrete implementation of the Offline Permissioned Ledger Client.
#[derive(Debug, Clone)]
pub struct PermissionedLedgerClient {
    store: AppendOnlyStore,
}

impl PermissionedLedgerClient {
    /// Creates a new ledger client instance for the specified validator.
    pub fn new(validator_id: &str) -> Self {
        Self {
            store: AppendOnlyStore::new(validator_id),
        }
    }

    /// Initializes from an existing store (shared across local nodes/threads).
    pub fn with_store(store: AppendOnlyStore) -> Self {
        Self { store }
    }

    /// Direct reference to the internal append-only store.
    pub fn store(&self) -> &AppendOnlyStore {
        &self.store
    }

    /// Ingests a signed `DecryptionEvent` into the offline permissioned ledger.
    pub fn submit_event(&self, event: DecryptionEvent) -> Result<crate::schema::LedgerReceipt, LedgerError> {
        self.store.append_event(event)
    }

    /// Retrieves an immutable `DecryptionEvent` by its unique `event_id`.
    pub fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError> {
        self.store.get_event(event_id)
    }

    /// Looks up a recorded `DecryptionEvent` by its `watermark_id` or `watermark_hash`.
    pub fn find_by_watermark(&self, watermark_identifier: &str) -> Result<DecryptionEvent, LedgerError> {
        self.store.find_by_watermark(watermark_identifier)
    }

    /// Cryptographically audits and verifies the integrity of an event's ledger record.
    pub fn verify_ledger_record(&self, event_id: &str) -> Result<LedgerVerificationResult, LedgerError> {
        // 1. Check whole chain integrity first
        let chain_valid = self.store.verify_chain_integrity()?;
        if !chain_valid {
            return Err(LedgerError::IntegrityCheckFailed(
                "ledger chain continuity or block integrity is compromised".into(),
            ));
        }

        // 2. Locate the event in chain
        let event = self.store.get_event(event_id)?;
        let (block_height, block_hash) = self
            .store
            .get_event_location(event_id)
            .ok_or_else(|| LedgerError::EventNotFound(event_id.to_string()))?;

        let blocks = self.store.get_all_blocks();
        let target_block = blocks
            .get(block_height as usize)
            .ok_or_else(|| LedgerError::EventNotFound(event_id.to_string()))?;

        // 3. Verify Merkle inclusion proof
        let target_event_idx = target_block
            .events
            .iter()
            .position(|e| e.event_id == event_id)
            .ok_or_else(|| LedgerError::EventNotFound(event_id.to_string()))?;

        let tree = MerkleTree::from_events(&target_block.events);
        let proof = tree.generate_proof(target_event_idx);
        let leaf_hash = hash_event(&event);

        let merkle_valid = MerkleTree::verify_proof(
            &leaf_hash,
            &proof,
            target_event_idx,
            &target_block.header.merkle_root,
        );

        let is_valid = chain_valid && merkle_valid && (target_block.current_hash == block_hash);

        Ok(LedgerVerificationResult {
            is_valid,
            block_height,
            block_hash,
            merkle_valid,
            audit_timestamp: Utc::now().to_rfc3339(),
        })
    }
}
