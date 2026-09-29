//! # storage.rs — Append-Only Cryptographic Block Store
//!
//! Enforces immutable, append-only block storage with cryptographic hash chaining
//! and integrity verification across the entire block history.

use std::sync::{Arc, RwLock};
use shared::models::DecryptionEvent;

use crate::client::dlt_client::LedgerError;
use crate::queries::LedgerIndex;
use crate::schema::{LedgerBlock, LedgerReceipt};

/// Append-only storage engine for an offline ledger node.
#[derive(Debug, Clone)]
pub struct AppendOnlyStore {
    blocks: Arc<RwLock<Vec<LedgerBlock>>>,
    index: Arc<RwLock<LedgerIndex>>,
    validator_id: String,
}

impl AppendOnlyStore {
    /// Initializes a new append-only store with a Genesis block.
    pub fn new(validator_id: &str) -> Self {
        let genesis_block = LedgerBlock::genesis();
        let mut index = LedgerIndex::new();

        for event in &genesis_block.events {
            index.index_event(0, event);
        }

        Self {
            blocks: Arc::new(RwLock::new(vec![genesis_block])),
            index: Arc::new(RwLock::new(index)),
            validator_id: validator_id.to_string(),
        }
    }

    /// Appends a new signed `DecryptionEvent` into a new block on the chain.
    pub fn append_event(&self, event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError> {
        let mut index = self.index.write().map_err(|e| {
            LedgerError::StorageError(format!("index lock failed: {e}"))
        })?;

        // 1. Prevent duplicate event IDs
        if index.contains_event(&event.event_id) {
            return Err(LedgerError::DuplicateEvent(format!(
                "event_id '{}' already exists in ledger",
                event.event_id
            )));
        }

        let mut blocks = self.blocks.write().map_err(|e| {
            LedgerError::StorageError(format!("blocks lock failed: {e}"))
        })?;

        let last_block = blocks.last().ok_or_else(|| {
            LedgerError::StorageError("ledger chain is missing genesis block".into())
        })?;

        let new_height = last_block.header.block_height + 1;
        let previous_hash = last_block.current_hash.clone();
        let event_id_clone = event.event_id.clone();

        // 2. Mint new block
        let new_block = LedgerBlock::new(
            new_height,
            previous_hash,
            vec![event.clone()],
            self.validator_id.clone(),
        );

        let receipt = new_block
            .generate_receipt(&event_id_clone)
            .ok_or_else(|| LedgerError::StorageError("failed to generate receipt".into()))?;

        // 3. Index event and commit block
        index.index_event(new_height, &event);
        blocks.push(new_block);

        Ok(receipt)
    }

    /// Appends a pre-validated block (used during multi-node consensus & synchronization).
    pub fn append_block(&self, block: LedgerBlock) -> Result<(), LedgerError> {
        // 1. Verify internal block integrity
        if !block.validate_integrity() {
            return Err(LedgerError::IntegrityCheckFailed(format!(
                "block {} failed internal integrity check",
                block.header.block_height
            )));
        }

        let mut blocks = self.blocks.write().map_err(|e| {
            LedgerError::StorageError(format!("blocks lock failed: {e}"))
        })?;

        let last_block = blocks.last().ok_or_else(|| {
            LedgerError::StorageError("missing genesis block".into())
        })?;

        // 2. Verify height and cryptographic hash chain link
        if block.header.block_height != last_block.header.block_height + 1 {
            return Err(LedgerError::IntegrityCheckFailed(format!(
                "invalid block height: expected {}, got {}",
                last_block.header.block_height + 1,
                block.header.block_height
            )));
        }

        if block.header.previous_hash != last_block.current_hash {
            return Err(LedgerError::IntegrityCheckFailed(format!(
                "broken cryptographic hash link: previous_hash mismatch"
            )));
        }

        let mut index = self.index.write().map_err(|e| {
            LedgerError::StorageError(format!("index lock failed: {e}"))
        })?;

        for event in &block.events {
            index.index_event(block.header.block_height, event);
        }

        blocks.push(block);
        Ok(())
    }

    /// Retrieves an event by `event_id`.
    pub fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError> {
        let index = self.index.read().map_err(|e| {
            LedgerError::StorageError(format!("index lock failed: {e}"))
        })?;

        match index.get_by_event_id(event_id) {
            Some((_, event)) => Ok(event.clone()),
            None => Err(LedgerError::EventNotFound(format!(
                "event_id '{event_id}' not found on ledger"
            ))),
        }
    }

    /// Looks up an event by `watermark_id` or `watermark_hash`.
    pub fn find_by_watermark(&self, identifier: &str) -> Result<DecryptionEvent, LedgerError> {
        let index = self.index.read().map_err(|e| {
            LedgerError::StorageError(format!("index lock failed: {e}"))
        })?;

        match index.find_by_watermark(identifier) {
            Some((_, event)) => Ok(event.clone()),
            None => Err(LedgerError::WatermarkNotFound(format!(
                "watermark '{identifier}' not found in ledger records"
            ))),
        }
    }

    /// Get block height and block hash for an event.
    pub fn get_event_location(&self, event_id: &str) -> Option<(u64, String)> {
        let index = self.index.read().ok()?;
        let (height, _) = index.get_by_event_id(event_id)?;
        let blocks = self.blocks.read().ok()?;
        let block = blocks.get(*height as usize)?;
        Some((*height, block.current_hash.clone()))
    }

    /// Retrieve all blocks in current chain.
    pub fn get_all_blocks(&self) -> Vec<LedgerBlock> {
        self.blocks.read().map(|b| b.clone()).unwrap_or_default()
    }

    /// Current height of the ledger.
    pub fn current_height(&self) -> u64 {
        self.blocks
            .read()
            .map(|b| b.last().map(|blk| blk.header.block_height).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Complete cryptographic audit of the entire chain history.
    pub fn verify_chain_integrity(&self) -> Result<bool, LedgerError> {
        let blocks = self.blocks.read().map_err(|e| {
            LedgerError::StorageError(format!("blocks lock failed: {e}"))
        })?;

        if blocks.is_empty() {
            return Ok(false);
        }

        // 1. Verify genesis block
        if blocks[0].header.block_height != 0 {
            return Ok(false);
        }

        // 2. Traverse and verify each block and hash link
        for i in 0..blocks.len() {
            let current = &blocks[i];

            // Verify internal block Merkle tree & hash
            if !current.validate_integrity() {
                return Ok(false);
            }

            // Verify chain continuity
            if i > 0 {
                let previous = &blocks[i - 1];
                if current.header.block_height != previous.header.block_height + 1 {
                    return Ok(false);
                }
                if current.header.previous_hash != previous.current_hash {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
