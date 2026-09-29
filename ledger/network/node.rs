//! # node.rs — Permissioned Ledger Node
//!
//! Represents an individual air-gapped node within the 4-node permissioned ledger network.

use std::sync::{Arc, Mutex};
use shared::models::DecryptionEvent;

use crate::client::{AppendOnlyStore, LedgerError, LedgerVerificationResult, PermissionedLedgerClient};
use crate::schema::{LedgerBlock, LedgerReceipt};

/// Individual Permissioned Node in the local offline cluster.
#[derive(Debug, Clone)]
pub struct LedgerNode {
    pub node_id: String,
    pub endpoint: String,
    pub is_active: bool,
    client: PermissionedLedgerClient,
    peers: Arc<Mutex<Vec<String>>>,
}

impl LedgerNode {
    /// Creates a new permissioned node instance.
    pub fn new(node_id: &str, endpoint: &str) -> Self {
        let store = AppendOnlyStore::new(node_id);
        Self {
            node_id: node_id.to_string(),
            endpoint: endpoint.to_string(),
            is_active: true,
            client: PermissionedLedgerClient::with_store(store),
            peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a peer node ID.
    pub fn add_peer(&self, peer_id: &str) {
        if let Ok(mut peers) = self.peers.lock() {
            if !peers.iter().any(|p| p == peer_id) {
                peers.push(peer_id.to_string());
            }
        }
    }

    /// Ingest and mint an event on this node.
    pub fn submit_event(&self, event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError> {
        self.client.submit_event(event)
    }

    /// Retrieve an event from this node's local ledger.
    pub fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError> {
        self.client.get_event(event_id)
    }

    /// Find an event by watermark on this node's local index.
    pub fn find_by_watermark(&self, identifier: &str) -> Result<DecryptionEvent, LedgerError> {
        self.client.find_by_watermark(identifier)
    }

    /// Verify local ledger record.
    pub fn verify_ledger_record(&self, event_id: &str) -> Result<LedgerVerificationResult, LedgerError> {
        self.client.verify_ledger_record(event_id)
    }

    /// Receive and append a block broadcast from another peer node.
    pub fn receive_block(&self, block: LedgerBlock) -> Result<(), LedgerError> {
        self.client.store().append_block(block)
    }

    /// Retrieve full block history from this node.
    pub fn get_chain(&self) -> Vec<LedgerBlock> {
        self.client.store().get_all_blocks()
    }

    /// Current block height on this node.
    pub fn height(&self) -> u64 {
        self.client.store().current_height()
    }

    /// Direct client handle.
    pub fn client(&self) -> &PermissionedLedgerClient {
        &self.client
    }
}
