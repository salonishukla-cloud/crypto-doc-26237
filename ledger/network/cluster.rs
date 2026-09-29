//! # cluster.rs — 4-Node Local Permissioned Network Cluster
//!
//! Manages a local cluster of 4 permissioned nodes:
//! - Node 1: Primary Air-Gapped Key Custody Validator
//! - Node 2: Document Ingestion & Verification Node
//! - Node 3: Forensic Attribution Analysis Node
//! - Node 4: Offline Audit & Archival Node
//!
//! Provides:
//! - Quorum consensus (3/4 nodes required for block finalization)
//! - Air-gapped offline synchronization bundles (Sneakernet / USB export/import)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use shared::models::DecryptionEvent;

use crate::client::LedgerError;
use crate::network::node::LedgerNode;
use crate::schema::{LedgerBlock, LedgerReceipt};

/// Offline air-gapped synchronization package for physical media transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGapSyncPackage {
    pub source_node_id: String,
    pub export_timestamp: String,
    pub exported_height: u64,
    pub blocks: Vec<LedgerBlock>,
    pub package_signature: String,
}

/// 4-Node Permissioned Cluster.
#[derive(Debug)]
pub struct LocalFourNodeCluster {
    pub nodes: HashMap<String, LedgerNode>,
    pub required_quorum: usize, // e.g., 3 out of 4 nodes
}

impl LocalFourNodeCluster {
    /// Initializes a standard 4-node permissioned offline cluster.
    pub fn new() -> Self {
        let mut nodes = HashMap::new();

        let node_configs = [
            ("node-1", "http://127.0.0.1:8001"),
            ("node-2", "http://127.0.0.1:8002"),
            ("node-3", "http://127.0.0.1:8003"),
            ("node-4", "http://127.0.0.1:8004"),
        ];

        for (id, endpoint) in &node_configs {
            nodes.insert(id.to_string(), LedgerNode::new(id, endpoint));
        }

        // Cross-connect peer IDs
        for id in nodes.keys().cloned().collect::<Vec<_>>() {
            for peer_id in nodes.keys().cloned().collect::<Vec<_>>() {
                if id != peer_id {
                    nodes.get(&id).unwrap().add_peer(&peer_id);
                }
            }
        }

        Self {
            nodes,
            required_quorum: 3, // Byzantine fault tolerant threshold (3/4 quorum)
        }
    }

    /// Submit an event to the primary node and broadcast the committed block across all active nodes.
    pub fn submit_and_replicate(
        &self,
        event: DecryptionEvent,
    ) -> Result<LedgerReceipt, LedgerError> {
        let primary_node = self.nodes.get("node-1").ok_or_else(|| {
            LedgerError::ConsensusError("primary node-1 is unavailable".into())
        })?;

        // 1. Primary node mints the block
        let receipt = primary_node.submit_event(event)?;
        let chain = primary_node.get_chain();
        let latest_block = chain.last().ok_or_else(|| {
            LedgerError::StorageError("no blocks found after submission".into())
        })?;

        // 2. Replicate block to all other 3 nodes (reaches 4/4 consensus)
        let mut consensus_count = 1; // node-1 already committed

        for (id, node) in &self.nodes {
            if id != "node-1" {
                if node.receive_block(latest_block.clone()).is_ok() {
                    consensus_count += 1;
                }
            }
        }

        if consensus_count < self.required_quorum {
            return Err(LedgerError::ConsensusError(format!(
                "quorum failed: only {} of {} nodes acknowledged block",
                consensus_count, self.required_quorum
            )));
        }

        Ok(receipt)
    }

    /// Retrieve an event from any designated node.
    pub fn get_event_from_node(
        &self,
        node_id: &str,
        event_id: &str,
    ) -> Result<DecryptionEvent, LedgerError> {
        let node = self.nodes.get(node_id).ok_or_else(|| {
            LedgerError::ConsensusError(format!("node '{}' not found", node_id))
        })?;
        node.get_event(event_id)
    }

    /// Reverse lookup by watermark across cluster.
    pub fn find_by_watermark_cluster(
        &self,
        identifier: &str,
    ) -> Result<DecryptionEvent, LedgerError> {
        for node in self.nodes.values() {
            if let Ok(event) = node.find_by_watermark(identifier) {
                return Ok(event);
            }
        }
        Err(LedgerError::WatermarkNotFound(format!(
            "watermark '{identifier}' not found across 4-node cluster"
        )))
    }

    /// Verify ledger record across all 4 nodes in cluster to ensure consensus consistency.
    pub fn verify_cluster_consensus(
        &self,
        event_id: &str,
    ) -> Result<bool, LedgerError> {
        let mut valid_nodes = 0;

        for node in self.nodes.values() {
            if let Ok(res) = node.verify_ledger_record(event_id) {
                if res.is_valid && res.merkle_valid {
                    valid_nodes += 1;
                }
            }
        }

        Ok(valid_nodes >= self.required_quorum)
    }

    /// Export an air-gapped sneakernet synchronization package.
    pub fn export_sync_package(&self, node_id: &str) -> Result<AirGapSyncPackage, LedgerError> {
        let node = self.nodes.get(node_id).ok_or_else(|| {
            LedgerError::ConsensusError(format!("node '{}' not found", node_id))
        })?;

        let chain = node.get_chain();
        let height = node.height();
        let timestamp = chrono::Utc::now().to_rfc3339();

        Ok(AirGapSyncPackage {
            source_node_id: node_id.to_string(),
            export_timestamp: timestamp,
            exported_height: height,
            blocks: chain,
            package_signature: format!("sync-sig-{}", node_id),
        })
    }

    /// Import and apply an air-gapped sync package onto a disconnected node.
    pub fn import_sync_package(
        &self,
        target_node_id: &str,
        package: AirGapSyncPackage,
    ) -> Result<usize, LedgerError> {
        let target_node = self.nodes.get(target_node_id).ok_or_else(|| {
            LedgerError::ConsensusError(format!("node '{}' not found", target_node_id))
        })?;

        let current_height = target_node.height();
        let mut imported_count = 0;

        for block in package.blocks {
            if block.header.block_height > current_height {
                target_node.receive_block(block)?;
                imported_count += 1;
            }
        }

        Ok(imported_count)
    }
}
