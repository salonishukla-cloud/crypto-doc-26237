//! # Member 4 — Distributed Ledger Module (`ledger`)
//!
//! Owns:
//! - Permissioned Offline DLT (Distributed Ledger Technology)
//! - 4-node local permissioned cluster with quorum consensus
//! - Immutable append-only cryptographic block store with SHA-256 chaining
//! - Binary Merkle Trees for cryptographic inclusion proofs
//! - Fast reverse index queries (`watermark_id`, `watermark_hash`, `event_id`)
//! - Air-gapped sneakernet synchronization packages
//!
//! ## Required APIs:
//! - `submit_event(event)`
//! - `get_event(event_id)`
//! - `find_by_watermark(watermark_identifier)`
//! - `verify_ledger_record(event_id)`

#[path = "../client/mod.rs"]
pub mod client;

#[path = "../network/mod.rs"]
pub mod network;

#[path = "../queries/mod.rs"]
pub mod queries;

#[path = "../schema/mod.rs"]
pub mod schema;

pub use client::{
    AppendOnlyStore, LedgerError, LedgerVerificationResult, PermissionedLedgerClient,
};
pub use network::{AirGapSyncPackage, LedgerNode, LocalFourNodeCluster};
pub use queries::LedgerIndex;
pub use schema::{
    hash_event, hash_pair, sha256_hex, BlockHeader, LedgerBlock, LedgerReceipt, MerkleTree,
};

use shared::models::DecryptionEvent;

// ── Top-Level Direct Functional APIs (Role 4 Contract) ──────────────────────

/// Submits a signed `DecryptionEvent` into a default local node ledger.
pub fn submit_event(event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError> {
    let client = PermissionedLedgerClient::new("node-1");
    client.submit_event(event)
}

/// Retrieves an event from the ledger by its `event_id`.
pub fn get_event(client: &PermissionedLedgerClient, event_id: &str) -> Result<DecryptionEvent, LedgerError> {
    client.get_event(event_id)
}

/// Reverse lookup to find a `DecryptionEvent` by its `watermark_id` or `watermark_hash`.
pub fn find_by_watermark(
    client: &PermissionedLedgerClient,
    watermark_identifier: &str,
) -> Result<DecryptionEvent, LedgerError> {
    client.find_by_watermark(watermark_identifier)
}

/// Cryptographically verifies the ledger record, Merkle proof, and hash chaining for an event.
pub fn verify_ledger_record(
    client: &PermissionedLedgerClient,
    event_id: &str,
) -> Result<LedgerVerificationResult, LedgerError> {
    client.verify_ledger_record(event_id)
}

// ── Primary Trait Definition ────────────────────────────────────────────────

/// Primary API contract for Member 4 (Ledger).
pub trait LedgerClient {
    /// Ingests a signed `DecryptionEvent` into the offline permissioned ledger.
    fn submit_event(&self, event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError>;

    /// Retrieves an immutable `DecryptionEvent` by its unique `event_id`.
    fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError>;

    /// Looks up a recorded `DecryptionEvent` by its unique `watermark_id` or `watermark_hash`.
    fn find_by_watermark(&self, watermark_identifier: &str) -> Result<DecryptionEvent, LedgerError>;

    /// Cryptographically verifies the integrity of an event's ledger record.
    fn verify_ledger_record(&self, event_id: &str) -> Result<LedgerVerificationResult, LedgerError>;
}

impl LedgerClient for PermissionedLedgerClient {
    fn submit_event(&self, event: DecryptionEvent) -> Result<LedgerReceipt, LedgerError> {
        self.submit_event(event)
    }

    fn get_event(&self, event_id: &str) -> Result<DecryptionEvent, LedgerError> {
        self.get_event(event_id)
    }

    fn find_by_watermark(&self, watermark_identifier: &str) -> Result<DecryptionEvent, LedgerError> {
        self.find_by_watermark(watermark_identifier)
    }

    fn verify_ledger_record(&self, event_id: &str) -> Result<LedgerVerificationResult, LedgerError> {
        self.verify_ledger_record(event_id)
    }
}
