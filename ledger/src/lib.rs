//! # Member 4 — Ledger Module
//!
//! Owns:
//! - Permissioned Offline DLT (Distributed Ledger Technology)
//! - Consensus mechanisms for air-gapped / sneakernet / periodic synchronization
//! - Event Storage & Merkle indexing
//! - Ledger Lookup and cryptographic audit verification
//!
//! Required API Contract:
//! - `submit_event()`
//! - `get_event()`
//! - `find_by_watermark()`
//! - `verify_ledger_record()`

pub mod client;
pub mod schema;

pub use client::{LedgerError, LedgerVerificationResult};
pub use schema::{BlockHeader, LedgerBlock, LedgerReceipt};

use shared::models::DecryptionEvent;

/// Primary API contract for Member 4 (Ledger).
pub trait LedgerClient {
    /// Ingests a signed `DecryptionEvent` into the offline permissioned ledger.
    ///
    /// Validates event structure, checks for duplicate event IDs, builds Merkle tree inclusion,
    /// and persists to the local immutable append-only ledger block store.
    fn submit_event(
        &self,
        event: DecryptionEvent,
    ) -> Result<LedgerReceipt, LedgerError>;

    /// Retrieves an immutable `DecryptionEvent` by its unique `event_id`.
    fn get_event(
        &self,
        event_id: &str,
    ) -> Result<DecryptionEvent, LedgerError>;

    /// Looks up a recorded `DecryptionEvent` by its unique `watermark_id` or `watermark_hash`.
    ///
    /// Used by forensic investigators when analyzing an extracted watermark from a leaked document.
    fn find_by_watermark(
        &self,
        watermark_identifier: &str,
    ) -> Result<DecryptionEvent, LedgerError>;

    /// Cryptographically verifies the integrity of an event's ledger record.
    ///
    /// Re-evaluates:
    /// 1. Merkle inclusion proof against the block's Merkle root.
    /// 2. Block header hash continuity in the chain/DAG.
    /// 3. Offline consensus signatures on the block.
    fn verify_ledger_record(
        &self,
        event_id: &str,
    ) -> Result<LedgerVerificationResult, LedgerError>;
}
