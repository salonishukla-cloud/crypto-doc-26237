//! # ledger_index.rs — Fast Reverse Query Indices for Offline Ledger
//!
//! Provides in-memory reverse indices mapping:
//! - `event_id` -> (block_height, event)
//! - `watermark_id` -> event_id
//! - `watermark_hash` -> event_id
//! - `document_id` -> Vec<event_id>
//! - `recipient_id` -> Vec<event_id>

use std::collections::HashMap;
use shared::models::DecryptionEvent;

/// Fast in-memory secondary index for ledger lookups.
#[derive(Debug, Default, Clone)]
pub struct LedgerIndex {
    events_by_id: HashMap<String, (u64, DecryptionEvent)>,
    event_by_watermark_id: HashMap<String, String>,
    event_by_watermark_hash: HashMap<String, String>,
    events_by_document: HashMap<String, Vec<String>>,
    events_by_recipient: HashMap<String, Vec<String>>,
}

impl LedgerIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a committed event into all secondary lookup tables.
    pub fn index_event(&mut self, block_height: u64, event: &DecryptionEvent) {
        self.events_by_id.insert(event.event_id.clone(), (block_height, event.clone()));
        self.event_by_watermark_id.insert(event.watermark_id.clone(), event.event_id.clone());
        self.event_by_watermark_hash.insert(event.watermark_hash.clone(), event.event_id.clone());
        
        self.events_by_document
            .entry(event.document_id.clone())
            .or_default()
            .push(event.event_id.clone());

        self.events_by_recipient
            .entry(event.recipient_id.clone())
            .or_default()
            .push(event.event_id.clone());
    }

    /// Retrieve an event by unique `event_id`.
    pub fn get_by_event_id(&self, event_id: &str) -> Option<&(u64, DecryptionEvent)> {
        self.events_by_id.get(event_id)
    }

    /// Retrieve an event by `watermark_id` or `watermark_hash`.
    pub fn find_by_watermark(&self, identifier: &str) -> Option<&(u64, DecryptionEvent)> {
        if let Some(event_id) = self.event_by_watermark_id.get(identifier) {
            return self.events_by_id.get(event_id);
        }
        if let Some(event_id) = self.event_by_watermark_hash.get(identifier) {
            return self.events_by_id.get(event_id);
        }
        None
    }

    /// Check if an `event_id` is already indexed (duplicate prevention).
    pub fn contains_event(&self, event_id: &str) -> bool {
        self.events_by_id.contains_key(event_id)
    }

    /// Total number of indexed events.
    pub fn total_events(&self) -> usize {
        self.events_by_id.len()
    }
}
