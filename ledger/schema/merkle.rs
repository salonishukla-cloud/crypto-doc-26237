//! # merkle.rs — Cryptographic Merkle Tree for Event Inclusion Proofs
//!
//! Provides binary SHA-256 Merkle tree construction, root computation,
//! and inclusion proof verification for `DecryptionEvent` records.

use sha2::{Digest, Sha256};
use shared::models::DecryptionEvent;

/// Computes SHA-256 hash of raw bytes and returns lowercase hex.
#[inline]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute the cryptographic leaf hash for a `DecryptionEvent`.
pub fn hash_event(event: &DecryptionEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(event.document_id.as_bytes());
    hasher.update(event.recipient_id.as_bytes());
    hasher.update(event.session_id.as_bytes());
    hasher.update(event.watermark_id.as_bytes());
    hasher.update(event.timestamp.as_bytes());
    hasher.update(event.watermark_hash.as_bytes());
    hasher.update(event.signature_algorithm.as_bytes());
    hasher.update(event.signature.as_bytes());
    hex::encode(hasher.finalize())
}

/// Combine two hex hashes into a parent node hash.
pub fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

/// Binary Merkle Tree over a list of `DecryptionEvent` items.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub root: String,
}

impl MerkleTree {
    /// Constructs a Merkle tree from a list of events.
    pub fn from_events(events: &[DecryptionEvent]) -> Self {
        if events.is_empty() {
            let empty_root = sha256_hex(b"EMPTY_MERKLE_ROOT");
            return Self {
                leaves: Vec::new(),
                root: empty_root,
            };
        }

        let leaves: Vec<String> = events.iter().map(hash_event).collect();
        let root = Self::compute_root_from_leaves(&leaves);

        Self { leaves, root }
    }

    /// Recursively computes the Merkle root from leaf hashes.
    pub fn compute_root_from_leaves(leaves: &[String]) -> String {
        if leaves.is_empty() {
            return sha256_hex(b"EMPTY_MERKLE_ROOT");
        }
        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                } else {
                    // Odd element: duplicate last leaf per Bitcoin/Merkle standard
                    next_level.push(hash_pair(&current_level[i], &current_level[i]));
                }
            }
            current_level = next_level;
        }

        current_level[0].clone()
    }

    /// Generates an audit inclusion proof path for an event at the given index.
    pub fn generate_proof(&self, leaf_index: usize) -> Vec<String> {
        if leaf_index >= self.leaves.len() {
            return Vec::new();
        }

        let mut proof = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut idx = leaf_index;

        while current_level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 {
                if idx + 1 < current_level.len() {
                    idx + 1
                } else {
                    idx
                }
            } else {
                idx - 1
            };

            proof.push(current_level[sibling_idx].clone());

            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                } else {
                    next_level.push(hash_pair(&current_level[i], &current_level[i]));
                }
            }
            idx /= 2;
            current_level = next_level;
        }

        proof
    }

    /// Verifies that a target leaf hash belongs to the Merkle tree with the given root.
    pub fn verify_proof(
        leaf_hash: &str,
        proof: &[String],
        mut leaf_index: usize,
        expected_root: &str,
    ) -> bool {
        let mut current_hash = leaf_hash.to_string();

        for sibling in proof {
            if leaf_index % 2 == 0 {
                current_hash = hash_pair(&current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, &current_hash);
            }
            leaf_index /= 2;
        }

        current_hash == expected_root
    }
}
