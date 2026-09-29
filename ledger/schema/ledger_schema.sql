-- =============================================================================
-- Offline Permissioned Ledger Metadata & Archival SQL Schema (PostgreSQL)
-- =============================================================================

-- 1. Blocks Table
CREATE TABLE IF NOT EXISTS ledger_blocks (
    block_height BIGINT PRIMARY KEY,
    block_hash VARCHAR(64) NOT NULL UNIQUE,
    previous_hash VARCHAR(64) NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    validator_id VARCHAR(128) NOT NULL,
    block_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Decryption Events Table
CREATE TABLE IF NOT EXISTS decryption_events (
    event_id VARCHAR(64) PRIMARY KEY,
    block_height BIGINT NOT NULL REFERENCES ledger_blocks(block_height),
    document_id VARCHAR(128) NOT NULL,
    recipient_id VARCHAR(256) NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    watermark_id VARCHAR(128) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    watermark_hash VARCHAR(64) NOT NULL,
    signature_algorithm VARCHAR(32) NOT NULL DEFAULT 'ML-DSA-65',
    signature TEXT NOT NULL,
    merkle_index INT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. High-Performance Secondary Indices for Reverse Lookup
CREATE INDEX IF NOT EXISTS idx_events_watermark_id ON decryption_events(watermark_id);
CREATE INDEX IF NOT EXISTS idx_events_watermark_hash ON decryption_events(watermark_hash);
CREATE INDEX IF NOT EXISTS idx_events_document_id ON decryption_events(document_id);
CREATE INDEX IF NOT EXISTS idx_events_recipient_id ON decryption_events(recipient_id);
CREATE INDEX IF NOT EXISTS idx_blocks_validator ON ledger_blocks(validator_id);
