//! # event.rs — DecryptionEvent Builder
//!
//! Constructs [`UnsignedDecryptionEvent`] instances from caller-supplied parameters.
//!
//! ## Signing Pipeline Context
//!
//! ```text
//! create_event(params)                    ← this file
//!      │
//!      ▼
//! UnsignedDecryptionEvent
//!      │
//!      ▼
//! serialize_event()  →  canonical JSON bytes   ← serialization.rs
//!      │
//!      ▼
//! sha256(bytes)      →  32-byte digest          ← hash.rs
//!      │
//!      ▼
//! ml_dsa_65::sign()  →  3293-byte signature     ← signing.rs
//!      │
//!      ▼
//! DecryptionEvent { ..unsigned_fields, signature: hex(sig) }
//! ```
//!
//! ## Field Validation
//! Every mandatory field is validated before the event is created.
//! An empty `document_id`, `recipient_id`, `session_id`, `watermark_id`,
//! or `watermark_hash` is rejected with [`PqCryptoError::InvalidEventSchema`].

use chrono::Utc;
use uuid::Uuid;

use shared::models::UnsignedDecryptionEvent;

use crate::identity::ALGORITHM_ID;
use crate::types::{CreateEventParams, PqCryptoError};

/// Event builder for [`UnsignedDecryptionEvent`].
pub struct EventBuilder;

impl EventBuilder {
    /// Construct a fully populated [`UnsignedDecryptionEvent`] from the given parameters.
    ///
    /// Automatically populates:
    /// - `event_id` — UUIDv4, cryptographically random
    /// - `timestamp` — current UTC time in RFC 3339 format
    /// - `signature_algorithm` — always `"ML-DSA-65"`
    ///
    /// # Errors
    /// Returns [`PqCryptoError::InvalidEventSchema`] if any required field is empty.
    pub fn create_event(params: CreateEventParams) -> Result<UnsignedDecryptionEvent, PqCryptoError> {
        // ── Validate required fields ──────────────────────────────────────────
        Self::require_non_empty("document_id",    &params.document_id)?;
        Self::require_non_empty("recipient_id",   &params.recipient_id)?;
        Self::require_non_empty("session_id",     &params.session_id)?;
        Self::require_non_empty("watermark_id",   &params.watermark_id)?;
        Self::require_non_empty("watermark_hash", &params.watermark_hash)?;

        // ── Populate auto-generated fields ────────────────────────────────────
        let event_id  = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        Ok(UnsignedDecryptionEvent {
            event_id,
            document_id:         params.document_id,
            recipient_id:        params.recipient_id,
            session_id:          params.session_id,
            watermark_id:        params.watermark_id,
            timestamp,
            watermark_hash:      params.watermark_hash,
            signature_algorithm: ALGORITHM_ID.to_string(),
        })
    }

    /// Validate that a field value is non-empty.
    fn require_non_empty(field: &str, value: &str) -> Result<(), PqCryptoError> {
        if value.trim().is_empty() {
            Err(PqCryptoError::InvalidEventSchema(format!(
                "required field `{field}` must not be empty"
            )))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CreateEventParams;

    fn valid_params() -> CreateEventParams {
        CreateEventParams {
            document_id:    "doc-001".into(),
            recipient_id:   "alice@gov.in".into(),
            session_id:     "sess-001".into(),
            watermark_id:   "wm-001".into(),
            watermark_hash: "deadbeef".into(),
        }
    }

    #[test]
    fn create_event_populates_all_fields() {
        let event = EventBuilder::create_event(valid_params()).unwrap();
        assert!(!event.event_id.is_empty(),            "event_id must be populated");
        assert!(!event.timestamp.is_empty(),           "timestamp must be populated");
        assert_eq!(event.signature_algorithm, ALGORITHM_ID);
        assert_eq!(event.document_id,  "doc-001");
        assert_eq!(event.recipient_id, "alice@gov.in");
    }

    #[test]
    fn event_id_is_valid_uuid_v4() {
        let event = EventBuilder::create_event(valid_params()).unwrap();
        let parsed = Uuid::parse_str(&event.event_id);
        assert!(parsed.is_ok(), "event_id must be a valid UUID: {}", event.event_id);
        assert_eq!(parsed.unwrap().get_version_num(), 4, "must be UUIDv4");
    }

    #[test]
    fn event_id_is_unique_per_call() {
        let e1 = EventBuilder::create_event(valid_params()).unwrap();
        let e2 = EventBuilder::create_event(valid_params()).unwrap();
        assert_ne!(e1.event_id, e2.event_id, "every event must have a unique ID");
    }

    #[test]
    fn timestamp_is_rfc3339() {
        let event = EventBuilder::create_event(valid_params()).unwrap();
        // RFC 3339 timestamps contain 'T' separator and 'Z' or offset
        assert!(event.timestamp.contains('T'), "timestamp must contain 'T' separator");
    }

    #[test]
    fn rejects_empty_document_id() {
        let mut params = valid_params();
        params.document_id = "".into();
        let err = EventBuilder::create_event(params);
        assert!(matches!(err, Err(PqCryptoError::InvalidEventSchema(_))));
    }

    #[test]
    fn rejects_empty_recipient_id() {
        let mut params = valid_params();
        params.recipient_id = "".into();
        let err = EventBuilder::create_event(params);
        assert!(matches!(err, Err(PqCryptoError::InvalidEventSchema(_))));
    }

    #[test]
    fn rejects_whitespace_only_field() {
        let mut params = valid_params();
        params.watermark_hash = "   ".into();
        let err = EventBuilder::create_event(params);
        assert!(matches!(err, Err(PqCryptoError::InvalidEventSchema(_))));
    }
}
