//! # Shared Foundation Crate
//!
//! Provides canonical data models, JSON schemas, protocol constants,
//! and serialization interfaces across all five domain modules.
//!
//! **Rule**: No business logic resides here. Only common schemas and interfaces.

pub mod constants;
pub mod models;
pub mod utils;

pub use constants::*;
pub use models::*;
pub use utils::*;
