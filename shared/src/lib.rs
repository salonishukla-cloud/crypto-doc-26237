//! # Shared Foundation Crate
//!
//! Provides canonical data models, JSON schemas, protocol constants,
//! and serialization interfaces across all five domain modules.
//!
//! **Rule**: No business logic resides here. Only common schemas and interfaces.

#[path = "../constants/mod.rs"]
pub mod constants;

#[path = "../models/mod.rs"]
pub mod models;

#[path = "../utils/mod.rs"]
pub mod utils;

pub use constants::*;
pub use models::*;
pub use utils::*;
