//! Argus DB - Database abstractions
//!
//! SQLx-based database layer for Argus services.

pub mod pool;
pub mod error;

pub use pool::*;
pub use error::*;
