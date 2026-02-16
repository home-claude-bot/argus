//! Argus Auth Core - Authentication business logic
//!
//! Core authentication functionality including Cognito integration,
//! session management, and tier/entitlement checks.

pub mod service;
pub mod error;

pub use service::*;
pub use error::*;
