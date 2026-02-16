//! Argus Auth Core - Authentication business logic
//!
//! Core authentication functionality including Cognito integration,
//! session management, and tier/entitlement checks.

pub mod error;
pub mod service;

pub use error::*;
pub use service::*;
