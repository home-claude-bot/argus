//! Argus Types - Shared domain types
//!
//! This crate contains domain types used across Argus services:
//! - User identity and authentication
//! - Session and token management
//! - Subscription tiers and pricing
//! - Billing and payment types
//! - API request/response envelopes
//!
//! # Example
//!
//! ```rust
//! use argus_types::{UserId, Tier, Session, ApiResponse};
//!
//! // Create a user ID
//! let user_id = UserId::new();
//!
//! // Check tier rate limits
//! let tier = Tier::Professional;
//! assert_eq!(tier.rate_limit(), 1000);
//!
//! // Wrap response in API envelope
//! let response = ApiResponse::success(user_id);
//! ```

// Core identity types
pub mod user;

// Authentication and session types
pub mod auth;
pub mod session;

// Subscription and tier types
pub mod entitlement;
pub mod subscription;
pub mod tier;

// Billing types
pub mod billing;

// API key management
pub mod api_key;

// API envelope types
pub mod api;

// Error types
pub mod error;

// Re-export commonly used types
pub use api::*;
pub use api_key::*;
pub use auth::*;
pub use billing::*;
pub use entitlement::*;
pub use error::*;
pub use session::*;
pub use subscription::*;
pub use tier::*;
pub use user::*;
