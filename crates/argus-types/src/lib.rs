//! Argus Types - Shared domain types
//!
//! This crate contains domain types used across Argus services:
//! - User identity and authentication
//! - Subscription tiers and pricing
//! - Billing and payment types

pub mod user;
pub mod tier;
pub mod subscription;
pub mod error;

pub use user::*;
pub use tier::*;
pub use subscription::*;
pub use error::*;
