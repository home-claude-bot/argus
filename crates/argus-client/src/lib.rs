//! Argus Client - SDK for service consumers
//!
//! Client SDK for integrating with Argus auth and billing services.

pub mod auth;
pub mod billing;
pub mod config;
pub mod error;

pub use auth::AuthClient;
pub use billing::BillingClient;
pub use config::ClientConfig;
pub use error::ClientError;
