//! Argus Proto - gRPC Protocol Buffers
//!
//! Generated code from Protocol Buffer definitions for Argus gRPC services.
//!
//! # Services
//!
//! - [`auth_service`] - Authentication and session management
//! - [`billing_service`] - Subscriptions, payments, and usage tracking
//! - [`identity_service`] - User and organization management
//!
//! # Example
//!
//! ```ignore
//! use argus_proto::auth_service::auth_service_client::AuthServiceClient;
//! use argus_proto::ValidateTokenRequest;
//!
//! let mut client = AuthServiceClient::connect("http://localhost:50051").await?;
//! let response = client.validate_token(ValidateTokenRequest {
//!     token: "bearer_token".to_string(),
//!     ..Default::default()
//! }).await?;
//! ```

// Suppress clippy warnings from generated tonic code
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::used_underscore_items)]

/// Argus v1 API types and services.
///
/// This module contains all generated types from the Protocol Buffer definitions.
pub mod argus {
    pub mod v1 {
        tonic::include_proto!("argus.v1");

        /// File descriptor set for gRPC reflection.
        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("argus_descriptor");
    }
}

// Re-export commonly used types at crate root for convenience
pub use argus::v1::*;

// Service module aliases for clearer imports
pub mod auth_service {
    pub use super::argus::v1::auth_service_client;
    pub use super::argus::v1::auth_service_server;
}

pub mod billing_service {
    pub use super::argus::v1::billing_service_client;
    pub use super::argus::v1::billing_service_server;
}

pub mod identity_service {
    pub use super::argus::v1::identity_service_client;
    pub use super::argus::v1::identity_service_server;
}
