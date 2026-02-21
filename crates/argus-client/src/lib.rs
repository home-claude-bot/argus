//! Argus Client - SDK for service consumers
//!
//! Client SDK for integrating with Argus auth, billing, and identity services.
//!
//! # Overview
//!
//! This crate provides high-level async clients for communicating with Argus services
//! over gRPC. It handles connection management, retry logic, and error handling.
//!
//! # Quick Start
//!
//! ```ignore
//! use argus_client::{ClientConfig, AuthClient};
//!
//! let config = ClientConfig::builder()
//!     .endpoint("https://argus.example.com")
//!     .bearer_token("your-token")
//!     .build()?;
//!
//! let auth = AuthClient::connect(config).await?;
//! let token_info = auth.validate_token("jwt-token").await?;
//! ```
//!
//! # Clients
//!
//! - [`AuthClient`] - Authentication and session management
//! - [`BillingClient`] - Subscriptions, payments, and usage tracking
//! - [`IdentityClient`] - User profiles, organizations, and API keys
//!
//! # Configuration
//!
//! Use [`ClientConfig::builder()`] to configure endpoints, timeouts, and retry settings.

pub mod auth;
pub mod billing;
pub mod channel;
pub mod config;
pub mod error;
pub mod identity;
pub mod interceptor;
pub mod metrics;
pub mod retry;

// Re-export primary types
pub use auth::AuthClient;
pub use billing::{BatchUsageResult, BillingClient, CheckoutOptions, LlmUsageEvent, UsageEvent};
pub use channel::{ArgusClient, ChannelFactory, SharedArgusClient};
pub use config::{ClientConfig, ClientConfigBuilder, ConfigError, CredentialSource, TlsConfig};
pub use error::ClientError;
pub use identity::{
    ApiKey, IdentityClient, Invitation, Organization, OrganizationMember, OrganizationMembership,
    OrganizationRole, User,
};
pub use interceptor::{AuthInterceptor, CombinedInterceptor, RequestIdInterceptor};
pub use retry::{with_retry, RetryConfig, RetryPolicy, RetryableError};

/// Result type for client operations.
pub type Result<T> = std::result::Result<T, ClientError>;
