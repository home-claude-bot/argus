//! Argus Billing Core - Billing business logic
//!
//! Core billing functionality including Stripe integration,
//! subscription management, usage tracking, and webhook handling.
//!
//! # Example
//!
//! ```rust,ignore
//! use argus_billing_core::{BillingService, BillingConfig};
//! use argus_db::Repositories;
//!
//! // Create billing service
//! let config = BillingConfig::new(
//!     "sk_test_...",
//!     "whsec_..."
//! )
//! .with_price(Tier::Professional, "price_...");
//!
//! let billing = BillingService::new(repos, config);
//!
//! // Create checkout session
//! let session = billing.create_checkout(&user_id, Tier::Professional, None, None).await?;
//!
//! // Record usage
//! billing.record_usage(&user_id, "api_calls", 1).await?;
//! ```

pub mod config;
pub mod error;
pub mod provider;
pub mod service;
pub mod stripe;
pub mod webhook;

pub use config::BillingConfig;
pub use error::BillingError;
pub use provider::PaymentProvider;
pub use service::{BillingService, UsageResult};
pub use stripe::StripeProvider;
pub use webhook::{WebhookEvent, WebhookEventData, WebhookEventType, WebhookHandler};

// Re-export checkout types from argus-types for convenience
pub use argus_types::{CheckoutSession, PortalSession};
