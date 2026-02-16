//! Billing errors

use thiserror::Error;

/// Billing errors
#[derive(Error, Debug)]
pub enum BillingError {
    /// Customer not found
    #[error("customer not found")]
    CustomerNotFound,

    /// Subscription not found
    #[error("subscription not found")]
    SubscriptionNotFound,

    /// Invalid tier
    #[error("invalid tier")]
    InvalidTier,

    /// Payment failed
    #[error("payment failed: {0}")]
    PaymentFailed(String),

    /// Not implemented
    #[error("not implemented")]
    NotImplemented,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}
