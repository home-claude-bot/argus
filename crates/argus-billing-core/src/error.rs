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

    /// Invoice not found
    #[error("invoice not found")]
    InvoiceNotFound,

    /// User not found
    #[error("user not found")]
    UserNotFound,

    /// Invalid tier
    #[error("invalid tier")]
    InvalidTier,

    /// Payment failed
    #[error("payment failed: {0}")]
    PaymentFailed(String),

    /// Payment provider error
    #[error("provider error: {0}")]
    ProviderError(String),

    /// Webhook verification or processing error
    #[error("webhook error: {0}")]
    WebhookError(String),

    /// Usage limit exceeded
    #[error("usage limit exceeded: {current} / {limit}")]
    UsageLimitExceeded {
        /// Current usage
        current: i64,
        /// Usage limit
        limit: i64,
    },

    /// Database error
    #[error("database error: {0}")]
    Database(#[from] argus_db::DbError),

    /// Not implemented
    #[error("not implemented")]
    NotImplemented,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl BillingError {
    /// Check if this is a not found error
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::CustomerNotFound
                | Self::SubscriptionNotFound
                | Self::InvoiceNotFound
                | Self::UserNotFound
        )
    }

    /// Check if this is a provider error
    pub fn is_provider_error(&self) -> bool {
        matches!(self, Self::ProviderError(_) | Self::PaymentFailed(_))
    }
}
