//! Payment provider abstraction

use async_trait::async_trait;

use argus_types::Tier;

use crate::{BillingError, CheckoutSession};

/// Payment provider trait
///
/// Abstracts payment processing to allow different providers (Stripe, etc.)
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Create a checkout session
    async fn create_checkout_session(
        &self,
        customer_id: &str,
        tier: Tier,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError>;

    /// Create a customer portal session
    async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String, BillingError>;

    /// Cancel a subscription
    async fn cancel_subscription(&self, subscription_id: &str) -> Result<(), BillingError>;
}
