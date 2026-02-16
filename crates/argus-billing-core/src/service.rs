//! Billing service

use argus_types::{Subscription, Tier, UserId};

use crate::BillingError;

/// Billing service
pub struct BillingService {
    // TODO: Add Stripe client, database, etc.
}

impl BillingService {
    /// Create a new billing service
    pub fn new() -> Self {
        Self {}
    }

    /// Get subscription for a user
    pub async fn get_subscription(&self, _user_id: &UserId) -> Result<Subscription, BillingError> {
        // TODO: Implement subscription lookup
        Err(BillingError::NotImplemented)
    }

    /// Record usage
    pub async fn record_usage(
        &self,
        _user_id: &UserId,
        _metric: &str,
        _quantity: i64,
    ) -> Result<UsageResult, BillingError> {
        // TODO: Implement usage recording
        Err(BillingError::NotImplemented)
    }

    /// Create checkout session
    pub async fn create_checkout(
        &self,
        _user_id: &UserId,
        _tier: Tier,
    ) -> Result<CheckoutSession, BillingError> {
        // TODO: Implement checkout creation
        Err(BillingError::NotImplemented)
    }
}

impl Default for BillingService {
    fn default() -> Self {
        Self::new()
    }
}

/// Usage recording result
#[derive(Debug, Clone)]
pub struct UsageResult {
    /// Whether the usage was recorded successfully
    pub success: bool,
    /// Total usage for the period
    pub total_usage: i64,
}

/// Checkout session
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    /// Session ID
    pub id: String,
    /// Checkout URL
    pub url: String,
}
