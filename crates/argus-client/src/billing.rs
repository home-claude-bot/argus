//! Billing client

use argus_types::{Subscription, Tier, UserId};

use crate::{ClientConfig, ClientError};

/// Billing client
pub struct BillingClient {
    _config: ClientConfig,
}

impl BillingClient {
    /// Create a new billing client
    pub fn new(config: ClientConfig) -> Self {
        Self { _config: config }
    }

    /// Get subscription
    pub async fn get_subscription(&self, _user_id: &UserId) -> Result<Subscription, ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }

    /// Record usage
    pub async fn record_usage(
        &self,
        _user_id: &UserId,
        _metric: &str,
        _quantity: i64,
    ) -> Result<(), ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }

    /// Create checkout session
    pub async fn create_checkout(
        &self,
        _user_id: &UserId,
        _tier: Tier,
    ) -> Result<String, ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }
}
