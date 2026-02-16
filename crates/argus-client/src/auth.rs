//! Auth client

use argus_types::{Tier, UserId};

use crate::{ClientConfig, ClientError};

/// Auth client
pub struct AuthClient {
    _config: ClientConfig,
}

impl AuthClient {
    /// Create a new auth client
    pub fn new(config: ClientConfig) -> Self {
        Self { _config: config }
    }

    /// Validate a token
    pub async fn validate_token(&self, _token: &str) -> Result<TokenInfo, ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }

    /// Get user tier
    pub async fn get_user_tier(&self, _user_id: &UserId) -> Result<Tier, ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }

    /// Check entitlement
    pub async fn check_entitlement(
        &self,
        _user_id: &UserId,
        _feature: &str,
    ) -> Result<bool, ClientError> {
        // TODO: Implement gRPC call
        Err(ClientError::NotImplemented)
    }
}

/// Token information
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// User ID
    pub user_id: UserId,
    /// User tier
    pub tier: Tier,
}
