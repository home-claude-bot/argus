//! Auth service

use argus_types::{Tier, UserId};

/// Authentication service
pub struct AuthService {
    // TODO: Add Cognito client, database, etc.
}

impl AuthService {
    /// Create a new auth service
    pub fn new() -> Self {
        Self {}
    }

    /// Validate a token
    pub async fn validate_token(&self, _token: &str) -> Result<TokenClaims, AuthError> {
        // TODO: Implement token validation
        Err(AuthError::NotImplemented)
    }

    /// Get user tier
    pub async fn get_user_tier(&self, _user_id: &UserId) -> Result<Tier, AuthError> {
        // TODO: Implement tier lookup
        Err(AuthError::NotImplemented)
    }

    /// Check entitlement
    pub async fn check_entitlement(
        &self,
        _user_id: &UserId,
        _feature: &str,
    ) -> Result<bool, AuthError> {
        // TODO: Implement entitlement check
        Err(AuthError::NotImplemented)
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}

/// Token claims
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// User ID
    pub sub: UserId,
    /// User email
    pub email: String,
    /// User tier
    pub tier: Tier,
}

use crate::AuthError;
