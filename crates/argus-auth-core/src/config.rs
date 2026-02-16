//! Configuration types for auth service

use std::time::Duration;

/// Auth service configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Cognito user pool ID (e.g., us-east-1_xxxxx)
    pub cognito_pool_id: String,
    /// AWS region (e.g., us-east-1)
    pub aws_region: String,
    /// Cognito app client ID
    pub cognito_client_id: String,
    /// HMAC secret for session signing (must match CloudFront function)
    pub session_secret: String,
    /// Session duration
    pub session_duration: Duration,
    /// JWKS cache duration
    pub jwks_cache_duration: Duration,
}

impl AuthConfig {
    /// Create a new auth config
    pub fn new(
        cognito_pool_id: impl Into<String>,
        aws_region: impl Into<String>,
        cognito_client_id: impl Into<String>,
        session_secret: impl Into<String>,
    ) -> Self {
        Self {
            cognito_pool_id: cognito_pool_id.into(),
            aws_region: aws_region.into(),
            cognito_client_id: cognito_client_id.into(),
            session_secret: session_secret.into(),
            session_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            jwks_cache_duration: Duration::from_secs(60 * 60),   // 1 hour
        }
    }

    /// Get the Cognito issuer URL
    pub fn cognito_issuer(&self) -> String {
        format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            self.aws_region, self.cognito_pool_id
        )
    }

    /// Get the JWKS URL
    pub fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.cognito_issuer())
    }

    /// Set session duration
    pub fn with_session_duration(mut self, duration: Duration) -> Self {
        self.session_duration = duration;
        self
    }

    /// Set JWKS cache duration
    pub fn with_jwks_cache_duration(mut self, duration: Duration) -> Self {
        self.jwks_cache_duration = duration;
        self
    }
}
