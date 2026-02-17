//! Configuration types for auth service

use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum secret length for HMAC-SHA256 (256 bits)
pub const MIN_SECRET_LENGTH: usize = 32;

/// Auth service configuration
#[derive(Clone)]
pub struct AuthConfig {
    /// Cognito user pool ID (e.g., us-east-1_xxxxx)
    pub cognito_pool_id: String,
    /// AWS region (e.g., us-east-1)
    pub aws_region: String,
    /// Cognito app client ID
    pub cognito_client_id: String,
    /// HMAC secret for session signing (must match CloudFront function)
    /// Stored as bytes to avoid accidental string operations
    session_secret: SecretBytes,
    /// Session duration
    pub session_duration: Duration,
    /// JWKS cache duration
    pub jwks_cache_duration: Duration,
    /// Override JWKS URL (for testing only)
    jwks_url_override: Option<String>,
}

/// Secret bytes wrapper that never exposes content in Debug/Display
///
/// # Security
///
/// - Contents are zeroed on drop to prevent secrets lingering in memory
/// - Debug impl shows only length, never content
/// - Clone creates a new zeroed copy
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Create from string slice (UTF-8 bytes)
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Get the secret bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED {} bytes])", self.0.len())
    }
}

impl AuthConfig {
    /// Create a new auth config
    ///
    /// # Panics
    /// Panics if session_secret is shorter than 32 bytes (256 bits).
    /// Use `try_new` for fallible construction.
    pub fn new(
        cognito_pool_id: impl Into<String>,
        aws_region: impl Into<String>,
        cognito_client_id: impl Into<String>,
        session_secret: impl AsRef<str>,
    ) -> Self {
        Self::try_new(
            cognito_pool_id,
            aws_region,
            cognito_client_id,
            session_secret,
        )
        .expect("session_secret must be at least 32 bytes")
    }

    /// Create a new auth config with validation
    ///
    /// Returns error if session_secret is shorter than 32 bytes.
    pub fn try_new(
        cognito_pool_id: impl Into<String>,
        aws_region: impl Into<String>,
        cognito_client_id: impl Into<String>,
        session_secret: impl AsRef<str>,
    ) -> Result<Self, ConfigError> {
        let secret = session_secret.as_ref();
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(ConfigError::SecretTooShort {
                actual: secret.len(),
                minimum: MIN_SECRET_LENGTH,
            });
        }

        Ok(Self {
            cognito_pool_id: cognito_pool_id.into(),
            aws_region: aws_region.into(),
            cognito_client_id: cognito_client_id.into(),
            session_secret: SecretBytes::from_string(secret),
            session_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            jwks_cache_duration: Duration::from_secs(60 * 60),   // 1 hour
            jwks_url_override: None,
        })
    }

    /// Get session secret bytes (for HMAC operations)
    #[inline]
    pub fn session_secret(&self) -> &[u8] {
        self.session_secret.as_bytes()
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
        self.jwks_url_override
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", self.cognito_issuer()))
    }

    /// Override the JWKS URL (for testing purposes only)
    ///
    /// This should only be used in integration tests to point to a mock JWKS server.
    /// In production, the JWKS URL is derived from the Cognito pool configuration.
    pub fn with_jwks_url_override(mut self, url: impl Into<String>) -> Self {
        self.jwks_url_override = Some(url.into());
        self
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

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("cognito_pool_id", &self.cognito_pool_id)
            .field("aws_region", &self.aws_region)
            .field("cognito_client_id", &self.cognito_client_id)
            .field("session_secret", &self.session_secret) // Uses SecretBytes Debug
            .field("session_duration", &self.session_duration)
            .field("jwks_cache_duration", &self.jwks_cache_duration)
            .field("jwks_url_override", &self.jwks_url_override)
            .finish()
    }
}

/// Configuration errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    /// Session secret is too short
    #[error("session secret too short: got {actual} bytes, need at least {minimum}")]
    SecretTooShort { actual: usize, minimum: usize },
}
