//! Client configuration
//!
//! Configuration options for connecting to Argus services.
//!
//! # Security Note
//!
//! The [`ClientConfig`] struct intentionally hides bearer tokens from debug
//! output to prevent accidental credential leakage in logs.

use std::fmt;
use std::time::Duration;

/// Default connection timeout
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default request timeout
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default retry attempts
const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default retry base delay
const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// Default retry max delay
const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

/// Client configuration for connecting to Argus services.
///
/// Use [`ClientConfig::builder()`] to create a configuration with custom settings.
///
/// # Security
///
/// The `Debug` implementation intentionally redacts the bearer token to prevent
/// accidental credential exposure in logs.
///
/// # Example
///
/// ```
/// use argus_client::ClientConfig;
/// use std::time::Duration;
///
/// let config = ClientConfig::builder()
///     .auth_endpoint("https://auth.example.com")
///     .billing_endpoint("https://billing.example.com")
///     .identity_endpoint("https://identity.example.com")
///     .request_timeout(Duration::from_secs(60))
///     .build()
///     .expect("valid config");
/// ```
#[derive(Clone)]
pub struct ClientConfig {
    /// Auth service endpoint URL
    pub(crate) auth_endpoint: String,

    /// Billing service endpoint URL
    pub(crate) billing_endpoint: String,

    /// Identity service endpoint URL
    pub(crate) identity_endpoint: String,

    /// Connection timeout
    pub(crate) connect_timeout: Duration,

    /// Request timeout
    pub(crate) request_timeout: Duration,

    /// Number of retry attempts for transient failures
    pub(crate) retry_attempts: u32,

    /// Base delay for exponential backoff
    pub(crate) retry_base_delay: Duration,

    /// Maximum delay between retries
    pub(crate) retry_max_delay: Duration,

    /// Bearer token for authentication (optional)
    pub(crate) bearer_token: Option<String>,

    /// Enable TLS (defaults to true for https:// endpoints)
    pub(crate) tls_enabled: bool,
}

// Manual Debug impl to redact bearer token
impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("auth_endpoint", &self.auth_endpoint)
            .field("billing_endpoint", &self.billing_endpoint)
            .field("identity_endpoint", &self.identity_endpoint)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("retry_attempts", &self.retry_attempts)
            .field("retry_base_delay", &self.retry_base_delay)
            .field("retry_max_delay", &self.retry_max_delay)
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "[REDACTED]"))
            .field("tls_enabled", &self.tls_enabled)
            .finish()
    }
}

impl ClientConfig {
    /// Create a configuration builder.
    #[must_use]
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }

    /// Create a simple configuration with default settings.
    ///
    /// For production use, prefer [`ClientConfig::builder()`].
    #[must_use]
    pub fn new(
        auth_endpoint: impl Into<String>,
        billing_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            auth_endpoint: auth_endpoint.into(),
            billing_endpoint: billing_endpoint.into(),
            identity_endpoint: String::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            retry_base_delay: DEFAULT_RETRY_BASE_DELAY,
            retry_max_delay: DEFAULT_RETRY_MAX_DELAY,
            bearer_token: None,
            tls_enabled: true,
        }
    }

    /// Get the auth service endpoint.
    #[must_use]
    pub fn auth_endpoint(&self) -> &str {
        &self.auth_endpoint
    }

    /// Get the billing service endpoint.
    #[must_use]
    pub fn billing_endpoint(&self) -> &str {
        &self.billing_endpoint
    }

    /// Get the identity service endpoint.
    #[must_use]
    pub fn identity_endpoint(&self) -> &str {
        &self.identity_endpoint
    }

    /// Get the request timeout.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Get the connect timeout.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Get the retry attempts.
    #[must_use]
    pub fn retry_attempts(&self) -> u32 {
        self.retry_attempts
    }

    /// Create a new config with a different bearer token.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }
}

/// Builder for [`ClientConfig`].
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    auth_endpoint: Option<String>,
    billing_endpoint: Option<String>,
    identity_endpoint: Option<String>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    retry_attempts: Option<u32>,
    retry_base_delay: Option<Duration>,
    retry_max_delay: Option<Duration>,
    bearer_token: Option<String>,
    tls_enabled: Option<bool>,
}

impl ClientConfigBuilder {
    /// Set the auth service endpoint.
    #[must_use]
    pub fn auth_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.auth_endpoint = Some(endpoint.into());
        self
    }

    /// Set the billing service endpoint.
    #[must_use]
    pub fn billing_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.billing_endpoint = Some(endpoint.into());
        self
    }

    /// Set the identity service endpoint.
    #[must_use]
    pub fn identity_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.identity_endpoint = Some(endpoint.into());
        self
    }

    /// Set all endpoints to the same URL (useful when services are co-located).
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let e = endpoint.into();
        self.auth_endpoint = Some(e.clone());
        self.billing_endpoint = Some(e.clone());
        self.identity_endpoint = Some(e);
        self
    }

    /// Set the connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Set the number of retry attempts.
    #[must_use]
    pub fn retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = Some(attempts);
        self
    }

    /// Set the base delay for exponential backoff.
    #[must_use]
    pub fn retry_base_delay(mut self, delay: Duration) -> Self {
        self.retry_base_delay = Some(delay);
        self
    }

    /// Set the maximum delay between retries.
    #[must_use]
    pub fn retry_max_delay(mut self, delay: Duration) -> Self {
        self.retry_max_delay = Some(delay);
        self
    }

    /// Set the bearer token for authentication.
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Enable or disable TLS.
    #[must_use]
    pub fn tls_enabled(mut self, enabled: bool) -> Self {
        self.tls_enabled = Some(enabled);
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required endpoints are not set.
    pub fn build(self) -> Result<ClientConfig, ConfigError> {
        let auth_endpoint = self.auth_endpoint
            .ok_or(ConfigError::MissingEndpoint("auth"))?;
        let billing_endpoint = self.billing_endpoint
            .ok_or(ConfigError::MissingEndpoint("billing"))?;
        let identity_endpoint = self.identity_endpoint
            .unwrap_or_else(|| auth_endpoint.clone());

        let tls_enabled = self.tls_enabled.unwrap_or_else(|| {
            auth_endpoint.starts_with("https://")
        });

        Ok(ClientConfig {
            auth_endpoint,
            billing_endpoint,
            identity_endpoint,
            connect_timeout: self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            request_timeout: self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            retry_attempts: self.retry_attempts.unwrap_or(DEFAULT_RETRY_ATTEMPTS),
            retry_base_delay: self.retry_base_delay.unwrap_or(DEFAULT_RETRY_BASE_DELAY),
            retry_max_delay: self.retry_max_delay.unwrap_or(DEFAULT_RETRY_MAX_DELAY),
            bearer_token: self.bearer_token,
            tls_enabled,
        })
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Required endpoint not provided.
    #[error("missing {0} endpoint")]
    MissingEndpoint(&'static str),

    /// Invalid endpoint URL.
    #[error("invalid endpoint URL: {0}")]
    InvalidEndpoint(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let config = ClientConfig::builder()
            .auth_endpoint("http://localhost:50051")
            .billing_endpoint("http://localhost:50052")
            .build()
            .unwrap();

        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(config.retry_attempts, DEFAULT_RETRY_ATTEMPTS);
    }

    #[test]
    fn test_builder_single_endpoint() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .build()
            .unwrap();

        assert_eq!(config.auth_endpoint, "http://localhost:50051");
        assert_eq!(config.billing_endpoint, "http://localhost:50051");
        assert_eq!(config.identity_endpoint, "http://localhost:50051");
    }

    #[test]
    fn test_builder_missing_endpoint() {
        let result = ClientConfig::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_with_bearer_token() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .bearer_token("test-token")
            .build()
            .unwrap();

        assert_eq!(config.bearer_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_bearer_token_redacted_in_debug() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .bearer_token("super-secret-token-12345")
            .build()
            .unwrap();

        let debug_output = format!("{:?}", config);

        // Token should be redacted
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret-token-12345"));
    }
}
