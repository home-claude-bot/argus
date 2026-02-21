//! Client configuration
//!
//! Configuration options for connecting to Argus services.
//!
//! # Security Note
//!
//! The [`ClientConfig`] struct intentionally hides bearer tokens from debug
//! output to prevent accidental credential leakage in logs.
//!
//! # TLS Configuration
//!
//! TLS is enabled by default for `https://` endpoints. For custom certificate
//! authorities or client certificates, use [`TlsConfig`].

use std::fmt;
use std::path::PathBuf;
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

    /// TLS configuration for custom certificates
    pub(crate) tls_config: Option<TlsConfig>,
}

/// Source for loading credentials (certificates, keys, tokens).
///
/// This enum supports multiple credential sources with a path toward
/// HashiCorp Vault integration.
///
/// # Example
///
/// ```
/// use argus_client::CredentialSource;
///
/// // Load from file
/// let file_source = CredentialSource::file("/etc/ssl/ca.pem");
///
/// // Load from environment variable
/// let env_source = CredentialSource::env("CA_CERT_PEM");
///
/// // Load from Vault (requires vault feature)
/// let vault_source = CredentialSource::vault("secret/data/certs", "ca_cert");
/// ```
#[derive(Debug, Clone)]
pub enum CredentialSource {
    /// Load credential from a file path.
    File(PathBuf),

    /// Load credential from an environment variable.
    Env(String),

    /// Load credential directly from PEM data.
    Pem(Vec<u8>),

    /// Load credential from HashiCorp Vault.
    ///
    /// Requires a separate Vault client to be configured.
    /// The first string is the secret path, the second is the key within the secret.
    ///
    /// # Future Integration
    ///
    /// When Vault is integrated, this will automatically fetch credentials
    /// using the Vault agent or API.
    Vault {
        /// Vault secret path (e.g., "secret/data/argus/certs")
        path: String,
        /// Key within the secret (e.g., "ca_cert")
        key: String,
    },
}

impl CredentialSource {
    /// Create a file credential source.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Create an environment variable credential source.
    #[must_use]
    pub fn env(var: impl Into<String>) -> Self {
        Self::Env(var.into())
    }

    /// Create a PEM data credential source.
    #[must_use]
    pub fn pem(data: impl Into<Vec<u8>>) -> Self {
        Self::Pem(data.into())
    }

    /// Create a Vault credential source.
    ///
    /// # Arguments
    ///
    /// * `path` - Vault secret path (e.g., "secret/data/argus/certs")
    /// * `key` - Key within the secret (e.g., "ca_cert")
    #[must_use]
    pub fn vault(path: impl Into<String>, key: impl Into<String>) -> Self {
        Self::Vault {
            path: path.into(),
            key: key.into(),
        }
    }

    /// Load the credential data.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be loaded.
    ///
    /// # Vault Support
    ///
    /// Currently, Vault sources return an error indicating Vault is not configured.
    /// When Vault integration is added, this will automatically fetch from Vault.
    pub fn load(&self) -> Result<Vec<u8>, ConfigError> {
        match self {
            Self::File(path) => std::fs::read(path).map_err(|e| {
                ConfigError::CredentialLoad(format!(
                    "failed to read credential from {}: {e}",
                    path.display()
                ))
            }),
            Self::Env(var) => std::env::var(var)
                .map(std::string::String::into_bytes)
                .map_err(|_| {
                    ConfigError::CredentialLoad(format!(
                        "environment variable {var} not set"
                    ))
                }),
            Self::Pem(data) => Ok(data.clone()),
            Self::Vault { path, key } => {
                // TODO: Implement Vault integration
                // This will require a Vault client configuration
                Err(ConfigError::CredentialLoad(format!(
                    "Vault integration not yet implemented (path: {path}, key: {key}). \
                     Configure VAULT_ADDR and authenticate first."
                )))
            }
        }
    }
}

/// TLS configuration for secure connections.
///
/// Use this when you need custom certificate authorities, client certificates,
/// or other TLS customizations beyond the system defaults.
///
/// # Security Warning
///
/// Setting `danger_accept_invalid_certs` to `true` disables certificate
/// validation. This should **ONLY** be used for development/testing with
/// self-signed certificates. **NEVER** use this in production.
///
/// # Credential Sources
///
/// Credentials can be loaded from multiple sources:
/// - Files (paths to PEM files)
/// - Environment variables
/// - Direct PEM data
/// - HashiCorp Vault (future integration)
///
/// # Example
///
/// ```
/// use argus_client::{TlsConfig, CredentialSource};
/// use std::path::PathBuf;
///
/// // Use a custom CA certificate from file
/// let tls = TlsConfig::new()
///     .with_ca_cert_path(PathBuf::from("/path/to/ca.pem"));
///
/// // Use CA cert from Vault (future)
/// let vault_tls = TlsConfig::new()
///     .with_ca_cert_source(CredentialSource::vault(
///         "secret/data/argus/certs",
///         "ca_cert"
///     ));
///
/// // For development with self-signed certs (DANGEROUS)
/// let dev_tls = TlsConfig::new()
///     .danger_accept_invalid_certs();
/// ```
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Path to CA certificate file (PEM format)
    pub(crate) ca_cert_path: Option<PathBuf>,

    /// CA certificate data (PEM format)
    pub(crate) ca_cert_pem: Option<Vec<u8>>,

    /// Path to client certificate file (PEM format) for mTLS
    pub(crate) client_cert_path: Option<PathBuf>,

    /// Client certificate data (PEM format) for mTLS
    pub(crate) client_cert_pem: Option<Vec<u8>>,

    /// Path to client private key file (PEM format) for mTLS
    pub(crate) client_key_path: Option<PathBuf>,

    /// Client private key data (PEM format) for mTLS
    pub(crate) client_key_pem: Option<Vec<u8>>,

    /// Server name for SNI (defaults to endpoint hostname)
    pub(crate) server_name: Option<String>,

    /// Skip certificate verification (DANGEROUS - development only)
    pub(crate) accept_invalid_certs: bool,

    /// CA certificate source (for Vault/unified credential loading)
    pub(crate) ca_cert_source: Option<CredentialSource>,

    /// Client certificate source (for Vault/unified credential loading)
    pub(crate) client_cert_source: Option<CredentialSource>,

    /// Client key source (for Vault/unified credential loading)
    pub(crate) client_key_source: Option<CredentialSource>,
}

impl TlsConfig {
    /// Create a new TLS configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set CA certificate from a credential source.
    ///
    /// This supports files, environment variables, and Vault.
    #[must_use]
    pub fn with_ca_cert_source(mut self, source: CredentialSource) -> Self {
        self.ca_cert_source = Some(source);
        self
    }

    /// Set client certificate from a credential source for mTLS.
    ///
    /// This supports files, environment variables, and Vault.
    #[must_use]
    pub fn with_client_cert_source(mut self, source: CredentialSource) -> Self {
        self.client_cert_source = Some(source);
        self
    }

    /// Set client key from a credential source for mTLS.
    ///
    /// This supports files, environment variables, and Vault.
    #[must_use]
    pub fn with_client_key_source(mut self, source: CredentialSource) -> Self {
        self.client_key_source = Some(source);
        self
    }

    /// Set the path to a CA certificate file (PEM format).
    ///
    /// Use this for custom certificate authorities not in the system store.
    #[must_use]
    pub fn with_ca_cert_path(mut self, path: PathBuf) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    /// Set CA certificate data directly (PEM format).
    #[must_use]
    pub fn with_ca_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.ca_cert_pem = Some(pem);
        self
    }

    /// Set the path to a client certificate file (PEM format) for mTLS.
    #[must_use]
    pub fn with_client_cert_path(mut self, path: PathBuf) -> Self {
        self.client_cert_path = Some(path);
        self
    }

    /// Set client certificate data directly (PEM format) for mTLS.
    #[must_use]
    pub fn with_client_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.client_cert_pem = Some(pem);
        self
    }

    /// Set the path to a client private key file (PEM format) for mTLS.
    #[must_use]
    pub fn with_client_key_path(mut self, path: PathBuf) -> Self {
        self.client_key_path = Some(path);
        self
    }

    /// Set client private key data directly (PEM format) for mTLS.
    #[must_use]
    pub fn with_client_key_pem(mut self, pem: Vec<u8>) -> Self {
        self.client_key_pem = Some(pem);
        self
    }

    /// Set the server name for SNI verification.
    ///
    /// This overrides the hostname extracted from the endpoint URL.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// **DANGEROUS**: Accept invalid certificates.
    ///
    /// This disables certificate verification. Only use for development
    /// with self-signed certificates.
    ///
    /// # Security Warning
    ///
    /// This makes the connection vulnerable to man-in-the-middle attacks.
    /// **NEVER** use this in production.
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.accept_invalid_certs = true;
        self
    }

    /// Check if this config has custom CA certificate.
    #[must_use]
    pub fn has_ca_cert(&self) -> bool {
        self.ca_cert_path.is_some() || self.ca_cert_pem.is_some()
    }

    /// Check if this config has client certificate for mTLS (legacy paths/pem).
    #[must_use]
    pub fn has_client_cert(&self) -> bool {
        (self.client_cert_path.is_some() || self.client_cert_pem.is_some())
            && (self.client_key_path.is_some() || self.client_key_pem.is_some())
    }

    /// Check if this config has client certificate via credential sources.
    #[must_use]
    pub fn has_client_cert_source(&self) -> bool {
        self.client_cert_source.is_some() && self.client_key_source.is_some()
    }

    /// Load TLS configuration from environment variables.
    ///
    /// Reads from:
    /// - `ARGUS_CA_CERT`: CA certificate PEM data (or path if prefixed with `file:`)
    /// - `ARGUS_CLIENT_CERT`: Client certificate PEM data (or path if prefixed with `file:`)
    /// - `ARGUS_CLIENT_KEY`: Client key PEM data (or path if prefixed with `file:`)
    /// - `ARGUS_TLS_SERVER_NAME`: Override server name for SNI
    /// - `ARGUS_TLS_INSECURE`: Set to "true" to skip cert verification (DANGEROUS)
    ///
    /// # Example
    ///
    /// ```bash
    /// export ARGUS_CA_CERT="file:/etc/ssl/certs/ca.pem"
    /// export ARGUS_CLIENT_CERT="-----BEGIN CERTIFICATE-----\n..."
    /// export ARGUS_TLS_SERVER_NAME="argus.internal"
    /// ```
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::new();

        // Load CA certificate
        if let Ok(ca_cert) = std::env::var("ARGUS_CA_CERT") {
            if let Some(path) = ca_cert.strip_prefix("file:") {
                config.ca_cert_path = Some(PathBuf::from(path));
            } else {
                config.ca_cert_pem = Some(ca_cert.into_bytes());
            }
        }

        // Load client certificate
        if let Ok(client_cert) = std::env::var("ARGUS_CLIENT_CERT") {
            if let Some(path) = client_cert.strip_prefix("file:") {
                config.client_cert_path = Some(PathBuf::from(path));
            } else {
                config.client_cert_pem = Some(client_cert.into_bytes());
            }
        }

        // Load client key
        if let Ok(client_key) = std::env::var("ARGUS_CLIENT_KEY") {
            if let Some(path) = client_key.strip_prefix("file:") {
                config.client_key_path = Some(PathBuf::from(path));
            } else {
                config.client_key_pem = Some(client_key.into_bytes());
            }
        }

        // Server name override
        if let Ok(server_name) = std::env::var("ARGUS_TLS_SERVER_NAME") {
            config.server_name = Some(server_name);
        }

        // Insecure mode (DANGEROUS)
        if let Ok(insecure) = std::env::var("ARGUS_TLS_INSECURE") {
            config.accept_invalid_certs = insecure.eq_ignore_ascii_case("true")
                || insecure == "1";
        }

        config
    }
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
            .field("tls_config", &self.tls_config)
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
            tls_config: None,
        }
    }

    /// Get the TLS configuration.
    #[must_use]
    pub fn tls_config(&self) -> Option<&TlsConfig> {
        self.tls_config.as_ref()
    }

    /// Check if TLS is enabled.
    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.tls_enabled
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
    tls_config: Option<TlsConfig>,
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

    /// Set TLS configuration for custom certificates.
    ///
    /// This automatically enables TLS.
    #[must_use]
    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self.tls_enabled = Some(true);
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
            tls_config: self.tls_config,
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

    /// Failed to load credential from source.
    #[error("credential load error: {0}")]
    CredentialLoad(String),
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

    #[test]
    fn test_credential_source_pem() {
        let source = CredentialSource::pem(b"-----BEGIN CERTIFICATE-----".to_vec());
        let data = source.load().unwrap();
        assert_eq!(data, b"-----BEGIN CERTIFICATE-----");
    }

    #[test]
    fn test_credential_source_env() {
        std::env::set_var("TEST_ARGUS_CERT", "test-cert-data");
        let source = CredentialSource::env("TEST_ARGUS_CERT");
        let data = source.load().unwrap();
        assert_eq!(data, b"test-cert-data");
        std::env::remove_var("TEST_ARGUS_CERT");
    }

    #[test]
    fn test_credential_source_env_missing() {
        let source = CredentialSource::env("NONEXISTENT_VAR_12345");
        let result = source.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_source_vault_not_implemented() {
        let source = CredentialSource::vault("secret/data/certs", "ca_cert");
        let result = source.load();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Vault integration not yet implemented"));
    }

    #[test]
    fn test_tls_config_with_credential_sources() {
        let tls = TlsConfig::new()
            .with_ca_cert_source(CredentialSource::vault("secret/data/certs", "ca"))
            .with_client_cert_source(CredentialSource::vault("secret/data/certs", "client_cert"))
            .with_client_key_source(CredentialSource::vault("secret/data/certs", "client_key"));

        assert!(tls.ca_cert_source.is_some());
        assert!(tls.has_client_cert_source());
    }
}
