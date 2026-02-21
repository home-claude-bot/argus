//! gRPC channel management
//!
//! Provides channel factory, connection pooling, and unified client access.
//!
//! # Connection Pooling
//!
//! The [`ArgusClient`] provides a unified interface that shares gRPC channels
//! across all service clients. This is more efficient than creating separate
//! connections for each client.
//!
//! # TLS Support
//!
//! TLS is automatically configured based on the endpoint URL scheme (`https://`).
//! For custom certificate authorities or client certificates, use [`TlsConfig`].
//!
//! # Example
//!
//! ```ignore
//! use argus_client::{ArgusClient, ClientConfig};
//!
//! let config = ClientConfig::builder()
//!     .endpoint("https://api.example.com")
//!     .bearer_token("token")
//!     .build()?;
//!
//! let client = ArgusClient::connect(config).await?;
//!
//! // All clients share the same underlying connections
//! let user = client.identity().get_user(&user_id).await?;
//! let subscription = client.billing().get_subscription(&user_id).await?;
//! ```

use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::instrument;

use crate::config::TlsConfig;
use crate::{AuthClient, BillingClient, ClientConfig, ClientError, IdentityClient};

/// Extract domain name from an endpoint URL for TLS SNI.
fn extract_domain(url: &str) -> Option<String> {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Take everything before the port or path
    let domain = without_scheme
        .split(':')
        .next()
        .and_then(|s| s.split('/').next())
        .map(String::from);

    domain.filter(|d| !d.is_empty())
}

/// Factory for creating and managing gRPC channels.
///
/// Channels are lazily connected and can be shared across multiple clients.
#[derive(Debug, Clone)]
pub struct ChannelFactory {
    config: Arc<ClientConfig>,
}

impl ChannelFactory {
    /// Create a new channel factory with the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Create a channel for the auth service.
    #[instrument(skip(self), level = "debug")]
    pub async fn auth_channel(&self) -> Result<Channel, ClientError> {
        self.create_channel(&self.config.auth_endpoint).await
    }

    /// Create a channel for the billing service.
    #[instrument(skip(self), level = "debug")]
    pub async fn billing_channel(&self) -> Result<Channel, ClientError> {
        self.create_channel(&self.config.billing_endpoint).await
    }

    /// Create a channel for the identity service.
    #[instrument(skip(self), level = "debug")]
    pub async fn identity_channel(&self) -> Result<Channel, ClientError> {
        self.create_channel(&self.config.identity_endpoint).await
    }

    /// Create a channel for the given endpoint.
    async fn create_channel(&self, endpoint_url: &str) -> Result<Channel, ClientError> {
        let mut endpoint = Endpoint::from_shared(endpoint_url.to_string())
            .map_err(|e| ClientError::connection(format!("invalid endpoint: {e}"), false))?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout);

        // Configure TLS if enabled
        if self.config.tls_enabled {
            let tls_config = self.build_tls_config(endpoint_url)?;
            endpoint = endpoint.tls_config(tls_config).map_err(|e| {
                ClientError::connection(format!("TLS configuration error: {e}"), false)
            })?;
        }

        let channel = endpoint.connect_lazy();

        tracing::debug!(
            endpoint = %endpoint_url,
            tls_enabled = self.config.tls_enabled,
            "created lazy channel"
        );

        Ok(channel)
    }

    /// Build TLS configuration from client config.
    fn build_tls_config(&self, endpoint_url: &str) -> Result<ClientTlsConfig, ClientError> {
        let mut tls_config = ClientTlsConfig::new();

        // Extract domain from endpoint for SNI
        if let Some(domain) = extract_domain(endpoint_url) {
            tls_config = tls_config.domain_name(domain);
        }

        // Apply custom TLS settings if provided
        if let Some(custom_tls) = &self.config.tls_config {
            // Override domain name if specified
            if let Some(server_name) = &custom_tls.server_name {
                tls_config = tls_config.domain_name(server_name);
            }

            // Add custom CA certificate (check credential source first)
            let ca_pem = if let Some(source) = &custom_tls.ca_cert_source {
                Some(source.load().map_err(|e| {
                    ClientError::connection(format!("failed to load CA certificate: {e}"), false)
                })?)
            } else if let Some(pem) = &custom_tls.ca_cert_pem {
                Some(pem.clone())
            } else if let Some(path) = &custom_tls.ca_cert_path {
                Some(std::fs::read(path).map_err(|e| {
                    ClientError::connection(
                        format!("failed to read CA certificate from {}: {e}", path.display()),
                        false,
                    )
                })?)
            } else {
                None
            };

            if let Some(ca_pem) = ca_pem {
                let ca_cert = tonic::transport::Certificate::from_pem(&ca_pem);
                tls_config = tls_config.ca_certificate(ca_cert);
            }

            // Add client certificate for mTLS
            if custom_tls.has_client_cert() || custom_tls.has_client_cert_source() {
                let (cert_pem, key_pem) = Self::load_client_cert(custom_tls)?;
                let identity = tonic::transport::Identity::from_pem(&cert_pem, &key_pem);
                tls_config = tls_config.identity(identity);
            }

            // Note: tonic's ClientTlsConfig doesn't have a direct method for
            // accepting invalid certs. This would require using rustls directly.
            // For now, we log a warning if this is requested.
            if custom_tls.accept_invalid_certs {
                tracing::warn!(
                    "accept_invalid_certs is set, but tonic doesn't support this directly. \
                     Consider using a custom rustls config or adding the CA to the trust store."
                );
            }
        }

        Ok(tls_config)
    }

    /// Load client certificate and key for mTLS.
    fn load_client_cert(tls_config: &TlsConfig) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        // Load certificate (credential source first, then legacy options)
        let cert_pem = if let Some(source) = &tls_config.client_cert_source {
            source.load().map_err(|e| {
                ClientError::connection(format!("failed to load client certificate: {e}"), false)
            })?
        } else if let Some(pem) = &tls_config.client_cert_pem {
            pem.clone()
        } else if let Some(path) = &tls_config.client_cert_path {
            std::fs::read(path).map_err(|e| {
                ClientError::connection(
                    format!(
                        "failed to read client certificate from {}: {e}",
                        path.display()
                    ),
                    false,
                )
            })?
        } else {
            return Err(ClientError::connection("missing client certificate", false));
        };

        // Load key (credential source first, then legacy options)
        let key_pem = if let Some(source) = &tls_config.client_key_source {
            source.load().map_err(|e| {
                ClientError::connection(format!("failed to load client key: {e}"), false)
            })?
        } else if let Some(pem) = &tls_config.client_key_pem {
            pem.clone()
        } else if let Some(path) = &tls_config.client_key_path {
            std::fs::read(path).map_err(|e| {
                ClientError::connection(
                    format!("failed to read client key from {}: {e}", path.display()),
                    false,
                )
            })?
        } else {
            return Err(ClientError::connection("missing client key", false));
        };

        Ok((cert_pem, key_pem))
    }

    /// Get the underlying configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

/// Wrapper for a gRPC channel with retry and interceptor support.
#[derive(Debug, Clone)]
pub struct ManagedChannel {
    channel: Channel,
    config: Arc<ClientConfig>,
}

impl ManagedChannel {
    /// Create a managed channel from a raw channel.
    pub fn new(channel: Channel, config: Arc<ClientConfig>) -> Self {
        Self { channel, config }
    }

    /// Get the underlying channel.
    pub fn inner(&self) -> Channel {
        self.channel.clone()
    }

    /// Get the configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

// =============================================================================
// Unified Client with Connection Pooling
// =============================================================================

/// Unified Argus client with shared connection pooling.
///
/// This client manages shared gRPC channels across all service clients,
/// providing efficient connection reuse and a convenient unified API.
///
/// # Example
///
/// ```ignore
/// use argus_client::{ArgusClient, ClientConfig};
///
/// let config = ClientConfig::builder()
///     .endpoint("https://api.example.com")
///     .build()?;
///
/// let client = ArgusClient::connect(config).await?;
///
/// // Access individual service clients
/// let mut auth = client.auth().await;
/// let token_info = auth.validate_token("jwt...").await?;
/// ```
#[derive(Clone)]
pub struct ArgusClient {
    config: Arc<ClientConfig>,
    auth_channel: Channel,
    billing_channel: Channel,
    identity_channel: Channel,
}

impl std::fmt::Debug for ArgusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArgusClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ArgusClient {
    /// Connect to all Argus services.
    ///
    /// Creates lazy connections to auth, billing, and identity services.
    /// Actual connections are established on first use.
    #[instrument(skip(config), level = "info")]
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let factory = ChannelFactory::new(config);

        let auth_channel = factory.auth_channel().await?;
        let billing_channel = factory.billing_channel().await?;
        let identity_channel = factory.identity_channel().await?;

        tracing::info!("ArgusClient initialized with lazy connections");

        Ok(Self {
            config: Arc::new(factory.config().clone()),
            auth_channel,
            billing_channel,
            identity_channel,
        })
    }

    /// Get an auth service client.
    ///
    /// The returned client shares the underlying connection with other clients.
    #[must_use]
    pub fn auth(&self) -> AuthClient {
        AuthClient::from_channel(self.auth_channel.clone(), (*self.config).clone())
    }

    /// Get a billing service client.
    ///
    /// The returned client shares the underlying connection with other clients.
    #[must_use]
    pub fn billing(&self) -> BillingClient {
        BillingClient::from_channel(self.billing_channel.clone(), (*self.config).clone())
    }

    /// Get an identity service client.
    ///
    /// The returned client shares the underlying connection with other clients.
    #[must_use]
    pub fn identity(&self) -> IdentityClient {
        IdentityClient::from_channel(self.identity_channel.clone(), (*self.config).clone())
    }

    /// Get the client configuration.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

/// Thread-safe wrapper for ArgusClient that allows mutable access.
///
/// Use this when you need to share the client across multiple tasks
/// and call methods that require `&mut self`.
#[derive(Clone)]
pub struct SharedArgusClient {
    inner: Arc<RwLock<ArgusClient>>,
}

impl SharedArgusClient {
    /// Create a shared client from an existing client.
    pub fn new(client: ArgusClient) -> Self {
        Self {
            inner: Arc::new(RwLock::new(client)),
        }
    }

    /// Connect and create a shared client.
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let client = ArgusClient::connect(config).await?;
        Ok(Self::new(client))
    }

    /// Get a read lock on the client.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, ArgusClient> {
        self.inner.read().await
    }

    /// Get a write lock on the client.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, ArgusClient> {
        self.inner.write().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_factory_creation() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .build()
            .unwrap();

        let factory = ChannelFactory::new(config);
        assert_eq!(factory.config().auth_endpoint(), "http://localhost:50051");
    }

    #[tokio::test]
    async fn test_lazy_channel_creation() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .build()
            .unwrap();

        let factory = ChannelFactory::new(config);

        // Lazy channel should be created without connecting
        let channel = factory.auth_channel().await;
        assert!(channel.is_ok());
    }

    #[tokio::test]
    async fn test_unified_client_connection() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .build()
            .unwrap();

        // Should create lazy connections without actually connecting
        let client = ArgusClient::connect(config).await;
        assert!(client.is_ok());

        let client = client.unwrap();

        // Should be able to get service clients
        let _auth = client.auth();
        let _billing = client.billing();
        let _identity = client.identity();
    }

    #[tokio::test]
    async fn test_shared_client() {
        let config = ClientConfig::builder()
            .endpoint("http://localhost:50051")
            .build()
            .unwrap();

        let shared = SharedArgusClient::connect(config).await.unwrap();

        // Should be able to clone and access from multiple handles
        let shared2 = shared.clone();

        let client1 = shared.read().await;
        drop(client1);

        let client2 = shared2.read().await;
        assert_eq!(client2.config().auth_endpoint(), "http://localhost:50051");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://api.example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://api.example.com:443"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://api.example.com:443/path"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://localhost:8080"),
            Some("localhost".to_string())
        );
        assert_eq!(
            extract_domain("api.example.com"),
            Some("api.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_tls_channel_creation() {
        // Test with TLS enabled (https endpoint)
        let config = ClientConfig::builder()
            .endpoint("https://localhost:50051")
            .build()
            .unwrap();

        assert!(config.tls_enabled());

        let factory = ChannelFactory::new(config);
        // Should create channel without error (lazy connect)
        let channel = factory.auth_channel().await;
        assert!(channel.is_ok());
    }

    #[test]
    fn test_tls_config_builder() {
        use crate::TlsConfig;
        use std::path::PathBuf;

        let tls = TlsConfig::new()
            .with_ca_cert_path(PathBuf::from("/etc/ssl/ca.pem"))
            .with_server_name("argus.internal");

        assert!(tls.has_ca_cert());
        assert!(!tls.has_client_cert());
        assert_eq!(tls.server_name, Some("argus.internal".to_string()));
    }

    #[test]
    fn test_tls_config_mtls() {
        use crate::TlsConfig;

        let tls = TlsConfig::new()
            .with_client_cert_pem(b"-----BEGIN CERTIFICATE-----".to_vec())
            .with_client_key_pem(b"-----BEGIN PRIVATE KEY-----".to_vec());

        assert!(tls.has_client_cert());
    }
}
