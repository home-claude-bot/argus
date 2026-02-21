//! gRPC channel management
//!
//! Provides channel factory and connection pooling for gRPC clients.

use std::sync::Arc;
use tonic::transport::{Channel, Endpoint};
use tracing::instrument;

use crate::{ClientConfig, ClientError};

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
        let endpoint = Endpoint::from_shared(endpoint_url.to_string())
            .map_err(|e| ClientError::connection(format!("invalid endpoint: {e}"), false))?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout);

        // Note: TLS configuration would be added here for production
        // For now, we rely on the endpoint URL scheme (https://)

        let channel = endpoint.connect_lazy();

        tracing::debug!(endpoint = %endpoint_url, "created lazy channel");

        Ok(channel)
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
}
