//! Configuration for the Billing API service.

use argus_billing_core::BillingConfig;
use std::time::Duration;

/// Billing API configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP server port
    pub http_port: u16,
    /// gRPC server port
    pub grpc_port: u16,
    /// Database URL
    pub database_url: String,
    /// Billing core configuration
    pub billing: BillingConfig,
    /// Request timeout
    pub request_timeout: Duration,
    /// Metrics enabled
    pub metrics_enabled: bool,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        // Database
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ConfigError::Missing("DATABASE_URL"))?;

        // Server ports
        let http_port = std::env::var("HTTP_PORT")
            .unwrap_or_else(|_| "8081".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("HTTP_PORT"))?;

        let grpc_port = std::env::var("GRPC_PORT")
            .unwrap_or_else(|_| "50052".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("GRPC_PORT"))?;

        // Stripe configuration
        let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY")
            .map_err(|_| ConfigError::Missing("STRIPE_SECRET_KEY"))?;

        let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
            .map_err(|_| ConfigError::Missing("STRIPE_WEBHOOK_SECRET"))?;

        // Default URLs for checkout/portal
        let default_success_url = std::env::var("BILLING_SUCCESS_URL")
            .unwrap_or_else(|_| "https://app.example.com/billing/success".to_string());

        let default_cancel_url = std::env::var("BILLING_CANCEL_URL")
            .unwrap_or_else(|_| "https://app.example.com/billing/cancel".to_string());

        // Request timeout
        let request_timeout_secs: u64 = std::env::var("REQUEST_TIMEOUT_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("REQUEST_TIMEOUT_SECS"))?;

        // Metrics
        let metrics_enabled = std::env::var("METRICS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        // Build billing config
        let billing = BillingConfig::new(&stripe_secret_key, &stripe_webhook_secret)
            .with_urls(&default_success_url, &default_cancel_url);

        Ok(Self {
            http_port,
            grpc_port,
            database_url,
            billing,
            request_timeout: Duration::from_secs(request_timeout_secs),
            metrics_enabled,
        })
    }
}

/// Configuration error
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(&'static str),

    #[error("Invalid value for environment variable: {0}")]
    Invalid(&'static str),
}
