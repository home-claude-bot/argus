//! Configuration for the Auth API service.

use argus_auth_core::AuthConfig;
use std::time::Duration;

/// Auth API configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP server port
    pub http_port: u16,

    /// gRPC server port
    pub grpc_port: u16,

    /// Database URL
    pub database_url: String,

    /// Auth core configuration
    pub auth: AuthConfig,

    /// Request timeout (reserved for future use)
    #[allow(dead_code)]
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
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("HTTP_PORT"))?;

        let grpc_port = std::env::var("GRPC_PORT")
            .unwrap_or_else(|_| "50051".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("GRPC_PORT"))?;

        // Cognito configuration
        let cognito_pool_id = std::env::var("COGNITO_USER_POOL_ID")
            .map_err(|_| ConfigError::Missing("COGNITO_USER_POOL_ID"))?;

        let cognito_region = std::env::var("COGNITO_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_string());

        let cognito_client_id = std::env::var("COGNITO_CLIENT_ID")
            .map_err(|_| ConfigError::Missing("COGNITO_CLIENT_ID"))?;

        // Session secret (minimum 32 bytes)
        let session_secret =
            std::env::var("SESSION_SECRET").map_err(|_| ConfigError::Missing("SESSION_SECRET"))?;

        if session_secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "SESSION_SECRET must be at least 32 characters",
            ));
        }

        // Session duration (default 24 hours)
        let session_duration_hours: u64 = std::env::var("SESSION_DURATION_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("SESSION_DURATION_HOURS"))?;

        // Request timeout (default 30 seconds)
        let request_timeout_secs: u64 = std::env::var("REQUEST_TIMEOUT_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|_| ConfigError::Invalid("REQUEST_TIMEOUT_SECS"))?;

        // Metrics
        let metrics_enabled = std::env::var("METRICS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        // Build auth config
        let auth = AuthConfig::try_new(
            &cognito_pool_id,
            &cognito_region,
            &cognito_client_id,
            &session_secret,
        )
        .map_err(|e| ConfigError::AuthConfig(e.to_string()))?
        .with_session_duration(Duration::from_secs(session_duration_hours * 3600));

        Ok(Self {
            http_port,
            grpc_port,
            database_url,
            auth,
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

    #[error("Auth config error: {0}")]
    AuthConfig(String),
}
