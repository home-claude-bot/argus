//! Auth errors

use thiserror::Error;

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid token (malformed, bad signature, etc.)
    #[error("invalid token")]
    InvalidToken,

    /// Token has expired
    #[error("token expired")]
    TokenExpired,

    /// Session has been revoked
    #[error("session revoked")]
    SessionRevoked,

    /// User not found
    #[error("user not found")]
    UserNotFound,

    /// Insufficient scope for the requested operation
    #[error("insufficient scope")]
    InsufficientScope,

    /// Feature not available for user's tier
    #[error("feature not available: {0}")]
    FeatureNotAvailable(String),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Invalid credentials (wrong password, etc.)
    #[error("invalid credentials")]
    InvalidCredentials,

    /// MFA required but not provided
    #[error("MFA required")]
    MfaRequired,

    /// Invalid MFA code
    #[error("invalid MFA code")]
    InvalidMfaCode,

    /// Database error
    #[error("database error: {0}")]
    Database(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidToken
            | Self::InvalidCredentials
            | Self::InvalidMfaCode
            | Self::TokenExpired
            | Self::SessionRevoked => 401,
            Self::UserNotFound => 404,
            Self::InsufficientScope | Self::FeatureNotAvailable(_) | Self::MfaRequired => 403,
            Self::RateLimitExceeded => 429,
            Self::Database(_) | Self::Configuration(_) | Self::Internal(_) => 500,
        }
    }

    /// Get error code for API responses
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidToken => "INVALID_TOKEN",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::SessionRevoked => "SESSION_REVOKED",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::InsufficientScope => "INSUFFICIENT_SCOPE",
            Self::FeatureNotAvailable(_) => "FEATURE_NOT_AVAILABLE",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::InvalidMfaCode => "INVALID_MFA_CODE",
            Self::Database(_) => "DATABASE_ERROR",
            Self::Configuration(_) => "CONFIGURATION_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl From<argus_db::DbError> for AuthError {
    fn from(err: argus_db::DbError) -> Self {
        tracing::error!("Database error: {}", err);
        Self::Database(err.to_string())
    }
}
