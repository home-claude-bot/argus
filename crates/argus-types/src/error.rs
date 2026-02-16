//! Common error types

use thiserror::Error;

/// Common errors across Argus
#[derive(Error, Debug)]
pub enum ArgusError {
    // Authentication errors
    /// Invalid credentials
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Token expired
    #[error("token expired")]
    TokenExpired,

    /// Token invalid
    #[error("invalid token")]
    InvalidToken,

    /// Session expired
    #[error("session expired")]
    SessionExpired,

    /// Session revoked
    #[error("session revoked")]
    SessionRevoked,

    /// MFA required
    #[error("MFA verification required")]
    MfaRequired,

    /// MFA code invalid
    #[error("invalid MFA code")]
    InvalidMfaCode,

    // Authorization errors
    /// Unauthorized
    #[error("unauthorized")]
    Unauthorized,

    /// Forbidden (authenticated but not allowed)
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Insufficient tier
    #[error("feature requires {0} tier or higher")]
    InsufficientTier(String),

    /// Feature not enabled
    #[error("feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    // Resource errors
    /// User not found
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Session not found
    #[error("session not found")]
    SessionNotFound,

    /// Subscription not found
    #[error("subscription not found")]
    SubscriptionNotFound,

    /// API key not found
    #[error("API key not found")]
    ApiKeyNotFound,

    /// Resource not found (generic)
    #[error("{0} not found")]
    NotFound(String),

    // Validation errors
    /// Invalid tier
    #[error("invalid tier: {0}")]
    InvalidTier(String),

    /// Invalid email
    #[error("invalid email: {0}")]
    InvalidEmail(String),

    /// Invalid password
    #[error("invalid password: {0}")]
    InvalidPassword(String),

    /// Validation error
    #[error("validation error: {0}")]
    Validation(String),

    // External service errors
    /// Cognito error
    #[error("cognito error: {0}")]
    Cognito(String),

    /// Stripe error
    #[error("stripe error: {0}")]
    Stripe(String),

    /// Database error
    #[error("database error: {0}")]
    Database(String),

    // Internal errors
    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),
}

impl ArgusError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            // 400 Bad Request
            Self::InvalidEmail(_)
            | Self::InvalidPassword(_)
            | Self::InvalidTier(_)
            | Self::Validation(_) => 400,

            // 401 Unauthorized
            Self::InvalidCredentials
            | Self::TokenExpired
            | Self::InvalidToken
            | Self::SessionExpired
            | Self::SessionRevoked
            | Self::InvalidMfaCode
            | Self::Unauthorized => 401,

            // 403 Forbidden
            Self::Forbidden(_)
            | Self::InsufficientTier(_)
            | Self::FeatureNotEnabled(_)
            | Self::MfaRequired => 403,

            // 404 Not Found
            Self::UserNotFound(_)
            | Self::SessionNotFound
            | Self::SubscriptionNotFound
            | Self::ApiKeyNotFound
            | Self::NotFound(_) => 404,

            // 429 Too Many Requests
            Self::RateLimitExceeded => 429,

            // 500 Internal Server Error
            Self::Cognito(_)
            | Self::Stripe(_)
            | Self::Database(_)
            | Self::Internal(_)
            | Self::Config(_) => 500,
        }
    }

    /// Get the error code for this error
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::SessionExpired => "SESSION_EXPIRED",
            Self::SessionRevoked => "SESSION_REVOKED",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::InvalidMfaCode => "INVALID_MFA_CODE",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::InsufficientTier(_) => "INSUFFICIENT_TIER",
            Self::FeatureNotEnabled(_) => "FEATURE_NOT_ENABLED",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::UserNotFound(_) => "USER_NOT_FOUND",
            Self::SessionNotFound => "SESSION_NOT_FOUND",
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::ApiKeyNotFound => "API_KEY_NOT_FOUND",
            Self::NotFound(_) => "NOT_FOUND",
            Self::InvalidTier(_) => "INVALID_TIER",
            Self::InvalidEmail(_) => "INVALID_EMAIL",
            Self::InvalidPassword(_) => "INVALID_PASSWORD",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::Cognito(_) => "COGNITO_ERROR",
            Self::Stripe(_) => "STRIPE_ERROR",
            Self::Database(_) => "DATABASE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Config(_) => "CONFIG_ERROR",
        }
    }
}

/// Result type alias for Argus operations
pub type ArgusResult<T> = Result<T, ArgusError>;
