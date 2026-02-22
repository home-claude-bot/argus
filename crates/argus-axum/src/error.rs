//! Error types for auth middleware and extractors.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Authentication and authorization errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No authentication credentials provided.
    #[error("authentication required")]
    Unauthenticated,

    /// Invalid or expired credentials.
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    /// User lacks required tier.
    #[error("insufficient subscription tier: requires {required}, have {actual}")]
    InsufficientTier {
        required: String,
        actual: String,
    },

    /// User lacks required feature.
    #[error("feature not available: {0}")]
    FeatureNotAvailable(String),

    /// User lacks required role.
    #[error("insufficient permissions: requires {0} role")]
    InsufficientRole(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded: retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        retry_after_secs: u64,
    },

    /// Internal error during auth processing.
    #[error("internal auth error: {0}")]
    Internal(String),

    /// Argus client error.
    #[error("argus client error: {0}")]
    Client(#[from] argus_client::ClientError),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InvalidCredentials(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsufficientTier { .. } => (StatusCode::FORBIDDEN, self.to_string()),
            Self::FeatureNotAvailable(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Self::InsufficientRole(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Self::RateLimitExceeded { retry_after_secs } => {
                let mut response = (StatusCode::TOO_MANY_REQUESTS, self.to_string()).into_response();
                response.headers_mut().insert(
                    "Retry-After",
                    retry_after_secs.to_string().parse().unwrap(),
                );
                return response;
            }
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
            Self::Client(e) => {
                tracing::error!(error = %e, "Argus client error");
                (StatusCode::SERVICE_UNAVAILABLE, "auth service unavailable".to_string())
            }
        };

        (status, message).into_response()
    }
}

impl AuthError {
    /// Create an insufficient tier error.
    #[must_use]
    pub fn insufficient_tier(required: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InsufficientTier {
            required: required.into(),
            actual: actual.into(),
        }
    }

    /// Create a rate limit exceeded error.
    #[must_use]
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self::RateLimitExceeded { retry_after_secs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AuthError::Unauthenticated;
        assert_eq!(err.to_string(), "authentication required");

        let err = AuthError::insufficient_tier("Professional", "Explorer");
        assert!(err.to_string().contains("Professional"));

        let err = AuthError::rate_limited(60);
        assert!(err.to_string().contains("60 seconds"));
    }
}
