//! Common error types

use thiserror::Error;

/// Common errors across Argus
#[derive(Error, Debug)]
pub enum ArgusError {
    /// User not found
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Invalid tier
    #[error("invalid tier: {0}")]
    InvalidTier(String),

    /// Unauthorized
    #[error("unauthorized")]
    Unauthorized,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}
