//! Auth errors

use thiserror::Error;

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid token
    #[error("invalid token")]
    InvalidToken,

    /// Token expired
    #[error("token expired")]
    TokenExpired,

    /// User not found
    #[error("user not found")]
    UserNotFound,

    /// Insufficient scope
    #[error("insufficient scope")]
    InsufficientScope,

    /// Not implemented
    #[error("not implemented")]
    NotImplemented,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}
