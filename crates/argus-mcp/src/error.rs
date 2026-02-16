//! MCP Error types

use thiserror::Error;

/// Errors that can occur in MCP operations
#[derive(Error, Debug)]
pub enum McpError {
    /// Resource not found
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    /// Invalid token
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// User not found
    #[error("User not found: {0}")]
    UserNotFound(String),

    /// Insufficient permissions
    #[error("Insufficient permissions")]
    InsufficientPermissions,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
