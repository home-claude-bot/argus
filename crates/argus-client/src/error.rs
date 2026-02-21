//! Client errors
//!
//! Error types for Argus client operations, with comprehensive mapping from gRPC status codes.

use thiserror::Error;
use tonic::Status;

/// Client errors for Argus operations.
#[derive(Error, Debug)]
pub enum ClientError {
    /// Connection error - failed to establish connection to server.
    #[error("connection error: {message}")]
    Connection {
        /// Error message
        message: String,
        /// Whether the error is retryable
        retryable: bool,
    },

    /// Request timeout.
    #[error("request timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// Authentication required - token missing or expired.
    #[error("authentication required: {0}")]
    Unauthenticated(String),

    /// Permission denied - insufficient permissions.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Invalid argument - request validation failed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Resource already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Resource exhausted - rate limit exceeded or quota depleted.
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Precondition failed - request cannot be processed in current state.
    #[error("precondition failed: {0}")]
    FailedPrecondition(String),

    /// Aborted - operation was aborted (concurrency conflict).
    #[error("aborted: {0}")]
    Aborted(String),

    /// Out of range - request value out of acceptable range.
    #[error("out of range: {0}")]
    OutOfRange(String),

    /// Unimplemented - operation not supported.
    #[error("unimplemented: {0}")]
    Unimplemented(String),

    /// Internal error - server-side error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Service unavailable - server is temporarily unavailable.
    #[error("service unavailable: {0}")]
    Unavailable(String),

    /// Data loss - unrecoverable data loss or corruption.
    #[error("data loss: {0}")]
    DataLoss(String),

    /// Cancelled - operation was cancelled.
    #[error("cancelled: {0}")]
    Cancelled(String),

    /// Unknown error.
    #[error("unknown error: {0}")]
    Unknown(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl ClientError {
    /// Returns true if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connection { retryable, .. } => *retryable,
            Self::Timeout(_) => true,
            Self::Unavailable(_) => true,
            Self::ResourceExhausted(_) => true, // Rate limits are typically retryable with backoff
            Self::Aborted(_) => true, // Concurrency conflicts can be retried
            Self::Internal(_) => false, // Internal errors might be permanent
            Self::Unauthenticated(_) => false, // Need new credentials
            Self::PermissionDenied(_) => false, // Permissions won't change
            Self::NotFound(_) => false,
            Self::InvalidArgument(_) => false,
            Self::AlreadyExists(_) => false,
            Self::FailedPrecondition(_) => false,
            Self::OutOfRange(_) => false,
            Self::Unimplemented(_) => false,
            Self::DataLoss(_) => false,
            Self::Cancelled(_) => false,
            Self::Unknown(_) => false,
            Self::Config(_) => false,
            Self::Serialization(_) => false,
        }
    }

    /// Returns the gRPC status code if this error originated from gRPC.
    #[must_use]
    pub fn grpc_code(&self) -> Option<tonic::Code> {
        match self {
            Self::Timeout(_) => Some(tonic::Code::DeadlineExceeded),
            Self::Unauthenticated(_) => Some(tonic::Code::Unauthenticated),
            Self::PermissionDenied(_) => Some(tonic::Code::PermissionDenied),
            Self::NotFound(_) => Some(tonic::Code::NotFound),
            Self::InvalidArgument(_) => Some(tonic::Code::InvalidArgument),
            Self::AlreadyExists(_) => Some(tonic::Code::AlreadyExists),
            Self::ResourceExhausted(_) => Some(tonic::Code::ResourceExhausted),
            Self::FailedPrecondition(_) => Some(tonic::Code::FailedPrecondition),
            Self::Aborted(_) => Some(tonic::Code::Aborted),
            Self::OutOfRange(_) => Some(tonic::Code::OutOfRange),
            Self::Unimplemented(_) => Some(tonic::Code::Unimplemented),
            Self::Internal(_) => Some(tonic::Code::Internal),
            Self::Unavailable(_) => Some(tonic::Code::Unavailable),
            Self::DataLoss(_) => Some(tonic::Code::DataLoss),
            Self::Cancelled(_) => Some(tonic::Code::Cancelled),
            Self::Unknown(_) => Some(tonic::Code::Unknown),
            Self::Connection { .. } | Self::Config(_) | Self::Serialization(_) => None,
        }
    }

    /// Create a connection error.
    pub fn connection(message: impl Into<String>, retryable: bool) -> Self {
        Self::Connection {
            message: message.into(),
            retryable,
        }
    }
}

impl From<Status> for ClientError {
    fn from(status: Status) -> Self {
        let message = status.message().to_string();

        match status.code() {
            tonic::Code::Ok => Self::Unknown("unexpected OK status".to_string()),
            tonic::Code::Cancelled => Self::Cancelled(message),
            tonic::Code::Unknown => Self::Unknown(message),
            tonic::Code::InvalidArgument => Self::InvalidArgument(message),
            tonic::Code::DeadlineExceeded => Self::Timeout(std::time::Duration::from_secs(0)),
            tonic::Code::NotFound => Self::NotFound(message),
            tonic::Code::AlreadyExists => Self::AlreadyExists(message),
            tonic::Code::PermissionDenied => Self::PermissionDenied(message),
            tonic::Code::ResourceExhausted => Self::ResourceExhausted(message),
            tonic::Code::FailedPrecondition => Self::FailedPrecondition(message),
            tonic::Code::Aborted => Self::Aborted(message),
            tonic::Code::OutOfRange => Self::OutOfRange(message),
            tonic::Code::Unimplemented => Self::Unimplemented(message),
            tonic::Code::Internal => Self::Internal(message),
            tonic::Code::Unavailable => Self::Unavailable(message),
            tonic::Code::DataLoss => Self::DataLoss(message),
            tonic::Code::Unauthenticated => Self::Unauthenticated(message),
        }
    }
}

impl From<tonic::transport::Error> for ClientError {
    fn from(err: tonic::transport::Error) -> Self {
        Self::Connection {
            message: err.to_string(),
            retryable: true, // Transport errors are typically transient
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_errors() {
        assert!(ClientError::Timeout(std::time::Duration::from_secs(1)).is_retryable());
        assert!(ClientError::Unavailable("server down".to_string()).is_retryable());
        assert!(ClientError::ResourceExhausted("rate limit".to_string()).is_retryable());
        assert!(ClientError::Aborted("conflict".to_string()).is_retryable());
    }

    #[test]
    fn test_non_retryable_errors() {
        assert!(!ClientError::NotFound("user".to_string()).is_retryable());
        assert!(!ClientError::InvalidArgument("bad input".to_string()).is_retryable());
        assert!(!ClientError::PermissionDenied("forbidden".to_string()).is_retryable());
        assert!(!ClientError::Unauthenticated("no token".to_string()).is_retryable());
    }

    #[test]
    fn test_from_grpc_status() {
        let status = Status::not_found("user not found");
        let error: ClientError = status.into();

        assert!(matches!(error, ClientError::NotFound(_)));
        assert_eq!(error.grpc_code(), Some(tonic::Code::NotFound));
    }

    #[test]
    fn test_connection_error() {
        let err = ClientError::connection("failed to connect", true);
        assert!(err.is_retryable());

        let err = ClientError::connection("invalid endpoint", false);
        assert!(!err.is_retryable());
    }
}
