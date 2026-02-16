//! Client errors

use thiserror::Error;

/// Client errors
#[derive(Error, Debug)]
pub enum ClientError {
    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Request failed
    #[error("request failed: {0}")]
    Request(String),

    /// Not implemented
    #[error("not implemented")]
    NotImplemented,
}
