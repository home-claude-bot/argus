//! Database errors

use thiserror::Error;

/// Database errors
#[derive(Error, Debug)]
pub enum DbError {
    /// SQLx error
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Record not found
    #[error("record not found")]
    NotFound,
}
