//! Database errors

use thiserror::Error;

/// Database errors
#[derive(Error, Debug)]
pub enum DbError {
    /// SQLx error
    #[error("database error: {0}")]
    Sqlx(sqlx::Error),

    /// Record not found
    #[error("record not found")]
    NotFound,

    /// Duplicate key violation
    #[error("duplicate key: {0}")]
    DuplicateKey(String),

    /// Foreign key violation
    #[error("foreign key violation: {0}")]
    ForeignKeyViolation(String),

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Migration error
    #[error("migration error: {0}")]
    Migration(String),
}

impl DbError {
    /// Check if the error is a not found error
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Check if the error is a duplicate key error
    pub fn is_duplicate_key(&self) -> bool {
        matches!(self, Self::DuplicateKey(_))
    }
}

/// Result type alias for database operations
pub type DbResult<T> = Result<T, DbError>;

// Helper to convert SQLx errors to more specific DbError variants
impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db_err) => {
                // PostgreSQL error codes
                if let Some(code) = db_err.code() {
                    match code.as_ref() {
                        "23505" => {
                            // unique_violation
                            return Self::DuplicateKey(db_err.message().to_string());
                        }
                        "23503" => {
                            // foreign_key_violation
                            return Self::ForeignKeyViolation(db_err.message().to_string());
                        }
                        _ => {}
                    }
                }
                Self::Sqlx(err)
            }
            _ => Self::Sqlx(err),
        }
    }
}
