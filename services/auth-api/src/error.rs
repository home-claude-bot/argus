//! Error types for the Auth API service.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// API error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// API error type
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Variants reserved for future use
pub enum ApiError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Session not found")]
    SessionNotFound,

    #[error("User not found")]
    UserNotFound,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error")]
    Database(#[from] argus_db::DbError),

    #[error("Auth error")]
    Auth(#[from] argus_auth_core::AuthError),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentials | Self::InvalidToken | Self::TokenExpired => {
                StatusCode::UNAUTHORIZED
            }
            Self::SessionNotFound | Self::UserNotFound => StatusCode::NOT_FOUND,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) | Self::Database(_) | Self::Auth(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::InvalidToken => "INVALID_TOKEN",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::SessionNotFound => "SESSION_NOT_FOUND",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Internal(_) | Self::Database(_) | Self::Auth(_) => "INTERNAL_ERROR",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();

        // Log internal errors
        if matches!(self, Self::Internal(_) | Self::Database(_) | Self::Auth(_)) {
            tracing::error!(error = ?self, "Internal API error");
        }

        let body = ErrorResponse {
            error: ErrorDetail {
                code: code.to_string(),
                message: self.to_string(),
                details: None,
            },
        };

        (status, Json(body)).into_response()
    }
}

/// Result type for API handlers
pub type ApiResult<T> = Result<T, ApiError>;
