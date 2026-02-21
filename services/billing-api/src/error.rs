//! Error types for the Billing API service.
//!
//! Security design:
//! - Internal errors NEVER leak to clients (DB errors, stack traces, etc.)
//! - Error codes are generic to prevent enumeration attacks
//! - Request IDs enable correlation without exposing internals

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// API error response - safe for client consumption
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Error detail - sanitized for external exposure
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    /// Machine-readable error code
    pub code: String,
    /// Human-readable message (sanitized - no internal details)
    pub message: String,
    /// Additional context (only for client-fixable errors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// API error type
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Variants used for future error handling
pub enum ApiError {
    #[error("Subscription not found")]
    SubscriptionNotFound,

    #[error("Invoice not found")]
    InvoiceNotFound,

    #[error("User not found")]
    UserNotFound,

    #[error("Customer not found")]
    CustomerNotFound,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Webhook error: {0}")]
    WebhookError(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error")]
    Database(#[from] argus_db::DbError),

    #[error("Billing error")]
    Billing(#[from] argus_billing_core::BillingError),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::SubscriptionNotFound
            | Self::InvoiceNotFound
            | Self::UserNotFound
            | Self::CustomerNotFound => StatusCode::NOT_FOUND,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::WebhookError(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) | Self::Database(_) | Self::Billing(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::InvoiceNotFound => "INVOICE_NOT_FOUND",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::CustomerNotFound => "CUSTOMER_NOT_FOUND",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::WebhookError(_) => "WEBHOOK_ERROR",
            Self::Internal(_) | Self::Database(_) | Self::Billing(_) => "INTERNAL_ERROR",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();

        // SECURITY: Sanitize error messages to prevent information leakage
        // Internal errors get generic messages; client errors get specific guidance
        let (message, should_log) = match &self {
            // Client errors - safe to expose details
            Self::SubscriptionNotFound => ("Subscription not found".to_string(), false),
            Self::InvoiceNotFound => ("Invoice not found".to_string(), false),
            Self::UserNotFound => ("User not found".to_string(), false),
            Self::CustomerNotFound => ("Billing account not configured".to_string(), false),
            Self::Forbidden(reason) => (format!("Access denied: {reason}"), false),
            Self::BadRequest(reason) => (format!("Invalid request: {reason}"), false),
            Self::WebhookError(_) => ("Webhook processing failed".to_string(), true),

            // SECURITY: Internal errors - NEVER expose details to client
            Self::Internal(internal_msg) => {
                tracing::error!(error = %internal_msg, "Internal error");
                ("An internal error occurred".to_string(), false)
            }
            Self::Database(db_err) => {
                tracing::error!(error = ?db_err, "Database error");
                ("An internal error occurred".to_string(), false)
            }
            Self::Billing(billing_err) => {
                tracing::error!(error = ?billing_err, "Billing service error");
                ("An internal error occurred".to_string(), false)
            }
        };

        if should_log {
            tracing::warn!(code = %code, "API error response");
        }

        let body = ErrorResponse {
            error: ErrorDetail {
                code: code.to_string(),
                message,
                details: None,
            },
        };

        (status, Json(body)).into_response()
    }
}

/// Result type for API handlers
pub type ApiResult<T> = Result<T, ApiError>;
