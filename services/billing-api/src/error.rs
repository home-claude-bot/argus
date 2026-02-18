//! Error types for the Billing API service.

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

        // Log internal errors
        if matches!(
            self,
            Self::Internal(_) | Self::Database(_) | Self::Billing(_)
        ) {
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
