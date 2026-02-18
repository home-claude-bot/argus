//! Stripe webhook handler

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use std::time::Instant;

use super::shared::record_op_duration;
use crate::state::AppState;

/// POST /webhooks/stripe
///
/// Handle Stripe webhook events with signature verification.
///
/// # Security
/// - Signature verification happens in billing-core (HMAC-SHA256)
/// - Timestamp freshness check prevents replay attacks (5 min window)
/// - Constant-time comparison prevents timing attacks
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let start = Instant::now();

    // Extract Stripe signature header
    let Some(sig_header) = headers.get("stripe-signature") else {
        tracing::warn!("Missing Stripe-Signature header");
        metrics::counter!("billing_webhooks_processed_total", "status" => "missing_signature")
            .increment(1);
        record_op_duration("process_webhook", start, false);
        return StatusCode::BAD_REQUEST;
    };

    let Ok(signature) = sig_header.to_str() else {
        tracing::warn!("Invalid Stripe-Signature header encoding");
        metrics::counter!("billing_webhooks_processed_total", "status" => "invalid_header")
            .increment(1);
        record_op_duration("process_webhook", start, false);
        return StatusCode::BAD_REQUEST;
    };

    // Process webhook
    match state.billing.process_webhook(&body, signature).await {
        Ok(()) => {
            metrics::counter!("billing_webhooks_processed_total", "status" => "success")
                .increment(1);
            record_op_duration("process_webhook", start, true);
            StatusCode::OK
        }
        Err(e) => {
            // SECURITY: Don't log full error details (may contain sensitive data)
            let err_str = e.to_string();
            let (status, error_type) =
                if err_str.contains("Signature") || err_str.contains("verification") {
                    (StatusCode::BAD_REQUEST, "signature_invalid")
                } else if err_str.contains("timestamp") {
                    (StatusCode::BAD_REQUEST, "timestamp_expired")
                } else if err_str.contains("parse") || err_str.contains("JSON") {
                    (StatusCode::BAD_REQUEST, "parse_error")
                } else {
                    // Log internal errors for debugging
                    tracing::error!(error = ?e, "Webhook processing failed");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                };

            metrics::counter!("billing_webhooks_processed_total", "status" => error_type)
                .increment(1);
            record_op_duration("process_webhook", start, false);
            status
        }
    }
}
