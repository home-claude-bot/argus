//! Stripe webhook handler

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use std::time::Instant;

use crate::state::AppState;

/// POST /webhooks/stripe
///
/// Handle Stripe webhook events with signature verification.
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let start = Instant::now();

    // Extract Stripe signature header
    let Some(sig_header) = headers.get("stripe-signature") else {
        tracing::warn!("Missing Stripe-Signature header");
        return StatusCode::BAD_REQUEST;
    };

    let Ok(signature) = sig_header.to_str() else {
        tracing::warn!("Invalid Stripe-Signature header encoding");
        return StatusCode::BAD_REQUEST;
    };

    // Process webhook
    match state.billing.process_webhook(&body, signature).await {
        Ok(()) => {
            metrics::counter!("billing_webhooks_processed_total", "status" => "success")
                .increment(1);
            metrics::histogram!(
                "billing_operation_duration_seconds",
                "operation" => "process_webhook"
            )
            .record(start.elapsed().as_secs_f64());

            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = ?e, "Webhook processing failed");
            metrics::counter!("billing_webhooks_processed_total", "status" => "error").increment(1);

            // Return 400 for signature/parsing errors, 500 for internal errors
            if e.to_string().contains("Signature")
                || e.to_string().contains("timestamp")
                || e.to_string().contains("parse")
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}
