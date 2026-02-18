//! Subscription handlers

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::instrument;

use argus_types::{Tier, UserId};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Record HTTP operation duration with result label
#[inline]
fn record_op_duration(operation: &'static str, start: Instant, success: bool) {
    let result = if success { "ok" } else { "err" };
    metrics::histogram!(
        "billing_operation_duration_seconds",
        "operation" => operation,
        "result" => result
    )
    .record(start.elapsed().as_secs_f64());
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub id: String,
    pub user_id: String,
    pub tier: String,
    pub status: String,
    pub current_period_start: String,
    pub current_period_end: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateCheckoutRequest {
    pub user_id: String,
    pub tier: String,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub session_id: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct CreatePortalRequest {
    pub user_id: String,
    pub return_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct GetSubscriptionRequest {
    pub user_id: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/v1/billing/subscription
#[instrument(skip(state, req), fields(user_id = %req.user_id))]
pub async fn get_subscription(
    State(state): State<AppState>,
    Json(req): Json<GetSubscriptionRequest>,
) -> ApiResult<Json<SubscriptionResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    let sub = state.billing.get_subscription(&user_id).await?;

    record_op_duration("get_subscription", start, true);

    Ok(Json(SubscriptionResponse {
        id: sub.id.0.to_string(),
        user_id: sub.user_id.0.to_string(),
        tier: sub.tier.to_string(),
        status: format!("{:?}", sub.status).to_lowercase(),
        current_period_start: sub.current_period_start.to_rfc3339(),
        current_period_end: sub.current_period_end.to_rfc3339(),
    }))
}

/// POST /api/v1/billing/checkout
#[instrument(skip(state, req), fields(user_id = %req.user_id, tier = %req.tier))]
pub async fn create_checkout(
    State(state): State<AppState>,
    Json(req): Json<CreateCheckoutRequest>,
) -> ApiResult<Json<CheckoutResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    let tier: Tier = req
        .tier
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("Invalid tier: {}", req.tier)))?;

    let session = state
        .billing
        .create_checkout(
            &user_id,
            tier,
            req.success_url.as_deref(),
            req.cancel_url.as_deref(),
        )
        .await?;

    metrics::counter!("billing_checkouts_created_total", "tier" => tier.to_string()).increment(1);
    record_op_duration("create_checkout", start, true);

    tracing::info!("Checkout session created");

    Ok(Json(CheckoutResponse {
        session_id: session.session_id,
        url: session.url,
    }))
}

/// POST /api/v1/billing/portal
#[instrument(skip(state, req), fields(user_id = %req.user_id))]
pub async fn create_portal(
    State(state): State<AppState>,
    Json(req): Json<CreatePortalRequest>,
) -> ApiResult<Json<PortalResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    let portal = state
        .billing
        .create_portal_session(&user_id, req.return_url.as_deref())
        .await?;

    record_op_duration("create_portal", start, true);

    Ok(Json(PortalResponse { url: portal.url }))
}
