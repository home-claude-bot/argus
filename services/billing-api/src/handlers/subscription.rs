//! Subscription handlers

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use argus_types::{Tier, UserId};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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
pub async fn get_subscription(
    State(state): State<AppState>,
    Json(req): Json<GetSubscriptionRequest>,
) -> ApiResult<Json<SubscriptionResponse>> {
    let start = Instant::now();

    let user_id = UserId::parse(&req.user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    let sub = state.billing.get_subscription(&user_id).await?;

    metrics::histogram!("billing_operation_duration_seconds", "operation" => "get_subscription")
        .record(start.elapsed().as_secs_f64());

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
pub async fn create_checkout(
    State(state): State<AppState>,
    Json(req): Json<CreateCheckoutRequest>,
) -> ApiResult<Json<CheckoutResponse>> {
    let start = Instant::now();

    let user_id = UserId::parse(&req.user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

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

    metrics::counter!("billing_checkouts_created_total").increment(1);
    metrics::histogram!("billing_operation_duration_seconds", "operation" => "create_checkout")
        .record(start.elapsed().as_secs_f64());

    tracing::info!(user_id = %user_id, tier = %tier, "Checkout session created");

    Ok(Json(CheckoutResponse {
        session_id: session.session_id,
        url: session.url,
    }))
}

/// POST /api/v1/billing/portal
pub async fn create_portal(
    State(state): State<AppState>,
    Json(req): Json<CreatePortalRequest>,
) -> ApiResult<Json<PortalResponse>> {
    let start = Instant::now();

    let user_id = UserId::parse(&req.user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    let portal = state
        .billing
        .create_portal_session(&user_id, req.return_url.as_deref())
        .await?;

    metrics::histogram!("billing_operation_duration_seconds", "operation" => "create_portal")
        .record(start.elapsed().as_secs_f64());

    Ok(Json(PortalResponse { url: portal.url }))
}
