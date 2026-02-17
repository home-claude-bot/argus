//! Tier management handlers

use argus_db::UserRepository;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::extractors::AuthUser;
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TierResponse {
    pub user_id: String,
    pub tier: String,
    pub features: Vec<String>,
    pub rate_limit: RateLimitInfo,
}

#[derive(Debug, Serialize)]
pub struct RateLimitInfo {
    /// Requests allowed per window
    pub requests: u32,
    /// Window size in seconds
    pub window_seconds: u32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTierRequest {
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateTierResponse {
    pub user_id: String,
    pub previous_tier: String,
    pub new_tier: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/v1/users/:id/tier
///
/// Get user's current tier
pub async fn get_user_tier(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    auth_user: AuthUser,
) -> ApiResult<Json<TierResponse>> {
    let start = Instant::now();

    // Users can only view their own tier (unless admin)
    let target_user_id = argus_types::UserId::from(user_id);

    if auth_user.user_id != target_user_id && !auth_user.is_admin() {
        return Err(ApiError::Forbidden(
            "Cannot view tier for other users".to_string(),
        ));
    }

    // Fetch tier and rate limit in parallel
    let (tier_result, rate_limit_result) = tokio::join!(
        state.auth.get_user_tier(&target_user_id),
        state.auth.get_rate_limit(&target_user_id)
    );

    let tier = tier_result?;
    let rate_limit = rate_limit_result?;

    metrics::histogram!("auth_operation_duration_seconds", "operation" => "get_tier")
        .record(start.elapsed().as_secs_f64());

    Ok(Json(TierResponse {
        user_id: user_id.to_string(),
        tier: tier.to_string(),
        features: tier.features().iter().copied().map(String::from).collect(),
        rate_limit: RateLimitInfo {
            requests: rate_limit.requests,
            window_seconds: rate_limit.window_seconds,
        },
    }))
}

/// POST /api/v1/users/:id/tier (admin only)
///
/// Update user's tier
pub async fn update_user_tier(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    auth_user: AuthUser,
    Json(req): Json<UpdateTierRequest>,
) -> ApiResult<Json<UpdateTierResponse>> {
    let start = Instant::now();

    // Admin only
    if !auth_user.is_admin() {
        return Err(ApiError::Forbidden("Admin access required".to_string()));
    }

    // Parse new tier
    let new_tier: argus_types::Tier = req
        .tier
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("Invalid tier: {}", req.tier)))?;

    let target_user_id = argus_types::UserId::from(user_id);

    // Get current tier
    let previous_tier = state.auth.get_user_tier(&target_user_id).await?;

    // Update tier in database
    state
        .repos
        .users
        .update_tier(user_id, &new_tier.to_string())
        .await?;

    // Invalidate caches
    state.auth.invalidate_user_cache(&target_user_id).await;

    metrics::counter!("auth_tier_updates_total", "from" => previous_tier.to_string(), "to" => new_tier.to_string()).increment(1);
    metrics::histogram!("auth_operation_duration_seconds", "operation" => "update_tier")
        .record(start.elapsed().as_secs_f64());

    tracing::info!(
        user_id = %user_id,
        previous_tier = %previous_tier,
        new_tier = %new_tier,
        admin_id = %auth_user.user_id,
        "User tier updated"
    );

    Ok(Json(UpdateTierResponse {
        user_id: user_id.to_string(),
        previous_tier: previous_tier.to_string(),
        new_tier: new_tier.to_string(),
    }))
}
