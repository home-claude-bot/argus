//! Usage tracking handlers

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::instrument;

use argus_types::UserId;

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

#[derive(Debug, Deserialize)]
pub struct RecordUsageRequest {
    pub user_id: String,
    pub metric: String,
    pub quantity: i64,
}

#[derive(Debug, Serialize)]
pub struct RecordUsageResponse {
    pub success: bool,
    pub total_usage: i64,
}

#[derive(Debug, Deserialize)]
pub struct GetUsageRequest {
    pub user_id: String,
    pub period: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UsageResponse {
    pub period: String,
    pub total_requests: u64,
    pub by_endpoint: Vec<EndpointUsage>,
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EndpointUsage {
    pub endpoint: String,
    pub count: u64,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/v1/billing/usage/record
/// Hot path - optimized for minimal latency
#[instrument(skip(state, req), fields(user_id = %req.user_id, metric = %req.metric, quantity = req.quantity))]
pub async fn record_usage(
    State(state): State<AppState>,
    Json(req): Json<RecordUsageRequest>,
) -> ApiResult<Json<RecordUsageResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    if req.quantity <= 0 {
        return Err(ApiError::BadRequest("Quantity must be positive".into()));
    }

    let result = state
        .billing
        .record_usage(&user_id, &req.metric, req.quantity)
        .await?;

    // Record usage metric (owned string needed for metrics)
    let metric_name = req.metric;
    metrics::counter!("billing_usage_recorded_total", "metric" => metric_name)
        .increment(req.quantity as u64);
    record_op_duration("record_usage", start, true);

    Ok(Json(RecordUsageResponse {
        success: result.success,
        total_usage: result.total_usage,
    }))
}

/// GET /api/v1/billing/usage
#[instrument(skip(state, req), fields(user_id = %req.user_id))]
pub async fn get_usage(
    State(state): State<AppState>,
    Json(req): Json<GetUsageRequest>,
) -> ApiResult<Json<UsageResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    let summary = state
        .billing
        .get_usage_summary(&user_id, req.period.as_deref())
        .await?;

    record_op_duration("get_usage", start, true);

    Ok(Json(UsageResponse {
        period: summary.period,
        total_requests: summary.total_requests,
        by_endpoint: summary
            .by_endpoint
            .into_iter()
            .map(|e| EndpointUsage {
                endpoint: e.endpoint,
                count: e.count,
            })
            .collect(),
        limit: summary.limit,
    }))
}
