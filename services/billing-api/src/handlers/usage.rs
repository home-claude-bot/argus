//! Usage tracking handlers

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use argus_types::UserId;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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
pub async fn record_usage(
    State(state): State<AppState>,
    Json(req): Json<RecordUsageRequest>,
) -> ApiResult<Json<RecordUsageResponse>> {
    let start = Instant::now();

    let user_id = UserId::parse(&req.user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    if req.quantity <= 0 {
        return Err(ApiError::BadRequest(
            "Quantity must be positive".to_string(),
        ));
    }

    let result = state
        .billing
        .record_usage(&user_id, &req.metric, req.quantity)
        .await?;

    metrics::counter!("billing_usage_recorded_total", "metric" => req.metric.clone())
        .increment(req.quantity as u64);
    metrics::histogram!("billing_operation_duration_seconds", "operation" => "record_usage")
        .record(start.elapsed().as_secs_f64());

    Ok(Json(RecordUsageResponse {
        success: result.success,
        total_usage: result.total_usage,
    }))
}

/// GET /api/v1/billing/usage
pub async fn get_usage(
    State(state): State<AppState>,
    Json(req): Json<GetUsageRequest>,
) -> ApiResult<Json<UsageResponse>> {
    let start = Instant::now();

    let user_id = UserId::parse(&req.user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    let summary = state
        .billing
        .get_usage_summary(&user_id, req.period.as_deref())
        .await?;

    metrics::histogram!("billing_operation_duration_seconds", "operation" => "get_usage")
        .record(start.elapsed().as_secs_f64());

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
