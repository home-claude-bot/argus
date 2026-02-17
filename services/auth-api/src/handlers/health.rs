//! Health check handlers

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::time::Instant;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub checks: ReadyChecks,
}

#[derive(Debug, Serialize)]
pub struct ReadyChecks {
    pub database: CheckResult,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub status: &'static str,
    pub latency_ms: u64,
}

/// GET /health - Liveness probe (fast, no dependencies)
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "auth-api",
    })
}

/// GET /ready - Readiness probe (checks DB connectivity)
pub async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, StatusCode> {
    let start = Instant::now();

    // Check database connectivity with a simple query
    let db_result = sqlx::query("SELECT 1").fetch_one(&*state.pool).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let db_check = match db_result {
        Ok(_) => CheckResult {
            status: "ok",
            latency_ms,
        },
        Err(_) => CheckResult {
            status: "error",
            latency_ms,
        },
    };

    if db_check.status == "ok" {
        Ok(Json(ReadyResponse {
            status: "ready",
            service: "auth-api",
            checks: ReadyChecks { database: db_check },
        }))
    } else {
        // Return 503 if any check fails
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
