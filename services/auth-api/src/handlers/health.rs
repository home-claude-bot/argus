//! Health check handlers

use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// GET /health - Liveness probe
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "auth-api",
    })
}

/// GET /ready - Readiness probe
pub async fn ready() -> Result<Json<HealthResponse>, StatusCode> {
    // TODO: Add database connectivity check
    Ok(Json(HealthResponse {
        status: "ready",
        service: "auth-api",
    }))
}
