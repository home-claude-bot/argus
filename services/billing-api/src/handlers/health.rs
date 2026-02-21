//! Health check handlers

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

/// Liveness probe - always returns OK if the service is running
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Readiness probe - checks database connectivity
pub async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, StatusCode> {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => Ok(Json(ReadyResponse {
            status: "ready",
            database: "connected",
        })),
        Err(e) => {
            tracing::error!(error = ?e, "Database health check failed");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
