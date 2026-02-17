//! Argus Auth API
//!
//! Authentication microservice providing REST and gRPC endpoints.
//!
//! ## REST Endpoints
//!
//! - `POST /api/v1/auth/login` - Exchange Cognito tokens for session
//! - `POST /api/v1/auth/logout` - Revoke current session
//! - `POST /api/v1/auth/refresh` - Refresh access token
//! - `GET /api/v1/auth/me` - Get current user info
//! - `GET /api/v1/users/:id/tier` - Get user's tier
//! - `POST /api/v1/users/:id/tier` - Update user's tier (admin)
//!
//! ## gRPC Service
//!
//! Implements `AuthService` from argus-proto on port 50051.
//!
//! ## Health Endpoints
//!
//! - `GET /health` - Liveness probe
//! - `GET /ready` - Readiness probe
//! - `GET /metrics` - Prometheus metrics

mod config;
mod error;
mod extractors;
mod grpc;
mod handlers;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use argus_auth_core::AuthService;
use argus_db::pg::Repositories;
use argus_proto::auth_service::auth_service_server::AuthServiceServer;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::routing::{get, post};
use axum::Router;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::signal;
use tonic::transport::Server as TonicServer;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::grpc::GrpcAuthService;
use crate::handlers::{health, ready};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("auth_api=debug".parse()?))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Argus Auth API");

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!(
        http_port = config.http_port,
        grpc_port = config.grpc_port,
        "Configuration loaded"
    );

    // Initialize metrics
    let metrics_handle = if config.metrics_enabled {
        Some(setup_metrics()?)
    } else {
        None
    };

    // Create database pool
    let pool = argus_db::create_pool(&config.database_url).await?;
    tracing::info!("Database pool created");

    // Create repositories
    let repos = Repositories::new(pool.clone());

    // Create auth service
    let auth = AuthService::new(
        config.auth.clone(),
        Arc::new(repos.users.clone()),
        Arc::new(repos.sessions.clone()),
    );

    // Create application state
    let state = AppState::new(auth, repos, pool, config.clone());

    // Build HTTP router
    let app = build_router(state.clone(), metrics_handle);

    // Start servers
    let http_addr = SocketAddr::from(([0, 0, 0, 0], config.http_port));
    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], config.grpc_port));

    // Run both servers concurrently
    tokio::select! {
        result = run_http_server(app, http_addr) => {
            if let Err(e) = result {
                tracing::error!(error = ?e, "HTTP server error");
            }
        }
        result = run_grpc_server(state, grpc_addr) => {
            if let Err(e) = result {
                tracing::error!(error = ?e, "gRPC server error");
            }
        }
        () = shutdown_signal() => {
            tracing::info!("Shutdown signal received");
        }
    }

    tracing::info!("Shutdown complete");
    Ok(())
}

fn build_router(state: AppState, metrics_handle: Option<PrometheusHandle>) -> Router {
    let request_timeout = state.request_timeout();

    // API v1 routes
    let api_v1 = Router::new()
        // Auth routes
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/refresh", post(handlers::refresh))
        .route("/auth/me", get(handlers::me))
        // Tier routes
        .route(
            "/users/{id}/tier",
            get(handlers::get_user_tier).post(handlers::update_user_tier),
        );

    // Health routes (no timeout - must always respond quickly)
    let health_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready));

    // Metrics route (no timeout)
    let metrics_route = if let Some(handle) = metrics_handle {
        Router::new().route("/metrics", get(move || async move { handle.render() }))
    } else {
        Router::new()
    };

    // Build middleware stack (order matters - outermost first)
    let middleware = ServiceBuilder::new()
        // Request ID propagation (outermost)
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        // Tracing with request details
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // CORS
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        // Request timeout (innermost - closest to handler)
        .layer(TimeoutLayer::new(request_timeout));

    // Combine all routes
    Router::new()
        .nest("/api/v1", api_v1)
        .layer(middleware)
        .merge(health_routes) // Health routes without timeout
        .merge(metrics_route) // Metrics route without timeout
        .with_state(state)
}

async fn run_http_server(app: Router, addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!("HTTP server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let service: IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
        app.into_make_service_with_connect_info();

    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn run_grpc_server(state: AppState, addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!("gRPC server listening on {}", addr);

    let grpc_service = GrpcAuthService::new(state.auth);
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(argus_proto::argus::v1::FILE_DESCRIPTOR_SET)
        .build()?;

    TonicServer::builder()
        .add_service(reflection)
        .add_service(AuthServiceServer::new(grpc_service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
}

fn setup_metrics() -> anyhow::Result<PrometheusHandle> {
    // Latency buckets optimized for auth operations
    // Most auth ops should complete in <50ms, SLO at <100ms p99
    let auth_latency_buckets = &[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

    let builder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            auth_latency_buckets,
        )?
        .set_buckets_for_metric(
            Matcher::Full("grpc_request_duration_seconds".to_string()),
            auth_latency_buckets,
        )?
        .set_buckets_for_metric(
            Matcher::Full("auth_operation_duration_seconds".to_string()),
            auth_latency_buckets,
        )?;

    let handle = builder.install_recorder()?;

    // Register metrics with descriptions
    metrics::describe_counter!(
        "auth_token_validations_total",
        "Total token validation attempts by result (valid/invalid/batch)"
    );
    metrics::describe_counter!("auth_sessions_created_total", "Total sessions created");
    metrics::describe_counter!("auth_sessions_revoked_total", "Total sessions revoked");
    metrics::describe_counter!(
        "auth_entitlement_checks_total",
        "Total entitlement checks by result"
    );
    metrics::describe_histogram!(
        "http_request_duration_seconds",
        "HTTP request latency in seconds"
    );
    metrics::describe_histogram!(
        "grpc_request_duration_seconds",
        "gRPC request latency in seconds by method"
    );
    metrics::describe_histogram!(
        "auth_operation_duration_seconds",
        "Auth operation latency in seconds by operation type"
    );

    Ok(handle)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful shutdown");
}
