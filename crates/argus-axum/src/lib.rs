//! Argus Axum Integration
//!
//! Axum middleware and extractors for integrating with Argus auth and billing services.
//!
//! # Overview
//!
//! This crate provides Axum-specific integrations for Argus:
//! - **Extractors**: `RequireAuth`, `MaybeAuth`, `RequireTier`, `RequireFeature`
//! - **Middleware**: `ArgusLayer` for automatic auth/rate-limiting
//! - **Tower Layers**: Integration with Tower middleware ecosystem
//!
//! # Quick Start
//!
//! ```ignore
//! use argus_axum::{ArgusLayer, RequireAuth, AuthContext};
//! use axum::{Router, routing::get};
//!
//! async fn protected_handler(auth: RequireAuth) -> String {
//!     format!("Hello, user {}!", auth.user_id)
//! }
//!
//! let app = Router::new()
//!     .route("/api/protected", get(protected_handler))
//!     .layer(ArgusLayer::new(argus_client));
//! ```
//!
//! # Extractors
//!
//! - [`RequireAuth`] - Requires valid authentication (401 if missing)
//! - [`MaybeAuth`] - Optional authentication (None if missing)
//! - [`RequireTier`] - Requires minimum subscription tier (403 if insufficient)
//! - [`RequireFeature`] - Requires specific feature entitlement (403 if not entitled)
//! - [`RequireAdmin`] - Requires admin role (403 if not admin)
//!
//! # Features
//!
//! - `rate-limiting` - Enable rate limiting via `governor` crate
//! - `metrics` - Enable Prometheus metrics collection

pub mod context;
pub mod error;
pub mod extractors;
pub mod layer;
#[cfg(feature = "rate-limiting")]
pub mod rate_limit;
pub mod usage;

// Re-export primary types
pub use context::{AuthContext, AuthSource, RateLimitPolicy, Role};
pub use error::AuthError;
pub use extractors::{MaybeAuth, RequireAdmin, RequireAuth, RequireFeature, RequireTier};
pub use layer::{ArgusLayer, ArgusService};
pub use usage::{StreamingAuthGuard, UsageRecorder, UsageTracker};
