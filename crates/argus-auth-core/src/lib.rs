//! Argus Auth Core - Authentication business logic
//!
//! Core authentication functionality including:
//! - AWS Cognito JWT validation with JWKS caching
//! - Session management with HMAC-signed cookies
//! - Tier and entitlement checks with caching
//!
//! # Security Features
//!
//! - **Constant-time signature verification** - Prevents timing attacks
//! - **Strict session validation** - Unknown sessions are rejected
//! - **JWKS caching with rotation** - Efficient key management
//!
//! # Example
//!
//! ```rust,ignore
//! use argus_auth_core::{AuthConfig, AuthService};
//! use argus_db::Repositories;
//!
//! // Create config
//! let config = AuthConfig::new(
//!     "us-east-1_xxxxx",  // Cognito pool ID
//!     "us-east-1",        // AWS region
//!     "client-id",        // App client ID
//!     "session-secret",   // HMAC secret (min 32 bytes)
//! );
//!
//! // Create service
//! let repos = Repositories::new(pool);
//! let auth = AuthService::new(config, repos.users, repos.sessions);
//!
//! // Validate a token
//! let claims = auth.validate_token(bearer_token).await?;
//! println!("User {} has tier {:?}", claims.user_id, claims.tier);
//!
//! // Check entitlement
//! let check = auth.check_entitlement(&claims.user_id, "webhooks").await?;
//! if check.allowed {
//!     // Process webhook request
//! }
//! ```

pub mod config;
pub mod crypto;
pub mod entitlement;
pub mod error;
pub mod service;
pub mod session;
pub mod token;

// Re-exports
pub use config::{AuthConfig, ConfigError, SecretBytes, MIN_SECRET_LENGTH};
pub use crypto::{constant_time_eq, hash_token, HmacKey};
pub use entitlement::EntitlementChecker;
pub use error::AuthError;
pub use service::{AuthService, ClaimsSource, ValidatedClaims};
pub use session::{extract_role_from_groups, extract_tier_from_groups, SessionManager, SessionPayload};
pub use token::{CognitoClaims, Jwk, Jwks, TokenValidator};
