//! Axum extractors for authentication and authorization.
//!
//! These extractors integrate with the Argus middleware to provide
//! convenient access to authentication context in handlers.
//!
//! # Usage
//!
//! ```ignore
//! use argus_axum::{RequireAuth, RequireTier, MaybeAuth};
//! use argus_types::Tier;
//!
//! // Requires authentication (401 if not authenticated)
//! async fn protected(auth: RequireAuth) -> String {
//!     format!("Hello, {}!", auth.user_id)
//! }
//!
//! // Requires specific tier (403 if insufficient)
//! async fn premium(auth: RequireTier<{ Tier::Professional as u8 }>) -> String {
//!     "Premium content".to_string()
//! }
//!
//! // Optional authentication
//! async fn maybe_auth(auth: MaybeAuth) -> String {
//!     match auth.0 {
//!         Some(ctx) => format!("Hello, {}!", ctx.user_id),
//!         None => "Hello, guest!".to_string(),
//!     }
//! }
//! ```

use std::ops::Deref;

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::context::AuthContext;
use crate::error::AuthError;

/// Extension key for storing auth context in request extensions.
#[derive(Debug, Clone)]
pub struct AuthContextExt(pub AuthContext);

/// Extractor that requires authentication.
///
/// Returns 401 Unauthorized if no valid authentication is present.
///
/// # Example
///
/// ```ignore
/// async fn handler(auth: RequireAuth) -> impl IntoResponse {
///     format!("User ID: {}", auth.user_id)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequireAuth(pub AuthContext);

impl Deref for RequireAuth {
    type Target = AuthContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContextExt>()
            .cloned()
            .map(|ext| Self(ext.0))
            .ok_or(AuthError::Unauthenticated)
    }
}

/// Extractor for optional authentication.
///
/// Returns `None` if no authentication is present, rather than failing.
///
/// # Example
///
/// ```ignore
/// async fn handler(auth: MaybeAuth) -> impl IntoResponse {
///     match auth.0 {
///         Some(ctx) => format!("Hello, {}!", ctx.user_id),
///         None => "Hello, guest!".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MaybeAuth(pub Option<AuthContext>);

impl Deref for MaybeAuth {
    type Target = Option<AuthContext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for MaybeAuth
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .extensions
            .get::<AuthContextExt>()
            .cloned()
            .map(|ext| ext.0);
        Ok(Self(auth))
    }
}

/// Extractor that requires a minimum subscription tier.
///
/// Returns 403 Forbidden if the user's tier is below the required level.
///
/// # Example
///
/// ```ignore
/// use argus_types::Tier;
///
/// async fn premium_handler(auth: RequireTier) -> impl IntoResponse {
///     // Access granted only for Professional tier and above
///     "Premium content"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequireTier {
    /// The authenticated context.
    pub context: AuthContext,
    /// The required tier that was checked.
    pub required_tier: argus_types::Tier,
}

impl Deref for RequireTier {
    type Target = AuthContext;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl RequireTier {
    /// Create a new RequireTier extractor that checks for a specific tier.
    ///
    /// This is typically used via the middleware configuration rather than
    /// directly in handlers.
    pub fn new(context: AuthContext, required: argus_types::Tier) -> Result<Self, AuthError> {
        if context.has_tier(required) {
            Ok(Self {
                context,
                required_tier: required,
            })
        } else {
            Err(AuthError::insufficient_tier(
                format!("{required:?}"),
                format!("{:?}", context.tier),
            ))
        }
    }
}

/// Extractor that requires a specific feature entitlement.
///
/// Returns 403 Forbidden if the user doesn't have the required feature.
///
/// # Example
///
/// ```ignore
/// async fn api_access(auth: RequireFeature) -> impl IntoResponse {
///     // Only users with "api_access" feature can reach this
///     "API response"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequireFeature {
    /// The authenticated context.
    pub context: AuthContext,
    /// The required feature that was checked.
    pub required_feature: String,
}

impl Deref for RequireFeature {
    type Target = AuthContext;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl RequireFeature {
    /// Create a new RequireFeature extractor that checks for a specific feature.
    pub fn new(context: AuthContext, feature: impl Into<String>) -> Result<Self, AuthError> {
        let feature = feature.into();
        if context.has_feature(&feature) {
            Ok(Self {
                context,
                required_feature: feature,
            })
        } else {
            Err(AuthError::FeatureNotAvailable(feature))
        }
    }
}

/// Extractor that requires admin role.
///
/// Returns 403 Forbidden if the user is not an admin.
///
/// # Example
///
/// ```ignore
/// async fn admin_only(auth: RequireAdmin) -> impl IntoResponse {
///     "Admin panel"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthContext);

impl Deref for RequireAdmin {
    type Target = AuthContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RequireAdmin
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .extensions
            .get::<AuthContextExt>()
            .cloned()
            .map(|ext| ext.0)
            .ok_or(AuthError::Unauthenticated)?;

        if auth.is_admin() {
            Ok(Self(auth))
        } else {
            Err(AuthError::InsufficientRole("admin".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Role;
    use argus_types::{Tier, UserId};

    fn make_auth_context(tier: Tier, role: Role, features: Vec<&str>) -> AuthContext {
        AuthContext::new(UserId::new(), tier)
            .with_role(role)
            .with_features(features.into_iter().map(String::from).collect())
    }

    #[test]
    fn test_require_tier_success() {
        let ctx = make_auth_context(Tier::Professional, Role::User, vec![]);
        let result = RequireTier::new(ctx, Tier::Explorer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_tier_failure() {
        let ctx = make_auth_context(Tier::Explorer, Role::User, vec![]);
        let result = RequireTier::new(ctx, Tier::Professional);
        assert!(matches!(result, Err(AuthError::InsufficientTier { .. })));
    }

    #[test]
    fn test_require_feature_success() {
        let ctx = make_auth_context(Tier::Professional, Role::User, vec!["premium", "api"]);
        let result = RequireFeature::new(ctx, "premium");
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_feature_failure() {
        let ctx = make_auth_context(Tier::Professional, Role::User, vec!["api"]);
        let result = RequireFeature::new(ctx, "premium");
        assert!(matches!(result, Err(AuthError::FeatureNotAvailable(_))));
    }
}
