//! Authentication context types.
//!
//! The [`AuthContext`] struct contains all authenticated user information
//! available to request handlers.

use argus_types::{Tier, UserId};

/// User role for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Regular user.
    #[default]
    User,
    /// Administrator.
    Admin,
    /// Super administrator with full access.
    SuperAdmin,
}

/// Source of the authentication credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    /// Bearer token from Authorization header.
    BearerToken,
    /// API key from X-API-Key header.
    ApiKey,
    /// Session from cookie or X-Cognito-Session header.
    Session,
    /// Unknown or internal source.
    Unknown,
}

/// Rate limit policy for the authenticated user.
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitPolicy {
    /// Maximum requests per minute.
    pub requests_per_minute: u32,
    /// Maximum requests per hour.
    pub requests_per_hour: Option<u32>,
    /// Maximum requests per day.
    pub requests_per_day: Option<u32>,
    /// Burst allowance above the rate limit.
    pub burst_size: u32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_hour: None,
            requests_per_day: None,
            burst_size: 10,
        }
    }
}

impl RateLimitPolicy {
    /// Create a policy for a given tier.
    #[must_use]
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Explorer => Self {
                requests_per_minute: 10,
                requests_per_hour: Some(100),
                requests_per_day: Some(500),
                burst_size: 5,
            },
            Tier::Professional => Self {
                requests_per_minute: 60,
                requests_per_hour: Some(1000),
                requests_per_day: Some(10000),
                burst_size: 20,
            },
            Tier::Business => Self {
                requests_per_minute: 120,
                requests_per_hour: Some(5000),
                requests_per_day: None,
                burst_size: 50,
            },
            Tier::Enterprise => Self {
                requests_per_minute: 600,
                requests_per_hour: None,
                requests_per_day: None,
                burst_size: 100,
            },
        }
    }
}

/// Authentication context containing user information and entitlements.
///
/// This struct is populated by the Argus middleware and can be accessed
/// via the auth extractors.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated user's ID.
    pub user_id: UserId,
    /// The user's subscription tier.
    pub tier: Tier,
    /// The user's role (user, admin, etc.).
    pub role: Role,
    /// Feature entitlements (e.g., "premium_models", "api_access").
    pub features: Vec<String>,
    /// Rate limiting policy for this user.
    pub rate_limits: RateLimitPolicy,
    /// Source of the authentication.
    pub source: AuthSource,
    /// Optional organization ID if user is acting on behalf of an org.
    pub organization_id: Option<String>,
    /// Optional session ID for session-based auth.
    pub session_id: Option<String>,
}

impl AuthContext {
    /// Create a new auth context with minimal information.
    #[must_use]
    pub fn new(user_id: UserId, tier: Tier) -> Self {
        Self {
            user_id,
            tier,
            role: Role::User,
            features: Vec::new(),
            rate_limits: RateLimitPolicy::for_tier(tier),
            source: AuthSource::Unknown,
            organization_id: None,
            session_id: None,
        }
    }

    /// Set the user's role.
    #[must_use]
    pub fn with_role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }

    /// Add feature entitlements.
    #[must_use]
    pub fn with_features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
    }

    /// Set the auth source.
    #[must_use]
    pub fn with_source(mut self, source: AuthSource) -> Self {
        self.source = source;
        self
    }

    /// Set the organization ID.
    #[must_use]
    pub fn with_organization(mut self, org_id: impl Into<String>) -> Self {
        self.organization_id = Some(org_id.into());
        self
    }

    /// Set the session ID.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set custom rate limits.
    #[must_use]
    pub fn with_rate_limits(mut self, limits: RateLimitPolicy) -> Self {
        self.rate_limits = limits;
        self
    }

    /// Check if the user has a specific feature entitlement.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// Check if the user has at least the specified tier.
    #[must_use]
    pub fn has_tier(&self, required: Tier) -> bool {
        self.tier >= required
    }

    /// Check if the user is an admin.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        matches!(self.role, Role::Admin | Role::SuperAdmin)
    }

    /// Check if the user is a super admin.
    #[must_use]
    pub fn is_super_admin(&self) -> bool {
        matches!(self.role, Role::SuperAdmin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_builder() {
        let ctx = AuthContext::new(UserId::new(), Tier::Professional)
            .with_role(Role::Admin)
            .with_features(vec!["premium".into(), "api".into()])
            .with_source(AuthSource::BearerToken)
            .with_organization("org_123");

        assert_eq!(ctx.tier, Tier::Professional);
        assert!(ctx.is_admin());
        assert!(ctx.has_feature("premium"));
        assert!(!ctx.has_feature("unknown"));
        assert_eq!(ctx.organization_id, Some("org_123".to_string()));
    }

    #[test]
    fn test_tier_comparison() {
        let ctx = AuthContext::new(UserId::new(), Tier::Professional);

        assert!(ctx.has_tier(Tier::Explorer));
        assert!(ctx.has_tier(Tier::Professional));
        assert!(!ctx.has_tier(Tier::Business));
        assert!(!ctx.has_tier(Tier::Enterprise));
    }

    #[test]
    fn test_rate_limit_for_tier() {
        let explorer = RateLimitPolicy::for_tier(Tier::Explorer);
        assert_eq!(explorer.requests_per_minute, 10);

        let enterprise = RateLimitPolicy::for_tier(Tier::Enterprise);
        assert_eq!(enterprise.requests_per_minute, 600);
        assert!(enterprise.requests_per_day.is_none());
    }
}
