//! Auth service - ties together token validation, session management, and entitlements

use argus_db::{SessionRepository, UserRepository};
use argus_types::{EntitlementCheck, Feature, RateLimit, SessionId, Tier, UserId};
use std::sync::Arc;

use crate::{
    config::AuthConfig,
    entitlement::EntitlementChecker,
    session::{extract_role_from_groups, extract_tier_from_groups, SessionManager},
    token::{CognitoClaims, TokenValidator},
    AuthError,
};

/// Validated token claims for API responses
#[derive(Debug, Clone)]
pub struct ValidatedClaims {
    /// User ID
    pub user_id: UserId,
    /// User email
    pub email: Option<String>,
    /// User tier
    pub tier: Tier,
    /// Cognito groups
    pub groups: Vec<String>,
    /// Whether this was validated from a JWT or session cookie
    pub source: ClaimsSource,
}

/// Source of validated claims
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsSource {
    /// Claims from Cognito JWT
    Jwt,
    /// Claims from session cookie
    Session,
}

/// Authentication service
///
/// Provides unified interface for:
/// - Token validation (Cognito JWT)
/// - Session management (signed cookies)
/// - Tier and entitlement checks
pub struct AuthService<U: UserRepository, S: SessionRepository> {
    config: AuthConfig,
    token_validator: TokenValidator,
    session_manager: SessionManager<S>,
    entitlement_checker: EntitlementChecker<U>,
    user_repo: Arc<U>,
}

impl<U: UserRepository, S: SessionRepository> AuthService<U, S> {
    /// Create a new auth service
    pub fn new(config: AuthConfig, user_repo: Arc<U>, session_repo: Arc<S>) -> Self {
        let session_duration_hours = (config.session_duration.as_secs() / 3600) as u32;

        Self {
            token_validator: TokenValidator::new(config.clone()),
            session_manager: SessionManager::new(
                config.session_secret(),
                session_duration_hours,
                session_repo,
            ),
            entitlement_checker: EntitlementChecker::new(Arc::clone(&user_repo)),
            user_repo,
            config,
        }
    }

    // =========================================================================
    // Token Validation
    // =========================================================================

    /// Validate a Cognito JWT access token
    pub async fn validate_jwt(&self, token: &str) -> Result<ValidatedClaims, AuthError> {
        let claims = self.token_validator.validate(token).await?;
        let user_id = UserId::parse(&claims.sub).map_err(|_| AuthError::InvalidToken)?;

        // Extract tier directly from Cognito groups - avoids unnecessary DB lookup
        // This is the source of truth from Cognito and matches what session creation uses
        let tier = extract_tier_from_groups(&claims.cognito_groups);

        Ok(ValidatedClaims {
            user_id,
            email: claims.email,
            tier,
            groups: claims.cognito_groups,
            source: ClaimsSource::Jwt,
        })
    }

    /// Validate a session cookie
    pub async fn validate_session(&self, cookie: &str) -> Result<ValidatedClaims, AuthError> {
        let payload = self.session_manager.validate_session(cookie).await?;

        let user_id = payload.user_id().ok_or(AuthError::InvalidToken)?;
        let tier: Tier = payload.tier.parse().unwrap_or(Tier::Explorer);

        Ok(ValidatedClaims {
            user_id,
            email: Some(payload.email),
            tier,
            groups: payload.groups,
            source: ClaimsSource::Session,
        })
    }

    /// Validate either a JWT or session cookie (auto-detect)
    ///
    /// Token detection:
    /// - JWT format: `xxxxx.xxxxx.xxxxx` (2 dots)
    /// - Session format: `payload.signature` (1 dot)
    pub async fn validate_token(&self, token: &str) -> Result<ValidatedClaims, AuthError> {
        // Fast path: count dots to determine token type
        // Using matches! for simple pattern matching on short tokens
        let dot_count = token.bytes().filter(|&b| b == b'.').count();

        match dot_count {
            2 => self.validate_jwt(token).await,
            1 => self.validate_session(token).await,
            _ => Err(AuthError::InvalidToken),
        }
    }

    // =========================================================================
    // Session Management
    // =========================================================================

    /// Create a session from Cognito tokens
    ///
    /// This should be called after successful Cognito authentication.
    /// Returns the session ID and signed cookie value.
    pub async fn create_session(
        &self,
        cognito_claims: &CognitoClaims,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SessionId, String), AuthError> {
        // Get or create user
        let user_id = self.get_or_create_user(cognito_claims).await?;

        let email = cognito_claims.email.clone().unwrap_or_default();
        let groups = cognito_claims.cognito_groups.clone();

        self.session_manager
            .create_session(user_id, email, groups, ip_address, user_agent)
            .await
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthError> {
        self.session_manager.revoke_session(session_id).await
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_sessions(&self, user_id: &UserId) -> Result<u64, AuthError> {
        self.session_manager.revoke_all_sessions(*user_id).await
    }

    // =========================================================================
    // User Management
    // =========================================================================

    /// Get or create a user from Cognito claims
    async fn get_or_create_user(&self, claims: &CognitoClaims) -> Result<UserId, AuthError> {
        // Try to find by Cognito sub
        if let Some(user) = self.user_repo.find_by_cognito_sub(&claims.sub).await? {
            return Ok(user.user_id());
        }

        // Create new user
        let email = claims
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@cognito", claims.sub));
        let tier = extract_tier_from_groups(&claims.cognito_groups);
        let role = extract_role_from_groups(&claims.cognito_groups);

        let new_user = argus_db::CreateUser {
            id: uuid::Uuid::new_v4(),
            email,
            cognito_sub: Some(claims.sub.clone()),
            tier: tier.to_string(),
            role: role.to_string(),
        };

        let user = self.user_repo.create(new_user).await?;
        Ok(user.user_id())
    }

    // =========================================================================
    // Tier and Entitlements
    // =========================================================================

    /// Get user's tier
    pub async fn get_user_tier(&self, user_id: &UserId) -> Result<Tier, AuthError> {
        self.entitlement_checker.get_tier(user_id).await
    }

    /// Check if user has access to a feature (string-based)
    pub async fn check_entitlement(
        &self,
        user_id: &UserId,
        feature: &str,
    ) -> Result<EntitlementCheck, AuthError> {
        self.entitlement_checker
            .check_feature(user_id, feature)
            .await
    }

    /// Check if user has access to a typed feature
    pub async fn check_feature(
        &self,
        user_id: &UserId,
        feature: Feature,
    ) -> Result<EntitlementCheck, AuthError> {
        self.entitlement_checker
            .check_typed_feature(user_id, feature)
            .await
    }

    /// Check if user has access to a feature (boolean result)
    pub async fn has_feature(&self, user_id: &UserId, feature: &str) -> Result<bool, AuthError> {
        let check = self.check_entitlement(user_id, feature).await?;
        Ok(check.allowed)
    }

    /// Get rate limit for user
    pub async fn get_rate_limit(&self, user_id: &UserId) -> Result<RateLimit, AuthError> {
        self.entitlement_checker.get_rate_limit(user_id).await
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Invalidate all caches for a user
    pub async fn invalidate_user_cache(&self, user_id: &UserId) {
        self.entitlement_checker.invalidate_tier(user_id).await;
    }

    /// Invalidate JWKS cache (call when keys rotate)
    pub async fn invalidate_jwks_cache(&self) {
        self.token_validator.invalidate_cache().await;
    }
}

impl<U: UserRepository, S: SessionRepository> std::fmt::Debug for AuthService<U, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_detection() {
        // JWT has 2 dots
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature";
        assert_eq!(jwt.bytes().filter(|&b| b == b'.').count(), 2);

        // Session cookie has 1 dot
        let session = "base64payload.signature";
        assert_eq!(session.bytes().filter(|&b| b == b'.').count(), 1);

        // Invalid token has 0 or 3+ dots
        let invalid = "nodots";
        assert_eq!(invalid.bytes().filter(|&b| b == b'.').count(), 0);
    }

    #[test]
    fn test_claims_source_equality() {
        assert_eq!(ClaimsSource::Jwt, ClaimsSource::Jwt);
        assert_eq!(ClaimsSource::Session, ClaimsSource::Session);
        assert_ne!(ClaimsSource::Jwt, ClaimsSource::Session);
    }
}
