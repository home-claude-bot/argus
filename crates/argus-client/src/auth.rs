//! Auth client
//!
//! Client for authentication and session management operations.

use argus_proto::auth_service::auth_service_client::AuthServiceClient;
use argus_types::{Tier, UserId};
use tonic::transport::Channel;
use tracing::instrument;

use crate::{ClientConfig, ClientError, Result};

/// Client for auth service operations.
///
/// Provides methods for:
/// - Token validation (single and batch)
/// - Session management (create, revoke, list)
/// - Token refresh
/// - Entitlement checks
/// - Rate limit queries
#[derive(Debug, Clone)]
pub struct AuthClient {
    inner: AuthServiceClient<Channel>,
    #[allow(dead_code)]
    config: ClientConfig,
}

impl AuthClient {
    /// Connect to the auth service.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let channel = tonic::transport::Channel::from_shared(config.auth_endpoint.clone())
            .map_err(|e| ClientError::connection(format!("invalid endpoint: {e}"), false))?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .connect_lazy();

        let inner = AuthServiceClient::new(channel);

        Ok(Self { inner, config })
    }

    /// Create from an existing channel.
    pub fn from_channel(channel: Channel, config: ClientConfig) -> Self {
        Self {
            inner: AuthServiceClient::new(channel),
            config,
        }
    }

    // =========================================================================
    // Token Validation
    // =========================================================================

    /// Validate a JWT or session token.
    ///
    /// Returns token claims if valid, or an error if invalid.
    #[instrument(skip(self, token), level = "debug")]
    pub async fn validate_token(&mut self, token: &str) -> Result<TokenInfo> {
        self.validate_token_with_options(token, None, &[]).await
    }

    /// Validate a token with audience and scope requirements.
    #[instrument(skip(self, token), level = "debug")]
    pub async fn validate_token_with_options(
        &mut self,
        token: &str,
        audience: Option<&str>,
        required_scopes: &[&str],
    ) -> Result<TokenInfo> {
        use argus_proto::ValidateTokenRequest;

        let request = ValidateTokenRequest {
            token: token.to_string(),
            audience: audience.unwrap_or_default().to_string(),
            required_scopes: required_scopes.iter().map(|s| (*s).to_string()).collect(),
        };

        let response = self.inner.validate_token(request).await?.into_inner();

        if !response.valid {
            let error_msg = response
                .error
                .map_or_else(|| "invalid token".to_string(), |e| e.message);
            return Err(ClientError::Unauthenticated(error_msg));
        }

        let claims = response
            .claims
            .ok_or_else(|| ClientError::Internal("missing claims in response".to_string()))?;

        Ok(TokenInfo::from_proto(claims))
    }

    /// Batch validate multiple tokens.
    ///
    /// Returns a vector of results in the same order as input tokens.
    pub async fn batch_validate_tokens(
        &mut self,
        tokens: &[&str],
        audience: Option<&str>,
        required_scopes: &[&str],
    ) -> Result<BatchValidateResult> {
        use argus_proto::BatchValidateTokensRequest;

        let request = BatchValidateTokensRequest {
            tokens: tokens.iter().map(|s| (*s).to_string()).collect(),
            audience: audience.unwrap_or_default().to_string(),
            required_scopes: required_scopes.iter().map(|s| (*s).to_string()).collect(),
        };

        let response = self
            .inner
            .batch_validate_tokens(request)
            .await?
            .into_inner();

        let results = response
            .results
            .into_iter()
            .map(|r| {
                if r.valid {
                    r.claims.map(TokenInfo::from_proto)
                } else {
                    None
                }
            })
            .collect();

        Ok(BatchValidateResult {
            results,
            valid_count: response.valid_count,
            invalid_count: response.invalid_count,
        })
    }

    // =========================================================================
    // Session Management
    // =========================================================================

    /// Create a session from Cognito tokens.
    #[instrument(skip(self, id_token, access_token), level = "debug")]
    pub async fn create_session(
        &mut self,
        id_token: &str,
        access_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<SessionInfo> {
        use argus_proto::CreateSessionRequest;

        let request = CreateSessionRequest {
            id_token: id_token.to_string(),
            access_token: access_token.to_string(),
            ip_address: ip_address.unwrap_or_default().to_string(),
            user_agent: user_agent.unwrap_or_default().to_string(),
        };

        let response = self.inner.create_session(request).await?.into_inner();

        let session_id = response
            .session_id
            .ok_or_else(|| ClientError::Internal("missing session_id in response".to_string()))?;

        Ok(SessionInfo {
            session_id: session_id.value,
            session_cookie: response.session_cookie,
            expires_at: response.expires_at.as_ref().map(timestamp_to_datetime),
        })
    }

    /// Refresh an access token.
    #[instrument(skip(self, refresh_token), level = "debug")]
    pub async fn refresh_token(&mut self, refresh_token: &str) -> Result<RefreshResult> {
        use argus_proto::RefreshTokenRequest;

        let request = RefreshTokenRequest {
            refresh_token: refresh_token.to_string(),
        };

        let response = self.inner.refresh_token(request).await?.into_inner();

        Ok(RefreshResult {
            access_token: response.access_token,
            id_token: if response.id_token.is_empty() {
                None
            } else {
                Some(response.id_token)
            },
            expires_in_secs: response.expires_in,
            token_type: response.token_type,
        })
    }

    /// Revoke a specific session.
    pub async fn revoke_session(
        &mut self,
        session_id: &str,
        requester_id: Option<&UserId>,
        reason: Option<&str>,
    ) -> Result<bool> {
        use argus_proto::{RevokeSessionRequest, SessionId, UserId as ProtoUserId};

        let request = RevokeSessionRequest {
            session_id: Some(SessionId {
                value: session_id.to_string(),
            }),
            requester_id: requester_id.map(|id| ProtoUserId {
                value: id.to_string(),
            }),
            reason: reason.unwrap_or_default().to_string(),
        };

        let response = self.inner.revoke_session(request).await?.into_inner();
        Ok(response.success)
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_sessions(
        &mut self,
        user_id: &UserId,
        exclude_session_id: Option<&str>,
        requester_id: Option<&UserId>,
        reason: Option<&str>,
    ) -> Result<u64> {
        use argus_proto::{RevokeAllSessionsRequest, SessionId, UserId as ProtoUserId};

        let request = RevokeAllSessionsRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            exclude_session_id: exclude_session_id.map(|id| SessionId {
                value: id.to_string(),
            }),
            requester_id: requester_id.map(|id| ProtoUserId {
                value: id.to_string(),
            }),
            reason: reason.unwrap_or_default().to_string(),
        };

        let response = self.inner.revoke_all_sessions(request).await?.into_inner();
        Ok(response.revoked_count)
    }

    /// List active sessions for a user.
    pub async fn list_sessions(
        &mut self,
        user_id: &UserId,
        include_revoked: bool,
    ) -> Result<Vec<Session>> {
        use argus_proto::{ListSessionsRequest, UserId as ProtoUserId};

        let request = ListSessionsRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            include_revoked,
            pagination: None,
        };

        let response = self.inner.list_sessions(request).await?.into_inner();

        let sessions = response
            .sessions
            .into_iter()
            .map(Session::from_proto)
            .collect();

        Ok(sessions)
    }

    // =========================================================================
    // Entitlements
    // =========================================================================

    /// Check if a user has access to a feature.
    #[instrument(skip(self), level = "debug")]
    pub async fn check_entitlement(
        &mut self,
        user_id: &UserId,
        feature: &str,
    ) -> Result<EntitlementResult> {
        use argus_proto::{CheckEntitlementRequest, UserId as ProtoUserId};

        let request = CheckEntitlementRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            feature: feature.to_string(),
        };

        let response = self.inner.check_entitlement(request).await?.into_inner();

        // Extract enum values before moving fields
        let tier = tier_from_proto(response.tier());
        let required_tier = tier_from_proto(response.required_tier());
        let allowed = response.allowed;
        let remaining = response.remaining;

        Ok(EntitlementResult {
            allowed,
            reason: if response.reason.is_empty() {
                None
            } else {
                Some(response.reason)
            },
            remaining,
            tier,
            required_tier,
        })
    }

    /// Batch check multiple entitlements.
    pub async fn batch_check_entitlements(
        &mut self,
        user_id: &UserId,
        features: &[&str],
    ) -> Result<BatchEntitlementResult> {
        use argus_proto::{BatchCheckEntitlementsRequest, UserId as ProtoUserId};

        let request = BatchCheckEntitlementsRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            features: features.iter().map(|s| (*s).to_string()).collect(),
        };

        let response = self
            .inner
            .batch_check_entitlements(request)
            .await?
            .into_inner();

        // Extract tier before consuming results
        let tier = tier_from_proto(response.tier());

        let results = response
            .results
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    SingleEntitlementResult {
                        allowed: v.allowed,
                        reason: if v.reason.is_empty() {
                            None
                        } else {
                            Some(v.reason)
                        },
                        remaining: v.remaining,
                    },
                )
            })
            .collect();

        Ok(BatchEntitlementResult { results, tier })
    }

    /// Get a user's tier.
    pub async fn get_user_tier(&mut self, user_id: &UserId) -> Result<UserTierInfo> {
        use argus_proto::{GetUserTierRequest, UserId as ProtoUserId};

        let request = GetUserTierRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.get_user_tier(request).await?.into_inner();

        Ok(UserTierInfo {
            tier: tier_from_proto(response.tier()),
            features: response.features,
            rate_limit: response.rate_limit.as_ref().map(RateLimit::from_proto),
        })
    }

    /// Get rate limit for a user.
    pub async fn get_rate_limit(&mut self, user_id: &UserId) -> Result<RateLimitInfo> {
        use argus_proto::{GetRateLimitRequest, UserId as ProtoUserId};

        let request = GetRateLimitRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.get_rate_limit(request).await?.into_inner();

        Ok(RateLimitInfo {
            rate_limit: response.rate_limit.as_ref().map(RateLimit::from_proto),
            status: response.status.as_ref().map(RateLimitStatus::from_proto),
        })
    }

    /// Introspect a token (get claims without full validation).
    ///
    /// **Note**: This is an internal-only operation.
    pub async fn introspect_token(&mut self, token: &str) -> Result<IntrospectResult> {
        use argus_proto::IntrospectTokenRequest;

        let request = IntrospectTokenRequest {
            token: token.to_string(),
        };

        let response = self.inner.introspect_token(request).await?.into_inner();

        Ok(IntrospectResult {
            active: response.active,
            claims: response.claims.map(TokenInfo::from_proto),
            token_type: response.token_type,
            client_id: response.client_id,
        })
    }

    /// Health check.
    pub async fn health_check(&mut self) -> Result<bool> {
        use argus_proto::HealthCheckRequest;

        let request = HealthCheckRequest {
            service: String::new(),
        };

        let response = self.inner.health_check(request).await?.into_inner();

        Ok(response.status() == argus_proto::health_check_response::ServingStatus::Serving)
    }
}

// =============================================================================
// Domain Types
// =============================================================================

/// Token information extracted from a validated token.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// User ID
    pub user_id: UserId,
    /// User email
    pub email: String,
    /// Whether email is verified
    pub email_verified: bool,
    /// User's subscription tier
    pub tier: Tier,
    /// Cognito groups
    pub groups: Vec<String>,
    /// Token scopes
    pub scopes: Vec<String>,
    /// Token source
    pub source: TokenSource,
}

impl TokenInfo {
    fn from_proto(proto: argus_proto::TokenClaims) -> Self {
        // Extract enum values before moving fields
        let tier = tier_from_proto(proto.tier());
        let source = match proto.source() {
            argus_proto::TokenSource::Jwt => TokenSource::Jwt,
            argus_proto::TokenSource::Session => TokenSource::Session,
            argus_proto::TokenSource::Unspecified => TokenSource::Unknown,
        };
        let email_verified = proto.email_verified;

        Self {
            user_id: UserId::parse(&proto.user_id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            email: proto.email,
            email_verified,
            tier,
            groups: proto.groups,
            scopes: proto.scopes,
            source,
        }
    }
}

/// Token source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// JWT token
    Jwt,
    /// Session cookie
    Session,
    /// Unknown source
    Unknown,
}

/// Result of batch token validation.
#[derive(Debug, Clone)]
pub struct BatchValidateResult {
    /// Results in same order as input tokens (None if invalid)
    pub results: Vec<Option<TokenInfo>>,
    /// Number of valid tokens
    pub valid_count: u32,
    /// Number of invalid tokens
    pub invalid_count: u32,
}

/// Session creation result.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: String,
    /// Signed session cookie value
    pub session_cookie: String,
    /// Session expiration
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Token refresh result.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// New access token
    pub access_token: String,
    /// New ID token (if applicable)
    pub id_token: Option<String>,
    /// Token expiration in seconds
    pub expires_in_secs: u64,
    /// Token type (Bearer)
    pub token_type: String,
}

/// Session information.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session ID
    pub session_id: String,
    /// When the session was created
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the session expires
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last activity time
    pub last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: String,
    /// Whether this is the current session
    pub is_current: bool,
    /// Whether session is revoked
    pub revoked: bool,
}

impl Session {
    fn from_proto(proto: argus_proto::SessionInfo) -> Self {
        Self {
            session_id: proto.session_id.map_or_else(String::new, |id| id.value),
            created_at: proto.created_at.as_ref().map(timestamp_to_datetime),
            expires_at: proto.expires_at.as_ref().map(timestamp_to_datetime),
            last_active_at: proto.last_active_at.as_ref().map(timestamp_to_datetime),
            ip_address: proto.ip_address,
            user_agent: proto.user_agent,
            is_current: proto.is_current,
            revoked: proto.revoked,
        }
    }
}

/// Entitlement check result.
#[derive(Debug, Clone)]
pub struct EntitlementResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reason if denied
    pub reason: Option<String>,
    /// Remaining usage (if limited)
    pub remaining: Option<u64>,
    /// User's current tier
    pub tier: Tier,
    /// Minimum tier required
    pub required_tier: Tier,
}

/// Single entitlement result (for batch checks).
#[derive(Debug, Clone)]
pub struct SingleEntitlementResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reason if denied
    pub reason: Option<String>,
    /// Remaining usage (if limited)
    pub remaining: Option<u64>,
}

/// Batch entitlement check result.
#[derive(Debug, Clone)]
pub struct BatchEntitlementResult {
    /// Results keyed by feature name
    pub results: std::collections::HashMap<String, SingleEntitlementResult>,
    /// User's current tier
    pub tier: Tier,
}

/// User tier information.
#[derive(Debug, Clone)]
pub struct UserTierInfo {
    /// User's current tier
    pub tier: Tier,
    /// Features available at this tier
    pub features: Vec<String>,
    /// Rate limit for this tier
    pub rate_limit: Option<RateLimit>,
}

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum requests per window
    pub requests: u32,
    /// Window duration in seconds
    pub window_seconds: u32,
}

impl RateLimit {
    fn from_proto(proto: &argus_proto::RateLimit) -> Self {
        Self {
            requests: proto.requests,
            window_seconds: proto.window_seconds,
        }
    }
}

/// Rate limit status.
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Maximum requests allowed
    pub limit: u32,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Seconds until window resets
    pub reset_seconds: u32,
}

impl RateLimitStatus {
    fn from_proto(proto: &argus_proto::RateLimitStatus) -> Self {
        Self {
            limit: proto.limit,
            remaining: proto.remaining,
            reset_seconds: proto.reset_seconds,
        }
    }
}

/// Rate limit information.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Rate limit configuration
    pub rate_limit: Option<RateLimit>,
    /// Current rate limit status
    pub status: Option<RateLimitStatus>,
}

/// Token introspection result.
#[derive(Debug, Clone)]
pub struct IntrospectResult {
    /// Whether token is active
    pub active: bool,
    /// Token claims (if active)
    pub claims: Option<TokenInfo>,
    /// Token type
    pub token_type: String,
    /// Client ID the token was issued to
    pub client_id: String,
}

// =============================================================================
// Helpers
// =============================================================================

fn tier_from_proto(tier: argus_proto::Tier) -> Tier {
    match tier {
        argus_proto::Tier::Unspecified | argus_proto::Tier::Explorer => Tier::Explorer,
        argus_proto::Tier::Professional => Tier::Professional,
        argus_proto::Tier::Business => Tier::Business,
        argus_proto::Tier::Enterprise => Tier::Enterprise,
    }
}

fn timestamp_to_datetime(ts: &prost_types::Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_else(chrono::Utc::now)
}
