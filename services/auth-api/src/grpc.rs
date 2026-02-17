//! gRPC AuthService implementation
//!
//! High-performance gRPC service with:
//! - Parallel batch operations using futures::join_all
//! - Request-level tracing with timing spans
//! - Prometheus metrics for all operations

use argus_auth_core::ClaimsSource;
use argus_proto::auth_service::auth_service_server::AuthService;
use argus_proto::{
    BatchCheckEntitlementsRequest, BatchCheckEntitlementsResponse, BatchValidateTokensRequest,
    BatchValidateTokensResponse, CheckEntitlementRequest, CheckEntitlementResponse,
    CreateSessionRequest, CreateSessionResponse, EntitlementResult, Error as ProtoError,
    GetRateLimitRequest, GetRateLimitResponse, GetUserTierRequest, GetUserTierResponse,
    HealthCheckRequest, HealthCheckResponse, IntrospectTokenRequest, IntrospectTokenResponse,
    ListSessionsRequest, ListSessionsResponse, RateLimit as ProtoRateLimit, RateLimitStatus,
    RefreshTokenRequest, RefreshTokenResponse, RevokeAllSessionsRequest, RevokeAllSessionsResponse,
    RevokeSessionRequest, RevokeSessionResponse, Role, SessionId as ProtoSessionId,
    Tier as ProtoTier, TokenClaims, TokenSource, UserId as ProtoUserId, ValidateTokenRequest,
    ValidateTokenResponse,
};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

use crate::state::AuthServiceImpl;

/// gRPC service implementation
pub struct GrpcAuthService {
    auth: Arc<AuthServiceImpl>,
}

impl GrpcAuthService {
    pub fn new(auth: Arc<AuthServiceImpl>) -> Self {
        Self { auth }
    }
}

// Helper functions for type conversions
fn tier_to_proto(tier: argus_types::Tier) -> i32 {
    match tier {
        argus_types::Tier::Explorer => ProtoTier::Explorer as i32,
        argus_types::Tier::Professional => ProtoTier::Professional as i32,
        argus_types::Tier::Business => ProtoTier::Business as i32,
        argus_types::Tier::Enterprise => ProtoTier::Enterprise as i32,
    }
}

fn source_to_proto(source: ClaimsSource) -> i32 {
    match source {
        ClaimsSource::Jwt => TokenSource::Jwt as i32,
        ClaimsSource::Session => TokenSource::Session as i32,
    }
}

#[allow(clippy::result_large_err)]
fn proto_to_user_id(proto_id: Option<ProtoUserId>) -> Result<argus_types::UserId, Status> {
    proto_id
        .and_then(|id| argus_types::UserId::parse(&id.value).ok())
        .ok_or_else(|| Status::invalid_argument("Invalid user_id"))
}

#[allow(clippy::result_large_err)]
fn proto_to_session_id(proto_id: Option<ProtoSessionId>) -> Result<argus_types::SessionId, Status> {
    proto_id
        .and_then(|id| uuid::Uuid::parse_str(&id.value).ok())
        .map(argus_types::SessionId::from)
        .ok_or_else(|| Status::invalid_argument("Invalid session_id"))
}

#[tonic::async_trait]
impl AuthService for GrpcAuthService {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let response = match self.auth.validate_token(&req.token).await {
            Ok(claims) => {
                metrics::counter!("auth_token_validations_total", "result" => "valid").increment(1);
                let now = chrono::Utc::now();
                ValidateTokenResponse {
                    valid: true,
                    claims: Some(TokenClaims {
                        user_id: Some(ProtoUserId {
                            value: claims.user_id.to_string(),
                        }),
                        email: claims.email.unwrap_or_default(),
                        email_verified: true,
                        tier: tier_to_proto(claims.tier),
                        role: Role::User as i32,
                        groups: claims.groups,
                        scopes: vec![],
                        issued_at: Some(prost_types::Timestamp {
                            seconds: now.timestamp(),
                            nanos: 0,
                        }),
                        expires_at: Some(prost_types::Timestamp {
                            seconds: now.timestamp() + 3600,
                            nanos: 0,
                        }),
                        source: source_to_proto(claims.source),
                    }),
                    error: None,
                }
            }
            Err(e) => {
                metrics::counter!("auth_token_validations_total", "result" => "invalid")
                    .increment(1);
                ValidateTokenResponse {
                    valid: false,
                    claims: None,
                    error: Some(ProtoError {
                        code: "INVALID_TOKEN".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                }
            }
        };

        metrics::histogram!("grpc_request_duration_seconds", "method" => "validate_token")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(response))
    }

    async fn batch_validate_tokens(
        &self,
        request: Request<BatchValidateTokensRequest>,
    ) -> Result<Response<BatchValidateTokensResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let batch_size = req.tokens.len();

        if batch_size > 100 {
            return Err(Status::invalid_argument("Maximum 100 tokens per batch"));
        }

        // Execute all validations in parallel for maximum throughput
        let auth = &self.auth;
        let futures: Vec<_> = req
            .tokens
            .into_iter()
            .map(|token| async move {
                let result = auth.validate_token(&token).await;
                (token, result)
            })
            .collect();

        let validation_results = join_all(futures).await;

        // Process results - single pass, no re-allocation
        let mut results = Vec::with_capacity(batch_size);
        let mut valid_count = 0u32;
        let mut invalid_count = 0u32;
        let now = chrono::Utc::now();

        for (_token, result) in validation_results {
            match result {
                Ok(claims) => {
                    valid_count += 1;
                    results.push(ValidateTokenResponse {
                        valid: true,
                        claims: Some(TokenClaims {
                            user_id: Some(ProtoUserId {
                                value: claims.user_id.to_string(),
                            }),
                            email: claims.email.unwrap_or_default(),
                            email_verified: true,
                            tier: tier_to_proto(claims.tier),
                            role: Role::User as i32,
                            groups: claims.groups,
                            scopes: vec![],
                            issued_at: Some(prost_types::Timestamp {
                                seconds: now.timestamp(),
                                nanos: 0,
                            }),
                            expires_at: Some(prost_types::Timestamp {
                                seconds: now.timestamp() + 3600,
                                nanos: 0,
                            }),
                            source: source_to_proto(claims.source),
                        }),
                        error: None,
                    });
                }
                Err(e) => {
                    invalid_count += 1;
                    results.push(ValidateTokenResponse {
                        valid: false,
                        claims: None,
                        error: Some(ProtoError {
                            code: "INVALID_TOKEN".to_string(),
                            message: e.to_string(),
                            details: HashMap::new(),
                        }),
                    });
                }
            }
        }

        let elapsed = start.elapsed();
        metrics::histogram!("grpc_request_duration_seconds", "method" => "batch_validate_tokens")
            .record(elapsed.as_secs_f64());
        metrics::counter!("auth_token_validations_total", "result" => "batch")
            .increment(batch_size as u64);
        tracing::debug!(
            batch_size,
            valid_count,
            invalid_count,
            elapsed_ms = elapsed.as_millis() as u64,
            "batch_validate_tokens completed"
        );

        Ok(Response::new(BatchValidateTokensResponse {
            results,
            valid_count,
            invalid_count,
        }))
    }

    async fn create_session(
        &self,
        request: Request<CreateSessionRequest>,
    ) -> Result<Response<CreateSessionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        // Validate the access token to get claims
        let claims = self
            .auth
            .validate_jwt(&req.access_token)
            .await
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        let now = chrono::Utc::now();

        // Create Cognito claims from validated token
        let cognito_claims = argus_auth_core::CognitoClaims {
            sub: claims.user_id.to_string(),
            email: claims.email,
            email_verified: Some(true),
            cognito_groups: claims.groups,
            iat: now.timestamp(),
            exp: now.timestamp() + 3600,
            iss: String::new(),
            aud: None,
            client_id: None,
            token_use: Some("access".to_string()),
        };

        // Use filter for cleaner empty string handling
        let ip_address = (!req.ip_address.is_empty()).then_some(req.ip_address);
        let user_agent = (!req.user_agent.is_empty()).then_some(req.user_agent);

        let (session_id, session_cookie) = self
            .auth
            .create_session(&cognito_claims, ip_address, user_agent)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let expires_at = now + chrono::Duration::hours(24);

        metrics::counter!("auth_sessions_created_total").increment(1);
        metrics::histogram!("grpc_request_duration_seconds", "method" => "create_session")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(CreateSessionResponse {
            session_id: Some(ProtoSessionId {
                value: session_id.to_string(),
            }),
            session_cookie,
            expires_at: Some(prost_types::Timestamp {
                seconds: expires_at.timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn refresh_token(
        &self,
        _request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        // Refresh tokens should be exchanged directly with Cognito
        Err(Status::unimplemented(
            "Refresh tokens should be exchanged directly with Cognito",
        ))
    }

    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = proto_to_session_id(req.session_id)?;

        self.auth
            .revoke_session(session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeSessionResponse { success: true }))
    }

    async fn revoke_all_sessions(
        &self,
        request: Request<RevokeAllSessionsRequest>,
    ) -> Result<Response<RevokeAllSessionsResponse>, Status> {
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let count = self
            .auth
            .revoke_all_sessions(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeAllSessionsResponse {
            revoked_count: count,
        }))
    }

    async fn list_sessions(
        &self,
        _request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        // TODO: Implement session listing
        Ok(Response::new(ListSessionsResponse {
            sessions: vec![],
            pagination: None,
        }))
    }

    async fn check_entitlement(
        &self,
        request: Request<CheckEntitlementRequest>,
    ) -> Result<Response<CheckEntitlementResponse>, Status> {
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let check = self
            .auth
            .check_entitlement(&user_id, &req.feature)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CheckEntitlementResponse {
            allowed: check.allowed,
            reason: check.reason.unwrap_or_default(),
            remaining: check.remaining,
            tier: tier_to_proto(check.tier),
            required_tier: tier_to_proto(check.required_tier),
        }))
    }

    async fn batch_check_entitlements(
        &self,
        request: Request<BatchCheckEntitlementsRequest>,
    ) -> Result<Response<BatchCheckEntitlementsResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let batch_size = req.features.len();

        if batch_size > 50 {
            return Err(Status::invalid_argument("Maximum 50 features per batch"));
        }

        let user_id = proto_to_user_id(req.user_id)?;

        // Execute all entitlement checks in parallel
        let auth = &self.auth;
        let futures: Vec<_> = req
            .features
            .into_iter()
            .map(|feature| {
                let uid = user_id;
                async move {
                    let result = auth.check_entitlement(&uid, &feature).await;
                    (feature, result)
                }
            })
            .collect();

        let check_results = join_all(futures).await;

        // Process results - use with_capacity for HashMap
        let mut results = HashMap::with_capacity(batch_size);
        let mut user_tier = ProtoTier::Explorer as i32;

        for (feature, result) in check_results {
            match result {
                Ok(check) => {
                    user_tier = tier_to_proto(check.tier);
                    results.insert(
                        feature,
                        EntitlementResult {
                            allowed: check.allowed,
                            reason: check.reason.unwrap_or_default(),
                            remaining: check.remaining,
                        },
                    );
                }
                Err(e) => {
                    results.insert(
                        feature,
                        EntitlementResult {
                            allowed: false,
                            reason: e.to_string(),
                            remaining: None,
                        },
                    );
                }
            }
        }

        let elapsed = start.elapsed();
        metrics::histogram!("grpc_request_duration_seconds", "method" => "batch_check_entitlements")
            .record(elapsed.as_secs_f64());
        tracing::debug!(
            batch_size,
            user_id = %user_id,
            elapsed_ms = elapsed.as_millis() as u64,
            "batch_check_entitlements completed"
        );

        Ok(Response::new(BatchCheckEntitlementsResponse {
            results,
            tier: user_tier,
        }))
    }

    async fn get_user_tier(
        &self,
        request: Request<GetUserTierRequest>,
    ) -> Result<Response<GetUserTierResponse>, Status> {
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let tier = self
            .auth
            .get_user_tier(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let rate_limit = self
            .auth
            .get_rate_limit(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetUserTierResponse {
            tier: tier_to_proto(tier),
            features: tier.features().iter().map(ToString::to_string).collect(),
            rate_limit: Some(ProtoRateLimit {
                requests: rate_limit.requests,
                window_seconds: rate_limit.window_seconds,
            }),
        }))
    }

    async fn get_rate_limit(
        &self,
        request: Request<GetRateLimitRequest>,
    ) -> Result<Response<GetRateLimitResponse>, Status> {
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let rate_limit = self
            .auth
            .get_rate_limit(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetRateLimitResponse {
            rate_limit: Some(ProtoRateLimit {
                requests: rate_limit.requests,
                window_seconds: rate_limit.window_seconds,
            }),
            status: Some(RateLimitStatus {
                limit: rate_limit.requests,
                remaining: rate_limit.requests, // Full quota (no usage tracked here)
                reset_seconds: rate_limit.window_seconds,
            }),
        }))
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        let req = request.into_inner();

        match self.auth.validate_token(&req.token).await {
            Ok(claims) => {
                let now = chrono::Utc::now();
                let token_type = match claims.source {
                    ClaimsSource::Jwt => "access_token",
                    ClaimsSource::Session => "session",
                };

                Ok(Response::new(IntrospectTokenResponse {
                    active: true,
                    claims: Some(TokenClaims {
                        user_id: Some(ProtoUserId {
                            value: claims.user_id.to_string(),
                        }),
                        email: claims.email.unwrap_or_default(),
                        email_verified: true,
                        tier: tier_to_proto(claims.tier),
                        role: Role::User as i32,
                        groups: claims.groups,
                        scopes: vec![],
                        issued_at: Some(prost_types::Timestamp {
                            seconds: now.timestamp(),
                            nanos: 0,
                        }),
                        expires_at: Some(prost_types::Timestamp {
                            seconds: now.timestamp() + 3600,
                            nanos: 0,
                        }),
                        source: source_to_proto(claims.source),
                    }),
                    token_type: token_type.to_string(),
                    client_id: String::new(),
                }))
            }
            Err(_) => Ok(Response::new(IntrospectTokenResponse {
                active: false,
                claims: None,
                token_type: String::new(),
                client_id: String::new(),
            })),
        }
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: argus_proto::health_check_response::ServingStatus::Serving as i32,
        }))
    }
}
