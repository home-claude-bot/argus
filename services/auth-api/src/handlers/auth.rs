//! Authentication handlers (login, logout, refresh, me)

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{ApiError, ApiResult};
use crate::extractors::AuthUser;
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Cognito ID token (reserved for token exchange)
    #[allow(dead_code)]
    pub id_token: String,
    /// Cognito access token
    pub access_token: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_id: String,
    pub expires_at: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: Option<String>,
    pub tier: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: UserInfo,
    pub session_source: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/v1/auth/login
///
/// Exchange Cognito tokens for a session cookie
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    // Get client info for audit
    let ip_address = Some(addr.ip().to_string());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Validate the access token first
    let claims = state.auth.validate_jwt(&req.access_token).await?;

    // Get Cognito claims from the token for session creation
    let cognito_claims = argus_auth_core::CognitoClaims {
        sub: claims.user_id.to_string(),
        email: claims.email.clone(),
        email_verified: Some(true),
        cognito_groups: claims.groups.clone(),
        iat: chrono::Utc::now().timestamp(),
        exp: chrono::Utc::now().timestamp() + 3600,
        iss: String::new(),
        aud: None,
        client_id: None,
        token_use: Some("access".to_string()),
    };

    // Create session
    let (session_id, session_cookie) = state
        .auth
        .create_session(&cognito_claims, ip_address, user_agent)
        .await?;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

    // Build response with Set-Cookie header
    let response = LoginResponse {
        session_id: session_id.to_string(),
        expires_at: expires_at.to_rfc3339(),
        user: UserInfo {
            id: claims.user_id.to_string(),
            email: claims.email,
            tier: claims.tier.to_string(),
            groups: claims.groups,
        },
    };

    // Create cookie header
    let cookie = format!(
        "argus_session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        session_cookie,
        24 * 3600
    );

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(response),
    ))
}

/// POST /api/v1/auth/logout
///
/// Revoke the current session
pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> ApiResult<Json<LogoutResponse>> {
    // Get session ID from the auth context
    if let Some(session_id) = auth_user.session_id {
        state.auth.revoke_session(session_id).await?;
    }

    Ok(Json(LogoutResponse { success: true }))
}

/// POST /api/v1/auth/refresh
///
/// Refresh an access token using a refresh token
pub async fn refresh(Json(req): Json<RefreshRequest>) -> ApiResult<Json<RefreshResponse>> {
    // Note: In a full implementation, this would call Cognito's token endpoint
    // For now, we return an error since refresh is handled by Cognito directly
    if req.refresh_token.is_empty() {
        return Err(ApiError::BadRequest(
            "refresh_token is required".to_string(),
        ));
    }

    // TODO: Call Cognito's InitiateAuth with REFRESH_TOKEN_AUTH
    // This requires the AWS SDK and Cognito client configuration
    Err(ApiError::BadRequest(
        "Refresh tokens should be exchanged directly with Cognito".to_string(),
    ))
}

/// GET /api/v1/auth/me
///
/// Get current user info from session or token
pub async fn me(auth_user: AuthUser) -> ApiResult<Json<MeResponse>> {
    let source = match auth_user.source {
        argus_auth_core::ClaimsSource::Jwt => "jwt",
        argus_auth_core::ClaimsSource::Session => "session",
    };

    Ok(Json(MeResponse {
        user: UserInfo {
            id: auth_user.user_id.to_string(),
            email: auth_user.email,
            tier: auth_user.tier.to_string(),
            groups: auth_user.groups,
        },
        session_source: source.to_string(),
    }))
}
