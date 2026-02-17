//! Axum extractors for authentication

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::Serialize;

use argus_auth_core::{ClaimsSource, ValidatedClaims};
use argus_types::{SessionId, Tier, UserId};

use crate::state::AppState;

/// Authenticated user extracted from request
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: UserId,
    pub email: Option<String>,
    pub tier: Tier,
    pub groups: Vec<String>,
    pub source: ClaimsSource,
    pub session_id: Option<SessionId>,
}

impl AuthUser {
    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.groups.iter().any(|g| g == "admin" || g == "admins")
    }

    /// Check if user has a specific group
    #[allow(dead_code)]
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }
}

impl From<ValidatedClaims> for AuthUser {
    fn from(claims: ValidatedClaims) -> Self {
        Self {
            user_id: claims.user_id,
            email: claims.email,
            tier: claims.tier,
            groups: claims.groups,
            source: claims.source,
            session_id: None,
        }
    }
}

/// Error response for auth failures
#[derive(Debug, Serialize)]
struct AuthErrorResponse {
    error: AuthErrorDetail,
}

#[derive(Debug, Serialize)]
struct AuthErrorDetail {
    code: &'static str,
    message: &'static str,
}

/// Auth rejection type
pub struct AuthRejection {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let body = AuthErrorResponse {
            error: AuthErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 S,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let app_state = AppState::from_ref(state);

            // Try to extract token from Authorization header or cookie
            let token = extract_token(parts)?;

            // Validate the token
            let claims = app_state.auth.validate_token(&token).await.map_err(|e| {
                tracing::debug!(error = ?e, "Token validation failed");
                AuthRejection {
                    status: StatusCode::UNAUTHORIZED,
                    code: "INVALID_TOKEN",
                    message: "Invalid or expired token",
                }
            })?;

            let mut auth_user = AuthUser::from(claims);

            // Try to extract session ID from the token if it's a session
            if auth_user.source == ClaimsSource::Session {
                // Parse session ID from the cookie payload
                // The session cookie format is: base64(payload).signature
                if let Some(payload) = token.split('.').next() {
                    if let Ok(decoded) =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)
                    {
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                            if let Some(sid) = json.get("sid").and_then(|v| v.as_str()) {
                                if let Ok(uuid) = uuid::Uuid::parse_str(sid) {
                                    auth_user.session_id = Some(SessionId::from(uuid));
                                }
                            }
                        }
                    }
                }
            }

            Ok(auth_user)
        })
    }
}

/// Extract token from Authorization header or session cookie
fn extract_token(parts: &Parts) -> Result<String, AuthRejection> {
    // Try Authorization header first (Bearer token)
    if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
        let auth_str = auth_header.to_str().map_err(|_| AuthRejection {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_HEADER",
            message: "Invalid Authorization header encoding",
        })?;

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            return Ok(token.to_string());
        }
    }

    // Try session cookie
    if let Some(cookie_header) = parts.headers.get(header::COOKIE) {
        let cookie_str = cookie_header.to_str().map_err(|_| AuthRejection {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_HEADER",
            message: "Invalid Cookie header encoding",
        })?;

        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix("argus_session=") {
                return Ok(value.to_string());
            }
        }
    }

    Err(AuthRejection {
        status: StatusCode::UNAUTHORIZED,
        code: "MISSING_TOKEN",
        message: "No authentication token provided",
    })
}

/// Optional auth extractor - doesn't fail if no auth is provided
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future use
pub struct OptionalAuthUser(pub Option<AuthUser>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 S,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            match AuthUser::from_request_parts(parts, state).await {
                Ok(user) => Ok(OptionalAuthUser(Some(user))),
                Err(_) => Ok(OptionalAuthUser(None)),
            }
        })
    }
}
