//! Session management with HMAC signing
//!
//! Implements session cookie signing that matches the CloudFront function format.

use argus_db::{CreateSession, SessionRepository, SessionRow};
use argus_types::{SessionId, UserId};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

use crate::AuthError;

type HmacSha256 = Hmac<Sha256>;

/// Session cookie payload (matches CloudFront function format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPayload {
    /// User ID
    pub user_id: String,
    /// User email
    pub email: String,
    /// Cognito groups
    pub groups: Vec<String>,
    /// User tier (extracted from groups)
    pub tier: String,
    /// User role (user or admin)
    pub role: String,
    /// Issue timestamp (milliseconds)
    pub issued: i64,
    /// Expiration timestamp (milliseconds)
    pub expires: i64,
}

impl SessionPayload {
    /// Create a new session payload
    pub fn new(
        user_id: UserId,
        email: impl Into<String>,
        groups: Vec<String>,
        duration_hours: u32,
    ) -> Self {
        let now = Utc::now().timestamp_millis();
        let expires = now + i64::from(duration_hours) * 60 * 60 * 1000;

        // Extract tier from groups
        let tier = extract_tier_from_groups(&groups);
        let role = if groups.iter().any(|g| g == "andrz_admin") {
            "admin".to_string()
        } else {
            "user".to_string()
        };

        Self {
            user_id: user_id.to_string(),
            email: email.into(),
            groups,
            tier,
            role,
            issued: now,
            expires,
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expires
    }

    /// Get the user ID
    pub fn user_id(&self) -> Option<UserId> {
        UserId::parse(&self.user_id).ok()
    }
}

/// Extract tier from Cognito groups
fn extract_tier_from_groups(groups: &[String]) -> String {
    // Priority order: enterprise > business > professional > explorer
    if groups.iter().any(|g| g.contains("enterprise")) {
        "enterprise".to_string()
    } else if groups.iter().any(|g| g.contains("business")) {
        "business".to_string()
    } else if groups.iter().any(|g| g.contains("professional") || g.contains("pro")) {
        "professional".to_string()
    } else {
        "explorer".to_string()
    }
}

/// Session manager handles session creation, signing, and validation
#[derive(Clone)]
pub struct SessionManager<R: SessionRepository> {
    secret: String,
    session_duration_hours: u32,
    repo: Arc<R>,
}

impl<R: SessionRepository> SessionManager<R> {
    /// Create a new session manager
    pub fn new(secret: impl Into<String>, session_duration_hours: u32, repo: Arc<R>) -> Self {
        Self {
            secret: secret.into(),
            session_duration_hours,
            repo,
        }
    }

    /// Create a new session and return the signed cookie value
    pub async fn create_session(
        &self,
        user_id: UserId,
        email: impl Into<String>,
        groups: Vec<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SessionId, String), AuthError> {
        let email = email.into();

        // Create payload
        let payload = SessionPayload::new(
            user_id,
            email.clone(),
            groups,
            self.session_duration_hours,
        );

        // Sign the payload
        let signed_cookie = self.sign_payload(&payload)?;

        // Create session in database
        let session_id = SessionId::new();
        let token_hash = Self::hash_token(&signed_cookie);
        let expires_at = Utc::now() + ChronoDuration::hours(i64::from(self.session_duration_hours));

        let create = CreateSession {
            id: session_id.0,
            user_id: user_id.0,
            token_hash,
            ip_address,
            user_agent,
            expires_at,
        };

        self.repo.create(create).await.map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            AuthError::Internal("Failed to create session".to_string())
        })?;

        Ok((session_id, signed_cookie))
    }

    /// Validate a signed session cookie
    pub fn validate_cookie(&self, cookie: &str) -> Result<SessionPayload, AuthError> {
        // Split signature from payload
        let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidToken);
        }

        let (signature, payload_b64) = (parts[0], parts[1]);

        // Verify signature
        let expected_sig = self.compute_signature(payload_b64)?;
        if signature != expected_sig {
            tracing::debug!("Session signature mismatch");
            return Err(AuthError::InvalidToken);
        }

        // Decode payload
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AuthError::InvalidToken)?;

        let payload: SessionPayload =
            serde_json::from_slice(&payload_json).map_err(|_| AuthError::InvalidToken)?;

        // Check expiration
        if payload.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        Ok(payload)
    }

    /// Validate session against database (checks revocation)
    pub async fn validate_session(&self, cookie: &str) -> Result<SessionPayload, AuthError> {
        // First validate the signature and expiration
        let payload = self.validate_cookie(cookie)?;

        // Check database for revocation
        let token_hash = Self::hash_token(cookie);
        let session = self
            .repo
            .find_by_token_hash(&token_hash)
            .await
            .map_err(|e| {
                tracing::error!("Failed to find session: {}", e);
                AuthError::Internal("Failed to validate session".to_string())
            })?;

        match session {
            Some(s) if s.revoked => {
                tracing::debug!("Session has been revoked");
                Err(AuthError::TokenExpired)
            }
            Some(s) if s.expires_at < Utc::now() => {
                tracing::debug!("Session expired in database");
                Err(AuthError::TokenExpired)
            }
            Some(_) => Ok(payload),
            None => {
                // Session not in database - might be old format or from different service
                // For backwards compatibility, trust the signed payload
                tracing::debug!("Session not found in database, trusting signed payload");
                Ok(payload)
            }
        }
    }

    /// Revoke a session by ID
    pub async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthError> {
        self.repo.revoke(session_id.0).await.map_err(|e| {
            tracing::error!("Failed to revoke session: {}", e);
            AuthError::Internal("Failed to revoke session".to_string())
        })
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_sessions(&self, user_id: UserId) -> Result<u64, AuthError> {
        self.repo.revoke_all_for_user(user_id.0).await.map_err(|e| {
            tracing::error!("Failed to revoke sessions: {}", e);
            AuthError::Internal("Failed to revoke sessions".to_string())
        })
    }

    /// Get all sessions for a user
    pub async fn get_user_sessions(&self, user_id: UserId) -> Result<Vec<SessionRow>, AuthError> {
        self.repo.find_by_user_id(user_id.0).await.map_err(|e| {
            tracing::error!("Failed to get sessions: {}", e);
            AuthError::Internal("Failed to get sessions".to_string())
        })
    }

    /// Update last active timestamp
    pub async fn touch_session(&self, session_id: SessionId) -> Result<(), AuthError> {
        self.repo.update_last_active(session_id.0).await.map_err(|e| {
            tracing::error!("Failed to update session: {}", e);
            AuthError::Internal("Failed to update session".to_string())
        })
    }

    /// Sign a session payload and return the cookie value
    fn sign_payload(&self, payload: &SessionPayload) -> Result<String, AuthError> {
        let payload_json = serde_json::to_vec(payload).map_err(|e| {
            tracing::error!("Failed to serialize payload: {}", e);
            AuthError::Internal("Failed to create session".to_string())
        })?;

        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signature = self.compute_signature(&payload_b64)?;

        Ok(format!("{payload_b64}.{signature}"))
    }

    /// Compute HMAC-SHA256 signature
    fn compute_signature(&self, data: &str) -> Result<String, AuthError> {
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes()).map_err(|e| {
            tracing::error!("Failed to create HMAC: {}", e);
            AuthError::Internal("Failed to sign session".to_string())
        })?;

        mac.update(data.as_bytes());
        let result = mac.finalize();
        Ok(URL_SAFE_NO_PAD.encode(result.into_bytes()))
    }

    /// Hash a token for storage (not the signature, the full cookie value)
    fn hash_token(token: &str) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl<R: SessionRepository> std::fmt::Debug for SessionManager<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("session_duration_hours", &self.session_duration_hours)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tier_from_groups() {
        assert_eq!(extract_tier_from_groups(&[]), "explorer");
        assert_eq!(
            extract_tier_from_groups(&["andrz_professional".to_string()]),
            "professional"
        );
        assert_eq!(
            extract_tier_from_groups(&["andrz_business".to_string()]),
            "business"
        );
        assert_eq!(
            extract_tier_from_groups(&["andrz_enterprise".to_string()]),
            "enterprise"
        );
        // Enterprise takes priority
        assert_eq!(
            extract_tier_from_groups(&["andrz_professional".to_string(), "andrz_enterprise".to_string()]),
            "enterprise"
        );
    }

    #[test]
    fn test_session_payload_expiration() {
        let user_id = UserId::new();
        let payload = SessionPayload::new(user_id, "test@example.com", vec![], 1);
        assert!(!payload.is_expired());

        let mut expired = payload.clone();
        expired.expires = Utc::now().timestamp_millis() - 1000;
        assert!(expired.is_expired());
    }
}
