//! Session management with HMAC signing
//!
//! Implements session cookie signing that matches the CloudFront function format.

use argus_db::{CreateSession, SessionRepository, SessionRow};
use argus_types::{SessionId, Tier, UserId};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::crypto::{constant_time_eq, HmacKey};
use crate::AuthError;

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

        // Extract tier and role from groups
        let tier = extract_tier_from_groups(&groups);
        let role = extract_role_from_groups(&groups).to_string();

        Self {
            user_id: user_id.to_string(),
            email: email.into(),
            groups,
            tier: tier.to_string(),
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

/// Extract tier from Cognito groups (returns Tier enum)
///
/// Uses exact suffix matching for security:
/// - Groups must end with `_enterprise`, `_business`, `_professional`, or `_pro`
/// - Prevents privilege escalation via crafted group names like "not_enterprise_user"
pub fn extract_tier_from_groups(groups: &[String]) -> Tier {
    // Priority order: enterprise > business > professional > explorer
    // Use exact suffix matching to prevent privilege escalation attacks
    if groups.iter().any(|g| g.ends_with("_enterprise")) {
        Tier::Enterprise
    } else if groups.iter().any(|g| g.ends_with("_business")) {
        Tier::Business
    } else if groups.iter().any(|g| g.ends_with("_professional") || g.ends_with("_pro")) {
        Tier::Professional
    } else {
        Tier::Explorer
    }
}

/// Extract role from Cognito groups
///
/// Returns "admin" if any group ends with `_admin`, otherwise "user".
/// Uses suffix matching consistent with tier extraction.
#[inline]
pub fn extract_role_from_groups(groups: &[String]) -> &'static str {
    if groups.iter().any(|g| g.ends_with("_admin")) {
        "admin"
    } else {
        "user"
    }
}

/// Session manager handles session creation, signing, and validation
#[derive(Clone)]
pub struct SessionManager<R: SessionRepository> {
    /// Pre-validated HMAC key for efficient signing
    hmac_key: HmacKey,
    session_duration_hours: u32,
    repo: Arc<R>,
}

impl<R: SessionRepository> SessionManager<R> {
    /// Create a new session manager
    ///
    /// # Arguments
    /// * `secret` - HMAC secret bytes (must be at least 32 bytes)
    /// * `session_duration_hours` - How long sessions are valid
    /// * `repo` - Session repository for persistence
    ///
    /// # Panics
    /// Panics if secret is shorter than 32 bytes.
    pub fn new(secret: impl AsRef<[u8]>, session_duration_hours: u32, repo: Arc<R>) -> Self {
        let hmac_key = HmacKey::new(secret)
            .expect("session secret must be at least 32 bytes");
        Self {
            hmac_key,
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

        // Verify signature using constant-time comparison to prevent timing attacks
        let expected_sig = self.compute_signature(payload_b64);
        if !constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
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
                Err(AuthError::SessionRevoked)
            }
            Some(s) if s.expires_at < Utc::now() => {
                tracing::debug!("Session expired in database");
                Err(AuthError::TokenExpired)
            }
            Some(_) => Ok(payload),
            None => {
                // Session not in database - MUST fail for security
                // A signed session not in DB means either:
                // 1. Session was revoked and cleaned up
                // 2. Session was created by a compromised key
                // 3. Session predates DB tracking (migration scenario)
                // In all cases, requiring re-authentication is the safe choice
                tracing::warn!("Session not found in database - rejecting");
                Err(AuthError::SessionRevoked)
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
        let signature = self.compute_signature(&payload_b64);

        Ok(format!("{payload_b64}.{signature}"))
    }

    /// Compute HMAC-SHA256 signature
    fn compute_signature(&self, data: &str) -> String {
        let signature = self.hmac_key.sign(data.as_bytes());
        URL_SAFE_NO_PAD.encode(signature)
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

    // Test-only minimal session manager for HMAC testing (no DB)
    struct HmacTester {
        hmac_key: HmacKey,
    }

    impl HmacTester {
        fn new(secret: &str) -> Self {
            // Pad short secrets for testing (production requires 32+ bytes)
            let padded = if secret.len() < 32 {
                format!("{:0<32}", secret)
            } else {
                secret.to_string()
            };
            Self {
                hmac_key: HmacKey::new(padded).expect("padded key is >= 32 bytes"),
            }
        }

        fn sign_payload(&self, payload: &SessionPayload) -> Result<String, AuthError> {
            let payload_json = serde_json::to_vec(payload).map_err(|_| {
                AuthError::Internal("Failed to serialize".to_string())
            })?;
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            let signature = self.compute_signature(&payload_b64);
            Ok(format!("{payload_b64}.{signature}"))
        }

        fn validate_cookie(&self, cookie: &str) -> Result<SessionPayload, AuthError> {
            let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
            if parts.len() != 2 {
                return Err(AuthError::InvalidToken);
            }
            let (signature, payload_b64) = (parts[0], parts[1]);
            let expected_sig = self.compute_signature(payload_b64);
            if !constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
                return Err(AuthError::InvalidToken);
            }
            let payload_json = URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|_| AuthError::InvalidToken)?;
            let payload: SessionPayload =
                serde_json::from_slice(&payload_json).map_err(|_| AuthError::InvalidToken)?;
            if payload.is_expired() {
                return Err(AuthError::TokenExpired);
            }
            Ok(payload)
        }

        fn compute_signature(&self, data: &str) -> String {
            let signature = self.hmac_key.sign(data.as_bytes());
            URL_SAFE_NO_PAD.encode(signature)
        }
    }

    #[test]
    fn test_extract_tier_from_groups() {
        assert_eq!(extract_tier_from_groups(&[]), Tier::Explorer);
        assert_eq!(
            extract_tier_from_groups(&["andrz_professional".to_string()]),
            Tier::Professional
        );
        assert_eq!(
            extract_tier_from_groups(&["andrz_business".to_string()]),
            Tier::Business
        );
        assert_eq!(
            extract_tier_from_groups(&["andrz_enterprise".to_string()]),
            Tier::Enterprise
        );
        // Enterprise takes priority
        assert_eq!(
            extract_tier_from_groups(&["andrz_professional".to_string(), "andrz_enterprise".to_string()]),
            Tier::Enterprise
        );
        // Pro shorthand
        assert_eq!(
            extract_tier_from_groups(&["andrz_pro".to_string()]),
            Tier::Professional
        );
    }

    #[test]
    fn test_extract_tier_rejects_fuzzy_matches() {
        // Security: ensure fuzzy matching doesn't allow privilege escalation
        // "enterprise_disabled" should NOT grant enterprise tier
        assert_eq!(
            extract_tier_from_groups(&["enterprise_disabled".to_string()]),
            Tier::Explorer
        );
        // "not_an_enterprise_user" should NOT grant enterprise tier
        assert_eq!(
            extract_tier_from_groups(&["not_an_enterprise_user".to_string()]),
            Tier::Explorer
        );
        // "professional_revoked" should NOT grant professional tier
        assert_eq!(
            extract_tier_from_groups(&["professional_revoked".to_string()]),
            Tier::Explorer
        );
        // Only exact suffix matches work
        assert_eq!(
            extract_tier_from_groups(&["tier_enterprise".to_string()]),
            Tier::Enterprise
        );
    }

    #[test]
    fn test_constant_time_eq() {
        // Equal strings
        assert!(constant_time_eq(b"abc123", b"abc123"));
        // Different lengths
        assert!(!constant_time_eq(b"abc", b"abcd"));
        // Same length, different content
        assert!(!constant_time_eq(b"abc123", b"xyz789"));
        // Empty strings
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_hmac_key_minimum_length() {
        // Short secret should fail
        let result = HmacKey::new("short");
        assert!(result.is_err());

        // 32-byte secret should succeed
        let result = HmacKey::new("a".repeat(32));
        assert!(result.is_ok());

        // Longer secret should succeed
        let result = HmacKey::new("a".repeat(64));
        assert!(result.is_ok());
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

    #[test]
    fn test_hmac_roundtrip() {
        let tester = HmacTester::new("super-secret-key-for-testing");
        let user_id = UserId::new();
        let payload = SessionPayload::new(
            user_id,
            "test@example.com",
            vec!["andrz_professional".to_string()],
            24,
        );

        // Sign the payload
        let cookie = tester.sign_payload(&payload).unwrap();

        // Validate should succeed
        let validated = tester.validate_cookie(&cookie).unwrap();
        assert_eq!(validated.email, "test@example.com");
        assert_eq!(validated.tier, "professional");
    }

    #[test]
    fn test_hmac_tampered_signature_rejected() {
        let tester = HmacTester::new("super-secret-key-for-testing");
        let user_id = UserId::new();
        let payload = SessionPayload::new(user_id, "test@example.com", vec![], 24);

        let cookie = tester.sign_payload(&payload).unwrap();

        // Tamper with the signature (change last char)
        let mut tampered = cookie.clone();
        let last_char = tampered.pop().unwrap();
        let new_char = if last_char == 'a' { 'b' } else { 'a' };
        tampered.push(new_char);

        // Validation should fail
        let result = tester.validate_cookie(&tampered);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_hmac_tampered_payload_rejected() {
        let tester = HmacTester::new("super-secret-key-for-testing");
        let user_id = UserId::new();
        let payload = SessionPayload::new(user_id, "test@example.com", vec![], 24);

        let cookie = tester.sign_payload(&payload).unwrap();
        let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
        let signature = parts[0];

        // Create a different payload and use old signature
        let evil_payload = SessionPayload::new(
            UserId::new(),
            "attacker@evil.com",
            vec!["andrz_enterprise".to_string()], // Privilege escalation attempt
            24,
        );
        let evil_payload_json = serde_json::to_vec(&evil_payload).unwrap();
        let evil_payload_b64 = URL_SAFE_NO_PAD.encode(&evil_payload_json);

        // Combine tampered payload with original signature
        let tampered_cookie = format!("{evil_payload_b64}.{signature}");

        // Validation should fail
        let result = tester.validate_cookie(&tampered_cookie);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_hmac_wrong_secret_rejected() {
        let signer = HmacTester::new("secret-one");
        let validator = HmacTester::new("secret-two");

        let user_id = UserId::new();
        let payload = SessionPayload::new(user_id, "test@example.com", vec![], 24);

        let cookie = signer.sign_payload(&payload).unwrap();

        // Validation with wrong secret should fail
        let result = validator.validate_cookie(&cookie);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_hmac_expired_session_rejected() {
        let tester = HmacTester::new("super-secret-key-for-testing");
        let user_id = UserId::new();
        let mut payload = SessionPayload::new(user_id, "test@example.com", vec![], 24);

        // Set expiration in the past
        payload.expires = Utc::now().timestamp_millis() - 1000;

        let cookie = tester.sign_payload(&payload).unwrap();

        // Validation should fail with TokenExpired
        let result = tester.validate_cookie(&cookie);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_hmac_malformed_cookie_rejected() {
        let tester = HmacTester::new("super-secret-key-for-testing");

        // No dots
        assert!(matches!(
            tester.validate_cookie("nodots"),
            Err(AuthError::InvalidToken)
        ));

        // Invalid base64
        assert!(matches!(
            tester.validate_cookie("!!!invalid!!!.sig"),
            Err(AuthError::InvalidToken)
        ));

        // Valid base64 but not JSON
        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        assert!(matches!(
            tester.validate_cookie(&format!("{not_json}.sig")),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn test_token_hash_deterministic() {
        // Direct hash computation (same logic as SessionManager::hash_token)
        fn hash_token(token: &str) -> String {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(token.as_bytes());
            hex::encode(hasher.finalize())
        }

        let token = "some-session-token-value";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);

        // Different token = different hash
        let hash3 = hash_token("different-token");
        assert_ne!(hash1, hash3);

        // Hash is 64 hex chars (256 bits)
        assert_eq!(hash1.len(), 64);
    }
}
