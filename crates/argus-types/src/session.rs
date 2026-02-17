//! Session and token types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::UserId;

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Create a new random session ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a session ID from a string
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SessionId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// User session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: SessionId,
    /// User who owns the session
    pub user_id: UserId,
    /// Hashed session token
    pub token_hash: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Last activity time
    pub last_active_at: DateTime<Utc>,
    /// IP address of session creation
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Whether session was revoked
    pub revoked: bool,
}

impl Session {
    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}

/// Token pair returned after authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access token (short-lived)
    pub access_token: String,
    /// Refresh token (long-lived)
    pub refresh_token: String,
    /// Access token expiration in seconds
    pub expires_in: u64,
    /// Token type (always "Bearer")
    pub token_type: String,
}

impl Default for TokenPair {
    fn default() -> Self {
        Self {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
        }
    }
}

/// Claims extracted from a validated token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Email address
    pub email: Option<String>,
    /// Email verified flag
    pub email_verified: Option<bool>,
    /// Cognito groups
    pub groups: Vec<String>,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<String>,
}

impl Claims {
    /// Check if the claims are expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        now > self.exp
    }

    /// Get the user ID from the subject claim
    pub fn user_id(&self) -> Option<UserId> {
        UserId::parse(&self.sub).ok()
    }
}

/// Signed session cookie format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookie {
    /// User ID
    pub user_id: UserId,
    /// User email
    pub email: String,
    /// User groups
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

impl SessionCookie {
    /// Check if the session cookie is expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp_millis();
        now > self.expires
    }
}
