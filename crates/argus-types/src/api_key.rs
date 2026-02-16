//! API key types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::UserId;

/// API key ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKeyId(pub Uuid);

impl ApiKeyId {
    /// Create a new API key ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ApiKeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// API key prefix (for identification without exposing the key)
pub const API_KEY_PREFIX: &str = "argus_";

/// API key (stored in database)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// API key ID
    pub id: ApiKeyId,
    /// User who owns the key
    pub user_id: UserId,
    /// Key prefix (first 8 chars for identification)
    pub prefix: String,
    /// Hashed key value (SHA-256)
    pub key_hash: String,
    /// Human-readable name
    pub name: String,
    /// Scopes/permissions granted
    pub scopes: Vec<String>,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires (if any)
    pub expires_at: Option<DateTime<Utc>>,
    /// When the key was last used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether the key is active
    pub active: bool,
}

impl ApiKey {
    /// Check if the API key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if the API key is valid (active and not expired)
    pub fn is_valid(&self) -> bool {
        self.active && !self.is_expired()
    }

    /// Check if the key has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }
}

/// Create API key request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    /// Human-readable name
    pub name: String,
    /// Scopes/permissions to grant
    pub scopes: Vec<String>,
    /// Expiration time (optional)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Create API key response (includes the raw key, shown only once)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    /// API key ID
    pub id: ApiKeyId,
    /// The raw API key (only shown once!)
    pub key: String,
    /// Key prefix for identification
    pub prefix: String,
    /// Human-readable name
    pub name: String,
    /// When the key expires (if any)
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key list item (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyListItem {
    /// API key ID
    pub id: ApiKeyId,
    /// Key prefix for identification
    pub prefix: String,
    /// Human-readable name
    pub name: String,
    /// Scopes granted
    pub scopes: Vec<String>,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires (if any)
    pub expires_at: Option<DateTime<Utc>>,
    /// When the key was last used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether the key is active
    pub active: bool,
}

/// Available API key scopes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Read predictions
    PredictionsRead,
    /// Create predictions
    PredictionsWrite,
    /// Read questions
    QuestionsRead,
    /// Create questions
    QuestionsWrite,
    /// Read account info
    AccountRead,
    /// Read usage data
    UsageRead,
    /// Full access
    Admin,
}

impl ApiKeyScope {
    /// Get the scope string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PredictionsRead => "predictions:read",
            Self::PredictionsWrite => "predictions:write",
            Self::QuestionsRead => "questions:read",
            Self::QuestionsWrite => "questions:write",
            Self::AccountRead => "account:read",
            Self::UsageRead => "usage:read",
            Self::Admin => "*",
        }
    }
}

impl std::fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
