//! Authentication types

use serde::{Deserialize, Serialize};

/// Authentication provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    /// AWS Cognito (username/password)
    Cognito,
    /// Google OAuth
    Google,
    /// GitHub OAuth
    GitHub,
    /// Apple Sign-In
    Apple,
}

impl std::fmt::Display for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cognito => write!(f, "cognito"),
            Self::Google => write!(f, "google"),
            Self::GitHub => write!(f, "github"),
            Self::Apple => write!(f, "apple"),
        }
    }
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Username and password
    Password,
    /// OAuth 2.0 provider
    OAuth,
    /// WebAuthn/Passkey
    Passkey,
    /// Multi-factor authentication (TOTP)
    Mfa,
    /// API key
    ApiKey,
    /// Refresh token
    RefreshToken,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::OAuth => write!(f, "oauth"),
            Self::Passkey => write!(f, "passkey"),
            Self::Mfa => write!(f, "mfa"),
            Self::ApiKey => write!(f, "api_key"),
            Self::RefreshToken => write!(f, "refresh_token"),
        }
    }
}

/// Login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Email or username
    pub email: String,
    /// Password
    pub password: String,
    /// MFA code (if MFA is enabled)
    pub mfa_code: Option<String>,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: String,
    /// Token expiration in seconds
    pub expires_in: u64,
    /// Whether MFA is required
    pub mfa_required: bool,
    /// MFA session token (if MFA is required)
    pub mfa_session: Option<String>,
}

/// OAuth callback parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallback {
    /// Authorization code
    pub code: String,
    /// State parameter (CSRF protection)
    pub state: String,
}

/// MFA setup response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    /// TOTP secret (base32 encoded)
    pub secret: String,
    /// QR code URL for authenticator apps
    pub qr_code_url: String,
}

/// MFA verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerifyRequest {
    /// MFA session token
    pub session: String,
    /// TOTP code from authenticator
    pub code: String,
}

/// Password reset request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetRequest {
    /// Email address
    pub email: String,
}

/// Password reset confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetConfirm {
    /// Reset code from email
    pub code: String,
    /// New password
    pub new_password: String,
}
