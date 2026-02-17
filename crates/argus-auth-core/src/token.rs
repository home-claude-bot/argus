//! JWT token validation with JWKS caching

use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::{AuthConfig, AuthError};

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Individual JWK (JSON Web Key)
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: Option<String>,
    pub n: String,
    pub e: String,
}

/// Claims extracted from a Cognito access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitoClaims {
    /// Subject (Cognito user sub)
    pub sub: String,
    /// Token use (access or id)
    pub token_use: Option<String>,
    /// Cognito groups
    #[serde(default)]
    pub cognito_groups: Vec<String>,
    /// Email (from id token)
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Client ID (audience for id token)
    pub aud: Option<String>,
    /// Client ID (for access token)
    pub client_id: Option<String>,
}

impl CognitoClaims {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Get the client ID (works for both access and id tokens)
    pub fn get_client_id(&self) -> Option<&str> {
        self.client_id.as_deref().or(self.aud.as_deref())
    }
}

/// Token validator with JWKS caching
///
/// Security features:
/// - Caches full JWKS to prevent fetch flooding attacks
/// - Rejects unknown key IDs without triggering refetch
/// - Uses constant-time comparison for client ID validation
#[derive(Clone)]
pub struct TokenValidator {
    config: AuthConfig,
    http_client: reqwest::Client,
    /// Cache of kid -> DecodingKey
    key_cache: Cache<String, Arc<DecodingKey>>,
    /// Cache of known valid key IDs (prevents fetch flooding)
    /// Maps "jwks" -> list of known kids
    jwks_kids_cache: Cache<String, Arc<Vec<String>>>,
}

impl TokenValidator {
    /// Create a new token validator with optimized HTTP client
    ///
    /// The HTTP client is configured for low-latency JWKS fetching:
    /// - Connection pooling with idle timeout
    /// - Aggressive timeouts to fail fast
    /// - Connection reuse for efficiency
    ///
    /// Security: JWKS fetching is protected against flooding attacks by
    /// caching known key IDs and rejecting unknown IDs without refetching.
    pub fn new(config: AuthConfig) -> Self {
        let cache_duration = config.jwks_cache_duration;

        // Optimized HTTP client for JWKS fetching
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(2) // JWKS is typically one host
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true) // Disable Nagle for lower latency
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            http_client,
            key_cache: Cache::builder()
                .time_to_live(cache_duration)
                .max_capacity(100)
                .build(),
            jwks_kids_cache: Cache::builder()
                .time_to_live(cache_duration)
                .max_capacity(1) // Only one entry: "jwks" -> kids list
                .build(),
        }
    }

    /// Create a validator with custom HTTP client
    ///
    /// Use this when you need custom proxy settings, TLS config, or
    /// want to share an HTTP client across services.
    pub fn with_client(config: AuthConfig, http_client: reqwest::Client) -> Self {
        let cache_duration = config.jwks_cache_duration;
        Self {
            config,
            http_client,
            key_cache: Cache::builder()
                .time_to_live(cache_duration)
                .max_capacity(100)
                .build(),
            jwks_kids_cache: Cache::builder()
                .time_to_live(cache_duration)
                .max_capacity(1)
                .build(),
        }
    }

    /// Validate a JWT token and return claims
    pub async fn validate(&self, token: &str) -> Result<CognitoClaims, AuthError> {
        // Decode header to get kid
        let header = decode_header(token).map_err(|e| {
            tracing::debug!("Failed to decode token header: {}", e);
            AuthError::InvalidToken
        })?;

        let kid = header.kid.ok_or_else(|| {
            tracing::debug!("Token missing kid");
            AuthError::InvalidToken
        })?;

        // Get the decoding key (from cache or fetch)
        let decoding_key = self.get_key(&kid).await?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.config.cognito_issuer()]);
        // Cognito tokens have audience in `aud` (id token) or `client_id` (access token)
        // We'll validate the issuer and check client_id manually
        validation.validate_aud = false;

        // Decode and validate
        let token_data =
            decode::<CognitoClaims>(token, &decoding_key, &validation).map_err(|e| {
                tracing::debug!("Token validation failed: {}", e);
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::InvalidToken,
                }
            })?;

        let claims = token_data.claims;

        // Validate client ID using constant-time comparison to prevent timing attacks
        let valid_client_id = claims.get_client_id().is_some_and(|id| {
            id.as_bytes()
                .ct_eq(self.config.cognito_client_id.as_bytes())
                .into()
        });

        if !valid_client_id {
            // Don't log actual client IDs to prevent information leakage
            tracing::debug!("Client ID mismatch");
            return Err(AuthError::InvalidToken);
        }

        // Check expiration (double check, jsonwebtoken should catch this)
        if claims.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }

    /// Get a decoding key for the given kid
    ///
    /// Security: This method is protected against JWKS fetch flooding attacks.
    /// - Uses request coalescing (try_get_with) to ensure only one JWKS fetch
    ///   per key ID, even under concurrent load
    /// - Caches list of known key IDs to reject unknown IDs without refetch
    async fn get_key(&self, kid: &str) -> Result<Arc<DecodingKey>, AuthError> {
        // Check key cache first (fast path)
        if let Some(key) = self.key_cache.get(kid).await {
            return Ok(key);
        }

        // Check if we have a cached list of known kids
        // If yes and kid isn't in it, reject immediately (no refetch)
        if let Some(known_kids) = self.jwks_kids_cache.get("jwks").await {
            // Use iter().any() with str comparison to avoid String allocation
            if !known_kids.iter().any(|k| k == kid) {
                tracing::debug!(
                    "Unknown key ID '{}' not in cached JWKS (known: {:?})",
                    kid,
                    known_kids.as_ref()
                );
                return Err(AuthError::InvalidToken);
            }
        }

        // Use try_get_with for request coalescing - concurrent requests for the
        // same kid will wait for the first one to complete instead of all fetching.
        // This is critical for preventing JWKS fetch flooding under concurrent load.
        let kid_owned = kid.to_string();
        let key_cache = self.key_cache.clone();
        let jwks_kids_cache = self.jwks_kids_cache.clone();
        let http_client = self.http_client.clone();
        let config = self.config.clone();

        self.key_cache
            .try_get_with(kid_owned.clone(), async move {
                Self::fetch_and_cache_key_inner(
                    kid_owned,
                    http_client,
                    config,
                    key_cache,
                    jwks_kids_cache,
                )
                .await
            })
            .await
            .map_err(|arc_err| (*arc_err).clone())
    }

    /// Internal helper: fetch JWKS and cache the requested key
    ///
    /// This is called via try_get_with which ensures only one concurrent
    /// execution per key ID (request coalescing).
    async fn fetch_and_cache_key_inner(
        kid: String,
        http_client: reqwest::Client,
        config: AuthConfig,
        key_cache: Cache<String, Arc<DecodingKey>>,
        jwks_kids_cache: Cache<String, Arc<Vec<String>>>,
    ) -> Result<Arc<DecodingKey>, AuthError> {
        // Fetch JWKS
        let jwks = Self::fetch_jwks_inner(&http_client, &config).await?;

        // Cache the list of known kids to prevent future flooding
        let kids: Vec<String> = jwks.keys.iter().map(|k| k.kid.clone()).collect();
        jwks_kids_cache
            .insert("jwks".to_string(), Arc::new(kids))
            .await;

        // Find the key with matching kid
        let jwk = jwks.keys.iter().find(|k| k.kid == kid).ok_or_else(|| {
            tracing::debug!("Key not found in JWKS: {}", kid);
            AuthError::InvalidToken
        })?;

        // Create decoding key for the requested kid
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            tracing::error!("Failed to create decoding key: {}", e);
            AuthError::Internal("Failed to create decoding key".to_string())
        })?;

        let key = Arc::new(decoding_key);

        // Pre-cache all OTHER keys from the JWKS (current one will be cached by try_get_with)
        for k in &jwks.keys {
            if k.kid != kid {
                if let Ok(dk) = DecodingKey::from_rsa_components(&k.n, &k.e) {
                    key_cache.insert(k.kid.clone(), Arc::new(dk)).await;
                }
            }
        }

        Ok(key)
    }

    /// Static version of fetch_jwks for use in the async closure
    async fn fetch_jwks_inner(
        http_client: &reqwest::Client,
        config: &AuthConfig,
    ) -> Result<Jwks, AuthError> {
        let url = config.jwks_url();
        tracing::debug!("Fetching JWKS from {}", url);

        let response = http_client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch JWKS: {}", e);
                AuthError::Internal("Failed to fetch JWKS".to_string())
            })?;

        if !response.status().is_success() {
            tracing::error!("JWKS fetch returned status: {}", response.status());
            return Err(AuthError::Internal("Failed to fetch JWKS".to_string()));
        }

        response.json::<Jwks>().await.map_err(|e| {
            tracing::error!("Failed to parse JWKS: {}", e);
            AuthError::Internal("Failed to parse JWKS".to_string())
        })
    }

    /// Invalidate all caches (useful when keys rotate)
    ///
    /// This clears both the decoding key cache and the known kids cache,
    /// forcing a fresh JWKS fetch on the next validation.
    pub async fn invalidate_cache(&self) {
        self.key_cache.invalidate_all();
        self.jwks_kids_cache.invalidate_all();
    }
}

impl std::fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenValidator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cognito_claims_is_expired() {
        let future_exp = Utc::now().timestamp() + 3600;
        let claims = CognitoClaims {
            sub: "test-sub".to_string(),
            token_use: Some("access".to_string()),
            cognito_groups: vec![],
            email: None,
            email_verified: None,
            iat: Utc::now().timestamp(),
            exp: future_exp,
            iss: "https://cognito.example.com".to_string(),
            aud: None,
            client_id: Some("test-client".to_string()),
        };
        assert!(!claims.is_expired());

        let past_exp = Utc::now().timestamp() - 3600;
        let expired_claims = CognitoClaims {
            exp: past_exp,
            ..claims
        };
        assert!(expired_claims.is_expired());
    }

    #[test]
    fn test_config_urls() {
        // Use 32+ byte secret to satisfy minimum length requirement
        let config = AuthConfig::new(
            "us-east-1_TestPool",
            "us-east-1",
            "test-client-id",
            "test-secret-that-is-at-least-32-bytes-long",
        );
        assert_eq!(
            config.cognito_issuer(),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
        );
        assert_eq!(
            config.jwks_url(),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool/.well-known/jwks.json"
        );
    }
}
