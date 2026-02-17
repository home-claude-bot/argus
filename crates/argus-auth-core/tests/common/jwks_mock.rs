//! Mock JWKS server for integration testing
//!
//! Provides wiremock-based JWKS endpoint and test JWT signing utilities.

use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockGuard, MockServer, ResponseTemplate};

// Pre-generated 2048-bit RSA keypair for testing (DO NOT use in production!)
// Generated with: openssl genrsa 2048
const TEST_RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUZjcJ1mytrTx3
ybEDnjJvbE0g4YErgkQcO0O64JhnKYRFPqyN5WiXf+WXIeRufAHKd6CnuUECD5/N
pS4gXqe0LHheiO5UbmUqICje5rlurv+R398dYtW/r9Pg1yu5D7drAMU/BXGmKnZ1
HXQuk8LHtoj3t78Lp7fb3tmJ+RvvBxkG0q7Ti1uYYmbUEPBTpcixIDgp020B3kA1
QSkpZDWdNYlkO7PmzCUlq3NSUULQGLUlqcKZYIam+L9bi9tFi54X007oZ1QpqOZn
e+4iEF1yAC+C2NJeGwUj+0ZcuyP5sbb3Fe0RPTVfpTK/Ug2Z1mQstw/vphj5FMoM
JN4A9vH9AgMBAAECggEAJP7p2suP0f+Q/v9xVwM83zYSyCWnSWQPB4jWHwykVyG+
4Y3NYgjhuzPCkpzLbGgqqrDEGbrVpS2CBQCexHIgTWyKidLZinjRI7GG1O6EwY/3
QZooQ3bV6uXOJsVr3vfrF5cChFvnJA2U5QjclglUPdOgT1+gxf+wcXqDUzpCAJPf
Sdr7jxAGk1PHCbxccEuvCQHAh6pXRagqjvGjf5EkyZdHq3kgfprpipQU15rUgk5O
7m/Rj4lPB+hJI6gkPBm8+rIhD7OOYsB/8jUabuwQPnPdmvF2fyJzBuPlflTOZFhH
tGOHmSXIR9/sdjeOlP5QHAo/h/n+kvjmMdQSzVU/kQKBgQD3lb4ZESEaWZ+lfcDQ
zLoDUprYjqRThItvanW7FMyM5Rms3p3Y17embiNNyXFBv4/IxWM95LKgbH107aFH
2O2B5NCMy1SiQWD2WYb48kFsjCiWmo3JNFRPDOHuNYcYbvNGyeY2sv27QTN2f0Tc
PCUsZZTkB4NB46AxN4gyhm0+zQKBgQDbnlGua+vQLQT10GRWHrWmNwzWdgKLu+TQ
73q5qFO46rNgtnce8XfrAeIISWwHyhTleXuBfDripvjgRsmg8oqhmkZt0Uf/+48Q
OcyCUcomOKGk8Xx+DTktIbx/Q8um6ZjVhDYcFtLI5JA9EvJQYsS+PiE479sQbZ5r
AkEfl5Qf8QKBgQC0KqDSRvfK4Atf93n3t/No9ZS/IFYOfLanFlakFEeiBBnCBaHi
KWB4WU+RjJTBXrA4TwOgB6vBOBG3pDEoQoDbdHIa8uAczuzLeGzS/h+D6R6kMcYZ
892iROKoYQV1T0/zZHsFtQ0VViYoBgdLKO14OFe39IucyBNLnXicI9ydxQKBgEcq
nYNs+2RhQks5tVnm56wuCJ3ybc7EG1jNUbKZ5k901p3PYviG/PoNiSZwTG6VwIHA
BRKnpBlQTDO5HJtoHR5S9OGfQLql1O1IHYpZYK1UCqV9j371YALM/N0spfC3n8wI
5NPjXXi2ADuaSSVdbC3Nykw+BXnkW8KHX30STHCxAoGAJ+UrfiuoDTtHT/gyc7OU
1RxNFYkzZQO18JCEB0z0NKhvZPytyMriOsYJobvlcB6HaOOtwD0mTj1C5n0Bwe6y
Sfd9ageEgOwrxx1Zot6yweyrnzKkj1TgybV9M/JJzTep2u6s/y9DBGPypTCVN/mr
dFcmwn8jCbuy2h8ZjEJIoxk=
-----END PRIVATE KEY-----"#;

// The modulus (n) and exponent (e) for the above key, base64url-encoded
const TEST_RSA_N: &str = "1GY3CdZsra08d8mxA54yb2xNIOGBK4JEHDtDuuCYZymERT6sjeVol3_llyHkbnwBynegp7lBAg-fzaUuIF6ntCx4XojuVG5lKiAo3ua5bq7_kd_fHWLVv6_T4NcruQ-3awDFPwVxpip2dR10LpPCx7aI97e_C6e3297Zifkb7wcZBtKu04tbmGJm1BDwU6XIsSA4KdNtAd5ANUEpKWQ1nTWJZDuz5swlJatzUlFC0Bi1JanCmWCGpvi_W4vbRYueF9NO6GdUKajmZ3vuIhBdcgAvgtjSXhsFI_tGXLsj-bG29xXtET01X6Uyv1INmdZkLLcP76YY-RTKDCTeAPbx_Q";
const TEST_RSA_E: &str = "AQAB";

const TEST_KEY_ID: &str = "test-key-id-12345";

/// Test Cognito claims builder
///
/// Note: Field names match what the CognitoClaims struct expects for deserialization.
/// Cognito actually uses `cognito:groups` in JWTs, but our deserializer expects `cognito_groups`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCognitoClaims {
    pub sub: String,
    pub token_use: Option<String>,
    #[serde(default)]
    pub cognito_groups: Vec<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: Option<String>,
    pub client_id: Option<String>,
}

impl TestCognitoClaims {
    /// Create valid claims for testing
    pub fn valid(issuer: &str, client_id: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            sub: uuid::Uuid::new_v4().to_string(),
            token_use: Some("access".to_string()),
            cognito_groups: vec![],
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            iat: now,
            exp: now + 3600, // 1 hour from now
            iss: issuer.to_string(),
            aud: Some(client_id.to_string()),
            client_id: Some(client_id.to_string()),
        }
    }

    /// Create expired claims
    #[allow(dead_code)]
    pub fn expired(issuer: &str, client_id: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            exp: now - 3600, // 1 hour ago
            iat: now - 7200,
            ..Self::valid(issuer, client_id)
        }
    }

    #[allow(dead_code)]
    pub fn with_sub(mut self, sub: &str) -> Self {
        self.sub = sub.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.cognito_groups = groups;
        self
    }

    #[allow(dead_code)]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.iss = issuer.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn with_client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self.aud = Some(client_id.to_string());
        self
    }
}

/// Test keypair for signing JWTs
pub struct TestKeyPair {
    encoding_key: EncodingKey,
    kid: String,
}

impl TestKeyPair {
    /// Load the test keypair
    pub fn load() -> Self {
        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("Failed to load test RSA key");
        Self {
            encoding_key,
            kid: TEST_KEY_ID.to_string(),
        }
    }

    /// Get the key ID
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Sign claims into a JWT
    pub fn sign(&self, claims: &TestCognitoClaims) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        encode(&header, claims, &self.encoding_key).expect("Failed to sign JWT")
    }

    /// Sign claims with a different key ID (for unknown kid tests)
    #[allow(dead_code)]
    pub fn sign_with_kid(&self, claims: &TestCognitoClaims, kid: &str) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_string());

        encode(&header, claims, &self.encoding_key).expect("Failed to sign JWT")
    }
}

/// JWKS mock server setup
pub struct JwksMockServer {
    server: MockServer,
}

impl JwksMockServer {
    /// Start a mock JWKS server
    pub async fn start() -> Self {
        let server = MockServer::start().await;

        // Set up the JWKS endpoint
        let jwks_json = serde_json::json!({
            "keys": [{
                "kid": TEST_KEY_ID,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": TEST_RSA_N,
                "e": TEST_RSA_E
            }]
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&server)
            .await;

        Self { server }
    }

    /// Get the base URL of the mock server (without trailing slash)
    #[allow(dead_code)]
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Get the JWKS URL
    #[allow(dead_code)]
    pub fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.server.uri())
    }

    /// Add a custom JWKS response for specific tests
    #[allow(dead_code)]
    pub async fn with_custom_jwks(&self, keys: Vec<serde_json::Value>) {
        let jwks_json = serde_json::json!({ "keys": keys });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&self.server)
            .await;
    }

    /// Configure JWKS endpoint to return an error
    #[allow(dead_code)]
    pub async fn with_error_response(&self, status_code: u16) {
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(status_code))
            .mount(&self.server)
            .await;
    }

    /// Mount a JWKS mock with exact call count expectation
    /// Returns a guard that panics on drop if expectations aren't met
    #[allow(dead_code)]
    pub async fn expect_jwks_calls(&self, expected_calls: u64) -> MockGuard {
        let jwks_json = serde_json::json!({
            "keys": [{
                "kid": TEST_KEY_ID,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": TEST_RSA_N,
                "e": TEST_RSA_E
            }]
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .expect(expected_calls)
            .mount_as_scoped(&self.server)
            .await
    }

    /// Start a bare mock server without JWKS mounted (for custom setups)
    #[allow(dead_code)]
    pub async fn start_bare() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_loads() {
        let keypair = TestKeyPair::load();
        assert_eq!(keypair.kid(), TEST_KEY_ID);
    }

    #[test]
    fn test_sign_jwt() {
        let keypair = TestKeyPair::load();
        let claims = TestCognitoClaims::valid("https://test-issuer.com", "test-client");
        let token = keypair.sign(&claims);

        // JWT should have 3 parts
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_mock_server_starts() {
        let server = JwksMockServer::start().await;
        let url = server.jwks_url();
        assert!(url.contains("/.well-known/jwks.json"));
    }
}
