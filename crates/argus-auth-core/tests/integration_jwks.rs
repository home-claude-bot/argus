//! Integration tests for JWKS-based JWT validation
//!
//! These tests use wiremock to simulate a Cognito JWKS endpoint and verify
//! that the TokenValidator correctly validates JWTs.

mod common;

use argus_auth_core::{AuthConfig, TokenValidator};
use common::{JwksMockServer, TestCognitoClaims, TestKeyPair};

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_POOL_ID: &str = "us-east-1_TestPool";
const TEST_REGION: &str = "us-east-1";

/// Create an AuthConfig pointing to the mock server
fn create_test_config(mock_url: &str) -> AuthConfig {
    AuthConfig::new(TEST_POOL_ID, TEST_REGION, TEST_CLIENT_ID, "a".repeat(32))
        .with_jwks_url_override(format!("{mock_url}/.well-known/jwks.json"))
}

#[tokio::test]
async fn test_valid_jwt_validates_successfully() {
    // Start mock JWKS server
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    // Create valid claims
    let claims = TestCognitoClaims::valid(&config.cognito_issuer(), TEST_CLIENT_ID);
    let token = keypair.sign(&claims);

    // Validate
    let result = validator.validate(&token).await;

    assert!(result.is_ok(), "Expected valid token, got: {result:?}");
    let validated_claims = result.unwrap();
    assert_eq!(validated_claims.sub, claims.sub);
}

#[tokio::test]
async fn test_expired_jwt_returns_token_expired() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    // Create expired claims
    let claims = TestCognitoClaims::expired(&config.cognito_issuer(), TEST_CLIENT_ID);
    let token = keypair.sign(&claims);

    // Validate should fail with TokenExpired
    let result = validator.validate(&token).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        argus_auth_core::AuthError::TokenExpired => {}
        other => panic!("Expected TokenExpired, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_unknown_kid_returns_invalid_token() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    // Create valid claims but sign with unknown kid
    let claims = TestCognitoClaims::valid(&config.cognito_issuer(), TEST_CLIENT_ID);
    let token = keypair.sign_with_kid(&claims, "unknown-kid-12345");

    // Validate should fail
    let result = validator.validate(&token).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        argus_auth_core::AuthError::InvalidToken => {}
        other => panic!("Expected InvalidToken, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_wrong_issuer_returns_invalid_token() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    // Create claims with wrong issuer
    let claims = TestCognitoClaims::valid("https://wrong-issuer.com/wrong-pool", TEST_CLIENT_ID);
    let token = keypair.sign(&claims);

    // Validate should fail
    let result = validator.validate(&token).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        argus_auth_core::AuthError::InvalidToken => {}
        other => panic!("Expected InvalidToken, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_wrong_client_id_returns_invalid_token() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config);
    let keypair = TestKeyPair::load();

    // Create claims with wrong client ID
    let claims = TestCognitoClaims::valid(
        &format!("https://cognito-idp.us-east-1.amazonaws.com/{TEST_POOL_ID}"),
        "wrong-client-id",
    );
    let token = keypair.sign(&claims);

    // Validate should fail
    let result = validator.validate(&token).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        argus_auth_core::AuthError::InvalidToken => {}
        other => panic!("Expected InvalidToken, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_jwt_with_cognito_groups() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    // Create claims with Cognito groups
    let claims = TestCognitoClaims::valid(&config.cognito_issuer(), TEST_CLIENT_ID)
        .with_groups(vec!["org_enterprise".to_string(), "org_admin".to_string()]);
    let token = keypair.sign(&claims);

    // Validate
    let result = validator.validate(&token).await;

    assert!(result.is_ok());
    let validated_claims = result.unwrap();
    assert_eq!(validated_claims.cognito_groups.len(), 2);
    assert!(validated_claims
        .cognito_groups
        .contains(&"org_enterprise".to_string()));
    assert!(validated_claims
        .cognito_groups
        .contains(&"org_admin".to_string()));
}

#[tokio::test]
async fn test_malformed_jwt_returns_invalid_token() {
    let mock_server = JwksMockServer::start().await;
    let config = create_test_config(&mock_server.url());

    let validator = TokenValidator::new(config);

    // Various malformed tokens
    let malformed_tokens = [
        "",
        "not-a-jwt",
        "one.two",
        "one.two.three.four",
        "eyJhbGciOiJSUzI1NiJ9.invalid-payload.signature",
    ];

    for token in malformed_tokens {
        let result = validator.validate(token).await;
        assert!(
            result.is_err(),
            "Expected error for malformed token: {token:?}"
        );
    }
}

#[tokio::test]
async fn test_jwks_caching_prevents_refetch() {
    // Start bare server and mount JWKS with exactly 1 expected call
    let mock_server = JwksMockServer::start_bare().await;
    let config = create_test_config(&mock_server.url());
    let _guard = mock_server.expect_jwks_calls(1).await;

    let validator = TokenValidator::new(config.clone());
    let keypair = TestKeyPair::load();

    let claims = TestCognitoClaims::valid(&config.cognito_issuer(), TEST_CLIENT_ID);
    let token = keypair.sign(&claims);

    // Validate multiple times - JWKS should only be fetched once due to caching
    for _ in 0..5 {
        let result = validator.validate(&token).await;
        assert!(result.is_ok());
    }

    // Guard verifies exactly 1 JWKS fetch on drop - proves caching works
}

#[tokio::test]
async fn test_jwks_flood_protection() {
    use std::sync::Arc;

    // Start bare server and mount JWKS expecting only 1 fetch despite concurrent load
    let mock_server = JwksMockServer::start_bare().await;
    let config = create_test_config(&mock_server.url());
    let _guard = mock_server.expect_jwks_calls(1).await;

    let validator = Arc::new(TokenValidator::new(config.clone()));
    let keypair = TestKeyPair::load();
    let claims = TestCognitoClaims::valid(&config.cognito_issuer(), TEST_CLIENT_ID);
    let token = Arc::new(keypair.sign(&claims));

    // Spawn 50 concurrent validation requests
    let handles: Vec<_> = (0..50)
        .map(|_| {
            let validator = Arc::clone(&validator);
            let token = Arc::clone(&token);
            tokio::spawn(async move { validator.validate(&token).await })
        })
        .collect();

    // All should succeed
    for handle in handles {
        let result = handle.await.expect("task panicked");
        assert!(result.is_ok(), "validation failed: {result:?}");
    }

    // Guard verifies exactly 1 JWKS fetch - proves flood protection works
}
