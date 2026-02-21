//! Integration tests for argus-client.
//!
//! These tests verify the client SDK components work correctly together.
//! Full gRPC server tests would require implementing all proto service methods,
//! so we focus on testing configuration, retry logic, and error handling.

use std::time::Duration;

use argus_client::{
    with_retry, ClientConfig, ClientError, CredentialSource, RetryConfig, RetryableError,
    TlsConfig,
};

// =============================================================================
// Configuration Integration Tests
// =============================================================================

#[test]
fn test_full_config_builder() {
    let tls = TlsConfig::new()
        .with_server_name("api.argus.internal")
        .with_ca_cert_pem(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_vec());

    let config = ClientConfig::builder()
        .auth_endpoint("https://auth.argus.io")
        .billing_endpoint("https://billing.argus.io")
        .identity_endpoint("https://identity.argus.io")
        .connect_timeout(Duration::from_secs(10))
        .request_timeout(Duration::from_secs(60))
        .retry_attempts(5)
        .retry_base_delay(Duration::from_millis(200))
        .retry_max_delay(Duration::from_secs(30))
        .bearer_token("api-key-12345")
        .tls_config(tls)
        .build()
        .unwrap();

    assert_eq!(config.auth_endpoint(), "https://auth.argus.io");
    assert_eq!(config.billing_endpoint(), "https://billing.argus.io");
    assert_eq!(config.identity_endpoint(), "https://identity.argus.io");
    assert_eq!(config.connect_timeout(), Duration::from_secs(10));
    assert_eq!(config.request_timeout(), Duration::from_secs(60));
    assert_eq!(config.retry_attempts(), 5);
    assert!(config.tls_enabled());
    assert!(config.tls_config().is_some());
}

#[test]
fn test_config_single_endpoint() {
    let config = ClientConfig::builder()
        .endpoint("http://localhost:50051")
        .build()
        .unwrap();

    // All endpoints should be the same
    assert_eq!(config.auth_endpoint(), "http://localhost:50051");
    assert_eq!(config.billing_endpoint(), "http://localhost:50051");
    assert_eq!(config.identity_endpoint(), "http://localhost:50051");
}

#[test]
fn test_config_bearer_token_security() {
    let config = ClientConfig::builder()
        .endpoint("http://localhost:50051")
        .bearer_token("super-secret-api-key")
        .build()
        .unwrap();

    // Token should not appear in debug output
    let debug = format!("{:?}", config);
    assert!(!debug.contains("super-secret-api-key"));
    assert!(debug.contains("[REDACTED]"));
}

// =============================================================================
// TLS Configuration Tests
// =============================================================================

#[test]
fn test_tls_config_all_options() {
    use std::path::PathBuf;

    let tls = TlsConfig::new()
        .with_ca_cert_path(PathBuf::from("/etc/ssl/certs/ca.pem"))
        .with_client_cert_path(PathBuf::from("/etc/ssl/certs/client.pem"))
        .with_client_key_path(PathBuf::from("/etc/ssl/private/client-key.pem"))
        .with_server_name("api.example.com");

    assert!(tls.has_ca_cert());
    assert!(tls.has_client_cert());
}

#[test]
fn test_tls_config_credential_sources() {
    let tls = TlsConfig::new()
        .with_ca_cert_source(CredentialSource::pem(b"ca cert data".to_vec()))
        .with_client_cert_source(CredentialSource::env("CLIENT_CERT"))
        .with_client_key_source(CredentialSource::vault(
            "secret/data/argus",
            "client_key",
        ));

    assert!(tls.has_client_cert_source());
}

#[test]
fn test_tls_config_danger_accept_invalid() {
    let tls = TlsConfig::new().danger_accept_invalid_certs();

    // This is a development-only option
    let config = ClientConfig::builder()
        .endpoint("https://localhost:50051")
        .tls_config(tls)
        .build()
        .unwrap();

    assert!(config.tls_enabled());
}

// =============================================================================
// Credential Source Tests
// =============================================================================

#[test]
fn test_credential_source_pem() {
    let data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
    let source = CredentialSource::pem(data.to_vec());

    let loaded = source.load().unwrap();
    assert_eq!(loaded, data);
}

#[test]
fn test_credential_source_env() {
    std::env::set_var("ARGUS_TEST_CRED", "test-credential-value");

    let source = CredentialSource::env("ARGUS_TEST_CRED");
    let loaded = source.load().unwrap();

    assert_eq!(String::from_utf8_lossy(&loaded), "test-credential-value");

    std::env::remove_var("ARGUS_TEST_CRED");
}

#[test]
fn test_credential_source_env_not_set() {
    let source = CredentialSource::env("ARGUS_NONEXISTENT_VAR_12345");
    let result = source.load();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not set"));
}

#[test]
fn test_credential_source_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "file-based-credential").unwrap();
    file.flush().unwrap();

    let source = CredentialSource::file(file.path());
    let loaded = source.load().unwrap();

    assert!(String::from_utf8_lossy(&loaded).contains("file-based-credential"));
}

#[test]
fn test_credential_source_file_not_found() {
    let source = CredentialSource::file("/nonexistent/path/to/credential.pem");
    let result = source.load();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("failed to read"));
}

#[test]
fn test_credential_source_vault_not_implemented() {
    let source = CredentialSource::vault("secret/data/certs", "ca_cert");
    let result = source.load();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Vault integration not yet implemented"));
}

// =============================================================================
// Retry Logic Tests
// =============================================================================

/// Test error type that implements RetryableError
#[derive(Debug)]
struct TestError {
    retryable: bool,
    message: String,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl RetryableError for TestError {
    fn is_retryable(&self) -> bool {
        self.retryable
    }
}

#[tokio::test]
async fn test_retry_succeeds_immediately() {
    let config = RetryConfig::new()
        .with_max_attempts(3)
        .with_base_delay(Duration::from_millis(1));

    let mut attempt = 0;

    let result = with_retry(config, || {
        attempt += 1;
        async { Ok::<_, TestError>(42) }
    })
    .await;

    assert_eq!(result.unwrap(), 42);
    assert_eq!(attempt, 1);
}

#[tokio::test]
async fn test_retry_succeeds_after_failures() {
    let config = RetryConfig::new()
        .with_max_attempts(3)
        .with_base_delay(Duration::from_millis(1));

    let mut attempt = 0;

    let result = with_retry(config, || {
        attempt += 1;
        async move {
            if attempt < 3 {
                Err(TestError {
                    retryable: true,
                    message: "transient failure".into(),
                })
            } else {
                Ok(42)
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), 42);
    assert_eq!(attempt, 3);
}

#[tokio::test]
async fn test_retry_exhausted() {
    let config = RetryConfig::new()
        .with_max_attempts(2)
        .with_base_delay(Duration::from_millis(1));

    let mut attempt = 0;

    let result: Result<i32, TestError> = with_retry(config, || {
        attempt += 1;
        async {
            Err(TestError {
                retryable: true,
                message: "always fails".into(),
            })
        }
    })
    .await;

    assert!(result.is_err());
    // Initial attempt + 2 retries = 3 total
    assert_eq!(attempt, 3);
}

#[tokio::test]
async fn test_retry_non_retryable_stops_immediately() {
    let config = RetryConfig::new()
        .with_max_attempts(5)
        .with_base_delay(Duration::from_millis(1));

    let mut attempt = 0;

    let result: Result<i32, TestError> = with_retry(config, || {
        attempt += 1;
        async {
            Err(TestError {
                retryable: false,
                message: "permanent failure".into(),
            })
        }
    })
    .await;

    assert!(result.is_err());
    assert_eq!(attempt, 1); // No retries for non-retryable errors
}

#[tokio::test]
async fn test_retry_with_closure_state() {
    let config = RetryConfig::new()
        .with_max_attempts(3)
        .with_base_delay(Duration::from_millis(1));

    // Using a shared counter to track state
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_clone = counter.clone();

    let result = with_retry(config, || {
        let c = counter_clone.clone();
        async move {
            let count = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count < 2 {
                Err(TestError {
                    retryable: true,
                    message: "not yet".into(),
                })
            } else {
                Ok("success")
            }
        }
    })
    .await;

    assert_eq!(result.unwrap(), "success");
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
}

// =============================================================================
// Error Type Tests
// =============================================================================

#[test]
fn test_client_error_is_retryable() {
    // Retryable errors
    assert!(ClientError::Unavailable("service down".into()).is_retryable());
    assert!(ClientError::ResourceExhausted("rate limited".into()).is_retryable());
    assert!(ClientError::Aborted("try again".into()).is_retryable());
    assert!(ClientError::Timeout(Duration::from_secs(30)).is_retryable());

    // Non-retryable errors
    assert!(!ClientError::Unauthenticated("bad token".into()).is_retryable());
    assert!(!ClientError::PermissionDenied("no access".into()).is_retryable());
    assert!(!ClientError::NotFound("missing resource".into()).is_retryable());
    assert!(!ClientError::InvalidArgument("bad input".into()).is_retryable());
}

#[test]
fn test_client_error_display() {
    let err = ClientError::Unauthenticated("invalid credentials".into());
    assert!(err.to_string().contains("invalid credentials"));

    let err = ClientError::connection("failed to connect", true);
    assert!(err.to_string().contains("failed to connect"));
}

// =============================================================================
// Channel Factory Tests (No actual gRPC)
// =============================================================================

#[tokio::test]
async fn test_channel_factory_lazy_creation() {
    use argus_client::ChannelFactory;

    let config = ClientConfig::builder()
        .endpoint("http://localhost:50051")
        .tls_enabled(false)
        .build()
        .unwrap();

    let factory = ChannelFactory::new(config);

    // These create lazy channels - no actual connection yet
    let auth_channel = factory.auth_channel().await;
    let billing_channel = factory.billing_channel().await;
    let identity_channel = factory.identity_channel().await;

    // Channels should be created successfully (lazy)
    assert!(auth_channel.is_ok());
    assert!(billing_channel.is_ok());
    assert!(identity_channel.is_ok());
}

#[tokio::test]
async fn test_unified_client_creation() {
    use argus_client::ArgusClient;

    let config = ClientConfig::builder()
        .endpoint("http://localhost:50051")
        .tls_enabled(false)
        .build()
        .unwrap();

    // This should succeed - connections are lazy
    let client = ArgusClient::connect(config).await;
    assert!(client.is_ok());

    let client = client.unwrap();

    // Getting service clients should work
    let _auth = client.auth();
    let _billing = client.billing();
    let _identity = client.identity();
}

#[tokio::test]
async fn test_shared_client() {
    use argus_client::SharedArgusClient;

    let config = ClientConfig::builder()
        .endpoint("http://localhost:50051")
        .tls_enabled(false)
        .build()
        .unwrap();

    let shared = SharedArgusClient::connect(config).await.unwrap();

    // Clone and access from multiple handles
    let shared2 = shared.clone();

    let client1 = shared.read().await;
    assert_eq!(
        client1.config().auth_endpoint(),
        "http://localhost:50051"
    );
    drop(client1);

    let client2 = shared2.read().await;
    assert_eq!(
        client2.config().auth_endpoint(),
        "http://localhost:50051"
    );
}
