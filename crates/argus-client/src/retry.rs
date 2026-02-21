//! Retry middleware with exponential backoff
//!
//! Provides retry logic for transient gRPC failures using tower middleware.
//!
//! # Features
//!
//! - Exponential backoff with configurable base delay and max delay
//! - Jitter to prevent thundering herd
//! - Respects `ClientError::is_retryable()` for retry decisions
//! - Configurable maximum retry attempts
//!
//! # Example
//!
//! ```ignore
//! use argus_client::retry::{RetryPolicy, RetryConfig};
//!
//! let config = RetryConfig::default()
//!     .with_max_attempts(3)
//!     .with_base_delay(Duration::from_millis(100));
//!
//! let policy = RetryPolicy::new(config);
//! ```

use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;
use tonic::Code;
use tracing::warn;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (excluding the initial request).
    pub max_attempts: u32,
    /// Base delay for exponential backoff.
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Whether to add jitter to prevent thundering herd.
    pub add_jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            add_jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of retry attempts.
    #[must_use]
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Set the base delay for exponential backoff.
    #[must_use]
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Set the maximum delay between retries.
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub fn with_jitter(mut self, enable: bool) -> Self {
        self.add_jitter = enable;
        self
    }

    /// Calculate the delay for a given attempt number.
    ///
    /// Uses exponential backoff: `base_delay * 2^attempt`
    /// Capped at `max_delay`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let multiplier = 2u64.saturating_pow(attempt);
        let delay_ms = self.base_delay.as_millis() as u64 * multiplier;
        let delay = Duration::from_millis(delay_ms.min(self.max_delay.as_millis() as u64));

        if self.add_jitter {
            // Add up to 25% jitter
            let jitter_range = delay.as_millis() as u64 / 4;
            let jitter = if jitter_range > 0 {
                // Simple pseudo-random jitter using current time
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as u64;
                Duration::from_millis(nanos % jitter_range)
            } else {
                Duration::ZERO
            };
            delay + jitter
        } else {
            delay
        }
    }
}

/// Retry policy that determines whether to retry a request.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    config: RetryConfig,
}

impl RetryPolicy {
    /// Create a new retry policy with the given configuration.
    #[must_use]
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Check if a gRPC status code should be retried.
    #[must_use]
    pub fn should_retry_code(&self, code: Code) -> bool {
        matches!(
            code,
            Code::Unavailable
                | Code::ResourceExhausted
                | Code::Aborted
                | Code::DeadlineExceeded
                | Code::Unknown // Unknown errors might be transient
        )
    }

    /// Get the delay before the next retry attempt.
    #[must_use]
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        self.config.delay_for_attempt(attempt)
    }

    /// Check if more retries are allowed.
    #[must_use]
    pub fn can_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_attempts
    }

    /// Get the retry configuration.
    #[must_use]
    pub fn config(&self) -> &RetryConfig {
        &self.config
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(RetryConfig::default())
    }
}

/// Execute an async operation with retry logic.
///
/// # Example
///
/// ```ignore
/// use argus_client::retry::{with_retry, RetryConfig};
///
/// let result = with_retry(RetryConfig::default(), || async {
///     client.validate_token("token").await
/// }).await;
/// ```
pub async fn with_retry<F, Fut, T, E>(config: RetryConfig, mut operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: RetryableError,
{
    let policy = RetryPolicy::new(config);
    let mut attempt = 0;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if !err.is_retryable() || !policy.can_retry(attempt) {
                    return Err(err);
                }

                let delay = policy.retry_delay(attempt);
                warn!(
                    attempt = attempt + 1,
                    max_attempts = policy.config().max_attempts,
                    delay_ms = delay.as_millis(),
                    "retrying after transient error"
                );

                sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

/// Trait for errors that can indicate whether they're retryable.
pub trait RetryableError {
    /// Returns true if this error is retryable.
    fn is_retryable(&self) -> bool;
}

// Implement for ClientError
impl RetryableError for crate::ClientError {
    fn is_retryable(&self) -> bool {
        crate::ClientError::is_retryable(self)
    }
}

// Implement for tonic::Status
impl RetryableError for tonic::Status {
    fn is_retryable(&self) -> bool {
        matches!(
            self.code(),
            Code::Unavailable
                | Code::ResourceExhausted
                | Code::Aborted
                | Code::DeadlineExceeded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.base_delay, Duration::from_millis(100));
        assert_eq!(config.max_delay, Duration::from_secs(10));
        assert!(config.add_jitter);
    }

    #[test]
    fn test_exponential_backoff() {
        let config = RetryConfig::new()
            .with_base_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(60))
            .with_jitter(false);

        // Without jitter, delays should be exact
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_max_delay_cap() {
        let config = RetryConfig::new()
            .with_base_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(5))
            .with_jitter(false);

        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(5)); // Capped
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(5)); // Still capped
    }

    #[test]
    fn test_retry_policy_codes() {
        let policy = RetryPolicy::default();

        // Should retry
        assert!(policy.should_retry_code(Code::Unavailable));
        assert!(policy.should_retry_code(Code::ResourceExhausted));
        assert!(policy.should_retry_code(Code::Aborted));
        assert!(policy.should_retry_code(Code::DeadlineExceeded));

        // Should not retry
        assert!(!policy.should_retry_code(Code::NotFound));
        assert!(!policy.should_retry_code(Code::InvalidArgument));
        assert!(!policy.should_retry_code(Code::PermissionDenied));
        assert!(!policy.should_retry_code(Code::Unauthenticated));
    }

    #[test]
    fn test_can_retry() {
        let policy = RetryPolicy::new(RetryConfig::new().with_max_attempts(3));

        assert!(policy.can_retry(0));
        assert!(policy.can_retry(1));
        assert!(policy.can_retry(2));
        assert!(!policy.can_retry(3));
        assert!(!policy.can_retry(4));
    }

    #[tokio::test]
    async fn test_with_retry_success() {
        let mut call_count = 0;

        let result = with_retry(RetryConfig::default(), || {
            call_count += 1;
            async { Ok::<_, TestError>(42) }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_with_retry_non_retryable() {
        let mut call_count = 0;

        let result = with_retry(RetryConfig::default(), || {
            call_count += 1;
            async { Err::<i32, _>(TestError { retryable: false }) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 1); // No retries for non-retryable errors
    }

    #[tokio::test]
    async fn test_with_retry_exhausted() {
        let mut call_count = 0;
        let config = RetryConfig::new()
            .with_max_attempts(2)
            .with_base_delay(Duration::from_millis(1));

        let result = with_retry(config, || {
            call_count += 1;
            async { Err::<i32, _>(TestError { retryable: true }) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count, 3); // Initial + 2 retries
    }

    // Test error type
    #[derive(Debug)]
    struct TestError {
        retryable: bool,
    }

    impl RetryableError for TestError {
        fn is_retryable(&self) -> bool {
            self.retryable
        }
    }
}
