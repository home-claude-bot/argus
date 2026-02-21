//! Client metrics for observability.
//!
//! Provides Prometheus-compatible metrics for monitoring client SDK usage.
//!
//! # Metrics
//!
//! - `argus_client_requests_total` - Counter of requests by service, method, status
//! - `argus_client_request_duration_seconds` - Histogram of request latencies
//! - `argus_client_retries_total` - Counter of retry attempts
//! - `argus_client_connections_total` - Counter of connection events
//!
//! # Usage
//!
//! Metrics are automatically recorded when using the client SDK if a metrics
//! recorder is installed. Use any `metrics`-compatible backend like
//! `metrics-exporter-prometheus`.
//!
//! ```ignore
//! use metrics_exporter_prometheus::PrometheusBuilder;
//!
//! // Install Prometheus exporter
//! PrometheusBuilder::new().install().unwrap();
//!
//! // Use client as normal - metrics are recorded automatically
//! let client = AuthClient::connect(config).await?;
//! client.validate_token("token").await?;
//! ```

use std::time::Instant;

use metrics::{counter, histogram};

/// Metric name for total requests.
pub const REQUESTS_TOTAL: &str = "argus_client_requests_total";

/// Metric name for request duration histogram.
pub const REQUEST_DURATION_SECONDS: &str = "argus_client_request_duration_seconds";

/// Metric name for retry counter.
pub const RETRIES_TOTAL: &str = "argus_client_retries_total";

/// Metric name for connection events.
pub const CONNECTIONS_TOTAL: &str = "argus_client_connections_total";

/// Service names for metric labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Auth,
    Billing,
    Identity,
}

impl Service {
    /// Get the service name as a string for metrics labels.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Billing => "billing",
            Self::Identity => "identity",
        }
    }
}

/// Request status for metrics labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    Error,
    Timeout,
    Cancelled,
}

impl Status {
    /// Get the status as a string for metrics labels.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Record a request completion.
///
/// # Arguments
///
/// * `service` - The service that was called
/// * `method` - The gRPC method name
/// * `status` - The request result status
/// * `duration_seconds` - The request duration
pub fn record_request(service: Service, method: &str, status: Status, duration_seconds: f64) {
    counter!(
        REQUESTS_TOTAL,
        "service" => service.as_str(),
        "method" => method.to_string(),
        "status" => status.as_str()
    )
    .increment(1);

    histogram!(
        REQUEST_DURATION_SECONDS,
        "service" => service.as_str(),
        "method" => method.to_string()
    )
    .record(duration_seconds);
}

/// Record a retry attempt.
///
/// # Arguments
///
/// * `service` - The service being retried
/// * `method` - The gRPC method name
/// * `attempt` - The retry attempt number (1-indexed)
pub fn record_retry(service: Service, method: &str, attempt: u32) {
    counter!(
        RETRIES_TOTAL,
        "service" => service.as_str(),
        "method" => method.to_string(),
        "attempt" => attempt.to_string()
    )
    .increment(1);
}

/// Record a connection event.
///
/// # Arguments
///
/// * `service` - The service being connected to
/// * `event` - The connection event type ("connect", "disconnect", "error")
pub fn record_connection(service: Service, event: &str) {
    counter!(
        CONNECTIONS_TOTAL,
        "service" => service.as_str(),
        "event" => event.to_string()
    )
    .increment(1);
}

/// Timer guard for automatically recording request duration.
///
/// Records the request duration when dropped.
///
/// # Example
///
/// ```ignore
/// let _timer = RequestTimer::start(Service::Auth, "validate_token");
/// let result = do_request().await;
/// // Timer records duration on drop
/// ```
#[must_use]
pub struct RequestTimer {
    service: Service,
    method: String,
    start: Instant,
    recorded: bool,
}

impl RequestTimer {
    /// Start a new request timer.
    pub fn start(service: Service, method: impl Into<String>) -> Self {
        Self {
            service,
            method: method.into(),
            start: Instant::now(),
            recorded: false,
        }
    }

    /// Record success and return the duration.
    pub fn success(mut self) -> std::time::Duration {
        let duration = self.start.elapsed();
        record_request(
            self.service,
            &self.method,
            Status::Success,
            duration.as_secs_f64(),
        );
        self.recorded = true;
        duration
    }

    /// Record an error and return the duration.
    pub fn error(mut self) -> std::time::Duration {
        let duration = self.start.elapsed();
        record_request(
            self.service,
            &self.method,
            Status::Error,
            duration.as_secs_f64(),
        );
        self.recorded = true;
        duration
    }

    /// Record a timeout and return the duration.
    pub fn timeout(mut self) -> std::time::Duration {
        let duration = self.start.elapsed();
        record_request(
            self.service,
            &self.method,
            Status::Timeout,
            duration.as_secs_f64(),
        );
        self.recorded = true;
        duration
    }

    /// Record a cancellation and return the duration.
    pub fn cancelled(mut self) -> std::time::Duration {
        let duration = self.start.elapsed();
        record_request(
            self.service,
            &self.method,
            Status::Cancelled,
            duration.as_secs_f64(),
        );
        self.recorded = true;
        duration
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        // If not already recorded, record as cancelled (e.g., panic)
        if !self.recorded {
            let duration = self.start.elapsed();
            record_request(
                self.service,
                &self.method,
                Status::Cancelled,
                duration.as_secs_f64(),
            );
        }
    }
}

/// Describe all metrics for registration with a recorder.
///
/// Call this during application startup to register metric descriptions.
///
/// ```ignore
/// argus_client::metrics::describe_metrics();
/// ```
pub fn describe_metrics() {
    use metrics::{describe_counter, describe_histogram, Unit};

    describe_counter!(
        REQUESTS_TOTAL,
        Unit::Count,
        "Total number of gRPC requests made by the Argus client SDK"
    );

    describe_histogram!(
        REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Duration of gRPC requests in seconds"
    );

    describe_counter!(
        RETRIES_TOTAL,
        Unit::Count,
        "Total number of retry attempts by the Argus client SDK"
    );

    describe_counter!(
        CONNECTIONS_TOTAL,
        Unit::Count,
        "Total number of connection events (connect, disconnect, error)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_names() {
        assert_eq!(Service::Auth.as_str(), "auth");
        assert_eq!(Service::Billing.as_str(), "billing");
        assert_eq!(Service::Identity.as_str(), "identity");
    }

    #[test]
    fn test_status_names() {
        assert_eq!(Status::Success.as_str(), "success");
        assert_eq!(Status::Error.as_str(), "error");
        assert_eq!(Status::Timeout.as_str(), "timeout");
        assert_eq!(Status::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn test_request_timer_success() {
        let timer = RequestTimer::start(Service::Auth, "test_method");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let duration = timer.success();

        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn test_request_timer_drop_records_cancelled() {
        // Timer dropped without explicit recording should count as cancelled
        let _timer = RequestTimer::start(Service::Billing, "test_method");
        // Timer drops here - should record as cancelled
    }

    #[test]
    fn test_record_request_does_not_panic() {
        // Even without a metrics recorder, calls should not panic
        record_request(Service::Auth, "validate_token", Status::Success, 0.1);
        record_request(Service::Billing, "get_subscription", Status::Error, 0.5);
    }

    #[test]
    fn test_record_retry_does_not_panic() {
        record_retry(Service::Identity, "get_user", 1);
        record_retry(Service::Identity, "get_user", 2);
    }

    #[test]
    fn test_record_connection_does_not_panic() {
        record_connection(Service::Auth, "connect");
        record_connection(Service::Auth, "disconnect");
        record_connection(Service::Auth, "error");
    }

    #[test]
    fn test_describe_metrics_does_not_panic() {
        describe_metrics();
    }
}
