//! Shared handler utilities
//!
//! Common validation, metrics, and helper functions used across handlers.
//! Centralizing these ensures consistent security policies and metrics.

use std::time::Instant;

use crate::error::ApiError;

// ============================================================================
// Input Validation
// ============================================================================

/// Maximum length for metric names (prevents cardinality explosion)
const MAX_METRIC_NAME_LEN: usize = 64;

/// Maximum length for user-provided strings
#[allow(dead_code)] // Available for future use
const MAX_STRING_LEN: usize = 256;

/// Validate a metric name for safe use in metrics and database.
///
/// # Security
/// - Prevents metrics cardinality attacks (unbounded label values)
/// - Prevents potential injection in metric labels
/// - Allows: alphanumeric, underscore, hyphen, dot
///
/// # Example
/// ```ignore
/// validate_metric_name("api_requests")?;  // Ok
/// validate_metric_name("foo.bar.baz")?;   // Ok
/// validate_metric_name("foo<script>")?;   // Err
/// ```
pub fn validate_metric_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest("Metric name cannot be empty".into()));
    }

    if name.len() > MAX_METRIC_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "Metric name too long (max {MAX_METRIC_NAME_LEN} chars)"
        )));
    }

    // Allow: a-z, A-Z, 0-9, _, -, .
    // This matches Prometheus label value restrictions
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(ApiError::BadRequest(
            "Metric name contains invalid characters (use alphanumeric, _, -, .)".into(),
        ));
    }

    // Must start with letter or underscore (Prometheus convention)
    if let Some(first) = name.chars().next() {
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(ApiError::BadRequest(
                "Metric name must start with letter or underscore".into(),
            ));
        }
    }

    Ok(())
}

/// Validate a user-provided string is within safe bounds.
#[allow(dead_code)] // Available for future use
pub fn validate_string_length(value: &str, field_name: &str) -> Result<(), ApiError> {
    if value.len() > MAX_STRING_LEN {
        return Err(ApiError::BadRequest(format!(
            "{field_name} too long (max {MAX_STRING_LEN} chars)"
        )));
    }
    Ok(())
}

// ============================================================================
// Metrics Helpers
// ============================================================================

/// Record HTTP operation duration with result label.
///
/// This helper ensures consistent metric naming and labels across all handlers.
/// Labels: operation, result (ok/err)
#[inline]
pub fn record_op_duration(operation: &'static str, start: Instant, success: bool) {
    let result = if success { "ok" } else { "err" };
    metrics::histogram!(
        "billing_operation_duration_seconds",
        "operation" => operation,
        "result" => result
    )
    .record(start.elapsed().as_secs_f64());
}

/// Record HTTP operation error.
/// Use this when you want to record error metrics without duration.
#[inline]
#[allow(dead_code)] // Available for future use
pub fn record_op_error(operation: &'static str) {
    metrics::counter!(
        "billing_operation_errors_total",
        "operation" => operation
    )
    .increment(1);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_metric_name_valid() {
        assert!(validate_metric_name("api_requests").is_ok());
        assert!(validate_metric_name("API_REQUESTS").is_ok());
        assert!(validate_metric_name("api.requests.v1").is_ok());
        assert!(validate_metric_name("api-requests").is_ok());
        assert!(validate_metric_name("_internal").is_ok());
        assert!(validate_metric_name("a").is_ok());
    }

    #[test]
    fn test_validate_metric_name_invalid() {
        // Empty
        assert!(validate_metric_name("").is_err());

        // Too long
        let long_name = "a".repeat(MAX_METRIC_NAME_LEN + 1);
        assert!(validate_metric_name(&long_name).is_err());

        // Invalid characters
        assert!(validate_metric_name("foo<bar>").is_err());
        assert!(validate_metric_name("foo bar").is_err());
        assert!(validate_metric_name("foo\nbar").is_err());
        assert!(validate_metric_name("foo;bar").is_err());

        // Doesn't start with letter/underscore
        assert!(validate_metric_name("123abc").is_err());
        assert!(validate_metric_name("-foo").is_err());
        assert!(validate_metric_name(".foo").is_err());
    }

    #[test]
    fn test_validate_string_length() {
        assert!(validate_string_length("short", "test").is_ok());

        let long_string = "a".repeat(MAX_STRING_LEN + 1);
        assert!(validate_string_length(&long_string, "test").is_err());
    }
}
