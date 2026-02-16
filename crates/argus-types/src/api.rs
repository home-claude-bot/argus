//! API request/response types

use serde::{Deserialize, Serialize};

/// Standard API response envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the request succeeded
    pub success: bool,
    /// Response data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error information (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(error: ApiError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// API error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error code (e.g., `UNAUTHORIZED`, `NOT_FOUND`)
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Additional error details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    /// Create a new API error
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Add details to the error
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    // Common error constructors

    /// Unauthorized error
    pub fn unauthorized() -> Self {
        Self::new("UNAUTHORIZED", "Authentication required")
    }

    /// Forbidden error
    pub fn forbidden() -> Self {
        Self::new("FORBIDDEN", "Access denied")
    }

    /// Not found error
    pub fn not_found(resource: &str) -> Self {
        Self::new("NOT_FOUND", format!("{resource} not found"))
    }

    /// Bad request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("BAD_REQUEST", message)
    }

    /// Rate limit exceeded error
    pub fn rate_limited() -> Self {
        Self::new("RATE_LIMITED", "Rate limit exceeded")
    }

    /// Internal server error
    pub fn internal() -> Self {
        Self::new("INTERNAL_ERROR", "An internal error occurred")
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    /// Page number (1-indexed)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    20
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

impl Pagination {
    /// Get the offset for database queries
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.per_page
    }

    /// Get the limit for database queries
    pub fn limit(&self) -> u32 {
        self.per_page.min(100) // Cap at 100
    }
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// Items in this page
    pub items: Vec<T>,
    /// Total number of items
    pub total: u64,
    /// Current page (1-indexed)
    pub page: u32,
    /// Items per page
    pub per_page: u32,
    /// Total number of pages
    pub total_pages: u32,
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response
    pub fn new(items: Vec<T>, total: u64, pagination: &Pagination) -> Self {
        let total_pages = ((total as f64) / (pagination.per_page as f64)).ceil() as u32;
        Self {
            items,
            total,
            page: pagination.page,
            per_page: pagination.per_page,
            total_pages,
        }
    }

    /// Check if there's a next page
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }

    /// Check if there's a previous page
    pub fn has_prev(&self) -> bool {
        self.page > 1
    }
}

/// Sort direction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    /// Ascending order
    Asc,
    /// Descending order (default)
    #[default]
    Desc,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status
    pub status: HealthStatus,
    /// Service version
    pub version: String,
    /// Component health checks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentHealth>>,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but functional
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

/// Component health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status
    pub status: HealthStatus,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
