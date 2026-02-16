//! MCP Server implementation

use std::sync::Arc;

/// Argus MCP Server
///
/// Provides MCP tools for auth and billing operations.
pub struct ArgusMcpServer {
    // TODO: Add auth_service and billing_service when those crates are ready
}

impl ArgusMcpServer {
    /// Create a new MCP server instance
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ArgusMcpServer {
    fn default() -> Self {
        Self::new()
    }
}
