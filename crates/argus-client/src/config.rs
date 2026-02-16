//! Client configuration

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Auth service URL
    pub auth_url: String,
    /// Billing service URL
    pub billing_url: String,
}

impl ClientConfig {
    /// Create a new client configuration
    pub fn new(auth_url: impl Into<String>, billing_url: impl Into<String>) -> Self {
        Self {
            auth_url: auth_url.into(),
            billing_url: billing_url.into(),
        }
    }
}
