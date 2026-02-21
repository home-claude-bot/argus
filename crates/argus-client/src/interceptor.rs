//! gRPC interceptors
//!
//! Request interceptors for adding authentication headers and other metadata.

use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Interceptor that adds a bearer token to requests.
#[derive(Debug, Clone)]
pub struct AuthInterceptor {
    token: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl AuthInterceptor {
    /// Create an interceptor with no token.
    pub fn new() -> Self {
        Self { token: None }
    }

    /// Create an interceptor with the given bearer token.
    pub fn with_token(token: impl AsRef<str>) -> Result<Self, InvalidToken> {
        let header_value = format!("Bearer {}", token.as_ref())
            .parse()
            .map_err(|_| InvalidToken)?;

        Ok(Self {
            token: Some(header_value),
        })
    }

    /// Set the bearer token.
    pub fn set_token(&mut self, token: impl AsRef<str>) -> Result<(), InvalidToken> {
        let header_value = format!("Bearer {}", token.as_ref())
            .parse()
            .map_err(|_| InvalidToken)?;

        self.token = Some(header_value);
        Ok(())
    }

    /// Clear the bearer token.
    pub fn clear_token(&mut self) {
        self.token = None;
    }

    /// Check if a token is set.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

impl Default for AuthInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(ref token) = self.token {
            request
                .metadata_mut()
                .insert("authorization", token.clone());
        }
        Ok(request)
    }
}

/// Error indicating an invalid token format.
#[derive(Debug, Clone, Copy)]
pub struct InvalidToken;

impl std::fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid token format")
    }
}

impl std::error::Error for InvalidToken {}

/// Interceptor that adds request ID for tracing.
#[derive(Debug, Clone, Default)]
pub struct RequestIdInterceptor;

impl RequestIdInterceptor {
    /// Create a new request ID interceptor.
    pub fn new() -> Self {
        Self
    }
}

impl Interceptor for RequestIdInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let value: MetadataValue<tonic::metadata::Ascii> = request_id
            .parse()
            .map_err(|_| Status::internal("failed to create request ID"))?;
        request.metadata_mut().insert("x-request-id", value);
        Ok(request)
    }
}

/// Combined interceptor that applies multiple interceptors.
#[derive(Debug, Clone)]
pub struct CombinedInterceptor {
    auth: AuthInterceptor,
    request_id: RequestIdInterceptor,
}

impl CombinedInterceptor {
    /// Create a combined interceptor with all features.
    pub fn new(auth: AuthInterceptor) -> Self {
        Self {
            auth,
            request_id: RequestIdInterceptor::new(),
        }
    }

    /// Get mutable access to the auth interceptor.
    pub fn auth_mut(&mut self) -> &mut AuthInterceptor {
        &mut self.auth
    }
}

impl Interceptor for CombinedInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let request = self.auth.call(request)?;
        self.request_id.call(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_interceptor_without_token() {
        let mut interceptor = AuthInterceptor::new();
        assert!(!interceptor.has_token());

        let request = Request::new(());
        let result = interceptor.call(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_interceptor_with_token() {
        let interceptor = AuthInterceptor::with_token("test-token");
        assert!(interceptor.is_ok());

        let mut interceptor = interceptor.unwrap();
        assert!(interceptor.has_token());

        let request = Request::new(());
        let result = interceptor.call(request);
        assert!(result.is_ok());

        let request = result.unwrap();
        let auth_header = request.metadata().get("authorization");
        assert!(auth_header.is_some());
        assert_eq!(auth_header.unwrap(), "Bearer test-token");
    }

    #[test]
    fn test_set_and_clear_token() {
        let mut interceptor = AuthInterceptor::new();
        assert!(!interceptor.has_token());

        interceptor.set_token("new-token").unwrap();
        assert!(interceptor.has_token());

        interceptor.clear_token();
        assert!(!interceptor.has_token());
    }

    #[test]
    fn test_request_id_interceptor() {
        let mut interceptor = RequestIdInterceptor::new();
        let request = Request::new(());
        let result = interceptor.call(request);
        assert!(result.is_ok());

        let request = result.unwrap();
        let request_id = request.metadata().get("x-request-id");
        assert!(request_id.is_some());

        // Should be a valid UUID
        let id_str = request_id.unwrap().to_str().unwrap();
        assert!(uuid::Uuid::parse_str(id_str).is_ok());
    }
}
