//! Tower middleware layer for Argus integration.
//!
//! The [`ArgusLayer`] provides authentication middleware for Axum applications.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, Request, Response};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::context::{AuthContext, AuthSource, Role};
use crate::extractors::AuthContextExt;
use argus_client::SharedArgusClient;
use argus_types::{Tier, UserId};

/// Configuration for the Argus middleware layer.
#[derive(Debug, Clone)]
pub struct ArgusConfig {
    /// Whether to require authentication for all requests.
    pub require_auth: bool,
    /// Whether to allow API key authentication.
    pub allow_api_key: bool,
    /// Whether to allow bearer token authentication.
    pub allow_bearer_token: bool,
    /// Custom header name for API key (default: X-API-Key).
    pub api_key_header: String,
    /// Whether to fail open (allow unauthenticated) on Argus errors.
    pub fail_open: bool,
}

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            require_auth: false,
            allow_api_key: true,
            allow_bearer_token: true,
            api_key_header: "X-API-Key".to_string(),
            fail_open: false,
        }
    }
}

impl ArgusConfig {
    /// Create a new config builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to require authentication.
    #[must_use]
    pub fn require_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    /// Set whether to allow API key auth.
    #[must_use]
    pub fn allow_api_key(mut self, allow: bool) -> Self {
        self.allow_api_key = allow;
        self
    }

    /// Set whether to allow bearer token auth.
    #[must_use]
    pub fn allow_bearer_token(mut self, allow: bool) -> Self {
        self.allow_bearer_token = allow;
        self
    }

    /// Set the API key header name.
    #[must_use]
    pub fn api_key_header(mut self, header: impl Into<String>) -> Self {
        self.api_key_header = header.into();
        self
    }

    /// Set whether to fail open on errors.
    #[must_use]
    pub fn fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }
}

/// Tower layer that adds Argus authentication to requests.
#[derive(Clone)]
pub struct ArgusLayer {
    client: SharedArgusClient,
    config: ArgusConfig,
}

impl ArgusLayer {
    /// Create a new Argus layer with the given client.
    #[must_use]
    pub fn new(client: SharedArgusClient) -> Self {
        Self {
            client,
            config: ArgusConfig::default(),
        }
    }

    /// Create a new Argus layer with custom configuration.
    #[must_use]
    pub fn with_config(client: SharedArgusClient, config: ArgusConfig) -> Self {
        Self { client, config }
    }
}

impl<S> Layer<S> for ArgusLayer {
    type Service = ArgusService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ArgusService {
            inner,
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

/// The Argus authentication service.
#[derive(Clone)]
pub struct ArgusService<S> {
    inner: S,
    client: SharedArgusClient,
    config: ArgusConfig,
}

impl<S> ArgusService<S> {
    /// Extract authentication credentials from the request.
    fn extract_credentials(
        &self,
        req: &Request<Body>,
    ) -> Option<(String, AuthSource)> {
        // Try bearer token first
        if self.config.allow_bearer_token {
            if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        return Some((token.to_string(), AuthSource::BearerToken));
                    }
                }
            }
        }

        // Try API key
        if self.config.allow_api_key {
            if let Some(api_key) = req.headers().get(&self.config.api_key_header) {
                if let Ok(key_str) = api_key.to_str() {
                    return Some((key_str.to_string(), AuthSource::ApiKey));
                }
            }
        }

        // Try session header (X-Cognito-Session for CloudFront edge auth)
        if let Some(session) = req.headers().get("X-Cognito-Session") {
            if let Ok(session_str) = session.to_str() {
                return Some((session_str.to_string(), AuthSource::Session));
            }
        }

        None
    }
}

impl<S, ResBody> Service<Request<Body>> for ArgusService<S>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ArgusServiceFuture<S, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let credentials = self.extract_credentials(&req);
        let client = self.client.clone();
        let config = self.config.clone();
        let inner = self.inner.clone();

        ArgusServiceFuture {
            state: FutureState::Authenticating {
                inner: Some(inner),
                req: Some(req),
                credentials,
                client,
                config,
            },
        }
    }
}

pin_project! {
    /// Future for the Argus service.
    pub struct ArgusServiceFuture<S, ResBody>
    where
        S: Service<Request<Body>, Response = Response<ResBody>>,
    {
        #[pin]
        state: FutureState<S, ResBody>,
    }
}

pin_project! {
    #[project = FutureStateProj]
    enum FutureState<S, ResBody>
    where
        S: Service<Request<Body>, Response = Response<ResBody>>,
    {
        Authenticating {
            inner: Option<S>,
            req: Option<Request<Body>>,
            credentials: Option<(String, AuthSource)>,
            client: SharedArgusClient,
            config: ArgusConfig,
        },
        Calling {
            #[pin]
            future: S::Future,
        },
        Done,
    }
}

impl<S, ResBody> Future for ArgusServiceFuture<S, ResBody>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ResBody: Default + Send + 'static,
{
    type Output = Result<S::Response, S::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let this = self.as_mut().project();

            match this.state.project() {
                FutureStateProj::Authenticating {
                    inner,
                    req,
                    credentials,
                    client: _,
                    config,
                } => {
                    // For now, we do synchronous auth validation
                    // In production, this would be async with caching
                    let auth_context = if let Some((_cred, source)) = credentials.take() {
                        // Mock auth validation - in production this calls argus-client
                        // For now, create a mock context based on credential format
                        let user_id = UserId::new();
                        Some(
                            AuthContext::new(user_id, Tier::Professional)
                                .with_source(source)
                                .with_role(Role::User),
                        )
                    } else {
                        None
                    };

                    let mut request = req.take().unwrap();

                    // Check if auth is required but not present
                    if config.require_auth && auth_context.is_none() {
                        // Return 401 Unauthorized
                        let response = Response::builder()
                            .status(401)
                            .body(ResBody::default())
                            .unwrap();
                        self.set(ArgusServiceFuture {
                            state: FutureState::Done,
                        });
                        return Poll::Ready(Ok(response));
                    }

                    // Add auth context to request extensions if present
                    if let Some(ctx) = auth_context {
                        request.extensions_mut().insert(AuthContextExt(ctx));
                    }

                    let mut service = inner.take().unwrap();
                    let future = service.call(request);

                    self.set(ArgusServiceFuture {
                        state: FutureState::Calling { future },
                    });
                }
                FutureStateProj::Calling { future } => {
                    return future.poll(cx);
                }
                FutureStateProj::Done => {
                    panic!("polled after completion");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = ArgusConfig::new()
            .require_auth(true)
            .allow_api_key(false)
            .api_key_header("X-Custom-Key")
            .fail_open(true);

        assert!(config.require_auth);
        assert!(!config.allow_api_key);
        assert_eq!(config.api_key_header, "X-Custom-Key");
        assert!(config.fail_open);
    }
}
