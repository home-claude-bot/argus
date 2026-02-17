//! Application state

use std::ops::Deref;
use std::sync::Arc;

use argus_auth_core::AuthService;
use argus_db::pg::{PgSessionRepository, PgUserRepository, Repositories};
use argus_db::DbPool;

use crate::config::Config;

/// Type alias for the auth service with concrete repository types
pub type AuthServiceImpl = AuthService<PgUserRepository, PgSessionRepository>;

/// Shared database pool wrapper for health checks
#[derive(Clone)]
pub struct SharedPool(Arc<DbPool>);

impl Deref for SharedPool {
    type Target = DbPool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Auth service for token validation and session management
    pub auth: Arc<AuthServiceImpl>,
    /// Database repositories
    pub repos: Repositories,
    /// Database connection pool (shared reference for health checks)
    pub pool: SharedPool,
    /// Application configuration
    pub config: Arc<Config>,
}

impl AppState {
    /// Create new application state
    pub fn new(auth: AuthServiceImpl, repos: Repositories, pool: DbPool, config: Config) -> Self {
        Self {
            auth: Arc::new(auth),
            repos,
            pool: SharedPool(Arc::new(pool)),
            config: Arc::new(config),
        }
    }

    /// Get request timeout from config
    pub fn request_timeout(&self) -> std::time::Duration {
        self.config.request_timeout
    }
}
