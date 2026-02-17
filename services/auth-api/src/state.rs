//! Application state

use std::sync::Arc;

use argus_auth_core::AuthService;
use argus_db::pg::{PgSessionRepository, PgUserRepository, Repositories};
use argus_db::DbPool;

use crate::config::Config;

/// Type alias for the auth service with concrete repository types
pub type AuthServiceImpl = AuthService<PgUserRepository, PgSessionRepository>;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Auth service for token validation and session management
    pub auth: Arc<AuthServiceImpl>,
    /// Database repositories
    pub repos: Repositories,
    /// Database connection pool
    #[allow(dead_code)]
    pub pool: DbPool,
    /// Application configuration
    #[allow(dead_code)]
    pub config: Arc<Config>,
}

impl AppState {
    /// Create new application state
    pub fn new(auth: AuthServiceImpl, repos: Repositories, pool: DbPool, config: Config) -> Self {
        Self {
            auth: Arc::new(auth),
            repos,
            pool,
            config: Arc::new(config),
        }
    }
}
