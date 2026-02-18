//! Application state for the Billing API service.

use argus_billing_core::BillingService;
use argus_db::pg::Repositories;
use argus_db::DbPool;
use std::sync::Arc;

use crate::config::Config;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Billing service (subscriptions, usage, invoices, webhooks)
    pub billing: Arc<BillingService>,
    /// Database repositories (for direct access if needed)
    #[allow(dead_code)]
    pub repos: Repositories,
    /// Database pool (for direct queries if needed)
    pub pool: DbPool,
    /// Configuration
    pub config: Arc<Config>,
}

impl AppState {
    /// Create new application state
    pub fn new(billing: BillingService, repos: Repositories, pool: DbPool, config: Config) -> Self {
        Self {
            billing: Arc::new(billing),
            repos,
            pool,
            config: Arc::new(config),
        }
    }

    /// Get request timeout from config
    pub fn request_timeout(&self) -> std::time::Duration {
        self.config.request_timeout
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
