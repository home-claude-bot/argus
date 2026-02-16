//! Database connection pool

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use tracing::info;

use crate::error::DbResult;

/// Database connection pool type alias
pub type DbPool = PgPool;

/// Pool configuration options
#[derive(Debug, Clone)]
pub struct PoolOptions {
    /// Maximum number of connections
    pub max_connections: u32,
    /// Minimum number of connections to keep open
    pub min_connections: u32,
    /// Maximum time to wait for a connection
    pub acquire_timeout: Duration,
    /// Maximum lifetime of a connection
    pub max_lifetime: Duration,
    /// Time before an idle connection is closed
    pub idle_timeout: Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(30 * 60), // 30 minutes
            idle_timeout: Duration::from_secs(10 * 60), // 10 minutes
        }
    }
}

/// Create a new database connection pool with default options
pub async fn create_pool(database_url: &str) -> DbResult<DbPool> {
    create_pool_with_options(database_url, PoolOptions::default()).await
}

/// Create a new database connection pool with custom options
pub async fn create_pool_with_options(
    database_url: &str,
    options: PoolOptions,
) -> DbResult<DbPool> {
    info!(
        max_connections = options.max_connections,
        min_connections = options.min_connections,
        "Creating database connection pool"
    );

    let pool = PgPoolOptions::new()
        .max_connections(options.max_connections)
        .min_connections(options.min_connections)
        .acquire_timeout(options.acquire_timeout)
        .max_lifetime(options.max_lifetime)
        .idle_timeout(options.idle_timeout)
        .connect(database_url)
        .await
        .map_err(|e| crate::error::DbError::Connection(e.to_string()))?;

    info!("Database connection pool created successfully");

    Ok(pool)
}

/// Run database migrations
pub async fn run_migrations(pool: &DbPool) -> DbResult<()> {
    info!("Running database migrations");

    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| crate::error::DbError::Migration(e.to_string()))?;

    info!("Database migrations completed");

    Ok(())
}

/// Check database health
pub async fn health_check(pool: &DbPool) -> DbResult<()> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(|e| crate::error::DbError::Connection(e.to_string()))?;

    Ok(())
}
