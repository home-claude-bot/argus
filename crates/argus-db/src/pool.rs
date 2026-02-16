//! Database connection pool

use sqlx::PgPool;

/// Database connection pool type alias
pub type DbPool = PgPool;

/// Create a new database connection pool
pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    PgPool::connect(database_url).await
}
