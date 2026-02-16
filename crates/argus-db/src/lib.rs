//! Argus DB - Database abstractions
//!
//! SQLx-based database layer for Argus services.
//!
//! # Example
//!
//! ```rust,ignore
//! use argus_db::{create_pool, Repositories};
//!
//! let pool = create_pool("postgres://localhost/argus").await?;
//! let repos = Repositories::new(pool);
//!
//! // Use repositories
//! let user = repos.users.find_by_email("user@example.com").await?;
//! ```

pub mod error;
pub mod models;
pub mod pg;
pub mod pool;
pub mod repo;

pub use error::{DbError, DbResult};
pub use models::*;
pub use pg::Repositories;
pub use pool::{create_pool, create_pool_with_options, DbPool, PoolOptions};
pub use repo::*;
