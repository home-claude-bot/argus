//! PostgreSQL repository implementations

mod api_key;
mod invoice;
mod session;
mod subscription;
mod usage;
mod user;

pub use api_key::PgApiKeyRepository;
pub use invoice::PgInvoiceRepository;
pub use session::PgSessionRepository;
pub use subscription::PgSubscriptionRepository;
pub use usage::PgUsageRepository;
pub use user::PgUserRepository;

use crate::DbPool;

/// All repositories bundled together
#[derive(Clone)]
pub struct Repositories {
    pub users: PgUserRepository,
    pub sessions: PgSessionRepository,
    pub subscriptions: PgSubscriptionRepository,
    pub api_keys: PgApiKeyRepository,
    pub usage: PgUsageRepository,
    pub invoices: PgInvoiceRepository,
}

impl Repositories {
    /// Create all repositories from a database pool
    pub fn new(pool: DbPool) -> Self {
        Self {
            users: PgUserRepository::new(pool.clone()),
            sessions: PgSessionRepository::new(pool.clone()),
            subscriptions: PgSubscriptionRepository::new(pool.clone()),
            api_keys: PgApiKeyRepository::new(pool.clone()),
            usage: PgUsageRepository::new(pool.clone()),
            invoices: PgInvoiceRepository::new(pool),
        }
    }
}
