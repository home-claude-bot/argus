//! Database row models
//!
//! These types map directly to database rows using SQLx's FromRow derive.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// User row from the database
#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub cognito_sub: Option<String>,
    pub tier: String,
    pub role: String,
    pub stripe_customer_id: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Session row from the database
#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Subscription row from the database
#[derive(Debug, Clone, FromRow)]
pub struct SubscriptionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tier: String,
    pub status: String,
    pub stripe_subscription_id: Option<String>,
    pub stripe_price_id: Option<String>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API key row from the database
#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub active: bool,
}

/// Usage row from the database
#[derive(Debug, Clone, FromRow)]
pub struct UsageRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub metric: String,
    pub count: i64,
    pub period: String,
    pub recorded_at: DateTime<Utc>,
}

/// Invoice row from the database
#[derive(Debug, Clone, FromRow)]
pub struct InvoiceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub stripe_invoice_id: Option<String>,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub description: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub invoice_pdf: Option<String>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub paid_at: Option<DateTime<Utc>>,
}

// Conversion implementations from Row types to argus-types domain types
impl UserRow {
    /// Convert to domain UserId
    pub fn user_id(&self) -> argus_types::UserId {
        argus_types::UserId(self.id)
    }
}

impl SessionRow {
    /// Convert to domain SessionId
    pub fn session_id(&self) -> argus_types::SessionId {
        argus_types::SessionId(self.id)
    }

    /// Convert to domain UserId
    pub fn user_id(&self) -> argus_types::UserId {
        argus_types::UserId(self.user_id)
    }
}

impl ApiKeyRow {
    /// Convert to domain ApiKeyId
    pub fn api_key_id(&self) -> argus_types::ApiKeyId {
        argus_types::ApiKeyId(self.id)
    }

    /// Convert to domain UserId
    pub fn user_id(&self) -> argus_types::UserId {
        argus_types::UserId(self.user_id)
    }
}
