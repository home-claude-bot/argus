//! Repository traits
//!
//! Define async repository interfaces for database operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::*;

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by ID
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<UserRow>>;

    /// Find a user by email
    async fn find_by_email(&self, email: &str) -> DbResult<Option<UserRow>>;

    /// Find a user by Cognito sub
    async fn find_by_cognito_sub(&self, sub: &str) -> DbResult<Option<UserRow>>;

    /// Find a user by Stripe customer ID
    async fn find_by_stripe_customer_id(&self, customer_id: &str) -> DbResult<Option<UserRow>>;

    /// Create a new user
    async fn create(&self, user: CreateUser) -> DbResult<UserRow>;

    /// Update user tier
    async fn update_tier(&self, id: Uuid, tier: &str) -> DbResult<()>;

    /// Update user's Stripe customer ID
    async fn update_stripe_customer_id(&self, id: Uuid, customer_id: &str) -> DbResult<()>;

    /// Update email verified status
    async fn update_email_verified(&self, id: Uuid, verified: bool) -> DbResult<()>;

    /// Delete a user
    async fn delete(&self, id: Uuid) -> DbResult<()>;
}

/// Create user input
#[derive(Debug, Clone)]
pub struct CreateUser {
    pub id: Uuid,
    pub email: String,
    pub cognito_sub: Option<String>,
    pub tier: String,
    pub role: String,
}

/// Session repository trait
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Find a session by ID
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<SessionRow>>;

    /// Find a session by token hash
    async fn find_by_token_hash(&self, token_hash: &str) -> DbResult<Option<SessionRow>>;

    /// Find all sessions for a user
    async fn find_by_user_id(&self, user_id: Uuid) -> DbResult<Vec<SessionRow>>;

    /// Create a new session
    async fn create(&self, session: CreateSession) -> DbResult<SessionRow>;

    /// Update last active timestamp
    async fn update_last_active(&self, id: Uuid) -> DbResult<()>;

    /// Revoke a session
    async fn revoke(&self, id: Uuid) -> DbResult<()>;

    /// Revoke all sessions for a user
    async fn revoke_all_for_user(&self, user_id: Uuid) -> DbResult<u64>;

    /// Delete expired sessions
    async fn delete_expired(&self) -> DbResult<u64>;
}

/// Create session input
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Subscription repository trait
#[async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Find a subscription by ID
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<SubscriptionRow>>;

    /// Find active subscription for a user
    async fn find_active_by_user_id(&self, user_id: Uuid) -> DbResult<Option<SubscriptionRow>>;

    /// Find subscription by Stripe subscription ID
    async fn find_by_stripe_id(&self, stripe_id: &str) -> DbResult<Option<SubscriptionRow>>;

    /// Create a new subscription
    async fn create(&self, sub: CreateSubscription) -> DbResult<SubscriptionRow>;

    /// Update subscription status
    async fn update_status(&self, id: Uuid, status: &str) -> DbResult<()>;

    /// Update subscription period
    async fn update_period(
        &self,
        id: Uuid,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DbResult<()>;

    /// Mark subscription for cancellation at period end
    async fn set_cancel_at_period_end(&self, id: Uuid, cancel: bool) -> DbResult<()>;

    /// Cancel subscription immediately
    async fn cancel(&self, id: Uuid) -> DbResult<()>;
}

/// Create subscription input
#[derive(Debug, Clone)]
pub struct CreateSubscription {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tier: String,
    pub stripe_subscription_id: Option<String>,
    pub stripe_price_id: Option<String>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
}

/// API key repository trait
#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    /// Find an API key by ID
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<ApiKeyRow>>;

    /// Find an API key by hash
    async fn find_by_key_hash(&self, key_hash: &str) -> DbResult<Option<ApiKeyRow>>;

    /// Find an API key by prefix
    async fn find_by_prefix(&self, prefix: &str) -> DbResult<Option<ApiKeyRow>>;

    /// Find all API keys for a user
    async fn find_by_user_id(&self, user_id: Uuid) -> DbResult<Vec<ApiKeyRow>>;

    /// Create a new API key
    async fn create(&self, key: CreateApiKey) -> DbResult<ApiKeyRow>;

    /// Update last used timestamp
    async fn update_last_used(&self, id: Uuid) -> DbResult<()>;

    /// Deactivate an API key
    async fn deactivate(&self, id: Uuid) -> DbResult<()>;

    /// Delete an API key
    async fn delete(&self, id: Uuid) -> DbResult<()>;
}

/// Create API key input
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub prefix: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Usage repository trait
#[async_trait]
pub trait UsageRepository: Send + Sync {
    /// Get usage for a user and period
    async fn get_usage(&self, user_id: Uuid, period: &str) -> DbResult<Vec<UsageRow>>;

    /// Get usage for a specific metric
    async fn get_metric_usage(
        &self,
        user_id: Uuid,
        metric: &str,
        period: &str,
    ) -> DbResult<Option<UsageRow>>;

    /// Increment usage count (upsert)
    async fn increment(
        &self,
        user_id: Uuid,
        metric: &str,
        period: &str,
        count: i64,
    ) -> DbResult<()>;

    /// Get total usage across all metrics for a period
    async fn get_total_for_period(&self, user_id: Uuid, period: &str) -> DbResult<i64>;
}

/// Invoice repository trait
#[async_trait]
pub trait InvoiceRepository: Send + Sync {
    /// Find an invoice by ID
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<InvoiceRow>>;

    /// Find an invoice by Stripe invoice ID
    async fn find_by_stripe_id(&self, stripe_id: &str) -> DbResult<Option<InvoiceRow>>;

    /// Find all invoices for a user
    async fn find_by_user_id(&self, user_id: Uuid, limit: i64) -> DbResult<Vec<InvoiceRow>>;

    /// Create a new invoice
    async fn create(&self, invoice: CreateInvoice) -> DbResult<InvoiceRow>;

    /// Update invoice status
    async fn update_status(&self, id: Uuid, status: &str) -> DbResult<()>;

    /// Mark invoice as paid
    async fn mark_paid(&self, id: Uuid, paid_at: DateTime<Utc>) -> DbResult<()>;
}

/// Create invoice input
#[derive(Debug, Clone)]
pub struct CreateInvoice {
    pub id: Uuid,
    pub user_id: Uuid,
    pub stripe_invoice_id: Option<String>,
    pub amount_cents: i64,
    pub currency: String,
    pub description: Option<String>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}
