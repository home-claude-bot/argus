//! PostgreSQL subscription repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::SubscriptionRow;
use crate::repo::{CreateSubscription, SubscriptionRepository};

/// PostgreSQL subscription repository
#[derive(Clone)]
pub struct PgSubscriptionRepository {
    pool: PgPool,
}

impl PgSubscriptionRepository {
    /// Create a new subscription repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SubscriptionRepository for PgSubscriptionRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<SubscriptionRow>> {
        let sub = sqlx::query_as::<_, SubscriptionRow>(
            r#"
            SELECT id, user_id, tier, status, stripe_subscription_id, stripe_price_id,
                   current_period_start, current_period_end, cancel_at_period_end,
                   canceled_at, created_at, updated_at
            FROM subscriptions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(sub)
    }

    async fn find_active_by_user_id(&self, user_id: Uuid) -> DbResult<Option<SubscriptionRow>> {
        let sub = sqlx::query_as::<_, SubscriptionRow>(
            r#"
            SELECT id, user_id, tier, status, stripe_subscription_id, stripe_price_id,
                   current_period_start, current_period_end, cancel_at_period_end,
                   canceled_at, created_at, updated_at
            FROM subscriptions
            WHERE user_id = $1 AND status IN ('active', 'trialing')
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(sub)
    }

    async fn find_by_stripe_id(&self, stripe_id: &str) -> DbResult<Option<SubscriptionRow>> {
        let sub = sqlx::query_as::<_, SubscriptionRow>(
            r#"
            SELECT id, user_id, tier, status, stripe_subscription_id, stripe_price_id,
                   current_period_start, current_period_end, cancel_at_period_end,
                   canceled_at, created_at, updated_at
            FROM subscriptions
            WHERE stripe_subscription_id = $1
            "#,
        )
        .bind(stripe_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(sub)
    }

    async fn create(&self, sub: CreateSubscription) -> DbResult<SubscriptionRow> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            r#"
            INSERT INTO subscriptions (id, user_id, tier, stripe_subscription_id,
                                       stripe_price_id, current_period_start, current_period_end)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, user_id, tier, status, stripe_subscription_id, stripe_price_id,
                      current_period_start, current_period_end, cancel_at_period_end,
                      canceled_at, created_at, updated_at
            "#,
        )
        .bind(sub.id)
        .bind(sub.user_id)
        .bind(&sub.tier)
        .bind(&sub.stripe_subscription_id)
        .bind(&sub.stripe_price_id)
        .bind(sub.current_period_start)
        .bind(sub.current_period_end)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_status(&self, id: Uuid, status: &str) -> DbResult<()> {
        sqlx::query("UPDATE subscriptions SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn update_period(
        &self,
        id: Uuid,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DbResult<()> {
        sqlx::query(
            "UPDATE subscriptions SET current_period_start = $1, current_period_end = $2 WHERE id = $3",
        )
        .bind(period_start)
        .bind(period_end)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn set_cancel_at_period_end(&self, id: Uuid, cancel: bool) -> DbResult<()> {
        sqlx::query("UPDATE subscriptions SET cancel_at_period_end = $1 WHERE id = $2")
            .bind(cancel)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn cancel(&self, id: Uuid) -> DbResult<()> {
        sqlx::query(
            "UPDATE subscriptions SET status = 'canceled', canceled_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
