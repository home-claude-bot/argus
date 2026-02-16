//! PostgreSQL user repository implementation

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::UserRow;
use crate::repo::{CreateUser, UserRepository};

/// PostgreSQL user repository
#[derive(Clone)]
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// Create a new user repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<UserRow>> {
        let user = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, cognito_sub, tier, role, stripe_customer_id,
                   email_verified, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> DbResult<Option<UserRow>> {
        let user = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, cognito_sub, tier, role, stripe_customer_id,
                   email_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    async fn find_by_cognito_sub(&self, sub: &str) -> DbResult<Option<UserRow>> {
        let user = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, cognito_sub, tier, role, stripe_customer_id,
                   email_verified, created_at, updated_at
            FROM users
            WHERE cognito_sub = $1
            "#,
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    async fn find_by_stripe_customer_id(&self, customer_id: &str) -> DbResult<Option<UserRow>> {
        let user = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, cognito_sub, tier, role, stripe_customer_id,
                   email_verified, created_at, updated_at
            FROM users
            WHERE stripe_customer_id = $1
            "#,
        )
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    async fn create(&self, user: CreateUser) -> DbResult<UserRow> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            INSERT INTO users (id, email, cognito_sub, tier, role)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email, cognito_sub, tier, role, stripe_customer_id,
                      email_verified, created_at, updated_at
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.cognito_sub)
        .bind(&user.tier)
        .bind(&user.role)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_tier(&self, id: Uuid, tier: &str) -> DbResult<()> {
        sqlx::query("UPDATE users SET tier = $1 WHERE id = $2")
            .bind(tier)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn update_stripe_customer_id(&self, id: Uuid, customer_id: &str) -> DbResult<()> {
        sqlx::query("UPDATE users SET stripe_customer_id = $1 WHERE id = $2")
            .bind(customer_id)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn update_email_verified(&self, id: Uuid, verified: bool) -> DbResult<()> {
        sqlx::query("UPDATE users SET email_verified = $1 WHERE id = $2")
            .bind(verified)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
