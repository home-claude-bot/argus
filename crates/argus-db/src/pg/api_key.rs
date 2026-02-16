//! PostgreSQL API key repository implementation

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::ApiKeyRow;
use crate::repo::{ApiKeyRepository, CreateApiKey};

/// PostgreSQL API key repository
#[derive(Clone)]
pub struct PgApiKeyRepository {
    pool: PgPool,
}

impl PgApiKeyRepository {
    /// Create a new API key repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiKeyRepository for PgApiKeyRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<ApiKeyRow>> {
        let key = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, user_id, prefix, key_hash, name, scopes,
                   created_at, expires_at, last_used_at, active
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    async fn find_by_key_hash(&self, key_hash: &str) -> DbResult<Option<ApiKeyRow>> {
        let key = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, user_id, prefix, key_hash, name, scopes,
                   created_at, expires_at, last_used_at, active
            FROM api_keys
            WHERE key_hash = $1 AND active = TRUE
                  AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    async fn find_by_prefix(&self, prefix: &str) -> DbResult<Option<ApiKeyRow>> {
        let key = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, user_id, prefix, key_hash, name, scopes,
                   created_at, expires_at, last_used_at, active
            FROM api_keys
            WHERE prefix = $1
            "#,
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> DbResult<Vec<ApiKeyRow>> {
        let keys = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, user_id, prefix, key_hash, name, scopes,
                   created_at, expires_at, last_used_at, active
            FROM api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    async fn create(&self, key: CreateApiKey) -> DbResult<ApiKeyRow> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            INSERT INTO api_keys (id, user_id, prefix, key_hash, name, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, user_id, prefix, key_hash, name, scopes,
                      created_at, expires_at, last_used_at, active
            "#,
        )
        .bind(key.id)
        .bind(key.user_id)
        .bind(&key.prefix)
        .bind(&key.key_hash)
        .bind(&key.name)
        .bind(&key.scopes)
        .bind(key.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_last_used(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn deactivate(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("UPDATE api_keys SET active = FALSE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
