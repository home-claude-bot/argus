//! PostgreSQL session repository implementation

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::SessionRow;
use crate::repo::{CreateSession, SessionRepository};

/// PostgreSQL session repository
#[derive(Clone)]
pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    /// Create a new session repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<SessionRow>> {
        let session = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, token_hash, ip_address, user_agent,
                   created_at, expires_at, last_active_at, revoked
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> DbResult<Option<SessionRow>> {
        let session = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, token_hash, ip_address, user_agent,
                   created_at, expires_at, last_active_at, revoked
            FROM sessions
            WHERE token_hash = $1 AND NOT revoked AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> DbResult<Vec<SessionRow>> {
        let sessions = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, token_hash, ip_address, user_agent,
                   created_at, expires_at, last_active_at, revoked
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    async fn create(&self, session: CreateSession) -> DbResult<SessionRow> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, token_hash, ip_address, user_agent,
                      created_at, expires_at, last_active_at, revoked
            "#,
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.token_hash)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(session.expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_last_active(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("UPDATE sessions SET last_active_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn revoke(&self, id: Uuid) -> DbResult<()> {
        sqlx::query("UPDATE sessions SET revoked = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> DbResult<u64> {
        let result = sqlx::query("UPDATE sessions SET revoked = TRUE WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn delete_expired(&self) -> DbResult<u64> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW() OR revoked = TRUE")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
