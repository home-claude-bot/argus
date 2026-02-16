//! PostgreSQL usage repository implementation

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::UsageRow;
use crate::repo::UsageRepository;

/// PostgreSQL usage repository
#[derive(Clone)]
pub struct PgUsageRepository {
    pool: PgPool,
}

impl PgUsageRepository {
    /// Create a new usage repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UsageRepository for PgUsageRepository {
    async fn get_usage(&self, user_id: Uuid, period: &str) -> DbResult<Vec<UsageRow>> {
        let usage = sqlx::query_as::<_, UsageRow>(
            r#"
            SELECT id, user_id, metric, count, period, recorded_at
            FROM usage
            WHERE user_id = $1 AND period = $2
            ORDER BY metric
            "#,
        )
        .bind(user_id)
        .bind(period)
        .fetch_all(&self.pool)
        .await?;

        Ok(usage)
    }

    async fn get_metric_usage(
        &self,
        user_id: Uuid,
        metric: &str,
        period: &str,
    ) -> DbResult<Option<UsageRow>> {
        let usage = sqlx::query_as::<_, UsageRow>(
            r#"
            SELECT id, user_id, metric, count, period, recorded_at
            FROM usage
            WHERE user_id = $1 AND metric = $2 AND period = $3
            "#,
        )
        .bind(user_id)
        .bind(metric)
        .bind(period)
        .fetch_optional(&self.pool)
        .await?;

        Ok(usage)
    }

    async fn increment(
        &self,
        user_id: Uuid,
        metric: &str,
        period: &str,
        count: i64,
    ) -> DbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO usage (user_id, metric, period, count)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, metric, period)
            DO UPDATE SET count = usage.count + EXCLUDED.count, recorded_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(metric)
        .bind(period)
        .bind(count)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_total_for_period(&self, user_id: Uuid, period: &str) -> DbResult<i64> {
        let result: (Option<i64>,) = sqlx::query_as(
            r#"
            SELECT COALESCE(SUM(count), 0)
            FROM usage
            WHERE user_id = $1 AND period = $2
            "#,
        )
        .bind(user_id)
        .bind(period)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.0.unwrap_or(0))
    }
}
