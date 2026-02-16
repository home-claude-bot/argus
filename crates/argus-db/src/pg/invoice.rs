//! PostgreSQL invoice repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::DbResult;
use crate::models::InvoiceRow;
use crate::repo::{CreateInvoice, InvoiceRepository};

/// PostgreSQL invoice repository
#[derive(Clone)]
pub struct PgInvoiceRepository {
    pool: PgPool,
}

impl PgInvoiceRepository {
    /// Create a new invoice repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvoiceRepository for PgInvoiceRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<InvoiceRow>> {
        let invoice = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, user_id, stripe_invoice_id, status, amount_cents, currency,
                   description, hosted_invoice_url, invoice_pdf, period_start,
                   period_end, created_at, paid_at
            FROM invoices
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(invoice)
    }

    async fn find_by_stripe_id(&self, stripe_id: &str) -> DbResult<Option<InvoiceRow>> {
        let invoice = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, user_id, stripe_invoice_id, status, amount_cents, currency,
                   description, hosted_invoice_url, invoice_pdf, period_start,
                   period_end, created_at, paid_at
            FROM invoices
            WHERE stripe_invoice_id = $1
            "#,
        )
        .bind(stripe_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(invoice)
    }

    async fn find_by_user_id(&self, user_id: Uuid, limit: i64) -> DbResult<Vec<InvoiceRow>> {
        let invoices = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, user_id, stripe_invoice_id, status, amount_cents, currency,
                   description, hosted_invoice_url, invoice_pdf, period_start,
                   period_end, created_at, paid_at
            FROM invoices
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(invoices)
    }

    async fn create(&self, invoice: CreateInvoice) -> DbResult<InvoiceRow> {
        let row = sqlx::query_as::<_, InvoiceRow>(
            r#"
            INSERT INTO invoices (id, user_id, stripe_invoice_id, amount_cents,
                                  currency, description, period_start, period_end)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, user_id, stripe_invoice_id, status, amount_cents, currency,
                      description, hosted_invoice_url, invoice_pdf, period_start,
                      period_end, created_at, paid_at
            "#,
        )
        .bind(invoice.id)
        .bind(invoice.user_id)
        .bind(&invoice.stripe_invoice_id)
        .bind(invoice.amount_cents)
        .bind(&invoice.currency)
        .bind(&invoice.description)
        .bind(invoice.period_start)
        .bind(invoice.period_end)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_status(&self, id: Uuid, status: &str) -> DbResult<()> {
        sqlx::query("UPDATE invoices SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn mark_paid(&self, id: Uuid, paid_at: DateTime<Utc>) -> DbResult<()> {
        sqlx::query("UPDATE invoices SET status = 'paid', paid_at = $1 WHERE id = $2")
            .bind(paid_at)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
