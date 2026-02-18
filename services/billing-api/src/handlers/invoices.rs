//! Invoice handlers

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::instrument;
use uuid::Uuid;

use argus_types::{InvoiceId, UserId};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Record HTTP operation duration with result label
#[inline]
fn record_op_duration(operation: &'static str, start: Instant, success: bool) {
    let result = if success { "ok" } else { "err" };
    metrics::histogram!(
        "billing_operation_duration_seconds",
        "operation" => operation,
        "result" => result
    )
    .record(start.elapsed().as_secs_f64());
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListInvoicesRequest {
    pub user_id: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct InvoiceResponse {
    pub id: String,
    pub user_id: String,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub description: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub invoice_pdf: Option<String>,
    pub period_start: String,
    pub period_end: String,
    pub created_at: String,
    pub paid_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListInvoicesResponse {
    pub invoices: Vec<InvoiceResponse>,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/v1/billing/invoices
#[instrument(skip(state, req), fields(user_id = %req.user_id, limit))]
pub async fn list_invoices(
    State(state): State<AppState>,
    Json(req): Json<ListInvoicesRequest>,
) -> ApiResult<Json<ListInvoicesResponse>> {
    let start = Instant::now();

    let user_id =
        UserId::parse(&req.user_id).map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;

    let limit = req.limit.unwrap_or(10).min(100);
    tracing::Span::current().record("limit", limit);

    let invoices = state.billing.get_invoices(&user_id, limit).await?;

    record_op_duration("list_invoices", start, true);

    Ok(Json(ListInvoicesResponse {
        invoices: invoices.into_iter().map(invoice_to_response).collect(),
    }))
}

/// GET /api/v1/billing/invoices/:id
#[instrument(skip(state), fields(invoice_id = %invoice_id))]
pub async fn get_invoice(
    State(state): State<AppState>,
    Path(invoice_id): Path<Uuid>,
) -> ApiResult<Json<InvoiceResponse>> {
    let start = Instant::now();

    let invoice_id = InvoiceId(invoice_id);
    let invoice = state.billing.get_invoice(&invoice_id).await?;

    record_op_duration("get_invoice", start, true);

    Ok(Json(invoice_to_response(invoice)))
}

fn invoice_to_response(inv: argus_types::Invoice) -> InvoiceResponse {
    InvoiceResponse {
        id: inv.id.0.to_string(),
        user_id: inv.user_id.0.to_string(),
        status: format!("{:?}", inv.status).to_lowercase(),
        amount_cents: inv.amount_cents,
        currency: inv.currency,
        description: inv.description,
        hosted_invoice_url: inv.hosted_invoice_url,
        invoice_pdf: inv.invoice_pdf,
        period_start: inv.period_start.to_rfc3339(),
        period_end: inv.period_end.to_rfc3339(),
        created_at: inv.created_at.to_rfc3339(),
        paid_at: inv.paid_at.map(|t| t.to_rfc3339()),
    }
}
