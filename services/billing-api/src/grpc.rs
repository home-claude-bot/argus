//! gRPC BillingService implementation
//!
//! High-performance gRPC service with:
//! - Request-level tracing with timing spans
//! - Prometheus metrics for all operations
//! - Full Stripe integration via billing-core
//! - Static plan data (zero allocation on list_plans)
//! - Batch usage recording for high throughput

use argus_billing_core::BillingService;
use argus_proto::billing_service::billing_service_server::BillingService as BillingServiceTrait;
use argus_proto::{
    BillingInterval, CancelSubscriptionRequest, CancelSubscriptionResponse, ChangePlanRequest,
    ChangePlanResponse, CreateCheckoutSessionRequest, CreateCheckoutSessionResponse,
    CreatePortalSessionRequest, CreatePortalSessionResponse, GetInvoiceRequest, GetInvoiceResponse,
    GetSubscriptionRequest, GetSubscriptionResponse, GetUpcomingInvoiceRequest,
    GetUpcomingInvoiceResponse, GetUsageSummaryRequest, GetUsageSummaryResponse,
    HandleWebhookRequest, HandleWebhookResponse, HealthCheckRequest, HealthCheckResponse,
    Invoice as ProtoInvoice, InvoiceStatus as ProtoInvoiceStatus, ListInvoicesRequest,
    ListInvoicesResponse, ListPaymentMethodsRequest, ListPaymentMethodsResponse, ListPlansRequest,
    ListPlansResponse, MetricUsage, Plan, RecordUsageRequest, RecordUsageResponse,
    ResumeSubscriptionRequest, ResumeSubscriptionResponse, SetDefaultPaymentMethodRequest,
    SetDefaultPaymentMethodResponse, StreamUsageRequest, Subscription as ProtoSubscription,
    SubscriptionStatus as ProtoSubscriptionStatus, Tier as ProtoTier, UsageEvent,
    UserId as ProtoUserId,
};
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};
use tracing::instrument;

// ============================================================================
// Input Validation (Security)
// ============================================================================

/// Maximum length for metric names (prevents cardinality explosion)
const MAX_METRIC_NAME_LEN: usize = 64;

/// Validate a metric name for safe use in metrics and database.
/// Security: Prevents metrics cardinality attacks and injection.
#[allow(clippy::result_large_err)]
fn validate_metric_name(name: &str) -> Result<(), Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("Metric name cannot be empty"));
    }
    if name.len() > MAX_METRIC_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "Metric name too long (max {MAX_METRIC_NAME_LEN} chars)"
        )));
    }
    // Allow: a-z, A-Z, 0-9, _, -, .
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(Status::invalid_argument(
            "Metric name contains invalid characters",
        ));
    }
    // Must start with letter or underscore
    if let Some(first) = name.chars().next() {
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(Status::invalid_argument(
                "Metric name must start with letter or underscore",
            ));
        }
    }
    Ok(())
}

// ============================================================================
// Plan Data Builder
// ============================================================================

/// Build plan data. Called rarely (not a hot path), so allocation is fine.
fn build_plans() -> Vec<Plan> {
    vec![
        Plan {
            id: "price_explorer".into(),
            name: "Explorer".into(),
            description: "Perfect for getting started".into(),
            tier: ProtoTier::Explorer as i32,
            price_cents: 0,
            currency: "usd".into(),
            interval: BillingInterval::Monthly as i32,
            features: vec!["1,000 API requests/month".into(), "Basic support".into()],
            rate_limit: Some(argus_proto::RateLimit {
                requests: 10,
                window_seconds: 60,
            }),
            active: true,
            display_order: 1,
        },
        Plan {
            id: "price_professional".into(),
            name: "Professional".into(),
            description: "For growing businesses".into(),
            tier: ProtoTier::Professional as i32,
            price_cents: 4900,
            currency: "usd".into(),
            interval: BillingInterval::Monthly as i32,
            features: vec![
                "50,000 API requests/month".into(),
                "Priority support".into(),
                "Advanced analytics".into(),
            ],
            rate_limit: Some(argus_proto::RateLimit {
                requests: 60,
                window_seconds: 60,
            }),
            active: true,
            display_order: 2,
        },
        Plan {
            id: "price_business".into(),
            name: "Business".into(),
            description: "For larger teams".into(),
            tier: ProtoTier::Business as i32,
            price_cents: 19900,
            currency: "usd".into(),
            interval: BillingInterval::Monthly as i32,
            features: vec![
                "500,000 API requests/month".into(),
                "24/7 support".into(),
                "Custom integrations".into(),
                "SLA guarantee".into(),
            ],
            rate_limit: Some(argus_proto::RateLimit {
                requests: 300,
                window_seconds: 60,
            }),
            active: true,
            display_order: 3,
        },
        Plan {
            id: "price_enterprise".into(),
            name: "Enterprise".into(),
            description: "Custom solutions".into(),
            tier: ProtoTier::Enterprise as i32,
            price_cents: 0, // Contact for pricing
            currency: "usd".into(),
            interval: BillingInterval::Monthly as i32,
            features: vec![
                "Unlimited API requests".into(),
                "Dedicated support".into(),
                "Custom contracts".into(),
                "On-premise options".into(),
            ],
            rate_limit: Some(argus_proto::RateLimit {
                requests: 1000,
                window_seconds: 60,
            }),
            active: true,
            display_order: 4,
        },
    ]
}

/// gRPC billing service implementation
pub struct GrpcBillingService {
    billing: Arc<BillingService>,
}

impl GrpcBillingService {
    pub fn new(billing: Arc<BillingService>) -> Self {
        Self { billing }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn tier_to_proto(tier: argus_types::Tier) -> i32 {
    match tier {
        argus_types::Tier::Explorer => ProtoTier::Explorer as i32,
        argus_types::Tier::Professional => ProtoTier::Professional as i32,
        argus_types::Tier::Business => ProtoTier::Business as i32,
        argus_types::Tier::Enterprise => ProtoTier::Enterprise as i32,
    }
}

fn subscription_status_to_proto(status: argus_types::SubscriptionStatus) -> i32 {
    match status {
        argus_types::SubscriptionStatus::Active => ProtoSubscriptionStatus::Active as i32,
        argus_types::SubscriptionStatus::PastDue => ProtoSubscriptionStatus::PastDue as i32,
        argus_types::SubscriptionStatus::Canceled => ProtoSubscriptionStatus::Canceled as i32,
        argus_types::SubscriptionStatus::Trialing => ProtoSubscriptionStatus::Trialing as i32,
    }
}

fn invoice_status_to_proto(status: argus_types::InvoiceStatus) -> i32 {
    match status {
        argus_types::InvoiceStatus::Draft => ProtoInvoiceStatus::Draft as i32,
        argus_types::InvoiceStatus::Open => ProtoInvoiceStatus::Open as i32,
        argus_types::InvoiceStatus::Paid => ProtoInvoiceStatus::Paid as i32,
        argus_types::InvoiceStatus::Void => ProtoInvoiceStatus::Void as i32,
        argus_types::InvoiceStatus::Uncollectible => ProtoInvoiceStatus::Uncollectible as i32,
    }
}

#[allow(clippy::result_large_err)]
fn proto_to_user_id(proto_id: Option<ProtoUserId>) -> Result<argus_types::UserId, Status> {
    proto_id
        .and_then(|id| argus_types::UserId::parse(&id.value).ok())
        .ok_or_else(|| Status::invalid_argument("Invalid user_id"))
}

fn subscription_to_proto(sub: argus_types::Subscription) -> ProtoSubscription {
    ProtoSubscription {
        id: sub.id.0.to_string(),
        user_id: Some(ProtoUserId {
            value: sub.user_id.0.to_string(),
        }),
        tier: tier_to_proto(sub.tier),
        status: subscription_status_to_proto(sub.status),
        current_period_start: Some(prost_types::Timestamp {
            seconds: sub.current_period_start.timestamp(),
            nanos: 0,
        }),
        current_period_end: Some(prost_types::Timestamp {
            seconds: sub.current_period_end.timestamp(),
            nanos: 0,
        }),
        cancel_at_period_end: false,
        created_at: Some(prost_types::Timestamp {
            seconds: sub.created_at.timestamp(),
            nanos: 0,
        }),
        trial_end: None,
        stripe_subscription_id: sub.stripe_subscription_id.unwrap_or_default(),
    }
}

/// Record gRPC request duration with result label
#[inline]
fn record_grpc_duration(method: &'static str, start: Instant, success: bool) {
    let result = if success { "ok" } else { "err" };
    metrics::histogram!(
        "grpc_request_duration_seconds",
        "method" => method,
        "result" => result
    )
    .record(start.elapsed().as_secs_f64());
}

fn invoice_to_proto(inv: argus_types::Invoice) -> ProtoInvoice {
    ProtoInvoice {
        id: inv.id.0.to_string(),
        user_id: Some(ProtoUserId {
            value: inv.user_id.0.to_string(),
        }),
        status: invoice_status_to_proto(inv.status),
        amount_cents: inv.amount_cents,
        amount_paid_cents: if inv.status == argus_types::InvoiceStatus::Paid {
            inv.amount_cents
        } else {
            0
        },
        currency: inv.currency,
        description: inv.description.unwrap_or_default(),
        period_start: Some(prost_types::Timestamp {
            seconds: inv.period_start.timestamp(),
            nanos: 0,
        }),
        period_end: Some(prost_types::Timestamp {
            seconds: inv.period_end.timestamp(),
            nanos: 0,
        }),
        created_at: Some(prost_types::Timestamp {
            seconds: inv.created_at.timestamp(),
            nanos: 0,
        }),
        paid_at: inv.paid_at.map(|t| prost_types::Timestamp {
            seconds: t.timestamp(),
            nanos: 0,
        }),
        hosted_invoice_url: inv.hosted_invoice_url.unwrap_or_default(),
        invoice_pdf_url: inv.invoice_pdf.unwrap_or_default(),
        line_items: vec![],
        stripe_invoice_id: inv.stripe_invoice_id.unwrap_or_default(),
    }
}

// ============================================================================
// BillingService Implementation
// ============================================================================

#[tonic::async_trait]
impl BillingServiceTrait for GrpcBillingService {
    // -------------------------------------------------------------------------
    // Subscription Management
    // -------------------------------------------------------------------------

    #[instrument(skip(self, request), fields(user_id))]
    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<GetSubscriptionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;
        tracing::Span::current().record("user_id", user_id.to_string());

        let subscription = self
            .billing
            .get_subscription(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        record_grpc_duration("get_subscription", start, true);

        Ok(Response::new(GetSubscriptionResponse {
            subscription: Some(subscription_to_proto(subscription)),
        }))
    }

    /// Returns plan data. Not a hot path - allocations are acceptable.
    async fn list_plans(
        &self,
        _request: Request<ListPlansRequest>,
    ) -> Result<Response<ListPlansResponse>, Status> {
        Ok(Response::new(ListPlansResponse {
            plans: build_plans(),
        }))
    }

    #[instrument(skip(self, request), fields(user_id, tier))]
    async fn create_checkout_session(
        &self,
        request: Request<CreateCheckoutSessionRequest>,
    ) -> Result<Response<CreateCheckoutSessionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        // Parse tier from price_id
        let tier = match req.price_id.as_str() {
            "price_explorer" => argus_types::Tier::Explorer,
            "price_professional" => argus_types::Tier::Professional,
            "price_business" => argus_types::Tier::Business,
            "price_enterprise" => argus_types::Tier::Enterprise,
            _ => return Err(Status::invalid_argument("Invalid price_id")),
        };

        let span = tracing::Span::current();
        span.record("user_id", user_id.to_string());
        span.record("tier", tier.to_string());

        // Use filter for cleaner empty string handling
        let success_url = (!req.success_url.is_empty()).then_some(req.success_url.as_str());
        let cancel_url = (!req.cancel_url.is_empty()).then_some(req.cancel_url.as_str());

        let session = self
            .billing
            .create_checkout(&user_id, tier, success_url, cancel_url)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::counter!("billing_checkouts_created_total", "tier" => tier.to_string())
            .increment(1);
        record_grpc_duration("create_checkout_session", start, true);

        Ok(Response::new(CreateCheckoutSessionResponse {
            session_id: session.session_id,
            url: session.url,
        }))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn create_portal_session(
        &self,
        request: Request<CreatePortalSessionRequest>,
    ) -> Result<Response<CreatePortalSessionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;
        tracing::Span::current().record("user_id", user_id.to_string());

        let return_url = (!req.return_url.is_empty()).then_some(req.return_url.as_str());

        let portal = self
            .billing
            .create_portal_session(&user_id, return_url)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        record_grpc_duration("create_portal_session", start, true);

        Ok(Response::new(CreatePortalSessionResponse {
            url: portal.url,
        }))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn cancel_subscription(
        &self,
        request: Request<CancelSubscriptionRequest>,
    ) -> Result<Response<CancelSubscriptionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;
        tracing::Span::current().record("user_id", user_id.to_string());

        self.billing
            .cancel_subscription(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Get updated subscription state
        let subscription = self
            .billing
            .get_subscription(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::counter!("billing_subscriptions_canceled_total").increment(1);
        record_grpc_duration("cancel_subscription", start, true);

        Ok(Response::new(CancelSubscriptionResponse {
            subscription: Some(subscription_to_proto(subscription)),
        }))
    }

    async fn resume_subscription(
        &self,
        _request: Request<ResumeSubscriptionRequest>,
    ) -> Result<Response<ResumeSubscriptionResponse>, Status> {
        // TODO: Implement resume subscription in billing-core
        Err(Status::unimplemented(
            "Resume subscription not yet implemented",
        ))
    }

    async fn change_plan(
        &self,
        _request: Request<ChangePlanRequest>,
    ) -> Result<Response<ChangePlanResponse>, Status> {
        // TODO: Implement plan changes in billing-core
        Err(Status::unimplemented("Change plan not yet implemented"))
    }

    // -------------------------------------------------------------------------
    // Payment Methods
    // -------------------------------------------------------------------------

    async fn list_payment_methods(
        &self,
        _request: Request<ListPaymentMethodsRequest>,
    ) -> Result<Response<ListPaymentMethodsResponse>, Status> {
        // Payment methods are managed through the Stripe portal
        Err(Status::unimplemented(
            "Use create_portal_session to manage payment methods",
        ))
    }

    async fn set_default_payment_method(
        &self,
        _request: Request<SetDefaultPaymentMethodRequest>,
    ) -> Result<Response<SetDefaultPaymentMethodResponse>, Status> {
        Err(Status::unimplemented(
            "Use create_portal_session to manage payment methods",
        ))
    }

    async fn delete_payment_method(
        &self,
        _request: Request<argus_proto::DeletePaymentMethodRequest>,
    ) -> Result<Response<argus_proto::DeletePaymentMethodResponse>, Status> {
        Err(Status::unimplemented(
            "Use create_portal_session to manage payment methods",
        ))
    }

    // -------------------------------------------------------------------------
    // Invoices
    // -------------------------------------------------------------------------

    #[instrument(skip(self, request), fields(user_id, limit))]
    async fn list_invoices(
        &self,
        request: Request<ListInvoicesRequest>,
    ) -> Result<Response<ListInvoicesResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let limit = req
            .pagination
            .as_ref()
            .map_or(10, |p| p.page_size as i64)
            .min(100);

        let span = tracing::Span::current();
        span.record("user_id", user_id.to_string());
        span.record("limit", limit);

        let invoices = self
            .billing
            .get_invoices(&user_id, limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        record_grpc_duration("list_invoices", start, true);

        Ok(Response::new(ListInvoicesResponse {
            invoices: invoices.into_iter().map(invoice_to_proto).collect(),
            pagination: None,
        }))
    }

    #[instrument(skip(self, request), fields(invoice_id))]
    async fn get_invoice(
        &self,
        request: Request<GetInvoiceRequest>,
    ) -> Result<Response<GetInvoiceResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        tracing::Span::current().record("invoice_id", &req.invoice_id);

        let invoice_id = uuid::Uuid::parse_str(&req.invoice_id)
            .map_err(|_| Status::invalid_argument("Invalid invoice_id"))?;

        let invoice = self
            .billing
            .get_invoice(&argus_types::InvoiceId(invoice_id))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        record_grpc_duration("get_invoice", start, true);

        Ok(Response::new(GetInvoiceResponse {
            invoice: Some(invoice_to_proto(invoice)),
        }))
    }

    async fn get_upcoming_invoice(
        &self,
        _request: Request<GetUpcomingInvoiceRequest>,
    ) -> Result<Response<GetUpcomingInvoiceResponse>, Status> {
        // TODO: Implement upcoming invoice preview via Stripe API
        Err(Status::unimplemented(
            "Upcoming invoice preview not yet implemented",
        ))
    }

    // -------------------------------------------------------------------------
    // Usage Tracking
    // -------------------------------------------------------------------------

    /// Record usage - hot path, optimized for minimal latency.
    /// Does NOT fetch subscription for period_limit (use get_usage_summary for that).
    #[instrument(skip(self, request), fields(user_id, metric, count))]
    async fn record_usage(
        &self,
        request: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;
        let usage_count = req.count;
        let metric = req.metric;

        // Input validation (security: prevent injection and cardinality attacks)
        validate_metric_name(&metric)?;

        if usage_count == 0 {
            return Err(Status::invalid_argument("Count must be positive"));
        }

        let span = tracing::Span::current();
        span.record("user_id", user_id.to_string());
        span.record("metric", &metric);
        span.record("count", usage_count);

        // Safe: we check for 0 above, typical usage counts are well under i64::MAX
        #[allow(clippy::cast_possible_wrap)]
        let count_i64 = usage_count as i64;

        let result = self
            .billing
            .record_usage(&user_id, &metric, count_i64)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::counter!("billing_usage_recorded_total", "metric" => metric)
            .increment(usage_count);
        record_grpc_duration("record_usage", start, true);

        // period_limit = 0 means "unknown" - caller should use get_usage_summary if needed
        // This avoids an extra DB call on every usage record (hot path optimization)
        Ok(Response::new(RecordUsageResponse {
            success: result.success,
            current_period_usage: result.total_usage as u64,
            period_limit: 0,
        }))
    }

    #[instrument(skip(self, request), fields(user_id, period))]
    async fn get_usage_summary(
        &self,
        request: Request<GetUsageSummaryRequest>,
    ) -> Result<Response<GetUsageSummaryResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let span = tracing::Span::current();
        span.record("user_id", user_id.to_string());
        span.record("period", &req.period);

        let period = (!req.period.is_empty()).then_some(req.period.as_str());

        let summary = self
            .billing
            .get_usage_summary(&user_id, period)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let limit = summary.limit.unwrap_or(0);
        let usage_percentage = if limit > 0 {
            (summary.total_requests as f64 / limit as f64) * 100.0
        } else {
            0.0
        };

        record_grpc_duration("get_usage_summary", start, true);

        Ok(Response::new(GetUsageSummaryResponse {
            period: summary.period,
            metrics: summary
                .by_endpoint
                .into_iter()
                .map(|e| MetricUsage {
                    metric: e.endpoint,
                    count: e.count,
                    daily: vec![],
                })
                .collect(),
            total_requests: summary.total_requests,
            limit,
            usage_percentage,
        }))
    }

    type StreamUsageStream = Pin<Box<dyn Stream<Item = Result<UsageEvent, Status>> + Send>>;

    async fn stream_usage(
        &self,
        _request: Request<StreamUsageRequest>,
    ) -> Result<Response<Self::StreamUsageStream>, Status> {
        // TODO: Implement real-time usage streaming
        Err(Status::unimplemented("Usage streaming not yet implemented"))
    }

    // -------------------------------------------------------------------------
    // Webhooks
    // -------------------------------------------------------------------------

    #[instrument(skip(self, request))]
    async fn handle_webhook(
        &self,
        request: Request<HandleWebhookRequest>,
    ) -> Result<Response<HandleWebhookResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        match self
            .billing
            .process_webhook(&req.payload, &req.signature)
            .await
        {
            Ok(()) => {
                metrics::counter!("billing_webhooks_processed_total", "status" => "success")
                    .increment(1);
                record_grpc_duration("handle_webhook", start, true);
                Ok(Response::new(HandleWebhookResponse {
                    success: true,
                    event_type: String::new(),
                }))
            }
            Err(e) => {
                tracing::error!(error = ?e, "Webhook processing failed");
                metrics::counter!("billing_webhooks_processed_total", "status" => "error")
                    .increment(1);
                record_grpc_duration("handle_webhook", start, false);

                let err_str = e.to_string();
                if err_str.contains("Signature")
                    || err_str.contains("timestamp")
                    || err_str.contains("parse")
                {
                    Err(Status::invalid_argument(err_str))
                } else {
                    Err(Status::internal(err_str))
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Health
    // -------------------------------------------------------------------------

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: argus_proto::health_check_response::ServingStatus::Serving as i32,
        }))
    }
}
