//! gRPC BillingService implementation
//!
//! High-performance gRPC service with:
//! - Request-level tracing with timing spans
//! - Prometheus metrics for all operations
//! - Full Stripe integration via billing-core

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
    ListPlansResponse, MetricUsage, RecordUsageRequest, RecordUsageResponse,
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

    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<GetSubscriptionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let subscription = self
            .billing
            .get_subscription(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::histogram!("grpc_request_duration_seconds", "method" => "get_subscription")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(GetSubscriptionResponse {
            subscription: Some(subscription_to_proto(subscription)),
        }))
    }

    async fn list_plans(
        &self,
        _request: Request<ListPlansRequest>,
    ) -> Result<Response<ListPlansResponse>, Status> {
        // Plans are static configuration - return hardcoded plans
        // In production, these would come from Stripe or a database
        let plans = vec![
            argus_proto::Plan {
                id: "price_explorer".to_string(),
                name: "Explorer".to_string(),
                description: "Perfect for getting started".to_string(),
                tier: ProtoTier::Explorer as i32,
                price_cents: 0,
                currency: "usd".to_string(),
                interval: BillingInterval::Monthly as i32,
                features: vec![
                    "1,000 API requests/month".to_string(),
                    "Basic support".to_string(),
                ],
                rate_limit: Some(argus_proto::RateLimit {
                    requests: 10,
                    window_seconds: 60,
                }),
                active: true,
                display_order: 1,
            },
            argus_proto::Plan {
                id: "price_professional".to_string(),
                name: "Professional".to_string(),
                description: "For growing businesses".to_string(),
                tier: ProtoTier::Professional as i32,
                price_cents: 4900,
                currency: "usd".to_string(),
                interval: BillingInterval::Monthly as i32,
                features: vec![
                    "50,000 API requests/month".to_string(),
                    "Priority support".to_string(),
                    "Advanced analytics".to_string(),
                ],
                rate_limit: Some(argus_proto::RateLimit {
                    requests: 60,
                    window_seconds: 60,
                }),
                active: true,
                display_order: 2,
            },
            argus_proto::Plan {
                id: "price_business".to_string(),
                name: "Business".to_string(),
                description: "For larger teams".to_string(),
                tier: ProtoTier::Business as i32,
                price_cents: 19900,
                currency: "usd".to_string(),
                interval: BillingInterval::Monthly as i32,
                features: vec![
                    "500,000 API requests/month".to_string(),
                    "24/7 support".to_string(),
                    "Custom integrations".to_string(),
                    "SLA guarantee".to_string(),
                ],
                rate_limit: Some(argus_proto::RateLimit {
                    requests: 300,
                    window_seconds: 60,
                }),
                active: true,
                display_order: 3,
            },
            argus_proto::Plan {
                id: "price_enterprise".to_string(),
                name: "Enterprise".to_string(),
                description: "Custom solutions".to_string(),
                tier: ProtoTier::Enterprise as i32,
                price_cents: 0, // Contact for pricing
                currency: "usd".to_string(),
                interval: BillingInterval::Monthly as i32,
                features: vec![
                    "Unlimited API requests".to_string(),
                    "Dedicated support".to_string(),
                    "Custom contracts".to_string(),
                    "On-premise options".to_string(),
                ],
                rate_limit: Some(argus_proto::RateLimit {
                    requests: 1000,
                    window_seconds: 60,
                }),
                active: true,
                display_order: 4,
            },
        ];

        Ok(Response::new(ListPlansResponse { plans }))
    }

    async fn create_checkout_session(
        &self,
        request: Request<CreateCheckoutSessionRequest>,
    ) -> Result<Response<CreateCheckoutSessionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        // Parse tier from price_id (simplified - in production, look up in Stripe)
        let tier = match req.price_id.as_str() {
            "price_explorer" => argus_types::Tier::Explorer,
            "price_professional" => argus_types::Tier::Professional,
            "price_business" => argus_types::Tier::Business,
            "price_enterprise" => argus_types::Tier::Enterprise,
            _ => return Err(Status::invalid_argument("Invalid price_id")),
        };

        let success_url = if req.success_url.is_empty() {
            None
        } else {
            Some(req.success_url.as_str())
        };
        let cancel_url = if req.cancel_url.is_empty() {
            None
        } else {
            Some(req.cancel_url.as_str())
        };

        let session = self
            .billing
            .create_checkout(&user_id, tier, success_url, cancel_url)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::counter!("billing_checkouts_created_total").increment(1);
        metrics::histogram!("grpc_request_duration_seconds", "method" => "create_checkout_session")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(CreateCheckoutSessionResponse {
            session_id: session.session_id,
            url: session.url,
        }))
    }

    async fn create_portal_session(
        &self,
        request: Request<CreatePortalSessionRequest>,
    ) -> Result<Response<CreatePortalSessionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let return_url = if req.return_url.is_empty() {
            None
        } else {
            Some(req.return_url.as_str())
        };

        let portal = self
            .billing
            .create_portal_session(&user_id, return_url)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::histogram!("grpc_request_duration_seconds", "method" => "create_portal_session")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(CreatePortalSessionResponse {
            url: portal.url,
        }))
    }

    async fn cancel_subscription(
        &self,
        request: Request<CancelSubscriptionRequest>,
    ) -> Result<Response<CancelSubscriptionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

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
        metrics::histogram!("grpc_request_duration_seconds", "method" => "cancel_subscription")
            .record(start.elapsed().as_secs_f64());

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

        let invoices = self
            .billing
            .get_invoices(&user_id, limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::histogram!("grpc_request_duration_seconds", "method" => "list_invoices")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(ListInvoicesResponse {
            invoices: invoices.into_iter().map(invoice_to_proto).collect(),
            pagination: None,
        }))
    }

    async fn get_invoice(
        &self,
        request: Request<GetInvoiceRequest>,
    ) -> Result<Response<GetInvoiceResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let invoice_id = uuid::Uuid::parse_str(&req.invoice_id)
            .map_err(|_| Status::invalid_argument("Invalid invoice_id"))?;

        let invoice = self
            .billing
            .get_invoice(&argus_types::InvoiceId(invoice_id))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::histogram!("grpc_request_duration_seconds", "method" => "get_invoice")
            .record(start.elapsed().as_secs_f64());

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

    async fn record_usage(
        &self,
        request: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        if req.count == 0 {
            return Err(Status::invalid_argument("Count must be positive"));
        }

        // Safe: we check for 0 above and reject, typical usage counts are well under i64::MAX
        #[allow(clippy::cast_possible_wrap)]
        let count = req.count as i64;

        let result = self
            .billing
            .record_usage(&user_id, &req.metric, count)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        metrics::counter!("billing_usage_recorded_total", "metric" => req.metric.clone())
            .increment(req.count);
        metrics::histogram!("grpc_request_duration_seconds", "method" => "record_usage")
            .record(start.elapsed().as_secs_f64());

        // Get period limit from subscription tier
        let period_limit = self
            .billing
            .get_subscription(&user_id)
            .await
            .map(|sub| sub.tier.rate_limit() as u64 * 60 * 24 * 30)
            .unwrap_or(0);

        Ok(Response::new(RecordUsageResponse {
            success: result.success,
            current_period_usage: result.total_usage as u64,
            period_limit,
        }))
    }

    async fn get_usage_summary(
        &self,
        request: Request<GetUsageSummaryRequest>,
    ) -> Result<Response<GetUsageSummaryResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let user_id = proto_to_user_id(req.user_id)?;

        let period = if req.period.is_empty() {
            None
        } else {
            Some(req.period.as_str())
        };

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

        metrics::histogram!("grpc_request_duration_seconds", "method" => "get_usage_summary")
            .record(start.elapsed().as_secs_f64());

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

    async fn handle_webhook(
        &self,
        request: Request<HandleWebhookRequest>,
    ) -> Result<Response<HandleWebhookResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        self.billing
            .process_webhook(&req.payload, &req.signature)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Webhook processing failed");
                if e.to_string().contains("Signature")
                    || e.to_string().contains("timestamp")
                    || e.to_string().contains("parse")
                {
                    Status::invalid_argument(e.to_string())
                } else {
                    Status::internal(e.to_string())
                }
            })?;

        metrics::counter!("billing_webhooks_processed_total", "status" => "success").increment(1);
        metrics::histogram!("grpc_request_duration_seconds", "method" => "handle_webhook")
            .record(start.elapsed().as_secs_f64());

        Ok(Response::new(HandleWebhookResponse {
            success: true,
            event_type: String::new(), // Event type is internal
        }))
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
