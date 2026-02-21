//! Billing client
//!
//! Client for subscription management, payments, and usage tracking.

use argus_proto::billing_service::billing_service_client::BillingServiceClient;
use argus_types::{Tier, UserId};
use tonic::transport::Channel;
use tracing::instrument;

use crate::{ClientConfig, ClientError, Result};

/// Client for billing service operations.
///
/// Provides methods for:
/// - Subscription management (get, cancel, resume, change plan)
/// - Checkout and portal sessions
/// - Payment methods
/// - Invoices
/// - Usage tracking
#[derive(Debug, Clone)]
pub struct BillingClient {
    inner: BillingServiceClient<Channel>,
    #[allow(dead_code)]
    config: ClientConfig,
}

impl BillingClient {
    /// Connect to the billing service.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let channel = tonic::transport::Channel::from_shared(config.billing_endpoint.clone())
            .map_err(|e| ClientError::connection(format!("invalid endpoint: {e}"), false))?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .connect_lazy();

        let inner = BillingServiceClient::new(channel);

        Ok(Self { inner, config })
    }

    /// Create from an existing channel.
    pub fn from_channel(channel: Channel, config: ClientConfig) -> Self {
        Self {
            inner: BillingServiceClient::new(channel),
            config,
        }
    }

    // =========================================================================
    // Subscription Management
    // =========================================================================

    /// Get user's current subscription.
    #[instrument(skip(self), level = "debug")]
    pub async fn get_subscription(&mut self, user_id: &UserId) -> Result<Subscription> {
        use argus_proto::{GetSubscriptionRequest, UserId as ProtoUserId};

        let request = GetSubscriptionRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.get_subscription(request).await?.into_inner();
        let subscription = response
            .subscription
            .ok_or_else(|| ClientError::Internal("missing subscription in response".to_string()))?;

        Ok(Subscription::from_proto(subscription))
    }

    /// List available subscription plans.
    pub async fn list_plans(
        &mut self,
        tier_filter: Option<Tier>,
        include_inactive: bool,
    ) -> Result<Vec<Plan>> {
        use argus_proto::ListPlansRequest;

        let request = ListPlansRequest {
            tier: tier_filter.map_or(argus_proto::Tier::Unspecified, tier_to_proto) as i32,
            include_inactive,
        };

        let response = self.inner.list_plans(request).await?.into_inner();
        let plans = response.plans.into_iter().map(Plan::from_proto).collect();

        Ok(plans)
    }

    /// Create a checkout session for subscription.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let session = client.create_checkout_session(
    ///     &user_id,
    ///     "price_xxx",
    ///     "https://example.com/success",
    ///     "https://example.com/cancel",
    ///     CheckoutOptions::new().with_trial_days(14),
    /// ).await?;
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub async fn create_checkout_session(
        &mut self,
        user_id: &UserId,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
        options: CheckoutOptions<'_>,
    ) -> Result<CheckoutSession> {
        use argus_proto::{CreateCheckoutSessionRequest, UserId as ProtoUserId};

        let request = CreateCheckoutSessionRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            price_id: price_id.to_string(),
            success_url: success_url.to_string(),
            cancel_url: cancel_url.to_string(),
            trial_days: options.trial_days.unwrap_or(0),
            promotion_code: options.promotion_code.unwrap_or_default().to_string(),
            idempotency_key: options.idempotency_key.unwrap_or_default().to_string(),
        };

        let response = self.inner.create_checkout_session(request).await?.into_inner();

        Ok(CheckoutSession {
            session_id: response.session_id,
            url: response.url,
        })
    }

    /// Create a customer portal session.
    pub async fn create_portal_session(
        &mut self,
        user_id: &UserId,
        return_url: &str,
    ) -> Result<String> {
        use argus_proto::{CreatePortalSessionRequest, UserId as ProtoUserId};

        let request = CreatePortalSessionRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            return_url: return_url.to_string(),
        };

        let response = self.inner.create_portal_session(request).await?.into_inner();
        Ok(response.url)
    }

    /// Cancel a subscription.
    pub async fn cancel_subscription(
        &mut self,
        user_id: &UserId,
        immediate: bool,
        reason: Option<&str>,
        idempotency_key: Option<&str>,
        requester_id: Option<&UserId>,
    ) -> Result<Subscription> {
        use argus_proto::{CancelSubscriptionRequest, UserId as ProtoUserId};

        let request = CancelSubscriptionRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            immediate,
            reason: reason.unwrap_or_default().to_string(),
            idempotency_key: idempotency_key.unwrap_or_default().to_string(),
            requester_id: requester_id.map(|id| ProtoUserId {
                value: id.to_string(),
            }),
        };

        let response = self.inner.cancel_subscription(request).await?.into_inner();
        let subscription = response
            .subscription
            .ok_or_else(|| ClientError::Internal("missing subscription in response".to_string()))?;

        Ok(Subscription::from_proto(subscription))
    }

    /// Resume a canceled subscription.
    pub async fn resume_subscription(&mut self, user_id: &UserId) -> Result<Subscription> {
        use argus_proto::{ResumeSubscriptionRequest, UserId as ProtoUserId};

        let request = ResumeSubscriptionRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.resume_subscription(request).await?.into_inner();
        let subscription = response
            .subscription
            .ok_or_else(|| ClientError::Internal("missing subscription in response".to_string()))?;

        Ok(Subscription::from_proto(subscription))
    }

    /// Change subscription plan.
    pub async fn change_plan(
        &mut self,
        user_id: &UserId,
        new_price_id: &str,
        prorate: bool,
        idempotency_key: Option<&str>,
        requester_id: Option<&UserId>,
    ) -> Result<ChangePlanResult> {
        use argus_proto::{ChangePlanRequest, UserId as ProtoUserId};

        let request = ChangePlanRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            new_price_id: new_price_id.to_string(),
            prorate,
            idempotency_key: idempotency_key.unwrap_or_default().to_string(),
            requester_id: requester_id.map(|id| ProtoUserId {
                value: id.to_string(),
            }),
        };

        let response = self.inner.change_plan(request).await?.into_inner();
        let subscription = response
            .subscription
            .ok_or_else(|| ClientError::Internal("missing subscription in response".to_string()))?;

        Ok(ChangePlanResult {
            subscription: Subscription::from_proto(subscription),
            prorated_amount_cents: response.prorated_amount_cents,
        })
    }

    // =========================================================================
    // Payment Methods
    // =========================================================================

    /// List payment methods for a user.
    pub async fn list_payment_methods(&mut self, user_id: &UserId) -> Result<Vec<PaymentMethod>> {
        use argus_proto::{ListPaymentMethodsRequest, UserId as ProtoUserId};

        let request = ListPaymentMethodsRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.list_payment_methods(request).await?.into_inner();
        let methods = response
            .payment_methods
            .into_iter()
            .map(PaymentMethod::from_proto)
            .collect();

        Ok(methods)
    }

    /// Set the default payment method.
    pub async fn set_default_payment_method(
        &mut self,
        user_id: &UserId,
        payment_method_id: &str,
    ) -> Result<bool> {
        use argus_proto::{SetDefaultPaymentMethodRequest, UserId as ProtoUserId};

        let request = SetDefaultPaymentMethodRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            payment_method_id: payment_method_id.to_string(),
        };

        let response = self.inner.set_default_payment_method(request).await?.into_inner();
        Ok(response.success)
    }

    /// Delete a payment method.
    pub async fn delete_payment_method(
        &mut self,
        user_id: &UserId,
        payment_method_id: &str,
    ) -> Result<bool> {
        use argus_proto::{DeletePaymentMethodRequest, UserId as ProtoUserId};

        let request = DeletePaymentMethodRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            payment_method_id: payment_method_id.to_string(),
        };

        let response = self.inner.delete_payment_method(request).await?.into_inner();
        Ok(response.success)
    }

    // =========================================================================
    // Invoices
    // =========================================================================

    /// List invoices for a user.
    pub async fn list_invoices(
        &mut self,
        user_id: &UserId,
        status_filter: Option<InvoiceStatus>,
    ) -> Result<Vec<Invoice>> {
        use argus_proto::{ListInvoicesRequest, UserId as ProtoUserId};

        let request = ListInvoicesRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            pagination: None,
            status: status_filter.map_or(0, invoice_status_to_proto),
        };

        let response = self.inner.list_invoices(request).await?.into_inner();
        let invoices = response
            .invoices
            .into_iter()
            .map(Invoice::from_proto)
            .collect();

        Ok(invoices)
    }

    /// Get invoice details.
    pub async fn get_invoice(&mut self, invoice_id: &str) -> Result<Invoice> {
        use argus_proto::GetInvoiceRequest;

        let request = GetInvoiceRequest {
            invoice_id: invoice_id.to_string(),
        };

        let response = self.inner.get_invoice(request).await?.into_inner();
        let invoice = response
            .invoice
            .ok_or_else(|| ClientError::Internal("missing invoice in response".to_string()))?;

        Ok(Invoice::from_proto(invoice))
    }

    /// Get upcoming invoice preview.
    pub async fn get_upcoming_invoice(&mut self, user_id: &UserId) -> Result<Option<Invoice>> {
        use argus_proto::{GetUpcomingInvoiceRequest, UserId as ProtoUserId};

        let request = GetUpcomingInvoiceRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.get_upcoming_invoice(request).await?.into_inner();
        Ok(response.invoice.map(Invoice::from_proto))
    }

    // =========================================================================
    // Usage Tracking
    // =========================================================================

    /// Record API usage.
    pub async fn record_usage(
        &mut self,
        user_id: &UserId,
        metric: &str,
        count: u64,
        metadata: Option<std::collections::HashMap<String, String>>,
    ) -> Result<UsageRecordResult> {
        use argus_proto::{RecordUsageRequest, UserId as ProtoUserId};

        let request = RecordUsageRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            metric: metric.to_string(),
            count,
            timestamp: None,
            metadata: metadata.unwrap_or_default(),
        };

        let response = self.inner.record_usage(request).await?.into_inner();

        Ok(UsageRecordResult {
            success: response.success,
            current_period_usage: response.current_period_usage,
            period_limit: response.period_limit,
        })
    }

    /// Get usage summary for a period.
    pub async fn get_usage_summary(
        &mut self,
        user_id: &UserId,
        period: Option<&str>,
        metrics: &[&str],
    ) -> Result<UsageSummary> {
        use argus_proto::{GetUsageSummaryRequest, UserId as ProtoUserId};

        let request = GetUsageSummaryRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            period: period.unwrap_or_default().to_string(),
            metrics: metrics.iter().map(|s| (*s).to_string()).collect(),
        };

        let response = self.inner.get_usage_summary(request).await?.into_inner();

        Ok(UsageSummary {
            period: response.period,
            metrics: response.metrics.into_iter().map(MetricUsage::from_proto).collect(),
            total_requests: response.total_requests,
            limit: response.limit,
            usage_percentage: response.usage_percentage,
        })
    }

    /// Health check.
    pub async fn health_check(&mut self) -> Result<bool> {
        use argus_proto::HealthCheckRequest;

        let request = HealthCheckRequest {
            service: String::new(),
        };

        let response = self.inner.health_check(request).await?.into_inner();

        Ok(response.status() == argus_proto::health_check_response::ServingStatus::Serving)
    }
}

// =============================================================================
// Domain Types
// =============================================================================

/// Options for creating a checkout session.
#[derive(Debug, Clone, Default)]
pub struct CheckoutOptions<'a> {
    /// Number of trial days (0 for no trial)
    pub trial_days: Option<i32>,
    /// Promotion code to apply
    pub promotion_code: Option<&'a str>,
    /// Idempotency key for safe retries
    pub idempotency_key: Option<&'a str>,
}

impl<'a> CheckoutOptions<'a> {
    /// Create new checkout options with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of trial days.
    #[must_use]
    pub fn with_trial_days(mut self, days: i32) -> Self {
        self.trial_days = Some(days);
        self
    }

    /// Set a promotion code.
    #[must_use]
    pub fn with_promotion_code(mut self, code: &'a str) -> Self {
        self.promotion_code = Some(code);
        self
    }

    /// Set an idempotency key for safe retries.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: &'a str) -> Self {
        self.idempotency_key = Some(key);
        self
    }
}

/// Subscription information.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription ID
    pub id: String,
    /// User ID
    pub user_id: UserId,
    /// Current tier
    pub tier: Tier,
    /// Subscription status
    pub status: SubscriptionStatus,
    /// Current period start
    pub current_period_start: Option<chrono::DateTime<chrono::Utc>>,
    /// Current period end
    pub current_period_end: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether subscription will cancel at period end
    pub cancel_at_period_end: bool,
    /// When the subscription was created
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Subscription {
    fn from_proto(proto: argus_proto::Subscription) -> Self {
        let tier = tier_from_proto(proto.tier());
        let status = subscription_status_from_proto(proto.status());
        let cancel_at_period_end = proto.cancel_at_period_end;

        Self {
            id: proto.id,
            user_id: UserId::parse(&proto.user_id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            tier,
            status,
            current_period_start: proto.current_period_start.as_ref().map(timestamp_to_datetime),
            current_period_end: proto.current_period_end.as_ref().map(timestamp_to_datetime),
            cancel_at_period_end,
            created_at: proto.created_at.as_ref().map(timestamp_to_datetime),
        }
    }
}

/// Subscription status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    /// Active subscription
    Active,
    /// Past due (payment failed)
    PastDue,
    /// Canceled
    Canceled,
    /// Incomplete (setup pending)
    Incomplete,
    /// In trial period
    Trialing,
    /// Paused
    Paused,
    /// Unknown status
    Unknown,
}

/// Subscription plan.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Plan ID (Stripe price ID)
    pub id: String,
    /// Plan name
    pub name: String,
    /// Plan description
    pub description: String,
    /// Tier this plan represents
    pub tier: Tier,
    /// Price in cents
    pub price_cents: i64,
    /// Currency
    pub currency: String,
    /// Billing interval
    pub interval: BillingInterval,
    /// Features included
    pub features: Vec<String>,
    /// Whether this plan is active
    pub active: bool,
}

impl Plan {
    fn from_proto(proto: argus_proto::Plan) -> Self {
        let tier = tier_from_proto(proto.tier());
        let interval = billing_interval_from_proto(proto.interval());
        let active = proto.active;

        Self {
            id: proto.id,
            name: proto.name,
            description: proto.description,
            tier,
            price_cents: proto.price_cents,
            currency: proto.currency,
            interval,
            features: proto.features,
            active,
        }
    }
}

/// Billing interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingInterval {
    /// Monthly billing
    Monthly,
    /// Yearly billing
    Yearly,
    /// Unknown interval
    Unknown,
}

/// Checkout session.
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    /// Session ID
    pub session_id: String,
    /// Checkout URL
    pub url: String,
}

/// Result of changing subscription plan.
#[derive(Debug, Clone)]
pub struct ChangePlanResult {
    /// Updated subscription
    pub subscription: Subscription,
    /// Prorated amount (positive = charge, negative = credit)
    pub prorated_amount_cents: i64,
}

/// Payment method information.
#[derive(Debug, Clone)]
pub struct PaymentMethod {
    /// Payment method ID
    pub id: String,
    /// Payment method type
    pub method_type: PaymentMethodType,
    /// Whether this is the default
    pub is_default: bool,
    /// Card details (if card)
    pub card: Option<CardDetails>,
    /// Created at
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl PaymentMethod {
    fn from_proto(proto: argus_proto::PaymentMethod) -> Self {
        let method_type = payment_method_type_from_proto(proto.r#type());
        let is_default = proto.is_default;

        Self {
            id: proto.id,
            method_type,
            is_default,
            card: proto.card.map(CardDetails::from_proto),
            created_at: proto.created_at.as_ref().map(timestamp_to_datetime),
        }
    }
}

/// Payment method type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentMethodType {
    /// Credit/debit card
    Card,
    /// Bank account
    BankAccount,
    /// PayPal
    PayPal,
    /// Unknown type
    Unknown,
}

/// Card details.
#[derive(Debug, Clone)]
pub struct CardDetails {
    /// Card brand (visa, mastercard, etc.)
    pub brand: String,
    /// Last 4 digits
    pub last4: String,
    /// Expiration month
    pub exp_month: u32,
    /// Expiration year
    pub exp_year: u32,
    /// Funding type
    pub funding: String,
}

impl CardDetails {
    fn from_proto(proto: argus_proto::CardDetails) -> Self {
        Self {
            brand: proto.brand,
            last4: proto.last4,
            exp_month: proto.exp_month,
            exp_year: proto.exp_year,
            funding: proto.funding,
        }
    }
}

/// Invoice status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceStatus {
    /// Draft invoice
    Draft,
    /// Open (awaiting payment)
    Open,
    /// Paid
    Paid,
    /// Void
    Void,
    /// Uncollectible
    Uncollectible,
    /// Unknown status
    Unknown,
}

/// Invoice information.
#[derive(Debug, Clone)]
pub struct Invoice {
    /// Invoice ID
    pub id: String,
    /// User ID
    pub user_id: UserId,
    /// Invoice status
    pub status: InvoiceStatus,
    /// Amount in cents
    pub amount_cents: i64,
    /// Amount paid in cents
    pub amount_paid_cents: i64,
    /// Currency
    pub currency: String,
    /// Description
    pub description: String,
    /// Period start
    pub period_start: Option<chrono::DateTime<chrono::Utc>>,
    /// Period end
    pub period_end: Option<chrono::DateTime<chrono::Utc>>,
    /// Created at
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Paid at
    pub paid_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hosted invoice URL
    pub hosted_invoice_url: Option<String>,
    /// PDF download URL
    pub invoice_pdf_url: Option<String>,
}

impl Invoice {
    fn from_proto(proto: argus_proto::Invoice) -> Self {
        let status = invoice_status_from_proto(proto.status());

        Self {
            id: proto.id,
            user_id: UserId::parse(&proto.user_id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            status,
            amount_cents: proto.amount_cents,
            amount_paid_cents: proto.amount_paid_cents,
            currency: proto.currency,
            description: proto.description,
            period_start: proto.period_start.as_ref().map(timestamp_to_datetime),
            period_end: proto.period_end.as_ref().map(timestamp_to_datetime),
            created_at: proto.created_at.as_ref().map(timestamp_to_datetime),
            paid_at: proto.paid_at.as_ref().map(timestamp_to_datetime),
            hosted_invoice_url: if proto.hosted_invoice_url.is_empty() {
                None
            } else {
                Some(proto.hosted_invoice_url)
            },
            invoice_pdf_url: if proto.invoice_pdf_url.is_empty() {
                None
            } else {
                Some(proto.invoice_pdf_url)
            },
        }
    }
}

/// Usage record result.
#[derive(Debug, Clone)]
pub struct UsageRecordResult {
    /// Whether usage was recorded
    pub success: bool,
    /// Updated usage for current period
    pub current_period_usage: u64,
    /// Period limit (if applicable)
    pub period_limit: u64,
}

/// Usage summary.
#[derive(Debug, Clone)]
pub struct UsageSummary {
    /// Billing period (YYYY-MM format)
    pub period: String,
    /// Usage by metric
    pub metrics: Vec<MetricUsage>,
    /// Total API requests
    pub total_requests: u64,
    /// Period limit
    pub limit: u64,
    /// Usage percentage (0-100)
    pub usage_percentage: f64,
}

/// Metric usage information.
#[derive(Debug, Clone)]
pub struct MetricUsage {
    /// Metric name
    pub metric: String,
    /// Total count
    pub count: u64,
}

impl MetricUsage {
    fn from_proto(proto: argus_proto::MetricUsage) -> Self {
        Self {
            metric: proto.metric,
            count: proto.count,
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn tier_from_proto(tier: argus_proto::Tier) -> Tier {
    match tier {
        argus_proto::Tier::Unspecified | argus_proto::Tier::Explorer => Tier::Explorer,
        argus_proto::Tier::Professional => Tier::Professional,
        argus_proto::Tier::Business => Tier::Business,
        argus_proto::Tier::Enterprise => Tier::Enterprise,
    }
}

fn tier_to_proto(tier: Tier) -> argus_proto::Tier {
    match tier {
        Tier::Explorer => argus_proto::Tier::Explorer,
        Tier::Professional => argus_proto::Tier::Professional,
        Tier::Business => argus_proto::Tier::Business,
        Tier::Enterprise => argus_proto::Tier::Enterprise,
    }
}

fn subscription_status_from_proto(status: argus_proto::SubscriptionStatus) -> SubscriptionStatus {
    match status {
        argus_proto::SubscriptionStatus::Active => SubscriptionStatus::Active,
        argus_proto::SubscriptionStatus::PastDue => SubscriptionStatus::PastDue,
        argus_proto::SubscriptionStatus::Canceled => SubscriptionStatus::Canceled,
        argus_proto::SubscriptionStatus::Incomplete => SubscriptionStatus::Incomplete,
        argus_proto::SubscriptionStatus::Trialing => SubscriptionStatus::Trialing,
        argus_proto::SubscriptionStatus::Paused => SubscriptionStatus::Paused,
        argus_proto::SubscriptionStatus::Unspecified => SubscriptionStatus::Unknown,
    }
}

fn billing_interval_from_proto(interval: argus_proto::BillingInterval) -> BillingInterval {
    match interval {
        argus_proto::BillingInterval::Monthly => BillingInterval::Monthly,
        argus_proto::BillingInterval::Yearly => BillingInterval::Yearly,
        argus_proto::BillingInterval::Unspecified => BillingInterval::Unknown,
    }
}

fn payment_method_type_from_proto(pmt: argus_proto::PaymentMethodType) -> PaymentMethodType {
    match pmt {
        argus_proto::PaymentMethodType::Card => PaymentMethodType::Card,
        argus_proto::PaymentMethodType::BankAccount => PaymentMethodType::BankAccount,
        argus_proto::PaymentMethodType::Paypal => PaymentMethodType::PayPal,
        argus_proto::PaymentMethodType::Unspecified => PaymentMethodType::Unknown,
    }
}

fn invoice_status_from_proto(status: argus_proto::InvoiceStatus) -> InvoiceStatus {
    match status {
        argus_proto::InvoiceStatus::Draft => InvoiceStatus::Draft,
        argus_proto::InvoiceStatus::Open => InvoiceStatus::Open,
        argus_proto::InvoiceStatus::Paid => InvoiceStatus::Paid,
        argus_proto::InvoiceStatus::Void => InvoiceStatus::Void,
        argus_proto::InvoiceStatus::Uncollectible => InvoiceStatus::Uncollectible,
        argus_proto::InvoiceStatus::Unspecified => InvoiceStatus::Unknown,
    }
}

fn invoice_status_to_proto(status: InvoiceStatus) -> i32 {
    match status {
        InvoiceStatus::Draft => argus_proto::InvoiceStatus::Draft as i32,
        InvoiceStatus::Open => argus_proto::InvoiceStatus::Open as i32,
        InvoiceStatus::Paid => argus_proto::InvoiceStatus::Paid as i32,
        InvoiceStatus::Void => argus_proto::InvoiceStatus::Void as i32,
        InvoiceStatus::Uncollectible => argus_proto::InvoiceStatus::Uncollectible as i32,
        InvoiceStatus::Unknown => argus_proto::InvoiceStatus::Unspecified as i32,
    }
}

fn timestamp_to_datetime(ts: &prost_types::Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
        .unwrap_or_else(chrono::Utc::now)
}
