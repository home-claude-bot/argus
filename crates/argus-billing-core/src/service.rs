//! Billing service

use chrono::Utc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use argus_db::{
    CreateInvoice, InvoiceRepository, Repositories, SubscriptionRepository, UsageRepository,
    UserRepository,
};
use argus_types::{
    CheckoutSession, Invoice, InvoiceId, InvoiceStatus, PortalSession, Subscription,
    SubscriptionId, SubscriptionStatus, Tier, UsageSummary, UserId,
};

use crate::config::BillingConfig;
use crate::error::BillingError;
use crate::provider::PaymentProvider;
use crate::stripe::StripeProvider;
use crate::webhook::{
    InvoiceData, SubscriptionData, WebhookEventData, WebhookEventType, WebhookHandler,
};

/// Billing service
///
/// Provides billing operations including:
/// - Subscription management
/// - Usage tracking and metering
/// - Checkout session creation
/// - Invoice management
/// - Webhook processing
pub struct BillingService<P: PaymentProvider = StripeProvider> {
    repos: Repositories,
    provider: P,
    webhook_handler: WebhookHandler,
    config: BillingConfig,
}

impl BillingService<StripeProvider> {
    /// Create a new billing service with Stripe provider
    pub fn new(repos: Repositories, config: BillingConfig) -> Self {
        let provider = StripeProvider::new(config.clone());
        let webhook_handler = WebhookHandler::new(&config.stripe_webhook_secret);
        Self {
            repos,
            provider,
            webhook_handler,
            config,
        }
    }
}

impl<P: PaymentProvider> BillingService<P> {
    /// Create billing service with custom provider (for testing)
    pub fn with_provider(repos: Repositories, provider: P, config: BillingConfig) -> Self {
        let webhook_handler = WebhookHandler::new(&config.stripe_webhook_secret);
        Self {
            repos,
            provider,
            webhook_handler,
            config,
        }
    }

    // =========================================================================
    // Subscription Management
    // =========================================================================

    /// Get subscription for a user
    #[instrument(skip(self))]
    pub async fn get_subscription(&self, user_id: &UserId) -> Result<Subscription, BillingError> {
        debug!(user_id = %user_id, "Getting subscription");

        let sub_row = self
            .repos
            .subscriptions
            .find_active_by_user_id(user_id.0)
            .await?
            .ok_or(BillingError::SubscriptionNotFound)?;

        Ok(Self::row_to_subscription(sub_row))
    }

    /// Create a checkout session for subscription
    #[instrument(skip(self))]
    pub async fn create_checkout(
        &self,
        user_id: &UserId,
        tier: Tier,
        success_url: Option<&str>,
        cancel_url: Option<&str>,
    ) -> Result<CheckoutSession, BillingError> {
        info!(user_id = %user_id, tier = %tier, "Creating checkout session");

        // Get user to find customer ID
        let user = self
            .repos
            .users
            .find_by_id(user_id.0)
            .await?
            .ok_or(BillingError::UserNotFound)?;

        let customer_id = user
            .stripe_customer_id
            .ok_or(BillingError::CustomerNotFound)?;

        let success = success_url.unwrap_or(&self.config.default_success_url);
        let cancel = cancel_url.unwrap_or(&self.config.default_cancel_url);

        self.provider
            .create_checkout_session(&customer_id, tier, success, cancel)
            .await
    }

    /// Create a customer portal session
    #[instrument(skip(self))]
    pub async fn create_portal_session(
        &self,
        user_id: &UserId,
        return_url: Option<&str>,
    ) -> Result<PortalSession, BillingError> {
        debug!(user_id = %user_id, "Creating portal session");

        let user = self
            .repos
            .users
            .find_by_id(user_id.0)
            .await?
            .ok_or(BillingError::UserNotFound)?;

        let customer_id = user
            .stripe_customer_id
            .ok_or(BillingError::CustomerNotFound)?;

        let return_url = return_url.unwrap_or(&self.config.default_success_url);

        let url = self
            .provider
            .create_portal_session(&customer_id, return_url)
            .await?;

        Ok(PortalSession { url })
    }

    /// Cancel a subscription
    #[instrument(skip(self))]
    pub async fn cancel_subscription(&self, user_id: &UserId) -> Result<(), BillingError> {
        info!(user_id = %user_id, "Canceling subscription");

        let sub = self
            .repos
            .subscriptions
            .find_active_by_user_id(user_id.0)
            .await?
            .ok_or(BillingError::SubscriptionNotFound)?;

        if let Some(stripe_id) = &sub.stripe_subscription_id {
            self.provider.cancel_subscription(stripe_id).await?;
        }

        self.repos.subscriptions.cancel(sub.id).await?;

        Ok(())
    }

    // =========================================================================
    // Usage Tracking
    // =========================================================================

    /// Record usage for a user
    #[instrument(skip(self))]
    pub async fn record_usage(
        &self,
        user_id: &UserId,
        metric: &str,
        quantity: i64,
    ) -> Result<UsageResult, BillingError> {
        debug!(user_id = %user_id, metric = %metric, quantity = %quantity, "Recording usage");

        let period = current_period();

        // Increment usage in database
        self.repos
            .usage
            .increment(user_id.0, metric, &period, quantity)
            .await?;

        // Get updated total
        let total = self
            .repos
            .usage
            .get_total_for_period(user_id.0, &period)
            .await?;

        Ok(UsageResult {
            success: true,
            total_usage: total,
        })
    }

    /// Get usage summary for a user
    #[instrument(skip(self))]
    pub async fn get_usage_summary(
        &self,
        user_id: &UserId,
        period: Option<&str>,
    ) -> Result<UsageSummary, BillingError> {
        let period = period.map_or_else(current_period, String::from);
        debug!(user_id = %user_id, period = %period, "Getting usage summary");

        let usage_rows = self.repos.usage.get_usage(user_id.0, &period).await?;

        let total_requests: u64 = usage_rows.iter().map(|r| r.count as u64).sum();

        let by_endpoint = usage_rows
            .into_iter()
            .map(|r| argus_types::EndpointUsage {
                endpoint: r.metric,
                count: r.count as u64,
            })
            .collect();

        // Get tier limit
        let limit = self
            .get_subscription(user_id)
            .await
            .ok()
            .map(|sub| sub.tier.rate_limit() as u64 * 60 * 24 * 30); // Monthly limit

        Ok(UsageSummary {
            period,
            total_requests,
            by_endpoint,
            limit,
        })
    }

    /// Check if usage is within limits
    #[instrument(skip(self))]
    pub async fn check_usage_limit(&self, user_id: &UserId) -> Result<bool, BillingError> {
        let summary = self.get_usage_summary(user_id, None).await?;

        match summary.limit {
            Some(limit) => Ok(summary.total_requests <= limit),
            None => Ok(true), // No limit = unlimited
        }
    }

    // =========================================================================
    // Invoice Management
    // =========================================================================

    /// Get invoices for a user
    #[instrument(skip(self))]
    pub async fn get_invoices(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<Invoice>, BillingError> {
        debug!(user_id = %user_id, limit = %limit, "Getting invoices");

        let rows = self
            .repos
            .invoices
            .find_by_user_id(user_id.0, limit)
            .await?;

        Ok(rows.into_iter().map(Self::row_to_invoice).collect())
    }

    /// Get a specific invoice
    #[instrument(skip(self))]
    pub async fn get_invoice(&self, invoice_id: &InvoiceId) -> Result<Invoice, BillingError> {
        debug!(invoice_id = %invoice_id, "Getting invoice");

        let row = self
            .repos
            .invoices
            .find_by_id(invoice_id.0)
            .await?
            .ok_or(BillingError::InvoiceNotFound)?;

        Ok(Self::row_to_invoice(row))
    }

    // =========================================================================
    // Webhook Processing
    // =========================================================================

    /// Process a webhook from Stripe
    #[instrument(skip(self, payload, signature))]
    pub async fn process_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), BillingError> {
        let event = self.webhook_handler.verify_and_parse(payload, signature)?;

        info!(event_id = %event.id, event_type = ?event.event_type, "Processing webhook");

        match event.event_type {
            WebhookEventType::CustomerSubscriptionCreated
            | WebhookEventType::CustomerSubscriptionUpdated => {
                if let WebhookEventData::Subscription(data) = event.data {
                    self.handle_subscription_update(data).await?;
                }
            }
            WebhookEventType::CustomerSubscriptionDeleted => {
                if let WebhookEventData::Subscription(data) = event.data {
                    self.handle_subscription_deleted(data).await?;
                }
            }
            WebhookEventType::InvoicePaid => {
                if let WebhookEventData::Invoice(data) = event.data {
                    self.handle_invoice_paid(data).await?;
                }
            }
            WebhookEventType::InvoicePaymentFailed => {
                if let WebhookEventData::Invoice(data) = event.data {
                    self.handle_invoice_failed(data).await?;
                }
            }
            _ => {
                debug!(event_type = ?event.event_type, "Ignoring unhandled webhook event");
            }
        }

        Ok(())
    }

    /// Handle subscription created/updated webhook
    async fn handle_subscription_update(&self, data: SubscriptionData) -> Result<(), BillingError> {
        info!(subscription_id = %data.subscription_id, status = %data.status, "Handling subscription update");

        // Find or create subscription
        let existing = self
            .repos
            .subscriptions
            .find_by_stripe_id(&data.subscription_id)
            .await?;

        if let Some(sub) = existing {
            // Update existing subscription
            self.repos
                .subscriptions
                .update_status(sub.id, &data.status)
                .await?;
            self.repos
                .subscriptions
                .update_period(sub.id, data.period_start, data.period_end)
                .await?;
            self.repos
                .subscriptions
                .set_cancel_at_period_end(sub.id, data.cancel_at_period_end)
                .await?;
        } else {
            warn!(subscription_id = %data.subscription_id, "Received update for unknown subscription");
        }

        Ok(())
    }

    /// Handle subscription deleted webhook
    async fn handle_subscription_deleted(
        &self,
        data: SubscriptionData,
    ) -> Result<(), BillingError> {
        info!(subscription_id = %data.subscription_id, "Handling subscription deletion");

        if let Some(sub) = self
            .repos
            .subscriptions
            .find_by_stripe_id(&data.subscription_id)
            .await?
        {
            self.repos.subscriptions.cancel(sub.id).await?;
        }

        Ok(())
    }

    /// Handle invoice paid webhook
    async fn handle_invoice_paid(&self, data: InvoiceData) -> Result<(), BillingError> {
        info!(invoice_id = %data.invoice_id, "Handling invoice paid");

        // Find or create invoice
        let existing = self
            .repos
            .invoices
            .find_by_stripe_id(&data.invoice_id)
            .await?;

        if let Some(inv) = existing {
            self.repos.invoices.mark_paid(inv.id, Utc::now()).await?;
        } else {
            // Create new invoice record
            let user = self.find_user_by_stripe_customer(&data.customer_id).await?;

            let create = CreateInvoice {
                id: Uuid::new_v4(),
                user_id: user.id,
                stripe_invoice_id: Some(data.invoice_id),
                amount_cents: data.amount_cents,
                currency: data.currency,
                description: None,
                period_start: data.period_start,
                period_end: data.period_end,
            };

            let inv = self.repos.invoices.create(create).await?;
            self.repos.invoices.mark_paid(inv.id, Utc::now()).await?;
        }

        Ok(())
    }

    /// Handle invoice payment failed webhook
    async fn handle_invoice_failed(&self, data: InvoiceData) -> Result<(), BillingError> {
        warn!(invoice_id = %data.invoice_id, "Handling invoice payment failure");

        if let Some(inv) = self
            .repos
            .invoices
            .find_by_stripe_id(&data.invoice_id)
            .await?
        {
            self.repos.invoices.update_status(inv.id, "open").await?;
        }

        // TODO: Send notification to user about payment failure

        Ok(())
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Find user by Stripe customer ID
    async fn find_user_by_stripe_customer(
        &self,
        customer_id: &str,
    ) -> Result<argus_db::UserRow, BillingError> {
        self.repos
            .users
            .find_by_stripe_customer_id(customer_id)
            .await?
            .ok_or(BillingError::UserNotFound)
    }

    /// Convert subscription row to domain type
    fn row_to_subscription(row: argus_db::SubscriptionRow) -> Subscription {
        Subscription {
            id: SubscriptionId(row.id),
            user_id: UserId(row.user_id),
            tier: row.tier.parse().unwrap_or(Tier::Explorer),
            status: parse_subscription_status(&row.status),
            stripe_subscription_id: row.stripe_subscription_id,
            current_period_start: row.current_period_start,
            current_period_end: row.current_period_end,
            created_at: row.created_at,
        }
    }

    /// Convert invoice row to domain type
    fn row_to_invoice(row: argus_db::InvoiceRow) -> Invoice {
        Invoice {
            id: InvoiceId(row.id),
            user_id: UserId(row.user_id),
            stripe_invoice_id: row.stripe_invoice_id,
            status: parse_invoice_status(&row.status),
            amount_cents: row.amount_cents,
            currency: row.currency,
            description: row.description,
            hosted_invoice_url: row.hosted_invoice_url,
            invoice_pdf: row.invoice_pdf,
            period_start: row.period_start,
            period_end: row.period_end,
            created_at: row.created_at,
            paid_at: row.paid_at,
        }
    }
}

/// Usage recording result
#[derive(Debug, Clone)]
pub struct UsageResult {
    /// Whether the usage was recorded successfully
    pub success: bool,
    /// Total usage for the period
    pub total_usage: i64,
}

/// Get current billing period (YYYY-MM format)
fn current_period() -> String {
    Utc::now().format("%Y-%m").to_string()
}

/// Parse subscription status from string
fn parse_subscription_status(s: &str) -> SubscriptionStatus {
    match s.to_lowercase().as_str() {
        "past_due" => SubscriptionStatus::PastDue,
        "canceled" | "cancelled" => SubscriptionStatus::Canceled,
        "trialing" => SubscriptionStatus::Trialing,
        // Default to active for "active" and any unknown status
        _ => SubscriptionStatus::Active,
    }
}

/// Parse invoice status from string
fn parse_invoice_status(s: &str) -> InvoiceStatus {
    match s.to_lowercase().as_str() {
        "draft" => InvoiceStatus::Draft,
        "paid" => InvoiceStatus::Paid,
        "void" => InvoiceStatus::Void,
        "uncollectible" => InvoiceStatus::Uncollectible,
        // Default to open for "open" and any unknown status
        _ => InvoiceStatus::Open,
    }
}
