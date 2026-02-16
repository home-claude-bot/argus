//! Stripe payment provider implementation

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument};

use argus_types::Tier;

use crate::config::BillingConfig;
use crate::error::BillingError;
use crate::provider::PaymentProvider;
use crate::CheckoutSession;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

/// Stripe payment provider
#[derive(Clone)]
pub struct StripeProvider {
    client: Client,
    config: BillingConfig,
}

impl StripeProvider {
    /// Create a new Stripe provider
    pub fn new(config: BillingConfig) -> Self {
        let client = Client::new();
        Self { client, config }
    }

    /// Make authenticated request to Stripe
    async fn stripe_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        form: Option<&[(&str, &str)]>,
    ) -> Result<T, BillingError> {
        let url = format!("{STRIPE_API_BASE}{endpoint}");

        let mut request = self
            .client
            .request(method, &url)
            .basic_auth(&self.config.stripe_secret_key, Option::<&str>::None);

        if let Some(form_data) = form {
            request = request.form(form_data);
        }

        let response = request.send().await.map_err(|e| {
            error!(error = %e, "Stripe API request failed");
            BillingError::ProviderError(e.to_string())
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            error!(status = %status, body = %error_body, "Stripe API error");
            return Err(BillingError::ProviderError(format!(
                "Stripe API error: {status}"
            )));
        }

        response.json::<T>().await.map_err(|e| {
            error!(error = %e, "Failed to parse Stripe response");
            BillingError::Internal(e.to_string())
        })
    }

    /// Create a Stripe customer
    #[instrument(skip(self))]
    pub async fn create_customer(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> Result<StripeCustomer, BillingError> {
        debug!(email = %email, "Creating Stripe customer");

        let mut form: Vec<(&str, &str)> = vec![("email", email)];
        if let Some(n) = name {
            form.push(("name", n));
        }

        self.stripe_request(reqwest::Method::POST, "/customers", Some(&form))
            .await
    }

    /// Get a Stripe customer
    #[instrument(skip(self))]
    pub async fn get_customer(&self, customer_id: &str) -> Result<StripeCustomer, BillingError> {
        debug!(customer_id = %customer_id, "Getting Stripe customer");

        self.stripe_request::<StripeCustomer>(
            reqwest::Method::GET,
            &format!("/customers/{customer_id}"),
            None,
        )
        .await
    }

    /// Get a subscription
    #[instrument(skip(self))]
    pub async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscription, BillingError> {
        debug!(subscription_id = %subscription_id, "Getting Stripe subscription");

        self.stripe_request::<StripeSubscription>(
            reqwest::Method::GET,
            &format!("/subscriptions/{subscription_id}"),
            None,
        )
        .await
    }

    /// List invoices for a customer
    #[instrument(skip(self))]
    pub async fn list_invoices(
        &self,
        customer_id: &str,
        limit: u32,
    ) -> Result<StripeList<StripeInvoice>, BillingError> {
        debug!(customer_id = %customer_id, limit = %limit, "Listing invoices");

        let limit_str = limit.to_string();
        let form = [("customer", customer_id), ("limit", &limit_str)];

        self.stripe_request(reqwest::Method::GET, "/invoices", Some(&form))
            .await
    }
}

#[async_trait]
impl PaymentProvider for StripeProvider {
    #[instrument(skip(self))]
    async fn create_checkout_session(
        &self,
        customer_id: &str,
        tier: Tier,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError> {
        debug!(customer_id = %customer_id, tier = %tier, "Creating checkout session");

        let price_id = self
            .config
            .get_price_id(tier)
            .ok_or(BillingError::InvalidTier)?;

        let form = [
            ("customer", customer_id),
            ("mode", "subscription"),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
            ("line_items[0][price]", price_id),
            ("line_items[0][quantity]", "1"),
        ];

        let session: StripeCheckoutSession = self
            .stripe_request(reqwest::Method::POST, "/checkout/sessions", Some(&form))
            .await?;

        Ok(CheckoutSession {
            session_id: session.id,
            url: session.url.unwrap_or_default(),
        })
    }

    #[instrument(skip(self))]
    async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String, BillingError> {
        debug!(customer_id = %customer_id, "Creating portal session");

        let form = [("customer", customer_id), ("return_url", return_url)];

        let session: StripeBillingPortalSession = self
            .stripe_request(
                reqwest::Method::POST,
                "/billing_portal/sessions",
                Some(&form),
            )
            .await?;

        Ok(session.url)
    }

    #[instrument(skip(self))]
    async fn cancel_subscription(&self, subscription_id: &str) -> Result<(), BillingError> {
        debug!(subscription_id = %subscription_id, "Canceling subscription");

        let _: StripeSubscription = self
            .stripe_request(
                reqwest::Method::DELETE,
                &format!("/subscriptions/{subscription_id}"),
                None,
            )
            .await?;

        Ok(())
    }
}

// Stripe API response types

/// Stripe customer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCustomer {
    /// Customer ID
    pub id: String,
    /// Customer email
    pub email: Option<String>,
    /// Customer name
    pub name: Option<String>,
    /// Whether the customer is deleted
    #[serde(default)]
    pub deleted: bool,
}

/// Stripe subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSubscription {
    /// Subscription ID
    pub id: String,
    /// Customer ID
    pub customer: String,
    /// Subscription status
    pub status: String,
    /// Current period start (Unix timestamp)
    pub current_period_start: i64,
    /// Current period end (Unix timestamp)
    pub current_period_end: i64,
    /// Whether subscription cancels at period end
    #[serde(default)]
    pub cancel_at_period_end: bool,
}

/// Stripe checkout session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCheckoutSession {
    /// Session ID
    pub id: String,
    /// Checkout URL
    pub url: Option<String>,
    /// Customer ID
    pub customer: Option<String>,
    /// Subscription ID (after completion)
    pub subscription: Option<String>,
}

/// Stripe billing portal session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeBillingPortalSession {
    /// Session ID
    pub id: String,
    /// Portal URL
    pub url: String,
}

/// Stripe invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeInvoice {
    /// Invoice ID
    pub id: String,
    /// Customer ID
    pub customer: String,
    /// Invoice status
    pub status: Option<String>,
    /// Amount due in cents
    pub amount_due: i64,
    /// Amount paid in cents
    pub amount_paid: i64,
    /// Currency
    pub currency: String,
    /// Hosted invoice URL
    pub hosted_invoice_url: Option<String>,
    /// Invoice PDF URL
    pub invoice_pdf: Option<String>,
    /// Period start (Unix timestamp)
    pub period_start: i64,
    /// Period end (Unix timestamp)
    pub period_end: i64,
}

/// Stripe list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeList<T> {
    /// List data
    pub data: Vec<T>,
    /// Whether there are more items
    pub has_more: bool,
}
