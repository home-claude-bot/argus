//! Billing and payment types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::UserId;

/// Stripe customer ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CustomerId(pub String);

impl CustomerId {
    /// Create a new customer ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for CustomerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stripe price ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PriceId(pub String);

impl PriceId {
    /// Create a new price ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for PriceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stripe product ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProductId(pub String);

impl ProductId {
    /// Create a new product ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for ProductId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Invoice ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvoiceId(pub Uuid);

impl InvoiceId {
    /// Create a new invoice ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for InvoiceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InvoiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Invoice status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    /// Invoice is a draft
    Draft,
    /// Invoice is open and awaiting payment
    Open,
    /// Invoice has been paid
    Paid,
    /// Invoice is void
    Void,
    /// Invoice is uncollectible
    Uncollectible,
}

/// Invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    /// Invoice ID
    pub id: InvoiceId,
    /// User who owns the invoice
    pub user_id: UserId,
    /// Stripe invoice ID
    pub stripe_invoice_id: Option<String>,
    /// Invoice status
    pub status: InvoiceStatus,
    /// Amount in cents
    pub amount_cents: i64,
    /// Currency (e.g., "usd")
    pub currency: String,
    /// Invoice description
    pub description: Option<String>,
    /// Hosted invoice URL
    pub hosted_invoice_url: Option<String>,
    /// PDF download URL
    pub invoice_pdf: Option<String>,
    /// Invoice period start
    pub period_start: DateTime<Utc>,
    /// Invoice period end
    pub period_end: DateTime<Utc>,
    /// When the invoice was created
    pub created_at: DateTime<Utc>,
    /// When the invoice was paid (if paid)
    pub paid_at: Option<DateTime<Utc>>,
}

/// Payment method type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethodType {
    /// Credit or debit card
    Card,
    /// Bank account (ACH)
    BankAccount,
    /// `PayPal`
    PayPal,
}

/// Payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    /// Stripe payment method ID
    pub id: String,
    /// Payment method type
    pub method_type: PaymentMethodType,
    /// Whether this is the default payment method
    pub is_default: bool,
    /// Card brand (if card)
    pub card_brand: Option<String>,
    /// Last 4 digits (if card)
    pub card_last4: Option<String>,
    /// Card expiration month (if card)
    pub card_exp_month: Option<u32>,
    /// Card expiration year (if card)
    pub card_exp_year: Option<u32>,
}

/// Usage record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// User who generated the usage
    pub user_id: UserId,
    /// Metric name (e.g., `prediction_requests`)
    pub metric: String,
    /// Usage count
    pub count: u64,
    /// Billing period (YYYY-MM format)
    pub period: String,
    /// When the usage was recorded
    pub recorded_at: DateTime<Utc>,
}

/// Checkout session request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutRequest {
    /// Price ID to subscribe to
    pub price_id: PriceId,
    /// Success redirect URL
    pub success_url: String,
    /// Cancel redirect URL
    pub cancel_url: String,
}

/// Checkout session response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    /// Stripe checkout session ID
    pub session_id: String,
    /// Checkout URL to redirect user to
    pub url: String,
}

/// Customer portal session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalSession {
    /// Portal session URL
    pub url: String,
}

/// Usage summary for a period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    /// Billing period
    pub period: String,
    /// Total API requests
    pub total_requests: u64,
    /// Requests by endpoint
    pub by_endpoint: Vec<EndpointUsage>,
    /// Tier limit for the period
    pub limit: Option<u64>,
}

/// Usage for a specific endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointUsage {
    /// Endpoint name
    pub endpoint: String,
    /// Request count
    pub count: u64,
}
