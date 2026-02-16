//! Stripe webhook handling

use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tracing::{debug, error, info, instrument, warn};

use crate::error::BillingError;
use crate::stripe::{StripeInvoice, StripeSubscription};

/// Webhook event types we handle
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEventType {
    /// Checkout session completed
    CheckoutSessionCompleted,
    /// Customer subscription created
    CustomerSubscriptionCreated,
    /// Customer subscription updated
    CustomerSubscriptionUpdated,
    /// Customer subscription deleted
    CustomerSubscriptionDeleted,
    /// Invoice paid
    InvoicePaid,
    /// Invoice payment failed
    InvoicePaymentFailed,
    /// Unknown event type
    Unknown(String),
}

impl From<&str> for WebhookEventType {
    fn from(s: &str) -> Self {
        match s {
            "checkout.session.completed" => Self::CheckoutSessionCompleted,
            "customer.subscription.created" => Self::CustomerSubscriptionCreated,
            "customer.subscription.updated" => Self::CustomerSubscriptionUpdated,
            "customer.subscription.deleted" => Self::CustomerSubscriptionDeleted,
            "invoice.paid" => Self::InvoicePaid,
            "invoice.payment_failed" => Self::InvoicePaymentFailed,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// Parsed webhook event
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: WebhookEventType,
    /// Event data
    pub data: WebhookEventData,
    /// When the event was created (Unix timestamp)
    pub created: i64,
}

/// Webhook event data
#[derive(Debug, Clone)]
pub enum WebhookEventData {
    /// Checkout session data
    CheckoutSession(CheckoutSessionData),
    /// Subscription data
    Subscription(SubscriptionData),
    /// Invoice data
    Invoice(InvoiceData),
    /// Raw JSON for unknown events
    Raw(serde_json::Value),
}

/// Checkout session completed data
#[derive(Debug, Clone)]
pub struct CheckoutSessionData {
    /// Session ID
    pub session_id: String,
    /// Customer ID
    pub customer_id: String,
    /// Subscription ID
    pub subscription_id: Option<String>,
}

/// Subscription event data
#[derive(Debug, Clone)]
pub struct SubscriptionData {
    /// Subscription ID
    pub subscription_id: String,
    /// Customer ID
    pub customer_id: String,
    /// Status
    pub status: String,
    /// Current period start
    pub period_start: DateTime<Utc>,
    /// Current period end
    pub period_end: DateTime<Utc>,
    /// Whether it cancels at period end
    pub cancel_at_period_end: bool,
}

/// Invoice event data
#[derive(Debug, Clone)]
pub struct InvoiceData {
    /// Invoice ID
    pub invoice_id: String,
    /// Customer ID
    pub customer_id: String,
    /// Subscription ID
    pub subscription_id: Option<String>,
    /// Status
    pub status: String,
    /// Amount in cents
    pub amount_cents: i64,
    /// Currency
    pub currency: String,
    /// Period start
    pub period_start: DateTime<Utc>,
    /// Period end
    pub period_end: DateTime<Utc>,
}

/// Webhook handler for processing Stripe events
#[derive(Clone)]
pub struct WebhookHandler {
    webhook_secret: String,
}

impl WebhookHandler {
    /// Create a new webhook handler
    pub fn new(webhook_secret: impl Into<String>) -> Self {
        Self {
            webhook_secret: webhook_secret.into(),
        }
    }

    /// Verify and parse a webhook payload
    #[instrument(skip(self, payload, signature))]
    pub fn verify_and_parse(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<WebhookEvent, BillingError> {
        // Verify signature
        self.verify_signature(payload, signature)?;

        // Parse event
        let raw_event: RawStripeEvent = serde_json::from_slice(payload)
            .map_err(|e| BillingError::WebhookError(e.to_string()))?;

        debug!(event_id = %raw_event.id, event_type = %raw_event.event_type, "Parsed webhook event");

        let event_type = WebhookEventType::from(raw_event.event_type.as_str());
        let data = Self::parse_event_data(&event_type, raw_event.data.object)?;

        Ok(WebhookEvent {
            id: raw_event.id,
            event_type,
            data,
            created: raw_event.created,
        })
    }

    /// Verify Stripe webhook signature
    fn verify_signature(&self, payload: &[u8], signature: &str) -> Result<(), BillingError> {
        // Parse signature header: t=timestamp,v1=signature
        let mut timestamp: Option<&str> = None;
        let mut sig_v1: Option<&str> = None;

        for part in signature.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "t" => timestamp = Some(value),
                    "v1" => sig_v1 = Some(value),
                    _ => {}
                }
            }
        }

        let timestamp = timestamp.ok_or_else(|| {
            warn!("Missing timestamp in webhook signature");
            BillingError::WebhookError("Missing timestamp".to_string())
        })?;

        let sig_v1 = sig_v1.ok_or_else(|| {
            warn!("Missing v1 signature in webhook signature");
            BillingError::WebhookError("Missing signature".to_string())
        })?;

        // Build signed payload
        let signed_payload = format!(
            "{}.{}",
            timestamp,
            std::str::from_utf8(payload)
                .map_err(|_| BillingError::WebhookError("Invalid payload encoding".to_string()))?
        );

        // Compute expected signature
        let mut mac = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| BillingError::Internal("HMAC error".to_string()))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Compare signatures (constant-time)
        if !constant_time_eq(sig_v1.as_bytes(), expected.as_bytes()) {
            error!("Webhook signature verification failed");
            return Err(BillingError::WebhookError(
                "Signature verification failed".to_string(),
            ));
        }

        // Check timestamp freshness (within 5 minutes)
        let ts: i64 = timestamp
            .parse()
            .map_err(|_| BillingError::WebhookError("Invalid timestamp format".to_string()))?;
        let now = Utc::now().timestamp();
        if (now - ts).abs() > 300 {
            warn!(timestamp = ts, now = now, "Webhook timestamp too old");
            return Err(BillingError::WebhookError("Timestamp too old".to_string()));
        }

        Ok(())
    }

    /// Parse event data based on type
    fn parse_event_data(
        event_type: &WebhookEventType,
        object: serde_json::Value,
    ) -> Result<WebhookEventData, BillingError> {
        match event_type {
            WebhookEventType::CheckoutSessionCompleted => {
                let session: RawCheckoutSession = serde_json::from_value(object)
                    .map_err(|e| BillingError::WebhookError(e.to_string()))?;
                Ok(WebhookEventData::CheckoutSession(CheckoutSessionData {
                    session_id: session.id,
                    customer_id: session.customer.unwrap_or_default(),
                    subscription_id: session.subscription,
                }))
            }
            WebhookEventType::CustomerSubscriptionCreated
            | WebhookEventType::CustomerSubscriptionUpdated
            | WebhookEventType::CustomerSubscriptionDeleted => {
                let sub: StripeSubscription = serde_json::from_value(object)
                    .map_err(|e| BillingError::WebhookError(e.to_string()))?;
                Ok(WebhookEventData::Subscription(SubscriptionData {
                    subscription_id: sub.id,
                    customer_id: sub.customer,
                    status: sub.status,
                    period_start: Utc.timestamp_opt(sub.current_period_start, 0).unwrap(),
                    period_end: Utc.timestamp_opt(sub.current_period_end, 0).unwrap(),
                    cancel_at_period_end: sub.cancel_at_period_end,
                }))
            }
            WebhookEventType::InvoicePaid | WebhookEventType::InvoicePaymentFailed => {
                let inv: StripeInvoice = serde_json::from_value(object)
                    .map_err(|e| BillingError::WebhookError(e.to_string()))?;
                Ok(WebhookEventData::Invoice(InvoiceData {
                    invoice_id: inv.id,
                    customer_id: inv.customer,
                    subscription_id: None, // Would need to parse from invoice.subscription
                    status: inv.status.unwrap_or_default(),
                    amount_cents: inv.amount_paid,
                    currency: inv.currency,
                    period_start: Utc.timestamp_opt(inv.period_start, 0).unwrap(),
                    period_end: Utc.timestamp_opt(inv.period_end, 0).unwrap(),
                }))
            }
            WebhookEventType::Unknown(_) => {
                info!("Received unknown webhook event type");
                Ok(WebhookEventData::Raw(object))
            }
        }
    }
}

/// Constant-time comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

// Raw Stripe event for parsing
#[derive(Debug, Deserialize)]
struct RawStripeEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: RawEventData,
    created: i64,
}

#[derive(Debug, Deserialize)]
struct RawEventData {
    object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RawCheckoutSession {
    id: String,
    customer: Option<String>,
    subscription: Option<String>,
}
