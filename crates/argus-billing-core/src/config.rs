//! Billing configuration

use argus_types::Tier;
use std::collections::HashMap;

/// Billing service configuration
#[derive(Debug, Clone)]
pub struct BillingConfig {
    /// Stripe secret key
    pub stripe_secret_key: String,
    /// Stripe webhook secret
    pub stripe_webhook_secret: String,
    /// Map of tiers to Stripe price IDs
    pub price_ids: HashMap<Tier, String>,
    /// Default success URL for checkout
    pub default_success_url: String,
    /// Default cancel URL for checkout
    pub default_cancel_url: String,
}

impl BillingConfig {
    /// Create a new billing config
    pub fn new(
        stripe_secret_key: impl Into<String>,
        stripe_webhook_secret: impl Into<String>,
    ) -> Self {
        Self {
            stripe_secret_key: stripe_secret_key.into(),
            stripe_webhook_secret: stripe_webhook_secret.into(),
            price_ids: HashMap::new(),
            default_success_url: "https://app.example.com/billing/success".to_string(),
            default_cancel_url: "https://app.example.com/billing/cancel".to_string(),
        }
    }

    /// Set price ID for a tier
    pub fn with_price(mut self, tier: Tier, price_id: impl Into<String>) -> Self {
        self.price_ids.insert(tier, price_id.into());
        self
    }

    /// Set default URLs
    pub fn with_urls(
        mut self,
        success_url: impl Into<String>,
        cancel_url: impl Into<String>,
    ) -> Self {
        self.default_success_url = success_url.into();
        self.default_cancel_url = cancel_url.into();
        self
    }

    /// Get price ID for a tier
    pub fn get_price_id(&self, tier: Tier) -> Option<&str> {
        self.price_ids.get(&tier).map(String::as_str)
    }
}
