//! Subscription types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Tier, UserId};

/// Unique subscription identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(pub Uuid);

/// Subscription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    /// Subscription is active
    Active,
    /// Payment is past due
    PastDue,
    /// Subscription was canceled
    Canceled,
    /// In trial period
    Trialing,
}

/// User subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Subscription ID
    pub id: SubscriptionId,
    /// User who owns the subscription
    pub user_id: UserId,
    /// Current tier
    pub tier: Tier,
    /// Subscription status
    pub status: SubscriptionStatus,
    /// Stripe subscription ID (if any)
    pub stripe_subscription_id: Option<String>,
    /// Current billing period start
    pub current_period_start: DateTime<Utc>,
    /// Current billing period end
    pub current_period_end: DateTime<Utc>,
    /// When the subscription was created
    pub created_at: DateTime<Utc>,
}
