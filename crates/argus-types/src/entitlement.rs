//! Entitlement and feature types

use serde::{Deserialize, Serialize};

use crate::Tier;

/// Feature identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeatureId(pub String);

impl FeatureId {
    /// Create a new feature ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for FeatureId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for FeatureId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Known features in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Basic API access
    ApiAccess,
    /// Basic prediction endpoints
    BasicPredictions,
    /// Advanced prediction features (confidence intervals, etc.)
    AdvancedPredictions,
    /// Webhook notifications
    Webhooks,
    /// Data export (CSV, JSON)
    Export,
    /// Team management (multiple users)
    TeamManagement,
    /// SLA-backed support
    SlaSupport,
    /// Custom model training
    CustomModels,
    /// Dedicated support channel
    DedicatedSupport,
    /// White-label branding
    WhiteLabel,
}

impl Feature {
    /// Get the feature ID string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApiAccess => "api_access",
            Self::BasicPredictions => "basic_predictions",
            Self::AdvancedPredictions => "advanced_predictions",
            Self::Webhooks => "webhooks",
            Self::Export => "export",
            Self::TeamManagement => "team_management",
            Self::SlaSupport => "sla_support",
            Self::CustomModels => "custom_models",
            Self::DedicatedSupport => "dedicated_support",
            Self::WhiteLabel => "white_label",
        }
    }

    /// Get the minimum tier required for this feature
    pub fn min_tier(&self) -> Tier {
        match self {
            Self::ApiAccess | Self::BasicPredictions => Tier::Explorer,
            Self::AdvancedPredictions | Self::Webhooks | Self::Export => Tier::Professional,
            Self::TeamManagement | Self::SlaSupport => Tier::Business,
            Self::CustomModels | Self::DedicatedSupport | Self::WhiteLabel => Tier::Enterprise,
        }
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// User entitlement (permission to use a feature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    /// Feature being granted
    pub feature: Feature,
    /// Whether the entitlement is active
    pub active: bool,
    /// Usage limit (if applicable)
    pub limit: Option<u64>,
    /// Current usage count
    pub used: Option<u64>,
}

impl Entitlement {
    /// Check if the entitlement has remaining usage
    pub fn has_remaining(&self) -> bool {
        match (self.limit, self.used) {
            (Some(limit), Some(used)) => used < limit,
            // No limit means unlimited, or has limit but no usage yet
            (None, _) | (Some(_), None) => true,
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateLimit {
    /// Requests per time window
    pub requests: u32,
    /// Time window in seconds
    pub window_seconds: u32,
}

impl RateLimit {
    /// Create a new rate limit
    pub const fn new(requests: u32, window_seconds: u32) -> Self {
        Self {
            requests,
            window_seconds,
        }
    }

    /// Get rate limit for a tier (requests per minute)
    pub fn for_tier(tier: Tier) -> Self {
        Self::new(tier.rate_limit(), 60)
    }
}

/// Entitlement check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementCheck {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reason if denied
    pub reason: Option<String>,
    /// Remaining usage (if limited)
    pub remaining: Option<u64>,
}
