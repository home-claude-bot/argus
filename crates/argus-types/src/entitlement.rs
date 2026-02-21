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
    /// User's current tier
    pub tier: Tier,
    /// Minimum tier required for this feature
    pub required_tier: Tier,
}

// =============================================================================
// LLM-Specific Entitlements (Prism integration)
// =============================================================================

/// LLM model tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmModelTier {
    /// Economy models (e.g., GPT-3.5, Claude Haiku)
    Economy,
    /// Balanced models (e.g., GPT-4o-mini, Claude Sonnet)
    Balanced,
    /// Reasoning/premium models (e.g., GPT-4o, Claude Opus)
    Reasoning,
}

impl LlmModelTier {
    /// Get the tier as a string
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Economy => "economy",
            Self::Balanced => "balanced",
            Self::Reasoning => "reasoning",
        }
    }
}

impl std::fmt::Display for LlmModelTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for LlmModelTier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "economy" => Ok(Self::Economy),
            "balanced" => Ok(Self::Balanced),
            "reasoning" => Ok(Self::Reasoning),
            _ => Err(format!("unknown LLM model tier: {s}")),
        }
    }
}

/// LLM-specific entitlements for Prism integration.
///
/// Controls access to different LLM model tiers, token budgets,
/// and rate limits for the LLM gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmEntitlements {
    /// Allowed model tiers (e.g., `economy`, `balanced`, `reasoning`)
    pub allowed_model_tiers: Vec<LlmModelTier>,
    /// Daily token budget (input + output tokens combined)
    pub daily_token_budget: u64,
    /// Requests per minute limit
    pub requests_per_minute: u32,
    /// Maximum tokens per request (input + output)
    pub max_tokens_per_request: Option<u32>,
    /// Whether streaming responses are allowed
    pub streaming_allowed: bool,
}

impl LlmEntitlements {
    /// Create entitlements for a given subscription tier.
    #[must_use]
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Explorer => Self {
                allowed_model_tiers: vec![LlmModelTier::Economy],
                daily_token_budget: 10_000,
                requests_per_minute: 10,
                max_tokens_per_request: Some(4096),
                streaming_allowed: false,
            },
            Tier::Professional => Self {
                allowed_model_tiers: vec![LlmModelTier::Economy, LlmModelTier::Balanced],
                daily_token_budget: 100_000,
                requests_per_minute: 100,
                max_tokens_per_request: Some(8192),
                streaming_allowed: true,
            },
            Tier::Business => Self {
                allowed_model_tiers: vec![
                    LlmModelTier::Economy,
                    LlmModelTier::Balanced,
                    LlmModelTier::Reasoning,
                ],
                daily_token_budget: 500_000,
                requests_per_minute: 500,
                max_tokens_per_request: Some(16384),
                streaming_allowed: true,
            },
            Tier::Enterprise => Self {
                allowed_model_tiers: vec![
                    LlmModelTier::Economy,
                    LlmModelTier::Balanced,
                    LlmModelTier::Reasoning,
                ],
                daily_token_budget: 1_000_000,
                requests_per_minute: 1000,
                max_tokens_per_request: None, // Unlimited
                streaming_allowed: true,
            },
        }
    }

    /// Check if a model tier is allowed.
    #[must_use]
    pub fn is_model_tier_allowed(&self, tier: LlmModelTier) -> bool {
        self.allowed_model_tiers.contains(&tier)
    }

    /// Check if a request would exceed the daily token budget.
    #[must_use]
    pub fn would_exceed_budget(&self, current_usage: u64, requested_tokens: u64) -> bool {
        current_usage.saturating_add(requested_tokens) > self.daily_token_budget
    }

    /// Get remaining token budget.
    #[must_use]
    pub fn remaining_budget(&self, current_usage: u64) -> u64 {
        self.daily_token_budget.saturating_sub(current_usage)
    }
}
