//! Subscription tier types

use serde::{Deserialize, Serialize};

/// Subscription tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Free tier - $29/mo, 100 req/min
    Explorer,
    /// Pro tier - $199/mo, 1000 req/min
    Professional,
    /// Business tier - $999/mo, 10000 req/min
    Business,
    /// Enterprise tier - $4999/mo, custom limits
    Enterprise,
}

impl Tier {
    /// Get the rate limit for this tier (requests per minute)
    pub const fn rate_limit(&self) -> u32 {
        match self {
            Self::Explorer => 100,
            Self::Professional => 1_000,
            Self::Business => 10_000,
            Self::Enterprise => 100_000,
        }
    }

    /// Get the monthly price in cents
    pub const fn price_cents(&self) -> u32 {
        match self {
            Self::Explorer => 2_900,
            Self::Professional => 19_900,
            Self::Business => 99_900,
            Self::Enterprise => 499_900,
        }
    }

    /// Get features available for this tier
    pub const fn features(&self) -> &'static [&'static str] {
        match self {
            Self::Explorer => &["api_access", "basic_predictions"],
            Self::Professional => &[
                "api_access",
                "basic_predictions",
                "advanced_predictions",
                "webhooks",
                "export",
            ],
            Self::Business => &[
                "api_access",
                "basic_predictions",
                "advanced_predictions",
                "webhooks",
                "export",
                "team_management",
                "sla_support",
            ],
            Self::Enterprise => &[
                "api_access",
                "basic_predictions",
                "advanced_predictions",
                "webhooks",
                "export",
                "team_management",
                "sla_support",
                "custom_models",
                "dedicated_support",
                "white_label",
            ],
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Explorer => write!(f, "explorer"),
            Self::Professional => write!(f, "professional"),
            Self::Business => write!(f, "business"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl std::str::FromStr for Tier {
    type Err = TierParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "explorer" => Ok(Self::Explorer),
            "professional" | "pro" => Ok(Self::Professional),
            "business" => Ok(Self::Business),
            "enterprise" => Ok(Self::Enterprise),
            _ => Err(TierParseError(s.to_string())),
        }
    }
}

/// Error parsing a tier string
#[derive(Debug, Clone)]
pub struct TierParseError(pub String);

impl std::fmt::Display for TierParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid tier: {}", self.0)
    }
}

impl std::error::Error for TierParseError {}
