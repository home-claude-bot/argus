//! Entitlement checking and rate limiting

use argus_db::UserRepository;
use argus_types::{EntitlementCheck, Feature, RateLimit, Tier, UserId};
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

use crate::AuthError;

/// Entitlement checker with caching
#[derive(Clone)]
pub struct EntitlementChecker<R: UserRepository> {
    repo: Arc<R>,
    /// Cache of user_id -> tier
    tier_cache: Cache<String, Tier>,
}

impl<R: UserRepository> EntitlementChecker<R> {
    /// Create a new entitlement checker
    pub fn new(repo: Arc<R>) -> Self {
        Self {
            repo,
            tier_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60)) // Cache tier for 1 minute
                .max_capacity(10_000)
                .build(),
        }
    }

    /// Create with custom cache duration
    pub fn with_cache_duration(repo: Arc<R>, cache_duration: Duration) -> Self {
        Self {
            repo,
            tier_cache: Cache::builder()
                .time_to_live(cache_duration)
                .max_capacity(10_000)
                .build(),
        }
    }

    /// Get user's tier
    pub async fn get_tier(&self, user_id: &UserId) -> Result<Tier, AuthError> {
        let cache_key = user_id.to_string();

        // Check cache first
        if let Some(tier) = self.tier_cache.get(&cache_key).await {
            return Ok(tier);
        }

        // Fetch from database
        let user = self
            .repo
            .find_by_id(user_id.0)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let tier: Tier = user.tier.parse().unwrap_or(Tier::Explorer);

        // Cache the result
        self.tier_cache.insert(cache_key, tier).await;

        Ok(tier)
    }

    /// Check if user has access to a feature
    pub async fn check_feature(&self, user_id: &UserId, feature: &str) -> Result<EntitlementCheck, AuthError> {
        let tier = self.get_tier(user_id).await?;

        // Check if the feature is available for this tier
        let tier_features = tier.features();
        let allowed = tier_features.contains(&feature);

        if allowed {
            Ok(EntitlementCheck {
                allowed: true,
                reason: None,
                remaining: None,
            })
        } else {
            // Find the minimum tier that has this feature
            let required_tier = find_min_tier_for_feature(feature);
            Ok(EntitlementCheck {
                allowed: false,
                reason: Some(format!(
                    "Feature '{}' requires {} tier or higher",
                    feature,
                    required_tier.map_or("unknown".to_string(), |t| t.to_string())
                )),
                remaining: None,
            })
        }
    }

    /// Check if user has access to a typed feature
    pub async fn check_typed_feature(&self, user_id: &UserId, feature: Feature) -> Result<EntitlementCheck, AuthError> {
        let tier = self.get_tier(user_id).await?;
        let min_tier = feature.min_tier();

        // Compare tier levels
        let allowed = tier_level(tier) >= tier_level(min_tier);

        if allowed {
            Ok(EntitlementCheck {
                allowed: true,
                reason: None,
                remaining: None,
            })
        } else {
            Ok(EntitlementCheck {
                allowed: false,
                reason: Some(format!(
                    "Feature '{feature}' requires {min_tier} tier or higher"
                )),
                remaining: None,
            })
        }
    }

    /// Get rate limit for user
    pub async fn get_rate_limit(&self, user_id: &UserId) -> Result<RateLimit, AuthError> {
        let tier = self.get_tier(user_id).await?;
        Ok(RateLimit::for_tier(tier))
    }

    /// Invalidate cached tier for a user
    pub async fn invalidate_tier(&self, user_id: &UserId) {
        self.tier_cache.invalidate(&user_id.to_string()).await;
    }
}

/// Find the minimum tier that has access to a feature
fn find_min_tier_for_feature(feature: &str) -> Option<Tier> {
    [Tier::Explorer, Tier::Professional, Tier::Business, Tier::Enterprise]
        .into_iter()
        .find(|tier| tier.features().contains(&feature))
}

/// Get numeric tier level for comparison
fn tier_level(tier: Tier) -> u8 {
    match tier {
        Tier::Explorer => 1,
        Tier::Professional => 2,
        Tier::Business => 3,
        Tier::Enterprise => 4,
    }
}

impl<R: UserRepository> std::fmt::Debug for EntitlementChecker<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntitlementChecker").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_level_ordering() {
        assert!(tier_level(Tier::Explorer) < tier_level(Tier::Professional));
        assert!(tier_level(Tier::Professional) < tier_level(Tier::Business));
        assert!(tier_level(Tier::Business) < tier_level(Tier::Enterprise));
    }

    #[test]
    fn test_find_min_tier_for_feature() {
        assert_eq!(find_min_tier_for_feature("api_access"), Some(Tier::Explorer));
        assert_eq!(find_min_tier_for_feature("webhooks"), Some(Tier::Professional));
        assert_eq!(find_min_tier_for_feature("team_management"), Some(Tier::Business));
        assert_eq!(find_min_tier_for_feature("custom_models"), Some(Tier::Enterprise));
        assert_eq!(find_min_tier_for_feature("nonexistent"), None);
    }
}
