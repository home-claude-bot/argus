//! Rate limiting middleware using the governor crate.
//!
//! This module provides rate limiting based on user tier and custom policies.
//! Enable with the `rate-limiting` feature.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use governor::clock::{Clock, DefaultClock};
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use tokio::sync::RwLock;

use crate::context::AuthContext;
use crate::error::AuthError;
use argus_types::{Tier, UserId};

/// Key for rate limiting (user ID or IP address).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum RateLimitKey {
    /// Rate limit by user ID (authenticated).
    User(UserId),
    /// Rate limit by IP address (unauthenticated).
    Ip(IpAddr),
}

/// Rate limiter state for a single key.
type KeyedLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-user rate limiter with configurable policies.
pub struct UserRateLimiter {
    /// Per-user rate limiters.
    limiters: RwLock<HashMap<RateLimitKey, Arc<KeyedLimiter>>>,
    /// Default quotas by tier.
    tier_quotas: HashMap<Tier, Quota>,
    /// Default quota for unauthenticated requests.
    anonymous_quota: Quota,
}

impl Default for UserRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl UserRateLimiter {
    /// Create a new rate limiter with default tier quotas.
    #[must_use]
    pub fn new() -> Self {
        use std::num::NonZeroU32;

        let mut tier_quotas = HashMap::new();

        // Default quotas per tier (requests per minute with burst)
        tier_quotas.insert(
            Tier::Explorer,
            Quota::per_minute(NonZeroU32::new(10).unwrap())
                .allow_burst(NonZeroU32::new(5).unwrap()),
        );
        tier_quotas.insert(
            Tier::Professional,
            Quota::per_minute(NonZeroU32::new(60).unwrap())
                .allow_burst(NonZeroU32::new(20).unwrap()),
        );
        tier_quotas.insert(
            Tier::Business,
            Quota::per_minute(NonZeroU32::new(120).unwrap())
                .allow_burst(NonZeroU32::new(50).unwrap()),
        );
        tier_quotas.insert(
            Tier::Enterprise,
            Quota::per_minute(NonZeroU32::new(600).unwrap())
                .allow_burst(NonZeroU32::new(100).unwrap()),
        );

        Self {
            limiters: RwLock::new(HashMap::new()),
            tier_quotas,
            anonymous_quota: Quota::per_minute(NonZeroU32::new(5).unwrap())
                .allow_burst(NonZeroU32::new(2).unwrap()),
        }
    }

    /// Set a custom quota for a tier.
    #[must_use]
    pub fn with_tier_quota(mut self, tier: Tier, quota: Quota) -> Self {
        self.tier_quotas.insert(tier, quota);
        self
    }

    /// Set the anonymous request quota.
    #[must_use]
    pub fn with_anonymous_quota(mut self, quota: Quota) -> Self {
        self.anonymous_quota = quota;
        self
    }

    /// Get the quota for a given tier.
    fn quota_for_tier(&self, tier: Tier) -> Quota {
        self.tier_quotas
            .get(&tier)
            .copied()
            .unwrap_or(self.anonymous_quota)
    }

    /// Check if a request is allowed for an authenticated user.
    pub async fn check_user(&self, auth: &AuthContext) -> Result<(), AuthError> {
        let key = RateLimitKey::User(auth.user_id);
        let quota = self.quota_for_tier(auth.tier);

        self.check_key(key, quota).await
    }

    /// Check if a request is allowed for an IP address.
    pub async fn check_ip(&self, ip: IpAddr) -> Result<(), AuthError> {
        let key = RateLimitKey::Ip(ip);
        self.check_key(key, self.anonymous_quota).await
    }

    async fn check_key(&self, key: RateLimitKey, quota: Quota) -> Result<(), AuthError> {
        // Get or create rate limiter for this key
        let limiter = {
            let read_guard = self.limiters.read().await;
            if let Some(limiter) = read_guard.get(&key) {
                limiter.clone()
            } else {
                drop(read_guard);

                let mut write_guard = self.limiters.write().await;
                // Double-check after acquiring write lock
                if let Some(limiter) = write_guard.get(&key) {
                    limiter.clone()
                } else {
                    let limiter = Arc::new(RateLimiter::direct(quota));
                    write_guard.insert(key, limiter.clone());
                    limiter
                }
            }
        };

        // Check if request is allowed
        match limiter.check() {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let wait_time = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
                Err(AuthError::rate_limited(wait_time.as_secs()))
            }
        }
    }

    /// Clear rate limiters for a user (e.g., on tier upgrade).
    pub async fn clear_user(&self, user_id: UserId) {
        let key = RateLimitKey::User(user_id);
        let mut write_guard = self.limiters.write().await;
        write_guard.remove(&key);
    }

    /// Clear all rate limiters (e.g., for testing).
    pub async fn clear_all(&self) {
        let mut write_guard = self.limiters.write().await;
        write_guard.clear();
    }

    /// Get the number of active rate limiters.
    pub async fn limiter_count(&self) -> usize {
        self.limiters.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_quota() {
        let limiter = UserRateLimiter::new();

        let auth = AuthContext::new(UserId::new(), Tier::Professional);

        // Should allow several requests
        for _ in 0..20 {
            assert!(limiter.check_user(&auth).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_rejects_over_quota() {
        use std::num::NonZeroU32;

        // Very restrictive quota for testing
        let limiter = UserRateLimiter::new().with_tier_quota(
            Tier::Explorer,
            Quota::per_minute(NonZeroU32::new(2).unwrap()),
        );

        let auth = AuthContext::new(UserId::new(), Tier::Explorer);

        // First two should succeed
        assert!(limiter.check_user(&auth).await.is_ok());
        assert!(limiter.check_user(&auth).await.is_ok());

        // Third should fail
        let result = limiter.check_user(&auth).await;
        assert!(matches!(result, Err(AuthError::RateLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_clear_user() {
        let limiter = UserRateLimiter::new();

        let user_id = UserId::new();
        let auth = AuthContext::new(user_id, Tier::Professional);

        // Make a request to create a limiter
        assert!(limiter.check_user(&auth).await.is_ok());
        assert_eq!(limiter.limiter_count().await, 1);

        // Clear the user
        limiter.clear_user(user_id).await;
        assert_eq!(limiter.limiter_count().await, 0);
    }
}
