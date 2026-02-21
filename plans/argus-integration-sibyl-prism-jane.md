# Argus Integration Plan: Sibyl + andrz.io Ecosystem

## Overview

Integrate `argus-client` SDK into Sibyl and the broader andrz.io ecosystem to centralize auth, billing, and identity management.

## Feedback Incorporated

Reviews received from: **James Bot** (observability), **Prism Bot**, **Sibyl Bot**

### Key Changes from Feedback

| Source | Feedback | Action |
|--------|----------|--------|
| James | Prometheus metrics endpoint | argus-client already has metrics.rs - expose via /metrics |
| James | Tracing spans | Already implemented with `#[instrument]` |
| James | Auth event stream | Add to Phase 5 (nice-to-have) |
| James | SLO for Argus availability | Add 99.9% target to risk mitigation |
| Prism | Include rate_limits in auth context | Add to AuthContext struct |
| Prism | LLM-specific entitlements | Add `LlmEntitlements` to argus-types |
| Prism | record_llm_usage with provider/model | Add to BillingClient |
| Prism | <1ms p99 latency | Add caching layer, connection pooling |
| Prism | Streaming: auth before, usage after | Document pattern in argus-axum |
| Sibyl | CloudFront edge auth (X-Cognito-Session) | Support in argus-axum extractors |
| Sibyl | Feature flags (RequireFeature) | Add to extractors |
| Sibyl | Match extractor names exactly | RequireAuth, RequireTier, RequireFeature, MaybeAuth |
| Sibyl | Phased migration vs fresh start | **Revised**: Phased rollout with feature flag |
| Jane | TradingEntitlements + WsAuthGuard | Add trading-specific types to argus-types |
| Jane | Position limit checking | Add check_position_allowed to AuthClient |
| Jane | Trading usage dimensions | Add record_trading_usage to BillingClient |
| Jane | Fail behavior for trading | **Fail-closed** - safety critical |
| Shannon | RequireScope extractor | Add fine-grained scope checking |
| Shannon | Batch quota check | Add batch_check_entitlements |

---

## Current State

### Sibyl
- **Auth**: API keys (SHA-256 hashed), Cognito sessions (HMAC-signed), custom extractors
- **Billing**: Stripe via `PaymentProvider` trait, checkout/portal sessions
- **Rate Limiting**: Per-user/API-key via `governor` crate
- **Tech**: Axum 0.8, Rust, PostgreSQL, AppState builder pattern

### andrz.io Ecosystem
- **Prism**: LLM gateway - needs auth for API access, rate limiting per provider
- **Jane**: Trading platform - needs auth for trading sessions
- **James**: Observability - could consume auth events for audit logging

### argus-client SDK (Ready)
- `AuthClient`: validate_token, check_entitlement, get_rate_limit, create_session
- `BillingClient`: get_subscription, create_checkout_session, record_usage
- `IdentityClient`: get_user, validate_api_key, create_api_key
- Connection pooling, retry middleware, TLS, metrics

### API Enhancements Needed (from feedback)

**AuthClient additions:**
```rust
// Return rate limits with auth context (Prism request)
pub struct AuthContextWithLimits {
    pub user_id: String,
    pub tier: Tier,
    pub features: Vec<String>,  // Sibyl: arbitrary feature entitlements
    pub rate_limits: RateLimitPolicy,  // Prism: avoid extra RPC
    pub remaining_quota: Option<QuotaStatus>,  // Prism: combined call
}

// LLM-specific entitlements (Prism)
pub struct LlmEntitlements {
    pub allowed_model_tiers: Vec<String>,  // "economy", "balanced", "reasoning"
    pub daily_token_budget: u64,
    pub requests_per_minute: u32,
}
```

**BillingClient additions:**
```rust
// LLM usage tracking with provider/model dimensions (Prism)
pub async fn record_llm_usage(&self, event: LlmUsageEvent) -> Result<()>;

pub struct LlmUsageEvent {
    pub user_id: String,
    pub provider: String,     // "openai", "anthropic"
    pub model: String,        // "gpt-4o", "claude-3-5-sonnet"
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub latency_ms: u64,
    pub cost_usd: f64,
}

// Batch usage recording for throughput (Prism)
pub async fn batch_record_usage(&self, events: Vec<UsageEvent>) -> Result<()>;
```

**Observability (James):**
- Metrics already in `argus-client/src/metrics.rs`
- Need to expose via `/metrics` endpoint or `metrics()` method
- Tracing spans already implemented via `#[instrument]`

**Trading-Specific (Jane):**
```rust
// Trading entitlements
pub struct TradingEntitlements {
    pub allowed_exchanges: Vec<String>,      // "binance_us", "coinbase"
    pub allowed_order_types: Vec<String>,    // "market", "limit", "stop"
    pub max_position_size_usd: f64,
    pub daily_loss_limit_usd: f64,
    pub paper_trading_only: bool,
    pub historical_data_depth_days: u32,
    pub realtime_symbols_limit: u32,
}

// Trading usage tracking
pub struct TradingUsageEvent {
    pub user_id: String,
    pub exchange: String,
    pub symbol: String,
    pub event_type: TradingEventType,  // Trade, DataStream, Backtest
    pub quantity: f64,
    pub value_usd: f64,
    pub data_bytes: u64,
    pub compute_seconds: f64,
}

// Position limit checking (risk management)
pub async fn check_position_allowed(
    &self, user_id: &str, symbol: &str, quantity: f64, side: OrderSide
) -> Result<PositionCheckResult>;
```

**WebSocket Auth (Jane):**
```rust
// For persistent WS connections (trading, market data)
pub struct WsAuthGuard {
    auth: AuthContext,
    connection_id: String,
    heartbeat_interval: Duration,
}

// Server can revoke mid-session (emergency kill switch)
pub async fn check_session_valid(&self, connection_id: &str) -> bool;
```

**Fine-Grained Scopes (Shannon/future):**
```rust
// RequireScope extractor for permissions like "shannon:read", "prism:admin"
pub struct RequireScope { context: AuthContext, required: Vec<String> }

// Batch entitlement check (single RPC for multiple features)
pub async fn batch_check_entitlements(
    &self, user_id: &str, features: &[&str]
) -> Result<HashMap<String, bool>>;
```

---

## Integration Strategy: Hybrid Wrapper Approach

**Rationale**: Keep existing Sibyl traits/interfaces, implement them using argus-client. This allows:
1. Incremental migration (feature flag controlled)
2. Backward compatibility during transition
3. Fallback to local auth if Argus is unavailable

---

## Phase 1: Sibyl Auth Integration (ARGUS-16)

### 1.1 Add argus-client dependency

**File**: `/data/ai/repos/sibyl/Cargo.toml`
```toml
[dependencies]
argus-client = { path = "../argus/crates/argus-client" }
```

### 1.2 Create Argus-backed AuthProvider

**New File**: `/data/ai/repos/sibyl/src/auth/argus_provider.rs`

```rust
pub struct ArgusAuthProvider {
    client: ArgusClient,
    fallback: Option<Arc<dyn LocalAuthProvider>>,
}

impl ArgusAuthProvider {
    pub async fn validate_api_key(&self, key: &str) -> Result<AuthContext, AuthError> {
        match self.client.auth().validate_api_key(key).await {
            Ok(result) => Ok(result.into()),
            Err(e) if e.is_retryable() && self.fallback.is_some() => {
                // Fallback to local validation
                self.fallback.as_ref().unwrap().validate_api_key(key).await
            }
            Err(e) => Err(e.into()),
        }
    }
}
```

### 1.3 Integrate into AppState

**File**: `/data/ai/repos/sibyl/src/lib.rs`

Add `argus_client: Option<ArgusClient>` to AppState, inject via builder.

### 1.4 Update Auth Extractors

**File**: `/data/ai/repos/sibyl/src/auth/extractors.rs`

Modify `RequireAuth` to optionally consult argus-client for policy decisions.

### 1.5 Configuration

**File**: `/data/ai/repos/sibyl/src/config.rs`

```rust
pub struct ArgusConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub api_token: SecretString,
    pub fallback_to_local: bool,
}
```

Environment variables:
- `ARGUS_ENABLED=true`
- `ARGUS_ENDPOINT=https://auth.argus.io`
- `ARGUS_API_TOKEN=sk_live_...`
- `ARGUS_FALLBACK_TO_LOCAL=true`

---

## Phase 2: Sibyl Billing Integration

### 2.1 Create Argus-backed PaymentProvider

**New File**: `/data/ai/repos/sibyl/src/billing/argus_provider.rs`

Implement `PaymentProvider` trait using `BillingClient`:

```rust
impl PaymentProvider for ArgusPaymentProvider {
    async fn create_checkout_session(&self, req: CheckoutRequest) -> BillingResult<CheckoutSession> {
        self.client.billing()
            .create_checkout_session(&req.user_id, &req.price_id, req.urls.into())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn get_subscription(&self, customer_id: &CustomerId) -> BillingResult<Option<Subscription>> {
        self.client.billing()
            .get_subscription(&customer_id.into())
            .await
            .map(|s| Some(s.into()))
            .map_err(Into::into)
    }
}
```

### 2.2 Wire into BillingService

**File**: `/data/ai/repos/sibyl/src/billing/service.rs`

Add constructor that accepts `ArgusPaymentProvider` or `StripeProvider`.

---

## Phase 3: Rate Limiting via Argus

### 3.1 Enhance Rate Limit Middleware

**File**: `/data/ai/repos/sibyl/src/infra/rate_limit.rs`

Before local rate limit check, query Argus for user's current limits:

```rust
if let Some(argus) = &state.argus_client {
    let rate_limit = argus.auth().get_rate_limit(&user_id).await?;
    // Use Argus-provided limits instead of hardcoded tiers
}
```

### 3.2 Usage Recording

After successful requests, fire-and-forget usage recording:

```rust
tokio::spawn(async move {
    let _ = argus.billing().record_usage(&user_id, "predictions", 1).await;
});
```

---

## Phase 4: andrz.io Ecosystem Integration

### 4.1 Prism Integration

**File**: `/data/ai/repos/prism/crates/prism-gateway/src/middleware/auth.rs`

Add argus-client for:
- API key validation before routing to LLM providers
- Usage tracking per provider/model
- Rate limiting based on subscription tier

### 4.2 Shared Integration Crate (Optional)

Create `/data/ai/repos/argus/crates/argus-axum` with:
- Axum middleware for auth extraction
- Standard extractors (`ArgusAuth`, `RequireArgusAuth`)
- Rate limit middleware
- Usage tracking middleware

This would be shared across Sibyl, Prism, and future services.

---

## File Changes Summary

### Sibyl (Phase 1-3)

| File | Change |
|------|--------|
| `Cargo.toml` | Add argus-client dependency |
| `src/config.rs` | Add ArgusConfig struct |
| `src/auth/mod.rs` | Export argus_provider |
| `src/auth/argus_provider.rs` | **NEW** - Argus-backed auth |
| `src/auth/extractors.rs` | Optional Argus consultation |
| `src/billing/argus_provider.rs` | **NEW** - Argus-backed billing |
| `src/billing/service.rs` | Support ArgusPaymentProvider |
| `src/infra/rate_limit.rs` | Argus rate limit queries |
| `src/lib.rs` | Add argus_client to AppState |

### Prism (Phase 4)

| File | Change |
|------|--------|
| `Cargo.toml` | Add argus-client dependency |
| `src/config.rs` | Add ArgusConfig |
| `src/middleware/auth.rs` | Argus validation |

---

## Decisions (Updated per Feedback)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Fallback behavior | **Fail closed** for billing, **fail-open with cache** for auth | Prism: brief outages shouldn't block cached tokens |
| Migration strategy | **Phased rollout** - Feature flag, not fresh start | Sibyl: avoid user churn for existing users |
| Shared crate | **Yes** - Create `argus-axum` for common middleware | All bots agreed |
| Priority | **Sibyl first**, then Prism | Unchanged |
| Latency target | **<1ms p99** for auth validation | Prism: critical requirement |
| SLO target | **99.9% availability** for Argus | James: monitoring requirement |

---

## Revised Implementation Plan

### Step 1: Create argus-axum shared crate

**New crate**: `/data/ai/repos/argus/crates/argus-axum/`

**Extractors** (matching Sibyl's naming per feedback):
```rust
// Core extractors
pub struct MaybeAuth(pub Option<AuthContext>);  // Optional auth
pub struct RequireAuth(pub AuthContext);         // 401 if not authenticated
pub struct RequireTier { context: AuthContext, required: Tier }  // 403 if tier insufficient
pub struct RequireFeature { context: AuthContext, feature: String }  // Feature flag check
pub struct RequireAdmin(pub AuthContext);        // Admin-only

// Auth context (includes rate limits per Prism feedback)
pub struct AuthContext {
    pub user_id: String,
    pub tier: Tier,
    pub role: Role,
    pub features: Vec<String>,
    pub rate_limits: RateLimitPolicy,
    pub llm_entitlements: Option<LlmEntitlements>,  // Prism-specific
}
```

**Middleware**:
- `ArgusLayer` - Tower layer for Argus integration
- `RateLimitLayer` - Local enforcement via `governor`, policies from Argus
- `UsageRecordingLayer` - Fire-and-forget via `tokio::spawn`
- `MetricsLayer` - Prometheus metrics (James requirement)

**CloudFront Edge Auth** (Sibyl requirement):
```rust
// Support X-Cognito-Session header with HMAC-signed payloads
pub fn parse_cloudfront_session(headers: &HeaderMap) -> Option<SessionClaims>;
```

**Streaming Pattern** (Prism requirement):
```rust
// Auth before stream starts, usage after stream completes
pub struct StreamingAuthGuard {
    auth: AuthContext,
    usage_tracker: UsageTracker,  // Records on drop
}
```

### Step 2: Integrate Sibyl with argus-axum (ARGUS-16)

1. Add `argus-axum` dependency to Sibyl
2. Remove local auth module (or keep as dead code temporarily)
3. Replace extractors with argus-axum extractors
4. Remove local billing, use `BillingClient` directly
5. Update AppState to require `ArgusClient`
6. Update all API handlers to use new extractors

### Step 3: Integrate Prism with argus-axum

1. Add `argus-axum` dependency
2. Add auth middleware to API routes
3. Implement per-provider rate limiting via Argus tiers
4. Record usage per LLM provider/model

---

## JIRA Tickets to Create

### argus-client Enhancements (from feedback)

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| ARGUS-24 | Add LlmEntitlements and record_llm_usage to BillingClient | 2 pts | Prism |
| ARGUS-25 | Add batch_record_usage for throughput | 1 pt | Prism |
| ARGUS-26 | Add auth caching layer (<1ms p99 target) | 2 pts | Prism |
| ARGUS-27 | Expose Prometheus metrics endpoint | 1 pt | James |

### argus-axum Shared Crate

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| ARGUS-21 | Create argus-axum shared crate | 3 pts | Plan |
| ARGUS-28 | Add CloudFront edge auth support (X-Cognito-Session) | 2 pts | Sibyl |
| ARGUS-29 | Add streaming auth guard pattern | 1 pt | Prism |

### Integration

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| ARGUS-16 | Integrate Sibyl with argus-axum | 5 pts | Plan |
| ARGUS-22 | Phased migration: feature flag for Argus auth | 2 pts | Sibyl |
| ARGUS-23 | Integrate Prism with argus-axum | 3 pts | Plan |

### Observability (James)

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| JAMES-8 | Create Argus health/latency dashboard in Grafana | 2 pts | James |
| JAMES-9 | Add Argus availability alerting (99.9% SLO) | 1 pt | James |

### Trading Platform (Jane)

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| ARGUS-30 | Add TradingEntitlements to argus-types | 2 pts | Jane |
| ARGUS-31 | Add record_trading_usage to BillingClient | 2 pts | Jane |
| ARGUS-32 | Add WsAuthGuard pattern to argus-axum | 2 pts | Jane |
| ARGUS-33 | Add position limit checking to AuthClient | 3 pts | Jane |
| JANE-XX | Integrate Jane with argus-axum | 5 pts | Jane |

### Future/Extensibility (Shannon)

| Ticket | Summary | Estimate | Source |
|--------|---------|----------|--------|
| ARGUS-34 | Add RequireScope extractor to argus-axum | 1 pt | Shannon |
| ARGUS-35 | Add batch_check_entitlements to AuthClient | 2 pts | Shannon |

---

## Key Files to Modify

### New Files
- `/data/ai/repos/argus/crates/argus-axum/src/lib.rs`
- `/data/ai/repos/argus/crates/argus-axum/src/extractors.rs`
- `/data/ai/repos/argus/crates/argus-axum/src/middleware.rs`
- `/data/ai/repos/argus/crates/argus-axum/Cargo.toml`

### Sibyl Modifications
- `/data/ai/repos/sibyl/Cargo.toml` - Add argus-axum
- `/data/ai/repos/sibyl/src/lib.rs` - Update AppState
- `/data/ai/repos/sibyl/src/api/mod.rs` - Add Argus middleware layer
- `/data/ai/repos/sibyl/src/api/predictions.rs` - Use new extractors
- `/data/ai/repos/sibyl/src/api/billing.rs` - Use BillingClient
- `/data/ai/repos/sibyl/src/api/auth.rs` - Use IdentityClient

### Prism Modifications
- `/data/ai/repos/prism/crates/prism-gateway/Cargo.toml`
- `/data/ai/repos/prism/crates/prism-gateway/src/middleware/auth.rs`

---

## Risk Mitigation

### Revised Strategy (per Sibyl/Prism feedback)

1. **Phased rollout** (not fresh start):
   - Phase 1: Deploy argus-axum alongside existing auth (feature flag: `ARGUS_AUTH_ENABLED=false`)
   - Phase 2: Enable for new users only (`ARGUS_AUTH_NEW_USERS=true`)
   - Phase 3: Migrate existing users via sync job
   - Phase 4: Cut over to Argus-only (`ARGUS_AUTH_ENABLED=true`)

2. **Fail behavior by service**:
   | Service | Auth | Billing/Quota | Rationale |
   |---------|------|---------------|-----------|
   | Sibyl | Fail-open (cached) | Fail-closed | Predictions aren't safety-critical |
   | Prism | Fail-open (cached) | Fail-closed | LLM requests can be retried |
   | Jane | **Fail-closed** | **Fail-closed** | Trading is safety-critical (Jane feedback) |

   - Cache recent auth validations (5s TTL) for Sibyl/Prism
   - Jane requires hard fail - cannot allow unauthorized trades

3. **Latency requirements** (<1ms p99):
   - gRPC with connection pooling (already in argus-client)
   - Local auth cache with short TTL
   - `governor` for local rate limit enforcement (policies from Argus)

4. **SLO monitoring** (James feedback):
   - Target: **99.9% Argus availability**
   - Metrics: `argus_client_requests_total`, `argus_client_request_duration_seconds`
   - Alerts: Argus error rate >0.1%, latency p99 >5ms

5. **CloudFront edge auth** (Sibyl feedback):
   - Support `X-Cognito-Session` header parsing in argus-axum
   - Validate HMAC signatures server-side
   - No changes to CloudFront Lambda@Edge initially

6. **Position tracking** (Jane feedback - decision needed):
   - **Option A**: Argus tracks positions real-time (more complex, single source of truth)
   - **Option B**: Jane reports positions periodically (simpler, Jane owns state)
   - **Recommendation**: Start with Option B, migrate to A if needed

---

## Implementation Order

### Sprint 1: argus-client Enhancements
1. **ARGUS-24**: Add `LlmEntitlements` to argus-types, `record_llm_usage` to BillingClient
2. **ARGUS-25**: Add `batch_record_usage` for throughput
3. **ARGUS-26**: Add auth caching layer (in-memory, 5s TTL)
4. **ARGUS-27**: Expose Prometheus metrics endpoint

### Sprint 2: argus-axum Shared Crate
5. **ARGUS-21**: Create argus-axum crate with extractors matching Sibyl naming
6. **ARGUS-28**: Add CloudFront edge auth support
7. **ARGUS-29**: Add streaming auth guard pattern

### Sprint 3: Sibyl Integration
8. **ARGUS-16**: Integrate Sibyl with argus-axum (feature-flagged)
9. **ARGUS-22**: Phased migration tooling

### Sprint 4: Prism Integration + Observability
10. **ARGUS-23**: Integrate Prism with argus-axum
11. **JAMES-8**: Grafana dashboard for Argus
12. **JAMES-9**: Alerting for Argus SLO

### Sprint 5: Jane Trading Integration
13. **ARGUS-30**: Add TradingEntitlements to argus-types
14. **ARGUS-31**: Add record_trading_usage to BillingClient
15. **ARGUS-32**: Add WsAuthGuard pattern to argus-axum
16. **ARGUS-33**: Add position limit checking to AuthClient
17. **JANE-XX**: Integrate Jane with argus-axum

### Sprint 6: Extensibility (Future)
18. **ARGUS-34**: Add RequireScope extractor
19. **ARGUS-35**: Add batch_check_entitlements
20. Shannon integration (when/if API is exposed)

---

## Summary

Plan updated with feedback from **5 bots**: James, Prism, Sibyl, Jane, Shannon (Manager Bot)

### Key Changes
| Change | Source |
|--------|--------|
| "Fresh start" → **phased migration** | Sibyl |
| Pure "fail closed" → **fail-open for auth with cache** | Prism |
| **LLM entitlements** + usage tracking | Prism |
| **Trading entitlements** + position limits | Jane |
| **WebSocket auth pattern** (WsAuthGuard) | Jane |
| **CloudFront edge auth** support | Sibyl |
| **<1ms p99 latency** with caching | Prism |
| **99.9% SLO** + alerting | James |
| **RequireScope** for fine-grained perms | Shannon |
| **Batch entitlement checks** | Shannon |

### Ticket Count
- Original plan: 4 tickets
- After feedback: **20 tickets** across 6 sprints

### Service Integration Priority
1. **Sibyl** (Sprint 3) - Core prediction service
2. **Prism** (Sprint 4) - LLM gateway
3. **Jane** (Sprint 5) - Trading platform
4. **Shannon** (Sprint 6) - Knowledge API (future)
