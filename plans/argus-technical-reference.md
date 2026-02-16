# Argus Technical Reference

> **Status**: Planning | **Created**: 2026-02-16 | **Author**: Boss Bot
> **Purpose**: Deep technical specifications, API contracts, crate architecture
> **Reading Time**: 30 minutes

---

## Crate Architecture

### Workspace Structure

```toml
# Cargo.toml (workspace root)
[workspace]
resolver = "2"
members = [
    "crates/argus-types",
    "crates/argus-db",
    "crates/argus-auth-core",
    "crates/argus-billing-core",
    "crates/argus-proto",
    "crates/argus-mcp",
    "crates/argus-client",
    "crates/argus-utils",
    "services/auth-api",
    "services/billing-api",
    "services/mcp-server",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["Bot Army <bots@example.com>"]
license = "MIT"
repository = "https://github.com/ahenry0125/argus"

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Web frameworks
axum = "0.8"
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "trace", "compression-gzip"] }

# gRPC
tonic = "0.13"
prost = "0.13"

# GraphQL
async-graphql = "7"

# MCP (Model Context Protocol)
rmcp = { version = "0.8", features = ["server", "macros", "transport-io", "transport-sse-server"] }
async-graphql-axum = "7"

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono", "json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Validation
validator = { version = "0.19", features = ["derive"] }

# Error handling
thiserror = "2"
anyhow = "1"

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
metrics = "0.24"

# AWS
aws-sdk-cognitoidentityprovider = "1"
aws-config = "1"

# Payments
stripe-rust = "27"

# Utilities
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
dotenvy = "0.15"
config = "0.15"
```

### Dependency Graph

```
                    argus-types
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
       argus-db     argus-utils   argus-proto
            │            │            │
    ┌───────┴───────┐    │            │
    ▼               ▼    │            │
argus-auth-core  argus-billing-core  │
    │               │                 │
    └───────┬───────┴─────────────────┘
            ▼
      argus-client
            │
    ┌───────┴───────┐
    ▼               ▼
auth-api      billing-api
```

---

## Crate Specifications

### argus-types

Zero-dependency domain types. No I/O, no async.

```rust
// crates/argus-types/src/lib.rs

pub mod user;
pub mod tier;
pub mod subscription;
pub mod billing;
pub mod auth;

// Re-exports
pub use user::*;
pub use tier::*;
pub use subscription::*;
pub use billing::*;
pub use auth::*;
```

**Key Types:**

```rust
// User identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub cognito_sub: String,
    pub email: String,
    pub tier: Tier,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Tier system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Explorer,
    Professional,
    Business,
    Enterprise,
}

impl Tier {
    pub fn rate_limit(&self) -> u32 {
        match self {
            Tier::Explorer => 100,
            Tier::Professional => 1_000,
            Tier::Business => 10_000,
            Tier::Enterprise => 100_000,
        }
    }
}

// Subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub user_id: UserId,
    pub tier: Tier,
    pub status: SubscriptionStatus,
    pub stripe_subscription_id: Option<String>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Trialing,
}
```

### argus-db

Database layer with SQLx compile-time checked queries.

```rust
// crates/argus-db/src/lib.rs

pub mod pool;
pub mod repositories;
pub mod migrations;

pub use pool::DbPool;
pub use repositories::*;

// Repository trait pattern
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn get_by_id(&self, id: &UserId) -> Result<Option<User>, DbError>;
    async fn get_by_cognito_sub(&self, sub: &str) -> Result<Option<User>, DbError>;
    async fn create(&self, user: &NewUser) -> Result<User, DbError>;
    async fn update_tier(&self, id: &UserId, tier: Tier) -> Result<(), DbError>;
}

// PostgreSQL implementation
pub struct PgUserRepository {
    pool: DbPool,
}

impl PgUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn get_by_id(&self, id: &UserId) -> Result<Option<User>, DbError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, cognito_sub, email, tier as "tier: Tier",
                   created_at, updated_at
            FROM auth.users
            WHERE id = $1
            "#,
            id.0
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError::from)
    }
    // ... other implementations
}
```

### argus-auth-core

Auth business logic, Cognito integration.

```rust
// crates/argus-auth-core/src/lib.rs

pub mod cognito;
pub mod session;
pub mod token;
pub mod service;
pub mod error;

pub use service::AuthService;
pub use error::AuthError;

// Auth service
pub struct AuthService<U: UserRepository> {
    cognito: CognitoClient,
    users: U,
    config: AuthConfig,
}

impl<U: UserRepository> AuthService<U> {
    pub async fn validate_token(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let claims = self.cognito.verify_token(token).await?;
        Ok(claims)
    }

    pub async fn get_user_tier(&self, user_id: &UserId) -> Result<Tier, AuthError> {
        let user = self.users.get_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;
        Ok(user.tier)
    }

    pub async fn check_entitlement(
        &self,
        user_id: &UserId,
        feature: &str,
    ) -> Result<bool, AuthError> {
        let tier = self.get_user_tier(user_id).await?;
        Ok(self.config.feature_flags.is_enabled(tier, feature))
    }
}
```

### argus-billing-core

Billing logic, payment provider abstraction.

```rust
// crates/argus-billing-core/src/lib.rs

pub mod provider;
pub mod stripe;
pub mod service;
pub mod webhook;
pub mod error;

pub use provider::PaymentProvider;
pub use service::BillingService;
pub use error::BillingError;

// Provider-agnostic abstraction
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    async fn create_checkout_session(
        &self,
        customer_id: &CustomerId,
        tier: Tier,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError>;

    async fn create_customer_portal(
        &self,
        customer_id: &CustomerId,
        return_url: &str,
    ) -> Result<PortalSession, BillingError>;

    async fn get_subscription(
        &self,
        subscription_id: &SubscriptionId,
    ) -> Result<Subscription, BillingError>;

    async fn cancel_subscription(
        &self,
        subscription_id: &SubscriptionId,
    ) -> Result<(), BillingError>;
}

// Stripe implementation
pub struct StripeProvider {
    client: stripe::Client,
    price_map: HashMap<Tier, String>,
}

#[async_trait]
impl PaymentProvider for StripeProvider {
    async fn create_checkout_session(
        &self,
        customer_id: &CustomerId,
        tier: Tier,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError> {
        let price_id = self.price_map.get(&tier)
            .ok_or(BillingError::InvalidTier)?;

        let session = stripe::CheckoutSession::create(
            &self.client,
            CreateCheckoutSession {
                customer: Some(customer_id.as_stripe_id()),
                line_items: Some(vec![CreateCheckoutSessionLineItems {
                    price: Some(price_id.clone()),
                    quantity: Some(1),
                    ..Default::default()
                }]),
                mode: Some(CheckoutSessionMode::Subscription),
                success_url: Some(success_url),
                cancel_url: Some(cancel_url),
                ..Default::default()
            }
        ).await?;

        Ok(CheckoutSession::from(session))
    }
    // ... other implementations
}
```

### argus-proto

Protocol Buffers for gRPC.

```protobuf
// crates/argus-proto/proto/auth.proto
syntax = "proto3";
package argus.auth.v1;

service AuthService {
    rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
    rpc GetUser(GetUserRequest) returns (GetUserResponse);
    rpc GetUserTier(GetUserTierRequest) returns (GetUserTierResponse);
    rpc CheckEntitlement(CheckEntitlementRequest) returns (CheckEntitlementResponse);
}

message ValidateTokenRequest {
    string token = 1;
}

message ValidateTokenResponse {
    string user_id = 1;
    string email = 2;
    Tier tier = 3;
    int64 expires_at = 4;
}

message GetUserTierRequest {
    string user_id = 1;
}

message GetUserTierResponse {
    Tier tier = 1;
    int32 rate_limit = 2;
}

message CheckEntitlementRequest {
    string user_id = 1;
    string feature = 2;
}

message CheckEntitlementResponse {
    bool allowed = 1;
    string reason = 2;
}

enum Tier {
    TIER_UNSPECIFIED = 0;
    TIER_EXPLORER = 1;
    TIER_PROFESSIONAL = 2;
    TIER_BUSINESS = 3;
    TIER_ENTERPRISE = 4;
}
```

```protobuf
// crates/argus-proto/proto/billing.proto
syntax = "proto3";
package argus.billing.v1;

service BillingService {
    rpc GetSubscription(GetSubscriptionRequest) returns (GetSubscriptionResponse);
    rpc CheckQuota(CheckQuotaRequest) returns (CheckQuotaResponse);
    rpc RecordUsage(RecordUsageRequest) returns (RecordUsageResponse);
    rpc GetCustomer(GetCustomerRequest) returns (GetCustomerResponse);
}

message CheckQuotaRequest {
    string user_id = 1;
    string resource = 2;
    int64 requested = 3;
}

message CheckQuotaResponse {
    bool allowed = 1;
    int64 remaining = 2;
    int64 reset_at = 3;
}

message RecordUsageRequest {
    string user_id = 1;
    string metric = 2;
    int64 quantity = 3;
    map<string, string> metadata = 4;
}

message RecordUsageResponse {
    bool success = 1;
    int64 total_usage = 2;
}
```

### argus-client

SDK for service consumers.

```rust
// crates/argus-client/src/lib.rs

pub mod auth;
pub mod billing;
pub mod config;
pub mod error;

pub use auth::AuthClient;
pub use billing::BillingClient;
pub use config::ClientConfig;
pub use error::ClientError;

// Auth client
pub struct AuthClient {
    grpc: AuthServiceClient<Channel>,
}

impl AuthClient {
    pub async fn new(config: &ClientConfig) -> Result<Self, ClientError> {
        let channel = Channel::from_shared(config.auth_url.clone())?
            .connect()
            .await?;
        Ok(Self {
            grpc: AuthServiceClient::new(channel),
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<TokenClaims, ClientError> {
        let response = self.grpc.clone()
            .validate_token(ValidateTokenRequest {
                token: token.to_string(),
            })
            .await?;
        Ok(response.into_inner().into())
    }

    pub async fn get_user_tier(&self, user_id: &UserId) -> Result<Tier, ClientError> {
        let response = self.grpc.clone()
            .get_user_tier(GetUserTierRequest {
                user_id: user_id.to_string(),
            })
            .await?;
        Ok(response.into_inner().tier.into())
    }

    pub async fn check_entitlement(
        &self,
        user_id: &UserId,
        feature: &str,
    ) -> Result<bool, ClientError> {
        let response = self.grpc.clone()
            .check_entitlement(CheckEntitlementRequest {
                user_id: user_id.to_string(),
                feature: feature.to_string(),
            })
            .await?;
        Ok(response.into_inner().allowed)
    }
}
```

### argus-mcp

MCP (Model Context Protocol) server implementation for LLM agent integration.

```rust
// crates/argus-mcp/src/lib.rs

pub mod server;
pub mod tools;
pub mod resources;
pub mod prompts;
pub mod auth;

pub use server::ArgusMcpServer;

// MCP server combining auth and billing tools
use rmcp::{ServerHandler, ServiceExt, model::*};
use rmcp::handler::server::tool::ToolRouter;

pub struct ArgusMcpServer {
    auth_service: Arc<AuthService>,
    billing_service: Arc<BillingService>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ArgusMcpServer {
    /// Validate a JWT or session token
    #[tool(description = "Validate a JWT or session token and return user info")]
    async fn validate_token(
        &self,
        #[arg(description = "The JWT or session token to validate")]
        token: String,
    ) -> Result<String, ToolError> {
        let claims = self.auth_service.validate_token(&token).await
            .map_err(|e| ToolError::new(e.to_string()))?;
        Ok(serde_json::to_string(&claims)?)
    }

    /// Get user's subscription tier
    #[tool(description = "Get the subscription tier for a user")]
    async fn get_user_tier(
        &self,
        #[arg(description = "The user ID to look up")]
        user_id: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let tier = self.auth_service.get_user_tier(&user_id).await?;
        Ok(serde_json::to_string(&TierInfo {
            tier,
            rate_limit: tier.rate_limit(),
            features: tier.features().to_vec(),
        })?)
    }

    /// Check if user has access to a feature
    #[tool(description = "Check if a user has access to a specific feature based on their tier")]
    async fn check_entitlement(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
        #[arg(description = "The feature to check (e.g., 'advanced_predictions', 'webhooks')")]
        feature: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let allowed = self.auth_service.check_entitlement(&user_id, &feature).await?;
        Ok(serde_json::to_string(&EntitlementResult { allowed, feature })?)
    }

    /// Record API usage for billing
    #[tool(description = "Record API usage for a user (for metered billing)")]
    async fn record_usage(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
        #[arg(description = "The metric name (e.g., 'api_calls', 'predictions')")]
        metric: String,
        #[arg(description = "The quantity to record")]
        quantity: i64,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let result = self.billing_service.record_usage(&user_id, &metric, quantity).await?;
        Ok(serde_json::to_string(&result)?)
    }

    /// Create a checkout session for subscription upgrade
    #[tool(description = "Create a Stripe checkout session for a tier upgrade")]
    async fn create_checkout(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
        #[arg(description = "Target tier: explorer, professional, business, enterprise")]
        tier: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let tier = Tier::from_str(&tier)?;
        let session = self.billing_service.create_checkout(&user_id, tier).await?;
        Ok(serde_json::to_string(&session)?)
    }

    /// Get current subscription status
    #[tool(description = "Get current subscription status for a user")]
    async fn get_subscription(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let subscription = self.billing_service.get_subscription(&user_id).await?;
        Ok(serde_json::to_string(&subscription)?)
    }
}

#[tool_handler]
impl ServerHandler for ArgusMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            name: "argus".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
            ..Default::default()
        }
    }

    async fn list_resources(&self) -> Result<Vec<Resource>, McpError> {
        Ok(vec![
            Resource {
                uri: "argus://config/tiers".to_string(),
                name: "Tier Configuration".to_string(),
                description: Some("Current tier definitions and pricing".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "argus://config/features".to_string(),
                name: "Feature Flags".to_string(),
                description: Some("Entitlement mappings by tier".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "argus://config/rate-limits".to_string(),
                name: "Rate Limits".to_string(),
                description: Some("Rate limit configuration by tier".to_string()),
                mime_type: Some("application/json".to_string()),
            },
        ])
    }

    async fn read_resource(&self, uri: &str) -> Result<ResourceContent, McpError> {
        match uri {
            "argus://config/tiers" => {
                Ok(ResourceContent::text(serde_json::to_string_pretty(&TierConfig::default())?))
            }
            "argus://config/features" => {
                Ok(ResourceContent::text(serde_json::to_string_pretty(&FeatureConfig::default())?))
            }
            "argus://config/rate-limits" => {
                Ok(ResourceContent::text(serde_json::to_string_pretty(&RateLimitConfig::default())?))
            }
            _ => Err(McpError::ResourceNotFound(uri.to_string())),
        }
    }

    async fn list_prompts(&self) -> Result<Vec<PromptInfo>, McpError> {
        Ok(vec![
            PromptInfo {
                name: "check-access".to_string(),
                description: Some("Check if a user can access a feature".to_string()),
                arguments: vec![
                    PromptArgument { name: "user_id".to_string(), required: true, description: Some("User ID".to_string()) },
                    PromptArgument { name: "feature".to_string(), required: true, description: Some("Feature name".to_string()) },
                ],
            },
            PromptInfo {
                name: "billing-summary".to_string(),
                description: Some("Get billing summary for a user".to_string()),
                arguments: vec![
                    PromptArgument { name: "user_id".to_string(), required: true, description: Some("User ID".to_string()) },
                ],
            },
        ])
    }
}
```

### MCP Server Binary

```rust
// services/mcp-server/src/main.rs

use argus_mcp::ArgusMcpServer;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging (stderr only - stdout is for MCP JSON-RPC)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Load configuration
    let config = Config::from_env()?;

    // Initialize services
    let db = DbPool::connect(&config.database_url).await?;
    let auth_service = Arc::new(AuthService::new(db.clone(), config.cognito.clone()));
    let billing_service = Arc::new(BillingService::new(db.clone(), config.stripe.clone()));

    // Create MCP server
    let server = ArgusMcpServer::new(auth_service, billing_service);

    // Run with STDIO transport (for local use with Claude Code)
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = server.serve(transport).await?;

    tracing::info!("Argus MCP server started");
    service.waiting().await?;

    Ok(())
}
```

### MCP Authentication for Other Servers

Argus can authenticate requests from other MCP servers:

```rust
// crates/argus-mcp/src/auth.rs

/// Middleware for authenticating MCP-to-MCP requests
pub struct McpAuthMiddleware {
    auth_service: Arc<AuthService>,
}

impl McpAuthMiddleware {
    /// Validate an MCP request contains valid credentials
    pub async fn authenticate_mcp_request(
        &self,
        request: &McpRequest,
    ) -> Result<McpIdentity, AuthError> {
        // Extract token from MCP request metadata
        let token = request.metadata()
            .get("authorization")
            .ok_or(AuthError::MissingToken)?;

        // Validate token
        let claims = self.auth_service.validate_token(token).await?;

        // Check MCP-specific scopes
        if !claims.scopes.contains("mcp:invoke") {
            return Err(AuthError::InsufficientScope);
        }

        Ok(McpIdentity {
            user_id: claims.sub,
            tier: claims.tier,
            scopes: claims.scopes,
        })
    }
}

/// Identity information for authenticated MCP requests
#[derive(Debug, Clone)]
pub struct McpIdentity {
    pub user_id: UserId,
    pub tier: Tier,
    pub scopes: Vec<String>,
}
```

### MCP Configuration

```json
// Example: Adding Argus MCP to Claude Code
{
  "mcp_servers": {
    "argus": {
      "command": "argus-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "${ARGUS_DATABASE_URL}",
        "COGNITO_POOL_ID": "${COGNITO_POOL_ID}",
        "STRIPE_SECRET_KEY": "${STRIPE_SECRET_KEY}"
      }
    }
  }
}
```

### HTTP Transport for Remote MCP

```rust
// services/mcp-server/src/http.rs

use axum::{Router, routing::post};
use rmcp::transport::sse::SseServerTransport;

/// HTTP server for remote MCP access
pub fn mcp_router(server: Arc<ArgusMcpServer>) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp_request))
        .route("/mcp/sse", get(handle_mcp_sse))
        .layer(AuthLayer::new()) // Require authentication
        .with_state(server)
}

async fn handle_mcp_request(
    State(server): State<Arc<ArgusMcpServer>>,
    auth: AuthenticatedUser,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    // Process MCP request with user context
    let response = server.handle_request(request, auth.into()).await;
    Json(response)
}
```

---

## API Specifications

### Auth API - REST Endpoints

```yaml
# OpenAPI 3.1 specification
openapi: 3.1.0
info:
  title: Argus Auth API
  version: 1.0.0

paths:
  /api/v1/auth/login:
    post:
      summary: Authenticate with Cognito
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
      responses:
        '200':
          description: Authentication successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenResponse'

  /api/v1/auth/me:
    get:
      summary: Get current user
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'

  /api/v1/auth/entitlements:
    get:
      summary: Get feature flags for current tier
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                type: object
                additionalProperties:
                  type: boolean

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        tier:
          $ref: '#/components/schemas/Tier'

    Tier:
      type: string
      enum: [explorer, professional, business, enterprise]

    TokenResponse:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        expires_in:
          type: integer

  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

### Billing API - REST Endpoints

```yaml
openapi: 3.1.0
info:
  title: Argus Billing API
  version: 1.0.0

paths:
  /api/v1/billing/checkout:
    post:
      summary: Create Stripe checkout session
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                tier:
                  $ref: '#/components/schemas/Tier'
                success_url:
                  type: string
                  format: uri
                cancel_url:
                  type: string
                  format: uri
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CheckoutSession'

  /api/v1/billing/subscription:
    get:
      summary: Get current subscription
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Subscription'

  /api/v1/billing/usage:
    get:
      summary: Get usage metrics
      security:
        - bearerAuth: []
      parameters:
        - name: start_date
          in: query
          schema:
            type: string
            format: date
        - name: end_date
          in: query
          schema:
            type: string
            format: date
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UsageReport'

  /webhooks/stripe:
    post:
      summary: Stripe webhook handler
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        '200':
          description: Webhook processed
```

---

## Database Schema

### Auth Schema

```sql
-- migrations/auth/001_initial.sql
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cognito_sub VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    tier VARCHAR(50) NOT NULL DEFAULT 'explorer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_cognito_sub ON auth.users(cognito_sub);
CREATE INDEX idx_users_email ON auth.users(email);

CREATE TABLE auth.sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id),
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id ON auth.sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON auth.sessions(expires_at);
```

### Billing Schema

```sql
-- migrations/billing/001_initial.sql
CREATE SCHEMA IF NOT EXISTS billing;

CREATE TABLE billing.customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL,
    stripe_customer_id VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_customers_user_id ON billing.customers(user_id);
CREATE INDEX idx_customers_stripe_id ON billing.customers(stripe_customer_id);

CREATE TABLE billing.subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES billing.customers(id),
    stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
    tier VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_customer ON billing.subscriptions(customer_id);
CREATE INDEX idx_subscriptions_status ON billing.subscriptions(status);

CREATE TABLE billing.usage_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    metric VARCHAR(100) NOT NULL,
    quantity BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX idx_usage_user_metric ON billing.usage_records(user_id, metric);
CREATE INDEX idx_usage_recorded_at ON billing.usage_records(recorded_at);

CREATE TABLE billing.webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL
);

CREATE INDEX idx_webhook_stripe_id ON billing.webhook_events(stripe_event_id);
```

---

## Configuration

### Environment Variables

```bash
# Auth API
AUTH_DATABASE_URL=postgres://user:pass@host/argus
AUTH_COGNITO_POOL_ID=us-east-1_xxxxx
AUTH_COGNITO_CLIENT_ID=xxxxx
AUTH_JWT_SECRET=xxxxx
AUTH_PORT=8080
AUTH_GRPC_PORT=9090

# Billing API
BILLING_DATABASE_URL=postgres://user:pass@host/argus
BILLING_STRIPE_SECRET_KEY=sk_xxxxx
BILLING_STRIPE_WEBHOOK_SECRET=whsec_xxxxx
BILLING_AUTH_SERVICE_URL=http://auth-api:9090
BILLING_PORT=8080
BILLING_GRPC_PORT=9090
```

### Feature Flags by Tier

```rust
// Defined in argus-types
impl Tier {
    pub fn features(&self) -> &'static [&'static str] {
        match self {
            Tier::Explorer => &["api_access", "basic_predictions"],
            Tier::Professional => &[
                "api_access", "basic_predictions", "advanced_predictions",
                "webhooks", "export"
            ],
            Tier::Business => &[
                "api_access", "basic_predictions", "advanced_predictions",
                "webhooks", "export", "team_management", "sla_support"
            ],
            Tier::Enterprise => &[
                "api_access", "basic_predictions", "advanced_predictions",
                "webhooks", "export", "team_management", "sla_support",
                "custom_models", "dedicated_support", "white_label"
            ],
        }
    }
}
```

---

*Next: Review [Operating Playbook](argus-operating-playbook.md) for CI/CD and deployment details.*
