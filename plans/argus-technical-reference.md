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
    "crates/argus-identity-core",
    "crates/argus-billing-core",
    "crates/argus-proto",
    "crates/argus-mcp",
    "crates/argus-client",
    "crates/argus-utils",
    "services/auth-api",
    "services/identity-api",
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
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
       argus-db         argus-utils      argus-proto
            │                │                │
    ┌───────┼───────┐        │                │
    ▼       ▼       ▼        │                │
auth-core identity billing   │                │
    │       │       │        │                │
    └───────┴───────┴────────┴────────────────┘
                    ▼
              argus-client
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
auth-api      identity-api    billing-api
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

### argus-identity-core

User lifecycle, profiles, organizations, preferences.

```rust
// crates/argus-identity-core/src/lib.rs

pub mod user;
pub mod profile;
pub mod organization;
pub mod preferences;
pub mod service;
pub mod error;

pub use service::IdentityService;
pub use error::IdentityError;

// Identity service - manages user lifecycle
pub struct IdentityService<U: UserRepository, O: OrgRepository> {
    users: U,
    orgs: O,
    config: IdentityConfig,
}

impl<U: UserRepository, O: OrgRepository> IdentityService<U, O> {
    /// Create a new user account
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, IdentityError> {
        // Validate email uniqueness
        if self.users.exists_by_email(&request.email).await? {
            return Err(IdentityError::EmailAlreadyExists);
        }

        // Create user with default profile
        let user = self.users.create(&NewUser {
            email: request.email,
            display_name: request.display_name,
            cognito_sub: request.cognito_sub,
        }).await?;

        // Create default preferences
        self.create_default_preferences(&user.id).await?;

        Ok(user)
    }

    /// Get user profile with preferences
    pub async fn get_profile(&self, user_id: &UserId) -> Result<UserProfile, IdentityError> {
        let user = self.users.get_by_id(user_id).await?
            .ok_or(IdentityError::UserNotFound)?;

        let preferences = self.get_preferences(user_id).await?;
        let org_memberships = self.get_user_orgs(user_id).await?;

        Ok(UserProfile {
            user,
            preferences,
            organizations: org_memberships,
        })
    }

    /// Update user profile
    pub async fn update_profile(
        &self,
        user_id: &UserId,
        update: UpdateProfileRequest,
    ) -> Result<UserProfile, IdentityError> {
        self.users.update(user_id, &update).await?;
        self.get_profile(user_id).await
    }

    /// Create organization with owner
    pub async fn create_organization(
        &self,
        owner_id: &UserId,
        request: CreateOrgRequest,
    ) -> Result<Organization, IdentityError> {
        // Validate org name uniqueness
        if self.orgs.exists_by_slug(&request.slug).await? {
            return Err(IdentityError::OrgSlugAlreadyExists);
        }

        let org = self.orgs.create(&NewOrg {
            name: request.name,
            slug: request.slug,
            owner_id: owner_id.clone(),
        }).await?;

        // Add owner as admin member
        self.add_org_member(&org.id, owner_id, OrgRole::Admin).await?;

        Ok(org)
    }

    /// Get organization members
    pub async fn get_org_members(
        &self,
        org_id: &OrgId,
    ) -> Result<Vec<OrgMember>, IdentityError> {
        self.orgs.get_members(org_id).await
    }

    /// Invite user to organization
    pub async fn invite_to_org(
        &self,
        org_id: &OrgId,
        email: &str,
        role: OrgRole,
    ) -> Result<OrgInvite, IdentityError> {
        // Create invite with expiry
        let invite = self.orgs.create_invite(&NewOrgInvite {
            org_id: org_id.clone(),
            email: email.to_string(),
            role,
            expires_at: Utc::now() + Duration::days(7),
        }).await?;

        // TODO: Send invite email via notification service

        Ok(invite)
    }

    /// Delete user account (soft delete with grace period)
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), IdentityError> {
        // Mark for deletion in 30 days
        self.users.mark_for_deletion(user_id, Utc::now() + Duration::days(30)).await?;

        // Remove from all orgs
        self.remove_from_all_orgs(user_id).await?;

        Ok(())
    }
}

// Domain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user: User,
    pub preferences: UserPreferences,
    pub organizations: Vec<OrgMembership>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub theme: Theme,
    pub timezone: String,
    pub locale: String,
    pub notification_settings: NotificationSettings,
    pub api_defaults: ApiDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrgId,
    pub name: String,
    pub slug: String,
    pub owner_id: UserId,
    pub tier: Tier,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
    Viewer,
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

```protobuf
// crates/argus-proto/proto/identity.proto
syntax = "proto3";
package argus.identity.v1;

service IdentityService {
    // User lifecycle
    rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
    rpc GetUser(GetUserRequest) returns (GetUserResponse);
    rpc UpdateUser(UpdateUserRequest) returns (UpdateUserResponse);
    rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);

    // Profile management
    rpc GetProfile(GetProfileRequest) returns (GetProfileResponse);
    rpc UpdateProfile(UpdateProfileRequest) returns (UpdateProfileResponse);
    rpc GetPreferences(GetPreferencesRequest) returns (GetPreferencesResponse);
    rpc UpdatePreferences(UpdatePreferencesRequest) returns (UpdatePreferencesResponse);

    // Organization management
    rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);
    rpc GetOrganization(GetOrganizationRequest) returns (GetOrganizationResponse);
    rpc GetOrgMembers(GetOrgMembersRequest) returns (GetOrgMembersResponse);
    rpc InviteToOrg(InviteToOrgRequest) returns (InviteToOrgResponse);
    rpc RemoveFromOrg(RemoveFromOrgRequest) returns (RemoveFromOrgResponse);
}

message CreateUserRequest {
    string email = 1;
    string display_name = 2;
    string cognito_sub = 3;
}

message CreateUserResponse {
    User user = 1;
}

message GetProfileRequest {
    string user_id = 1;
}

message GetProfileResponse {
    User user = 1;
    UserPreferences preferences = 2;
    repeated OrgMembership organizations = 3;
}

message UpdateProfileRequest {
    string user_id = 1;
    optional string display_name = 2;
    optional string avatar_url = 3;
    optional string bio = 4;
}

message User {
    string id = 1;
    string email = 2;
    string display_name = 3;
    string avatar_url = 4;
    Tier tier = 5;
    int64 created_at = 6;
    int64 updated_at = 7;
}

message UserPreferences {
    string theme = 1;        // "light", "dark", "system"
    string timezone = 2;     // IANA timezone
    string locale = 3;       // BCP 47 locale
    NotificationSettings notifications = 4;
}

message NotificationSettings {
    bool email_enabled = 1;
    bool slack_enabled = 2;
    bool webhook_enabled = 3;
}

message Organization {
    string id = 1;
    string name = 2;
    string slug = 3;
    string owner_id = 4;
    Tier tier = 5;
    int64 created_at = 6;
}

message OrgMembership {
    string org_id = 1;
    string org_name = 2;
    OrgRole role = 3;
    int64 joined_at = 4;
}

message OrgMember {
    string user_id = 1;
    string email = 2;
    string display_name = 3;
    OrgRole role = 4;
    int64 joined_at = 5;
}

enum OrgRole {
    ORG_ROLE_UNSPECIFIED = 0;
    ORG_ROLE_OWNER = 1;
    ORG_ROLE_ADMIN = 2;
    ORG_ROLE_MEMBER = 3;
    ORG_ROLE_VIEWER = 4;
}

message CreateOrganizationRequest {
    string name = 1;
    string slug = 2;
}

message CreateOrganizationResponse {
    Organization organization = 1;
}

message GetOrgMembersRequest {
    string org_id = 1;
}

message GetOrgMembersResponse {
    repeated OrgMember members = 1;
}

message InviteToOrgRequest {
    string org_id = 1;
    string email = 2;
    OrgRole role = 3;
}

message InviteToOrgResponse {
    string invite_id = 1;
    int64 expires_at = 2;
}
```

### argus-client

SDK for service consumers.

```rust
// crates/argus-client/src/lib.rs

pub mod auth;
pub mod identity;
pub mod billing;
pub mod config;
pub mod error;

pub use auth::AuthClient;
pub use identity::IdentityClient;
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

// Identity client
pub struct IdentityClient {
    grpc: IdentityServiceClient<Channel>,
}

impl IdentityClient {
    pub async fn new(config: &ClientConfig) -> Result<Self, ClientError> {
        let channel = Channel::from_shared(config.identity_url.clone())?
            .connect()
            .await?;
        Ok(Self {
            grpc: IdentityServiceClient::new(channel),
        })
    }

    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, ClientError> {
        let response = self.grpc.clone()
            .create_user(request)
            .await?;
        Ok(response.into_inner().user.into())
    }

    pub async fn get_profile(&self, user_id: &UserId) -> Result<UserProfile, ClientError> {
        let response = self.grpc.clone()
            .get_profile(GetProfileRequest {
                user_id: user_id.to_string(),
            })
            .await?;
        Ok(response.into_inner().into())
    }

    pub async fn update_profile(
        &self,
        user_id: &UserId,
        update: UpdateProfileRequest,
    ) -> Result<UserProfile, ClientError> {
        let response = self.grpc.clone()
            .update_profile(update.with_user_id(user_id))
            .await?;
        Ok(response.into_inner().into())
    }

    pub async fn get_org_members(&self, org_id: &OrgId) -> Result<Vec<OrgMember>, ClientError> {
        let response = self.grpc.clone()
            .get_org_members(GetOrgMembersRequest {
                org_id: org_id.to_string(),
            })
            .await?;
        Ok(response.into_inner().members.into_iter().map(Into::into).collect())
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

// MCP server combining auth, identity, and billing tools
use rmcp::{ServerHandler, ServiceExt, model::*};
use rmcp::handler::server::tool::ToolRouter;

pub struct ArgusMcpServer {
    auth_service: Arc<AuthService>,
    identity_service: Arc<IdentityService>,
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

    // === Identity Tools ===

    /// Get user profile with preferences and org memberships
    #[tool(description = "Get full user profile including preferences and organization memberships")]
    async fn get_user_profile(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let profile = self.identity_service.get_profile(&user_id).await?;
        Ok(serde_json::to_string(&profile)?)
    }

    /// Create a new user account (for autonomous onboarding)
    #[tool(description = "Create a new user account for autonomous onboarding workflows")]
    async fn create_user(
        &self,
        #[arg(description = "User email address")]
        email: String,
        #[arg(description = "Display name for the user")]
        display_name: Option<String>,
    ) -> Result<String, ToolError> {
        let user = self.identity_service.create_user(CreateUserRequest {
            email,
            display_name,
            cognito_sub: None, // Will be set on first login
        }).await?;
        Ok(serde_json::to_string(&user)?)
    }

    /// Update user preferences
    #[tool(description = "Update user preferences like theme, timezone, notifications")]
    async fn update_preferences(
        &self,
        #[arg(description = "The user ID")]
        user_id: String,
        #[arg(description = "Preferences to update as JSON")]
        preferences: String,
    ) -> Result<String, ToolError> {
        let user_id = UserId::parse(&user_id)?;
        let prefs: UserPreferences = serde_json::from_str(&preferences)?;
        let updated = self.identity_service.update_preferences(&user_id, prefs).await?;
        Ok(serde_json::to_string(&updated)?)
    }

    /// Get organization members
    #[tool(description = "List all members of an organization with their roles")]
    async fn get_org_members(
        &self,
        #[arg(description = "The organization ID")]
        org_id: String,
    ) -> Result<String, ToolError> {
        let org_id = OrgId::parse(&org_id)?;
        let members = self.identity_service.get_org_members(&org_id).await?;
        Ok(serde_json::to_string(&members)?)
    }

    // === Billing Tools ===

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
    let identity_service = Arc::new(IdentityService::new(db.clone()));
    let billing_service = Arc::new(BillingService::new(db.clone(), config.stripe.clone()));

    // Create MCP server
    let server = ArgusMcpServer::new(auth_service, identity_service, billing_service);

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

### Identity API - REST Endpoints

```yaml
openapi: 3.1.0
info:
  title: Argus Identity API
  version: 1.0.0
  description: |
    User lifecycle management, profiles, organizations, and preferences.
    Supports autonomous operations for LLM agents.

paths:
  /api/v1/users:
    post:
      summary: Create a new user
      description: Provision a new user account (for autonomous onboarding)
      security:
        - bearerAuth: []
        - mcpAuth: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'

  /api/v1/users/{user_id}:
    get:
      summary: Get user by ID
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
    delete:
      summary: Delete user (soft delete with 30-day grace period)
      security:
        - bearerAuth: []
      responses:
        '202':
          description: User marked for deletion

  /api/v1/users/{user_id}/profile:
    get:
      summary: Get full user profile with preferences and orgs
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserProfile'
    patch:
      summary: Update user profile
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateProfileRequest'
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserProfile'

  /api/v1/users/{user_id}/preferences:
    get:
      summary: Get user preferences
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserPreferences'
    put:
      summary: Update user preferences
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserPreferences'
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserPreferences'

  /api/v1/organizations:
    post:
      summary: Create a new organization
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateOrgRequest'
      responses:
        '201':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Organization'

  /api/v1/organizations/{org_id}:
    get:
      summary: Get organization details
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Organization'

  /api/v1/organizations/{org_id}/members:
    get:
      summary: List organization members
      security:
        - bearerAuth: []
      responses:
        '200':
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/OrgMember'
    post:
      summary: Invite user to organization
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/InviteRequest'
      responses:
        '201':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/OrgInvite'

  /api/v1/organizations/{org_id}/members/{user_id}:
    delete:
      summary: Remove member from organization
      security:
        - bearerAuth: []
      responses:
        '204':
          description: Member removed

components:
  schemas:
    CreateUserRequest:
      type: object
      required: [email]
      properties:
        email:
          type: string
          format: email
        display_name:
          type: string
        cognito_sub:
          type: string

    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
        display_name:
          type: string
        avatar_url:
          type: string
        tier:
          $ref: '#/components/schemas/Tier'
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time

    UserProfile:
      type: object
      properties:
        user:
          $ref: '#/components/schemas/User'
        preferences:
          $ref: '#/components/schemas/UserPreferences'
        organizations:
          type: array
          items:
            $ref: '#/components/schemas/OrgMembership'

    UserPreferences:
      type: object
      properties:
        theme:
          type: string
          enum: [light, dark, system]
        timezone:
          type: string
        locale:
          type: string
        notifications:
          $ref: '#/components/schemas/NotificationSettings'

    NotificationSettings:
      type: object
      properties:
        email_enabled:
          type: boolean
        slack_enabled:
          type: boolean
        webhook_enabled:
          type: boolean

    Organization:
      type: object
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
        slug:
          type: string
        owner_id:
          type: string
          format: uuid
        tier:
          $ref: '#/components/schemas/Tier'
        member_count:
          type: integer

    OrgMember:
      type: object
      properties:
        user_id:
          type: string
          format: uuid
        email:
          type: string
        display_name:
          type: string
        role:
          $ref: '#/components/schemas/OrgRole'
        joined_at:
          type: string
          format: date-time

    OrgRole:
      type: string
      enum: [owner, admin, member, viewer]

    CreateOrgRequest:
      type: object
      required: [name, slug]
      properties:
        name:
          type: string
        slug:
          type: string
          pattern: '^[a-z0-9-]+$'

    InviteRequest:
      type: object
      required: [email, role]
      properties:
        email:
          type: string
          format: email
        role:
          $ref: '#/components/schemas/OrgRole'
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

### Identity Schema

```sql
-- migrations/identity/001_initial.sql
CREATE SCHEMA IF NOT EXISTS identity;

-- User profiles (extended user data beyond auth)
CREATE TABLE identity.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL,  -- References auth.users
    display_name VARCHAR(255),
    avatar_url TEXT,
    bio TEXT,
    company VARCHAR(255),
    job_title VARCHAR(255),
    location VARCHAR(255),
    website_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_profiles_user_id ON identity.profiles(user_id);

-- User preferences
CREATE TABLE identity.preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL,
    theme VARCHAR(20) NOT NULL DEFAULT 'system',  -- light, dark, system
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    locale VARCHAR(20) NOT NULL DEFAULT 'en-US',
    date_format VARCHAR(20) DEFAULT 'YYYY-MM-DD',
    time_format VARCHAR(10) DEFAULT '24h',
    notification_email BOOLEAN NOT NULL DEFAULT TRUE,
    notification_slack BOOLEAN NOT NULL DEFAULT FALSE,
    notification_webhook BOOLEAN NOT NULL DEFAULT FALSE,
    api_defaults JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_preferences_user_id ON identity.preferences(user_id);

-- Organizations
CREATE TABLE identity.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    owner_id UUID NOT NULL,  -- References auth.users
    tier VARCHAR(50) NOT NULL DEFAULT 'explorer',
    description TEXT,
    logo_url TEXT,
    website_url TEXT,
    billing_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organizations_slug ON identity.organizations(slug);
CREATE INDEX idx_organizations_owner ON identity.organizations(owner_id);

-- Organization members
CREATE TABLE identity.org_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',  -- owner, admin, member, viewer
    invited_by UUID,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, user_id)
);

CREATE INDEX idx_org_members_org ON identity.org_members(org_id);
CREATE INDEX idx_org_members_user ON identity.org_members(user_id);

-- Organization invites
CREATE TABLE identity.org_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    token VARCHAR(64) UNIQUE NOT NULL,
    invited_by UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_org_invites_org ON identity.org_invites(org_id);
CREATE INDEX idx_org_invites_email ON identity.org_invites(email);
CREATE INDEX idx_org_invites_token ON identity.org_invites(token);

-- User deletion queue (soft delete with grace period)
CREATE TABLE identity.deletion_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    requested_by UUID,  -- NULL if self-requested
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deletion_queue_scheduled ON identity.deletion_queue(scheduled_at);
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

# Identity API
IDENTITY_DATABASE_URL=postgres://user:pass@host/argus
IDENTITY_AUTH_SERVICE_URL=http://auth-api:9090
IDENTITY_PORT=8081
IDENTITY_GRPC_PORT=9091
IDENTITY_DEFAULT_TIMEZONE=UTC
IDENTITY_DEFAULT_LOCALE=en-US

# Billing API
BILLING_DATABASE_URL=postgres://user:pass@host/argus
BILLING_STRIPE_SECRET_KEY=sk_xxxxx
BILLING_STRIPE_WEBHOOK_SECRET=whsec_xxxxx
BILLING_AUTH_SERVICE_URL=http://auth-api:9090
BILLING_IDENTITY_SERVICE_URL=http://identity-api:9091
BILLING_PORT=8082
BILLING_GRPC_PORT=9092
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
