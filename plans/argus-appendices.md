# Argus Appendices

> **Status**: Planning | **Created**: 2026-02-16 | **Author**: Boss Bot
> **Purpose**: Migration guides, JIRA breakdown, resources, references
> **Reading Time**: 15 minutes

---

## Appendix A: Migration Guide from Sibyl

### Phase 1: Parallel Operation

During migration, both systems run:

```
┌─────────────────────────────────────────────────────┐
│                     Sibyl                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Auth (old)  │  │Billing (old)│  │ Predictions │ │
│  └──────┬──────┘  └──────┬──────┘  └─────────────┘ │
│         │ Feature        │ Feature                  │
│         │ Flag           │ Flag                     │
│         ▼                ▼                          │
│  ┌──────────────────────────────┐                  │
│  │      argus-client SDK        │                  │
│  └──────────────┬───────────────┘                  │
└─────────────────┼───────────────────────────────────┘
                  │ gRPC
┌─────────────────▼───────────────────────────────────┐
│                     Argus                           │
│  ┌─────────────┐  ┌─────────────┐                  │
│  │  Auth API   │  │ Billing API │                  │
│  └─────────────┘  └─────────────┘                  │
└─────────────────────────────────────────────────────┘
```

### Phase 2: Feature Flag Control

```rust
// In Sibyl's config
pub struct MigrationConfig {
    /// Use Argus for auth (vs local)
    pub use_argus_auth: bool,
    /// Use Argus for billing (vs local)
    pub use_argus_billing: bool,
    /// Percentage of traffic to route to Argus
    pub argus_traffic_percentage: u8,
}

// Usage
async fn check_auth(token: &str, config: &MigrationConfig) -> Result<User> {
    if config.use_argus_auth {
        argus_client.validate_token(token).await
    } else {
        local_auth::validate_token(token).await
    }
}
```

### Phase 3: Cutover Checklist

- [ ] All traffic routing to Argus (100%)
- [ ] Monitoring stable for 48 hours
- [ ] Rollback tested
- [ ] Old code paths disabled
- [ ] Documentation updated
- [ ] Legacy tables archived

### Phase 4: Cleanup

```bash
# Remove old auth/billing code from Sibyl
git rm -r src/auth/
git rm -r src/billing/

# Update Cargo.toml to depend on argus-client
```

---

## Appendix B: JIRA Epic & Story Breakdown

### Epic: ARGUS - Centralized Auth & Billing Platform

**Summary**: Build centralized microservices for auth and billing
**Priority**: Highest
**Labels**: `project-argus`, `milestone-q1`

### Stories

#### Story 1: Repository Setup and CI/CD
**Summary**: Initialize Argus repository with CI/CD pipeline
**Points**: 5
**Labels**: `agent-claude`, `area-infra`, `type-setup`

**Acceptance Criteria:**
- [ ] GitHub repo created at ahenry0125/argus
- [ ] ahenry125 added as admin collaborator
- [ ] Rust workspace compiles
- [ ] CI workflow runs on PR
- [ ] Branch protection enabled

---

#### Story 2: argus-types Crate
**Summary**: Implement shared domain types crate
**Points**: 3
**Labels**: `agent-claude`, `area-core`, `type-feature`

**Acceptance Criteria:**
- [ ] User, Tier, Subscription types defined
- [ ] Serde serialization working
- [ ] Unit tests for type conversions
- [ ] Documentation on public types

---

#### Story 3: argus-db Crate
**Summary**: Implement database abstraction layer
**Points**: 5
**Labels**: `agent-claude`, `area-core`, `type-feature`

**Acceptance Criteria:**
- [ ] Repository traits defined
- [ ] PostgreSQL implementations
- [ ] SQLx compile-time checks working
- [ ] Migrations for auth and billing schemas
- [ ] Integration tests

---

#### Story 4: argus-auth-core Crate
**Summary**: Extract and implement auth business logic
**Points**: 8
**Labels**: `agent-claude`, `area-auth`, `type-feature`

**Acceptance Criteria:**
- [ ] Cognito integration working
- [ ] Token validation
- [ ] Session management
- [ ] Tier/entitlement checks
- [ ] Unit and integration tests

---

#### Story 5: argus-billing-core Crate
**Summary**: Implement billing business logic
**Points**: 8
**Labels**: `agent-claude`, `area-billing`, `type-feature`

**Acceptance Criteria:**
- [ ] PaymentProvider trait defined
- [ ] Stripe implementation
- [ ] Mock provider for testing
- [ ] Subscription lifecycle management
- [ ] Unit and integration tests

---

#### Story 6: Auth API Service
**Summary**: Build auth microservice with REST/gRPC
**Points**: 8
**Labels**: `agent-claude`, `area-auth`, `type-feature`

**Acceptance Criteria:**
- [ ] REST endpoints implemented
- [ ] gRPC service implemented
- [ ] Health/ready endpoints
- [ ] Dockerfile and K8s manifests
- [ ] API documentation

---

#### Story 7: Billing API Service
**Summary**: Build billing microservice with REST/gRPC
**Points**: 8
**Labels**: `agent-claude`, `area-billing`, `type-feature`

**Acceptance Criteria:**
- [ ] REST endpoints implemented
- [ ] gRPC service implemented
- [ ] Webhook handler for Stripe
- [ ] Dockerfile and K8s manifests
- [ ] API documentation

---

#### Story 8: argus-client SDK
**Summary**: Build client SDK for service consumers
**Points**: 5
**Labels**: `agent-claude`, `area-client`, `type-feature`

**Acceptance Criteria:**
- [ ] Auth client with all operations
- [ ] Billing client with all operations
- [ ] Connection pooling/retry logic
- [ ] Documentation and examples

---

#### Story 9: Sibyl Integration
**Summary**: Integrate Sibyl with Argus services
**Points**: 5
**Labels**: `agent-claude`, `area-integration`, `type-feature`

**Acceptance Criteria:**
- [ ] Sibyl depends on argus-client
- [ ] Feature flags for migration
- [ ] All auth calls routed to Argus
- [ ] All billing calls routed to Argus
- [ ] Tests passing

---

#### Story 10: Nimbus Deployment
**Summary**: Deploy Argus to AWS via Terraform
**Points**: 5
**Labels**: `agent-claude`, `area-infra`, `type-feature`

**Acceptance Criteria:**
- [ ] Terraform modules in Nimbus
- [ ] EKS deployment working
- [ ] RDS database provisioned
- [ ] Secrets management configured
- [ ] Staging environment live

---

#### Story 11: Production Migration
**Summary**: Complete production cutover and cleanup
**Points**: 3
**Labels**: `agent-claude`, `area-infra`, `type-feature`

**Acceptance Criteria:**
- [ ] Production deployment successful
- [ ] Monitoring and alerting configured
- [ ] Legacy code removed from Sibyl
- [ ] Documentation updated
- [ ] Runbooks in place

---

#### Story 12: MCP Server Implementation
**Summary**: Implement MCP (Model Context Protocol) server for LLM agent integration
**Points**: 8
**Labels**: `agent-claude`, `area-mcp`, `type-feature`

**Acceptance Criteria:**
- [ ] argus-mcp crate with tools, resources, prompts
- [ ] STDIO transport for local Claude Code integration
- [ ] HTTP/SSE transport for remote access
- [ ] MCP-to-MCP authentication middleware
- [ ] Unit and integration tests
- [ ] Documentation for MCP tools

**Tools to Expose:**
- `validate_token` - Verify JWT/session tokens
- `get_user_tier` - Get subscription tier
- `check_entitlement` - Verify feature access
- `record_usage` - Track API consumption
- `create_checkout` - Generate payment session
- `get_subscription` - Get subscription status

**Resources to Expose:**
- `argus://config/tiers` - Tier definitions
- `argus://config/features` - Feature flag mappings
- `argus://config/rate-limits` - Rate limit config

---

#### Story 13: Auth Performance Optimization
**Summary**: Optimize auth system for low latency and high throughput
**Points**: 5
**Labels**: `agent-claude`, `area-auth`, `type-performance`
**Migrated From**: SYBIL-44

**Acceptance Criteria:**
- [ ] Token validation < 10ms p99
- [ ] Connection pooling for Cognito
- [ ] In-memory caching for frequently accessed data
- [ ] Benchmarks and load tests
- [ ] X-Ray tracing integration

---

#### Story 14: Auth Testing Maturity
**Summary**: Comprehensive testing for auth system
**Points**: 5
**Labels**: `agent-claude`, `area-auth`, `type-testing`
**Migrated From**: SYBIL-43

**Acceptance Criteria:**
- [ ] 80%+ unit test coverage on auth-core
- [ ] Integration tests for all auth flows
- [ ] Security test suite (OWASP checks)
- [ ] CI enforcement of test requirements

---

#### Story 15: OAuth Provider UI
**Summary**: Add OAuth provider buttons to dashboard
**Points**: 3
**Labels**: `agent-claude`, `area-ui`, `type-feature`
**Migrated From**: SYBIL-49

**Acceptance Criteria:**
- [ ] Google OAuth button
- [ ] GitHub OAuth button
- [ ] Consistent styling with dashboard

---

### Sibyl Auth Ticket Migration

The following Sibyl tickets are being migrated to Argus:

| Sibyl Key | Argus Story | Status |
|-----------|-------------|--------|
| SYBIL-57 | Auth System Enhancements → Core Argus implementation | Superseded |
| SYBIL-44 | Auth Performance → Story 13 | Migrated |
| SYBIL-43 | Auth Testing → Story 14 | Migrated |
| SYBIL-49 | OAuth UI → Story 15 | Migrated |
| SYBIL-60 | M2M Auth → Story 12 (MCP) | Migrated |

**Action Items:**
1. Close SYBIL-57 with note pointing to ARGUS epic
2. Move SYBIL-44, 43, 49, 60 to ARGUS project (or close with links)
3. Update Sibyl roadmap to remove auth/billing work

---

## Appendix C: Technology Decisions

### ADR-001: Rust for Services

**Status**: Accepted
**Context**: Need to choose language for microservices
**Decision**: Use Rust
**Rationale**:
- Existing expertise in team
- Performance characteristics for auth/billing
- Compile-time safety
- Excellent async support (tokio)

### ADR-002: Multi-Protocol APIs

**Status**: Accepted
**Context**: Different consumers have different needs
**Decision**: Support REST, gRPC, GraphQL
**Rationale**:
- REST: Easy for external consumers
- gRPC: Efficient for service-to-service
- GraphQL: Flexible for dashboard queries

### ADR-003: Shared Database

**Status**: Accepted
**Context**: How to handle database for microservices
**Decision**: Single database with schema separation
**Rationale**:
- Simpler operations initially
- Schema isolation provides boundaries
- Can split later if needed

### ADR-004: MCP Protocol Support

**Status**: Accepted
**Context**: Need to enable LLM agents to interact with auth/billing
**Decision**: Implement MCP server using rmcp SDK
**Rationale**:
- Standard protocol adopted by Anthropic, OpenAI, and ecosystem
- Enables Claude Code and other LLM agents to authenticate users
- Provides M2M authentication for other MCP servers
- JSON-RPC based, well-documented specification
- STDIO transport for local, HTTP/SSE for remote

**MCP Use Cases:**
1. **LLM Agent Auth** - Agents validate tokens before taking protected actions
2. **Tier-Aware Behavior** - Agents check entitlements to adjust responses
3. **Usage Metering** - Automatic consumption tracking for billing
4. **MCP Gateway** - Authenticate requests from other MCP servers

### ADR-005: Sibyl Auth Migration

**Status**: Accepted
**Context**: Sibyl has auth-related work in progress (SYBIL-43,44,49,57,60)
**Decision**: Migrate auth work to Argus rather than completing in Sibyl
**Rationale**:
- Avoids duplicate implementation
- Consolidates auth expertise in Argus
- Sibyl becomes consumer of Argus via argus-client
- Performance/testing work applies to centralized service

---

## Appendix D: Resources

### Documentation Links

| Resource | URL |
|----------|-----|
| Axum | https://docs.rs/axum |
| Tonic (gRPC) | https://docs.rs/tonic |
| SQLx | https://docs.rs/sqlx |
| async-graphql | https://docs.rs/async-graphql |
| stripe-rust | https://docs.rs/stripe-rust |
| AWS SDK | https://docs.aws.amazon.com/sdk-for-rust |

### Confluence Pages

| Page | Space | Purpose |
|------|-------|---------|
| Argus Overview | ARGUS | Main landing page |
| Architecture Decisions | ARGUS | ADRs |
| API Documentation | ARGUS | OpenAPI specs |
| Runbooks | ARGUS | Operational guides |

### JIRA Queries

```jql
# All Argus issues
project = ARGUS

# In-progress work
project = ARGUS AND status = "In Progress"

# Ready for review
project = ARGUS AND status = "In Review"

# Blocked issues
project = ARGUS AND labels = blocked
```

---

## Appendix E: Sibyl Plan Updates

The following updates are needed in Sibyl's plans:

### sibyl-executive-brief.md

Add note in Architecture section:
```markdown
### Service Dependencies

Sibyl depends on **Argus** for:
- User authentication (via argus-client)
- Billing and subscriptions (via argus-client)
- Tier/entitlement checks (via argus-client)

See [Argus Executive Brief](../argus/plans/argus-executive-brief.md)
```

### sibyl-technical-reference.md

Update Dependencies section:
```markdown
### External Services

| Service | Purpose | Protocol |
|---------|---------|----------|
| Argus Auth API | Authentication, tiers | gRPC |
| Argus Billing API | Subscriptions, usage | gRPC |
```

Add to Cargo.toml dependencies:
```toml
argus-client = { git = "https://github.com/ahenry0125/argus" }
```

---

## Appendix F: Bot Worktree Setup

### Creating Sibyl Worktree for Predictions Bot

```bash
# Create worktree
cd /data/ai/claude
git worktree add sibyl -b feat/predictions-service /data/ai/repos/sibyl

# Set up Claude context
mkdir -p /data/ai/claude/sibyl/.claude
cat > /data/ai/claude/sibyl/.claude/CLAUDE.md << 'EOF'
# Sibyl Predictions Service Context

You are working on the **Sibyl Predictions Service** - the core prediction engine using conformal prediction.

## Focus Areas
- Conformal prediction implementation
- Calibration pipeline
- REST/WebSocket APIs for predictions
- James/InfluxDB observability

## Out of Scope (Handled by Argus)
- User authentication → Use argus-client
- Billing/subscriptions → Use argus-client
- Tier management → Use argus-client

## Key Files
- `src/prediction/` - Core prediction logic
- `src/calibration/` - Calibration pipeline
- `src/api/predictions.rs` - Prediction endpoints

## Related Documentation
- Plan files: `/data/ai/repos/sibyl/plans/`
- Argus plans: `/data/ai/repos/argus/plans/`
- Bot tooling: `/data/ai/repos/blitz/`
- Cloud infra: `/data/ai/repos/nimbus/`
EOF
```

---

*This completes the Argus documentation suite.*
