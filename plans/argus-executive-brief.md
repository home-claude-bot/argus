# Argus Executive Brief

> **Status**: Planning | **Created**: 2026-02-16 | **Author**: Boss Bot
> **Purpose**: Strategic overview, architecture decisions, team alignment
> **Reading Time**: 10 minutes

---

## Document Overview

This Executive Brief contains everything needed for:
- Understanding Argus's purpose and scope
- Architecture decision rationale
- Go/No-Go decision making
- Team alignment on microservices approach

**Related Documents:**
| Document | Purpose | When to Read |
|----------|---------|--------------|
| [Operating Playbook](argus-operating-playbook.md) | CI/CD, deployment, operations | During implementation |
| [Technical Reference](argus-technical-reference.md) | Deep technical specs | As needed |
| [Appendices](argus-appendices.md) | Migration guides, resources | Reference |

---

## Executive Summary

**Argus** is a centralized auth and billing microservices platform, providing identity management and payment processing as reusable services across the organization.

### The Name

*Argus Panoptes* - the all-seeing giant of Greek mythology, guardian with a hundred eyes. Perfect for an identity and access management system that watches over all services.

### Why Argus?

The current architecture has problems:

| Problem | Impact |
|---------|--------|
| Auth/billing in Sibyl | Tightly coupled, not reusable |
| No service boundaries | Changes ripple everywhere |
| Duplicate implementations | Each service rebuilds auth |

**Argus Solution:**

```
Before:                          After:
┌─────────────────┐              ┌─────────────────┐
│     Sibyl       │              │     Sibyl       │
│  ┌───────────┐  │              │   (Predictions) │
│  │   Auth    │  │              └────────┬────────┘
│  ├───────────┤  │                       │ gRPC
│  │  Billing  │  │              ┌────────▼────────┐
│  ├───────────┤  │              │      Argus      │
│  │Predictions│  │              │  ┌──────────┐   │
│  └───────────┘  │              │  │ Auth API │   │
└─────────────────┘              │  ├──────────┤   │
                                 │  │Billing API│  │
                                 │  └──────────┘   │
                                 └─────────────────┘
```

### Core Services

| Service | Purpose | Protocols |
|---------|---------|-----------|
| **Auth API** | Identity, sessions, tiers, entitlements | REST, gRPC, GraphQL, MCP |
| **Billing API** | Subscriptions, payments, usage tracking | REST, gRPC, Webhooks, MCP |
| **MCP Gateway** | LLM agent authentication & authorization | MCP (JSON-RPC) |

### MCP (Model Context Protocol) Support

Argus implements MCP to enable LLM agents to interact with auth and billing:

```
┌─────────────────────────────────────────────────────────────┐
│                     LLM Applications                        │
│  (Claude Code, Custom Agents, AI Workflows)                 │
└─────────────────────┬───────────────────────────────────────┘
                      │ MCP (JSON-RPC)
┌─────────────────────▼───────────────────────────────────────┐
│                   Argus MCP Server                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Tools:                                               │   │
│  │  • validate_token - Verify JWT/session tokens        │   │
│  │  • get_user_tier - Check subscription tier           │   │
│  │  • check_entitlement - Verify feature access         │   │
│  │  • record_usage - Track API consumption              │   │
│  │  • create_checkout - Generate payment session        │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ Resources:                                           │   │
│  │  • tier_config - Current tier definitions            │   │
│  │  • feature_flags - Entitlement mappings              │   │
│  │  • rate_limits - Current limits by tier              │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ Prompts:                                             │   │
│  │  • "Check user access" - Authorization workflow      │   │
│  │  • "Handle billing" - Subscription management        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**MCP Use Cases:**
1. **Agent Authentication** - LLMs validate tokens before taking action
2. **Tier-Aware Responses** - Agents adjust behavior based on user tier
3. **Usage Tracking** - Automatic consumption recording for billing
4. **MCP-to-MCP Auth** - Argus authenticates requests from other MCP servers

### Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Rust | Performance, safety, existing expertise |
| Web Framework | Axum | Async-first, tower middleware |
| gRPC | Tonic | Native Rust, excellent performance |
| GraphQL | async-graphql | Dashboard-friendly queries |
| MCP | rmcp | Official Rust SDK, full MCP 2025-11-25 spec |
| Database | PostgreSQL | SQLx for compile-time checks |
| Identity | AWS Cognito | Managed auth, already in use |
| Payments | Stripe | Industry standard, excellent API |
| Deploy | EKS via Nimbus | Existing infrastructure |

---

## Architecture Principles

### 1. Service Independence
- Each service owns its schema
- No shared tables between services
- Communication via gRPC/events only

### 2. Multi-Protocol APIs
- REST for external consumers
- gRPC for internal service-to-service
- GraphQL for dashboard
- WebSocket for real-time

### 3. Shared Nothing
- Services can be deployed/scaled independently
- No shared state except through APIs
- Event-driven for async operations

### 4. Client SDK Pattern
- `argus-client` crate for consumers
- Type-safe, compile-time checked
- Abstracts protocol details

---

## Tier System

Argus manages the unified tier system across all services:

| Tier | Price | Rate Limits | Features |
|------|-------|-------------|----------|
| Explorer | $29/mo | 100 req/min | Basic API access |
| Professional | $199/mo | 1,000 req/min | Advanced features, webhooks |
| Business | $999/mo | 10,000 req/min | Team management, SLA |
| Enterprise | $4,999/mo | Custom | Dedicated support, custom |

---

## Integration with Ecosystem

### Sibyl Integration
```
Sibyl Service
    │
    ├─ Startup: Validate config with Auth API
    ├─ Request: Check tier/entitlements via gRPC
    ├─ Usage: Record API calls to Billing API
    └─ Webhooks: Subscribe to tier change events
```

### Future Services
Any new service integrates via `argus-client`:
```rust
use argus_client::{AuthClient, BillingClient};

// Type-safe, compile-time checked
let tier = auth.get_user_tier(user_id).await?;
billing.record_usage(user_id, "api_call", 1).await?;
```

---

## Success Criteria

### Phase 1: Repository Setup
- [ ] GitHub repo created with CI/CD
- [ ] Rust workspace compiles
- [ ] ahenry125 has admin access
- [ ] Basic crate structure exists

### Phase 2: Auth Core
- [ ] argus-auth-core extracted from Sibyl
- [ ] Cognito integration working
- [ ] REST + gRPC endpoints functional
- [ ] Deployed to staging

### Phase 3: Billing Core
- [ ] argus-billing-core implemented
- [ ] Stripe integration tested
- [ ] Webhook handling working
- [ ] Deployed to staging

### Phase 4: Integration
- [ ] argus-client SDK published
- [ ] Sibyl migrated to use Argus
- [ ] Production deployment
- [ ] Legacy code removed

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Migration complexity | Medium | High | Phased approach, feature flags |
| Service latency | Low | Medium | gRPC, connection pooling |
| Breaking changes | Medium | Medium | Versioned APIs, deprecation policy |
| Operational overhead | Low | Low | Kubernetes, auto-scaling |

---

## JIRA Tracking

**Project**: ARGUS (to be created)
**Epic**: Centralized Auth & Billing Platform

See [Appendices](argus-appendices.md) for full story breakdown.

---

## Related JIRA Issues (From Sibyl)

These auth-related issues will be addressed by Argus:

| Key | Summary | Priority | Status |
|-----|---------|----------|--------|
| SYBIL-57 | Auth System Enhancements (Epic) | Medium | To Do |
| SYBIL-44 | Auth System Performance Optimization | High | To Do |
| SYBIL-43 | Auth System Testing Maturity | High | To Do |
| SYBIL-49 | OAuth provider buttons | Medium | To Do |
| SYBIL-60 | Cognito M2M auth evaluation | Low | To Do |

**Migration Strategy:**
- SYBIL-57 (Epic) → Becomes ARGUS auth-api implementation
- SYBIL-44 (Performance) → Incorporated into Argus with Rust performance benefits
- SYBIL-43 (Testing) → Part of Argus CI/CD with comprehensive test suite
- SYBIL-49 (OAuth UI) → Argus dashboard OAuth buttons
- SYBIL-60 (M2M auth) → Argus MCP-based M2M authentication

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-02-16 | Name: Argus | Greek guardian, short, memorable |
| 2026-02-16 | Rust monorepo | Existing expertise, shared types |
| 2026-02-16 | Multi-protocol | REST external, gRPC internal |
| 2026-02-16 | Nimbus deploy | Existing EKS infrastructure |
| 2026-02-16 | MCP support | Enable LLM agents to authenticate/authorize |
| 2026-02-16 | Absorb Sibyl auth work | Consolidate SYBIL-43,44,49,57,60 into Argus |

---

*Next: Review [Technical Reference](argus-technical-reference.md) for implementation details.*
