# Security Bot Onboarding - Argus Project

> **Welcome!** This document provides context for security bot to get started on Argus development.

## Project Overview

**Argus** (Greek: "all-seeing guardian") is a centralized auth and billing microservices platform written in Rust. It extracts authentication and billing logic from Sibyl into reusable, independent services.

### Why Argus Exists

| Problem | Solution |
|---------|----------|
| Auth/billing embedded in Sibyl | Standalone microservices |
| Duplicate auth code across services | Single source of truth |
| Tight coupling | Clean service boundaries |
| No MCP auth for LLM agents | Native MCP support |

## Architecture At a Glance

```
┌─────────────────────────────────────────────┐
│              Consumer Services              │
│  (Sibyl, Future Services, LLM Agents)       │
└──────────────────┬──────────────────────────┘
                   │ argus-client SDK / MCP
┌──────────────────▼──────────────────────────┐
│                   Argus                      │
│  ┌───────────┐  ┌───────────┐  ┌─────────┐  │
│  │ Auth API  │  │Billing API│  │MCP Server│ │
│  └─────┬─────┘  └─────┬─────┘  └────┬────┘  │
│        │              │              │       │
│  ┌─────▼──────────────▼──────────────▼────┐ │
│  │           PostgreSQL (argus-db)         │ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
         │                        │
    ┌────▼────┐              ┌────▼────┐
    │ Cognito │              │  Stripe │
    └─────────┘              └─────────┘
```

## Crate Structure

| Crate | Purpose | Status |
|-------|---------|--------|
| `argus-types` | Domain types (User, Tier, Session, etc.) | ✅ Done (ARGUS-7) |
| `argus-db` | SQLx database layer | 🔄 PR Open (ARGUS-8) |
| `argus-auth-core` | Auth business logic | **Your Task** |
| `argus-billing-core` | Billing business logic | To Do |
| `argus-proto` | gRPC definitions | To Do |
| `argus-mcp` | MCP server implementation | To Do |
| `argus-client` | Consumer SDK | To Do |

## Essential Reading

### Must Read First
1. **Executive Brief**: `/data/ai/repos/argus/plans/argus-executive-brief.md`
   - Project rationale and architecture decisions
   - Tier system (Explorer → Enterprise)
   - MCP integration strategy

2. **Technical Reference**: `/data/ai/repos/argus/plans/argus-technical-reference.md`
   - Crate specifications and API contracts
   - Database schema design
   - Authentication flow details

### Reference as Needed
3. **Operating Playbook**: `/data/ai/repos/argus/plans/argus-operating-playbook.md`
   - CI/CD pipeline details
   - Deployment strategy

4. **Appendices**: `/data/ai/repos/argus/plans/argus-appendices.md`
   - JIRA story details
   - Migration guides

### Existing Code
5. **argus-types**: `/data/ai/repos/argus/crates/argus-types/src/`
   - Domain types you'll be working with
   - Session, Claims, Tier, Entitlement types

6. **argus-db**: `/data/ai/repos/argus/crates/argus-db/src/`
   - Repository traits and implementations
   - UserRepository, SessionRepository patterns

## Your First Task: ARGUS-9

**JIRA**: [ARGUS-9 - Implement argus-auth-core business logic](https://andrz2.atlassian.net/browse/ARGUS-9)

### What to Build

`argus-auth-core` provides the authentication business logic:

```rust
// Key responsibilities:
pub struct AuthService {
    db: Repositories,
    cognito: CognitoClient,
}

impl AuthService {
    // Session management
    async fn create_session(&self, user: &User) -> Result<Session>;
    async fn validate_session(&self, token: &str) -> Result<Claims>;
    async fn refresh_session(&self, refresh_token: &str) -> Result<TokenPair>;
    async fn revoke_session(&self, session_id: SessionId) -> Result<()>;

    // Tier/Entitlement checks
    async fn get_user_tier(&self, user_id: UserId) -> Result<Tier>;
    async fn check_entitlement(&self, user_id: UserId, feature: Feature) -> Result<bool>;
    async fn get_rate_limit(&self, user_id: UserId) -> Result<RateLimit>;
}
```

### Key Files to Create

1. `crates/argus-auth-core/src/service.rs` - Main AuthService implementation
2. `crates/argus-auth-core/src/cognito.rs` - AWS Cognito integration
3. `crates/argus-auth-core/src/session.rs` - Session management logic
4. `crates/argus-auth-core/src/entitlement.rs` - Tier/entitlement checking

### Dependencies You'll Use

```toml
[dependencies]
argus-types = { path = "../argus-types" }
argus-db = { path = "../argus-db" }
aws-sdk-cognitoidentityprovider.workspace = true
aws-config.workspace = true
jsonwebtoken.workspace = true
```

## Research Recommendations

### From Shannon Context Library
These resources may help with authentication patterns:

1. **JWT Best Practices** - Token structure, claims, refresh patterns
2. **AWS Cognito SDK** - Official Rust SDK documentation
3. **Session Management** - Secure session handling patterns
4. **Rate Limiting** - Token bucket algorithms, sliding window

### External References
- [AWS Cognito Developer Guide](https://docs.aws.amazon.com/cognito/)
- [jsonwebtoken crate docs](https://docs.rs/jsonwebtoken)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## Development Workflow

### Getting Started
```bash
cd /data/ai/repos/argus
cargo check -p argus-auth-core  # Verify stub compiles
```

### Running Tests
```bash
cargo test -p argus-auth-core
```

### Creating a PR
1. Create feature branch: `git checkout -b feat/argus-9-auth-core`
2. Make changes, ensure `cargo clippy` passes
3. Push and create PR via `gh pr create`
4. Link PR in JIRA comment

## Coordination Notes

- **Boss Bot** is coordinating overall Argus development
- **ARGUS-8** (argus-db) PR is currently in review - provides the repository traits you'll need
- Ask in `#bot-coordination` if you have questions about interfaces

## Quick Links

| Resource | Path |
|----------|------|
| Argus repo | `/data/ai/repos/argus` |
| Executive Brief | `plans/argus-executive-brief.md` |
| Technical Reference | `plans/argus-technical-reference.md` |
| JIRA Project | [ARGUS](https://andrz2.atlassian.net/browse/ARGUS) |
| PR #1 (argus-db) | [GitHub](https://github.com/home-claude-bot/argus/pull/1) |

---

*Questions? Post in #bot-coordination or check the plan docs.*
