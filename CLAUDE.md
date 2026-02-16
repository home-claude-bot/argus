# Argus - AI Agent Context

You are working on **Argus** - centralized auth and billing microservices.

## Project Structure

```
argus/
├── crates/
│   ├── argus-types/         # Domain types (User, Tier, Subscription)
│   ├── argus-db/            # Database layer (SQLx, PostgreSQL)
│   ├── argus-auth-core/     # Auth business logic
│   ├── argus-billing-core/  # Billing business logic
│   ├── argus-proto/         # gRPC Protocol Buffers
│   ├── argus-mcp/           # MCP server implementation
│   ├── argus-client/        # Client SDK
│   └── argus-utils/         # Utilities
├── services/
│   ├── auth-api/            # Auth microservice
│   ├── billing-api/         # Billing microservice
│   └── mcp-server/          # MCP server binary
├── plans/                   # Architecture plans
└── deploy/                  # Kubernetes manifests
```

## Key Technologies

- **Language**: Rust (Edition 2021, MSRV 1.75)
- **Web**: Axum for REST APIs
- **gRPC**: Tonic + Prost
- **MCP**: rmcp SDK
- **Database**: PostgreSQL with SQLx
- **Auth**: AWS Cognito integration
- **Payments**: Stripe integration

## Development Commands

```bash
cargo build              # Build all crates
cargo test               # Run all tests
cargo clippy             # Lint
cargo fmt                # Format
cargo run -p auth-api    # Run auth service
cargo run -p argus-mcp-server  # Run MCP server
```

## Architecture Principles

1. **Service Independence**: Each service owns its schema
2. **Multi-Protocol**: REST (external), gRPC (internal), MCP (LLM agents)
3. **Type Safety**: Compile-time checked queries with SQLx
4. **Provider Agnostic**: PaymentProvider trait abstracts Stripe

## MCP Implementation

The `argus-mcp` crate exposes:
- **Tools**: validate_token, get_user_tier, check_entitlement, record_usage
- **Resources**: tier config, feature flags, rate limits
- **Prompts**: authorization workflows

## Related Projects

- **Sibyl**: Prediction service (consumer of Argus via argus-client)
- **Nimbus**: Cloud infrastructure (Terraform deployment)
- **Blitz**: Bot Army tooling

## Plan Files

Detailed architecture plans are in `/plans/`:
- `argus-executive-brief.md` - Strategic overview
- `argus-technical-reference.md` - Deep technical specs
- `argus-operating-playbook.md` - CI/CD and operations
- `argus-appendices.md` - JIRA stories, migration guide
