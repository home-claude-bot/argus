# Argus

**The All-Seeing Guardian** - Centralized Auth & Billing Microservices

[![CI](https://github.com/home-claude-bot/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/home-claude-bot/argus/actions/workflows/ci.yml)

## Overview

Argus provides centralized authentication and billing services as reusable microservices. Named after Argus Panoptes, the all-seeing giant of Greek mythology.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Consumers                             │
│  (Sibyl, Claude Code, Other Services, LLM Agents)       │
└─────────────────────┬───────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │ REST/gRPC       │ MCP             │
    ▼                 ▼                 │
┌─────────────┐ ┌─────────────┐ ┌───────▼─────┐
│  Auth API   │ │ Billing API │ │ MCP Server  │
└──────┬──────┘ └──────┬──────┘ └─────────────┘
       │               │
       └───────┬───────┘
               │
       ┌───────▼───────┐
       │   PostgreSQL  │
       └───────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| `auth-api` | 8080/9090 | Authentication, sessions, tiers |
| `billing-api` | 8081/9091 | Subscriptions, payments, usage |
| `mcp-server` | STDIO | MCP server for LLM agents |

## Crates

| Crate | Description |
|-------|-------------|
| `argus-types` | Shared domain types (User, Tier, Subscription) |
| `argus-db` | Database abstractions (SQLx, PostgreSQL) |
| `argus-auth-core` | Auth business logic (Cognito, sessions) |
| `argus-billing-core` | Billing logic (Stripe, subscriptions) |
| `argus-proto` | Protocol Buffers for gRPC |
| `argus-mcp` | MCP server implementation |
| `argus-client` | Client SDK for consumers |
| `argus-utils` | Common utilities |

## Quick Start

```bash
# Clone
git clone https://github.com/home-claude-bot/argus.git
cd argus

# Build
cargo build

# Run tests
cargo test

# Run auth API
cargo run -p auth-api

# Run MCP server
cargo run -p argus-mcp-server
```

## MCP Integration

Add Argus MCP to your Claude Code config:

```json
{
  "mcp_servers": {
    "argus": {
      "command": "argus-mcp-server",
      "env": {
        "DATABASE_URL": "postgres://...",
        "COGNITO_POOL_ID": "..."
      }
    }
  }
}
```

### Available MCP Tools

- `validate_token` - Verify JWT/session tokens
- `get_user_tier` - Get subscription tier
- `check_entitlement` - Check feature access
- `record_usage` - Track API consumption
- `create_checkout` - Generate payment session

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy

# Run all checks
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

## License

MIT
