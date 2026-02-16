//! Argus MCP (Model Context Protocol) Server
//!
//! This crate implements an MCP server that enables LLM agents to interact with
//! Argus auth and billing services.
//!
//! ## Features
//!
//! - **Tools**: validate_token, get_user_tier, check_entitlement, record_usage, create_checkout
//! - **Resources**: tier configuration, feature flags, rate limits
//! - **Prompts**: authorization workflows, billing management
//!
//! ## Example
//!
//! ```ignore
//! use argus_mcp::ArgusMcpServer;
//!
//! let server = ArgusMcpServer::new(auth_service, billing_service);
//! let transport = (tokio::io::stdin(), tokio::io::stdout());
//! server.serve(transport).await?;
//! ```

pub mod auth;
pub mod error;
pub mod prompts;
pub mod resources;
pub mod server;
pub mod tools;

pub use error::McpError;
pub use server::ArgusMcpServer;
