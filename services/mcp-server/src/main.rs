//! Argus MCP Server
//!
//! MCP server for LLM agent integration with Argus auth and billing services.
//!
//! ## Usage
//!
//! Run with STDIO transport (for Claude Code integration):
//! ```bash
//! argus-mcp-server
//! ```
//!
//! ## MCP Configuration
//!
//! Add to your MCP config:
//! ```json
//! {
//!   "mcp_servers": {
//!     "argus": {
//!       "command": "argus-mcp-server",
//!       "args": [],
//!       "env": {
//!         "DATABASE_URL": "postgres://...",
//!         "COGNITO_POOL_ID": "...",
//!         "STRIPE_SECRET_KEY": "..."
//!       }
//!     }
//!   }
//! }
//! ```

use argus_mcp::ArgusMcpServer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize logging (stderr only - stdout is for MCP JSON-RPC)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting Argus MCP server");

    // Create MCP server
    let _server = ArgusMcpServer::new();

    // TODO: When rmcp is properly integrated, run with STDIO transport:
    // let transport = (tokio::io::stdin(), tokio::io::stdout());
    // let service = server.serve(transport).await?;
    // service.waiting().await?;

    tracing::info!("Argus MCP server ready");

    // For now, just keep running
    tokio::signal::ctrl_c().await?;

    Ok(())
}
