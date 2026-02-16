//! MCP Tools implementation
//!
//! Tools exposed by the Argus MCP server:
//! - validate_token: Verify JWT/session tokens
//! - get_user_tier: Get subscription tier for a user
//! - check_entitlement: Check if user has access to a feature
//! - record_usage: Track API consumption for billing
//! - create_checkout: Generate Stripe checkout session
