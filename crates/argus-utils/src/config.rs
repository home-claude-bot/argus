//! Configuration utilities

/// Load configuration from environment
pub fn load_env() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    Ok(())
}
