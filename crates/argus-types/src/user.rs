//! User types

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique user identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl UserId {
    /// Create a new random user ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a user ID from a string
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}
