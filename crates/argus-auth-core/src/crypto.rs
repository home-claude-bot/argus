//! Cryptographic utilities for secure operations
//!
//! This module provides security-critical primitives that must be implemented
//! correctly to prevent timing attacks and other side-channel vulnerabilities.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

/// Pre-computed HMAC key for efficient repeated signing operations.
///
/// Creating an HMAC instance from raw bytes has overhead. This struct
/// pre-validates the key and allows efficient cloning for signing.
#[derive(Clone)]
pub struct HmacKey {
    key_bytes: Arc<[u8]>,
}

impl HmacKey {
    /// Minimum allowed key length in bytes (256 bits)
    pub const MIN_KEY_LENGTH: usize = 32;

    /// Create a new HMAC key from bytes.
    ///
    /// # Errors
    /// Returns error if key is too short (less than 32 bytes).
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, HmacKeyError> {
        let key_bytes = key.as_ref();
        if key_bytes.len() < Self::MIN_KEY_LENGTH {
            return Err(HmacKeyError::KeyTooShort {
                actual: key_bytes.len(),
                minimum: Self::MIN_KEY_LENGTH,
            });
        }
        Ok(Self {
            key_bytes: Arc::from(key_bytes),
        })
    }

    /// Create HMAC instance for signing
    pub fn create_hmac(&self) -> Hmac<Sha256> {
        // This cannot fail because we validated key length in new()
        Hmac::<Sha256>::new_from_slice(&self.key_bytes)
            .expect("HMAC key length already validated")
    }

    /// Sign data and return the MAC bytes
    pub fn sign(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = self.create_hmac();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify a signature in constant time
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let expected = self.sign(data);
        constant_time_eq(&expected, signature)
    }
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey")
            .field("key_length", &self.key_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when creating an HMAC key
#[derive(Debug, Clone, thiserror::Error)]
pub enum HmacKeyError {
    #[error("HMAC key too short: got {actual} bytes, need at least {minimum}")]
    KeyTooShort { actual: usize, minimum: usize },
}

/// Constant-time byte slice comparison.
///
/// This function compares two byte slices in constant time to prevent
/// timing attacks. The comparison time depends only on the length of
/// the slices, not on their contents.
///
/// # Security
/// - Returns `false` immediately if lengths differ (length is not secret)
/// - Compares all bytes even after finding a difference
/// - Uses XOR accumulator to prevent branch prediction attacks
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // XOR all bytes together - will be 0 only if all bytes match
    // This runs in constant time regardless of where differences are
    let result = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));

    result == 0
}

/// Constant-time string comparison.
///
/// Wrapper around `constant_time_eq` for string comparisons.
#[inline]
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Securely hash a token for storage.
///
/// Uses SHA-256 to create a one-way hash of the token.
/// The original token cannot be recovered from the hash.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let a: &[u8] = b"";
        let b: &[u8] = b"";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_str_eq() {
        assert!(constant_time_str_eq("secret", "secret"));
        assert!(!constant_time_str_eq("secret", "secreT"));
    }

    #[test]
    fn test_hmac_key_too_short() {
        let result = HmacKey::new("short");
        assert!(matches!(result, Err(HmacKeyError::KeyTooShort { .. })));
    }

    #[test]
    fn test_hmac_key_valid() {
        let key = "a]".repeat(32); // 64 bytes
        let result = HmacKey::new(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hmac_sign_verify() {
        let key = HmacKey::new("a]".repeat(32)).unwrap();
        let data = b"test data to sign";
        let signature = key.sign(data);
        assert!(key.verify(data, &signature));
        assert!(!key.verify(b"wrong data", &signature));
    }

    #[test]
    fn test_hash_token() {
        let token = "session_cookie_value";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars

        // Different tokens produce different hashes
        let hash3 = hash_token("different_token");
        assert_ne!(hash1, hash3);
    }
}
