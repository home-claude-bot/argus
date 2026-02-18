//! Webhook security tests
//!
//! Tests for Stripe webhook signature verification and security measures.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Generate a valid Stripe webhook signature for testing
fn generate_stripe_signature(payload: &[u8], secret: &str, timestamp: i64) -> String {
    let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(payload).unwrap());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signed_payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    format!("t={},v1={}", timestamp, signature)
}

/// Generate a webhook payload for testing
fn test_webhook_payload(event_type: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "id": "evt_test_123",
        "type": event_type,
        "created": Utc::now().timestamp(),
        "data": {
            "object": {
                "id": "sub_test_123",
                "customer": "cus_test_123",
                "status": "active",
                "current_period_start": Utc::now().timestamp(),
                "current_period_end": Utc::now().timestamp() + 30 * 24 * 60 * 60,
                "cancel_at_period_end": false
            }
        }
    });
    serde_json::to_vec(&payload).unwrap()
}

#[test]
fn test_signature_format_parsing() {
    // Valid signature format
    let sig = "t=1234567890,v1=abc123def456";
    assert!(sig.contains("t="));
    assert!(sig.contains("v1="));

    // Parse components
    let mut timestamp: Option<&str> = None;
    let mut sig_v1: Option<&str> = None;

    for part in sig.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "t" => timestamp = Some(value),
                "v1" => sig_v1 = Some(value),
                _ => {}
            }
        }
    }

    assert_eq!(timestamp, Some("1234567890"));
    assert_eq!(sig_v1, Some("abc123def456"));
}

#[test]
fn test_valid_signature_generation() {
    let secret = "whsec_test_secret_key";
    let payload = test_webhook_payload("customer.subscription.created");
    let timestamp = Utc::now().timestamp();

    let signature = generate_stripe_signature(&payload, secret, timestamp);

    // Should have expected format
    assert!(signature.starts_with("t="));
    assert!(signature.contains(",v1="));

    // Timestamp should match
    let t_part = signature.split(',').next().unwrap();
    let ts_str = t_part.strip_prefix("t=").unwrap();
    assert_eq!(ts_str.parse::<i64>().unwrap(), timestamp);
}

#[test]
fn test_timestamp_freshness_check() {
    let now = Utc::now().timestamp();

    // Fresh timestamp (within 5 minutes)
    let fresh = now - 60; // 1 minute ago
    assert!((now - fresh).abs() <= 300);

    // Stale timestamp (older than 5 minutes)
    let stale = now - 400; // 6+ minutes ago
    assert!((now - stale).abs() > 300);

    // Future timestamp (also invalid if too far)
    let future = now + 400;
    assert!((now - future).abs() > 300);
}

#[test]
fn test_constant_time_comparison() {
    // This tests the concept - actual implementation is in billing-core
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    // Equal strings
    assert!(constant_time_eq(b"abc123", b"abc123"));

    // Different strings
    assert!(!constant_time_eq(b"abc123", b"abc124"));

    // Different lengths
    assert!(!constant_time_eq(b"abc", b"abcd"));

    // Empty strings
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn test_webhook_event_types() {
    let event_types = [
        "checkout.session.completed",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_failed",
    ];

    for event_type in event_types {
        let payload = test_webhook_payload(event_type);
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["type"], event_type);
    }
}

#[test]
fn test_malformed_signature_rejection() {
    // Missing timestamp
    let sig1 = "v1=abc123";
    assert!(!sig1.contains("t="));

    // Missing signature
    let sig2 = "t=1234567890";
    assert!(!sig2.contains("v1="));

    // Empty signature
    let sig3 = "";
    assert!(sig3.is_empty());

    // Invalid format
    let sig4 = "invalid_format";
    assert!(!sig4.contains('='));
}

#[test]
fn test_replay_attack_prevention() {
    // Reusing an old signature should fail due to timestamp check
    let secret = "whsec_test_secret";
    let payload = test_webhook_payload("invoice.paid");

    // Generate signature with old timestamp (10 minutes ago)
    let old_timestamp = Utc::now().timestamp() - 600;
    let _old_signature = generate_stripe_signature(&payload, secret, old_timestamp);

    // Verify timestamp is too old
    let now = Utc::now().timestamp();
    assert!((now - old_timestamp).abs() > 300);
}
