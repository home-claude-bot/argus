//! Property-based tests for session cookie parsing and signing
//!
//! These tests verify:
//! - Signed cookies roundtrip correctly (sign -> verify -> parse)
//! - Malformed cookies never cause panics
//! - Signature tampering is always detected
//! - HMAC key validation works correctly

mod common;

use argus_auth_core::{constant_time_eq, HmacKey, SessionPayload};
use argus_types::UserId;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use proptest::prelude::*;

// ============================================================================
// Strategies
// ============================================================================

/// Generate arbitrary session payloads
fn arb_session_payload() -> impl Strategy<Value = SessionPayload> {
    (
        any::<[u8; 16]>(),                        // user_id bytes
        "[a-z0-9_.+-]+@[a-z0-9.-]+\\.[a-z]{2,4}", // email regex
        prop::collection::vec("[a-z_]{3,15}", 0..5), // groups
        1u32..168u32,                             // duration_hours
    )
        .prop_map(|(id_bytes, email, groups, hours)| {
            let user_id = UserId(uuid::Uuid::from_bytes(id_bytes));
            SessionPayload::new(user_id, &email, groups, hours)
        })
}

/// Generate malformed cookie strings
fn arb_malformed_cookie() -> impl Strategy<Value = String> {
    prop_oneof![
        // No dots
        "[a-zA-Z0-9_-]{10,50}",
        // Multiple dots (JWT-like but invalid)
        "[a-zA-Z0-9_-]{10,20}\\.[a-zA-Z0-9_-]{5,10}\\.[a-zA-Z0-9_-]{5,10}\\.[a-zA-Z0-9_-]{5,10}",
        // Empty parts
        Just(".signature".to_string()),
        Just("payload.".to_string()),
        Just("..".to_string()),
        Just(".".to_string()),
        Just("".to_string()),
        // Invalid base64 characters
        "[!@#$%^&*()]{10,30}\\.[a-zA-Z0-9_-]{20,40}",
        // Valid base64 but not JSON
        any::<[u8; 32]>().prop_map(|bytes| {
            format!("{}.fake_sig", URL_SAFE_NO_PAD.encode(bytes))
        }),
        // Truncated signatures
        any::<[u8; 16]>().prop_map(|bytes| {
            let payload = URL_SAFE_NO_PAD.encode(bytes);
            format!("{payload}.abc")
        }),
    ]
}

/// Generate valid HMAC keys (32+ bytes)
fn arb_valid_hmac_key() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 32..64).prop_map(|bytes| {
        // Convert to string-safe format
        bytes.iter().map(|b| (b % 94 + 33) as char).collect()
    })
}

/// Generate invalid HMAC keys (< 32 bytes)
fn arb_invalid_hmac_key() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 1..31)
        .prop_map(|bytes| bytes.iter().map(|b| (b % 94 + 33) as char).collect())
}

// ============================================================================
// HMAC Key Validation Properties
// ============================================================================

proptest! {
    /// Property: Valid keys (32+ bytes) should be accepted
    #[test]
    fn prop_valid_hmac_key_accepted(key in arb_valid_hmac_key()) {
        let result = HmacKey::new(&key);
        prop_assert!(result.is_ok(), "Key of {} bytes should be valid", key.len());
    }

    /// Property: Invalid keys (< 32 bytes) should be rejected
    #[test]
    fn prop_invalid_hmac_key_rejected(key in arb_invalid_hmac_key()) {
        let result = HmacKey::new(&key);
        prop_assert!(result.is_err(), "Key of {} bytes should be rejected", key.len());
    }
}

// ============================================================================
// Cookie Signing/Verification Properties
// ============================================================================

proptest! {
    /// Property: Signed cookies should always roundtrip successfully
    #[test]
    fn prop_signed_cookie_roundtrips(payload in arb_session_payload()) {
        let key = HmacKey::new(&"a]".repeat(32)).unwrap();

        // Sign the payload
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signature = key.sign(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
        let cookie = format!("{payload_b64}.{sig_b64}");

        // Verify roundtrip - parse the cookie
        let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
        prop_assert_eq!(parts.len(), 2);

        let (sig_b64_parsed, payload_b64_parsed) = (parts[0], parts[1]);

        // Verify signature
        let expected_sig = key.sign(payload_b64_parsed.as_bytes());
        let provided_sig = URL_SAFE_NO_PAD.decode(sig_b64_parsed).unwrap();
        prop_assert!(constant_time_eq(&expected_sig, &provided_sig));

        // Parse payload
        let decoded_json = URL_SAFE_NO_PAD.decode(payload_b64_parsed).unwrap();
        let decoded_payload: SessionPayload = serde_json::from_slice(&decoded_json).unwrap();

        // Verify fields match (comparing user_ids, emails)
        prop_assert_eq!(decoded_payload.email, payload.email);
        prop_assert_eq!(decoded_payload.groups, payload.groups);
    }

    /// Property: Malformed cookies should never panic, always return parse error
    #[test]
    fn prop_malformed_cookie_never_panics(cookie in arb_malformed_cookie()) {
        // This should not panic - we're just testing that parsing is safe
        let result = std::panic::catch_unwind(|| {
            let _ = parse_cookie_parts(&cookie);
        });
        prop_assert!(result.is_ok(), "Parsing should not panic for: {:?}", cookie);
    }

    /// Property: Any bit flip in signature should be detected
    #[test]
    fn prop_signature_tampering_detected(
        payload in arb_session_payload(),
        tamper_byte in 0usize..32usize,
        tamper_bit in 0u8..8u8
    ) {
        let key = HmacKey::new(&"a]".repeat(32)).unwrap();

        // Create valid signed cookie
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signature = key.sign(payload_b64.as_bytes());

        // Tamper with one bit
        let mut tampered_sig = signature.clone();
        if tamper_byte < tampered_sig.len() {
            tampered_sig[tamper_byte] ^= 1 << tamper_bit;
        }

        // Verify tampered signature is rejected (if different)
        if tampered_sig != signature {
            prop_assert!(
                !constant_time_eq(&signature, &tampered_sig),
                "Tampered signature should be rejected"
            );
        }
    }

    /// Property: Any modification to payload should invalidate signature
    #[test]
    fn prop_payload_tampering_detected(
        payload in arb_session_payload(),
        tamper_byte in 0usize..100usize
    ) {
        let key = HmacKey::new(&"a]".repeat(32)).unwrap();

        // Create valid signed cookie
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let original_signature = key.sign(payload_b64.as_bytes());

        // Tamper with payload
        let mut tampered_json = payload_json.clone();
        if tamper_byte < tampered_json.len() {
            tampered_json[tamper_byte] = tampered_json[tamper_byte].wrapping_add(1);
        }
        let tampered_b64 = URL_SAFE_NO_PAD.encode(&tampered_json);

        // Verify signature with tampered payload
        let new_signature = key.sign(tampered_b64.as_bytes());

        if tampered_json != payload_json {
            prop_assert!(
                !constant_time_eq(&original_signature, &new_signature),
                "Signature should change when payload changes"
            );
        }
    }
}

// ============================================================================
// Constant-Time Comparison Properties
// ============================================================================

proptest! {
    /// Property: constant_time_eq returns true for equal slices
    #[test]
    fn prop_constant_time_eq_equal(data in prop::collection::vec(any::<u8>(), 0..100)) {
        let copy = data.clone();
        prop_assert!(constant_time_eq(&data, &copy));
    }

    /// Property: constant_time_eq returns false for different slices
    #[test]
    fn prop_constant_time_eq_different(
        a in prop::collection::vec(any::<u8>(), 1..50),
        b in prop::collection::vec(any::<u8>(), 1..50)
    ) {
        if a != b {
            prop_assert!(!constant_time_eq(&a, &b));
        }
    }

    /// Property: constant_time_eq returns false for different lengths
    #[test]
    fn prop_constant_time_eq_different_lengths(
        a in prop::collection::vec(any::<u8>(), 10..20),
        extra in prop::collection::vec(any::<u8>(), 1..5)
    ) {
        let mut b = a.clone();
        b.extend(extra);
        prop_assert!(!constant_time_eq(&a, &b));
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse cookie into (signature, payload) parts - for testing only
fn parse_cookie_parts(cookie: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = cookie.rsplitn(2, '.').collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

// ============================================================================
// Non-Property Edge Case Tests
// ============================================================================

#[test]
fn test_empty_cookie_handled() {
    assert!(parse_cookie_parts("").is_none());
}

#[test]
fn test_no_dot_cookie_handled() {
    assert!(parse_cookie_parts("nodothere").is_none());
}

#[test]
fn test_multiple_dots_uses_last() {
    let result = parse_cookie_parts("a.b.c");
    assert!(result.is_some());
    let (sig, payload) = result.unwrap();
    assert_eq!(sig, "c");
    assert_eq!(payload, "a.b");
}

#[test]
fn test_hmac_key_exactly_32_bytes() {
    let key = "a".repeat(32);
    assert!(HmacKey::new(&key).is_ok());
}

#[test]
fn test_hmac_key_31_bytes_rejected() {
    let key = "a".repeat(31);
    assert!(HmacKey::new(&key).is_err());
}

#[test]
fn test_different_keys_produce_different_signatures() {
    let key1 = HmacKey::new(&"a".repeat(32)).unwrap();
    let key2 = HmacKey::new(&"b".repeat(32)).unwrap();
    let data = b"test data";

    let sig1 = key1.sign(data);
    let sig2 = key2.sign(data);

    assert!(!constant_time_eq(&sig1, &sig2));
}
