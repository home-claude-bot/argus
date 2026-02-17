//! Property-based tests for tier and role extraction
//!
//! These tests verify the security properties of the tier/role extraction logic:
//! - Suffix-only matching (no fuzzy/contains matching)
//! - Correct priority ordering (enterprise > business > professional > explorer)
//! - Safe defaults (unknown groups -> explorer/user)

mod common;

use argus_auth_core::{extract_role_from_groups, extract_tier_and_role, extract_tier_from_groups};
use argus_types::Tier;
use proptest::prelude::*;

// ============================================================================
// Strategies
// ============================================================================

/// Generate valid tier group names with their expected tier
fn arb_tier_group() -> impl Strategy<Value = (String, Tier)> {
    prop_oneof![
        "[a-z]{3,10}_explorer".prop_map(|g| (g, Tier::Explorer)),
        "[a-z]{3,10}_professional".prop_map(|g| (g, Tier::Professional)),
        "[a-z]{3,10}_pro".prop_map(|g| (g, Tier::Professional)),
        "[a-z]{3,10}_business".prop_map(|g| (g, Tier::Business)),
        "[a-z]{3,10}_enterprise".prop_map(|g| (g, Tier::Enterprise)),
    ]
}

/// Generate group names that should NOT grant tiers (security test)
fn arb_non_tier_group() -> impl Strategy<Value = String> {
    prop_oneof![
        // Tier keyword NOT at end (should NOT match)
        "enterprise_[a-z]{3,10}",
        "professional_disabled",
        "business_revoked",
        "not_an_enterprise_user",
        // Random group names
        "[a-z]{5,15}",
        "[a-z]+_users",
        "team_[a-z]+",
        // Partial matches that should NOT grant tier
        "enterpris",
        "professiona",
        "busines",
    ]
}

/// Generate admin group patterns
fn arb_admin_group() -> impl Strategy<Value = String> {
    "[a-z]{3,10}_admin".prop_map(|s| s)
}

/// Generate non-admin groups that contain "admin" substring (security test)
/// These should NOT grant admin because "admin" is not at the suffix position
fn arb_fake_admin_group() -> impl Strategy<Value = String> {
    prop_oneof![
        "admin_[a-z]{3,10}",                // admin at start, not suffix
        "[a-z]+_admin_[a-z]+",              // admin in middle, not suffix
        Just("administrator".to_string()),  // different word
        Just("admin_disabled".to_string()), // admin at start
        Just("admin_revoked".to_string()),  // admin at start
        Just("admins".to_string()),         // plural, not _admin suffix
    ]
}

// ============================================================================
// Tier Extraction Properties
// ============================================================================

proptest! {
    /// Property: Valid tier suffixes at end of group name should grant correct tier
    #[test]
    fn prop_valid_tier_suffix_grants_tier(
        (group, expected_tier) in arb_tier_group()
    ) {
        let groups = vec![group];
        let tier = extract_tier_from_groups(&groups);
        prop_assert_eq!(tier, expected_tier);
    }

    /// Property: Non-tier groups should result in Explorer tier (safe default)
    #[test]
    fn prop_non_tier_groups_default_to_explorer(
        groups in prop::collection::vec(arb_non_tier_group(), 1..5)
    ) {
        let tier = extract_tier_from_groups(&groups);
        prop_assert_eq!(tier, Tier::Explorer, "Non-tier groups should default to Explorer, got {:?} for {:?}", tier, groups);
    }

    /// Property: Enterprise tier takes priority over all others
    #[test]
    fn prop_enterprise_takes_priority(
        other_groups in prop::collection::vec(arb_tier_group(), 0..3)
    ) {
        let mut groups: Vec<String> = other_groups.into_iter().map(|(g, _)| g).collect();
        groups.push("org_enterprise".to_string());

        let tier = extract_tier_from_groups(&groups);
        prop_assert_eq!(tier, Tier::Enterprise, "Enterprise should take priority, got {:?}", tier);
    }

    /// Property: Business takes priority over Professional
    #[test]
    fn prop_business_over_professional(prefix in "[a-z]{3,10}") {
        let groups = vec![
            format!("{prefix}_professional"),
            format!("{prefix}_business"),
        ];
        let tier = extract_tier_from_groups(&groups);
        prop_assert_eq!(tier, Tier::Business);
    }

    /// Property: Professional takes priority over Explorer
    #[test]
    fn prop_professional_over_explorer(prefix in "[a-z]{3,10}") {
        let groups = vec![
            format!("{prefix}_explorer"),
            format!("{prefix}_professional"),
        ];
        let tier = extract_tier_from_groups(&groups);
        prop_assert_eq!(tier, Tier::Professional);
    }

    /// Property: Empty groups always result in Explorer tier
    #[test]
    fn prop_empty_groups_default_to_explorer(_dummy: bool) {
        let tier = extract_tier_from_groups(&[]);
        prop_assert_eq!(tier, Tier::Explorer);
    }
}

// ============================================================================
// Role Extraction Properties
// ============================================================================

proptest! {
    /// Property: _admin suffix grants admin role
    #[test]
    fn prop_admin_suffix_grants_admin(group in arb_admin_group()) {
        let groups = vec![group];
        let role = extract_role_from_groups(&groups);
        prop_assert_eq!(role, "admin");
    }

    /// Property: Fake admin groups (admin not at end) do NOT grant admin
    #[test]
    fn prop_fake_admin_not_granted(groups in prop::collection::vec(arb_fake_admin_group(), 1..3)) {
        let role = extract_role_from_groups(&groups);
        prop_assert_eq!(role, "user", "Fake admin groups should not grant admin role, got {:?} for {:?}", role, groups);
    }

    /// Property: Empty groups result in user role
    #[test]
    fn prop_empty_groups_default_to_user(_dummy: bool) {
        let role = extract_role_from_groups(&[]);
        prop_assert_eq!(role, "user");
    }
}

// ============================================================================
// Combined Extraction Properties
// ============================================================================

proptest! {
    /// Property: extract_tier_and_role is equivalent to calling both separately
    #[test]
    fn prop_combined_extraction_matches_separate(
        groups in prop::collection::vec("[a-z_]{3,20}", 0..5)
    ) {
        let (combined_tier, combined_role) = extract_tier_and_role(&groups);
        let separate_tier = extract_tier_from_groups(&groups);
        let separate_role = extract_role_from_groups(&groups);

        prop_assert_eq!(combined_tier, separate_tier);
        prop_assert_eq!(combined_role, separate_role);
    }

    /// Property: Combined extraction with both tier and admin groups
    #[test]
    fn prop_combined_with_tier_and_admin(
        prefix in "[a-z]{3,8}"
    ) {
        let groups = vec![
            format!("{prefix}_enterprise"),
            format!("{prefix}_admin"),
        ];
        let (tier, role) = extract_tier_and_role(&groups);
        prop_assert_eq!(tier, Tier::Enterprise);
        prop_assert_eq!(role, "admin");
    }
}

// ============================================================================
// Security Edge Cases (Non-Property Tests)
// ============================================================================

#[test]
fn test_tier_requires_exact_suffix() {
    // These should NOT match - tier keyword NOT at the suffix position
    let non_matching = vec![
        vec!["enterprise".to_string()],              // No underscore prefix
        vec!["enterpriseX".to_string()],             // Suffix after tier
        vec!["org_ENTERPRISE".to_string()],          // Wrong case
        vec!["org_enterprise_disabled".to_string()], // Not at end
        vec!["enterprise_users".to_string()],        // Tier at start not end
    ];

    for groups in non_matching {
        let tier = extract_tier_from_groups(&groups);
        assert_eq!(
            tier,
            Tier::Explorer,
            "Groups {:?} should not grant tier, got {:?}",
            groups,
            tier
        );
    }
}

#[test]
fn test_admin_requires_exact_suffix() {
    // These should NOT grant admin - "admin" NOT at suffix position
    let non_matching = vec![
        vec!["admin".to_string()],              // No underscore prefix
        vec!["adminX".to_string()],             // Suffix after admin
        vec!["org_ADMIN".to_string()],          // Wrong case
        vec!["org_admin_disabled".to_string()], // Not at end
        vec!["administrator".to_string()],      // Similar but different word
        vec!["admin_users".to_string()],        // Admin at start not end
    ];

    for groups in non_matching {
        let role = extract_role_from_groups(&groups);
        assert_eq!(
            role, "user",
            "Groups {:?} should not grant admin, got {:?}",
            groups, role
        );
    }
}

#[test]
fn test_tier_priority_order() {
    // All tiers present - enterprise should win
    let groups = vec![
        "a_explorer".to_string(),
        "a_professional".to_string(),
        "a_business".to_string(),
        "a_enterprise".to_string(),
    ];
    assert_eq!(extract_tier_from_groups(&groups), Tier::Enterprise);

    // Without enterprise - business should win
    let groups = vec![
        "a_explorer".to_string(),
        "a_professional".to_string(),
        "a_business".to_string(),
    ];
    assert_eq!(extract_tier_from_groups(&groups), Tier::Business);

    // Without business - professional should win
    let groups = vec!["a_explorer".to_string(), "a_professional".to_string()];
    assert_eq!(extract_tier_from_groups(&groups), Tier::Professional);
}

#[test]
fn test_pro_alias_works() {
    // "_pro" should be equivalent to "_professional"
    let groups = vec!["org_pro".to_string()];
    assert_eq!(extract_tier_from_groups(&groups), Tier::Professional);
}
