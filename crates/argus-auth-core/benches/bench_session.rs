//! Benchmarks for session management hot paths

use argus_auth_core::{extract_tier_and_role, extract_tier_from_groups, HmacKey, SessionPayload};
use argus_types::UserId;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_session_payload_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_payload");

    let group_counts = [0, 1, 5, 10];

    for count in group_counts {
        let groups: Vec<String> = (0..count).map(|i| format!("group_{i}")).collect();

        group.bench_with_input(BenchmarkId::new("create", count), &groups, |b, groups| {
            let user_id = UserId::new();
            b.iter(|| {
                SessionPayload::new(
                    black_box(user_id),
                    black_box("user@example.com"),
                    black_box(groups.clone()),
                    24,
                )
            });
        });
    }

    group.finish();
}

fn bench_session_cookie_operations(c: &mut Criterion) {
    let key = HmacKey::new("a]".repeat(32)).unwrap();
    let user_id = UserId::new();
    let payload = SessionPayload::new(
        user_id,
        "benchmark@example.com",
        vec!["andrz_professional".to_string(), "andrz_admin".to_string()],
        24,
    );

    let mut group = c.benchmark_group("session_cookie");

    // Benchmark signing
    group.bench_function("sign", |b| {
        b.iter(|| {
            let payload_json = serde_json::to_vec(black_box(&payload)).unwrap();
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            let signature = key.sign(payload_b64.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
            format!("{payload_b64}.{sig_b64}")
        });
    });

    // Pre-create a signed cookie for verification benchmark
    let payload_json = serde_json::to_vec(&payload).unwrap();
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signature = key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    let cookie = format!("{payload_b64}.{sig_b64}");

    // Benchmark verification (without DB check)
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            let parts: Vec<&str> = black_box(&cookie).rsplitn(2, '.').collect();
            let (sig_b64, payload_b64) = (parts[0], parts[1]);

            let expected = key.sign(payload_b64.as_bytes());
            let provided = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();

            argus_auth_core::constant_time_eq(&expected, &provided)
        });
    });

    // Benchmark full parsing
    group.bench_function("parse_payload", |b| {
        b.iter(|| {
            let parts: Vec<&str> = black_box(&cookie).rsplitn(2, '.').collect();
            let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
            let _: SessionPayload = serde_json::from_slice(&payload_json).unwrap();
        });
    });

    group.finish();
}

fn bench_tier_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier_extraction");

    // Various group configurations
    let test_cases: Vec<(&str, Vec<String>)> = vec![
        ("empty", vec![]),
        ("single_explorer", vec!["org_explorer".to_string()]),
        ("single_enterprise", vec!["org_enterprise".to_string()]),
        (
            "mixed_5",
            vec![
                "users".to_string(),
                "org_professional".to_string(),
                "team_alpha".to_string(),
                "org_admin".to_string(),
                "readonly".to_string(),
            ],
        ),
        (
            "many_groups_10",
            (0..10).map(|i| format!("group_{i}")).collect(),
        ),
    ];

    for (name, groups) in &test_cases {
        group.bench_with_input(
            BenchmarkId::new("single_func", *name),
            groups,
            |b, groups| {
                b.iter(|| extract_tier_from_groups(black_box(groups)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("combined_func", *name),
            groups,
            |b, groups| {
                b.iter(|| extract_tier_and_role(black_box(groups)));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_session_payload_creation,
    bench_session_cookie_operations,
    bench_tier_extraction,
);
criterion_main!(benches);
