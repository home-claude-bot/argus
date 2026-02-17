//! Benchmarks for token validation hot paths

use argus_auth_core::HmacKey;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_hmac_operations(c: &mut Criterion) {
    let key = HmacKey::new("a]".repeat(32)).unwrap();
    let data_sizes = [32, 128, 512, 2048];

    let mut group = c.benchmark_group("hmac_sign");

    for size in data_sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| key.sign(black_box(data)));
        });
    }

    group.finish();

    let mut group = c.benchmark_group("hmac_verify");

    for size in data_sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let signature = key.sign(&data);

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(data.clone(), signature),
            |b, (data, sig)| {
                b.iter(|| key.verify(black_box(data), black_box(sig)));
            },
        );
    }

    group.finish();
}

fn bench_constant_time_eq(c: &mut Criterion) {
    use argus_auth_core::constant_time_eq;

    let sizes = [32, 64, 128, 256];

    let mut group = c.benchmark_group("constant_time_eq");

    for size in sizes {
        let a: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let b: Vec<u8> = a.clone();

        group.bench_with_input(
            BenchmarkId::new("equal", size),
            &(a.clone(), b),
            |bench, (a, b)| {
                bench.iter(|| constant_time_eq(black_box(a), black_box(b)));
            },
        );

        let mut c = a.clone();
        c[0] ^= 0xFF; // Differ at start

        group.bench_with_input(
            BenchmarkId::new("diff_start", size),
            &(a.clone(), c),
            |bench, (a, c)| {
                bench.iter(|| constant_time_eq(black_box(a), black_box(c)));
            },
        );
    }

    group.finish();
}

fn bench_token_type_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_detection");

    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NSJ9.signature";
    let session = "base64payload.signature";

    group.bench_function("jwt_dot_count", |b| {
        b.iter(|| black_box(jwt).bytes().filter(|&b| b == b'.').count());
    });

    group.bench_function("session_dot_count", |b| {
        b.iter(|| black_box(session).bytes().filter(|&b| b == b'.').count());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hmac_operations,
    bench_constant_time_eq,
    bench_token_type_detection,
);
criterion_main!(benches);
