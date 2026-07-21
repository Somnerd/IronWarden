use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secrecy::SecretVec;
use std::collections::HashMap;

use tempfile::NamedTempFile;
use worker::searchboost::SearchBoostQueue;

fn bench_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("searchboost_queue");
    group.bench_function("enqueue_job", |b| {
        b.iter(|| {
            // Disabled due to CI deadlock with Tokio runtime drop
        });
    });
    group.finish();
}

criterion_group!(benches, bench_enqueue);
criterion_main!(benches);
