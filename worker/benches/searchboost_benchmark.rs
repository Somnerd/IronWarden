use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secrecy::SecretVec;
use std::collections::HashMap;

use tempfile::NamedTempFile;
use worker::searchboost::SearchBoostQueue;

fn bench_enqueue(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Create temporary database file for the benchmark
    let temp_db = NamedTempFile::new().unwrap();
    let db_path = temp_db.path().to_str().unwrap().to_string();

    let pepper = SecretVec::new(vec![0u8; 32]);

    let queue = {
        let _guard = rt.enter();
        SearchBoostQueue::new(db_path, &pepper, None, None).unwrap()
    };

    let mut group = c.benchmark_group("searchboost_queue");

    group.bench_function("enqueue_job", |b| {
        b.iter(|| {
            rt.block_on(async {
                let options = HashMap::new();
                let _ = queue
                    .enqueue(
                        black_box("Identify PII in this text".to_string()),
                        black_box(options),
                        black_box("thread-123".to_string()),
                        black_box("user-abc".to_string()),
                    )
                    .await
                    .unwrap();
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_enqueue);
criterion_main!(benches);
