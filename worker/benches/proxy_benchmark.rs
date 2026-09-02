use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iw_worker::metrics::GatewayMetrics;
use iw_worker::sse_proxy::SseRehydrator;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

fn bench_streaming_rehydration(c: &mut Criterion) {
    let mut map = HashMap::new();
    map.insert(
        "[PII_EMAIL_1]".to_string(),
        "john.doe@enterprise.com".to_string(),
    );
    map.insert("[PII_SSN_1]".to_string(), "123-45-6789".to_string());
    map.insert(
        "[PII_CARD_1]".to_string(),
        "4532-1234-5678-9012".to_string(),
    );

    let mut group = c.benchmark_group("streaming_rehydration");

    group.bench_function("rehydrate_chunk_without_tokens", |b| {
        let chunk = "The patient shows significant improvement and normal vital signs today. ";
        b.iter(|| {
            let mut rehydrator = SseRehydrator::new(black_box(&map));
            let out = rehydrator.feed(black_box(chunk));
            let flush = rehydrator.flush_all();
            black_box((out, flush));
        })
    });

    group.bench_function("rehydrate_chunk_with_complete_tokens", |b| {
        let chunk = "Patient contact: [PII_EMAIL_1] and verified SSN [PII_SSN_1]. ";
        b.iter(|| {
            let mut rehydrator = SseRehydrator::new(black_box(&map));
            let out = rehydrator.feed(black_box(chunk));
            let flush = rehydrator.flush_all();
            black_box((out, flush));
        })
    });

    group.bench_function("rehydrate_split_tokens_across_chunks", |b| {
        let chunk1 = "Customer payment card: [PII_";
        let chunk2 = "CARD_1] was charged successfully.";
        b.iter(|| {
            let mut rehydrator = SseRehydrator::new(black_box(&map));
            let out1 = rehydrator.feed(black_box(chunk1));
            let out2 = rehydrator.feed(black_box(chunk2));
            let flush = rehydrator.flush_all();
            black_box((out1, out2, flush));
        })
    });

    group.finish();
}

fn bench_metrics_recording(c: &mut Criterion) {
    let metrics = GatewayMetrics::new();
    let mut group = c.benchmark_group("gateway_metrics");

    group.bench_function("atomic_request_increment", |b| {
        b.iter(|| {
            metrics
                .requests_chat_completions
                .fetch_add(black_box(1), Ordering::Relaxed);
        })
    });

    group.bench_function("prometheus_render", |b| {
        b.iter(|| {
            let text = metrics.render_prometheus(black_box(100));
            black_box(text);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_streaming_rehydration,
    bench_metrics_recording
);
criterion_main!(benches);
