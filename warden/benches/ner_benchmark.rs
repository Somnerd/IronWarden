use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iw_warden::shadow_ner::ShadowNer;

fn criterion_benchmark(c: &mut Criterion) {
    let ner = ShadowNer::new(vec![]);
    let text = "This is a test of the analyze function with multiple names like Juan Pablo Garcia de la Cruz and Mohammad bin Rashid. And Nikolas Papadopoulos is here too.";

    c.bench_function("shadow_ner_analyze", |b| b.iter(|| ner.analyze(black_box(text))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
