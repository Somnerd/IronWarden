use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use iw_worker::LocalLibrarian;
use tempfile::TempDir;

fn seed_corpus(rt: &tokio::runtime::Runtime, n: usize) -> (TempDir, LocalLibrarian) {
    let dir = TempDir::new().expect("tempdir for librarian benchmark");
    let path = dir.path().to_str().expect("utf8 tempdir path");

    let librarian = rt.block_on(async {
        let lib = LocalLibrarian::new(path)
            .await
            .expect("LocalLibrarian::new failed");

        let rare_en_slots = [n / 5, (2 * n) / 5, (3 * n) / 5, (4 * n) / 5, n - 1];
        let greek_slots = [
            n / 5 - 1,
            (2 * n) / 5 - 1,
            (3 * n) / 5 - 1,
            (4 * n) / 5 - 1,
            n - 2,
        ];

        for i in 0..n {
            let mut text = format!("enterprise handbook record entry {i}");
            if i % 20 == 0 {
                text.push_str(" quarterly governance compliance");
            }
            if rare_en_slots.contains(&i) {
                text.push_str(" strict compliance encryption mandate");
            }
            if greek_slots.contains(&i) {
                text.push_str(" πολιτική ασφάλειας κρυπτογράφηση");
            }
            lib.add_document(&text, "tenant_alpha")
                .await
                .expect("add_document tenant_alpha failed");
        }

        for i in 0..(n / 2) {
            let text = if i % 10 == 0 {
                format!(
                    "beta tenant decoy {i} strict compliance encryption mandate quarterly governance compliance πολιτική ασφάλειας κρυπτογράφηση"
                )
            } else {
                format!("beta tenant background policy item {i}")
            };
            lib.add_document(&text, "tenant_beta")
                .await
                .expect("add_document tenant_beta failed");
        }

        for q in [
            "strict compliance encryption mandate",
            "quarterly governance compliance",
            "πολιτική ασφάλειας κρυπτογράφηση",
        ] {
            let hits = lib
                .retrieve_policy_context(q, "tenant_alpha", 5)
                .await
                .expect("sanity retrieve failed");
            assert!(!hits.is_empty(), "expected hits for seeded query: {q}");
        }

        lib
    });

    (dir, librarian)
}

fn bench_librarian_retrieval(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("librarian_retrieve");

    for n in [50usize, 500, 5_000] {
        let (_dir, lib) = seed_corpus(&rt, n);

        group.bench_with_input(BenchmarkId::new("rare_english", n), &n, |b, _| {
            b.iter(|| {
                let hits = rt
                    .block_on(lib.retrieve_policy_context(
                        black_box("strict compliance encryption mandate"),
                        black_box("tenant_alpha"),
                        black_box(5),
                    ))
                    .expect("retrieve rare_english");
                black_box(hits);
            });
        });

        group.bench_with_input(BenchmarkId::new("common_english", n), &n, |b, _| {
            b.iter(|| {
                let hits = rt
                    .block_on(lib.retrieve_policy_context(
                        black_box("quarterly governance compliance"),
                        black_box("tenant_alpha"),
                        black_box(5),
                    ))
                    .expect("retrieve common_english");
                black_box(hits);
            });
        });

        group.bench_with_input(BenchmarkId::new("greek_accented", n), &n, |b, _| {
            b.iter(|| {
                let hits = rt
                    .block_on(lib.retrieve_policy_context(
                        black_box("πολιτική ασφάλειας κρυπτογράφηση"),
                        black_box("tenant_alpha"),
                        black_box(5),
                    ))
                    .expect("retrieve greek_accented");
                black_box(hits);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_librarian_retrieval);
criterion_main!(benches);
