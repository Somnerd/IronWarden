use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iw_core::crypto::AadCipher;
use secrecy::{ExposeSecret, SecretVec};

fn bench_grounding_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("grounding_crypto");
    let pepper = SecretVec::new(vec![42u8; 32]);
    let query =
        "Patient John Doe with confidential health record seeking medical grounding analysis.";
    let username = "tenant_enterprise_user_1";
    let info = b"warden-v1-queue-encryption";

    group.bench_function("encrypt_sanitized_query", |b| {
        b.iter(|| {
            let encrypted = AadCipher::encrypt(
                black_box(query.as_bytes()),
                black_box(username),
                black_box(pepper.expose_secret()),
                black_box(info),
            )
            .expect("Encryption must succeed");
            black_box(encrypted);
        });
    });

    let encrypted = AadCipher::encrypt(query.as_bytes(), username, pepper.expose_secret(), info)
        .expect("Pre-encryption failed");

    group.bench_function("decrypt_sanitized_query", |b| {
        b.iter(|| {
            let decrypted = AadCipher::decrypt(
                black_box(&encrypted),
                black_box(username),
                black_box(pepper.expose_secret()),
                black_box(info),
            )
            .expect("Decryption must succeed");
            black_box(decrypted);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_grounding_encryption);
criterion_main!(benches);
