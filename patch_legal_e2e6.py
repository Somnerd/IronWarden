import re
import os

with open("app/tests/legal_e2e_test.rs", "r") as f:
    content = f.read()

# Since `data/knowledge` requires absolute path from root or current dir:
content = content.replace('concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge")', 'concat!(env!("CARGO_MANIFEST_DIR"), "/data/knowledge")')
content = content.replace('concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge/greek_legal_brief.md")', 'concat!(env!("CARGO_MANIFEST_DIR"), "/data/knowledge/greek_legal_brief.md")')

# wait, app directory IS CARGO_MANIFEST_DIR. The workspace root is the parent. So "/../data/knowledge" was correct.
# Why did it fail? Maybe `data/knowledge` doesn't exist relative to CARGO_MANIFEST_DIR/../data/knowledge ?
# Actually we created `data/knowledge` at workspace root. So CARGO_MANIFEST_DIR/../data/knowledge IS correct.
# BUT wait! If we run `cargo test -p app` from workspace root, `data/knowledge` at workspace root works relative to current dir.
# Let's just create the tempdir in the test itself to make it robust, instead of relying on workspace directories.

replacement = """#[tokio::test]
async fn test_legal_e2e() {
    let config_dir = "../config/regions";
    let mut config = WardenConfig::from_dir(config_dir).expect("Failed to load config");
    config.ai_enabled = false;
    let secret = secrecy::SecretVec::new(vec![0u8; 32]);
    let engine = config.compile_engine(&secret).expect("Failed to compile engine");

    let shield: Arc<dyn PiiShield + Send + Sync> = Arc::new(engine);
    let queue = Arc::new(SearchBoostQueue::new("file::memory:?cache=shared".to_string(), &secret, Some(shield.clone()), None).unwrap());

    // Create temp dir
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap();

    let librarian = worker::LocalLibrarian::new(temp_path).await.unwrap();
    let brief = "Nikolas Alexandrakis AFM: 123456789".to_string();
    librarian.add_document(&brief, "legal_user").await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let storage = WorkerStorage::new(
        "file::memory:?cache=shared",
        temp_path,
        secret,
        Some((*queue).clone()),
        None
    ).await.expect("Failed to initialize storage");
"""

content = re.sub(r'#\[tokio::test\]\nasync fn test_legal_e2e\(\) \{.*?None\n    \)\.await\.expect\("Failed to initialize storage"\);', replacement, content, flags=re.DOTALL)
# add use tempfile::tempdir;
content = "use tempfile::tempdir;\n" + content

with open("app/tests/legal_e2e_test.rs", "w") as f:
    f.write(content)
