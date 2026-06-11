import re
import os

with open("app/tests/legal_e2e_test.rs", "r") as f:
    content = f.read()

# Since tests are run from the workspace root by default but the binary might execute inside target/debug/deps, we can just use std::env::current_dir() + "/data/knowledge"
content = content.replace('"data/knowledge"', 'concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge")')
content = content.replace('"data/knowledge/greek_legal_brief.md"', 'concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge/greek_legal_brief.md")')

with open("app/tests/legal_e2e_test.rs", "w") as f:
    f.write(content)
