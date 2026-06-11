import re
import os

with open("app/tests/legal_e2e_test.rs", "r") as f:
    content = f.read()

# Since tests are run from the workspace root by default but might be run from `app/` sometimes.
# It's safer to use an absolute path via `env!("CARGO_MANIFEST_DIR")` + "/../data/knowledge"
content = content.replace('"data/knowledge"', 'concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge")')
content = content.replace('"../data/knowledge/greek_legal_brief.md"', 'concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge/greek_legal_brief.md")')

with open("app/tests/legal_e2e_test.rs", "w") as f:
    f.write(content)
