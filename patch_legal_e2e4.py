import re
import os

with open("app/tests/legal_e2e_test.rs", "r") as f:
    content = f.read()

# Since tests are run from the workspace root by default
content = content.replace('concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge")', '"data/knowledge"')
content = content.replace('concat!(env!("CARGO_MANIFEST_DIR"), "/../data/knowledge/greek_legal_brief.md")', '"data/knowledge/greek_legal_brief.md"')

with open("app/tests/legal_e2e_test.rs", "w") as f:
    f.write(content)
