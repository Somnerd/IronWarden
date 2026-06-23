import os
import re

test_dir = "integration_tests/tests"
for root, _, files in os.walk(test_dir):
    for f in files:
        if f.endswith(".rs"):
            path = os.path.join(root, f)
            with open(path, "r") as file:
                content = file.read()
            
            # Fix any .sanitized_text.contains
            content = re.sub(r'(\w+)\.sanitized_text\.contains', r'String::from_utf8_lossy(&\1.sanitized_text).contains', content)
            
            with open(path, "w") as file:
                file.write(content)
