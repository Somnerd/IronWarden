import os
import re

test_dir = "integration_tests/tests"
for root, _, files in os.walk(test_dir):
    for f in files:
        if f.endswith(".rs"):
            path = os.path.join(root, f)
            with open(path, "r") as file:
                content = file.read()
            
            # Fix enginesanitize_prompt to engine.sanitize_prompt
            content = content.replace("enginesanitize_prompt(", "engine.sanitize_prompt(")
            content = content.replace("engine2sanitize_prompt(", "engine2.sanitize_prompt(")
            content = content.replace("engine3sanitize_prompt(", "engine3.sanitize_prompt(")
            content = content.replace("shieldsanitize_prompt(", "shield.sanitize_prompt(")
            
            # Revert any axum::body::Bytes to bytes::Bytes (just in case)
            content = content.replace("axum::body::Bytes", "bytes::Bytes")
            
            # Fix Mock ScrubbingReport sanitized_text fields
            content = re.sub(r'sanitized_text:\s*("[^"]*")\.to_string\(\)', r'sanitized_text: \1.to_string().into()', content)
            content = re.sub(r'sanitized_text:\s*format!\("([^"]*)",\s*i\)', r'sanitized_text: format!("\1", i).into()', content)
            
            with open(path, "w") as file:
                file.write(content)
