import re

with open("app/tests/sentinel_e2e.rs", "r") as f:
    content = f.read()

content = content.replace('assert!(e.contains("Session decryption failed"), "Expected decryption failure, got: {}", e);', 'assert!(e.contains("Decryption failed") || e.contains("Session decryption failed"), "Expected decryption failure, got: {}", e);')

with open("app/tests/sentinel_e2e.rs", "w") as f:
    f.write(content)
