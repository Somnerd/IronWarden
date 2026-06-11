import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Add JWT_PUBLIC_KEY to self.env if not there
content = content.replace('"JWT_SECRET": "another_very_secret_key_32_bytes_long",', '"JWT_SECRET": "another_very_secret_key_32_bytes_long",\n            "JWT_PRIVATE_KEY": PRIVATE_KEY,\n            "JWT_PUBLIC_KEY": PUBLIC_KEY,')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
