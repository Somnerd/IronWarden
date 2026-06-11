import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

content = content.replace('"WARDEN_MODE": "Development"', '"WARDEN_MODE": "hybrid"')
content = content.replace('"WARDEN_MODE": "ephemeral"', '"WARDEN_MODE": "hybrid"')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
