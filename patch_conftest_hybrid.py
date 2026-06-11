import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Let's change the start to WARDEN_MODE = hybrid instead of Development
content = content.replace('"WARDEN_MODE": "Development"', '"WARDEN_MODE": "hybrid"')
with open("test_suites/conftest.py", "w") as f:
    f.write(content)
