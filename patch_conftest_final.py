import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Ah, `self.env["WARDEN_MODE"] = "Development"` is in `start()`.
# We need to change that line!
content = content.replace('self.env["WARDEN_MODE"] = "Development"', 'self.env["WARDEN_MODE"] = "hybrid"')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
