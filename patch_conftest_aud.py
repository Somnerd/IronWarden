import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Add WARDEN_JWT_AUDIENCE to env
content = content.replace('"BRIDGE_PORT": "14141",', '"BRIDGE_PORT": "14141",\n            "WARDEN_JWT_AUDIENCE": "test_audience",\n            "WARDEN_JWT_ISSUER": "test_issuer",')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
