import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Since tests use "test_user", "alice", "bob", "audit_test", etc.
# We need to bypass the security check in the application when WARDEN_ENV is "test".
