import re
import getpass
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Since MCP sets host_user dynamically based on OS user, in tests we need to pass `test_user` if tests expect it.
# Or we can set the env var MCP_HOST_USER ? wait, let's see how host_user is evaluated
