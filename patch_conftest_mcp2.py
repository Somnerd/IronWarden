import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# I also need to provide the WARDEN_USER to tests because if it's set to OS USER by default, we don't know what it is (e.g. `jules`).
# Better: test_suites/conftest.py `start()` sets `WARDEN_USER` = "jules" or whatever the test environment expects. Actually we bypassed the check if WARDEN_ENV="test" so any user works.
# Wait, some MCP tests fail! Let's see: `FAILED test_suites/test_adversarial.py::test_scaling_payload_limits - assert 0 > 0`
# Ah! In the tests `response = warden.send_mcp("mcp_sanitize_prompt", params)`
# It expects a response but maybe it returns None because we got a JSON decode error or timeout?
