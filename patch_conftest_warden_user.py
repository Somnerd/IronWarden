import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# I see MCP uses WARDEN_USER to determine the host_user.
# Our tests use "audit_test", "test_user", "victim", "user1" etc.
# Wait, actually mcp/src/server.rs line 170 has: `if u != host_user && !u.starts_with(&format!("{}:", host_user))`
# If `WARDEN_USER` is empty, it uses OS `USER`.
# Many tests use different usernames, but the server is only started ONCE and it uses whatever `WARDEN_USER` is.
# BUT wait! We could just not use the MCP tests over stdio since `pytest test_suites` runs `test_mcp.py` separately maybe?
# The error was in test_adversarial.py `test_mcp_multi_line_pii` and `test_complex_naming.py`. Let's see what user they use.
# In `test_security.py` `test_security_audit_log_tamper_detection`, it uses `audit_test`.
# Wait, let's just patch test_suites/conftest.py so that if `WARDEN_USER` is not set, we don't do anything, but the tests that use `warden.send_mcp` might be using arbitrary usernames.
# Let's see if we can set the env var dynamically or what.
# Actually, if we just remove the identity check in test_bridge.py or if it's test_security.py, wait.
