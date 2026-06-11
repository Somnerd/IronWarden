import pytest
import requests
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_security_policy_bypass_naming(warden):
    """
    EXPLOIT TEST: The engine uses rule_id.contains("block") to enforce blocking.
    """
    params = {
        "username": "tester",
        "prompt": "My SSN is 123-45-6789"
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Proves that high-sensitivity data is NOT blocked because the rule ID 'us_ssn' is missing 'block'
    assert result["is_blocked"] is False
    assert "[TOKEN_" in result["sanitized_text"]

def test_security_path_traversal_config(warden_bin):
    """
    Test if setting WARDEN_CONFIG_PATH to a directory without rules fails safely.
    """
    from conftest import IronWardenRunner
    runner = IronWardenRunner(warden_bin, env_overrides={"WARDEN_CONFIG_PATH": "/tmp"})
    try:
        runner.start()
        # If it starts with 0 rules, it should ideally warn.
        # But we check if it actually loads any rules from rules.yaml (which is NOT in /tmp)
        params = {"username": "t", "prompt": "Alice"}
        response = runner.send_mcp("mcp_sanitize_prompt", params)
        # If Alice is NOT redacted, it means no rules were loaded.
        assert "Alice" in response["result"]["sanitized_text"]
        assert len(response["result"]["redactions"]) == 0
    finally:
        runner.stop()

def test_scaling_payload_limits(warden):
    """
    Verify the gateway's payload size limits.
    """
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    import jwt
    token = jwt.encode({"sub": "tester", "aud": "test_audience", "iss": "test_issuer", "exp": int(time.time()) + 3600}, warden.env["JWT_PRIVATE_KEY"], algorithm="RS256")
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2MB should be rejected (413)
    large_query = "A" * (2 * 1024 * 1024)
    response = requests.post(f"{bridge_url}/enqueue", json={"query": large_query, "thread_id": "h"}, headers=headers)
    assert response.status_code == 413

    # 500KB should be accepted
    medium_query = "A" * (512 * 1024)
    response = requests.post(f"{bridge_url}/enqueue", json={"query": medium_query, "thread_id": "m"}, headers=headers)
    assert response.status_code == 200

def test_scaling_ai_mutex_contention(warden):
    """
    Verify that multiple concurrent requests are serialized by the AI Mutex.
    (Indirectly observed via latency spikes).
    """
    # Note: Since our AI is a mock, this might be fast, but if we add a sleep in the mock...
    # For now, just ensure 5 concurrent heavy requests don't crash.
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    import jwt
    token = jwt.encode({"sub": "tester", "aud": "test_audience", "iss": "test_issuer", "exp": int(time.time()) + 3600}, warden.env["JWT_PRIVATE_KEY"], algorithm="RS256")
    headers = {"Authorization": f"Bearer {token}"}
    
    def send():
        return requests.post(f"{bridge_url}/enqueue", json={"query": "Alice " * 10, "thread_id": "t"}, headers=headers)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(send) for _ in range(10)]
        for f in as_completed(futures):
            assert f.result().status_code in [200, 429]

def test_mcp_multi_line_pii(warden):
    params = {
        "username": "tester",
        "prompt": "User Name:\nAlice\nEmail:\nalice@example.com"
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    assert len(result["redactions"]) >= 2
