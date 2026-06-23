"""
Integration tests for the JSON-RPC Model Context Protocol (MCP) interface of IronWarden.
Validates the initialize endpoint, PII sanitization/tokenization, session-isolated token
restoration, and malformed JSON request error handling.
"""
import pytest
import time
import json

def test_mcp_initialize(warden):
    response = warden.send_mcp("initialize", {})
    assert response["result"]["serverInfo"]["name"] == "IronWarden"
    assert "capabilities" in response["result"]

def test_mcp_sanitize_basic(warden):
    params = {
        "username": "alice",
        "prompt": "Hello Alice, my email is alice@example.com"
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    assert "sanitized_text" in result
    assert "alice@example.com" not in result["sanitized_text"]
    # Depending on order, it might be TOKEN_1 or TOKEN_2
    assert "[TOKEN_" in result["sanitized_text"]
    assert len(result["redactions"]) >= 1

def test_mcp_restore_basic(warden):
    # 1. Sanitize to create session data
    sanitize_params = {
        "username": "bob",
        "prompt": "Call me at 555-0199" # Matches \d{3}-\d{4}
    }
    sanitize_resp = warden.send_mcp("mcp_sanitize_prompt", sanitize_params)
    assert len(sanitize_resp["result"]["redactions"]) > 0
    token = sanitize_resp["result"]["redactions"][0]["placeholder"]
    
    # 2. Restore
    restore_params = {
        "username": "bob",
        "response": f"Acknowledged, {token}."
    }
    restore_resp = warden.send_mcp("mcp_restore_prompt", restore_params)
    assert "555-0199" in restore_resp["result"]
    assert token not in restore_resp["result"]

def test_mcp_session_isolation(warden):
    # Alice's secret
    resp_a = warden.send_mcp("mcp_sanitize_prompt", {"username": "alice", "prompt": "SecretA"})
    token_a = resp_a["result"]["redactions"][0]["placeholder"]
    
    # Bob's secret
    resp_b = warden.send_mcp("mcp_sanitize_prompt", {"username": "bob", "prompt": "SecretB"})
    token_b = resp_b["result"]["redactions"][0]["placeholder"]
    
    # Note: in ephemeral mode with shared cache, they might get DIFFERENT tokens or SAME tokens 
    # but the mapping MUST be isolated by username.
    
    # Bob tries to restore Alice's token
    restore_resp = warden.send_mcp("mcp_restore_prompt", {
        "username": "bob",
        "response": f"Restore {token_a}"
    })
    
    # If isolation works, token_a (which is SecretA for Alice) should NOT resolve to SecretA for Bob.
    # It should either stay as token_a or resolve to something else if Bob happened to have the same token.
    assert "SecretA" not in restore_resp["result"]
    
    # Bob restores his own token
    restore_resp_b = warden.send_mcp("mcp_restore_prompt", {
        "username": "bob",
        "response": f"Restore {token_b}"
    })
    assert "SecretB" in restore_resp_b["result"]

def test_mcp_malformed_json(warden):
    # Send raw malformed string directly
    warden.process.stdin.write("not json\n")
    warden.process.stdin.flush()
    
    # Expect error response
    line = warden.process.stdout.readline()
    response = json.loads(line)
    assert "error" in response
    assert response["error"]["code"] == -32603 # Internal error code used in server.rs
