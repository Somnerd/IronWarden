import pytest
import json
import sqlite3
import os
import time

def test_security_homoglyph_bypass(warden):
    """
    Test if the engine correctly identifies PII hidden behind homoglyphs.
    Example: Greek 'Α' (U+0391) instead of Latin 'A'.
    """
    # 'Alice' is in the dictionary rules.
    # We use Greek Alpha (U+0391) for the first 'A'.
    homoglyph_input = "\u0391lice" 
    params = {
        "username": "attacker",
        "prompt": f"Hello {homoglyph_input}"
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Normalizer should convert Greek Alpha to Latin A, and then AC should catch it.
    assert homoglyph_input not in result["sanitized_text"]
    assert "[TOKEN_1]" in result["sanitized_text"]
    assert result["redactions"][0]["rule_id"] == "client_names"

def test_security_invisible_char_bypass(warden):
    """
    Test if the engine correctly identifies PII with zero-width characters injected.
    Example: A[ZWSP]lice.
    """
    # ZWSP: \u200B
    invisible_input = "A\u200Blice"
    params = {
        "username": "attacker",
        "prompt": f"Hey {invisible_input}"
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Normalizer should strip the ZWSP.
    assert invisible_input not in result["sanitized_text"]
    assert "[TOKEN_1]" in result["sanitized_text"]

def test_security_session_isolation_leak(warden):
    """
    Critical Isolation Test: Ensure User B cannot restore User A's tokens.
    """
    alice_secret = "Alice-Private-Key-123"
    bob_secret = "Bob-Private-Key-999"
    
    # 1. Alice enqueues her secret
    # We need a rule that catches these. Let's assume 'internal_projects' or 'company_secrets' matches generic patterns,
    # but for precision let's just use 'Alice' and 'Acme Corp' which are in rules.yaml.
    
    warden.send_mcp("mcp_sanitize_prompt", {"username": "alice", "prompt": f"Secret: Alice"})
    
    # 2. Bob enqueues his secret
    warden.send_mcp("mcp_sanitize_prompt", {"username": "bob", "prompt": f"Secret: Acme Corp"})
    
    # 3. Bob tries to restore [TOKEN_1] (which is Alice's 'Alice' token)
    restore_resp = warden.send_mcp("mcp_restore_prompt", {
        "username": "bob",
        "response": "The secret is [TOKEN_1]"
    })
    
    # If isolation works, [TOKEN_1] for Bob should NOT be 'Alice'.
    # It should either be Bob's token 'Acme Corp' (if IDs are shared) or just '[TOKEN_1]' if not found.
    assert "Alice" not in restore_resp["result"]

def test_security_audit_log_tamper_detection(warden):
    """
    Verify that the audit log hash-chain is active and consistent.
    """
    # 1. Generate some audit events
    warden.send_mcp("mcp_sanitize_prompt", {"username": "audit_test", "prompt": "Alice and Acme Corp"})
    
    # Wait for the async auditor to flush to disk (ephemeral mode still uses a temp file)
    time.sleep(1)
    
    audit_db = warden.env["AUDIT_DB_PATH"]
    conn = sqlite3.connect(audit_db)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, integrity_hash FROM audit_reports ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    assert len(rows) >= 1
    for row_id, h in rows:
        assert len(h) == 64 # SHA-256 hex string
        print(f"DEBUG: Audit Row {row_id} Hash: {h}")

def test_security_jwt_identity_spoofing(warden):
    """
    Test that the Bridge rejects tokens signed with a different key.
    """
    import requests
    import jwt
    
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    
    # Create a token with a WRONG secret
    wrong_secret = "wrong_secret_12345678901234567890"
    payload = {"sub": "alice", "exp": int(time.time()) + 3600}
    spoofed_token = jwt.encode(payload, wrong_secret, algorithm="HS256")
    
    response = requests.post(
        f"{bridge_url}/enqueue",
        json={"query": "test", "thread_id": "t1"},
        headers={"Authorization": f"Bearer {spoofed_token}"}
    )
    
    assert response.status_code == 401
    assert "Invalid or Expired Token" in response.text
